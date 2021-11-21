//! Deployment logic.

pub mod goal;

pub use goal::Goal;

pub mod limits;
pub use limits::{EvaluationNodeLimit, ParallelismLimit};

pub mod options;
pub use options::Options;

use std::collections::HashMap;
use std::mem;
use std::sync::Arc;

use futures::future::join_all;
use itertools::Itertools;

use crate::progress::Sender as ProgressSender;
use crate::job::{JobMonitor, JobHandle, JobType, JobState};
use crate::util;

use super::{
    Hive,
    Host,
    NodeName,
    NodeConfig,
    NixError,
    NixResult,
    Profile,
    ProfileMap,
    StoreDerivation,
    CopyDirection,
    key::{Key, UploadAt as UploadKeyAt},
};
use super::host;

/// A deployment.
pub type DeploymentHandle = Arc<Deployment>;

/// A map of target nodes.
pub type TargetNodeMap = HashMap<NodeName, TargetNode>;

/// A deployment.
#[derive(Debug)]
pub struct Deployment {
    /// The configuration.
    hive: Hive,

    /// The goal of this deployment.
    goal: Goal,

    /// Deployment options.
    options: Options,

    /// Handle to send messages to the ProgressOutput.
    progress: Option<ProgressSender>,

    /// Names of the target nodes.
    nodes: Vec<NodeName>,

    /// Handles to the deployment targets.
    targets: HashMap<NodeName, TargetNode>,

    /// Parallelism limit.
    parallelism_limit: ParallelismLimit,

    /// Evaluation limit.
    evaluation_node_limit: EvaluationNodeLimit,

    /// Whether it was executed.
    executed: bool,
}

/// Handle to a target node.
#[derive(Debug)]
pub struct TargetNode {
    /// Name of the node.
    name: NodeName,

    /// The host to deploy to.
    host: Option<Box<dyn Host>>,

    /// The config.deployment values of the node.
    config: NodeConfig,
}

impl TargetNode {
    pub fn new(name: NodeName, host: Option<Box<dyn Host>>, config: NodeConfig) -> Self {
        Self { name, host, config }
    }

    pub fn into_host(self) -> Option<Box<dyn Host>> {
        self.host
    }
}

impl Deployment {
    /// Creates a new deployment.
    pub fn new(hive: Hive, targets: TargetNodeMap, goal: Goal, progress: Option<ProgressSender>) -> Self {
        Self {
            hive,
            goal,
            progress,
            nodes: targets.keys().cloned().collect(),
            targets,
            parallelism_limit: ParallelismLimit::default(),
            evaluation_node_limit: EvaluationNodeLimit::default(),
            options: Options::default(),
            executed: false,
        }
    }

    /// Executes the deployment.
    ///
    /// If a ProgressSender is supplied, then this should be run in parallel
    /// with its `run_until_completion()` future.
    pub async fn execute(mut self) -> NixResult<()> {
        if self.executed {
            return Err(NixError::DeploymentAlreadyExecuted);
        }

        self.executed = true;

        let (mut monitor, meta) = JobMonitor::new(self.progress.clone());

        if let Some(width) = util::get_label_width(&self.targets) {
            monitor.set_label_width(width);
        }

        if self.goal == Goal::UploadKeys {
            // Just upload keys
            let targets = mem::take(&mut self.targets);
            let deployment = DeploymentHandle::new(self);
            let meta_future = meta.run(|meta| async move {
                let mut futures = Vec::new();

                for target in targets.into_values() {
                    futures.push(deployment.clone().upload_keys_to_node(meta.clone(), target));
                }

                let result: NixResult<Vec<()>> = join_all(futures).await.into_iter().collect();

                result?;

                Ok(())
            });

            let (result, _) = tokio::join!(
                meta_future,
                monitor.run_until_completion(),
            );

            result?;

            Ok(())
        } else {
            // Do the whole eval-build-deploy flow
            let chunks = self.get_chunks();
            let deployment = DeploymentHandle::new(self);
            let meta_future = meta.run(|meta| async move {
                let mut futures = Vec::new();

                for chunk in chunks.into_iter() {
                    futures.push(deployment.clone().execute_chunk(meta.clone(), chunk));
                }

                let result: NixResult<Vec<()>> = join_all(futures).await.into_iter().collect();

                result?;

                Ok(())
            });

            let (result, _) = tokio::join!(
                meta_future,
                monitor.run_until_completion(),
            );

            result?;

            Ok(())
        }
    }

    pub fn set_options(&mut self, options: Options) {
        self.options = options;
    }

    pub fn set_parallelism_limit(&mut self, limit: ParallelismLimit) {
        self.parallelism_limit = limit;
    }

    pub fn set_evaluation_node_limit(&mut self, limit: EvaluationNodeLimit) {
        self.evaluation_node_limit = limit;
    }

    fn get_chunks(&mut self) -> Vec<TargetNodeMap> {
        let eval_limit = self.evaluation_node_limit.get_limit()
            .unwrap_or(self.targets.len());
        let mut result = Vec::new();

        for chunk in self.targets.drain().chunks(eval_limit).into_iter() {
            let mut map = HashMap::new();
            for (name, host) in chunk {
                map.insert(name, host);
            }
            result.push(map);
        }

        result
    }

    /// Executes the deployment against a portion of nodes.
    async fn execute_chunk(self: DeploymentHandle, parent: JobHandle, mut chunk: TargetNodeMap) -> NixResult<()> {
        if self.goal == Goal::UploadKeys {
            unreachable!(); // some logic is screwed up
        }

        let nodes: Vec<NodeName> = chunk.keys().cloned().collect();
        let profiles = self.clone().build_nodes(parent.clone(), nodes.clone()).await?;

        if self.goal == Goal::Build {
            return Ok(());
        }

        for (name, profile) in profiles.iter() {
            let target = chunk.remove(&name).unwrap();
            self.clone().deploy_node(parent.clone(), target, profile.clone()).await?;
        }

        // Create GC root
        if self.options.create_gc_roots {
            let job = parent.create_job(JobType::CreateGcRoots, nodes.clone())?;
            let arc_self = self.clone();
            job.run_waiting(|job| async move {
                if let Some(dir) = arc_self.hive.context_dir() {
                    job.state(JobState::Running)?;
                    let base = dir.join(".gcroots");

                    profiles.create_gc_roots(&base).await?;
                } else {
                    job.noop("No context directory to create GC roots in".to_string())?;
                }
                Ok(())
            }).await?;
        }

        Ok(())
    }

    /// Evaluates a set of nodes, returning a store derivation.
    async fn evaluate_nodes(self: DeploymentHandle, parent: JobHandle, nodes: Vec<NodeName>)
        -> NixResult<StoreDerivation<ProfileMap>>
    {
        let job = parent.create_job(JobType::Evaluate, nodes.clone())?;

        job.run_waiting(|job| async move {
            // Wait for eval limit
            let permit = self.parallelism_limit.evaluation.acquire().await.unwrap();
            job.state(JobState::Running)?;

            let result = self.hive.eval_selected(&nodes, Some(job.clone())).await;

            drop(permit);
            result
        }).await
    }

    /// Builds a set of nodes, returning a set of profiles.
    async fn build_nodes(self: DeploymentHandle, parent: JobHandle, nodes: Vec<NodeName>)
        -> NixResult<ProfileMap>
    {
        let job = parent.create_job(JobType::Build, nodes.clone())?;

        job.run_waiting(|job| async move {
            let derivation = self.clone().evaluate_nodes(job.clone(), nodes.clone()).await?;

            // Wait for build limit
            let permit = self.parallelism_limit.apply.acquire().await.unwrap();
            job.state(JobState::Running)?;

            // FIXME: Remote builder?
            let nix_options = self.hive.nix_options().await.unwrap();
            let mut builder = host::local(nix_options);

            let map = derivation.realize(&mut *builder).await?;

            job.profiles_built(map.clone())?;

            drop(permit);
            Ok(map)
        }).await
    }

    /// Only uploads keys to a node.
    async fn upload_keys_to_node(self: DeploymentHandle, parent: JobHandle, mut target: TargetNode) -> NixResult<()> {
        let nodes = vec![target.name.clone()];
        let job = parent.create_job(JobType::UploadKeys, nodes)?;
        job.run(|_| async move {
            if target.host.is_none() {
                return Err(NixError::Unsupported);
            }

            let host = target.host.as_mut().unwrap();
            host.upload_keys(&target.config.keys, true).await?;

            Ok(())
        }).await
    }

    /// Pushes and optionally activates a system profile on a given node.
    ///
    /// This will also upload keys to the node.
    async fn deploy_node(self: DeploymentHandle, parent: JobHandle, mut target: TargetNode, profile: Profile)
        -> NixResult<()>
    {
        if self.goal == Goal::Build {
            unreachable!();
        }

        let nodes = vec![target.name.clone()];

        let push_job = parent.create_job(JobType::Push, nodes.clone())?;
        let push_profile = profile.clone();
        let arc_self = self.clone();
        let mut target = push_job.run_waiting(|job| async move {
            if target.host.is_none() {
                return Err(NixError::Unsupported);
            }

            let permit = arc_self.parallelism_limit.apply.acquire().await.unwrap();
            job.state(JobState::Running)?;

            let host = target.host.as_mut().unwrap();
            host.copy_closure(
                push_profile.as_store_path(),
                CopyDirection::ToRemote,
                arc_self.options.to_copy_options()).await?;

            drop(permit);
            Ok(target)
        }).await?;

        if !self.goal.requires_activation() {
            // We are done here :)
            return Ok(());
        }

        // Upload pre-activation keys
        let mut target = if self.options.upload_keys {
            let job = parent.create_job(JobType::UploadKeys, nodes.clone())?;
            job.run_waiting(|job| async move {
                let keys = target.config.keys.iter()
                    .filter(|(_, v)| v.upload_at() == UploadKeyAt::PreActivation)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Key>>();

                if keys.is_empty() {
                    job.noop("No pre-activation keys to upload".to_string())?;
                    return Ok(target);
                }

                job.state(JobState::Running)?;
                job.message("Uploading pre-activation keys...".to_string())?;

                let host = target.host.as_mut().unwrap();
                host.upload_keys(&keys, false).await?;

                job.success_with_message("Uploaded keys (pre-activation)".to_string())?;
                Ok(target)
            }).await?
        } else {
            target
        };

        // Activate profile
        let activation_job = parent.create_job(JobType::Activate, nodes.clone())?;
        let arc_self = self.clone();
        let profile_r = profile.clone();
        let mut target = activation_job.run(|job| async move {
            let host = target.host.as_mut().unwrap();

            if !target.config.replace_unknown_profiles {
                job.message("Checking remote profile...".to_string())?;
                match host.active_derivation_known().await {
                    Ok(_) => {
                        job.message("Remote profile known".to_string())?;
                    }
                    Err(e) => {
                        if arc_self.options.force_replace_unknown_profiles {
                            job.message("warning: remote profile is unknown, but unknown profiles are being ignored".to_string())?;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }

            host.activate(&profile_r, arc_self.goal).await?;

            job.success_with_message(arc_self.goal.success_str().to_string())?;

            Ok(target)
        }).await?;

        // Upload post-activation keys
        if self.options.upload_keys {
            let job = parent.create_job(JobType::UploadKeys, nodes.clone())?;
            job.run_waiting(|job| async move {
                let keys = target.config.keys.iter()
                    .filter(|(_, v)| v.upload_at() == UploadKeyAt::PostActivation)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Key>>();

                if keys.is_empty() {
                    job.noop("No post-activation keys to upload".to_string())?;
                    return Ok(());
                }

                job.state(JobState::Running)?;
                job.message("Uploading post-activation keys...".to_string())?;

                let host = target.host.as_mut().unwrap();
                host.upload_keys(&keys, true).await?;

                job.success_with_message("Uploaded keys (post-activation)".to_string())?;
                Ok(())
            }).await?;
        }

        Ok(())
    }
}
