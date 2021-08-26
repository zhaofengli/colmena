use std::cmp::max;
use std::collections::HashMap;
use std::sync::Arc;

use futures::future::join_all;
use tokio::sync::{Mutex, Semaphore};

use super::{Hive, Host, CopyOptions, NodeConfig, Profile, StoreDerivation, ProfileMap, host};
use super::key::{Key, UploadAt};
use crate::progress::{Progress, TaskProgress, OutputStyle};

/// Amount of RAM reserved for the system, in MB.
const EVAL_RESERVE_MB: u64 = 1024;

/// Estimated amount of RAM needed to evaluate one host, in MB.
const EVAL_PER_HOST_MB: u64 = 512;

const BATCH_OPERATION_LABEL: &'static str = "(...)";

macro_rules! set_up_batch_progress_bar {
    ($progress:ident, $style:ident, $chunk:ident, $single_text:expr, $batch_text:expr) => {{
        if $chunk.len() == 1 {
            let mut bar = $progress.create_task_progress($chunk[0].to_string());
            bar.log($single_text);
            bar
        } else {
            let mut bar = $progress.create_task_progress(BATCH_OPERATION_LABEL.to_string());
            bar.log(&format!($batch_text, $chunk.len()));
            bar
        }
    }};
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Goal {
    /// Build the configurations only.
    Build,

    /// Push the closures only.
    Push,

    /// Make the configuration the boot default and activate now.
    Switch,

    /// Make the configuration the boot default.
    Boot,

    /// Activate the configuration, but don't make it the boot default.
    Test,

    /// Show what would be done if this configuration were activated.
    DryActivate,
}

impl Goal {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "build" => Some(Self::Build),
            "push" => Some(Self::Push),
            "switch" => Some(Self::Switch),
            "boot" => Some(Self::Boot),
            "test" => Some(Self::Test),
            "dry-activate" => Some(Self::DryActivate),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'static str> {
        use Goal::*;
        match self {
            Build => None,
            Push => None,
            Switch => Some("switch"),
            Boot => Some("boot"),
            Test => Some("test"),
            DryActivate => Some("dry-activate"),
        }
    }

    pub fn success_str(&self) -> Option<&'static str> {
        use Goal::*;
        match self {
            Build => Some("Configuration built"),
            Push => Some("Pushed"),
            Switch => Some("Activation successful"),
            Boot => Some("Will be activated next boot"),
            Test => Some("Activation successful (test)"),
            DryActivate => Some("Dry activation successful"),
        }
    }

    pub fn should_switch_profile(&self) -> bool {
        use Goal::*;
        match self {
            Boot | Switch => true,
            _ => false,
        }
    }

    pub fn requires_activation(&self) -> bool {
        use Goal::*;
        match self {
            Build | Push => false,
            _ => true,
        }
    }
}

/// Internal deployment stages.
#[derive(Debug)]
enum Stage {
    Evaluate(Vec<String>),
    Build(Vec<String>),
    Apply(String),
}

/// Results of a deployment to a node.
#[derive(Debug)]
struct DeploymentResult {
    /// Stage in which the deployment ended.
    stage: Stage,

    /// Whether the deployment succeeded or not.
    success: bool,

    /// Unstructured logs of the deployment.
    logs: Option<String>,
}

impl DeploymentResult {
    fn success(stage: Stage, logs: Option<String>) -> Self {
        Self {
            stage,
            success: true,
            logs,
        }
    }

    fn failure(stage: Stage, logs: Option<String>) -> Self {
        Self {
            stage,
            success: false,
            logs,
        }
    }

    fn is_successful(&self) -> bool {
        self.success
    }

    fn print(&self) {
        use Stage::*;

        if self.is_successful() {
            unimplemented!();
        }

        match &self.stage {
            Evaluate(nodes) => {
                self.print_failed_nodes("Evaluation of", &nodes, true);
            }
            Build(nodes) => {
                self.print_failed_nodes("Build of", &nodes, true);
            }
            Apply(node) => {
                self.print_failed_nodes("Deployment to", &vec![node.clone()], false);
            }
        }
    }

    fn print_failed_nodes(&self, prefix: &'static str, nodes: &Vec<String>, full_logs: bool) {
        let msg = if nodes.len() == 1 {
            format!("{} {} failed.", prefix, nodes[0])
        } else {
            format!("{} {} nodes failed.", prefix, nodes.len())
        };

        if let Some(logs) = self.logs.as_ref() {
            let mut lines = logs.split("\n").collect::<Vec<&str>>();

            if full_logs {
                log::error!("{} Logs:", msg);
            } else {
                lines = lines.drain(..).rev().take(10).rev().collect();
                log::error!("{} Last {} lines of logs:", msg, lines.len());
            }

            for line in lines {
                log::error!("{}", line);
            }
        }
    }
}

/// A deployment target.
#[derive(Debug)]
pub struct Target {
    host: Box<dyn Host>,
    config: NodeConfig,
}

impl Target {
    pub fn new(host: Box<dyn Host>, config: NodeConfig) -> Self {
        Self { host, config }
    }
}

#[derive(Debug)]
pub struct Deployment {
    hive: Hive,
    goal: Goal,
    target_names: Vec<String>,
    targets: Mutex<HashMap<String, Target>>,
    label_width: usize,
    parallelism_limit: ParallelismLimit,
    evaluation_node_limit: EvaluationNodeLimit,
    options: DeploymentOptions,
    results: Mutex<Vec<DeploymentResult>>,
}

impl Deployment {
    pub fn new(hive: Hive, targets: HashMap<String, Target>, goal: Goal) -> Self {
        let target_names: Vec<String> = targets.keys().cloned().collect();

        let label_width = if let Some(len) = target_names.iter().map(|n| n.len()).max() {
            max(BATCH_OPERATION_LABEL.len(), len)
        } else {
            BATCH_OPERATION_LABEL.len()
        };

        Self {
            hive,
            goal,
            target_names,
            targets: Mutex::new(targets),
            label_width,
            parallelism_limit: ParallelismLimit::default(),
            evaluation_node_limit: EvaluationNodeLimit::default(),
            options: DeploymentOptions::default(),
            results: Mutex::new(Vec::new()),
        }
    }

    pub fn set_options(&mut self, options: DeploymentOptions) {
        self.options = options;
    }

    pub fn set_parallelism_limit(&mut self, limit: ParallelismLimit) {
        self.parallelism_limit = limit;
    }

    pub fn set_evaluation_node_limit(&mut self, limit: EvaluationNodeLimit) {
        self.evaluation_node_limit = limit;
    }

    /// Uploads keys only (user-facing)
    pub async fn upload_keys(self: Arc<Self>) -> bool {
        let progress = {
            let mut progress = Progress::default();
            progress.set_label_width(self.label_width);
            Arc::new(progress)
        };

        let arc_self = self.clone();

        {
            let arc_self = self.clone();
            progress.run(|progress| async move {
                let mut futures = Vec::new();

                for node in self.target_names.iter() {
                    let node = node.to_owned();

                    let mut target = {
                        let mut targets = arc_self.targets.lock().await;
                        targets.remove(&node).unwrap()
                    };

                    let arc_self = self.clone();
                    let progress = progress.clone();
                    futures.push(async move {
                        let permit = arc_self.parallelism_limit.apply.acquire().await.unwrap();
                        let mut task = progress.create_task_progress(node.clone());

                        task.log("Uploading keys...");

                        if let Err(e) = target.host.upload_keys(&target.config.keys, true).await {
                            task.failure_err(&e);

                            let mut results = arc_self.results.lock().await;
                            let stage = Stage::Apply(node.to_string());
                            let logs = target.host.dump_logs().await.map(|s| s.to_string());
                            results.push(DeploymentResult::failure(stage, logs));
                            return;
                        } else {
                            task.success("Keys uploaded");
                        }

                        drop(permit);
                    });
                }

                join_all(futures).await
            }).await;
        }

        arc_self.print_logs().await;

        arc_self.all_successful().await
    }

    /// Executes the deployment (user-facing)
    ///
    /// Self must be wrapped inside an Arc.
    pub async fn execute(self: Arc<Self>) -> bool {
        let progress = {
            let mut progress = if !self.options.progress_bar {
                Progress::with_style(OutputStyle::Plain)
            } else {
                Progress::default()
            };
            progress.set_label_width(self.label_width);
            Arc::new(progress)
        };

        let arc_self = self.clone();

        {
            let arc_self = self.clone();
            let eval_limit = arc_self.clone().eval_limit();

            progress.run(|progress| async move {
                let mut futures = Vec::new();

                for chunk in self.target_names.chunks(eval_limit) {
                    let arc_self = arc_self.clone();
                    let progress = progress.clone();

                    // FIXME: Eww
                    let chunk: Vec<String> = chunk.iter().map(|s| s.to_string()).collect();

                    futures.push(async move {
                        let drv = {
                            // Evaluation phase
                            let permit = arc_self.parallelism_limit.evaluation.acquire().await.unwrap();

                            let bar = set_up_batch_progress_bar!(progress, style, chunk,
                                "Evaluating configuration...",
                                "Evaluating configurations for {} nodes"
                            );

                            let arc_self = arc_self.clone();
                            let drv = match arc_self.eval_profiles(&chunk, bar).await {
                                Some(drv) => drv,
                                None => {
                                    return;
                                }
                            };

                            drop(permit);
                            drv
                        };

                        let profiles = {
                            // Build phase
                            let permit = arc_self.parallelism_limit.build.acquire().await.unwrap();
                            let bar = set_up_batch_progress_bar!(progress, style, chunk,
                                "Building configuration...",
                                "Building configurations for {} nodes"
                            );

                            let goal = arc_self.goal;
                            let profiles = arc_self.clone().build_profiles(&chunk, drv, bar.clone()).await;

                            let profiles = match profiles {
                                Some(profiles) => profiles,
                                None => {
                                    return;
                                }
                            };

                            bar.success_quiet();
                            if goal == Goal::Build {
                                for (node, profile) in profiles.iter() {
                                    let bar = progress.create_task_progress(node.to_string());
                                    bar.success(&format!("Built {:?}", profile.as_path()));
                                }
                            }

                            if arc_self.options.create_gc_roots {
                                // Create GC roots
                                if let Some(dir) = arc_self.hive.context_dir() {
                                    let base = dir.join(".gcroots");

                                    if let Err(e) = profiles.create_gc_roots(&base).await {
                                        let bar = progress.create_task_progress(BATCH_OPERATION_LABEL.to_string());
                                        bar.failure(&format!("Failed to create GC roots: {:?}", e));
                                    }
                                }
                            }

                            drop(permit);
                            profiles
                        };

                        // Should we continue?
                        if arc_self.goal == Goal::Build {
                            return;
                        }

                        // Apply phase
                        let mut futures = Vec::new();
                        for node in chunk {
                            let arc_self = arc_self.clone();
                            let progress = progress.clone();

                            let target = {
                                let mut targets = arc_self.targets.lock().await;
                                targets.remove(&node).unwrap()
                            };
                            let profile = profiles.get(&node).cloned()
                                .expect(&format!("Somehow profile for {} was not built", node));

                            futures.push(async move {
                                arc_self.apply_profile(&node, target, profile, progress).await
                            });
                        }
                        join_all(futures).await;
                    });
                }

                join_all(futures).await;
            }).await;
        }

        arc_self.print_logs().await;

        arc_self.all_successful().await
    }

    async fn all_successful(&self) -> bool {
        let results = self.results.lock().await;
        results.iter().filter(|r| !r.is_successful()).count() == 0
    }

    async fn print_logs(&self) {
        let results = self.results.lock().await;
        for result in results.iter() {
            if !result.is_successful() {
                result.print();
            }
        }
    }

    async fn eval_profiles(self: Arc<Self>, chunk: &Vec<String>, progress: TaskProgress) -> Option<StoreDerivation<ProfileMap>> {
        let (eval, logs) = self.hive.eval_selected(&chunk, progress.clone()).await;

        match eval {
            Ok(drv) => {
                progress.success_quiet();
                Some(drv)
            }
            Err(e) => {
                progress.failure(&format!("Evalation failed: {}", e));

                let mut results = self.results.lock().await;
                let stage = Stage::Evaluate(chunk.clone());
                results.push(DeploymentResult::failure(stage, logs));
                None
            }
        }
    }

    async fn build_profiles(self: Arc<Self>, chunk: &Vec<String>, derivation: StoreDerivation<ProfileMap>, progress: TaskProgress) -> Option<ProfileMap> {
        let nix_options = self.hive.nix_options().await.unwrap();
        // FIXME: Remote build?
        let mut builder = host::local(nix_options);

        builder.set_progress_bar(progress.clone());

        match derivation.realize(&mut *builder).await {
            Ok(profiles) => {
                progress.success("Build successful");

                let mut results = self.results.lock().await;
                let stage = Stage::Build(chunk.clone());
                let logs = builder.dump_logs().await.map(|s| s.to_string());
                results.push(DeploymentResult::success(stage, logs));

                Some(profiles)
            }
            Err(e) => {
                progress.failure(&format!("Build failed: {}", e));

                let mut results = self.results.lock().await;
                let stage = Stage::Build(chunk.clone());
                let logs = builder.dump_logs().await.map(|s| s.to_string());
                results.push(DeploymentResult::failure(stage, logs));
                None
            }
        }
    }

    async fn apply_profile(self: Arc<Self>, name: &str, mut target: Target, profile: Profile, multi: Arc<Progress>) {
        let permit = self.parallelism_limit.apply.acquire().await.unwrap();

        let mut bar = multi.create_task_progress(name.to_string());

        // FIXME: Would be nicer to check remote status before spending time evaluating/building
        if !target.config.replace_unknown_profiles {
            bar.log("Checking remote profile...");
            match target.host.active_derivation_known().await {
                Ok(_) => {
                    bar.log("Remote profile known");
                }
                Err(e) => {
                    if self.options.force_replace_unknown_profiles {
                        bar.log("warning: remote profile is unknown, but unknown profiles are being ignored");
                    } else {
                        bar.failure(&format!("Failed: {}", e));
                        return;
                    }
                }
            }
        }

        let pre_activation_keys = target.config.keys.iter()
            .filter(|(_, v)| v.upload_at() == UploadAt::PreActivation)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<String, Key>>();

        let post_activation_keys = target.config.keys.iter()
            .filter(|(_, v)| v.upload_at() == UploadAt::PostActivation)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<String, Key>>();

        if self.options.upload_keys && !pre_activation_keys.is_empty() {
            bar.log("Uploading keys...");

            if let Err(e) = target.host.upload_keys(&pre_activation_keys, false).await {
                bar.failure_err(&e);

                let mut results = self.results.lock().await;
                let stage = Stage::Apply(name.to_string());
                let logs = target.host.dump_logs().await.map(|s| s.to_string());
                results.push(DeploymentResult::failure(stage, logs));
                return;
            }
        }

        bar.log("Starting...");

        target.host.set_progress_bar(bar.clone());

        let copy_options = self.options.to_copy_options()
            .include_outputs(true);

        match target.host.deploy(&profile, self.goal, copy_options).await {
            Ok(_) => {
                // FIXME: This is ugly
                if self.options.upload_keys && !post_activation_keys.is_empty() {
                    bar.log("Uploading keys (post-activation)...");

                    if let Err(e) = target.host.upload_keys(&post_activation_keys, true).await {
                        bar.failure_err(&e);

                        let mut results = self.results.lock().await;
                        let stage = Stage::Apply(name.to_string());
                        let logs = target.host.dump_logs().await.map(|s| s.to_string());
                        results.push(DeploymentResult::failure(stage, logs));
                        return;
                    }
                }

                bar.success(self.goal.success_str().unwrap());

                let mut results = self.results.lock().await;
                let stage = Stage::Apply(name.to_string());
                let logs = target.host.dump_logs().await.map(|s| s.to_string());
                results.push(DeploymentResult::success(stage, logs));
            }
            Err(e) => {
                bar.failure(&format!("Failed: {}", e));

                let mut results = self.results.lock().await;
                let stage = Stage::Apply(name.to_string());
                let logs = target.host.dump_logs().await.map(|s| s.to_string());
                results.push(DeploymentResult::failure(stage, logs));
            }
        }

        drop(permit);
    }

    fn eval_limit(&self) -> usize {
        if let Some(limit) = self.evaluation_node_limit.get_limit() {
            limit
        } else {
            self.target_names.len()
        }
    }
}

#[derive(Debug)]
pub struct ParallelismLimit {
    /// Limit of concurrent evaluation processes.
    evaluation: Semaphore,

    /// Limit of concurrent build processes.
    build: Semaphore,

    /// Limit of concurrent apply processes.
    apply: Semaphore,
}

impl Default for ParallelismLimit {
    fn default() -> Self {
        Self {
            evaluation: Semaphore::new(1),
            build: Semaphore::new(2),
            apply: Semaphore::new(10),
        }
    }
}

impl ParallelismLimit {
    // Do we actually want them to be configurable?
    /*
    /// Sets the concurrent evaluation limit.
    ///
    /// This limits the number of evaluation processes, not
    /// the number of nodes in each evaluation process.
    /// The latter is controlled in DeploymentOptions.
    pub fn set_evaluation_limit(&mut self, limit: usize) {
        self.evaluation = Semaphore::new(limit);
    }

    /// Sets the concurrent build limit.
    pub fn set_build_limit(&mut self, limit: usize) {
        self.build = Semaphore::new(limit);
    }
    */

    /// Sets the concurrent apply limit.
    pub fn set_apply_limit(&mut self, limit: usize) {
        self.apply = Semaphore::new(limit);
    }
}

#[derive(Clone, Debug)]
pub struct DeploymentOptions {
    /// Whether to show condensed progress bars.
    ///
    /// If set to false, verbose logs will be displayed instead.
    progress_bar: bool,

    /// Whether to use binary caches when copying closures to remote hosts.
    substituters_push: bool,

    /// Whether to use gzip when copying closures to remote hosts.
    gzip: bool,

    /// Whether to upload keys when deploying.
    upload_keys: bool,

    /// Whether to create GC roots for node profiles.
    ///
    /// If true, .gc_roots will be created under the hive's context
    /// directory if it exists.
    create_gc_roots: bool,

    /// Ignore the node-level `deployment.replaceUnknownProfiles` option.
    force_replace_unknown_profiles: bool,
}

impl Default for DeploymentOptions {
    fn default() -> Self {
        Self {
            progress_bar: true,
            substituters_push: true,
            gzip: true,
            upload_keys: true,
            create_gc_roots: false,
            force_replace_unknown_profiles: false,
        }
    }
}

impl DeploymentOptions {
    pub fn set_progress_bar(&mut self, value: bool) {
        self.progress_bar = value;
    }

    pub fn set_substituters_push(&mut self, value: bool) {
        self.substituters_push = value;
    }

    pub fn set_gzip(&mut self, value: bool) {
        self.gzip = value;
    }

    pub fn set_upload_keys(&mut self, enable: bool) {
        self.upload_keys = enable;
    }

    pub fn set_create_gc_roots(&mut self, enable: bool) {
        self.create_gc_roots = enable;
    }

    pub fn set_force_replace_unknown_profiles(&mut self, enable: bool) {
        self.force_replace_unknown_profiles = enable;
    }

    fn to_copy_options(&self) -> CopyOptions {
        let options = CopyOptions::default();

        options
            .use_substitutes(self.substituters_push)
            .gzip(self.gzip)
    }
}

/// Limit of the number of nodes in each evaluation process.
///
/// The evaluation process is very RAM-intensive, with memory
/// consumption scaling linearly with the number of nodes
/// evaluated at the same time. This can be a problem if you
/// are deploying to a large number of nodes at the same time,
/// where `nix-instantiate` may consume too much RAM and get
/// killed by the OS (`NixKilled` error).
///
/// Evaluating each node on its own is not an efficient solution,
/// with total CPU time and memory consumption vastly exceeding the
/// case where we evaluate the same set of nodes at the same time
/// (TODO: Provide statistics).
///
/// To overcome this problem, we split the evaluation process into
/// chunks when necessary, with the maximum number of nodes in
/// each `nix-instantiate` invocation determined with:
///
/// - A simple heuristic based on remaining memory in the system
/// - A supplied number
/// - No limit at all
#[derive(Copy, Clone, Debug)]
pub enum EvaluationNodeLimit {
    /// Use a naive heuristic based on available memory.
    Heuristic,

    /// Supply the maximum number of nodes.
    Manual(usize),

    /// Do not limit the number of nodes in each evaluation process
    None,
}

impl Default for EvaluationNodeLimit {
    fn default() -> Self {
        Self::Heuristic
    }
}

impl EvaluationNodeLimit {
    /// Returns the maximum number of hosts in each evaluation.
    ///
    /// The result should be cached.
    pub fn get_limit(&self) -> Option<usize> {
        match self {
            EvaluationNodeLimit::Heuristic => {
                if let Ok(mem_info) = sys_info::mem_info() {
                    let mut mb = mem_info.avail / 1024;

                    if mb >= EVAL_RESERVE_MB {
                        mb -= EVAL_RESERVE_MB;
                    }

                    let nodes = mb / EVAL_PER_HOST_MB;

                    if nodes == 0 {
                        Some(1)
                    } else {
                        Some(nodes as usize)
                    }
                } else {
                    Some(10)
                }
            }
            EvaluationNodeLimit::Manual(limit) => Some(*limit),
            EvaluationNodeLimit::None => None,
        }
    }
}
