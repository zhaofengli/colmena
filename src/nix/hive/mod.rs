use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::convert::AsRef;

use tempfile::{NamedTempFile, TempPath};
use tokio::process::Command;
use tokio::sync::RwLock;
use serde::Serialize;
use validator::Validate;

use super::{
    Flake,
    StoreDerivation,
    NixResult,
    NodeName,
    NodeConfig,
    NodeFilter,
    ProfileMap,
};
use super::deployment::TargetNode;
use super::NixCommand;
use crate::util::CommandExecution;
use crate::job::JobHandle;

const HIVE_EVAL: &'static [u8] = include_bytes!("eval.nix");

#[derive(Debug)]
pub enum HivePath {
    /// A Nix Flake.
    ///
    /// The flake must contain the `colmena` output.
    Flake(Flake),

    /// A regular .nix file
    Legacy(PathBuf),
}

impl HivePath {
    pub async fn from_path<P: AsRef<Path>>(path: P) -> NixResult<Self> {
        let path = path.as_ref();

        if let Some(osstr) = path.file_name() {
            if osstr == "flake.nix" {
                let parent = path.parent().unwrap();
                let flake = Flake::from_dir(parent).await?;
                return Ok(Self::Flake(flake));
            }
        }

        Ok(Self::Legacy(path.to_owned()))
    }

    fn context_dir(&self) -> Option<PathBuf> {
        match self {
            Self::Legacy(p) => {
                p.parent().map(|d| d.to_owned())
            }
            Self::Flake(flake) => {
                flake.local_dir().map(|d| d.to_owned())
            }
        }
    }
}

#[derive(Debug)]
pub struct Hive {
    /// Path to the hive.
    path: HivePath,

    /// Path to the context directory.
    ///
    /// Normally this is directory containing the "hive.nix"
    /// or "flake.nix".
    context_dir: Option<PathBuf>,

    /// Path to temporary file containing eval.nix.
    eval_nix: TempPath,

    /// Whether to pass --show-trace in Nix commands.
    show_trace: bool,

    /// The cached --builders expression.
    builders: RwLock<Option<Option<String>>>,
}

impl Hive {
    pub fn new(path: HivePath) -> NixResult<Self> {
        let mut eval_nix = NamedTempFile::new()?;
        eval_nix.write_all(HIVE_EVAL).unwrap();

        let context_dir = path.context_dir();

        Ok(Self {
            path,
            context_dir,
            eval_nix: eval_nix.into_temp_path(),
            show_trace: false,
            builders: RwLock::new(None),
        })
    }

    pub fn context_dir(&self) -> Option<&Path> {
        self.context_dir.as_ref().map(|p| p.as_ref())
    }

    pub fn set_show_trace(&mut self, value: bool) {
        self.show_trace = value;
    }

    pub async fn nix_options(&self) -> NixResult<Vec<String>> {
        let mut options = self.builder_args().await?;

        if self.show_trace {
            options.push("--show-trace".to_owned());
        }

        Ok(options)
    }

    /// Convenience wrapper to filter nodes for CLI actions.
    pub async fn select_nodes(&self, filter: Option<NodeFilter>, ssh_config: Option<PathBuf>, ssh_only: bool) -> NixResult<HashMap<NodeName, TargetNode>> {
        let mut node_configs = None;

        log::info!("Enumerating nodes...");

        let all_nodes = self.node_names().await?;
        let selected_nodes = match filter {
            Some(filter) => {
                if filter.has_node_config_rules() {
                    log::debug!("Retrieving deployment info for all nodes...");

                    let all_node_configs = self.deployment_info().await?;
                    let filtered = filter.filter_node_configs(all_node_configs.iter())
                        .into_iter().collect();

                    node_configs = Some(all_node_configs);

                    filtered
                } else {
                    filter.filter_node_names(&all_nodes)?
                        .into_iter().collect()
                }
            }
            None => all_nodes.clone(),
        };

        let n_selected = selected_nodes.len();

        let mut node_configs = if let Some(configs) = node_configs {
            configs
        } else {
            log::debug!("Retrieving deployment info for selected nodes...");
            self.deployment_info_selected(&selected_nodes).await?
        };

        let mut targets = HashMap::new();
        let mut n_ssh = 0;
        for node in selected_nodes.into_iter() {
            let config = node_configs.remove(&node).unwrap();

            let host = config.to_ssh_host().map(|mut host| {
                n_ssh += 1;

                if let Some(ssh_config) = &ssh_config {
                    host.set_ssh_config(ssh_config.clone());
                }
                host.upcast()
            });
            let ssh_host = host.is_some();
            let target = TargetNode::new(node.clone(), host, config);

            if !ssh_only || ssh_host {
                targets.insert(node, target);
            }
        }

        let skipped = n_selected - n_ssh;

        if targets.is_empty() {
            if skipped != 0 {
                log::warn!("No hosts selected.");
            } else {
                log::warn!("No hosts selected ({} skipped).", skipped);
            }
        } else if targets.len() == all_nodes.len() {
            log::info!("Selected all {} nodes.", targets.len());
        } else if !ssh_only || skipped == 0 {
            log::info!("Selected {} out of {} hosts.", targets.len(), all_nodes.len());
        } else {
            log::info!("Selected {} out of {} hosts ({} skipped).", targets.len(), all_nodes.len(), skipped);
        }

        Ok(targets)
    }

    /// Returns a list of all node names.
    pub async fn node_names(&self) -> NixResult<Vec<NodeName>> {
        self.nix_instantiate("attrNames hive.nodes").eval()
            .capture_json().await
    }

    /// Retrieve deployment info for all nodes.
    pub async fn deployment_info(&self) -> NixResult<HashMap<NodeName, NodeConfig>> {
        // FIXME: Really ugly :(
        let s: String = self.nix_instantiate("hive.deploymentConfigJson").eval_with_builders().await?
            .capture_json().await?;

        let configs: HashMap<NodeName, NodeConfig> = serde_json::from_str(&s).unwrap();
        for config in configs.values() {
            config.validate()?;
            for key in config.keys.values() {
                key.validate()?;
            }
        }
        Ok(configs)
    }

    /// Retrieve deployment info for a single node.
    pub async fn deployment_info_single(&self, node: &NodeName) -> NixResult<Option<NodeConfig>> {
        let expr = format!("toJSON (hive.nodes.\"{}\".config.deployment or null)", node.as_str());
        let s: String = self.nix_instantiate(&expr).eval_with_builders().await?
            .capture_json().await?;

        Ok(serde_json::from_str(&s).unwrap())
    }

    /// Retrieve deployment info for a list of nodes.
    pub async fn deployment_info_selected(&self, nodes: &[NodeName]) -> NixResult<HashMap<NodeName, NodeConfig>> {
        let nodes_expr = SerializedNixExpresssion::new(nodes)?;

        // FIXME: Really ugly :(
        let s: String = self.nix_instantiate(&format!("hive.deploymentConfigJsonSelected {}", nodes_expr.expression()))
            .eval_with_builders().await?
            .capture_json().await?;

        let configs: HashMap<NodeName, NodeConfig> = serde_json::from_str(&s).unwrap();
        for config in configs.values() {
            config.validate()?;
            for key in config.keys.values() {
                key.validate()?;
            }
        }

        Ok(configs)
    }

    /// Evaluates selected nodes.
    ///
    /// Evaluation may take up a lot of memory, so we make it possible
    /// to split up the evaluation process into chunks and run them
    /// concurrently with other processes (e.g., build and apply).
    pub async fn eval_selected(&self, nodes: &Vec<NodeName>, job: Option<JobHandle>) -> NixResult<StoreDerivation<ProfileMap>> {
        let nodes_expr = SerializedNixExpresssion::new(nodes)?;

        let expr = format!("hive.buildSelected {}", nodes_expr.expression());

        let command = self.nix_instantiate(&expr).instantiate_with_builders().await?;
        let mut execution = CommandExecution::new(command);
        execution.set_job(job);

        let path = execution.capture_store_path().await?;
        let drv = path.to_derivation()
            .expect("The result should be a store derivation");

        Ok(drv)
    }

    /// Evaluates an expression using values from the configuration
    pub async fn introspect(&self, expression: String, instantiate: bool) -> NixResult<String> {
        if instantiate {
            let expression = format!("hive.introspect ({})", expression);
            self.nix_instantiate(&expression).instantiate_with_builders().await?
                .capture_output().await
        } else {
            let expression = format!("toJSON (hive.introspect ({}))", expression);
            self.nix_instantiate(&expression).eval_with_builders().await?
                .capture_json().await
        }
    }

    /// Retrieve machinesFile setting for the hive.
    async fn machines_file(&self) -> NixResult<Option<String>> {
        if let Some(builders_opt) = &*self.builders.read().await {
            return Ok(builders_opt.clone());
        }

        let expr = "toJSON (hive.meta.machinesFile or null)";
        let s: String = self.nix_instantiate(&expr).eval()
            .capture_json().await?;

        let parsed: Option<String> = serde_json::from_str(&s).unwrap();
        self.builders.write().await.replace(parsed.clone());

        Ok(parsed)
    }

    /// Returns Nix arguments to set builders.
    async fn builder_args(&self) -> NixResult<Vec<String>> {
        let mut options = Vec::new();

        if let Some(machines_file) = self.machines_file().await? {
            options.append(&mut vec![
                "--option".to_owned(),
                "builders".to_owned(),
                format!("@{}", machines_file).to_owned()
            ]);
        }

        Ok(options)
    }

    fn nix_instantiate(&self, expression: &str) -> NixInstantiate {
        NixInstantiate::new(&self, expression.to_owned())
    }

    fn path(&self) -> &HivePath {
        &self.path
    }
}

struct NixInstantiate<'hive> {
    hive: &'hive Hive,
    expression: String,
}

impl<'hive> NixInstantiate<'hive> {
    fn new(hive: &'hive Hive, expression: String) -> Self {
        Self {
            hive,
            expression,
        }
    }

    fn instantiate(self) -> Command {
        // FIXME: unwrap
        // Technically filenames can be arbitrary byte strings (OsStr),
        // but Nix may not like it...

        let mut command = Command::new("nix-instantiate");

        match self.hive.path() {
            HivePath::Legacy(path) => {
                command
                    .arg("--no-gc-warning")
                    .arg("-E")
                    .arg(format!(
                        "with builtins; let eval = import {}; hive = eval {{ rawHive = import {}; }}; in {}",
                        self.hive.eval_nix.to_str().unwrap(),
                        path.to_str().unwrap(),
                        self.expression,
                    ));
            }
            HivePath::Flake(flake) => {
                command
                    .args(&["--experimental-features", "flakes"])
                    .arg("--no-gc-warning")
                    .arg("-E")
                    .arg(format!(
                        "with builtins; let eval = import {}; hive = eval {{ flakeUri = \"{}\"; }}; in {}",
                        self.hive.eval_nix.to_str().unwrap(),
                        flake.uri(),
                        self.expression,
                    ));
            }
        }

        if self.hive.show_trace {
            command.arg("--show-trace");
        }

        command
    }

    fn eval(self) -> Command {
        let mut command = self.instantiate();
        command.arg("--eval").arg("--json");
        command
    }

    async fn instantiate_with_builders(self) -> NixResult<Command> {
        let hive = self.hive;
        let mut command = self.instantiate();

        let builder_args = hive.builder_args().await?;
        command.args(&builder_args);

        Ok(command)
    }

    async fn eval_with_builders(self) -> NixResult<Command> {
        let hive = self.hive;
        let mut command = self.eval();

        let builder_args = hive.builder_args().await?;
        command.args(&builder_args);

        Ok(command)
    }
}

/// A serialized Nix expression.
///
/// Very hacky and involves an Import From Derivation, so should be
/// avoided as much as possible. But I suppose it's more robust than attempting
/// to generate Nix expressions directly or escaping a JSON string to strip
/// off Nix interpolation.
struct SerializedNixExpresssion {
    json_file: TempPath, 
}

impl SerializedNixExpresssion {
    pub fn new<'de, T>(data: T) -> NixResult<Self> where T: Serialize {
        let mut tmp = NamedTempFile::new()?;
        let json = serde_json::to_vec(&data).expect("Could not serialize data");
        tmp.write_all(&json)?;

        Ok(Self {
            json_file: tmp.into_temp_path(),
        })
    }

    pub fn expression(&self) -> String {
        format!("(builtins.fromJSON (builtins.readFile {}))", self.json_file.to_str().unwrap())
    }
}
