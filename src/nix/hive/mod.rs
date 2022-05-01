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
    NixOptions,
    NodeName,
    NodeConfig,
    NodeFilter,
    NixExpression,
    ProfileDerivation,
    StorePath,
};
use super::deployment::TargetNode;
use crate::error::ColmenaResult;
use crate::util::{CommandExecution, CommandExt};
use crate::job::JobHandle;

#[cfg(test)]
mod tests;

const HIVE_EVAL: &[u8] = include_bytes!("eval.nix");
const HIVE_OPTIONS: &[u8] = include_bytes!("options.nix");
const HIVE_MODULES: &[u8] = include_bytes!("modules.nix");

#[derive(Debug)]
pub enum HivePath {
    /// A Nix Flake.
    ///
    /// The flake must contain the `colmena` output.
    Flake(Flake),

    /// A regular .nix file
    Legacy(PathBuf),
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

    /// Path to temporary file containing options.nix.
    options_nix: TempPath,

    /// Path to temporary file containing modules.nix.
    modules_nix: TempPath,

    /// Whether to pass --show-trace in Nix commands.
    show_trace: bool,

    /// The cached machines_file expression.
    machines_file: RwLock<Option<Option<String>>>,
}

struct NixInstantiate<'hive> {
    hive: &'hive Hive,
    expression: String,
}

/// A serialized Nix expression.
///
/// Very hacky so should be avoided as much as possible. But I suppose it's
/// more robust than attempting to generate Nix expressions directly or
/// escaping a JSON string to strip off Nix interpolation.
struct SerializedNixExpression {
    json_file: TempPath,
}

/// An expression to evaluate the system profiles of selected nodes.
struct EvalSelectedExpression<'hive> {
    hive: &'hive Hive,
    nodes_expr: SerializedNixExpression,
}

impl HivePath {
    pub async fn from_path<P: AsRef<Path>>(path: P) -> ColmenaResult<Self> {
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

impl Hive {
    pub fn new(path: HivePath) -> ColmenaResult<Self> {
        let mut eval_nix = NamedTempFile::new()?;
        let mut options_nix = NamedTempFile::new()?;
        let mut modules_nix = NamedTempFile::new()?;
        eval_nix.write_all(HIVE_EVAL).unwrap();
        options_nix.write_all(HIVE_OPTIONS).unwrap();
        modules_nix.write_all(HIVE_MODULES).unwrap();

        let context_dir = path.context_dir();

        Ok(Self {
            path,
            context_dir,
            eval_nix: eval_nix.into_temp_path(),
            options_nix: options_nix.into_temp_path(),
            modules_nix: modules_nix.into_temp_path(),
            show_trace: false,
            machines_file: RwLock::new(None),
        })
    }

    pub fn context_dir(&self) -> Option<&Path> {
        self.context_dir.as_ref().map(|p| p.as_ref())
    }

    pub fn set_show_trace(&mut self, value: bool) {
        self.show_trace = value;
    }

    /// Returns Nix options to set for this Hive.
    pub fn nix_options(&self) -> NixOptions {
        let mut options = NixOptions::default();
        options.set_show_trace(self.show_trace);
        options
    }

    /// Returns Nix options to set for this Hive, with configured remote builders.
    pub async fn nix_options_with_builders(&self) -> ColmenaResult<NixOptions> {
        let mut options = NixOptions::default();
        options.set_show_trace(self.show_trace);

        if let Some(machines_file) = self.machines_file().await? {
            options.set_builders(Some(format!("@{}", machines_file)));
        }

        Ok(options)
    }

    /// Convenience wrapper to filter nodes for CLI actions.
    pub async fn select_nodes(&self, filter: Option<NodeFilter>, ssh_config: Option<PathBuf>, ssh_only: bool) -> ColmenaResult<HashMap<NodeName, TargetNode>> {
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
    pub async fn node_names(&self) -> ColmenaResult<Vec<NodeName>> {
        self.nix_instantiate("attrNames hive.nodes").eval()
            .capture_json().await
    }

    /// Retrieve deployment info for all nodes.
    pub async fn deployment_info(&self) -> ColmenaResult<HashMap<NodeName, NodeConfig>> {
        let configs: HashMap<NodeName, NodeConfig> = self.nix_instantiate("hive.deploymentConfig").eval_with_builders().await?
            .capture_json().await?;

        for config in configs.values() {
            config.validate()?;
            for key in config.keys.values() {
                key.validate()?;
            }
        }
        Ok(configs)
    }

    /// Retrieve deployment info for a single node.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub async fn deployment_info_single(&self, node: &NodeName) -> ColmenaResult<Option<NodeConfig>> {
        let expr = format!("hive.nodes.\"{}\".config.deployment or null", node.as_str());
        self.nix_instantiate(&expr).eval_with_builders().await?
            .capture_json().await
    }

    /// Retrieve deployment info for a list of nodes.
    pub async fn deployment_info_selected(&self, nodes: &[NodeName]) -> ColmenaResult<HashMap<NodeName, NodeConfig>> {
        let nodes_expr = SerializedNixExpression::new(nodes)?;

        let configs: HashMap<NodeName, NodeConfig> = self.nix_instantiate(&format!("hive.deploymentConfigSelected {}", nodes_expr.expression()))
            .eval_with_builders().await?
            .capture_json().await?;

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
    pub async fn eval_selected(&self, nodes: &[NodeName], job: Option<JobHandle>) -> ColmenaResult<HashMap<NodeName, ProfileDerivation>> {
        let nodes_expr = SerializedNixExpression::new(nodes)?;

        let expr = format!("hive.evalSelectedDrvPaths {}", nodes_expr.expression());

        let command = self.nix_instantiate(&expr)
            .eval_with_builders().await?;
        let mut execution = CommandExecution::new(command);
        execution.set_job(job);
        execution.set_hide_stdout(true);

        execution
            .capture_json::<HashMap<NodeName, StorePath>>().await?
            .into_iter().map(|(name, path)| {
                let path = path.into_derivation()?;
                Ok((name, path))
            })
            .collect()
    }

    /// Returns the expression to evaluate selected nodes.
    pub fn eval_selected_expr(&self, nodes: &[NodeName]) -> ColmenaResult<impl NixExpression + '_> {
        let nodes_expr = SerializedNixExpression::new(nodes)?;

        Ok(EvalSelectedExpression {
            hive: self,
            nodes_expr,
        })
    }

    /// Evaluates an expression using values from the configuration.
    pub async fn introspect(&self, expression: String, instantiate: bool) -> ColmenaResult<String> {
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

    /// Retrieve the machinesFile setting for the Hive.
    async fn machines_file(&self) -> ColmenaResult<Option<String>> {
        if let Some(machines_file) = &*self.machines_file.read().await {
            return Ok(machines_file.clone());
        }

        let expr = "toJSON (hive.meta.machinesFile or null)";
        let s: String = self.nix_instantiate(expr).eval()
            .capture_json().await?;

        let parsed: Option<String> = serde_json::from_str(&s).unwrap();
        self.machines_file.write().await.replace(parsed.clone());

        Ok(parsed)
    }

    /// Returns the base expression from which the evaluated Hive can be used.
    fn get_base_expression(&self) -> String {
        match self.path() {
            HivePath::Legacy(path) => {
                format!(
                    "with builtins; let eval = import {}; hive = eval {{ rawHive = import {}; colmenaOptions = import {}; colmenaModules = import {}; }}; in ",
                    self.eval_nix.to_str().unwrap(),
                    path.to_str().unwrap(),
                    self.options_nix.to_str().unwrap(),
                    self.modules_nix.to_str().unwrap(),
                )
            }
            HivePath::Flake(flake) => {
                format!(
                    "with builtins; let eval = import {}; hive = eval {{ flakeUri = \"{}\"; colmenaOptions = import {}; colmenaModules = import {}; }}; in ",
                    self.eval_nix.to_str().unwrap(),
                    flake.uri(),
                    self.options_nix.to_str().unwrap(),
                    self.modules_nix.to_str().unwrap(),
                )
            }
        }
    }

    /// Returns whether this Hive is a flake.
    fn is_flake(&self) -> bool {
        matches!(self.path(), HivePath::Flake(_))
    }

    fn nix_instantiate(&self, expression: &str) -> NixInstantiate {
        NixInstantiate::new(self, expression.to_owned())
    }

    fn path(&self) -> &HivePath {
        &self.path
    }
}

impl<'hive> NixInstantiate<'hive> {
    fn new(hive: &'hive Hive, expression: String) -> Self {
        Self {
            hive,
            expression,
        }
    }

    fn instantiate(&self) -> Command {
        let mut command = Command::new("nix-instantiate");

        if self.hive.is_flake() {
            command.args(&["--experimental-features", "flakes"]);
        }

        let mut full_expression = self.hive.get_base_expression();
        full_expression += &self.expression;

        command
            .arg("--no-gc-warning")
            .arg("-E")
            .arg(&full_expression);

        command
    }

    fn eval(self) -> Command {
        let mut command = self.instantiate();
        let options = self.hive.nix_options();
        command.arg("--eval").arg("--json").arg("--strict")
            // Ensures the derivations are instantiated
            // Required for system profile evaluation and IFD
            .arg("--read-write-mode")
            .args(options.to_args());
        command
    }

    async fn instantiate_with_builders(self) -> ColmenaResult<Command> {
        let options = self.hive.nix_options_with_builders().await?;
        let mut command = self.instantiate();

        command.args(options.to_args());

        Ok(command)
    }

    async fn eval_with_builders(self) -> ColmenaResult<Command> {
        let options = self.hive.nix_options_with_builders().await?;
        let mut command = self.eval();

        command.args(options.to_args());

        Ok(command)
    }
}

impl SerializedNixExpression {
    pub fn new<T>(data: T) -> ColmenaResult<Self> where T: Serialize {
        let mut tmp = NamedTempFile::new()?;
        let json = serde_json::to_vec(&data).expect("Could not serialize data");
        tmp.write_all(&json)?;

        Ok(Self {
            json_file: tmp.into_temp_path(),
        })
    }
}

impl NixExpression for SerializedNixExpression {
    fn expression(&self) -> String {
        format!("(builtins.fromJSON (builtins.readFile {}))", self.json_file.to_str().unwrap())
    }
}

impl<'hive> NixExpression for EvalSelectedExpression<'hive> {
    fn expression(&self) -> String {
        format!(
            "{} hive.evalSelected {}",
            self.hive.get_base_expression(),
            self.nodes_expr.expression(),
        )
    }

    fn requires_flakes(&self) -> bool {
        self.hive.is_flake()
    }
}
