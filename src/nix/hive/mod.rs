mod assets;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::convert::AsRef;
use std::path::{Path, PathBuf};

use tokio::process::Command;
use tokio::sync::OnceCell;
use validator::Validate;

use super::deployment::TargetNode;
use super::{
    Flake, MetaConfig, NixExpression, NixOptions, NodeConfig, NodeFilter, NodeName,
    ProfileDerivation, SerializedNixExpression, StorePath,
};
use crate::error::ColmenaResult;
use crate::job::JobHandle;
use crate::util::{CommandExecution, CommandExt};
use assets::Assets;

#[derive(Debug, Clone)]
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

    /// Static files required to evaluate a Hive configuration.
    assets: Assets,

    /// Whether to pass --show-trace in Nix commands.
    show_trace: bool,

    /// Whether to pass --impure in Nix commands.
    impure: bool,

    meta_config: OnceCell<MetaConfig>,
}

struct NixInstantiate<'hive> {
    hive: &'hive Hive,
    expression: String,
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

        Ok(Self::Legacy(path.canonicalize()?))
    }

    fn is_flake(&self) -> bool {
        matches!(self, Self::Flake(_))
    }

    fn context_dir(&self) -> Option<PathBuf> {
        match self {
            Self::Legacy(p) => p.parent().map(|d| d.to_owned()),
            Self::Flake(flake) => flake.local_dir().map(|d| d.to_owned()),
        }
    }
}

impl Hive {
    pub async fn new(path: HivePath) -> ColmenaResult<Self> {
        let context_dir = path.context_dir();
        let assets = Assets::new(path.clone()).await?;

        Ok(Self {
            path,
            context_dir,
            assets,
            show_trace: false,
            impure: false,
            meta_config: OnceCell::new(),
        })
    }

    pub fn context_dir(&self) -> Option<&Path> {
        self.context_dir.as_ref().map(|p| p.as_ref())
    }

    pub async fn get_meta_config(&self) -> ColmenaResult<&MetaConfig> {
        self.meta_config
            .get_or_try_init(|| async {
                self.nix_instantiate("hive.metaConfig")
                    .eval()
                    .capture_json()
                    .await
            })
            .await
    }

    pub fn set_show_trace(&mut self, value: bool) {
        self.show_trace = value;
    }

    pub fn set_impure(&mut self, impure: bool) {
        self.impure = impure;
    }

    /// Returns Nix options to set for this Hive.
    pub fn nix_options(&self) -> NixOptions {
        let mut options = NixOptions::default();
        options.set_show_trace(self.show_trace);
        options.set_pure_eval(self.path.is_flake());
        options.set_impure(self.impure);
        options
    }

    /// Returns Nix options to set for this Hive, with configured remote builders.
    pub async fn nix_options_with_builders(&self) -> ColmenaResult<NixOptions> {
        let mut options = NixOptions::default();
        options.set_show_trace(self.show_trace);

        if let Some(machines_file) = &self.get_meta_config().await?.machines_file {
            options.set_builders(Some(format!("@{}", machines_file)));
        }

        Ok(options)
    }

    /// Convenience wrapper to filter nodes for CLI actions.
    pub async fn select_nodes(
        &self,
        filter: Option<NodeFilter>,
        ssh_config: Option<PathBuf>,
        ssh_only: bool,
    ) -> ColmenaResult<HashMap<NodeName, TargetNode>> {
        let mut node_configs = None;

        log::info!("Enumerating nodes...");

        let all_nodes = self.node_names().await?;
        let selected_nodes = match filter {
            Some(filter) => {
                if filter.has_node_config_rules() {
                    log::debug!("Retrieving deployment info for all nodes...");

                    let all_node_configs = self.deployment_info().await?;
                    let filtered = filter
                        .filter_node_configs(all_node_configs.iter())
                        .into_iter()
                        .collect();

                    node_configs = Some(all_node_configs);

                    filtered
                } else {
                    filter.filter_node_names(&all_nodes)?.into_iter().collect()
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
            log::info!(
                "Selected {} out of {} hosts.",
                targets.len(),
                all_nodes.len()
            );
        } else {
            log::info!(
                "Selected {} out of {} hosts ({} skipped).",
                targets.len(),
                all_nodes.len(),
                skipped
            );
        }

        Ok(targets)
    }

    /// Returns a list of all node names.
    pub async fn node_names(&self) -> ColmenaResult<Vec<NodeName>> {
        self.nix_instantiate("attrNames hive.nodes")
            .eval()
            .capture_json()
            .await
    }

    /// Retrieve deployment info for all nodes.
    pub async fn deployment_info(&self) -> ColmenaResult<HashMap<NodeName, NodeConfig>> {
        let configs: HashMap<NodeName, NodeConfig> = self
            .nix_instantiate("hive.deploymentConfig")
            .eval_with_builders()
            .await?
            .capture_json()
            .await?;

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
    pub async fn deployment_info_single(
        &self,
        node: &NodeName,
    ) -> ColmenaResult<Option<NodeConfig>> {
        let expr = format!("hive.nodes.\"{}\".config.deployment or null", node.as_str());
        self.nix_instantiate(&expr)
            .eval_with_builders()
            .await?
            .capture_json()
            .await
    }

    /// Retrieve deployment info for a list of nodes.
    pub async fn deployment_info_selected(
        &self,
        nodes: &[NodeName],
    ) -> ColmenaResult<HashMap<NodeName, NodeConfig>> {
        let nodes_expr = SerializedNixExpression::new(nodes);

        let configs: HashMap<NodeName, NodeConfig> = self
            .nix_instantiate(&format!(
                "hive.deploymentConfigSelected {}",
                nodes_expr.expression()
            ))
            .eval_with_builders()
            .await?
            .capture_json()
            .await?;

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
    pub async fn eval_selected(
        &self,
        nodes: &[NodeName],
        job: Option<JobHandle>,
    ) -> ColmenaResult<HashMap<NodeName, ProfileDerivation>> {
        let nodes_expr = SerializedNixExpression::new(nodes);

        let expr = format!("hive.evalSelectedDrvPaths {}", nodes_expr.expression());

        let command = self.nix_instantiate(&expr).eval_with_builders().await?;
        let mut execution = CommandExecution::new(command);
        execution.set_job(job);
        execution.set_hide_stdout(true);

        execution
            .capture_json::<HashMap<NodeName, StorePath>>()
            .await?
            .into_iter()
            .map(|(name, path)| {
                let path = path.into_derivation()?;
                Ok((name, path))
            })
            .collect()
    }

    /// Returns the expression to evaluate selected nodes.
    pub fn eval_selected_expr(&self, nodes: &[NodeName]) -> ColmenaResult<impl NixExpression + '_> {
        let nodes_expr = SerializedNixExpression::new(nodes);

        Ok(EvalSelectedExpression {
            hive: self,
            nodes_expr,
        })
    }

    /// Evaluates an expression using values from the configuration.
    pub async fn introspect(&self, expression: String, instantiate: bool) -> ColmenaResult<String> {
        if instantiate {
            let expression = format!("hive.introspect ({})", expression);
            self.nix_instantiate(&expression)
                .instantiate_with_builders()
                .await?
                .capture_output()
                .await
        } else {
            let expression = format!("toJSON (hive.introspect ({}))", expression);
            self.nix_instantiate(&expression)
                .eval_with_builders()
                .await?
                .capture_json()
                .await
        }
    }

    /// Returns the base expression from which the evaluated Hive can be used.
    fn get_base_expression(&self) -> String {
        self.assets.get_base_expression()
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
        Self { hive, expression }
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
        command
            .arg("--eval")
            .arg("--json")
            .arg("--strict")
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
