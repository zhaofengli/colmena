use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::{NamedTempFile, TempPath};
use tokio::process::Command;
use serde::Serialize;
use validator::Validate;

use super::{
    StoreDerivation,
    NixResult,
    NodeConfig,
    ProfileMap,
};
use super::NixCommand;
use crate::util::CommandExecution;
use crate::progress::TaskProgress;

// Manual evaluator. This is not used for flakes.
const HIVE_EVAL: &'static [u8] = include_bytes!("eval.nix");
const HIVE_MODULES: &'static [u8] = include_bytes!("modules.nix");

#[derive(Debug, Clone)]
pub struct HivePath {
    // File path if we're using hive.nix,
    // or a qualified flake path for flakes
    pub file: Option<PathBuf>,
    pub flake: Option<String>,
}

#[derive(Debug)]
pub struct Hive {
    pub path: HivePath,
    eval_nix: TempPath,
    mod_nix: TempPath,
    show_trace: bool,

    // Extra arguments to be passed to `nix eval`
    extra_args: Vec<String>
}

impl HivePath {
    pub fn from_file(path: &Path) -> Self {
        Self { file: Some(path.to_path_buf()), flake: None }
    }

    pub fn from_flake(path: String) -> Self {
        Self { file: None, flake: Some(path) }
    }

    pub fn is_flake(&self) -> bool {
        self.flake.is_some()
    }
}

impl Hive {
    pub fn new(path: HivePath, extra_args: Vec<String>) -> NixResult<Self> {
        // I hate this, but it's just what we have to do for now...
        let mut eval_nix = NamedTempFile::new()?;
        eval_nix.write_all(HIVE_EVAL).unwrap();

        let mut mod_nix = NamedTempFile::new()?;
        mod_nix.write_all(HIVE_MODULES).unwrap();

        Ok(Self {
            path: path,
            eval_nix: eval_nix.into_temp_path(),
            mod_nix: mod_nix.into_temp_path(),
            show_trace: false,
            extra_args: extra_args
        })
    }

    pub fn show_trace(&mut self, value: bool) {
        self.show_trace = value;
    }

    /// Retrieve deployment info for all nodes.
    pub async fn deployment_info(&self) -> NixResult<HashMap<String, NodeConfig>> {
        let configs: HashMap<String, NodeConfig> = self.nix_instantiate("hive.deploymentConfig").eval()
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
    pub async fn deployment_info_for(&self, node: &str) -> NixResult<Option<NodeConfig>> {
        let expr = format!("builtins.toJSON (hive.nodes.\"{}\".config.deployment or null)", node);
        let s: String = self.nix_instantiate(&expr).eval()
            .capture_json().await?;

        Ok(serde_json::from_str(&s).unwrap())
    }

    /// Evaluates selected nodes.
    ///
    /// Evaluation may take up a lot of memory, so we make it possible
    /// to split up the evaluation process into chunks and run them
    /// concurrently with other processes (e.g., build and apply).
    pub async fn eval_selected(&self, nodes: &Vec<String>, progress_bar: TaskProgress) -> (NixResult<StoreDerivation<ProfileMap>>, Option<String>) {
        // FIXME: The return type is ugly...

        let nodes_expr = SerializedNixExpresssion::new(nodes);
        if let Err(e) = nodes_expr {
            return (Err(e), None);
        }
        let nodes_expr = nodes_expr.unwrap();

        // we need to grab the drvPath output if we're building a flake
        let path_suffix = if self.path.is_flake() {
            ".drvPath"
        } else {
            ""
        };

        let expr = format!("(hive.buildSelected {{ names = {}; }}){}", nodes_expr.expression(), path_suffix);

        let command = self.nix_instantiate(&expr).instantiate(false);
        let mut execution = CommandExecution::new(command);
        execution.set_progress_bar(progress_bar);

        let eval = execution
            .capture_store_path().await;

        let (_, stderr) = execution.get_logs();

        match eval {
            Ok(path) => {
                let drv = path.to_derivation()
                    .expect("The result should be a store derivation");

                (Ok(drv), stderr.cloned())
            }
            Err(e) => {
                (Err(e), stderr.cloned())
            }
        }
    }

    /// Evaluates an expression using values from the configuration
    pub async fn introspect(&self, expression: String) -> NixResult<String> {
        let expression = format!("builtins.toJSON (hive.introspect ({}))", expression);
        self.nix_instantiate(&expression).eval()
            .capture_json().await
    }

    fn nix_instantiate(&self, expression: &str) -> NixInstantiate {
        NixInstantiate::new(&self, expression.to_owned())
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

    fn instantiate(self, for_eval: bool) -> Command {
        // FIXME: unwrap
        // Technically filenames can be arbitrary byte strings (OsStr),
        // but Nix may not like it...

        let hive_path = self.hive.path.clone();
        let mut command = if hive_path.is_flake() {
            Command::new("nix")
        } else {
            Command::new("nix-instantiate")
        };

        if self.hive.path.is_flake() {
            command
                .arg("eval")
                .arg(format!(
                    "{}#colmena",
                    hive_path.flake.unwrap()
                ))
                .arg("--impure") // HACK: required for IFD
                .arg("--apply")
                .arg(format!(
                    "(hive: {})",
                    self.expression
                ));

                if !for_eval {
                    // so we don't output quoted JSON
                    command.arg("--raw");
                }
        } else {
            command
                .arg("--no-gc-warning")
                .arg("-E")
                .arg(format!(
                    "with builtins; let eval = import {}; hive = eval {{ sharedModules = {}; rawHive = import {}; }}; in {}",
                    self.hive.eval_nix.to_str().unwrap(),
                    self.hive.mod_nix.to_str().unwrap(),
                    hive_path.file.unwrap().to_str().unwrap(),
                    self.expression,
                ));
        };

        if self.hive.show_trace {
            command.arg("--show-trace");
        }

        for extra_arg in &self.hive.extra_args {
            command.arg(extra_arg);
        }

        command
    }

    fn eval(self) -> Command {
        let hive_path = self.hive.path.clone();
        let mut command = self.instantiate(true);

        if !hive_path.is_flake() {
            command.arg("--eval");
        }

        command.arg("--json");
        command
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
