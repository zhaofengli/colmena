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

const HIVE_EVAL: &'static [u8] = include_bytes!("eval.nix");

#[derive(Debug)]
pub struct Hive {
    hive: PathBuf,
    eval_nix: TempPath,
    show_trace: bool,
}

impl Hive {
    pub fn new<P: AsRef<Path>>(hive: P) -> NixResult<Self> {
        let mut eval_nix = NamedTempFile::new()?;
        eval_nix.write_all(HIVE_EVAL).unwrap();

        Ok(Self {
            hive: hive.as_ref().to_owned(),
            eval_nix: eval_nix.into_temp_path(),
            show_trace: false,
        })
    }

    pub fn show_trace(&mut self, value: bool) {
        self.show_trace = value;
    }

    pub fn as_path(&self) -> &Path {
        &self.hive
    }

    /// Retrieve deployment info for all nodes.
    pub async fn deployment_info(&self) -> NixResult<HashMap<String, NodeConfig>> {
        // FIXME: Really ugly :(
        let s: String = self.nix_instantiate("hive.deploymentConfigJson").eval()
            .capture_json().await?;

        let configs: HashMap<String, NodeConfig> = serde_json::from_str(&s).unwrap();
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
        let expr = format!("toJSON (hive.nodes.\"{}\".config.deployment or null)", node);
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

        let expr = format!("hive.buildSelected {{ names = {}; }}", nodes_expr.expression());

        let command = self.nix_instantiate(&expr).instantiate();
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
        let expression = format!("toJSON (hive.introspect ({}))", expression);
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

    fn instantiate(self) -> Command {
        // FIXME: unwrap
        // Technically filenames can be arbitrary byte strings (OsStr),
        // but Nix may not like it...

        let mut command = Command::new("nix-instantiate");
        command
            .arg("--no-gc-warning")
            .arg("-E")
            .arg(format!(
                "with builtins; let eval = import {}; hive = eval {{ rawHive = import {}; }}; in {}",
                self.hive.eval_nix.to_str().unwrap(),
                self.hive.as_path().to_str().unwrap(),
                self.expression,
            ));

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
