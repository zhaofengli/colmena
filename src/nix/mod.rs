use std::path::{Path, PathBuf};
use std::convert::AsRef;
use std::io::Write;
use std::process::Stdio;
use std::collections::HashMap;
use std::fs;

use async_trait::async_trait;
use clap::ArgMatches;
use indicatif::ProgressBar;
use serde::de::DeserializeOwned;
use serde::{Serialize, Deserialize};
use snafu::Snafu;
use tempfile::{NamedTempFile, TempPath};
use tokio::process::Command;
use tokio::sync::Mutex;

mod host;
pub use host::{Host, CopyDirection};
use host::SSH;

const HIVE_EVAL: &'static [u8] = include_bytes!("eval.nix");

pub type NixResult<T> = Result<T, NixError>;

#[derive(Debug, Snafu)]
pub enum NixError {
    #[snafu(display("I/O Error: {}", error))]
    IoError { error: std::io::Error },

    #[snafu(display("Nix returned invalid response: {}", output))]
    BadOutput { output: String },

    #[snafu(display("Nix exited with error code: {}", exit_code))]
    NixFailure { exit_code: i32 },

    #[snafu(display("Nix was interrupted"))]
    NixKilled,

    #[snafu(display("This operation is not supported"))]
    Unsupported,

    #[snafu(display("Nix Error: {}", message))]
    Unknown { message: String },
}

impl From<std::io::Error> for NixError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError { error }
    }
}

pub struct Hive {
    hive: PathBuf,
    eval_nix: TempPath,
    builder: Box<dyn Host>,
}

impl Hive {
    pub fn new<P: AsRef<Path>>(hive: P) -> NixResult<Self> {
        let mut eval_nix = NamedTempFile::new()?;
        eval_nix.write_all(HIVE_EVAL)?;

        Ok(Self {
            hive: hive.as_ref().to_owned(),
            eval_nix: eval_nix.into_temp_path(),
            builder: host::local(),
        })
    }

    pub fn from_config_arg(args: &ArgMatches<'_>) -> NixResult<Self> {
        let path = args.value_of("config").expect("The config arg should exist").to_owned();
        let path = canonicalize_path(path);

        Self::new(path)
    }

    /// Retrieve deployment info for all nodes
    pub async fn deployment_info(&self) -> NixResult<HashMap<String, DeploymentConfig>> {
        // FIXME: Really ugly :(
        let s: String = self.nix_instantiate("hive.deploymentConfigJson").eval()
            .capture_json().await?;

        Ok(serde_json::from_str(&s).unwrap())
    }

    /// Builds selected nodes
    pub async fn build_selected(&mut self, nodes: Vec<String>) -> NixResult<HashMap<String, StorePath>> {
        let nodes_expr = SerializedNixExpresssion::new(&nodes)?;
        let expr = format!("hive.buildSelected {{ names = {}; }}", nodes_expr.expression());

        self.build_common(&expr).await
    }

    #[allow(dead_code)]
    /// Builds all node configurations
    pub async fn build_all(&mut self) -> NixResult<HashMap<String, StorePath>> {
        self.build_common("hive.buildAll").await
    }

    /// Evaluates an expression using values from the configuration
    pub async fn introspect(&mut self, expression: String) -> NixResult<String> {
        let expression = format!("toJSON (hive.introspect ({}))", expression);
        self.nix_instantiate(&expression).eval()
            .capture_json().await
    }

    /// Builds node configurations
    ///
    /// Expects the resulting store path to point to a JSON file containing
    /// a map of node name -> store path.
    async fn build_common(&mut self, expression: &str) -> NixResult<HashMap<String, StorePath>> {
        let build: StorePath = self.nix_instantiate(expression).instantiate()
            .capture_store_path().await?;

        let realization = self.builder.realize(&build).await?;
        assert!(realization.len() == 1);

        let json = fs::read_to_string(&realization[0].as_path())?;
        let result_map = serde_json::from_str(&json)
            .expect("Bad result from our own build routine");

        Ok(result_map)
    }

    fn nix_instantiate(&self, expression: &str) -> NixInstantiate {
        NixInstantiate::new(&self.eval_nix, &self.hive, expression.to_owned())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentConfig {
    #[serde(rename = "targetHost")]
    target_host: String,

    #[serde(rename = "targetUser")]
    target_user: String,
    tags: Vec<String>,
}

impl DeploymentConfig {
    pub fn tags(&self) -> &[String] { &self.tags }
    pub fn to_host(&self) -> Box<dyn Host> {
        let host = SSH::new(self.target_user.clone(), self.target_host.clone());
        Box::new(host)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum DeploymentGoal {
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

impl DeploymentGoal {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "push" => Some(Self::Push),
            "switch" => Some(Self::Switch),
            "boot" => Some(Self::Boot),
            "test" => Some(Self::Test),
            "dry-activate" => Some(Self::DryActivate),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'static str> {
        use DeploymentGoal::*;
        match self {
            Push => None,
            Switch => Some("switch"),
            Boot => Some("boot"),
            Test => Some("test"),
            DryActivate => Some("dry-activate"),
        }
    }

    pub fn success_str(&self) -> Option<&'static str> {
        use DeploymentGoal::*;
        match self {
            Push => Some("Pushed"),
            Switch => Some("Activation successful"),
            Boot => Some("Will be activated next boot"),
            Test => Some("Activation successful (test)"),
            DryActivate => Some("Dry activation successful"),
        }
    }
}

struct NixInstantiate<'hive> {
    eval_nix: &'hive Path,
    hive: &'hive Path,
    expression: String,
}

impl<'hive> NixInstantiate<'hive> {
    fn new(eval_nix: &'hive Path, hive: &'hive Path, expression: String) -> Self {
        Self {
            eval_nix,
            expression,
            hive,
        }
    }

    fn instantiate(self) -> Command {
        // FIXME: unwrap
        // Technically filenames can be arbitrary byte strings (OsStr),
        // but Nix may not like it...

        let mut command = Command::new("nix-instantiate");
        command
            .arg("-E")
            .arg(format!(
                "with builtins; let eval = import {}; hive = eval {{ rawHive = import {}; }}; in {}",
                self.eval_nix.to_str().unwrap(),
                self.hive.to_str().unwrap(),
                self.expression,
            ));
        command
    }

    fn eval(self) -> Command {
        let mut command = self.instantiate();
        command.arg("--eval").arg("--json");
        command
    }
}

#[async_trait]
trait NixCommand {
    async fn passthrough(&mut self) -> NixResult<()>;
    async fn capture_output(&mut self) -> NixResult<String>;
    async fn capture_json<T>(&mut self) -> NixResult<T> where T: DeserializeOwned;
    async fn capture_store_path(&mut self) -> NixResult<StorePath>;
}

#[async_trait]
impl NixCommand for Command {
    /// Runs the command with stdout and stderr passed through to the user.
    async fn passthrough(&mut self) -> NixResult<()> {
        let exit = self
            .spawn()?
            .wait()
            .await?;

        if exit.success() {
            Ok(())
        } else {
            Err(match exit.code() {
                Some(exit_code) => NixError::NixFailure { exit_code },
                None => NixError::NixKilled,
            })
        }
    }

    /// Captures output as a String.
    async fn capture_output(&mut self) -> NixResult<String> {
        // We want the user to see the raw errors
        let output = self
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?
            .wait_with_output()
            .await?;

        if output.status.success() {
            // FIXME: unwrap
            Ok(String::from_utf8(output.stdout).unwrap())
        } else {
            Err(match output.status.code() {
                Some(exit_code) => NixError::NixFailure { exit_code },
                None => NixError::NixKilled,
            })
        }
    }

    /// Captures deserialized output from JSON.
    async fn capture_json<T>(&mut self) -> NixResult<T> where T: DeserializeOwned {
        let output = self.capture_output().await?;
        serde_json::from_str(&output).map_err(|_| NixError::BadOutput {
            output: output.clone()
        })
    }

    /// Captures a single store path.
    async fn capture_store_path(&mut self) -> NixResult<StorePath> {
        let output = self.capture_output().await?;
        Ok(StorePath(output.trim_end().into()))
    }
}

/// A Nix store path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorePath(PathBuf);

impl StorePath {
    /// Returns the store path
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl From<String> for StorePath {
    fn from(s: String) -> Self {
        Self(s.into())
    }
}

impl Into<PathBuf> for StorePath {
    fn into(self) -> PathBuf {
        self.0
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

#[derive(Debug)]
pub struct DeploymentTask {
    /// Name of the target.
    name: String,

    /// The target to deploy to.
    target: Mutex<Box<dyn Host>>,

    /// Nix store path to the system profile to deploy.
    profile: StorePath,

    /// The goal of this deployment.
    goal: DeploymentGoal,
}

impl DeploymentTask {
    pub fn new(name: String, target: Box<dyn Host>, profile: StorePath, goal: DeploymentGoal) -> Self {
        Self {
            name,
            target: Mutex::new(target),
            profile,
            goal,
        }
    }

    pub fn name(&self) -> &str { &self.name }
    pub fn goal(&self) -> DeploymentGoal { self.goal }

    /// Set the progress bar used during deployment.
    pub async fn set_progress_bar(&mut self, progress: ProgressBar) {
        let mut target = self.target.lock().await;
        target.set_progress_bar(progress);
    }

    /// Executes the deployment.
    pub async fn execute(&mut self) -> NixResult<()> {
        match self.goal {
            DeploymentGoal::Push => {
                self.push().await
            }
            _ => {
                self.push_and_activate().await
            }
        }
    }

    /// Takes the Host out, consuming the DeploymentTask.
    pub async fn to_host(self) -> Box<dyn Host> {
        self.target.into_inner()
    }

    async fn push(&mut self) -> NixResult<()> {
        let mut target = self.target.lock().await;
        target.copy_closure(&self.profile, CopyDirection::ToRemote, true).await
    }

    async fn push_and_activate(&mut self) -> NixResult<()> {
        self.push().await?;
        {
            let mut target = self.target.lock().await;
            target.activate(&self.profile, self.goal).await
        }
    }
}

fn canonicalize_path(path: String) -> PathBuf {
    if !path.starts_with("/") {
        format!("./{}", path).into()
    } else {
        path.into()
    }
}

