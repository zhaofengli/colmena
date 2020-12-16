//! A Colmena Hive.

use std::path::{Path, PathBuf};
use std::convert::AsRef;
use std::io::Write;
use std::process::{ExitStatus, Stdio};
use std::collections::HashMap;
use std::fs;
use std::fmt;

use console::style;
use async_trait::async_trait;
use clap::ArgMatches;
use indicatif::{ProgressBar, ProgressStyle};
use serde::de::DeserializeOwned;
use serde::{Serialize, Deserialize};
use snafu::Snafu;
use tempfile::{NamedTempFile, TempPath};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const HIVE_EVAL: &'static [u8] = include_bytes!("eval.nix");

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentInfo {
    #[serde(rename = "targetHost")]
    target_host: String,

    #[serde(rename = "targetUser")]
    target_user: String,
    tags: Vec<String>,
}

#[derive(Debug)]
pub struct DeploymentTask<'task> {
    /// Name of the target.
    name: String,

    /// The target to deploy to.
    target: DeploymentInfo,

    /// Nix store path to the system profile to deploy.
    profile: PathBuf,

    /// The goal of this deployment.
    goal: DeploymentGoal,

    /// A ProgressBar to show the deployment progress to the user.
    progress: Option<&'task ProgressBar>,

    /// The ProgressStyle to set when the deployment is failing.
    failing_spinner_style: Option<ProgressStyle>,
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

/// Results of a DeploymentTask to show to the user.
pub struct DeploymentResult {
    name: String,
    push_output: Option<String>,
    push_successful: Option<bool>,
    activate_output: Option<String>,
    activate_successful: Option<bool>,
}

impl DeploymentResult {
    fn new(name: String) -> Self {
        Self {
            name,
            push_output: None,
            push_successful: None,
            activate_output: None,
            activate_successful: None,
        }
    }

    /// Whether the deployment was successful overall.
    pub fn success(&self) -> bool {
        if let Some(push_successful) = self.push_successful {
            if !push_successful {
                return false;
            }
        }

        if let Some(activate_successful) = self.activate_successful {
            if !activate_successful {
                return false;
            }
        }

        true
    }

    fn dump_log(f: &mut fmt::Formatter<'_>, output: Option<&String>) -> fmt::Result {
        if let Some(output) = output {
            writeln!(f, "Last 10 lines of log:")?;
            writeln!(f, "~~~~~~~~~~")?;
            let lines: Vec<&str> = output.split("\n").collect();

            let start = if lines.len() < 10 {
                0
            } else {
                lines.len() - 10
            };

            for i in start..lines.len() {
                writeln!(f, "{}", lines[i])?;
            }
            writeln!(f, "~~~~~~~~~~")?;
        }

        writeln!(f)
    }
}

impl fmt::Display for DeploymentResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(push_successful) = self.push_successful {
            if push_successful {
                writeln!(f, "Deployment on node {} succeeded.", self.name)?;
            } else {
                write!(f, "Deployment on node {} failed. ", self.name)?;
                Self::dump_log(f, self.push_output.as_ref())?;
            }
        }
        if let Some(activate_successful) = self.activate_successful {
            if activate_successful {
                writeln!(f, "Activation on node {} succeeded.", self.name)?;
            } else {
                write!(f, "Activation on node {} failed.", self.name)?;
                Self::dump_log(f, self.activate_output.as_ref())?;
            }
        }
        Ok(())
    }
}

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

    #[snafu(display("Nix Error: {}", message))]
    Unknown { message: String },
}

pub type NixResult<T> = Result<T, NixError>;

pub struct Hive {
    hive: PathBuf,
    eval_nix: TempPath,
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
            .spawn()
            .map_err(map_io_error)?
            .wait()
            .await
            .map_err(map_io_error)?;

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
            .spawn()
            .map_err(map_io_error)?
            .wait_with_output()
            .await
            .map_err(map_io_error)?;

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
#[derive(Debug, Serialize, Deserialize)]
struct StorePath(PathBuf);

impl StorePath {
    /// Builds the store path.
    pub async fn realise(&self) -> NixResult<Vec<PathBuf>> {
        Command::new("nix-store")
            .arg("--realise")
            .arg(&self.0)
            .capture_output()
            .await
            .map(|paths| {
                paths.lines().map(|p| p.into()).collect()
            })
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
        let mut tmp = NamedTempFile::new().map_err(map_io_error)?;
        let json = serde_json::to_vec(&data).expect("Could not serialize data");
        tmp.write_all(&json).map_err(map_io_error)?;

        Ok(Self {
            json_file: tmp.into_temp_path(),
        })
    }

    pub fn expression(&self) -> String {
        format!("(builtins.fromJSON (builtins.readFile {}))", self.json_file.to_str().unwrap())
    }
}

impl Hive {
    pub fn new<P: AsRef<Path>>(hive: P) -> NixResult<Self> {
        let mut eval_nix = NamedTempFile::new().map_err(map_io_error)?;
        eval_nix.write_all(HIVE_EVAL).map_err(map_io_error)?;

        Ok(Self {
            hive: hive.as_ref().to_owned(),
            eval_nix: eval_nix.into_temp_path(),
        })
    }

    pub fn from_config_arg(args: &ArgMatches<'_>) -> NixResult<Self> {
        let path = args.value_of("config").expect("The config arg should exist").to_owned();
        let path = canonicalize_path(path);

        Self::new(path)
    }

    /// Retrieve a list of nodes in the hive
    pub async fn nodes(&self) -> NixResult<Vec<String>> {
        self.nix_instantiate("attrNames hive.nodes").eval()
            .capture_json().await
    }

    /// Retrieve deployment info for all nodes
    pub async fn deployment_info(&self) -> NixResult<HashMap<String, DeploymentInfo>> {
        // FIXME: Really ugly :(
        let s: String = self.nix_instantiate("hive.deploymentInfoJson").eval()
            .capture_json().await?;

        Ok(serde_json::from_str(&s).unwrap())
    }

    /// Builds selected nodes
    pub async fn build_selected(&self, nodes: Vec<String>) -> NixResult<HashMap<String, PathBuf>> {
        let nodes_expr = SerializedNixExpresssion::new(&nodes)?;
        let expr = format!("hive.buildSelected {{ names = {}; }}", nodes_expr.expression());

        self.build_common(&expr).await
    }

    /// Builds all node configurations
    pub async fn build_all(&self) -> NixResult<HashMap<String, PathBuf>> {
        self.build_common("hive.buildAll").await
    }

    /// Builds node configurations
    ///
    /// Expects the resulting store path to point to a JSON file containing
    /// a map of node name -> store path.
    async fn build_common(&self, expression: &str) -> NixResult<HashMap<String, PathBuf>> {
        let build: StorePath = self.nix_instantiate(expression).instantiate()
            .capture_store_path().await?;

        let realization = build.realise().await?;
        assert!(realization.len() == 1);

        let json = fs::read_to_string(&realization[0]).map_err(map_io_error)?;
        let result_map: HashMap<String, PathBuf> = serde_json::from_str(&json)
            .expect("Bad result from our own build routine");

        Ok(result_map)
    }

    fn nix_instantiate(&self, expression: &str) -> NixInstantiate {
        NixInstantiate::new(&self.eval_nix, &self.hive, expression.to_owned())
    }
}

impl<'task> DeploymentTask<'task> {
    pub fn new(name: String, target: DeploymentInfo, profile: PathBuf, goal: DeploymentGoal) -> Self {
        Self {
            name,
            target,
            profile,
            goal,
            progress: None,
            failing_spinner_style: None,
        }
    }

    pub fn name(&self) -> &str { &self.name }
    pub fn goal(&self) -> DeploymentGoal { self.goal }

    /// Set the progress bar used during deployment.
    pub fn set_progress_bar(&mut self, progress: &'task ProgressBar) {
        self.progress = Some(progress);
    }

    /// Set a spinner style to switch to when the deployment is failing.
    pub fn set_failing_spinner_style(&mut self, style: ProgressStyle) {
        self.failing_spinner_style = Some(style);
    }

    pub async fn execute(&mut self) -> NixResult<DeploymentResult> {
        match self.goal {
            DeploymentGoal::Push => {
                self.push().await
            }
            _ => {
                self.push_and_activate().await
            }
        }
    }

    async fn push(&mut self) -> NixResult<DeploymentResult> {
        let mut result = DeploymentResult::new(self.name.clone());

        // Issue of interest:
        // https://github.com/NixOS/nix/issues?q=ipv6
        let target = format!("{}@{}", self.target.target_user, self.target.target_host);
        let mut command = Command::new("nix-copy-closure");
        command
            .arg("--to")
            .arg("--gzip")
            .arg("--include-outputs")
            .arg("--use-substitutes")
            .arg(&target)
            .arg(&self.profile);

        let (exit, output) = self.run_command(&mut command, false).await?;

        if let Some(progress) = self.progress.as_mut() {
            if !exit.success() {
                if self.failing_spinner_style.is_some() {
                    let style = self.failing_spinner_style.as_ref().unwrap().clone();
                    progress.set_style(style);
                }
            }
        }

        result.push_successful = Some(exit.success());
        result.push_output = output;

        Ok(result)
    }

    async fn push_and_activate(&mut self) -> NixResult<DeploymentResult> {
        let mut result = self.push().await?;

        if !result.success() {
            // Don't go any further
            return Ok(result);
        }

        let target = format!("{}@{}", self.target.target_user, self.target.target_host);
        let activation_command = format!("{}/bin/switch-to-configuration", self.profile.to_str().unwrap());
        let mut command = Command::new("ssh");
        command
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg(&target)
            .arg("--")
            .arg(activation_command)
            .arg(self.goal.as_str().unwrap());

        let (exit, output) = self.run_command(&mut command, true).await?;

        if let Some(progress) = self.progress.as_mut() {
            if !exit.success() {
                if self.failing_spinner_style.is_some() {
                    let style = self.failing_spinner_style.as_ref().unwrap().clone();
                    progress.set_style(style);
                }
            }
        }

        result.activate_successful = Some(exit.success());
        result.activate_output = output;

        Ok(result)
    }

    async fn run_command(&mut self, command: &mut Command, capture_stdout: bool) -> NixResult<(ExitStatus, Option<String>)> {
        command.stdin(Stdio::null());
        command.stderr(Stdio::piped());

        if capture_stdout {
            command.stdout(Stdio::piped());
        }

        let mut child = command.spawn().map_err(map_io_error)?;

        let mut stderr = BufReader::new(child.stderr.as_mut().unwrap());
        let mut output = String::new();

        loop {
            let mut line = String::new();
            let len = stderr.read_line(&mut line).await.unwrap();

            if len == 0 {
                break;
            }

            let trimmed = line.trim_end();
            if let Some(progress) = self.progress.as_mut() {
                progress.set_message(trimmed);
                progress.inc(0);
            } else {
                println!("{} | {}", style(&self.name).cyan(), trimmed);
            }
            output += &line;
        }
        let exit = child.wait().await.map_err(map_io_error)?;
        Ok((exit, Some(output)))
    }
}

fn map_io_error(error: std::io::Error) -> NixError {
    NixError::IoError { error }
}

fn canonicalize_path(path: String) -> PathBuf {
    if !path.starts_with("/") {
        format!("./{}", path).into()
    } else {
        path.into()
    }
}

