use std::process::Stdio;
use std::collections::HashSet;

use console::style;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use indicatif::ProgressBar;

use super::{StorePath, DeploymentGoal, NixResult, NixError, NixCommand, SYSTEM_PROFILE};

pub(crate) fn local() -> Box<dyn Host + 'static> {
    Box::new(Local {})
}

#[derive(Copy, Clone, Debug)]
pub enum CopyDirection {
    ToRemote,
    FromRemote,
}

/// A Nix(OS) host.
///
/// The underlying implementation must be Send and Sync.
#[async_trait]
pub trait Host: Send + Sync + std::fmt::Debug {
    /// Sends or receives the specified closure to the host
    ///
    /// The StorePath and its dependent paths will then exist on this host.
    async fn copy_closure(&mut self, closure: &StorePath, direction: CopyDirection, include_outputs: bool) -> NixResult<()>;

    /// Realizes the specified derivation on the host
    ///
    /// The derivation must already exist on the host.
    /// After realization, paths in the Vec<StorePath> will then
    /// exist on the host.
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>>;

    /// Realizes the specified local derivation on the host then retrieves the outputs.
    async fn realize(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        self.copy_closure(derivation, CopyDirection::ToRemote, false).await?;
        let paths = self.realize_remote(derivation).await?;
        self.copy_closure(derivation, CopyDirection::FromRemote, true).await?;

        Ok(paths)
    }

    #[allow(unused_variables)] 
    /// Activates a system profile on the host, if it runs NixOS.
    async fn activate(&mut self, profile: &StorePath, goal: DeploymentGoal) -> NixResult<()> {
        Err(NixError::Unsupported)
    }

    #[allow(unused_variables)] 
    /// Provides a ProgressBar to use during operations.
    fn set_progress_bar(&mut self, bar: ProgressBar) {
    }

    /// Dumps human-readable unstructured log messages related to the host.
    async fn dump_logs(&self) -> Option<&[String]> {
        None
    }
}

/// The local machine running Colmena.
///
/// It may not be capable of realizing some derivations
/// (e.g., building Linux derivations on macOS).
#[derive(Debug)]
pub struct Local {}

#[async_trait]
impl Host for Local {
    async fn copy_closure(&mut self, _closure: &StorePath, _direction: CopyDirection, _include_outputs: bool) -> NixResult<()> {
        Ok(())
    }
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        Command::new("nix-store")
            .arg("--realise")
            .arg(derivation.as_path())
            .capture_output()
            .await
            .map(|paths| {
                paths.lines().map(|p| p.to_string().into()).collect()
            })
    }
    async fn activate(&mut self, profile: &StorePath, goal: DeploymentGoal) -> NixResult<()> {
        let profile = profile.as_path().to_str().unwrap();
        Command::new("nix-env")
            .args(&["--profile", SYSTEM_PROFILE])
            .args(&["--set", profile])
            .passthrough()
            .await?;

        let activation_command = format!("{}/bin/switch-to-configuration", profile);
        Command::new(activation_command)
            .arg(goal.as_str().unwrap())
            .passthrough()
            .await
    }
}

/// A remote machine connected over SSH.
#[derive(Debug)]
pub struct SSH {
    /// The username to use to connect.
    user: String,

    /// The hostname or IP address to connect to.
    host: String,

    friendly_name: String,
    path_cache: HashSet<StorePath>,
    progress: Option<ProgressBar>,
    logs: Vec<String>,
}

#[async_trait]
impl Host for SSH {
    async fn copy_closure(&mut self, closure: &StorePath, direction: CopyDirection, include_outputs: bool) -> NixResult<()> {
        let command = self.nix_copy_closure(closure, direction, include_outputs);
        self.run_command(command).await
    }
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        // FIXME
        self.ssh(&["nix-store", "--realise", derivation.as_path().to_str().unwrap()])
            .capture_output()
            .await
            .map(|paths| {
                paths.lines().map(|p| p.to_string().into()).collect()
            })
    }
    async fn activate(&mut self, profile: &StorePath, goal: DeploymentGoal) -> NixResult<()> {
        let profile = profile.as_path().to_str().unwrap();

        let set_profile = self.ssh(&["nix-env", "--profile", SYSTEM_PROFILE, "--set", profile]);
        self.run_command(set_profile).await?;

        let activation_command = format!("{}/bin/switch-to-configuration", profile);
        let command = self.ssh(&[&activation_command, goal.as_str().unwrap()]);
        self.run_command(command).await
    }
    fn set_progress_bar(&mut self, bar: ProgressBar) {
        self.progress = Some(bar);
    }
    async fn dump_logs(&self) -> Option<&[String]> {
        Some(&self.logs)
    }
}

impl SSH {
    pub fn new(user: String, host: String) -> SSH {
        let friendly_name = host.clone();
        Self {
            user,
            host,
            friendly_name,
            path_cache: HashSet::new(),
            progress: None,
            logs: Vec::new(),
        }
    }

    async fn run_command(&mut self, mut command: Command) -> NixResult<()> {
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn()?;

        let mut stderr = BufReader::new(child.stderr.as_mut().unwrap());

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
                println!("{} | {}", style(&self.friendly_name).cyan(), trimmed);
            }
            self.logs.push(line);
        }
        let exit = child.wait().await?;

        if exit.success() {
            Ok(())
        } else {
            Err(NixError::NixFailure { exit_code: exit.code().unwrap() })
        }
    }

    fn ssh_target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    fn nix_copy_closure(&self, path: &StorePath, direction: CopyDirection, include_outputs: bool) -> Command {
        let mut command = Command::new("nix-copy-closure");
        match direction {
            CopyDirection::ToRemote => {
                command.arg("--to");
            }
            CopyDirection::FromRemote => {
                command.arg("--from");
            }
        }
        if include_outputs {
            command.arg("--include-outputs");
        }

        command
            .arg("--gzip")
            .arg("--use-substitutes")
            .arg(&self.ssh_target())
            .arg(path.as_path());

        command
    }

    fn ssh(&self, command: &[&str]) -> Command {
        // TODO: Allow configuation of SSH parameters

        let mut cmd = Command::new("ssh");
        cmd.arg(self.ssh_target())
            .args(&["-o", "StrictHostKeyChecking=accept-new"])
            .arg("--")
            .args(command);

        cmd
    }
}
