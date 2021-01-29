use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use tokio::process::Command;
use indicatif::ProgressBar;

use super::{StorePath, Profile, DeploymentGoal, NixResult, NixError, NixCommand, SYSTEM_PROFILE};
use crate::util::CommandExecution;

pub(crate) fn local() -> Box<dyn Host + 'static> {
    Box::new(Local::new())
}

#[derive(Copy, Clone, Debug)]
pub enum CopyDirection {
    ToRemote,
    FromRemote,
}

#[derive(Copy, Clone, Debug)]
pub struct CopyOptions {
    include_outputs: bool,
    use_substitutes: bool,
    gzip: bool,
}

impl Default for CopyOptions {
    fn default() -> Self {
        Self {
            include_outputs: true,
            use_substitutes: true,
            gzip: true,
        }
    }
}

impl CopyOptions {
    pub fn include_outputs(mut self, val: bool) -> Self {
        self.include_outputs = val;
        self
    }

    pub fn use_substitutes(mut self, val: bool) -> Self {
        self.use_substitutes = val;
        self
    }

    pub fn gzip(mut self, val: bool) -> Self {
        self.gzip = val;
        self
    }
}

/// A Nix(OS) host.
///
/// The underlying implementation must be Send and Sync.
#[async_trait]
pub trait Host: Send + Sync + std::fmt::Debug {
    /// Sends or receives the specified closure to the host
    ///
    /// The StorePath and its dependent paths will then exist on this host.
    async fn copy_closure(&mut self, closure: &StorePath, direction: CopyDirection, options: CopyOptions) -> NixResult<()>;

    /// Realizes the specified derivation on the host
    ///
    /// The derivation must already exist on the host.
    /// After realization, paths in the Vec<StorePath> will then
    /// exist on the host.
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>>;

    /// Realizes the specified local derivation on the host then retrieves the outputs.
    async fn realize(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        let options = CopyOptions::default();

        self.copy_closure(derivation, CopyDirection::ToRemote, options.include_outputs(false)).await?;
        let paths = self.realize_remote(derivation).await?;
        self.copy_closure(derivation, CopyDirection::FromRemote, options.include_outputs(true)).await?;

        Ok(paths)
    }

    /// Pushes and optionally activates a profile to the host.
    async fn deploy(&mut self, profile: &Profile, goal: DeploymentGoal, copy_options: CopyOptions) -> NixResult<()> {
        self.copy_closure(profile.as_store_path(), CopyDirection::ToRemote, copy_options).await?;

        if goal.requires_activation() {
            self.activate(profile, goal).await?;
        }

        Ok(())
    }

    #[allow(unused_variables)] 
    /// Activates a system profile on the host, if it runs NixOS.
    ///
    /// The profile must already exist on the host. You should probably use deploy instead.
    async fn activate(&mut self, profile: &Profile, goal: DeploymentGoal) -> NixResult<()> {
        Err(NixError::Unsupported)
    }

    #[allow(unused_variables)] 
    /// Provides a ProgressBar to use during operations.
    fn set_progress_bar(&mut self, bar: ProgressBar) {
    }

    /// Dumps human-readable unstructured log messages related to the host.
    async fn dump_logs(&self) -> Option<&str> {
        None
    }
}

/// The local machine running Colmena.
///
/// It may not be capable of realizing some derivations
/// (e.g., building Linux derivations on macOS).
#[derive(Debug)]
pub struct Local {
    progress_bar: Option<ProgressBar>,
    logs: String,
}

impl Local {
    pub fn new() -> Self {
        Self {
            progress_bar: None,
            logs: String::new(),
        }
    }
}

#[async_trait]
impl Host for Local {
    async fn copy_closure(&mut self, _closure: &StorePath, _direction: CopyDirection, _options: CopyOptions) -> NixResult<()> {
        Ok(())
    }
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        let mut command = Command::new("nix-store");
        command
            .arg("--no-gc-warning")
            .arg("--realise")
            .arg(derivation.as_path());

        let mut execution = CommandExecution::new("local", command);

        if let Some(bar) = self.progress_bar.as_ref() {
            execution.set_progress_bar(bar.clone());
        }

        execution.run().await?;

        let (stdout, stderr) = execution.get_logs();
        self.logs += stderr.unwrap();

        stdout.unwrap().lines().map(|p| p.to_string().try_into()).collect()
    }
    async fn activate(&mut self, profile: &Profile, goal: DeploymentGoal) -> NixResult<()> {
        if goal.should_switch_profile() {
            let path = profile.as_path().to_str().unwrap();
            Command::new("nix-env")
                .args(&["--profile", SYSTEM_PROFILE])
                .args(&["--set", path])
                .passthrough()
                .await?;
        }

        let activation_command = profile.activation_command(goal).unwrap();
        let mut command = Command::new(&activation_command[0]);
        command
            .args(&activation_command[1..]);

        let mut execution = CommandExecution::new("local", command);

        if let Some(bar) = self.progress_bar.as_ref() {
            execution.set_progress_bar(bar.clone());
        }

        let result = execution.run().await;

        // FIXME: Bad - Order of lines is messed up
        let (stdout, stderr) = execution.get_logs();
        self.logs += stdout.unwrap();
        self.logs += stderr.unwrap();

        result
    }
    fn set_progress_bar(&mut self, bar: ProgressBar) {
        self.progress_bar = Some(bar);
    }
    async fn dump_logs(&self) -> Option<&str> {
        Some(&self.logs)
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
    progress_bar: Option<ProgressBar>,
    logs: String,
}

#[async_trait]
impl Host for SSH {
    async fn copy_closure(&mut self, closure: &StorePath, direction: CopyDirection, options: CopyOptions) -> NixResult<()> {
        let command = self.nix_copy_closure(closure, direction, options);
        self.run_command(command).await
    }
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        // FIXME
        let paths = self.ssh(&["nix-store", "--no-gc-warning", "--realise", derivation.as_path().to_str().unwrap()])
            .capture_output()
            .await;

        match paths {
            Ok(paths) => {
                paths.lines().map(|p| p.to_string().try_into()).collect()
            }
            Err(e) => Err(e),
        }
    }
    async fn activate(&mut self, profile: &Profile, goal: DeploymentGoal) -> NixResult<()> {
        if goal.should_switch_profile() {
            let path = profile.as_path().to_str().unwrap();
            let set_profile = self.ssh(&["nix-env", "--profile", SYSTEM_PROFILE, "--set", path]);
            self.run_command(set_profile).await?;
        }

        let activation_command = profile.activation_command(goal).unwrap();
        let v: Vec<&str> = activation_command.iter().map(|s| &**s).collect();
        let command = self.ssh(&v);
        self.run_command(command).await
    }
    fn set_progress_bar(&mut self, bar: ProgressBar) {
        self.progress_bar = Some(bar);
    }
    async fn dump_logs(&self) -> Option<&str> {
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
            progress_bar: None,
            logs: String::new(),
        }
    }

    async fn run_command(&mut self, command: Command) -> NixResult<()> {
        let mut execution = CommandExecution::new(&self.friendly_name, command);

        if let Some(bar) = self.progress_bar.as_ref() {
            execution.set_progress_bar(bar.clone());
        }

        let result = execution.run().await;

        // FIXME: Bad - Order of lines is messed up
        let (stdout, stderr) = execution.get_logs();
        self.logs += stdout.unwrap();
        self.logs += stderr.unwrap();

        result
    }

    fn ssh_target(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    fn nix_copy_closure(&self, path: &StorePath, direction: CopyDirection, options: CopyOptions) -> Command {
        let mut command = Command::new("nix-copy-closure");
        match direction {
            CopyDirection::ToRemote => {
                command.arg("--to");
            }
            CopyDirection::FromRemote => {
                command.arg("--from");
            }
        }

        // FIXME: Host-agnostic abstraction
        if options.include_outputs {
            command.arg("--include-outputs");
        }
        if options.use_substitutes {
            command.arg("--use-substitutes");
        }
        if options.gzip {
            command.arg("--gzip");
        }

        command
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
