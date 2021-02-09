use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::process::Stdio;

use async_trait::async_trait;
use indicatif::ProgressBar;
use tokio::process::Command;
use tokio::io::AsyncWriteExt;

use super::{CopyDirection, CopyOptions, Host};
use crate::nix::{StorePath, Profile, DeploymentGoal, NixResult, NixCommand, NixError, Key, SYSTEM_PROFILE};
use crate::util::CommandExecution;

const DEPLOY_KEY_TEMPLATE: &'static str = include_str!("./deploy-key.template");

/// A remote machine connected over SSH.
#[derive(Debug)]
pub struct Ssh {
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
impl Host for Ssh {
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
    async fn upload_keys(&mut self, keys: &HashMap<String, Key>) -> NixResult<()> {
        for (name, key) in keys {
            self.upload_key(&name, &key).await?;
        }

        Ok(())
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

impl Ssh {
    pub fn new(user: String, host: String) -> Self {
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
            .args(&["-o", "StrictHostKeyChecking=accept-new", "-T"])
            .arg("--")
            .args(command);

        cmd
    }
}

impl Ssh {
    /// Uploads a single key.
    async fn upload_key(&mut self, name: &str, key: &Key) -> NixResult<()> {
        if let Some(progress_bar) = self.progress_bar.as_ref() {
            progress_bar.set_message(&format!("Deploying key {}", name));
        }

        let dest_path = key.dest_dir.join(name);

        let remote_command = DEPLOY_KEY_TEMPLATE.to_string()
            .replace("%DESTINATION%", dest_path.to_str().unwrap())
            .replace("%USER%", &key.user)
            .replace("%GROUP%", &key.group)
            .replace("%PERMISSIONS%", &key.permissions);

        let mut command = self.ssh(&["sh", "-c", &remote_command]);

        command.stdin(Stdio::piped());
        command.stderr(Stdio::null());
        command.stdout(Stdio::null());

        let mut child = command.spawn()?;

        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(key.text.as_bytes()).await?;
        stdin.flush().await?;
        drop(stdin);

        let exit = child.wait().await?;
        if exit.success() {
            Ok(())
        } else {
            Err(NixError::NixFailure { exit_code: exit.code().unwrap() })
        }
    }
}
