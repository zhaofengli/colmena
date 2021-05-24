use std::collections::HashMap;
use std::convert::TryInto;
use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use super::{CopyDirection, CopyOptions, Host, key_uploader};
use crate::nix::{StorePath, Profile, Goal, NixResult, NixCommand, NixError, Key, SYSTEM_PROFILE};
use crate::util::CommandExecution;
use crate::progress::TaskProgress;

/// A remote machine connected over SSH.
#[derive(Debug)]
pub struct Ssh {
    /// The username to use to connect.
    user: String,

    /// The hostname or IP address to connect to.
    host: String,

    /// The port to connect to.
    port: Option<u16>,

    /// Local path to a ssh_config file.
    ssh_config: Option<PathBuf>,

    friendly_name: String,
    progress_bar: TaskProgress,
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
    async fn activate(&mut self, profile: &Profile, goal: Goal) -> NixResult<()> {
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
    async fn active_derivation_known(&mut self) -> NixResult<bool> {
        let paths = self.ssh(&["realpath", SYSTEM_PROFILE])
            .capture_output()
            .await;

        match paths {
            Ok(paths) => {
                for path in paths.lines().into_iter() {
                    let remote_profile: StorePath = path.to_string().try_into().unwrap();
                    if remote_profile.exists() {
                        return Ok(true);
                    }
                    return Err(NixError::ActiveProfileUnknown {
                        store_path: path.to_string(),
                    });
                }
                return Ok(false);
            }
            Err(e) => Err(e),
        }
    }
    fn set_progress_bar(&mut self, bar: TaskProgress) {
        self.progress_bar = bar;
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
            port: None,
            ssh_config: None,
            friendly_name,
            progress_bar: TaskProgress::default(),
            logs: String::new(),
        }
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = Some(port);
    }

    pub fn set_ssh_config(&mut self, ssh_config: PathBuf) {
        self.ssh_config = Some(ssh_config);
    }

    pub fn upcast(self) -> Box<dyn Host> {
        Box::new(self)
    }

    /// Returns a Tokio Command to run an arbitrary command on the host.
    pub fn ssh(&self, command: &[&str]) -> Command {
        let options = self.ssh_options();
        let options_str = options.join(" ");

        let mut cmd = Command::new("ssh");

        cmd
            .arg(self.ssh_target())
            .args(&options)
            .arg("--")
            .args(command)
            .env("NIX_SSHOPTS", options_str);

        cmd
    }

    async fn run_command(&mut self, command: Command) -> NixResult<()> {
        let mut execution = CommandExecution::new(command);

        execution.set_progress_bar(self.progress_bar.clone());

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
        let ssh_options = self.ssh_options();
        let ssh_options_str = ssh_options.join(" ");

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
            .arg(path.as_path())
            .env("NIX_SSHOPTS", ssh_options_str);

        command
    }

    fn ssh_options(&self) -> Vec<String> {
        // TODO: Allow configuation of SSH parameters

        let mut options: Vec<String> = ["-o", "StrictHostKeyChecking=accept-new", "-T"]
            .iter().map(|s| s.to_string()).collect();

        if let Some(port) = self.port {
            options.push("-p".to_string());
            options.push(port.to_string());
        }

        if let Some(ssh_config) = self.ssh_config.as_ref() {
            options.push("-F".to_string());
            options.push(ssh_config.to_str().unwrap().to_string());
        }

        options
    }

    /// Uploads a single key.
    async fn upload_key(&mut self, name: &str, key: &Key) -> NixResult<()> {
        self.progress_bar.log(&format!("Deploying key {}", name));

        let dest_path = key.dest_dir().join(name);
        let key_script = key_uploader::generate_script(key, &dest_path);

        let mut command = self.ssh(&["sh", "-c", &key_script]);

        command.stdin(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdout(Stdio::piped());

        let uploader = command.spawn()?;
        key_uploader::feed_uploader(uploader, key, self.progress_bar.clone(), &mut self.logs).await
    }
}
