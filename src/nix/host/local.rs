use std::convert::TryInto;
use std::collections::HashMap;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use super::{CopyDirection, CopyOptions, Host, key_uploader};
use crate::nix::{StorePath, Profile, Goal, NixResult, NixCommand, Key, SYSTEM_PROFILE};
use crate::util::CommandExecution;
use crate::progress::TaskProgress;

/// The local machine running Colmena.
///
/// It may not be capable of realizing some derivations
/// (e.g., building Linux derivations on macOS).
#[derive(Debug)]
pub struct Local {
    progress_bar: TaskProgress,
    logs: String,
    nix_options: Vec<String>,
}

impl Local {
    pub fn new(nix_options: Vec<String>) -> Self {
        Self {
            progress_bar: TaskProgress::default(),
            logs: String::new(),
            nix_options,
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

        command.args(self.nix_options.clone());
        command
            .arg("--no-gc-warning")
            .arg("--realise")
            .arg(derivation.as_path());

        let mut execution = CommandExecution::new(command);

        execution.set_progress_bar(self.progress_bar.clone());

        let result = execution.run().await;

        let (stdout, stderr) = execution.get_logs();
        self.logs += stderr.unwrap();

        match result {
            Ok(()) => {
                stdout.unwrap().lines().map(|p| p.to_string().try_into()).collect()
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

        let mut execution = CommandExecution::new(command);

        execution.set_progress_bar(self.progress_bar.clone());

        let result = execution.run().await;

        // FIXME: Bad - Order of lines is messed up
        let (stdout, stderr) = execution.get_logs();
        self.logs += stdout.unwrap();
        self.logs += stderr.unwrap();

        result
    }
    fn set_progress_bar(&mut self, bar: TaskProgress) {
        self.progress_bar = bar;
    }
    async fn dump_logs(&self) -> Option<&str> {
        Some(&self.logs)
    }
}

impl Local {
    /// "Uploads" a single key.
    async fn upload_key(&mut self, name: &str, key: &Key) -> NixResult<()> {
        self.progress_bar.log(&format!("Deploying key {}", name));

        let dest_path = key.dest_dir().join(name);
        let key_script = format!("'{}'", key_uploader::generate_script(key, &dest_path));

        let mut command = Command::new("sh");

        command.args(&["-c", &key_script]);
        command.stdin(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdout(Stdio::piped());

        let uploader = command.spawn()?;
        key_uploader::feed_uploader(uploader, key, self.progress_bar.clone(), &mut self.logs).await
    }
}
