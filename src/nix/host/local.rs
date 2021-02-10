use std::convert::TryInto;
use std::collections::HashMap;
use std::fs;

use async_trait::async_trait;
use tokio::fs::OpenOptions;
use tokio::process::Command;
use tempfile::NamedTempFile;

use super::{CopyDirection, CopyOptions, Host};
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
}

impl Local {
    pub fn new() -> Self {
        Self {
            progress_bar: TaskProgress::default(),
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

        let dest_path = key.dest_dir.join(name);

        let temp = NamedTempFile::new()?;
        let (_, temp_path) = temp.keep().map_err(|pe| pe.error)?;
        let mut reader = key.reader().await?;
        let mut writer = OpenOptions::new().write(true).open(&temp_path).await?;
        tokio::io::copy(reader.as_mut(), &mut writer).await?;

        // Well, we need the userspace chmod program to parse the
        // permission, for NixOps compatibility
        {
            let mut command = Command::new("chmod");
            command
                .arg(&key.permissions)
                .arg(&temp_path);

            let mut execution = CommandExecution::new(command);
            let exit = execution.run().await;

            let (stdout, stderr) = execution.get_logs();
            self.logs += stdout.unwrap();
            self.logs += stderr.unwrap();

            exit?;
        }
        {
            let mut command = Command::new("chown");
            command
                .arg(&format!("{}:{}", key.user, key.group))
                .arg(&temp_path);

            let mut execution = CommandExecution::new(command);
            let exit = execution.run().await;

            let (stdout, stderr) = execution.get_logs();
            self.logs += stdout.unwrap();
            self.logs += stderr.unwrap();

            exit?;
        }

        let parent_dir = dest_path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        if fs::rename(&temp_path, &dest_path).is_err() {
            // Linux can not rename across different filesystems, try copy-then-remove
            let copy_result = fs::copy(&temp_path, &dest_path);
            fs::remove_file(&temp_path)?;
            copy_result?;
        }

        Ok(())
    }
}
