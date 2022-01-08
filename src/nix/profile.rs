use std::convert::TryFrom;
use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use super::{
    Goal,
    ColmenaResult,
    ColmenaError,
    StorePath,
    StoreDerivation,
    BuildResult,
};

pub type ProfileDerivation = StoreDerivation<Profile>;

/// A NixOS system profile.
#[derive(Clone, Debug)]
pub struct Profile(StorePath);

impl Profile {
    pub fn from_store_path(path: StorePath) -> ColmenaResult<Self> {
        if
            !path.is_dir() ||
            !path.join("bin/switch-to-configuration").exists()
        {
            return Err(ColmenaError::InvalidProfile);
        }

        if path.to_str().is_none() {
            Err(ColmenaError::InvalidProfile)
        } else {
            Ok(Self(path))
        }
    }

    /// Returns the command to activate this profile.
    pub fn activation_command(&self, goal: Goal) -> Option<Vec<String>> {
        if let Some(goal) = goal.as_str() {
            let path = self.as_path().join("bin/switch-to-configuration");
            let switch_to_configuration = path.to_str()
                .expect("The string should be UTF-8 valid")
                .to_string();

            Some(vec![
                switch_to_configuration,
                goal.to_string(),
            ])
        } else {
            None
        }
    }

    /// Returns the store path.
    pub fn as_store_path(&self) -> &StorePath {
        &self.0
    }

    /// Returns the raw store path.
    pub fn as_path(&self) -> &Path {
        self.0.as_path()
    }

    /// Create a GC root for this profile.
    pub async fn create_gc_root(&self, path: &Path) -> ColmenaResult<()> {
        let mut command = Command::new("nix-store");
        command.args(&["--no-build-output", "--indirect", "--add-root", path.to_str().unwrap()]);
        command.args(&["--realise", self.as_path().to_str().unwrap()]);
        command.stdout(Stdio::null());

        let status = command.status().await?;
        if !status.success() {
            return Err(status.into());
        }

        Ok(())
    }

    fn from_store_path_unchecked(path: StorePath) -> Self {
        Self(path)
    }
}

impl TryFrom<BuildResult<Profile>> for Profile {
    type Error = ColmenaError;

    fn try_from(result: BuildResult<Self>) -> ColmenaResult<Self> {
        let paths = result.paths();

        if paths.is_empty() {
            return Err(ColmenaError::BadOutput {
                output: String::from("There is no store path"),
            });
        }

        if paths.len() > 1 {
            return Err(ColmenaError::BadOutput {
                output: String::from("Build resulted in more than 1 store path"),
            });
        }

        let path = paths.iter().next()
            .unwrap().to_owned();

        Ok(Self::from_store_path_unchecked(path))
    }
}
