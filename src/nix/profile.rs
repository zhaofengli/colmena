use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use super::{
    Goal,
    NixResult,
    NixError,
    StorePath,
};

/// A NixOS system profile.
#[derive(Clone, Debug)]
pub struct Profile(StorePath);

impl Profile {
    pub fn from_store_path(path: StorePath) -> NixResult<Self> {
        if
            !path.is_dir() ||
            !path.join("bin/switch-to-configuration").exists()
        {
            return Err(NixError::InvalidProfile);
        }

        if let None = path.to_str() {
            Err(NixError::InvalidProfile)
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

            let mut v = Vec::new();
            v.push(switch_to_configuration);
            v.push(goal.to_string());

            Some(v)
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
        &self.0.as_path()
    }
}

/// A map of names to their associated NixOS system profiles.
#[derive(Debug)]
pub struct ProfileMap(HashMap<String, Profile>);

impl Deref for ProfileMap {
    type Target = HashMap<String, Profile>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ProfileMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<Vec<StorePath>> for ProfileMap {
    type Error = NixError;

    fn try_from(paths: Vec<StorePath>) -> NixResult<Self> {
        match paths.len() {
            0 => Err(NixError::BadOutput {
                output: String::from("Build produced no outputs"),
            }),
            l if l > 1 => Err(NixError::BadOutput {
                output: String::from("Build produced multiple outputs"),
            }),
            _ => {
                // We expect a JSON file containing a
                // HashMap<String, StorePath>

                let path = paths[0].as_path();
                let json: String = fs::read_to_string(path)?;
                let mut raw_map: HashMap<String, StorePath> = serde_json::from_str(&json).map_err(|_| NixError::BadOutput {
                    output: String::from("The returned profile map is invalid"),
                })?;

                let mut checked_map = HashMap::new();
                for (node, profile) in raw_map.drain() {
                    let profile = Profile::from_store_path(profile)?;
                    checked_map.insert(node, profile);
                }

                Ok(Self(checked_map))
            }
        }
    }
}

impl ProfileMap {
    /// Create GC roots for all profiles in the map.
    ///
    /// The created links will be located at `{base}/node-{node_name}`.
    pub async fn create_gc_roots(&self, base: &Path) -> NixResult<()> {
        // This will actually try to build all profiles, but since they
        // already exist only the GC roots will be created.
        for (node, profile) in self.0.iter() {
            let path = base.join(format!("node-{}", node));

            let mut command = Command::new("nix-store");
            command.args(&["--no-build-output", "--indirect", "--add-root", path.to_str().unwrap()]);
            command.args(&["--realise", profile.as_path().to_str().unwrap()]);
            command.stdout(Stdio::null());

            let status = command.status().await?;
            if !status.success() {
                return Err(status.into());
            }
        }

        Ok(())
    }
}
