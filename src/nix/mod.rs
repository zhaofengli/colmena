use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
use std::process::Stdio;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use snafu::Snafu;
use tokio::process::Command;
use validator::{Validate, ValidationErrors, ValidationError as ValidationErrorType};

use crate::util::CommandExecution;

pub mod host;
pub use host::{Host, CopyDirection, CopyOptions};
use host::Ssh;

pub mod hive;
pub use hive::Hive;
pub use hive::HivePath;

pub mod store;
pub use store::{StorePath, StoreDerivation};

pub mod key;
pub use key::Key;

pub mod profile;
pub use profile::{Profile, ProfileMap};

pub mod deployment;
pub use deployment::{Goal, Target, Deployment};

#[cfg(test)]
mod tests;

pub const SYSTEM_PROFILE: &'static str = "/nix/var/nix/profiles/system";

pub type NixResult<T> = Result<T, NixError>;

#[non_exhaustive]
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

    #[snafu(display("Invalid Nix store path"))]
    InvalidStorePath,

    #[snafu(display("Validation error"))]
    ValidationError { errors: ValidationErrors },

    #[snafu(display("Failed to upload keys: {}", error))]
    KeyError { error: key::KeyError },

    #[snafu(display("Invalid NixOS system profile"))]
    InvalidProfile,

    #[snafu(display("Nix Error: {}", message))]
    Unknown { message: String },
}

impl From<std::io::Error> for NixError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError { error }
    }
}

impl From<key::KeyError> for NixError {
    fn from(error: key::KeyError) -> Self {
        Self::KeyError { error }
    }
}

impl From<ValidationErrors> for NixError {
    fn from(errors: ValidationErrors) -> Self {
        Self::ValidationError { errors }
    }
}

#[derive(Debug, Clone, Validate, Deserialize)]
pub struct NodeConfig {
    #[serde(rename = "targetHost")]
    target_host: Option<String>,

    #[serde(rename = "targetUser")]
    target_user: String,

    #[serde(rename = "targetPort")]
    target_port: Option<u16>,

    #[serde(rename = "allowLocalDeployment")]
    allow_local_deployment: bool,
    tags: Vec<String>,

    #[validate(custom = "validate_keys")]
    keys: HashMap<String, Key>,
}

impl NodeConfig {
    pub fn tags(&self) -> &[String] { &self.tags }
    pub fn allows_local_deployment(&self) -> bool { self.allow_local_deployment }

    pub fn to_ssh_host(&self) -> Option<Ssh> {
        self.target_host.as_ref().map(|target_host| {
            let mut host = Ssh::new(self.target_user.clone(), target_host.clone());

            if let Some(target_port) = self.target_port {
                host.set_port(target_port);
            }

            host
        })
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
        let path = output.trim_end().to_owned();
        StorePath::try_from(path)
    }
}

#[async_trait]
impl NixCommand for CommandExecution {
    async fn passthrough(&mut self) -> NixResult<()> {
        self.run().await
    }

    /// Captures output as a String.
    async fn capture_output(&mut self) -> NixResult<String> {
        self.run().await?;
        let (stdout, _) = self.get_logs();

        Ok(stdout.unwrap().to_owned())
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
        let path = output.trim_end().to_owned();
        StorePath::try_from(path)
    }
}

fn validate_keys(keys: &HashMap<String, Key>) -> Result<(), ValidationErrorType> {
    // Bad secret names:
    // - /etc/passwd
    // - ../../../../../etc/passwd

    for name in keys.keys() {
        let path = Path::new(name);
        if path.has_root() {
            return Err(ValidationErrorType::new("Secret key name cannot be absolute"));
        }

        if path.components().collect::<Vec<_>>().len() != 1 {
            return Err(ValidationErrorType::new("Secret key name cannot contain path separators"));
        }
    }
    Ok(())
}
