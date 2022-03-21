//! Custom error types.

use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use snafu::Snafu;
use validator::ValidationErrors;

use crate::nix::{key, StorePath};

pub type ColmenaResult<T> = Result<T, ColmenaError>;

#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum ColmenaError {
    #[snafu(display("I/O Error: {}", error))]
    IoError { error: std::io::Error },

    #[snafu(display("Nix returned invalid response: {}", output))]
    BadOutput { output: String },

    #[snafu(display("Child process exited with error code: {}", exit_code))]
    ChildFailure { exit_code: i32 },

    #[snafu(display("Child process was killed by signal {}", signal))]
    ChildKilled { signal: i32 },

    #[snafu(display("This operation is not supported"))]
    Unsupported,

    #[snafu(display("Invalid Nix store path"))]
    InvalidStorePath,

    #[snafu(display("Validation error"))]
    ValidationError { errors: ValidationErrors },

    #[snafu(display("Failed to upload keys: {}", error))]
    KeyError { error: key::KeyError },

    #[snafu(display("Store path {:?} is not a derivation", store_path))]
    NotADerivation { store_path: StorePath },

    #[snafu(display("Invalid NixOS system profile"))]
    InvalidProfile,

    #[snafu(display("Unknown active profile: {:?}", store_path))]
    ActiveProfileUnknown { store_path: StorePath },

    #[snafu(display("Could not determine current profile"))]
    FailedToGetCurrentProfile,

    #[snafu(display("Current Nix version does not support Flakes"))]
    NoFlakesSupport,

    #[snafu(display("Don't know how to connect to the node"))]
    NoTargetHost,

    #[snafu(display("Node name cannot be empty"))]
    EmptyNodeName,

    #[snafu(display("Filter rule cannot be empty"))]
    EmptyFilterRule,

    #[snafu(display("Deployment already executed"))]
    DeploymentAlreadyExecuted,

    #[snafu(display("Unknown error: {}", message))]
    Unknown { message: String },
}

impl From<std::io::Error> for ColmenaError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError { error }
    }
}

impl From<key::KeyError> for ColmenaError {
    fn from(error: key::KeyError) -> Self {
        Self::KeyError { error }
    }
}

impl From<ValidationErrors> for ColmenaError {
    fn from(errors: ValidationErrors) -> Self {
        Self::ValidationError { errors }
    }
}

impl From<ExitStatus> for ColmenaError {
    fn from(status: ExitStatus) -> Self {
        match status.code() {
            Some(exit_code) => Self::ChildFailure { exit_code },
            None => Self::ChildKilled {
                signal: status.signal().unwrap(),
            },
        }
    }
}

impl ColmenaError {
    pub fn unknown(error: Box<dyn std::error::Error>) -> Self {
        let message = error.to_string();
        Self::Unknown { message }
    }
}
