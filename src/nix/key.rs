use std::{
    convert::TryFrom,
    io::{self, Cursor},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tokio::{
    fs::File,
    io::AsyncRead,
    process::Command,
};
use validator::{Validate, ValidationError};

#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum KeyError {
    #[snafu(display("I/O Error: {}", error))]
    IoError { error: io::Error },
    #[snafu(display("Key command failed: {}, stderr: {}", status, stderr))]
    KeyCommandStatus { status: ExitStatus, stderr: String },
}

impl From<std::io::Error> for KeyError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError { error }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "KeySources")]
enum KeySource {
    #[serde(rename = "text")]
    Text(String),

    #[serde(rename = "keyCommand")]
    Command(Vec<String>),

    #[serde(rename = "keyFile")]
    File(PathBuf),
}

impl TryFrom<KeySources> for KeySource {
    type Error = String;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match (ks.text, ks.command, ks.file) {
            (Some(text), None, None) => {
                Ok(KeySource::Text(text))
            }
            (None, Some(command), None) => {
                Ok(KeySource::Command(command))
            }
            (None, None, Some(file)) => {
                Ok(KeySource::File(file))
            }
            x => {
                Err(format!("Somehow 0 or more than 1 key source was specified: {:?}", x))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeySources {
    text: Option<String>,

    #[serde(rename = "keyCommand")]
    command: Option<Vec<String>>,

    #[serde(rename = "keyFile")]
    file: Option<PathBuf>,
}

/// When to upload a given key.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum UploadAt {
    /// Before activating the system profile.
    #[serde(rename = "pre-activation")]
    PreActivation,

    /// After successfully activating the system profile.
    #[serde(rename = "post-activation")]
    PostActivation,
}

#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
pub struct Key {
    name: String,

    path: PathBuf,

    #[serde(flatten)]
    source: KeySource,

    #[validate(custom = "validate_dest_dir")]
    #[serde(rename = "destDir")]
    dest_dir: PathBuf,

    #[validate(custom = "validate_unix_name")]
    user: String,

    #[validate(custom = "validate_unix_name")]
    group: String,

    permissions: String,

    #[serde(rename = "uploadAt")]
    upload_at: UploadAt,
}

impl Key {
    pub async fn reader(&'_ self) -> Result<Box<dyn AsyncRead + Send + Unpin + '_>, KeyError> {
        match &self.source {
            KeySource::Text(content) => {
                Ok(Box::new(Cursor::new(content)))
            }
            KeySource::Command(command) => {
                let pathname = &command[0];
                let argv = &command[1..];

                let output = Command::new(pathname)
                    .args(argv)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?
                    .wait_with_output().await?;

                if output.status.success() {
                    Ok(Box::new(Cursor::new(output.stdout)))
                } else {
                    Err(KeyError::KeyCommandStatus {
                        status: output.status,
                        stderr: std::str::from_utf8(&output.stderr)
                            .unwrap_or_default()
                            .trim_end()
                            .into(),
                    })
                }
            }
            KeySource::File(path) => {
                Ok(Box::new(File::open(path).await?))
            }
        }
    }

    pub fn path(&self) -> &Path { &self.path }
    pub fn user(&self) -> &str { &self.user }
    pub fn group(&self) -> &str { &self.group }
    pub fn permissions(&self) -> &str { &self.permissions }
    pub fn upload_at(&self) -> UploadAt { self.upload_at }
}

fn validate_unix_name(name: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[a-z][-a-z0-9]*$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(ValidationError::new("Invalid user/group name"))
    }
}

fn validate_dest_dir(dir: &Path) -> Result<(), ValidationError> {
    if dir.has_root() {
        Ok(())
    } else {
        Err(ValidationError::new("Secret key destination directory must be absolute"))
    }
}
