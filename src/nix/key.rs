use std::{
    io::{self, Cursor},
    path::{Path, PathBuf},
    process::Stdio,
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::AsyncRead,
    process::Command,
};
use validator::{Validate, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
enum KeySource {
    #[serde(rename = "text")]
    Text(String),

    #[serde(rename = "keyCommand")]
    Command(Vec<String>),

    #[serde(rename = "keyFile")]
    File(PathBuf),
}

#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
pub struct Key {
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
}

impl Key {
    pub async fn reader(&'_ self,) -> Result<Box<dyn AsyncRead + Send + Unpin + '_>, io::Error> {
        match &self.source {
            KeySource::Text(content) => {
                Ok(Box::new(Cursor::new(content)))
            }
            KeySource::Command(command) => {
                let pathname = &command[0];
                let argv = &command[1..];

                let stdout = Command::new(pathname)
                    .args(argv)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()?
                    .stdout.take().unwrap();

                Ok(Box::new(stdout))
            }
            KeySource::File(path) => {
                Ok(Box::new(File::open(path).await?))
            }
        }
    }

    pub fn dest_dir(&self) -> &Path { &self.dest_dir }
    pub fn user(&self) -> &str { &self.user }
    pub fn group(&self) -> &str { &self.user }
    pub fn permissions(&self) -> &str { &self.permissions }
}

fn validate_unix_name(name: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[a-z][-a-z0-9]*$").unwrap();
    if re.is_match(name) {
        Ok(())
    } else {
        Err(ValidationError::new("Invalid user/group name"))
    }
}

fn validate_dest_dir(dir: &PathBuf) -> Result<(), ValidationError> {
    if dir.has_root() {
        Ok(())
    } else {
        Err(ValidationError::new("Secret key destination directory must be absolute"))
    }
}
