use std::{
    io::{self, Cursor},
    path::PathBuf,
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncRead};
use validator::{Validate, ValidationError};

#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
pub struct Key {
    pub(crate) text: Option<String>,
    #[serde(rename = "keyFile")]
    pub(crate) key_file: Option<String>,
    #[validate(custom = "validate_dest_dir")]
    #[serde(rename = "destDir")]
    pub(super) dest_dir: PathBuf,
    #[validate(custom = "validate_unix_name")]
    pub(super) user: String,
    #[validate(custom = "validate_unix_name")]
    pub(super) group: String,
    pub(super) permissions: String,
}

impl Key {
    pub(crate) async fn reader(&'_ self,) -> Result<Box<dyn AsyncRead + Send + Unpin + '_>, io::Error> {
        if let Some(ref t) = self.text {
            Ok(Box::new(Cursor::new(t)))
        } else if let Some(ref p) = self.key_file {
            Ok(Box::new(File::open(p).await?))
        } else {
            unreachable!("Neither `text` nor `keyFile` set. This should have been validated by Nix assertions.");
        }
    }
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
