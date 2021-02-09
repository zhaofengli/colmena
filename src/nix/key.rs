use std::path::PathBuf;

use regex::Regex;
use serde::{Serialize, Deserialize};
use validator::{Validate, ValidationError};

#[derive(Debug, Clone, Validate, Serialize, Deserialize)]
pub struct Key {
    pub(crate) text: String,
    #[validate(custom = "validate_dest_dir")]
    #[serde(rename = "destDir")]
    pub(super) dest_dir: PathBuf,
    #[validate(custom = "validate_unix_name")]
    pub(super) user: String,
    #[validate(custom = "validate_unix_name")]
    pub(super) group: String,
    pub(super) permissions: String,
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
