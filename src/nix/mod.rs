use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::path::Path;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize};
use users::get_current_username;
use validator::{Validate, ValidationError as ValidationErrorType};

use crate::error::{ColmenaResult, ColmenaError};

pub mod host;
pub use host::{Host, CopyDirection, CopyOptions};
use host::Ssh;

pub mod hive;
pub use hive::{Hive, HivePath};

pub mod store;
pub use store::{StorePath, StoreDerivation, BuildResult};

pub mod key;
pub use key::Key;

pub mod profile;
pub use profile::{Profile, ProfileDerivation};

pub mod deployment;
pub use deployment::Goal;

pub mod info;
pub use info::NixCheck;

pub mod flake;
pub use flake::Flake;

pub mod node_filter;
pub use node_filter::NodeFilter;

/// Path to the main system profile.
pub const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

/// Path to the system profile that's currently active.
pub const CURRENT_PROFILE: &str = "/run/current-system";

/// A node's attribute name.
#[derive(Serialize, Deserialize, Clone, Debug, Hash, Eq, PartialEq)]
#[serde(transparent)]
pub struct NodeName(
    #[serde(deserialize_with = "NodeName::deserialize")]
    String
);

#[derive(Debug, Clone, Validate, Deserialize)]
pub struct NodeConfig {
    #[serde(rename = "targetHost")]
    target_host: Option<String>,

    #[serde(rename = "targetUser")]
    target_user: Option<String>,

    #[serde(rename = "targetPort")]
    target_port: Option<u16>,

    #[serde(rename = "allowLocalDeployment")]
    allow_local_deployment: bool,

    #[serde(rename = "buildOnTarget")]
    build_on_target: bool,

    tags: Vec<String>,

    #[serde(rename = "replaceUnknownProfiles")]
    replace_unknown_profiles: bool,

    #[serde(rename = "privilegeEscalationCommand")]
    privilege_escalation_command: Vec<String>,

    #[validate(custom = "validate_keys")]
    keys: HashMap<String, Key>,
}

impl NodeName {
    /// Returns the string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Creates a NodeName from a String.
    pub fn new(name: String) -> ColmenaResult<Self> {
        let validated = Self::validate(name)?;
        Ok(Self(validated))
    }

    /// Deserializes a potentially-invalid node name.
    fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
        where D: Deserializer<'de>
    {
        use de::Error;
        String::deserialize(deserializer)
            .and_then(|s| {
                Self::validate(s).map_err(|e| Error::custom(e.to_string()))
            })
    }

    fn validate(s: String) -> ColmenaResult<String> {
        // FIXME: Elaborate
        if s.is_empty() {
            return Err(ColmenaError::EmptyNodeName);
        }

        Ok(s)
    }
}

impl Deref for NodeName {
    type Target = str;

    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

impl NodeConfig {
    pub fn tags(&self) -> &[String] { &self.tags }
    pub fn allows_local_deployment(&self) -> bool { self.allow_local_deployment }

    pub fn build_on_target(&self) -> bool { self.build_on_target }
    pub fn set_build_on_target(&mut self, enable: bool) {
        self.build_on_target = enable;
    }

    pub fn to_ssh_host(&self) -> Option<Ssh> {
        self.target_host.as_ref().map(|target_host| {
            let username =
                match &self.target_user {
                    Some(uname) => uname.clone(),
                    None => get_current_username().unwrap().into_string().unwrap(),
                };
            let mut host = Ssh::new(username, target_host.clone());
            host.set_privilege_escalation_command(self.privilege_escalation_command.clone());

            if let Some(target_port) = self.target_port {
                host.set_port(target_port);
            }

            host
        })
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

        if path.components().count() != 1 {
            return Err(ValidationErrorType::new("Secret key name cannot contain path separators"));
        }
    }
    Ok(())
}
