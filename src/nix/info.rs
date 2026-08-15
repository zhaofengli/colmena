use std::fmt;
use std::process::Stdio;

use regex::Regex;

use super::{NixCommand, NixFlags};

pub struct NixVersion {
    major: usize,
    minor: usize,
    string: String,
}

impl NixVersion {
    fn parse(string: String) -> Self {
        let re = Regex::new(r" (?P<major>\d+)\.(?P<minor>\d+)").unwrap();
        if let Some(caps) = re.captures(&string) {
            let major = caps.name("major").unwrap().as_str().parse().unwrap();
            let minor = caps.name("minor").unwrap().as_str().parse().unwrap();

            Self {
                major,
                minor,
                string,
            }
        } else {
            Self {
                major: 0,
                minor: 0,
                string: String::from("unknown"),
            }
        }
    }
}

impl fmt::Display for NixVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.major != 0 {
            write!(f, "{}.{}", self.major, self.minor)
        } else {
            write!(f, "{}???", self.string)
        }
    }
}

pub struct NixCheck {
    version: Option<NixVersion>,
    flakes_enabled: bool,
}

impl NixCheck {
    const NO_NIX: Self = Self {
        version: None,
        flakes_enabled: false,
    };

    pub async fn detect(flags: &NixFlags) -> Self {
        // The version probe detects the Nix installation itself, so it
        // deliberately runs without the user-supplied flags: a bogus
        // --option must not make the version appear undetectable. The
        // flakes probe reflects the effective configuration, so the
        // user-supplied flags apply (e.g., experimental-features
        // enabled via --nix-option).
        let (version_cmd, flake_cmd) = tokio::join!(
            NixCommand::nix_instantiate(NixFlags::default())
                .arg("--version")
                .build()
                .output(),
            NixCommand::nix_instantiate(flags.clone())
                .args(["--eval", "-E", "builtins.getFlake"])
                .build()
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        );

        let (Ok(version_output), Ok(flake_status)) = (version_cmd, flake_cmd) else {
            return Self::NO_NIX;
        };

        let version =
            NixVersion::parse(String::from_utf8_lossy(&version_output.stdout).to_string());

        Self {
            version: Some(version),
            flakes_enabled: flake_status.success(),
        }
    }

    pub fn print_version_info(&self) {
        if let Some(v) = &self.version {
            tracing::info!("Nix Version: {}", v);
        } else {
            tracing::info!("Nix Version: Not found");
        }
    }

    pub fn print_flakes_info(&self) {
        if self.version.is_none() {
            tracing::error!("Nix doesn't appear to be installed.");
            return;
        }

        if self.flakes_enabled {
            tracing::info!("The Nix version you are using supports Flakes and it's enabled.");
        } else {
            tracing::warn!("The Nix version you are using supports Flakes but it's disabled.");
            tracing::warn!(
                "Colmena will automatically enable Flakes for its operations, but you should enable it in your Nix configuration:"
            );
            tracing::warn!("    experimental-features = nix-command flakes");
        }
    }
}
