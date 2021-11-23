//! Deployment goals.

/// The goal of a deployment.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Goal {
    /// Build the configurations only.
    Build,

    /// Push the closures only.
    Push,

    /// Make the configuration the boot default and activate now.
    Switch,

    /// Make the configuration the boot default.
    Boot,

    /// Activate the configuration, but don't make it the boot default.
    Test,

    /// Show what would be done if this configuration were activated.
    DryActivate,

    /// Only upload keys.
    UploadKeys,
}

impl Goal {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "build" => Some(Self::Build),
            "push" => Some(Self::Push),
            "switch" => Some(Self::Switch),
            "boot" => Some(Self::Boot),
            "test" => Some(Self::Test),
            "dry-activate" => Some(Self::DryActivate),
            "keys" => Some(Self::UploadKeys),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'static str> {
        use Goal::*;
        match self {
            Build => None,
            Push => None,
            Switch => Some("switch"),
            Boot => Some("boot"),
            Test => Some("test"),
            DryActivate => Some("dry-activate"),
            UploadKeys => Some("keys"),
        }
    }

    pub fn success_str(&self) -> &'static str {
        use Goal::*;
        match self {
            Build => "Configuration built",
            Push => "Pushed",
            Switch => "Activation successful",
            Boot => "Will be activated next boot",
            Test => "Activation successful (test)",
            DryActivate => "Dry activation successful",
            UploadKeys => "Uploaded keys",
        }
    }

    pub fn should_switch_profile(&self) -> bool {
        use Goal::*;
        matches!(self, Boot | Switch)
    }

    pub fn requires_activation(&self) -> bool {
        use Goal::*;
        !matches!(self, Build | UploadKeys | Push)
    }

    pub fn requires_target_host(&self) -> bool {
        use Goal::*;
        !matches!(self, Build)
    }
}
