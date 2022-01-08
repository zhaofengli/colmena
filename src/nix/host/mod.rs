use std::collections::HashMap;

use async_trait::async_trait;

use super::{StorePath, Profile, Goal, ColmenaResult, ColmenaError, Key};
use crate::job::JobHandle;

mod ssh;
pub use ssh::Ssh;

mod local;
pub use local::Local;

mod key_uploader;

pub(crate) fn local(nix_options: Vec<String>) -> Box<dyn Host + 'static> {
    Box::new(Local::new(nix_options))
}

#[derive(Copy, Clone, Debug)]
pub enum CopyDirection {
    ToRemote,
    FromRemote,
}

#[derive(Copy, Clone, Debug)]
pub struct CopyOptions {
    include_outputs: bool,
    use_substitutes: bool,
    gzip: bool,
}

impl Default for CopyOptions {
    fn default() -> Self {
        Self {
            include_outputs: true,
            use_substitutes: true,
            gzip: true,
        }
    }
}

impl CopyOptions {
    pub fn include_outputs(mut self, val: bool) -> Self {
        self.include_outputs = val;
        self
    }

    pub fn use_substitutes(mut self, val: bool) -> Self {
        self.use_substitutes = val;
        self
    }

    pub fn gzip(mut self, val: bool) -> Self {
        self.gzip = val;
        self
    }
}

/// A Nix(OS) host.
///
/// The underlying implementation must be Send and Sync.
#[async_trait]
pub trait Host: Send + Sync + std::fmt::Debug {
    /// Sends or receives the specified closure to the host
    ///
    /// The StorePath and its dependent paths will then exist on this host.
    async fn copy_closure(&mut self, closure: &StorePath, direction: CopyDirection, options: CopyOptions) -> ColmenaResult<()>;

    /// Realizes the specified derivation on the host
    ///
    /// The derivation must already exist on the host.
    /// After realization, paths in the Vec<StorePath> will then
    /// exist on the host.
    async fn realize_remote(&mut self, derivation: &StorePath) -> ColmenaResult<Vec<StorePath>>;

    /// Provides a JobHandle to use during operations.
    fn set_job(&mut self, bar: Option<JobHandle>);

    /// Realizes the specified local derivation on the host then retrieves the outputs.
    async fn realize(&mut self, derivation: &StorePath) -> ColmenaResult<Vec<StorePath>> {
        let options = CopyOptions::default()
            .include_outputs(true);

        self.copy_closure(derivation, CopyDirection::ToRemote, options).await?;
        let paths = self.realize_remote(derivation).await?;
        self.copy_closure(derivation, CopyDirection::FromRemote, options).await?;

        Ok(paths)
    }

    /// Pushes and optionally activates a profile to the host.
    async fn deploy(&mut self, profile: &Profile, goal: Goal, copy_options: CopyOptions) -> ColmenaResult<()> {
        self.copy_closure(profile.as_store_path(), CopyDirection::ToRemote, copy_options).await?;

        if goal.requires_activation() {
            self.activate(profile, goal).await?;
        }

        Ok(())
    }

    /// Uploads a set of keys to the host.
    ///
    /// If `require_ownership` is false, then the ownership of a key
    /// will not be applied if the specified user/group does not
    /// exist.
    #[allow(unused_variables)] 
    async fn upload_keys(&mut self, keys: &HashMap<String, Key>, require_ownership: bool) -> ColmenaResult<()> {
        Err(ColmenaError::Unsupported)
    }

    /// Returns the main system profile on the host.
    ///
    /// This may _not_ be the system profile that's currently activated!
    /// It will first try `/nix/var/nix/profiles/system`, falling back
    /// to `/run/current-system` if it doesn't exist.
    async fn get_main_system_profile(&mut self) -> ColmenaResult<StorePath>;

    /// Activates a system profile on the host, if it runs NixOS.
    ///
    /// The profile must already exist on the host. You should probably use deploy instead.
    #[allow(unused_variables)]
    async fn activate(&mut self, profile: &Profile, goal: Goal) -> ColmenaResult<()> {
        Err(ColmenaError::Unsupported)
    }

    /// Runs an arbitrary command on the host.
    #[allow(unused_variables)] 
    async fn run_command(&mut self, command: &[&str]) -> ColmenaResult<()> {
        Err(ColmenaError::Unsupported)
    }
}
