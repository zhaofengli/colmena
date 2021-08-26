use std::collections::HashMap;

use async_trait::async_trait;

use super::{StorePath, Profile, Goal, NixResult, NixError, Key};
use crate::progress::TaskProgress;

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
    async fn copy_closure(&mut self, closure: &StorePath, direction: CopyDirection, options: CopyOptions) -> NixResult<()>;

    /// Realizes the specified derivation on the host
    ///
    /// The derivation must already exist on the host.
    /// After realization, paths in the Vec<StorePath> will then
    /// exist on the host.
    async fn realize_remote(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>>;

    /// Realizes the specified local derivation on the host then retrieves the outputs.
    async fn realize(&mut self, derivation: &StorePath) -> NixResult<Vec<StorePath>> {
        let options = CopyOptions::default();

        self.copy_closure(derivation, CopyDirection::ToRemote, options.include_outputs(false)).await?;
        let paths = self.realize_remote(derivation).await?;
        self.copy_closure(derivation, CopyDirection::FromRemote, options.include_outputs(true)).await?;

        Ok(paths)
    }

    /// Pushes and optionally activates a profile to the host.
    async fn deploy(&mut self, profile: &Profile, goal: Goal, copy_options: CopyOptions) -> NixResult<()> {
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
    async fn upload_keys(&mut self, keys: &HashMap<String, Key>, require_ownership: bool) -> NixResult<()> {
        Err(NixError::Unsupported)
    }

    /// Check if the active profile is known to the host running Colmena
    async fn active_derivation_known(&mut self) -> NixResult<bool>;

    #[allow(unused_variables)]
    /// Activates a system profile on the host, if it runs NixOS.
    ///
    /// The profile must already exist on the host. You should probably use deploy instead.
    async fn activate(&mut self, profile: &Profile, goal: Goal) -> NixResult<()> {
        Err(NixError::Unsupported)
    }

    #[allow(unused_variables)] 
    /// Provides a TaskProgress to use during operations.
    fn set_progress_bar(&mut self, bar: TaskProgress) {
    }

    /// Dumps human-readable unstructured log messages related to the host.
    async fn dump_logs(&self) -> Option<&str> {
        None
    }
}
