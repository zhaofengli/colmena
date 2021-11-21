//! Deployment options.

use crate::nix::CopyOptions;

/// Options for a deployment.
#[derive(Clone, Debug)]
pub struct Options {
    /// Whether to use binary caches when copying closures to remote hosts.
    pub(super) substituters_push: bool,

    /// Whether to use gzip when copying closures to remote hosts.
    pub(super) gzip: bool,

    /// Whether to upload keys when deploying.
    pub(super) upload_keys: bool,

    /// Whether to create GC roots for node profiles.
    ///
    /// If true, .gc_roots will be created under the hive's context
    /// directory if it exists.
    pub(super) create_gc_roots: bool,

    /// Ignore the node-level `deployment.replaceUnknownProfiles` option.
    pub(super) force_replace_unknown_profiles: bool,
}

impl Options {
    pub fn set_substituters_push(&mut self, value: bool) {
        self.substituters_push = value;
    }

    pub fn set_gzip(&mut self, value: bool) {
        self.gzip = value;
    }

    pub fn set_upload_keys(&mut self, enable: bool) {
        self.upload_keys = enable;
    }

    pub fn set_create_gc_roots(&mut self, enable: bool) {
        self.create_gc_roots = enable;
    }

    pub fn set_force_replace_unknown_profiles(&mut self, enable: bool) {
        self.force_replace_unknown_profiles = enable;
    }

    pub fn to_copy_options(&self) -> CopyOptions {
        let options = CopyOptions::default();

        options
            .use_substitutes(self.substituters_push)
            .gzip(self.gzip)
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            substituters_push: true,
            gzip: true,
            upload_keys: true,
            create_gc_roots: false,
            force_replace_unknown_profiles: false,
        }
    }
}
