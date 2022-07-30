//! Static files required to evaluate a Hive configuation.
//!
//! We embed Nix expressions (eval.nix, options.nix, modules.nix) as well as
//! as the auto-rollback script (auto-rollback.sh) into the resulting binary
//! to ease distribution. The files are written to a temporary path when
//! we need to use them.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use tempfile::TempDir;

use super::HivePath;

const EVAL_NIX: &[u8] = include_bytes!("eval.nix");
const OPTIONS_NIX: &[u8] = include_bytes!("options.nix");
const MODULES_NIX: &[u8] = include_bytes!("modules.nix");

/// Static files required to evaluate a Hive configuration.
#[derive(Debug)]
pub(super) struct Assets {
    /// Temporary directory holding the files.
    temp_dir: TempDir,
}

impl Assets {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();

        create_file(&temp_dir, "eval.nix", false, EVAL_NIX);
        create_file(&temp_dir, "options.nix", false, OPTIONS_NIX);
        create_file(&temp_dir, "modules.nix", false, MODULES_NIX);

        Self { temp_dir }
    }

    /// Returns the base expression from which the evaluated Hive can be used.
    pub fn get_base_expression(&self, hive_path: &HivePath) -> String {
        match hive_path {
            HivePath::Legacy(path) => {
                format!(
                    "with builtins; let eval = import {eval_nix}; hive = eval {{ rawHive = import {path}; colmenaOptions = import {options_nix}; colmenaModules = import {modules_nix}; }}; in ",
                    path = path.to_str().unwrap(),
                    eval_nix = self.get_path("eval.nix"),
                    options_nix = self.get_path("options.nix"),
                    modules_nix = self.get_path("modules.nix"),
                )
            }
            HivePath::Flake(flake) => {
                format!(
                    "with builtins; let eval = import {eval_nix}; hive = eval {{ flakeUri = \"{flake_uri}\"; colmenaOptions = import {options_nix}; colmenaModules = import {modules_nix}; }}; in ",
                    flake_uri = flake.uri(),
                    eval_nix = self.get_path("eval.nix"),
                    options_nix = self.get_path("options.nix"),
                    modules_nix = self.get_path("modules.nix"),
                )
            }
        }
    }

    fn get_path(&self, name: &str) -> String {
        self.temp_dir
            .path()
            .join(name)
            .to_str()
            .unwrap()
            .to_string()
    }
}

fn create_file(base: &TempDir, name: &str, executable: bool, contents: &[u8]) {
    let mode = if executable { 0o700 } else { 0o600 };
    let path = base.path().join(name);
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)
        .unwrap();

    f.write_all(contents).unwrap();
}
