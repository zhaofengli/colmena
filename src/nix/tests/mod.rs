//! Integration-ish tests

use super::*;
use crate::progress::TaskProgress;

use std::collections::HashSet;
use std::hash::Hash;
use std::io::Write;
use std::iter::{FromIterator, Iterator};
use std::ops::Deref;

use tempfile::NamedTempFile;
use tokio_test::block_on;

fn set_eq<T>(a: &[T], b: &[T]) -> bool
where
    T: Eq + Hash,
{
    let a: HashSet<_> = HashSet::from_iter(a);
    let b: HashSet<_> = HashSet::from_iter(b);

    a == b
}

/// An ad-hoc Hive configuration.
struct TempHive {
    hive: Hive,
    _temp_file: NamedTempFile,
}

impl TempHive {
    pub fn new(text: &str) -> Self {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(text.as_bytes()).unwrap();

        let hive_path = HivePath::from_path(temp_file.path());
        let hive = Hive::new(hive_path).unwrap();

        Self {
            hive,
            _temp_file: temp_file,
        }
    }

    /// Asserts that the configuration is valid.
    ///
    /// Note that this _does not_ attempt to evaluate `config.toplevel`.
    pub fn valid(text: &str) {
        let mut hive = Self::new(text);
        hive.hive.set_show_trace(true);
        assert!(block_on(hive.deployment_info()).is_ok());
    }

    /// Asserts that the configuration is invalid.
    ///
    /// Note that this _does not_ attempt to evaluate `config.toplevel`.
    pub fn invalid(text: &str) {
        let hive = Self::new(text);
        assert!(block_on(hive.deployment_info()).is_err());
    }

    /// Asserts that the specified nodes can be fully evaluated.
    pub fn eval_success(text: &str, nodes: Vec<String>) {
        let hive = Self::new(text);
        let progress = TaskProgress::new("tests".to_string(), 5);
        let (profiles, _) = block_on(hive.eval_selected(&nodes, progress));
        assert!(profiles.is_ok());
    }

    /// Asserts that the specified nodes will fail to evaluate.
    pub fn eval_failure(text: &str, nodes: Vec<String>) {
        let hive = Self::new(text);
        let progress = TaskProgress::new("tests".to_string(), 5);
        let (profiles, _) = block_on(hive.eval_selected(&nodes, progress));
        assert!(profiles.is_err());
    }
}

impl Deref for TempHive {
    type Target = Hive;

    fn deref(&self) -> &Hive {
        &self.hive
    }
}

// eval.nix tests

#[test]
fn test_parse_simple() {
    let hive = TempHive::new(r#"
      {
        defaults = { pkgs, ... }: {
          environment.systemPackages = with pkgs; [
            vim wget curl
          ];
          boot.loader.grub.device = "/dev/sda";
          fileSystems."/" = {
            device = "/dev/sda1";
            fsType = "ext4";
          };

          deployment.tags = [ "common-tag" ];
        };

        host-a = { name, nodes, ... }: {
          networking.hostName = name;
          time.timeZone = nodes.host-b.config.time.timeZone;

          deployment.tags = [ "a-tag" ];
        };

        host-b = {
          deployment = {
            targetHost = "somehost.tld";
            targetPort = 1234;
            targetUser = "luser";
          };
          time.timeZone = "America/Los_Angeles";
        };
      }
    "#);
    let nodes = block_on(hive.deployment_info()).unwrap();

    assert!(set_eq(
        &["host-a", "host-b"],
        &nodes.keys().map(String::as_str).collect::<Vec<&str>>(),
    ));

    // host-a
    assert!(set_eq(
        &["common-tag", "a-tag"],
        &nodes["host-a"].tags.iter().map(String::as_str).collect::<Vec<&str>>(),
    ));
    assert_eq!(Some("host-a"), nodes["host-a"].target_host.as_deref());
    assert_eq!(None, nodes["host-a"].target_port);
    assert_eq!("root", &nodes["host-a"].target_user);

    // host-b
    assert!(set_eq(
        &["common-tag"],
        &nodes["host-b"].tags.iter().map(String::as_str).collect::<Vec<&str>>(),
    ));
    assert_eq!(Some("somehost.tld"), nodes["host-b"].target_host.as_deref());
    assert_eq!(Some(1234), nodes["host-b"].target_port);
    assert_eq!("luser", &nodes["host-b"].target_user);
}

#[test]
fn test_parse_flake() {
    let hive_path = HivePath::Flake("path:./src/nix/tests/simple-flake".to_string());
    let mut hive = Hive::new(hive_path).unwrap();

    hive.set_show_trace(true);

    let nodes = block_on(hive.deployment_info()).unwrap();
    assert!(set_eq(
        &["host-a", "host-b"],
        &nodes.keys().map(String::as_str).collect::<Vec<&str>>(),
    ));
}

#[test]
fn test_parse_node_references() {
    TempHive::valid(r#"
      with builtins;
      {
        host-a = { name, nodes, ... }:
          assert name == "host-a";
          assert length (attrNames nodes) == 2;
        {
          time.timeZone = "America/Los_Angeles";
        };
        host-b = { name, nodes, ... }:
          assert name == "host-b";
          assert length (attrNames nodes) == 2;
          assert nodes.host-a.config.time.timeZone == "America/Los_Angeles";
        {};
      }
    "#);
}

#[test]
fn test_parse_unknown_option() {
    TempHive::invalid(r#"
      {
        bad = {
          deployment.noSuchOption = "not kidding";
        };
      }
    "#);
}

#[test]
fn test_parse_key_text() {
    TempHive::valid(r#"
      {
        test = {
          deployment.keys.topSecret = {
            text = "be sure to drink your ovaltine";
          };
        };
      }
    "#);
}

#[test]
fn test_parse_key_command_good() {
    TempHive::valid(r#"
      {
        test = {
          deployment.keys.elohim = {
            keyCommand = [ "eternalize" ];
          };
        };
      }
    "#);
}

#[test]
fn test_parse_key_command_bad() {
    TempHive::invalid(r#"
      {
        test = {
          deployment.keys.elohim = {
            keyCommand = "transcend";
          };
        };
      }
    "#);
}

#[test]
fn test_parse_key_file() {
    TempHive::valid(r#"
      {
        test = {
          deployment.keys.l337hax0rwow = {
            keyFile = "/etc/passwd";
          };
        };
      }
    "#);
}

#[test]
fn test_eval_non_existent_pkg() {
    // Sanity check
    TempHive::eval_failure(r#"
      {
        test = { pkgs, ... }: {
          boot.isContainer = true;
          environment.systemPackages = with pkgs; [ thisPackageDoesNotExist ];
        };
      }
    "#, vec![ "test".to_string() ]);
}

// Nixpkgs config tests

#[test]
fn test_nixpkgs_overlay_meta_nixpkgs() {
    // Only set overlays in meta.nixpkgs
    TempHive::eval_success(r#"
      {
        meta = {
          nixpkgs = import <nixpkgs> {
            overlays = [
              (self: super: { my-coreutils = super.coreutils; })
            ];
          };
        };
        test = { pkgs, ... }: {
          boot.isContainer = true;
          environment.systemPackages = with pkgs; [ my-coreutils ];
        };
      }
    "#, vec![ "test".to_string() ]);
}

#[test]
fn test_nixpkgs_overlay_node_config() {
    // Only set overlays in node config
    TempHive::eval_success(r#"
      {
        test = { pkgs, ... }: {
          boot.isContainer = true;
          nixpkgs.overlays = [
            (self: super: { my-coreutils = super.coreutils; })
          ];
          environment.systemPackages = with pkgs; [ my-coreutils ];
        };
      }
    "#, vec![ "test".to_string() ]);
}

#[test]
fn test_nixpkgs_overlay_both() {
    // Set overlays both in meta.nixpkgs and in node config
    TempHive::eval_success(r#"
      {
        meta = {
          nixpkgs = import <nixpkgs> {
            overlays = [
              (self: super: { meta-coreutils = super.coreutils; })
            ];
          };
        };
        test = { pkgs, ... }: {
          boot.isContainer = true;
          nixpkgs.overlays = [
            (self: super: { node-busybox = super.busybox; })
          ];
          environment.systemPackages = with pkgs; [ meta-coreutils node-busybox ];
        };
      }
    "#, vec![ "test".to_string() ]);
}

#[test]
fn test_nixpkgs_config_meta_nixpkgs() {
    // Set config in meta.nixpkgs
    TempHive::eval_success(r#"
      {
        meta = {
          nixpkgs = import <nixpkgs> {
            config = {
              allowUnfree = true;
            };
          };
        };
        test = { pkgs, ... }: {
          boot.isContainer = assert pkgs.config.allowUnfree; true;
        };
      }
    "#, vec![ "test".to_string() ]);
}

#[test]
fn test_nixpkgs_config_node_config() {
    // Set config in node config
    TempHive::eval_success(r#"
      {
        test = { pkgs, ... }: {
          nixpkgs.config = {
            allowUnfree = true;
          };
          boot.isContainer = assert pkgs.config.allowUnfree; true;
        };
      }
    "#, vec![ "test".to_string() ]);
}

#[test]
fn test_nixpkgs_config_override() {
    // Set same config both in meta.nixpkgs and in node config
    let template = r#"
      {
        meta = {
          nixpkgs = import <nixpkgs> {
            config = {
              allowUnfree = META_VAL;
            };
          };
        };
        test = { pkgs, ... }: {
          nixpkgs.config = {
            allowUnfree = NODE_VAL;
          };
          boot.isContainer = assert pkgs.config.allowUnfree == EXPECTED_VAL; true;
        };
      }
    "#;

    TempHive::eval_success(
        &template
            .replace("META_VAL", "true")
            .replace("NODE_VAL", "false")
            .replace("EXPECTED_VAL", "false"),
        vec![ "test".to_string() ]
    );

    TempHive::eval_success(
        &template
            .replace("META_VAL", "false")
            .replace("NODE_VAL", "true")
            .replace("EXPECTED_VAL", "true"),
        vec![ "test".to_string() ]
    );
}

#[test]
fn test_meta_special_args() {
    TempHive::valid(r#"
      {
        meta.specialArgs = {
          undine = "assimilated";
        };

        borg = { undine, ... }:
          assert undine == "assimilated";
        {
          boot.isContainer = true;
        };
      }
    "#);
}
