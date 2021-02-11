//! Integration-ish tests

use super::*;

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

        let hive = Hive::new(temp_file.path()).unwrap();

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
        hive.hive.show_trace(true);
        assert!(block_on(hive.deployment_info()).is_ok());
    }

    /// Asserts that the configuration is invalid.
    ///
    /// Note that this _does not_ attempt to evaluate `config.toplevel`.
    pub fn invalid(text: &str) {
        let hive = Self::new(text);
        assert!(block_on(hive.deployment_info()).is_err());
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
