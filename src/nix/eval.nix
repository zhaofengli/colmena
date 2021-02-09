{ rawHive }:
with builtins;
let
  defaultHive = {
    # Will be set in defaultHiveMeta
    meta = {};

    # Like in NixOps, there is a special host named `defaults`
    # containing configurations that will be applied to all
    # hosts.
    defaults = {};
  };

  defaultMeta = {
    name = "hive";
    description = "A Colmena Hive";

    # Can be a path, a lambda, or an initialized Nixpkgs attrset
    nixpkgs = <nixpkgs>;

    # Per-node Nixpkgs overrides
    # Keys are hostnames.
    nodeNixpkgs = {};
  };

  types = lib.types;

  # Colmena-specific options
  #
  # Largely compatible with NixOps/Morph.
  deploymentOptions = { name, lib, ... }: {
    options = {
      deployment = {
        targetHost = lib.mkOption {
          description = ''
            The target SSH node for deployment.

            By default, the node's attribute name will be used.
            If set to null, only local deployment will be supported.
          '';
          type = types.nullOr types.str;
          default = name;
        };
        targetUser = lib.mkOption {
          description = ''
            The user to use to log into the remote node.
          '';
          type = types.str;
          default = "root";
        };
        allowLocalDeployment = lib.mkOption {
          description = ''
            Allow the configuration to be applied locally on the host running
            Colmena.

            For local deployment to work, all of the following must be true:
            - The node must be running NixOS.
            - The node must have deployment.allowLocalDeployment set to true.
            - The node's networking.hostName must match the hostname.

            To apply the configurations locally, run `colmena apply-local`.
            You can also set deployment.targetHost to null if the nost is not
            accessible over SSH (only local deployment will be possible).
          '';
          type = types.bool;
          default = false;
        };
        tags = lib.mkOption {
          description = ''
            A list of tags for the node.

            Can be used to select a group of nodes for deployment.
          '';
          type = types.listOf types.str;
          default = [];
        };
        keys = lib.mkOption {
          description = ''
            A set of secrets to be deployed to the node.

            Secrets are transferred to the node out-of-band and
            never ends up in the Nix store.
          '';
          type = types.attrsOf keyType;
          default = {};
        };
      };
    };
  };

  keyType = types.submodule {
    options = {
      text = lib.mkOption {
        description = ''
          Content of the key.
        '';
        type = types.str;
      };
      destDir = lib.mkOption {
        description = ''
          Destination directory on the host.
        '';
        default = "/run/keys";
        type = types.str;
      };
      user = lib.mkOption {
        description = ''
          The group that will own the file.
        '';
        default = "root";
        type = types.str;
      };
      group = lib.mkOption {
        description = ''
          The group that will own the file.
        '';
        default = "root";
        type = types.str;
      };
      permissions = lib.mkOption {
        description = ''
          Permissions to set for the file.
        '';
        default = "0600";
        type = types.str;
      };
    };
  };

  userMeta =
    if rawHive ? meta && rawHive ? network then
      throw "Only one of `network` and `meta` may be specified. `meta` should be used as `network` is for NixOps compatibility."
    else if rawHive ? meta then rawHive.meta
    else if rawHive ? network then rawHive.network
    else {};

  # The final hive will always have the meta key instead of network.
  hive = let 
    mergedHive = removeAttrs (defaultHive // rawHive) [ "meta" "network" ];
    meta = {
      meta = lib.recursiveUpdate defaultMeta userMeta;
    };
  in mergedHive // meta;

  mkNixpkgs = configName: pkgConf:
    if typeOf pkgConf == "path" then
      # The referenced file might return an initialized Nixpkgs attribute set directly
      mkNixpkgs configName (import pkgConf)
    else if typeOf pkgConf == "lambda" then
      pkgConf {}
    else if typeOf pkgConf == "set" then
      pkgConf
    else throw ''
      ${configName} must be one of:

      - A path to Nixpkgs (e.g., <nixpkgs>)
      - A Nixpkgs lambda (e.g., import <nixpkgs>)
      - A Nixpkgs attribute set
    '';

  pkgs = mkNixpkgs "meta.nixpkgs" (defaultMeta // userMeta).nixpkgs;
  lib = pkgs.lib;
  reservedNames = [ "defaults" "network" "meta" ];

  evalNode = name: config: let
    npkgs =
      if hasAttr name hive.meta.nodeNixpkgs
      then mkNixpkgs "meta.nodeNixpkgs.${name}" hive.meta.nodeNixpkgs.${name}
      else pkgs;
    evalConfig = import (npkgs.path + "/nixos/lib/eval-config.nix");
  in evalConfig {
    modules = [
      deploymentOptions
      hive.defaults
      config
    ] ++ (import (npkgs.path + "/nixos/modules/module-list.nix"));
    specialArgs = {
      inherit name nodes;
      modulesPath = npkgs.path + "/nixos/modules";
    };
  };

  nodeNames = filter (name: ! elem name reservedNames) (attrNames hive);

  # Exported attributes
  #
  # Functions are intended to be called with `nix-instantiate --eval --json`

  nodes = listToAttrs (map (name: {
    inherit name;
    value = evalNode name hive.${name};
  }) nodeNames);

  deploymentConfigJson = toJSON (lib.attrsets.mapAttrs (name: eval: eval.config.deployment) nodes);

  toplevel = lib.attrsets.mapAttrs (name: eval: eval.config.system.build.toplevel) nodes;

  buildAll = buildSelected {
    names = nodeNames;
  };
  buildSelected = { names ? null }: let
    # Change in the order of the names should not cause a derivation to be created
    selected = lib.attrsets.filterAttrs (name: _: elem name names) toplevel;
  in derivation rec {
    name = "colmena-${hive.meta.name}";
    system = currentSystem;
    json = toJSON (lib.attrsets.mapAttrs (k: v: toString v) selected);
    builder = pkgs.writeScript "${name}.sh" ''
      #!/bin/sh
      echo "$json" > $out
    '';
  };

  introspect = function: function {
    inherit pkgs lib nodes;
  };
in {
  inherit nodes deploymentConfigJson toplevel buildAll buildSelected introspect;
}
