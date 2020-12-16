{ rawHive }:
with builtins;
let
  defaultHive = {
    # Will be set in defaultHiveMeta
    network = {};

    # Like in NixOps, there is a special host named `defaults`
    # containing configurations that will be applied to all
    # hosts.
    defaults = {};
  };

  defaultHiveMeta = {
    name = "hive";
    description = "A Colmena Hive";

    # Can be a path, a lambda, or an initialized Nixpkgs attrset
    nixpkgs = <nixpkgs>;
  };

  # Colmena-specific options
  #
  # Largely compatible with NixOps/Morph.
  deploymentOptions = { name, lib, ... }:
  let
    types = lib.types;
  in {
    options = {
      deployment = {
        targetHost = lib.mkOption {
          description = ''
            The target SSH node for deployment.

            If not specified, the node's attribute name will be used.
          '';
          type = types.str;
          default = name;
        };
        targetUser = lib.mkOption {
          description = ''
            The user to use to log into the remote node.
          '';
          type = types.str;
          default = "root";
        };
        tags = lib.mkOption {
          description = ''
            A list of tags for the node.

            Can be used to select a group of nodes for deployment.
          '';
          type = types.listOf types.str;
          default = [];
        };
      };
    };
  };

  hiveMeta = {
    network = defaultHiveMeta // (if rawHive ? network then rawHive.network else {});
  };
  hive = defaultHive // rawHive // hiveMeta;

  pkgs = let
    pkgConf = hive.network.nixpkgs;
  in if typeOf pkgConf == "path" then
    import pkgConf {}
  else if typeOf pkgConf == "lambda" then
    pkgConf {}
  else if typeOf pkgConf == "set" then
    pkgConf
  else throw ''
    network.nixpkgs must be one of:

    - A path to Nixpkgs (e.g., <nixpkgs>)
    - A Nixpkgs lambda (e.g., import <nixpkgs>)
    - A Nixpkgs attribute set
  '';

  lib = pkgs.lib;
  reservedNames = [ "defaults" "network" "meta" ];

  evalNode = name: config: let
    evalConfig = import (pkgs.path + "/nixos/lib/eval-config.nix");
  in evalConfig {
    system = currentSystem;
    modules = [
      deploymentOptions
      hive.defaults
      config
    ] ++ (import (pkgs.path + "/nixos/modules/module-list.nix"));
    specialArgs = {
      inherit name nodes;
      modulesPath = pkgs.path + "/nixos/modules";
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

  deploymentInfoJson = toJSON (lib.attrsets.mapAttrs (name: eval: eval.config.deployment) nodes);

  toplevel = lib.attrsets.mapAttrs (name: eval: eval.config.system.build.toplevel) nodes;

  buildAll = buildSelected {
    names = nodeNames;
  };
  buildSelected = { names ? null }: let
    # Change in the order of the names should not cause a derivation to be created
    selected = lib.attrsets.filterAttrs (name: _: elem name names) toplevel;
  in derivation rec {
    name = "colmena-${hive.network.name}";
    system = currentSystem;
    json = toJSON (lib.attrsets.mapAttrs (k: v: toString v) selected);
    builder = pkgs.writeScript "${name}.sh" ''
      #!/bin/sh
      echo "$json" > $out
    '';
  };
in {
  inherit nodes deploymentInfoJson toplevel buildAll buildSelected;
}
