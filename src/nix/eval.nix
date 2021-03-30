{ sharedModules, rawHive }:
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

  types = lib.types;

  # Hive-wide options
  metaOptions = { lib, ... }: {
    options = {
      name = lib.mkOption {
        description = ''
          Name of the configuration.
        '';
        type = types.str;
        default = "hive";
      };
      description = lib.mkOption {
        description = ''
          A short description for the configuration.
        '';
        type = types.str;
        default = "A Colmena Hive";
      };
      nixpkgs = lib.mkOption {
        description = ''
          Pinned Nixpkgs. Accepts one of the following:

          - A path to a Nixpkgs checkout
          - The Nixpkgs lambda (e.g., import <nixpkgs>)
          - An initialized Nixpkgs attribute set
        '';
        type = types.unspecified;
        default = <nixpkgs>;
      };
      nodeNixpkgs = lib.mkOption {
        description = ''
          Node-specific Nixpkgs overrides.
        '';
        type = types.attrsOf types.unspecified;
        default = {};
      };
    };
  };

  uncheckedUserMeta =
    if rawHive ? meta && rawHive ? network then
      throw "Only one of `network` and `meta` may be specified. `meta` should be used as `network` is for NixOps compatibility."
    else if rawHive ? meta then rawHive.meta
    else if rawHive ? network then rawHive.network
    else {};

  userMeta = (lib.modules.evalModules {
    modules = [ metaOptions uncheckedUserMeta ];
  }).config;

  # The final hive will always have the meta key instead of network.
  hive = let 
    mergedHive = removeAttrs (defaultHive // rawHive) [ "meta" "network" ];
    meta = {
      meta = userMeta;
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

  pkgs = let
    # Can't rely on the module system yet
    nixpkgsConf = if uncheckedUserMeta ? nixpkgs then uncheckedUserMeta.nixpkgs else <nixpkgs>;
  in mkNixpkgs "meta.nixpkgs" nixpkgsConf;

  lib = pkgs.lib;
  reservedNames = [ "defaults" "network" "meta" ];

  evalNode = name: config: let
    npkgs =
      if hasAttr name hive.meta.nodeNixpkgs
      then mkNixpkgs "meta.nodeNixpkgs.${name}" hive.meta.nodeNixpkgs.${name}
      else pkgs;
    evalConfig = import (npkgs.path + "/nixos/lib/eval-config.nix");

    # Here we need to merge the configurations in meta.nixpkgs
    # and in machine config.
    nixpkgsModule = { config, lib, ... }: {
      nixpkgs.overlays = lib.mkBefore npkgs.overlays;
      nixpkgs.config = lib.mkOptionDefault npkgs.config;

      # The merging of nixpkgs.config seems to be broken.
      # Let's warn the user if not all config attributes set in
      # meta.nixpkgs are overridden.
      warnings = let
        metaKeys = attrNames npkgs.config;
        nodeKeys = [ "doCheckByDefault" "warnings" ] ++ (attrNames config.nixpkgs.config);
        remainingKeys = filter (k: ! elem k nodeKeys) metaKeys;
      in
        lib.optional (length remainingKeys != 0)
        "The following Nixpkgs configuration keys set in meta.nixpkgs will be ignored: ${toString remainingKeys}";
    };
  in evalConfig {
    modules = (attrValues (import sharedModules { inherit lib; }))
      ++ [ nixpkgsModule hive.defaults config ]
      ++ (import (npkgs.path + "/nixos/modules/module-list.nix"));
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
