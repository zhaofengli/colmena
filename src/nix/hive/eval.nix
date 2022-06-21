{ rawHive ? null               # Colmena Hive attrset
, flakeUri ? null              # Nix Flake URI with `outputs.colmena`
, hermetic ? flakeUri != null  # Whether we are allowed to use <nixpkgs>
, colmenaOptions
, colmenaModules
}:
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


  uncheckedHive = let
    flakeToHive = flakeUri: let
      flake = builtins.getFlake flakeUri;
      hive = if flake.outputs ? colmena then flake.outputs.colmena else throw "Flake must define outputs.colmena.";
    in hive;

    rawToHive = rawHive:
      if typeOf rawHive == "lambda" || rawHive ? __functor then rawHive {}
      else if typeOf rawHive == "set" then rawHive
      else throw "The config must evaluate to an attribute set.";
  in
    if rawHive != null then rawToHive rawHive
    else if flakeUri != null then flakeToHive flakeUri
    else throw "Either an attribute set or a flake URI must be specified.";

  uncheckedUserMeta =
    if uncheckedHive ? meta && uncheckedHive ? network then
      throw "Only one of `network` and `meta` may be specified. `meta` should be used as `network` is for NixOps compatibility."
    else if uncheckedHive ? meta then uncheckedHive.meta
    else if uncheckedHive ? network then uncheckedHive.network
    else {};

  # The final hive will always have the meta key instead of network.
  hive = let
    userMeta = (lib.modules.evalModules {
      modules = [ colmenaOptions.metaOptions uncheckedUserMeta ];
    }).config;

    mergedHive = removeAttrs (defaultHive // uncheckedHive) [ "meta" "network" ];
    meta = {
      meta =
        if !hermetic && userMeta.nixpkgs == null
        then userMeta // { nixpkgs = <nixpkgs>; }
        else userMeta;
    };
  in mergedHive // meta;

  configsFor = node: let
    nodeConfig = hive.${node};
  in
    assert lib.assertMsg (!elem node reservedNames) "\"${node}\" is a reserved name and cannot be used as the name of a node";
    if typeOf nodeConfig == "list" then nodeConfig
    else [ nodeConfig ];

  mkNixpkgs = configName: pkgConf: let
    uninitializedError = typ: ''
      Passing ${typ} as ${configName} is no longer accepted with Flakes.
      Please initialize Nixpkgs like the following:

      {
        # ...
        outputs = { nixpkgs, ... }: {
          colmena = {
            ${configName} = import nixpkgs {
              system = "${currentSystem}";
              overlays = [];
            };
          };
        };
      }
    '';
  in
    if typeOf pkgConf == "path" || (typeOf pkgConf == "set" && pkgConf ? outPath) then
      if hermetic then throw (uninitializedError "a path to Nixpkgs")
      # The referenced file might return an initialized Nixpkgs attribute set directly
      else mkNixpkgs configName (import pkgConf)
    else if typeOf pkgConf == "lambda" then
      if hermetic then throw (uninitializedError "a Nixpkgs lambda")
      else pkgConf { overlays = []; }
    else if typeOf pkgConf == "set" then
      if pkgConf ? outputs then throw (uninitializedError "an uninitialized Nixpkgs input")
      else pkgConf
    else throw ''
      ${configName} must be one of:

      - A path to Nixpkgs (e.g., <nixpkgs>)
      - A Nixpkgs lambda (e.g., import <nixpkgs>)
      - A Nixpkgs attribute set
    '';

  nixpkgs = let
    # Can't rely on the module system yet
    nixpkgsConf =
      if uncheckedUserMeta ? nixpkgs then uncheckedUserMeta.nixpkgs
      else if hermetic then throw "meta.nixpkgs must be specified in hermetic mode."
      else <nixpkgs>;
  in mkNixpkgs "meta.nixpkgs" nixpkgsConf;

  lib = nixpkgs.lib;
  reservedNames = [ "defaults" "network" "meta" ];

  evalNode = name: configs: let
    npkgs =
      if hasAttr name hive.meta.nodeNixpkgs
      then mkNixpkgs "meta.nodeNixpkgs.${name}" hive.meta.nodeNixpkgs.${name}
      else nixpkgs;
    evalConfig = import (npkgs.path + "/nixos/lib/eval-config.nix");

    # Here we need to merge the configurations in meta.nixpkgs
    # and in machine config.
    nixpkgsModule = { config, lib, ... }: let
      hasTypedConfig = lib.versionAtLeast lib.version "22.11pre";
    in {
      nixpkgs.overlays = lib.mkBefore npkgs.overlays;
      nixpkgs.config = if hasTypedConfig then lib.mkBefore npkgs.config else lib.mkOptionDefault npkgs.config;

      warnings = let
        # Before 22.11, most config keys were untyped thus the merging
        # was broken. Let's warn the user if not all config attributes
        # set in meta.nixpkgs are overridden.
        metaKeys = attrNames npkgs.config;
        nodeKeys = [ "doCheckByDefault" "warnings" "allowAliases" ] ++ (attrNames config.nixpkgs.config);
        remainingKeys = filter (k: ! elem k nodeKeys) metaKeys;
      in
        lib.optional (!hasTypedConfig && length remainingKeys != 0)
        "The following Nixpkgs configuration keys set in meta.nixpkgs will be ignored: ${toString remainingKeys}";
    };
  in evalConfig {
    inherit (npkgs) system;

    modules = [
      nixpkgsModule
      colmenaModules.assertionModule
      colmenaModules.keyChownModule
      colmenaModules.keyServiceModule
      colmenaOptions.deploymentOptions
      hive.defaults
    ] ++ configs;
    specialArgs = hive.meta.specialArgs // {
      inherit name;
      nodes = uncheckedNodes;
    };
  };

  nodeNames = filter (name: ! elem name reservedNames) (attrNames hive);

  # Used as the `nodes` argument in modules. We skip recursive type checking
  # for performance.
  uncheckedNodes = listToAttrs (map (name: let
    configs = [
      {
        _module.check = false;
      }
    ] ++ configsFor name;
  in {
    inherit name;
    value = evalNode name configs;
  }) nodeNames);

  # Exported attributes
  #
  # Functions are intended to be called with `nix-instantiate --eval --json`

  nodes = listToAttrs (map (name: {
    inherit name;
    value = evalNode name (configsFor name);
  }) nodeNames);

  toplevel = lib.mapAttrs (name: eval: eval.config.system.build.toplevel) nodes;

  deploymentConfig = lib.mapAttrs (name: eval: eval.config.deployment) nodes;

  deploymentConfigSelected = names:
    listToAttrs (map (name: { inherit name; value = nodes.${name}.config.deployment; }) names);

  evalAll = evalSelected nodeNames;
  evalSelected = names: let
    selected = lib.filterAttrs (name: _: elem name names) toplevel;
  in selected;
  evalSelectedDrvPaths = names: lib.mapAttrs (k: v: v.drvPath) (evalSelected names);

  introspect = function: function {
    inherit lib;
    pkgs = nixpkgs;
    nodes = uncheckedNodes;
  };

  suppressModuleArgsDocs = { lib, ... }: {
    options = {
      _module.args = lib.mkOption {
        internal = true;
      };
    };
  };

  # Add required config Key here since we don't want to eval nixpkgs
  metaConfigKeys = [
    "name" "description"
    "machinesFile"
    "allowApplyAll"
  ];

  metaConfig = lib.filterAttrs (n: v: elem n metaConfigKeys) hive.meta;
in {
  inherit
    nodes toplevel
    deploymentConfig deploymentConfigSelected
    evalAll evalSelected evalSelectedDrvPaths introspect
    metaConfig;

  meta = hive.meta;

  nixosModules = { inherit (colmenaOptions) deploymentOptions; };

  docs = {
    deploymentOptions = pkgs: let
      eval = pkgs.lib.evalModules {
        modules = [ colmenaOptions.deploymentOptions suppressModuleArgsDocs ];
        specialArgs = {
          name = "nixos";
          nodes = {};
        };
      };
    in eval.options;

    metaOptions = pkgs: let
      eval = pkgs.lib.evalModules {
        modules = [ colmenaOptions.metaOptions suppressModuleArgsDocs ];
      };
    in eval.options;
  };
}
