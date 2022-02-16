{ rawHive ? null               # Colmena Hive attrset
, flakeUri ? null              # Nix Flake URI with `outputs.colmena`
, hermetic ? flakeUri != null  # Whether we are allowed to use <nixpkgs>
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

  # Hive-wide options
  metaOptions = { lib, ... }: let
    inherit (lib) types;
  in {
    options = {
      name = lib.mkOption {
        description = ''
          The name of the configuration.
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
          The pinned Nixpkgs package set. Accepts one of the following:

          - A path to a Nixpkgs checkout
          - The Nixpkgs lambda (e.g., import <nixpkgs>)
          - An initialized Nixpkgs attribute set

          This option must be specified when using Flakes.
        '';
        type = types.unspecified;
        default = if !hermetic then <nixpkgs> else null;
      };
      nodeNixpkgs = lib.mkOption {
        description = ''
          Node-specific Nixpkgs pins.
        '';
        type = types.attrsOf types.unspecified;
        default = {};
      };
      machinesFile = lib.mkOption {
        description = ''
          Use the machines listed in this file when building this hive configuration.

          If your Colmena host has nix configured to allow for remote builds
          (for nix-daemon, your user being included in trusted-users)
          you can set a machines file that will be passed to the underlying
          nix-store command during derivation realization as a builders option.
          For example, if you support multiple orginizations each with their own
          build machine(s) you can ensure that builds only take place on your
          local machine and/or the machines specified in this file.

          See https://nixos.org/manual/nix/stable/#chap-distributed-builds
          for the machine specification format.

          This option is ignored when builds are initiated on the remote nodes
          themselves via `deployment.buildOnTarget` or `--build-on-target`. To
          still use the Nix distributed build functionality, configure the
          builders on the target nodes with `nix.buildMachines`.
        '';
        default = null;
        apply = value: if value == null then null else toString value;
        type = types.nullOr types.path;
      };
      specialArgs = lib.mkOption {
        description = ''
          A set of special arguments to be passed to NixOS modules.

          This will be merged into the `specialArgs` used to evaluate
          the NixOS configurations.
        '';
        default = {};
        type = types.attrsOf types.unspecified;
      };
    };
  };

  # Colmena-specific options
  #
  # Largely compatible with NixOps/Morph.
  deploymentOptions = { name, lib, ... }: let
    inherit (lib) types;
  in {
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
        targetPort = lib.mkOption {
          description = ''
            The target SSH port for deployment.

            By default, the port is the standard port (22) or taken
            from your ssh_config.
          '';
          type = types.nullOr types.ints.unsigned;
          default = null;
        };
        targetUser = lib.mkOption {
          description = ''
            The user to use to log into the remote node. If null, login as the
            current user.
          '';
          type = types.nullOr types.str;
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
        buildOnTarget = lib.mkOption {
          description = ''
            Whether to build the system profiles on the target node itself.

            When enabled, Colmena will copy the derivation to the target
            node and initiate the build there. This avoids copying back the
            build results involved with the native distributed build
            feature. Furthermore, the `build` goal will be equivalent to
            the `push` goal. Since builds happen on the target node, the
            results are automatically "pushed" and won't exist in the local
            Nix store.

            You can temporarily override per-node settings by passing
            `--build-on-target` (enable for all nodes) or
            `--no-build-on-target` (disable for all nodes) on the command
            line.
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
          type = types.attrsOf (types.submodule keyType);
          default = {};
        };
        replaceUnknownProfiles = lib.mkOption {
          description = ''
            Allow a configuration to be applied to a host running a profile we
            have no knowledge of. By setting this option to false, you reduce
            the likelyhood of rolling back changes made via another Colmena user.

            Unknown profiles are usually the result of either:
            - The node had a profile applied, locally or by another Colmena.
            - The host running Colmena garbage-collecting the profile.

            To force profile replacement on all targeted nodes during apply,
            use the flag `--force-replace-unknown-profiles`.
          '';
          type = types.bool;
          default = true;
        };
        privilegeEscalationCommand = lib.mkOption {
          description = ''
            Command to use to elevate privileges when activating the new profiles on SSH hosts.

            This is used on SSH hosts when `deployment.targetUser` is not `root`.
            The user must be allowed to use the command non-interactively.
          '';
          type = types.listOf types.str;
          default = [ "sudo" "-H" "--" ];
        };
      };
    };
  };

  keyType = { lib, name, config, ... }: let
    inherit (lib) types;
  in {
    options = {
      name = lib.mkOption {
        description = ''
          File name of the key.
        '';
        default = name;
        type = types.str;
      };
      text = lib.mkOption {
        description = ''
          Content of the key.
          One of `text`, `keyCommand` and `keyFile` must be set.
        '';
        default = null;
        type = types.nullOr types.str;
      };
      keyFile = lib.mkOption {
        description = ''
          Path of the local file to read the key from.
          One of `text`, `keyCommand` and `keyFile` must be set.
        '';
        default = null;
        apply = value: if value == null then null else toString value;
        type = types.nullOr types.path;
      };
      keyCommand = lib.mkOption {
        description = ''
          Command to run to generate the key.
          One of `text`, `keyCommand` and `keyFile` must be set.
        '';
        default = null;
        type = let
          nonEmptyList = types.addCheck (types.listOf types.str) (l: length l > 0);
        in types.nullOr nonEmptyList;
      };
      destDir = lib.mkOption {
        description = ''
          Destination directory on the host.
        '';
        default = "/run/keys";
        type = types.path;
      };
      path = lib.mkOption {
        description = ''
          Full path to the destination.
        '';
        default = "${config.destDir}/${config.name}";
        type = types.path;
        internal = true;
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
      uploadAt = lib.mkOption {
        description = ''
          When to upload the keys.

          - pre-activation (default): Upload the keys before activating the new system profile.
          - post-activation: Upload the keys after successfully activating the new system profile.

          For `colmena upload-keys`, all keys are uploaded at the same time regardless of the configuration here.
        '';
        default = "pre-activation";
        type = types.enum [ "pre-activation" "post-activation" ];
      };
    };
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
      modules = [ metaOptions uncheckedUserMeta ];
    }).config;

    mergedHive = removeAttrs (defaultHive // uncheckedHive) [ "meta" "network" ];
    meta = {
      meta = userMeta;
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
            };
          };
        };
      }
    '';
  in
    if typeOf pkgConf == "path" then
      if hermetic then throw (uninitializedError "a path to Nixpkgs")
      # The referenced file might return an initialized Nixpkgs attribute set directly
      else mkNixpkgs configName (import pkgConf)
    else if typeOf pkgConf == "lambda" then
      if hermetic then throw (uninitializedError "a Nixpkgs lambda")
      else pkgConf {}
    else if typeOf pkgConf == "set" then
      if pkgConf ? outputs then throw (uninitializedError "an uninitialized Nixpkgs input")
      else pkgConf
    else throw ''
      ${configName} must be one of:

      - A path to Nixpkgs (e.g., <nixpkgs>)
      - A Nixpkgs lambda (e.g., import <nixpkgs>)
      - A Nixpkgs attribute set
    '';

  pkgs = let
    # Can't rely on the module system yet
    nixpkgsConf =
      if uncheckedUserMeta ? nixpkgs then uncheckedUserMeta.nixpkgs
      else if hermetic then throw "meta.nixpkgs must be specified in hermetic mode."
      else <nixpkgs>;
  in mkNixpkgs "meta.nixpkgs" nixpkgsConf;

  lib = pkgs.lib;
  reservedNames = [ "defaults" "network" "meta" ];

  evalNode = name: configs: let
    npkgs =
      if hasAttr name hive.meta.nodeNixpkgs
      then mkNixpkgs "meta.nodeNixpkgs.${name}" hive.meta.nodeNixpkgs.${name}
      else pkgs;
    evalConfig = import (npkgs.path + "/nixos/lib/eval-config.nix");
    assertionModule = { config, ... }: {
      assertions = lib.mapAttrsToList (key: opts: let
        nonNulls = l: filter (x: x != null) l;
      in {
        assertion = length (nonNulls [opts.text opts.keyCommand opts.keyFile]) == 1;
        message =
          let prefix = "${name}.deployment.keys.${key}";
          in "Exactly one of `${prefix}.text`, `${prefix}.keyCommand` and `${prefix}.keyFile` must be set.";
        }) config.deployment.keys;
    };

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

    # Change the ownership of all keys uploaded pre-activation
    #
    # This is built as part of the system profile.
    # We must be careful not to access `text` / `keyCommand` / `keyFile` here
    keyChownModule = { lib, config, ... }: let
      preActivationKeys = lib.filterAttrs (name: key: key.uploadAt == "pre-activation") config.deployment.keys;
      scriptDeps = if config.system.activationScripts ? groups then [ "groups" ] else [ "users" ];

      commands = lib.mapAttrsToList (name: key: let
        keyPath = "${key.destDir}/${name}";
      in ''
        if [ -f "${keyPath}" ]; then
          if ! chown ${key.user}:${key.group} "${keyPath}"; then
            # Error should be visible in stderr
            failed=1
          fi
        else
          >&2 echo "Key ${keyPath} does not exist. Skipping chown."
        fi
      '') preActivationKeys;

      script = lib.stringAfter scriptDeps ''
        # This script is injected by Colmena to change the ownerships
        # of keys (`deployment.keys`) deployed before system activation.

        >&2 echo "setting up key ownerships..."

        # We set the ownership of as many keys as possible before failing
        failed=

        ${concatStringsSep "\n" commands}

        if [ -n "$failed" ]; then
          >&2 echo "Failed to set the ownership of some keys."

          # The activation script has a trap to handle failed
          # commands and print out various debug information.
          # Let's trigger that instead of `exit 1`.
          false
        fi
      '';
    in {
      system.activationScripts.colmena-chown-keys = lib.mkIf (length commands != 0) script;
    };

    # Create "${name}-key" services for NixOps compatibility
    #
    # This is built as part of the system profile.
    # We must be careful not to access `text` / `keyCommand` / `keyFile` here
    #
    # Sadly, path units don't automatically deactivate the bound units when
    # the key files are deleted, so we use inotifywait in the services' scripts.
    #
    # <https://github.com/systemd/systemd/issues/3642>
    keyServiceModule = { pkgs, lib, config, ... }: {
      systemd.paths = lib.mapAttrs' (name: val: {
        name = "${name}-key";
        value = {
          wantedBy = [ "paths.target" ];
          pathConfig = {
            PathExists = val.path;
          };
        };
      }) config.deployment.keys;

      systemd.services = lib.mapAttrs' (name: val: {
        name = "${name}-key";
        value = {
          bindsTo = [ "${name}-key.path" ];
          serviceConfig = {
            Restart = "on-failure";
          };
          path = [ pkgs.inotifyTools ];
          script = ''
            if [[ ! -e "${val.path}" ]]; then
              >&2 echo "${val.path} does not exist"
              exit 0
            fi

            inotifywait -qq -e delete_self "${val.path}"
            >&2 echo "${val.path} disappeared"
          '';
        };
      }) config.deployment.keys;
    };
  in evalConfig {
    inherit (npkgs) system;

    modules = [
      assertionModule
      nixpkgsModule
      keyChownModule
      keyServiceModule
      deploymentOptions
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
    inherit pkgs lib;
    nodes = uncheckedNodes;
  };
in {
  inherit
    nodes toplevel
    deploymentConfig deploymentConfigSelected
    evalAll evalSelected evalSelectedDrvPaths introspect;

  meta = hive.meta;

  nixosModules = { inherit deploymentOptions; };

  docs = {
    deploymentOptions = pkgs: let
      eval = pkgs.lib.evalModules {
        modules = [ deploymentOptions ];
        specialArgs = {
          name = "nixos";
          nodes = {};
        };
      };
    in eval.options;

    metaOptions = pkgs: let
      eval = pkgs.lib.evalModules {
        modules = [ metaOptions ];
      };
    in eval.options;
  };
}
