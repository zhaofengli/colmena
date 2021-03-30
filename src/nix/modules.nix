{ lib, ... }: with lib;
let
  keyType = types.submodule {
    options = {
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
in {
  inherit deploymentOptions assertionModule;
}
