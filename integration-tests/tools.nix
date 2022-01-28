# Adapted from the NixOps test in Nixpkgs.
#
# By default, we have four nodes: deployer, alpha, beta, gamma.
# deployer is where colmena will run.
#
# `nixos/lib/build-vms.nix` will generate NixOS configurations
# for each node, and we need to include those configurations
# in our Colmena setup as well.

{ insideVm ? false
, deployers ? [ "deployer" ]           # Nodes configured as deployers (with Colmena and pre-built system closure)
, targets ? [ "alpha" "beta" "gamma" ] # Nodes configured as targets (minimal config)
, prebuiltTarget ? "alpha"             # Target node to prebuild system closure for, or null

, pkgs ? if insideVm then import <nixpkgs> {} else throw "Must specify pkgs"
, colmena ? if !insideVm then pkgs.colmena else throw "Cannot eval inside VM"
}:

with builtins;

assert elem "deployer" deployers;

let
  inherit (pkgs) lib;

  colmenaExec = "${colmena}/bin/colmena";

  sshKeys = import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs;
  buildVms = import (pkgs.path + "/nixos/lib/build-vms.nix") {
    inherit (pkgs) system pkgs lib;
  };

  # Common setup
  nodes = let
    # Setup for deployer nodes
    #
    # We include the input closure of a prebuilt system profile
    # so it can build system profiles for the targets without
    # network access.
    deployerConfig = { lib, config, ... }: {
      nix.nixPath = [
        "nixpkgs=${pkgs.path}"
      ];

      nix.binaryCaches = lib.mkForce [];

      virtualisation = {
        memorySize = 3072;
        writableStore = true;
        additionalPaths = [
          "${pkgs.path}"
        ] ++ lib.optionals (prebuiltTarget != null) [
          prebuiltSystem
          (inputClosureOf prebuiltSystem)
        ];
      };

      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [
        sshKeys.snakeOilPublicKey
      ];

      environment.systemPackages = with pkgs; [
        git # for git flake tests
        inotifyTools # for key services build

        # HACK: copy stderr to both stdout and stderr
        # (the test framework only captures stdout, and only stderr appears on screen during the build)
        (writeShellScriptBin "run-copy-stderr" ''
          exec "$@" 2> >(tee /dev/stderr)
        '')
      ];
    };

    # Setup for target nodes
    #
    # Kept as minimal as possible.
    targetConfig = { lib, ... }: {
      nix.binaryCaches = lib.mkForce [];

      documentation.nixos.enable = lib.mkOverride 60 true;

      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [
        sshKeys.snakeOilPublicKey
      ];
      virtualisation.writableStore = true;
    };

    deployerNodes = map (name: lib.nameValuePair name deployerConfig) deployers;
    targetNodes = map (name: lib.nameValuePair name targetConfig) targets;
  in listToAttrs (deployerNodes ++ targetNodes);

  prebuiltSystem = let
    all = buildVms.buildVirtualNetwork nodes;
  in all.${prebuiltTarget}.config.system.build.toplevel;

  # Utilities
  getStandaloneConfigFor = node: let
    configsWithIp = buildVms.assignIPAddresses nodes;
  in { modulesPath, lib, config, ... }: {
    imports = configsWithIp.${node} ++ [
      (modulesPath + "/virtualisation/qemu-vm.nix")
      (modulesPath + "/testing/test-instrumentation.nix")
    ];

    documentation.nixos.enable = lib.mkOverride 55 false;
    boot.loader.grub.enable = false;
    system.nixos.revision = lib.mkForce "constant-nixos-revision";

    # otherwise the evaluation is unnecessarily slow in VM
    virtualisation.additionalPaths = lib.mkForce [];
    nix.nixPath = lib.mkForce [ "nixpkgs=/nixpkgs" ];

    deployment.tags = lib.optional (config.networking.hostName != "deployer") "target";
  };

  inputClosureOf = pkg: pkgs.runCommand "full-closure" {
    refs = pkgs.writeReferencesToFile pkg.drvPath;
  } ''
    touch $out

    while read ref; do
      case $ref in
        *.drv)
          cat $ref >>$out
          ;;
      esac
    done <$refs
  '';

  makeTest = test: let
    targetList = "[${concatStringsSep ", " targets}]";

    fullScript = ''
      start_all()
    '' + lib.optionalString (prebuiltTarget != null) ''
      deployer.succeed("nix-store -qR ${prebuiltSystem}")
    '' + ''
      deployer.succeed("nix-store -qR ${pkgs.path}")
      deployer.succeed("ln -sf ${pkgs.path} /nixpkgs")
      deployer.succeed("mkdir -p /root/.ssh && touch /root/.ssh/id_rsa && chmod 600 /root/.ssh/id_rsa && cat ${sshKeys.snakeOilPrivateKey} > /root/.ssh/id_rsa")

      for node in ${targetList}:
          node.wait_for_unit("sshd.service")
          deployer.succeed(f"ssh -o StrictHostKeyChecking=accept-new {node.name} true")

      deployer.succeed("cp --no-preserve=mode -r ${bundle} /tmp/bundle && chmod u+w /tmp/bundle")

      orig_store_paths = set(deployer.succeed("ls /nix/store").strip().split("\n"))
      def get_new_store_paths():
          cur_store_paths = set(deployer.succeed("ls /nix/store").strip().split("\n"))
          new_store_paths = cur_store_paths.difference(orig_store_paths)
          deployer.log(f"{len(new_store_paths)} store paths were created")

          l = list(map(lambda n: f"/nix/store/{n}", new_store_paths))
          return l
    '' + test.testScript;

    bundle = pkgs.stdenv.mkDerivation {
      name = "${test.name}-bundle";
      dontUnpack = true;
      dontInstall = true;
      buildPhase = ''
        cp -r ${test.bundle} $out
        chmod u+w $out
        cp ${./tools.nix} $out/tools.nix
      '';
    };

    combined = {
      inherit nodes;
    } // test // {
      testScript = fullScript;
    };
  in lib.makeOverridable pkgs.nixosTest combined;
in {
  inherit pkgs nodes colmena colmenaExec
    getStandaloneConfigFor inputClosureOf makeTest;
}
