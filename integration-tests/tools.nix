# Adapted from the NixOps test in Nixpkgs.
#
# We have four nodes: deployer, alpha, beta, gamma.
# deployer is where colmena will run.
#
# `nixos/lib/build-vms.nix` will generate NixOS configurations
# for each node, and we need to include those configurations
# in our Colmena setup as well.

{ insideVm ? false }:

let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  pinned = if insideVm then <nixpkgs> else fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/${lock.nodes.nixpkgs.locked.rev}.tar.gz";
    sha256 = lock.nodes.nixpkgs.locked.narHash;
  };
  pkgs = import pinned {};

  colmena =
    if !insideVm then import ../default.nix { inherit pkgs; }
    else throw "Cannot be used inside the VM";
  colmenaExec = "${colmena}/bin/colmena";

  sshKeys = import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs;
  buildVms = import (pkgs.path + "/nixos/lib/build-vms.nix") {
    inherit (pkgs) system pkgs lib;
  };

  # Common setup
  nodes = let
    deployer = { lib, config, ... }: {
      nix.nixPath = [
        "nixpkgs=${pkgs.path}"
      ];

      nix.binaryCaches = lib.mkForce [];

      virtualisation = {
        memorySize = 2048;
        writableStore = true;
        additionalPaths = [
          "${pkgs.path}"
          prebuiltNode
          (inputClosureOf prebuiltNode)
        ];
      };

      environment.systemPackages = [
        # HACK: copy stderr to both stdout and stderr
        # (the test framework only captures stdout, and only stderr appears on screen during the build)
        (pkgs.writeShellScriptBin "run-copy-stderr" ''
          exec "$@" 2> >(tee /dev/stderr)
        '')
      ];
    };
    target = { lib, ... }: {
      nix.binaryCaches = lib.mkForce [];

      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [
        sshKeys.snakeOilPublicKey
      ];
      virtualisation.writableStore = true;
    };
  in {
    inherit deployer;
    alpha = target;
    beta = target;
    gamma = target;
  };

  prebuiltNode = let
    all = buildVms.buildVirtualNetwork nodes;
  in all.alpha.config.system.build.toplevel;

  # Utilities
  getStandaloneConfigFor = node: let
    configsWithIp = buildVms.assignIPAddresses nodes;
  in { modulesPath, lib, config, ... }: {
    imports = configsWithIp.${node} ++ [
      (modulesPath + "/virtualisation/qemu-vm.nix")
      (modulesPath + "/testing/test-instrumentation.nix")
    ];

    documentation.nixos.enable = false;
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
    fullScript = ''
      start_all()

      deployer.succeed("nix-store -qR ${prebuiltNode}")
      deployer.succeed("nix-store -qR ${pkgs.path}")
      deployer.succeed("ln -sf ${pkgs.path} /nixpkgs")
      deployer.succeed("mkdir -p /root/.ssh && touch /root/.ssh/id_rsa && chmod 600 /root/.ssh/id_rsa && cat ${sshKeys.snakeOilPrivateKey} > /root/.ssh/id_rsa")

      for node in [alpha, beta, gamma]:
          node.wait_for_unit("sshd.service")
      deployer.succeed("ssh -o StrictHostKeyChecking=accept-new alpha ls")

      deployer.succeed("cp --no-preserve=mode -r ${bundle} /tmp/bundle && chmod u+w /tmp/bundle")

      orig_store_paths = set(deployer.succeed("ls /nix/store | sort").strip().split("\n"))
      def get_new_store_paths():
          cur_store_paths = set(deployer.succeed("ls /nix/store | sort").strip().split("\n"))
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
  in pkgs.nixosTest combined;
in {
  inherit pkgs nodes colmena colmenaExec prebuiltNode
    getStandaloneConfigFor inputClosureOf makeTest;
}
