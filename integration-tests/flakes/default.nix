{ pkgs ? import ../nixpkgs.nix
, evaluator ? "chunked"
}:

let
  tools = pkgs.callPackage ../tools.nix {
    targets = [ "alpha" ];
  };
in tools.makeTest {
  name = "colmena-flakes-${evaluator}";

  bundle = ./.;

  testScript = ''
    import re

    deployer.succeed("sed -i \"s @nixpkgs@ $(readlink /nixpkgs) g\" /tmp/bundle/flake.nix")

    with subtest("Lock flake dependencies"):
        # --impure required for path:/nixpkgs which is a symlink to a store path
        deployer.succeed("cd /tmp/bundle && nix --experimental-features \"nix-command flakes\" flake lock --impure")

    with subtest("Deploy with a plain flake without git"):
        deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply --on @target --evaluator ${evaluator}")
        alpha.succeed("grep FIRST /etc/deployment")

    with subtest("Deploy with a git flake"):
        deployer.succeed("sed -i s/FIRST/SECOND/g /tmp/bundle/probe.nix")

        # don't put probe.nix in source control - should fail
        deployer.succeed("cd /tmp/bundle && git init && git add flake.nix flake.lock hive.nix tools.nix")
        logs = deployer.fail("cd /tmp/bundle && run-copy-stderr ${tools.colmenaExec} apply --on @target --evaluator ${evaluator}")
        assert re.search(r"probe.nix.*No such file or directory", logs)

        # now it should succeed
        deployer.succeed("cd /tmp/bundle && git add probe.nix")
        deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply --on @target --evaluator ${evaluator}")
        alpha.succeed("grep SECOND /etc/deployment")
  '';
}
