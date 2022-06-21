{ pkgs ? import ../nixpkgs.nix }:

let
  tools = pkgs.callPackage ../tools.nix {
    targets = [ "alpha" ];
  };
in tools.makeTest {
  name = "colmena-allow-apply-all";

  bundle = ./.;

  testScript = ''
    logs = deployer.fail("cd /tmp/bundle && run-copy-stderr ${tools.colmenaExec} apply")

    assert "no filter supplied" in logs

    deployer.succeed("cd /tmp/bundle && run-copy-stderr ${tools.colmenaExec} apply --on @target")
  '';
}
