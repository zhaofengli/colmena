{ pkgs }:

let
  tools = pkgs.callPackage ../tools.nix {
    targets = [ "alpha" ];
  };
in tools.runTest {
  name = "colmena-allow-apply-all";

  colmena.test = {
    bundle = ./.;

    testScript = ''
      logs = deployer.fail("cd /tmp/bundle && run-copy-stderr ${tools.colmenaExec} apply")

      assert "No node filter" in logs

      deployer.succeed("cd /tmp/bundle && run-copy-stderr ${tools.colmenaExec} apply --on @target")
    '';
  };
}
