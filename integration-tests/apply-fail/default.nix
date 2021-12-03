let
  tools = import ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply-fail";

  bundle = ./.;

  testScript = ''
    beta.block()

    # HACK: copy stderr to both stdout and stderr
    # (stdout is what's returned, and only stderr appears on screen during the build)
    logs = deployer.fail("cd /tmp/bundle && ${tools.colmenaExec} apply -v --eval-node-limit 4 --on @target 2> >(tee /dev/stderr)")

    alpha.succeed("grep SUCCESS /etc/deployment")
    gamma.succeed("grep SUCCESS /etc/deployment")
  '';
}
