let
  tools = import ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply";

  bundle = ./.;

  testScript = ''
    logs = deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply -v --on @target 2> >(tee /dev/stderr)")

    with subtest("Check whether build messages are logged correctly"):
        assert "must appear during build" in logs

    with subtest("Check whether push messages are logged correctly"):
        assert "copying path" in logs

    with subtest("Check whether activation messages are logged correctly"):
        assert "must appear during activation" in logs

    alpha.succeed("grep SUCCESS /etc/deployment")
    alpha.succeed("grep 'key content' /run/keys/example")

    deployer.succeed("ssh alpha true")
    deployer.succeed("ssh beta true")
    deployer.succeed("ssh gamma true")
  '';
}
