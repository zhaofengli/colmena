let
  tools = import ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply-local";

  bundle = ./.;

  testScript = ''
    deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply-local")
    deployer.succeed("grep SUCCESS /etc/deployment")
  '';
}
