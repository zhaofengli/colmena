let
  tools = import ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply";

  bundle = ./.;

  testScript = ''
    colmena = "${tools.colmenaExec}"
  '' + builtins.readFile ./test-script.py;
}
