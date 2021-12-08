{ pkgs ? import ../nixpkgs.nix }:

let
  tools = pkgs.callPackage ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply";

  bundle = ./.;

  testScript = ''
    colmena = "${tools.colmenaExec}"
  '' + builtins.readFile ./test-script.py;
}
