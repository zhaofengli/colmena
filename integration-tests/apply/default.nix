{ pkgs ? import ../nixpkgs.nix
, evaluator ? "chunked"
}:

let
  tools = pkgs.callPackage ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply-${evaluator}";

  bundle = ./.;

  testScript = ''
    colmena = "${tools.colmenaExec}"
    evaluator = "${evaluator}"
  '' + builtins.readFile ./test-script.py;
}
