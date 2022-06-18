{
  apply = import ./apply {};
  apply-streaming = import ./apply { evaluator = "streaming"; };
  apply-local = import ./apply-local {};
  build-on-target = import ./build-on-target {};
  exec = import ./exec {};
  flakes = import ./flakes {};
  flakes-streaming = import ./flakes { evaluator = "streaming"; };
  parallel = import ./parallel {};

  allow-apply-all = import ./allow-apply-all {};

  apply-stable = let
    test = import ./apply { pkgs = import ./nixpkgs-stable.nix; };
  in test.override (old: {
    name = "apply-stable";
  });
}
