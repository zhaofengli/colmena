{ pkgs ? import ./nixpkgs.nix
, pkgsStable ? import ./nixpkgs-stable.nix
}:

{
  apply = import ./apply { inherit pkgs; };
  apply-streaming = import ./apply { inherit pkgs; evaluator = "streaming"; };
  apply-local = import ./apply-local { inherit pkgs; };
  build-on-target = import ./build-on-target { inherit pkgs; };
  exec = import ./exec { inherit pkgs; };

  # FIXME: The old evaluation method doesn't work purely with Nix 2.21+
  flakes = import ./flakes {
    inherit pkgs;
    extraApplyFlags = "--experimental-flake-eval";
  };
  flakes-impure = import ./flakes {
    inherit pkgs;
    extraApplyFlags = "--impure";
  };
  #flakes-streaming = import ./flakes { inherit pkgs; evaluator = "streaming"; };

  parallel = import ./parallel { inherit pkgs; };

  allow-apply-all = import ./allow-apply-all { inherit pkgs; };

  apply-stable = import ./apply { pkgs = pkgsStable; };
}
