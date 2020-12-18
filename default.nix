{
  pkgs ? import ./pkgs.nix {},
}: let
  cargo = pkgs.callPackage ./Cargo.nix {};
in cargo.rootCrate.build
