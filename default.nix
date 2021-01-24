{
  pkgs ? import ./pkgs.nix {},
}: let
  lib = pkgs.lib;
  rustPlatform = if pkgs ? pinnedRust then pkgs.makeRustPlatform {
    rustc = pkgs.pinnedRust;
    cargo = pkgs.pinnedRust;
  } else pkgs.rustPlatform;
in rustPlatform.buildRustPackage {
  name = "colmena-dev";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    filter = name: type: !(type == "directory" && baseNameOf name == "target");
    src = lib.cleanSourceWith {
      filter = lib.cleanSourceFilter;
      src = ./.;
    };
  };
  cargoSha256 = "0m35xjslm5gxr2cb5fw8pkqpm853hsznhsncry2kvicqzwh63ldm";
}
