{
  pkgs ? import ./pkgs.nix {},
}: let
  rustPlatform = if pkgs ? pinnedRust then pkgs.makeRustPlatform {
    rustc = pkgs.pinnedRust;
    cargo = pkgs.pinnedRust;
  } else pkgs.rustPlatform;
in rustPlatform.buildRustPackage {
  name = "colmena-dev";
  version = "0.1.0";

  src = ./.;
  cargoSha256 = "1ayfw41kaa5wcqym4sz1l44gldi0qz1pfhfsqd53hgaim4nqiwrn";
}
