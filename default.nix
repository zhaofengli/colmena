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
  cargoSha256 = "1ai046vbvydyqhwiy8qz0d28dch5jpxg3rzk7nrh2sdwcvxirmvm";
}
