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
  cargoSha256 = "06qw50wd8w9b6j7hayx75c9hvff9kxa0cllaqg8x854b1ww9pk8j";
}
