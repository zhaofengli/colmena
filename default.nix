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
  cargoSha256 = "0gwjbzvx6hlbjb8892rc2p9rj5l432y13aq1nxr2h71rgqppxflg";
}
