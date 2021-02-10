{
  pkgs ? import ./pkgs.nix,
}: let
  lib = pkgs.lib;
  rustPlatform = pkgs.rustPlatform;
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
  cargoSha256 = "1ibhn8bbcx0y9gjl42d9ba478j6a5dr928v0ds61vwn7lbm68dzr";
}
