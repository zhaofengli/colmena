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
  cargoSha256 = "0rkpv9afkg33i1d0yjlq34zrdqy3i6ldbdag0hgsvxi3v3jfg4qv";

  # Recursive Nix is not stable yet
  doCheck = false;
}
