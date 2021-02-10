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
  cargoSha256 = "0imalrw8im6zl5lq8k5j05msykax85lya39vq0fxagifdckcdfsb";
}
