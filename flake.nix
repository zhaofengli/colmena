{
  description = "A simple, stateless NixOS deployment tool modeled after NixOps.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, ... }: let
    supportedSystems = utils.lib.defaultSystems ++ [ "riscv64-linux" ];
  in utils.lib.eachSystem supportedSystems (system: let
    pkgs = import nixpkgs { inherit system; };
  in rec {
    # We still maintain the expression in a Nixpkgs-acceptable form
    legacyPackages.colmena = import ./default.nix { inherit pkgs; };
    defaultPackage = self.legacyPackages.${system}.colmena;

    defaultApp = self.apps.${system}.colmena;
    apps.colmena = {
      type = "app";
      program = "${defaultPackage}/bin/colmena";
    };

    devShell = pkgs.mkShell {
      inputsFrom = [ defaultPackage ];
      buildInputs = [ pkgs.nixUnstable ];
    };
  });
}
