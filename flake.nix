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
    supportedSystems = [ "x86_64-linux" "i686-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
  in utils.lib.eachSystem supportedSystems (system: let
    pkgs = import nixpkgs { inherit system; };
  in rec {
    # We still maintain the expression in a Nixpkgs-acceptable form
    defaultPackage = self.packages.${system}.colmena;
    packages = rec {
      colmena = pkgs.callPackage ./package.nix { };

      # Full user manual
      manual = let
        colmena = self.packages.${system}.colmena;
        evalNix = import ./src/nix/hive/eval.nix {
          hermetic = true;
        };
        deploymentOptionsMd = (pkgs.nixosOptionsDoc {
          options = evalNix.docs.deploymentOptions pkgs;
        }).optionsCommonMark;
        metaOptionsMd = (pkgs.nixosOptionsDoc {
          options = evalNix.docs.metaOptions pkgs;
        }).optionsCommonMark;
      in pkgs.callPackage ./manual {
        inherit colmena deploymentOptionsMd metaOptionsMd;
      };

      # User manual without the CLI reference
      manualFast = manual.override { colmena = null; };

      # User manual with the version treated as stable
      manualForceStable = manual.override { unstable = false; };
    };

    defaultApp = self.apps.${system}.colmena;
    apps.colmena = {
      type = "app";
      program = "${defaultPackage}/bin/colmena";
    };

    devShell = pkgs.mkShell {
      inputsFrom = [ defaultPackage ];
      packages = with pkgs; [ clippy mdbook python3 editorconfig-checker rust-analyzer ];
      shellHook = ''
        export NIX_PATH=nixpkgs=${pkgs.path}
      '';
    };
  }) // {
    overlay = final: prev: {
      colmena = final.callPackage ./package.nix { };
    };
  };
}
