{
  description = "A simple, stateless NixOS deployment tool modeled after NixOps.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    stable.url = "github:NixOS/nixpkgs/nixos-21.11";

    utils.url = "github:numtide/flake-utils";

    # not yet upstreamed
    nix-eval-jobs.url = "github:zhaofengli/nix-eval-jobs/colmena";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, nix-eval-jobs, ... }: let
    supportedSystems = [ "x86_64-linux" "i686-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    evalNix = import ./src/nix/hive/eval.nix {
      hermetic = true;
    };
  in utils.lib.eachSystem supportedSystems (system: let
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self._evalJobsOverlay ];
    };
  in rec {
    # We still maintain the expression in a Nixpkgs-acceptable form
    defaultPackage = self.packages.${system}.colmena;
    packages = rec {
      colmena = pkgs.callPackage ./package.nix { };

      # Full user manual
      manual = let
        colmena = self.packages.${system}.colmena;
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
    # For use in integration tests
    _evalJobsOverlay =
      (final: prev: {
        nix-eval-jobs = (final.callPackage nix-eval-jobs.outPath {}).overrideAttrs (old: {
          version = "0.0.3-colmena";
        });
      });

    overlay = final: prev: {
      colmena = final.callPackage ./package.nix { };
    };
    inherit (evalNix) nixosModules;
  };
}
