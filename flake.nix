{
  description = "A simple, stateless NixOS deployment tool modeled after NixOps.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    stable.url = "github:NixOS/nixpkgs/nixos-21.11";

    utils.url = "github:numtide/flake-utils";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, ... }: let
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
      inputsFrom = [ defaultPackage packages.manualFast ];
      packages = with pkgs; [
        python3 editorconfig-checker
        clippy rust-analyzer cargo-outdated
      ];
      shellHook = ''
        export NIX_PATH=nixpkgs=${pkgs.path}
      '';
    };
  }) // {
    # For use in integration tests
    _evalJobsOverlay =
      (final: prev: {
        nix-eval-jobs = prev.nix-eval-jobs.overrideAttrs (old: {
          version = old.version + "-colmena";
          patches = (old.patches or []) ++ [
            # Add --show-trace
            (final.fetchpatch {
              url = "https://github.com/nix-community/nix-eval-jobs/commit/1e0f309fefc9b2d597f8475a74c82ce29c189152.patch";
              sha256 = "sha256-246t3SGRA/9JsV2XPcI4Exp+TxmyYBoldQ43Wr5CcsM=";
            })

            # Fix buffering when piped
            (final.fetchpatch {
              url = "https://github.com/zhaofengli/nix-eval-jobs/commit/6d61193286aedd4e514fd8f375b2000b95fff4fb.patch";
              sha256 = "sha256-yOuUwKHSS7Bt3q3nClirVk7DzJhxNFFZ8JnYjrPRJVc=";
            })
          ];
        });
      });

    overlay = final: prev: {
      colmena = final.callPackage ./package.nix { };
    };
    inherit (evalNix) nixosModules;
  };
}
