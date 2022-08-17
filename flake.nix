{
  description = "A simple, stateless NixOS deployment tool modeled after NixOps.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    stable.url = "github:NixOS/nixpkgs/nixos-22.05";

    utils.url = "github:numtide/flake-utils";

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, ... }: let
    supportedSystems = [ "x86_64-linux" "i686-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    colmenaOptions = import ./src/nix/hive/options.nix;
    colmenaModules = import ./src/nix/hive/modules.nix;
  in utils.lib.eachSystem supportedSystems (system: let
    pkgs = import nixpkgs {
      inherit system;
    };
  in rec {
    # We still maintain the expression in a Nixpkgs-acceptable form
    defaultPackage = self.packages.${system}.colmena;
    packages = rec {
      colmena = pkgs.callPackage ./package.nix { };

      # Full user manual
      manual = let
        suppressModuleArgsDocs = { lib, ... }: {
          options = {
            _module.args = lib.mkOption {
              internal = true;
            };
          };
        };
        colmena = self.packages.${system}.colmena;
        deploymentOptionsMd = (pkgs.nixosOptionsDoc {
          inherit (pkgs.lib.evalModules {
            modules = [ colmenaOptions.deploymentOptions suppressModuleArgsDocs];
            specialArgs = { name = "nixos"; nodes = {}; };
          }) options;
        }).optionsCommonMark;
        metaOptionsMd = (pkgs.nixosOptionsDoc {
          inherit (pkgs.lib.evalModules {
            modules = [ colmenaOptions.metaOptions  suppressModuleArgsDocs];
          }) options;
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
    apps.default = self.apps.${system}.colmena;
    apps.colmena = {
      type = "app";
      program = "${defaultPackage}/bin/colmena";
    };

    devShell = pkgs.mkShell {
      RUST_SRC_PATH = "${pkgs.rustPlatform.rustcSrc}/library";
      NIX_PATH = "nixpkgs=${pkgs.path}";

      inputsFrom = [ defaultPackage packages.manualFast ];
      packages = with pkgs; [
        bashInteractive
        editorconfig-checker
        clippy rust-analyzer cargo-outdated cargo-audit rustfmt
        python3 python3Packages.flake8
      ];
    };
  }) // {
    overlay = final: prev: {
      colmena = final.callPackage ./package.nix { };
    };
    nixosModules = {
        inherit (colmenaOptions) deploymentOptions metaOptions;
        inherit (colmenaModules) keyChownModule keyServiceModule;
    };
  };

  nixConfig = {
    extra-substituters = [
      "https://colmena.cachix.org"
    ];
    extra-trusted-public-keys = [
      "colmena.cachix.org-1:7BzpDnjjH8ki2CT3f6GdOk7QAzPOl+1t3LvTLXqYcSg="
    ];
  };
}
