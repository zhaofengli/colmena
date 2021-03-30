{
    description = "A simple, stateless NixOS deployment tool modeled after NixOps.";

    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
        utils.url = "github:numtide/flake-utils";

        naersk = {
            url = "github:nmattia/naersk/master";
            inputs.nixpkgs.follows = "nixpkgs";
        };

        flake-compat = {
            url = "github:edolstra/flake-compat";
            flake = false;
        };
    };

    outputs = { self, nixpkgs, utils, naersk, ... }: let
        inherit (nixpkgs) lib; 
    in {
        # make our shared outputs
        nixosModules = import ./src/nix/modules.nix { inherit lib; };
    } // (utils.lib.eachDefaultSystem (system: let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
    in {
        # make packages for every system
        defaultPackage = self.packages.${system}.colmena;
        packages.colmena = naersk-lib.buildPackage { root = ./.; };

        defaultApp = self.apps."${system}".colmena;
        apps.colmena = {
            type = "app";
            program = "${self.defaultPackage."${system}"}/bin/colmena";
        };

        devShell = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.colmena ];
            buildInputs = [ pkgs.nixUnstable ];
        };

        checks.colmena = self.defaultPackage.${system}.overrideAttrs (super: { doCheck = true; });

        lib = import ./src/nix/flakelib.nix { inherit lib pkgs; };
    }));
}