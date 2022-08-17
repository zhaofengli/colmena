{
  description = "A simple deployment";

  inputs = {
    nixpkgs.url = "@nixpkgs@";
  };

  outputs = { self, nixpkgs }: let
    pkgs = import nixpkgs {
      system = "x86_64-linux";
    };
  in {
    colmena = import ./hive.nix { inherit pkgs; };
  };
}
