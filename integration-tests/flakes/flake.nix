{
  description = "A simple deployment";

  inputs = {
    nixpkgs.url = "@nixpkgs@";
    colmena.url = "@colmena@";
  };

  outputs = { self, nixpkgs, colmena }: let
    pkgs = import nixpkgs {
      system = "x86_64-linux";
    };
  in {
    colmena = import ./hive.nix { inherit pkgs; };
    colmenaHive = colmena.lib.makeHive self.outputs.colmena;
  };
}
