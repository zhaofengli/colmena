{
  description = "Internal Colmena expressions";

  inputs = {
    hive.url = "%hive%";
  };

  outputs = { self, hive }: {
    colmenaEval = import ./eval.nix {
      rawFlake = hive;
      colmenaOptions = import ./options.nix;
      colmenaModules = import ./modules.nix;
    };
  };
}
