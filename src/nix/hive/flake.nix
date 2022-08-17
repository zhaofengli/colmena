{
  description = "Internal Colmena expressions";

  outputs = { ... }: {
    lib.colmenaEval = {
      rawHive ? null,
      flakeUri ? null,
      hermetic ? flakeUri != null,
    }: import ./eval.nix {
      inherit rawHive flakeUri hermetic;
      colmenaOptions = import ./options.nix;
      colmenaModules = import ./modules.nix;
    };
  };
}
