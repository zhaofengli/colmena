let
  flake = (import ../flake-compat.nix).defaultNix;
in import flake.inputs.stable.outPath {
  overlays = [
    flake.overlay

    # Our nix-eval-jobs patch cannot be applied to 0.0.1
    (final: prev: {
      colmena = prev.colmena.override {
        nix-eval-jobs = null;
      };
    })
  ];
}
