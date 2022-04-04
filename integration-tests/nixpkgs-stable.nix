let
  flake = (import ../flake-compat.nix).defaultNix;
in import flake.inputs.stable.outPath {
  overlays = [
    flake.overlay
  ];
}
