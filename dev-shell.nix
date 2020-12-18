let
  pkgs = import ./pkgs.nix {};
in pkgs.mkShell {
  buildInputs = with pkgs; [
    pinnedRust
  ];
}
