let
  pkgs = import ./pkgs.nix {};
in pkgs.mkShell {
  buildInputs = with pkgs; [
    #rust
    crate2nix
  ];
}
