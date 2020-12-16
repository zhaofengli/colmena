let
  pkgs = import ./pkgs.nix {};
in pkgs.mkShell {
  buildInputs = with pkgs; [
    (import ./Cargo.nix {}).rootCrate.build
  ];
}
