let
  pkgs = import ./pkgs.nix {};
in pkgs.mkShell {
  buildInputs = [
    (import ./default.nix {})
  ];
}
