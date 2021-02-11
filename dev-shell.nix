let
  pkgs = import ./pkgs.nix;
in pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc cargo
  ];
  shellHook = ''
    export NIX_PATH=nixpkgs=${pkgs.path}
  '';
}
