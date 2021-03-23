{
  pkgs ? import ./pkgs.nix,
}: let
  lib = pkgs.lib;
  rustPlatform = pkgs.rustPlatform;
in rustPlatform.buildRustPackage {
  name = "colmena-dev";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    filter = name: type: !(type == "directory" && baseNameOf name == "target");
    src = lib.cleanSourceWith {
      filter = lib.cleanSourceFilter;
      src = ./.;
    };
  };
  cargoSha256 = "1yjaqhv9gd86jq56vsrhv6qv3k5qh2pnc4zyxbi2fm2hdrvy0440";

  postBuild = ''
    mkdir completions
    for shell in bash fish zsh; do
      cargo run --frozen -- gen-completions $shell > completions/$shell
    done
  '';

  postInstall = ''
    mkdir -p "$out/share/"{bash-completion/completions,fish/vendor_completions.d,zsh/site-functions}
    cp completions/bash $out/share/bash-completion/completions/colmena
    cp completions/fish $out/share/fish/vendor_completions.d/colmena.fish
    cp completions/zsh $out/share/zsh/site-functions/_colmena
  '';

  # Recursive Nix is not stable yet
  doCheck = false;
}
