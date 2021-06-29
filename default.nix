let
  lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  lockedPkgs = import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/${lock.nodes.nixpkgs.locked.rev}.tar.gz";
    sha256 = lock.nodes.nixpkgs.locked.narHash;
  }) {};
in {
  pkgs ? lockedPkgs,
}: let
  lib = pkgs.lib;
  stdenv = pkgs.stdenv;
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
  cargoSha256 = "10h8bsy8hh36mvdgpnbw4vxnzkxyfw2vb4r1pn7fxfn0nklgakq7";

  postInstall = lib.optionalString (stdenv.hostPlatform == stdenv.buildPlatform) ''
    mkdir completions
    for shell in bash fish zsh; do
      $out/bin/colmena gen-completions $shell > completions/$shell
    done

    mkdir -p "$out/share/"{bash-completion/completions,fish/vendor_completions.d,zsh/site-functions}
    cp completions/bash $out/share/bash-completion/completions/colmena
    cp completions/fish $out/share/fish/vendor_completions.d/colmena.fish
    cp completions/zsh $out/share/zsh/site-functions/_colmena
  '';

  # Recursive Nix is not stable yet
  doCheck = false;
}
