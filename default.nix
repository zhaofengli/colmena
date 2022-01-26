let
  lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  lockedPkgs = import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/${lock.nodes.nixpkgs.locked.rev}.tar.gz";
    sha256 = lock.nodes.nixpkgs.locked.narHash;
  }) {};
in {
  pkgs ? lockedPkgs,
}: let
  inherit (pkgs) lib stdenv rustPlatform;
in rustPlatform.buildRustPackage rec {
  pname = "colmena";
  version = "0.2.1";

  # We guarantee CLI and Nix API stability for the same minor version
  apiVersion = builtins.concatStringsSep "." (lib.take 2 (lib.splitString "." version));

  src = lib.cleanSourceWith {
    filter = name: type: !(type == "directory" && builtins.elem (baseNameOf name) [ "target" "manual" ]);
    src = lib.cleanSource ./.;
  };

  cargoSha256 = "sha256-wMC2GAVVxkwrgJtOIJL0P+Uxh+ouW4VwLDrXJlD10AA=";

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

  meta = with lib; {
    description = "A simple, stateless NixOS deployment tool";
    homepage = "https://zhaofengli.github.io/colmena/${apiVersion}";
    license = licenses.mit;
    maintainers = with maintainers; [ zhaofengli ];
  };
}
