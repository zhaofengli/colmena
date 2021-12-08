let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  pinned = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/${lock.nodes.nixpkgs.locked.rev}.tar.gz";
    sha256 = lock.nodes.nixpkgs.locked.narHash;
  };
in import pinned {
  overlays = [
    (final: prev: {
      colmena = final.callPackage ../default.nix { };
    })
  ];
}
