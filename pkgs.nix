{
  sources ? import ./nix/sources.nix,
  rustNightly ? "2020-11-10",
}: let
  pkgs = import sources.nixpkgs {
    overlays = [
      (import sources.nixpkgs-mozilla)
      (self: super: let
        rustChannel = super.rustChannelOf {
          channel = "nightly";
          date = rustNightly;
        };
      in rec {
        pinnedRust = rustChannel.rust.override {
          extensions = [ "rust-src" ];
        };
      })
    ];
  };
in pkgs
