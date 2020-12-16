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
        rustc = rustChannel.rust.override {
          extensions = [ "rust-src" ];
        };
        inherit (rustChannel) cargo rust-fmt rust-std clippy;
        crate2nix = super.callPackage sources.crate2nix {};
      })
    ];
  };
in pkgs
