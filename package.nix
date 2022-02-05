{ lib, stdenv, rustPlatform, installShellFiles, nix-eval-jobs ? null }:

rustPlatform.buildRustPackage rec {
  pname = "colmena";
  version = "0.3.0-pre";

  src = lib.cleanSourceWith {
    filter = name: type: !(type == "directory" && builtins.elem (baseNameOf name) [ "target" "manual" "integration-tests" ]);
    src = lib.cleanSource ./.;
  };

  cargoSha256 = "sha256-D/ucaDLb1UGX9cwz7gP9Nsito1uoIfnpoT1doCgA5zo=";

  nativeBuildInputs = [ installShellFiles ];

  propagatedBuildInputs = lib.optional (nix-eval-jobs != null) nix-eval-jobs;

  NIX_EVAL_JOBS = lib.optionalString (nix-eval-jobs != null) "${nix-eval-jobs}/bin/nix-eval-jobs";

  postInstall = lib.optionalString (stdenv.hostPlatform == stdenv.buildPlatform) ''
    installShellCompletion --cmd colmena \
      --bash <($out/bin/colmena gen-completions bash) \
      --zsh <($out/bin/colmena gen-completions zsh) \
      --fish <($out/bin/colmena gen-completions fish)
  '';

  # Recursive Nix is not stable yet
  doCheck = false;

  passthru = {
    # We guarantee CLI and Nix API stability for the same minor version
    apiVersion = builtins.concatStringsSep "." (lib.take 2 (lib.splitString "." version));
  };

  meta = with lib; {
    description = "A simple, stateless NixOS deployment tool";
    homepage = "https://zhaofengli.github.io/colmena/${passthru.apiVersion}";
    license = licenses.mit;
    maintainers = with maintainers; [ zhaofengli ];
    platforms = platforms.linux ++ platforms.darwin;
  };
}
