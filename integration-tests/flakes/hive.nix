{ pkgs }:

let
  tools = import ./tools.nix {
    inherit pkgs;
    insideVm = true;
    targets = [ "alpha" ];
  };
in {
  meta = {
    nixpkgs = tools.pkgs;
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  alpha = {
    imports = [
      (tools.getStandaloneConfigFor "alpha")
    ];

    environment.etc."deployment".text = import ./probe.nix;
  };
}
