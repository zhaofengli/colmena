let
  tools = import ./tools.nix { insideVm = true; };
in {
  meta = {
    nixpkgs = tools.pkgs;
  };

  deployer = { lib, ... }: {
    imports = [
      (tools.getStandaloneConfigFor "deployer")
    ];

    deployment = {
      allowLocalDeployment = true;
    };

    environment.etc."deployment".text = "SUCCESS";
  };

  alpha = tools.getStandaloneConfigFor "alpha";
  beta = tools.getStandaloneConfigFor "beta";
  gamma = tools.getStandaloneConfigFor "gamma";
}
