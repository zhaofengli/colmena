let
  tools = import ./tools.nix {
    insideVm = true;
    deployers = [
      "deployer"
      "alpha"
      "beta"
    ];
    targets = [ ];
  };
in
{
  meta = {
    nixpkgs = tools.pkgs;
  };

  defaults = {
    environment.etc."deployment".text = "SUCCESS";
  };

  deployer = tools.getStandaloneConfigFor "deployer";

  alpha = {
    imports = [
      (tools.getStandaloneConfigFor "alpha")
    ];

    deployment.buildOnTarget = true;
  };

  beta = {
    imports = [
      (tools.getStandaloneConfigFor "beta")
    ];

    deployment.buildOnTarget = false;
  };
}
