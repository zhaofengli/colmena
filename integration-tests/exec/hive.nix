let
  tools = import ./tools.nix { insideVm = true; };
in
{
  meta = {
    nixpkgs = tools.pkgs;
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  alpha = tools.getStandaloneConfigFor "alpha";
  beta = tools.getStandaloneConfigFor "beta";
  gamma = tools.getStandaloneConfigFor "gamma";
}
