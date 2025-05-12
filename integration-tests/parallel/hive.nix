let
  tools = import ./tools.nix { insideVm = true; };
in
{
  meta = {
    nixpkgs = tools.pkgs;
  };

  defaults = {
    environment.etc."deployment".text = "SUCCESS";

    system.activationScripts.activationDelay.text = ''
      >&2 echo "Activation triggered --- $(date +%s%N)"
      sleep 3
    '';
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  alpha = tools.getStandaloneConfigFor "alpha";
  beta = tools.getStandaloneConfigFor "beta";
  gamma = tools.getStandaloneConfigFor "gamma";
}
