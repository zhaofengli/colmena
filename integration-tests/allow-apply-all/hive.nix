let
  tools = import ./tools.nix {
    insideVm = true;
    targets = [ "alpha" ];
  };
in
{
  meta = {
    nixpkgs = tools.pkgs;
    allowApplyAll = false;
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  alpha = tools.getStandaloneConfigFor "alpha";
}
