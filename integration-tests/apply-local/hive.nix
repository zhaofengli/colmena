let
  tools = import ./tools.nix {
    insideVm = true;
    targets = [ ];
    prebuiltTarget = "deployer";
  };
in
{
  meta = {
    nixpkgs = tools.pkgs;
  };

  deployer =
    { lib, ... }:
    {
      imports = [
        (tools.getStandaloneConfigFor "deployer")
      ];

      deployment = {
        allowLocalDeployment = true;
      };

      environment.etc."deployment".text = "SUCCESS";

      # /run/keys/key-text
      deployment.keys."key-text".text = "SECRET";
    };
}
