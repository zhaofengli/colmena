{ pkgs }:

let
  tools = pkgs.callPackage ../tools.nix {
    targets = [ ];
    prebuiltTarget = "deployer";
    extraDeployerConfig = {
      users.users.colmena = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
      };
      security.sudo.wheelNeedsPassword = false;
    };
  };
in
tools.runTest {
  name = "colmena-apply-local";

  colmena.test = {
    bundle = ./.;

    testScript = ''
      deployer.succeed("cd /tmp/bundle && sudo -u colmena ${tools.colmenaExec} apply-local --sudo")
      deployer.succeed("grep SUCCESS /etc/deployment")
      deployer.succeed("grep SECRET /run/keys/key-text")
    '';
  };
}
