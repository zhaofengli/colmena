{ pkgs ? import ../nixpkgs.nix }:

let
  tools = pkgs.callPackage ../tools.nix {
    targets = [];
    prebuiltTarget = "deployer";
    extraDeployerConfig = {
      users.users.colmena = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
      };
      security.sudo.wheelNeedsPassword = false;
    };
  };
in tools.makeTest {
  name = "colmena-apply-local";

  bundle = ./.;

  testScript = ''
    deployer.succeed("cd /tmp/bundle && sudo -u colmena ${tools.colmenaExec} apply-local --sudo")
    deployer.succeed("grep SUCCESS /etc/deployment")
    deployer.succeed("grep SECRET /run/keys/key-text")
  '';
}
