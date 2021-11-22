let
  tools = import ./tools.nix { insideVm = true; };

  testPkg = tools.pkgs.runCommand "test-package" {} ''
    echo "must appear during build"
    mkdir -p $out
  '';
in {
  meta = {
    nixpkgs = tools.pkgs;
  };

  alpha = { lib, ... }: {
    imports = [
      (tools.getStandaloneConfigFor "alpha")
    ];

    environment.systemPackages = [ testPkg ];
    environment.etc."deployment".text = "SUCCESS";

    system.activationScripts.colmena-test.text = ''
      echo "must appear during activation"
    '';

    deployment.keys.example.text = ''
      key content
    '';
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  beta = tools.getStandaloneConfigFor "beta";
  gamma = tools.getStandaloneConfigFor "gamma";
}
