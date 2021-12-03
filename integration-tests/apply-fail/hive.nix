let
  tools = import ./tools.nix { insideVm = true; };

  testPkg = let
    text = builtins.trace "must appear during evaluation" ''
      echo "must appear during build"
      mkdir -p $out
    '';
  in tools.pkgs.runCommand "test-package" {} text;
in {
  meta = {
    nixpkgs = tools.pkgs;
  };

  defaults = {
    environment.etc."deployment".text = "SUCCESS";
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  alpha = tools.getStandaloneConfigFor "alpha";
  beta = tools.getStandaloneConfigFor "beta";
  gamma = tools.getStandaloneConfigFor "gamma";
}
