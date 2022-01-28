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
    environment.etc."deployment".text = "FIRST";

    # Will be created during activation
    users.users.testuser = {
      isSystemUser = true;
      group = "testgroup";
    };
    users.groups.testgroup = {};

    # /run/keys/custom-name
    deployment.keys.original-name = {
      name = "custom-name";
      text = "@poison@";
    };

    # /run/keys/key-text
    deployment.keys.key-text = {
      text = "@poison@";
    };

    # /tmp/another-key-dir/key-command
    deployment.keys.key-command = {
      destDir = "/tmp/another-key-dir";
      keyCommand = [ "hostname" ];
    };

    # /tmp/another-key-dir/key-file
    deployment.keys.key-file = {
      destDir = "/tmp/another-key-dir";
      keyFile = "/tmp/bundle/key-file";
    };

    # /tmp/another-key-dir/key-file-2
    deployment.keys.key-file-2 = {
      destDir = "/tmp/another-key-dir";
      keyFile = ./key-file;
    };

    # /run/keys/pre-activation
    deployment.keys.pre-activation = {
      text = "pre-activation key";
      uploadAt = "pre-activation";

      user = "testuser";
      group = "testgroup";
      permissions = "640";
    };

    # /run/keys/post-activation
    deployment.keys.post-activation = {
      text = "post-activation key";
      uploadAt = "post-activation";

      user = "testuser";
      group = "testgroup";
      permissions = "600";
    };
  };

  alpha = { lib, ... }: {
    imports = [
      (tools.getStandaloneConfigFor "alpha")
    ];

    environment.systemPackages = [ testPkg ];

    documentation.nixos.enable = lib.mkForce true;

    system.activationScripts.colmena-test.text = ''
      echo "must appear during activation"
    '';
  };

  deployer = tools.getStandaloneConfigFor "deployer";
  beta = tools.getStandaloneConfigFor "beta";
  gamma = tools.getStandaloneConfigFor "gamma";
}
