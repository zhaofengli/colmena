{ pkgs ? import ../nixpkgs.nix }:

let
  tools = pkgs.callPackage ../tools.nix {
    deployers = [ "deployer" "alpha" "beta" ];
    targets = [];
  };
in tools.makeTest {
  name = "colmena-build-on-target";

  bundle = ./.;

  testScript = ''
    # The actual build will be initiated on alpha
    deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply --on alpha")

    with subtest("Check that the new configurations are indeed applied"):
        alpha.succeed("grep SUCCESS /etc/deployment")

    alpha_profile = alpha.succeed("readlink /run/current-system")

    with subtest("Check that the built profile is not on the deployer"):
        deployer.fail(f"nix-store -qR {alpha_profile}")

    with subtest("Check that we can override per-node settings and build locally"):
        deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} build --on alpha --no-build-on-target")
        deployer.succeed(f"nix-store -qR {alpha_profile}")

    with subtest("Check that we can override per-node settings and build remotely"):
        deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply --on beta --build-on-target")
        beta.succeed("grep SUCCESS /etc/deployment")
        profile = beta.succeed("readlink /run/current-system")
        deployer.fail(f"nix-store -qR {profile}")
  '';
}
