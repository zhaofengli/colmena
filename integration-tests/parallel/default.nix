{ pkgs }:

let
  tools = pkgs.callPackage ../tools.nix {};
in tools.runTest {
  name = "colmena-parallel";

  colmena.test = {
    bundle = ./.;

    testScript = ''
      deployer.succeed("cd /tmp/bundle &&" \
          "${tools.colmenaExec} apply push --eval-node-limit 4 --on @target")

      logs = deployer.succeed("cd /tmp/bundle &&" \
          "run-copy-stderr ${tools.colmenaExec} apply switch --eval-node-limit 4 --parallel 4 --on @target")

      for node in [alpha, beta, gamma]:
          node.succeed("grep SUCCESS /etc/deployment")

      with subtest("Check that activation is correctly parallelized"):
          timestamps = list(map(lambda l: int(l.strip().split("---")[1]) / 1000000,
              filter(lambda l: "Activation triggered" in l, logs.split("\n"))))

          delay = max(timestamps) - min(timestamps)
          deployer.log(f"Time between activations: {delay}ms")

          assert delay < 2000
    '';
  };
}
