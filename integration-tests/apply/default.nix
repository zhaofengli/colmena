let
  tools = import ../tools.nix {};
in tools.makeTest {
  name = "colmena-apply";

  bundle = ./.;

  testScript = ''
    poison = " ".join(["this", "must", "not", "exist", "in", "nix", "store"])
    deployer.succeed(f"echo '{poison}' > /tmp/bundle/key-file")
    deployer.succeed(f"sed -i 's|@poison@|{poison}|g' /tmp/bundle/hive.nix")

    # HACK: copy stderr to both stdout and stderr
    # (stdout is what's returned, and only stderr appears on screen during the build)
    logs = deployer.succeed("cd /tmp/bundle && ${tools.colmenaExec} apply -v --eval-node-limit 4 --on @target 2> >(tee /dev/stderr)")

    with subtest("Check that evaluation messages were logged correctly"):
        assert "must appear during evaluation" in logs

    with subtest("Check that build messages were logged correctly"):
        assert "must appear during build" in logs

    with subtest("Check that push messages were logged correctly"):
        assert "copying path" in logs

    with subtest("Check that activation messages were logged correctly"):
        assert "must appear during activation" in logs

    with subtest("Check that we can still connect to the target nodes"):
        deployer.succeed("ssh alpha true")
        deployer.succeed("ssh beta true")
        deployer.succeed("ssh gamma true")

    with subtest("Check that the new configuration is indeed applied"):
        alpha.succeed("grep SUCCESS /etc/deployment")

    with subtest("Check that key files have correct contents"):
        contents = {
            "/run/keys/key-text":               poison,
            "/tmp/another-key-dir/key-command": "deployer",
            "/tmp/another-key-dir/key-file":    poison,
            "/tmp/another-key-dir/key-file-2":  poison,
            "/run/keys/pre-activation":         "pre-activation key",
            "/run/keys/post-activation":        "post-activation key",
        }

        for path, content in contents.items():
            alpha.succeed(f"grep '{content}' '{path}'")

    with subtest("Check that key files have correct permissions"):
        alpha.succeed("getent passwd testuser")
        alpha.succeed("getent group testgroup")

        permissions = {
            "/run/keys/key-text":               "600 root root",
            "/tmp/another-key-dir/key-command": "600 root root",
            "/tmp/another-key-dir/key-file":    "600 root root",
            "/tmp/another-key-dir/key-file-2":  "600 root root",
            "/run/keys/pre-activation":         "640 testuser testgroup",
            "/run/keys/post-activation":        "600 testuser testgroup",
        }

        for path, permission in permissions.items():
            alpha.succeed(f"if [[ \"{permission}\" != \"$(stat -c '%a %U %G' '{path}')\" ]]; then ls -lah '{path}'; exit 1; fi")

    with subtest("Check that key contents are not in the Nix store"):
        new_store_paths = " ".join(get_new_store_paths())

        ret, stdout = deployer.execute(f"grep -r '{poison}' {new_store_paths}")

        if ret != 1:
            deployer.log("Forbidden text found in: " + stdout)

        assert ret == 1

    with subtest("Check that our Nix store test is actually working"):
        deployer.succeed(f"nix-build -E 'with import <nixpkgs> {{}}; writeText \"forbidden-text.txt\" \"{poison}\"'")
        new_store_paths = " ".join(get_new_store_paths())
        deployer.succeed(f"grep -r '{poison}' {new_store_paths}")
  '';
}
