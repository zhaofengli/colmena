# Local Deployment

For some machines, you may still want to stick with the manual `nixos-rebuild`-type of workflow.
Colmena allows you to build and activate configurations on the host running Colmena itself, provided that:

1. The node must be running NixOS.
1. The node must have `deployment.allowLocalDeployment` set to `true`.
1. The node's _attribute name_ must match the hostname of the machine.

If you invoke `apply-local` with `--sudo`, Colmena will attempt to elevate privileges with `sudo` if it's not run as root.
You may also find it helpful to set `deployment.targetHost` to `null` if you don't intend to deploy to the host via SSH.

As an example, the following `hive.nix` includes a node (`laptop`) that is meant to be only deployed with `apply-local`:

```nix
{
  meta = {
    nixpkgs = ./deps/nixpkgs-stable;

    # I'd like to use the unstable version of Nixpkgs on
    # my desktop machines.
    nodeNixpkgs = {
      laptop = ./deps/nixpkgs-unstable;
    };
  };

  # This attribute name must match the output of `hostname` on your machine
  laptop = { name, nodes, ... }: {
    networking.hostName = "laptop";

    deployment = {
      # Allow local deployment with `colmena apply-local`
      allowLocalDeployment = true;

      # Disable SSH deployment. This node will be skipped in a
      # normal`colmena apply`.
      targetHost = null;
    };

    # ... Rest of configuration ...
  };

  server-a = { pkgs, ... }: {
    # This node will use the default Nixpkgs checkout specified
    # in `meta.nixpkgs`.

    # ... Rest of configuration ...
  };
}
```

On `laptop`, run `colmena apply-local --sudo` to activate the configuration.
