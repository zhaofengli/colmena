# Tutorial

## Installation

<!-- STABLE_BEGIN -->

`colmena` is included in Nixpkgs beginning with 21.11.

For this tutorial, use the following command to enter an ephemeral environment with the `colmena` command:

```bash
nix-shell -p colmena
```

If you are interested in trying out the bleeding-edge version of Colmena, Read [the unstable version](https://colmena.cli.rs/unstable) of the Manual for instructions.
<!-- STABLE_END -->

<!-- UNSTABLE_BEGIN -->

To install the latest development version to the user profile, use the following command:

```bash
nix-env -if https://github.com/zhaofengli/colmena/tarball/main
```

To install the latest stable version, read [the corresponding Manual](https://colmena.cli.rs/stable) for instructions.

### Unstable Binary Cache

A public binary cache is available at [https://colmena.cachix.org](https://colmena.cachix.org), courtesy of Cachix.
This binary cache contains unstable versions of Colmena built by [GitHub Actions](https://github.com/zhaofengli/colmena/actions).
<!-- UNSTABLE_END -->

## Basic Configuration

*If you use Nix Flakes, follow the Flake version [here](flakes.md).*

Colmena should work with your existing NixOps and morph configurations with minimal modification (see [Migrating from NixOps/morph](migration.md)).

Here is a sample `hive.nix` with two nodes, with some common configurations applied to both nodes:

```nix
{
  meta = {
    # Override to pin the Nixpkgs version (recommended). This option
    # accepts one of the following:
    # - A path to a Nixpkgs checkout
    # - The Nixpkgs lambda (e.g., import <nixpkgs>)
    # - An initialized Nixpkgs attribute set
    nixpkgs = <nixpkgs>;

    # You can also override Nixpkgs by node!
    nodeNixpkgs = {
      node-b = ./another-nixos-checkout;
    };

    # If your Colmena host has nix configured to allow for remote builds
    # (for nix-daemon, your user being included in trusted-users)
    # you can set a machines file that will be passed to the underlying
    # nix-store command during derivation realization as a builders option.
    # For example, if you support multiple orginizations each with their own
    # build machine(s) you can ensure that builds only take place on your
    # local machine and/or the machines specified in this file.
    # machinesFile = ./machines.client-a;
  };

  defaults = { pkgs, ... }: {
    # This module will be imported by all hosts
    environment.systemPackages = with pkgs; [
      vim wget curl
    ];

    # By default, Colmena will replace unknown remote profile
    # (unknown means the profile isn't in the nix store on the
    # host running Colmena) during apply (with the default goal,
    # boot, and switch).
    # If you share a hive with others, or use multiple machines,
    # and are not careful to always commit/push/pull changes
    # you can accidentaly overwrite a remote profile so in those
    # scenarios you might want to change this default to false.
    # deployment.replaceUnknownProfiles = true;
  };

  host-a = { name, nodes, ... }: {
    # The name and nodes parameters are supported in Colmena,
    # allowing you to reference configurations in other nodes.
    networking.hostName = name;
    time.timeZone = nodes.host-b.config.time.timeZone;

    boot.loader.grub.device = "/dev/sda";
    fileSystems."/" = {
      device = "/dev/sda1";
      fsType = "ext4";
    };
  };

  host-b = {
    # Like NixOps and Morph, Colmena will attempt to connect to
    # the remote host using the attribute name by default. You
    # can override it like:
    deployment.targetHost = "host-b.mydomain.tld";

    # It's also possible to override the target SSH port.
    # For further customization, use the SSH_CONFIG_FILE
    # environment variable to specify a ssh_config file.
    deployment.targetPort = 1234;

    # Override the default for this target host
    deployment.replaceUnknownProfiles = false;

    # You can filter hosts by tags with --on @tag-a,@tag-b.
    # In this example, you can deploy to hosts with the "web" tag using:
    #    colmena apply --on @web
    # You can use globs in tag matching as well:
    #    colmena apply --on '@infra-*'
    deployment.tags = [ "web" "infra-lax" ];

    time.timeZone = "America/Los_Angeles";

    boot.loader.grub.device = "/dev/sda";
    fileSystems."/" = {
      device = "/dev/sda1";
      fsType = "ext4";
    };
  };
}
```

The full set of `deployment` options can be found [here](../reference/deployment.md).

Now you are ready to use Colmena! To build the configuration:

```bash
colmena build
```

To build and deploy to all nodes:

```bash
colmena apply
```

## Next Steps

- Head to the [Features](../features/index.md) section to see what else Colmena can do.
- Read more about options available in Colmena in the [Reference](../reference/index.md) section.

