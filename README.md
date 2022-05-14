# Colmena

[![Matrix Channel](https://img.shields.io/badge/Matrix-%23colmena%3Anixos.org-blueviolet)](https://matrix.to/#/#colmena:nixos.org)
[![Stable Manual](https://img.shields.io/badge/Manual-Stable-informational)](https://colmena.cli.rs/stable)
[![Unstable Manual](https://img.shields.io/badge/Manual-Unstable-orange)](https://colmena.cli.rs/unstable)
[![Build](https://github.com/zhaofengli/colmena/workflows/Build/badge.svg)](https://github.com/zhaofengli/colmena/actions/workflows/build.yml)

Colmena is a simple, stateless [NixOS](https://nixos.org) deployment tool modeled after [NixOps](https://github.com/NixOS/nixops) and [morph](https://github.com/DBCDK/morph), written in Rust.
It's a thin wrapper over Nix commands like `nix-instantiate` and `nix-copy-closure`, and supports parallel deployment.

Now with 100% more flakes! See *Tutorial with Flakes* below.

<pre>
$ <b>colmena apply --on @tag-a</b>
[INFO ] Enumerating nodes...
[INFO ] Selected 7 out of 45 hosts.
  (...) ✅ 0s Build successful
  <b>sigma</b> 🕗 7s copying path '/nix/store/h6qpk8rwm3dh3zsl1wlj1jharzf8aw9f-unit-haigha-agent.service' to 'ssh://root@sigma.redacted'...
  <b>theta</b> ✅ 7s Activation successful
  <b>gamma</b> 🕘 8s Starting...
  <b>alpha</b> ✅ 1s Activation successful
<b>epsilon</b> 🕗 7s copying path '/nix/store/fhh4rfixny8b21l6jqzk7nqwxva5k20h-nixos-system-epsilon-20.09pre-git' to 'ssh://root@epsilon.redacted'...
   <b>beta</b> 🕗 7s removing obsolete file /boot/kernels/z28ayg10kpnlrz0s2qrb9pzv82lc20s2-initrd-linux-5.4.89-initrd
  <b>kappa</b> ✅ 2s Activation successful
</pre>

## Installation

`colmena` is included in Nixpkgs beginning with 21.11.

Use the following command to enter a shell environment with the `colmena` command:

```bash
nix-shell -p colmena
```

### Unstable Version

To install the latest development version to your user profile:

```bash
nix-env -if https://github.com/zhaofengli/colmena/tarball/main
```

Alternatively, if you have a local clone of the repo:

```bash
nix-env -if default.nix
```

A public binary cache is available at https://colmena.cachix.org, courtesy of Cachix.
This binary cache contains unstable versions of Colmena built by [GitHub Actions](https://github.com/zhaofengli/colmena/actions).

## Tutorial

*See Tutorial with Flakes for usage with Nix Flakes.*

Colmena should work with your existing NixOps and morph configurations with minimal modification.
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
    # Like NixOps and morph, Colmena will attempt to connect to
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

The full set of options can be found in [the manual](https://colmena.cli.rs/unstable/reference).
Run `colmena build` in the same directory to build the configuration, or do `colmena apply` to build and deploy it to all nodes.

## Tutorial with Flakes

To use with Nix Flakes, create `outputs.colmena` in your `flake.nix`.

Here is a short example:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };
  outputs = { nixpkgs, ... }: {
    colmena = {
      meta = {
        nixpkgs = import nixpkgs {
          system = "x86_64-linux";
        };
      };

      # Also see the non-Flakes hive.nix example above.
      host-a = { name, nodes, pkgs, ... }: {
        boot.isContainer = true;
        time.timeZone = nodes.host-b.config.time.timeZone;
      };
      host-b = {
        deployment = {
          targetHost = "somehost.tld";
          targetPort = 1234;
          targetUser = "luser";
        };
        boot.isContainer = true;
        time.timeZone = "America/Los_Angeles";
      };
    };
  };
}
```

The full set of options can be found in [the manual](https://colmena.cli.rs/unstable/reference).
Run `colmena build` in the same directory to build the configuration, or do `colmena apply` to build and deploy it to all nodes.

## Manual

Read [the Colmena Manual](https://colmena.cli.rs).

## Environment Variables

- `SSH_CONFIG_FILE`: Path to a `ssh_config` file

## Current Limitations

- It's required to use SSH keys to log into the remote hosts, and interactive authentication will not work.
- Error reporting is lacking.

## Licensing

Colmena is available under the MIT License.
