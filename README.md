# Colmena

Colmena is a simple, stateless NixOS deployment tool modeled after [NixOps](https://github.com/NixOS/nixops) and [Morph](https://github.com/DBCDK/morph), written in Rust.
It's a thin wrapper over Nix commands like `nix-instantiate` and `nix-copy-closure`, and supports parallel deployment.

Colmena is still an early prototype.

## Tutorial

Enter a `nix-shell` with `colmena` with:
```
nix-shell test-shell.nix
```

Colmena should work with your existing NixOps and Morph configurations with minimal modification.
Here is a sample `hive.nix` with two nodes, with some common configurations applied to both nodes:

```nix
{
  network = {
    # Override to pin the Nixpkgs version (recommended). This option
    # accepts one of the following:
    # - A path to a Nixpkgs checkout
    # - The Nixpkgs lambda (e.g., import <nixpkgs>)
    # - An initialized Nixpkgs attribute set
    nixpkgs = <nixpkgs>;
  };

  defaults = { pkgs, ... }: {
    # This module will be imported by all hosts
    environment.systemPackages = with pkgs; [
      vim wget curl
    ];
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

    time.timeZone = "America/Los_Angeles";

    boot.loader.grub.device = "/dev/sda";
    fileSystems."/" = {
      device = "/dev/sda1";
      fsType = "ext4";
    };
  };
}
```

The full set of options can be found at `src/eval.nix`.
Run `colmena build` in the same directory to build the configuration, or do `colmena apply` to deploy it to all nodes.

## `colmena introspect`

Sometimes you may want to extract values from your Hive configuration for consumption in another program (e.g., [OctoDNS](https://github.com/octodns/octodns)).
To do that, create a `.nix` file with a lambda:

```nix
{ nodes, pkgs, lib, ... }:
# Feels like a NixOS module - But you can return any JSON-serializable value
lib.attrsets.mapAttrs (k: v: v.config.deployment.targetHost) nodes
```

Then you can evaluate with:

```
colmena introspect your-lambda.nix
```

## Current limitations

- It's required to use SSH keys to log into the remote hosts, and interactive authentication will not work.
- There is no option to override SSH or `nix-copy-closure` options.
- Error reporting is lacking.

## Licensing

Colmena is available under the MIT License.
