# Colmena

![Build](https://github.com/zhaofengli/colmena/workflows/Build/badge.svg)

Colmena is a simple, stateless [NixOS](https://nixos.org) deployment tool modeled after [NixOps](https://github.com/NixOS/nixops) and [Morph](https://github.com/DBCDK/morph), written in Rust.
It's a thin wrapper over Nix commands like `nix-instantiate` and `nix-copy-closure`, and supports parallel deployment.

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

Colmena is still an early prototype.

## Installation

Colmena doesn't have a stable release yet.
To install the latest development version to the user profile, use `default.nix`:

```
nix-env -if default.nix
```

## Tutorial

Enter a shell with `colmena` with:
```
nix-shell
```

Colmena should work with your existing NixOps and Morph configurations with minimal modification.
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

    # It's also possible to override the target SSH port.
    # For further customization, use the SSH_CONFIG_FILE
    # environment variable to specify a ssh_config file.
    deployment.targetPort = 1234;

    time.timeZone = "America/Los_Angeles";

    boot.loader.grub.device = "/dev/sda";
    fileSystems."/" = {
      device = "/dev/sda1";
      fsType = "ext4";
    };
  };
}
```

The full set of options can be found at `src/nix/eval.nix`.
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

## `colmena apply-local`

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

    # Rest of configuration...
  };

  server-a = { pkgs, ... }: {
    # This node will use the default Nixpkgs checkout specified
    # in `meta.nixpkgs`.

    # Rest of configuration...
  };
}
```

On `laptop`, run `colmena apply-local --sudo` to activate the configuration.

## Secrets

Colmena allows you to upload secret files to nodes that will not be stored in the Nix store.
It implements a subset of the `deployment.keys` options supported by NixOps.

For example, to deploy DNS-01 credentials for use with `security.acme`:

```nix
{
  shared-box = {
    security.acme.certs."my-site.tld".credentialsFile = "/run/keys/acme-credentials.secret";
    deployment.keys."acme-credentials.secret" = {
      # Alternatively, `text` (string) or `keyFile` (path to file)
      # may be specified.
      keyCommand = [ "vault" "read" "-field=env" "secret/dns01" ];

      destDir = "/run/keys"; # Default: /run/keys
      user = "acme";         # Default: root
      group = "nginx";       # Default: root
      mode = "0640";         # Default: 0600
    };
    # Rest of configuration...
  };
}
```

Take note that if you use the default path (`/run/keys`), the secret files are only stored in-memory and will not survive reboots.
To upload your secrets without performing a full deployment, use `colmena upload-keys`.

## Parallelism

Colmena is built from the ground up to support parallel deployments.
Evaluation, build, and deployment of node configurations can happen at the same time.
This parallelism can be controlled primarily through two flags:

- `--limit <number>`: Number of hosts to deploy at once in the final step (pushing closures and activating new profiles).
- `--eval-node-limit <number>`: By default, Colmena will automatically determine the maximum number of nodes to evaluate at the same time according to available RAM. This flag allows you to set the limit to a predetermined value.

## Environment variables

- `SSH_CONFIG_FILE`: Path to a `ssh_config` file

## Current limitations

- It's required to use SSH keys to log into the remote hosts, and interactive authentication will not work.
- Error reporting is lacking.

## Licensing

Colmena is available under the MIT License.
