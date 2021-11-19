# Usage with Flakes

## Installation

<!-- STABLE_BEGIN -->
To quickly try Colmena out, use the following command to enter an ephemeral environment with the latest stable version of `colmena`:

```bash
nix shell github:zhaofengli/colmena/stable
```

To install Colmena to the user profile, use the following command:

```bash
nix-env -if https://github.com/zhaofengli/colmena/tarball/stable
```

You can also add `github:zhaofengli/colmena/stable` as an input in your Flake and add the `colmena` package to your `devShell`.

If you are interested in trying out the bleeding-edge version of Colmena, Read [the unstable version](https://zhaofengli.github.io/colmena/unstable) of the Manual for instructions.
<!-- STABLE_END -->

<!-- UNSTABLE_BEGIN -->
<!-- To install the latest stable version, read [the corresponding Manual](https://zhaofengli.github.io/colmena/stable) for instructions. -->

To quickly try Colmena out, use the following command to enter an ephemeral environment with the latest development version of `colmena`:

```bash
nix shell github:zhaofengli/colmena
```

To install Colmena to the user profile, use the following command:

```bash
nix-env -if https://github.com/zhaofengli/colmena/tarball/main
```

You can also add `github:zhaofengli/colmena` as an input in your Flake and add the `colmena` package to your `devShell`.

### Unstable Binary Cache

A public binary cache is available at [https://colmena.cachix.org](https://colmena.cachix.org), courtesy of Cachix.
This binary cache contains unstable versions of Colmena built by [GitHub Actions](https://github.com/zhaofengli/colmena/actions).
<!-- UNSTABLE_END -->

## Basic Configuration

Colmena reads the `colmena` output in your Flake.

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

The full set of `deployment` options can be found [here](../reference/deployment.md).
You can also check out the example in [the main tutorial](index.md) for some inspiration.

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
