# Ad Hoc Evaluation

Sometimes you may want to extract values from your Hive configuration for consumption in another program (e.g., [OctoDNS](https://github.com/octodns/octodns)).
To do that, create a `.nix` file with a lambda:

```nix
{ nodes, pkgs, lib, ... }:
# Feels like a NixOS module - But you can return any JSON-serializable value
lib.attrsets.mapAttrs (k: v: v.config.deployment.targetHost) nodes
```

Then you can obtain a JSON output with:

```console
$ colmena eval target-hosts.nix
{"alpha":"fd12:3456::1","beta":"fd12:3456::2"}
```

You can also specify an expression directly on the command line:

```console
$ colmena eval -E '{ nodes, pkgs, lib, ... }: ...'
```

## Instantiation

You may directly instantiate an expression that evaluates to a derivation:

```console
$ colmena eval --instantiate -E '{ nodes, ... }: nodes.alpha.config.boot.kernelPackages.kernel'
/nix/store/7ggmhnwvywrqcd1z2sdpan8afz55sw7z-linux-5.14.14.drv
```
