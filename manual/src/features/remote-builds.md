# Remote Builds

If the host running Colmena is not powerful enough, consider offloading the actual builds to remote machines.
Colmena supports two ways to achieve this:

## Using Colmena's `deployment.buildOnTarget`

If you set [`deployment.buildOnTarget = true;`](../reference/deployment.md#deploymentbuildontarget) for a node, then the actual build process will be initiated on the node itself.
Colmena will evaluate the configuration locally before copying the derivations to the target node.
You can temporarily enable this for all nodes by passing `--build-on-target` on the command line, or disable it with `--no-build-on-target`.

This is most useful in scenarios where the machine running Colmena is bandwidth-constrained, or it's inconvenient to configure designated builders beforehand.
With this method, the build results will _not_ be copied back to the local machine or otherwise shared across the target nodes.
If you have custom packages used on multiple nodes, the work required to build those packages will be duplicated across the nodes.

## Using the native distributed build feature in Nix

When [distributed build](https://nixos.org/manual/nix/unstable/advanced-topics/distributed-builds.html) is enabled, Nix will transparently forward builds to the configured builders.
After the builds are done, Nix will copy the results back to the local machine.

Builders can either be configured globally or in your configuration with [`meta.machinesFile`](../reference/meta.md#machinesFile).
