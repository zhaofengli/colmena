# Migrating from NixOps/morph

Colmena should work with existing NixOps and morph configurations with minimal modification.
That said, there are a few things to look out for:

## Colmena deploys to *existing* NixOS hosts

Unlike NixOps which can be configured to manage the entire lifecycles of NixOS machines (e.g., spinning up AWS EC2 instances), Colmena can only deploy to hosts already running NixOS.

## `network` vs `meta`

Colmena accepts [a set of options](/reference/meta.md) to configure the deployment itself as `meta`.
For NixOps compatibility, it also accepts `network` as an alias so you don't have to change your existing configuration.

## Pinning Nixpkgs

You can pin the nixpkgs version by setting `meta.nixpkgs` (or `network.nixpkgs` if you use the alias).
This is required if you [use Flakes](flakes.md).
The options accepts one of the following:

- Path to a Nixpkgs checkout *(not supported in Flakes)*
    - Example: `./nixpkgs`
- The Nixpkgs lambda returned by importing its `default.nix` *(not supported in Flakes)*
    - Example: `import ./nixpkgs`
- A fully initialized Nixpkgs attribute set
    - Example: `import ./nixpkgs { system = "x86_64-linux"; }`
