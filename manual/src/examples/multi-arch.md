# Multi-Architecture Deployments

You can deploy to hosts running different architectures with a single configuration.
There are two ways to achieve this:

## Using `binfmt` Emulation

On Linux hosts, you can run builds through transparent binary emulation using [QEMU and binfmt-misc](https://nixos.wiki/wiki/NixOS_on_ARM#Compiling_through_QEMU).

This following example sets up binfmt, allowing an X86-64 host (`laptop`) to build derivations for an AArch64 host (`rpi`) through QEMU:

```nix
{
  # The NixOS machine you are running Colmena on (x86_64-linux)
  laptop = { pkgs, ... }: {
    # Enable binfmt emulation for aarch64-linux
    boot.binfmt.emulatedSystems = [ "aarch64-linux" ];

    # ... Rest of configuration ...
  };

  # The remote machine running a foreign architecture (aarch64-linux)
  rpi = { pkgs, ... }: {
    # Override nixpkgs architecture
    nixpkgs.system = "aarch64-linux";

    # ... Rest of configuration ...
  };
}
```

*(For Flake users, the above attribute set is the value of `outputs.colmena`)*

First, deploy the local configuration with `colmena apply-local --sudo`.
For more information on what is required on the local system, see [Local Deployment](../features/apply-local.md).

After the new configuration is activated, binfmt emulation will be set up on the local machine.
You can then deploy to the `rpi` node with `colmena apply --on rpi`.

## Building Remotely

If the remote nodes are powerful enough, you may also execute builds on them directly.
See [Remote Builds](../features/remote-builds.md) for more details.
