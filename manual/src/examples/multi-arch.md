# Multi-Architecture Deployments

You can deploy to hosts running different architectures with a single configuration.
This requires you to either [set up remote builders](https://nixos.org/manual/nix/stable/advanced-topics/distributed-builds.html) running the foreign architecture(s), or [set up binfmt emulation](https://nixos.wiki/wiki/NixOS_on_ARM#Compiling_through_QEMU) on the host running Colmena.

## `binfmt` Emulation

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
