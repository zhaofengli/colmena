# Introduction

**Colmena** is a simple, stateless [NixOS](https://nixos.org) deployment tool modeled after [NixOps](https://github.com/NixOS/nixops) and [morph](https://github.com/DBCDK/morph), written in Rust.
It's a thin wrapper over Nix commands like `nix-instantiate` and `nix-copy-closure`, and supports parallel deployment.

Interested? Get started [here](tutorial)!

<pre><div class="hljs">$ <b>colmena apply --on @tag-a</b>
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
</div></pre>

<!-- UNSTABLE_BEGIN -->
You are currently reading **the unstable version** of the Colmena Manual, built against the tip of [the development branch](https://github.com/zhaofengli/colmena).
Features described here will eventually become a part of **version @apiVersion@**.
<!-- UNSTABLE_END -->

<!-- STABLE_BEGIN -->
You are currently reading **version @apiVersion@** of the Colmena Manual, built against version @version@.
<!-- STABLE_END -->

## Links

- [GitHub](https://github.com/zhaofengli/colmena)
- [Deployment Options Reference](reference/deployment.md)
