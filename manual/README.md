# Manual

You can read the rendered version [here](https://zhaofengli.github.io/colmena).

## Building the Manual

The manual is rendered using [mdBook](https://github.com/rust-lang/mdBook).
To build the manual, do `nix build .#manual`.
You can also do `nix build .#manualFast` for a version without the CLI usage reference.

## Marking Text for Specific Versions

You can mark text to be only visible in the unstable version of the manual:

```
<!-- UNSTABLE_BEGIN -->
You are currently reading the unstable version of the Colmena Manual.
Features described here will eventually become a part of version @apiVersion@.
<!-- UNSTABLE_END -->
```

The opposite can be done with the `STABLE_{BEGIN,END}` markers:

```
<!-- STABLE_BEGIN -->
You are currently reading the version @apiVersion@ of the Colmena Manual.
<!-- STABLE_END -->
```

## Substitutions

- `@version@` - Full version string
- `@apiVersion@` - Stable API version string (major.minor)
