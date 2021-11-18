# Node Tagging

With node tags, you can quickly select a subset of nodes for deployment.
You can specify tags using the `deployment.tags` option:

```nix
{
  alpha = { pkgs, ... }: {
    deployment.tags = [ "web" "infra-lax" ];

    # ... Rest of configuration ...
  };
  beta = { pkgs, ... }: {
    deployment.tags = [ "infra-sfo" ];

    # ... Rest of configuration ...
  };
}
```

You can filter hosts by tags or names with `--on`, which accepts a comma-separated list of node names or @tags.

To select all nodes with `web`:

```console
$ colmena apply --on @web
```

Wildcards are supported as well.
To select all nodes with a tag beginning with `infra-`:

```console
$ colmena apply --on '@infra-*'
```
*(Note the quotes around the argument)*
