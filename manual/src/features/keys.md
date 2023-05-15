# Secrets

Colmena allows you to upload secret files that will not be stored in the Nix store to nodes.
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

      destDir = "/run/keys";       # Default: /run/keys
      user = "acme";               # Default: root
      group = "nginx";             # Default: root
      permissions = "0640";        # Default: 0600

      uploadAt = "pre-activation"; # Default: pre-activation, Alternative: post-activation
    };
    # Rest of configuration...
  };
}
```

Take note that if you use the default path (`/run/keys`), the secret files are only stored in-memory and will not survive reboots.
To upload your secrets without performing a full deployment, use `colmena upload-keys`.

## Key Services

For each secret file deployed using `deployment.keys`, a systemd service with the name of `${name}-key.service` is created (`acme-credentials.secret-key.service` for the example above).
This unit is only active when the corresponding file is present, allowing you to set up dependencies for services requiring secret files to function.

## Key Permissions

The `/run/keys` directory is owned by the `keys` group. If you are using a
systemd service running as a non-root user, you will likely need to add:
```
SupplementaryGroups = [ "keys" ];
```
to your service configuration.

## Flakes

If you are using flakes, Nix will copy the entire flake (everything tracked by git) into the Nix store during evaluation.
This means that all files as checked out by git are world-readable, including the ones managed by filter-based encryption tools like `git-crypt`.
To use `deployment.keys.<name>.keyFile` with flakes without having the secrets copied to the Nix store, a quoted absolute path can be used.
