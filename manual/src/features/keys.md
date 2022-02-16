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
