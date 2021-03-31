{ lib, pkgs, ... }:
let
    inherit (builtins) elem attrNames toJSON;
    inherit (lib) mapAttrs filterAttrs;
in {
    # Utility method to create Colmena hive outputs from a set of NixOS configurations
    mkColmenaHive = { nodes, system }: let
        # convert the deployment config inside the nodes to json
        # nodes must be an attrset of NixOS configurations with hostnames as keys
        deploymentConfig = mapAttrs (name: eval: eval.config.deployment) nodes;
        toplevel = mapAttrs (name: eval: eval.config.system.build.toplevel) nodes;

        nodeNames = attrNames nodes;

        # builds all nodes
        buildAll = buildSelected {
            names = nodeNames;
        };

        # builds selected nodes
        buildSelected = { names ? null }: let
            # Change in the order of the names should not cause a derivation to be created
            selected = filterAttrs (name: _: elem name names) toplevel;
        in derivation rec {
            inherit system;

            #name = "colmena-${hive.meta.name}";
            name = "colmena-hive"; # TODO - where to put this with flakes?
            json = toJSON (mapAttrs (k: v: toString v) selected);
            builder = pkgs.writeScript "${name}.sh" ''
                #!/bin/sh
                echo "$json" > $out
            '';
        };

        introspect = function: function {
            #inherit pkgs lib nodes;
            inherit lib nodes;
        };
    in {
        inherit deploymentConfig toplevel buildAll buildSelected introspect;
    };
}
