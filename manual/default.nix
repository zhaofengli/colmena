let
  notFound = typ: "<span style=\"color: red;\">Error: No ${typ} passed to the builder</span>";
in

{ stdenv, nix-gitignore, mdbook
, release ? null
, deploymentOptionsMd ? notFound "deployment options text"
, metaOptionsMd ? notFound "meta options text"
, colmena ? null
}:

stdenv.mkDerivation {
  inherit colmena deploymentOptionsMd metaOptionsMd release;

  name = if release == null then "colmena-manual-dev" else "colmena-manual-${release}";

  src = nix-gitignore.gitignoreSource [] ./.;

  nativeBuildInputs = [ mdbook ];

  patchPhase = ''
    if [ -n "$release" ]; then
        find . -name '*.md' -exec sed -i "/REMOVE_FOR_RELEASE/d" {} \;
        sed "s/RELEASE/$release/g" book.release.toml > book.toml
    fi
  '';

  buildPhase = ''
    if [ -n "$colmena" ]; then
        echo "Generating CLI help text"
        $colmena/bin/colmena gen-help-markdown >> src/reference/cli.md
    else
        echo "Error: No colmena executable passed to the builder" >> src/reference/cli.md
    fi

    echo "$deploymentOptionsMd" >> src/reference/deployment.md
    echo "$metaOptionsMd" >> src/reference/meta.md

    mdbook build -d $out
  '';

  installPhase = "true";
}
