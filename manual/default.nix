let
  notFound = typ: "<span style=\"color: red;\">Error: No ${typ} passed to the builder</span>";
in

{ lib, stdenv, nix-gitignore, mdbook, python3, writeScript
, deploymentOptionsMd ? notFound "deployment options text"
, metaOptionsMd ? notFound "meta options text"
, colmena ? null

, version ? null   # Full version (default: detected from colmena)
, unstable ? null  # Whether this build is unstable (default: detected from version)
}:

let
  versionComp =
    if version == null then
      if colmena != null then colmena.version else "unstable"
    else version;

  unstableComp =
    if unstable == null then versionComp == "unstable" || lib.hasInfix "-" versionComp
    else unstable;

  apiVersion = builtins.concatStringsSep "." (lib.take 2 (lib.splitString "." versionComp));

  redirectTemplate = lib.escapeShellArg ''
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Redirecting</title>
      <meta http-equiv="refresh" content="0; URL=https://zhaofengli.github.io/colmena@path@">
    </head>
    <body>
      Redirecting to <a href="https://zhaofengli.github.io/colmena@path@">https://zhaofengli.github.io/colmena@path@</a>
    </body>
    </html>
  '';

in stdenv.mkDerivation {
  inherit deploymentOptionsMd metaOptionsMd;

  pname = "colmena-manual" + (if unstableComp then "-unstable" else "");
  version = versionComp;

  src = nix-gitignore.gitignoreSource [] ./.;

  nativeBuildInputs = [ mdbook python3 ];

  outputs = [ "out" "redirectFarm" ];

  COLMENA_VERSION = versionComp;
  COLMENA_UNSTABLE = unstableComp;

  patchPhase = ''
    if [ -z "${toString unstableComp}" ]; then
        sed "s|@apiVersion@|${apiVersion}|g" book.stable.toml > book.toml
    fi
  '';

  buildPhase = ''
    if [ -n "${colmena}" ]; then
        echo "Generating CLI help text"
        ${colmena}/bin/colmena gen-help-markdown >> src/reference/cli.md
    else
        echo "Error: No colmena executable passed to the builder" >> src/reference/cli.md
    fi

    echo "$deploymentOptionsMd" >> src/reference/deployment.md
    echo "$metaOptionsMd" >> src/reference/meta.md

    mdbook build -d $out

    # Build the redirect farm
    # GitHub Pages doesn't play well with directory symlinks. Default
    # pages (index.html) don't work when a symlink is traversed.

    mkdir -p $redirectFarm

    subdir="/unstable"
    if [ -z "${toString unstableComp}" ]; then
      subdir="/${apiVersion}"
    fi

    pushd $redirectFarm
    (cd $out; find . -name "*.html") | while read -r page; do
        strippedPage=''${page#.}
        target="$subdir$strippedPage"
        mkdir -p $(dirname $page)
        echo ${redirectTemplate} | sed "s|@path@|$target|g" > $page
    done
    popd
  '';

  installPhase = "true";
}
