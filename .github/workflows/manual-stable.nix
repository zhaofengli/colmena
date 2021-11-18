name: Manual (Stable)

on:
  push:
    branches:
      - release-0.2.x
jobs:
  deploy:
    env:
      LATEST_STABLE_API: 0.2

    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2.3.5
      - uses: cachix/install-nix-action@v15
        with:
          install_url: https://releases.nixos.org/nix/nix-2.4/install
          extra_nix_config: |
            experimental-features = nix-command flakes
      - uses: cachix/cachix-action@v10
        with:
          name: colmena
          authToken: '${{ secrets.CACHIX_AUTH_TOKEN }}'

      - name: Check API version
        run: echo "api_version=$(nix eval .#colmena.apiVersion)" >> $GITHUB_ENV

      # == Manual
      - name: Build manual
        run: nix build -o out .#manual -L

      # Ugly hack so it has permission to delete the worktree afterwards
      - name: Copy manual
        run: cp --no-preserve=mode -r out/ public/

      - name: Deploy manual
        uses: JamesIves/github-pages-deploy-action@4.1.5
        with:
          branch: gh-pages
          folder: public
          target-folder: '${{ env.api_version }}'

      # == Redirect Farm for Latest Stable
      # /stable -> /api_version

      - name: Build redirect farm
        run: nix build -o out .#manual.redirectFarm -L
        if: ${{ env.api_version == env.LATEST_STABLE_API }}

      # Ugly hack so it has permission to delete the worktree afterwards
      - name: Copy redirect farm
        run: cp --no-preserve=mode -r out-redirectFarm/ redirect-farm/
        if: ${{ success() }}

      - name: Deploy redirect farm
        uses: JamesIves/github-pages-deploy-action@4.1.5
        with:
          branch: gh-pages
          folder: redirect-farm
          target-folder: stable
        if: ${{ success() }}
