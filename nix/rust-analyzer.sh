#!/usr/bin/env nix-shell
#! nix-shell -i bash ../shell.nix

exec rust-analyzer "$@"
