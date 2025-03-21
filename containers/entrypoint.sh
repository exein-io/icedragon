#!/bin/sh

# Entrypoint script which installs rustup in case the it's not available.
# `~/.cargo` and `~/.rustup` directories are volumes and are not a part of the
# container image. This our design decision which allows persistency of binary
# crates and additional Rust toolchains installed by users.

set -e

if ! which rustup > /dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
fi

"$@"
