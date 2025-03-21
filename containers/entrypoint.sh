#!/bin/sh

# Entrypoint script which installs rustup in case the it's not available.
# `~/.cargo` and `~/.rustup` directories are volumes and are not a part of the
# container image. This our design decision which allows persistency of binary
# crates and additional Rust toolchains installed by users.

set -e

if ! which rustup > /dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

  # Install stable and beta Rust toolchains with `default` rustup profile
  # (containing rust-docs, rustfmt, and clippy) for all supported targets.
  #
  # Install nightly Rust toolchains with `complete` rustup profile (containing
  # all components provided by rustup, available only for nightly toolchains)
  # for all supported targets.
  rustup toolchain install stable beta --profile=default \
    --target=aarch64-unknown-linux-musl,x86_64-unknown-linux-musl
  rustup toolchain install nightly --profile=complete \
    --target=aarch64-unknown-linux-musl,x86_64-unknown-linux-musl
fi

"$@"
