#!/bin/sh

# Entrypoint script which installs rustup in case the it's not available.
# `~/.cargo` and `~/.rustup` directories are volumes and are not a part of the
# container image. This is our design decision which allows persistence of
# binary crates and additional Rust toolchains installed by users.

set -e

if ! which rustup > /dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

  # Install stable Rust toolchain with `default` rustup profile (containing
  # rust-docs, rustfmt, and clippy) for all supported targets.
  rustup toolchain install stable --profile=default \
    --target=aarch64-unknown-linux-musl,x86_64-unknown-linux-musl
fi

"$@"
