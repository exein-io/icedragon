#!/bin/sh

set -e

if ! which rustup > /dev/null 2>&1; then
  # Set up symlinks from system-wide installation of rustup to ~/.cargo and
  # ~/.rustup.
  rustup-init-gentoo --symlink

  # Install the current stable toolchain, set it as default.
  rustup toolchain install stable
  rustup default stable
fi

"$@"
