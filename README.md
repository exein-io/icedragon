# icedragon

Linux cross-compilation suite for building portable, statically linked
software.

Currently supports the following languages:

* C
* C++
* Rust

Icedragon comes in two forms:

* Container images, with a "zero-setup" set of toolchains and essential
  libraries.
* CLI, which leverages the container images, but feels like using a regular
  compiler on your host.

It's based on:

* [Gentoo Linux][gentoo] ([musl-llvm][gentoo-musl-llvm] flavor), which is used
  as the base system for the containers.
  * [crossdev][crossdev], which manages Gentoo sysroots for different
    architectures.
* [musl][musl] libc, which, unlike [glibc][glibc], can be statically linked
  without imposing any runtime dependencies.
* [LLVM][llvm] compiler infrastructer.
* [Rustup][rustup], which is used for managing [Rust][rust] toolchains.

## How is icedragon different from Alpine Linux?

Let's start with similarities. Both icedragon and [Alpine][alpine] are using
[musl][musl] as the C standard library. Both can be used to build portable,
statically linked binaries.

The first difference is that [Alpine][alpine] uses [GCC][gcc]
and [GNU C++ library][libstdc++]. Icedragon uses [LLVM][llvm] and
[LLVM C++ library][libcxx] and doesn't come with [GCC][gcc].

The second difference is strong focus on cross-compilation in icedragon.
Ability to build for different targets without manual setup of a cross
sysroot is one of the most important goals.

## Featured libraries

Icedragon comes with a set of static libraries which can be considered "build
essentials" for the most of C/C++ software on Linux, as well as for Rust
crates, which  don't vendor C dependencies and expect them to be present in the
system.

* Compression libraries:
  * brotli
  * zstd
  * zlib
* Cryptography libraries:
  * gpgme
  * OpenSSL
* JSON
  * json-c
* Key-value stores
  * rocksdb
* Linux-specific libraries and utilities:
  * util-linux
* Network libraries:
  * c-ares
  * libcurl
* Regular expressions:
  * libpcre2

## GNU extensions

Icedragon doesn't use glibc, but it also doesn't require rigurous POSIX
compatibility. It makes use of various projects, which provide ports of GNU
extensions, while still being compatible with a musl/LLVM toolchain:

* [argp-standalone][argp-standalone]
* [error-standalone][error-standalone]
* [llvm-libgcc][llvm-libgcc]
* [musl-fts][musl-tfs]

At the same time, these ports can be linked statically and don't issue any
`dlopen` calls.

[gentoo]: https://www.gentoo.org
[crossdev]: https://wiki.gentoo.org/wiki/Crossdev
[musl]: https://musl.libc.org
[glibc]: https://www.gnu.org/software/libc
[llvm]: https://llvm.org
[rustup]: https://rustup.rs
[rust]: https://www.rust-lang.org
[alpine]: https://www.alpinelinux.org
[gcc]: https://gcc.gnu.org
[libstdc++]: https://gcc.gnu.org/onlinedocs/libstdc++
[libcxx]: https://libcxx.llvm.org
[argp-standalone]: https://github.com/ericonr/argp-standalone
[error-standalone]: https://hacktivis.me/git/error-standalone
[musl-fts]: https://github.com/void-linux/musl-fts
