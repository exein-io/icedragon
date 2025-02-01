# icedragon

Linux cross-compilation suite for building portable, statically linked
software.

Currently supports the following languages:

* C
* C++
* Rust

Icedragon consists of two parts:

* Container images, with a "zero-setup" set of toolchains and essential
  libraries.
* CLI, which leverages the container images, but feels like using a regular
  compiler on your host.

It's based on:

* [Gentoo] ([musl-llvm] flavor), which is used as the base system for the
  containers.
  * [crossdev], which manages [Gentoo] sysroots for different
    architectures.
* [musl] libc, which, unlike [glibc], can be statically linked
  without imposing any runtime dependencies.
* [LLVM] compiler infrastructure.
* [rustup], which is used for managing [Rust] toolchains.

## How is icedragon different from Alpine Linux?

Let's start with similarities. Both icedragon and [Alpine] are using
[musl] as the C standard library. Both can be used to build portable,
statically linked binaries.

The most important difference is that icedragon is not a Linux distribution.
It's just [Gentoo] with specific configuration, provided as ready to use
containers. All packaging-related work necessary for icedragon to work is done
upstream.

The second difference is that [Alpine] uses [GCC] and [GNU C++ library].
Icedragon uses [LLVM] and [LLVM C++ library] and doesn't come with [GCC].

The last difference is strong focus on cross-compilation in icedragon, which
provides sysroots and toolchains for foreign architectures out of the box. It
does so thanks to [crossdev], which allows management and installation of
packages inside sysroots. There is no such tooling on Alpine.

## Featured libraries

Icedragon comes with a set of static libraries which can be considered "build
essentials" for the most of C/C++ software on Linux, as well as for Rust
crates, which don't vendor C dependencies and expect them to be present in the
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

musl aims to stay compatible with the [POSIX C standard] for the sake of
portability. [glibc], on the other hand, adds so called [GNU extensions] -
additional modules and functions which are not part of the standard. As a
result, software making use of GNU extensions doesn't build with musl.

However, there are projects which provide standalone, musl-compatible ports of
various GNU extensions:

* [argp-standalone]
* [error-standalone]
* [musl-fts]

They still don't provide 100% compatibility with glibc, but they are good enough
to make building of most [Gentoo] packages possible.

These ports can be linked statically and don't issue any `dlopen` calls.

A similar incompatibility exists between [compiler-rt] (the runtime library
provided by [LLVM], used in icedragon), and [libgcc] (a similar library
provided by [GCC]). [libgcc] comes with extensions, which are not included by
default in [compiler-rt]. It also exports symbols from [libunwind] ([GCC]'s
unwinder library).

LLVM community addressed that problem by creating [llvm-libgcc] subproject,
which:

* Builds a copy of [compiler-rt] with GNU extensions enabled.
* Uses [LLVM libunwind], which is compatible with GCC's unwinder library.
* Links them together, providing a drop-in replacement for [libgcc].

icedragon provides all the GNU extension ports mentioned above.

[Gentoo]: https://www.gentoo.org
[crossdev]: https://wiki.gentoo.org/wiki/Crossdev
[musl]: https://musl.libc.org
[glibc]: https://www.gnu.org/software/libc
[LLVM]: https://llvm.org
[rustup]: https://rustup.rs
[Rust]: https://www.rust-lang.org
[Alpine]: https://www.alpinelinux.org
[GCC]: https://gcc.gnu.org
[GNU C++ library]: https://gcc.gnu.org/onlinedocs/libstdc++
[LLVM C++ library]: https://libcxx.llvm.org
[POSIX C library]: https://en.wikipedia.org/wiki/C_POSIX_library
[GNU extensions]: https://www.gnu.org/software/gnulib/manual/html_node/Glibc-Function-Substitutes.html
[argp-standalone]: https://github.com/ericonr/argp-standalone
[error-standalone]: https://hacktivis.me/git/error-standalone
[musl-fts]: https://github.com/void-linux/musl-fts
[libgcc]: https://gcc.gnu.org/onlinedocs/gccint/Libgcc.html
[libunwind]: https://libunwind.nongnu.org/docs.html
[llvm-libgcc]: https://github.com/llvm/llvm-project/tree/main/llvm-libgcc
[LLVM libunwind]: https://github.com/llvm/llvm-project/tree/main/libunwind
