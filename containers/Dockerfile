FROM docker.io/gentoo/stage3:musl-llvm

# The newest LLVM major version which is stabilited in Gentoo.
# See: https://packages.gentoo.org/packages/llvm-core/llvm
ARG LLVM_VERSION=19

# Gentoo stores LLVM toolchains in "slotted" directories inside /usr/lib/llvm.
# Rustup stores Rust toolchains in ~/.cargo/bin. Add these directories to PATH.
ENV PATH="/root/.cargo/bin:/usr/lib/llvm/${LLVM_VERSION}/bin:${PATH}"
# Enable static libraries for installed packages (zstd, zlib etc.).
ENV USE="static-libs"
# Specify QEMU targets to enable.
ENV QEMU_USER_TARGETS="aarch64 x86_64"

COPY package.accept_keywords/* /etc/portage/package.accept_keywords/

# Install QEMU, which can be used for running foreign binaries and therefore is
# useful for running `cargo test` for foreign targets.
#
# Install git, needed by cargo if there are any `git` dependencies specified.
#
# Install crossdev[0], which is a manager of cross sysroots, providing wrapper
# for:
# * clang, which can be used for compiling C/C++ projects without doing the
#   whole dance with `--target` and `--sysroot` arguments.
# * emerge, which let you install packages in the cross sysroot.
# For example, if you create a sysroot for aarch64-unknown-linux-musl, crossdev
# creates aarch64-linux-musl-clang{,++} and aarch64-linux-musl-emerge wrappers.
#
# Install llvm-libgcc[1] which is an unified flavor of LLVM runtime libraries
# (compiler-rt, libunwind) with GNU symbols (which are not provided in default
# builds of compiler-rt). It can be used as a drop-in replacement for GCC
# runtime library (libgcc_s). Rust toolchain binaries provided by rustup are
# linked against libgcc_s and don't work with vanilla LLVM compiler
# runtime[2][3], so llvm-libgcc is required for rustup to work.
#
# Create cross sysroots using crossdev for the following targets:
#
# * aarch64-unknown-linux-musl
# * x86_64-unknown-linux-musl
#
# Unpack the stage3 tarball into that sysroot to avoiding compilation of the
# whole base system from scratch. Otherwise, bootstraping the base sysroot with
# `aarch64-unknown-linux-musl-emerge @system` would take an eternity to run on
# free GitHub runners.
#
# This container image is multiarch, so we make no assumption about the host
# architecture and therefore, we don't directly use the main sysroot for
# anything else than managing sysroots and Rust toolchains. Instead, we use
# crossdev sysroots for performing the actual builds.
#
# Install the following dependencies, which can be considered "build essentials"
# for the most of C/C++ software on Linux, as well as for Rust crates, which
# don't vendor C dependencies and expect them to be present in the system. All of
# these dependencies provide static libraries.
#
# * Ports of GNU, non-POSIX functionality:
#   * llvm-libgcc (we provide it not only on the host system, but also in
#     sysroots, to allow linking libgcc_s)
#   * musl-compatible ports of glibc's GNU extensions:
#     * argp-standalone
#     * error-standalone
#     * musl-fts (packaged as fts-standalone in Gentoo)
# * Compression libraries:
#   * brotli
#   * xz
#   * zstd
#   * zlib
# * Cryptography libraries:
#   * gpgme
#   * OpenSSL
# * Databases
#   * sqlite
#   * rocksdb
# * JSON
#   * json-c
# * Linux-specific libraries and utilities:
#   * util-linux
# * Network libraries:
#   * c-ares
#   * libcurl
# * Regular expressions:
#   * libpcre2
#
# [0] https://wiki.gentoo.org/wiki/Crossdev
# [1] https://github.com/llvm/llvm-project/tree/main/llvm-libgcc
# [2] https://github.com/rust-lang/rust/issues/119504
# [3] https://github.com/rust-lang/rustup/issues/2213#issuecomment-1888615413
RUN emerge-webrsync \
    && emerge \
        app-emulation/qemu \
        app-eselect/eselect-repository \
        app-misc/ca-certificates \
        dev-libs/protobuf \
        dev-vcs/git \
        llvm-runtimes/libgcc \
        sys-devel/crossdev \
    && eselect repository create crossdev \
    && crossdev --llvm --target aarch64-unknown-linux-musl \
    && curl -L "https://ftp-osl.osuosl.org/pub/gentoo/releases/arm64/autobuilds/current-stage3-arm64-musl-llvm/$(\
        curl -L "https://ftp-osl.osuosl.org/pub/gentoo/releases/arm64/autobuilds/current-stage3-arm64-musl-llvm/latest-stage3-arm64-musl-llvm.txt" | \
        grep tar.xz | cut -d ' ' -f 1)" | \
        tar -xJpf - -C /usr/aarch64-unknown-linux-musl --exclude=dev --skip-old-files \
    && ln -s \
        /etc/portage/repos.conf \
        /usr/aarch64-unknown-linux-musl/etc/portage/repos.conf \
    && ln -s \
        /etc/portage/package.accept_keywords/* \
        /usr/aarch64-unknown-linux-musl/etc/portage/package.accept_keywords \
    && PORTAGE_CONFIGROOT=/usr/aarch64-unknown-linux-musl eselect profile set \
        default/linux/arm64/23.0/musl/llvm \
    && aarch64-unknown-linux-musl-emerge \
        app-arch/brotli \
        app-arch/xz-utils \
        app-arch/zstd \
        app-crypt/gpgme \
        dev-db/sqlite \
        dev-libs/json-c \
        dev-libs/libpcre2 \
        dev-libs/openssl \
        dev-libs/rocksdb \
        llvm-runtimes/libgcc \
        net-dns/c-ares \
        net-misc/curl \
        sys-apps/util-linux \
        sys-libs/argp-standalone \
        sys-libs/error-standalone \
        sys-libs/fts-standalone \
        sys-libs/zlib \
    && crossdev --llvm --target x86_64-unknown-linux-musl \
    && curl -L "https://ftp-osl.osuosl.org/pub/gentoo/releases/amd64/autobuilds/current-stage3-amd64-musl-llvm/$(\
        curl -L "https://ftp-osl.osuosl.org/pub/gentoo/releases/amd64/autobuilds/current-stage3-amd64-musl-llvm/latest-stage3-amd64-musl-llvm.txt" | \
        grep tar.xz | cut -d ' ' -f 1)" | \
        tar -xJpf - -C /usr/x86_64-unknown-linux-musl --exclude=dev --skip-old-files \
    && ln -s \
        /etc/portage/repos.conf \
        /usr/x86_64-unknown-linux-musl/etc/portage/repos.conf \
    && ln -s \
        /etc/portage/package.accept_keywords/* \
        /usr/x86_64-unknown-linux-musl/etc/portage/package.accept_keywords \
    && PORTAGE_CONFIGROOT=/usr/x86_64-unknown-linux-musl eselect profile set \
        default/linux/amd64/23.0/musl/llvm \
    && x86_64-unknown-linux-musl-emerge \
        app-arch/brotli \
        app-arch/xz-utils \
        app-arch/zstd \
        app-crypt/gpgme \
        dev-db/sqlite \
        dev-libs/json-c \
        dev-libs/libpcre2 \
        dev-libs/openssl \
        dev-libs/rocksdb \
        llvm-runtimes/libgcc \
        net-dns/c-ares \
        net-misc/curl \
        sys-apps/util-linux \
        sys-libs/argp-standalone \
        sys-libs/error-standalone \
        sys-libs/fts-standalone \
        sys-libs/zlib \
    && rm -rf \
        /var/cache/binpkgs/* \
        /var/cache/distfiles/* \
        /var/db/repos/* \
        /var/tmp/portage/*
