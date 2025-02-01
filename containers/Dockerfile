FROM docker.io/gentoo/stage3:musl-llvm

ARG LLVM_VERSION=19

ENV PATH="/root/.cargo/bin:/usr/lib/llvm/${LLVM_VERSION}/bin:${PATH}"
# Enable static libraries for installed packages (zstd, zlib etc.).
ENV USE="static-libs"

COPY package.accept_keywords/* /etc/portage/package.accept_keywords/
COPY package.use/* /etc/portage/package.use/

# Install the following dependencies, which can be considered "build essentials"
# for the most of C/C++ software on Linux, as well as for Rust crates, which
# don't vendor C dependencies and expect them to be present in the system. All of
# these dependencies provide static libraries.
#
# * Ports of GNU, non-POSIX functionality:
#   * llvm-libgcc[0] - LLVM's runtime library with GNU symbols. Many
#     third-party binaries, including Rust toolchains from rustup, rely on them
#     and wouldn't work with vanilla LLVM compiler runtime[1][2].
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
# [0] https://github.com/llvm/llvm-project/tree/main/llvm-libgcc
# [1] https://github.com/rust-lang/rust/issues/119504
# [2] https://github.com/rust-lang/rustup/issues/2213#issuecomment-1888615413
RUN emerge-webrsync \
    && emerge \
        app-emulation/qemu \
        app-eselect/eselect-repository \
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
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && rustup toolchain install stable --component rust-src \
    && rustup toolchain install beta --component rust-src \
    && rustup toolchain install nightly --component rust-src \
    && cargo install btfdump \
    && rm -rf \
        /var/cache/binpkgs/* \
        /var/cache/distfiles/* \
        /var/db/repos/* \
        /var/tmp/portage/*
