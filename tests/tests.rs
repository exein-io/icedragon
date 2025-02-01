use std::{
    env, fmt,
    fs::{self, File},
    io::{BufReader, Read},
    path::Path,
    process::Command,
    sync::LazyLock,
};

use anyhow::Context;
use assert_cmd::{assert::OutputAssertExt as _, cargo::CommandCargoExt as _};
use flate2::bufread::GzDecoder;
use goblin::elf::{header as elf_header, Elf};
use liblzma::bufread::XzDecoder;
use tar::Archive;
use tempfile::TempDir;
use test_case::test_case;

/// A temporary directory where we keep sources to build.
static TEMPDIR: LazyLock<TempDir> = LazyLock::new(|| {
    let temp_dir = TempDir::new().unwrap();
    let temp_dir_path = temp_dir.path();

    download_and_extract_tarball(
        "https://github.com/exein-io/pulsar/archive/refs/tags/v0.9.0.tar.gz",
        temp_dir_path,
    );
    download_and_extract_tarball(
        "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/llvm-project-19.1.7.src.tar.xz",
        temp_dir_path,
    );

    temp_dir
});

fn extract_tarball<P, R>(mut archive: Archive<R>, dest_dir: P)
where
    P: AsRef<Path>,
    R: Read,
{
    for entry_result in archive.entries().unwrap() {
        let mut entry = entry_result.unwrap();

        let entry_path = entry.path().unwrap();
        let entry_path = dest_dir.as_ref().join(entry_path);
        if let Some(parent) = entry_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }

        entry.unpack(entry_path).unwrap();
    }
}

fn download_and_extract_tarball<P>(url: &str, dest_dir: P)
where
    P: AsRef<Path>,
{
    let response = reqwest::blocking::get(url).unwrap();
    let bytes = response.bytes().unwrap();
    let reader = BufReader::new(&*bytes);

    if url.ends_with(".gz") {
        let stream = GzDecoder::new(reader);
        let archive = Archive::new(stream);
        extract_tarball(archive, dest_dir);
    } else if url.ends_with(".xz") {
        let stream = XzDecoder::new(reader);
        let archive = Archive::new(stream);
        extract_tarball(archive, dest_dir);
    } else {
        panic!("unsupported compression format in the URL {url}");
    }
}

fn icedragon_cmd<P>(dir: P, subcommand: &str, target: &str) -> Command
where
    P: AsRef<Path>,
{
    let mut cmd = Command::cargo_bin("icedragon").unwrap();
    cmd.args([subcommand, "--target", target]).current_dir(dir);
    if let Some(container_image) = env::var_os("ICEDRAGON_CONTAINER_IMAGE") {
        cmd.arg("--container-image").arg(&container_image);
    }
    cmd.arg("--");
    cmd
}

/// Asserts the architecture of the given binary.
fn assert_bin_arch<P>(bin_path: P, elf_machine: u16)
where
    P: AsRef<Path> + fmt::Debug,
{
    let bin_file = File::open(&bin_path)
        .with_context(|| format!("failed to open the binary file {bin_path:?}"))
        .unwrap();
    let mut bin_content = Vec::new();
    let mut reader = BufReader::new(bin_file);
    reader
        .read_to_end(&mut bin_content)
        .with_context(|| format!("could not read the binary file {bin_path:?}"))
        .unwrap();
    let elf = Elf::parse(&bin_content)
        .with_context(|| format!("could not parse the binary file {bin_path:?}"))
        .unwrap();
    assert_eq!(elf.header.e_machine, elf_machine);
}

/// Tests cargo support by cross-compiling pulsar.
#[test_case("aarch64-unknown-linux-musl", elf_header::EM_AARCH64 ; "aarch64")]
#[test_case("x86_64-unknown-linux-musl", elf_header::EM_X86_64 ; "x86_64")]
fn test_cargo_pulsar(target: &str, elf_machine: u16) {
    let dir = TEMPDIR.path().join("pulsar-0.9.0");
    icedragon_cmd(&dir, "cargo", target)
        .arg("build")
        .assert()
        .success();
    let bin_path = dir.join("target").join(target).join("debug/pulsar-exec");
    assert_bin_arch(bin_path, elf_machine);
}

/// Tests CMake support by cross-compiling compiler-rt.
#[test_case(
    "aarch64-unknown-linux-musl",
    "aarch64",
    elf_header::EM_AARCH64,
    &["-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON"]
    ; "aarch64"
)]
#[test_case(
    "x86_64-unknown-linux-musl",
    "x86_64",
    elf_header::EM_X86_64,
    &[]
    ; "x86_64"
)]
fn test_cmake_compiler_rt(target: &str, arch: &str, elf_machine: u16, extra_args: &[&'static str]) {
    let dir = TEMPDIR.path().join("llvm-project-19.1.7.src");
    let build_dir = format!("build-{target}");
    icedragon_cmd(&dir, "cmake", target)
        .args([
            "-S",
            "compiler-rt",
            "-B",
            &build_dir,
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCOMPILER_RT_INCLUDE_TESTS=OFF",
            "-DCOMPILER_RT_BUILD_CTX_PROFILE=OFF",
            "-DCOMPILER_RT_BUILD_LIBFUZZER=OFF",
            "-DCOMPILER_RT_BUILD_MEMPROF=OFF",
            "-DCOMPILER_RT_BUILD_ORC=OFF",
            "-DCOMPILER_RT_BUILD_PROFILE=OFF",
            "-DCOMPILER_RT_BUILD_SANITIZERS=OFF",
            "-DCOMPILER_RT_BUILD_XRAY=OFF",
        ])
        .args(extra_args)
        .assert()
        .success();
    icedragon_cmd(&dir, "cmake", target)
        .args(["--build", &build_dir])
        .assert()
        .success();
    let bin_filename = format!("clang_rt.crtbegin-{arch}.o");
    let bin_path = dir.join(&build_dir).join("lib/linux").join(bin_filename);
    assert_bin_arch(bin_path, elf_machine);
}
