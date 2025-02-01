use std::{env, process::Command};

use assert_cmd::{assert::OutputAssertExt, prelude::CommandCargoExt};
use git2::{build::RepoBuilder, FetchOptions};
use tempfile::TempDir;

fn clone_repo(url: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();

    let mut fetch_options = FetchOptions::new();
    fetch_options.depth(1);
    RepoBuilder::new()
        .fetch_options(fetch_options)
        .clone(url, temp_dir.path())
        .unwrap();

    temp_dir
}

/// Test the buid of [`llvm-sys`] - a crate which provides bindings to libLLVM
/// and requires the same C libraries that LLVM does - libxml, libzstd, zlib.
/// The crate doesn't bundle these C dependencies, therefore requires them to
/// be present in the system.
#[test]
fn test_cargo_llvm_sys() {
    let repo_dir = clone_repo("https://gitlab.com/taricorp/llvm-sys.rs");
    env::set_current_dir(repo_dir).unwrap();

    let mut cmd = Command::cargo_bin("icedragon").unwrap();
    cmd.args(&["cargo", "build"]);

    cmd.assert().success();
}
