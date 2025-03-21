use std::{
    collections::{vec_deque::Iter, VecDeque},
    env,
    ffi::{OsStr, OsString},
    io::{BufRead as _, BufReader, Write as _},
    iter,
    os::unix::ffi::OsStrExt as _,
    process::{Command, Stdio},
    str::FromStr as _,
    thread,
};

use anyhow::{anyhow, Context as _};
use clap::{Parser, Subcommand, ValueEnum};
use log::{error, info};
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};
use which::which;

/// Content of the dockerfile.
const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

/// A wrapper over [`VecDeque`] making it easy to gather platform-native
/// strings.
#[derive(Debug, Default)]
struct OsVecDeque(VecDeque<OsString>);

impl OsVecDeque {
    fn with_capacity(capacity: usize) -> Self {
        Self(VecDeque::with_capacity(capacity))
    }

    fn contains_any<S>(&self, items: &[S]) -> bool
    where
        S: AsRef<OsStr>,
    {
        self.0
            .iter()
            .any(|a| items.iter().any(|b| a.eq(b.as_ref())))
    }

    fn iter(&self) -> Iter<'_, OsString> {
        self.0.iter()
    }

    fn push_back<S: AsRef<OsStr>>(&mut self, s: S) {
        self.0.push_back(s.as_ref().to_owned());
    }

    fn push_front<S: AsRef<OsStr>>(&mut self, s: S) {
        self.0.push_front(s.as_ref().to_owned());
    }
}

impl<S> From<Vec<S>> for OsVecDeque
where
    S: AsRef<OsStr>,
{
    fn from(vec: Vec<S>) -> Self {
        let vec_deque = vec.into_iter().map(|s| s.as_ref().to_owned()).collect();
        Self(vec_deque)
    }
}

/// Linux cross-compilation suite for building portable software.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Container engine (if not provided, is going to be autodetected).
    #[arg(global = true, long)]
    container_engine: Option<ContainerEngine>,

    /// Target triple.
    #[arg(global = true, long)]
    target: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Build container image.
    BuildContainerImage(BuildContainerImageArgs),
    /// Run cargo.
    Cargo(RunArgs),
    /// Run clang.
    Clang(RunArgs),
    /// Run cmake.
    Cmake(RunArgs),
    /// Run a custom command.
    Run(RunArgs),
}

/// Supported container engines.
#[derive(Clone, ValueEnum)]
pub enum ContainerEngine {
    Docker,
    Podman,
}

impl AsRef<OsStr> for ContainerEngine {
    fn as_ref(&self) -> &OsStr {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
        .as_ref()
    }
}

impl ContainerEngine {
    /// Autodetects an available container engine.
    ///
    /// # Errors
    ///
    /// Returns an error if no supported container engine is found.
    pub fn autodetect() -> anyhow::Result<Self> {
        match which("docker") {
            Ok(_) => return Ok(Self::Docker),
            Err(e) => {
                if !matches!(e, which::Error::CannotFindBinaryPath) {
                    return Err(e.into());
                }
            }
        }
        match which("podman") {
            Ok(_) => return Ok(Self::Podman),
            Err(e) => {
                if !matches!(e, which::Error::CannotFindBinaryPath) {
                    return Err(e.into());
                }
            }
        }
        Err(anyhow!(
            "no supported container engine (docker, podman) was found"
        ))
    }
}

#[derive(Parser)]
struct BuildContainerImageArgs {
    /// Do not use existing cached images for the container build. Build from
    /// the start with a new set of cached layers.
    #[arg(long)]
    no_cache: bool,

    /// Push the image after build.
    #[arg(long)]
    push: bool,

    /// Container image tag.
    #[arg(
        short,
        long = "tag",
        name = "tag",
        default_value = "ghcr.io/exein-io/icedragon:latest"
    )]
    tags: Vec<OsString>,
}

/// Pushes an image with the given `tag` to the registry.
///
/// # Errors
///
/// Returns an error if the push was not successful.
fn push_image(container_engine: &ContainerEngine, tag: &OsStr) -> anyhow::Result<()> {
    let mut cmd = Command::new(container_engine);
    cmd.arg("push")
        .arg(tag)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    info!("Pushing image with command: {cmd:?}");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                info!("{line}");
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                error!("{line}");
            }
        });
    });
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("failed to push a container image: {status}"));
    }

    Ok(())
}

/// Builds a container image.
///
/// # Errors
///
/// Returns an error if:
///
/// * The image build was unsuccessful.
/// * If any of the tags could not be pushed.
fn build_container_image(
    container_engine: &ContainerEngine,
    args: BuildContainerImageArgs,
) -> anyhow::Result<()> {
    let BuildContainerImageArgs {
        no_cache,
        push,
        tags,
    } = args;

    let mut cmd = Command::new(container_engine);
    cmd.current_dir("containers");
    cmd.args(["buildx", "build"]);
    for tag in &tags {
        cmd.arg("-t").arg(tag);
    }
    cmd.args(["-f", "-", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if no_cache {
        cmd.arg("--no-cache");
    }
    info!("Building container image with command: {cmd:?}");

    let mut child = cmd.spawn()?;
    {
        let mut stdin = child.stdin.take().expect("child should have piped stdin");
        stdin.write_all(DOCKERFILE)?;
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                info!("{line}");
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                // Use `info!` even for stderr. The most of stderr messages are
                // progress-related logs from emerge, logging them with `error!`
                // would be confusing.
                info!("{line}");
            }
        });
    });
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("failed to build container image: {status}"));
    }

    let mut errors = Vec::new();
    if push {
        for tag in &tags {
            if let Err(e) = push_image(container_engine, tag)
                .with_context(|| format!("failed to push the tag {tag:?}"))
            {
                errors.push(e);
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("Failed to push images: {errors:?}"))
    }
}

#[derive(Parser)]
struct RunArgs {
    /// Container image to use.
    #[arg(long, default_value = "ghcr.io/exein-io/icedragon:latest")]
    pub container_image: OsString,

    /// Additional volumes to mount to the container.
    #[arg(long = "volume", short)]
    pub volumes: Vec<OsString>,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<OsString>,
}

/// Takes a `cmd`, representing a container engine, and adds `--env` arguments,
/// consisting of:
///
/// * The current environment variables, except `HOME`, `PATH` and the ones
///   related to the Rust ecosystem (with `CARGO` and `RUSTUP` prefix), which
///   should remain unchanged.
/// * Additional variables defined by us:
///   * `CXXFLAGS` and `LDFLAGS`, pointing to LLVM libc++ as a C++ stdlib, LLD
///     as a linker, compiler-rt as a runtime library and LLVM libunwind as
///     unwinder.
///   * `PKG_CONFIG_SYSROOT_DIR`, to point pkg-config to the sysroot.
/// * Variables extended with values defined by us:
///   * `RUSTFLAGS`, which we extend with the `linker` and `link-arg` options,
///     enforcing the usage of clang as a linker and pointing to the cross
///     sysroot.
fn add_env_args(cmd: &mut Command, triple: &Triple) {
    for (key, value) in env::vars_os() {
        let key_b = key.as_bytes();
        if key == "HOME"
            || key == "PATH"
            || key_b.starts_with(b"CARGO_")
            || key_b.starts_with(b"RUSTUP_")
        {
            continue;
        }

        let mut env_arg = OsString::from("--env=");
        env_arg.push(key);
        env_arg.push("=");
        env_arg.push(value);
        cmd.arg(env_arg);
    }
    cmd.arg("--env=CXXFLAGS=--stdlib=libc++");
    cmd.arg("--env=LDFLAGS=-fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind");
    cmd.arg(format!("--env=PKG_CONFIG_SYSROOT_DIR=/usr/{triple}"));

    let mut rustflags_arg = OsString::from("--env=RUSTFLAGS=");
    rustflags_arg.push(env::var_os("RUSTFLAGS").unwrap_or_default());
    rustflags_arg.push(format!(
        "-C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}"
    ));
    cmd.arg(rustflags_arg);
}

/// Runs a command inside a container.
///
/// The main work done by this function is constructing a container engine
/// call from the provided arguments. It does so by merging the following
/// parts into a list or arguments:
///
/// * `container_engine`, wrapped by a `runner`, if provided.
/// * Container engine options:
///   * `--rm`, which removes the container after execution.
///   * `-it`, if the `interactive` option is enabled.
///   * Bind mount of the current directory as `/src` inside container
///     (equivalent of `-v $(pwd):/src`).
///   * Container image determined based on `cli_args`
///   * Additional `container_engine_args` provided by a caller.
/// * Provided `cmd_args` as a command to run inside a container.
///
/// Target `triple` is used to determine additional environment variables,
fn run_container(
    container_engine: &ContainerEngine,
    interactive: bool,
    triple: &Triple,
    container_image: &OsStr,
    container_engine_args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    volumes: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cmd_args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> anyhow::Result<()> {
    let mut bind_mount = env::current_dir()?.into_os_string();
    bind_mount.push(":/src");

    let uid = nix::unistd::getuid();

    let mut container = Command::new(container_engine);
    container.arg("run");
    add_env_args(&mut container, triple);
    if interactive {
        container.arg("-it");
    }
    container
        .args([
            "--rm",
            "-v",
            "cargo:/home/icedragon/.cargo",
            "-v",
            "rustup:/home/icedragon/.rustup",
            "-v",
        ])
        .arg(&bind_mount)
        .arg("-u")
        .arg(format!("{uid}:1000"));
    for volume in volumes {
        container.arg("-v");
        container.arg(volume);
    }
    container
        .args(["-w", "/src"])
        .args(container_engine_args)
        .arg(container_image)
        .args(cmd_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    info!("Running container with command: {container:?}");

    let mut child = container.spawn()?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "failed to run command {:?}, exit code: {:?}",
            container.get_args(),
            status.code()
        ))
    }
}

/// Runs cargo inside a container.
fn cargo(
    container_engine: &ContainerEngine,
    triple: &Triple,
    container_image: &OsStr,
    volumes: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cmd: &mut OsVecDeque,
) -> anyhow::Result<()> {
    // Pass additional environment variables:
    //
    // * `CARGO_BUILD_TARGET`, pointing to our target.
    // * `CARGO_TARGET_*_RUNNER`, defined only for foreigh architectures,
    //    referencing the user-space emulator (QEMU) as a runner.
    // * `CC` and `CXX`, used by `cc-rs` and many build systems, which might
    //   potentially get called by build.rs of various crates, to determine a
    //   C/C++ compiler to use. Set them to the clang wrappers.
    // * `RUSTFLAGS`, which we extend, pointing Rust to an appropriate clang
    //   wrapper as a linker and to a cross sysroot.
    // * `RUSTUP_HOME`, which points to the directory with toolchains inside the
    //   container filesystem.
    let mut rustflags_arg = OsString::from("--env=RUSTFLAGS=");
    rustflags_arg.push(env::var_os("RUSTFLAGS").unwrap_or_default());
    rustflags_arg.push(format!(
        "-C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}"
    ));
    let mut container_engine_args = OsVecDeque::with_capacity(4);
    container_engine_args.push_back(format!("--env=CARGO_BUILD_TARGET={triple}"));
    // If the target CPU architecture is different, use the user-space emulator
    // (QEMU) as a runner.
    let Triple { architecture, .. } = triple;
    if architecture != &target_lexicon::HOST.architecture {
        let triple = triple.to_string().to_uppercase().replace('-', "_");
        container_engine_args.push_back(format!(
            "--env=CARGO_TARGET_{triple}_RUNNER=qemu-{architecture}"
        ));
    }
    container_engine_args.push_back(format!("--env=CC={triple}-clang"));
    container_engine_args.push_back(format!("--env=CXX={triple}-clang++"));
    container_engine_args.push_back(rustflags_arg);

    // The command is `cargo` followed by arguments provided by the caller.
    cmd.push_front("cargo");

    run_container(
        container_engine,
        false,
        triple,
        container_image,
        container_engine_args.iter(),
        volumes,
        cmd.iter(),
    )
}

/// Runs clang inside a container.
fn clang(
    container_engine: &ContainerEngine,
    triple: &Triple,
    container_image: &OsStr,
    volumes: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cmd: &mut OsVecDeque,
) -> anyhow::Result<()> {
    // The command is a clang wrapper (e.g. `aarch64-unknown-linux-musl-clang`)
    // followed by arguments provided by the caller.
    let Triple {
        architecture,
        operating_system,
        environment,
        ..
    } = &triple;
    let clang_cmd = match (architecture, operating_system, environment) {
        (Architecture::Aarch64(_), OperatingSystem::Linux, Environment::Musl) => {
            "aarch64-unknown-linux-musl-clang"
        }
        (Architecture::X86_64, OperatingSystem::Linux, Environment::Musl) => {
            "x86_64-unknown-linux-musl-clang"
        }
        (_, _, _) => return Err(anyhow!("target {triple} is not supported")),
    };
    cmd.push_front(clang_cmd);

    run_container(
        container_engine,
        false,
        triple,
        container_image,
        iter::empty::<OsString>(),
        volumes,
        cmd.iter(),
    )
}

/// Runs `CMake` inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
fn cmake(
    container_engine: &ContainerEngine,
    triple: &Triple,
    container_image: &OsStr,
    volumes: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cmd: &mut OsVecDeque,
) -> anyhow::Result<()> {
    // Determine whether we are configuring a CMake project.
    //
    // Usage of any of the following arguments means performing an action other
    // than configuring the project.
    // This would've been easier to determine if CMake actions were treated as
    // subcommands instead of regular arguments with no enforced order...
    let configure = !cmd.contains_any(&["--build", "--help", "--install", "--open"]);

    // The command is `cmake` followed by arguments provided by the caller...
    cmd.push_front("cmake");

    // ...and then by options necessary for cross-compilation. Do it only when
    // configuring the project.
    if configure {
        let Triple { architecture, .. } = triple;
        // In case of CMake, we don't use the clang wrappers. CMake supports
        // building some of the binaries natively, even during a cross build.
        // The use case is a possibility to build binaries, which serve as a
        // build dependency for the rest of the build.
        // For example, LLVM's CMake configuration uses that option to build a
        // native copy of `llvm-min-tblgen`, which is used during the build of
        // the rest of LLVM.
        // Instead, we specify the cross target with `-DCMAKE_*_COMPILER_TARGET`
        // options. CMake is smart enough to use it only for the non-native
        // artifacts.
        cmd.push_back("-DCMAKE_ASM_COMPILER=clang");
        cmd.push_back(format!("-DCMAKE_ASM_COMPILER_TARGET={triple}"));
        cmd.push_back("-DCMAKE_C_COMPILER=clang");
        cmd.push_back(format!("-DCMAKE_C_COMPILER_TARGET={triple}"));
        cmd.push_back("-DCMAKE_CXX_COMPILER=clang++");
        cmd.push_back(format!("-DCMAKE_CXX_COMPILER_TARGET={triple}"));
        // Tell CMake to look for libraries, headers and packages (through
        // pkg-config) only in the specified sysroot. Prevent picking them
        // from the main sysroot.
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY");
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY");
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY");
        // Tell CMake to look for the other build system binaries (like Ninja
        // or make) only on the host sysroot, not in the cross sysroot.
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER");
        // CMake requires both of these variables to indicate that we are
        // performing a cross build.
        // Currently, we support only Linux targets, so let's just hard code
        // the name.
        // If we ever want to support other systems, we need to convert the OS
        // part of the target triple to a capitalized value that CMake expects
        // (e.g. Darwin, Linux, FreeBSD, Windows). Passing lower-case names
        // doesn't work.
        cmd.push_back("-DCMAKE_SYSTEM_NAME=Linux");
        cmd.push_back(format!("-DCMAKE_SYSTEM_PROCESSOR={architecture}"));
        // Point to the crossdev's target sysroot.
        cmd.push_back(format!("-DCMAKE_SYSROOT=/usr/{triple}"));
    }

    run_container(
        container_engine,
        false,
        triple,
        container_image,
        iter::empty::<OsString>(),
        volumes,
        cmd.iter(),
    )
}

/// Run a command inside a container.
fn run(
    container_engine: &ContainerEngine,
    triple: &Triple,
    container_image: &OsStr,
    volumes: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cmd: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> anyhow::Result<()> {
    run_container(
        container_engine,
        true,
        triple,
        container_image,
        iter::empty::<OsString>(),
        volumes,
        cmd,
    )
}

/// Parses and validates the given `target` triple.
fn parse_target(target: Option<&str>) -> anyhow::Result<Triple> {
    // Parse target.
    let triple = if let Some(target) = target {
        Triple::from_str(target).map_err(|e| anyhow!("failed to parse target {target}: {e}"))?
    } else {
        // Use the host target as the default one.
        let mut target = target_lexicon::HOST;
        // Enforce usage of musl.
        target.environment = Environment::Musl;
        target
    };

    // Check if the target is supported.
    let Triple {
        architecture,
        operating_system,
        environment,
        ..
    } = &triple;
    if !matches!(
        (architecture, operating_system, environment),
        (
            Architecture::Aarch64(_) | Architecture::X86_64,
            OperatingSystem::Linux,
            Environment::Musl
        )
    ) {
        return Err(anyhow!("target {triple} is not supported"));
    }

    Ok(triple)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Cli {
        command,
        container_engine,
        target,
    } = cli;

    let container_engine = match container_engine {
        Some(ref container_engine) => container_engine,
        None => &ContainerEngine::autodetect()?,
    };

    let triple = parse_target(target.as_deref())?;

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    match command {
        Commands::BuildContainerImage(args) => build_container_image(container_engine, args),
        Commands::Cargo(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cargo(
                container_engine,
                &triple,
                &container_image,
                &volumes,
                &mut cmd.into(),
            )
        }
        Commands::Clang(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            clang(
                container_engine,
                &triple,
                &container_image,
                &volumes,
                &mut cmd.into(),
            )
        }
        Commands::Cmake(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cmake(
                container_engine,
                &triple,
                &container_image,
                &volumes,
                &mut cmd.into(),
            )
        }
        Commands::Run(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            run(container_engine, &triple, &container_image, &volumes, &cmd)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vec_deque_conv() {
        let vec = vec!["foo", "bar", "baz"];
        let vec_deq: OsVecDeque = vec.into();

        for (a, b) in vec_deq.iter().zip(&[
            OsString::from("foo"),
            OsString::from("bar"),
            OsString::from("baz"),
        ]) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_vec_deque_push() {
        let mut vec_deq = OsVecDeque::default();

        vec_deq.push_back("ayy");
        vec_deq.push_back("lmao");

        vec_deq.push_front("bar");
        vec_deq.push_front("foo");

        for (a, b) in vec_deq.iter().zip(&[
            OsString::from("foo"),
            OsString::from("bar"),
            OsString::from("ayy"),
            OsString::from("lmao"),
        ]) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_vec_deque_contains_any() {
        let cmake_action_args = &["--build", "--help", "--install", "--open"];

        let args: OsVecDeque = vec!["cmake", "--build"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: OsVecDeque = vec!["cmake", "--help"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: OsVecDeque = vec!["cmake", "--install"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: OsVecDeque = vec!["cmake", "--open", "myproject"].into();
        assert!(args.contains_any(cmake_action_args));

        let args: OsVecDeque = vec![
            "cmake",
            "-S",
            "llvm",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        ]
        .into();
        assert!(!args.contains_any(cmake_action_args));
    }
}
