use std::{
    env,
    ffi::{OsStr, OsString},
    io::{BufRead as _, BufReader, Write as _},
    iter,
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

/// Linux cross-compilation suite for building portable software.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Container engine (if not provided, is going to be autodetected).
    #[arg(global = true, long)]
    container_engine: Option<ContainerEngine>,

    /// The command used to wrap the container engine call (e.g. sudo, doas).
    #[arg(global = true, long)]
    runner: Option<OsString>,

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
    runner: Option<&OsStr>,
    args: BuildContainerImageArgs,
) -> anyhow::Result<()> {
    let BuildContainerImageArgs {
        no_cache,
        push,
        tags,
    } = args;

    let mut cmd = match runner {
        Some(runner) => {
            let mut cmd = Command::new(runner);
            cmd.arg(container_engine);
            cmd
        }
        None => Command::new(container_engine),
    };
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
    pub volumes: Vec<String>,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<OsString>,
}

/// Takes a `cmd`, representing a container engine, and adds `--env` arguments,
/// consisting of:
///
/// * The current environment variables, except `PATH`, which should be
///   inherited from the Dockerfile.
/// * Additional variables defined by us:
///   * `CXXFLAGS` and `LDFLAGS`, pointing to LLVM libc++ as a C++ stdlib, LLD
///     as a linker, compiler-rt as a runtime library and LLVM libunwind as
///     unwinder.
///   * `PKG_CONFIG_SYSROOT_DIR`, to point pkg-config to the sysroot.
fn add_env_args(cmd: &mut Command, triple: &Triple) {
    for (key, value) in env::vars_os() {
        if key != "PATH" {
            let mut env_arg = OsString::from("--env=");
            env_arg.push(key);
            env_arg.push("=");
            env_arg.push(value);
            cmd.arg(env_arg);
        }
    }
    cmd.arg("--env=CXXFLAGS=--stdlib=libc++");
    cmd.arg("--env=LDFLAGS=-fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind");
    cmd.arg(format!("--env=PKG_CONFIG_SYSROOT_DIR=/usr/{triple}"));
    cmd.arg("--env=RUSTUP_HOME=/root/.rustup");

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
    runner: Option<&OsStr>,
    interactive: bool,
    triple: &Triple,
    container_image: &OsStr,
    container_engine_args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    volumes: impl IntoIterator<Item = impl AsRef<OsStr>>,
    cmd_args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> anyhow::Result<()> {
    let mut bind_mount = env::current_dir()?.into_os_string();
    bind_mount.push(":/src");

    let mut container = match runner {
        Some(runner) => {
            let mut cmd = Command::new(runner);
            cmd.arg(container_engine);
            cmd
        }
        None => Command::new(container_engine),
    };
    container.arg("run");
    add_env_args(&mut container, triple);
    if interactive {
        container.arg("-it");
    }
    container.args(["--rm", "-v"]).arg(&bind_mount);
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
fn cargo<'a>(
    container_engine: &ContainerEngine,
    runner: Option<&OsStr>,
    triple: &Triple,
    container_image: &OsStr,
    volumes: &[String],
    cmd: impl IntoIterator<Item = &'a dyn AsRef<OsStr>>,
) -> anyhow::Result<()> {
    // Pass additional environment variables:
    //
    // * `CARGO_BUILD_TARGET`, pointing to our target.
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
    let container_engine_args: &[OsString] = &[
        format!("--env=CARGO_BUILD_TARGET={triple}").into(),
        format!("--env=CC={triple}-clang").into(),
        format!("--env=CXX={triple}-clang++").into(),
        rustflags_arg,
    ];

    // The command is `cargo` followed by arguments provided by the caller.
    let cargo_cmd: &dyn AsRef<OsStr> = &"cargo";
    let cmd_args = iter::once(cargo_cmd);
    let cmd_args = cmd_args.chain(cmd);

    run_container(
        container_engine,
        runner,
        false,
        triple,
        container_image,
        container_engine_args,
        volumes,
        cmd_args,
    )
}

/// Runs clang inside a container.
fn clang<'a>(
    container_engine: &ContainerEngine,
    runner: Option<&OsStr>,
    triple: &Triple,
    container_image: &OsStr,
    volumes: &[String],
    cmd: impl IntoIterator<Item = &'a dyn AsRef<OsStr>>,
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
    let clang_cmd: &dyn AsRef<OsStr> = &clang_cmd;
    let cmd_args = iter::once(clang_cmd);
    let cmd_args = cmd_args.chain(cmd);

    let container_engine_args: &[OsString] = &[];

    run_container(
        container_engine,
        runner,
        false,
        triple,
        container_image,
        container_engine_args,
        volumes,
        cmd_args,
    )
}

/// Runs `CMake` inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
fn cmake<'a>(
    container_engine: &ContainerEngine,
    runner: Option<&OsStr>,
    triple: &Triple,
    container_image: &OsStr,
    volumes: &[String],
    cmd: impl Iterator<Item = &'a dyn AsRef<OsStr>>,
) -> anyhow::Result<()> {
    // Determine whether we are configuring a CMake project.
    //
    // Usage of any of the following arguments means performing an action other
    // than configuring the project.
    // This would've been easier to determine if CMake actions were treated as
    // subcommands instead of regular arguments with no enforced order...
    let configure = !cmd
        .iter()
        .any(|arg| matches!(arg.as_str(), "--build" | "--help" | "--install" | "--open"));

    // The command is `cmake` followed by arguments provided by the caller...
    let mut cmd_args = vec!["cmake".to_owned()];
    cmd_args.extend_from_slice(cmd);

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
        cmd_args.push("-DCMAKE_ASM_COMPILER=clang".to_string());
        cmd_args.push(format!("-DCMAKE_ASM_COMPILER_TARGET={triple}"));
        cmd_args.push("-DCMAKE_C_COMPILER=clang".to_string());
        cmd_args.push(format!("-DCMAKE_C_COMPILER_TARGET={triple}"));
        cmd_args.push("-DCMAKE_CXX_COMPILER=clang++".to_string());
        cmd_args.push(format!("-DCMAKE_CXX_COMPILER_TARGET={triple}"));
        // Tell CMake to look for libraries, headers and packages (through
        // pkg-config) only in the specified sysroot. Prevent picking them
        // from the main sysroot.
        cmd_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY".to_string());
        cmd_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY".to_string());
        cmd_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY".to_string());
        // Tell CMake to look for the other build system binaries (like Ninja
        // or make) only on the host sysroot, not in the cross sysroot.
        cmd_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER".to_string());
        // CMake requires both of these variables to indicate that we are
        // performing a cross build.
        // Currently, we support only Linux targets, so let's just hard code
        // the name.
        // If we ever want to support other systems, we need to convert the OS
        // part of the target triple to a capitalized value that CMake expects
        // (e.g. Darwin, Linux, FreeBSD, Windows). Passing lower-case names
        // doesn't work.
        cmd_args.push("-DCMAKE_SYSTEM_NAME=Linux".to_string());
        cmd_args.push(format!("-DCMAKE_SYSTEM_PROCESSOR={architecture}"));
        // Point to the crossdev's target sysroot.
        cmd_args.push(format!("-DCMAKE_SYSROOT=/usr/{triple}"));
    }

    let container_engine_args: &[OsString] = &[];

    run_container(
        container_engine,
        runner,
        false,
        triple,
        container_image,
        container_engine_args,
        volumes,
        &cmd_args,
    )
}

/// Run a command inside a container.
fn run<'a>(
    container_engine: &ContainerEngine,
    runner: Option<&OsStr>,
    triple: &Triple,
    container_image: &OsStr,
    volumes: &[String],
    cmd: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> anyhow::Result<()> {
    let container_engine_args: &[OsString] = &[];
    run_container(
        container_engine,
        runner,
        true,
        triple,
        container_image,
        container_engine_args,
        volumes,
        cmd,
    )
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Cli {
        command,
        container_engine,
        runner,
        target,
    } = cli;

    let container_engine = match container_engine {
        Some(ref container_engine) => container_engine,
        None => &ContainerEngine::autodetect()?,
    };

    // Parse target.
    let triple = if let Some(ref target) = target {
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

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let runner = runner.as_deref();

    match command {
        Commands::BuildContainerImage(args) => {
            build_container_image(container_engine, runner, args)
        }
        Commands::Cargo(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            let cmd = cmd.iter().map(|arg| {
                let arg: &dyn AsRef<OsStr> = arg;
                arg
            });
            cargo(
                container_engine,
                runner,
                &triple,
                &container_image,
                &volumes,
                cmd,
            )
        }
        Commands::Clang(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            let cmd = cmd.iter().map(|arg| {
                let arg: &dyn AsRef<OsStr> = arg;
                arg
            });
            clang(
                container_engine,
                runner,
                &triple,
                &container_image,
                &volumes,
                cmd,
            )
        }
        Commands::Cmake(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            let cmd = cmd.iter().map(|arg| {
                let arg: &dyn AsRef<OsStr> = arg;
                arg
            });
            cmake(
                container_engine,
                runner,
                &triple,
                &container_image,
                &volumes,
                cmd,
            )
        }
        Commands::Run(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            run(
                container_engine,
                runner,
                &triple,
                &container_image,
                &volumes,
                &cmd,
            )
        }
    }
}
