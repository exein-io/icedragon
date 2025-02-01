use std::{
    env,
    ffi::{OsStr, OsString},
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    str::FromStr as _,
    thread,
};

use clap::{Parser, Subcommand, ValueEnum};
use log::{error, info};
use target_lexicon::{Architecture, Environment, OperatingSystem, ParseError, Triple};
use thiserror::Error;
use which::which;

/// Content of the container image.
const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

#[derive(Debug, Error)]
pub enum IcedragonError {
    #[error("no supported container engine was found")]
    ContainerEngineNotFound,
    #[error("failed to parse the target {0}: {1}")]
    ParseTarget(String, ParseError),
    #[error("target {0} is not supported")]
    UnsupportedTarget(Triple),
    #[error("failed to build a container image")]
    ContainerImageBuild,
    #[error("failed to push a container image")]
    ContainerImagePush,
    #[error("failed to run command")]
    Run,
}

/// Linux cross-compilation suite for building portable software.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Subcommands
    #[command(subcommand)]
    command: Commands,

    /// Container engine (if not provided, is going to be autodetected).
    #[arg(global = true, long)]
    container_engine: Option<ContainerEngine>,

    /// The command used to wrap the container engine (e.g. sudo, doas).
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

#[derive(Clone, ValueEnum)]
pub enum ContainerEngine {
    Docker,
    Podman,
}

impl AsRef<OsStr> for ContainerEngine {
    fn as_ref(&self) -> &OsStr {
        match self {
            Self::Docker => OsStr::new("docker"),
            Self::Podman => OsStr::new("podman"),
        }
    }
}

impl ContainerEngine {
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
        Err(IcedragonError::ContainerEngineNotFound.into())
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

fn push_image(container_engine: &ContainerEngine, tag: &OsStr) -> anyhow::Result<()> {
    let mut cmd = Command::new(container_engine);
    cmd.arg("push")
        .arg(tag)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    info!("Pushing image with command: {cmd:?}");
    let stdout = child.stdout.take().unwrap();
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            info!("{line}");
        }
    });
    let stderr = child.stderr.take().unwrap();
    let stderr_reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            error!("{line}");
        }
    });

    if !child.wait()?.success() {
        return Err(IcedragonError::ContainerImagePush.into());
    }

    stdout_reader.join().expect("failed to read from stdout");
    stderr_reader.join().expect("failed to read from stderr");

    Ok(())
}

fn build_container_image(
    container_engine: ContainerEngine,
    runner: Option<&OsStr>,
    args: BuildContainerImageArgs,
) -> anyhow::Result<()> {
    let BuildContainerImageArgs {
        no_cache,
        push,
        tags,
        ..
    } = args;

    let mut cmd = match runner {
        Some(runner) => {
            let mut cmd = Command::new(runner);
            cmd.arg(&container_engine);
            cmd
        }
        None => Command::new(&container_engine),
    };
    cmd.current_dir("containers");
    cmd.args(["buildx", "build"]);
    for tag in tags.iter() {
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
    let stdout_reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            info!("{line}");
        }
    });
    let stderr = child.stderr.take().unwrap();
    let stderr_reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            // Use `info!` even for stderr. The most of stderr messages are
            // progress-related logs from emerge, logging them with `error!`
            // would be confusing.
            info!("{line}");
        }
    });
    if !child.wait()?.success() {
        return Err(IcedragonError::ContainerImageBuild.into());
    }
    stdout_reader.join().expect("stdout reader thread failed");
    stderr_reader.join().expect("stderr reader thread failed");

    if push {
        for tag in tags.iter() {
            if let Err(e) = push_image(&container_engine, tag) {
                error!("Failed to push the tag {tag:?}: {e}");
            }
        }
    }

    Ok(())
}

#[derive(Parser)]
struct RunArgs {
    /// Container image to use.
    #[arg(long, default_value = "ghcr.io/exein-io/icedragon:latest")]
    pub container_image: OsString,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<String>,
}

/// Returns a vector of `--env` arguments of the containers, consisting of:
///
/// * The current environment variables, except `PATH`, which should be
///   inherited from the Dockerfile.
/// * Additional variables which are often needed for cross-compilation:
///   * `CC`, used by `cc-rs` and many build systems to determine a C compiler
///     to use. Set it to the clang wrapper.
///   * `CXX`, used by many build systems to determine a C++ compiler. Set it
///     to clang++ wrapper.
///   * `PKG_CONFIG_SYSROOT_DIR`, to point pkg-config to the sysroot.
///   * `RUSTFLAGS`, which we extend, pointing Rust to an appropriate clang
///     wrapper as a linker and to a cross sysroot.
fn env_args(triple: &Triple) -> Vec<OsString> {
    let mut args: Vec<OsString> = env::vars_os()
        .filter(|(key, _)| key != "PATH")
        .map(|(key, value)| {
            let mut env_arg = OsString::from("--env=");
            env_arg.push(key);
            env_arg.push("=");
            env_arg.push(value);
            env_arg
        })
        .collect();
    args.push(OsString::from(format!("--env=CC={triple}-clang")));
    args.push(OsString::from(format!("--env=CXX={triple}-clang++")));
    args.push(OsString::from(format!(
        "--env=PKG_CONFIG_SYSROOT_DIR=/usr/{triple}"
    )));
    let mut rustflags_arg = OsString::from("--env=RUSTFLAGS=\"");
    rustflags_arg.push(env::var_os("RUSTFLAGS").unwrap_or_default());
    rustflags_arg.push(format!(
        " -C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}"
    ));
    rustflags_arg.push("\"");
    args
}

fn run_container<S, E>(
    container_engine: ContainerEngine,
    runner: Option<&OsStr>,
    triple: &Triple,
    cli_args: RunArgs,
    start_args: &[S],
    end_args: &[E],
) -> anyhow::Result<()>
where
    S: AsRef<OsStr>,
    E: AsRef<OsStr>,
{
    let RunArgs {
        container_image,
        cmd,
    } = cli_args;

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
    container.args(env_args(triple).as_slice());
    container
        .args(["--rm", "-it", "-v"])
        .arg(&bind_mount)
        .args(["-w", "/src"])
        .arg(&container_image)
        .args(start_args)
        .args(cmd)
        .args(end_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    info!("Running container with command: {container:?}");

    let mut child = container.spawn()?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(IcedragonError::Run.into())
    }
}

fn cargo(
    container_engine: ContainerEngine,
    runner: Option<&OsStr>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let start_args = vec!["cargo"];

    // We need to:
    //
    // * Adjust `RUSTFLAGS` to use an appropriate clang cross wrapper
    //   (e.g. `aarch64-unknown-linux-musl-clang`) and sysroot.
    // * Set the `CC` variable to a clang wrapper, to make `cc-rs` work.
    // * Pass a `--target` argument to cargo.
    let mut rustflags = env::var_os("RUSTFLAGS").unwrap_or_default();
    let mut end_args: Vec<String> = Vec::new();
    rustflags.push(format!(
        " -C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}"
    ));
    end_args.push(format!("--target={triple}"));

    run_container(
        container_engine,
        runner,
        &triple,
        args,
        start_args.as_slice(),
        end_args.as_slice(),
    )
}

fn clang(
    container_engine: ContainerEngine,
    runner: Option<&OsStr>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
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
        (_, _, _) => return Err(IcedragonError::UnsupportedTarget(triple.to_owned()).into()),
    };

    let end_args: &[OsString] = &[];
    run_container(
        container_engine,
        runner,
        &triple,
        args,
        &[clang_cmd],
        end_args,
    )
}

/// Runs CMake inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
fn cmake(
    container_engine: ContainerEngine,
    runner: Option<&OsStr>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let start_args = vec!["cmake"];

    // Point CMake to cross-compiler wrappers. Do it only when configuring the
    // project.
    let mut end_args: Vec<String> = Vec::new();
    if !args
        .cmd
        .iter()
        // Usage of any of these arguments means performing an action other
        // than configuring the project.
        // This would've been easier to determine if CMake was split into
        // subcommands and didn't treat everything as regular arguments...
        .any(|arg| matches!(arg.as_str(), "--build" | "--help" | "--install" | "--open"))
    {
        end_args.push(format!("-DCMAKE_ASM_COMPILER={triple}-clang"));
        end_args.push(format!("-DCMAKE_ASM_COMPILER_TARGET={triple}"));
        end_args.push(format!("-DCMAKE_C_COMPILER={triple}-clang"));
        end_args.push(format!("-DCMAKE_C_COMPILER_TARGET={triple}"));
        end_args.push(format!("-DCMAKE_CXX_COMPILER={triple}-clang++"));
        end_args.push(format!("-DCMAKE_CXX_COMPILER_TARGET={triple}"));
    }

    run_container(
        container_engine,
        runner,
        &triple,
        args,
        start_args.as_slice(),
        end_args.as_slice(),
    )
}

/// Run a command inside a container.
fn run(
    container_engine: ContainerEngine,
    runner: Option<&OsStr>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let start_args: &[OsString] = &[];
    let end_args: &[OsString] = &[];
    run_container(
        container_engine,
        runner,
        &triple,
        args,
        start_args,
        end_args,
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
        Some(ref container_engine) => container_engine.to_owned(),
        None => ContainerEngine::autodetect()?,
    };

    // Parse target.
    let triple = match target {
        Some(ref target) => Triple::from_str(target)
            .map_err(|e| IcedragonError::ParseTarget(target.to_owned(), e))?,
        None => {
            // Use the host target as the default one.
            let mut target = target_lexicon::HOST;
            // Enforce usage of musl.
            target.environment = Environment::Musl;
            target
        }
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
            Architecture::Aarch64(_),
            OperatingSystem::Linux,
            Environment::Musl
        ) | (
            Architecture::X86_64,
            OperatingSystem::Linux,
            Environment::Musl
        )
    ) {
        return Err(IcedragonError::UnsupportedTarget(triple).into());
    }

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let runner = runner.as_deref();

    match command {
        Commands::BuildContainerImage(args) => {
            build_container_image(container_engine, runner, args)
        }
        Commands::Cargo(args) => cargo(container_engine, runner, triple, args),
        Commands::Clang(args) => clang(container_engine, runner, triple, args),
        Commands::Cmake(args) => cmake(container_engine, runner, triple, args),
        Commands::Run(args) => run(container_engine, runner, triple, args),
    }
}
