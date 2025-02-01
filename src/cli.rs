use std::{
    env,
    ffi::{OsStr, OsString},
    str::FromStr,
};

use clap::{Parser, Subcommand};
use env_logger::Env;
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};

use crate::{
    containers::{build_container_image, run_container, BuildContainerImageArgs, ContainerEngine},
    run::{run, RunArgs},
    IcedragonError,
};

/// Containerized (cross, but not only) LLVM toolchains.
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

impl Cli {
    pub fn container_engine(&self) -> Result<ContainerEngine, IcedragonError> {
        match self.container_engine {
            Some(ref container_engine) => Ok(container_engine.to_owned()),
            None => ContainerEngine::autodetect(),
        }
    }

    pub fn triple(&self) -> Result<Triple, IcedragonError> {
        let target = match self.target {
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

        let Triple {
            architecture,
            operating_system,
            environment,
            ..
        } = &target;
        match (architecture, operating_system, environment) {
            (Architecture::Aarch64(_), OperatingSystem::Linux, Environment::Musl)
            | (Architecture::X86_64, OperatingSystem::Linux, Environment::Musl) => Ok(target),
            (_, _, _) => Err(IcedragonError::UnsupportedTarget(target)),
        }
    }
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

pub fn cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let container_engine = cli.container_engine()?;
    let triple = cli.triple()?;
    let runner = cli.runner;

    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    match cli.command {
        Commands::BuildContainerImage(args) => {
            build_container_image(container_engine, runner, args)
        }
        Commands::Cargo(args) => cargo(container_engine, runner, triple, args),
        Commands::Clang(args) => clang(container_engine, runner, triple, args),
        Commands::Cmake(args) => cmake(container_engine, runner, triple, args),
        Commands::Run(args) => run(container_engine, runner, args),
    }
}

fn cargo(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let start_args = vec!["cargo"];

    // We need to adjust `RUSTFLAGS` to use `clang` as a linker. In case of a
    // cross-build, we need to use an appropriate cross wrapper
    // (`aarch64-unknown-linux-musl-clang`).
    //
    // We also need to pass a `--target` argument to cargo when cross-building.
    //
    // Make sure that `cc-rs`, or any other consumer of the `CC` variable
    let mut rustflags = env::var_os("RUSTFLAGS").unwrap_or_default();
    let mut end_args: Vec<String> = Vec::new();
    if triple.architecture != target_lexicon::HOST.architecture {
        rustflags.push(format!(
            " -C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}"
        ));
        end_args.push(format!("--target={triple}"));
        env::set_var("CC", format!("{triple}-clang"));
    } else {
        rustflags.push(" -C linker=clang");
        env::set_var("CC", "clang");
    }
    env::set_var("RUSTFLAGS", rustflags);

    run_container(
        container_engine,
        runner,
        args,
        start_args.as_slice(),
        end_args.as_slice(),
    )
}

fn clang(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let Triple {
        architecture,
        operating_system,
        environment,
        ..
    } = &triple;
    let clang_cmd = if triple.architecture != target_lexicon::HOST.architecture {
        match (architecture, operating_system, environment) {
            (Architecture::Aarch64(_), OperatingSystem::Linux, Environment::Musl) => {
                OsStr::new("aarch64-unknown-linux-musl-clang")
            }
            (Architecture::X86_64, OperatingSystem::Linux, Environment::Musl) => {
                OsStr::new("x86_64-unknown-linux-musl-clang")
            }
            (_, _, _) => OsStr::new("clang"),
        }
    } else {
        OsStr::new("clang")
    };

    let end_args: &[OsString] = &[];
    run_container(container_engine, runner, args, &[clang_cmd], end_args)
}

fn cmake(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let start_args = vec!["cmake".to_owned()];

    // Point CMake to cross-compiler wrappers. Do it only when configuring the
    // project.
    let mut end_args: Vec<String> = Vec::new();
    if !args
        .cmd
        .iter()
        .any(|arg| matches!(arg.as_str(), "--build" | "--help" | "--install" | "--open"))
        && triple.architecture != target_lexicon::HOST.architecture
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
        args,
        start_args.as_slice(),
        end_args.as_slice(),
    )
}
