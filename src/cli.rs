use std::{ffi::OsString, str::FromStr};

use clap::{Parser, Subcommand};
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};

use crate::{
    clang::clang,
    containers::{build_container_image, BuildContainerImageArgs, ContainerEngine},
    errors::IcedragonError,
    run::{run, RunArgs},
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
    /// Run clang.
    Clang(RunArgs),
    /// Run a custom command.
    Run(RunArgs),
}

pub fn cli() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let container_engine = cli.container_engine()?;
    let triple = cli.triple()?;
    let runner = cli.runner;

    env_logger::init();

    match cli.command {
        Commands::BuildContainerImage(args) => {
            build_container_image(container_engine, runner, triple, args)
        }
        Commands::Clang(args) => clang(container_engine, runner, triple, args),
        Commands::Run(args) => run(container_engine, runner, triple, args),
    }
}
