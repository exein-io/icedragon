use std::ffi::OsString;

use clap::Parser;

use crate::containers::{run_container, ContainerEngine};

#[derive(Parser)]
pub struct RunArgs {
    /// Container image to use.
    #[arg(long, default_value = "ghcr.io/exein-io/icedragon:latest")]
    pub container_image: OsString,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<String>,
}

pub fn run(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    args: RunArgs,
) -> anyhow::Result<()> {
    let start_args: &[OsString] = &[];
    let end_args: &[OsString] = &[];
    run_container(container_engine, runner, args, start_args, end_args)
}
