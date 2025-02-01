use std::ffi::OsString;

use clap::Parser;
use target_lexicon::Triple;

use crate::containers::{run_container, ContainerEngine};

#[derive(Parser)]
pub struct RunArgs {
    /// Container image to use.
    #[arg(long)]
    pub container_image: Option<OsString>,

    /// Container tag to use.
    #[arg(long, default_value = "latest")]
    pub container_tag: OsString,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<String>,
}

pub fn run(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let cmd_args: &[OsString] = &[];
    run_container(container_engine, runner, triple, args, cmd_args)
}
