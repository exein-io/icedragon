use std::ffi::{OsStr, OsString};

use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};

use crate::{
    containers::{run_container, ContainerEngine},
    run::RunArgs,
    target::TripleExt,
};

pub fn clang(
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

    let clang_cmd = if triple.is_cross() {
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

    run_container(container_engine, runner, triple, args, &[clang_cmd])
}
