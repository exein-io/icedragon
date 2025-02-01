use std::ffi::OsString;

use target_lexicon::Triple;

use crate::{
    containers::{run_container, ContainerEngine},
    run::RunArgs,
    target::TripleExt,
};

pub fn cmake(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    args: RunArgs,
) -> anyhow::Result<()> {
    let mut cmd_args = vec!["cmake".to_owned()];

    if triple.is_cross() {
        let c_compiler = format!("{triple}-clang");
        cmd_args.push(format!("-DCMAKE_ASM_COMPILER={c_compiler}"));
        cmd_args.push(format!("-DCMAKE_C_COMPILER={c_compiler}"));
        cmd_args.push(format!("-DCMAKE_CXX_COMPILER={triple}-clang++"))
    }

    run_container(container_engine, runner, triple, args, cmd_args.as_slice())
}
