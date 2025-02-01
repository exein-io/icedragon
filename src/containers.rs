use std::{
    env,
    ffi::{OsStr, OsString},
    io::{BufRead, BufReader, BufWriter, Write},
    process::{Command, Stdio},
    thread,
};

use clap::{Parser, ValueEnum};
use log::{error, info};
use which::which;

use crate::{run::RunArgs, IcedragonError};

const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

#[derive(Clone, ValueEnum)]
pub enum ContainerEngine {
    Docker,
    Podman,
}

impl AsRef<OsStr> for ContainerEngine {
    fn as_ref(&self) -> &std::ffi::OsStr {
        match self {
            Self::Docker => OsStr::new("docker"),
            Self::Podman => OsStr::new("podman"),
        }
    }
}

impl ContainerEngine {
    pub fn autodetect() -> Result<Self, IcedragonError> {
        if which("docker").is_ok() {
            Ok(Self::Docker)
        } else if which("podman").is_ok() {
            Ok(Self::Podman)
        } else {
            Err(IcedragonError::ContainerEngineNotFound)
        }
    }
}

#[derive(Parser)]
pub struct BuildContainerImageArgs {
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

/// Returns a vector of `--env` arguments of the containers, consisting of all
/// the current environment variables, except `PATH`, which should be inherited
/// from the Dockerfile.
fn env_args() -> Vec<OsString> {
    env::vars_os()
        .filter(|(key, _)| key != "PATH")
        .map(|(key, value)| {
            let mut env_arg = OsString::from("--env=");
            env_arg.push(key);
            env_arg.push("=");
            env_arg.push(value);
            env_arg
        })
        .collect()
}

pub fn run_container<S, E>(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
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
        ..
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
    container.args(env_args().as_slice());
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

fn push_image(container_engine: &ContainerEngine, tag: &OsStr) -> anyhow::Result<()> {
    let mut cmd = Command::new(container_engine);
    cmd.args([OsStr::new("push"), tag])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    info!("Pushing image with command: {cmd:?}");
    if cmd.status()?.success() {
        Ok(())
    } else {
        Err(IcedragonError::ContainerImagePush.into())
    }
}

pub fn build_container_image(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
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
        cmd.args([OsStr::new("-t"), tag]);
    }
    cmd.args([OsStr::new("-f"), OsStr::new("-"), OsStr::new(".")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if no_cache {
        cmd.arg(OsStr::new("--no-cache"));
    }
    info!("Building container image with command: {cmd:?}");

    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        let mut writer = BufWriter::new(stdin);
        writer.write_all(DOCKERFILE).unwrap();
        writer.flush().unwrap();
    });
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
    writer.join().expect("failed to write to stdin");
    stdout_reader.join().expect("failed to read from stdout");
    stderr_reader.join().expect("failed to read from stderr");

    if push {
        for tag in tags.iter() {
            if let Err(e) = push_image(&container_engine, tag) {
                error!("Failed to push the tag {tag:?}: {e}");
            }
        }
    }

    Ok(())
}
