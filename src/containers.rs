use std::{
    env,
    ffi::{OsStr, OsString},
    io::{BufRead, BufReader, BufWriter, Write},
    process::{Command, Stdio},
    thread,
};

use clap::{Parser, ValueEnum};
use log::{error, info};
use target_lexicon::Triple;
use which::which;

use crate::{run::RunArgs, target::TripleExt, IcedragonError};

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
    #[arg(short, long = "tag", name = "tag")]
    tags: Vec<OsString>,
}

pub fn run_container<S>(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    cli_args: RunArgs,
    cmd_args: &[S],
) -> anyhow::Result<()>
where
    S: AsRef<OsStr>,
{
    let RunArgs {
        container_image,
        container_tag,
        cmd,
        ..
    } = cli_args;

    let container_image =
        container_image.unwrap_or(triple.default_container_image_name(&container_tag));

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
    container
        .args([
            OsStr::new("run"),
            OsStr::new("--rm"),
            OsStr::new("-it"),
            OsStr::new("-v"),
            &bind_mount,
            OsStr::new("-w"),
            OsStr::new("/src"),
            &container_image,
        ])
        .args(cmd_args)
        .args(cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    info!("Running container with command: {container:?}");

    let mut child = container.spawn()?;
    child.wait()?;

    Ok(())
}

fn push_image(container_engine: &ContainerEngine, tag: &OsStr) -> anyhow::Result<()> {
    let mut cmd = Command::new(container_engine);
    cmd.args([OsStr::new("push"), tag])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    info!("Pushing image with command: {cmd:?}");
    if !cmd.status()?.success() {
        return Err(IcedragonError::ContainerImagePush.into());
    }

    Ok(())
}

pub fn build_container_image(
    container_engine: ContainerEngine,
    runner: Option<OsString>,
    triple: Triple,
    args: BuildContainerImageArgs,
) -> anyhow::Result<()> {
    let BuildContainerImageArgs {
        no_cache,
        push,
        tags,
        ..
    } = args;

    let tags = if tags.is_empty() {
        vec![triple.default_container_image_name(OsStr::new("latest"))]
    } else {
        tags
    };

    let dockerfile = triple.dockerfile()?;

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
        writer.write_all(dockerfile).unwrap();
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
