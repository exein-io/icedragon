use std::{
    collections::{vec_deque::Iter, VecDeque},
    env,
    ffi::{CString, OsStr, OsString},
    fs::{self, OpenOptions},
    io::{BufRead as _, BufReader, Write},
    ops::{Deref, DerefMut},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr as _,
    thread,
};

use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use ipc_channel::ipc;
use log::{debug, error, info};
use nix::{
    mount::{mount, MsFlags},
    sched::{clone, unshare, CloneFlags},
    sys::wait::waitpid,
    unistd::{chdir, chroot, execvpe, Gid, Pid, Uid},
};
use oci_client::{
    client::{ClientConfig as OciClientConfig, ClientProtocol as OciClientProtocol},
    secrets::RegistryAuth as OciRegistryAuth,
    Client as OciClient, Reference,
};
use rand::{distr::Alphanumeric, rngs::StdRng, Rng as _, SeedableRng};
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};
use tokio::{io::AsyncWriteExt as _, task::JoinSet};
use tokio_stream::StreamExt as _;
use which::which;

/// Content of the dockerfile.
const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

const LLVM_VERSION: u32 = 19;

macro_rules! c_format {
    ($($arg:tt)*) => {{
        let fmt_str = format!($($arg)*);
        CString::new(fmt_str).expect("failed to convert to CString")
    }};
}

/// Linux cross-compilation suite for building portable software.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Directory where the internal state is stored.
    #[arg(global = true, long, default_value = "~/.icedragon")]
    state_dir: OsString,

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
    /// Container engine (if not provided, is going to be autodetected).
    #[arg(global = true, long)]
    container_engine: Option<ContainerEngine>,

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
fn build_container_image(args: BuildContainerImageArgs) -> anyhow::Result<()> {
    let BuildContainerImageArgs {
        container_engine,
        no_cache,
        push,
        tags,
    } = args;

    let container_engine = match container_engine {
        Some(ref container_engine) => container_engine,
        None => &ContainerEngine::autodetect()?,
    };

    let mut cmd = Command::new(container_engine);
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
    pub container_image: String,

    /// Additional volumes to mount to the container.
    #[arg(long = "volume", short)]
    pub volumes: Vec<String>,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<CString>,
}

/// Returns a vector of environment variables to use in the container spec,
/// consisting of:
///
/// * The current environment variables, except ones like `HOME`, `PATH` etc.,
///   which would break the containerized environment.
/// * Additional variables defined by us to shape the behavior of compilers and
///   making sure they perform a correct cross build for the given `target`:
///   * `CARGO_BUILD_TARGET`, telling cargo what target to build for.
///   * `CC` and `CXX` pointing to the clang cross wrappers.
///   * `CXXFLAGS` and `LDFLAGS`, pointing to LLVM libc++ as a C++ stdlib, LLD
///     as a linker, compiler-rt as a runtime library and LLVM libunwind as
///     unwinder.
///   * `PATH` including the directories of LLVM and Rust toolchains.
///   * `PKG_CONFIG_SYSROOT_DIR`, to point pkg-config to the sysroot.
///   * `RUSTUP_HOME` pointing to the directory with Rust toolchains.
///   * `RUSTFLAGS` telling Rust to:
///     * Use an appropriate clang wrapper as a linker.
///     * Use the cross sysroot.
///   * `CARGO_TARGET_{triple}_RUNNER`, pointing to a QEMU user-space emulator,
///     if the host and target CPU targets are different.
fn prepare_env(triple: &Triple) -> Vec<CString> {
    let mut env: Vec<CString> = env::vars()
        .filter_map(|(key, value)| {
            if matches!(key.as_str(), "HOME" | "OLDPWD" | "PATH" | "PWD" | "USER") {
                None
            } else {
                Some(c_format!("{key}={value}"))
            }
        })
        .collect();
    env.extend_from_slice(&[
        c_format!("CARGO_BUILD_TARGET={triple}"),
        c_format!("CC={triple}-clang"),
        c_format!("CXX={triple}-clang++"),
        c_format!("CXXFLAGS={} --stdlib=libc++", env::var("CXXFLAGS").unwrap_or_default()),
        c_format!("LDFLAGS={} -fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind", env::var("LDFLAGS").unwrap_or_default()),
        c_format!("PATH=/root/.cargo/bin:/usr/lib/llvm/{LLVM_VERSION}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        c_format!("PKG_CONFIG_SYSROOT_DIR=/usr/{triple}"),
        c_format!("RUSTUP_HOME=/root/.rustup"),
        c_format!("RUSTFLAGS={} -C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}",
            env::var("RUSTFLAGS").unwrap_or_default()
        ),
    ]);
    let Triple { architecture, .. } = triple;
    if architecture != &target_lexicon::HOST.architecture {
        let triple = triple.to_string().to_uppercase().replace('-', "_");
        env.push(c_format!(
            "CARGO_TARGET_{triple}_RUNNER=qemu-{architecture}"
        ));
    }
    env
}

/// Returns a random string with the given `len`.
fn rand_string(rng: &mut StdRng, len: usize) -> String {
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

async fn pull_image(
    rootfs_dir: &PathBuf,
    layers_dir: &Path,
    digest_file: &PathBuf,
    container_image: &str,
) -> anyhow::Result<Option<(String, Vec<PathBuf>)>> {
    let config = OciClientConfig {
        protocol: OciClientProtocol::Https,
        ..Default::default()
    };
    let client = OciClient::new(config);
    let reference: Reference = container_image.parse()?;

    let (manifest, digest) = client
        .pull_image_manifest(&reference, &OciRegistryAuth::Anonymous)
        .await?;

    // Check if we have an up-to-date image fetched locally.
    if digest_file.exists() {
        let local_digest = tokio::fs::read_to_string(&digest_file).await?;
        if local_digest == digest {
            debug!(
                "Image already up-to-date (local digest: {local_digest}, latest digest: {digest})"
            );
            return Ok(None);
        }
    }

    info!("📥 Pulling image");
    let mut layer_files = Vec::with_capacity(manifest.layers.len());
    let mut download_tasks = JoinSet::new();

    let mpb = MultiProgress::new();

    for layer in manifest.layers {
        let client = client.clone();
        let reference = reference.clone();
        let mpb = mpb.clone();
        let pb_style = ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
        .progress_chars("#>-");

        let layer_file = layers_dir.join(&layer.digest);
        layer_files.push(layer_file.clone());

        download_tasks.spawn(async move {
            let mut layer_file = tokio::fs::File::create(layer_file).await.unwrap();

            let mut stream = client.pull_blob_stream(&reference, &layer).await.unwrap();

            // Why is `oci-spec` storing layer size as `i64`? No idea. ¯\_(ツ)_/¯
            #[allow(clippy::cast_sign_loss)]
            let content_length = stream.content_length.unwrap_or(layer.size as u64);

            let pb = mpb.add(ProgressBar::new(content_length));
            pb.set_style(pb_style.clone());
            while let Some(res) = stream.next().await {
                let chunk = res.unwrap();
                layer_file.write_all(&chunk).await.unwrap();
                pb.inc(chunk.len() as u64);
            }
            pb.finish_and_clear();
        });
    }
    download_tasks.join_all().await;

    // Remove the outdated image.
    if rootfs_dir.exists() {
        tokio::fs::remove_dir_all(&rootfs_dir).await?;
    }
    tokio::fs::create_dir_all(&rootfs_dir).await?;

    Ok(Some((digest, layer_files)))
}

fn unpack_image(
    rootfs_dir: &PathBuf,
    layers_dir: &PathBuf,
    layer_files: impl IntoIterator<Item = PathBuf>,
) -> anyhow::Result<()> {
    info!("📦 Unpacking image");
    // NOTE(vadorovsky): You might be wondering why downloading is done in async
    // Rust and unpacking is not. The reason is - there are multiple
    // `tokio-tar` crates... and none of them is working properly:
    //
    // * `tokio-tar` and `krata-tokio-tar` are not able to unpack Python
    //   artifacts, failing with errors like `failed to unpack [..]/__pycache__/t`.
    //   Not sure what the issue is there, but might be related to symlinks.
    // * `astral-tokio-tar` doesn't preserve the permissions and execute bits of
    //   unpacked files.
    //
    // The upstream, non-async `tar` crate works just fine. Using it here is
    // not ideal, we should definitely fix that at some poit.
    //
    // Overall, the most frustrating thing is that all the "async tar" crates
    // are full forks, which end up broken and not up-to-date. There is a
    // proposal of making a sans-io tar crate[0], which sounds like a good
    // idea.
    //
    // The other way could be writing a collection of extension traits for
    // types from the `tar` crate (like `Archive` or `Entry`) which work with
    // async reader types, trying to re-use as much of the upstream logic as
    // possible.
    //
    // [0] https://github.com/alexcrichton/tar-rs/issues/379
    thread::scope(|s| {
        for layer_file in layer_files {
            s.spawn(|| {
                let layer_file = std::fs::File::open(layer_file).unwrap();
                let reader = std::io::BufReader::new(layer_file);
                let stream = flate2::bufread::GzDecoder::new(reader);
                let mut archive = tar::Archive::new(stream);
                archive.unpack(rootfs_dir).unwrap();
            });
        }
    });

    fs::remove_dir_all(&layers_dir)?;

    Ok(())
}

fn write_digest(digest_file: &PathBuf, digest: &str) -> anyhow::Result<()> {
    let mut digest_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&digest_file)?;
    digest_file.write_all(digest.as_bytes())?;
    Ok(())
}

/// Pulls the given `container_image` from an OCI registry and unpacks it into
/// the given `rootfs_dir`.
///
/// The `{state_dir}/digest` file is used for storing the digest of the
/// downloaded image. The image pull is skipped if the digest stored there is
/// already up-to-date. Otherwise, it's updated after the successfull image
/// pull.
fn pull_and_unpack_image(
    state_dir: &Path,
    rootfs_dir: &PathBuf,
    container_image: &str,
) -> anyhow::Result<()> {
    let mut rng = StdRng::from_os_rng();
    let layers_dir = rand_string(&mut rng, 6);
    let layers_dir = Path::new("/tmp").join(layers_dir);
    fs::create_dir_all(&layers_dir)?;

    let digest_file = state_dir.join("digest");

    if let Some((digest, layer_files)) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(pull_image(
            rootfs_dir,
            &layers_dir,
            &digest_file,
            container_image,
        ))?
    {
        unpack_image(rootfs_dir, &layers_dir, layer_files)?;
        write_digest(&digest_file, &digest)?;
    }
    Ok(())
}

fn write_mapping(map_file: &Path, host_id: u32) -> anyhow::Result<()> {
    debug!("Writing mapping to {map_file:?}");
    let mapping = format!("0 {host_id} 1");
    std::fs::write(map_file, mapping)?;
    Ok(())
}

fn write_mappings(pid: Pid) -> anyhow::Result<()> {
    let proc_self = Path::new("/proc").join(pid.as_raw().to_string());
    std::fs::write(proc_self.join("setgroups"), "deny")?;
    write_mapping(&proc_self.join("uid_map"), Uid::current().as_raw())?;
    write_mapping(&proc_self.join("gid_map"), Gid::current().as_raw())?;
    Ok(())
}

fn bind_mount(
    rootfs_dir: &PathBuf,
    src: impl AsRef<Path>,
    dst: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let mut full_dst = rootfs_dir.clone();
    for component in dst.as_ref().components() {
        // Pushing an absolute path with `/` to an existing `PathBuf`, replaces
        // its old content entirely. That's not our intention - we want to
        // merge `rootfs_dir` with `dst` even if `dst` is absolute.
        if !matches!(component, Component::RootDir) {
            full_dst.push(component);
        }
    }
    if !full_dst.exists() {
        if src.as_ref().is_dir() {
            // When source is a directory, the destination has to be a
            // directory as well.
            fs::create_dir_all(&full_dst)?;
        } else {
            // Otherwise, the destination has to be a regular file. It can be
            // empty.
            if let Some(parent) = full_dst.parent() {
                fs::create_dir_all(&parent)?;
            }
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&full_dst)?;
        }
    }

    debug!("Mounting {:?} to {full_dst:?}", src.as_ref());
    mount(
        Some(src.as_ref()),
        &full_dst,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    debug!("mounted");
    Ok(())
}

fn mount_host_volumes(
    rootfs_dir: &PathBuf,
    volumes: impl IntoIterator<Item = String>,
) -> anyhow::Result<()> {
    // Mount the current directory.
    bind_mount(rootfs_dir, env::current_dir()?, "/src")?;
    // Mount `/etc/resolv.conf`, otherwise the container might not be able to
    // resolve domains.
    bind_mount(rootfs_dir, "/etc/resolv.conf", "/etc/resolv.conf")?;
    // Mount all the user-provided volumes.
    for volume in volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("invalid volume format: {volume}"));
        }
        let (src, dst) = (parts[0], parts[2]);
        bind_mount(rootfs_dir, src, dst)?;
    }
    Ok(())
}

fn proc_mount() -> anyhow::Result<()> {
    debug!("Mounting /proc");
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )?;
    Ok(())
}

fn sys_mount() -> anyhow::Result<()> {
    debug!("Mounting /sys");
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
        None::<&str>,
    )?;
    debug!("Mounting /sys/fs/cgroup");
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup",
        Some("cgroup"),
        MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC
            | MsFlags::MS_NOSUID
            | MsFlags::MS_PRIVATE
            | MsFlags::MS_RDONLY
            | MsFlags::MS_RELATIME,
        None::<&str>,
    )?;
    Ok(())
}

fn mount_local_volumes() -> anyhow::Result<()> {
    proc_mount()?;
    // sys_mount()?;
    Ok(())
}

/// Runs a container, based on a `bundle_dir` with an OCI-compliant spec and
/// `rootfs`.
fn run_container(
    interactive: bool,
    rootfs_dir: &PathBuf,
    triple: &Triple,
    volumes: Vec<String>,
    mut cmd: VecDeque<CString>,
) -> anyhow::Result<()> {
    // Channel for notifying the readiness of the child process, ensuring that
    // `waitpid` is not called too early.
    let (child_readiness_tx, child_readiness_rx) = ipc::channel()?;
    // Channel for notifying about the readiness of UID/GID mapping, ensuring
    // that `chroot` and `execvpe` are not called before it's done.
    let (id_map_readiness_tx, id_map_readiness_rx) = ipc::channel()?;
    // Channel for capturing errors from the child process.
    let (err_tx, err_rx) = ipc::channel()?;
    let mut child_stack = vec![0; 1024 * 1024];
    let pid = unsafe {
        clone(
            Box::new(move || {
                child_readiness_tx
                    .send(())
                    .expect("failed to message parent about readiness");
                id_map_readiness_rx
                    .recv()
                    .expect("failed to receive message from parent");

                let mut run_process = || -> anyhow::Result<()> {
                    mount_host_volumes(rootfs_dir, volumes.clone())?;
                    chroot(rootfs_dir)?;
                    chdir("/src")?;
                    mount_local_volumes()?;
                    let args = cmd.make_contiguous();
                    let filename = CString::new(args[0].as_bytes())?;
                    let env = prepare_env(triple);
                    child_readiness_tx.send(()).unwrap();
                    execvpe(&filename, args, &env)?;
                    // child_readiness_tx.send(()).unwrap();
                    Ok(())
                };
                let res = run_process().map_err(|e| serde_error::Error::new(&*e));
                err_tx.send(res).expect("failed to send the child result");

                0
            }),
            &mut child_stack,
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWUSER,
            None,
        )?
    };
    child_readiness_rx
        .recv()
        .context("failed to receive readiness message from child")?;
    write_mappings(pid)?;
    id_map_readiness_tx.send(())?;

    std::thread::sleep(std::time::Duration::from_millis(100));
    // waitpid(pid, None)?;

    err_rx
        .recv()
        .context("failed to receive the child result")?
        .context("child process returned an error")?;

    Ok(())
}

/// Runs cargo inside a container.
fn cargo(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: VecDeque<CString>,
) -> anyhow::Result<()> {
    // The command is `cargo` followed by arguments provided by the caller.
    cmd.push_front(c"cargo".to_owned());

    run(false, state_dir, triple, container_image, volumes, cmd)
}

/// Runs clang inside a container.
fn clang(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: VecDeque<CString>,
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
            c"aarch64-unknown-linux-musl-clang"
        }
        (Architecture::X86_64, OperatingSystem::Linux, Environment::Musl) => {
            c"x86_64-unknown-linux-musl-clang"
        }
        (_, _, _) => return Err(anyhow!("target {triple} is not supported")),
    };
    cmd.push_front(clang_cmd.to_owned());

    run(false, state_dir, triple, container_image, volumes, cmd)
}

/// Runs `CMake` inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
fn cmake(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: VecDeque<CString>,
) -> anyhow::Result<()> {
    // Determine whether we are configuring a CMake project.
    //
    // Usage of any of the following arguments means performing an action other
    // than configuring the project.
    // This would've been easier to determine if CMake actions were treated as
    // subcommands instead of regular arguments with no enforced order...
    let cmake_commands = &[c"--build", c"--help", c"--install", c"--open"];
    let configure = cmd
        .iter()
        .any(|a| cmake_commands.iter().any(|b| a.as_c_str().eq(b)));

    // The command is `cmake` followed by arguments provided by the caller...
    cmd.push_front(c"cmake".to_owned());

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
        cmd.push_back(c"-DCMAKE_ASM_COMPILER=clang".to_owned());
        cmd.push_back(c_format!("-DCMAKE_ASM_COMPILER_TARGET={triple}"));
        cmd.push_back(c"-DCMAKE_C_COMPILER=clang".to_owned());
        cmd.push_back(c_format!("-DCMAKE_C_COMPILER_TARGET={triple}"));
        cmd.push_back(c"-DCMAKE_CXX_COMPILER=clang++".to_owned());
        cmd.push_back(c_format!("-DCMAKE_CXX_COMPILER_TARGET={triple}"));
        // Tell CMake to look for libraries, headers and packages (through
        // pkg-config) only in the specified sysroot. Prevent picking them
        // from the main sysroot.
        cmd.push_back(c"-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY".to_owned());
        cmd.push_back(c"-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY".to_owned());
        cmd.push_back(c"-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY".to_owned());
        // Tell CMake to look for the other build system binaries (like Ninja
        // or make) only on the host sysroot, not in the cross sysroot.
        cmd.push_back(c"-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER".to_owned());
        // CMake requires both of these variables to indicate that we are
        // performing a cross build.
        // Currently, we support only Linux targets, so let's just hard code
        // the name.
        // If we ever want to support other systems, we need to convert the OS
        // part of the target triple to a capitalized value that CMake expects
        // (e.g. Darwin, Linux, FreeBSD, Windows). Passing lower-case names
        // doesn't work.
        cmd.push_back(c"-DCMAKE_SYSTEM_NAME=Linux".to_owned());
        cmd.push_back(c_format!("-DCMAKE_SYSTEM_PROCESSOR={architecture}"));
        // Point to the crossdev's target sysroot.
        cmd.push_back(c_format!("-DCMAKE_SYSROOT=/usr/{triple}"));
    }

    run(false, state_dir, triple, container_image, volumes, cmd)
}

/// Run a command inside a container.
fn run(
    interactive: bool,
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    cmd: VecDeque<CString>,
) -> anyhow::Result<()> {
    let rootfs_dir = state_dir.join("rootfs");
    pull_and_unpack_image(state_dir, &rootfs_dir, container_image)?;
    run_container(interactive, &rootfs_dir, triple, volumes, cmd)?;

    Ok(())
}

/// Parses and validates the given `target` triple.
fn parse_target(target: Option<&str>) -> anyhow::Result<Triple> {
    // Parse target.
    let triple = if let Some(target) = target {
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

    Ok(triple)
}

/// Expands a tilde with a home directory in the given path.
fn expand_tilde<P: AsRef<Path>>(p: P) -> anyhow::Result<PathBuf> {
    let p = p.as_ref();
    if p.starts_with("~") {
        let mut home = match env::var_os("HOME") {
            Some(home) => PathBuf::from(home),
            None => bail!("the current user has no HOME directory"),
        };
        if !p.ends_with("~") {
            home.extend(p.components().skip(1));
        }
        Ok(home)
    } else {
        Ok(p.to_path_buf())
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Cli {
        command,
        state_dir,
        target,
    } = cli;

    let state_dir = expand_tilde(state_dir)?;
    fs::create_dir_all(&state_dir)?;
    let triple = parse_target(target.as_deref())?;

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    match command {
        Commands::BuildContainerImage(args) => build_container_image(args),
        Commands::Cargo(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cargo(&state_dir, &triple, &container_image, volumes, cmd.into())
        }
        Commands::Clang(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            clang(&state_dir, &triple, &container_image, volumes, cmd.into())
        }
        Commands::Cmake(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cmake(&state_dir, &triple, &container_image, volumes, cmd.into())
        }
        Commands::Run(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            run(
                true,
                &state_dir,
                &triple,
                &container_image,
                volumes,
                cmd.into(),
            )
        }
    }
}
