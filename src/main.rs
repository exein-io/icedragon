use std::{
    collections::{vec_deque::Iter, VecDeque},
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::{Component, Path, PathBuf},
    process::{self, Command, Stdio},
    str::FromStr as _,
    thread,
};

use anyhow::{anyhow, bail, Context as _};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use ipc_channel::ipc;
use log::{debug, error, info};
use nix::{
    mount::{mount, MsFlags},
    sched::{clone, CloneFlags},
    unistd::{chdir, chroot, Gid, Pid, Uid},
};
use oci_client::{
    client::{ClientConfig as OciClientConfig, ClientProtocol as OciClientProtocol},
    secrets::RegistryAuth as OciRegistryAuth,
    Client as OciClient, Reference,
};
use rand::{distr::Alphanumeric, rngs::StdRng, Rng as _, SeedableRng as _};
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};
use tokio::{io::AsyncWriteExt as _, task::JoinSet};
use tokio_stream::StreamExt as _;
use which::which;

/// Content of the dockerfile.
const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

const LLVM_VERSION: u32 = 19;

const PROGRESS_BAR_TEMPLATE: &str = "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";
const PROGRESS_BAR_CHARS: &str = "#>-";

/// A wrapper over [`VecDeque`] making it easy to gather platform-native
/// strings.
#[derive(Clone, Debug, Default)]
struct OsVecDeque(VecDeque<OsString>);

impl OsVecDeque {
    fn command(&self) -> anyhow::Result<Command> {
        let mut iter = self.iter();
        let cmd = iter
            .next()
            .ok_or(anyhow!("cannot create a command, vector is empty"))?;
        let mut cmd = Command::new(cmd);
        for arg in iter {
            cmd.arg(arg);
        }
        Ok(cmd)
    }

    fn contains_any<S>(&self, items: &[S]) -> bool
    where
        S: AsRef<OsStr>,
    {
        self.0
            .iter()
            .any(|a| items.iter().any(|b| a.eq(b.as_ref())))
    }

    fn iter(&self) -> Iter<'_, OsString> {
        self.0.iter()
    }

    fn push_back<S: AsRef<OsStr>>(&mut self, s: S) {
        self.0.push_back(s.as_ref().to_owned());
    }

    fn push_front<S: AsRef<OsStr>>(&mut self, s: S) {
        self.0.push_front(s.as_ref().to_owned());
    }
}

impl<S> From<Vec<S>> for OsVecDeque
where
    S: AsRef<OsStr>,
{
    fn from(vec: Vec<S>) -> Self {
        let vec_deque = vec.into_iter().map(|s| s.as_ref().to_owned()).collect();
        Self(vec_deque)
    }
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
    pub cmd: Vec<OsString>,
}

/// Parameters used to launch a container.
#[derive(Clone)]
struct ContainerContext {
    /// Indicates whether stdin should be piped to the container.
    interactive: bool,
    /// Path to the main directory with icedragon's state.
    state_dir: PathBuf,
    /// Path to the container root filesystem.
    rootfs_dir: PathBuf,
    /// Target triple.
    triple: Triple,
    /// List of user-provided volumes to bind mount to the container.
    volumes: Vec<String>,
    /// List of command line arguments to launch inside the container.
    cmd: OsVecDeque,
}

impl ContainerContext {
    /// Creates a new [`Self`] based on provided `state_dir`, target `triple`,
    /// a list of user-provided `volumes` and `cmd` with list of command line
    /// arguments to launch inside the container.
    ///
    /// `interactive` indicates whether stdin should be piped to the container.
    fn new(
        interactive: bool,
        state_dir: &Path,
        triple: Triple,
        volumes: Vec<String>,
        cmd: OsVecDeque,
    ) -> Self {
        let rootfs_dir = state_dir.join("rootfs");
        Self {
            interactive,
            state_dir: state_dir.to_path_buf(),
            rootfs_dir,
            triple,
            volumes,
            cmd,
        }
    }
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

/// Returns a vector of environment variables to use in the container spec,
/// consisting of:
///
/// * The current environment variables, except ones like `HOME`, `PATH` etc.,
///   which would break the containerized environment. We filter out variables
///   prefixed by `CARGO` and `RUSTUP` to make sure that the Rust toolchain
///   inside container is isolated, expecially when icedragon is launched with
///   `cargo run`. Variables prefixed by `SSL` are filtered to make sure that
///   ca-certificates from the container are used.
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
fn prepare_env(triple: &Triple) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = env::vars()
        .filter_map(|(key, value)| {
            if matches!(key.as_str(), "HOME" | "OLDPWD" | "PATH" | "PWD" | "USER")
                || key.as_str().starts_with("CARGO")
                || key.as_str().starts_with("RUSTUP")
                || key.as_str().starts_with("SSL")
            {
                None
            } else {
                Some((key, value))
            }
        })
        .collect();
    env.extend_from_slice(&[
        ("CARGO_BUILD_TARGET".to_owned(), format!("{triple}")),
        ("CC".to_owned(), format!("{triple}-clang")),
        ("CXX".to_owned(), format!("{triple}-clang++")),
        ("CXXFLAGS".to_owned(), format!("{} --stdlib=libc++", env::var("CXXFLAGS").unwrap_or_default())),
        ("LDFLAGS".to_owned(), format!("{} -fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind", env::var("LDFLAGS").unwrap_or_default())),
        ("PATH".to_owned(), format!("/root/.cargo/bin:/usr/lib/llvm/{LLVM_VERSION}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")),
        ("PKG_CONFIG_SYSROOT_DIR".to_owned(), format!("/usr/{triple}")),
        ("RUSTUP_HOME".to_owned(), "/root/.rustup".to_owned()),
        ("RUSTFLAGS".to_owned(), format!("{} -C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}",
            env::var("RUSTFLAGS").unwrap_or_default()
        )),
    ]);
    let Triple { architecture, .. } = triple;
    if architecture != &target_lexicon::HOST.architecture {
        let triple = triple.to_string().to_uppercase().replace('-', "_");
        env.push((
            format!("CARGO_TARGET_{triple}_RUNNER"),
            format!("qemu-{architecture}"),
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
    ctx: &ContainerContext,
    download_dir: &Path,
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
        let pb_style =
            ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE)?.progress_chars(PROGRESS_BAR_CHARS);

        let layer_file = download_dir.join(&layer.digest);
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
    if ctx.rootfs_dir.exists() {
        tokio::fs::remove_dir_all(&ctx.rootfs_dir).await?;
    }
    tokio::fs::create_dir_all(&ctx.rootfs_dir).await?;

    Ok(Some((digest, layer_files)))
}

fn unpack_image(
    ctx: &ContainerContext,
    download_dir: &PathBuf,
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
                archive.unpack(&ctx.rootfs_dir).unwrap();
            });
        }
    });

    fs::remove_dir_all(download_dir)?;

    Ok(())
}

fn write_digest(digest_file: &PathBuf, digest: &str) -> anyhow::Result<()> {
    let mut digest_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(digest_file)?;
    digest_file.write_all(digest.as_bytes())?;
    Ok(())
}

/// Prepares a rootfs for the container based on provided `container_image`.
///
/// The `{state_dir}/digest` file is used for storing the digest of the
/// downloaded image. The image pull is skipped if the digest stored there is
/// already up-to-date. Otherwise, it's updated after the successfull image
/// pull.
fn prepare_container(ctx: &ContainerContext, container_image: &str) -> anyhow::Result<()> {
    let mut rng = StdRng::from_os_rng();
    let download_dir = rand_string(&mut rng, 6);
    let download_dir = Path::new("/tmp").join(download_dir);
    fs::create_dir_all(&download_dir)?;

    let digest_file = ctx.state_dir.join("digest");

    if let Some((digest, layer_files)) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(pull_image(
            ctx,
            &download_dir,
            &digest_file,
            container_image,
        ))?
    {
        unpack_image(ctx, &download_dir, layer_files)?;
        write_digest(&digest_file, &digest)?;
    }
    Ok(())
}

/// Writes an ID mapping from the given `host_id` (representing a host user) to
/// `0` (representing `root` inside container) to the given `map_file`.
fn write_mapping(map_file: &Path, host_id: u32) -> anyhow::Result<()> {
    debug!("Writing mapping to {map_file:?}");
    let mapping = format!("0 {host_id} 1");
    std::fs::write(map_file, mapping)?;
    Ok(())
}

/// Writes UID and UID mappings from the host user to `0` (representing `root`
/// inside container) for the given `pid`.
fn write_mappings(pid: Pid) -> anyhow::Result<()> {
    let proc_self = Path::new("/proc").join(pid.as_raw().to_string());
    std::fs::write(proc_self.join("setgroups"), "deny")?;
    write_mapping(&proc_self.join("uid_map"), Uid::current().as_raw())?;
    write_mapping(&proc_self.join("gid_map"), Gid::current().as_raw())?;
    Ok(())
}

/// Mounts `procfs` inside `rootfs_dir`.
fn proc_mount(rootfs_dir: &Path) -> anyhow::Result<()> {
    debug!("Mounting /proc");
    mount(
        Some("proc"),
        &rootfs_dir.join("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )?;
    Ok(())
}

/// Mounts `tmpfs` to `/dev` inside `rootfs_dir` and then selectivly mounts
/// single devices that are essential for having a functional system. Some of
/// them can be new mounts (`mqueue`, `pts`). Some of them need to be bind
/// mounted from the host (`null`, `urandom` etc.).
fn dev_mount(rootfs_dir: &Path) -> anyhow::Result<()> {
    debug!("Mounting /dev");
    mount(
        Some("tmpfs"),
        &rootfs_dir.join("dev"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )?;
    debug!("Mounting /dev/mqueue");
    let mqueue_path = rootfs_dir.join("dev/mqueue");
    if !mqueue_path.exists() {
        fs::create_dir_all(&mqueue_path)?;
    }
    mount(
        Some("mqueue"),
        &mqueue_path,
        Some("mqueue"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )?;
    debug!("Mounting /dev/pts");
    let pts_path = rootfs_dir.join("dev/pts");
    if !pts_path.exists() {
        fs::create_dir_all(&pts_path)?;
    }
    mount(
        Some("devpts"),
        &pts_path,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        // Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        None::<&str>,
    )?;
    debug!("Mounting /dev/null");
    bind_mount(rootfs_dir, "/dev/null", "/dev/null")?;
    debug!("Mounting /dev/zero");
    bind_mount(rootfs_dir, "/dev/zero", "/dev/zero")?;
    debug!("Mounting /dev/full");
    bind_mount(rootfs_dir, "/dev/full", "/dev/full")?;
    debug!("Mounting /dev/tty");
    bind_mount(rootfs_dir, "/dev/tty", "/dev/tty")?;
    debug!("Mounting /dev/urandom");
    bind_mount(rootfs_dir, "/dev/urandom", "/dev/urandom")?;
    debug!("Mounting /dev/random");
    bind_mount(rootfs_dir, "/dev/random", "/dev/random")?;
    Ok(())
}

/// Bind mounts the given `src` into `dst` prefixed by `rootfs_dir`.
fn bind_mount(
    rootfs_dir: &Path,
    src: impl AsRef<Path>,
    dst: impl AsRef<Path>,
) -> anyhow::Result<()> {
    let mut full_dst = rootfs_dir.to_path_buf();
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
                fs::create_dir_all(parent)?;
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
    Ok(())
}

/// Mount filesystems into the `rootfs_dir`:
///
/// * `/proc`, see [`proc_mount`] for details.
/// * `/dev`, see [`dev_mount`] for details.
/// * `/src`, where we mount the current directory.
/// * `/etc/resolv.conf`, which makes sure that resolving domains works insice
///   container.
/// * User-provided bind volumes.
fn mount_volumes(ctx: &ContainerContext) -> anyhow::Result<()> {
    proc_mount(&ctx.rootfs_dir)?;
    dev_mount(&ctx.rootfs_dir)?;
    bind_mount(&ctx.rootfs_dir, env::current_dir()?, "/src")?;
    bind_mount(&ctx.rootfs_dir, "/etc/resolv.conf", "/etc/resolv.conf")?;
    // Mount all the user-provided volumes.
    for volume in &ctx.volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("invalid volume format: {volume}"));
        }
        let (src, dst) = (parts[0], parts[1]);
        bind_mount(&ctx.rootfs_dir, src, dst)?;
    }
    Ok(())
}

fn container_child(ctx: &ContainerContext) -> anyhow::Result<Option<i32>> {
    mount_volumes(ctx)?;
    chroot(&ctx.rootfs_dir).context("`chroot` syscall failed")?;
    chdir("/src").context("failed to change directory to `/src`")?;

    let envs = prepare_env(&ctx.triple);

    let mut cmd = ctx.cmd.command()?;
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    if ctx.interactive {
        cmd.stdin(Stdio::inherit());
    }
    let status = cmd.env_clear().envs(envs).spawn()?.wait()?;

    Ok(status.code())
}

/// Runs a container, based on provided `cmd` and `rootfs_dir`.
fn run_container(ctx: ContainerContext) -> anyhow::Result<()> {
    // Channel for notifying the readiness of the child process, ensuring that
    // UID/GID mapping is not written too early.
    let (child_tx, child_rx) = ipc::channel()?;
    // Channel for notifying about the readiness of UID/GID mapping, ensuring
    // that `chroot` and the command are not called before it's done.
    let (id_map_tx, id_map_rx) = ipc::channel()?;
    let (res_tx, res_rx) = ipc::channel()?;

    // Spawn a separate process with new namespaces and in our sysroot.
    let mut child_stack = vec![0; 1024 * 1024];
    // SAFETY: We use `clone` only to spawn a new process, which uses entirely
    // safe Rust and `ipc-channel`. The `child_stack` is a safely allocated and
    // zeroed buffer.
    let pid = unsafe {
        clone(
            Box::new(move || {
                child_tx
                    .send(())
                    .expect("failed to notify the parent process about readiness");
                id_map_rx.recv().expect("failed to retrieve the message about readiness of UID/GID mappings from the parent process");
                let res = container_child(&ctx).map_err(|e| serde_error::Error::new(&*e));
                res_tx
                    .send(res)
                    .expect("failed to send child result to the channel");

                0
            }),
            &mut child_stack,
            CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWCGROUP
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWUTS,
            None,
        )?
    };

    // mount_volumes(rootfs_dir, volumes.clone())?;

    child_rx
        .recv()
        .context("failed to receive the message about readiness of the child process")?;
    write_mappings(pid)?;
    id_map_tx.send(())?;

    let exit_code = res_rx.recv()??;
    if let Some(exit_code) = exit_code {
        process::exit(exit_code);
    }

    Ok(())
}

/// Runs cargo inside a container.
fn cargo(
    state_dir: &Path,
    triple: Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: OsVecDeque,
) -> anyhow::Result<()> {
    // The command is `cargo` followed by arguments provided by the caller.
    cmd.push_front("cargo");

    run(false, state_dir, triple, container_image, volumes, cmd)
}

/// Runs clang inside a container.
fn clang(
    state_dir: &Path,
    triple: Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: OsVecDeque,
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
            "aarch64-unknown-linux-musl-clang"
        }
        (Architecture::X86_64, OperatingSystem::Linux, Environment::Musl) => {
            "x86_64-unknown-linux-musl-clang"
        }
        (_, _, _) => return Err(anyhow!("target {triple} is not supported")),
    };
    cmd.push_front(clang_cmd);

    run(false, state_dir, triple, container_image, volumes, cmd)
}

/// Runs `CMake` inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
fn cmake(
    state_dir: &Path,
    triple: Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: OsVecDeque,
) -> anyhow::Result<()> {
    // Determine whether we are configuring a CMake project.
    //
    // Usage of any of the following arguments means performing an action other
    // than configuring the project.
    // This would've been easier to determine if CMake actions were treated as
    // subcommands instead of regular arguments with no enforced order...
    let configure = !cmd.contains_any(&["--build", "--help", "--install", "--open"]);

    // The command is `cmake` followed by arguments provided by the caller...
    cmd.push_front("cmake");

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
        cmd.push_back("-DCMAKE_ASM_COMPILER=clang");
        cmd.push_back(format!("-DCMAKE_ASM_COMPILER_TARGET={triple}"));
        cmd.push_back("-DCMAKE_C_COMPILER=clang");
        cmd.push_back(format!("-DCMAKE_C_COMPILER_TARGET={triple}"));
        cmd.push_back("-DCMAKE_CXX_COMPILER=clang++");
        cmd.push_back(format!("-DCMAKE_CXX_COMPILER_TARGET={triple}"));
        // Tell CMake to look for libraries, headers and packages (through
        // pkg-config) only in the specified sysroot. Prevent picking them
        // from the main sysroot.
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY");
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY");
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY");
        // Tell CMake to look for the other build system binaries (like Ninja
        // or make) only on the host sysroot, not in the cross sysroot.
        cmd.push_back("-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER");
        // CMake requires both of these variables to indicate that we are
        // performing a cross build.
        // Currently, we support only Linux targets, so let's just hard code
        // the name.
        // If we ever want to support other systems, we need to convert the OS
        // part of the target triple to a capitalized value that CMake expects
        // (e.g. Darwin, Linux, FreeBSD, Windows). Passing lower-case names
        // doesn't work.
        cmd.push_back("-DCMAKE_SYSTEM_NAME=Linux");
        cmd.push_back(format!("-DCMAKE_SYSTEM_PROCESSOR={architecture}"));
        // Point to the crossdev's target sysroot.
        cmd.push_back(format!("-DCMAKE_SYSROOT=/usr/{triple}"));
    }

    run(false, state_dir, triple, container_image, volumes, cmd)
}

/// Run a command inside a container.
fn run(
    interactive: bool,
    state_dir: &Path,
    triple: Triple,
    container_image: &str,
    volumes: Vec<String>,
    cmd: OsVecDeque,
) -> anyhow::Result<()> {
    let ctx = ContainerContext::new(interactive, state_dir, triple, volumes, cmd);
    prepare_container(&ctx, container_image)?;
    run_container(ctx)?;

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
            cargo(&state_dir, triple, &container_image, volumes, cmd.into())
        }
        Commands::Clang(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            clang(&state_dir, triple, &container_image, volumes, cmd.into())
        }
        Commands::Cmake(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cmake(&state_dir, triple, &container_image, volumes, cmd.into())
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
                triple,
                &container_image,
                volumes,
                cmd.into(),
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vec_deque_conv() {
        let vec = vec!["foo", "bar", "baz"];
        let vec_deq: OsVecDeque = vec.into();

        for (a, b) in vec_deq.iter().zip(&[
            OsString::from("foo"),
            OsString::from("bar"),
            OsString::from("baz"),
        ]) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_vec_deque_push() {
        let mut vec_deq = OsVecDeque::default();

        vec_deq.push_back("ayy");
        vec_deq.push_back("lmao");

        vec_deq.push_front("bar");
        vec_deq.push_front("foo");

        for (a, b) in vec_deq.iter().zip(&[
            OsString::from("foo"),
            OsString::from("bar"),
            OsString::from("ayy"),
            OsString::from("lmao"),
        ]) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_vec_deque_contains_any() {
        let cmake_action_args = &["--build", "--help", "--install", "--open"];

        let args: OsVecDeque = vec!["cmake", "--build"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: OsVecDeque = vec!["cmake", "--help"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: OsVecDeque = vec!["cmake", "--install"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: OsVecDeque = vec!["cmake", "--open", "myproject"].into();
        assert!(args.contains_any(cmake_action_args));

        let args: OsVecDeque = vec![
            "cmake",
            "-S",
            "llvm",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        ]
        .into();
        assert!(!args.contains_any(cmake_action_args));
    }

    #[test]
    fn test_expand_tilde() {
        env::set_var("HOME", "/home/test");
        assert_eq!(expand_tilde("~").unwrap(), PathBuf::from("/home/test"));
        assert_eq!(
            expand_tilde("~/foo").unwrap(),
            PathBuf::from("/home/test/foo")
        );
        assert_eq!(
            expand_tilde("~/foo/bar").unwrap(),
            PathBuf::from("/home/test/foo/bar")
        );
    }
}
