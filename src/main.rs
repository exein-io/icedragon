#[cfg(test)]
use std::collections::vec_deque::Iter;
use std::{
    collections::VecDeque,
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr as _,
};

use anyhow::{anyhow, bail, Context as _};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use libcontainer::{
    container::builder::ContainerBuilder,
    oci_spec::runtime::{
        get_rootless_mounts, Linux, Mount, MountBuilder, ProcessBuilder, RootBuilder, Spec,
        SpecBuilder,
    },
    syscall::syscall::SyscallType,
    workload::default::DefaultExecutor,
};
use log::{debug, error, info};
use nix::{
    sys::wait::waitpid,
    unistd::{Gid, Uid},
};
use oci_client::{
    client::{ClientConfig as OciClientConfig, ClientProtocol as OciClientProtocol},
    secrets::RegistryAuth as OciRegistryAuth,
    Client as OciClient, Reference,
};
use rand::{distr::Alphanumeric, rngs::StdRng, Rng as _, SeedableRng as _};
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};
use tokio::{
    fs::{self, read_to_string, File, OpenOptions},
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::Command,
    task::JoinSet,
};
use tokio_stream::StreamExt as _;
use which::which;

/// Content of the dockerfile.
const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

const LLVM_VERSION: u32 = 19;

/// A wrapper over [`VecDeque`] making it easy to gather strings without manual
/// conversions on the caller's side.
#[derive(Debug, Default)]
struct StringVecDeque(VecDeque<String>);

impl StringVecDeque {
    fn with_capacity(capacity: usize) -> Self {
        Self(VecDeque::with_capacity(capacity))
    }

    fn contains_any<S: PartialEq<String>>(&self, items: &[S]) -> bool {
        self.0.iter().any(|a| items.iter().any(|b| b.eq(a)))
    }

    #[cfg(test)]
    fn iter(&self) -> Iter<'_, String> {
        self.0.iter()
    }

    fn push_back<S: Into<String>>(&mut self, s: S) {
        self.0.push_back(s.into());
    }

    fn push_front<S: Into<String>>(&mut self, s: S) {
        self.0.push_front(s.into());
    }
}

impl From<Vec<&str>> for StringVecDeque {
    fn from(src: Vec<&str>) -> Self {
        let mut dst = Self::with_capacity(src.len());
        for s in src {
            dst.push_back(s);
        }
        dst
    }
}

impl From<Vec<String>> for StringVecDeque {
    fn from(vec: Vec<String>) -> Self {
        Self(VecDeque::from(vec))
    }
}

impl From<StringVecDeque> for Vec<String> {
    fn from(val: StringVecDeque) -> Self {
        Vec::from(val.0)
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

/// Pushes an image with the given `tag` to the registry.
///
/// # Errors
///
/// Returns an error if the push was not successful.
async fn push_image(container_engine: &ContainerEngine, tag: &OsStr) -> anyhow::Result<()> {
    let mut cmd = Command::new(container_engine);
    cmd.arg("push")
        .arg(tag)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    info!("Pushing image with command: {cmd:?}");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => info!("{line}"),
                Ok(None) => break,
                Err(e) => error!("Failed to read stdout: {e}"),
            }
        }
    });
    tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => error!("{line}"),
                Ok(None) => break,
                Err(e) => error!("Failed to read stderr: {e}"),
            }
        }
    });
    let status = child.wait().await?;
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
async fn build_container_image(args: BuildContainerImageArgs) -> anyhow::Result<()> {
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
        stdin.write_all(DOCKERFILE).await?;
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => info!("{line}"),
                Ok(None) => break,
                Err(e) => error!("Failed to read stdout: {e}"),
            }
        }
    });
    tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                // Use `info!` even for stderr. The most of stderr messages are
                // progress-related logs from emerge, logging them with `error!`
                // would be confusing.
                Ok(Some(line)) => info!("{line}"),
                Ok(None) => break,
                Err(e) => error!("Failed to read stderr: {e}"),
            }
        }
    });
    let status = child.wait().await?;
    if !status.success() {
        return Err(anyhow!("failed to build container image: {status}"));
    }

    let mut errors = Vec::new();
    if push {
        for tag in &tags {
            if let Err(e) = push_image(container_engine, tag)
                .await
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
    pub cmd: Vec<String>,
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
fn prepare_env(triple: &Triple) -> Vec<String> {
    let mut env: Vec<String> = env::vars()
        .filter_map(|(key, value)| {
            if matches!(key.as_str(), "HOME" | "OLDPWD" | "PATH" | "PWD" | "USER") {
                None
            } else {
                Some(format!("{key}={value}"))
            }
        })
        .collect();
    env.extend_from_slice(&[
        format!("CARGO_BUILD_TARGET={triple}"),
        format!("CC={triple}-clang"),
        format!("CXX={triple}-clang++"),
        format!("CXXFLAGS={} --stdlib=libc++", env::var("CXXFLAGS").unwrap_or_default()),
        format!("LDFLAGS={} -fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind", env::var("LDFLAGS").unwrap_or_default()),
        format!("PATH=/root/.cargo/bin:/usr/lib/llvm/{LLVM_VERSION}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        format!("PKG_CONFIG_SYSROOT_DIR=/usr/{triple}"),
        "RUSTUP_HOME=/root/.rustup".to_owned(),
        format!(
            "RUSTFLAGS={} -C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}",
            env::var("RUSTFLAGS").unwrap_or_default()
        ),
    ]);
    let Triple { architecture, .. } = triple;
    if architecture != &target_lexicon::HOST.architecture {
        let triple = triple.to_string().to_uppercase().replace('-', "_");
        env.push(format!("CARGO_TARGET_{triple}_RUNNER=qemu-{architecture}"));
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

/// Pulls the given `container_image` from an OCI registry and unpacks it into
/// the given `rootfs_dir`.
///
/// The `{state_dir}/digest` file is used for storing the digest of the
/// downloaded image. The image pull is skipped if the digest stored there is
/// already up-to-date. Otherwise, it's updated after the successfull image
/// pull.
async fn pull_image(
    rng: &mut StdRng,
    state_dir: &Path,
    rootfs_dir: &PathBuf,
    container_image: &str,
) -> anyhow::Result<()> {
    let config = OciClientConfig {
        protocol: OciClientProtocol::Https,
        ..Default::default()
    };
    let client = OciClient::new(config);
    let reference: Reference = container_image.parse()?;

    let layers_dir = rand_string(rng, 6);
    let layers_dir = Path::new("/tmp").join(layers_dir);

    fs::create_dir_all(&layers_dir).await?;

    let (manifest, digest) = client
        .pull_image_manifest(&reference, &OciRegistryAuth::Anonymous)
        .await?;

    // Check if we have an up-to-date image fetched locally.
    let digest_file = state_dir.join("digest");
    if digest_file.exists() {
        let local_digest = read_to_string(&digest_file).await?;
        if local_digest == digest {
            debug!(
                "Image already up-to-date (local digest: {local_digest}, latest digest: {digest})"
            );
            return Ok(());
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
            let mut layer_file = File::create(layer_file).await.unwrap();

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
        fs::remove_dir_all(&rootfs_dir).await?;
    }
    fs::create_dir_all(&rootfs_dir).await?;

    info!("📦 Unpacking image");
    // NOTE(vadorovsky): There are multiple `tokio-tar` crates... and none of
    // them is working properly:
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
    let mut unpack_tasks = JoinSet::new();
    for layer_file in layer_files {
        unpack_tasks.spawn_blocking({
            let rootfs_dir = rootfs_dir.clone();
            move || {
                let layer_file = std::fs::File::open(layer_file).unwrap();
                let reader = std::io::BufReader::new(layer_file);
                let stream = flate2::bufread::GzDecoder::new(reader);
                let mut archive = tar::Archive::new(stream);
                archive.unpack(&rootfs_dir).unwrap();
            }
        });
    }
    unpack_tasks.join_all().await;

    fs::remove_dir_all(&layers_dir).await?;

    let mut digest_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&digest_file)
        .await?;
    digest_file.write_all(digest.as_bytes()).await?;

    Ok(())
}

/// Returns an OCI-compliant mount declaration of a bind mount from `src` to `dst`.
fn bind_mount(src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> anyhow::Result<Mount> {
    let mount = MountBuilder::default()
        .destination(dst)
        .typ("bind")
        .source(src)
        .options(["bind".into()])
        .build()?;
    Ok(mount)
}

/// Returns mounts for the container - predefined defaults and the bind mounts
/// based on user-provided `volumes`.
fn mounts(volumes: Vec<String>) -> anyhow::Result<Vec<Mount>> {
    let mut mounts = get_rootless_mounts();
    // Mount the current directory.
    let src_mount = bind_mount(env::current_dir()?, "/src")?;
    mounts.push(src_mount);
    // Mount `/etc/resolv.conf`, otherwise the container might not be able to
    // resolve domains.
    let resolv_mount = bind_mount("/etc/resolv.conf", "/etc/resolv.conf")?;
    mounts.push(resolv_mount);
    // Mount all the user-provided volumes.
    for volume in volumes {
        let parts: Vec<&str> = volume.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("invalid volume format: {volume}"));
        }
        let (src, dst) = (parts[0], parts[2]);
        mounts.push(bind_mount(src, dst)?);
    }
    Ok(mounts)
}

/// Returns a spec of a container.
fn container_spec(
    interactive: bool,
    rootfs_dir: &Path,
    triple: &Triple,
    volumes: Vec<String>,
    cmd_args: impl Into<Vec<String>>,
) -> anyhow::Result<Spec> {
    let uid = Uid::current().as_raw();
    let gid = Gid::current().as_raw();
    let linux_spec = Linux::rootless(uid, gid);
    let root = RootBuilder::default()
        .readonly(false)
        .path(rootfs_dir)
        .build()?;
    let env = prepare_env(triple);
    let process = ProcessBuilder::default()
        .terminal(interactive)
        .args(cmd_args)
        .env(env)
        .cwd("/src")
        .build()?;
    let spec = SpecBuilder::default()
        .root(root)
        .mounts(mounts(volumes)?)
        .process(process)
        .linux(linux_spec)
        .build()?;
    Ok(spec)
}

/// Runs a container, based on a `bundle_dir` with an OCI-compliant spec and
/// `rootfs`.
async fn run_container(
    rng: &mut StdRng,
    bundle_dir: PathBuf,
    rootfs_dir: PathBuf,
) -> anyhow::Result<()> {
    let container_id = rand_string(rng, 5);
    let container_id = format!("icdrgn-{container_id}");
    let container_task = tokio::task::spawn_blocking({
        move || {
            let mut container = ContainerBuilder::new(container_id, SyscallType::Linux)
                .with_executor(DefaultExecutor {})
                .with_root_path(&rootfs_dir)
                .unwrap()
                .validate_id()
                .unwrap()
                .as_init(&bundle_dir)
                .with_systemd(false)
                .build()
                .unwrap();

            container.start().unwrap();
            waitpid(container.pid().expect("container should have a pid"), None).unwrap();
            container.delete(true).unwrap();
        }
    });
    container_task.await?;
    Ok(())
}

/// Runs a command inside a container.
///
/// It does so in the following steps:
///
/// * Creating an unique, temporary bundle directory.
/// * Generating a container spec.
/// * Saving the container spec in the bundle directory.
/// * Running the container based on the bundle directory.
///
/// Unfortunately, libcontainer's public API allows only runing containers
/// based on bundle directories. Passing a spec as a struct is not
/// possible.
async fn run_command(
    interactive: bool,
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    cmd_args: impl Into<Vec<String>>,
) -> anyhow::Result<()> {
    let mut rng = StdRng::from_os_rng();

    let bundle_dir = rand_string(&mut rng, 6);
    let bundle_dir = Path::new("/tmp").join(bundle_dir);
    if !bundle_dir.exists() {
        fs::create_dir_all(&bundle_dir).await?;
    }

    let rootfs_dir = state_dir.join("rootfs");
    pull_image(&mut rng, state_dir, &rootfs_dir, container_image).await?;
    let spec_file = bundle_dir.join("config.json");
    let spec = container_spec(interactive, &rootfs_dir, triple, volumes, cmd_args)?;
    spec.save(&spec_file)?;

    run_container(&mut rng, bundle_dir.clone(), rootfs_dir).await?;

    fs::remove_dir_all(&bundle_dir).await?;

    Ok(())
}

/// Runs cargo inside a container.
async fn cargo(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: StringVecDeque,
) -> anyhow::Result<()> {
    // The command is `cargo` followed by arguments provided by the caller.
    cmd.push_front("cargo");

    run_command(false, state_dir, triple, container_image, volumes, cmd).await
}

/// Runs clang inside a container.
async fn clang(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: StringVecDeque,
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

    run_command(false, state_dir, triple, container_image, volumes, cmd).await
}

/// Runs `CMake` inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
async fn cmake(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    mut cmd: StringVecDeque,
) -> anyhow::Result<()> {
    // Determine whether we are configuring a CMake project.
    //
    // Usage of any of the following arguments means performing an action other
    // than configuring the project.
    // This would've been easier to determine if CMake actions were treated as
    // subcommands instead of regular arguments with no enforced order...
    let configure = !cmd.contains_any(&["--build", "--help", "--install", "--open"]);

    // The command is `cmake` followed by arguments provided by the caller...
    cmd.push_front("cmake".to_owned());

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

    run_command(false, state_dir, triple, container_image, volumes, cmd).await
}

/// Run a command inside a container.
async fn run(
    state_dir: &Path,
    triple: &Triple,
    container_image: &str,
    volumes: Vec<String>,
    cmd: Vec<String>,
) -> anyhow::Result<()> {
    run_command(true, state_dir, triple, container_image, volumes, cmd).await
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Cli {
        command,
        state_dir,
        target,
    } = cli;

    let state_dir = expand_tilde(state_dir)?;
    fs::create_dir_all(&state_dir).await?;
    let triple = parse_target(target.as_deref())?;

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    match command {
        Commands::BuildContainerImage(args) => build_container_image(args).await,
        Commands::Cargo(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cargo(&state_dir, &triple, &container_image, volumes, cmd.into()).await
        }
        Commands::Clang(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            clang(&state_dir, &triple, &container_image, volumes, cmd.into()).await
        }
        Commands::Cmake(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cmake(&state_dir, &triple, &container_image, volumes, cmd.into()).await
        }
        Commands::Run(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            run(&state_dir, &triple, &container_image, volumes, cmd).await
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vec_deque_conv() {
        let vec = vec!["foo".to_owned(), "bar".to_owned(), "baz".to_owned()];
        let vec_deq: StringVecDeque = vec.into();

        for (a, b) in vec_deq.iter().zip(&["foo", "bar", "baz"]) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_vec_deque_push() {
        let mut vec_deq = StringVecDeque::default();

        vec_deq.push_back("ayy");
        vec_deq.push_back("lmao");

        vec_deq.push_front("bar");
        vec_deq.push_front("foo");

        for (a, b) in vec_deq.iter().zip(&["foo", "bar", "ayy", "lmao"]) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_vec_deque_contains_any() {
        let cmake_action_args = &["--build", "--help", "--install", "--open"];

        let args: StringVecDeque = vec!["cmake", "--build"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: StringVecDeque = vec!["cmake", "--help"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: StringVecDeque = vec!["cmake", "--install"].into();
        assert!(args.contains_any(cmake_action_args));
        let args: StringVecDeque = vec!["cmake", "--open", "myproject"].into();
        assert!(args.contains_any(cmake_action_args));

        let args: StringVecDeque = vec![
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
}
