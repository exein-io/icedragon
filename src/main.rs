use std::{
    borrow::Cow,
    collections::{vec_deque::Iter, VecDeque},
    env,
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs,
    io::{BufRead as _, BufReader, Write as _},
    os::unix::{ffi::OsStrExt as _, process::ExitStatusExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    str::FromStr,
    sync::mpsc,
    thread,
};

use anyhow::{anyhow, Context as _};
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
    manifest::OciDescriptor,
    secrets::RegistryAuth as OciRegistryAuth,
    Client as OciClient, Reference,
};
use rand::{distr::Alphanumeric, rngs::StdRng, Rng as _, SeedableRng as _};
use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};
use tokio::io::AsyncWriteExt as _;
use tokio_stream::StreamExt as _;
use which::which;

/// Template string for the download progress bar.
const PROGRESS_BAR_TEMPLATE: &str = "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";
/// Progress characters (filled, current, to do) for the download progress bar.
const PROGRESS_BAR_CHARS: &str = "#>-";

/// A wrapper over [`VecDeque`] making it easy to gather platform-native
/// strings.
#[derive(Debug, Default)]
struct OsVecDeque(VecDeque<OsString>);

impl OsVecDeque {
    fn command(&self) -> anyhow::Result<Command> {
        let mut iter = self.iter();
        let cmd = iter
            .next()
            .ok_or(anyhow!("cannot create a command, vector is empty"))?;
        let mut cmd = Command::new(cmd);
        cmd.args(iter);
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
    state_dir: PathBuf,

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
    /// Container engine (if not provided, will be autodetected).
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

/// Parse a single key-value pair CLI argument, using `:` as a delimiter.
fn parse_key_val<T, U>(
    s: &str,
) -> Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let mut components = s.split(':');
    let key = components.next().ok_or_else(|| {
        anyhow!("failed to retrieve the key in the `[key]:[value]` format from {s}")
    })?;
    let key = key
        .parse()
        .with_context(|| format!("failed to parse the key `{key}`"))?;
    let value = components.next().ok_or(anyhow!(
        "failed to retrieve the value in the `[key]:[value]` format from {s}"
    ))?;
    let value = value
        .parse()
        .with_context(|| format!("failed to parse the value `{value}`"))?;
    if components.next().is_some() {
        return Err(anyhow!(
            "expected only two values separated by `:` in format `[key]:[value]`, got `{s}`"
        )
        .into());
    }
    Ok((key, value))
}

#[derive(Parser)]
struct RunArgs {
    /// Container image to use.
    #[arg(long, default_value = "ghcr.io/exein-io/icedragon:latest")]
    pub container_image: String,

    /// Additional volumes to mount to the container.
    #[arg(long = "volume", value_parser = parse_key_val::<PathBuf, PathBuf>)]
    pub volumes: Vec<(PathBuf, PathBuf)>,

    /// The command to run inside the container.
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<OsString>,
}

/// Parameters used to launch a container.
struct ContainerContext {
    /// Indicates whether stdin should be piped to the container.
    interactive: bool,
    /// Path to the main directory with icedragon's state.
    state_dir: PathBuf,
    /// Path to the container root filesystem.
    rootfs_dir: PathBuf,
    /// Target triple.
    triple: Triple,
    /// Indicates whether `CC` and `CXX` variables should be set.
    ///
    /// Such override is convenient for the most of Rust projects, where
    /// `build.rs` calls the C/C++ compiler either through the [`cc`] or
    /// directly.
    ///
    /// However, build systems like `CMake` or Meson often use the C/C++
    /// compiler for building native binaries, which are needed for performing
    /// the rest of the build, even during cross builds. In that case, setting
    /// these variables would break the native build. Furthermore, these build
    /// system are smart enough to pick the cross compiler for building cross
    /// artifacts.
    override_cc_with_cross: bool,
    /// List of user-provided volumes to bind mount to the container.
    volumes: Vec<(PathBuf, PathBuf)>,
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
        state_dir: PathBuf,
        triple: Triple,
        override_cc_with_cross: bool,
        volumes: Vec<(PathBuf, PathBuf)>,
        cmd: OsVecDeque,
    ) -> Self {
        let rootfs_dir = state_dir.join("rootfs");
        Self {
            interactive,
            state_dir,
            rootfs_dir,
            triple,
            override_cc_with_cross,
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

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command {cmd:?}"))?;
    info!("Pushing image with command: {cmd:?}");
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("expected piped stdout in command {cmd:?}"));
    let stderr = child
        .stderr
        .take()
        .unwrap_or_else(|| panic!("expected piped stderr in command {cmd:?}"));
    thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap_or_else(|e| {
                    panic!("failed to retrieve stdout line from command {cmd:?}: {e:?}")
                });
                info!("{line}");
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap_or_else(|e| {
                    panic!("failed to retrieve stderr line from command {cmd:?}: {e:?}")
                });
                error!("{line}");
            }
        });
    });
    let status = child
        .wait()
        .with_context(|| format!("failed to wait for command {cmd:?}"))?;
    if !status.success() {
        return Err(anyhow!(
            "failed to push a container image {status} with command {cmd:?}: {status}"
        ));
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
    /// Content of the dockerfile.
    const DOCKERFILE: &[u8] = include_bytes!("../containers/Dockerfile");

    let BuildContainerImageArgs {
        container_engine,
        no_cache,
        push,
        tags,
    } = args;

    let container_engine = match container_engine {
        Some(container_engine) => container_engine,
        None => ContainerEngine::autodetect()?,
    };

    let mut cmd = Command::new(&container_engine);
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

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command {cmd:?}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("expected piped stdin in command {cmd:?}"));
        stdin.write_all(DOCKERFILE).with_context(|| {
            format!("failed to write the dockerfile content to stdin of command {cmd:?}")
        })?;
    }
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("expected piped stdout in command {cmd:?}"));
    let stderr = child
        .stderr
        .take()
        .unwrap_or_else(|| panic!("expected piped stderr in command {cmd:?}"));
    thread::scope(|s| {
        s.spawn(|| {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap_or_else(|e| {
                    panic!("failed to retrieve stdout line from command {cmd:?}: {e:?}")
                });
                info!("{line}");
            }
        });
        s.spawn(|| {
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap_or_else(|e| {
                    panic!("failed to retrieve stderr line from command {cmd:?}: {e:?}");
                });
                // Use `info!` even for stderr. The most of stderr messages are
                // progress-related logs from emerge, logging them with `error!`
                // would be confusing.
                info!("{line}");
            }
        });
    });
    let status = child
        .wait()
        .with_context(|| format!("failed to wait for command {cmd:?}"))?;
    if !status.success() {
        return Err(anyhow!(
            "failed to build container image with command {cmd:?}: {status}"
        ));
    }

    let mut errors = Vec::new();
    if push {
        for tag in &tags {
            if let Err(e) = push_image(&container_engine, tag)
                .with_context(|| format!("failed to push the tag {tag:?}"))
            {
                errors.push(e);
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("failed to push images: {errors:?}"))
    }
}

/// Returns environment variables to use in containerized processes, to ensure
/// successful cross-compilation for the given target `triple`.
///
/// The `override_cc_with_cross` parameter indicates whether `CC` and `CXX`
/// should point to the clang cross wrappers. This override is useful in simple
/// C/C++ builds where the build system isn't aware of cross-compilation, which
/// can occur with a straightforward usage of autotools or make. However, for
/// more complex build systems such as `CMake` or Meson, which differentiate
/// between native and cross builds, it's better to let them set the compiler
/// target.
fn prepare_env(
    triple: &Triple,
    override_cc_with_cross: bool,
) -> impl Iterator<Item = (Cow<'static, OsStr>, Cow<'static, OsStr>)> {
    /// LLVM version installed in the image.
    const LLVM_VERSION: u32 = 19;

    // Pass the current environment variables, except the ones like `HOME`,
    // `PATH` etc., which would break the containerized environment. We also
    // filter out variables prefixed by `CARGO` and `RUSTUP` to make sure that
    // the Rust toolchain inside the container is isolated, especially when
    // icedragon is launched with `cargo run`. Variables prefixed by `SSL` are
    // filtered to make sure that ca-certificates from the container are used.
    let env = env::vars_os().filter_map(|(key, value)| {
        if key == "HOME"
            || key == "OLDPWD"
            || key == "PATH"
            || key == "PWD"
            || key == "USER"
            || key.as_bytes().starts_with("CARGO".as_bytes())
            || key.as_bytes().starts_with("RUSTUP".as_bytes())
            || key.as_bytes().starts_with("SSL".as_bytes())
        {
            None
        } else {
            Some((key.into(), value.into()))
        }
    });

    // Use all LLVM components, including the linker, standard C++ library and runtime libraries.
    // Without being explicit about that, clang might still try to use the GNU equivalents.
    let mut cxxflags = env::var_os("CXXFLAGS").unwrap_or_default();
    cxxflags.push(" --stdlib=libc++");
    let mut ldflags = env::var_os("LDFLAGS").unwrap_or_default();
    ldflags.push(" -fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind");
    let mut rustflags = env::var_os("RUSTFLAGS").unwrap_or_default();
    rustflags.push(" ");
    write!(
        &mut rustflags,
        "-C linker={triple}-clang -C link-arg=--sysroot=/usr/{triple}"
    )
    .unwrap();

    let env = env.chain([
        // Tell cargo what target to build for.
        ("CARGO_BUILD_TARGET", OsString::from(format!("{triple}")).into()),
        ("CXXFLAGS", cxxflags.into()),
        ("LDFLAGS", ldflags.into()),
        // Include the directories of the LLVM and Rust toolchains in `PATH`.
        ("PATH", OsString::from(format!("/root/.cargo/bin:/usr/lib/llvm/{LLVM_VERSION}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")).into()),
        // Point `pkg-config` to the cross sysroot.
        ("PKG_CONFIG_SYSROOT_DIR", OsString::from(format!("/usr/{triple}")).into()),
        // Point to the directory with Rust toolchains.
        ("RUSTUP_HOME", OsStr::new("/root/.rustup").into()),
        // Tell Rust to use the cross sysroot and to use a clang wrapper as its
        // linker.
        ("RUSTFLAGS", rustflags.into()),
    ].into_iter().map(|(key, value)| {
        (OsStr::new(key).into(), value)
    }));
    let env = if override_cc_with_cross {
        either::Left(
            env.chain(
                [
                    ("CC", format!("{triple}-clang")),
                    ("CXX", format!("{triple}-clang++")),
                ]
                .map(|(key, value)| (OsStr::new(key).into(), OsString::from(value).into())),
            ),
        )
    } else {
        either::Right(env)
    };
    let Triple { architecture, .. } = triple;
    if architecture != &target_lexicon::HOST.architecture {
        let mut cargo_target_triple_runner = format!("CARGO_TARGET_{triple}_RUNNER");
        cargo_target_triple_runner.make_ascii_uppercase();
        // SAFETY: we promise not to put invalid UTF-8 in the string.
        for c in unsafe { cargo_target_triple_runner.as_bytes_mut() } {
            if *c == b'-' {
                *c = b'_';
            }
        }
        either::Left(env.chain(std::iter::once((
            OsString::from(cargo_target_triple_runner).into(),
            OsString::from(format!("qemu-{architecture}")).into(),
        ))))
    } else {
        either::Right(env)
    }
}

async fn download_layer(
    client: &OciClient,
    mpb: &MultiProgress,
    reference: &Reference,
    layer: &OciDescriptor,
    layer_filename: &PathBuf,
) -> anyhow::Result<()> {
    let layer_file = tokio::fs::File::create(&layer_filename)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to open layer file: {}: {e:?}",
                layer_filename.display()
            )
        });
    let mut layer_file = tokio::io::BufWriter::new(layer_file);

    let mut stream = client
        .pull_blob_stream(reference, &layer)
        .await
        .with_context(|| format!("failed to stream the OCI layer of {reference}"))?;

    // Why is `oci-spec` storing layer size as `i64`? No idea. ¯\_(ツ)_/¯
    let content_length = match stream.content_length {
        Some(content_length) => content_length,
        None => u64::try_from(layer.size)
            .with_context(|| format!("invalid layer size: {}", layer.size))?,
    };

    let pb = mpb.add(ProgressBar::new(content_length));
    let pb_style =
        ProgressStyle::with_template(PROGRESS_BAR_TEMPLATE)?.progress_chars(PROGRESS_BAR_CHARS);
    pb.set_style(pb_style);
    while let Some(res) = stream.next().await {
        let chunk = res.with_context(|| {
            format!("failed to read the stream of the OCI layer of {reference}")
        })?;
        layer_file.write_all(&chunk).await.with_context(|| {
            format!(
                "failed to write the chunk of the OCI image {reference} into {}",
                layer_filename.display()
            )
        })?;
        let chunk_len = chunk.len();
        let chunk_len = u64::try_from(chunk_len)
            .with_context(|| format!("invalid chunk length: {chunk_len}"))?;
        pb.inc(chunk_len);
    }
    layer_file.flush().await.with_context(|| {
        format!(
            "failed to flush the layer file {}",
            layer_filename.display()
        )
    })?;
    pb.finish_and_clear();

    Ok(())
}

/// Pulls the given `container_image` from the OCI registry.
async fn pull_image(
    download_dir: &Path,
    digest_file: &PathBuf,
    container_image: &str,
) -> anyhow::Result<Option<(String, Vec<PathBuf>)>> {
    let config = OciClientConfig {
        protocol: OciClientProtocol::Https,
        ..Default::default()
    };
    let client = OciClient::new(config);
    let reference: Reference = container_image
        .parse()
        .with_context(|| format!("failed to parse container image URI {container_image}"))?;

    let (manifest, digest) = client
        .pull_image_manifest(&reference, &OciRegistryAuth::Anonymous)
        .await
        .with_context(|| {
            format!("failed to pull the manifest of container image {container_image}")
        })?;

    // Check if we have an up-to-date image fetched locally.
    if digest_file.exists() {
        let local_digest = tokio::fs::read_to_string(&digest_file)
            .await
            .with_context(|| {
                format!(
                    "failed to read the local digest file {}",
                    digest_file.display()
                )
            })?;
        if local_digest == digest {
            debug!(
                "Image already up-to-date (local digest: {local_digest}, latest digest: {digest})"
            );
            return Ok(None);
        }
    }

    info!("📥 Pulling image");
    let layer_files: Vec<_> = manifest
        .layers
        .iter()
        .map(|layer| download_dir.join(&layer.digest))
        .collect();
    let mpb = MultiProgress::new();
    let download_layer_futures = manifest
        .layers
        .iter()
        .zip(layer_files.iter())
        .map(|(layer, layer_file)| download_layer(&client, &mpb, &reference, layer, layer_file));
    futures::future::try_join_all(download_layer_futures).await?;

    Ok(Some((digest, layer_files)))
}

/// Removes and creates the `rootfs_dir`.
fn create_rootfs(rootfs_dir: &Path) -> anyhow::Result<()> {
    if rootfs_dir.exists() {
        fs::remove_dir_all(rootfs_dir).with_context(|| {
            format!("failed to remove rootfs directory {}", rootfs_dir.display())
        })?;
    }
    fs::create_dir_all(rootfs_dir)
        .with_context(|| format!("failed to create rootfs directory {}", rootfs_dir.display()))
}

/// Unpacks `tarball` in `.tar.gz` format into `dest`.
fn unpack_tarball<T, D>(tarball_path: T, dest_path: D) -> anyhow::Result<()>
where
    T: AsRef<Path>,
    D: AsRef<Path>,
{
    let tarball_path = tarball_path.as_ref();
    let dest_path = dest_path.as_ref();
    let tarball = std::fs::File::open(tarball_path)
        .with_context(|| format!("failed to open the tarball {}", tarball_path.display()))?;
    let reader = std::io::BufReader::new(&tarball);
    let stream = flate2::bufread::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(stream);
    archive.unpack(dest_path).with_context(|| {
        format!(
            "failed to unpack tarball {} into {}",
            tarball_path.display(),
            dest_path.display()
        )
    })
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
    let (tx, rx) = mpsc::channel();
    thread::scope(move |s| {
        for layer_file in layer_files {
            let tx = tx.clone();
            s.spawn(move || {
                let res = unpack_tarball(&layer_file, &ctx.rootfs_dir);
                tx.send(res).unwrap_or_else(|e| {
                    panic!("failed to send the result of the unpacking thread: {e:?}")
                });
            });
        }
    });
    for result in &rx {
        result?;
    }

    fs::remove_dir_all(download_dir).with_context(|| {
        format!(
            "failed to remove download directory {}",
            download_dir.display()
        )
    })
}

/// Prepares a rootfs for the container based on provided `container_image`.
///
/// The `{state_dir}/digest` file is used for storing the digest of the
/// downloaded image. The image pull is skipped if the digest stored there is
/// already up-to-date. Otherwise, it's updated after the successfull image
/// pull.
fn prepare_container(ctx: &ContainerContext, container_image: &str) -> anyhow::Result<()> {
    let rng = StdRng::from_os_rng();
    let download_dir: String = rng
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    let download_dir = Path::new("/tmp").join(download_dir);
    fs::create_dir_all(&download_dir).with_context(|| {
        format!(
            "failed to create download directory {}",
            download_dir.display()
        )
    })?;

    let digest_file = ctx.state_dir.join("digest");

    if let Some((digest, layer_files)) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the tokio runtime for pulling the container image")?
        .block_on(pull_image(&download_dir, &digest_file, container_image))?
    {
        create_rootfs(&ctx.rootfs_dir)?;
        unpack_image(ctx, &download_dir, layer_files)?;
        fs::write(&digest_file, &digest).with_context(|| {
            format!(
                "failed to write to the local digest file {}",
                digest_file.display()
            )
        })?;
    }
    Ok(())
}

/// Writes an ID mapping from the given `host_id` (representing a host user) to
/// `0` (representing `root` inside container) to the given `map_file`.
fn write_mapping(map_file: &Path, host_id: u32) -> anyhow::Result<()> {
    debug!("Writing mapping to {}", map_file.display());
    let mapping = format!("0 {host_id} 1");
    std::fs::write(map_file, mapping).with_context(|| {
        format!(
            "failed to write the ID mapping to file {}",
            map_file.display()
        )
    })
}

/// Writes UID and UID mappings from the host user to `0` (representing `root`
/// inside container) for the given `pid`.
fn write_mappings(pid: Pid) -> anyhow::Result<()> {
    let proc_self = Path::new("/proc").join(pid.as_raw().to_string());
    let setgroups_file = proc_self.join("setgroups");
    std::fs::write(&setgroups_file, "deny").with_context(|| {
        format!(
            "failed to disable the use of `setgroups` syscall by writing to file {}",
            setgroups_file.display()
        )
    })?;
    write_mapping(&proc_self.join("uid_map"), Uid::current().as_raw())
        .context("failed to write UID mapping")?;
    write_mapping(&proc_self.join("gid_map"), Gid::current().as_raw())
        .context("failed to write GID mapping")?;
    Ok(())
}

/// Mounts `procfs` inside `rootfs_dir`.
fn proc_mount(rootfs_dir: &Path) -> anyhow::Result<()> {
    debug!("Mounting /proc");
    let dest = rootfs_dir.join("proc");
    mount(
        Some("proc"),
        &dest,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .with_context(|| format!("failed to mount proc filesystem into {}", dest.display()))
}

/// Mounts `tmpfs` to `/dev` inside `rootfs_dir` and then selectivly mounts
/// single devices that are essential for having a functional system. Some of
/// them can be new mounts (`mqueue`, `pts`). Some of them need to be bind
/// mounted from the host (`null`, `urandom` etc.).
fn dev_mount(rootfs_dir: &Path) -> anyhow::Result<()> {
    debug!("Mounting /dev");
    let dev_path = rootfs_dir.join("dev");
    mount(
        Some("tmpfs"),
        &dev_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )
    .with_context(|| format!("failed to mount tmpfs into {}", dev_path.display()))?;
    debug!("Mounting /dev/mqueue");
    let mqueue_path = rootfs_dir.join("dev/mqueue");
    fs::create_dir_all(&mqueue_path)?;
    mount(
        Some("mqueue"),
        &mqueue_path,
        Some("mqueue"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .with_context(|| format!("failed to mount mqueue into {}", mqueue_path.display()))?;
    debug!("Mounting /dev/pts");
    let pts_path = rootfs_dir.join("dev/pts");
    fs::create_dir_all(&pts_path)?;
    mount(
        Some("devpts"),
        &pts_path,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        // Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        None::<&str>,
    )
    .with_context(|| format!("failed to mount devpts into {}", pts_path.display()))?;
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
    bind_mount(rootfs_dir, "/dev/random", "/dev/random")
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
    if src.as_ref().is_dir() {
        // When source is a directory, the destination has to be a
        // directory as well.
        fs::create_dir_all(&full_dst).with_context(|| {
            format!(
                "failed to create destination directory for bind mount {}",
                full_dst.display()
            )
        })?;
    } else {
        // Otherwise, the destination has to be a regular file. It can be
        // empty.
        if let Some(parent) = full_dst.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directories {} for the bind mount destination file {}",
                    parent.display(),
                    full_dst.display()
                )
            })?;
        }
        fs::write(&full_dst, []).with_context(|| {
            format!(
                "failed to create the bind mount destination file {}",
                full_dst.display()
            )
        })?;
    }

    let src = src.as_ref();
    debug!("Mounting {} to {}", src.display(), full_dst.display());
    mount(
        Some(src),
        &full_dst,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "failed to bind mount {} into {}",
            src.display(),
            full_dst.display()
        )
    })
}

/// Resolves the home path of the current user.
fn home_dir() -> anyhow::Result<PathBuf> {
    // TODO: Remove this function and use `std::env::home_dir` once it's
    // un-deprecated in a stable Rust release.
    match env::var_os("HOME") {
        Some(home) => Ok(PathBuf::from(home)),
        None => Err(anyhow!("`HOME` environment variable is not set")),
    }
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
    bind_mount(&ctx.rootfs_dir, env::current_dir()?, "/src")
        .context("failed to mount the current directory")?;
    bind_mount(&ctx.rootfs_dir, "/etc/resolv.conf", "/etc/resolv.conf")?;
    // Mount the directory with SSH keys (`$HOME/.ssh`) to be able to access
    // private repositories.
    let home_dir = home_dir()?;
    let ssh_keys_dir = Path::new(&home_dir).join(".ssh");
    if ssh_keys_dir.exists() {
        bind_mount(&ctx.rootfs_dir, ssh_keys_dir, "/root/.ssh")?;
    }
    if let Some(ssh_auth_sock) = env::var_os("SSH_AUTH_SOCK") {
        bind_mount(&ctx.rootfs_dir, &ssh_auth_sock, &ssh_auth_sock)?;
    }
    // Mount all the user-provided volumes.
    for (src, dst) in &ctx.volumes {
        bind_mount(&ctx.rootfs_dir, src, dst)
            .context("failed to mount an user-provided directory")?;
    }
    Ok(())
}

fn container_child(ctx: &ContainerContext) -> anyhow::Result<u8> {
    mount_volumes(ctx)?;
    chroot(&ctx.rootfs_dir).context("`chroot` syscall failed")?;
    chdir("/src").context("failed to change directory to `/src`")?;

    let envs = prepare_env(&ctx.triple, ctx.override_cc_with_cross);

    let mut cmd = ctx.cmd.command()?;
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    if ctx.interactive {
        cmd.stdin(Stdio::inherit());
    }
    let status = cmd
        .env_clear()
        .envs(envs)
        .spawn()
        .with_context(|| format!("failed to run command {cmd:?}"))?
        .wait()
        .with_context(|| format!("failed to wait for command {cmd:?}"))?;
    let status = status.code().ok_or_else(|| {
        // In case child's exit code could not be retrieved, try to figure out
        // the reason and return an error.
        if let Some(signal) = status.signal() {
            anyhow!("command {cmd:?} was terminated by signal {signal}")
        } else if let Some(signal) = status.stopped_signal() {
            anyhow!("command {cmd:?} was stopped by signal {signal}")
        } else if status.continued() {
            anyhow!("failed to retrieve the status of continued command {cmd:?}")
        } else {
            anyhow!("failed to retrieve the status of command {cmd:?}")
        }
    })?;
    // We want to return the child's exit code in our main parent process. The
    // cleanest way to return an exit code in Rust is to return any type
    // implemementing `Termination` trait in the `main` function. The simpliest
    // type implementing it is `ExitCode`.
    // `ExitCode` implements only `From<u8>`. Correct exit codes in Unix-like
    // systems should fit into `u8`.
    // There is an unstable Windows API implementing `From<u32>`, but for now
    // we don't care about it.
    // We return `u8` instead of `ExitCode`, because it's easier to send it
    // through the IPC channel, We convert it later on the parent side.
    let status = u8::try_from(status).with_context(|| format!("invalid status code {status}"))?;

    Ok(status)
}

/// Runs a container, based on provided `cmd` and `rootfs_dir`.
fn run_container(ctx: ContainerContext) -> anyhow::Result<ExitCode> {
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

    child_rx
        .recv()
        .context("failed to receive the message about readiness of the child process")?;
    write_mappings(pid)?;
    id_map_tx.send(())?;

    let exit_code = res_rx
        .recv()?
        .context("containerized process failed with an error")?
        .into();

    Ok(exit_code)
}

/// Runs cargo inside a container.
fn cargo(
    state_dir: PathBuf,
    triple: Triple,
    container_image: &str,
    volumes: Vec<(PathBuf, PathBuf)>,
    mut cmd: OsVecDeque,
) -> anyhow::Result<ExitCode> {
    // The command is `cargo` followed by arguments provided by the caller.
    cmd.push_front("cargo");

    run(
        false,
        state_dir,
        triple,
        true,
        container_image,
        volumes,
        cmd,
    )
}

/// Runs clang inside a container.
fn clang(
    state_dir: PathBuf,
    triple: Triple,
    container_image: &str,
    volumes: Vec<(PathBuf, PathBuf)>,
    mut cmd: OsVecDeque,
) -> anyhow::Result<ExitCode> {
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

    run(
        false,
        state_dir,
        triple,
        true,
        container_image,
        volumes,
        cmd,
    )
}

/// Runs `CMake` inside a container. If the command involves configuring a
/// project, adds parameters necessary for cross-compilation for the given
/// target.
fn cmake(
    state_dir: PathBuf,
    triple: Triple,
    container_image: &str,
    volumes: Vec<(PathBuf, PathBuf)>,
    mut cmd: OsVecDeque,
) -> anyhow::Result<ExitCode> {
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

    run(
        false,
        state_dir,
        triple,
        false,
        container_image,
        volumes,
        cmd,
    )
}

/// Run a command inside a container.
fn run(
    interactive: bool,
    state_dir: PathBuf,
    triple: Triple,
    override_cc_with_cross: bool,
    container_image: &str,
    volumes: Vec<(PathBuf, PathBuf)>,
    cmd: OsVecDeque,
) -> anyhow::Result<ExitCode> {
    let ctx = ContainerContext::new(
        interactive,
        state_dir,
        triple,
        override_cc_with_cross,
        volumes,
        cmd,
    );
    prepare_container(&ctx, container_image)?;
    run_container(ctx)
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
fn expand_tilde(p: PathBuf) -> anyhow::Result<PathBuf> {
    let mut components = p.components();
    // Check whether the first path component is `~`.
    //
    // If yes, create a new path with user directory replacing the `~`.
    //
    // Otherwise, just return the original path.
    if matches!(components.next(), Some(Component::Normal(first)) if first == "~") {
        let mut home = home_dir()?;
        // Extend the home path with all the following components.
        home.extend(components);
        Ok(home)
    } else {
        Ok(p)
    }
}

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let Cli {
        command,
        state_dir,
        target,
    } = cli;

    let state_dir = expand_tilde(state_dir)?;
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("failed to create state directory {}", state_dir.display()))?;
    let triple = parse_target(target.as_deref())?;

    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    match command {
        Commands::BuildContainerImage(args) => {
            build_container_image(args)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Cargo(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cargo(state_dir, triple, &container_image, volumes, cmd.into())
        }
        Commands::Clang(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            clang(state_dir, triple, &container_image, volumes, cmd.into())
        }
        Commands::Cmake(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            cmake(state_dir, triple, &container_image, volumes, cmd.into())
        }
        Commands::Run(args) => {
            let RunArgs {
                container_image,
                volumes,
                cmd,
            } = args;
            run(
                true,
                state_dir,
                triple,
                false,
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
        assert_eq!(
            expand_tilde("~".into()).unwrap(),
            PathBuf::from("/home/test")
        );
        assert_eq!(
            expand_tilde("~/foo".into()).unwrap(),
            PathBuf::from("/home/test/foo")
        );
        assert_eq!(
            expand_tilde("~/foo/bar".into()).unwrap(),
            PathBuf::from("/home/test/foo/bar")
        );
    }
}
