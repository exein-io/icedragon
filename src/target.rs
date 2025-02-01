use std::ffi::{OsStr, OsString};

use target_lexicon::{Architecture, Environment, OperatingSystem, Triple};

use crate::errors::IcedragonError;

const DOCKERFILE_X86_64: &[u8] =
    include_bytes!("../containers/Dockerfile.native-x86_64-unknown-linux-musl");
const DOCKERFILE_CROSS_AARCH64: &[u8] =
    include_bytes!("../containers/Dockerfile.cross-aarch64-unknown-linux-musl");

pub trait TripleExt {
    fn default_container_image_name(&self, container_tag: &OsStr) -> OsString;
    fn dockerfile(&self) -> Result<&'static [u8], IcedragonError>;
    fn is_cross(&self) -> bool;
}

impl TripleExt for Triple {
    fn default_container_image_name(&self, container_tag: &OsStr) -> OsString {
        let mut image_name = OsString::from("ghcr.io/exein-io/icedragon/");
        let prefix = if self.is_cross() { "cross" } else { "native" };
        image_name.push(prefix);
        image_name.push("-");
        image_name.push(self.to_string());
        image_name.push(":");
        image_name.push(container_tag);

        image_name
    }

    fn dockerfile(&self) -> Result<&'static [u8], IcedragonError> {
        let Triple {
            architecture,
            operating_system,
            environment,
            ..
        } = self;

        if self.is_cross() {
            match (architecture, operating_system, environment) {
                (Architecture::Aarch64(_), OperatingSystem::Linux, Environment::Musl) => {
                    Ok(DOCKERFILE_CROSS_AARCH64)
                }
                _ => Err(IcedragonError::UnsupportedTarget(self.to_owned())),
            }
        } else {
            match (architecture, operating_system, environment) {
                (Architecture::X86_64, OperatingSystem::Linux, Environment::Musl) => {
                    Ok(DOCKERFILE_X86_64)
                }
                _ => Err(IcedragonError::UnsupportedTarget(self.to_owned())),
            }
        }
    }

    fn is_cross(&self) -> bool {
        self.architecture != target_lexicon::HOST.architecture
    }
}
