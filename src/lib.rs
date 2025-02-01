use target_lexicon::{ParseError, Triple};
use thiserror::Error;

pub mod cli;
pub mod containers;
pub mod run;
pub mod target;

#[derive(Debug, Error)]
pub enum IcedragonError {
    #[error("no supported container engine was found")]
    ContainerEngineNotFound,
    #[error("failed to parse the target {0}: {1}")]
    ParseTarget(String, ParseError),
    #[error("target {0} is not supported")]
    UnsupportedTarget(Triple),
    #[error("failed to build a container image")]
    ContainerImageBuild,
    #[error("failed to push a container image")]
    ContainerImagePush,
}
