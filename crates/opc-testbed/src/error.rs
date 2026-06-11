//! Crate error types for opc-testbed (scenario parse, validation, fixture, time, etc.).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TestbedError {
    #[error("scenario parse error: {0}")]
    ScenarioParse(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("fixture provenance error: {0}")]
    Fixture(String),

    #[error("virtual time error: {0}")]
    VirtualTime(String),

    #[error("assertion error: {0}")]
    Assertion(String),

    #[error("simulator error: {0}")]
    Simulator(String),

    #[error("evidence emission error: {0}")]
    Evidence(String),
}
