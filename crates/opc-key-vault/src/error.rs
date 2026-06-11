use thiserror::Error;

/// Errors specific to Vault operations.
///
/// All variants are redacted and contain no secret material.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VaultError {
    #[error("vault authentication failed")]
    AuthFailed,
    #[error("invalid vault URL")]
    InvalidUrl,
    #[error("vault request failed")]
    RequestFailed,
    #[error("vault response malformed")]
    MalformedResponse,
}

impl From<reqwest::Error> for VaultError {
    fn from(_: reqwest::Error) -> Self {
        Self::RequestFailed
    }
}
