use thiserror::Error;

/// Error type for session store operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    #[error("record not found")]
    NotFound,
    #[error("stale fence: current fence is higher")]
    StaleFence,
    #[error("compare-and-set conflict")]
    CasConflict,
    #[error("capability not supported: {0}")]
    CapabilityNotSupported(String),
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("lease held by another owner")]
    LeaseHeld,
    #[error("lease expired")]
    LeaseExpired,
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("payload too large: {actual} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge { actual: usize, max: usize },
}

/// Error type for lease operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LeaseError {
    #[error("lease already held by another owner")]
    AlreadyHeld,
    #[error("lease expired")]
    Expired,
    #[error("stale fence: current fence is higher")]
    StaleFence,
    #[error("lease not found")]
    NotFound,
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<StoreError> for LeaseError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::LeaseHeld => LeaseError::AlreadyHeld,
            StoreError::LeaseExpired => LeaseError::Expired,
            StoreError::StaleFence => LeaseError::StaleFence,
            StoreError::NotFound => LeaseError::NotFound,
            other => LeaseError::Backend(other.to_string()),
        }
    }
}

/// Error type for capability validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("backend lacks capabilities required for profile '{profile}': {missing:?}")]
    MissingCapabilities {
        profile: crate::capability::SessionStateProfile,
        missing: Vec<&'static str>,
    },
}
