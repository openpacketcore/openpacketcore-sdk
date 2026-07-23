use crate::KeyId;
use thiserror::Error;

/// Fail-closed reason an admitted key-custody operation did not run or could
/// not return a trustworthy result.
///
/// Every variant is fieldless and renders only its stable machine-readable
/// code. Provider-native messages never cross this boundary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum KeyCustodyOperationError {
    /// No key-custody module has been installed in this process.
    #[error("key_custody_not_installed")]
    NotInstalled,
    /// The installed module's identity changed after admission.
    #[error("key_custody_identity_changed")]
    IdentityChanged,
    /// The installed module's validation declaration changed after admission.
    #[error("key_custody_validation_changed")]
    ValidationChanged,
    /// The admission did not grant every capability required for sealed
    /// custody.
    #[error("key_custody_capability_not_admitted")]
    CapabilityNotAdmitted,
    /// One or more admitted capabilities are no longer advertised or
    /// serviceable.
    #[error("key_custody_capability_withdrawn")]
    CapabilityWithdrawn,
    /// The selected module failed without a safely preservable public
    /// [`KeyError`] classification.
    #[error("key_custody_provider_operation_failed")]
    ProviderOperationFailed,
    /// A successful provider response violated the bounded output contract.
    #[error("key_custody_invalid_provider_output")]
    InvalidProviderOutput,
}

impl KeyCustodyOperationError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "key_custody_not_installed",
            Self::IdentityChanged => "key_custody_identity_changed",
            Self::ValidationChanged => "key_custody_validation_changed",
            Self::CapabilityNotAdmitted => "key_custody_capability_not_admitted",
            Self::CapabilityWithdrawn => "key_custody_capability_withdrawn",
            Self::ProviderOperationFailed => "key_custody_provider_operation_failed",
            Self::InvalidProviderOutput => "key_custody_invalid_provider_output",
        }
    }
}

/// Provider and crypto-adapter failures.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyError {
    #[error("key provider unavailable")]
    Unavailable,
    #[error("key id not found")]
    NotFound,
    #[error("duplicate key id: {key_id}")]
    DuplicateKeyId { key_id: KeyId },
    #[error("invalid metadata field {field}: {message}")]
    InvalidMetadata {
        field: &'static str,
        message: String,
    },
    #[error("invalid key id: {message}")]
    InvalidKeyId { message: String },
    #[error("invalid envelope algorithm id: {id}")]
    InvalidAlgorithm { id: u16 },
    #[error("key rotation failed")]
    RotationFailed,
    /// An admitted key-custody boundary rejected or failed an operation.
    #[error(transparent)]
    CustodyOperation(#[from] KeyCustodyOperationError),
}

impl KeyError {
    pub(crate) fn invalid_key_id(message: impl Into<String>) -> Self {
        Self::InvalidKeyId {
            message: message.into(),
        }
    }

    pub(crate) fn invalid_metadata(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidMetadata {
            field,
            message: message.into(),
        }
    }

    pub(crate) fn invalid_algorithm(id: u16) -> Self {
        Self::InvalidAlgorithm { id }
    }
}

/// Redacted payload-level failures.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoOperationError {
    #[error("payload encryption failed")]
    EncryptionFailed,
    #[error("payload decryption failed")]
    DecryptionFailed,
}
