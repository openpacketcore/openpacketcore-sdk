use crate::KeyId;
use thiserror::Error;

/// Fail-closed reason an admitted key-custody operation did not run or could
/// not return a trustworthy result.
///
/// Every variant is fieldless and renders only its stable machine-readable
/// code. Provider-native messages never cross this boundary. None of these
/// states proves key loss or ciphertext rejection; retain data until repaired.
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
///
/// Only positive key/ciphertext evidence permits terminal rejection. Use
/// [`KeyError::is_definitive_rejection`]; all other errors retain protected data.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyError {
    /// The provider could not service the request because it is unavailable.
    /// Outages, transport loss, timeouts and explicit busy/throttled replies
    /// permit bounded backoff within the caller's original budget. This is
    /// never a verdict on stored data or proof that a mutation did not run.
    #[error("key provider unavailable")]
    Unavailable,
    /// The requested key is positively absent, not an endpoint or route failure.
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
    /// The provider positively established key revocation or ciphertext
    /// rejection. A generic request refusal, authentication failure or unknown
    /// reply is not sufficient evidence for this variant.
    /// This fieldless error exposes no provider context. Endpoint, channel,
    /// authentication and invalid-response failures use [`Self::ProviderUnusable`].
    #[error("key provider operation failed")]
    OperationFailed,
    /// The provider cannot be used as configured: endpoint, permissions, TLS,
    /// authentication, protocol or local provider state needs operator repair.
    /// This is not a verdict on a key or data and never authorizes teardown,
    /// deletion or release. Preserve pending work, report the configuration
    /// problem, and back off; do not spend the outage budget on a tight retry.
    #[error("key provider unusable as configured")]
    ProviderUnusable,
}

impl KeyError {
    /// Whether this error positively establishes a missing/revoked key or a
    /// rejected ciphertext. Only this predicate authorizes a provider error to
    /// cross a terminal data-rejection boundary. All other errors retain data.
    ///
    /// Both matches are exhaustive inside the defining crate: adding a key or
    /// custody variant requires an explicit classification here. Custody health,
    /// admission, identity and output-contract failures are never data verdicts.
    pub const fn is_definitive_rejection(&self) -> bool {
        match self {
            Self::NotFound | Self::OperationFailed => true,
            Self::Unavailable
            | Self::ProviderUnusable
            | Self::DuplicateKeyId { .. }
            | Self::InvalidMetadata { .. }
            | Self::InvalidKeyId { .. }
            | Self::InvalidAlgorithm { .. }
            | Self::RotationFailed => false,
            Self::CustodyOperation(error) => match error {
                KeyCustodyOperationError::NotInstalled
                | KeyCustodyOperationError::IdentityChanged
                | KeyCustodyOperationError::ValidationChanged
                | KeyCustodyOperationError::CapabilityNotAdmitted
                | KeyCustodyOperationError::CapabilityWithdrawn
                | KeyCustodyOperationError::ProviderOperationFailed
                | KeyCustodyOperationError::InvalidProviderOutput => false,
            },
        }
    }

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
