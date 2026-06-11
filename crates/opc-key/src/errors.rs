use crate::KeyId;
use thiserror::Error;

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
