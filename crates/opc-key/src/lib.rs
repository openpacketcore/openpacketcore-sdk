//! Key-provider traits and tenant-bound payload encryption helpers.
//!
//! The RFC 003 key boundary requires purpose-separated active-key lookup,
//! historical-key lookup by ID, and redacted failure modes for corrupted or
//! mismatched AEAD metadata. This crate exposes the provider trait, a
//! deterministic in-memory adapter for tests, and envelope metadata types that
//! bind ciphertext to tenant, purpose, version, and schema/state metadata.

#![forbid(unsafe_code)]

pub mod errors;
pub mod kms;
pub mod memory;
pub mod provider;
pub mod remote;
pub mod scope;

#[cfg(test)]
mod tests;

pub use errors::{CryptoOperationError, KeyError};
pub use kms::{KmsKeyProvider, KmsRemoteSealProvider};
pub use memory::MemoryKeyProvider;
pub use provider::{
    EncryptedPayload, KeyHandle, KeyProvider, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
pub use remote::{MemoryRemoteSealProvider, RemoteSealProvider};
pub use scope::{
    decode_bound_aad, key_id_from_bound_aad, serialize_bound_aad, AeadAlgorithm, ConfigAad,
    EnvelopeAad, EnvelopeMetadata, KeyId, KeyPurpose, SessionAad, ShadowSecurityAad,
};
