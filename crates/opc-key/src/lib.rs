//! Key-provider traits, admitted sealed custody, and tenant-bound payload
//! encryption helpers.
//!
//! The RFC 003 key boundary requires purpose-separated active-key lookup,
//! historical-key lookup by ID, and redacted failure modes for corrupted or
//! mismatched AEAD metadata. This crate exposes local and remote provider
//! traits, a deterministic in-memory adapter for tests, and envelope metadata
//! types that bind ciphertext to tenant, purpose, version, and schema/state
//! metadata.
//!
//! [`install_key_custody_module`] adds an opt-in process boundary for sealing
//! through a provider that declares non-exportable custody. Capability
//! evidence and operations come from one exact [`KeyCustodyModule`], and
//! callers can obtain the opaque [`AdmittedKeyCustody`] adapter only after
//! policy admission succeeds. The SDK gates on, but does not independently
//! certify, provider declarations. Existing [`KeyProvider`] and direct
//! [`RemoteSealProvider`] values remain ordinary unadmitted compatibility paths
//! and never inherit that admission.

#![forbid(unsafe_code)]

pub mod custody;
pub mod errors;
pub mod kms;
pub mod memory;
pub mod provider;
pub mod remote;
pub mod scope;

#[cfg(test)]
mod tests;

pub use custody::{
    admitted_key_custody, install_key_custody_module, key_custody_required_capabilities,
    AdmittedKeyCustody, KeyCustodyInstallError, KeyCustodyModule, MAX_KEY_CUSTODY_BOUND_AAD_BYTES,
};
pub use errors::{CryptoOperationError, KeyCustodyOperationError, KeyError};
pub use kms::{KmsKeyProvider, KmsRemoteSealProvider};
pub use memory::MemoryKeyProvider;
pub use opc_crypto_provider::{
    CapabilityReport, CapabilitySet, CryptoCapability, PolicyError, ProviderPolicy,
};
pub use provider::{
    EncryptedPayload, KeyHandle, KeyProvider, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
pub use remote::{
    MemoryRemoteSealProvider, RemoteSealMaterialController, RemoteSealMaterialEpoch,
    RemoteSealProvider,
};
pub use scope::{
    decode_bound_aad, key_id_from_bound_aad, serialize_bound_aad, AeadAlgorithm, ConfigAad,
    EnvelopeAad, EnvelopeMetadata, KeyId, KeyPurpose, SessionAad, ShadowSecurityAad,
};
