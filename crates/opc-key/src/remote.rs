use async_trait::async_trait;
use opc_types::TenantId;
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{EncryptedPayload, KeyHandle, AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN},
    scope::{serialize_bound_aad, EnvelopeAad, KeyId, KeyPurpose},
};

/// Server-side payload sealing contract.
///
/// Implementations delegate AEAD execution to a KMS/HSM boundary, so the
/// key-encryption key or data-encryption key never has to enter application
/// memory. Callers still build the same [`EnvelopeAad`] used by the local
/// [`crate::KeyProvider`] path, and implementations must bind the exact bytes
/// from [`serialize_bound_aad`] into the remote encrypt/decrypt request.
#[async_trait]
pub trait RemoteSealProvider: Send + Sync {
    /// Seal inside the KMS/HSM; the key never enters app memory.
    async fn seal(&self, aad: &EnvelopeAad, plaintext: &[u8])
        -> Result<EncryptedPayload, KeyError>;

    /// Unseal inside the KMS/HSM.
    async fn unseal(
        &self,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}

/// Deterministic remote-seal test adapter.
///
/// This adapter intentionally performs AES-256-GCM-SIV in process, but only
/// through the [`RemoteSealProvider`] API. It is for unit tests and local
/// development where a real KMS/HSM is not available.
#[derive(Clone)]
pub struct MemoryRemoteSealProvider {
    handle: KeyHandle,
    nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
}

impl MemoryRemoteSealProvider {
    /// Create a deterministic in-memory remote-seal adapter.
    pub fn new(
        key_id: KeyId,
        purpose: KeyPurpose,
        tenant: TenantId,
        secret: Zeroizing<[u8; AES_256_GCM_SIV_KEY_LEN]>,
    ) -> Self {
        Self {
            handle: KeyHandle::new(key_id, purpose, tenant, secret),
            nonce: [0x42; AES_256_GCM_SIV_NONCE_LEN],
        }
    }

    /// Create an adapter from an existing local key handle.
    pub fn from_handle(handle: KeyHandle) -> Self {
        Self {
            handle,
            nonce: [0x42; AES_256_GCM_SIV_NONCE_LEN],
        }
    }

    /// Override the deterministic nonce used by the test adapter.
    ///
    /// Production remote seal providers should not expose nonce management to
    /// callers; this is only for deterministic test vectors.
    pub fn with_nonce(mut self, nonce: [u8; AES_256_GCM_SIV_NONCE_LEN]) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn key_id(&self) -> &KeyId {
        self.handle.key_id()
    }
}

#[async_trait]
impl RemoteSealProvider for MemoryRemoteSealProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        self.handle
            .encrypt_payload(aad, plaintext, self.nonce)
            .map_err(|_| KeyError::Unavailable)
    }

    async fn unseal(
        &self,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        self.handle
            .decrypt_payload(
                aad,
                &serialize_bound_aad(aad, self.handle.key_id())?,
                ciphertext_and_tag,
                self.nonce,
            )
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Unavailable)
    }
}
