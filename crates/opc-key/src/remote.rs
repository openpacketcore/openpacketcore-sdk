use async_trait::async_trait;
use opc_types::TenantId;
use std::fmt;
use std::sync::{Arc, Mutex};
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

    /// Unseal inside the KMS/HSM using the exact key selected by the envelope.
    ///
    /// `key_id` is validated envelope metadata, not provider configuration.
    /// Implementations must select that exact historical key and must not
    /// silently substitute their current active key.
    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}

/// Opaque process-local generation of active remote-seal configuration.
///
/// The value is safe for low-cardinality status correlation. It deliberately
/// contains no key identifier, tenant, endpoint, or provider detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSealMaterialEpoch(u64);

impl RemoteSealMaterialEpoch {
    const INITIAL: Self = Self(1);

    /// Numeric process-local epoch value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

struct RemoteSealMaterialState {
    epoch: RemoteSealMaterialEpoch,
    active_key_id: KeyId,
}

/// Coherent, constant-space active-key publication for remote sealing.
///
/// A seal operation snapshots one `(epoch, key_id)` pair before provider I/O.
/// Publishing a new active key therefore cannot retarget an in-flight request.
/// Historical key material is intentionally not cached here: unseal receives
/// the exact envelope key ID and the remote KMS/HSM remains authoritative for
/// retention and revocation.
#[derive(Clone)]
pub struct RemoteSealMaterialController {
    inner: Arc<Mutex<RemoteSealMaterialState>>,
}

impl RemoteSealMaterialController {
    /// Start at epoch one with the supplied active remote key ID.
    pub fn new(active_key_id: KeyId) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RemoteSealMaterialState {
                epoch: RemoteSealMaterialEpoch::INITIAL,
                active_key_id,
            })),
        }
    }

    /// Atomically publish the key used by future seal operations.
    ///
    /// Re-publishing the current key is idempotent. A different key advances
    /// the epoch with checked arithmetic; exhaustion fails closed.
    pub fn publish_active_key(
        &self,
        active_key_id: KeyId,
    ) -> Result<RemoteSealMaterialEpoch, KeyError> {
        let mut state = self.inner.lock().map_err(|_| KeyError::Unavailable)?;
        if state.active_key_id == active_key_id {
            return Ok(state.epoch);
        }
        let next = state
            .epoch
            .0
            .checked_add(1)
            .ok_or(KeyError::RotationFailed)?;
        state.active_key_id = active_key_id;
        state.epoch = RemoteSealMaterialEpoch(next);
        Ok(state.epoch)
    }

    /// Current redaction-safe material epoch.
    pub fn epoch(&self) -> Result<RemoteSealMaterialEpoch, KeyError> {
        self.inner
            .lock()
            .map(|state| state.epoch)
            .map_err(|_| KeyError::Unavailable)
    }

    pub(crate) fn active_selection(&self) -> Result<(RemoteSealMaterialEpoch, KeyId), KeyError> {
        self.inner
            .lock()
            .map(|state| (state.epoch, state.active_key_id.clone()))
            .map_err(|_| KeyError::Unavailable)
    }
}

impl fmt::Debug for RemoteSealMaterialController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteSealMaterialController")
            .field("epoch", &self.epoch().ok())
            .finish_non_exhaustive()
    }
}

/// Deterministic remote-seal test adapter.
///
/// This adapter intentionally performs AES-256-GCM-SIV in process, but only
/// through the [`RemoteSealProvider`] API. It is for unit tests and local
/// development where a real KMS/HSM is not available.
#[derive(Clone)]
pub struct MemoryRemoteSealProvider {
    provider: Arc<crate::MemoryKeyProvider>,
    purpose: KeyPurpose,
    tenant: TenantId,
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
        Self::from_handle(KeyHandle::new(key_id, purpose, tenant, secret))
    }

    /// Create an adapter from an existing local key handle.
    pub fn from_handle(handle: KeyHandle) -> Self {
        let purpose = handle.purpose();
        let tenant = handle.tenant().clone();
        let provider = Arc::new(crate::MemoryKeyProvider::from_active_handle(handle));
        Self {
            provider,
            purpose,
            tenant,
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

    /// Rotate the deterministic test adapter while retaining historical keys.
    pub async fn rotate_key(&self) -> Result<KeyId, KeyError> {
        use crate::KeyProvider;
        self.provider.rotate_key(self.purpose, &self.tenant).await
    }

    /// Active key ID used by the next seal operation.
    pub async fn active_key_id(&self) -> Result<KeyId, KeyError> {
        use crate::KeyProvider;
        self.provider
            .get_active_key(self.purpose, &self.tenant)
            .await
            .map(|handle| handle.key_id().clone())
    }
}

#[async_trait]
impl RemoteSealProvider for MemoryRemoteSealProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        use crate::KeyProvider;
        let handle = self
            .provider
            .get_active_key(aad.purpose(), aad.tenant())
            .await?;
        handle
            .encrypt_payload(aad, plaintext, self.nonce)
            .map_err(|_| KeyError::Unavailable)
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        use crate::KeyProvider;
        let handle = self.provider.get_key_by_id(key_id).await?;
        if handle.purpose() != aad.purpose() || handle.tenant() != aad.tenant() {
            return Err(KeyError::NotFound);
        }
        handle
            .decrypt_payload(
                aad,
                &serialize_bound_aad(aad, key_id)?,
                ciphertext_and_tag,
                self.nonce,
            )
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Unavailable)
    }
}

#[cfg(test)]
mod material_tests {
    use super::*;

    #[test]
    fn publication_is_shared_idempotent_and_redacted() {
        let old_key = KeyId::new("remote-sensitive-old").expect("old key ID");
        let new_key = KeyId::new("remote-sensitive-new").expect("new key ID");
        let controller = RemoteSealMaterialController::new(old_key.clone());
        let publisher = controller.clone();

        assert_eq!(
            publisher
                .publish_active_key(old_key.clone())
                .expect("idempotent publication")
                .get(),
            1
        );
        assert_eq!(
            publisher
                .publish_active_key(new_key.clone())
                .expect("new publication")
                .get(),
            2
        );
        assert_eq!(
            controller.active_selection().expect("active selection"),
            (RemoteSealMaterialEpoch(2), new_key.clone())
        );

        let rendered = format!("{controller:?}");
        assert!(!rendered.contains(old_key.as_str()));
        assert!(!rendered.contains(new_key.as_str()));
    }

    #[test]
    fn epoch_exhaustion_fails_without_changing_the_active_key() {
        let old_key = KeyId::new("remote-old-at-epoch-limit").expect("old key ID");
        let new_key = KeyId::new("remote-new-at-epoch-limit").expect("new key ID");
        let controller = RemoteSealMaterialController::new(old_key.clone());
        {
            let mut state = controller.inner.lock().expect("material state");
            state.epoch = RemoteSealMaterialEpoch(u64::MAX);
        }

        assert_eq!(
            controller
                .publish_active_key(new_key)
                .expect_err("epoch exhaustion must fail closed"),
            KeyError::RotationFailed
        );
        assert_eq!(
            controller.active_selection().expect("active selection"),
            (RemoteSealMaterialEpoch(u64::MAX), old_key)
        );
    }
}
