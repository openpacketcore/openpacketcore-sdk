use async_trait::async_trait;
use opc_types::TenantId;
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{
        EncryptedPayload, KeyHandle, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN,
        AES_256_GCM_SIV_NONCE_LEN,
    },
    scope::{serialize_bound_aad, EnvelopeAad, KeyId, KeyPurpose},
};

/// Maximum UTF-8 width accepted for a remote envelope key identifier.
///
/// This is the protocol bound imposed by [`KeyId`].  Remote providers declare
/// their supported subset through [`RemoteSealCapabilities::max_key_id_bytes`]
/// so persistence wrappers can reserve an exact envelope header budget.
pub const REMOTE_SEAL_MAX_KEY_ID_BYTES: usize = 512;

/// Bounded, provider-declared remote sealing limits.
///
/// All limits are hard limits.  A zero-valued default intentionally declares
/// no usable remote sealing service, which keeps pre-existing third-party
/// implementations fail-closed until they explicitly state their bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSealCapabilities {
    /// Largest plaintext accepted by [`RemoteSealProvider::seal`].
    pub max_seal_plaintext_bytes: usize,
    /// Largest plaintext returned by [`RemoteSealProvider::unseal`].
    pub max_unseal_output_bytes: usize,
    /// Largest caller plaintext guaranteed to complete a seal/unseal round trip.
    pub max_round_trip_plaintext_bytes: usize,
    /// Exact ciphertext-and-tag growth over the caller plaintext.
    ///
    /// Remote envelopes currently use AES-256-GCM-SIV, whose detached
    /// authentication tag is the only expansion.  Providers must therefore
    /// declare exactly [`AEAD_TAG_LEN`], rather than an upper bound which
    /// could permit a non-round-trippable provider response to persist.
    pub max_ciphertext_expansion_bytes: usize,
    /// Largest key ID that can appear in a sealed envelope.
    pub max_key_id_bytes: usize,
}

/// A provider-owned digest made under the exact active remote key selection.
///
/// The key ID pins the immediately following seal operation to the same key
/// generation that produced `digest`; callers must not treat it as a mutable
/// provider-default alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSealActiveKeyedDigest {
    /// Exact remote key generation selected by the provider.
    pub key_id: KeyId,
    /// Domain-separated 32-byte provider-keyed digest.
    pub digest: [u8; 32],
}

impl RemoteSealCapabilities {
    /// A deliberately unusable declaration for providers that have not
    /// audited and published their I/O and expansion bounds.
    pub const fn unavailable() -> Self {
        Self {
            max_seal_plaintext_bytes: 0,
            max_unseal_output_bytes: 0,
            max_round_trip_plaintext_bytes: 0,
            max_ciphertext_expansion_bytes: 0,
            max_key_id_bytes: 0,
        }
    }

    /// Whether this declaration can safely carry one authenticated envelope.
    pub const fn is_usable(self) -> bool {
        self.max_seal_plaintext_bytes > 0
            && self.max_unseal_output_bytes > 0
            && self.max_round_trip_plaintext_bytes > 0
            && self.max_round_trip_plaintext_bytes <= self.max_seal_plaintext_bytes
            && self.max_round_trip_plaintext_bytes <= self.max_unseal_output_bytes
            && self.max_ciphertext_expansion_bytes == AEAD_TAG_LEN
            && self.max_key_id_bytes > 0
            && self.max_key_id_bytes <= REMOTE_SEAL_MAX_KEY_ID_BYTES
    }

    /// Check caller plaintext before a seal request is sent.
    pub fn validate_seal_plaintext(self, len: usize) -> Result<(), KeyError> {
        if !self.is_usable() || len > self.max_seal_plaintext_bytes {
            return Err(KeyError::Unavailable);
        }
        Ok(())
    }

    /// Check a ciphertext-and-tag input before an unseal request is sent.
    pub fn validate_unseal_input(self, len: usize) -> Result<(), KeyError> {
        let max = self
            .max_unseal_output_bytes
            .checked_add(self.max_ciphertext_expansion_bytes)
            .ok_or(KeyError::Unavailable)?;
        if !self.is_usable() || len < AEAD_TAG_LEN || len > max {
            return Err(KeyError::Unavailable);
        }
        Ok(())
    }

    /// Check a remote seal response against the submitted plaintext length.
    pub fn validate_seal_output(
        self,
        plaintext_len: usize,
        ciphertext_len: usize,
    ) -> Result<(), KeyError> {
        let expected = plaintext_len
            .checked_add(self.max_ciphertext_expansion_bytes)
            .ok_or(KeyError::Unavailable)?;
        if !self.is_usable() || ciphertext_len != expected {
            return Err(KeyError::Unavailable);
        }
        Ok(())
    }

    /// Check a remote unseal response before exposing it to the caller.
    pub fn validate_unseal_output(
        self,
        ciphertext_len: usize,
        plaintext_len: usize,
    ) -> Result<(), KeyError> {
        let expected = ciphertext_len
            .checked_sub(self.max_ciphertext_expansion_bytes)
            .ok_or(KeyError::Unavailable)?;
        if !self.is_usable()
            || plaintext_len != expected
            || plaintext_len > self.max_unseal_output_bytes
        {
            return Err(KeyError::Unavailable);
        }
        Ok(())
    }
}

/// Server-side payload sealing contract.
///
/// Implementations delegate AEAD execution to a KMS/HSM boundary, so the
/// key-encryption key or data-encryption key never has to enter application
/// memory. Callers still build the same [`EnvelopeAad`] used by the local
/// [`crate::KeyProvider`] path, and implementations must bind the exact bytes
/// from [`serialize_bound_aad`] into the remote encrypt/decrypt request.
#[async_trait]
pub trait RemoteSealProvider: Send + Sync {
    /// Hard limits enforced by this provider.
    ///
    /// The default is intentionally unusable. Implementations must opt in by
    /// publishing exact bounds, allowing persistence wrappers to make a
    /// truthful plaintext-capacity promise before provider I/O.
    fn capabilities(&self) -> RemoteSealCapabilities {
        RemoteSealCapabilities::unavailable()
    }

    /// Select the active remote key and derive a domain-separated digest
    /// without exporting key material.
    ///
    /// The returned key ID must be accepted by [`Self::seal_with_key_id`], so
    /// a rotation cannot make an AAD digest and its ciphertext use different
    /// key generations.
    async fn active_keyed_digest(
        &self,
        _domain: &[u8],
        _input: &[u8],
    ) -> Result<RemoteSealActiveKeyedDigest, KeyError> {
        Err(KeyError::Unavailable)
    }

    /// Derive a domain-separated digest using an exact historical key.
    ///
    /// This is used before remote unseal so envelope AAD binding is verified
    /// by the same provider-owned key generation as the authentication tag.
    async fn keyed_digest(
        &self,
        _key_id: &KeyId,
        _domain: &[u8],
        _input: &[u8],
    ) -> Result<[u8; 32], KeyError> {
        Err(KeyError::Unavailable)
    }

    /// Seal with the exact key generation selected for an AAD digest.
    async fn seal_with_key_id(
        &self,
        _key_id: &KeyId,
        _aad: &EnvelopeAad,
        _plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        Err(KeyError::Unavailable)
    }

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
    fn capabilities(&self) -> RemoteSealCapabilities {
        RemoteSealCapabilities {
            max_seal_plaintext_bytes: usize::MAX - AEAD_TAG_LEN,
            max_unseal_output_bytes: usize::MAX - AEAD_TAG_LEN,
            max_round_trip_plaintext_bytes: usize::MAX - AEAD_TAG_LEN,
            max_ciphertext_expansion_bytes: AEAD_TAG_LEN,
            max_key_id_bytes: REMOTE_SEAL_MAX_KEY_ID_BYTES,
        }
    }

    async fn active_keyed_digest(
        &self,
        domain: &[u8],
        input: &[u8],
    ) -> Result<RemoteSealActiveKeyedDigest, KeyError> {
        use crate::KeyProvider;
        let handle = self
            .provider
            .get_active_key(self.purpose, &self.tenant)
            .await?;
        Ok(RemoteSealActiveKeyedDigest {
            key_id: handle.key_id().clone(),
            digest: handle.keyed_digest(domain, input),
        })
    }

    async fn keyed_digest(
        &self,
        key_id: &KeyId,
        domain: &[u8],
        input: &[u8],
    ) -> Result<[u8; 32], KeyError> {
        use crate::KeyProvider;
        let handle = self.provider.get_key_by_id(key_id).await?;
        if handle.purpose() != self.purpose || handle.tenant() != &self.tenant {
            return Err(KeyError::NotFound);
        }
        Ok(handle.keyed_digest(domain, input))
    }

    async fn seal_with_key_id(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        let capabilities = self.capabilities();
        capabilities.validate_seal_plaintext(plaintext.len())?;
        use crate::KeyProvider;
        let handle = self.provider.get_key_by_id(key_id).await?;
        if handle.purpose() != aad.purpose() || handle.tenant() != aad.tenant() {
            return Err(KeyError::NotFound);
        }
        let sealed = handle
            .encrypt_payload(aad, plaintext, self.nonce)
            .map_err(|_| KeyError::Unavailable)?;
        capabilities.validate_seal_output(plaintext.len(), sealed.ciphertext_and_tag.len())?;
        Ok(sealed)
    }

    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        let capabilities = self.capabilities();
        capabilities.validate_seal_plaintext(plaintext.len())?;
        use crate::KeyProvider;
        let handle = self
            .provider
            .get_active_key(aad.purpose(), aad.tenant())
            .await?;
        let sealed = handle
            .encrypt_payload(aad, plaintext, self.nonce)
            .map_err(|_| KeyError::Unavailable)?;
        capabilities.validate_seal_output(plaintext.len(), sealed.ciphertext_and_tag.len())?;
        Ok(sealed)
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let capabilities = self.capabilities();
        capabilities.validate_unseal_input(ciphertext_and_tag.len())?;
        use crate::KeyProvider;
        let handle = self.provider.get_key_by_id(key_id).await?;
        if handle.purpose() != aad.purpose() || handle.tenant() != aad.tenant() {
            return Err(KeyError::NotFound);
        }
        let plaintext = handle
            .decrypt_payload(
                aad,
                &serialize_bound_aad(aad, key_id)?,
                ciphertext_and_tag,
                self.nonce,
            )
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Unavailable)?;
        capabilities.validate_unseal_output(ciphertext_and_tag.len(), plaintext.len())?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod material_tests {
    use super::*;

    #[test]
    fn capabilities_require_the_exact_aead_expansion_for_seal_and_unseal() {
        let capabilities = RemoteSealCapabilities {
            max_seal_plaintext_bytes: 32,
            max_unseal_output_bytes: 32,
            max_round_trip_plaintext_bytes: 32,
            max_ciphertext_expansion_bytes: AEAD_TAG_LEN,
            max_key_id_bytes: REMOTE_SEAL_MAX_KEY_ID_BYTES,
        };

        assert!(capabilities.is_usable());
        assert!(capabilities.validate_seal_output(0, AEAD_TAG_LEN).is_ok());
        assert!(capabilities.validate_unseal_output(AEAD_TAG_LEN, 0).is_ok());
        assert!(capabilities.validate_seal_output(1, AEAD_TAG_LEN).is_err());
        assert!(capabilities
            .validate_seal_output(1, AEAD_TAG_LEN + 2)
            .is_err());
        assert!(capabilities
            .validate_unseal_output(AEAD_TAG_LEN + 1, 0)
            .is_err());
        assert!(capabilities
            .validate_unseal_output(AEAD_TAG_LEN + 1, 2)
            .is_err());

        let non_exact = RemoteSealCapabilities {
            max_ciphertext_expansion_bytes: AEAD_TAG_LEN + 1,
            ..capabilities
        };
        assert!(!non_exact.is_usable());
    }

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
