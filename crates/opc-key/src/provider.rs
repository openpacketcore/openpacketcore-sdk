use aes_gcm_siv::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256GcmSiv,
};
use async_trait::async_trait;
use hkdf::Hkdf;
use opc_types::TenantId;
use sha2::Sha256;
use std::fmt;
use std::sync::Arc;
use subtle::ConstantTimeEq;
pub use zeroize::Zeroizing;

use crate::{
    errors::{CryptoOperationError, KeyError},
    scope::{serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, KeyPurpose},
};

pub const AES_256_GCM_SIV_KEY_LEN: usize = 32;
pub const AES_256_GCM_SIV_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

/// Serialized AEAD inputs returned to the envelope layer after encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub aad: Vec<u8>,
    pub ciphertext_and_tag: Vec<u8>,
}

/// Key-provider contract from RFC 003.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError>;

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError>;

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError>;
}

#[derive(Clone)]
pub(crate) struct SecretMaterial {
    pub(crate) bytes: Zeroizing<[u8; AES_256_GCM_SIV_KEY_LEN]>,
}

/// Opaque handle returned by a [`KeyProvider`].
#[derive(Clone)]
pub struct KeyHandle {
    pub(crate) key_id: KeyId,
    pub(crate) purpose: KeyPurpose,
    pub(crate) tenant: TenantId,
    pub(crate) algorithm: AeadAlgorithm,
    pub(crate) material: Arc<SecretMaterial>,
}

impl fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHandle")
            .field("key_id", &self.key_id)
            .field("purpose", &self.purpose)
            .field("tenant", &self.tenant)
            .field("algorithm", &self.algorithm)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl KeyHandle {
    /// Creates a key handle from zeroizing secret material.
    ///
    /// Callers should prefer constructing the secret in [`Zeroizing`] form so
    /// the raw bytes can be cleared after transfer into the handle.
    pub fn new(
        key_id: KeyId,
        purpose: KeyPurpose,
        tenant: TenantId,
        secret: Zeroizing<[u8; AES_256_GCM_SIV_KEY_LEN]>,
    ) -> Self {
        Self {
            key_id,
            purpose,
            tenant,
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            material: Arc::new(SecretMaterial { bytes: secret }),
        }
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Derives a keyed, non-secret digest for backend-visible correlation data.
    ///
    /// The digest is scoped to this handle's secret material, purpose, tenant,
    /// and caller-provided domain so callers can bind opaque identifiers into
    /// AAD without exposing stable unkeyed hashes of subscriber or config data.
    pub fn keyed_digest(&self, domain: &[u8], input: &[u8]) -> [u8; 32] {
        let hkdf = Hkdf::<Sha256>::new(Some(domain), &self.material.bytes[..]);
        let mut info = Vec::with_capacity(
            (3 * std::mem::size_of::<u64>())
                + self.purpose.as_str().len()
                + self.tenant.as_str().len()
                + input.len(),
        );
        append_digest_field(&mut info, self.purpose.as_str().as_bytes());
        append_digest_field(&mut info, self.tenant.as_str().as_bytes());
        append_digest_field(&mut info, input);

        let mut digest = [0_u8; 32];
        hkdf.expand(&info, &mut digest)
            .expect("HKDF-SHA256 accepts 32-byte output");
        digest
    }

    pub fn encrypt_payload(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
        nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
    ) -> Result<EncryptedPayload, CryptoOperationError> {
        if !self.matches_context(aad) {
            return Err(CryptoOperationError::EncryptionFailed);
        }
        let serialized_aad = serialize_bound_aad(aad, &self.key_id)
            .map_err(|_| CryptoOperationError::EncryptionFailed)?;
        let derived_key = self.derive_aead_key(aad, CryptoOperationError::EncryptionFailed)?;

        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&derived_key[..]));
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                serialized_aad.as_slice(),
                &mut ciphertext,
            )
            .map_err(|_| CryptoOperationError::EncryptionFailed)?;
        ciphertext.extend_from_slice(tag.as_slice());

        Ok(EncryptedPayload {
            aad: serialized_aad,
            ciphertext_and_tag: ciphertext,
        })
    }

    pub fn decrypt_payload(
        &self,
        expected_aad: &EnvelopeAad,
        bound_aad: &[u8],
        ciphertext_and_tag: &[u8],
        nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
    ) -> Result<Vec<u8>, CryptoOperationError> {
        if !self.matches_context(expected_aad) {
            return Err(CryptoOperationError::DecryptionFailed);
        }

        if ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(CryptoOperationError::DecryptionFailed);
        }

        let expected_serialized = serialize_bound_aad(expected_aad, &self.key_id)
            .map_err(|_| CryptoOperationError::DecryptionFailed)?;
        if expected_serialized.len() != bound_aad.len()
            || expected_serialized.as_slice().ct_eq(bound_aad).unwrap_u8() != 1
        {
            return Err(CryptoOperationError::DecryptionFailed);
        }

        let derived_key =
            self.derive_aead_key(expected_aad, CryptoOperationError::DecryptionFailed)?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&derived_key[..]));
        let split = ciphertext_and_tag.len() - AEAD_TAG_LEN;
        let mut plaintext = ciphertext_and_tag[..split].to_vec();
        let tag = GenericArray::clone_from_slice(&ciphertext_and_tag[split..]);

        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                expected_serialized.as_slice(),
                &mut plaintext,
                &tag,
            )
            .map_err(|_| CryptoOperationError::DecryptionFailed)?;

        Ok(plaintext)
    }

    fn matches_context(&self, aad: &EnvelopeAad) -> bool {
        aad.validate().is_ok() && aad.tenant == self.tenant && aad.purpose == self.purpose
    }

    fn derive_aead_key(
        &self,
        aad: &EnvelopeAad,
        failure: CryptoOperationError,
    ) -> Result<Zeroizing<[u8; AES_256_GCM_SIV_KEY_LEN]>, CryptoOperationError> {
        let (salt, info) = aad.kdf_context(&self.key_id).map_err(|_| failure)?;
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), self.material.bytes.as_slice());
        let mut derived = Zeroizing::new([0_u8; AES_256_GCM_SIV_KEY_LEN]);
        hkdf.expand(&info, &mut *derived).map_err(|_| failure)?;
        Ok(derived)
    }
}

fn append_digest_field(out: &mut Vec<u8>, field: &[u8]) {
    let len = u64::try_from(field.len()).expect("usize length fits in u64");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}
