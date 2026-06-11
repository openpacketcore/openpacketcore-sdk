use opc_crypto::{
    decrypt_decoded_envelope_with_handle, encrypt_envelope_with_handle, CryptoEnvelopeV1,
};
use opc_key::{EnvelopeAad, KeyHandle, KeyProvider, KeyPurpose, SessionAad, Zeroizing};
use opc_types::Timestamp;

use crate::{
    error::StoreError,
    hex::encode_lower,
    model::{FenceToken, Generation, OwnerId, SessionKey, StateClass, StateType},
};

const SESSION_ENVELOPE_VERSION: u64 = 1;
const SESSION_KEY_AAD_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-key-aad/v1";
const SESSION_ENVELOPE_AAD_FAILED_MESSAGE: &str = "session envelope AAD construction failed";
const SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE: &str = "session envelope encryption failed";
const SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE: &str = "session envelope decryption failed";
const SESSION_ENVELOPE_MISSING_CIPHERTEXT_MESSAGE: &str = "session envelope ciphertext is missing";

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPayloadEncoding {
    Plaintext,
    LegacyPlaintext,
    EnvelopeV1,
    Unclassified,
}

/// Session payload bytes held by a session record.
///
/// Above [`crate::backend::EncryptingSessionBackend`], callers provide
/// plaintext bytes and the wrapper seals them before persistence. Backend-facing
/// records that are not protected by that wrapper MUST carry AEAD ciphertext
/// unless the deployment profile explicitly trusts the backend.
///
/// Durable adapters that reconstruct [`StoredSessionRecord`] from persisted
/// bytes MUST preserve payload encoding explicitly:
///
/// - use [`EncryptedSessionPayload::envelope`] for RFC 003 ciphertext rows
/// - use [`EncryptedSessionPayload::legacy_plaintext`] only for intentional
///   one-time migrations of pre-envelope plaintext rows
///
/// [`EncryptedSessionPayload::new`] is for caller-facing plaintext payloads
/// above the persistence boundary and must not be used for stored envelope
/// bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSessionPayload {
    bytes: Zeroizing<Vec<u8>>,
    encoding: SessionPayloadEncoding,
}

impl serde::Serialize for EncryptedSessionPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EncryptedSessionPayload", 2)?;
        state.serialize_field("bytes", self.as_bytes())?;
        state.serialize_field("encoding", &self.encoding)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for EncryptedSessionPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Helper {
            bytes: Vec<u8>,
            encoding: SessionPayloadEncoding,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(Self::from_vec_with_encoding(helper.bytes, helper.encoding))
    }
}

impl EncryptedSessionPayload {
    /// Construct caller-facing plaintext payload bytes.
    ///
    /// This is intended for data above the persistence boundary before
    /// [`crate::backend::EncryptingSessionBackend`] seals it. Durable adapters
    /// must use [`Self::envelope`] or [`Self::legacy_plaintext`] instead.
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_with_encoding(data.as_ref().to_vec(), SessionPayloadEncoding::Plaintext)
    }

    /// Construct caller-facing plaintext payload bytes from a Zeroizing wrapper.
    pub fn new_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            encoding: SessionPayloadEncoding::Plaintext,
        }
    }

    /// Construct already-encrypted RFC 003 envelope bytes for backend-facing records.
    pub fn envelope(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_with_encoding(data.as_ref().to_vec(), SessionPayloadEncoding::EnvelopeV1)
    }

    /// Construct a legacy plaintext payload row that predates envelope writes.
    pub fn legacy_plaintext(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_with_encoding(
            data.as_ref().to_vec(),
            SessionPayloadEncoding::LegacyPlaintext,
        )
    }

    /// Construct a payload for migration/probing of unclassified legacy database rows.
    pub fn unclassified(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_with_encoding(data.as_ref().to_vec(), SessionPayloadEncoding::Unclassified)
    }

    pub(crate) fn from_vec_with_encoding(bytes: Vec<u8>, encoding: SessionPayloadEncoding) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            encoding,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn encoding(&self) -> SessionPayloadEncoding {
        self.encoding
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub async fn encrypt<P: KeyProvider + ?Sized>(
        provider: &P,
        record: &StoredSessionRecord,
        backend_namespace: &str,
    ) -> Result<Self, StoreError> {
        let handle = provider
            .get_active_key(KeyPurpose::Session, &record.key.tenant)
            .await
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        let aad = build_session_envelope_aad(record, backend_namespace, &handle)?;
        let ciphertext = encrypt_envelope_with_handle(&handle, &aad, record.payload.as_bytes())
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        Ok(Self::from_vec_with_encoding(
            ciphertext,
            SessionPayloadEncoding::EnvelopeV1,
        ))
    }

    pub async fn decrypt<P: KeyProvider + ?Sized>(
        &self,
        provider: &P,
        key: &SessionKey,
        state_type: &StateType,
        generation: Generation,
        fence: FenceToken,
        backend_namespace: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let envelope = match self.encoding {
            SessionPayloadEncoding::Plaintext => return Ok(self.bytes.clone()),
            SessionPayloadEncoding::LegacyPlaintext => return Ok(self.bytes.clone()),
            SessionPayloadEncoding::Unclassified => match CryptoEnvelopeV1::decode(&self.bytes) {
                Ok(envelope) => envelope,
                Err(_) => return Ok(self.bytes.clone()),
            },
            SessionPayloadEncoding::EnvelopeV1 => {
                if self.bytes.is_empty() {
                    return Err(StoreError::Crypto(
                        SESSION_ENVELOPE_MISSING_CIPHERTEXT_MESSAGE.into(),
                    ));
                }

                CryptoEnvelopeV1::decode(&self.bytes).map_err(|_| {
                    StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into())
                })?
            }
        };
        let handle = provider
            .get_key_by_id(&envelope.key_id)
            .await
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;
        let aad = build_session_aad(
            key,
            state_type,
            generation,
            fence,
            backend_namespace,
            &handle,
        )?;
        decrypt_decoded_envelope_with_handle(&handle, &aad, &envelope)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))
    }
}

impl std::fmt::Debug for EncryptedSessionPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedSessionPayload")
            .field("encoding", &self.encoding)
            .field("len", &self.len())
            .finish()
    }
}

/// Persistent representation of a session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSessionRecord {
    pub key: SessionKey,
    pub generation: Generation,
    pub owner: OwnerId,
    pub fence: FenceToken,
    pub state_class: StateClass,
    pub state_type: StateType,
    pub expires_at: Option<Timestamp>,
    pub payload: EncryptedSessionPayload,
}

impl StoredSessionRecord {
    /// Check if the session record's TTL has expired.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Timestamp::now_utc())
    }

    /// Check if the session record's TTL has expired at a given timestamp.
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at <= now
        } else {
            false
        }
    }
}

pub(crate) fn build_session_envelope_aad(
    record: &StoredSessionRecord,
    backend_namespace: &str,
    key_handle: &KeyHandle,
) -> Result<EnvelopeAad, StoreError> {
    build_session_aad(
        &record.key,
        &record.state_type,
        record.generation,
        record.fence,
        backend_namespace,
        key_handle,
    )
}

fn build_session_aad(
    key: &SessionKey,
    state_type: &StateType,
    generation: Generation,
    fence: FenceToken,
    backend_namespace: &str,
    key_handle: &KeyHandle,
) -> Result<EnvelopeAad, StoreError> {
    let session_key_digest =
        key_handle.keyed_digest(SESSION_KEY_AAD_DIGEST_DOMAIN, &key.canonical_digest_input());
    let metadata = SessionAad::new(
        key.nf_kind.as_str(),
        encode_lower(&session_key_digest),
        state_type.as_str(),
        generation.get(),
        fence.get(),
        backend_namespace,
    )
    .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_AAD_FAILED_MESSAGE.into()))?;
    Ok(EnvelopeAad::session(
        key.tenant.clone(),
        // Session records bind the per-record generation and fence in
        // `SessionAad`; this version is the envelope/AAD format version.
        SESSION_ENVELOPE_VERSION,
        metadata,
    ))
}
