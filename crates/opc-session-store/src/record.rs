//! Stored record format and encrypted payload envelopes (RFC 004 §8, §14).
//!
//! `StoredSessionRecord` is the unit of persistence: payload bytes plus the
//! generation, owner, fence, and TTL metadata that backends validate on every
//! fenced write. Payloads are sealed as RFC 003 AEAD envelopes whose AAD
//! binds tenant, NF kind, a keyed session-key digest, state type, generation,
//! fence, and backend namespace — so ciphertext copied to another record,
//! version, tenant, or backend fails to decrypt instead of silently decoding.

use opc_crypto::{
    decrypt_decoded_envelope_with_handle, encrypt_envelope_with_handle, CryptoEnvelopeV1,
};
use opc_key::{
    key_id_from_bound_aad, serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyHandle, KeyProvider,
    KeyPurpose, RemoteSealProvider, SessionAad, Zeroizing, AEAD_TAG_LEN,
};
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

/// Declared interpretation of the bytes inside an `EncryptedSessionPayload`.
///
/// The encoding decides how `EncryptedSessionPayload::decrypt` treats the
/// bytes, so durable adapters must persist and restore it faithfully —
/// mislabeling ciphertext as plaintext (or vice versa) either leaks envelope
/// bytes to callers or fails decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPayloadEncoding {
    /// Caller-facing plaintext above the persistence boundary; the
    /// `EncryptingSessionBackend` wrapper seals it before it reaches a
    /// backend. `decrypt` returns the bytes unchanged.
    Plaintext,
    /// Plaintext row written before envelope encryption existed. Only for
    /// intentional one-time migrations; `decrypt` returns the bytes
    /// unchanged rather than failing.
    LegacyPlaintext,
    /// RFC 003 `CryptoEnvelopeV1` AEAD ciphertext — the only encoding that
    /// should reach a backend outside the deployment's trusted cryptographic
    /// boundary. `decrypt` requires a valid envelope and matching AAD.
    EnvelopeV1,
    /// Encoding unknown (e.g. a legacy database row being probed during
    /// migration). `decrypt` attempts an envelope decode and falls back to
    /// treating the bytes as plaintext if they do not parse as one.
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

    /// Raw payload bytes in their current encoding: AEAD envelope bytes for
    /// `EnvelopeV1`, plaintext otherwise. Check `encoding` before
    /// interpreting them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How `as_bytes` is to be interpreted (and how `decrypt` will treat it).
    pub fn encoding(&self) -> SessionPayloadEncoding {
        self.encoding
    }

    /// Size of the stored bytes — ciphertext size for envelopes, which is
    /// what backends compare against their `max_value_bytes` capability.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when no payload bytes are present. An empty `EnvelopeV1`
    /// payload is invalid and fails decryption.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Seal `record`'s payload into an RFC 003 AEAD envelope using the
    /// tenant's active session key from `provider`.
    ///
    /// The AAD binds tenant, NF kind, a keyed digest of the session key,
    /// state type, generation, fence, and `backend_namespace`, so the
    /// ciphertext only ever decrypts for exactly this record version in this
    /// namespace. Failures are reported as a deliberately coarse
    /// `StoreError::Crypto` to avoid acting as an encryption oracle.
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

    /// Seal `record`'s payload through a remote KMS/HSM provider.
    ///
    /// The record is still stored as an RFC 003 envelope and the same tenant,
    /// NF, session digest, state type, generation, fence, and backend
    /// namespace are bound into the serialized AAD. Unlike
    /// [`Self::encrypt`], AEAD execution is delegated to `provider`; callers
    /// must keep a store on one seal mode because local and remote ciphertexts
    /// use different key custody and are not expected to decrypt across modes.
    pub async fn remote_seal<S: RemoteSealProvider + ?Sized>(
        provider: &S,
        record: &StoredSessionRecord,
        backend_namespace: &str,
    ) -> Result<Self, StoreError> {
        let aad = build_remote_session_envelope_aad(record, backend_namespace)?;
        let sealed = provider
            .seal(&aad, record.payload.as_bytes())
            .await
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        if sealed.ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into(),
            ));
        }
        let key_id = key_id_from_bound_aad(&sealed.aad)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        let expected_aad = serialize_bound_aad(&aad, &key_id)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        if expected_aad != sealed.aad {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into(),
            ));
        }

        let envelope = CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::RemoteSeal,
            key_id,
            nonce: Vec::new(),
            aad: sealed.aad,
            ciphertext_and_tag: sealed.ciphertext_and_tag,
        }
        .encode()
        .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;

        Ok(Self::from_vec_with_encoding(
            envelope,
            SessionPayloadEncoding::EnvelopeV1,
        ))
    }

    /// Recover the plaintext payload according to the declared encoding.
    ///
    /// `Plaintext` and `LegacyPlaintext` return the bytes unchanged;
    /// `Unclassified` tries an envelope decode and falls back to returning
    /// the bytes as-is. For `EnvelopeV1` the decryption key is looked up by
    /// the key id embedded in the envelope, and the AAD is rebuilt from the
    /// `key`, `state_type`, `generation`, `fence`, and `backend_namespace`
    /// arguments — these must be the values the record was encrypted with
    /// (i.e. the record's own header fields), otherwise decryption fails with
    /// `StoreError::Crypto`. That failure is the integrity check: ciphertext
    /// spliced onto a different record, generation, or namespace cannot
    /// decode.
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

    /// Recover plaintext from a remotely sealed payload.
    ///
    /// Remote seal adds one KMS/HSM round-trip per seal operation (normally a
    /// checkpoint off the hot path) and one round-trip per unseal on failover
    /// restore, so restore latency and availability depend on the remote KMS.
    pub async fn remote_unseal<S: RemoteSealProvider + ?Sized>(
        &self,
        provider: &S,
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

        if envelope.algorithm != AeadAlgorithm::RemoteSeal {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into(),
            ));
        }

        let aad = build_remote_session_aad(key, state_type, generation, fence, backend_namespace)?;
        let expected_aad = serialize_bound_aad(&aad, &envelope.key_id)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;
        if expected_aad != envelope.aad {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into(),
            ));
        }

        provider
            .unseal(&aad, &envelope.ciphertext_and_tag)
            .await
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
    /// Tenant- and type-scoped identity of the session this record belongs
    /// to; must match the key the record is stored under.
    pub key: SessionKey,
    /// Monotonic per-session version. For state classes that require
    /// monotonic generations, every successful compare-and-set must write a
    /// strictly greater value, which is how replicas order replicated copies
    /// without comparing wall clocks.
    pub generation: Generation,
    /// Replica that performed the last authoritative write; backends require
    /// it to match the lease presented with the write.
    pub owner: OwnerId,
    /// Fence token the record was written under. Backends record the highest
    /// token per key and reject later writes carrying a lower one, which is
    /// what stops a stale owner from resurrecting old state.
    pub fence: FenceToken,
    /// Consistency class of this state (RFC 004 §4); decides whether
    /// monotonic-generation enforcement applies and which backend capability
    /// profile is required to hold the record.
    pub state_class: StateClass,
    /// Schema discriminator for the payload. Bound into the encryption AAD,
    /// so a payload cannot be reinterpreted under a different state type.
    pub state_type: StateType,
    /// TTL deadline; `None` means the record never expires. Once passed, the
    /// record reads as absent and may be pruned — refresh it with a fenced
    /// `refresh_ttl` before the deadline to keep it alive.
    pub expires_at: Option<Timestamp>,
    /// Payload bytes, either caller-facing plaintext or a sealed envelope
    /// depending on `EncryptedSessionPayload::encoding`.
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

pub(crate) fn build_remote_session_envelope_aad(
    record: &StoredSessionRecord,
    backend_namespace: &str,
) -> Result<EnvelopeAad, StoreError> {
    build_remote_session_aad(
        &record.key,
        &record.state_type,
        record.generation,
        record.fence,
        backend_namespace,
    )
}

fn build_remote_session_aad(
    key: &SessionKey,
    state_type: &StateType,
    generation: Generation,
    fence: FenceToken,
    backend_namespace: &str,
) -> Result<EnvelopeAad, StoreError> {
    let session_key_digest = key.digest();
    build_session_aad_with_digest(
        key,
        state_type,
        generation,
        fence,
        backend_namespace,
        &session_key_digest,
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
    build_session_aad_with_digest(
        key,
        state_type,
        generation,
        fence,
        backend_namespace,
        &session_key_digest,
    )
}

fn build_session_aad_with_digest(
    key: &SessionKey,
    state_type: &StateType,
    generation: Generation,
    fence: FenceToken,
    backend_namespace: &str,
    session_key_digest: &[u8; 32],
) -> Result<EnvelopeAad, StoreError> {
    let metadata = SessionAad::new(
        key.nf_kind.as_str(),
        encode_lower(session_key_digest),
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
