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
    decode_bound_aad, key_id_from_bound_aad, serialize_bound_aad, AeadAlgorithm, EnvelopeAad,
    EnvelopeMetadata, KeyHandle, KeyProvider, KeyPurpose, RemoteSealProvider, SessionAad,
    Zeroizing, AEAD_TAG_LEN,
};
use opc_types::Timestamp;

use crate::{
    error::StoreError,
    hex::encode_lower,
    model::{FenceToken, Generation, OwnerId, SessionKey, StateClass, StateType},
};

const SESSION_ENVELOPE_VERSION: u64 = 1;
// RemoteSeal v1 used an unkeyed session-key digest. Keep that exact format
// readable only under its historical discriminator; v2 binds the digest to
// the remote provider key generation that sealed the envelope.
const LEGACY_REMOTE_SESSION_ENVELOPE_VERSION: u64 = SESSION_ENVELOPE_VERSION;
const REMOTE_SESSION_ENVELOPE_VERSION: u64 = 2;
const SESSION_KEY_AAD_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-key-aad/v1";
const SESSION_ENVELOPE_AAD_FAILED_MESSAGE: &str = "session envelope AAD construction failed";
const SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE: &str = "session envelope encryption failed";
const SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE: &str = "session envelope decryption failed";
const SESSION_ENVELOPE_MISSING_CIPHERTEXT_MESSAGE: &str = "session envelope ciphertext is missing";
const SESSION_ENVELOPE_INVALID_MESSAGE: &str = "session envelope is invalid";

fn invalid_session_envelope() -> StoreError {
    StoreError::Crypto(SESSION_ENVELOPE_INVALID_MESSAGE.into())
}

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
/// - use [`EncryptedSessionPayload::try_envelope`] for RFC 003 ciphertext rows
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
        #[serde(deny_unknown_fields)]
        struct Helper {
            bytes: Vec<u8>,
            encoding: SessionPayloadEncoding,
        }
        let helper = Helper::deserialize(deserializer)?;
        Self::try_from_vec_with_encoding(helper.bytes, helper.encoding)
            .map_err(serde::de::Error::custom)
    }
}

impl EncryptedSessionPayload {
    /// Construct caller-facing plaintext payload bytes.
    ///
    /// This is intended for data above the persistence boundary before
    /// [`crate::backend::EncryptingSessionBackend`] seals it. Durable adapters
    /// must use [`Self::try_envelope`] or [`Self::legacy_plaintext`] instead.
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_unchecked(data.as_ref().to_vec(), SessionPayloadEncoding::Plaintext)
    }

    /// Construct caller-facing plaintext payload bytes from a Zeroizing wrapper.
    pub fn new_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            encoding: SessionPayloadEncoding::Plaintext,
        }
    }

    /// Validate and construct already-encrypted RFC 003 envelope bytes for a
    /// backend-facing record.
    ///
    /// The exact canonical envelope, algorithm nonce, session AAD, embedded
    /// key ID, and authentication-tag shape are checked without resolving a
    /// key or decrypting the ciphertext. Record-specific AAD fields are
    /// checked again at the consensus boundary.
    pub fn try_envelope(data: impl AsRef<[u8]>) -> Result<Self, StoreError> {
        Self::try_from_vec_with_encoding(data.as_ref().to_vec(), SessionPayloadEncoding::EnvelopeV1)
    }

    /// Construct a legacy plaintext payload row that predates envelope writes.
    pub fn legacy_plaintext(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_unchecked(
            data.as_ref().to_vec(),
            SessionPayloadEncoding::LegacyPlaintext,
        )
    }

    /// Construct a payload for migration/probing of unclassified legacy database rows.
    pub fn unclassified(data: impl AsRef<[u8]>) -> Self {
        Self::from_vec_unchecked(data.as_ref().to_vec(), SessionPayloadEncoding::Unclassified)
    }

    pub(crate) fn try_from_vec_with_encoding(
        bytes: Vec<u8>,
        encoding: SessionPayloadEncoding,
    ) -> Result<Self, StoreError> {
        let payload = Self {
            bytes: Zeroizing::new(bytes),
            encoding,
        };
        if encoding == SessionPayloadEncoding::EnvelopeV1 {
            payload.decode_valid_session_envelope()?;
        }
        Ok(payload)
    }

    fn from_vec_unchecked(bytes: Vec<u8>, encoding: SessionPayloadEncoding) -> Self {
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

    /// Validate that this payload is one canonical RFC 003 session envelope.
    pub fn validate_envelope(&self) -> Result<(), StoreError> {
        self.decode_valid_session_envelope().map(|_| ())
    }

    /// Validate the envelope and every record field visible without a key.
    ///
    /// The tenant, NF kind, state type, generation, and fence embedded in AAD
    /// must match the record header. The keyed session digest and backend
    /// namespace remain authenticated ciphertext metadata and are verified
    /// during decrypt by the outer protection adapter.
    pub(crate) fn validate_envelope_for_record(
        &self,
        record: &StoredSessionRecord,
    ) -> Result<(), StoreError> {
        let (_, aad) = self.decode_valid_session_envelope()?;
        validate_session_envelope_scope(
            &aad,
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            None,
        )
    }

    fn decode_valid_session_envelope(&self) -> Result<(CryptoEnvelopeV1, EnvelopeAad), StoreError> {
        if self.encoding != SessionPayloadEncoding::EnvelopeV1 || self.bytes.is_empty() {
            return Err(invalid_session_envelope());
        }
        decode_valid_session_envelope_bytes(&self.bytes)
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
        Self::try_envelope(ciphertext)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))
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
        let capabilities = provider.capabilities();
        capabilities
            .validate_seal_plaintext(record.payload.len())
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        let active_digest = provider
            .active_keyed_digest(
                SESSION_KEY_AAD_DIGEST_DOMAIN,
                &record.key.canonical_digest_input(),
            )
            .await
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        let aad = build_session_aad_with_digest(
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            backend_namespace,
            REMOTE_SESSION_ENVELOPE_VERSION,
            &active_digest.digest,
        )?;
        let sealed = provider
            .seal_with_key_id(&active_digest.key_id, &aad, record.payload.as_bytes())
            .await
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        if sealed.ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into(),
            ));
        }
        let key_id = key_id_from_bound_aad(&sealed.aad)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))?;
        if key_id != active_digest.key_id {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into(),
            ));
        }
        if key_id.as_str().len() > capabilities.max_key_id_bytes {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into(),
            ));
        }
        capabilities
            .validate_seal_output(record.payload.len(), sealed.ciphertext_and_tag.len())
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

        Self::try_envelope(envelope)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_ENCRYPT_FAILED_MESSAGE.into()))
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
    /// Version 2 remote sealing performs one provider call to bind the active
    /// key and one to seal. Version 2 unsealing likewise performs one keyed
    /// digest call and one unseal call; legacy version 1 unsealing needs only
    /// the unseal call. Restore latency and availability therefore depend on
    /// the remote KMS/HSM.
    pub async fn remote_unseal<S: RemoteSealProvider + ?Sized>(
        &self,
        provider: &S,
        key: &SessionKey,
        state_type: &StateType,
        generation: Generation,
        fence: FenceToken,
        backend_namespace: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let (envelope, embedded_aad) = match self.encoding {
            SessionPayloadEncoding::Plaintext => return Ok(self.bytes.clone()),
            SessionPayloadEncoding::LegacyPlaintext => return Ok(self.bytes.clone()),
            SessionPayloadEncoding::Unclassified => match CryptoEnvelopeV1::decode(&self.bytes) {
                Ok(_) => decode_valid_session_envelope_bytes(&self.bytes).map_err(|_| {
                    StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into())
                })?,
                Err(_) => return Ok(self.bytes.clone()),
            },
            SessionPayloadEncoding::EnvelopeV1 => {
                if self.bytes.is_empty() {
                    return Err(StoreError::Crypto(
                        SESSION_ENVELOPE_MISSING_CIPHERTEXT_MESSAGE.into(),
                    ));
                }

                decode_valid_session_envelope_bytes(&self.bytes).map_err(|_| {
                    StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into())
                })?
            }
        };

        if envelope.algorithm != AeadAlgorithm::RemoteSeal {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into(),
            ));
        }

        // Reject clear AAD/header scope mismatches before invoking the remote
        // provider. The keyed session digest still requires the provider, but
        // a wrong tenant, record header, or namespace must not become a KMS
        // lookup oracle.
        validate_session_envelope_scope(
            &embedded_aad,
            key,
            state_type,
            generation,
            fence,
            Some(backend_namespace),
        )
        .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;

        let capabilities = provider.capabilities();
        if envelope.key_id.as_str().len() > capabilities.max_key_id_bytes {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into(),
            ));
        }
        capabilities
            .validate_unseal_input(envelope.ciphertext_and_tag.len())
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;

        let aad = match embedded_aad.version() {
            LEGACY_REMOTE_SESSION_ENVELOPE_VERSION => build_legacy_remote_session_aad(
                key,
                state_type,
                generation,
                fence,
                backend_namespace,
            )
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?,
            REMOTE_SESSION_ENVELOPE_VERSION => {
                let session_key_digest = provider
                    .keyed_digest(
                        &envelope.key_id,
                        SESSION_KEY_AAD_DIGEST_DOMAIN,
                        &key.canonical_digest_input(),
                    )
                    .await
                    .map_err(|_| {
                        StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into())
                    })?;
                build_session_aad_with_digest(
                    key,
                    state_type,
                    generation,
                    fence,
                    backend_namespace,
                    REMOTE_SESSION_ENVELOPE_VERSION,
                    &session_key_digest,
                )
                .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?
            }
            _ => {
                return Err(StoreError::Crypto(
                    SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into(),
                ));
            }
        };
        let expected_aad = serialize_bound_aad(&aad, &envelope.key_id)
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;
        if expected_aad != envelope.aad {
            return Err(StoreError::Crypto(
                SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into(),
            ));
        }

        let plaintext = provider
            .unseal(&envelope.key_id, &aad, &envelope.ciphertext_and_tag)
            .await
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;
        capabilities
            .validate_unseal_output(envelope.ciphertext_and_tag.len(), plaintext.len())
            .map_err(|_| StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into()))?;
        Ok(plaintext)
    }
}

fn decode_valid_session_envelope_bytes(
    bytes: &[u8],
) -> Result<(CryptoEnvelopeV1, EnvelopeAad), StoreError> {
    let envelope = CryptoEnvelopeV1::decode(bytes).map_err(|_| invalid_session_envelope())?;
    if envelope.nonce.len() != envelope.algorithm.nonce_len()
        || envelope.ciphertext_and_tag.len() < AEAD_TAG_LEN
        || envelope
            .encode()
            .map_err(|_| invalid_session_envelope())?
            .as_slice()
            != bytes
    {
        return Err(invalid_session_envelope());
    }
    let (aad, aad_key_id) =
        decode_bound_aad(&envelope.aad).map_err(|_| invalid_session_envelope())?;
    if aad_key_id != envelope.key_id
        || aad.purpose() != KeyPurpose::Session
        || !matches!(
            aad.version(),
            LEGACY_REMOTE_SESSION_ENVELOPE_VERSION | REMOTE_SESSION_ENVELOPE_VERSION
        )
        || !matches!(aad.metadata(), EnvelopeMetadata::Session(_))
    {
        return Err(invalid_session_envelope());
    }
    Ok((envelope, aad))
}

fn validate_session_envelope_scope(
    aad: &EnvelopeAad,
    key: &SessionKey,
    state_type: &StateType,
    generation: Generation,
    fence: FenceToken,
    backend_namespace: Option<&str>,
) -> Result<(), StoreError> {
    let EnvelopeMetadata::Session(session) = aad.metadata() else {
        return Err(invalid_session_envelope());
    };
    if aad.tenant() != &key.tenant
        || session.nf_kind() != key.nf_kind.as_str()
        || session.state_type() != state_type.as_str()
        || session.generation() != generation.get()
        || session.fence() != fence.get()
        || backend_namespace.is_some_and(|namespace| session.backend_namespace() != namespace)
    {
        return Err(invalid_session_envelope());
    }
    Ok(())
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Absolute TTL deadline. A finite value may be at most
    /// [`crate::MAX_SESSION_TTL`] after the mutation coordinator's authority
    /// time; past and immediate deadlines are valid and read as absent.
    /// `None` intentionally means never expires for every state class except
    /// [`StateClass::EphemeralProcedure`], whose profile requires a finite
    /// deadline. Refresh a finite deadline with fenced `refresh_ttl`.
    pub expires_at: Option<Timestamp>,
    /// Payload bytes, either caller-facing plaintext or a sealed envelope
    /// depending on `EncryptedSessionPayload::encoding`.
    pub payload: EncryptedSessionPayload,
}

// Records cross application and consumer boundaries. Keep their persisted
// identity, ownership, fencing, expiry, and protected payload out of generic
// diagnostics so enclosing consumer responses cannot reintroduce data that
// their own `Debug` implementations deliberately redact.
impl std::fmt::Debug for StoredSessionRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StoredSessionRecord(<redacted>)")
    }
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
    build_session_aad_with_digest(
        key,
        state_type,
        generation,
        fence,
        backend_namespace,
        SESSION_ENVELOPE_VERSION,
        &session_key_digest,
    )
}

fn build_legacy_remote_session_aad(
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
        LEGACY_REMOTE_SESSION_ENVELOPE_VERSION,
        &session_key_digest,
    )
}

fn build_session_aad_with_digest(
    key: &SessionKey,
    state_type: &StateType,
    generation: Generation,
    fence: FenceToken,
    backend_namespace: &str,
    version: u64,
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
        version,
        metadata,
    ))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        AeadAlgorithm, KeyId, KeyPurpose, MemoryRemoteSealProvider, RemoteSealProvider, Zeroizing,
        AES_256_GCM_SIV_KEY_LEN,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    use super::*;

    const TEST_NAMESPACE: &str = "remote-compat-sensitive-namespace";

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("tenant-a-sensitive").expect("tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: crate::SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"remote-compat-sensitive-key")
                .try_into()
                .expect("stable ID"),
        }
    }

    fn test_record(key: SessionKey) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(7),
            owner: OwnerId::new("remote-compat-owner").expect("owner"),
            fence: FenceToken::new(11),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("smf-pdu-context").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"remote-compat-sensitive-plaintext"),
        }
    }

    fn test_provider(secret: u8) -> MemoryRemoteSealProvider {
        MemoryRemoteSealProvider::new(
            KeyId::new("remote-compat-key").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("tenant-a-sensitive").expect("tenant"),
            Zeroizing::new([secret; AES_256_GCM_SIV_KEY_LEN]),
        )
    }

    fn assert_redacted_decrypt_failure(error: StoreError) {
        assert_eq!(
            error,
            StoreError::Crypto(SESSION_ENVELOPE_DECRYPT_FAILED_MESSAGE.into())
        );
        let rendered = format!("{error} {error:?}");
        for secret in [
            "tenant-a-sensitive",
            "remote-compat-sensitive-key",
            TEST_NAMESPACE,
            "remote-compat-key",
            "remote-compat-sensitive-plaintext",
            "tampered-sensitive-state",
        ] {
            assert!(!rendered.contains(secret), "leaked {secret}");
        }
    }

    #[tokio::test]
    async fn remote_unseal_reads_legacy_v1_aad_envelopes() {
        let record = test_record(test_key());
        let provider = test_provider(0x33);
        let aad = build_legacy_remote_session_aad(
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            TEST_NAMESPACE,
        )
        .expect("legacy AAD");
        let sealed = provider
            .seal(&aad, record.payload.as_bytes())
            .await
            .expect("legacy seal");
        let key_id = key_id_from_bound_aad(&sealed.aad).expect("legacy key ID");
        let bytes = CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::RemoteSeal,
            key_id,
            nonce: Vec::new(),
            aad: sealed.aad,
            ciphertext_and_tag: sealed.ciphertext_and_tag,
        }
        .encode()
        .expect("legacy envelope");
        let payload = EncryptedSessionPayload::try_envelope(bytes).expect("legacy payload");

        let plaintext = payload
            .remote_unseal(
                &provider,
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                TEST_NAMESPACE,
            )
            .await
            .expect("legacy unseal");

        assert_eq!(plaintext.as_slice(), record.payload.as_bytes());
    }

    #[tokio::test]
    async fn remote_seal_v2_round_trip_is_provider_key_bound() {
        let record = test_record(test_key());
        let provider = test_provider(0x33);
        let payload = EncryptedSessionPayload::remote_seal(&provider, &record, TEST_NAMESPACE)
            .await
            .expect("remote seal");
        let (_, aad) = payload
            .decode_valid_session_envelope()
            .expect("v2 envelope");
        assert_eq!(aad.version(), REMOTE_SESSION_ENVELOPE_VERSION);

        let plaintext = payload
            .remote_unseal(
                &provider,
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                TEST_NAMESPACE,
            )
            .await
            .expect("remote unseal");

        assert_eq!(plaintext.as_slice(), record.payload.as_bytes());
    }

    #[tokio::test]
    async fn remote_seal_v2_rejects_provider_key_and_scope_tampering() {
        let record = test_record(test_key());
        let provider = test_provider(0x33);
        let payload = EncryptedSessionPayload::remote_seal(&provider, &record, TEST_NAMESPACE)
            .await
            .expect("remote seal");

        let wrong_provider = test_provider(0x44);
        let provider_error = payload
            .remote_unseal(
                &wrong_provider,
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                TEST_NAMESPACE,
            )
            .await
            .expect_err("different provider key must fail");
        assert_redacted_decrypt_failure(provider_error);

        let wrong_key = SessionKey {
            stable_id: Bytes::from_static(b"remote-compat-tampered-key")
                .try_into()
                .expect("stable ID"),
            ..record.key.clone()
        };
        let key_error = payload
            .remote_unseal(
                &provider,
                &wrong_key,
                &record.state_type,
                record.generation,
                record.fence,
                TEST_NAMESPACE,
            )
            .await
            .expect_err("different session key must fail");
        assert_redacted_decrypt_failure(key_error);

        let wrong_state_type = StateType::new("tampered-sensitive-state").expect("state type");
        let scope_error = payload
            .remote_unseal(
                &provider,
                &record.key,
                &wrong_state_type,
                record.generation,
                record.fence,
                TEST_NAMESPACE,
            )
            .await
            .expect_err("different record scope must fail");
        assert_redacted_decrypt_failure(scope_error);
    }

    #[tokio::test]
    async fn remote_seal_rejects_unknown_aad_version_with_redacted_failure() {
        let record = test_record(test_key());
        let provider = test_provider(0x33);
        let aad = build_session_aad_with_digest(
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            TEST_NAMESPACE,
            REMOTE_SESSION_ENVELOPE_VERSION + 1,
            &record.key.digest(),
        )
        .expect("unknown-version AAD");
        let sealed = provider
            .seal(&aad, record.payload.as_bytes())
            .await
            .expect("unknown-version seal");
        let key_id = key_id_from_bound_aad(&sealed.aad).expect("unknown-version key ID");
        let bytes = CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::RemoteSeal,
            key_id,
            nonce: Vec::new(),
            aad: sealed.aad,
            ciphertext_and_tag: sealed.ciphertext_and_tag,
        }
        .encode()
        .expect("unknown-version envelope");

        let error = EncryptedSessionPayload::try_envelope(&bytes)
            .expect_err("unknown session AAD version must be rejected");
        assert_eq!(
            error,
            StoreError::Crypto(SESSION_ENVELOPE_INVALID_MESSAGE.into())
        );
        let rendered = format!("{error} {error:?}");
        for secret in ["tenant-a-sensitive", TEST_NAMESPACE, "remote-compat-key"] {
            assert!(!rendered.contains(secret), "leaked {secret}");
        }
        let payload = EncryptedSessionPayload::unclassified(bytes);
        let error = payload
            .remote_unseal(
                &provider,
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                TEST_NAMESPACE,
            )
            .await
            .expect_err("unknown AAD version must not reach remote unseal");
        assert_redacted_decrypt_failure(error);
    }
}
