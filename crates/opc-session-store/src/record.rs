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
use std::sync::Arc;

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

#[cfg_attr(test, allow(dead_code))]
pub(crate) const PAYLOAD_DESERIALIZE_CHUNK_BYTES: usize = 4 * 1024;

struct WipingPayloadBytes(Zeroizing<Vec<u8>>);

// These are test-only evidence counters for durable payload ownership. They
// intentionally count actual allocation/adoption and byte-copy boundaries,
// rather than inferring them from a higher-level request or command counter.
#[cfg(test)]
static PAYLOAD_VISIT_BYTES_OWNERS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_VISIT_BYTES_COPIED_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_VISIT_BYTE_BUF_OWNERS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_SEQUENCE_CHUNK_ALLOCATIONS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_SEQUENCE_CHUNK_CAPACITY_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_SEQUENCE_STAGED_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_SEQUENCE_FINAL_ALLOCATIONS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_SEQUENCE_FINAL_ALLOCATION_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static PAYLOAD_SEQUENCE_FINAL_COPIED_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
fn note(counter: &std::sync::atomic::AtomicU64, value: usize) {
    counter.fetch_add(value as u64, std::sync::atomic::Ordering::Relaxed);
}

impl<'de> serde::Deserialize<'de> for WipingPayloadBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct WipingPayloadVisitor;

        impl<'de> serde::de::Visitor<'de> for WipingPayloadVisitor {
            type Value = WipingPayloadBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("opaque session payload bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                #[cfg(test)]
                {
                    note(&PAYLOAD_VISIT_BYTES_OWNERS, 1);
                    note(&PAYLOAD_VISIT_BYTES_COPIED_BYTES, value.len());
                }
                Ok(WipingPayloadBytes(Zeroizing::new(value.to_vec())))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                #[cfg(test)]
                note(&PAYLOAD_VISIT_BYTE_BUF_OWNERS, 1);
                Ok(WipingPayloadBytes(Zeroizing::new(value)))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut chunks = Vec::new();
                #[cfg(test)]
                {
                    note(&PAYLOAD_SEQUENCE_CHUNK_ALLOCATIONS, 1);
                    note(
                        &PAYLOAD_SEQUENCE_CHUNK_CAPACITY_BYTES,
                        PAYLOAD_DESERIALIZE_CHUNK_BYTES,
                    );
                }
                let mut current =
                    Zeroizing::new(Vec::with_capacity(PAYLOAD_DESERIALIZE_CHUNK_BYTES));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if current.len() == PAYLOAD_DESERIALIZE_CHUNK_BYTES {
                        chunks.push(current);
                        #[cfg(test)]
                        {
                            note(&PAYLOAD_SEQUENCE_CHUNK_ALLOCATIONS, 1);
                            note(
                                &PAYLOAD_SEQUENCE_CHUNK_CAPACITY_BYTES,
                                PAYLOAD_DESERIALIZE_CHUNK_BYTES,
                            );
                        }
                        current =
                            Zeroizing::new(Vec::with_capacity(PAYLOAD_DESERIALIZE_CHUNK_BYTES));
                    }
                    current.push(byte);
                    #[cfg(test)]
                    note(&PAYLOAD_SEQUENCE_STAGED_BYTES, 1);
                }
                let total = chunks
                    .iter()
                    .try_fold(current.len(), |total, chunk| total.checked_add(chunk.len()));
                let total = total.ok_or_else(|| {
                    serde::de::Error::custom("opaque session payload bytes are invalid")
                })?;
                #[cfg(test)]
                if total != 0 {
                    note(&PAYLOAD_SEQUENCE_FINAL_ALLOCATIONS, 1);
                    note(&PAYLOAD_SEQUENCE_FINAL_ALLOCATION_BYTES, total);
                }
                let mut bytes = Zeroizing::new(vec![0_u8; total]);
                let mut offset = 0;
                for chunk in chunks.iter().chain(std::iter::once(&current)) {
                    let end = offset + chunk.len();
                    bytes[offset..end].copy_from_slice(chunk);
                    #[cfg(test)]
                    note(&PAYLOAD_SEQUENCE_FINAL_COPIED_BYTES, chunk.len());
                    offset = end;
                }
                Ok(WipingPayloadBytes(bytes))
            }
        }

        // `EncryptedSessionPayload::serialize` has always emitted this field
        // as a generic Serde sequence. Request the same data model here so
        // formats that distinguish sequences from byte buffers continue to
        // read bytes produced by older and current SDKs.
        deserializer.deserialize_seq(WipingPayloadVisitor)
    }
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
#[derive(PartialEq, Eq)]
pub struct EncryptedSessionPayload {
    // The sealed bytes are shared only by immutable durable operation and
    // replication values.  The final Arc drop runs `Zeroizing` exactly once;
    // cloning a record therefore cannot copy ciphertext while it remains
    // protected in memory.
    bytes: Arc<Zeroizing<Vec<u8>>>,
    encoding: SessionPayloadEncoding,
}

// The prepared-checkpoint maximum-payload regression test observes record
// ownership separately from the deserializer allocation/copy counters above.
// A clone must only retain the immutable handle, never copy ciphertext.
#[cfg(test)]
static ENCRYPTED_SESSION_PAYLOAD_HANDLE_CLONES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static ENCRYPTED_SESSION_PAYLOAD_DESERIALIZED_OWNERS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNERS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNED_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static ENCRYPTED_SESSION_PAYLOAD_OWNERSHIP_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[cfg(test)]
fn note_encrypted_session_payload_initial_bytes(bytes: usize) {
    use std::sync::atomic::Ordering;
    ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNERS.fetch_add(1, Ordering::Relaxed);
    ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

impl Clone for EncryptedSessionPayload {
    fn clone(&self) -> Self {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            ENCRYPTED_SESSION_PAYLOAD_HANDLE_CLONES.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            bytes: Arc::clone(&self.bytes),
            encoding: self.encoding,
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_encrypted_session_payload_ownership_counters() {
    use std::sync::atomic::Ordering;
    ENCRYPTED_SESSION_PAYLOAD_HANDLE_CLONES.store(0, Ordering::Relaxed);
    ENCRYPTED_SESSION_PAYLOAD_DESERIALIZED_OWNERS.store(0, Ordering::Relaxed);
    ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNERS.store(0, Ordering::Relaxed);
    ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNED_BYTES.store(0, Ordering::Relaxed);
    for counter in [
        &PAYLOAD_VISIT_BYTES_OWNERS,
        &PAYLOAD_VISIT_BYTES_COPIED_BYTES,
        &PAYLOAD_VISIT_BYTE_BUF_OWNERS,
        &PAYLOAD_SEQUENCE_CHUNK_ALLOCATIONS,
        &PAYLOAD_SEQUENCE_CHUNK_CAPACITY_BYTES,
        &PAYLOAD_SEQUENCE_STAGED_BYTES,
        &PAYLOAD_SEQUENCE_FINAL_ALLOCATIONS,
        &PAYLOAD_SEQUENCE_FINAL_ALLOCATION_BYTES,
        &PAYLOAD_SEQUENCE_FINAL_COPIED_BYTES,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub(crate) fn acquire_encrypted_session_payload_ownership_test_permit(
) -> std::sync::MutexGuard<'static, ()> {
    ENCRYPTED_SESSION_PAYLOAD_OWNERSHIP_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptedSessionPayloadOwnershipCounters {
    pub(crate) initial_owners: u64,
    pub(crate) initial_owned_bytes: u64,
    pub(crate) handle_clones: u64,
    pub(crate) deserialized_owners: u64,
    pub(crate) visit_bytes_owners: u64,
    pub(crate) visit_bytes_copied_bytes: u64,
    pub(crate) visit_byte_buf_owners: u64,
    pub(crate) sequence_chunk_allocations: u64,
    pub(crate) sequence_chunk_capacity_bytes: u64,
    pub(crate) sequence_staged_bytes: u64,
    pub(crate) sequence_final_allocations: u64,
    pub(crate) sequence_final_allocation_bytes: u64,
    pub(crate) sequence_final_copied_bytes: u64,
}

#[cfg(test)]
pub(crate) fn encrypted_session_payload_ownership_counters(
) -> EncryptedSessionPayloadOwnershipCounters {
    use std::sync::atomic::Ordering;
    EncryptedSessionPayloadOwnershipCounters {
        initial_owners: ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNERS.load(Ordering::Relaxed),
        initial_owned_bytes: ENCRYPTED_SESSION_PAYLOAD_INITIAL_OWNED_BYTES.load(Ordering::Relaxed),
        handle_clones: ENCRYPTED_SESSION_PAYLOAD_HANDLE_CLONES.load(Ordering::Relaxed),
        deserialized_owners: ENCRYPTED_SESSION_PAYLOAD_DESERIALIZED_OWNERS.load(Ordering::Relaxed),
        visit_bytes_owners: PAYLOAD_VISIT_BYTES_OWNERS.load(Ordering::Relaxed),
        visit_bytes_copied_bytes: PAYLOAD_VISIT_BYTES_COPIED_BYTES.load(Ordering::Relaxed),
        visit_byte_buf_owners: PAYLOAD_VISIT_BYTE_BUF_OWNERS.load(Ordering::Relaxed),
        sequence_chunk_allocations: PAYLOAD_SEQUENCE_CHUNK_ALLOCATIONS.load(Ordering::Relaxed),
        sequence_chunk_capacity_bytes: PAYLOAD_SEQUENCE_CHUNK_CAPACITY_BYTES
            .load(Ordering::Relaxed),
        sequence_staged_bytes: PAYLOAD_SEQUENCE_STAGED_BYTES.load(Ordering::Relaxed),
        sequence_final_allocations: PAYLOAD_SEQUENCE_FINAL_ALLOCATIONS.load(Ordering::Relaxed),
        sequence_final_allocation_bytes: PAYLOAD_SEQUENCE_FINAL_ALLOCATION_BYTES
            .load(Ordering::Relaxed),
        sequence_final_copied_bytes: PAYLOAD_SEQUENCE_FINAL_COPIED_BYTES.load(Ordering::Relaxed),
    }
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
            bytes: WipingPayloadBytes,
            encoding: SessionPayloadEncoding,
        }
        let helper = Helper::deserialize(deserializer)?;
        #[cfg(test)]
        ENCRYPTED_SESSION_PAYLOAD_DESERIALIZED_OWNERS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self::try_from_zeroizing_with_encoding(helper.bytes.0, helper.encoding)
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
        #[cfg(test)]
        note_encrypted_session_payload_initial_bytes(bytes.len());
        Self {
            bytes: Arc::new(bytes),
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
        Self::try_from_zeroizing_with_encoding(Zeroizing::new(bytes), encoding)
    }

    fn try_from_zeroizing_with_encoding(
        bytes: Zeroizing<Vec<u8>>,
        encoding: SessionPayloadEncoding,
    ) -> Result<Self, StoreError> {
        #[cfg(test)]
        note_encrypted_session_payload_initial_bytes(bytes.len());
        let payload = Self {
            bytes: Arc::new(bytes),
            encoding,
        };
        if encoding == SessionPayloadEncoding::EnvelopeV1 {
            payload.decode_valid_session_envelope()?;
        }
        Ok(payload)
    }

    fn from_vec_unchecked(bytes: Vec<u8>, encoding: SessionPayloadEncoding) -> Self {
        #[cfg(test)]
        note_encrypted_session_payload_initial_bytes(bytes.len());
        Self {
            bytes: Arc::new(Zeroizing::new(bytes)),
            encoding,
        }
    }

    /// Raw payload bytes in their current encoding: AEAD envelope bytes for
    /// `EnvelopeV1`, plaintext otherwise. Check `encoding` before
    /// interpreting them.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref().as_slice()
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
        let EnvelopeMetadata::Session(session) = aad.metadata() else {
            return Err(invalid_session_envelope());
        };
        if aad.tenant() != &record.key.tenant
            || session.nf_kind() != record.key.nf_kind.as_str()
            || session.state_type() != record.state_type.as_str()
            || session.generation() != record.generation.get()
            || session.fence() != record.fence.get()
        {
            return Err(invalid_session_envelope());
        }
        Ok(())
    }

    fn decode_valid_session_envelope(&self) -> Result<(CryptoEnvelopeV1, EnvelopeAad), StoreError> {
        if self.encoding != SessionPayloadEncoding::EnvelopeV1 || self.bytes.is_empty() {
            return Err(invalid_session_envelope());
        }
        let envelope = CryptoEnvelopeV1::decode(self.bytes.as_ref().as_slice())
            .map_err(|_| invalid_session_envelope())?;
        if envelope.nonce.len() != envelope.algorithm.nonce_len()
            || envelope.ciphertext_and_tag.len() < AEAD_TAG_LEN
            || envelope
                .encode()
                .map_err(|_| invalid_session_envelope())?
                .as_slice()
                != self.bytes.as_ref().as_slice()
        {
            return Err(invalid_session_envelope());
        }
        let (aad, aad_key_id) =
            decode_bound_aad(&envelope.aad).map_err(|_| invalid_session_envelope())?;
        if aad_key_id != envelope.key_id
            || aad.purpose() != KeyPurpose::Session
            || aad.version() != SESSION_ENVELOPE_VERSION
            || !matches!(aad.metadata(), EnvelopeMetadata::Session(_))
        {
            return Err(invalid_session_envelope());
        }
        Ok((envelope, aad))
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
            SessionPayloadEncoding::Plaintext => return Ok((*self.bytes).clone()),
            SessionPayloadEncoding::LegacyPlaintext => return Ok((*self.bytes).clone()),
            SessionPayloadEncoding::Unclassified => {
                match CryptoEnvelopeV1::decode(self.bytes.as_ref().as_slice()) {
                    Ok(envelope) => envelope,
                    Err(_) => return Ok((*self.bytes).clone()),
                }
            }
            SessionPayloadEncoding::EnvelopeV1 => {
                if self.bytes.is_empty() {
                    return Err(StoreError::Crypto(
                        SESSION_ENVELOPE_MISSING_CIPHERTEXT_MESSAGE.into(),
                    ));
                }

                CryptoEnvelopeV1::decode(self.bytes.as_ref().as_slice()).map_err(|_| {
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
            SessionPayloadEncoding::Plaintext => return Ok((*self.bytes).clone()),
            SessionPayloadEncoding::LegacyPlaintext => return Ok((*self.bytes).clone()),
            SessionPayloadEncoding::Unclassified => {
                match CryptoEnvelopeV1::decode(self.bytes.as_ref().as_slice()) {
                    Ok(envelope) => envelope,
                    Err(_) => return Ok((*self.bytes).clone()),
                }
            }
            SessionPayloadEncoding::EnvelopeV1 => {
                if self.bytes.is_empty() {
                    return Err(StoreError::Crypto(
                        SESSION_ENVELOPE_MISSING_CIPHERTEXT_MESSAGE.into(),
                    ));
                }

                CryptoEnvelopeV1::decode(self.bytes.as_ref().as_slice()).map_err(|_| {
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
            .unseal(&envelope.key_id, &aad, &envelope.ciphertext_and_tag)
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

#[cfg(test)]
mod tests {
    use super::WipingPayloadBytes;
    use serde::{de, Deserialize};

    struct BytesOnlyDeserializer<'a>(&'a [u8]);

    impl<'de> serde::Deserializer<'de> for BytesOnlyDeserializer<'de> {
        type Error = de::value::Error;

        fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: de::Visitor<'de>,
        {
            Err(de::Error::custom("expected the sequence data model"))
        }

        fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: de::Visitor<'de>,
        {
            visitor.visit_bytes(self.0)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct tuple tuple_struct map struct
            enum identifier ignored_any
        }
    }

    struct ByteBufOnlyDeserializer(Vec<u8>);

    impl<'de> serde::Deserializer<'de> for ByteBufOnlyDeserializer {
        type Error = de::value::Error;

        fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: de::Visitor<'de>,
        {
            Err(de::Error::custom("expected the sequence data model"))
        }

        fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: de::Visitor<'de>,
        {
            visitor.visit_byte_buf(self.0)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct tuple tuple_struct map struct
            enum identifier ignored_any
        }
    }

    struct SequenceOnlyDeserializer;

    impl<'de> serde::Deserializer<'de> for SequenceOnlyDeserializer {
        type Error = de::value::Error;

        fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: de::Visitor<'de>,
        {
            Err(de::Error::custom("expected the sequence data model"))
        }

        fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: de::Visitor<'de>,
        {
            visitor.visit_seq(de::value::SeqDeserializer::<_, Self::Error>::new(
                std::iter::once(0xa5_u8),
            ))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct tuple tuple_struct map struct
            enum identifier ignored_any
        }
    }

    #[test]
    fn payload_deserialization_preserves_the_generic_sequence_wire_contract() {
        let _permit = super::acquire_encrypted_session_payload_ownership_test_permit();
        super::reset_encrypted_session_payload_ownership_counters();
        let payload = WipingPayloadBytes::deserialize(SequenceOnlyDeserializer)
            .expect("the payload byte field must request a Serde sequence");
        assert_eq!(payload.0.as_slice(), &[0xa5]);
        let counters = super::encrypted_session_payload_ownership_counters();
        assert_eq!(
            counters.sequence_chunk_allocations, 1,
            "the generic-sequence decoder retains one zeroizing staging chunk: {counters:?}"
        );
        assert_eq!(
            counters.sequence_final_allocations, 1,
            "a nonempty generic sequence makes its one final zeroizing output allocation"
        );
    }

    #[test]
    fn payload_deserialization_counts_borrowed_copy_and_owned_adoption() {
        let _permit = super::acquire_encrypted_session_payload_ownership_test_permit();
        super::reset_encrypted_session_payload_ownership_counters();
        let copied = WipingPayloadBytes::deserialize(BytesOnlyDeserializer(b"ciphertext"))
            .expect("borrowed bytes deserialize");
        assert_eq!(copied.0.as_slice(), b"ciphertext");
        let counters = super::encrypted_session_payload_ownership_counters();
        assert_eq!(counters.visit_bytes_owners, 1);
        assert_eq!(counters.visit_bytes_copied_bytes, 10);
        assert_eq!(counters.visit_byte_buf_owners, 0);

        super::reset_encrypted_session_payload_ownership_counters();
        let adopted =
            WipingPayloadBytes::deserialize(ByteBufOnlyDeserializer(b"ciphertext".to_vec()))
                .expect("owned bytes deserialize");
        assert_eq!(adopted.0.as_slice(), b"ciphertext");
        let counters = super::encrypted_session_payload_ownership_counters();
        assert_eq!(counters.visit_bytes_owners, 0);
        assert_eq!(counters.visit_bytes_copied_bytes, 0);
        assert_eq!(counters.visit_byte_buf_owners, 1);
    }
}
