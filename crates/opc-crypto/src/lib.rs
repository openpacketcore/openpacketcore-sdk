//! AEAD envelope encoding and decryption helpers.
//!
//! RFC 001 defines the envelope wire format, while RFC 003 and RFC 004 require
//! AAD binding across tenant, purpose, version, and schema/session metadata.
//! This crate ties the envelope header to [`opc_key::KeyProvider`] lookups and
//! returns redacted integrity failures for wrong keys, wrong AAD, corrupt tags,
//! and unknown key IDs.

#![forbid(unsafe_code)]

use opc_key::{
    AeadAlgorithm, EnvelopeAad, KeyHandle, KeyId, KeyProvider, Zeroizing, AEAD_TAG_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use rand::{rngs::SysRng, TryRng};
use thiserror::Error;

const ENVELOPE_MAGIC: [u8; 4] = *b"OPCE";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_LEN: usize = 4 + 2 + 2 + 2 + 2 + 4;

/// Decoded RFC 001 envelope structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoEnvelopeV1 {
    pub algorithm: AeadAlgorithm,
    pub key_id: KeyId,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub ciphertext_and_tag: Vec<u8>,
}

impl CryptoEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let key_id = self.key_id.as_str().as_bytes();
        let key_id_len = u16::try_from(key_id.len()).map_err(|_| CryptoError::InvalidEnvelope)?;
        let nonce_len =
            u16::try_from(self.nonce.len()).map_err(|_| CryptoError::InvalidEnvelope)?;
        let aad_len = u32::try_from(self.aad.len()).map_err(|_| CryptoError::InvalidEnvelope)?;

        let mut out = Vec::with_capacity(
            HEADER_LEN
                + key_id.len()
                + self.nonce.len()
                + self.aad.len()
                + self.ciphertext_and_tag.len(),
        );
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.algorithm.id().to_be_bytes());
        out.extend_from_slice(&key_id_len.to_be_bytes());
        out.extend_from_slice(&nonce_len.to_be_bytes());
        out.extend_from_slice(&aad_len.to_be_bytes());
        out.extend_from_slice(key_id);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.aad);
        out.extend_from_slice(&self.ciphertext_and_tag);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < HEADER_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }

        if bytes[..4] != ENVELOPE_MAGIC {
            return Err(CryptoError::InvalidEnvelope);
        }

        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != ENVELOPE_VERSION {
            return Err(CryptoError::InvalidEnvelope);
        }

        let algorithm = AeadAlgorithm::from_id(u16::from_be_bytes([bytes[6], bytes[7]]))
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let key_id_len = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
        let nonce_len = usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
        let aad_len = usize::try_from(u32::from_be_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]))
        .map_err(|_| CryptoError::InvalidEnvelope)?;

        let payload_offset = HEADER_LEN
            .checked_add(key_id_len)
            .and_then(|value| value.checked_add(nonce_len))
            .and_then(|value| value.checked_add(aad_len))
            .ok_or(CryptoError::InvalidEnvelope)?;
        if payload_offset > bytes.len() {
            return Err(CryptoError::InvalidEnvelope);
        }

        let key_id_end = HEADER_LEN + key_id_len;
        let nonce_end = key_id_end + nonce_len;
        let aad_end = nonce_end + aad_len;
        let ciphertext_and_tag = bytes[aad_end..].to_vec();
        if ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }

        let key_id = std::str::from_utf8(&bytes[HEADER_LEN..key_id_end])
            .map_err(|_| CryptoError::InvalidEnvelope)?;

        Ok(Self {
            algorithm,
            key_id: KeyId::new(key_id.to_owned()).map_err(|_| CryptoError::InvalidEnvelope)?,
            nonce: bytes[key_id_end..nonce_end].to_vec(),
            aad: bytes[nonce_end..aad_end].to_vec(),
            ciphertext_and_tag,
        })
    }
}

/// Redacted envelope-operation failures.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("invalid envelope encoding")]
    InvalidEnvelope,
    #[error("envelope encryption failed")]
    EncryptionFailed,
    #[error("envelope decryption failed")]
    DecryptionFailed,
}

pub async fn encrypt_envelope<P: KeyProvider + ?Sized>(
    provider: &P,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0_u8; AES_256_GCM_SIV_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    encrypt_envelope_with_nonce(provider, aad, plaintext, nonce).await
}

/// Deterministic encryption for test vectors.
///
/// Callers MUST NOT reuse a nonce with the same key. Prefer [`encrypt_envelope`]
/// for production use.
pub async fn encrypt_envelope_with_nonce<P: KeyProvider + ?Sized>(
    provider: &P,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let handle = provider
        .get_active_key(aad.purpose(), aad.tenant())
        .await
        .map_err(|_| CryptoError::EncryptionFailed)?;
    encrypt_envelope_with_handle_and_nonce(&handle, aad, plaintext, nonce)
}

pub fn encrypt_envelope_with_handle(
    handle: &KeyHandle,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0_u8; AES_256_GCM_SIV_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    encrypt_envelope_with_handle_and_nonce(handle, aad, plaintext, nonce)
}

/// Deterministic encryption with a pre-selected key handle for test vectors
/// and callers that must bind AAD to the same handle used for encryption.
///
/// Callers MUST NOT reuse a nonce with the same key.
pub fn encrypt_envelope_with_handle_and_nonce(
    handle: &KeyHandle,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let payload = handle
        .encrypt_payload(aad, plaintext, nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    CryptoEnvelopeV1 {
        algorithm: handle.algorithm(),
        key_id: handle.key_id().clone(),
        nonce: nonce.to_vec(),
        aad: payload.aad,
        ciphertext_and_tag: payload.ciphertext_and_tag,
    }
    .encode()
}

pub fn decrypt_envelope_with_handle(
    handle: &KeyHandle,
    expected_aad: &EnvelopeAad,
    envelope_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let envelope =
        CryptoEnvelopeV1::decode(envelope_bytes).map_err(|_| CryptoError::DecryptionFailed)?;
    decrypt_decoded_envelope_with_handle(handle, expected_aad, &envelope)
}

/// Decrypt a pre-decoded RFC 001 envelope with a pre-selected key handle.
pub fn decrypt_decoded_envelope_with_handle(
    handle: &KeyHandle,
    expected_aad: &EnvelopeAad,
    envelope: &CryptoEnvelopeV1,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if &envelope.key_id != handle.key_id() {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce = decode_nonce(envelope)?;

    verify_algorithm(handle, envelope.algorithm)?;
    handle
        .decrypt_payload(
            expected_aad,
            &envelope.aad,
            &envelope.ciphertext_and_tag,
            nonce,
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub async fn decrypt_envelope<P: KeyProvider + ?Sized>(
    provider: &P,
    expected_aad: &EnvelopeAad,
    envelope_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let envelope =
        CryptoEnvelopeV1::decode(envelope_bytes).map_err(|_| CryptoError::DecryptionFailed)?;
    let handle = provider
        .get_key_by_id(&envelope.key_id)
        .await
        .map_err(|_| CryptoError::DecryptionFailed)?;

    decrypt_decoded_envelope_with_handle(&handle, expected_aad, &envelope)
}

fn decode_nonce(
    envelope: &CryptoEnvelopeV1,
) -> Result<[u8; AES_256_GCM_SIV_NONCE_LEN], CryptoError> {
    if envelope.nonce.len() != AES_256_GCM_SIV_NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut nonce = [0_u8; AES_256_GCM_SIV_NONCE_LEN];
    nonce.copy_from_slice(&envelope.nonce);
    Ok(nonce)
}

fn verify_algorithm(handle: &KeyHandle, algorithm: AeadAlgorithm) -> Result<(), CryptoError> {
    if handle.algorithm() != algorithm {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_key::{ConfigAad, KeyPurpose, MemoryKeyProvider, SessionAad, Zeroizing};
    use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};
    use std::str::FromStr;

    fn tenant() -> TenantId {
        TenantId::new("tenant-a").expect("tenant")
    }

    fn config_aad() -> EnvelopeAad {
        EnvelopeAad::config(
            tenant(),
            9,
            ConfigAad::new(
                TxId::from_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("tx id"),
                Some(TxId::from_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("tx id")),
                Timestamp::from_str("2026-05-28T08:30:00Z").expect("timestamp"),
                "spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
                SchemaDigest::from_str(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("schema digest"),
                "running",
            )
            .expect("valid config aad"),
        )
    }

    fn config_metadata() -> ConfigAad {
        ConfigAad::new(
            TxId::from_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("tx id"),
            Some(TxId::from_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("tx id")),
            Timestamp::from_str("2026-05-28T08:30:00Z").expect("timestamp"),
            "spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
            SchemaDigest::from_str(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("schema digest"),
            "running",
        )
        .expect("valid config aad")
    }

    fn session_aad() -> EnvelopeAad {
        EnvelopeAad::session(tenant(), 3, session_metadata("amf-registration-context"))
    }

    fn session_metadata(state_type: &str) -> SessionAad {
        SessionAad::new("amf", "sub-a1f5f3d9", state_type, 42, 7, "regional-cache-a")
            .expect("valid session aad")
    }

    fn provider_with_active_key(
        purpose: KeyPurpose,
        key_id: &str,
        secret: u8,
    ) -> MemoryKeyProvider {
        let provider = MemoryKeyProvider::new();
        provider
            .insert_active_key(
                KeyId::new(key_id).expect("key id"),
                purpose,
                tenant(),
                Zeroizing::new([secret; 32]),
            )
            .expect("insert active key");
        provider
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[tokio::test]
    async fn deterministic_config_envelope_round_trip() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x41);
        let nonce = *b"0123456789ab";
        let plaintext = br#"{"hostname":"amf-01"}"#;
        let aad = config_aad();

        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");
        let round_trip = decrypt_envelope(&provider, &aad, &encoded)
            .await
            .expect("decrypt");

        assert_eq!(round_trip.as_slice(), plaintext);
        assert_eq!(
            encoded,
            encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
                .await
                .expect("deterministic re-encrypt")
        );
        assert_eq!(
            hex(&encoded),
            "4f504345000100010012000c000001c8636f6e6669672d6b65792d323032362d30313031323334353637383961627b2274656e616e74223a2274656e616e742d61222c22707572706f7365223a22636f6e666967222c2276657273696f6e223a392c226b65795f6964223a22636f6e6669672d6b65792d323032362d3031222c226d65746164617461223a7b226b696e64223a22636f6e666967222c2274785f6964223a2261616161616161612d616161612d346161612d386161612d616161616161616161616161222c22706172656e745f74785f6964223a2262626262626262622d626262622d346262622d386262622d626262626262626262626262222c22636f6d6d69747465645f6174223a22323032362d30352d32385430383a33303a30305a222c227072696e636970616c223a227370696666653a2f2f636f72652e6578616d706c652f74656e616e742f74656e616e742d612f6e732f636f72652f73612f636f6e6669672d7772697465722f6e662f616d662f696e7374616e63652f616d662d3031222c22736368656d615f646967657374223a2230313233343536373839616263646566303132333435363738396162636465663031323334353637383961626364656630313233343536373839616263646566222c2273746f72655f6b696e64223a2272756e6e696e67227d7de5fd7c442206ff6206123d9ad41b4f53ae45f776edfd64d21e3e02c0f7a6dce07054f6313e"
        );
    }

    #[tokio::test]
    async fn production_encrypt_envelope_round_trip() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x41);
        let plaintext = br#"{"hostname":"amf-01"}"#;
        let aad = config_aad();

        let encoded = encrypt_envelope(&provider, &aad, plaintext)
            .await
            .expect("encrypt");
        let envelope = CryptoEnvelopeV1::decode(&encoded).expect("decode");
        let round_trip = decrypt_envelope(&provider, &aad, &encoded)
            .await
            .expect("decrypt");

        assert_eq!(round_trip.as_slice(), plaintext);
        assert_eq!(envelope.nonce.len(), AES_256_GCM_SIV_NONCE_LEN);
    }

    #[tokio::test]
    async fn decoded_envelope_round_trips_with_prefetched_handle() {
        let provider = provider_with_active_key(KeyPurpose::Session, "session-key-2026-01", 0x33);
        let plaintext = b"amf session snapshot";
        let aad = session_aad();
        let nonce = *b"abcdefghijkl";

        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");
        let envelope = CryptoEnvelopeV1::decode(&encoded).expect("decode");
        let handle = provider
            .get_key_by_id(&envelope.key_id)
            .await
            .expect("handle");

        let decrypted =
            decrypt_decoded_envelope_with_handle(&handle, &aad, &envelope).expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn decrypt_rejects_wrong_key_aad_corrupt_tag_and_unknown_key_id_with_redacted_errors() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x11);
        let aad = config_aad();
        let nonce = *b"0123456789ab";
        let plaintext = b"secret payload";
        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");

        let wrong_tenant_aad = EnvelopeAad::config(
            TenantId::new("tenant-b").expect("tenant"),
            aad.version(),
            config_metadata(),
        );
        let wrong_aad_err = decrypt_envelope(&provider, &wrong_tenant_aad, &encoded)
            .await
            .expect_err("wrong aad should fail");

        let wrong_key_provider =
            provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x7f);
        let wrong_key_err = decrypt_envelope(&wrong_key_provider, &aad, &encoded)
            .await
            .expect_err("wrong key should fail");

        let mut corrupt = encoded.clone();
        let last = corrupt.last_mut().expect("tag byte");
        *last ^= 0x01;
        let corrupt_err = decrypt_envelope(&provider, &aad, &corrupt)
            .await
            .expect_err("corrupt tag should fail");

        let mut unknown = CryptoEnvelopeV1::decode(&encoded).expect("decode");
        unknown.key_id = KeyId::new("config-key-2026-missing").expect("key id");
        let unknown = unknown.encode().expect("encode");
        let unknown_key_err = decrypt_envelope(&provider, &aad, &unknown)
            .await
            .expect_err("unknown key should fail");

        for err in [wrong_aad_err, wrong_key_err, corrupt_err, unknown_key_err] {
            assert_eq!(err, CryptoError::DecryptionFailed);
            assert_eq!(err.to_string(), "envelope decryption failed");
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_version_only_mismatch() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x11);
        let aad = config_aad();
        let nonce = *b"0123456789ab";
        let plaintext = b"secret payload";
        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");

        let wrong_version = EnvelopeAad::config(tenant(), aad.version() + 1, config_metadata());

        let err = decrypt_envelope(&provider, &wrong_version, &encoded)
            .await
            .expect_err("version mismatch should fail");
        assert_eq!(err, CryptoError::DecryptionFailed);
    }

    #[tokio::test]
    async fn decrypt_rejects_wrong_key_lane_aad() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x11);
        let aad = config_aad();
        let nonce = *b"0123456789ab";
        let plaintext = b"secret payload";
        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");

        let wrong_purpose = EnvelopeAad::session(
            tenant(),
            aad.version(),
            session_metadata("amf-registration-context"),
        );

        let err = decrypt_envelope(&provider, &wrong_purpose, &encoded)
            .await
            .expect_err("wrong key lane should fail");
        assert_eq!(err, CryptoError::DecryptionFailed);
        assert_eq!(err.to_string(), "envelope decryption failed");
    }

    #[tokio::test]
    async fn session_state_metadata_is_bound_into_aad() {
        let provider = provider_with_active_key(KeyPurpose::Session, "session-key-2026-01", 0x33);
        let nonce = *b"abcdefghijkl";
        let plaintext = b"amf session snapshot";
        let aad = session_aad();
        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");
        let decrypted = decrypt_envelope(&provider, &aad, &encoded)
            .await
            .expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
        assert_eq!(
            encoded,
            encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
                .await
                .expect("deterministic re-encrypt")
        );
        assert_eq!(
            hex(&encoded),
            "4f504345000100010013000c0000010f73657373696f6e2d6b65792d323032362d30316162636465666768696a6b6c7b2274656e616e74223a2274656e616e742d61222c22707572706f7365223a2273657373696f6e222c2276657273696f6e223a332c226b65795f6964223a2273657373696f6e2d6b65792d323032362d3031222c226d65746164617461223a7b226b696e64223a2273657373696f6e222c226e665f6b696e64223a22616d66222c2273657373696f6e5f6b65795f646967657374223a227375622d6131663566336439222c2273746174655f74797065223a22616d662d726567697374726174696f6e2d636f6e74657874222c2267656e65726174696f6e223a34322c2266656e6365223a372c226261636b656e645f6e616d657370616365223a22726567696f6e616c2d63616368652d61227d7dfa64a9e220bbcf2f6345fa4b94f1dbbcf47f422272366d045109fb5b36f972c7d184031b"
        );

        let wrong =
            EnvelopeAad::session(tenant(), aad.version(), session_metadata("smf-pdu-context"));

        let err = decrypt_envelope(&provider, &wrong, &encoded)
            .await
            .expect_err("wrong state metadata should fail");
        assert_eq!(err, CryptoError::DecryptionFailed);
        assert_eq!(err.to_string(), "envelope decryption failed");
    }

    #[tokio::test]
    async fn decrypt_rejects_truncated_ciphertext_and_tag_payload() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x11);
        let aad = config_aad();
        let nonce = *b"0123456789ab";
        let plaintext = b"secret payload";
        let encoded = encrypt_envelope_with_nonce(&provider, &aad, plaintext, nonce)
            .await
            .expect("encrypt");

        let mut truncated = CryptoEnvelopeV1::decode(&encoded).expect("decode");
        truncated.ciphertext_and_tag.truncate(AEAD_TAG_LEN - 1);
        let truncated = truncated.encode().expect("encode");

        let decode_err = CryptoEnvelopeV1::decode(&truncated).expect_err("decode should fail");
        assert_eq!(decode_err, CryptoError::InvalidEnvelope);

        let decrypt_err = decrypt_envelope(&provider, &aad, &truncated)
            .await
            .expect_err("truncated ciphertext must fail");
        assert_eq!(decrypt_err, CryptoError::DecryptionFailed);
        assert_eq!(decrypt_err.to_string(), "envelope decryption failed");
    }

    #[test]
    fn decode_rejects_truncated_envelope() {
        let err = CryptoEnvelopeV1::decode(b"OPCE").expect_err("short buffer should fail");
        assert_eq!(err, CryptoError::InvalidEnvelope);
    }

    #[tokio::test]
    async fn random_nonce_has_full_entropy_and_is_unique() {
        let provider = provider_with_active_key(KeyPurpose::Config, "config-key-2026-01", 0x41);
        let plaintext = br#"{"hostname":"amf-01"}"#;
        let aad = config_aad();

        let encoded1 = encrypt_envelope(&provider, &aad, plaintext)
            .await
            .expect("encrypt");
        let encoded2 = encrypt_envelope(&provider, &aad, plaintext)
            .await
            .expect("encrypt");

        let envelope1 = CryptoEnvelopeV1::decode(&encoded1).expect("decode");
        let envelope2 = CryptoEnvelopeV1::decode(&encoded2).expect("decode");

        assert_eq!(envelope1.nonce.len(), AES_256_GCM_SIV_NONCE_LEN);
        assert_eq!(envelope2.nonce.len(), AES_256_GCM_SIV_NONCE_LEN);
        assert_ne!(
            envelope1.nonce, envelope2.nonce,
            "random nonces must differ"
        );

        let round_trip = decrypt_envelope(&provider, &aad, &encoded1)
            .await
            .expect("decrypt");
        assert_eq!(round_trip.as_slice(), plaintext);
    }
}
