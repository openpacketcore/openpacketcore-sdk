//! Ephemeral provider verification of exact source/destination configuration.
//! This is authority preparation, not an offline recipient verification API.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{TargetEncryptedBlobV1, TargetSourceV1};
use crate::audit_authority::AuditAuthorityError;
use crate::consensus::PreparedConfigCommit;

const V2_MAGIC: &[u8] = b"\x89OPCCFG\x02\r\n\x1a\n";
const CONFIG_FIRST: &[u8] = b"{\"config\":";

// Match the existing SDK writer's wrapper without allocating or interpreting
// configuration values. Unknown or duplicate metadata fields are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapper {
    #[serde(rename = "config")]
    _config: serde::de::IgnoredAny,
    #[serde(default, rename = "source")]
    _source: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "idempotency_key")]
    _idempotency_key: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "apply_plan")]
    _apply_plan: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "request_fingerprint")]
    _request_fingerprint: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "request_id")]
    _request_id: Option<serde::de::IgnoredAny>,
}

pub(super) fn configuration_bytes(plaintext: &[u8]) -> Result<&[u8], AuditAuthorityError> {
    let bad = AuditAuthorityError::BindingMismatch;
    let Some(encoded) = plaintext.strip_prefix(V2_MAGIC) else {
        // Original config-only JSON has no binary prefix. Do not normalize it:
        // exact serialized configuration bytes must survive a copy unchanged.
        serde_json::from_slice::<serde::de::IgnoredAny>(plaintext).map_err(|_| bad)?;
        return Ok(plaintext);
    };
    serde_json::from_slice::<Wrapper>(encoded).map_err(|_| bad)?;
    let value = encoded.strip_prefix(CONFIG_FIRST).ok_or(bad)?;
    let mut stream =
        serde_json::Deserializer::from_slice(value).into_iter::<serde::de::IgnoredAny>();
    stream.next().ok_or(bad)?.map_err(|_| bad)?;
    value.get(..stream.byte_offset()).ok_or(bad)
}

/// Only provider-authenticated preparation constructs this binding. Decoding
/// one is not authentication: the whole closed effect still needs its original
/// authority MAC, and application rechecks the exact retained source.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetCopyBindingV1 {
    source_ciphertext_digest: [u8; 32],
    source_plaintext_digest: [u8; 32],
    destination_ciphertext_digest: [u8; 32],
    destination_plaintext_digest: [u8; 32],
    schema: opc_types::SchemaDigest,
}

impl TargetCopyBindingV1 {
    pub(super) async fn prepare(
        provider: &dyn opc_key::KeyProvider,
        source: &TargetEncryptedBlobV1,
        destination: &PreparedConfigCommit,
    ) -> Result<Self, AuditAuthorityError> {
        let bad = AuditAuthorityError::BindingMismatch;
        source.validate()?;
        destination.validate().map_err(|_| bad)?;
        let record = &destination.record;
        if source.schema != record.schema_digest {
            return Err(bad);
        }
        let source_envelope =
            opc_crypto::CryptoEnvelopeRef::decode(&source.encrypted_blob).map_err(|_| bad)?;
        let destination_envelope =
            opc_crypto::CryptoEnvelopeRef::decode(&record.encrypted_blob).map_err(|_| bad)?;
        let (source_aad, _) = opc_key::decode_bound_aad(source_envelope.aad).map_err(|_| bad)?;
        let (destination_aad, _) =
            opc_key::decode_bound_aad(destination_envelope.aad).map_err(|_| bad)?;
        if source_aad.tenant() != destination_aad.tenant() {
            return Err(bad);
        }
        // The provider owns AEAD key custody. Plaintext exists only in the
        // existing zeroizing return buffers; it never enters a command or row.
        let source_plaintext =
            opc_crypto::decrypt_envelope(provider, &source_aad, &source.encrypted_blob)
                .await
                .map_err(|_| AuditAuthorityError::Unavailable)?;
        let destination_plaintext =
            opc_crypto::decrypt_envelope(provider, &destination_aad, &record.encrypted_blob)
                .await
                .map_err(|_| AuditAuthorityError::Unavailable)?;
        let source_digest: [u8; 32] = Sha256::digest(source_plaintext.as_slice()).into();
        let destination_digest: [u8; 32] = Sha256::digest(destination_plaintext.as_slice()).into();
        if source_digest != source.plaintext_digest
            || destination_digest.as_slice() != record.plaintext_digest
            || configuration_bytes(&source_plaintext)?
                != configuration_bytes(&destination_plaintext)?
        {
            return Err(bad);
        }
        Ok(Self {
            source_ciphertext_digest: Sha256::digest(&source.encrypted_blob).into(),
            source_plaintext_digest: source_digest,
            destination_ciphertext_digest: Sha256::digest(&record.encrypted_blob).into(),
            destination_plaintext_digest: destination_digest,
            schema: source.schema,
        })
    }

    pub(super) fn validate(
        &self,
        source: Option<&TargetSourceV1>,
        destination: &PreparedConfigCommit,
    ) -> Result<(), AuditAuthorityError> {
        let bad = AuditAuthorityError::BindingMismatch;
        let (schema, ciphertext) = match source.ok_or(bad)? {
            TargetSourceV1::Running {
                schema,
                ciphertext_digest,
                ..
            }
            | TargetSourceV1::Candidate {
                schema,
                ciphertext_digest,
                ..
            }
            | TargetSourceV1::Startup {
                schema,
                ciphertext_digest,
                ..
            }
            | TargetSourceV1::CandidateFallback {
                schema,
                ciphertext_digest,
                ..
            } => (schema, ciphertext_digest),
        };
        if *schema != self.schema
            || *ciphertext != self.source_ciphertext_digest
            || self.schema != destination.record.schema_digest
            || self.destination_plaintext_digest.as_slice() != destination.record.plaintext_digest
            || self.destination_ciphertext_digest
                != <[u8; 32]>::from(Sha256::digest(&destination.record.encrypted_blob))
        {
            return Err(bad);
        }
        Ok(())
    }

    pub(super) fn matches_source_digest(&self, digest: &[u8]) -> bool {
        self.source_plaintext_digest == digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped(suffix: &[u8]) -> Vec<u8> {
        [V2_MAGIC, suffix].concat()
    }

    #[test]
    fn target_copy_codec_preserves_exact_configuration_bytes_across_replay_wrappers() {
        let config = br#"{"limit":18446744073709551617,"nested":["\u0061",{"v":-0.0}]}"#;
        let mut first = [V2_MAGIC, CONFIG_FIRST, config].concat();
        first.extend_from_slice(br#", "source":"Northbound","request_id":"synthetic-one"}"#);
        let mut second = [V2_MAGIC, CONFIG_FIRST, config].concat();
        second.extend_from_slice(br#", "request_id":"synthetic-two","idempotency_key":"synthetic-key","apply_plan":null,"request_fingerprint":null}"#);
        assert_eq!(configuration_bytes(config).unwrap(), config);
        assert_eq!(configuration_bytes(&first).unwrap(), config);
        assert_eq!(configuration_bytes(&second).unwrap(), config);
        assert_ne!(first, second);
    }

    #[test]
    fn target_copy_codec_refuses_ambiguous_unknown_and_incomplete_wrappers() {
        for value in [
            br#"{"config":null,"config":null}"#.as_slice(),
            br#"{"config":null,"request_id":null,"request_id":null}"#,
            br#"{"config":null,"unknown":null}"#,
            br#"{"request_id":null,"config":null}"#,
            br#"{"source":null}"#,
            br#"{"config":null"#,
            br#"{"config":null}true"#,
            b"null",
        ] {
            assert_eq!(
                configuration_bytes(&wrapped(value)),
                Err(AuditAuthorityError::BindingMismatch)
            );
        }
        for value in [
            b"".as_slice(),
            b"null false",
            b"\x89OPCCFG\x03\r\n\x1a\n{\"config\":null}",
        ] {
            assert_eq!(
                configuration_bytes(value),
                Err(AuditAuthorityError::BindingMismatch)
            );
        }
    }
}
