//! Purpose-separated metadata for non-authoritative configuration checkpoints.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::KeyError;

/// Expected consumer scope and exact local storage binding.
///
/// These digests are derived by the SDK checkpoint adapter from its independently
/// admitted consensus identity/epoch, schema, consumer, backing and file identity.
/// They confer neither configuration authoring nor voter authority. The enclosing
/// [`crate::EnvelopeAad`] version is the local checkpoint generation, distinct from
/// the original configuration version retained inside the sealed payload.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ConsumerCheckpointAad {
    pub(crate) binding_digest: [u8; 32],
    pub(crate) storage_digest: [u8; 32],
}

impl ConsumerCheckpointAad {
    /// Bind one checkpoint envelope to exact expected consumer and storage scopes.
    pub fn new(binding_digest: [u8; 32], storage_digest: [u8; 32]) -> Result<Self, KeyError> {
        let value = Self {
            binding_digest,
            storage_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), KeyError> {
        if self.binding_digest == [0; 32] || self.storage_digest == [0; 32] {
            return Err(KeyError::invalid_metadata(
                "consumer_checkpoint",
                "requires nonzero scope bindings",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ConsumerCheckpointAad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerCheckpointAad(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for ConsumerCheckpointAad {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Metadata {
            binding_digest: [u8; 32],
            storage_digest: [u8; 32],
        }
        let metadata = Metadata::deserialize(deserializer)?;
        Self::new(metadata.binding_digest, metadata.storage_digest)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_bound_aad, serialize_bound_aad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing,
    };
    use opc_types::TenantId;

    fn aad(binding: u8, storage: u8, generation: u64) -> EnvelopeAad {
        EnvelopeAad::consumer_checkpoint(
            TenantId::from_static("checkpoint-test"),
            generation,
            ConsumerCheckpointAad::new([binding; 32], [storage; 32]).expect("metadata"),
        )
    }

    #[test]
    fn checkpoint_custody_rejects_scope_storage_generation_and_purpose_confusion() {
        let tenant = TenantId::from_static("checkpoint-test");
        let key_id = KeyId::new("consumer-checkpoint-test-key").expect("key ID");
        let handle = KeyHandle::new(
            key_id.clone(),
            KeyPurpose::ConfigConsumerCheckpoint,
            tenant.clone(),
            Zeroizing::new([0x61; 32]),
        );
        let expected = aad(1, 2, 3);
        let nonce = [0x73; 12];
        let payload = handle
            .encrypt_payload(&expected, b"synthetic checkpoint", nonce)
            .expect("seal");
        assert_eq!(
            handle
                .decrypt_payload(&expected, &payload.aad, &payload.ciphertext_and_tag, nonce)
                .expect("open"),
            b"synthetic checkpoint"
        );
        for wrong in [aad(4, 2, 3), aad(1, 4, 3), aad(1, 2, 4)] {
            assert!(handle
                .decrypt_payload(&wrong, &payload.aad, &payload.ciphertext_and_tag, nonce)
                .is_err());
        }
        let authoring_key = KeyHandle::new(
            key_id,
            KeyPurpose::Config,
            tenant,
            Zeroizing::new([0x61; 32]),
        );
        assert!(authoring_key
            .encrypt_payload(&expected, b"synthetic checkpoint", nonce)
            .is_err());
        assert!(authoring_key
            .decrypt_payload(&expected, &payload.aad, &payload.ciphertext_and_tag, nonce)
            .is_err());
    }

    #[test]
    fn checkpoint_metadata_is_canonical_bounded_and_redacted() {
        let expected = aad(1, 2, 3);
        let key_id = KeyId::new("checkpoint-test-key").expect("key ID");
        let bytes = serialize_bound_aad(&expected, &key_id).expect("encode");
        assert_eq!(
            decode_bound_aad(&bytes).expect("decode"),
            (expected, key_id)
        );
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture");
        value["metadata"]["unrecognized"] = true.into();
        assert!(decode_bound_aad(&serde_json::to_vec(&value).expect("fixture bytes")).is_err());
        assert!(ConsumerCheckpointAad::new([0; 32], [1; 32]).is_err());
        assert!(ConsumerCheckpointAad::new([1; 32], [0; 32]).is_err());
        assert_eq!(
            format!(
                "{:?}",
                ConsumerCheckpointAad::new([0x71; 32], [0x72; 32]).expect("metadata")
            ),
            "ConsumerCheckpointAad(<redacted>)"
        );
    }
}
