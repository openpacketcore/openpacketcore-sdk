//! Authenticated sizes for an exact retained configuration record.
//!
//! This proof is independent of process-local reservations, audit-operation
//! authority and ordinary request-outcome retention. It never creates a fresh
//! encryption claim or authorizes a mutation on its own.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use opc_crypto::{
    ConfigCapacityProfile, CryptoEnvelopeRef, CONFIG_CAPACITY_V1_AAD_BYTES,
    CONFIG_CAPACITY_V1_ENVELOPE_BYTES, CONFIG_CAPACITY_V1_LOGICAL_BYTES,
    CONFIG_CAPACITY_V1_PLAINTEXT_BYTES, CONFIG_CAPACITY_V1_REPLAY_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::{validate_encrypted_record, ConfigConsensusIdentity};
use crate::{AttestedConfigCommit, AuditKey, CommitRecord, PersistError};

const RECORD_CAPACITY_DOMAIN: &[u8] = b"openpacketcore/config-capacity/record/v1\0";
const RECORD_CAPACITY_REVISION: u16 = 1;
const HEADER_BYTES: usize = 12;
pub(super) const RECORD_CAPACITY_BYTES: usize = HEADER_BYTES + 32;

/// Private deterministic data, not evidence of validation merely by decoding.
/// The explicit byte arrays avoid variable-sized proof allocations and retain
/// the same canonical 44-byte representation in the SQL row and postcard field.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapacityRecordBinding {
    header: [u8; HEADER_BYTES],
    tag: [u8; 32],
}

impl CapacityRecordBinding {
    /// The issuer accepts only evidence still paired with the immutable record
    /// by the one-shot encryption claim. It cannot issue from copied counts.
    pub(super) fn issue(
        commit: &AttestedConfigCommit,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
        profile: ConfigCapacityProfile,
    ) -> Result<Self, PersistError> {
        let evidence = commit.capacity_evidence().ok_or_else(invalid)?;
        if profile != ConfigCapacityProfile::BoundedV1 || evidence.profile() != profile {
            return Err(invalid());
        }
        let logical = u32::try_from(evidence.logical_bytes()).map_err(|_| invalid())?;
        let replay = u32::try_from(evidence.replay_bytes()).map_err(|_| invalid())?;
        let mut binding = Self {
            header: [0; HEADER_BYTES],
            tag: [0; 32],
        };
        binding.header[..2].copy_from_slice(&RECORD_CAPACITY_REVISION.to_be_bytes());
        binding.header[2..4].copy_from_slice(&profile.revision().to_be_bytes());
        binding.header[4..8].copy_from_slice(&logical.to_be_bytes());
        binding.header[8..12].copy_from_slice(&replay.to_be_bytes());
        binding.validate_record(commit.record(), profile)?;
        binding.tag = binding
            .mac(commit.record(), identity, key)?
            .finalize()
            .into_bytes()
            .into();
        Ok(binding)
    }

    /// Validate using the independently admitted scope/profile and existing key.
    /// Call within the same immutable command or SQL transaction that consumes
    /// the record. History callers must first reconstruct the original AEAD
    /// parent using the separately authenticated retention boundary.
    pub(super) fn verify(
        &self,
        record: &CommitRecord,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
        profile: ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        self.validate_record(record, profile)?;
        self.mac(record, identity, key)?
            .verify_slice(&self.tag)
            .map_err(|_| invalid())
    }

    pub(super) fn encode(self) -> [u8; RECORD_CAPACITY_BYTES] {
        let mut encoded = [0; RECORD_CAPACITY_BYTES];
        encoded[..HEADER_BYTES].copy_from_slice(&self.header);
        encoded[HEADER_BYTES..].copy_from_slice(&self.tag);
        encoded
    }

    /// Fixed-width parsing alone confers no authenticity or mutation authority.
    pub(super) fn decode(encoded: &[u8]) -> Result<Self, PersistError> {
        if encoded.len() != RECORD_CAPACITY_BYTES {
            return Err(invalid());
        }
        let mut binding = Self {
            header: [0; HEADER_BYTES],
            tag: [0; 32],
        };
        binding.header.copy_from_slice(&encoded[..HEADER_BYTES]);
        binding.tag.copy_from_slice(&encoded[HEADER_BYTES..]);
        Ok(binding)
    }

    fn validate_record(
        &self,
        record: &CommitRecord,
        profile: ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        if profile != ConfigCapacityProfile::BoundedV1
            || self.header[..2] != RECORD_CAPACITY_REVISION.to_be_bytes()
            || self.header[2..4] != profile.revision().to_be_bytes()
            || record.encrypted_blob.len() > CONFIG_CAPACITY_V1_ENVELOPE_BYTES
            || record.plaintext_digest.len() != 32
        {
            return Err(invalid());
        }
        let logical = u32::from_be_bytes([
            self.header[4],
            self.header[5],
            self.header[6],
            self.header[7],
        ]);
        let replay = u32::from_be_bytes([
            self.header[8],
            self.header[9],
            self.header[10],
            self.header[11],
        ]);
        let logical = usize::try_from(logical).map_err(|_| invalid())?;
        let replay = usize::try_from(replay).map_err(|_| invalid())?;
        let plaintext = logical.checked_add(replay).ok_or_else(invalid)?;
        if logical == 0
            || logical > CONFIG_CAPACITY_V1_LOGICAL_BYTES
            || replay > CONFIG_CAPACITY_V1_REPLAY_BYTES
            || plaintext > CONFIG_CAPACITY_V1_PLAINTEXT_BYTES
        {
            return Err(invalid());
        }
        preflight_envelope_lengths(&record.encrypted_blob)?;
        let envelope = CryptoEnvelopeRef::decode(&record.encrypted_blob).map_err(|_| invalid())?;
        if envelope.algorithm != opc_key::AeadAlgorithm::Aes256GcmSiv
            || envelope.nonce.len() != opc_key::AES_256_GCM_SIV_NONCE_LEN
            || envelope.aad.len() > CONFIG_CAPACITY_V1_AAD_BYTES
            || envelope
                .ciphertext_and_tag
                .len()
                .checked_sub(opc_key::AEAD_TAG_LEN)
                != Some(plaintext)
        {
            return Err(invalid());
        }
        // Bounded framing is checked before the existing AAD decoder. This
        // also checks key-ID, tenant, parent, transaction, timestamp, principal,
        // schema and version against the envelope without decrypting it.
        validate_encrypted_record(record).map_err(|_| invalid())
    }

    fn mac(
        &self,
        record: &CommitRecord,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
    ) -> Result<Hmac<Sha256>, PersistError> {
        let envelope_bytes = u64::try_from(record.encrypted_blob.len()).map_err(|_| invalid())?;
        if record.plaintext_digest.len() != 32 {
            return Err(invalid());
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| invalid())?;
        mac.update(RECORD_CAPACITY_DOMAIN);
        mac.update(&self.header);
        mac.update(&key.epoch().to_be_bytes());
        mac.update(identity.cluster_id().as_bytes());
        mac.update(identity.configuration_id().as_bytes());
        mac.update(&identity.configuration_epoch().get().to_be_bytes());
        mac.update(record.tx_id.as_uuid().as_bytes());
        mac.update(&record.version.get().to_be_bytes());
        mac.update(&envelope_bytes.to_be_bytes());
        mac.update(&Sha256::digest(&record.encrypted_blob));
        // Deliberate adversarial mutation: omit the plaintext digest.
        Ok(mac)
    }
}

/// The general borrowed envelope parser owns its key-ID string before that
/// type checks its maximum. Refuse the bounded profile's framing lengths from
/// the fixed header first, without allocating that rejected string or AAD.
fn preflight_envelope_lengths(encoded: &[u8]) -> Result<(), PersistError> {
    let header = encoded.get(..16).ok_or_else(invalid)?;
    let key_id = usize::from(u16::from_be_bytes([header[8], header[9]]));
    let nonce = usize::from(u16::from_be_bytes([header[10], header[11]]));
    let aad = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
    let aad = usize::try_from(aad).map_err(|_| invalid())?;
    if key_id > 512
        || nonce != opc_key::AES_256_GCM_SIV_NONCE_LEN
        || aad > CONFIG_CAPACITY_V1_AAD_BYTES
    {
        return Err(invalid());
    }
    Ok(())
}

impl fmt::Debug for CapacityRecordBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapacityRecordBinding(<redacted>)")
    }
}

fn invalid() -> PersistError {
    PersistError::corrupt_blob()
}

#[cfg(test)]
#[path = "capacity_record_tests.rs"]
mod tests;
