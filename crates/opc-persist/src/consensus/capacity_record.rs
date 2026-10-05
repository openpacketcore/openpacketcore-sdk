//! Fixed authenticated lengths for an exact bounded encrypted record.
//!
//! A binding authenticates representation, not permission to apply a command.
//! Preparation consumes the original encryption claim and retains its lease.
//! No store or receiver selects these representations until it admits their
//! distinct profile; legacy command decoding and validation remain closed.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use opc_crypto::{
    ConfigCapacityEvidence, ConfigCapacityProfile, ConfigPreparationPool,
    ConfigPreparationReservation, CryptoEnvelopeRef, CONFIG_CAPACITY_V1_AAD_BYTES,
    CONFIG_CAPACITY_V1_ENVELOPE_BYTES, CONFIG_CAPACITY_V1_LOGICAL_BYTES,
    CONFIG_CAPACITY_V1_PLAINTEXT_BYTES, CONFIG_CAPACITY_V1_REPLAY_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ConfigConsensusIdentity, PreparedConfigCommit};
use crate::{
    AttestedConfigCommit, AuditKey, CommitRecord, ConfirmedCommitResolution, PersistError,
};

mod aad_shape;

const DOMAIN: &[u8] = b"openpacketcore/config-capacity/record/v1\0";
const REVISION: u16 = 1;
const HEADER_BYTES: usize = 12;
pub(super) const RECORD_CAPACITY_BYTES: usize = HEADER_BYTES + 32;

/// The record and its size evidence stay paired through consumed preparation.
/// The reservation is process-local and never part of the serialized command.
pub(super) struct PreparedCapacityCommit {
    pub(super) commit: PreparedConfigCommit,
    pub(super) resolution: Option<ConfirmedCommitResolution>,
    pub(super) binding: CapacityRecordBinding,
    pub(super) reservation: ConfigPreparationReservation,
}

impl PreparedCapacityCommit {
    pub(super) fn prepare(
        attested: AttestedConfigCommit,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
        pool: &ConfigPreparationPool,
    ) -> Result<Self, PersistError> {
        // Identity is the receiving authority's private pool, never a supplied
        // store name. Refuse foreign or unreserved encryption before parsing,
        // finalizing audit metadata or issuing a record binding.
        if !attested.preparation().is_some_and(|lease| pool.owns(lease)) {
            return Err(invalid());
        }
        let (record, audit, resolution, evidence, reservation) = attested.into_capacity_parts();
        let binding = CapacityRecordBinding::issue_record(
            &record,
            evidence.ok_or_else(invalid)?,
            identity,
            key,
        )?;
        // Preparation changes audit fields only, preserving the exact encrypted
        // record already paired with the original one-shot claim.
        let commit = PreparedConfigCommit::prepare(record, audit, key)?;
        Ok(Self {
            commit,
            resolution,
            binding,
            reservation: reservation.ok_or_else(invalid)?,
        })
    }
}

/// Fixed-width data; decoding does not grant authenticity or mutation authority.
/// Arrays preserve the same 44 bytes in postcard and the standalone encoding.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacityRecordBinding {
    header: [u8; HEADER_BYTES],
    tag: [u8; 32],
}

impl CapacityRecordBinding {
    // No issuer taking separated evidence escapes this module. The production
    // caller above consumes the immutable attestation, after checking its pool.
    fn issue_record(
        record: &CommitRecord,
        evidence: ConfigCapacityEvidence,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
    ) -> Result<Self, PersistError> {
        let logical = u32::try_from(evidence.logical_bytes()).map_err(|_| invalid())?;
        let replay = u32::try_from(evidence.replay_bytes()).map_err(|_| invalid())?;
        let mut binding = Self {
            header: [0; HEADER_BYTES],
            tag: [0; 32],
        };
        binding.header[..2].copy_from_slice(&REVISION.to_be_bytes());
        binding.header[2..4].copy_from_slice(&evidence.profile().revision().to_be_bytes());
        binding.header[4..8].copy_from_slice(&logical.to_be_bytes());
        binding.header[8..12].copy_from_slice(&replay.to_be_bytes());
        binding.validate(record, ConfigCapacityProfile::BoundedV1)?;
        binding.tag = binding
            .mac(record, identity, key)?
            .finalize()
            .into_bytes()
            .into();
        Ok(binding)
    }

    #[cfg(test)]
    pub(super) fn issue(
        attested: &AttestedConfigCommit,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
    ) -> Result<Self, PersistError> {
        Self::issue_record(
            attested.record(),
            attested.capacity_evidence().ok_or_else(invalid)?,
            identity,
            key,
        )
    }

    /// Verify against the receiving authority's independently selected scope,
    /// key and profile. The record remains immutable throughout this check.
    pub(super) fn verify(
        &self,
        record: &CommitRecord,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
        profile: ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        self.validate(record, profile)?;
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

    /// Parse only the fixed representation; callers must still verify it.
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

    fn validate(
        &self,
        record: &CommitRecord,
        profile: ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        if profile != ConfigCapacityProfile::BoundedV1
            || self.header[..2] != REVISION.to_be_bytes()
            || self.header[2..4] != profile.revision().to_be_bytes()
            || record.plaintext_digest.len() != 32
        {
            return Err(invalid());
        }
        let logical = u32::from_be_bytes(self.header[4..8].try_into().map_err(|_| invalid())?);
        let replay = u32::from_be_bytes(self.header[8..12].try_into().map_err(|_| invalid())?);
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
            || envelope
                .ciphertext_and_tag
                .len()
                .checked_sub(opc_key::AEAD_TAG_LEN)
                != Some(plaintext)
        {
            return Err(invalid());
        }
        aad_shape::preflight(envelope.aad)?;
        // Shape admission precedes the canonical AAD decoder and metadata
        // binding. No decoded value or successful authentication is cached.
        super::types::validate_record_representability(record).map_err(|_| invalid())
    }

    fn mac(
        &self,
        record: &CommitRecord,
        identity: ConfigConsensusIdentity,
        key: &AuditKey,
    ) -> Result<Hmac<Sha256>, PersistError> {
        let envelope_bytes = u64::try_from(record.encrypted_blob.len()).map_err(|_| invalid())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| invalid())?;
        mac.update(DOMAIN);
        mac.update(&self.header);
        mac.update(&key.epoch().to_be_bytes());
        mac.update(identity.cluster_id().as_bytes());
        mac.update(identity.configuration_id().as_bytes());
        mac.update(&identity.configuration_epoch().get().to_be_bytes());
        mac.update(record.tx_id.as_uuid().as_bytes());
        mac.update(&record.version.get().to_be_bytes());
        mac.update(&envelope_bytes.to_be_bytes());
        mac.update(&Sha256::digest(&record.encrypted_blob));
        mac.update(&record.plaintext_digest);
        Ok(mac)
    }
}

// Inspect declared extents before the general envelope parser owns a key ID.
fn preflight_envelope_lengths(encoded: &[u8]) -> Result<(), PersistError> {
    if encoded.len() > CONFIG_CAPACITY_V1_ENVELOPE_BYTES {
        return Err(invalid());
    }
    let header = encoded.get(..16).ok_or_else(invalid)?;
    let key = u16::from_be_bytes([header[8], header[9]]);
    let nonce = u16::from_be_bytes([header[10], header[11]]);
    let aad = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
    if key > 512
        || usize::from(nonce) != opc_key::AES_256_GCM_SIV_NONCE_LEN
        || usize::try_from(aad).map_err(|_| invalid())? > CONFIG_CAPACITY_V1_AAD_BYTES
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
mod tests;
