//! Reserved scope rows, outside every ordinary request-receipt collection.
//! The existing keyed durable row codec carries these explicitly discriminated
//! metadata records. Child secrets remain inside their sealed envelopes.
//!
//! This module owns the only child/claim key encoding. All scope writers,
//! lane readers and coherent scans use [`namespace_prefix`], [`namespace_key`]
//! or the typed [`child_key`]/[`claim_key`] wrappers; no slice derives its own.

#[cfg(test)]
#[path = "scope_storage_tests.rs"]
mod tests;

use std::{collections::HashSet, fmt};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scope_authority::{
    ScopeId, ScopeNamespace, ScopeProfileActivation, ScopeProfileContinuation,
};
use crate::scope_batch::{
    ScopeBatchCheckpoint, ScopeBatchError, ScopeChildKey, ScopeChildRecord, ScopeClaimKey,
    MAX_SCOPE_BATCH_LEDGER_BYTES, MAX_SCOPE_CHILD_CLAIMS, MAX_SCOPE_CHILD_VALUE_BYTES,
    SCOPE_BATCH_LANES, SCOPE_COUNTERS,
};
use crate::{
    EncryptedSessionPayload, FenceToken, Generation, OwnerId, SessionConsensusClusterId,
    SessionKey, SessionKeyType, SessionPayloadEncoding, StableId, StateClass, StateType,
    StoredSessionRecord,
};

const MAGIC: &[u8; 5] = b"OPSC\x04";
const BATCH: &str = "opc-scope-batch";
const CHILD: &str = "opc-scope-child";
const CLAIM: &str = "opc-scope-claim";
const PROFILE: &str = "opc-scope-profile";
const CONTINUATION: &str = "opc-scope-continuation";
pub(crate) const RESERVED_KEY_TYPES: [&str; 7] = [
    "opc-scope-authority",
    "opc-scope-lease",
    BATCH,
    CHILD,
    CLAIM,
    PROFILE,
    CONTINUATION,
];
pub(crate) const MAX_SCOPE_ROW_BYTES: usize = MAX_SCOPE_CHILD_VALUE_BYTES + 4096;
const MAX_METADATA_BYTES: usize = 16 * 1024;

/// Recognize the declared fresh-install boundary without decoding or migrating
/// a previous row. Unknown or malformed current formats remain corruption.
pub(crate) fn require_current_record_format(record: &StoredSessionRecord) -> std::io::Result<()> {
    if record.key.key_type.as_str() == "opc-scope-lease"
        || (is_scope_record_key(&record.key)
            && record.payload.encoding() == SessionPayloadEncoding::Plaintext
            && (record.payload.as_bytes().starts_with(b"OPSC\x02")
                || record.payload.as_bytes().starts_with(b"OPSC\x03")
                || record.state_type.as_str() == "opc-scope-authority-v2"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            crate::consensus::storage::SessionConsensusStorageError::FreshInstallationRequired,
        ));
    }
    Ok(())
}

/// Log replay can encounter activation before any scope row is materialized.
/// This is the frozen profile-2 digest, not an additional supported profile.
pub(crate) fn require_current_profile_format(
    certificate: &ScopeProfileActivation,
) -> std::io::Result<()> {
    const PREVIOUS: [u8; 32] = [
        0xe2, 0xed, 0x8b, 0x85, 0x7a, 0x26, 0x81, 0x98, 0x12, 0x86, 0x56, 0x7a, 0xaf, 0xe5, 0x24,
        0xd0, 0xc9, 0x7e, 0xdc, 0x99, 0x9e, 0xf5, 0x8f, 0x92, 0x1b, 0x17, 0x40, 0x14, 0x7b, 0x4f,
        0x97, 0x15,
    ];
    const PREVIOUS_TIMED: [u8; 32] = [
        0x2a, 0x80, 0xba, 0xa7, 0x04, 0x49, 0xad, 0xc6, 0x13, 0x87, 0x14, 0x7e, 0x04, 0xa2, 0x8d,
        0x99, 0xa7, 0x05, 0xc4, 0xba, 0x53, 0x04, 0xdf, 0xe0, 0xd1, 0x26, 0xa2, 0xd0, 0x3f, 0xa7,
        0x93, 0x2a,
    ];
    if certificate.profile == PREVIOUS || certificate.profile == PREVIOUS_TIMED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            crate::consensus::storage::SessionConsensusStorageError::FreshInstallationRequired,
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn previous_profile_record_for_test(
    mut certificate: ScopeProfileActivation,
) -> StoredSessionRecord {
    let mut record = ScopeRow::Activation(certificate.clone())
        .to_record()
        .unwrap();
    // Frozen profile-2 encoding from eb1a60bfd, including G = 77 seconds.
    certificate.profile =
        hex::decode("e2ed8b857a2681981286567aafe524d0c97edc999ef58f921b1740147b4f9715")
            .unwrap()
            .try_into()
            .unwrap();
    let mut bytes = b"OPSC\x02".to_vec();
    bytes.extend(postcard::to_allocvec(&ScopeRow::Activation(certificate)).unwrap());
    record.state_type = StateType::from_static("opc-scope-state-v2");
    record.payload = EncryptedSessionPayload::new(bytes);
    record
}

pub(crate) fn is_scope_record_key(key: &SessionKey) -> bool {
    RESERVED_KEY_TYPES.contains(&key.key_type.as_str())
}

pub(crate) fn is_batch_record_key(key: &SessionKey) -> bool {
    matches!(&key.key_type, SessionKeyType::Other(name) if matches!(name.as_str(), BATCH | CHILD | CLAIM | PROFILE | CONTINUATION))
}

fn scoped_key(scope: &ScopeId, kind: &str, suffix: &[u8]) -> Result<SessionKey, ScopeBatchError> {
    let mut bytes = scope.slot().to_vec();
    bytes.extend_from_slice(suffix);
    Ok(SessionKey {
        tenant: scope.tenant().clone(),
        nf_kind: scope.nf_kind().clone(),
        key_type: SessionKeyType::other(kind).map_err(|_| ScopeBatchError::FormatMismatch)?,
        stable_id: StableId::new(Bytes::from(bytes))
            .map_err(|_| ScopeBatchError::FormatMismatch)?,
    })
}
pub(crate) fn batch_key(scope: &ScopeId) -> Result<SessionKey, ScopeBatchError> {
    scoped_key(scope, BATCH, &[])
}
/// Canonical A64 namespace commitment for child/claim scan prefixes.
///
/// Exactly SHA-256(`openpacketcore/scope-namespace/key/v4\0` followed by the
/// Postcard encoding of the complete namespace). Obtain the predecessor's
/// incarnation from stable authority and scan that exact namespace. Initial
/// admission's broader orphan scan still decodes rows across incarnations.
pub(crate) fn namespace_prefix(namespace: &ScopeNamespace) -> Result<[u8; 32], ScopeBatchError> {
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/scope-namespace/key/v4\0");
    hash.update(postcard::to_allocvec(namespace).map_err(|_| ScopeBatchError::FormatMismatch)?);
    Ok(hash.finalize().into())
}

/// Sole full-key codec: the canonical 32-byte namespace commitment followed
/// by the unchanged 32-byte logical key. Prefer the typed child/claim wrappers
/// below; range adapters may use this shared helper with the corresponding kind.
pub(crate) fn namespace_key(
    namespace: &ScopeNamespace,
    kind: &str,
    suffix: &[u8; 32],
) -> Result<SessionKey, ScopeBatchError> {
    let mut bytes = namespace_prefix(namespace)?.to_vec();
    bytes.extend_from_slice(suffix);
    let mut key = scoped_key(namespace.scope(), kind, &[])?;
    key.stable_id =
        StableId::new(Bytes::from(bytes)).map_err(|_| ScopeBatchError::FormatMismatch)?;
    Ok(key)
}
/// Canonical child key; delegates to the shared A64 codec.
pub(crate) fn child_key(
    namespace: &ScopeNamespace,
    key: ScopeChildKey,
) -> Result<SessionKey, ScopeBatchError> {
    namespace_key(namespace, CHILD, key.as_bytes())
}
/// Canonical claim key; delegates to the shared A64 codec.
pub(crate) fn claim_key(
    namespace: &ScopeNamespace,
    key: ScopeClaimKey,
) -> Result<SessionKey, ScopeBatchError> {
    namespace_key(namespace, CLAIM, key.as_bytes())
}

pub(crate) fn profile_key(
    cluster: SessionConsensusClusterId,
) -> Result<SessionKey, ScopeBatchError> {
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/scope-profile/key/2\0");
    hash.update(postcard::to_allocvec(&cluster).map_err(|_| ScopeBatchError::FormatMismatch)?);
    Ok(SessionKey {
        tenant: opc_types::TenantId::from_static("opc-system"),
        nf_kind: opc_types::NetworkFunctionKind::from_static("store"),
        key_type: SessionKeyType::other(PROFILE).map_err(|_| ScopeBatchError::FormatMismatch)?,
        stable_id: StableId::new(Bytes::copy_from_slice(&hash.finalize()))
            .map_err(|_| ScopeBatchError::FormatMismatch)?,
    })
}

pub(crate) fn continuation_key(
    cluster: SessionConsensusClusterId,
) -> Result<SessionKey, ScopeBatchError> {
    let mut key = profile_key(cluster)?;
    key.key_type =
        SessionKeyType::other(CONTINUATION).map_err(|_| ScopeBatchError::FormatMismatch)?;
    Ok(key)
}

/// One bounded retained row per cluster. The log index prevents an aborted
/// transition or a stale snapshot from rolling back the latest attestation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuationRow {
    pub(crate) certificate: ScopeProfileContinuation,
    pub(crate) log_index: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimOwner {
    pub(crate) child: ScopeChildKey,
    pub(crate) birth: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimRow {
    pub(crate) namespace: ScopeNamespace,
    pub(crate) key: ScopeClaimKey,
    pub(crate) revision: u64,
    pub(crate) owner: Option<ClaimOwner>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum ScopeRow {
    Batch(Box<ScopeBatchCheckpoint>),
    Child(ScopeChildRecord),
    Claim(ClaimRow),
    Activation(ScopeProfileActivation),
    Continuation(Box<ContinuationRow>),
}

impl fmt::Debug for ScopeRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeRow(<redacted>)")
    }
}

/// Scalar catalog facts preserve authority and birth floors when already
/// validated command changes are coalesced into a durable generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Facts {
    object: [u8; 32],
    body: [u8; 32],
    revision: u64,
    birth: u64,
    generation: u64,
    counters: [u64; SCOPE_COUNTERS],
    lanes: [(u64, u64, [u8; 32]); SCOPE_BATCH_LANES],
}
impl Facts {
    pub(crate) fn can_replace(self, before: Self) -> bool {
        self.object == before.object
            && if self.revision == before.revision {
                self.body == before.body
            } else {
                self.revision > before.revision
                    && self.lanes.iter().zip(before.lanes).all(|(next, previous)| {
                        next.0 >= previous.0
                            && next.1 >= previous.1
                            && (next.0 != previous.0 || next.2 == previous.2)
                    })
                    && self
                        .counters
                        .iter()
                        .zip(before.counters)
                        .all(|(next, previous)| *next >= previous)
                    && self.birth >= before.birth
                    && (self.birth > before.birth
                        || (before.generation == 0 && self.generation == 0)
                        || self.generation > before.generation)
            }
    }
}

impl ScopeRow {
    pub(crate) fn key(&self) -> Result<SessionKey, ScopeBatchError> {
        match self {
            Self::Batch(row) => batch_key(&row.scope),
            Self::Child(row) => child_key(&row.namespace, row.key),
            Self::Claim(row) => claim_key(&row.namespace, row.key),
            Self::Activation(row) => profile_key(row.identity.cluster_id()),
            Self::Continuation(row) => {
                continuation_key(row.certificate.predecessor.identity.cluster_id())
            }
        }
    }
    fn revision(&self) -> u64 {
        match self {
            Self::Batch(row) => row.revision,
            Self::Child(row) => row.batch_revision,
            Self::Claim(row) => row.revision,
            Self::Activation(row) => row.identity.configuration_epoch().get(),
            Self::Continuation(row) => row.log_index,
        }
    }
    pub(crate) fn scope(&self) -> Option<&ScopeId> {
        match self {
            Self::Batch(row) => Some(&row.scope),
            Self::Child(row) => Some(row.namespace.scope()),
            Self::Claim(row) => Some(row.namespace.scope()),
            Self::Activation(_) | Self::Continuation(_) => None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        if self.revision() > i64::MAX as u64
            || (self.revision() == 0 && !matches!(self, Self::Batch(_)))
            || self.scope().is_some_and(|scope| scope.slot() == &[0; 32])
        {
            return Err(ScopeBatchError::FormatMismatch);
        }
        match self {
            Self::Batch(row) => row.validate_stored(),
            Self::Child(row) => {
                crate::scope_batch::ScopeChildRevision::new(
                    row.revision.birth(),
                    row.revision.generation(),
                )?;
                if row.key.as_bytes() == &[0; 32]
                    || row.claims.len() > MAX_SCOPE_CHILD_CLAIMS
                    || row.claims.iter().any(|key| key.as_bytes() == &[0; 32])
                    || row.claims.iter().collect::<HashSet<_>>().len() != row.claims.len()
                    || (row.value.is_none() && !row.claims.is_empty())
                {
                    return Err(ScopeBatchError::FormatMismatch);
                }
                Ok(())
            }
            Self::Claim(row) => {
                if row.key.as_bytes() == &[0; 32]
                    || row.owner.is_some_and(|owner| {
                        owner.child.as_bytes() == &[0; 32]
                            || !(1..=i64::MAX as u64).contains(&owner.birth)
                    })
                {
                    return Err(ScopeBatchError::FormatMismatch);
                }
                Ok(())
            }
            Self::Activation(row) => row.validate().map_err(|_| ScopeBatchError::FormatMismatch),
            Self::Continuation(row) => row
                .certificate
                .validate()
                .map_err(|_| ScopeBatchError::FormatMismatch),
        }
    }
    fn body(&self) -> Result<Vec<u8>, ScopeBatchError> {
        self.validate()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self).map_err(|_| ScopeBatchError::FormatMismatch)?);
        let limit = match self {
            Self::Child(_) => MAX_SCOPE_ROW_BYTES,
            Self::Batch(_) => MAX_SCOPE_BATCH_LEDGER_BYTES,
            _ => MAX_METADATA_BYTES,
        };
        if bytes.len() > limit {
            return Err(ScopeBatchError::FormatMismatch);
        }
        Ok(bytes)
    }
    pub(crate) fn to_record(&self) -> Result<StoredSessionRecord, ScopeBatchError> {
        Ok(StoredSessionRecord {
            key: self.key()?,
            generation: Generation::new(self.revision()),
            owner: OwnerId::new("scope-state").map_err(|_| ScopeBatchError::FormatMismatch)?,
            fence: FenceToken::new(0),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("opc-scope-state-v4"),
            expires_at: None,
            payload: EncryptedSessionPayload::new_zeroizing(zeroize::Zeroizing::new(self.body()?)),
        })
    }
    pub(crate) fn from_record(record: &StoredSessionRecord) -> Result<Self, ScopeBatchError> {
        let bytes = record.payload.as_bytes();
        if !is_batch_record_key(&record.key)
            || record.payload.encoding() != SessionPayloadEncoding::Plaintext
            || bytes.len() > MAX_SCOPE_ROW_BYTES
            || !bytes.starts_with(MAGIC)
        {
            return Err(ScopeBatchError::FormatMismatch);
        }
        let (row, trailing): (Self, &[u8]) = postcard::take_from_bytes(&bytes[MAGIC.len()..])
            .map_err(|_| ScopeBatchError::FormatMismatch)?;
        if !trailing.is_empty() || row.to_record()? != *record {
            return Err(ScopeBatchError::FormatMismatch);
        }
        Ok(row)
    }
    pub(crate) fn facts(&self) -> Result<Facts, ScopeBatchError> {
        let (birth, generation) = match self {
            Self::Batch(row) => (row.birth_floor, 0),
            Self::Child(row) => (row.revision.birth(), row.revision.generation()),
            _ => (0, 0),
        };
        Ok(Facts {
            object: Sha256::digest(
                postcard::to_allocvec(&(self.key()?, self.scope()))
                    .map_err(|_| ScopeBatchError::FormatMismatch)?,
            )
            .into(),
            body: Sha256::digest(self.body()?).into(),
            revision: self.revision(),
            birth,
            generation,
            counters: match self {
                Self::Batch(row) => row.counters,
                _ => [0; SCOPE_COUNTERS],
            },
            lanes: match self {
                Self::Batch(row) => row.lane_floors()?,
                _ => [(0, 0, [0; 32]); SCOPE_BATCH_LANES],
            },
        })
    }

    /// Validate the original row and its exact bounded cross-row predicates.
    /// The same routine runs at live publication and cold reconstruction.
    pub(crate) fn validate_links(
        &self,
        read: &impl Fn(&SessionKey) -> Result<Option<Self>, ScopeBatchError>,
    ) -> Result<(), ScopeBatchError> {
        let Some(scope) = self.scope() else {
            return Ok(());
        };
        let batch = match read(&batch_key(scope)?)? {
            Some(Self::Batch(batch))
                if batch.scope == *scope && batch.revision >= self.revision() =>
            {
                batch
            }
            _ => return Err(ScopeBatchError::FormatMismatch),
        };
        match self {
            Self::Child(child) => {
                if child.revision.birth() > batch.birth_floor {
                    return Err(ScopeBatchError::FormatMismatch);
                }
                for claim in &child.claims {
                    match read(&claim_key(&child.namespace, *claim)?)? {
                        Some(Self::Claim(row))
                            if row.namespace == child.namespace
                                && row.owner
                                    == Some(ClaimOwner {
                                        child: child.key,
                                        birth: child.revision.birth(),
                                    }) => {}
                        _ => return Err(ScopeBatchError::FormatMismatch),
                    }
                }
            }
            Self::Claim(claim) => {
                if let Some(owner) = claim.owner {
                    match read(&child_key(&claim.namespace, owner.child)?)? {
                        Some(Self::Child(row))
                            if row.namespace == claim.namespace
                                && row.value.is_some()
                                && row.revision.birth() == owner.birth
                                && row.claims.contains(&claim.key) => {}
                        _ => return Err(ScopeBatchError::FormatMismatch),
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn previous_timed_profile_record_for_test(
    mut certificate: ScopeProfileActivation,
) -> StoredSessionRecord {
    let mut record = ScopeRow::Activation(certificate.clone())
        .to_record()
        .unwrap();
    // Frozen timed profile 3. Activation's structural payload
    // did not change; this is a fixture, never a compatibility decoder.
    certificate.profile =
        hex::decode("2a80baa70449adc61387147e04a28d99a705c4ba5304dfe0d126a2d03fa7932a")
            .unwrap()
            .try_into()
            .unwrap();
    let mut bytes = b"OPSC\x03".to_vec();
    bytes.extend(postcard::to_allocvec(&ScopeRow::Activation(certificate)).unwrap());
    record.state_type = StateType::from_static("opc-scope-state-v3");
    record.payload = EncryptedSessionPayload::new(bytes);
    record
}
