//! Reserved scope rows, outside every ordinary request-receipt collection.
//! The existing keyed durable row codec carries these explicitly discriminated
//! metadata records. Child secrets remain inside their sealed envelopes.

use std::{collections::HashSet, fmt};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scope_batch::{
    ScopeBatchCheckpoint, ScopeBatchError, ScopeChildKey, ScopeChildRecord, ScopeClaimKey,
    MAX_SCOPE_CHILD_CLAIMS, MAX_SCOPE_CHILD_VALUE_BYTES,
};
use crate::scope_lease::{ScopeLeaseId, ScopeProfileActivation};
use crate::{
    EncryptedSessionPayload, FenceToken, Generation, OwnerId, SessionConsensusClusterId,
    SessionKey, SessionKeyType, SessionPayloadEncoding, StableId, StateClass, StateType,
    StoredSessionRecord,
};

const MAGIC: &[u8; 5] = b"OPSC\x02";
const BATCH: &str = "opc-scope-batch";
const CHILD: &str = "opc-scope-child";
const CLAIM: &str = "opc-scope-claim";
const PROFILE: &str = "opc-scope-profile";
pub(crate) const RESERVED_KEY_TYPES: [&str; 5] = ["opc-scope-lease", BATCH, CHILD, CLAIM, PROFILE];
pub(crate) const MAX_SCOPE_ROW_BYTES: usize = MAX_SCOPE_CHILD_VALUE_BYTES + 4096;
const MAX_METADATA_BYTES: usize = 16 * 1024;

pub(crate) fn is_scope_record_key(key: &SessionKey) -> bool {
    RESERVED_KEY_TYPES.contains(&key.key_type.as_str())
}

pub(crate) fn is_batch_record_key(key: &SessionKey) -> bool {
    matches!(&key.key_type, SessionKeyType::Other(name) if matches!(name.as_str(), BATCH | CHILD | CLAIM | PROFILE))
}

fn scoped_key(
    scope: &ScopeLeaseId,
    kind: &str,
    suffix: &[u8],
) -> Result<SessionKey, ScopeBatchError> {
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
pub(crate) fn batch_key(scope: &ScopeLeaseId) -> Result<SessionKey, ScopeBatchError> {
    scoped_key(scope, BATCH, &[])
}
pub(crate) fn child_key(
    scope: &ScopeLeaseId,
    key: ScopeChildKey,
) -> Result<SessionKey, ScopeBatchError> {
    scoped_key(scope, CHILD, key.as_bytes())
}
pub(crate) fn claim_key(
    scope: &ScopeLeaseId,
    key: ScopeClaimKey,
) -> Result<SessionKey, ScopeBatchError> {
    scoped_key(scope, CLAIM, key.as_bytes())
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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimOwner {
    pub(crate) child: ScopeChildKey,
    pub(crate) birth: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimRow {
    pub(crate) scope: ScopeLeaseId,
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
}
impl Facts {
    pub(crate) fn can_replace(self, before: Self) -> bool {
        self.object == before.object
            && if self.revision == before.revision {
                self.body == before.body
            } else {
                self.revision > before.revision
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
            Self::Child(row) => child_key(&row.scope, row.key),
            Self::Claim(row) => claim_key(&row.scope, row.key),
            Self::Activation(row) => profile_key(row.identity.cluster_id()),
        }
    }
    fn revision(&self) -> u64 {
        match self {
            Self::Batch(row) => row.revision,
            Self::Child(row) => row.batch_revision,
            Self::Claim(row) => row.revision,
            Self::Activation(row) => row.identity.configuration_epoch().get(),
        }
    }
    pub(crate) fn scope(&self) -> Option<&ScopeLeaseId> {
        match self {
            Self::Batch(row) => Some(&row.scope),
            Self::Child(row) => Some(&row.scope),
            Self::Claim(row) => Some(&row.scope),
            Self::Activation(_) => None,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        if !(1..=i64::MAX as u64).contains(&self.revision())
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
        }
    }
    fn body(&self) -> Result<Vec<u8>, ScopeBatchError> {
        self.validate()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self).map_err(|_| ScopeBatchError::FormatMismatch)?);
        let limit = if matches!(self, Self::Child(_)) {
            MAX_SCOPE_ROW_BYTES
        } else {
            MAX_METADATA_BYTES
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
            state_type: StateType::from_static("opc-scope-state-v2"),
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
                    match read(&claim_key(scope, *claim)?)? {
                        Some(Self::Claim(row))
                            if row.scope == *scope
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
                    match read(&child_key(scope, owner.child)?)? {
                        Some(Self::Child(row))
                            if row.scope == *scope
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
