//! Bounded, non-capability child observations and their request codec.

use super::*;

/// Maximum distinct children in one current-authority point observation.
pub const MAX_SCOPE_CHILD_READ_KEYS: usize = 32;
/// Maximum canonical method-17 request, excluding transport framing.
pub const MAX_SCOPE_CHILD_READ_REQUEST_BYTES: usize =
    2 + crate::scope_authority::MAX_SCOPE_AUTHORITY_RECORD_BYTES + 1 + 32 * 32;
/// Maximum canonical live child record, including all metadata.
pub const MAX_SCOPE_CHILD_RECORD_BYTES: usize = MAX_SCOPE_CHILD_VALUE_BYTES + 8192;
/// Complete observation body budget after the fixed transport header and result envelope.
pub const MAX_SCOPE_CHILD_OBSERVATION_BYTES: usize = 2 * 1024 * 1024 + 512 - 128 - 69;
/// Maximum lifetime of a point-read cut, independent of the client's deadline.
pub const SCOPE_CHILD_READ_MAX_CUT_LIFETIME: std::time::Duration =
    std::time::Duration::from_secs(10);

/// Full authority comparison and ordered opaque keys. This is a claim, never a capability.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeChildReadRequest {
    stamp: ScopeAuthorityStamp,
    keys: Vec<ScopeChildKey>,
}

impl ScopeChildReadRequest {
    /// Validate a full stamp and 1–32 distinct, nonzero keys before any admission.
    pub fn new(
        stamp: &ScopeAuthorityStamp,
        keys: Vec<ScopeChildKey>,
    ) -> Result<Self, ScopeBatchError> {
        stamp
            .validate()
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        validate_keys(&keys)?;
        Ok(Self {
            stamp: stamp.clone(),
            keys,
        })
    }

    /// Exact claimed active authority, independently checked at the read cut.
    pub const fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }

    /// Requested keys in response order.
    pub fn keys(&self) -> &[ScopeChildKey] {
        &self.keys
    }

    /// Revision-2 method-17 bytes: LP16(stamp), U8(count), then fixed-width keys.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeBatchError> {
        validate_keys(&self.keys)?;
        let stamp = self
            .stamp
            .encode_canonical()
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        let mut bytes = Vec::with_capacity(3 + stamp.len() + self.keys.len() * 32);
        bytes.extend_from_slice(&(stamp.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&stamp);
        bytes.push(self.keys.len() as u8);
        for key in &self.keys {
            bytes.extend_from_slice(key.as_bytes());
        }
        Ok(bytes)
    }

    /// Reject counts and lengths before allocating keys; refuse alternate or trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeBatchError> {
        if bytes.len() > MAX_SCOPE_CHILD_READ_REQUEST_BYTES || bytes.len() < 3 {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let stamp_len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if stamp_len > crate::scope_authority::MAX_SCOPE_AUTHORITY_RECORD_BYTES {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let count = usize::from(
            *bytes
                .get(2 + stamp_len)
                .ok_or(ScopeBatchError::InvalidRequest)?,
        );
        if !(1..=MAX_SCOPE_CHILD_READ_KEYS).contains(&count)
            || bytes.len() != 3 + stamp_len + count * 32
        {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let stamp = ScopeAuthorityStamp::decode_canonical(&bytes[2..2 + stamp_len])
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        let keys = bytes[3 + stamp_len..]
            .chunks_exact(32)
            .map(|key| ScopeChildKey::new(key.try_into().expect("fixed-width key")))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(&stamp, keys)
    }
}

pub(crate) fn validate_keys(keys: &[ScopeChildKey]) -> Result<(), ScopeBatchError> {
    if !(1..=MAX_SCOPE_CHILD_READ_KEYS).contains(&keys.len())
        || keys.iter().any(|key| key.as_bytes() == &[0; 32])
        || keys.iter().collect::<HashSet<_>>().len() != keys.len()
    {
        return Err(ScopeBatchError::InvalidRequest);
    }
    Ok(())
}

/// Value-free observation failure. None of these errors proves a mutation outcome.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeChildReadError {
    /// Exact store refusal or unresolved transport observation.
    #[error("scope_child_read_batch: {0}")]
    Batch(ScopeBatchError),
    /// The complete set cannot fit; no partial entries were returned.
    #[error("scope_child_observation_too_large")]
    ObservationTooLarge,
    /// The enclosing builder has exhausted its exchange budget.
    #[error("scope_child_read_budget_exceeded")]
    ReadBudgetExceeded,
    /// This call encountered an incompatible transport revision; never latched.
    #[error("scope_transport_revision_mismatch")]
    TransportRevisionMismatch,
}

impl From<ScopeBatchError> for ScopeChildReadError {
    fn from(error: ScopeBatchError) -> Self {
        match error {
            ScopeBatchError::TransportRevisionMismatch => Self::TransportRevisionMismatch,
            other => Self::Batch(other),
        }
    }
}

impl ScopeChildRecord {
    /// Committed batch revision at which this exact record was written.
    pub const fn batch_revision(&self) -> u64 {
        self.batch_revision
    }

    /// Shared stored-row invariants, including deletion tombstones.
    pub(crate) fn validate_stored(&self) -> Result<(), ScopeBatchError> {
        ScopeChildRevision::new(self.revision.birth(), self.revision.generation())?;
        if self.namespace.scope().slot() == &[0; 32]
            || !(1..=COUNTER_MAX).contains(&self.batch_revision)
            || self.key.as_bytes() == &[0; 32]
            || self.claims.len() > MAX_SCOPE_CHILD_CLAIMS
            || self.claims.iter().any(|key| key.as_bytes() == &[0; 32])
            || self.claims.iter().collect::<HashSet<_>>().len() != self.claims.len()
            || (self.value.is_none() && !self.claims.is_empty())
        {
            return Err(ScopeBatchError::FormatMismatch);
        }
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<(), ScopeBatchError> {
        self.validate_stored()
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        let value = self.value.as_ref().ok_or(ScopeBatchError::InvalidRequest)?;
        if value.envelope().len() > MAX_SCOPE_CHILD_VALUE_BYTES {
            return Err(ScopeBatchError::InvalidRequest);
        }
        opc_crypto::CryptoEnvelopeRef::decode(value.envelope())
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        Ok(())
    }
}
