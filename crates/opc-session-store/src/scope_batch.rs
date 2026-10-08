//! Atomic child records under one strictly durable scope grant.
//!
//! A batch contains at most 64 child mutations and 16 counter comparisons.
//! Claims are unique within the scope and are changed with their child rows.
//! The apply fence is the stable grant, selection and execution, independent
//! of lease renewal revisions. The current retained permit must still be live.
//!
//! Retain the complete request and allow one unresolved batch per scope. This
//! initial profile uses lane zero, an exact scope batch revision and one retained
//! result. Eight lane slots are reserved for later independent replay; coherent
//! scans remain separate. A lost
//! reply or configuration switch can return [`ScopeBatchError::OutcomeUnknown`];
//! retry the exact request before submitting its successor.

use std::{collections::HashSet, fmt};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::scope_lease::{
    ScopeClockBounds, ScopeLeaseError, ScopeLeaseId, ScopePermit, ScopeState,
};
use crate::SessionKey;

mod service;
pub(crate) mod state;
pub use service::ScopeBatchStore;

/// Maximum child records touched by one atomic command.
pub const MAX_SCOPE_BATCH_CHILDREN: usize = 64;
/// Maximum serialized consensus command, including authority and framing.
pub const MAX_SCOPE_BATCH_COMMAND_BYTES: usize = 2 * 1024 * 1024;
/// Maximum sealed envelope bytes in one child value.
pub const MAX_SCOPE_CHILD_VALUE_BYTES: usize = 1024 * 1024;
/// Maximum unique claims owned by one live child.
pub const MAX_SCOPE_CHILD_CLAIMS: usize = 8;
/// Fixed number of independently compared counters in one scope.
pub const SCOPE_COUNTERS: usize = 16;
/// Fixed durable replay slots. This initial API admits only lane zero.
pub const SCOPE_BATCH_LANES: usize = 8;
const COUNTER_MAX: u64 = i64::MAX as u64;
const COMMAND_HEADROOM: usize = 16 * 1024;

macro_rules! opaque_key {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Construct a nonzero, opaque identity. It must contain no secret.
            pub fn new(bytes: [u8; 32]) -> Result<Self, ScopeBatchError> {
                if bytes == [0; 32] {
                    return Err(ScopeBatchError::InvalidRequest);
                }
                Ok(Self(bytes))
            }
            /// Return the exact opaque bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}
opaque_key!(
    ScopeChildKey,
    "Opaque child identity within one stable scope."
);
opaque_key!(
    ScopeClaimKey,
    "Opaque unique claim identity within one stable scope."
);

/// Exact child incarnation and version. Delete/recreate changes the birth;
/// every successful update advances the generation within that birth.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeChildRevision {
    birth: u64,
    generation: u64,
}

impl ScopeChildRevision {
    /// Construct an exact, positive birth and generation comparison.
    pub fn new(birth: u64, generation: u64) -> Result<Self, ScopeBatchError> {
        if !(1..=COUNTER_MAX).contains(&birth) || !(1..=COUNTER_MAX).contains(&generation) {
            return Err(ScopeBatchError::InvalidRequest);
        }
        Ok(Self { birth, generation })
    }
    /// Monotonic birth allocated by committed apply, never reused after delete.
    pub const fn birth(self) -> u64 {
        self.birth
    }
    /// Monotonic generation within this birth.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Already sealed RFC 003 envelope. The SDK validates its bounded envelope
/// shape without a decryption key. The consumer binds its logical scope and
/// child identity in the AAD, and verifies that binding when opening the value.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeSealedValue(Zeroizing<Vec<u8>>);

impl ScopeSealedValue {
    /// Accept a canonical sealed envelope; plaintext and malformed values fail.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ScopeBatchError> {
        if bytes.len() > MAX_SCOPE_CHILD_VALUE_BYTES {
            return Err(ScopeBatchError::InvalidRequest);
        }
        opc_crypto::CryptoEnvelopeRef::decode(&bytes)
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
    /// Opaque envelope bytes. Reading them alone does not grant ownership.
    pub fn envelope(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for ScopeSealedValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&BASE64.encode(self.envelope()))
        } else {
            serializer.serialize_bytes(self.envelope())
        }
    }
}

impl<'de> Deserialize<'de> for ScopeSealedValue {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Value;
        impl serde::de::Visitor<'_> for Value {
            type Value = ScopeSealedValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded canonical sealed scope value")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX_SCOPE_CHILD_VALUE_BYTES.div_ceil(3) * 4 {
                    return Err(E::custom("scope value exceeds profile"));
                }
                let bytes = BASE64
                    .decode(value)
                    .map_err(|_| E::custom("scope value encoding invalid"))?;
                if BASE64.encode(&bytes) != value {
                    return Err(E::custom("scope value encoding is not canonical"));
                }
                ScopeSealedValue::new(bytes).map_err(E::custom)
            }
            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                if value.len() > MAX_SCOPE_CHILD_VALUE_BYTES {
                    return Err(E::custom("scope value exceeds profile"));
                }
                ScopeSealedValue::new(value.to_vec()).map_err(E::custom)
            }
        }
        if decoder.is_human_readable() {
            decoder.deserialize_str(Value)
        } else {
            decoder.deserialize_bytes(Value)
        }
    }
}

/// One typed child mutation. Claims describe the complete successor set.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ScopeChildMutation {
    /// Create an absent child; committed apply allocates its next birth.
    Create {
        /// Child identity.
        key: ScopeChildKey,
        /// Already sealed value.
        value: ScopeSealedValue,
        /// Complete unique claim set.
        claims: Vec<ScopeClaimKey>,
    },
    /// Replace exactly one live birth and generation.
    CompareAndSet {
        /// Child identity.
        key: ScopeChildKey,
        /// Exact predecessor; a replacement birth never matches.
        expected: ScopeChildRevision,
        /// Already sealed successor value.
        value: ScopeSealedValue,
        /// Complete successor claim set, changed atomically with the row.
        claims: Vec<ScopeClaimKey>,
    },
    /// Delete exactly one live birth and generation and release its claims.
    Delete {
        /// Child identity.
        key: ScopeChildKey,
        /// Exact predecessor.
        expected: ScopeChildRevision,
    },
}

impl ScopeChildMutation {
    /// Exact child touched by this mutation.
    pub const fn key(&self) -> ScopeChildKey {
        match self {
            Self::Create { key, .. }
            | Self::CompareAndSet { key, .. }
            | Self::Delete { key, .. } => *key,
        }
    }
    fn claims(&self) -> &[ScopeClaimKey] {
        match self {
            Self::Create { claims, .. } | Self::CompareAndSet { claims, .. } => claims,
            Self::Delete { .. } => &[],
        }
    }
    fn expected(&self) -> Option<ScopeChildRevision> {
        match self {
            Self::Create { .. } => None,
            Self::CompareAndSet { expected, .. } | Self::Delete { expected, .. } => Some(*expected),
        }
    }
}

/// Exact compare-and-set of one fixed counter. Values are bounded by i64::MAX;
/// this is accounting, not a default session quota or allocation policy.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCounterMutation {
    counter: u8,
    expected: u64,
    next: u64,
}
impl ScopeCounterMutation {
    /// Compare and replace one of the scope's sixteen counters.
    pub fn new(counter: u8, expected: u64, next: u64) -> Result<Self, ScopeBatchError> {
        if usize::from(counter) >= SCOPE_COUNTERS || expected > COUNTER_MAX || next > COUNTER_MAX {
            return Err(ScopeBatchError::InvalidRequest);
        }
        Ok(Self {
            counter,
            expected,
            next,
        })
    }
    /// Fixed counter index.
    pub const fn counter(self) -> u8 {
        self.counter
    }
    /// Exact compared value.
    pub const fn expected(self) -> u64 {
        self.expected
    }
    /// Proposed replacement value.
    pub const fn next(self) -> u64 {
        self.next
    }
}

/// Complete exact request, retained until its outcome is known. Only the grant,
/// selection and execution in `permit` form the batch fence; renewal timestamps
/// do not. Apply checks the currently retained permit's absolute expiry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchRequest {
    permit: ScopePermit,
    request_id: [u8; 16],
    lane: u8,
    sequence: u64,
    expected_revision: u64,
    operations: Vec<ScopeChildMutation>,
    counters: Vec<ScopeCounterMutation>,
}
impl ScopeBatchRequest {
    /// Build one bounded batch in lane zero, with sequence `expected_revision + 1`.
    /// Counter-only batches are permitted; other lanes are reserved.
    pub fn new(
        permit: &ScopePermit,
        request_id: [u8; 16],
        expected_revision: u64,
        operations: Vec<ScopeChildMutation>,
        counters: Vec<ScopeCounterMutation>,
    ) -> Result<Self, ScopeBatchError> {
        let value = Self {
            permit: permit.clone(),
            request_id,
            lane: 0,
            sequence: expected_revision
                .checked_add(1)
                .ok_or(ScopeBatchError::InvalidRequest)?,
            expected_revision,
            operations,
            counters,
        };
        value.validate()?;
        Ok(value)
    }
    /// Stable scope of this batch.
    pub const fn scope(&self) -> &ScopeLeaseId {
        self.permit.scope()
    }
    /// Original operation identity.
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    /// Replay lane, always zero in this initial profile.
    pub const fn lane(&self) -> u8 {
        self.lane
    }
    /// Positive lane sequence, one greater than the compared revision.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Scope batch revision compared by committed apply.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    /// Child mutations in result order.
    pub fn operations(&self) -> &[ScopeChildMutation] {
        &self.operations
    }
    /// Exact counter comparisons and replacements.
    pub fn counters(&self) -> &[ScopeCounterMutation] {
        &self.counters
    }

    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        if self.request_id == [0; 16]
            || self.expected_revision >= COUNTER_MAX
            || self.lane != 0
            || self.sequence != self.expected_revision + 1
            || self.operations.len() > MAX_SCOPE_BATCH_CHILDREN
            || self.counters.len() > SCOPE_COUNTERS
            || (self.operations.is_empty() && self.counters.is_empty())
        {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let mut keys = HashSet::new();
        for op in &self.operations {
            if op.key().0 == [0; 32]
                || !keys.insert(op.key())
                || op.claims().len() > MAX_SCOPE_CHILD_CLAIMS
                || op.claims().iter().any(|key| key.0 == [0; 32])
                || op.claims().iter().collect::<HashSet<_>>().len() != op.claims().len()
            {
                return Err(ScopeBatchError::InvalidRequest);
            }
            if let Some(expected) = op.expected() {
                ScopeChildRevision::new(expected.birth, expected.generation)?;
            }
        }
        let mut counters = HashSet::new();
        for counter in &self.counters {
            ScopeCounterMutation::new(counter.counter, counter.expected, counter.next)?;
            if !counters.insert(counter.counter) {
                return Err(ScopeBatchError::InvalidRequest);
            }
        }
        // Reserve the fixed outer consensus/authority headers before admission.
        let encoded = serde_json::to_vec(self).map_err(|_| ScopeBatchError::InvalidRequest)?;
        if encoded.len() > MAX_SCOPE_BATCH_COMMAND_BYTES - COMMAND_HEADROOM {
            return Err(ScopeBatchError::InvalidRequest);
        }
        Ok(())
    }
    fn digest(&self) -> Result<[u8; 32], ScopeBatchError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-batch/request/v1\0");
        hash.update(postcard::to_allocvec(self).map_err(|_| ScopeBatchError::InvalidRequest)?);
        Ok(hash.finalize().into())
    }
}

/// Identifies only the rows, claims and counters which must be reread and
/// regrouped. No child value or secret appears in a conflict.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchConflicts {
    /// Child comparisons that failed.
    pub children: Vec<ScopeChildKey>,
    /// Unique claims that were already held by another birth.
    pub claims: Vec<ScopeClaimKey>,
    /// Counter comparisons that failed.
    pub counters: Vec<u8>,
}

/// Stable, value-free batch refusal or unresolved outcome.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeBatchError {
    /// A field, count or encoded byte bound is invalid.
    #[error("scope_batch_invalid_request")]
    InvalidRequest,
    /// The scope grant, platform admission or profile gate refused this operation.
    /// `ProfileNotActivated` is a no-effect, retryable result; retry the exact
    /// request so the service can activate the current configuration.
    #[error("scope_batch_authority: {0}")]
    Scope(ScopeLeaseError),
    /// No effect occurred; reread and regroup these comparisons.
    #[error("scope_batch_conflict")]
    Conflict(ScopeBatchConflicts),
    /// The expected batch revision does not match the current revision.
    #[error("scope_batch_revision_conflict")]
    RevisionConflict,
    /// The retained request ID was reused with changed bytes.
    #[error("scope_batch_idempotency_conflict")]
    IdempotencyConflict,
    /// An incompatible or inconsistent stored profile was found.
    #[error("scope_batch_format_mismatch")]
    FormatMismatch,
    /// The exact request may have committed; retry it before any successor.
    #[error("scope_batch_outcome_unknown")]
    OutcomeUnknown,
    /// A linearizable, strictly durable backend was unavailable.
    #[error("scope_batch_unavailable")]
    Unavailable,
}
impl From<ScopeLeaseError> for ScopeBatchError {
    fn from(value: ScopeLeaseError) -> Self {
        Self::Scope(value)
    }
}

/// One committed atomic outcome. Entries correspond to request mutation order;
/// deletion returns the final tombstone revision, not a live child record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchOutcome {
    request_digest: [u8; 32],
    lane: u8,
    sequence: u64,
    revision: u64,
    rows: Vec<ScopeChildRevision>,
    counters: [u64; SCOPE_COUNTERS],
}

/// Current batch revision and fixed counters, observed through a linearizable
/// point read. This observation never grants ownership or a coherent scan.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeBatchView {
    revision: u64,
    counters: [u64; SCOPE_COUNTERS],
}
impl ScopeBatchView {
    /// Exact revision for the next serialized batch, zero before first use.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Current bounded accounting values.
    pub const fn counters(&self) -> &[u64; SCOPE_COUNTERS] {
        &self.counters
    }
}
impl ScopeBatchOutcome {
    /// Replay lane of the committed request.
    pub const fn lane(&self) -> u8 {
        self.lane
    }
    /// Exact committed sequence within that lane.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Revision for the next serialized batch.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Committed child versions in request order.
    pub fn rows(&self) -> &[ScopeChildRevision] {
        &self.rows
    }
    /// Counter values after all changes committed together.
    pub const fn counters(&self) -> &[u64; SCOPE_COUNTERS] {
        &self.counters
    }
}

/// One stored child and its exact birth, generation, sealed value and claims.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeChildRecord {
    pub(crate) scope: ScopeLeaseId,
    pub(crate) key: ScopeChildKey,
    pub(crate) revision: ScopeChildRevision,
    pub(crate) batch_revision: u64,
    pub(crate) value: Option<ScopeSealedValue>,
    pub(crate) claims: Vec<ScopeClaimKey>,
}
impl ScopeChildRecord {
    /// Exact opaque child identity.
    pub const fn key(&self) -> ScopeChildKey {
        self.key
    }
    /// Current birth and generation.
    pub const fn revision(&self) -> ScopeChildRevision {
        self.revision
    }
    /// Sealed value; a deletion tombstone has no value.
    pub const fn value(&self) -> Option<&ScopeSealedValue> {
        self.value.as_ref()
    }
    /// Complete current claim set.
    pub fn claims(&self) -> &[ScopeClaimKey] {
        &self.claims
    }
}

/// Internal versioned command. The quorum service authenticates and admits its
/// caller; replicated apply independently checks the retained scope fence.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchCommand {
    pub(crate) request: ScopeBatchRequest,
    pub(crate) bounds: ScopeClockBounds,
}
impl ScopeBatchCommand {
    #[cfg(target_os = "linux")]
    pub(crate) fn log_row_reuse_allocation_bytes(&self) -> Option<usize> {
        use std::mem::size_of;
        // The fixed authority allowance covers the bounded scope and execution
        // identifiers. Child values and every Vec use their actual capacities.
        let mut bytes = size_of::<Self>()
            .checked_add(crate::scope_lease::MAX_SCOPE_LEASE_RECORD_BYTES)?
            .checked_add(
                self.request
                    .operations
                    .capacity()
                    .checked_mul(size_of::<ScopeChildMutation>())?,
            )?
            .checked_add(
                self.request
                    .counters
                    .capacity()
                    .checked_mul(size_of::<ScopeCounterMutation>())?,
            )?;
        for operation in &self.request.operations {
            if let ScopeChildMutation::Create { value, claims, .. }
            | ScopeChildMutation::CompareAndSet { value, claims, .. } = operation
            {
                bytes = bytes
                    .checked_add(value.0.capacity())?
                    .checked_add(claims.capacity().checked_mul(size_of::<ScopeClaimKey>())?)?;
            }
        }
        Some(bytes)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn largest_value_bytes(&self) -> usize {
        self.request
            .operations
            .iter()
            .map(|operation| match operation {
                ScopeChildMutation::Create { value, .. }
                | ScopeChildMutation::CompareAndSet { value, .. } => value.envelope().len(),
                ScopeChildMutation::Delete { .. } => 0,
            })
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn matches_error(&self, error: &ScopeBatchError) -> bool {
        match error {
            ScopeBatchError::Conflict(conflicts) => {
                let unique = |len, count| len == count;
                (!conflicts.children.is_empty()
                    || !conflicts.claims.is_empty()
                    || !conflicts.counters.is_empty())
                    && conflicts.children.len() <= MAX_SCOPE_BATCH_CHILDREN
                    && conflicts.claims.len() <= MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS
                    && conflicts.counters.len() <= SCOPE_COUNTERS
                    && unique(
                        conflicts.children.len(),
                        conflicts.children.iter().collect::<HashSet<_>>().len(),
                    )
                    && unique(
                        conflicts.claims.len(),
                        conflicts.claims.iter().collect::<HashSet<_>>().len(),
                    )
                    && unique(
                        conflicts.counters.len(),
                        conflicts.counters.iter().collect::<HashSet<_>>().len(),
                    )
                    && conflicts
                        .children
                        .iter()
                        .all(|key| self.request.operations.iter().any(|op| op.key() == *key))
                    && conflicts.claims.iter().all(|key| {
                        self.request
                            .operations
                            .iter()
                            .any(|op| op.claims().contains(key))
                    })
                    && conflicts
                        .counters
                        .iter()
                        .all(|key| self.request.counters.iter().any(|op| op.counter == *key))
            }
            _ => true,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        self.request.validate()?;
        ScopeClockBounds::new(self.bounds.earliest(), self.bounds.latest())?;
        Ok(())
    }
    pub(crate) fn matches(&self, outcome: &ScopeBatchOutcome) -> bool {
        self.request.digest() == Ok(outcome.request_digest)
            && outcome.lane == self.request.lane
            && outcome.sequence == self.request.sequence
            && outcome.revision == self.request.expected_revision + 1
            && outcome.rows.len() == self.request.operations.len()
            && outcome
                .rows
                .iter()
                .zip(&self.request.operations)
                .all(|(row, op)| {
                    ScopeChildRevision::new(row.birth, row.generation).is_ok()
                        && match op.expected() {
                            Some(old) => {
                                row.birth == old.birth && row.generation == old.generation + 1
                            }
                            None => row.generation == 1,
                        }
                })
            && outcome.counters.iter().all(|value| *value <= COUNTER_MAX)
            && self
                .request
                .counters
                .iter()
                .all(|counter| outcome.counters[usize::from(counter.counter)] == counter.next)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeBatchCheckpoint {
    pub(crate) scope: ScopeLeaseId,
    pub(crate) revision: u64,
    pub(crate) birth_floor: u64,
    pub(crate) counters: [u64; SCOPE_COUNTERS],
    lanes: [ScopeBatchLaneCheckpoint; SCOPE_BATCH_LANES],
}

/// Reserve the complete fixed lane layout now. Only slot zero is populated
/// until independent lanes are enabled; other slots must remain canonical zero.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeBatchLaneCheckpoint {
    floor: u64,
    sequence: u64,
    last_request_id: [u8; 16],
    last_digest: [u8; 32],
    outcome: Option<ScopeBatchOutcome>,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })+ };
}
redacted_debug!(
    ScopeChildKey,
    ScopeClaimKey,
    ScopeChildRevision,
    ScopeSealedValue,
    ScopeChildMutation,
    ScopeCounterMutation,
    ScopeBatchRequest,
    ScopeBatchConflicts,
    ScopeBatchError,
    ScopeBatchOutcome,
    ScopeBatchView,
    ScopeChildRecord,
    ScopeBatchCommand,
    ScopeBatchCheckpoint,
    ScopeBatchLaneCheckpoint
);

#[cfg(test)]
pub(crate) mod tests;
