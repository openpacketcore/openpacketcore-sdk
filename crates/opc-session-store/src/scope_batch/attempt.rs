//! Exact immutable attempts and the sole terminal winner of apply/cancel.

use super::*;

/// Complete immutable attempt identity without child payloads. A decoded value
/// is an observation or query key; it grants neither authority nor effect rights.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchAttempt {
    pub(super) stamp: ScopeAuthorityStamp,
    pub(super) request_id: [u8; 16],
    pub(super) lane: u8,
    pub(super) sequence: u64,
    pub(super) request_digest: [u8; 32],
}

impl ScopeBatchRequest {
    /// Extract the exact identity for cancellation and read-only resolution.
    pub fn attempt(&self) -> Result<ScopeBatchAttempt, ScopeBatchError> {
        Ok(ScopeBatchAttempt {
            stamp: self.stamp.clone(),
            request_id: self.request_id,
            lane: self.lane,
            sequence: self.sequence,
            request_digest: self.digest()?,
        })
    }
}

impl ScopeBatchAttempt {
    /// Exact admitted authority named by the original request.
    pub const fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }
    /// Original nonzero request identity.
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    /// Independently sequenced lane.
    pub const fn lane(&self) -> u8 {
        self.lane
    }
    /// Exact positive terminal sequence this attempt competes for.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Canonical digest of every field in the original request.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    /// Domain-separated commitment to cancelling this exact immutable attempt.
    /// Authenticated transports can bind cancellation without the child payloads.
    pub fn cancellation_digest(&self) -> Result<[u8; 32], ScopeBatchError> {
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-batch/cancel/v4\0");
        hash.update(self.encode_canonical()?);
        Ok(hash.finalize().into())
    }
    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        self.stamp.validate()?;
        if self.request_id == [0; 16]
            || usize::from(self.lane) >= SCOPE_BATCH_LANES
            || !(1..=COUNTER_MAX).contains(&self.sequence)
        {
            return Err(ScopeBatchError::InvalidRequest);
        }
        Ok(())
    }
    pub(super) fn key(&self) -> Result<lane::LaneAttemptKey, ScopeBatchError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-batch/attempt/v4\0");
        hash.update(postcard::to_allocvec(self).map_err(|_| ScopeBatchError::InvalidRequest)?);
        Ok(lane::LaneAttemptKey {
            sequence: self.sequence,
            request_id: self.request_id,
            binding_digest: hash.finalize().into(),
        })
    }
}

/// Sole durable winner for one immutable attempt and lane sequence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeBatchTerminal {
    /// The complete bounded effects committed atomically with this receipt.
    Applied(Box<ScopeBatchOutcome>),
    /// Cancellation consumed the sequence without changing children or counters.
    Cancelled,
}

/// Complete retained terminal receipt, including the original authority stamp.
/// Deserializing this value alone is never evidence of authority or commitment.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchReceipt {
    pub(super) attempt: ScopeBatchAttempt,
    pub(super) revision: u64,
    pub(super) terminal: ScopeBatchTerminal,
}

impl ScopeBatchReceipt {
    /// Complete immutable attempt that won this terminal sequence.
    pub const fn attempt(&self) -> &ScopeBatchAttempt {
        &self.attempt
    }
    /// Stable-scope revision at which this terminal receipt committed.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Immutable applied or cancelled terminal winner.
    pub const fn terminal(&self) -> &ScopeBatchTerminal {
        &self.terminal
    }
    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        self.attempt.validate()?;
        if !(self.attempt.sequence..=COUNTER_MAX).contains(&self.revision) {
            return Err(ScopeBatchError::InvalidRequest);
        }
        if let ScopeBatchTerminal::Applied(outcome) = &self.terminal {
            outcome.validate()?;
            if outcome.request_digest != self.attempt.request_digest
                || outcome.lane != self.attempt.lane
                || outcome.sequence != self.attempt.sequence
                || outcome.revision != self.revision
            {
                return Err(ScopeBatchError::InvalidRequest);
            }
        }
        Ok(())
    }
}

/// Read-only result from one authority/checkpoint cut after a full quorum barrier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeBatchLookup {
    /// Exact retained receipt proves application.
    Applied(Box<ScopeBatchOutcome>),
    /// Exact retained receipt proves cancellation.
    Cancelled,
    /// The sequence or permanently superseded authority excludes application.
    NotApplied,
    /// No terminal receipt is recorded; a still-eligible attempt may apply later.
    NotRecorded,
    /// The receipt was discarded; fencing does not recover its historical result.
    Pruned,
}

/// Internal cancellation command. Apply compares the same complete attempt as
/// the original batch; the winning terminal receipt can never be overwritten.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBatchCancelCommand {
    pub(crate) attempt: ScopeBatchAttempt,
}

impl ScopeBatchCancelCommand {
    pub(crate) fn validate(&self) -> Result<(), ScopeBatchError> {
        self.attempt.encode_canonical().map(|_| ())
    }
    pub(crate) fn proposal_id(&self) -> Result<[u8; 16], ScopeBatchError> {
        let digest = self.attempt.cancellation_digest()?;
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Ok(id)
    }
    pub(crate) fn matches(&self, receipt: &ScopeBatchReceipt) -> bool {
        self.validate().is_ok() && receipt.validate().is_ok() && receipt.attempt == self.attempt
    }
    pub(crate) fn matches_error(&self, error: &ScopeBatchError) -> bool {
        !matches!(
            error,
            ScopeBatchError::Conflict(_)
                | ScopeBatchError::RevisionConflict
                | ScopeBatchError::Cancelled
                | ScopeBatchError::ScopeGuardStalled
        )
    }
}

impl fmt::Debug for ScopeBatchAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeBatchAttempt(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeBatchTerminal(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeBatchReceipt(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeBatchLookup(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchCancelCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeBatchCancelCommand(<redacted>)")
    }
}
