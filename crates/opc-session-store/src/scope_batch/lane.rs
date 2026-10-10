//! Pure replay-frontier decisions; authority and terminal effects stay with apply.

use std::fmt;

/// Computed from a complete, validated attempt, never accepted as a wire proof.
/// The binding digest includes namespace, full authority stamp, lane, sequence,
/// request ID and canonical request digest. It is recomputed from query fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct LaneAttemptKey {
    pub(super) sequence: u64,
    pub(super) request_id: [u8; 16],
    pub(super) binding_digest: [u8; 32],
}

impl LaneAttemptKey {
    fn validate(&self) -> Result<(), LaneProtocolError> {
        if !(1..=i64::MAX as u64).contains(&self.sequence) || self.request_id == [0; 16] {
            return Err(LaneProtocolError::InvalidAttempt);
        }
        Ok(())
    }
}

/// A validated projection of a stored lane and its immutable terminal receipt.
/// The enclosing checkpoint additionally validates complete receipt bytes.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct LaneFrontier {
    pub(super) sequence: u64,
    pub(super) discarded_through: u64,
    pub(super) retained: Option<LaneAttemptKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LaneLookup {
    Retained,
    NotApplied,
    NotRecorded,
    Pruned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LaneProtocolError {
    InvalidAttempt,
    Corrupt,
    IdempotencyConflict,
    SequenceConflict,
    SequenceExhausted,
}

impl LaneFrontier {
    pub(super) fn validate(&self) -> Result<(), LaneProtocolError> {
        if self.sequence == 0 {
            return if self.discarded_through == 0 && self.retained.is_none() {
                Ok(())
            } else {
                Err(LaneProtocolError::Corrupt)
            };
        }
        let retained = self.retained.ok_or(LaneProtocolError::Corrupt)?;
        if self.sequence > i64::MAX as u64
            || self.discarded_through != self.sequence - 1
            || retained.sequence != self.sequence
            || retained.validate().is_err()
        {
            return Err(LaneProtocolError::Corrupt);
        }
        Ok(())
    }

    /// `permanently_fenced` must come from the same authority/checkpoint cut.
    /// Neither the caller's clock nor an absent receipt supplies that proof.
    pub(super) fn lookup(
        &self,
        attempt: &LaneAttemptKey,
        permanently_fenced: bool,
    ) -> Result<LaneLookup, LaneProtocolError> {
        self.validate()?;
        attempt.validate()?;
        if let Some(retained) = self.retained {
            if retained.request_id == attempt.request_id {
                return if retained == *attempt {
                    Ok(LaneLookup::Retained)
                } else {
                    Err(LaneProtocolError::IdempotencyConflict)
                };
            }
        }
        if attempt.sequence <= self.discarded_through {
            return Ok(LaneLookup::Pruned);
        }
        if attempt.sequence == self.sequence || permanently_fenced {
            return Ok(LaneLookup::NotApplied);
        }
        Ok(LaneLookup::NotRecorded)
    }

    pub(super) fn next_sequence(&self) -> Result<u64, LaneProtocolError> {
        self.validate()?;
        self.sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or(LaneProtocolError::SequenceExhausted)
    }

    /// Return a detached terminal successor. Authority and all effects must be
    /// checked before this is published atomically with the complete receipt.
    pub(super) fn advance(&self, attempt: LaneAttemptKey) -> Result<Self, LaneProtocolError> {
        self.lookup(&attempt, false)?;
        if attempt.sequence != self.next_sequence()? {
            return Err(LaneProtocolError::SequenceConflict);
        }
        Ok(Self {
            sequence: attempt.sequence,
            discarded_through: attempt.sequence - 1,
            retained: Some(attempt),
        })
    }
}

impl fmt::Debug for LaneAttemptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LaneAttemptKey(<redacted>)")
    }
}

impl fmt::Debug for LaneFrontier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LaneFrontier(<redacted>)")
    }
}

#[cfg(test)]
#[path = "lane_tests.rs"]
mod tests;
