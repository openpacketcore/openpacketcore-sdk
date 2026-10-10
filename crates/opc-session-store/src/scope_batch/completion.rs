//! Terminal observations delivered until exact application reconciliation.

use super::*;
use crate::scope_authority::ScopeAuthorityView;

/// Positive no-application evidence produced by a validated same-cut lookup,
/// including an immutable same-lane receipt that permanently excludes the attempt.
/// It is bound to an exact attempt and grants no effect or mutation authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeBatchNoApplyProof {
    binding: [u8; 32],
    authority: ScopeAuthorityView,
    revision: u64,
    lane_sequence: u64,
}

impl ScopeBatchNoApplyProof {
    pub(super) fn new(
        attempt: &ScopeBatchAttempt,
        cut: &ScopeBatchReopen,
    ) -> Result<Self, ScopeBatchError> {
        match cut.lookup(attempt) {
            Ok(ScopeBatchLookup::NotApplied) => {}
            Err(ScopeBatchError::IdempotencyConflict) => {
                // The lookup already validated the complete cut and scope.
                // At the same sequence, an immutable different receipt won.
                // At the next sequence, retiring this colliding receipt would
                // itself consume the attempted sequence. Neither can apply.
                // A gap or another lane can become eligible later; old pruned
                // attempts may already have applied. They remain unresolved.
                let permanent = match cut {
                    ScopeBatchReopen::Initialized(view) => view.lanes()
                        [usize::from(attempt.lane())]
                    .receipt()
                    .is_some_and(|receipt| {
                        receipt.attempt().request_id() == attempt.request_id()
                            && receipt.attempt() != attempt
                            && (receipt.attempt().sequence() == attempt.sequence()
                                || Some(receipt.attempt().sequence())
                                    == attempt.sequence().checked_sub(1))
                    }),
                    ScopeBatchReopen::Uninitialized => false,
                };
                if !permanent {
                    return Err(ScopeBatchError::IdempotencyConflict);
                }
            }
            Err(error) => return Err(error),
            _ => return Err(ScopeBatchError::OutcomeUnknown),
        }
        let ScopeBatchReopen::Initialized(view) = cut else {
            return Err(ScopeBatchError::OutcomeUnknown);
        };
        Ok(Self {
            binding: attempt.key()?.binding_digest,
            authority: view.authority().clone(),
            revision: view.revision(),
            lane_sequence: view.lanes()[usize::from(attempt.lane())].sequence(),
        })
    }
    /// Check the complete original namespace, authority, ID, lane, sequence and digest.
    pub fn matches(&self, attempt: &ScopeBatchAttempt) -> bool {
        attempt
            .key()
            .is_ok_and(|key| key.binding_digest == self.binding)
    }
    /// Authority observed in the same backend snapshot as the lane frontier.
    pub const fn authority(&self) -> &ScopeAuthorityView {
        &self.authority
    }
    /// Stable-scope revision observed by this proof.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Last consumed sequence observed in the attempted lane.
    pub const fn lane_sequence(&self) -> u64 {
        self.lane_sequence
    }
}

/// A positively resolved result; uncertainty never appears on the terminal stream.
#[derive(Clone, PartialEq, Eq)]
pub enum ScopeBatchCompletionOutcome {
    /// The exact complete atomic outcome was retained or returned by committed apply.
    Applied(Box<ScopeBatchOutcome>),
    /// Cancellation won the exact attempt's terminal sequence.
    Cancelled,
    /// A consumed sequence, permanent ID collision or superseded authority
    /// excludes application.
    NotApplied(Box<ScopeBatchNoApplyProof>),
}

/// One exact terminal result, delivered at least once until acknowledged.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeBatchCompletion {
    pub(super) attempt: ScopeBatchAttempt,
    pub(super) outcome: ScopeBatchCompletionOutcome,
    pub(super) refusal: Option<ScopeBatchError>,
}

impl ScopeBatchCompletion {
    pub(super) fn from_receipt(receipt: ScopeBatchReceipt) -> Result<Self, ScopeBatchError> {
        receipt.validate()?;
        Ok(Self {
            attempt: receipt.attempt,
            outcome: match receipt.terminal {
                ScopeBatchTerminal::Applied(outcome) => {
                    ScopeBatchCompletionOutcome::Applied(outcome)
                }
                ScopeBatchTerminal::Cancelled => ScopeBatchCompletionOutcome::Cancelled,
            },
            refusal: None,
        })
    }
    /// Complete immutable identity of the resolved request.
    pub const fn attempt(&self) -> &ScopeBatchAttempt {
        &self.attempt
    }
    /// The terminal result to reconcile before acknowledging this attempt.
    pub const fn outcome(&self) -> &ScopeBatchCompletionOutcome {
        &self.outcome
    }
    /// A preceding no-effect refusal that caused the supervisor to seal the attempt.
    /// An Applied race still wins; this field cannot override its terminal result.
    pub const fn refusal(&self) -> Option<&ScopeBatchError> {
        self.refusal.as_ref()
    }
}

impl fmt::Debug for ScopeBatchNoApplyProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchNoApplyProof(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchCompletionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchCompletionOutcome(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchCompletion(<redacted>)")
    }
}
