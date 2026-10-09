//! Shared backend dispatch for the two competing terminal transitions.

use super::*;
use crate::consensus::{SessionMutationIntent, SessionMutationOutcome};
use crate::scope_storage::ScopeRow;

#[derive(Clone, Copy)]
pub(crate) enum Operation<'a> {
    Apply(&'a ScopeBatchCommand),
    Cancel(&'a ScopeBatchCancelCommand),
}

impl<'a> Operation<'a> {
    pub(crate) fn from_intent(intent: &'a SessionMutationIntent) -> Option<Self> {
        let intent = match intent {
            SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
            intent => intent,
        };
        match intent {
            SessionMutationIntent::ScopeBatch(command) => Some(Self::Apply(command)),
            SessionMutationIntent::ScopeBatchCancel(command) => Some(Self::Cancel(command)),
            _ => None,
        }
    }

    pub(crate) fn scope(self) -> &'a ScopeId {
        match self {
            Self::Apply(command) => command.request.scope(),
            Self::Cancel(command) => command.attempt.stamp.scope(),
        }
    }

    pub(crate) fn validate(self) -> Result<(), ScopeBatchError> {
        match self {
            Self::Apply(command) => command.validate(),
            Self::Cancel(command) => command.validate(),
        }
    }

    pub(crate) fn plan(
        self,
        authority: &ScopeState,
        checkpoint: &ScopeBatchCheckpoint,
        read: impl Fn(&SessionKey) -> Result<Option<ScopeRow>, ScopeBatchError>,
    ) -> Result<state::ScopeBatchPlan, ScopeBatchError> {
        match self {
            Self::Apply(command) => command.plan(authority, checkpoint, read),
            Self::Cancel(command) => command.plan(authority, checkpoint),
        }
    }

    pub(crate) fn success(
        self,
        checkpoint: &ScopeBatchCheckpoint,
    ) -> Result<SessionMutationOutcome, ScopeBatchError> {
        match self {
            Self::Apply(command) => checkpoint
                .outcome(command.request.lane())
                .filter(|outcome| command.matches(outcome))
                .cloned()
                .map(|outcome| SessionMutationOutcome::ScopeBatch(Ok(outcome))),
            Self::Cancel(command) => checkpoint
                .receipt(command.attempt.lane())
                .filter(|receipt| command.matches(receipt))
                .cloned()
                .map(|receipt| SessionMutationOutcome::ScopeBatchCancel(Ok(receipt))),
        }
        .ok_or(ScopeBatchError::FormatMismatch)
    }

    pub(crate) fn failure(self, error: ScopeBatchError) -> SessionMutationOutcome {
        match self {
            Self::Apply(_) => SessionMutationOutcome::ScopeBatch(Err(error)),
            Self::Cancel(_) => SessionMutationOutcome::ScopeBatchCancel(Err(error)),
        }
    }
}
