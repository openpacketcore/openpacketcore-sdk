//! One non-escaping predicate reader borrows the builder's running entitlement.
use super::*;
use std::future::Future;
use tokio::time::{timeout_at, Instant as Deadline};

/// Explicit limits for the complete post-grant builder, including its reopening
/// observation, predicate reads and request construction. Every attempted child
/// exchange consumes budget; no retry or split is implicit.
#[derive(Clone, Copy, Debug)]
pub struct ScopeBatchReadBudget {
    deadline: Deadline,
    exchanges: usize,
}

impl ScopeBatchReadBudget {
    /// Require 1–64 exchanges and a fixed absolute monotonic deadline.
    /// An elapsed deadline is refused when the builder starts, without dispatch.
    pub fn new(deadline: Deadline, exchanges: usize) -> Result<Self, ScopeChildReadError> {
        if !(1..=64).contains(&exchanges) {
            return Err(ScopeBatchError::InvalidRequest.into());
        }
        Ok(Self {
            deadline,
            exchanges,
        })
    }

    /// Unchanged deadline shared by all stages of this builder.
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Maximum attempted child exchanges, including refusals and explicit splits.
    pub const fn max_exchanges(&self) -> usize {
        self.exchanges
    }
}

/// A serialized predicate reader borrowed from one admitted builder. It has no
/// public constructor, cannot be cloned, and never reserves another entitlement.
/// Its class is fixed by the actual running grant, including lane inheritance.
///
/// The context cannot escape its enclosing builder:
/// ```compile_fail
/// use opc_session_store::scope_batch::ScopeBatchReadContext;
/// fn escape(context: ScopeBatchReadContext<'_>) -> ScopeBatchReadContext<'static> {
///     context
/// }
/// ```
/// It cannot be detached into independently running work:
/// ```compile_fail
/// use opc_session_store::scope_batch::ScopeBatchReadContext;
/// fn detach(context: ScopeBatchReadContext<'_>) {
///     tokio::spawn(async move { drop(context); });
/// }
/// ```
pub struct ScopeBatchReadContext<'run> {
    build: &'run ScopeBatchBuildContext,
    stamp: &'run ScopeAuthorityStamp,
    backend: &'run dyn ScopeBatchPort,
    permit: &'run ScopeWorkPermit,
    deadline: Deadline,
    remaining: usize,
}

impl<'run> ScopeBatchReadContext<'run> {
    pub(super) fn new(
        build: &'run ScopeBatchBuildContext,
        stamp: &'run ScopeAuthorityStamp,
        backend: &'run dyn ScopeBatchPort,
        permit: &'run ScopeWorkPermit,
        budget: ScopeBatchReadBudget,
    ) -> Self {
        Self {
            build,
            stamp,
            backend,
            permit,
            deadline: budget.deadline,
            remaining: budget.exchanges,
        }
    }

    /// Fresh lane, sequence and authority/ledger facts obtained after running admission.
    pub const fn build(&self) -> &ScopeBatchBuildContext {
        self.build
    }

    /// Trusted effective class of this running attempt, never a response claim.
    pub const fn class(&self) -> ScopeWorkClass {
        self.permit.class()
    }

    /// Read an ordered set under the earlier of this call's and the builder's
    /// original deadline. A mutable borrow serializes exchanges. Refusals consume
    /// budget; a caller may explicitly split an oversized request within that budget.
    pub async fn read_children(
        &mut self,
        keys: &[ScopeChildKey],
        deadline: Deadline,
    ) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        if self.remaining == 0 {
            return Err(ScopeChildReadError::ReadBudgetExceeded);
        }
        self.remaining -= 1;
        super::super::child_read::validate_keys(keys)?;
        let request = ScopeChildReadRequest::new(self.stamp, keys.to_vec())?;
        let rows = before(
            deadline.min(self.deadline),
            self.backend
                .read_current(&request, self.class(), deadline.min(self.deadline)),
        )
        .await?;
        if Deadline::now() >= deadline.min(self.deadline)
            || rows.len() != keys.len()
            || rows.iter().zip(keys).any(|(row, key)| {
                row.as_ref().is_some_and(|row| {
                    row.namespace() != self.stamp.namespace()
                        || row.key() != *key
                        || row.validate().is_err()
                })
            })
        {
            return Err(ScopeBatchError::Unavailable.into());
        }
        Ok(rows)
    }
}

impl fmt::Debug for ScopeBatchReadContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchReadContext(<redacted>)")
    }
}

pub(super) async fn before<T>(
    deadline: Deadline,
    work: impl Future<Output = Result<T, ScopeChildReadError>>,
) -> Result<T, ScopeChildReadError> {
    if Deadline::now() >= deadline {
        return Err(ScopeBatchError::Unavailable.into());
    }
    timeout_at(deadline, work)
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
}
