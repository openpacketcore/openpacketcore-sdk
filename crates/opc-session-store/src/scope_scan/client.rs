//! Bounded, cut-aware restore driver over a trusted local or authenticated port.

use super::{
    progress::InventoryTotals,
    protocol::ReplyBody,
    retry::{RestoreRetryState, RetryDecision},
};
use super::{
    ScopeCut, ScopeRestoreStalled, ScopeScanCheckpoint, ScopeScanCursor, ScopeScanError,
    ScopeScanPageLimits, ScopeScanReply, ScopeScanRetryCause, ScopeScanRetryPolicy,
};
use crate::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT;
use crate::{scope_authority::ScopeAuthorityView, SessionConsensusNodeId};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::time::{sleep, timeout, timeout_at, Instant};

/// Immutable opening observations returned by the trusted transport.
/// A remote implementation must authenticate and bind these to its handle.
pub trait ScopeScanClientView: Send + Sync {
    /// Immutable cut; all replies must match it exactly.
    fn cut(&self) -> &ScopeCut;
    /// Successor authority observed at the cut; it grants no new capability.
    fn authority(&self) -> &ScopeAuthorityView;
    /// Stable-scope checkpoint observed with the inventory.
    fn checkpoint(&self) -> &ScopeScanCheckpoint;
    /// Input to the first page. Retry this cursor until its reply is accepted.
    fn initial_cursor(&self) -> &ScopeScanCursor;
}

/// A port distinguishes resource recovery from a final refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeScanRequestFailure {
    /// Consume one recovery attempt; only lost-cut causes reopen.
    Retryable(ScopeScanRetryCause),
    /// Stop this restore. A new authority grant requires a new caller decision.
    Final(ScopeScanError),
}

/// Trusted scan transport. Pages stay on the opened handle's serving node.
/// Authentication, frame bounds and response binding are the implementation's
/// responsibility. Admission and local backpressure wait until the caller's
/// restore deadline or cancellation; they do not consume recovery attempts.
#[async_trait]
pub trait ScopeScanTransport: Send + Sync {
    /// Owning handle. Its drop must release local resources or leave only the
    /// server's bounded idle retention; it must not keep a view alive forever.
    type View: ScopeScanClientView;
    /// Prefer this node on reopen; an initial open may prefer the leader.
    async fn open(
        &self,
        preferred: Option<SessionConsensusNodeId>,
        limits: ScopeScanPageLimits,
    ) -> Result<Self::View, ScopeScanRequestFailure>;
    /// Exactly retry the supplied input cursor on a transient transport failure.
    async fn page(
        &self,
        view: &Self::View,
        cursor: &ScopeScanCursor,
    ) -> Result<Arc<ScopeScanReply>, ScopeScanRequestFailure>;
    /// Best-effort close, also bounded by the driver's request deadline.
    async fn close(&self, view: Self::View);
}

/// Streaming staging for one cut, with no whole-inventory buffer in the SDK.
#[async_trait]
pub trait ScopeScanSink: Send {
    /// Consumer failure stops this restore and discards its staging.
    type Error: Send;
    /// Consumer result after accepting a complete inventory.
    type Output: Send;
    /// Prepare staging. A cancelled or failed begin is followed by discard.
    async fn begin(
        &mut self,
        cut: &ScopeCut,
        authority: &ScopeAuthorityView,
        checkpoint: &ScopeScanCheckpoint,
    ) -> Result<(), Self::Error>;
    /// Accept one page before the SDK sends its successor acknowledgement.
    /// Preserve held-claim and incomplete-inventory restrictions independently
    /// of staging: discard/reopen must never clear these safety restrictions.
    async fn stage(&mut self, reply: &ScopeScanReply) -> Result<(), Self::Error>;
    /// Commit staging only after an explicit same-cut Complete. Every failure
    /// has already appeared in the stream; the low-level API provides rescans.
    async fn finish(&mut self, reply: &ScopeScanReply) -> Result<Self::Output, Self::Error>;
    /// Synchronously discard this cut's partial staging, including on future
    /// cancellation. Preserve independently required claim/allocation restrictions.
    fn discard(&mut self, cut: &ScopeCut);
}

/// Final result of one restore driver invocation.
#[derive(Debug)]
pub enum ScopeScanClientError<E> {
    /// The caller's overall deadline elapsed, including admission and staging.
    DeadlineElapsed,
    /// The lifetime recovery budget ended; it is not reset by progress or reopen.
    Stalled(ScopeRestoreStalled),
    /// Final operation-level refusal.
    Request(ScopeScanError),
    /// A trusted transport returned inconsistent cut or protocol observations.
    InvalidReply,
    /// Staging failed and was discarded.
    Sink(E),
}

/// One streaming client invocation owns one recovery budget across all cuts.
pub struct ScopeScanClient<T> {
    transport: T,
    limits: ScopeScanPageLimits,
    policy: ScopeScanRetryPolicy,
}
impl<T: ScopeScanTransport> ScopeScanClient<T> {
    /// Use the default 256-row pages and sixteen lifetime recovery attempts.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ScopeScanPageLimits::default(),
            policy: ScopeScanRetryPolicy::default(),
        }
    }
    /// Select validated per-page and finite retry limits before starting.
    pub fn with_limits(
        mut self,
        limits: ScopeScanPageLimits,
        policy: ScopeScanRetryPolicy,
    ) -> Self {
        self.limits = limits;
        self.policy = policy;
        self
    }
    /// Restore without materializing the whole inventory, within one required
    /// caller-owned deadline. Admission, paging, staging and recovery share
    /// that deadline; queue waits retain their place without consuming retries.
    /// Dropping this future or reaching the deadline discards partial staging.
    pub async fn restore<S: ScopeScanSink>(
        &self,
        sink: &mut S,
        deadline: Instant,
    ) -> Result<S::Output, ScopeScanClientError<S::Error>> {
        if Instant::now() >= deadline {
            return Err(ScopeScanClientError::DeadlineElapsed);
        }
        timeout_at(deadline, self.restore_inner(sink))
            .await
            .unwrap_or(Err(ScopeScanClientError::DeadlineElapsed))
    }

    async fn restore_inner<S: ScopeScanSink>(
        &self,
        sink: &mut S,
    ) -> Result<S::Output, ScopeScanClientError<S::Error>> {
        let mut staging = Staging { sink, cut: None };
        let mut retries = RestoreRetryState::new(self.policy, self.limits.rows())
            .map_err(|_| ScopeScanClientError::Request(ScopeScanError::InvalidPageLimits))?;
        let mut limits = self.limits;
        let mut preferred = None;
        'open: loop {
            let view = loop {
                let result = self.transport.open(preferred, limits).await;
                match result {
                    Ok(view) => break view,
                    Err(ScopeScanRequestFailure::Final(error)) => {
                        return Err(ScopeScanClientError::Request(error))
                    }
                    Err(ScopeScanRequestFailure::Retryable(cause)) => match retries.failed(cause) {
                        RetryDecision::Stalled(stalled) => {
                            return Err(ScopeScanClientError::Stalled(stalled))
                        }
                        RetryDecision::Retry {
                            row_limit, delay, ..
                        } => {
                            limits.0.rows = row_limit;
                            sleep(delay).await;
                        }
                    },
                }
            };
            if view
                .authority()
                .stamp()
                .is_none_or(|stamp| stamp.namespace() != view.cut().namespace())
                || !view.authority().is_active()
                || view.authority().revision() != view.cut().authority_revision()
                || view.checkpoint().revision() != view.cut().batch_revision()
            {
                self.close(view).await;
                return Err(ScopeScanClientError::InvalidReply);
            }
            preferred = Some(view.cut().serving_node());
            // Own the rollback before beginning: cancellation halfway through
            // the consumer's begin/stage awaits must discard that partial cut.
            staging.cut = Some(view.cut().clone());
            if let Err(error) = staging
                .sink
                .begin(view.cut(), view.authority(), view.checkpoint())
                .await
            {
                staging.discard();
                self.close(view).await;
                return Err(ScopeScanClientError::Sink(error));
            }
            let mut cursor = view.initial_cursor().clone();
            let mut last = None;
            let mut totals = InventoryTotals::default();
            loop {
                let result = self.transport.page(&view, &cursor).await;
                let failure = match result {
                    Err(failure) => failure,
                    Ok(reply) => {
                        if reply.cut() != view.cut() {
                            staging.discard();
                            self.close(view).await;
                            return Err(ScopeScanClientError::InvalidReply);
                        }
                        match &reply.body {
                            ReplyBody::Data { items, next } => {
                                let mut observed = totals;
                                let mut position = last.clone();
                                let valid = !items.is_empty()
                                    && next != &cursor
                                    && items.iter().all(|item| {
                                        if position
                                            .as_ref()
                                            .is_some_and(|previous| &item.position <= previous)
                                        {
                                            return false;
                                        }
                                        let Some(count) = observed.items.checked_add(1) else {
                                            return false;
                                        };
                                        observed.items = count;
                                        let failures = item.inspection.failures.len() as u64;
                                        let Some(count) = observed.failures.checked_add(failures)
                                        else {
                                            return false;
                                        };
                                        observed.failures = count;
                                        if failures > 0 {
                                            let Some(count) = observed.failed_items.checked_add(1)
                                            else {
                                                return false;
                                            };
                                            observed.failed_items = count;
                                        }
                                        observed.claims_incomplete |=
                                            item.inspection.inventory_incomplete;
                                        position = Some(item.position.clone());
                                        true
                                    });
                                if !valid {
                                    staging.discard();
                                    self.close(view).await;
                                    return Err(ScopeScanClientError::InvalidReply);
                                }
                                if let Err(error) = staging.sink.stage(&reply).await {
                                    staging.discard();
                                    self.close(view).await;
                                    return Err(ScopeScanClientError::Sink(error));
                                }
                                // Sending this successor is the acknowledgement;
                                // advance only after the consumer accepted the page.
                                cursor = next.clone();
                                totals = observed;
                                last = position;
                                continue;
                            }
                            ReplyBody::Complete {
                                totals: final_totals,
                                ..
                            } => {
                                if final_totals != &totals {
                                    staging.discard();
                                    self.close(view).await;
                                    return Err(ScopeScanClientError::InvalidReply);
                                }
                                // Release the view before the consumer commits;
                                // a close that reaches the restore deadline must
                                // still be able to discard uncommitted staging.
                                self.close(view).await;
                                let result = staging.sink.finish(&reply).await;
                                if result.is_ok() {
                                    staging.cut = None;
                                } else {
                                    staging.discard();
                                }
                                return result.map_err(ScopeScanClientError::Sink);
                            }
                            ReplyBody::WorkBudget { next } => {
                                if next == &cursor {
                                    staging.discard();
                                    self.close(view).await;
                                    return Err(ScopeScanClientError::InvalidReply);
                                }
                                cursor = next.clone();
                                ScopeScanRequestFailure::Retryable(
                                    ScopeScanRetryCause::WorkBudgetExceeded,
                                )
                            }
                        }
                    }
                };
                match failure {
                    ScopeScanRequestFailure::Final(error) => {
                        staging.discard();
                        self.close(view).await;
                        return Err(ScopeScanClientError::Request(error));
                    }
                    ScopeScanRequestFailure::Retryable(cause) => match retries.failed(cause) {
                        RetryDecision::Stalled(stalled) => {
                            staging.discard();
                            self.close(view).await;
                            return Err(ScopeScanClientError::Stalled(stalled));
                        }
                        RetryDecision::Retry {
                            row_limit,
                            delay,
                            reopen,
                            ..
                        } => {
                            limits.0.rows = row_limit;
                            if reopen {
                                staging.discard();
                                self.close(view).await;
                                sleep(delay).await;
                                continue 'open;
                            }
                            sleep(delay).await;
                        }
                    },
                }
            }
        }
    }

    /// Alias for [`Self::restore`] with the same required overall deadline.
    pub async fn restore_until<S: ScopeScanSink>(
        &self,
        sink: &mut S,
        deadline: Instant,
    ) -> Result<S::Output, ScopeScanClientError<S::Error>> {
        self.restore(sink, deadline).await
    }

    async fn close(&self, view: T::View) {
        let _ = timeout(
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            self.transport.close(view),
        )
        .await;
    }
}

struct Staging<'a, S: ScopeScanSink> {
    sink: &'a mut S,
    cut: Option<ScopeCut>,
}
impl<S: ScopeScanSink> Staging<'_, S> {
    fn discard(&mut self) {
        if let Some(cut) = self.cut.take() {
            self.sink.discard(&cut);
        }
    }
}
impl<S: ScopeScanSink> Drop for Staging<'_, S> {
    fn drop(&mut self) {
        self.discard();
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
