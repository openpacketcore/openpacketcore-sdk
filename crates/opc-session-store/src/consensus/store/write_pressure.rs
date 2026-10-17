//! Owned retry of positively acknowledged, unproposed log-pressure work.

use super::*;
use std::future::Future;

impl ConsensusSessionStore {
    /// `None` means only an authenticated pre-proposal pressure acknowledgement.
    /// Every other result is terminal for this owner, including ambiguous delivery.
    /// The initial attempt retains its existing deadline and cancellation rules.
    /// Once pressure is observed, resident admission bounds retained immutable
    /// work independently of proposal/forward running credits. Dropping the
    /// result observer does not cancel an admitted retry owner.
    pub(crate) async fn own_pressure_retries<T, F, Fut>(
        &self,
        key: ScopeSchedulerKey,
        class: ScopeWorkClass,
        first_deadline: tokio::time::Instant,
        mut attempt: F,
    ) -> Result<T, PressureRetryFailure>
    where
        T: Send + 'static,
        F: FnMut(tokio::time::Instant) -> Fut + Send + 'static,
        Fut: Future<Output = Option<T>> + Send,
    {
        if self.inner.raft.metrics().borrow().running_state.is_err() {
            return Err(PressureRetryFailure::NotTransmitted);
        }
        if let Some(result) = attempt(first_deadline).await {
            return Ok(result);
        }
        let resident = self
            .inner
            .write_retry_admission
            .reserve_for(key, class)
            .await
            .map_err(|_| PressureRetryFailure::NotTransmitted)?;
        let store = self.clone();
        tokio::spawn(async move {
            let _resident = resident;
            loop {
                // No running proposal, peer call, or authority gate survives
                // the pressure result. A changed leader wakes every owner;
                // ordinary heartbeats cannot turn pacing into a busy retry.
                let mut metrics = store.inner.raft.metrics();
                let route = {
                    let current = metrics.borrow();
                    (current.vote, current.current_leader)
                };
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(100)) => {},
                    _ = metrics.wait_for(|current| {
                        (current.vote, current.current_leader) != route
                            || current.running_state.is_err()
                    }) => {},
                }
                if metrics.borrow().running_state.is_err()
                    || store.inner.retirement.is_started()
                    || store
                        .inner
                        .shutdown
                        .completion
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .is_some()
                {
                    return Err(PressureRetryFailure::NotTransmitted);
                }
                let deadline = store.operation_deadline_from(tokio::time::Instant::now());
                if let Some(result) = attempt(deadline).await {
                    return Ok(result);
                }
            }
        })
        .await
        // Losing the retained task cannot prove where its last attempt got.
        .map_err(|_| PressureRetryFailure::OutcomeUnknown)?
    }
}
