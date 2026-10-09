//! Accepted work retains its original resident entitlement across exact retries.

use super::*;
use crate::scope_scheduler::ScopeWorkPermit;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

#[derive(Clone, Copy)]
enum Action {
    Apply,
    Lookup,
    Cancel,
}

pub(super) async fn run(
    inner: Arc<Inner>,
    request: Arc<ScopeBatchRequest>,
    control: Arc<Control>,
    guard: Arc<ScopeLaneGuard>,
    mut permit: ScopeWorkPermit,
) {
    let attempt = request
        .attempt()
        .expect("the registered request was validated before dispatch");
    let mut action = Action::Apply;
    let mut refusal = None;
    let mut delay = Duration::from_millis(25);
    loop {
        let class = permit.class();
        let backend = inner.backend();
        if matches!(action, Action::Apply) && control.cancelled.load(Ordering::Acquire) {
            action = Action::Cancel;
        }
        let mut completed = None;
        let mut error = None;
        match action {
            Action::Apply => {
                let result = AssertUnwindSafe(backend.apply(&request, class))
                    .catch_unwind()
                    .await
                    .unwrap_or(Err(ScopeBatchError::OutcomeUnknown));
                match result {
                    Ok(outcome) if outcome.matches_request(&request) => {
                        completed = Some(ScopeBatchCompletionOutcome::Applied(Box::new(outcome)))
                    }
                    Ok(_) => error = Some(ScopeBatchError::FormatMismatch),
                    Err(ScopeBatchError::Cancelled) => {
                        completed = Some(ScopeBatchCompletionOutcome::Cancelled)
                    }
                    Err(failure) => {
                        if !matches!(
                            failure,
                            ScopeBatchError::OutcomeUnknown
                                | ScopeBatchError::Unavailable
                                | ScopeBatchError::Scope(
                                    ScopeAuthorityError::Unavailable
                                        | ScopeAuthorityError::OutcomeUnknown
                                        | ScopeAuthorityError::ProfileNotActivated
                                )
                        ) {
                            refusal.get_or_insert_with(|| failure.clone());
                            control.cancelled.store(true, Ordering::Release);
                        }
                        error = Some(failure);
                    }
                }
                action = Action::Lookup;
            }
            Action::Cancel => {
                let result = AssertUnwindSafe(backend.cancel(&attempt, class))
                    .catch_unwind()
                    .await
                    .unwrap_or(Err(ScopeBatchError::OutcomeUnknown));
                match result {
                    Ok(receipt) if receipt.attempt() == &attempt && receipt.validate().is_ok() => {
                        completed = ScopeBatchCompletion::from_receipt(receipt)
                            .ok()
                            .map(|completion| completion.outcome);
                    }
                    Ok(_) => error = Some(ScopeBatchError::FormatMismatch),
                    Err(failure) => error = Some(failure),
                }
                action = Action::Lookup;
            }
            Action::Lookup => {
                let result = AssertUnwindSafe(backend.reopen(class))
                    .catch_unwind()
                    .await
                    .unwrap_or(Err(ScopeBatchError::Unavailable));
                match result.map(|cut| {
                    let outcome = cut.lookup(&attempt);
                    (cut, outcome)
                }) {
                    Ok((_, Ok(ScopeBatchLookup::Applied(outcome))))
                        if outcome.matches_request(&request) =>
                    {
                        completed = Some(ScopeBatchCompletionOutcome::Applied(outcome))
                    }
                    Ok((_, Ok(ScopeBatchLookup::Applied(_)))) => {
                        error = Some(ScopeBatchError::FormatMismatch)
                    }
                    Ok((_, Ok(ScopeBatchLookup::Cancelled))) => {
                        completed = Some(ScopeBatchCompletionOutcome::Cancelled)
                    }
                    Ok((
                        cut,
                        lookup @ (Ok(ScopeBatchLookup::NotApplied)
                        | Err(ScopeBatchError::IdempotencyConflict)),
                    )) => match ScopeBatchNoApplyProof::new(&attempt, &cut) {
                        Ok(proof) => {
                            if lookup == Err(ScopeBatchError::IdempotencyConflict) {
                                refusal.get_or_insert(ScopeBatchError::IdempotencyConflict);
                            }
                            completed =
                                Some(ScopeBatchCompletionOutcome::NotApplied(Box::new(proof)))
                        }
                        Err(failure) => error = Some(failure),
                    },
                    Ok((_, Ok(ScopeBatchLookup::NotRecorded))) => {
                        action = if control.cancelled.load(Ordering::Acquire) {
                            Action::Cancel
                        } else {
                            Action::Apply
                        }
                    }
                    Ok((_, Ok(ScopeBatchLookup::Pruned))) => {
                        error = Some(ScopeBatchError::OutcomeUnknown)
                    }
                    Ok((_, Err(failure))) | Err(failure) => error = Some(failure),
                }
            }
        }
        let resident = permit.finish_unknown();
        if let Some(outcome) = completed {
            let completion = ScopeBatchCompletion {
                attempt: attempt.clone(),
                outcome,
                refusal,
            };
            {
                let mut state = lock(&inner.state);
                if let Some(slot) = state.slots[usize::from(attempt.lane())]
                    .as_mut()
                    .filter(|slot| slot.attempt == attempt && slot.terminal.is_none())
                {
                    let binding = slot.binding;
                    slot.request = None;
                    slot.last_error = None;
                    slot.unresolved_since = None;
                    slot.terminal = Some(completion.clone());
                    // Retain the guard through ack. The worker's reference can
                    // disappear without changing this shared owner.
                    debug_assert!(Arc::ptr_eq(&slot.guard, &guard));
                    state
                        .ages
                        .observe(attempt.lane(), binding, Instant::now())
                        .expect("one immutable completion per occupied lane");
                    if !matches!(
                        completion.outcome,
                        ScopeBatchCompletionOutcome::NotApplied(_)
                    ) {
                        state.receipt_ids[usize::from(attempt.lane())] =
                            Some(*attempt.request_id());
                    }
                    control.result.send_replace(Some(completion));
                }
            }
            drop(resident); // Resolved payload bytes no longer consume a resident entitlement.
            inner.changed.notify_waiters();
            return;
        }
        if let Some(error) = error {
            if let Some(slot) = lock(&inner.state).slots[usize::from(attempt.lane())].as_mut() {
                slot.last_error = Some(error);
            }
        }
        // This is liveness-only pacing. Time never clears the slot, replaces
        // request bytes, or converts absence into a terminal result.
        tokio::select! { _ = control.changed.notified() => {}, _ = tokio::time::sleep(delay) => {} }
        delay = delay.saturating_mul(2).min(Duration::from_secs(1));
        match resident.start_in_lane(&guard).await {
            Ok(next) => permit = next,
            Err(error) => {
                // Explicit final scheduler closure is not a no-apply proof.
                // Preserve exact bytes, lane and diagnostic state for recovery.
                if let Some(slot) = lock(&inner.state).slots[usize::from(attempt.lane())].as_mut() {
                    slot.last_error = Some(scheduler_error(error.error()));
                    slot._retained_resident = Some(error.into_reservation());
                }
                return;
            }
        }
    }
}
