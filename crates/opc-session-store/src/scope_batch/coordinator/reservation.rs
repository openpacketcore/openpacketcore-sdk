//! Shared lanes take resident capacity first; exclusive lane 7 takes its lane
//! first. Both grants precede request construction and ownership transfer.

use super::*;
use crate::scope_scheduler::ScopeWorkReservation;
use std::future::Future;

/// Affine pre-dispatch reservation. Dropping it releases its lane and resident
/// credit without consuming a sequence, because no command has been submitted.
pub struct ScopeBatchReservation {
    inner: Arc<Inner>,
    lane: u8,
    guard: Arc<ScopeLaneGuard>,
    resident: ScopeWorkReservation,
}

/// Fresh authority/ledger observation obtained after lane and running admission.
/// Use the bounded builder to read remaining predicates, then seal the request.
#[derive(Clone)]
pub struct ScopeBatchBuildContext {
    stamp: ScopeAuthorityStamp,
    lane: u8,
    sequence: u64,
    view: ScopeBatchReopenState,
}

impl ScopeBatchBuildContext {
    /// Reserved independent replay lane.
    pub const fn lane(&self) -> u8 {
        self.lane
    }
    /// Exact next sequence observed in this lane.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Whole-scope revision at this observation; ordinary batches need no guard.
    pub const fn revision(&self) -> u64 {
        self.view.revision()
    }
    /// Same-cut authority claims, counters and all terminal frontiers.
    pub const fn view(&self) -> &ScopeBatchReopenState {
        &self.view
    }
    /// Build an independently sequenced request under this exact execution.
    /// Add every additional read dependency with `with_read_conditions`.
    /// Each rebuilt attempt needs a fresh request ID. Only the supervisor's
    /// exact retry of unchanged bytes may reuse an ID.
    pub fn request(
        &self,
        request_id: [u8; 16],
        operations: Vec<ScopeChildMutation>,
        counters: Vec<ScopeCounterMutation>,
    ) -> Result<ScopeBatchRequest, ScopeBatchError> {
        ScopeBatchRequest::in_lane(
            &self.stamp,
            request_id,
            self.lane,
            self.sequence,
            operations,
            counters,
        )
    }
}

impl ScopeBatchCoordinator {
    /// Obtain the class's resident credit before waiting for a shared lane.
    /// Established Emergency takes reserved lane 7 before its resident credit;
    /// other data classes share lanes 0–6. Neither path builds before both grants.
    pub async fn reserve(
        &self,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReservation, ScopeBatchError> {
        if class == ScopeWorkClass::SafetyControl {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        if class == ScopeWorkClass::Emergency {
            return self.reserve_lane(7, class).await;
        }
        let resident = self.reserve_resident(class).await?;
        let waiting = (0..7)
            .map(|index| {
                let lane = self.inner.lanes[index].clone();
                Box::pin(async move { (index as u8, lane.acquire(class).await) })
            })
            .collect::<Vec<_>>();
        let ((lane, guard), _, remaining) = futures_util::future::select_all(waiting).await;
        drop(remaining);
        Ok(self.admit(lane, guard.map_err(scheduler_error)?, resident))
    }

    /// Wait for a specific lane. Shared lanes, including an Emergency dependency
    /// on predecessor work, require the class's resident credit first. Exclusive
    /// Emergency lane 7 takes its lane first, so its waiters hold no resident
    /// credits. The scheduler guard supplies class order and dynamic inheritance.
    pub async fn reserve_lane(
        &self,
        lane: u8,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReservation, ScopeBatchError> {
        if usize::from(lane) >= SCOPE_BATCH_LANES {
            return Err(ScopeBatchError::InvalidRequest);
        }
        if class == ScopeWorkClass::SafetyControl
            || (lane == 7 && class != ScopeWorkClass::Emergency)
        {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        if lane == 7 {
            let guard = self.inner.lanes[7]
                .acquire(class)
                .await
                .map_err(scheduler_error)?;
            let resident = self.reserve_resident(class).await?;
            return Ok(self.admit(lane, guard, resident));
        }
        let resident = self.reserve_resident(class).await?;
        let guard = self.inner.lanes[usize::from(lane)]
            .acquire(class)
            .await
            .map_err(scheduler_error)?;
        Ok(self.admit(lane, guard, resident))
    }

    async fn reserve_resident(
        &self,
        class: ScopeWorkClass,
    ) -> Result<ScopeWorkReservation, ScopeBatchError> {
        self.inner
            .scheduler
            .reserve(self.inner.key, class)
            .await
            .map_err(scheduler_error)
    }

    fn admit(
        &self,
        lane: u8,
        guard: ScopeLaneGuard,
        resident: ScopeWorkReservation,
    ) -> ScopeBatchReservation {
        ScopeBatchReservation {
            inner: Arc::clone(&self.inner),
            lane,
            guard: Arc::new(guard),
            resident,
        }
    }

    /// Rebuild a rare whole-scope guarded operation after positively resolved,
    /// reconciled conflicts. The completion stream must be serviced concurrently:
    /// no retry starts until its preceding terminal result is explicitly acked.
    /// Backoff is 25 ms–1 s; sixteen resolved revision conflicts return a typed
    /// stall. An Applied race returns its exact result without replanning.
    /// The builder must assign a fresh ID on every call; a rebuilt attempt
    /// cannot reuse the preceding attempt's ID, even after cancellation.
    pub async fn execute_guarded<F, Fut>(
        &self,
        class: ScopeWorkClass,
        mut build: F,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError>
    where
        F: FnMut(ScopeBatchBuildContext) -> Fut,
        Fut: Future<Output = Result<ScopeBatchRequest, ScopeBatchError>>,
    {
        let mut progress = progress::GuardRetryProgress::default();
        loop {
            let handle = self
                .reserve(class)
                .await?
                .submit(|context| {
                    let revision = context.revision();
                    let building = build(context);
                    async move { building.await?.with_revision_guard(revision) }
                })
                .await?;
            let completion = handle.completion().await;
            if let ScopeBatchCompletionOutcome::Applied(outcome) = completion.outcome() {
                return Ok(*outcome.clone());
            }
            if completion.refusal() != Some(&ScopeBatchError::RevisionConflict) {
                return Err(completion
                    .refusal()
                    .cloned()
                    .unwrap_or(ScopeBatchError::Cancelled));
            }
            handle.acknowledged().await;
            match progress.resolved_conflict() {
                progress::GuardRetryDecision::Stalled => {
                    return Err(ScopeBatchError::ScopeGuardStalled)
                }
                progress::GuardRetryDecision::Delay(delay) => tokio::time::sleep(delay).await,
            }
        }
    }
}

impl ScopeBatchReservation {
    /// Reserved lane; it does not grant authority or priority on its own.
    pub const fn lane(&self) -> u8 {
        self.lane
    }

    /// Under one running credit, read a fresh cut and call the bounded builder.
    /// The builder must not await another lane or an unrelated request's outcome.
    /// Before dispatch, exact bytes and the lane transfer to the supervisor in
    /// one synchronous step. Cancelling this future after that step only detaches
    /// the observer; a completion remains available to the reconciler.
    pub async fn submit<F, Fut>(self, build: F) -> Result<ScopeBatchHandle, ScopeBatchError>
    where
        F: FnOnce(ScopeBatchBuildContext) -> Fut,
        Fut: Future<Output = Result<ScopeBatchRequest, ScopeBatchError>>,
    {
        let permit = self
            .resident
            .start_in_lane(&self.guard)
            .await
            // Nothing has been built or dispatched, so this affine reservation
            // may release its entitlement when pre-dispatch start fails.
            .map_err(|error| scheduler_error(error.error()))?;
        let cut = self.inner.backend().reopen(permit.class()).await?;
        let view = cut.check_stamp(&self.inner.stamp)?;
        let sequence = view.lanes()[usize::from(self.lane)]
            .sequence()
            .checked_add(1)
            .filter(|sequence| *sequence <= COUNTER_MAX)
            .ok_or(ScopeBatchError::InvalidRequest)?;
        let context = ScopeBatchBuildContext {
            stamp: self.inner.stamp.clone(),
            lane: self.lane,
            sequence,
            view: view.clone(),
        };
        let request = build(context).await?;
        request.validate()?;
        if request.stamp() != &self.inner.stamp
            || request.lane() != self.lane
            || request.sequence() != sequence
        {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let request = Arc::new(request);
        let attempt = request.attempt()?;
        let binding = attempt.key()?.binding_digest;
        let control = Control::new();
        {
            let mut state = lock(&self.inner.state);
            if view.lanes().iter().any(|lane| {
                lane.receipt()
                    .is_some_and(|receipt| receipt.attempt().request_id() == request.request_id())
            }) || state
                .receipt_ids
                .iter()
                .flatten()
                .any(|id| id == request.request_id())
                || state
                    .slots
                    .iter()
                    .flatten()
                    .any(|slot| slot.attempt.request_id() == request.request_id())
            {
                return Err(ScopeBatchError::IdempotencyConflict);
            }
            let slot = &mut state.slots[usize::from(self.lane)];
            if slot.is_some() {
                return Err(ScopeBatchError::FormatMismatch);
            }
            *slot = Some(Slot {
                attempt: attempt.clone(),
                binding,
                guard: Arc::clone(&self.guard),
                control: Arc::clone(&control),
                request: Some(Arc::clone(&request)),
                terminal: None,
                last_error: None,
                unresolved_since: Some(Instant::now()),
                _retained_resident: None,
                _owner: Arc::clone(&self.inner),
            });
        }
        // No await separates durable-attempt ownership from spawning its sole
        // supervisor. The observer never owns the accepted request or guard.
        tokio::spawn(supervisor::run(
            Arc::clone(&self.inner),
            request,
            Arc::clone(&control),
            self.guard,
            permit,
        ));
        Ok(ScopeBatchHandle { attempt, control })
    }
}

impl fmt::Debug for ScopeBatchReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchReservation(<redacted>)")
    }
}
impl fmt::Debug for ScopeBatchBuildContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchBuildContext(<redacted>)")
    }
}
