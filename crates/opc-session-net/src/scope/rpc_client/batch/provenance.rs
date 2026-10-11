//! Only the concrete authenticated port can seal a native completion proof.
use super::*;

pub(super) struct AppliedFact {
    attempt: ScopeBatchAttempt,
    outcome: ScopeBatchOutcome,
}

// Private, non-serializable and never exported. A public port can wrap arbitrary
// Any values or copy a genuine context, but cannot retag its client, original
// submission class, exact result or core retention identity.
struct NativeCompletion {
    // Retained result observations must not retain the client's process lock.
    // Weak identity still names this allocation without keeping the boot alive.
    client: std::sync::Weak<Inner>,
    fact: AppliedFact,
    class: ScopeWorkClass,
    retention: ScopeBatchCompletionRetention,
}

/// Authenticated Applied completion held for current-child activation readback.
/// This is not an effect capability. Keep it alive across that readback and
/// release it before acknowledging the coordinator result.
pub struct VerifiedScopeBatchCompletion {
    outcome: ScopeBatchOutcome,
    class: ScopeWorkClass,
    _receipt: ScopeBatchCompletionReadGuard,
}
impl VerifiedScopeBatchCompletion {
    /// Exact authenticated result matching the original complete request.
    pub fn outcome(&self) -> &ScopeBatchOutcome {
        &self.outcome
    }
    /// Original submission class, independent of temporary lane inheritance.
    pub const fn class(&self) -> ScopeWorkClass {
        self.class
    }
}
impl std::fmt::Debug for VerifiedScopeBatchCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedScopeBatchCompletion(<redacted>)")
    }
}

impl ScopeClient {
    /// Authenticate a supervised completion before activation readback. Bare
    /// receipts, arbitrary public ports, different clients and early-acknowledged
    /// results cannot yield this pin. Verification makes no network exchange,
    /// reserves no lane and never submits or retries the activation.
    pub fn verify_batch_completion(
        &self,
        authority: &CommittedScopeAuthority,
        request: &ScopeBatchRequest,
        completion: &ScopeBatchCompletion,
    ) -> Result<VerifiedScopeBatchCompletion, ScopeBatchError> {
        authority.check_execution(&self.0.execution)?;
        if authority.stamp().scope() != &self.0.config.scope || request.stamp() != authority.stamp()
        {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        let proof = completion
            .context()
            .and_then(|context| context.downcast_ref::<NativeCompletion>())
            .ok_or(ScopeBatchError::OutcomeUnknown)?;
        let ScopeBatchCompletionOutcome::Applied(outcome) = completion.outcome() else {
            return Err(ScopeBatchError::OutcomeUnknown);
        };
        if !proof.client.ptr_eq(&Arc::downgrade(&self.0))
            || &proof.fact.attempt != completion.attempt()
            || proof.fact.attempt != request.attempt()?
            || &proof.fact.outcome != outcome.as_ref()
            || !outcome.matches_request(request)
            || !completion
                .retention()
                .is_some_and(|retention| proof.retention.is_same(retention))
        {
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        data_class(proof.class)?;
        let receipt = proof
            .retention
            .acquire()
            .ok_or(ScopeBatchError::OutcomeUnknown)?;
        Ok(VerifiedScopeBatchCompletion {
            outcome: *outcome.clone(),
            class: proof.class,
            _receipt: receipt,
        })
    }
}

impl BatchPort {
    pub(super) fn observe_applied(&self, attempt: ScopeBatchAttempt, outcome: &ScopeBatchOutcome) {
        if attempt.stamp() != &self.stamp {
            return;
        }
        let Ok(mut observed) = self.observed.lock() else {
            return;
        };
        let Some(slot) = observed.get_mut(usize::from(attempt.lane())) else {
            return;
        };
        if slot
            .as_ref()
            .is_none_or(|old| old.attempt.sequence() <= attempt.sequence())
        {
            *slot = Some(AppliedFact {
                attempt,
                outcome: outcome.clone(),
            });
        }
    }

    pub(super) fn observe_receipt(&self, receipt: &ScopeBatchReceipt) {
        if let ScopeBatchTerminal::Applied(outcome) = receipt.terminal() {
            self.observe_applied(receipt.attempt().clone(), outcome);
        }
    }

    pub(super) fn observe_cut(&self, cut: &ScopeBatchReopen) {
        if let ScopeBatchReopen::Initialized(view) = cut {
            for receipt in view.lanes().iter().filter_map(|lane| lane.receipt()) {
                self.observe_receipt(receipt);
            }
        }
    }

    pub(super) fn seal_completion(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
        outcome: &ScopeBatchCompletionOutcome,
        retention: ScopeBatchCompletionRetention,
    ) -> Option<ScopeBatchCompletionContext> {
        data_class(class).ok()?;
        let ScopeBatchCompletionOutcome::Applied(outcome) = outcome else {
            return None;
        };
        if request.stamp() != &self.stamp || !outcome.matches_request(request) {
            return None;
        }
        let attempt = request.attempt().ok()?;
        let observed = self.observed.lock().ok()?;
        let fact = observed.get(usize::from(attempt.lane()))?.as_ref()?;
        if fact.attempt != attempt || &fact.outcome != outcome.as_ref() {
            return None;
        }
        Some(ScopeBatchCompletionContext::new(NativeCompletion {
            client: Arc::downgrade(&self.client.0),
            fact: AppliedFact {
                attempt,
                outcome: *outcome.clone(),
            },
            class,
            retention,
        }))
    }
}
