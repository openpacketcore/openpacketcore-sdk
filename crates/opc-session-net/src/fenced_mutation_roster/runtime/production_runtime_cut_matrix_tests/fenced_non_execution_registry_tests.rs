//! Local execution closure must reach every registration of an admission.
//! Physical exclusion is tested separately against the namespace actor.

use super::*;

struct TerminalBoundaryProvider {
    calls: AtomicUsize,
    hold_execute: bool,
    hold_reconcile: bool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl TerminalBoundaryProvider {
    fn new(hold_execute: bool, hold_reconcile: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            hold_execute,
            hold_reconcile,
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
}

#[async_trait]
impl MemberProvider for TerminalBoundaryProvider {
    type Error = ();

    async fn prepare(&self, _: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderCallOutcome::prepared_not_run())
    }

    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hold_execute {
            self.entered.notify_one();
            self.release.notified().await;
        }
        signed_provider_receipt(call, RosterProviderOutcomeV1::AppliedExecuted, vec![0xE1])
    }

    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        signed_provider_receipt(call, RosterProviderOutcomeV1::AppliedAdopted, vec![0xE1])
    }

    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.status(call).await
    }

    async fn reconcile_member(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hold_reconcile {
            self.entered.notify_one();
            self.release.notified().await;
        }
        signed_provider_receipt(
            call,
            RosterProviderOutcomeV1::NotAppliedReconciled,
            vec![0xE2],
        )
    }
}

fn terminal_boundary_executor(
    provider: Arc<TerminalBoundaryProvider>,
) -> RosterExecutor<TerminalBoundaryProvider, CutBackend> {
    RosterExecutor::new(
        provider,
        Arc::new(CutBackend::default()),
        CutAttestor::new(request().admission().scope()),
        NonZeroUsize::new(4).unwrap(),
    )
}

#[tokio::test]
async fn fenced_non_execution_established_receipt_revokes_every_readback_provider_call() {
    let provider = TerminalBoundaryProvider::new(false, false);
    let executor = terminal_boundary_executor(Arc::clone(&provider));
    let request = request_with_members(1);
    let active = executor.register(request.clone()).await.unwrap();
    let second = recovered(executor.admission_status(request.clone()).await.unwrap());
    assert!(matches!(
        executor.prepare(&active, 0).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    let applied = conclusive(executor.execute(&active, 0).await.unwrap());
    let prepared = executor
        .prepare_terminal(&active, vec![applied])
        .await
        .unwrap();
    assert_eq!(
        executor
            .terminalize(&active, &prepared)
            .await
            .unwrap()
            .phase(),
        Phase::Established
    );
    assert!(matches!(
        executor.admission_status(request).await.unwrap(),
        RecoveryResult::Established(_)
    ));
    let before = provider.calls.load(Ordering::SeqCst);
    let status = executor.status(&second, 0).await;
    let adopt = executor.adopt(&second, 0).await;
    let reconcile = executor.reconcile_member(&second, 0).await;
    assert_eq!(provider.calls.load(Ordering::SeqCst), before,
        "a terminal receipt must revoke provider dispatch through every earlier exact readback registration");
    assert!(status.is_err() && adopt.is_err() && reconcile.is_err());
}

#[tokio::test]
async fn fenced_non_execution_established_receipt_discards_reconcile_held_after_precheck() {
    let provider = TerminalBoundaryProvider::new(false, true);
    let executor = Arc::new(terminal_boundary_executor(Arc::clone(&provider)));
    let request = request_with_members(1);
    let active = executor.register(request.clone()).await.unwrap();
    let second = Arc::new(recovered(executor.admission_status(request).await.unwrap()));
    assert!(matches!(
        executor.prepare(&active, 0).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    let applied = conclusive(executor.execute(&active, 0).await.unwrap());
    let pending = tokio::spawn({
        let executor = Arc::clone(&executor);
        let second = Arc::clone(&second);
        async move { executor.reconcile_member(&second, 0).await }
    });
    provider.entered.notified().await;
    let prepared = executor
        .prepare_terminal(&active, vec![applied])
        .await
        .unwrap();
    assert_eq!(
        executor
            .terminalize(&active, &prepared)
            .await
            .unwrap()
            .phase(),
        Phase::Established
    );
    provider.release.notify_one();
    let result = pending.await.unwrap();
    assert!(
        matches!(
            result,
            Ok(CallResult::OutcomeUnknown) | Err(ExecutorError::OutcomeUnknown)
        ),
        "a signed result from a provider call held through terminal release must be discarded"
    );
    assert!(second.local.lock().unwrap().first_conclusive[0].is_none());
}

#[tokio::test]
async fn fenced_non_execution_applied_acknowledgement_after_closure_stays_unknown() {
    let provider = TerminalBoundaryProvider::new(true, false);
    let executor = Arc::new(terminal_boundary_executor(Arc::clone(&provider)));
    let request = request_with_members(1);
    let active = Arc::new(executor.register(request.clone()).await.unwrap());
    assert!(matches!(
        executor.prepare(&active, 0).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    let second = recovered(executor.admission_status(request).await.unwrap());
    let pending = tokio::spawn({
        let executor = Arc::clone(&executor);
        let active = Arc::clone(&active);
        async move { executor.execute(&active, 0).await }
    });
    provider.entered.notified().await;
    assert!(matches!(
        executor.reconcile_member(&second, 0).await.unwrap(),
        CallResult::Conclusive(_)
    ));
    provider.release.notify_one();
    assert!(matches!(
        pending.await.unwrap(),
        Ok(CallResult::OutcomeUnknown) | Err(ExecutorError::OutcomeUnknown)
    ));
    assert!(active.local.lock().unwrap().first_conclusive[0].is_none());
}

struct ClosureProbeProvider {
    prepares: AtomicUsize,
    executions: AtomicUsize,
    close_unknown: bool,
}

#[async_trait]
impl MemberProvider for ClosureProbeProvider {
    type Error = ();

    async fn prepare(&self, _: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderCallOutcome::prepared_not_run())
    }

    async fn execute(&self, _: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        // This probe reports dispatch, not a physical effect. It cannot undo
        // the negative receipt or turn an invalid dispatch into Applied.
        Ok(ProviderCallOutcome::outcome_unknown())
    }

    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        signed_provider_receipt(
            call,
            RosterProviderOutcomeV1::NotAppliedReconciled,
            vec![0xE8, call.ordinal()],
        )
    }

    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.status(call).await
    }

    async fn reconcile_member(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        if self.close_unknown {
            Ok(ProviderCallOutcome::outcome_unknown())
        } else {
            self.status(call).await
        }
    }
}

fn closure_executor(
    provider: Arc<ClosureProbeProvider>,
    backend: Arc<CutBackend>,
) -> RosterExecutor<ClosureProbeProvider, CutBackend> {
    RosterExecutor::new(
        provider,
        backend,
        CutAttestor::new(request().admission().scope()),
        NonZeroUsize::new(2).unwrap(),
    )
}

#[tokio::test]
async fn fenced_non_execution_reconcile_revokes_stale_sdk_execution_for_all_members() {
    let request = request_with_members(2);
    let provider = Arc::new(ClosureProbeProvider {
        prepares: AtomicUsize::new(0),
        executions: AtomicUsize::new(0),
        close_unknown: false,
    });
    let backend = Arc::new(CutBackend::default());
    let executor = closure_executor(Arc::clone(&provider), Arc::clone(&backend));
    let stale = executor.register(request.clone()).await.unwrap();
    for ordinal in 0..2 {
        assert!(matches!(
            executor.prepare(&stale, ordinal).await,
            Ok(CallResult::PreparedNotRun)
        ));
    }
    let current = recovered(executor.admission_status(request.clone()).await.unwrap());
    let first = conclusive(executor.reconcile_member(&current, 0).await.unwrap());
    // Closure covers the entire admission even before the second member's
    // provider has been reconciled. The old registrations have distinct locks.
    let stale_result = executor.execute(&stale, 1).await;
    let stale_dispatches = provider.executions.load(Ordering::SeqCst);
    let second = conclusive(executor.reconcile_member(&current, 1).await.unwrap());
    let terminal = executor
        .prepare_terminal(&current, vec![first, second])
        .await
        .unwrap();
    assert_eq!(
        executor
            .terminalize(&current, &terminal)
            .await
            .unwrap()
            .phase(),
        Phase::Aborted
    );
    let after_aborted = executor.execute(&stale, 0).await;
    let total_dispatches = provider.executions.load(Ordering::SeqCst);
    assert_eq!((stale_dispatches, total_dispatches), (0, 0),
        "reconciliation must revoke stale SDK handles before and after Aborted; refused before={}, refused after={}", stale_result.is_err(), after_aborted.is_err());
    assert_eq!(backend.admission_calls().len(), 1);
    assert_eq!(backend.terminal_calls().len(), 1);
}

#[tokio::test]
async fn fenced_non_execution_terminal_readback_reinstallation_never_revives_old_permits() {
    let request = request_with_members(2);
    let provider = Arc::new(ClosureProbeProvider {
        prepares: AtomicUsize::new(0),
        executions: AtomicUsize::new(0),
        close_unknown: false,
    });
    let backend = Arc::new(CutBackend::default());
    let executor = closure_executor(Arc::clone(&provider), Arc::clone(&backend));
    let stale = executor.register(request.clone()).await.unwrap();
    for ordinal in 0..2 {
        assert!(matches!(
            executor.prepare(&stale, ordinal).await,
            Ok(CallResult::PreparedNotRun)
        ));
    }
    let current = recovered(executor.admission_status(request.clone()).await.unwrap());
    let proofs = vec![
        conclusive(executor.reconcile_member(&current, 0).await.unwrap()),
        conclusive(executor.reconcile_member(&current, 1).await.unwrap()),
    ];
    let terminal = executor.prepare_terminal(&current, proofs).await.unwrap();
    assert_eq!(
        executor
            .terminalize(&current, &terminal)
            .await
            .unwrap()
            .phase(),
        Phase::Aborted
    );
    assert!(
        executor.local_authority.check(&stale.authority_permit)
            == LocalAuthorityCheck::RevokedOrExpired
    );

    // This is the actual installation step in admission_status, stopped in
    // the error window before a terminal readback can release the new entry.
    let recreated = executor
        .local_authority
        .install_admission(
            stale.backend_registration(),
            stale.admission(),
            stale.authority(),
        )
        .unwrap();
    assert!(executor.local_authority.check(&recreated) == LocalAuthorityCheck::Current);
    let late = executor.execute(&stale, 0).await;
    assert_eq!(
        provider.executions.load(Ordering::SeqCst),
        0,
        "terminal readback recreated a current stale permit; refused={}",
        late.is_err()
    );
    assert_ne!(recreated.generation, stale.authority_permit.generation);
    assert_eq!(backend.admission_calls().len(), 1);
    assert_eq!(backend.terminal_calls().len(), 1);
}

#[tokio::test]
async fn fenced_non_execution_successor_rebuilds_identical_terminal_after_lost_closure_reply() {
    let request = request_with_members(2);
    let provider = Arc::new(ClosureProbeProvider {
        prepares: AtomicUsize::new(0),
        executions: AtomicUsize::new(0),
        close_unknown: false,
    });
    let backend = Arc::new(CutBackend::default());
    let first = closure_executor(Arc::clone(&provider), Arc::clone(&backend));
    let _stale = first.register(request.clone()).await.unwrap();
    let current = recovered(first.admission_status(request.clone()).await.unwrap());
    // The caller never consumes this first signed closure response.
    let _ = first.reconcile_member(&current, 0).await.unwrap();
    let repeated = recovered(first.admission_status(request.clone()).await.unwrap());
    let first_proofs = vec![
        conclusive(first.reconcile_member(&repeated, 0).await.unwrap()),
        conclusive(first.reconcile_member(&repeated, 1).await.unwrap()),
    ];
    let evidence = first_proofs
        .iter()
        .map(|proof| proof.evidence_commitment)
        .collect::<Vec<_>>();
    let prepared = first
        .prepare_terminal(&repeated, first_proofs)
        .await
        .unwrap();
    let recovery = successor(&request, (1_u64 << 40) + 1);
    backend.install_successor_authority(recovery.authority().clone());
    let second = closure_executor(Arc::clone(&provider), Arc::clone(&backend));
    let recovered = recovered(second.recover(recovery).await.unwrap());
    let successor_proofs = vec![
        conclusive(second.reconcile_member(&recovered, 0).await.unwrap()),
        conclusive(second.reconcile_member(&recovered, 1).await.unwrap()),
    ];
    assert_eq!(
        successor_proofs
            .iter()
            .map(|proof| proof.evidence_commitment)
            .collect::<Vec<_>>(),
        evidence
    );
    let rebuilt = second
        .prepare_terminal(&recovered, successor_proofs)
        .await
        .unwrap();
    assert_eq!(rebuilt.body.commitment(), prepared.body.commitment());
    backend.lose_next_terminal_reply();
    assert!(matches!(
        second.terminalize(&recovered, &rebuilt).await,
        Err(ExecutorError::TerminalizeOutcomeUnknown)
    ));
    match second.terminal_status(&recovered, &rebuilt).await.unwrap() {
        TerminalStatusResult::Recorded(receipt) => assert_eq!(receipt.phase(), Phase::Aborted),
        _ => panic!("lost terminal reply must retain the exact Aborted body"),
    }
    assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
    assert_eq!(backend.admission_calls().len(), 1);
    assert_eq!(backend.terminal_calls().len(), 1);
}

#[derive(Clone, Copy)]
enum ClosureResponse {
    NotTransmitted,
    Unknown,
    Unsigned,
    Held,
}

#[derive(Debug, PartialEq, Eq)]
struct ObservedClosureCall {
    fence: u64,
    expires_at: Timestamp,
    binding: [u8; 32],
    ordinal: u8,
}

struct ContractProvider {
    inner: ClosureProbeProvider,
    response: ClosureResponse,
    calls: Mutex<Vec<ObservedClosureCall>>,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl ContractProvider {
    fn new(response: ClosureResponse) -> Arc<Self> {
        Arc::new(Self {
            inner: ClosureProbeProvider {
                prepares: AtomicUsize::new(0),
                executions: AtomicUsize::new(0),
                close_unknown: false,
            },
            response,
            calls: Mutex::new(Vec::new()),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
}

#[async_trait]
impl MemberProvider for ContractProvider {
    type Error = ();
    async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.inner.prepare(call).await
    }
    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.inner.execute(call).await
    }
    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.inner.status(call).await
    }
    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.inner.adopt(call).await
    }
    async fn reconcile_member(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.calls.lock().unwrap().push(ObservedClosureCall {
            fence: call.current_fence().get(),
            expires_at: call.current_lease_expires_at(),
            binding: call.fence_binding_commitment(),
            ordinal: call.ordinal(),
        });
        self.started.notify_one();
        match self.response {
            ClosureResponse::NotTransmitted => Ok(ProviderCallOutcome::not_transmitted()),
            ClosureResponse::Unknown => Ok(ProviderCallOutcome::outcome_unknown()),
            ClosureResponse::Unsigned => {
                let ProviderCallOutcomeParts::Conclusive(valid) =
                    self.inner.status(call).await?.into_parts()
                else {
                    return Err(());
                };
                let valid = valid.decode().map_err(|_| ())?;
                let unsigned = call
                    .provider_receipt_challenge()
                    .protected_provider_leaf_signed_capsule(
                        valid.outcome,
                        valid.evidence,
                        valid.certificate,
                        [0; 64],
                    )
                    .map_err(|_| ())?;
                assert!(
                    unsigned.decode().is_ok(),
                    "signature negative must reach verification, not a wire-format guard"
                );
                Ok(ProviderCallOutcome::conclusive_receipt(unsigned))
            }
            ClosureResponse::Held => {
                self.release.notified().await;
                self.inner.status(call).await
            }
        }
    }
}

fn contract_executor(
    provider: Arc<ContractProvider>,
    backend: Arc<CutBackend>,
    clock: Arc<dyn Clock>,
) -> RosterExecutor<ContractProvider, CutBackend> {
    RosterExecutor::new_with_clock(
        provider,
        backend,
        CutAttestor::new(request().admission().scope()),
        NonZeroUsize::new(2).unwrap(),
        clock,
    )
}

async fn inconclusive_closure_still_revokes(response: ClosureResponse) {
    let request = request_with_members(2);
    let provider = ContractProvider::new(response);
    let backend = Arc::new(CutBackend::default());
    let executor = contract_executor(
        Arc::clone(&provider),
        Arc::clone(&backend),
        Arc::new(SystemClock),
    );
    let stale = executor.register(request.clone()).await.unwrap();
    assert!(matches!(
        executor.prepare(&stale, 1).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    let first = recovered(executor.admission_status(request.clone()).await.unwrap());
    let first_result = executor.reconcile_member(&first, 0).await;
    match response {
        ClosureResponse::NotTransmitted => {
            assert!(matches!(first_result, Ok(CallResult::NotTransmitted)))
        }
        ClosureResponse::Unknown => assert!(matches!(first_result, Ok(CallResult::OutcomeUnknown))),
        ClosureResponse::Unsigned => assert!(matches!(
            first_result,
            Err(ExecutorError::InvalidProviderResponse)
        )),
        ClosureResponse::Held => unreachable!("held closure has its own budget test"),
    }
    // Repeat exact retained readback at the equal fence. It must preserve the
    // irreversible local closure even when the provider saw no request byte.
    let repeated = recovered(executor.admission_status(request.clone()).await.unwrap());
    assert!(!matches!(
        executor.reconcile_member(&repeated, 0).await,
        Ok(CallResult::Conclusive(_))
    ));
    let delayed = executor.execute(&stale, 1).await;
    assert_eq!(
        backend.admission_calls().len(),
        1,
        "no renewed admission is allowed"
    );
    assert!(
        backend.terminal_calls().is_empty(),
        "inconclusive proof cannot terminalize"
    );
    let calls = provider.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0], calls[1],
        "retry must retain the exact binding, ordinal, lease and fence"
    );
    drop(calls);
    assert_eq!(
        provider.inner.executions.load(Ordering::SeqCst),
        0,
        "inconclusive reconciliation reopened a different member's execution; refused={}",
        delayed.is_err()
    );
}

#[tokio::test]
async fn fenced_non_execution_not_transmitted_does_not_reopen_execution_or_admission() {
    inconclusive_closure_still_revokes(ClosureResponse::NotTransmitted).await;
}

#[tokio::test]
async fn fenced_non_execution_unknown_does_not_reopen_execution_or_admission() {
    inconclusive_closure_still_revokes(ClosureResponse::Unknown).await;
}

#[tokio::test]
async fn fenced_non_execution_unsigned_response_cannot_prove_settlement_or_reopen_execution() {
    inconclusive_closure_still_revokes(ClosureResponse::Unsigned).await;
}

#[tokio::test(start_paused = true)]
async fn fenced_non_execution_lease_expiry_keeps_the_original_budget_and_ambiguity() {
    let clock: Arc<dyn Clock> = Arc::new(opc_session_store::TokioVirtualClock::new());
    let original = request_with_members(1);
    let authority = original.authority();
    let now = clock.now_utc();
    let request = RegistrationRequest::new_with_lease_metadata(
        original.admission().clone(),
        authority.owner().clone(),
        authority.fence(),
        authority.credential_id(),
        authority.generation(),
        now.add_seconds(-1).unwrap(),
        now.add_seconds(2).unwrap(),
    )
    .unwrap();
    let provider = ContractProvider::new(ClosureResponse::Held);
    let backend = Arc::new(CutBackend::default());
    let executor = Arc::new(contract_executor(
        Arc::clone(&provider),
        Arc::clone(&backend),
        Arc::clone(&clock),
    ));
    let _registered = executor.register(request.clone()).await.unwrap();
    let recovered = Arc::new(recovered(
        executor.admission_status(request.clone()).await.unwrap(),
    ));
    let call = tokio::spawn({
        let executor = Arc::clone(&executor);
        let recovered = Arc::clone(&recovered);
        async move { executor.reconcile_member(&recovered, 0).await }
    });
    provider.started.notified().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let result = call.await.unwrap();
    let completed_at = clock.now_utc();
    provider.release.notify_one();
    assert!(
        !matches!(result, Ok(CallResult::Conclusive(_))),
        "expiry cannot establish exclusion"
    );
    let retry = executor.reconcile_member(&recovered, 0).await;
    assert!(matches!(retry, Err(ExecutorError::AuthorityRejected)));
    let calls = provider.calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "expired original authority cannot dispatch another closure"
    );
    assert_eq!(calls[0].fence, request.authority().fence().get());
    assert_eq!(calls[0].expires_at, request.authority().expires_at());
    assert!(
        completed_at <= request.authority().expires_at(),
        "closure wait outlived the original lease instead of returning ambiguity at expiry"
    );
    assert_eq!(provider.inner.executions.load(Ordering::SeqCst), 0);
    assert_eq!(backend.admission_calls().len(), 1);
    assert!(backend.terminal_calls().is_empty());
}

#[tokio::test]
async fn fenced_non_execution_incomplete_and_substituted_proofs_cannot_commit_terminal() {
    let request = request_with_members(2);
    let provider = Arc::new(ClosureProbeProvider {
        prepares: AtomicUsize::new(0),
        executions: AtomicUsize::new(0),
        close_unknown: false,
    });
    let backend = Arc::new(CutBackend::default());
    let executor = closure_executor(Arc::clone(&provider), Arc::clone(&backend));
    let _registered = executor.register(request.clone()).await.unwrap();
    let current = recovered(executor.admission_status(request.clone()).await.unwrap());
    let first = conclusive(executor.reconcile_member(&current, 0).await.unwrap());
    let second = conclusive(executor.reconcile_member(&current, 1).await.unwrap());
    assert!(executor
        .prepare_terminal(&current, vec![first.clone()])
        .await
        .is_err());
    assert!(executor
        .prepare_terminal(&current, vec![first.clone(), first.clone()])
        .await
        .is_err());
    let mut unsigned = first.clone();
    unsigned.provider_signature = [0; 64];
    assert!(executor
        .prepare_terminal(&current, vec![unsigned, second.clone()])
        .await
        .is_err());
    let mut changed_evidence = first.clone();
    changed_evidence.evidence.push(0xFF);
    assert!(executor
        .prepare_terminal(&current, vec![changed_evidence, second.clone()])
        .await
        .is_err());
    let mut changed_binding = first.clone();
    changed_binding.binding_commitment[0] ^= 1;
    assert!(executor
        .prepare_terminal(&current, vec![changed_binding, second.clone()])
        .await
        .is_err());
    assert!(
        backend.terminal_calls().is_empty(),
        "invalid member evidence must fail before consensus"
    );
    let terminal = executor
        .prepare_terminal(&current, vec![first, second])
        .await
        .unwrap();
    assert_eq!(
        executor
            .terminalize(&current, &terminal)
            .await
            .unwrap()
            .phase(),
        Phase::Aborted
    );
    assert_eq!(backend.admission_calls().len(), 1);
    assert_eq!(backend.terminal_calls().len(), 1);
    assert_eq!(provider.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(provider.executions.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct DelayedReadbackBackend {
    inner: CutBackend,
    hold_readback: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl DelayedReadbackBackend {
    async fn hold(&self, decision: RegistrationDecision) -> RegistrationDecision {
        if self.hold_readback.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        decision
    }
}

#[async_trait]
impl RosterExecutorBackend for DelayedReadbackBackend {
    type Error = ();

    fn expected_roster_attestation_trust_root_identity(
        &self,
    ) -> Option<RosterAttestationTrustRootIdentityV1> {
        self.inner.expected_roster_attestation_trust_root_identity()
    }

    fn current_roster_configuration_identity(&self) -> Option<SessionConsensusIdentity> {
        self.inner.current_roster_configuration_identity()
    }

    async fn register(&self, request: &RegistrationRequest) -> Result<RegistrationDecision, ()> {
        self.inner.register(request).await
    }

    async fn admission_status(
        &self,
        request: AdmissionStatusRequest<'_>,
    ) -> Result<RegistrationDecision, ()> {
        Ok(self.hold(self.inner.admission_status(request).await?).await)
    }

    async fn recover(&self, request: &RecoveryRequest) -> Result<RegistrationDecision, ()> {
        Ok(self.hold(self.inner.recover(request).await?).await)
    }

    async fn terminal_status(
        &self,
        request: TerminalStatusRequest<'_>,
    ) -> Result<TerminalStatusDecision, ()> {
        self.inner.terminal_status(request).await
    }

    async fn terminalize(
        &self,
        request: TerminalizeRequest<'_>,
    ) -> Result<TerminalizeDecision, ()> {
        self.inner.terminalize(request).await
    }
}

async fn delayed_readback_cannot_reinstall_after_terminal(successor_read: bool, established: bool) {
    let request = request_with_members(1);
    let provider = TerminalBoundaryProvider::new(false, false);
    let backend = Arc::new(DelayedReadbackBackend::default());
    let executor = Arc::new(RosterExecutor::new(
        Arc::clone(&provider),
        Arc::clone(&backend),
        CutAttestor::new(request.admission().scope()),
        NonZeroUsize::new(4).unwrap(),
    ));
    let mut current = executor.register(request.clone()).await.unwrap();
    let recovery = successor(&request, 2);
    if successor_read {
        backend
            .inner
            .install_successor_authority(recovery.authority().clone());
        current = recovered(executor.recover(recovery.clone()).await.unwrap());
    }
    let proof = if established {
        if successor_read {
            conclusive(executor.status(&current, 0).await.unwrap())
        } else {
            assert!(matches!(
                executor.prepare(&current, 0).await.unwrap(),
                CallResult::PreparedNotRun
            ));
            conclusive(executor.execute(&current, 0).await.unwrap())
        }
    } else {
        conclusive(executor.reconcile_member(&current, 0).await.unwrap())
    };
    backend.hold_readback.store(true, Ordering::SeqCst);
    let pending = tokio::spawn({
        let executor = Arc::clone(&executor);
        async move {
            if successor_read {
                executor.recover(recovery).await
            } else {
                executor.admission_status(request).await
            }
        }
    });
    backend.entered.notified().await;
    let terminal = executor
        .prepare_terminal(&current, vec![proof])
        .await
        .unwrap();
    let receipt = executor.terminalize(&current, &terminal).await.unwrap();
    assert_eq!(
        receipt.phase(),
        if established {
            Phase::Established
        } else {
            Phase::Aborted
        }
    );
    if established {
        // Complete the actual publication acknowledgement transition, which
        // releases the same authority entry retained by Established.
        let call = EstablishedPublicationCall::from_executor(
            receipt.publication_authority().unwrap(),
            receipt.protected_checkpoint(),
            receipt.protected_result(),
        )
        .unwrap();
        executor
            .local_authority
            .linearize_publication(&call, || Ok(()))
            .unwrap();
    }
    assert!(
        executor.local_authority.check(&current.authority_permit)
            == LocalAuthorityCheck::RevokedOrExpired
    );
    let before = provider.calls.load(Ordering::SeqCst);
    backend.release.notify_one();
    if let Ok(RecoveryResult::PollAdmitted(stale)) = pending.await.unwrap() {
        let _ = executor.reconcile_member(&stale.registration, 0).await;
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), before,
        "a delayed PollAdmitted readback must not recreate provider authority after terminal release");
}

#[tokio::test]
async fn fenced_non_execution_delayed_admission_readback_cannot_reinstall_after_terminal() {
    for established in [false, true] {
        delayed_readback_cannot_reinstall_after_terminal(false, established).await;
    }
}

#[tokio::test]
async fn fenced_non_execution_delayed_successor_readback_cannot_reinstall_after_terminal() {
    for established in [false, true] {
        delayed_readback_cannot_reinstall_after_terminal(true, established).await;
    }
}
