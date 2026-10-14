//! Local execution closure must reach every registration of an admission.
//! Physical exclusion is tested separately against the namespace actor.

use super::*;

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
