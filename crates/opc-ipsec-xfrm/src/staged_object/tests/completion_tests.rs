//! Hold the runner after its backend result, before publishing completion.

use super::*;

fn classify_owned(plan: &XfrmObjectInstallRecoveryPlan) -> XfrmObjectInstallRecoveryClassification {
    if plan.is_empty() {
        plan.classification()
    } else {
        classify(plan, XfrmResidueClassification::Owned)
    }
}

async fn assert_terminal_publication(
    request: XfrmObjectInstallRequest,
    error: Option<XfrmError>,
    terminal: XfrmObjectInstallOwnership,
    detach_observer: bool,
) {
    let mut backend = GatedBackend::new();
    match request.object() {
        XfrmInstallObject::Sa => backend.install_sa_error = error,
        XfrmInstallObject::Policy => backend.install_policy_error = error,
    }
    let backend = Arc::new(backend);
    let barrier = Arc::new(RunnerFinishBarrier::default());
    let mut staged = XfrmStagedObjectInstall::new(request);
    staged.finish_barrier = Some(barrier.clone());
    let journal = staged.journal();
    let runner = tokio::spawn(staged.run(backend.clone()));
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        barrier.reached.notified(),
    )
    .await
    .expect("runner reaches final publication barrier");

    let runner = if detach_observer {
        runner.abort();
        assert!(runner.await.is_err());
        None
    } else {
        Some(runner)
    };

    // The backend result is known, but the runner still owns the operation.
    assert_eq!(journal.state().lifecycle, RunLifecycle::Running);
    assert_eq!(
        journal.ownership(),
        XfrmObjectInstallOwnership::InstallInFlight
    );
    let operations = backend.operations();
    let live_plan = journal.recovery_plan();
    let error = journal
        .recover(backend.clone(), classify_owned(&live_plan))
        .await
        .expect_err("recovery cannot overtake the final runner transition");
    assert!(matches!(
        error,
        XfrmObjectInstallRecoveryError::RunnerNotFinished
    ));
    assert_eq!(
        journal.commit(),
        Err(XfrmObjectInstallCommitError::RunnerNotFinished)
    );
    assert_eq!(backend.operations(), operations);

    barrier.release.notify_one();
    wait_for_ownership(&journal, terminal).await;
    assert_eq!(journal.state().lifecycle, RunLifecycle::Finished);

    // Do not join the runner first: ownership itself must be a safe handoff.
    let completed_plan = journal.recovery_plan();
    journal
        .recover(backend.clone(), classify_owned(&completed_plan))
        .await
        .expect("terminal ownership is immediately recoverable");
    assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
    assert!(!backend.sa_present());
    assert!(!backend.policy_present());
    if let Some(runner) = runner {
        assert_eq!(
            runner.await.expect("owned runner exits normally").is_ok(),
            terminal == XfrmObjectInstallOwnership::Acquired,
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acquired_sa_is_published_only_with_finished() {
    assert_terminal_publication(
        sa_install_request(),
        None,
        XfrmObjectInstallOwnership::Acquired,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acquired_policy_is_published_only_with_finished() {
    assert_terminal_publication(
        policy_install_request(),
        None,
        XfrmObjectInstallOwnership::Acquired,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_sa_is_published_only_with_finished() {
    assert_terminal_publication(
        sa_install_request(),
        Some(XfrmError::Unavailable),
        XfrmObjectInstallOwnership::NotStarted,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_policy_is_published_only_with_finished() {
    assert_terminal_publication(
        policy_install_request(),
        Some(XfrmError::Unavailable),
        XfrmObjectInstallOwnership::NotStarted,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indeterminate_sa_is_published_only_with_finished() {
    assert_terminal_publication(
        sa_install_request(),
        Some(XfrmError::StateIndeterminate {
            operation: "test_install_sa",
        }),
        XfrmObjectInstallOwnership::Indeterminate {
            operation: XfrmCompositeOperation::InstallSa,
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indeterminate_policy_is_published_only_with_finished() {
    assert_terminal_publication(
        policy_install_request(),
        Some(XfrmError::StateIndeterminate {
            operation: "test_install_policy",
        }),
        XfrmObjectInstallOwnership::Indeterminate {
            operation: XfrmCompositeOperation::InstallPolicy,
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_sa_observer_retains_claim_until_finished() {
    assert_terminal_publication(
        sa_install_request(),
        None,
        XfrmObjectInstallOwnership::Acquired,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_policy_observer_retains_claim_until_finished() {
    assert_terminal_publication(
        policy_install_request(),
        None,
        XfrmObjectInstallOwnership::Acquired,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acquired_can_be_committed_without_joining_runner() {
    for request in [sa_install_request(), policy_install_request()] {
        let object = request.object();
        let backend = Arc::new(GatedBackend::new());
        let barrier = Arc::new(RunnerFinishBarrier::default());
        let mut staged = XfrmStagedObjectInstall::new(request);
        staged.finish_barrier = Some(barrier.clone());
        let journal = staged.journal();
        let runner = tokio::spawn(staged.run(backend.clone()));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            barrier.reached.notified(),
        )
        .await
        .expect("runner reaches final publication barrier");
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::RunnerNotFinished)
        );

        barrier.release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::Acquired).await;
        journal
            .commit()
            .expect("acquired ownership is immediately committable");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Committed);
        assert!(journal.recovery_plan().is_empty());
        assert_eq!(backend.sa_present(), object == XfrmInstallObject::Sa);
        assert_eq!(
            backend.policy_present(),
            object == XfrmInstallObject::Policy
        );
        runner
            .await
            .expect("runner joins")
            .expect("install succeeds");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Committed);
    }
}
