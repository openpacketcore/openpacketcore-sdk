//! Hold the runner after its last backend result, before publishing completion.

use super::*;

async fn assert_terminal_publication(
    backend: GatedBackend,
    while_finishing: XfrmInstallOwnership,
    terminal: XfrmInstallOwnership,
) {
    let backend = Arc::new(backend);
    let barrier = Arc::new(RunnerFinishBarrier::default());
    let mut staged = XfrmStagedInstall::new(install_request());
    staged.finish_barrier = Some(barrier.clone());
    let journal = staged.journal();
    let runner = tokio::spawn(staged.run(backend.clone()));
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        barrier.reached.notified(),
    )
    .await
    .expect("runner reaches final publication barrier");

    // The backend result is known, but the runner still owns the operation.
    assert_eq!(journal.state().lifecycle, RunLifecycle::Running);
    assert_eq!(journal.ownership(), while_finishing);
    let operations = backend.operations();
    let live_plan = journal.recovery_plan();
    let error = journal
        .recover(backend.clone(), classify_all_owned(&live_plan))
        .await
        .expect_err("recovery cannot overtake the final runner transition");
    assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
    assert_eq!(
        journal.commit(),
        Err(XfrmInstallCommitError::RunnerNotFinished)
    );
    assert_eq!(backend.operations(), operations);

    // Any injected rollback error has already returned. Allow later recovery.
    backend.clear_remove_sa_error();
    barrier.release.notify_one();
    wait_for_ownership(&journal, terminal).await;
    assert_eq!(journal.state().lifecycle, RunLifecycle::Finished);

    // Do not join the runner first: ownership itself must be a safe handoff.
    // There is one recovery attempt, using the plan observed at that handoff.
    let completed_plan = journal.recovery_plan();
    journal
        .recover(backend.clone(), classify_all_owned(&completed_plan))
        .await
        .expect("terminal ownership is immediately recoverable");
    assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
    assert!(!backend.sa_present());
    assert!(!backend.policy_present());
    assert_eq!(
        runner.await.expect("owned runner exits normally").is_ok(),
        terminal == XfrmInstallOwnership::Complete,
    );
}

fn indeterminate(operations: &[XfrmCompositeOperation]) -> XfrmInstallOwnership {
    let mut set = XfrmIndeterminateOperations::default();
    for operation in operations {
        set.insert(*operation);
    }
    XfrmInstallOwnership::Indeterminate { operations: set }
}

fn rollback_in_progress() -> XfrmInstallOwnership {
    XfrmInstallOwnership::Recovering {
        operation: XfrmCompositeOperation::RollbackRemoveSa,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend::new(),
        XfrmInstallOwnership::PolicyInFlight,
        XfrmInstallOwnership::Complete,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_can_be_committed_without_joining_runner() {
    let backend = Arc::new(GatedBackend::new());
    let barrier = Arc::new(RunnerFinishBarrier::default());
    let mut staged = XfrmStagedInstall::new(install_request());
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
        Err(XfrmInstallCommitError::RunnerNotFinished)
    );

    barrier.release.notify_one();
    wait_for_ownership(&journal, XfrmInstallOwnership::Complete).await;
    journal
        .commit()
        .expect("complete ownership is immediately committable");
    assert_eq!(journal.ownership(), XfrmInstallOwnership::Committed);
    assert!(journal.recovery_plan().is_empty());
    assert!(backend.sa_present());
    assert!(backend.policy_present());
    runner
        .await
        .expect("runner joins")
        .expect("install succeeds");
    assert_eq!(journal.ownership(), XfrmInstallOwnership::Committed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_sa_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend {
            install_sa_error: Some(XfrmError::Unavailable),
            ..GatedBackend::new()
        },
        XfrmInstallOwnership::SaInFlight,
        XfrmInstallOwnership::NotStarted,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indeterminate_sa_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend {
            install_sa_error: Some(XfrmError::StateIndeterminate {
                operation: "test_install_sa",
            }),
            ..GatedBackend::new()
        },
        XfrmInstallOwnership::SaInFlight,
        indeterminate(&[XfrmCompositeOperation::InstallSa]),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rolled_back_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend::with_policy_error(XfrmError::Unavailable),
        rollback_in_progress(),
        XfrmInstallOwnership::RolledBack,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_rollback_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend::with_policy_and_rollback_errors(
            XfrmError::Unavailable,
            XfrmError::Unavailable,
        ),
        rollback_in_progress(),
        XfrmInstallOwnership::SaAcquired,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indeterminate_policy_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend::with_policy_error(XfrmError::StateIndeterminate {
            operation: "test_install_policy",
        }),
        rollback_in_progress(),
        indeterminate(&[XfrmCompositeOperation::InstallPolicy]),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indeterminate_rollback_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend::with_policy_and_rollback_errors(
            XfrmError::Unavailable,
            XfrmError::StateIndeterminate {
                operation: "test_rollback",
            },
        ),
        rollback_in_progress(),
        indeterminate(&[XfrmCompositeOperation::RollbackRemoveSa]),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_uncertainty_is_published_only_with_finished() {
    assert_terminal_publication(
        GatedBackend::with_policy_and_rollback_errors(
            XfrmError::StateIndeterminate {
                operation: "test_install_policy",
            },
            XfrmError::StateIndeterminate {
                operation: "test_rollback",
            },
        ),
        rollback_in_progress(),
        indeterminate(&[
            XfrmCompositeOperation::InstallPolicy,
            XfrmCompositeOperation::RollbackRemoveSa,
        ]),
    )
    .await;
}
