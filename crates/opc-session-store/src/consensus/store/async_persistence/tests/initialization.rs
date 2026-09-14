//! Ordinary admission controls for per-call deadline evidence.

use super::*;
use crate::consensus::store::initialization_evidence::{self, DeadlineStage, ProbeControl};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_admission_probe_deadline_is_call_local_and_release_runs_the_real_probe() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let store = fleet.store((fleet.leader() + 1) % 3).clone();
        let started = tokio::time::Instant::now();
        let expired = initialization_evidence::observe(&store, ProbeControl::UntilDeadline).await;
        assert!(started.elapsed() >= OPERATION_BOUND);
        assert_eq!(
            expired.result,
            Err(ConsensusSessionStoreOpenError::ClusterFormationRejected)
        );
        assert_eq!(
            expired.expired_stage(),
            Some(DeadlineStage::InitializedProbe)
        );
        assert!(!expired.cold_on_entry);
        assert!(expired.probe_was_active_and_unadmitted());
        assert!(!store.status().admitted);
        assert!(store.persistence_health().engine_running);
        assert!(store.persistence_health().storage_failure.is_none());

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let resumed = {
            let store = store.clone();
            let control = ProbeControl::Pause {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            };
            tokio::spawn(async move { initialization_evidence::observe(&store, control).await })
        };
        tokio::time::timeout(OPERATION_BOUND, entered.notified())
            .await
            .unwrap();
        assert!(
            !store.status().admitted,
            "reaching the probe is not admission"
        );
        release.notify_one();
        let resumed = resumed.await.unwrap();
        assert_eq!(resumed.result, Ok(()));
        assert_eq!(
            resumed.expired_stage(),
            None,
            "a later call cannot inherit timeout evidence"
        );
        assert!(store.status().admitted);
        assert!(!resumed.retryable_recovery_attempt());

        store.shutdown().await.unwrap();
        let stopped = initialization_evidence::observe(&store, ProbeControl::Run).await;
        assert_eq!(
            stopped.result,
            Err(ConsensusSessionStoreOpenError::EngineUnavailable)
        );
        assert_eq!(stopped.expired_stage(), None);
        assert!(
            !stopped.retryable_recovery_attempt(),
            "real engine failure is never a retryable deadline"
        );
        assert!(!store.status().admitted);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_scope_rejection_cannot_reuse_a_previous_admission_deadline() {
    use crate::readiness::PlacementResiliencePolicy::{
        AllowReducedResilience, RequireIndependentFailureDomains,
    };
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let store = fleet.store((fleet.leader() + 1) % 3).clone();
        let expired = initialization_evidence::observe(&store, ProbeControl::UntilDeadline).await;
        assert_eq!(
            expired.expired_stage(),
            Some(DeadlineStage::InitializedProbe)
        );
        let wal = store.inner.private_wal.as_ref().unwrap();
        wal.replace_native_placement_for_test(
            AllowReducedResilience,
            RequireIndependentFailureDomains,
        )
        .unwrap();
        // Mutate the actual native authority field, not an error-return stub.
        let rejected =
            AssertUnwindSafe(initialization_evidence::observe(&store, ProbeControl::Run))
                .catch_unwind()
                .await;
        wal.replace_native_placement_for_test(
            RequireIndependentFailureDomains,
            AllowReducedResilience,
        )
        .unwrap();
        let rejected = rejected.unwrap();
        assert_eq!(
            rejected.result,
            Err(ConsensusSessionStoreOpenError::ClusterFormationRejected)
        );
        assert_eq!(rejected.expired_stage(), None);
        assert!(
            !rejected.retryable_recovery_attempt(),
            "real scope rejection cannot borrow earlier timeout evidence"
        );
        assert!(!store.status().admitted);
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
