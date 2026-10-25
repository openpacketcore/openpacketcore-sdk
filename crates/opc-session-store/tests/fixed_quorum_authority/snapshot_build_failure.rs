//! Deterministic local snapshot build failure, retry and degradation regressions.
//!
//! #1254: a failed local snapshot build must not stop the Raft engine. The
//! production builder retries a failed attempt under a fixed bounded budget and
//! fixed backoff. If every attempt fails, it reports the unchanged current
//! snapshot to Openraft (a duplicate build result), so the engine keeps serving
//! and the next snapshot policy trigger or explicit trigger retries the build.
//!
//! These fixtures are Linux-only because the fixed-quorum consensus storage
//! path is Linux-hosted; hosted CI executes them in the serial opc-session-store
//! lane.

use super::*;

use opc_session_store::test_support::{
    append_consensus_padding_entry_for_test, consensus_local_durable_progress_for_test,
    consensus_snapshot_build_failure_counters_for_test,
    fail_next_consensus_snapshot_builds_for_test,
    fail_next_consensus_snapshot_builds_with_indeterminate_publication_for_test,
    trigger_consensus_snapshot_for_test, wait_for_consensus_progress_for_test,
    wait_for_consensus_snapshot_build_degraded_for_test,
    wait_for_consensus_snapshot_build_failures_for_test, ConsensusEngineStateForTest,
    ConsensusStorageErrorSubjectForTest, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS,
    CONSENSUS_SNAPSHOT_BUILD_RETRY_BACKOFF,
};
use opc_session_store::SessionSnapshotBuildFailureReason;

const SNAPSHOT_BUILD_WAIT: Duration = Duration::from_secs(20);

async fn open_leader() -> (
    tempfile::TempDir,
    Vec<PathBuf>,
    Vec<ConsensusSessionStore>,
    BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
    usize,
) {
    let (directory, database_paths, stores, paths) =
        open_fixed_cluster_with_paths(3, PlacementResiliencePolicy::AllowReducedResilience).await;
    let leader = (0..3)
        .find(|index| {
            let status = stores[*index].status();
            status.leader_id == Some(status.node_id)
        })
        .expect("fixed cluster leader");
    (directory, database_paths, stores, paths, leader)
}

/// Wait until this voter has applied and published a snapshot through `index`.
async fn wait_for_applied_snapshot(store: &ConsensusSessionStore, index: u64) {
    let progress = tokio::time::timeout(
        SNAPSHOT_BUILD_WAIT,
        wait_for_consensus_progress_for_test(store, |progress| {
            progress
                .applied_index
                .is_some_and(|applied| applied >= index)
                && progress
                    .snapshot_index
                    .is_some_and(|snapshot| snapshot >= index)
        }),
    )
    .await
    .expect("snapshot publication within the fixture deadline");
    assert_eq!(
        ConsensusEngineStateForTest::Running,
        progress.engine_state,
        "{progress:?}"
    );
    assert!(progress
        .applied_index
        .is_some_and(|applied| applied >= index));
    assert!(progress
        .snapshot_index
        .is_some_and(|snapshot| snapshot >= index));
}

/// Wait until this voter has applied `index`; the engine must still be running.
async fn wait_for_applied(store: &ConsensusSessionStore, index: u64) {
    let progress = tokio::time::timeout(
        SNAPSHOT_BUILD_WAIT,
        wait_for_consensus_progress_for_test(store, |progress| {
            progress
                .applied_index
                .is_some_and(|applied| applied >= index)
        }),
    )
    .await
    .expect("apply progress within the fixture deadline");
    assert_eq!(
        ConsensusEngineStateForTest::Running,
        progress.engine_state,
        "{progress:?}"
    );
}

async fn shutdown(
    stores: &[ConsensusSessionStore],
    paths: &BTreeMap<(usize, usize), Arc<ScopedLoopbackPeer>>,
) {
    shutdown_fixed_cluster_for_reopen(stores, paths).await;
}

#[tokio::test]
async fn failed_local_snapshot_build_is_retried_and_the_engine_keeps_serving() {
    let (_directory, _database_paths, stores, paths, leader) = open_leader().await;
    let store = &stores[leader];

    // Establish one published snapshot before arming the injected failure, so
    // the bounded retry is exercised against a store with a current snapshot.
    let first = append_consensus_padding_entry_for_test(store, [0xA1; 16])
        .await
        .expect("initial padding entry");
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger baseline snapshot");
    wait_for_applied_snapshot(store, first).await;
    let (started_before, failed_before, retried_before, degraded_before, _) =
        consensus_snapshot_build_failure_counters_for_test(store);
    assert_eq!(failed_before, 0, "baseline build must not fail");

    // Fail exactly one local build attempt: the bounded retry must publish the
    // next snapshot in-process instead of stopping the engine.
    fail_next_consensus_snapshot_builds_for_test(store, 1);
    let second = append_consensus_padding_entry_for_test(store, [0xA2; 16])
        .await
        .expect("second padding entry");
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger retried snapshot");
    wait_for_consensus_snapshot_build_failures_for_test(
        store,
        failed_before + 1,
        SNAPSHOT_BUILD_WAIT,
    )
    .await;
    wait_for_applied_snapshot(store, second).await;

    let (started_after, failed_after, retried_after, degraded_after, consecutive) =
        consensus_snapshot_build_failure_counters_for_test(store);
    assert_eq!(
        failed_after,
        failed_before + 1,
        "exactly one bounded retry failure is recorded"
    );
    assert_eq!(
        retried_after,
        retried_before + 1,
        "the failed attempt is retried exactly once before success"
    );
    assert_eq!(degraded_after, degraded_before, "no degraded publication");
    assert!(
        started_after >= started_before + 2,
        "the retried snapshot starts a second attempt"
    );
    assert_eq!(consecutive, 0, "successful publication clears the streak");
    let failure = store
        .snapshot_build_failure()
        .expect("typed build failure remains observable after recovery");
    assert_eq!(
        failure.reason,
        SessionSnapshotBuildFailureReason::BuildFailed
    );
    assert_eq!(failure.degraded_builds, degraded_after);

    // The engine still serves ordinary proposals after the recovered build.
    let third = append_consensus_padding_entry_for_test(store, [0xA3; 16])
        .await
        .expect("third padding entry");
    wait_for_applied(store, third).await;

    shutdown(&stores, &paths).await;
}

#[tokio::test]
async fn every_local_snapshot_build_failure_degrades_without_stopping_the_engine() {
    let (_directory, _database_paths, stores, paths, leader) = open_leader().await;
    let store = &stores[leader];

    let first = append_consensus_padding_entry_for_test(store, [0xB1; 16])
        .await
        .expect("initial padding entry");
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger baseline snapshot");
    wait_for_applied_snapshot(store, first).await;
    let (started_before, failed_before, retried_before, degraded_before, _) =
        consensus_snapshot_build_failure_counters_for_test(store);

    // Fail every attempt of the next build command. The builder must exhaust
    // exactly its fixed bounded attempt budget, then keep the engine serving on
    // the unchanged published snapshot.
    fail_next_consensus_snapshot_builds_for_test(store, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS);
    let second = append_consensus_padding_entry_for_test(store, [0xB2; 16])
        .await
        .expect("second padding entry");
    let triggered_at = std::time::Instant::now();
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger failing snapshot");
    wait_for_consensus_snapshot_build_degraded_for_test(
        store,
        degraded_before + 1,
        SNAPSHOT_BUILD_WAIT,
    )
    .await;
    let elapsed = triggered_at.elapsed();
    wait_for_applied(store, second).await;

    let (started_after, failed_after, retried_after, degraded_after, consecutive) =
        consensus_snapshot_build_failure_counters_for_test(store);
    assert_eq!(
        failed_after,
        failed_before + CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64,
        "the attempt budget is fixed, so retries are bounded"
    );
    assert_eq!(
        started_after,
        started_before + CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64,
        "no attempt beyond the fixed budget is started"
    );
    assert_eq!(
        retried_after,
        retried_before + (CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64 - 1),
        "one retry per bounded attempt after the first"
    );
    assert_eq!(
        degraded_after,
        degraded_before + 1,
        "one degraded build keeps the engine on the unchanged snapshot"
    );
    assert_eq!(
        consecutive, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64,
        "all bounded attempts failed consecutively"
    );
    let bounded_retry_time =
        CONSENSUS_SNAPSHOT_BUILD_RETRY_BACKOFF * (CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u32 - 1);
    assert!(
        elapsed >= bounded_retry_time,
        "the fixed backoff between bounded attempts elapses: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the bounded retry budget completes quickly: {elapsed:?}"
    );
    let failure = store
        .snapshot_build_failure()
        .expect("degraded build keeps a typed failure");
    assert_eq!(
        failure.reason,
        SessionSnapshotBuildFailureReason::BuildFailed
    );
    assert_eq!(failure.degraded_builds, degraded_after);

    // The degraded command must not advance the snapshot past the published
    // baseline: no snapshot is claimed before it is durably published.
    let degraded_progress = consensus_local_durable_progress_for_test(store);
    assert_eq!(
        ConsensusEngineStateForTest::Running,
        degraded_progress.engine_state,
        "engine keeps running after a degraded build: {degraded_progress:?}"
    );
    assert_eq!(
        degraded_progress.snapshot_index,
        Some(first),
        "degraded build leaves the durable snapshot frontier unchanged"
    );

    // Engine still serves: apply advances after the degraded build.
    let third = append_consensus_padding_entry_for_test(store, [0xB3; 16])
        .await
        .expect("third padding entry");
    wait_for_applied(store, third).await;

    // The injection is exhausted; a later snapshot build succeeds, proving the
    // failure state is retryable and does not stop the engine permanently.
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger recovered snapshot");
    wait_for_applied_snapshot(store, third).await;
    let (_, _, _, _, consecutive_after) = consensus_snapshot_build_failure_counters_for_test(store);
    assert_eq!(
        consecutive_after, 0,
        "the later successful build clears the failure streak"
    );

    shutdown(&stores, &paths).await;
}

#[tokio::test]
async fn mid_build_indeterminate_publication_stops_the_engine_fatally() {
    let (_directory, _database_paths, stores, paths, leader) = open_leader().await;
    let store = &stores[leader];

    // Publish a baseline snapshot, so the degradation path would otherwise be
    // available: the indeterminate latch must still be fatal, not degraded.
    let first = append_consensus_padding_entry_for_test(store, [0xC1; 16])
        .await
        .expect("initial padding entry");
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger baseline snapshot");
    wait_for_applied_snapshot(store, first).await;
    let (started_before, _, retried_before, degraded_before, _) =
        consensus_snapshot_build_failure_counters_for_test(store);

    // The injected failure latches the mid-publication indeterminate state, as
    // a real publication failure can. The retry wrapper must re-check the latch
    // after the failed attempt and stop the engine instead of retrying/degrading.
    fail_next_consensus_snapshot_builds_with_indeterminate_publication_for_test(store, 1);
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger indeterminate snapshot");
    let progress = tokio::time::timeout(
        SNAPSHOT_BUILD_WAIT,
        wait_for_consensus_progress_for_test(store, |_| false),
    )
    .await
    .expect("the indeterminate publication stops the engine");
    assert_ne!(
        ConsensusEngineStateForTest::Running,
        progress.engine_state,
        "an indeterminate publication is fatal: {progress:?}"
    );
    assert_eq!(
        Some(ConsensusStorageErrorSubjectForTest::Snapshot),
        progress.storage_error_subject,
        "the fatal storage error names the snapshot subject: {progress:?}"
    );

    let failure = store
        .snapshot_build_failure()
        .expect("indeterminate publication keeps a typed failure");
    assert_eq!(
        failure.reason,
        SessionSnapshotBuildFailureReason::IndeterminatePublication
    );
    let (started_after, failed_after, retried_after, degraded_after, _) =
        consensus_snapshot_build_failure_counters_for_test(store);
    assert_eq!(
        started_after,
        started_before + 1,
        "the latch is re-checked before any retry is started"
    );
    assert_eq!(retried_after, retried_before, "no retry after the latch");
    assert_eq!(degraded_after, degraded_before, "no degraded publication");
    assert!(failed_after > 0);

    drop(stores);
    drop(paths);
}

#[tokio::test]
async fn build_failure_with_no_published_snapshot_stops_the_engine_fatally() {
    let (_directory, _database_paths, stores, paths, leader) = open_leader().await;
    let store = &stores[leader];

    // A pristine fixed voter has no published snapshot; there is no unchanged
    // current snapshot the bounded failure policy could keep serving at.
    let progress_before = consensus_local_durable_progress_for_test(store);
    assert_eq!(
        None, progress_before.snapshot_index,
        "fixture starts without a published snapshot: {progress_before:?}"
    );

    fail_next_consensus_snapshot_builds_for_test(store, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS);
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger failing snapshot");
    let progress = tokio::time::timeout(
        SNAPSHOT_BUILD_WAIT,
        wait_for_consensus_progress_for_test(store, |_| false),
    )
    .await
    .expect("a build failure with no published snapshot stops the engine");
    assert_ne!(
        ConsensusEngineStateForTest::Running,
        progress.engine_state,
        "no-published-snapshot build failure is fatal: {progress:?}"
    );
    assert_eq!(
        Some(ConsensusStorageErrorSubjectForTest::Snapshot),
        progress.storage_error_subject,
        "the fatal storage error names the snapshot subject: {progress:?}"
    );

    let failure = store
        .snapshot_build_failure()
        .expect("fatal build failure keeps a typed failure");
    assert_eq!(
        failure.reason,
        SessionSnapshotBuildFailureReason::NoPublishedSnapshot
    );
    let (started, failed, retried, degraded, consecutive) =
        consensus_snapshot_build_failure_counters_for_test(store);
    assert_eq!(
        started, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64,
        "exactly the fixed bounded attempt budget is consumed"
    );
    assert_eq!(failed, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64);
    assert_eq!(retried, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64 - 1);
    assert_eq!(degraded, 0, "no snapshot exists to degrade to");
    assert_eq!(consecutive, CONSENSUS_SNAPSHOT_BUILD_MAX_ATTEMPTS as u64);

    drop(stores);
    drop(paths);
}
