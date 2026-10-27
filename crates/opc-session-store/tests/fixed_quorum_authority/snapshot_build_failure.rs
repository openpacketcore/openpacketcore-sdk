//! Local snapshot failures retain the fail-stop storage contract.
//!
//! Retry/degraded build and install recovery (#1254/#1243) is deferred until
//! retained-log admission (#1249) exists and is qualified. These four original
//! fault scenarios require a real build error to stop the engine immediately,
//! preserve the published frontier, and refuse subsequent local work.

use super::*;

use opc_session_store::test_support::{
    append_consensus_padding_entry_for_test, consensus_local_durable_progress_for_test,
    consensus_snapshot_build_failures_remaining_for_test, consensus_snapshot_build_phase_for_test,
    fail_next_consensus_snapshot_builds_for_test,
    fail_next_consensus_snapshot_builds_with_indeterminate_publication_for_test,
    trigger_consensus_snapshot_for_test, wait_for_consensus_progress_for_test,
    ConsensusEngineStateForTest, ConsensusStorageErrorSubjectForTest,
    ConsensusStorageErrorVerbForTest,
};

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

/// Establish a real durable predecessor under the same fixture deadline.
async fn publish_baseline(store: &ConsensusSessionStore) -> u64 {
    let index = append_consensus_padding_entry_for_test(store, [0xA1; 16])
        .await
        .expect("initial padding entry");
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger baseline snapshot");
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
    assert_eq!(ConsensusEngineStateForTest::Running, progress.engine_state);
    assert_eq!(Some(index), progress.snapshot_index);
    assert!(progress
        .applied_index
        .is_some_and(|applied| applied >= index));
    index
}

fn snapshot_children(directory: &std::path::Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(directory)
        .expect("snapshot namespace")
        .map(|entry| {
            let entry = entry.expect("snapshot namespace child");
            assert!(entry.file_type().expect("child type").is_file());
            (
                entry.file_name(),
                std::fs::read(entry.path()).expect("child bytes"),
            )
        })
        .collect()
}

async fn assert_build_failure_stops_engine(
    with_predecessor: bool,
    staging_failures: usize,
    indeterminate_publication: bool,
) {
    let (directory, _database_paths, stores, paths, leader) = open_leader().await;
    let store = &stores[leader];
    let published = if with_predecessor {
        Some(publish_baseline(store).await)
    } else {
        None
    };
    let before = consensus_local_durable_progress_for_test(store);
    assert_eq!(published, before.snapshot_index);
    assert_eq!(ConsensusEngineStateForTest::Running, before.engine_state);
    let snapshot_directory = directory.path().join(format!("snapshots-{leader}"));
    let children_before = snapshot_children(&snapshot_directory);
    let completed_before = store.status().completed_snapshot_count;
    let applied = append_consensus_padding_entry_for_test(store, [0xA2; 16])
        .await
        .expect("apply before fault injection");
    let expected_remaining = if indeterminate_publication {
        fail_next_consensus_snapshot_builds_with_indeterminate_publication_for_test(store, 2);
        (0, 1)
    } else {
        fail_next_consensus_snapshot_builds_for_test(store, staging_failures);
        (staging_failures - 1, 0)
    };
    let triggered_at = std::time::Instant::now();
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("trigger failing snapshot");
    let progress = tokio::time::timeout(
        SNAPSHOT_BUILD_WAIT,
        wait_for_consensus_progress_for_test(store, |_| false),
    )
    .await
    .expect("the first snapshot build failure must stop the engine");
    assert_eq!(
        ConsensusEngineStateForTest::StorageIo,
        progress.engine_state,
        "snapshot failure must reach Openraft: {progress:?}"
    );
    assert_eq!(
        Some(ConsensusStorageErrorSubjectForTest::Snapshot),
        progress.storage_error_subject
    );
    assert_eq!(
        Some(ConsensusStorageErrorVerbForTest::Write),
        progress.storage_error_verb
    );
    assert_eq!(
        published, progress.snapshot_index,
        "no unpublished snapshot frontier"
    );
    assert_eq!(
        before.purged_index, progress.purged_index,
        "no unsupported log purge"
    );
    assert!(progress.applied_index.is_some_and(|index| index >= applied));
    assert_eq!(completed_before, store.status().completed_snapshot_count);
    assert_eq!(
        expected_remaining,
        consensus_snapshot_build_failures_remaining_for_test(store),
        "exactly one failing attempt, without retry or degradation"
    );
    assert_eq!(
        if indeterminate_publication {
            "publication_failed"
        } else {
            "staging_failed"
        },
        consensus_snapshot_build_phase_for_test(store),
        "the fault must exercise the real staging or sealed-publication boundary"
    );
    assert!(
        triggered_at.elapsed() < Duration::from_secs(10),
        "fail-stop completes promptly"
    );

    let children_after = snapshot_children(&snapshot_directory);
    for (name, bytes) in &children_before {
        assert_eq!(
            Some(bytes),
            children_after.get(name),
            "predecessor bytes remain intact"
        );
    }
    if indeterminate_publication {
        assert_eq!(
            children_before.len() + 1,
            children_after.len(),
            "retain only the indeterminate sealed candidate for a fresh owner's audit"
        );
        let candidate = children_after
            .keys()
            .find(|name| !children_before.contains_key(*name))
            .expect("retained candidate");
        let candidate = candidate.to_str().expect("generated candidate name");
        assert!(candidate.starts_with("snapshot-") && candidate.ends_with(".opc"));
    } else {
        assert_eq!(
            children_before, children_after,
            "both staged children are reclaimed"
        );
    }

    assert!(
        append_consensus_padding_entry_for_test(store, [0xA3; 16])
            .await
            .is_err(),
        "the stopped engine must refuse subsequent proposals"
    );
    assert!(
        trigger_consensus_snapshot_for_test(store).await.is_err(),
        "a later trigger cannot silently resume the stopped engine"
    );
    assert_eq!(
        expected_remaining,
        consensus_snapshot_build_failures_remaining_for_test(store)
    );
    assert_eq!(
        published,
        consensus_local_durable_progress_for_test(store).snapshot_index
    );
    drop(stores);
    drop(paths);
}

#[tokio::test]
async fn failed_local_snapshot_build_stops_the_engine_without_retry() {
    assert_build_failure_stops_engine(true, 1, false).await;
}

#[tokio::test]
async fn persistent_local_snapshot_build_failure_stops_without_degradation() {
    assert_build_failure_stops_engine(true, usize::MAX, false).await;
}

#[tokio::test]
async fn mid_build_indeterminate_publication_stops_without_retry() {
    assert_build_failure_stops_engine(true, 0, true).await;
}

#[tokio::test]
async fn first_local_snapshot_build_failure_stops_without_retry() {
    assert_build_failure_stops_engine(false, 3, false).await;
}
