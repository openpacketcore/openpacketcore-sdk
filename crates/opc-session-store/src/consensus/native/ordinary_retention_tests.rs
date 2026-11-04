use super::*;
use crate::consensus::native::test_journal::journal_page_for_test_sync;
use changes::tests::{clock, fixture, time};
use std::time::Duration;

const WATCH_WINDOW: usize = 65_536;

pub(super) fn acquire(index: u64, key: &SessionKey) -> Entry<SessionRaftTypeConfig> {
    let mut entry = clock(index, time(2));
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.intent = SessionMutationIntent::AcquireLease {
        key: key.clone(),
        owner: crate::OwnerId::new("notification-retention-owner").unwrap(),
        ttl: Duration::from_secs(60),
    };
    entry
}

// A complete admitted window isolates pruning, catalog and snapshot checks
// from command receipt retention. The first test independently fills the
// same window through real committed commands.
pub(super) fn window_fixture() -> (NativeStorage, SessionKey) {
    let (mut storage, _, outcome) = fixture();
    let mut key = outcome.lease().key().clone();
    key.stable_id = bytes::Bytes::from_static(b"notification-retention-key")
        .try_into()
        .unwrap();
    let applied = changes::tests::apply(&mut storage, &[acquire(2, &key)]);
    let original = &applied.notifications[0];
    storage.business.notifications.clear();
    for sequence in 1..=WATCH_WINDOW as u64 {
        storage.business.notifications.push_back(
            NotificationRow::new(NativeNotification::new(ReplicationEntry {
                sequence,
                ..original.clone()
            }))
            .unwrap(),
        );
    }
    storage.business.frontiers.watch_sequence = WATCH_WINDOW as u64;
    storage.business.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    storage.validate_image().unwrap();
    (storage, key)
}

pub(crate) fn retired_notification_fixture() -> (
    NativeStorage,
    SessionConsensusIdentity,
    BTreeSet<SessionConsensusNodeId>,
) {
    let (mut storage, key) = window_fixture();
    changes::tests::apply(&mut storage, &[acquire(3, &key)]);
    let identity = storage.business.identity;
    let members = storage.business.members.clone();
    (storage, identity, members)
}

#[test]
fn native_notification_retention_bounds_committed_replay_and_rejects_stale_cursor() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::test_process::CommandExt as _;
        const CHILD: &str = "OPC_NATIVE_NOTIFICATION_REPLAY_CHILD";
        const TEST: &str = "consensus::native::ordinary_retention_tests::native_notification_retention_bounds_committed_replay_and_rejects_stale_cursor";
        if std::env::var_os(CHILD).is_none() {
            // This complete window owns a process-wide verification reservation.
            // Keep its replay checks independent of concurrent unit fixtures.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(CHILD, "1")
                .test_output_with_deadline(std::time::Duration::from_secs(1800))
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            println!(
                "native_notification_replay_child={}",
                serde_json::json!({
                    "exit_code": output.status.code(),
                    "stdout": stdout,
                    "stderr": stderr,
                    "notification_window": WATCH_WINDOW,
                })
            );
            assert!(
                output.status.success(),
                "the complete notification window must replay in the child"
            );
            assert!(
                stdout.contains(&format!("test {TEST} ... ok"))
                    && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                "the exact bounded replay test must execute in the child"
            );
            return;
        }
        let (storage, _, outcome) = fixture();
        let mut state = storage.business;
        let mut key = outcome.lease().key().clone();
        key.stable_id = bytes::Bytes::from_static(b"notification-retention-key")
            .try_into()
            .unwrap();
        for index in 2..WATCH_WINDOW as u64 + 4 {
            let applied = state.apply(&[acquire(index, &key)]).unwrap();
            assert!(applied.responses[0].result.is_ok());
            assert_eq!(applied.notifications.len(), 1);
            assert_eq!(applied.notifications[0].sequence, index);
        }
        assert_eq!(state.notifications.len(), WATCH_WINDOW);
        assert_eq!(state.frontiers.watch_sequence, WATCH_WINDOW as u64 + 3);
        assert_eq!(
            state.replication_log(1, 1, &|| Ok(())).unwrap_err(),
            StoreError::ReplicationLogCursorCompacted { resume_from: 4 }
        );
        let replay = journal_page_for_test_sync(|| state.replication_log(4, 2, &|| Ok(())));
        assert_eq!(
            replay.iter().map(|row| row.sequence).collect::<Vec<_>>(),
            [4, 5]
        );
        assert!(journal_page_for_test_sync(|| state.replication_log(1, 0, &|| Ok(()))).is_empty());
        state.validate_full_business().unwrap();
    });
}

#[test]
fn native_notification_retention_survives_full_image_round_trip() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        use crate::test_process::CommandExt as _;
        const CHILD: &str = "OPC_NATIVE_NOTIFICATION_ROUND_TRIP_CHILD";
        const TEST: &str = "consensus::native::ordinary_retention_tests::native_notification_retention_survives_full_image_round_trip";
        if std::env::var_os(CHILD).is_none() {
            // The complete window and its decoded image share the process-wide
            // verification budget. Keep this fixture's budget independent of
            // concurrent unit fixtures while preserving every row and assertion.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(CHILD, "1")
                .test_output_with_deadline(std::time::Duration::from_secs(1800))
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            println!(
                "native_notification_round_trip_child={}",
                serde_json::json!({
                    "exit_code": output.status.code(),
                    "stdout": stdout,
                    "stderr": stderr,
                    "notification_window": WATCH_WINDOW,
                })
            );
            assert!(
                output.status.success(),
                "the complete notification window must round-trip in the child"
            );
            assert!(
                stdout.contains(&format!("test {TEST} ... ok"))
                    && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                "the exact notification round-trip test must execute in the child"
            );
            return;
        }
        let (mut storage, key) = window_fixture();
        for index in 3..11 {
            changes::tests::apply(&mut storage, &[acquire(index, &key)]);
        }
        let floor = storage.business.frontiers.retention.watch_retired_through;
        let watch = storage.business.frontiers.watch_sequence;
        assert_eq!(floor, 8);
        let mut bytes = Vec::new();
        storage.write_image(&mut bytes, [0xCE; 32], 17).unwrap();
        let restored = NativeStorage::read_image(
            &mut bytes.as_slice(),
            [0xCE; 32],
            17,
            storage.business.identity(),
        )
        .unwrap();
        assert!(restored.business.frontiers == storage.business.frontiers);
        assert_eq!(restored.business.notifications.len(), WATCH_WINDOW);
        assert_eq!(
            restored.business.notifications.front().unwrap().sequence(),
            floor + 1
        );
        assert_eq!(
            restored.business.notifications.back().unwrap().sequence(),
            watch
        );
        restored.business.validate_full_business_rows().unwrap();
        restored.validate_image().unwrap();
        assert_eq!(
            restored
                .business
                .replication_log(0, 8, &|| Ok(()))
                .unwrap_err(),
            StoreError::ReplicationLogCursorCompacted {
                resume_from: floor + 1
            }
        );
        // Replay the complete window through bounded pages, as an ordinary reader
        // does, without reserving the whole window's worst-case verification size.
        let mut next = floor + 1;
        let mut delivered = 0;
        while next <= watch {
            let page = journal_page_for_test_sync(|| {
                restored.business.replication_log(next, 128, &|| Ok(()))
            });
            assert!(!page.is_empty());
            for entry in &page {
                assert_eq!(entry.sequence, next);
                next += 1;
            }
            delivered += page.len();
        }
        assert_eq!(delivered, WATCH_WINDOW);
        assert_eq!(next, watch + 1);
    });
}

/// An admitted complete window whose first row is a real committed recovery.
/// Padding isolates physical snapshot coordinates from mutation workload cost.
pub(crate) fn retained_recovery_notification_fixture() -> (NativeStorage, u64) {
    let mut storage =
        crate::consensus::native::key_retention_tests::explicit_replay_policy_fixture();
    let mut original = Vec::new();
    NativeNotification::visit_export(
        &storage.business.notifications,
        &storage.business.frontiers,
        &|| Ok(()),
        &mut |entry| {
            original.push(owned::notification(entry)?);
            Ok(())
        },
    )
    .unwrap();
    let first = original
        .iter()
        .find(|entry| {
            matches!(
                entry.replay_policy.recovery,
                crate::ReplicationRecoveryBoundary::Recover { .. }
            )
        })
        .unwrap()
        .sequence;
    let mut policy = crate::ReplicationReplayPolicy::preserve();
    policy.async_fence_floor = storage.business.frontiers.async_fence_floor();
    let head = first + WATCH_WINDOW as u64 - 1;
    storage.business.notifications.clear();
    for sequence in first..=head {
        let entry = original
            .iter()
            .find(|entry| entry.sequence == sequence)
            .cloned()
            .unwrap_or_else(|| ReplicationEntry {
                sequence,
                tx_id: ReplicationTxId::from_request_bytes(u128::from(sequence).to_be_bytes()),
                timestamp: time(6),
                replay_policy: policy,
                op: crate::ReplicationOp::Batch { ops: Vec::new() },
            });
        storage
            .business
            .notifications
            .push_back(NotificationRow::new(NativeNotification::new(entry)).unwrap());
    }
    storage.business.frontiers.watch_sequence = head;
    storage.business.frontiers.retention.watch_retired_through = first - 1;
    storage.business.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    storage.validate_image().unwrap();
    (storage, first)
}

pub(crate) fn notify_after_retained_recovery_reopen(storage: &mut NativeStorage) {
    let mut key = changes::tests::request(1, None).lease().key().clone();
    key.stable_id = bytes::Bytes::from_static(b"notify-after-retained-recovery-reopen")
        .try_into()
        .unwrap();
    let index = storage.business.applied().unwrap().index + 1;
    let mut entry = crate::consensus::native::key_retention_tests::command_at(
        index,
        SessionMutationIntent::AcquireLease {
            key,
            owner: crate::OwnerId::new("recovery-retention-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
        time(8),
    );
    entry.log_id.leader_id = storage.business.applied().unwrap().leader_id;
    let applied = changes::tests::apply(storage, &[entry]);
    assert!(applied.responses[0].result.is_ok());
    assert_eq!(applied.notifications.len(), 1);
    storage.validate_image().unwrap();
}
