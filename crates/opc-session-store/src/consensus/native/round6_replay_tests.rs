use super::*;
use crate::{LeaseError, SessionLeaseManager, SessionStore, SqliteSessionBackend};
use futures_util::StreamExt;

fn recovery(native: &NativeStorage, index: u64, era: u64) -> Entry<SessionRaftTypeConfig> {
    use crate::sqlite::consensus::wal::async_authority::Reservation;
    let floor = Reservation::from_era(era).unwrap().retired_through();
    let mut entry = key_retention_tests::command_at(
        index,
        SessionMutationIntent::AsyncRecoveryBoundary {
            era,
            plan: [era as u8; 32],
            protected: None,
        },
        time(3),
    );
    entry.log_id.leader_id = opc_consensus::engine::CommittedLeaderId::new(
        floor + 2,
        *native.business.members.first().unwrap(),
    );
    entry
}

async fn committed_slice(boundaries: usize, trailing: bool) {
    let (mut native, old) = key_retention_tests::retired_key_fixture();
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(3))));
    let fake = replay_prefix(&native, clock).await;
    let start = fake.max_replication_sequence().await.unwrap() + 1;
    let mut watch = SessionStore::new(fake.clone()).watch(start).await.unwrap();
    let first = native.business.applied().unwrap().index + 1;
    let mut entries = vec![key_retention_tests::command_at(
        first,
        SessionMutationIntent::AcquireLease {
            key: key(old.key(), 8000),
            owner: crate::OwnerId::new("slice-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
        time(3),
    )];
    for n in 0..boundaries {
        entries.push(recovery(
            &native,
            first + entries.len() as u64,
            2 + n as u64,
        ));
        if trailing || n + 1 < boundaries {
            let mut entry = key_retention_tests::command_at(
                first + entries.len() as u64,
                SessionMutationIntent::AcquireLease {
                    key: key(old.key(), 8001 + n as u64),
                    owner: crate::OwnerId::new("slice-owner").unwrap(),
                    ttl: Duration::from_secs(60),
                },
                time(3),
            );
            entry.log_id.leader_id = entries.last().unwrap().log_id.leader_id;
            entries.push(entry);
        }
    }
    let mut separate = native.clone();
    let mut expected = Vec::new();
    for entry in &entries {
        let result = apply(&mut separate, std::slice::from_ref(entry));
        assert!(result.responses.iter().all(|r| r.result.is_ok()));
        expected.extend(result.notifications);
    }
    let combined = apply(&mut native, &entries);
    assert!(combined.responses.iter().all(|r| r.result.is_ok()));
    assert_eq!(
        combined.notifications, expected,
        "one committed slice must deliver every notification under its original frontier"
    );
    for entry in combined.notifications {
        fake.replicate_entry(entry.clone()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), watch.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            entry
        );
    }
    assert_eq!(native_state(&native), native_state(&separate));
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
    let mut raw = Vec::new();
    NativeNotification::visit_export(
        &native.business.notifications,
        &native.business.frontiers,
        &|| Ok(()),
        &mut |entry| {
            raw.push(owned::notification(entry)?);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        raw.last().unwrap().sequence,
        native.business.frontiers.watch_sequence
    );
}

#[tokio::test]
async fn round6_committed_slice_before_recovery_delivers_every_notification() {
    committed_slice(1, false).await;
}
#[tokio::test]
async fn round6_committed_slice_before_recovery_and_after_stays_contiguous() {
    committed_slice(1, true).await;
}
#[tokio::test]
async fn round6_committed_slice_with_two_recoveries_stays_contiguous() {
    committed_slice(2, true).await;
}

fn context(sequence: u64, policy: crate::ReplicationReplayPolicy) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: ReplicationTxId::from_request_bytes(u128::from(sequence).to_be_bytes()),
        timestamp: time(3),
        op: crate::ReplicationOp::Batch { ops: Vec::new() },
        replay_policy: policy,
    }
}

#[tokio::test]
async fn round6_session_store_watch_emits_recovery_row_at_resume_cursor() {
    let fake = FakeSessionBackend::new();
    fake.replicate_entry(context(1, crate::ReplicationReplayPolicy::preserve()))
        .await
        .unwrap();
    let mut boundary = crate::ReplicationReplayPolicy::preserve();
    boundary.async_fence_floor = 100;
    boundary.recovery = crate::ReplicationRecoveryBoundary::Recover {
        previous_sequence: 1,
    };
    fake.replicate_entry(context(101, boundary)).await.unwrap();
    let mut watch = SessionStore::new(fake).watch(101).await.unwrap();
    let row = tokio::time::timeout(Duration::from_secs(180), watch.next())
        .await
        .expect("recovery watch stalled before its committed resume row")
        .unwrap()
        .unwrap();
    assert_eq!(row.sequence, 101);
}

async fn local_lease_after_recovery(operation: u8) {
    let (mut native, _, live) = changes::tests::fixture();
    let old = live.lease().clone();
    let fake = replay_prefix(
        &native,
        Arc::new(ReplayClock(std::sync::Mutex::new(time(3)))),
    )
    .await;
    let entry = recovery(&native, native.business.applied().unwrap().index + 1, 2);
    let result = apply(&mut native, &[entry]);
    for entry in result.notifications {
        fake.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
    let before = crate::fake::tests::backend_data_snapshot(&fake).await;
    let owner = crate::OwnerId::new("successor-owner").unwrap();
    let intent = match operation {
        0 => SessionMutationIntent::AcquireLease {
            key: old.key().clone(),
            owner: owner.clone(),
            ttl: Duration::from_secs(60),
        },
        1 => SessionMutationIntent::RenewLease {
            lease: old.clone(),
            ttl: Duration::from_secs(60),
        },
        _ => SessionMutationIntent::ReleaseLease(old.clone()),
    };
    let mut command = key_retention_tests::command_at(
        native.business.applied().unwrap().index + 1,
        intent,
        time(3),
    );
    command.log_id.leader_id = native.business.applied().unwrap().leader_id;
    let result = apply(&mut native, &[command]);
    if operation == 0 {
        let Ok(SessionMutationOutcome::Lease(expected)) = &result.responses[0].result else {
            panic!("successor acquire")
        };
        let actual = fake
            .acquire(old.key(), owner, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(&actual, expected);
        assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
    } else {
        assert_eq!(result.responses[0].result, Err(StoreError::StaleFence));
        if operation == 1 {
            assert_eq!(
                fake.renew(&old, Duration::from_secs(60)).await,
                Err(LeaseError::StaleFence)
            );
        } else {
            assert_eq!(fake.release(old).await, Err(LeaseError::StaleFence));
        }
        assert_eq!(
            crate::fake::tests::backend_data_snapshot(&fake).await,
            before,
            "refusal publishes no lazy materialization"
        );
    }
}
#[tokio::test]
async fn round6_local_successor_acquisition_applies_replayed_floor() {
    local_lease_after_recovery(0).await;
}
#[tokio::test]
async fn round6_local_renewal_refuses_recovered_credential_atomically() {
    local_lease_after_recovery(1).await;
}
#[tokio::test]
async fn round6_local_release_refuses_recovered_credential_atomically() {
    local_lease_after_recovery(2).await;
}

fn sqlite_rows(path: &std::path::Path) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let conn = rusqlite::Connection::open(path).unwrap();
    [
        "session_records",
        "leases",
        "key_fences",
        "lease_globals",
        "session_replication_log",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1, 2"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

async fn sqlite_time_case(kind: u8) {
    let at = |second| time(0).add_seconds(second).unwrap();
    let (native, _, live) = changes::tests::fixture();
    let guard = live.lease();
    let key = guard.key().clone();
    let make = |sequence, timestamp, op| {
        let mut entry = context(
            sequence,
            if kind == 0 {
                crate::ReplicationReplayPolicy::prune_expired()
            } else {
                crate::ReplicationReplayPolicy::preserve()
            },
        );
        entry.timestamp = timestamp;
        entry.op = op;
        entry
    };
    let mut entries = vec![make(
        1,
        at(1),
        crate::ReplicationOp::AcquireLease {
            key: key.clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            credential_id: guard.credential_id(),
            ttl: Duration::from_secs(60),
            expires_at: at(61),
        },
    )];
    let mut record = native.business.keys[&key].record.clone().unwrap();
    record.expires_at = Some(at(51));
    let cas = || crate::ReplicationOp::CompareAndSet {
        key: key.clone(),
        expected_generation: None,
        credential_id: guard.credential_id(),
        guard_expires_at: at(61),
        new_record: record.clone(),
    };
    if kind == 2 {
        entries.push(make(2, at(2), cas()));
    }
    entries.push(make(
        entries.len() as u64 + 1,
        at(11),
        crate::ReplicationOp::AcquireLease {
            key: super::key(&key, 8100),
            owner: guard.owner().clone(),
            fence: crate::FenceToken::new(guard.fence().get() + 1),
            credential_id: guard.credential_id() + 1,
            ttl: Duration::from_secs(60),
            expires_at: at(71),
        },
    ));
    let last = match kind {
        0 => crate::ReplicationOp::RenewLease {
            key: key.clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            credential_id: guard.credential_id(),
            ttl: Duration::from_secs(60),
            expires_at: at(81),
        },
        1 => cas(),
        _ => crate::ReplicationOp::RefreshTtl {
            key: key.clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            ttl: Duration::from_secs(60),
            expires_at: at(81),
        },
    };
    entries.push(make(entries.len() as u64 + 1, at(21), last));
    let replica_clock = Arc::new(ReplayClock(std::sync::Mutex::new(at(1))));
    let directory = tempfile::tempdir().unwrap();
    let live_path = directory.path().join("live.sqlite");
    let rebuilt_path = directory.path().join("rebuilt.sqlite");
    let replica = SqliteSessionBackend::open(&live_path)
        .unwrap()
        .with_clock(replica_clock.clone());
    let before_pause = if kind == 2 { 2 } else { 1 };
    for entry in &entries[..before_pause] {
        replica.replicate_entry(entry.clone()).await.unwrap();
    }
    *replica_clock.0.lock().unwrap() = at(71);
    for entry in &entries[before_pause..] {
        replica.replicate_entry(entry.clone()).await.unwrap();
    }
    let rebuilt = SqliteSessionBackend::open(&rebuilt_path)
        .unwrap()
        .with_clock(replica_clock);
    rebuilt.rebuild_replication_state(entries).await.unwrap();
    assert_eq!(sqlite_rows(&live_path), sqlite_rows(&rebuilt_path));
}

#[tokio::test]
async fn round6_sqlite_live_replay_uses_committed_time_like_rebuild() {
    sqlite_time_case(0).await;
}
#[tokio::test]
async fn round6_sqlite_cas_replay_verifies_at_committed_time() {
    sqlite_time_case(1).await;
}
#[tokio::test]
async fn round6_sqlite_refresh_replay_verifies_at_committed_time() {
    sqlite_time_case(2).await;
}

#[tokio::test]
async fn round6_sqlite_framed_replay_survives_reopen_and_partial_rebuild() {
    use crate::ReplicationCommandBoundary as Boundary;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("framed.sqlite");
    let rebuilt_path = directory.path().join("rebuilt.sqlite");
    let source = SqliteSessionBackend::open(&path).unwrap();
    let mut policy = crate::ReplicationReplayPolicy::preserve();
    policy.command = Boundary::Start {
        id: [61; 16],
        following_entries: 1,
    };
    let first = context(1, policy);
    policy.command = Boundary::Continue {
        id: [61; 16],
        remaining_entries: 0,
    };
    let second = context(2, policy);
    source.replicate_entry(first.clone()).await.unwrap();
    drop(source);
    let source = SqliteSessionBackend::open(&path).unwrap();
    let rebuilt = SqliteSessionBackend::open(&rebuilt_path).unwrap();
    rebuilt
        .rebuild_replication_state(vec![first.clone()])
        .await
        .unwrap();
    assert_eq!(sqlite_rows(&path), sqlite_rows(&rebuilt_path));
    let before = sqlite_rows(&path);
    let (_, _, request) = changes::tests::fixture();
    assert!(source
        .acquire(
            request.lease().key(),
            crate::OwnerId::new("framing-owner").unwrap(),
            Duration::from_secs(60)
        )
        .await
        .is_err());
    assert_eq!(
        sqlite_rows(&path),
        before,
        "local admission cannot interleave a committed command"
    );
    for field in 0..3 {
        let mut invalid = second.clone();
        match field {
            0 => {
                invalid.replay_policy.command = Boundary::Continue {
                    id: [62; 16],
                    remaining_entries: 0,
                }
            }
            1 => invalid.timestamp = time(4),
            _ => invalid.replay_policy.command = Boundary::Single,
        }
        assert!(source.replicate_entry(invalid).await.is_err());
        assert_eq!(sqlite_rows(&path), before, "invalid continuation is atomic");
    }
    source.replicate_entry(second.clone()).await.unwrap();
    source.replicate_entry(second.clone()).await.unwrap();
    rebuilt.replicate_entry(second.clone()).await.unwrap();
    assert_eq!(sqlite_rows(&path), sqlite_rows(&rebuilt_path));
    rebuilt
        .rebuild_replication_state(vec![first, second])
        .await
        .unwrap();
    assert_eq!(sqlite_rows(&path), sqlite_rows(&rebuilt_path));
    source
        .acquire(
            request.lease().key(),
            crate::OwnerId::new("framing-owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
}

#[path = "round6_recovery_parity.rs"]
mod round6_recovery_parity;

#[tokio::test]
async fn round6_sqlite_release_replay_preserves_committed_guard_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("release-source.sqlite");
    let replica_path = directory.path().join("release-replica.sqlite");
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(1))));
    let source = SqliteSessionBackend::open(&source_path)
        .unwrap()
        .with_clock(clock.clone());
    let replica = SqliteSessionBackend::open(&replica_path)
        .unwrap()
        .with_clock(clock.clone());
    let (_, _, template) = changes::tests::fixture();
    let guard = source
        .acquire(
            template.lease().key(),
            crate::OwnerId::new("release-owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let mut first = context(1, crate::ReplicationReplayPolicy::preserve());
    first.timestamp = time(1);
    first.op = crate::ReplicationOp::AcquireLease {
        key: guard.key().clone(),
        owner: guard.owner().clone(),
        fence: guard.fence(),
        credential_id: guard.credential_id(),
        ttl: Duration::from_secs(60),
        expires_at: guard.expires_at(),
    };
    replica.replicate_entry(first).await.unwrap();
    *clock.0.lock().unwrap() = time(2);
    source.release(guard.clone()).await.unwrap();
    let mut second = context(2, crate::ReplicationReplayPolicy::preserve());
    second.timestamp = time(2);
    second.op = crate::ReplicationOp::ReleaseLease {
        key: guard.key().clone(),
        owner: guard.owner().clone(),
        fence: guard.fence(),
        credential_id: guard.credential_id(),
    };
    replica.replicate_entry(second).await.unwrap();
    assert_eq!(
        &sqlite_rows(&source_path)[..4],
        &sqlite_rows(&replica_path)[..4]
    );
}
