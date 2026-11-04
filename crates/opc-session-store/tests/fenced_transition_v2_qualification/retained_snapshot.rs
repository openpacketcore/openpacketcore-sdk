//! Full-window portable snapshots, real follower installation and cold reopen.

use super::*;
use futures_util::FutureExt as _;
use opc_session_store::test_support::{
    consensus_local_replication_sequence_for_test,
    consensus_native_snapshot_install_origin_for_test,
    shutdown_consensus_without_close_proof_for_test, trigger_consensus_log_purge_through_for_test,
    trigger_consensus_snapshot_for_test,
};
use opc_session_store::{
    ConsensusSessionStoreOpenError, RestoreScanRequest, SessionAsyncRecoveryState,
    SessionPersistenceMode, SnapshotIntegrityPolicy,
};

type ExpectedRecords = BTreeMap<Vec<u8>, [u8; 32]>;
const RETAINED_NOTIFICATIONS: usize = 65_536;
const LIVE_KEYS: usize = 64;

async fn initialize_after_cold_restart(
    stores: &[ConsensusSessionStore],
    mode: SessionPersistenceMode,
) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let mut completed = true;
            for result in futures_util::future::join_all(
                stores.iter().map(ConsensusSessionStore::initialize_cluster),
            )
            .await
            {
                match result {
                    Ok(()) => {}
                    Err(ConsensusSessionStoreOpenError::RecoveryRequired)
                        if mode == SessionPersistenceMode::Async =>
                    {
                        completed = false
                    }
                    Err(error) => panic!("cold initialization failed: {error:?}"),
                }
            }
            if completed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the real cold admission protocol completes");
}

async fn admitted_leader(stores: &[ConsensusSessionStore]) -> usize {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let reports = futures_util::future::join_all(
                stores
                    .iter()
                    .map(ConsensusSessionStore::probe_fixed_quorum_readiness),
            )
            .await;
            let statuses: Vec<_> = stores.iter().map(ConsensusSessionStore::status).collect();
            if reports.iter().all(|r| r.traffic_authority().is_granted())
                && statuses.iter().all(|s| s.admitted)
                && statuses[0].leader_id.is_some()
                && statuses
                    .iter()
                    .all(|s| s.leader_id == statuses[0].leader_id)
            {
                return statuses
                    .iter()
                    .position(|s| Some(s.node_id) == s.leader_id)
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the mode-aware three-voter quorum becomes ready")
}

async fn wait_for_notifications(store: &ConsensusSessionStore, sequence: u64) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if consensus_local_replication_sequence_for_test(store)
                .await
                .unwrap()
                == sequence
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the voter applies the exact notification frontier");
}

async fn snapshot(store: &ConsensusSessionStore) {
    let before = store.status();
    let phase_before =
        opc_session_store::test_support::consensus_snapshot_build_phase_for_test(store);
    trigger_consensus_snapshot_for_test(store)
        .await
        .expect("request the production snapshot finalizer");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if store.status().completed_snapshot_count > before.completed_snapshot_count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "the production finalizer publishes the exact retained prefix: {error:?}; request_enqueued=true, before={before:?}, after={:?}, phase_before={phase_before:?}, phase_after={:?}, durable_progress={:?}",
            store.status(),
            opc_session_store::test_support::consensus_snapshot_build_phase_for_test(store),
            consensus_local_durable_progress_for_test(store)
        )
    });
}

async fn purge_verified_snapshot(store: &ConsensusSessionStore) {
    let captured = consensus_local_durable_progress_for_test(store)
        .snapshot_index
        .expect("a completed verified snapshot is selected");
    trigger_consensus_log_purge_through_for_test(store, captured)
        .await
        .expect("purge only the log prefix covered by the verified snapshot");
    tokio::time::timeout(Duration::from_secs(30), async {
        while consensus_local_durable_progress_for_test(store).purged_index < Some(captured) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the snapshot-covered prefix is durably purged");
    assert!(consensus_local_durable_progress_for_test(store).snapshot_index >= Some(captured));
}

async fn write_range(
    store: &ConsensusSessionStore,
    begin: usize,
    end: usize,
    provider: &MemoryKeyProvider,
    expected: &mut ExpectedRecords,
    latest: &mut Vec<FencedTransitionOutcome>,
) {
    let epoch = FencedTransitionV2HistoryEpoch::new(1).unwrap();
    for start in (begin..end).step_by(LIVE_KEYS) {
        let mut batch = Vec::new();
        let mut slots = Vec::new();
        for index in start..(start + LIVE_KEYS).min(end) {
            let slot = index % LIVE_KEYS;
            let request = if let Some(previous) = latest.get(slot) {
                renew_update_request(index, epoch, previous, provider).await
            } else {
                create_request(index, epoch, key(slot), FenceToken::new(0), provider).await
            };
            batch.push(request);
            slots.push(slot);
        }
        let FencedTransitionV2Effect::Resolved(Ok(outcomes)) =
            store.fenced_transition_v2_batch_effect(batch.clone()).await
        else {
            panic!("the complete public mutation batch must resolve");
        };
        assert_eq!(batch.len(), outcomes.len());
        for ((request, slot), outcome) in batch.iter().zip(slots).zip(outcomes) {
            let outcome = outcome.expect("every mutation succeeds");
            assert_exact_qualified_v2_success(request, &outcome);
            let (record, created) = match request.mutation() {
                FencedTransitionMutation::Create { record } => (record, true),
                FencedTransitionMutation::Update { record, .. } => (record, false),
                _ => panic!("the fixture submits creates and exact generation updates"),
            };
            let replaced = expected.insert(
                serde_json::to_vec(&record.key).unwrap(),
                Sha256::digest(serde_json::to_vec(record).unwrap()).into(),
            );
            if created {
                assert!(replaced.is_none());
                assert_eq!(slot, latest.len());
                latest.push(outcome);
            } else {
                assert!(replaced.is_some());
                latest[slot] = outcome;
            }
        }
    }
    assert_eq!(expected.len(), LIVE_KEYS);
    assert_eq!(latest.len(), LIVE_KEYS);
}

async fn audit_retained_notifications(stores: &[ConsensusSessionStore], first: u64, head: u64) {
    let mut reference = None;
    for store in stores {
        let mut next = first;
        let mut digest = Sha256::new();
        while next <= head {
            let page = store
                .get_replication_log(next, 512)
                .await
                .expect("read every retained notification");
            assert!(!page.is_empty());
            assert!(page.len() <= 512);
            for entry in page {
                assert_eq!(
                    entry.sequence, next,
                    "the entire retained window is contiguous"
                );
                assert!(entry.sequence <= head);
                let encoded = serde_json::to_vec(&entry).unwrap();
                digest.update((encoded.len() as u64).to_be_bytes());
                digest.update(encoded);
                next += 1;
            }
        }
        assert_eq!(next, head + 1);
        let hash: [u8; 32] = digest.finalize().into();
        if let Some(reference) = reference {
            assert_eq!(hash, reference);
        } else {
            reference = Some(hash);
        }
        assert!(store
            .get_replication_log(head + 1, 1)
            .await
            .unwrap()
            .is_empty());
    }
}

async fn audit_all_records(
    stores: &[ConsensusSessionStore],
    expected: &ExpectedRecords,
    provider: &MemoryKeyProvider,
) {
    for store in stores {
        let mut unseen = expected.clone();
        let mut request = RestoreScanRequest::all(256);
        let mut count = 0;
        loop {
            let page = store
                .scan_restore_records(request.clone())
                .await
                .expect("scan all acknowledged records");
            for record in &page.records {
                let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(record).unwrap()).into();
                assert_eq!(
                    unseen.remove(&serde_json::to_vec(&record.key).unwrap()),
                    Some(digest),
                    "no missing, repeated or changed complete record"
                );
                let plaintext = record
                    .payload
                    .decrypt(
                        provider,
                        &record.key,
                        &record.state_type,
                        record.generation,
                        record.fence,
                        key(0).tenant.as_str(),
                    )
                    .await
                    .expect("the complete record still decrypts");
                let expected_plaintext: &[u8] = if record.generation == Generation::new(1) {
                    b"qualification"
                } else {
                    b"qualification-update"
                };
                assert_eq!(plaintext.as_slice(), expected_plaintext);
                count += 1;
            }
            if page.complete {
                assert!(page.next_cursor.is_none());
                break;
            }
            assert!(page.next_cursor.is_some());
            assert_ne!(page.next_cursor, request.cursor);
            request.cursor = page.next_cursor;
        }
        assert_eq!(count, expected.len());
        assert!(unseen.is_empty());
    }
}

async fn assert_compacted_watch(stores: &[ConsensusSessionStore]) {
    for store in stores {
        assert!(matches!(
            store.get_replication_log(0, 1).await,
            Err(StoreError::ReplicationLogCursorCompacted { .. })
        ));
        assert!(
            matches!(
                store.watch(0).await,
                Err(StoreError::ReplicationLogCursorCompacted { .. })
            ),
            "watch registration must refuse a cursor below the retained floor"
        );
    }
}

async fn round_trip(mode: SessionPersistenceMode) {
    let directory = tempfile::tempdir().unwrap();
    let snapshots = tempfile::tempdir().unwrap();
    let clock = Arc::new(MutableClock::new(Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap(),
    )));
    let (stores, _, _, peers) = fixed_cluster_with_snapshot_integrity_and_persistence(
        directory.path(),
        snapshots.path(),
        clock.clone(),
        SnapshotIntegrityPolicy::PortableVerified,
        mode,
    )
    .await;
    let leader = admitted_leader(&stores).await;
    let provider = sealing_provider();
    let mut expected = ExpectedRecords::new();
    let mut latest = Vec::new();
    write_range(
        &stores[leader],
        0,
        RETAINED_NOTIFICATIONS,
        &provider,
        &mut expected,
        &mut latest,
    )
    .await;
    for store in &stores {
        wait_for_notifications(store, RETAINED_NOTIFICATIONS as u64).await;
        snapshot(store).await;
    }
    // Drive the normal snapshot-covered log retirement before installing a
    // later image. The complete notification window, records and receipts stay
    // intact; the follower need not revalidate already-covered command bodies.
    for store in &stores {
        purge_verified_snapshot(store).await;
    }
    write_range(
        &stores[leader],
        RETAINED_NOTIFICATIONS,
        RETAINED_NOTIFICATIONS + 1,
        &provider,
        &mut expected,
        &mut latest,
    )
    .await;
    for store in &stores {
        wait_for_notifications(store, (RETAINED_NOTIFICATIONS + 1) as u64).await;
        snapshot(store).await;
    }
    assert_compacted_watch(&stores).await;

    let lagging = (leader + 1) % VOTERS;
    let lagging_node = stores[lagging].status().node_id;
    for peer in &peers {
        if peer.source_index == lagging || peer.node_id == lagging_node {
            peer.clear().await;
        }
    }
    write_range(
        &stores[leader],
        RETAINED_NOTIFICATIONS + 1,
        RETAINED_NOTIFICATIONS + 2,
        &provider,
        &mut expected,
        &mut latest,
    )
    .await;
    for (index, store) in stores.iter().enumerate() {
        if index != lagging {
            wait_for_notifications(store, (RETAINED_NOTIFICATIONS + 2) as u64).await;
            snapshot(store).await;
        }
    }
    let purged = stores
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != lagging)
        .map(|(_, store)| {
            consensus_local_durable_progress_for_test(store)
                .snapshot_index
                .unwrap()
        })
        .min()
        .unwrap();
    for (index, store) in stores.iter().enumerate() {
        if index == lagging {
            continue;
        }
        trigger_consensus_log_purge_through_for_test(store, purged)
            .await
            .expect("purge only through the verified snapshot");
        tokio::time::timeout(Duration::from_secs(30), async {
            while consensus_local_durable_progress_for_test(store).purged_index < Some(purged) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the source purges the missing follower log before healing");
    }
    for peer in &peers {
        let target = stores
            .iter()
            .position(|store| store.status().node_id == peer.node_id)
            .unwrap();
        peer.install(stores[target].rpc_handler()).await;
    }
    eprintln!("retained_snapshot_phase=wait_follower_install");
    let installation = tokio::time::timeout(Duration::from_secs(150), async {
        while consensus_local_durable_progress_for_test(&stores[lagging]).snapshot_index
            < Some(purged)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if installation.is_err() {
        for (index, store) in stores.iter().enumerate() {
            eprintln!("retained_snapshot_install_observation voter={index} required={purged} progress={:?} costs={:?}",
                consensus_local_durable_progress_for_test(store),
                opc_session_store::test_support::consensus_local_wal_costs_for_test(store));
        }
        // Join owned engines before temporary directories disappear. Diagnostic
        // teardown must not obscure the original wait failure with unlinks.
        for peer in &peers {
            peer.clear().await;
        }
        for store in &stores {
            eprintln!(
                "retained_snapshot_failed_wait_shutdown={:?}",
                store.shutdown().await
            );
        }
    }
    installation.expect("the follower installs the retained snapshot through real Raft RPC");
    let (native, origin) =
        consensus_native_snapshot_install_origin_for_test(&stores[lagging]).unwrap();
    assert!(native);
    assert!(
        origin.is_some(),
        "the follower retains the authenticated installation origin"
    );
    for store in &stores {
        wait_for_notifications(store, (RETAINED_NOTIFICATIONS + 2) as u64).await;
        snapshot(store).await;
    }
    audit_all_records(&stores, &expected, &provider).await;
    audit_retained_notifications(&stores, 3, (RETAINED_NOTIFICATIONS + 2) as u64).await;
    assert_compacted_watch(&stores).await;
    if mode == SessionPersistenceMode::Async {
        futures_util::future::join_all(peers.iter().map(|peer| peer.clear())).await;
        for result in futures_util::future::join_all(
            stores
                .iter()
                .map(shutdown_consensus_without_close_proof_for_test),
        )
        .await
        {
            result.expect("join the asynchronous owners without a completed-close proof");
        }
    } else {
        shutdown_fixed_cluster(&stores, &peers).await;
    }
    drop(peers);
    drop(stores);

    let (reopened, _, _, peers) = open_fixed_cluster_with_snapshot_integrity_and_persistence(
        directory.path(),
        snapshots.path(),
        clock,
        SnapshotIntegrityPolicy::PortableVerified,
        mode,
    )
    .await;
    let recovery = std::panic::AssertUnwindSafe(async {
        if mode == SessionPersistenceMode::Async {
            for store in &reopened {
                assert_eq!(
                    store.persistence_health().recovery,
                    Some(SessionAsyncRecoveryState::AwaitingLiveQuorum),
                    "an uncertified cold incarnation must obtain real recovery authority"
                );
            }
        }
        initialize_after_cold_restart(&reopened, mode).await;
        let leader = admitted_leader(&reopened).await;
        audit_all_records(&reopened, &expected, &provider).await;
        assert_compacted_watch(&reopened).await;
        for store in &reopened {
            snapshot(store).await;
        }
        let before = reopened[leader].max_replication_sequence().await.unwrap();
        if mode == SessionPersistenceMode::Async {
            assert!(
                before > (RETAINED_NOTIFICATIONS + 2) as u64,
                "cold async recovery uses outward reservation sequences"
            );
        } else {
            assert_eq!(before, (RETAINED_NOTIFICATIONS + 2) as u64);
        }
        let next_key = key(RETAINED_NOTIFICATIONS + 2);
        let observation = reopened[leader]
            .observe_fenced_transition(&next_key)
            .await
            .unwrap();
        let history = reopened[leader]
            .fenced_transition_v2_history_state()
            .await
            .unwrap();
        let request = create_request(
            RETAINED_NOTIFICATIONS + 2,
            history.active_epoch().unwrap(),
            next_key,
            observation.current_fence(),
            &provider,
        )
        .await;
        let FencedTransitionV2Effect::Resolved(Ok(outcomes)) = reopened[leader]
            .fenced_transition_v2_batch_effect(vec![request.clone()])
            .await
        else {
            panic!("a new create after recovery must resolve");
        };
        assert_eq!(outcomes.len(), 1);
        assert_exact_qualified_v2_success(&request, outcomes[0].as_ref().unwrap());
        let FencedTransitionMutation::Create { record } = request.mutation() else {
            panic!("the fixture submits a create");
        };
        assert!(expected
            .insert(
                serde_json::to_vec(&record.key).unwrap(),
                Sha256::digest(serde_json::to_vec(record).unwrap()).into()
            )
            .is_none());
        for store in &reopened {
            wait_for_notifications(store, before + 1).await;
            let tail = store.get_replication_log(before + 1, 1).await.unwrap();
            assert_eq!(tail.len(), 1);
            assert_eq!(
                tail[0].sequence,
                before + 1,
                "translate the physical suffix into the recovered outward sequence space"
            );
            let mut watcher = store.watch(before + 1).await.unwrap();
            let entry = tokio::time::timeout(Duration::from_secs(5), watcher.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(entry.sequence, before + 1);
            drop(watcher);
            snapshot(store).await;
        }
        audit_all_records(&reopened, &expected, &provider).await;
    })
    .catch_unwind()
    .await;
    if recovery.is_ok() {
        shutdown_fixed_cluster(&reopened, &peers).await;
    } else {
        futures_util::future::join_all(peers.iter().map(|peer| peer.clear())).await;
        for result in futures_util::future::join_all(
            reopened
                .iter()
                .map(shutdown_consensus_without_close_proof_for_test),
        )
        .await
        {
            eprintln!("retained_snapshot_failed_recovery_shutdown={result:?}");
        }
    }
    recovery.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_retained_notification_snapshot_boundary_round_trip() {
    round_trip(SessionPersistenceMode::Durable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_retained_notification_snapshot_boundary_round_trip() {
    round_trip(SessionPersistenceMode::Async).await;
}
