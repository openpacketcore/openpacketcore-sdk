//! Snapshot installation must carry an audited successor absent on the recipient.

use super::*;
use opc_persist::{ConfigHistoryLimits, ConfigHistoryRetention};

struct Expected {
    record: CommitRecord,
    aad: EnvelopeAad,
    plaintext: Vec<u8>,
    original_handle: Vec<u8>,
}

fn ledger_digest(database: &Path) -> [u8; 32] {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only retained audited state");
    let (state, mac): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("complete authenticated ledger row");
    let mut digest = Sha256::new();
    digest.update((state.len() as u64).to_be_bytes());
    digest.update(state);
    digest.update(mac);
    digest.finalize().into()
}

async fn commit_audited(
    store: &ConsensusConfigStore,
    version: u64,
    parent: Option<TxId>,
    principal: &str,
    local: bool,
    completion_stores: Option<(&[ConsensusConfigStore], opc_consensus::ConsensusNodeId)>,
) -> Expected {
    let mut phase = phase_trace::Span::api("audited_input");
    let (input, aad, plaintext) = phase
        .track(input(store, version, parent, principal, 0))
        .await;
    phase.returned(phase_trace::ResultClass::Ok);
    let record = input.record().clone();
    let mut phase = phase_trace::Span::api("audited_prepare");
    let prepared = store
        .prepare_audited_commit(
            &privacy(),
            &event(version, principal),
            input,
            Duration::from_secs(60),
        )
        .expect("joint-maximum audited snapshot input");
    phase.returned(phase_trace::ResultClass::Ok);
    let mut phase = phase_trace::Span::api("audited_handle_roundtrip");
    let original_handle = prepared
        .handle()
        .encode()
        .expect("original handle encoding");
    let handle = AuditOperationHandle::decode(&original_handle).expect("original handle only");
    phase.returned(phase_trace::ResultClass::Ok);
    let mut phase = phase_trace::Span::api("audited_admit");
    let admission = phase
        .track(async {
            if local {
                store
                    .admit_audit_operation_local(&handle, caller(principal))
                    .await
            } else {
                store
                    .admit_audit_operation(&handle, caller(principal))
                    .await
            }
        })
        .await;
    phase.returned(phase_trace::audit(&admission));
    let AuditAdmission::Applied(admission) = admission else {
        panic!("snapshot operation requires an authoritative intent receipt");
    };
    assert_eq!(admission.state(), AuditOperationState::Intent);
    let completion = completion_stores.map(|(stores, leader)| {
        let origin = std::time::Instant::now();
        let registrations = stores
            .iter()
            .map(|store| {
                store
                    .observe_capacity_completion_for_test(&prepared, origin)
                    .expect("bounded native completion registration")
            })
            .collect::<Vec<_>>();
        (registrations, leader)
    });
    let mut phase = phase_trace::Span::api("audited_submit");
    let result = phase
        .track(async {
            if local {
                store
                    .submit_audited_mutation_local(&prepared, &admission, caller(principal))
                    .await
            } else {
                store
                    .submit_audited_mutation(&prepared, &admission, caller(principal))
                    .await
            }
        })
        .await;
    phase.returned(phase_trace::audit(&result));
    let completion = completion.map(|(registrations, leader)| {
        let snapshots = registrations
            .into_iter()
            .map(|registration| {
                registration
                    .finish()
                    .expect("matching native completion registration")
            })
            .collect::<Vec<_>>();
        // Deactivate every node before printing; output never runs in a worker.
        for (node, snapshot) in snapshots.iter().enumerate() {
            eprintln!(
                "CONFIG_CAPACITY_NATIVE_COMPLETION node={node} cutoff_us={} events={} omitted={}",
                snapshot.cutoff_us, snapshot.events.len(), snapshot.omitted,
            );
            for event in &snapshot.events {
                eprintln!(
                    "CONFIG_CAPACITY_NATIVE_COMPLETION_EVENT node={node} at_us={} phase={:?} index={:?} deadline_us={:?}",
                    event.at_us, event.phase, event.index, event.deadline_us,
                );
            }
        }
        (snapshots, leader)
    });
    let AuditAdmission::Applied(receipt) = result else {
        panic!("snapshot operation requires a durable original result");
    };
    assert_eq!(receipt.state(), AuditOperationState::Committed { version });
    if let Some((snapshots, leader)) = completion {
        use opc_persist::config_completion_observation::Phase;
        assert!(
            snapshots.iter().all(|snapshot| snapshot.omitted == 0),
            "native completion trace must remain bounded without omission"
        );
        let selected = snapshots
            .iter()
            .find(|snapshot| snapshot.node == leader)
            .expect("native completion trace must bind the original leader");
        let index = selected
            .events
            .iter()
            .find(|event| event.phase == Phase::EngineResponseOk)
            .and_then(|event| event.index)
            .expect("native completion trace must observe the original engine response index");
        for phase in [
            Phase::ApplyQueued,
            Phase::ApplyWorkerEntered,
            Phase::NativeApplyEntered,
            Phase::ApplyTransactionCommitted,
            Phase::NativeApplyReturned,
            Phase::StorageApplyReturned,
        ] {
            assert!(
                selected
                    .events
                    .iter()
                    .any(|event| event.phase == phase && event.index == Some(index)),
                "native completion trace omitted matching {phase:?} for original leader/index"
            );
        }
    }
    Expected {
        record,
        aad,
        plaintext,
        original_handle,
    }
}

async fn recover(store: &ConsensusConfigStore, expected: &[Expected], principal: &str) {
    for value in expected {
        let handle = AuditOperationHandle::decode(&value.original_handle)
            .expect("exact caller-retained original handle");
        let result = store
            .lookup_audit_operation(&handle, caller(principal))
            .await
            .expect("authoritative audited snapshot recovery")
            .expect("original operation retained through snapshot installation");
        assert_eq!(
            result.state(),
            AuditOperationState::Committed {
                version: value.record.version.get()
            }
        );
    }
    let records = store
        .load_since(ConfigVersion::INITIAL, 64)
        .await
        .expect("complete installed history lineage");
    assert_eq!(records.len(), expected.len());
    for (record, value) in records.iter().zip(expected) {
        assert_readback(record, &value.record, &value.aad, &value.plaintext);
    }
    let latest = store
        .load_latest()
        .await
        .expect("installed quorum read")
        .expect("installed head");
    let last = expected.last().expect("nonempty original history");
    assert_readback(&latest, &last.record, &last.aad, &last.plaintext);
}

native_case!(
    config_capacity_957_joint_audited_snapshot_installs_missing_result_and_lineage,
    {
        let directory = disk_fixture();
        let pki = Pki::new();
        let manifest = manifest();
        let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
        let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
        let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
        let profile = ConfigCapacityProfile::BoundedV1;
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, false, profile,
        )
        .await;
        let (mut servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        snapshot::ready(&stores).await;
        let leader_id = stores[0]
            .status()
            .leader_id
            .expect("audited snapshot leader");
        let leader = stores
            .iter()
            .position(|store| store.status().node_id == leader_id)
            .expect("audited snapshot leader belongs to fixture");
        let follower = (leader + 1) % 3;
        let lagging = (leader + 2) % 3;
        let principal = principal(true);
        let trace = phase_trace::Session::start("audited_snapshot_control", &stores);
        let mut phase = phase_trace::Span::api("audit_authority_initialize");
        let initialized = phase
            .track(stores[leader].initialize_audit_authority(
                &privacy(),
                AuditLedgerLimits::new(12, 4).expect("original finite audit limits"),
            ))
            .await;
        phase.returned(phase_trace::audit_initialization(&initialized));
        initialized.expect("native replicated audit authority");
        let first = commit_audited(
            &stores[leader],
            1,
            None,
            &principal,
            true,
            Some((&stores, leader_id)),
        )
        .await;
        for store in &stores {
            let mut phase = phase_trace::Span::api("audited_initial_recovery_readback");
            phase
                .track(recover(store, std::slice::from_ref(&first), &principal))
                .await;
            phase.returned(phase_trace::ResultClass::Ok);
        }
        trace.finish();
        let original_ledger = databases.each_ref().map(|path| ledger_digest(path));
        assert!(original_ledger
            .iter()
            .all(|digest| *digest == original_ledger[leader]));
        assert!(snapshot::current_snapshot(&databases[lagging]).is_none());

        // The recipient has neither the second intent nor its commit/lineage.
        servers[lagging]
            .take()
            .expect("lagging authenticated listener")
            .abort_and_wait()
            .await;
        stores[lagging]
            .shutdown()
            .await
            .expect("stop original lagging authority");
        *addresses[lagging].write().expect("retire offline endpoint") = None;
        let lagging_index = stores[lagging]
            .status()
            .applied_index
            .expect("offline applied frontier");
        let offline_counts = effect_counts(&databases[lagging]);
        let trace = phase_trace::Session::start("audited_snapshot_forwarded_successor", &stores);
        let second = commit_audited(
            &stores[follower],
            2,
            Some(first.record.tx_id),
            &principal,
            false,
            None,
        )
        .await;
        trace.finish();
        let expected = [first, second];
        for index in [leader, follower] {
            recover(&stores[index], &expected, &principal).await;
        }
        assert_eq!(effect_counts(&databases[lagging]), offline_counts);
        assert_eq!(ledger_digest(&databases[lagging]), original_ledger[lagging]);
        let complete_ledger = ledger_digest(&databases[leader]);
        assert_ne!(complete_ledger, original_ledger[lagging]);
        assert_eq!(faults[follower].actual_forwards.load(Ordering::SeqCst), 2);

        let retention = ConfigHistoryRetention::new(
            expected[1].record.tx_id,
            ConfigVersion::new(2),
            ConfigVersion::new(1),
            ConfigVersion::new(1),
            ConfigHistoryLimits::new(2, 16 * 1024 * 1024)
                .expect("finite two-record snapshot history"),
        )
        .expect("acknowledged no-pruning history decision");
        let engine = opc_consensus::durable_openraft_config(
            opc_consensus::DurableOpenraftDomain::ConfigurationState,
        )
        .expect("original production compaction profile");
        let advance = engine.max_in_snapshot_log_to_keep + engine.purge_batch_size + 16;
        assert!(advance < 4096 - 8);
        for _ in 0..advance {
            stores[leader]
                .retain_history_idempotent(
                    ConfigConsensusRequestId::from_bytes([0xED; 16]),
                    retention.clone(),
                )
                .await
                .expect("same acknowledged decision advances real native log");
        }
        for index in [leader, follower] {
            stores[index]
                .probe_durable_readiness()
                .await
                .expect("snapshot source applied frontier");
            stores[index]
                .trigger_snapshot()
                .await
                .expect("native snapshot trigger");
        }
        tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                if [leader, follower]
                    .iter()
                    .all(|index| snapshot::purged_beyond(&databases[*index], lagging_index))
                {
                    break;
                }
                stores[leader]
                    .probe_durable_readiness()
                    .await
                    .expect("original event-driven compaction readiness");
            }
        })
        .await
        .expect("original compaction deadline");
        assert_eq!(effect_counts(&databases[lagging]), offline_counts);
        assert_eq!(ledger_digest(&databases[lagging]), original_ledger[lagging]);
        assert!(snapshot::current_snapshot(&databases[lagging]).is_none());
        let retained_counts = snapshot::authority_counts(&databases);
        let retained_ledgers = databases.each_ref().map(|path| ledger_digest(path));
        snapshot::stop(stores, servers, released, &addresses).await;

        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, true, profile,
        )
        .await;
        assert_eq!(snapshot::authority_counts(&databases), retained_counts);
        assert_eq!(
            databases.each_ref().map(|path| ledger_digest(path)),
            retained_ledgers
        );
        assert!(snapshot::current_snapshot(&databases[lagging]).is_none());
        for fault in &faults {
            fault.snapshots[lagging]
                .enabled
                .store(true, Ordering::SeqCst);
        }
        let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        snapshot::ready(&stores).await;
        for store in &stores {
            recover(store, &expected, &principal).await;
        }
        let (snapshot_id, bytes) = snapshot::current_snapshot(&databases[lagging])
            .expect("original lagging authority installed real snapshot");
        assert!(bytes > (2 * BOUNDED_LOGICAL_BYTES) as u64);
        let chunks = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                if let Some(chunks) = faults
                    .iter()
                    .find_map(|fault| fault.snapshots[lagging].complete(snapshot_id, bytes))
                {
                    break chunks;
                }
                stores[lagging]
                    .probe_durable_readiness()
                    .await
                    .expect("recipient applied through final chunk acknowledgement");
            }
        })
        .await
        .expect("original acknowledged-chunk deadline");
        assert!(databases
            .iter()
            .all(|path| ledger_digest(path) == complete_ledger));
        let installed_counts = snapshot::authority_counts(&databases);
        assert!(installed_counts
            .iter()
            .all(|value| *value == retained_counts[leader]));
        snapshot::stop(stores, servers, released, &addresses).await;

        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, true, profile,
        )
        .await;
        assert_eq!(snapshot::authority_counts(&databases), installed_counts);
        assert!(databases
            .iter()
            .all(|path| ledger_digest(path) == complete_ledger));
        assert!(snapshot::current_snapshot(&databases[lagging]) == Some((snapshot_id, bytes)));
        let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        snapshot::ready(&stores).await;
        let before = databases.each_ref().map(|path| effect_counts(path));
        for store in &stores {
            recover(store, &expected, &principal).await;
        }
        assert_eq!(databases.each_ref().map(|path| effect_counts(path)), before);
        assert!(databases
            .iter()
            .all(|path| ledger_digest(path) == complete_ledger));
        assert_eq!(
            faults
                .iter()
                .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
                .sum::<usize>(),
            2
        );
        snapshot::stop(stores, servers, released, &addresses).await;
        println!("CONFIG_CAPACITY_AUDITED_SNAPSHOT logical=1572864 replay=65536 aad=65536 key_id=512 audit_paths=21 chunks={chunks} installed_bytes={bytes} missing_before=true lineage=true original_handle=true original_paths=true mtls=true native_wal=true resubmitted=false");
    }
);
