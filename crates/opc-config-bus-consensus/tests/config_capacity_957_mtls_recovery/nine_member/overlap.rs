//! Partial owner census on real nine-voter audited replication and snapshot IO.
//! Includes selected native command/ledger owners; no complete 32/256 MiB bound is claimed.

use super::super::joint_metadata as joint;
use super::*;
use opc_persist::audit_authority::{AuditAdmission, AuditLedgerLimits, AuditOperationState};
use opc_persist::config_capacity_observation::{
    NativeOwnerObserver, NativeOwnerSample, NativeRegistration, NativeStage, PreparationCensus,
};
use opc_persist::{ConfigHistoryLimits, ConfigHistoryRetention};
use opc_session_net::consensus::capacity_observation::NativeTransportOverlap;

#[derive(Debug, Default)]
struct NativeResults {
    decoded: Option<NativeOwnerSample>,
    validated: Option<NativeOwnerSample>,
    mutation: Option<(NativeOwnerSample, Option<NativeTransportOverlap>)>,
    written: Option<NativeOwnerSample>,
    counts: [usize; 4],
}

// Owns only counter snapshots and transport controls; never the observed
// preparations, native command, ledger, request, frame or database.
struct NativeBridge {
    transport: Arc<ConsensusBufferObservation>,
    results: std::sync::Mutex<NativeResults>,
}

impl NativeOwnerObserver for NativeBridge {
    fn observe(&self, sample: NativeOwnerSample) {
        let overlap = (sample.stage == NativeStage::AuthenticatedMutation).then(|| {
            self.transport
                .capture_native_overlap_and_release(sample.source)
        });
        let mut results = self.results.lock().unwrap();
        match sample.stage {
            NativeStage::DecodedLedger => {
                results.counts[0] += 1;
                results.decoded = Some(sample);
            }
            NativeStage::ValidatedLedger => {
                results.counts[3] += 1;
                results.validated = Some(sample);
            }
            NativeStage::AuthenticatedMutation => {
                results.counts[1] += 1;
                results.mutation = Some((sample, overlap.flatten()));
            }
            NativeStage::LedgerWrite => {
                results.counts[2] += 1;
                results.written = Some(sample);
            }
        }
    }
}
use opc_session_net::consensus::capacity_observation::ConsensusBufferObservation;
use opc_session_net::SessionConsensusServerHandle;

type Released = tokio::sync::oneshot::Receiver<()>;

async fn listen_one(
    stores: &[ConsensusConfigStore],
    member: usize,
    pki: &Pki,
    manifest: &Arc<SessionReplicationManifest>,
    addresses: &[Arc<RwLock<Option<SocketAddr>>>; MEMBERS],
) -> (SessionConsensusServerHandle, Released) {
    let (handler, released) = observed_handler(&stores[member]);
    let (server, address) = SessionConsensusServer::new(
        handler,
        pki.server(member),
        manifest
            .bind_local(replica_id(member))
            .expect("original nine-voter binding"),
    )
    .listen("127.0.0.1:0".parse().unwrap())
    .await
    .expect("real authenticated listener");
    *addresses[member].write().unwrap() = Some(address);
    (server, released)
}

async fn ready(stores: &[ConsensusConfigStore], pending_snapshot: Option<usize>, phase: &str) {
    println!("CONFIG_CAPACITY_NINE_OVERLAP_PHASE phase={phase} stage=initialization_begin");
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        // Re-admit every original voter through real all-peer compatibility.
        // A pending snapshot excludes only that node's quorum readiness probe.
        for (member, result) in join_all(stores.iter().map(|store| store.initialize_cluster()))
            .await
            .into_iter()
            .enumerate()
        {
            result.unwrap_or_else(|error| {
                panic!("original nine-voter initialization phase={phase} member={member}: {error:?}")
            });
            assert!(
                stores[member].status().admitted,
                "original voter admitted phase={phase} member={member}"
            );
        }
        println!("CONFIG_CAPACITY_NINE_OVERLAP_PHASE phase={phase} stage=initialization_complete members=9");
        println!("CONFIG_CAPACITY_NINE_OVERLAP_PHASE phase={phase} stage=readiness_begin pending_snapshot={pending_snapshot:?}");
        for (member, result) in join_all(
            stores
                .iter()
                .enumerate()
                .filter(|(member, _)| Some(*member) != pending_snapshot)
                .map(|(member, store)| async move { (member, store.probe_durable_readiness().await) }),
        )
        .await
        {
            result.unwrap_or_else(|error| {
                panic!("original nine-voter readiness phase={phase} member={member}: {error:?}")
            });
        }
    })
    .await
    .unwrap_or_else(|_| panic!("readiness phase={phase} inside unchanged operation budget"));
    println!("CONFIG_CAPACITY_NINE_OVERLAP_PHASE phase={phase} stage=readiness_complete");
}

// A deferred snapshot suppresses the target's ordinary replication heartbeat.
// Use finite preparation boundaries to ask the native engine for read-index
// heartbeats; the actual lagging reply, not another quorum's result, is required.
async fn snapshot_vote_checkpoint(
    stores: &[ConsensusConfigStore],
    transfers: &[Arc<Transfers>; MEMBERS],
    source: usize,
    target: usize,
    previous: Option<snapshot::VoteAgreement>,
    force: bool,
) -> Option<snapshot::VoteAgreement> {
    let now = tokio::time::Instant::now();
    let refresh_after =
        DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(ConsensusRpcFamily::AppendEntries);
    let deadline =
        previous.map_or(now, |agreement| agreement.started) + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
    // The pinned engine's committed-vote timer includes the leader lease
    // (election max) plus its sampled election timeout (at least election min).
    const {
        assert!(
            DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis
                < DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis
                    + DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_min_millis
        );
    }
    assert!(
        now < deadline,
        "native vote setup budget expired; never refresh a stale witness"
    );
    if !force
        && previous.is_some_and(|agreement| now.duration_since(agreement.started) < refresh_after)
    {
        return previous;
    }
    let probe = &transfers[source].vote_probes[target];
    let completion = probe.arm();
    let result = tokio::time::timeout_at(deadline, async {
        tokio::join!(stores[source].ensure_local_authority(), completion)
    })
    .await;
    probe.disarm();
    let (authority, agreement) =
        result.expect("one native setup barrier inside the existing operation budget");
    let agreement = agreement.expect("the exact observed native heartbeat returned, not cancelled");
    let source_status = stores[source].status();
    let target_status = stores[target].status();
    println!("CONFIG_CAPACITY_SNAPSHOT_VOTE_CHECKPOINT force={force} source={:?} target={:?} vote={:?} accepted={} reason={} higher={:?} elapsed_ms={} local_authority={authority:?} source_term={} target_term={} target_leader={:?}",
        source_status.node_id, target_status.node_id, agreement.vote, agreement.accepted, agreement.reason,
        agreement.higher, agreement.started.elapsed().as_millis(), source_status.term,
        target_status.term, target_status.leader_id);
    assert!(
        tokio::time::Instant::now() < deadline,
        "native vote setup barrier stays inside the prior proof budget"
    );
    assert_eq!(
        authority,
        opc_persist::ConfigLocalAuthorityOutcome::LocalAuthority,
        "native setup source lost authority; no fixture retry"
    );
    assert!(
        agreement.accepted,
        "lagging native vote rejected; no selected snapshot has been armed"
    );
    assert_eq!(
        agreement.vote,
        opc_consensus::engine::Vote::new_committed(source_status.term, source_status.node_id)
    );
    assert_eq!(target_status.term, source_status.term);
    assert_eq!(target_status.leader_id, Some(source_status.node_id));
    assert!(source_status.admitted && target_status.admitted);
    assert!(
        agreement.started.elapsed() < refresh_after,
        "native agreement must still be fresh when the setup barrier returns"
    );
    Some(agreement)
}

async fn preparation_before_vote_expiry<T>(
    agreement: Option<snapshot::VoteAgreement>,
    prepare: impl std::future::Future<Output = T>,
) -> T {
    match agreement {
        Some(agreement) => tokio::time::timeout_at(
            agreement.started + DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            prepare,
        )
        .await
        .expect("preparation stays within the accepted native vote setup budget"),
        None => prepare.await,
    }
}

async fn stop(
    native_registration: Option<&NativeRegistration>,
    stores: Vec<ConsensusConfigStore>,
    servers: Vec<Option<SessionConsensusServerHandle>>,
    released: Vec<Released>,
    addresses: &[Arc<RwLock<Option<SocketAddr>>>; MEMBERS],
) {
    for (store, server) in stores.iter().zip(servers) {
        if let Some(server) = server {
            server.abort_and_wait().await;
            store
                .shutdown()
                .await
                .expect("stop original native authority");
        }
    }
    all_handlers_released(released).await;
    if let Some(registration) = native_registration {
        // All real native/peer tasks have joined, while the original backend
        // connection still exists. Conditional detach cannot remove a successor.
        registration.detach();
    }
    drop(stores);
    for address in addresses {
        *address.write().unwrap() = None;
    }
}

native_case!(
    config_capacity_957_nine_audited_snapshot_frame_owner_overlap,
    {
        let directory = disk_fixture();
        let databases: [_; MEMBERS] =
            std::array::from_fn(|member| directory.join(format!("config-{member}.sqlite")));
        let pki = Pki::new();
        let manifest = nine_manifest();
        let addresses = std::array::from_fn(|_| Arc::new(RwLock::new(None)));
        let transfers: [_; MEMBERS] = std::array::from_fn(|_| Arc::new(Transfers::default()));
        let observation = Arc::new(ConsensusBufferObservation::default());
        let stores = open_nine(
            &directory,
            &manifest,
            &pki,
            &addresses,
            &transfers,
            false,
            Some(&observation),
        )
        .await;
        let mut servers = Vec::new();
        let mut released = Vec::new();
        for member in 0..MEMBERS {
            let (server, receipt) = listen_one(&stores, member, &pki, &manifest, &addresses).await;
            servers.push(Some(server));
            released.push(receipt);
        }
        ready(&stores, None, "initial").await;
        let first_leader = stores
            .iter()
            .position(|store| Some(store.status().node_id) == stores[0].status().leader_id)
            .unwrap();
        let (control, control_aad, control_plaintext) =
            commit(&stores[first_leader], 1, None).await;
        let control_record = control.record().clone();
        let prepared = stores[first_leader]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0x94; 16]),
                control,
                CALLER,
            )
            .unwrap();
        stores[first_leader]
            .append_prepared_commit_local(prepared)
            .await
            .unwrap();
        read_all(&stores, &control_record, &control_aad, &control_plaintext).await;
        // Retention requires both a head and predecessor. Keep both genuine records
        // and one record of headroom for the single later audited mutation.
        let (control, control_aad, control_plaintext) =
            commit(&stores[first_leader], 2, Some(control_record.tx_id)).await;
        let control_record = control.record().clone();
        let prepared = stores[first_leader]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0x97; 16]),
                control,
                CALLER,
            )
            .unwrap();
        stores[first_leader]
            .append_prepared_commit_local(prepared)
            .await
            .unwrap();
        read_all(&stores, &control_record, &control_aad, &control_plaintext).await;
        // Establish the two ordinary seed records before mandatory audit is
        // activated. Every subsequent configuration mutation is audited.
        stores[first_leader]
            .initialize_audit_authority(&joint::privacy(), AuditLedgerLimits::new(12, 4).unwrap())
            .await
            .expect("original native audit authority");
        let lagging = (first_leader + 1) % MEMBERS;
        // Freeze an applied audit-authority prefix, not a follower's pending
        // tail that could legitimately finish applying during reopen.
        stores[lagging]
            .probe_durable_readiness()
            .await
            .expect("lagging member applies audit activation before isolation");
        servers[lagging].take().unwrap().abort_and_wait().await;
        stores[lagging].shutdown().await.unwrap();
        *addresses[lagging].write().unwrap() = None;
        let lagging_index = stores[lagging].status().applied_index.unwrap();
        let offline_counts = effect_counts(&databases[lagging]);
        let retention = ConfigHistoryRetention::new(
            control_record.tx_id,
            ConfigVersion::new(2),
            ConfigVersion::new(1),
            ConfigVersion::new(1),
            ConfigHistoryLimits::new(3, 16 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let profile = opc_consensus::durable_openraft_config(
            opc_consensus::DurableOpenraftDomain::ConfigurationState,
        )
        .expect("unchanged production snapshot profile");
        let advance = profile.max_in_snapshot_log_to_keep + profile.purge_batch_size + 16;
        assert!(advance < 4096 - 8);
        for _ in 0..advance {
            stores[first_leader]
                .retain_history_idempotent(
                    ConfigConsensusRequestId::from_bytes([0x95; 16]),
                    retention.clone(),
                )
                .await
                .expect("real unchanged native compaction prefix");
        }
        for (member, store) in stores.iter().enumerate() {
            if member != lagging {
                store.probe_durable_readiness().await.unwrap();
                store.trigger_snapshot().await.unwrap();
            }
        }
        tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                if (0..MEMBERS)
                    .filter(|member| *member != lagging)
                    .all(|member| snapshot::purged_beyond(&databases[member], lagging_index))
                {
                    break;
                }
                stores[first_leader]
                    .probe_durable_readiness()
                    .await
                    .unwrap();
            }
        })
        .await
        .expect("production compaction finishes under original guard");
        assert_eq!(effect_counts(&databases[lagging]), offline_counts);
        assert!(snapshot::current_snapshot(&databases[lagging]).is_none());
        stop(None, stores, servers, released, &addresses).await;
        assert_eq!(observation.snapshot().live.calls, 0);

        // Every donor has purged beyond the lagging prefix. Keep the real
        // listener available for compatibility, but defer the snapshot needed
        // to bridge that gap until all genuine preparations are held.
        for transfer in &transfers {
            transfer.defer_snapshots[lagging].store(true, Ordering::SeqCst);
        }
        println!("CONFIG_CAPACITY_NINE_OVERLAP_PHASE phase=reopened stage=snapshot_fault_armed target={lagging}");
        let stores = open_nine(
            &directory,
            &manifest,
            &pki,
            &addresses,
            &transfers,
            true,
            Some(&observation),
        )
        .await;
        let mut servers: Vec<Option<SessionConsensusServerHandle>> =
            (0..MEMBERS).map(|_| None).collect();
        let mut released = Vec::new();
        for (member, slot) in servers.iter_mut().enumerate() {
            let (server, receipt) = listen_one(&stores, member, &pki, &manifest, &addresses).await;
            *slot = Some(server);
            released.push(receipt);
        }
        ready(&stores, Some(lagging), "reopened").await;
        let leader_id = stores
            .iter()
            .enumerate()
            .find(|(member, _)| *member != lagging)
            .unwrap()
            .1
            .status()
            .leader_id
            .unwrap();
        let leader = stores
            .iter()
            .position(|store| store.status().node_id == leader_id)
            .unwrap();
        assert_ne!(leader, lagging);
        let mut setup_vote =
            snapshot_vote_checkpoint(&stores, &transfers, leader, lagging, None, true).await;
        let principal = joint::principal(true);
        let (input, aad, plaintext) = joint::input(
            &stores[leader],
            3,
            Some(control_record.tx_id),
            &principal,
            0,
        )
        .await;
        let expected = input.record().clone();
        let prepared = stores[leader]
            .prepare_audited_commit(
                &joint::privacy(),
                &joint::event(3, &principal),
                input,
                Duration::from_secs(60),
            )
            .expect("real joint-maximum audited preparation");
        let handle_bytes = prepared.handle().encode().unwrap();
        let handle =
            opc_persist::audit_authority::AuditOperationHandle::decode(&handle_bytes).unwrap();
        // Admit before saturating: the fixture must not deadlock its own control admission.
        let AuditAdmission::Applied(admission) = stores[leader]
            .admit_audit_operation_local(&handle, joint::caller(&principal))
            .await
        else {
            panic!("original native Intent receipt");
        };
        assert_eq!(admission.state(), AuditOperationState::Intent);
        let admitted_at = std::time::Instant::now();
        let prepared_alias = prepared.clone();
        let recovery = prepared
            .encode()
            .expect("original SDK recovery encoding remains owned");
        let mut held: Vec<Vec<PreparedConfigCommitOperation>> =
            (0..MEMBERS).map(|_| Vec::new()).collect();
        setup_vote =
            snapshot_vote_checkpoint(&stores, &transfers, leader, lagging, setup_vote, true).await;
        for (member, store) in stores.iter().enumerate() {
            let count = PREPARATIONS - usize::from(member == leader);
            for slot in 0..count {
                let (value, _, _) = preparation_before_vote_expiry(
                    setup_vote,
                    commit(store, 3, Some(control_record.tx_id)),
                )
                .await;
                let mut id = [0x96; 16];
                id[0] = member as u8;
                id[1] = slot as u8;
                held[member].push(
                    store
                        .prepare_recoverable_commit(
                            ConfigConsensusRequestId::from_bytes(id),
                            value,
                            CALLER,
                        )
                        .expect("genuine held encrypted preparation"),
                );
                setup_vote = snapshot_vote_checkpoint(
                    &stores, &transfers, leader, lagging, setup_vote, false,
                )
                .await;
            }
            assert_exhausted(store);
        }
        // Traverse the actual normalized preparations once. The guards borrow
        // immutable owners; the two audited aliases share the same allocations.
        let census = Arc::new(PreparationCensus::default());
        let mut preparation_owners = Vec::new();
        for (member, operations) in held.iter().enumerate() {
            for operation in operations {
                preparation_owners
                    .extend(census.observe_commit(stores[member].status().node_id, operation));
            }
        }
        preparation_owners.extend(census.observe_audited(leader_id, &prepared));
        preparation_owners.extend(census.observe_audited(leader_id, &prepared_alias));
        let native_bridge = Arc::new(NativeBridge {
            transport: observation.clone(),
            results: std::sync::Mutex::new(NativeResults::default()),
        });
        // Deterministically suspend an actual snapshot whose adapter context
        // predates registration. Its original request stays in its real future.
        setup_vote =
            snapshot_vote_checkpoint(&stores, &transfers, leader, lagging, setup_vote, true).await;
        let vote_at_arm = (stores[leader].status(), stores[lagging].status());
        let paused_snapshot = &transfers[leader].snapshot_pauses[lagging];
        paused_snapshot.arm();
        tokio::time::timeout(
            DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            paused_snapshot.wait_entered(),
        )
        .await
        .expect("real pre-registration snapshot reaches the scheduling barrier");
        let native_registration = stores[leader]
            .observe_capacity_native_owners_for_test(
                &prepared,
                census.clone(),
                native_bridge.clone(),
            )
            .await
            .expect("attach exact native connection and selected request");
        let before_ninth = authority_states(&databases);
        for store in &stores {
            assert_exhausted(store);
        }
        assert_authority_unchanged(&before_ninth, &authority_states(&databases));
        let before_append: [_; MEMBERS] = std::array::from_fn(|target| {
            transfers[leader].large_append_success[target].load(Ordering::SeqCst)
        });
        assert_eq!(stores[lagging].status().applied_index, Some(lagging_index));
        assert_eq!(effect_counts(&databases[lagging]), offline_counts);
        assert!(snapshot::current_snapshot(&databases[lagging]).is_none());
        assert!(stores.iter().all(|store| store.status().admitted));
        let lagging_id = stores[lagging].status().node_id;
        observation.hold_snapshot_writes(lagging_id);
        let minority = (0..MEMBERS)
            .find(|member| *member != leader && *member != lagging)
            .unwrap();
        let minority_id = stores[minority].status().node_id;
        observation.hold_native_append_writes(leader_id, minority_id);
        for transfer in &transfers {
            transfer.snapshots[lagging]
                .enabled
                .store(true, Ordering::SeqCst);
        }
        // Retire the setup fault before the real frame enters its original
        // bounded write deadline; it must not affect the measured operation.
        for transfer in &transfers {
            transfer.defer_snapshots[lagging].store(false, Ordering::SeqCst);
        }
        assert!(transfers.iter().all(|transfer| transfer
            .defer_snapshots
            .iter()
            .all(|deferred| !deferred.load(Ordering::SeqCst))));
        let deferred_requests: usize = transfers
            .iter()
            .map(|transfer| transfer.deferred_snapshot_attempts[lagging].load(Ordering::SeqCst))
            .sum();
        println!("CONFIG_CAPACITY_NINE_OVERLAP_PHASE phase=overlap stage=snapshot_fault_released deferred_requests={deferred_requests}");
        paused_snapshot.resume();
        let old_snapshot_progress = tokio::time::timeout(
            DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            paused_snapshot.wait_completed(),
        )
        .await;
        if old_snapshot_progress.is_err() {
            observation.release_snapshot_writes();
        }
        old_snapshot_progress.expect(
            "CONFIG_CAPACITY_UNTYPED_SNAPSHOT_PROGRESS_RED: the exact pre-registration call completes without waiting for a typed pair",
        );
        // This next wait must accept only a current typed call. The old call's
        // success is checked after the complete original lifecycle below.
        tokio::time::timeout(
            DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            observation.wait_for_snapshot_write(lagging_id),
        )
        .await
        .expect("real encoded snapshot chunk reaches bounded write boundary");
        let intent_age_ms = admitted_at.elapsed().as_millis();
        let submission_started = std::time::Instant::now();
        let result = stores[leader]
            .submit_audited_mutation_local(&prepared_alias, &admission, joint::caller(&principal))
            .await;
        let submission_ms = submission_started.elapsed().as_millis();
        let overlap = observation.snapshot().overlap;
        // Release even when the mutation reports an error; do not strand other stores.
        observation.release_snapshot_writes();
        let disposition = match &result {
            AuditAdmission::Applied(_) => "applied",
            AuditAdmission::Rejected(_) => "rejected",
            AuditAdmission::Unknown(_) => "unknown",
        };
        println!("CONFIG_CAPACITY_NINE_OVERLAP_SUBMISSION intent_age_ms={intent_age_ms} submission_ms={submission_ms} disposition={disposition}");
        let receipt = match result {
            AuditAdmission::Applied(receipt) => receipt,
            AuditAdmission::Rejected(error) => panic!(
                "one original audited operation commits during the snapshot transfer: rejected {error:?}"
            ),
            AuditAdmission::Unknown(_) => panic!(
                "one original audited operation commits during the snapshot transfer: unknown"
            ),
        };
        assert_eq!(
            receipt.state(),
            AuditOperationState::Committed { version: 3 }
        );
        for store in &stores {
            let value = store.load_latest().await.unwrap().unwrap();
            joint::assert_readback(&value, &expected, &aad, &plaintext);
            let outcome = store
                .lookup_audit_operation(&handle, joint::caller(&principal))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                outcome.state(),
                AuditOperationState::Committed { version: 3 }
            );
            assert_exhausted(store);
        }
        let (snapshot_id, snapshot_bytes) = snapshot::current_snapshot(&databases[lagging])
            .expect("original lagging store installed a real snapshot");
        let chunks = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                if let Some(chunks) = transfers.iter().find_map(|transfer| {
                    transfer.snapshots[lagging].complete(snapshot_id, snapshot_bytes)
                }) {
                    break chunks;
                }
                stores[lagging].probe_durable_readiness().await.unwrap();
            }
        })
        .await
        .expect("contiguous acknowledged native snapshot chunks");
        assert!(chunks >= 2);
        for (target, before) in before_append.iter().enumerate() {
            if target != leader && target != lagging {
                assert!(
                    transfers[leader].large_append_success[target].load(Ordering::SeqCst) > *before,
                    "real large native append reached each of the seven other targets"
                );
            }
        }
        assert!(!recovery.is_empty());
        let preparations_before_drop = census.snapshot();
        drop(preparation_owners);
        let preparations_after_drop = census.snapshot();
        drop(recovery);
        drop(prepared);
        assert_exhausted(&stores[leader]);
        drop(prepared_alias);
        drop(held);
        for store in &stores {
            let slots: Vec<_> = (0..PREPARATIONS)
                .map(|_| store.try_reserve_config_preparation().unwrap().unwrap())
                .collect();
            assert_exhausted(store);
            drop(slots);
        }
        let committed = databases.each_ref().map(|path| effect_counts(path));
        stop(
            Some(&native_registration),
            stores,
            servers,
            released,
            &addresses,
        )
        .await;
        let native_drain = native_registration.snapshot();
        let native_results = std::mem::take(&mut *native_bridge.results.lock().unwrap());
        drop(native_registration);
        let drained = observation.snapshot();
        assert_eq!(drained.live, Default::default());

        let stores = open_nine(
            &directory,
            &manifest,
            &pki,
            &addresses,
            &transfers,
            true,
            Some(&observation),
        )
        .await;
        let mut servers = Vec::new();
        let mut released = Vec::new();
        for member in 0..MEMBERS {
            let (server, receipt) = listen_one(&stores, member, &pki, &manifest, &addresses).await;
            servers.push(Some(server));
            released.push(receipt);
        }
        ready(&stores, None, "recovery").await;
        for store in &stores {
            let outcome = store
                .lookup_audit_operation(&handle, joint::caller(&principal))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                outcome.state(),
                AuditOperationState::Committed { version: 3 }
            );
            joint::assert_readback(
                &store.load_latest().await.unwrap().unwrap(),
                &expected,
                &aad,
                &plaintext,
            );
        }
        assert_eq!(
            databases.each_ref().map(|path| effect_counts(path)),
            committed,
            "original handle recovery and reopen do not resubmit or mutate effects"
        );
        stop(None, stores, servers, released, &addresses).await;
        assert_eq!(observation.snapshot().live, Default::default());
        for transfer in &transfers {
            assert_eq!(transfer.active.load(Ordering::SeqCst), 0);
            assert_eq!(transfer.active_capacity.load(Ordering::SeqCst), 0);
        }
        // Allocation assertions follow the entire real lifecycle in every control.
        println!("CONFIG_CAPACITY_NINE_OVERLAP_LIFECYCLE members=9 prepared=72 audited_commits=1 append_targets=7 snapshot_chunks={chunks} exact_readback=true original_handle=true original_paths=true drained=true native_wal=true durability=Durable");
        let overlap = overlap.expect(
            "CONFIG_CAPACITY_FRAME_OVERLAP_RED: real append and snapshot frame intersection",
        );
        assert_eq!(overlap.source, leader_id);
        assert_eq!(overlap.snapshot_target, lagging_id);
        assert_ne!(overlap.append_target, lagging_id);
        assert!(overlap.append_rpc_bytes > BOUNDED_LOGICAL_BYTES);
        assert!(overlap.snapshot_rpc_bytes > 1_048_576);
        assert_eq!(
            overlap.rpc_bytes,
            overlap.append_rpc_bytes + overlap.snapshot_rpc_bytes
        );
        assert!(
            overlap.frame_allocations > 2,
            "CONFIG_CAPACITY_FRAME_OWNER_RED: actual independent boxed frame owners"
        );
        assert!(overlap.frame_bytes > overlap.rpc_bytes,
        "CONFIG_CAPACITY_FRAME_OWNER_RED: actual outer JSON capacities overlap actual RPC buffers");
        println!("CONFIG_CAPACITY_SNAPSHOT_VOTE_ALIGNMENT_LIFECYCLE agreement={setup_vote:?} source_term={} target_term={} target_leader={:?} original_call=true joined_shutdown=true",
            vote_at_arm.0.term, vote_at_arm.1.term, vote_at_arm.1.leader_id);
        assert!(setup_vote.is_some_and(|agreement| agreement.accepted
            && agreement.vote == opc_consensus::engine::Vote::new_committed(vote_at_arm.0.term, leader_id))
            && vote_at_arm.0.leader_id == Some(leader_id)
            && vote_at_arm.1.leader_id == Some(leader_id)
            && vote_at_arm.0.term == vote_at_arm.1.term,
            "CONFIG_CAPACITY_SNAPSHOT_VOTE_ALIGNMENT_RED: the exact original call starts after real native vote agreement");
        let scheduled_snapshot = paused_snapshot.snapshot();
        println!("CONFIG_CAPACITY_NATIVE_SNAPSHOT_SCHEDULE_LIFECYCLE scheduled={scheduled_snapshot:?} original_call=true joined_shutdown=true");
        assert_eq!(scheduled_snapshot.entered, 1);
        assert_eq!(scheduled_snapshot.completed, 1);
        assert!(scheduled_snapshot.untyped && scheduled_snapshot.success,
            "CONFIG_CAPACITY_UNTYPED_SNAPSHOT_SCHEDULE_RED: the original untyped call completed successfully, without expiry or retry masking");
        println!("CONFIG_CAPACITY_NATIVE_OWNER_BRIDGE_LIFECYCLE members=9 prepared=72 aliases=73 native={native_drain:?} preparations_before={preparations_before_drop:?} preparations_after={preparations_after_drop:?} native_counts={:?} full_memory_bound=false", native_results.counts);
        let (native, transport) = native_results.mutation.expect(
            "CONFIG_CAPACITY_NATIVE_OWNER_BRIDGE_RED: actual native mutation checkpoint after completed lifecycle",
        );
        let transport = transport.expect(
            "CONFIG_CAPACITY_NATIVE_TRANSPORT_JOIN_RED: currently live selected append and snapshot at native mutation",
        );
        assert_eq!(
            native_results.counts,
            [1, 1, 1, 1],
            "one actual decoded/validated/mutation/write checkpoint"
        );
        assert_eq!(native_drain.callbacks, 4);
        assert!(!native_drain.registered);
        assert_eq!(native_drain.native_scopes, 0);
        assert_eq!(native_drain.transport_scopes, 0);
        assert_eq!(preparations_before_drop.registrations, 73);
        assert_eq!(preparations_before_drop.commands, 72);
        assert_eq!(preparations_after_drop, Default::default());
        assert_eq!(native.preparations, preparations_before_drop);
        assert_eq!(native.node_prepared_commands, 8);
        assert_eq!(native.source, leader_id);
        assert!(native.selected_prepared_bytes > BOUNDED_LOGICAL_BYTES);
        assert!(native.node_prepared_bytes > native.selected_prepared_bytes);
        assert!(native.native_command_bytes > BOUNDED_LOGICAL_BYTES);
        assert!(native.native_ledger_bytes > 0);
        assert!(
            native.native_is_distinct,
            "real independent native decoding, no prepared alias charge"
        );
        assert_eq!(native.native_write_bytes, 0);
        assert_eq!(native.native_derived_bytes, 0);
        let validated = native_results.validated.unwrap();
        assert!(validated.native_derived_bytes > 0);
        assert_eq!(validated.native_write_bytes, 0);
        assert!(native_results.decoded.unwrap().native_ledger_bytes > 0);
        assert!(native_results.written.unwrap().native_write_bytes > 0);
        assert_eq!(transport.pair.source, leader_id);
        assert_eq!(transport.pair.snapshot_target, lagging_id);
        assert_eq!(transport.pair.append_target, minority_id);
        assert!(transport.snapshot_data_bytes >= 1_048_576);
        assert!(transport.pair.append_rpc_bytes > BOUNDED_LOGICAL_BYTES);
        assert!(transport.pair.snapshot_rpc_bytes > 1_048_576);
        assert_eq!(
            transport.pair.rpc_bytes,
            transport.pair.append_rpc_bytes + transport.pair.snapshot_rpc_bytes
        );
        assert!(transport.pair.frame_allocations > 2);
        assert!(transport.pair.frame_bytes > transport.pair.rpc_bytes);
        assert_ne!(transport.append_generation, transport.snapshot_generation);
        let current = &transport.current;
        let owners: Vec<_> = current
            .groups
            .iter()
            .flat_map(|group| group.owners.iter().map(move |owner| (group, owner)))
            .collect();
        let call_ids: BTreeSet<_> = owners.iter().map(|(_, owner)| owner.call_id).collect();
        assert_eq!(
            current.total.calls,
            owners.len(),
            "CONFIG_CAPACITY_CURRENT_NATIVE_RED: every current registration has provenance"
        );
        assert_eq!(call_ids.len(), owners.len());
        assert!(call_ids.iter().all(|id| *id > 0));
        assert_eq!(current.total.calls, current.additional.calls + 2);
        assert_eq!(
            current.total.ready_frames,
            current.additional.ready_frames + 2
        );
        assert_eq!(
            current.total.rpc_bytes,
            transport.pair.rpc_bytes + current.additional.rpc_bytes
        );
        assert_eq!(
            current.total.frame_bytes,
            transport.pair.frame_bytes + current.additional.frame_bytes
        );
        assert_eq!(
            current.total.frame_allocations,
            transport.pair.frame_allocations + current.additional.frame_allocations
        );
        for group in &current.groups {
            assert_eq!(group.totals.calls, group.owners.len());
            assert!(group.owners.iter().all(|owner| owner.buffers.calls == 1));
        }
        let (append_group, append_owner) = owners
            .iter()
            .find(|(_, owner)| owner.call_id == transport.append_call_id)
            .copied()
            .expect("selected actual append is part of the current census");
        let (snapshot_group, snapshot_owner) = owners
            .iter()
            .find(|(_, owner)| owner.call_id == transport.snapshot_call_id)
            .copied()
            .expect("selected actual snapshot is part of the current census");
        assert_eq!(append_group.source, leader_id);
        assert_eq!(append_group.family, ConsensusRpcFamily::AppendEntries);
        assert_eq!(append_owner.target, minority_id);
        assert_eq!(append_owner.generation, transport.append_generation);
        assert!(append_owner.selected_append);
        assert_eq!(append_owner.buffers.ready_frames, 1);
        assert_eq!(
            append_owner.buffers.rpc_bytes,
            transport.pair.append_rpc_bytes
        );
        assert_eq!(snapshot_group.source, leader_id);
        assert_eq!(snapshot_group.family, ConsensusRpcFamily::InstallSnapshot);
        assert_eq!(snapshot_owner.target, lagging_id);
        assert_eq!(snapshot_owner.generation, transport.snapshot_generation);
        assert_eq!(snapshot_owner.buffers.ready_frames, 1);
        assert_eq!(
            snapshot_owner.buffers.rpc_bytes,
            transport.pair.snapshot_rpc_bytes
        );
        let current_append_targets: BTreeSet<_> = append_group
            .owners
            .iter()
            .map(|owner| owner.target)
            .collect();
        // All currently registered append RPCs from this source are distinct
        // from native mutation storage. Snapshot RPC and outer-frame storage
        // remain separate; source/family groups can alias and are not summed.
        let current_node_mutation_bytes =
            native.node_mutation_bytes + append_group.totals.rpc_bytes;
        println!("CONFIG_CAPACITY_CURRENT_NATIVE_LIFECYCLE observed_calls={} additional_calls={} current_append_targets={} completed_append_targets=7 native_node_mutation_bytes={} current_append_rpc_bytes={} current_snapshot_rpc_bytes={} current_node_mutation_bytes={} current_outer_frame_bytes={} current={current:?} full_memory_bound=false",
            current.total.calls, current.additional.calls, current_append_targets.len(),
            native.node_mutation_bytes, append_group.totals.rpc_bytes, snapshot_group.totals.rpc_bytes,
            current_node_mutation_bytes, current.total.frame_bytes);
        let pending = &transport.pending;
        let pending_after_shutdown = observation.pending_snapshot();
        assert_eq!(pending_after_shutdown, Default::default(),
            "CONFIG_CAPACITY_PENDING_NATIVE_DRAIN_RED: pool-acquisition registrations drain after the original lifecycle");
        // Zero is a valid current observation; this scenario does not require
        // both lanes of any one peer pool to be contended at the checkpoint.
        println!("CONFIG_CAPACITY_PENDING_NATIVE_LIFECYCLE pending_calls={} pending_rpc_allocations={} pending_rpc_bytes={} additional_pending_rpc_bytes={} observed_rpc_union_bytes={} pending={pending:?} drained=true full_memory_bound=false",
            pending.owners.len(), pending.rpc_allocations, pending.rpc_bytes,
            pending.additional_rpc_bytes, pending.observed_rpc_bytes);
        // Preserve the original selected-owner partial bounds separately from
        // the broader current census; neither establishes a complete budget.
        let selected_mutation_bytes =
            native.selected_mutation_bytes + transport.pair.append_rpc_bytes;
        let node_mutation_bytes = native.node_mutation_bytes + transport.pair.append_rpc_bytes;
        assert!(selected_mutation_bytes <= 32 * 1024 * 1024,
            "CONFIG_CAPACITY_NATIVE_OPERATION_BYTES_RED: measured simultaneous partial owners exceed operation envelope");
        assert!(node_mutation_bytes <= 256 * 1024 * 1024,
            "CONFIG_CAPACITY_NATIVE_NODE_BYTES_RED: measured simultaneous partial owners exceed node envelope");
        println!("CONFIG_CAPACITY_NATIVE_OWNER_BRIDGE native={native:?} transport={transport:?} selected_mutation_bytes={selected_mutation_bytes} node_mutation_bytes={node_mutation_bytes} full_memory_bound=false");
        println!("CONFIG_CAPACITY_NINE_OVERLAP members=9 prepared=72 audited_commits=1 append_targets=7 snapshot_chunks={chunks} snapshot_bytes={snapshot_bytes} overlap={overlap:?} drained=true original_paths=true original_handle=true native_wal=true durability=Durable full_memory_bound=false");
    }
);
