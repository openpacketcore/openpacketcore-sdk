//! Native nine-member replication while every preparation pool holds real values.
//!
//! This is a fan-out and reservation-lifetime detector. Observed record and
//! outgoing-request capacities are partial measurements, not a whole-process
//! or complete mutation/transport memory bound. Cancellation, simultaneous
//! accepted writes and snapshot overlap have separate qualification obligations.

use super::*;
use futures_util::{future::join_all, stream, StreamExt};
use opc_persist::PreparedConfigCommitOperation;
use opc_session_net::consensus::capacity_observation::ConsensusBufferObservation;

#[path = "nine_member/fanout.rs"]
mod fanout;
#[path = "nine_member/overlap.rs"]
mod overlap;

const MEMBERS: usize = 9;
const PREPARATIONS: usize = 8;

#[derive(Default, Debug)]
struct Transfers {
    fanout: fanout::Gate,
    native_raft: Arc<std::sync::Mutex<BTreeMap<u64, u64>>>,
    large_append_success: [AtomicUsize; MEMBERS],
    active: AtomicUsize,
    active_capacity: AtomicUsize,
    peak_active: AtomicUsize,
    peak_capacity: AtomicUsize,
    snapshots: [Arc<snapshot::Observation>; MEMBERS],
    defer_snapshots: [AtomicBool; MEMBERS],
    deferred_snapshot_attempts: [AtomicUsize; MEMBERS],
    snapshot_pauses: [SnapshotPause; MEMBERS],
    vote_probes: [snapshot::VoteProbe; MEMBERS],
}

impl Transfers {
    fn record_snapshot_completion(
        &self,
        target: usize,
        paused_snapshot: bool,
        chunk: Option<snapshot::PendingChunk>,
        result: &Result<ConsensusWireResponse, ConsensusPeerError>,
    ) {
        // Consume this invocation's captured chunk once. The aggregate chunk
        // oracle and one-shot pause use the same decoded acknowledgment.
        let acknowledged = match (chunk, result) {
            (Some(chunk), Ok(response)) => self.snapshots[target].record(chunk, response),
            _ => false,
        };
        if paused_snapshot {
            self.snapshot_pauses[target].complete(acknowledged);
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SnapshotPauseTotals {
    entered: usize,
    completed: usize,
    untyped: bool,
    success: bool,
}

/// Schedule one real pre-registration snapshot; retain only controls/counters.
#[derive(Debug, Default)]
struct SnapshotPause {
    armed: AtomicBool,
    totals: std::sync::Mutex<SnapshotPauseTotals>,
    entered: tokio::sync::Notify,
    resumed: tokio::sync::Notify,
    completed: tokio::sync::Notify,
}

impl SnapshotPause {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn pause_once(&self, untyped: bool) -> bool {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return false;
        }
        {
            let mut totals = self.totals.lock().unwrap();
            totals.entered += 1;
            totals.untyped = untyped;
        }
        self.entered.notify_one();
        self.resumed.notified().await;
        true
    }

    async fn wait_entered(&self) {
        self.entered.notified().await;
    }

    fn resume(&self) {
        self.resumed.notify_one();
    }

    fn complete(&self, success: bool) {
        {
            let mut totals = self.totals.lock().unwrap();
            totals.completed += 1;
            totals.success = success;
        }
        self.completed.notify_one();
    }

    async fn wait_completed(&self) {
        self.completed.notified().await;
    }

    fn snapshot(&self) -> SnapshotPauseTotals {
        *self.totals.lock().unwrap()
    }
}

struct ActiveRequest<'a> {
    transfers: &'a Transfers,
    capacity: usize,
}

impl<'a> ActiveRequest<'a> {
    fn new(transfers: &'a Transfers, capacity: usize) -> Self {
        let active = transfers.active.fetch_add(1, Ordering::SeqCst) + 1;
        let bytes = transfers
            .active_capacity
            .fetch_add(capacity, Ordering::SeqCst)
            + capacity;
        transfers.peak_active.fetch_max(active, Ordering::SeqCst);
        transfers.peak_capacity.fetch_max(bytes, Ordering::SeqCst);
        Self {
            transfers,
            capacity,
        }
    }
}

impl Drop for ActiveRequest<'_> {
    fn drop(&mut self) {
        self.transfers.active.fetch_sub(1, Ordering::SeqCst);
        self.transfers
            .active_capacity
            .fetch_sub(self.capacity, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct NinePeer {
    inner: RemoteSessionConsensusPeer,
    target: usize,
    transfers: Arc<Transfers>,
}

impl NinePeer {
    async fn invoke(
        &self,
        request: ConsensusWireRequest,
        timeout: Option<Duration>,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let invocation_entered = tokio::time::Instant::now();
        assert!(request.payload.len() <= opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
        let typed = opc_persist::config_capacity_observation::transport_witness(
            &request,
            self.inner.node_id(),
        );
        let raft = opc_persist::config_capacity_observation::raft_buffers::raft_append_witness(
            &request,
            self.inner.node_id(),
        );
        if let (Some(typed), Some(raft)) = (typed, raft) {
            // Both witnesses checked this exact original wire allocation. Keep
            // only their numeric relation; a later native capture must still
            // prove the transport owner and Raft origin are currently live.
            assert!(typed.selected_append);
            assert!(self
                .transfers
                .native_raft
                .lock()
                .unwrap()
                .insert(typed.generation, raft.generation)
                .is_none());
        }
        // The typed context was captured by the real adapter before this peer
        // was invoked. Pause before reading defer_snapshots so arming exercises
        // the exact pre-registration interleaving, without restarting the RPC.
        let paused_snapshot = request.family == ConsensusRpcFamily::InstallSnapshot
            && self.transfers.snapshot_pauses[self.target]
                .pause_once(typed.is_none())
                .await;
        // Setup-only fault: keep compatibility probes, votes and append/heartbeat
        // traffic on the real authenticated transport while deferring state transfer.
        if request.family == ConsensusRpcFamily::InstallSnapshot
            && self.transfers.defer_snapshots[self.target].load(Ordering::SeqCst)
        {
            self.transfers.deferred_snapshot_attempts[self.target].fetch_add(1, Ordering::SeqCst);
            if paused_snapshot {
                self.transfers.snapshot_pauses[self.target].complete(false);
            }
            return Err(ConsensusPeerError::Unavailable);
        }
        let large_append = request.family == ConsensusRpcFamily::AppendEntries
            && request.payload.len() > 1_048_576;
        // This observes the one public request buffer at the peer boundary.
        // TLS, inner encoders, responses and retained engine entries are not
        // measured by this guard and cannot be inferred from its high water.
        let _active = ActiveRequest::new(&self.transfers, request.payload.capacity());
        let fanout_call = self
            .transfers
            .fanout
            .pause(&request, self.inner.node_id(), invocation_entered)
            .await;
        // Test-only decoding for the existing contiguous acknowledged-chunk
        // witness. Its temporary copy is not a measured production owner.
        let chunk = self.transfers.snapshots[self.target].capture(&request);
        let vote_probe = self.transfers.vote_probes[self.target].capture(&request);
        let _fanout_call = fanout_call.map(|call| self.transfers.fanout.in_flight(call));
        let result = opc_session_net::consensus::capacity_observation::scope_typed_transport(
            typed.is_some_and(|witness| witness.selected_append),
            typed.map_or(0, |witness| witness.snapshot_data_bytes),
            typed.map_or(0, |witness| witness.generation),
            async {
                match timeout {
                    Some(timeout) => self.inner.call_with_timeout(request, timeout).await,
                    None => self.inner.call(request).await,
                }
            },
        )
        .await;
        if let Some(call) = fanout_call {
            self.transfers.fanout.response_ready(call, &result).await;
            self.transfers.fanout.complete(call, &result);
        }
        if let Some(probe) = vote_probe {
            probe.record(&result);
        }
        self.transfers
            .record_snapshot_completion(self.target, paused_snapshot, chunk, &result);
        if large_append
            && result
                .as_ref()
                .is_ok_and(|response| response.result.is_ok())
        {
            self.transfers.large_append_success[self.target].fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

#[async_trait]
impl ConsensusPeer for NinePeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.inner.node_id()
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        self.inner.scope_identity()
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.invoke(request, None).await
    }

    async fn call_with_timeout(
        &self,
        request: ConsensusWireRequest,
        timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.invoke(request, Some(timeout)).await
    }
}

fn nine_manifest() -> Arc<SessionReplicationManifest> {
    let descriptors = (0..MEMBERS)
        .map(|member| {
            QuorumReplicaDescriptor::new(
                replica_id(member),
                ReplicaEndpoint::new(format!("config-{member}.qualification.invalid"), 7443)
                    .expect("synthetic endpoint"),
                ReplicaTlsIdentity::new(spiffe(member)).expect("synthetic TLS identity"),
                ReplicaFailureDomain::new(format!("zone-{member}")).expect("failure domain"),
                ReplicaBackingIdentity::new(format!("disk-{member}")).expect("backing identity"),
            )
        })
        .collect();
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("synthetic-config-capacity-nine").expect("cluster"),
            SessionConfigurationGeneration::new("config-capacity-nine").expect("generation"),
            SessionConfigurationEpoch::new(1).expect("epoch"),
            descriptors,
        )
        .expect("nine-member authenticated manifest"),
    )
}

async fn open_nine(
    directory: &Path,
    manifest: &Arc<SessionReplicationManifest>,
    pki: &Pki,
    addresses: &[Arc<RwLock<Option<SocketAddr>>>; MEMBERS],
    transfers: &[Arc<Transfers>; MEMBERS],
    reopen: bool,
    observation: Option<&Arc<ConsensusBufferObservation>>,
) -> Vec<ConsensusConfigStore> {
    let node_ids: [_; MEMBERS] = std::array::from_fn(|member| {
        manifest
            .bind_local(replica_id(member))
            .expect("original local member")
            .local_consensus_node_id()
    });
    let members = node_ids.into_iter().collect::<BTreeSet<_>>();
    let provision = |source: usize| {
        let node_ids = &node_ids;
        let members = &members;
        async move {
            let local = manifest
                .bind_local(replica_id(source))
                .expect("original source member");
            let peers = (0..MEMBERS)
                .filter(|target| *target != source)
                .map(|target| {
                    let inner = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                        local
                            .clone()
                            .bind_remote(replica_id(target))
                            .expect("original target binding"),
                        resolver(addresses[target].clone()),
                        pki.client(source),
                    );
                    let inner = match observation {
                        Some(observation) => inner.with_buffer_observation(observation.clone()),
                        None => inner,
                    };
                    (
                        node_ids[target],
                        Arc::new(NinePeer {
                            inner,
                            target,
                            transfers: transfers[source].clone(),
                        }) as Arc<dyn ConsensusPeer>,
                    )
                })
                .collect();
            let topology = ConfigConsensusTopology::try_new(
                manifest.consensus_identity(),
                node_ids[source],
                members.clone(),
            )
            .expect("nine-voter native topology");
            let options = RetainedConfigOptions::new(
                directory.join(format!("config-{source}.sqlite")),
                RetainedConfigBinding::new(
                    topology.clone(),
                    [0xD3 + source as u8; 32],
                    [0xD6 + source as u8; 32],
                )
                .expect("independent immutable native binding")
                .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
                RetainedConfigDurability::Durable {
                    min_free_bytes: 128 * 1024 * 1024,
                },
                256 * 1024 * 1024,
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            )
            .expect("unchanged native Durable options");
            let key = AuditKey::new([0xD9; 32]).expect("synthetic shared audit key");
            let backend = if reopen {
                SqliteBackend::reopen_config_authority(options, key).await
            } else {
                SqliteBackend::provision_config_authority(options, key).await
            }
            .expect("real native authority on original paths");
            (topology, backend, peers)
        }
    };
    // Retained provisioning has a process-wide four-slot fail-fast gate.
    // Respect it without retries, then start all cores together so elections
    // do not run while another group is still provisioning its authority.
    let prepared = stream::iter((0..MEMBERS).map(provision))
        .buffered(4)
        .collect::<Vec<_>>()
        .await;
    join_all(prepared.into_iter().enumerate().map(
        |(source, (topology, backend, peers))| async move {
            ConsensusConfigStore::open(
                topology,
                backend,
                directory.join(format!("snapshots-{source}")),
                peers,
            )
            .await
            .expect("real native consensus member")
        },
    ))
    .await
}

fn authority_states(
    databases: &[PathBuf; MEMBERS],
) -> [profile_rejection::AuthorityDigest; MEMBERS] {
    databases
        .each_ref()
        .map(|path| profile_rejection::authority_digest(path))
}

fn assert_authority_unchanged(
    before: &[profile_rejection::AuthorityDigest; MEMBERS],
    after: &[profile_rejection::AuthorityDigest; MEMBERS],
) {
    for (member, (before, after)) in before.iter().zip(after).enumerate() {
        if before != after {
            for (table, (digest, rows)) in &before.tables {
                let (next_digest, next_rows) =
                    after.tables.get(table).expect("same authority tables");
                if digest != next_digest || rows != next_rows {
                    eprintln!("CONFIG_CAPACITY_NINE_AUTHORITY_CHANGE member={member} table={table} rows_before={rows} rows_after={next_rows}");
                }
            }
        }
    }
    assert!(
        before == after,
        "CONFIG_CAPACITY_NINE_EFFECTS_RED: all native authority rows unchanged"
    );
}

fn assert_exhausted(store: &ConsensusConfigStore) {
    let error = store
        .try_reserve_config_preparation()
        .expect_err("CONFIG_CAPACITY_NINE_SLOTS_RED: ninth preparation must be refused");
    assert!(matches!(error.kind(), PersistErrorKind::Unavailable));
}

async fn read_all(
    stores: &[ConsensusConfigStore],
    expected: &CommitRecord,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) {
    let records = tokio::time::timeout(
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        join_all(stores.iter().map(|store| store.load_latest())),
    )
    .await
    .expect("all nine original read deadlines");
    for record in records {
        let record = record
            .expect("quorum-current native read")
            .expect("native head");
        assert!(
            record.record == *expected,
            "same atomic configuration on all nine members"
        );
        assert_decrypted(&record.record, aad, plaintext);
    }
}

native_case!(
    config_capacity_957_nine_native_members_replicate_with_all_preparations_full,
    {
        let directory = disk_fixture();
        let databases: [_; MEMBERS] =
            std::array::from_fn(|member| directory.join(format!("config-{member}.sqlite")));
        let pki = Pki::new();
        let manifest = nine_manifest();
        let addresses: [_; MEMBERS] = std::array::from_fn(|_| Arc::new(RwLock::new(None)));
        let transfers: [_; MEMBERS] = std::array::from_fn(|_| Arc::new(Transfers::default()));
        let stores = open_nine(
            &directory, &manifest, &pki, &addresses, &transfers, false, None,
        )
        .await;
        let mut servers = Vec::new();
        let mut released = Vec::new();
        for (member, store) in stores.iter().enumerate() {
            let (handler, release) = observed_handler(store);
            let (server, address) = SessionConsensusServer::new(
                handler,
                pki.server(member),
                manifest
                    .bind_local(replica_id(member))
                    .expect("original voter"),
            )
            .listen("127.0.0.1:0".parse().expect("loopback listener"))
            .await
            .expect("real authenticated listener");
            *addresses[member].write().expect("publish original address") = Some(address);
            servers.push(server);
            released.push(release);
        }
        tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            for result in join_all(stores.iter().map(|store| store.initialize_cluster())).await {
                result.expect("original nine-voter admission");
            }
            for result in join_all(stores.iter().map(|store| store.probe_durable_readiness())).await
            {
                result.expect("original nine-voter readiness");
            }
        })
        .await
        .expect("nine-voter readiness inside unchanged operation budget");
        let leader_id = stores[0].status().leader_id.expect("native leader");
        assert!(stores
            .iter()
            .all(|store| store.status().leader_id == Some(leader_id)));
        let leader = stores
            .iter()
            .position(|store| store.status().node_id == leader_id)
            .unwrap();
        let (control, control_aad, control_plaintext) = commit(&stores[leader], 1, None).await;
        let control_record = control.record().clone();
        let operation = stores[leader]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0xC7; 16]),
                control,
                CALLER,
            )
            .expect("prepare real at-limit control");
        stores[leader]
            .append_prepared_commit_local(operation)
            .await
            .expect("real native control");
        read_all(&stores, &control_record, &control_aad, &control_plaintext).await;
        let before = authority_states(&databases);

        let mut pending: Vec<Vec<PreparedConfigCommitOperation>> = (0..MEMBERS)
            .map(|_| Vec::with_capacity(PREPARATIONS))
            .collect();
        let mut record_capacity = [0_usize; MEMBERS];
        let mut selected = None;
        for (member, store) in stores.iter().enumerate() {
            for slot in 0..PREPARATIONS {
                let (input, aad, plaintext) = commit(store, 2, Some(control_record.tx_id)).await;
                assert_eq!(plaintext.len(), 1_572_864);
                let record = input.record();
                // Actual capacities at the attested transfer boundary only. The
                // fixture's plaintext and readback copies remain caller-owned.
                record_capacity[member] += record.encrypted_blob.capacity()
                    + record.plaintext_digest.capacity()
                    + record.principal.capacity();
                if member == leader && slot == 0 {
                    selected = Some((record.clone(), aad, plaintext));
                }
                let mut id = [0xC8; 16];
                id[0] = member as u8;
                id[1] = slot as u8;
                pending[member].push(
                    store
                        .prepare_recoverable_commit(
                            ConfigConsensusRequestId::from_bytes(id),
                            input,
                            CALLER,
                        )
                        .expect("independent at-limit prepared owner"),
                );
            }
            assert_exhausted(store);
        }
        assert_authority_unchanged(&before, &authority_states(&databases));
        let before_append: [_; MEMBERS] = std::array::from_fn(|target| {
            transfers[leader].large_append_success[target].load(Ordering::SeqCst)
        });
        let operation = pending[leader].remove(0);
        let handle = ConfigCommitRecoveryHandle::from_bytes(operation.recovery_handle().as_bytes())
            .expect("retain exact original operation handle");
        let (expected, aad, plaintext) = selected.expect("one selected valid successor");
        stores[leader]
        .append_prepared_commit_local(operation)
        .await
        .expect("CONFIG_CAPACITY_NINE_REPLICATION_RED: native replication progresses through full preparation pools");
        read_all(&stores, &expected, &aad, &plaintext).await;
        assert!(stores
            .iter()
            .all(|store| store.status().leader_id == Some(leader_id)));
        for (target, previous) in before_append.iter().enumerate() {
            if target != leader {
                assert!(transfers[leader].large_append_success[target].load(Ordering::SeqCst) > *previous,
                "CONFIG_CAPACITY_NINE_FANOUT_RED: actual larger AppendEntries reached every remote native store");
            }
        }
        // Occupy the one completed operation's released slot. All nine pools are
        // full again while exact recovery uses the original durable operation.
        let released_leader_slot = stores[leader]
            .try_reserve_config_preparation()
            .expect("completed original ownership released")
            .expect("bounded original pool");
        let committed_authority = authority_states(&databases);
        for store in &stores {
            assert_exhausted(store);
            assert!(matches!(
                store
                    .lookup_commit_operation(&handle, CALLER)
                    .await
                    .expect("read-only exact recovery with full pool"),
                ConfigCommitRecoveryOutcome::Committed
            ));
        }
        assert_authority_unchanged(&committed_authority, &authority_states(&databases));

        let mut replacement_slots = Vec::new();
        for (member, store) in stores.iter().enumerate() {
            drop(pending[member].pop().expect("one unsent prepared owner"));
            replacement_slots.push(
                store
                    .try_reserve_config_preparation()
                    .expect("one owner releases one slot")
                    .expect("bounded slot"),
            );
            for other in &stores {
                assert_exhausted(other);
            }
        }
        drop(replacement_slots);
        drop(released_leader_slot);
        drop(pending);
        for store in &stores {
            let all = (0..PREPARATIONS)
                .map(|_| {
                    store
                        .try_reserve_config_preparation()
                        .expect("all exact owners released")
                        .expect("bounded slot")
                })
                .collect::<Vec<_>>();
            assert_exhausted(store);
            drop(all);
        }
        assert_authority_unchanged(&committed_authority, &authority_states(&databases));
        for (member, observation) in transfers.iter().enumerate() {
            eprintln!("CONFIG_CAPACITY_NINE_OBSERVATION member={member} transferred_record_capacity={} request_peak_count={} request_peak_capacity={}",
            record_capacity[member], observation.peak_active.load(Ordering::SeqCst), observation.peak_capacity.load(Ordering::SeqCst));
        }
        for (store, server) in stores.iter().zip(servers) {
            server.abort_and_wait().await;
            store
                .shutdown()
                .await
                .expect("stop only original native member");
        }
        all_handlers_released(released).await;
        drop(stores);
        for address in &addresses {
            *address.write().expect("retire only original listener") = None;
        }
        for observation in &transfers {
            assert_eq!(observation.active.load(Ordering::SeqCst), 0);
            assert_eq!(observation.active_capacity.load(Ordering::SeqCst), 0);
        }
        println!("CONFIG_CAPACITY_NINE members=9 encrypted_preparations=72 per_node=8 rejected_ninth=9 real_large_targets=8 native_atomic_readback=true exact_recovery=true owner_conservation=true full_memory_bound=false");
    }
);

#[cfg(test)]
mod snapshot_ack_tests {
    use super::*;
    use opc_consensus::engine::error::{Fatal, InstallSnapshotError, RaftError};
    use opc_consensus::engine::raft::InstallSnapshotResponse;
    use opc_consensus::engine::{EmptyNode, SnapshotMeta, StoredMembership, Vote};
    use serde::Serialize;

    type SnapshotReply = Result<
        InstallSnapshotResponse<ConsensusNodeId>,
        RaftError<ConsensusNodeId, InstallSnapshotError>,
    >;

    #[derive(Serialize)]
    struct Wire<T> {
        revision: u16,
        value: T,
    }

    // The same public request field order captured by snapshot::Observation.
    #[derive(Serialize)]
    struct Chunk {
        vote: Vote<ConsensusNodeId>,
        meta: SnapshotMeta<ConsensusNodeId, EmptyNode>,
        offset: u64,
        data: Vec<u8>,
        done: bool,
    }

    fn request(
        vote: Vote<ConsensusNodeId>,
        offset: u64,
        data: Vec<u8>,
        done: bool,
    ) -> ConsensusWireRequest {
        let local = nine_manifest().bind_local(replica_id(0)).unwrap();
        ConsensusWireRequest::try_new(
            local.consensus_identity(),
            local.local_consensus_node_id(),
            ConsensusRpcFamily::InstallSnapshot,
            opc_consensus::encode_bounded(&Wire {
                revision: 8,
                value: Chunk {
                    vote,
                    meta: SnapshotMeta {
                        last_log_id: None,
                        last_membership: StoredMembership::default(),
                        snapshot_id: "synthetic-snapshot-ack".into(),
                    },
                    offset,
                    data,
                    done,
                },
            })
            .unwrap(),
        )
        .unwrap()
    }

    fn response(reply: SnapshotReply) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        Ok(ConsensusWireResponse {
            result: Ok(opc_consensus::encode_bounded(&Wire {
                revision: 8,
                value: reply,
            })
            .unwrap()),
        })
    }

    async fn exercise(
        reply: SnapshotReply,
        expected_success: bool,
        expected_before_retry: Option<usize>,
    ) {
        // These encoded responses isolate the real shared recording path. They
        // do not claim a native snapshot, network or storage operation occurred.
        let (
            original,
            after_tail,
            after_retry,
            before_retry,
            complete,
            captured,
            pauses,
            active,
            weak,
        ) = {
            let transfers = Transfers::default();
            let target = 1;
            transfers.snapshots[target]
                .enabled
                .store(true, Ordering::SeqCst);
            let pause = &transfers.snapshot_pauses[target];
            pause.arm();
            let (original_paused, ()) = tokio::join!(pause.pause_once(true), async {
                pause.wait_entered().await;
                pause.resume();
            });
            let sender = nine_manifest()
                .bind_local(replica_id(0))
                .unwrap()
                .local_consensus_node_id();
            let vote = Vote::new_committed(7, sender);
            let first = request(vote, 0, vec![1, 2, 3], false);
            let final_chunk = request(vote, 3, vec![4, 5], true);
            let first_reply = response(reply);
            let chunk = transfers.snapshots[target].capture(&first);
            let captured = chunk.is_some();
            transfers.record_snapshot_completion(target, original_paused, chunk, &first_reply);
            pause.wait_completed().await;
            let original = pause.snapshot();

            // Finish the other offset before retrying the failed original one.
            // An aggregate transfer can complete later without acknowledging
            // the one exact invocation which passed through the pause.
            let tail_paused = pause.pause_once(false).await;
            let accepted = response(Ok(InstallSnapshotResponse { vote }));
            transfers.record_snapshot_completion(
                target,
                tail_paused,
                transfers.snapshots[target].capture(&final_chunk),
                &accepted,
            );
            let after_tail = pause.snapshot();
            let snapshot_id = Sha256::digest(b"synthetic-snapshot-ack").into();
            let before_retry = transfers.snapshots[target].complete(snapshot_id, 5);
            let retry_paused = pause.pause_once(false).await;
            transfers.record_snapshot_completion(
                target,
                retry_paused,
                transfers.snapshots[target].capture(&first),
                &accepted,
            );
            let after_retry = pause.snapshot();
            let complete = transfers.snapshots[target].complete(snapshot_id, 5);
            let active = (
                transfers.active.load(Ordering::SeqCst),
                transfers.active_capacity.load(Ordering::SeqCst),
            );
            let weak = Arc::downgrade(&transfers.snapshots[target]);
            (
                original,
                after_tail,
                after_retry,
                before_retry,
                complete,
                captured,
                (original_paused, tail_paused, retry_paused),
                active,
                weak,
            )
        };
        // All local requests, encoded replies, observers and pause controls
        // have been dropped before any acknowledgment/coverage assertion.
        assert!(weak.upgrade().is_none(), "local snapshot observer released");
        assert_eq!(active, (0, 0));
        println!("CONFIG_CAPACITY_SNAPSHOT_ACK_LOCAL_CLEANUP owners_released=true native_operation=false");
        assert!(captured);
        assert_eq!(pauses, (true, false, false));
        assert_eq!((original.entered, original.completed), (1, 1));
        assert!(original.untyped);
        assert_eq!(
            complete,
            Some(2),
            "later matching retry completes both exact chunks"
        );
        assert_eq!((after_tail.entered, after_tail.completed), (1, 1),
            "CONFIG_CAPACITY_SNAPSHOT_ACK_RETRY_RED: later chunk acknowledgments cannot complete the original pause");
        assert_eq!((after_retry.entered, after_retry.completed), (1, 1),
            "CONFIG_CAPACITY_SNAPSHOT_ACK_RETRY_RED: only the original invocation completes the pause");
        assert_eq!(after_tail.success, original.success);
        assert_eq!(after_retry.success, original.success,
            "CONFIG_CAPACITY_SNAPSHOT_ACK_RETRY_RED: a later successful retry cannot replace the original result");
        assert_eq!(
            before_retry, expected_before_retry,
            "exact original chunk acknowledgment"
        );
        assert_eq!(original.success, expected_success,
            "CONFIG_CAPACITY_SNAPSHOT_ACK_SEMANTIC_RED: decoded engine Ok must acknowledge the captured request vote");
        println!("CONFIG_CAPACITY_SNAPSHOT_ACK_PASS original_success={expected_success} chunks=2 native_operation=false");
    }

    #[tokio::test]
    async fn paused_snapshot_rejects_encoded_engine_error() {
        exercise(Err(RaftError::Fatal(Fatal::Stopped)), false, None).await;
    }

    #[tokio::test]
    async fn paused_snapshot_rejects_wrong_vote() {
        let sender = nine_manifest()
            .bind_local(replica_id(0))
            .unwrap()
            .local_consensus_node_id();
        exercise(
            Ok(InstallSnapshotResponse {
                vote: Vote::new_committed(8, sender),
            }),
            false,
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn paused_snapshot_accepts_matching_ack() {
        let sender = nine_manifest()
            .bind_local(replica_id(0))
            .unwrap()
            .local_consensus_node_id();
        exercise(
            Ok(InstallSnapshotResponse {
                vote: Vote::new_committed(7, sender),
            }),
            true,
            Some(2),
        )
        .await;
    }
}
