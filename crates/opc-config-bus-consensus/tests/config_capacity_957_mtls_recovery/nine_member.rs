//! Native nine-member replication while every preparation pool holds real values.
//!
//! This is a fan-out and reservation-lifetime detector. Observed record and
//! outgoing-request capacities are partial measurements, not a whole-process
//! or complete mutation/transport memory bound. Cancellation, simultaneous
//! accepted writes and snapshot overlap have separate qualification obligations.

use super::*;
use futures_util::{future::join_all, stream, StreamExt};
use opc_persist::PreparedConfigCommitOperation;

const MEMBERS: usize = 9;
const PREPARATIONS: usize = 8;

#[derive(Default, Debug)]
struct Transfers {
    large_append_success: [AtomicUsize; MEMBERS],
    active: AtomicUsize,
    active_capacity: AtomicUsize,
    peak_active: AtomicUsize,
    peak_capacity: AtomicUsize,
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
        assert!(request.payload.len() <= opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
        let large_append = request.family == ConsensusRpcFamily::AppendEntries
            && request.payload.len() > 1_048_576;
        // This observes the one public request buffer at the peer boundary.
        // TLS, inner encoders, responses and retained engine entries are not
        // measured by this guard and cannot be inferred from its high water.
        let _active = ActiveRequest::new(&self.transfers, request.payload.capacity());
        let result = match timeout {
            Some(timeout) => self.inner.call_with_timeout(request, timeout).await,
            None => self.inner.call(request).await,
        };
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
            let backend = SqliteBackend::provision_config_authority(
                options,
                AuditKey::new([0xD9; 32]).expect("synthetic shared audit key"),
            )
            .await
            .expect("real native authority");
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
        let stores = open_nine(&directory, &manifest, &pki, &addresses, &transfers).await;
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
