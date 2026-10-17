use super::*;
use opc_consensus::voter_slots::{
    VoterAuthenticatedResponse, VoterPeerResolver, VoterPeerRoute, VoterRpcBinding,
    VoterSlotMember, VoterSlotPhase, VoterSlotRecord,
};

#[derive(serde::Deserialize)]
struct ReceivedRepairChunk {
    vote: opc_consensus::engine::Vote<ConfigConsensusNodeId>,
    meta: opc_consensus::engine::SnapshotMeta<
        ConfigConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    offset: u64,
    bytes: Vec<u8>,
    done: bool,
}

#[derive(Debug)]
struct RepairChunkObservation {
    vote: opc_consensus::engine::Vote<ConfigConsensusNodeId>,
    meta: opc_consensus::engine::SnapshotMeta<
        ConfigConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    offset: u64,
    length: usize,
    done: bool,
}

#[derive(Debug, Default)]
struct RepairControl {
    pause_after_first_chunk: AtomicBool,
    chunk_limit: AtomicUsize,
    chunks: AtomicUsize,
    calls: AtomicUsize,
    received: StdMutex<Vec<RepairChunkObservation>>,
    blocked: tokio::sync::Notify,
}

#[derive(Debug)]
struct RepairPeer {
    peer: Arc<dyn ConsensusPeer>,
    control: Arc<RepairControl>,
}

impl RepairPeer {
    async fn before_repair(&self) {
        self.control.calls.fetch_add(1, Ordering::SeqCst);
        let chunks = self.control.chunks.load(Ordering::SeqCst);
        let limit = self.control.chunk_limit.load(Ordering::SeqCst);
        if (chunks > 0 && self.control.pause_after_first_chunk.load(Ordering::SeqCst))
            || (limit > 0 && chunks >= limit)
        {
            self.control.blocked.notify_one();
            std::future::pending::<()>().await;
        }
    }

    fn observe_repair(&self, response: &ConsensusWireResponse) {
        if let Ok(bytes) = &response.result {
            let (_, chunk): (u16, ReceivedRepairChunk) =
                opc_consensus::decode_bounded(bytes).unwrap();
            self.control
                .received
                .lock()
                .unwrap()
                .push(RepairChunkObservation {
                    vote: chunk.vote,
                    meta: chunk.meta,
                    offset: chunk.offset,
                    length: chunk.bytes.len(),
                    done: chunk.done,
                });
            self.control.chunks.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl ConsensusPeer for RepairPeer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.peer.node_id()
    }

    fn with_compatibility(
        &self,
        compatibility: opc_consensus::ConsensusCompatibility,
    ) -> Option<Arc<dyn ConsensusPeer>> {
        Some(Arc::new(Self {
            peer: self.peer.with_compatibility(compatibility)?,
            control: self.control.clone(),
        }))
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.call_with_compatibility(request, None, Duration::from_secs(30))
            .await
            .map(|reply| reply.response)
    }

    async fn call_with_compatibility(
        &self,
        request: ConsensusWireRequest,
        required: Option<opc_consensus::ConsensusCompatibility>,
        timeout: Duration,
    ) -> Result<opc_consensus::ConsensusCallResponse, ConsensusPeerError> {
        let repair = request.family == ConsensusRpcFamily::MemberRepair;
        if repair {
            self.before_repair().await;
        }
        let reply = self
            .peer
            .call_with_compatibility(request, required, timeout)
            .await?;
        if repair {
            self.observe_repair(&reply.response);
        }
        Ok(reply)
    }

    async fn call_with_incarnation(
        &self,
        request: ConsensusWireRequest,
        binding: VoterRpcBinding,
        timeout: Duration,
    ) -> Result<VoterAuthenticatedResponse, ConsensusPeerError> {
        let repair = request.family == ConsensusRpcFamily::MemberRepair;
        if repair {
            self.before_repair().await;
        }
        let reply = self
            .peer
            .call_with_incarnation(request, binding, timeout)
            .await?;
        if repair {
            self.observe_repair(&reply.response);
        }
        Ok(reply)
    }
}

#[derive(Debug)]
struct RepairResolver {
    inner: retained_incarnations::Resolver,
    controls: BTreeMap<usize, Arc<RepairControl>>,
}

impl VoterPeerResolver for RepairResolver {
    fn resolve(&self, member: &VoterSlotMember) -> Result<VoterPeerRoute, ConsensusPeerError> {
        let mut route = self.inner.resolve(member)?;
        if let Some(control) = self
            .controls
            .get(&usize::from(member.identity.slot().get() - 1))
        {
            route.peer = Arc::new(RepairPeer {
                peer: route.peer,
                control: control.clone(),
            });
        }
        Ok(route)
    }
}

fn repair_resolver(
    cluster: &ThreeNodeCluster,
    source: usize,
    control: &Arc<RepairControl>,
) -> Arc<dyn VoterPeerResolver> {
    Arc::new(RepairResolver {
        inner: retained_incarnations::Resolver {
            source,
            paths: cluster.paths.clone(),
        },
        controls: (0..cluster.stores.len())
            .filter(|target| *target != source)
            .map(|target| (target, control.clone()))
            .collect(),
    })
}

fn staged_repair_bytes(path: &std::path::Path) -> Vec<u64> {
    std::fs::read_dir(path)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("incoming-"))
        .map(|entry| entry.metadata().unwrap().len())
        .collect()
}

fn staged_repair_files(path: &std::path::Path) -> Vec<(std::ffi::OsString, u64)> {
    std::fs::read_dir(path)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("incoming-"))
        .map(|entry| (entry.file_name(), entry.metadata().unwrap().len()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saved_repair_rediscovers_successor_when_former_source_stalls() {
    let directory = tempfile::tempdir().unwrap();
    let nodes = [1, 2, 3, 4, 5].map(|id| ConfigConsensusNodeId::new(id).unwrap());
    let mut initial = retained_incarnations::genesis();
    initial.cluster_instance = ConfigConsensusClusterId::new("stalled-member-repair").unwrap();
    initial.manifest_digest = [0x71; 32];
    initial.slots = (1..=5)
        .map(|slot| VoterSlotRecord {
            member: retained_incarnations::member(slot, 1),
            retired_through: 0,
            phase: VoterSlotPhase::Voting,
            last_result: None,
        })
        .collect();
    let mut paths = BTreeMap::new();
    for source in 0..5 {
        for (target, node) in nodes.iter().enumerate() {
            if source != target {
                paths.insert((source, target), Arc::new(LoopbackPeer::new(*node)));
            }
        }
    }
    let controls: [_; 4] = std::array::from_fn(|_| Arc::new(RepairControl::default()));
    let resolver_for = |source| -> Arc<dyn VoterPeerResolver> {
        Arc::new(RepairResolver {
            inner: retained_incarnations::Resolver {
                source,
                paths: paths.clone(),
            },
            controls: if source == 4 {
                controls
                    .iter()
                    .enumerate()
                    .map(|(target, control)| (target, control.clone()))
                    .collect()
            } else {
                BTreeMap::new()
            },
        })
    };
    let mut stores = Vec::new();
    for (index, &local_node) in nodes.iter().enumerate() {
        let backend = SqliteBackend::open_with_audit_key(
            directory.path().join(format!("node-{index}.sqlite")),
            true,
            0,
            audit_key(),
        )
        .await
        .unwrap();
        stores.push(
            ConsensusConfigStore::open_with_voter_slots_and_operation_timeout(
                initial.clone(),
                local_node,
                backend,
                directory.path().join(format!("snapshots-{index}")),
                resolver_for(index),
                Duration::from_secs(10),
            )
            .await
            .unwrap(),
        );
    }
    for ((_, target), peer) in &paths {
        peer.install_incarnation(nodes[*target], stores[*target].rpc_handler())
            .await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(|s| s.initialize_cluster())).await
    {
        result.unwrap();
    }
    for store in &stores {
        store.probe_durable_readiness().await.unwrap();
    }
    assert_eq!(stores[0].status().leader_id, Some(nodes[0]));
    stores[4].shutdown().await.unwrap();
    let tx = TxId::new();
    stores[0]
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x42; 16]),
            large_attested(tx),
        )
        .await
        .unwrap();
    for ((_, target), peer) in &paths {
        if *target == 4 {
            *peer.handler.write().await = None;
        }
    }
    tokio::time::sleep(opc_consensus::voter_slots::VOTER_RECENT_TRAFFIC_WINDOW).await;
    let prepared = stores[0]
        .replace_voter(retained_incarnations::verified_request(&initial, 5))
        .await
        .unwrap()
        .table()
        .clone();
    let local = retained_incarnations::member(5, 2).identity.node_id();
    let backend = SqliteBackend::provision_config_member_repair(
        retained_incarnations::options(
            &directory.path().join("replacement.sqlite"),
            prepared.clone(),
            local,
            9,
        ),
        audit_key(),
    )
    .await
    .unwrap();
    let snapshots = directory.path().join("repair-snapshots");
    stores[4] = ConsensusConfigStore::open_with_voter_slots_and_operation_timeout(
        prepared,
        local,
        backend,
        &snapshots,
        resolver_for(4),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    for ((_, target), peer) in &paths {
        if *target == 4 {
            peer.install_incarnation(local, stores[4].rpc_handler())
                .await;
        }
    }
    let former = &controls[0];
    former.pause_after_first_chunk.store(true, Ordering::SeqCst);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stores[4].initialize_cluster())
            .await
            .expect("initial attempt retains its one-second operation deadline")
            .is_err()
    );
    assert_eq!(former.chunks.load(Ordering::SeqCst), 1);
    assert_eq!(staged_repair_bytes(&snapshots), [128 * 1024]);
    assert!(!stores[4].status().admitted);
    assert!(stores[4].status().applied_index.is_none());
    {
        let received = former.received.lock().unwrap();
        assert_eq!(received[0].offset, 0);
        assert_eq!(received[0].length, 128 * 1024);
        assert!(!received[0].done);
    }

    let report = stores[0].shutdown_with_report().await.unwrap();
    let opc_consensus::PlannedShutdownOutcome::LeaderTransferred { successor } = report else {
        panic!("former leader must finish its ordinary planned handoff: {report:?}");
    };
    let successor_index = nodes.iter().position(|node| *node == successor).unwrap();
    assert!((1..4).contains(&successor_index));
    for store in &stores[1..4] {
        store.probe_durable_readiness().await.unwrap();
    }
    let current = &controls[successor_index];
    let requests_before = current.calls.load(Ordering::SeqCst);
    let mut completed = false;
    for _ in 0..3 {
        let result = tokio::time::timeout(Duration::from_secs(2), stores[4].initialize_cluster())
            .await
            .expect("each retry retains its one-second operation deadline");
        if result.is_ok() {
            completed = true;
            break;
        }
        assert!(!stores[4].status().admitted);
        assert!(
            stores[4].status().applied_index.is_none(),
            "unfinished retry: result={result:?}, status={:?}, replacement={:?}",
            stores[4].status(),
            stores[4].voter_slot_state().await.map(|state| state
                .table()
                .replacement
                .as_ref()
                .map(|operation| operation.phase)),
        );
        stores[successor_index]
            .probe_durable_readiness()
            .await
            .unwrap();
    }
    let admitted = stores[4].status().admitted;
    let recovered = if completed {
        stores[4]
            .load_latest()
            .await
            .unwrap()
            .map(|value| value.record.tx_id)
    } else {
        None
    };
    for result in futures_util::future::join_all(stores.iter().map(|s| s.shutdown())).await {
        result.unwrap();
    }
    assert!(former.pause_after_first_chunk.load(Ordering::SeqCst));
    assert!(
        completed,
        "saved repair must rediscover the healthy successor within three bounded retries while the former source stays stalled; successor repair requests: {}",
        current.calls.load(Ordering::SeqCst) - requests_before
    );
    assert!(admitted);
    assert_eq!(recovered, Some(tx));
    assert!(current.calls.load(Ordering::SeqCst) > requests_before);
    let old = former.received.lock().unwrap();
    let new = current.received.lock().unwrap();
    assert_eq!(new[0].offset, 0, "a different vote starts a clean snapshot");
    assert_ne!(old[0].vote, new[0].vote);
    assert_eq!(new[0].vote.leader_id.voted_for(), Some(successor));
    assert_eq!(old[0].meta.last_membership, new[0].meta.last_membership);
    assert!(staged_repair_bytes(&snapshots).is_empty());
}

#[tokio::test]
async fn repair_rediscovery_reuses_the_verified_checkpoint_for_the_same_snapshot() {
    let mut cluster =
        ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedIncarnations)
            .await;
    for result in futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.initialize_cluster()),
    )
    .await
    {
        result.unwrap();
    }
    cluster.wait_ready().await;
    let tx = TxId::new();
    cluster.stores[cluster.leader()]
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x44; 16]),
            large_attested(tx),
        )
        .await
        .unwrap();
    cluster.stores[0].shutdown().await.unwrap();
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            *peer.handler.write().await = None;
        }
    }
    let prepared = retained_incarnations::prepare(&cluster, 0).await;
    let local = retained_incarnations::member(1, 2).identity.node_id();
    let backend = SqliteBackend::provision_config_member_repair(
        retained_incarnations::options(
            &cluster._directory.path().join("rediscovery-repair.sqlite"),
            prepared.clone(),
            local,
            11,
        ),
        audit_key(),
    )
    .await
    .unwrap();
    let control = Arc::new(RepairControl::default());
    let resolver = repair_resolver(&cluster, 0, &control);
    let snapshots = cluster._directory.path().join("rediscovery-snapshots");
    cluster.stores[0] = ConsensusConfigStore::open_with_voter_slots_and_operation_timeout(
        prepared,
        local,
        backend,
        &snapshots,
        resolver,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            peer.install_incarnation(local, cluster.stores[0].rpc_handler())
                .await;
        }
    }
    control.chunk_limit.store(1, Ordering::SeqCst);
    assert!(cluster.stores[0].initialize_cluster().await.is_err());
    let checkpoint = staged_repair_files(&snapshots);
    assert_eq!(checkpoint.len(), 1);
    assert_eq!(checkpoint[0].1, 128 * 1024);
    // This retry makes no progress. The next one must rediscover, while
    // retaining these bytes unless the authenticated snapshot has changed.
    assert!(cluster.stores[0].initialize_cluster().await.is_err());
    assert_eq!(staged_repair_files(&snapshots), checkpoint);
    control.chunk_limit.store(2, Ordering::SeqCst);
    assert!(cluster.stores[0].initialize_cluster().await.is_err());
    let rediscovered_checkpoint = staged_repair_files(&snapshots);
    assert!(!cluster.stores[0].status().admitted);
    assert!(cluster.stores[0].status().applied_index.is_none());
    control.chunk_limit.store(0, Ordering::SeqCst);
    cluster.stores[0].initialize_cluster().await.unwrap();
    let recovered = cluster.stores[0]
        .load_latest()
        .await
        .unwrap()
        .unwrap()
        .record
        .tx_id;
    cluster.shutdown().await;

    let received = control.received.lock().unwrap();
    assert_eq!(
        received[1].offset, 0,
        "an unchanged retry triggers fresh discovery"
    );
    assert_eq!(received[0].vote, received[1].vote);
    assert_eq!(received[0].meta, received[1].meta);
    assert_eq!(
        rediscovered_checkpoint, checkpoint,
        "matching discovery must retain the same staging file and verified bytes"
    );
    assert!(received.iter().any(|chunk| chunk.offset == 128 * 1024));
    assert_eq!(recovered, tx);
    assert!(staged_repair_bytes(&snapshots).is_empty());
}

#[tokio::test]
async fn repair_download_makes_progress_across_bounded_initialize_attempts() {
    let mut cluster =
        ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedIncarnations)
            .await;
    let (a, b, c) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster()
    );
    a.unwrap();
    b.unwrap();
    c.unwrap();
    cluster.wait_ready().await;
    let tx = TxId::new();
    cluster.stores[cluster.leader()]
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x43; 16]),
            large_attested(tx),
        )
        .await
        .unwrap();
    cluster.stores[0].shutdown().await.unwrap();

    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            *peer.handler.write().await = None;
        }
    }
    let prepared = retained_incarnations::prepare(&cluster, 0).await;
    let local = retained_incarnations::member(1, 2).identity.node_id();
    let options = retained_incarnations::options(
        &cluster._directory.path().join("bounded-repair.sqlite"),
        prepared.clone(),
        local,
        10,
    );
    let backend = SqliteBackend::provision_config_member_repair(options.clone(), audit_key())
        .await
        .unwrap();
    let control = Arc::new(RepairControl::default());
    let resolver = repair_resolver(&cluster, 0, &control);
    let snapshots = cluster._directory.path().join("bounded-repair-snapshots");
    cluster.stores[0] = ConsensusConfigStore::open_with_voter_slots_and_operation_timeout(
        prepared.clone(),
        local,
        backend,
        &snapshots,
        resolver.clone(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            peer.install_incarnation(local, cluster.stores[0].rpc_handler())
                .await;
        }
    }
    let mut previous_bytes = 0;
    let mut completed = false;
    for attempt in 0..16 {
        let chunks_before = control.chunks.load(Ordering::SeqCst);
        control
            .chunk_limit
            .store(chunks_before + 1, Ordering::SeqCst);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            cluster.stores[0].initialize_cluster(),
        )
        .await
        .expect("each initialization keeps its original bounded deadline");
        if result.is_ok() {
            assert!(attempt > 0, "snapshot needs more than one admitted chunk");
            completed = true;
            break;
        }
        assert!(!cluster.stores[0].status().admitted);
        assert!(
            cluster.stores[0].status().applied_index.is_none(),
            "unfinished attempt {attempt}: result={result:?}, status={:?}, replacement={:?}",
            cluster.stores[0].status(),
            cluster.stores[0].voter_slot_state().await.map(|state| state
                .table()
                .replacement
                .as_ref()
                .map(|operation| operation.phase)),
        );
        assert_eq!(
            control.chunks.load(Ordering::SeqCst),
            chunks_before + 1,
            "a real snapshot chunk arrived before the bounded attempt ended"
        );
        let incoming = std::fs::read_dir(&snapshots)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("incoming-"))
            .collect::<Vec<_>>();
        assert_eq!(incoming.len(), 1, "deadline retains the partial download");
        let bytes = incoming[0].metadata().unwrap().len();
        assert!(
            bytes > previous_bytes,
            "retry advances instead of restarting"
        );
        previous_bytes = bytes;
        if attempt == 0 {
            // Cancel a resumed attempt, after it has taken the checkpoint.
            control.blocked.notified().await;
            let recovering = cluster.stores[0].clone();
            let resumed = tokio::spawn(async move { recovering.initialize_cluster().await });
            tokio::time::timeout(Duration::from_secs(2), control.blocked.notified())
                .await
                .expect("resumed attempt reached the paused next chunk");
            resumed.abort();
            assert!(resumed.await.unwrap_err().is_cancelled());
            assert!(std::fs::read_dir(&snapshots).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("incoming-")));
            previous_bytes = 0;
        } else if attempt == 1 {
            // A saved download must not outlive shutdown, even while another
            // store clone still exists. Reopen retries from its empty root.
            cluster.stores[0].shutdown().await.unwrap();
            assert!(std::fs::read_dir(&snapshots).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("incoming-")));
            for ((_, target), peer) in &cluster.paths {
                if *target == 0 {
                    *peer.handler.write().await = None;
                }
            }
            drop(cluster.stores.remove(0));
            let backend = SqliteBackend::reopen_config_authority(options.clone(), audit_key())
                .await
                .unwrap();
            let reopened = ConsensusConfigStore::open_with_voter_slots_and_operation_timeout(
                prepared.clone(),
                local,
                backend,
                &snapshots,
                resolver.clone(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            for ((_, target), peer) in &cluster.paths {
                if *target == 0 {
                    peer.install_incarnation(local, reopened.rpc_handler())
                        .await;
                }
            }
            cluster.stores.insert(0, reopened);
            previous_bytes = 0;
        }
    }
    assert!(
        completed,
        "finite snapshot completes across bounded retries"
    );
    assert_eq!(
        cluster.stores[0]
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .record
            .tx_id,
        tx
    );
    cluster.shutdown().await;
}

fn large_attested(tx: TxId) -> AttestedConfigCommit {
    let mut record = commit(tx, None, 1, 0x41);
    let aad = EnvelopeAad::config(
        opc_types::TenantId::from_static("tenant-a"),
        record.version.get(),
        ConfigAad::new(
            tx,
            None,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            "running",
        )
        .unwrap(),
    );
    let handle = KeyHandle::new(
        KeyId::new("repair-snapshot-key").unwrap(),
        KeyPurpose::Config,
        opc_types::TenantId::from_static("tenant-a"),
        Zeroizing::new([0x41; AES_256_GCM_SIV_KEY_LEN]),
    );
    let plaintext = vec![0x41; 256 * 1024];
    let envelope = encrypt_attested_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        &plaintext,
        [0x41; AES_256_GCM_SIV_NONCE_LEN],
    )
    .unwrap();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    record.encrypted_blob = envelope.encoded().to_vec();
    AttestedConfigCommit::try_new(record, audit(tx), envelope.claim().unwrap()).unwrap()
}

#[tokio::test]
async fn cancelled_repair_requires_fresh_quorum_then_reopens_with_a_majority() {
    let mut cluster =
        ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedIncarnations)
            .await;
    let (a, b, c) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster()
    );
    a.unwrap();
    b.unwrap();
    c.unwrap();
    cluster.wait_ready().await;
    let first = TxId::new();
    cluster.stores[cluster.leader()]
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x41; 16]),
            large_attested(first),
        )
        .await
        .unwrap();
    cluster.stores[0].shutdown().await.unwrap();
    let leader = cluster.leader();
    assert_ne!(leader, 0);
    cluster.stores[leader].trigger_snapshot().await.unwrap();

    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            *peer.handler.write().await = None;
        }
    }
    let prepared = retained_incarnations::prepare(&cluster, 0).await;
    let local = retained_incarnations::member(1, 2).identity.node_id();
    let options = retained_incarnations::options(
        &cluster._directory.path().join("repair.sqlite"),
        prepared.clone(),
        local,
        9,
    );
    let backend = SqliteBackend::provision_config_member_repair(options.clone(), audit_key())
        .await
        .unwrap();
    let control = Arc::new(RepairControl::default());
    control
        .pause_after_first_chunk
        .store(true, Ordering::SeqCst);
    let resolver = repair_resolver(&cluster, 0, &control);
    let snapshots = cluster._directory.path().join("repair-snapshots");
    cluster.stores[0] = ConsensusConfigStore::open_with_voter_slots(
        prepared.clone(),
        local,
        backend,
        &snapshots,
        resolver.clone(),
    )
    .await
    .unwrap();
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            peer.install_incarnation(local, cluster.stores[0].rpc_handler())
                .await;
        }
    }
    let recovering = cluster.stores[0].clone();
    let attempt = tokio::spawn(async move { recovering.initialize_cluster().await });
    tokio::time::timeout(
        opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        control.blocked.notified(),
    )
    .await
    .expect("second chunk reached after a real partial download");
    assert_eq!(control.chunks.load(Ordering::SeqCst), 1);
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());
    assert!(!cluster.stores[0].status().admitted);
    assert!(cluster.stores[0].status().applied_index.is_none());
    assert!(
        std::fs::read_dir(&snapshots).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("incoming-")),
        "cancelled download removes its staging file"
    );

    let second = TxId::new();
    let record = commit(second, Some(first), 2, 0x42);
    let audit = audit(second);
    let request_id = ConfigConsensusRequestId::from_bytes([0x42; 16]);
    cluster.stores[leader]
        .append_commit_idempotent(request_id, attested(record.clone(), audit.clone()))
        .await
        .expect("surviving quorum writes while replacement remains gated");
    let other = (1..3).find(|index| *index != leader).unwrap();
    cluster.isolate(other);
    control
        .pause_after_first_chunk
        .store(false, Ordering::SeqCst);
    let chunks_before = control.chunks.load(Ordering::SeqCst);
    assert!(
        cluster.stores[0].initialize_cluster().await.is_err(),
        "an old snapshot and the empty replacement cannot substitute for the surviving quorum"
    );
    assert_eq!(
        control.chunks.load(Ordering::SeqCst),
        chunks_before,
        "no chunk is authorized by a stale leader observation"
    );
    assert!(!cluster.stores[0].status().admitted);
    assert!(cluster.stores[0].status().applied_index.is_none());
    for ((source, target), peer) in &cluster.paths {
        if *source == other || *target == other {
            peer.set_enabled(true);
        }
    }
    cluster.stores[0]
        .initialize_cluster()
        .await
        .expect("same-store recovery retry");
    cluster.wait_ready().await;
    assert!(
        control.chunks.load(Ordering::SeqCst) > 2,
        "restored a multi-chunk snapshot"
    );
    assert_eq!(
        cluster.stores[0]
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .record
            .tx_id,
        second,
        "fresh snapshot covers writes accepted after the cancelled download"
    );
    cluster.stores[0]
        .append_commit_idempotent(request_id, attested(record.clone(), audit.clone()))
        .await
        .expect("snapshot preserves exact request replay");

    cluster.stores[0].shutdown().await.unwrap();
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            *peer.handler.write().await = None;
        }
    }
    // Drop the final closed store before reacquiring the retained lock.
    let old = cluster.stores.remove(0);
    drop(old);
    let backend = SqliteBackend::reopen_config_authority(options, audit_key())
        .await
        .unwrap();
    let restored =
        ConsensusConfigStore::open_with_voter_slots(prepared, local, backend, snapshots, resolver)
            .await
            .unwrap();
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            peer.install_incarnation(local, restored.rpc_handler())
                .await;
        }
    }
    cluster.stores.insert(0, restored);
    let leader = cluster.leader();
    assert_ne!(leader, 0);
    let other = (1..3).find(|index| *index != leader).unwrap();
    cluster.isolate(other);
    let repair_calls = control.calls.load(Ordering::SeqCst);
    cluster.stores[0]
        .initialize_cluster()
        .await
        .expect("durably repaired voter rejoins with itself and one survivor");
    assert_eq!(
        control.calls.load(Ordering::SeqCst),
        repair_calls,
        "ordinary retained restart does not repeat empty-root repair"
    );
    assert_eq!(
        cluster.stores[0]
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .record
            .tx_id,
        second
    );
    cluster.shutdown().await;
}
