use super::*;

#[derive(Clone, Copy)]
enum Protocol {
    Current,
    Legacy,
    Incompatible,
}

fn different_profile(
    mut profile: opc_consensus::ConsensusCompatibility,
) -> opc_consensus::ConsensusCompatibility {
    profile[0] ^= 1;
    profile
}

// Model a build with another connection profile while retaining the real
// durable store. Both sides of that process offer the changed digest.
#[derive(Debug)]
struct IncompatiblePeer(Arc<LoopbackPeer>);
#[async_trait]
impl ConsensusPeer for IncompatiblePeer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.0.node_id()
    }
    fn with_compatibility(
        &self,
        profile: opc_consensus::ConsensusCompatibility,
    ) -> Option<Arc<dyn ConsensusPeer>> {
        self.0.with_compatibility(different_profile(profile))
    }
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.0.call(request).await
    }
}

#[derive(Debug)]
struct IncompatibleHandler(Arc<dyn ConsensusRpcHandler>);
#[async_trait]
impl ConsensusRpcHandler for IncompatibleHandler {
    fn compatibility(&self) -> Option<opc_consensus::ConsensusCompatibility> {
        self.0.compatibility().map(different_profile)
    }
    async fn handle(
        &self,
        sender: ConfigConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        self.0.handle(sender, request).await
    }
}

// Preserve the old transport port and the old inbound engine dispatch. This
// fixture deliberately does not advertise the new connection extension.
#[derive(Debug)]
struct LegacyPeer(Arc<LoopbackPeer>);
#[async_trait]
impl ConsensusPeer for LegacyPeer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.0.node_id()
    }
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.0.call(request).await
    }
}

#[derive(Debug)]
struct LegacyHandler(Arc<dyn ConsensusRpcHandler>);
#[async_trait]
impl ConsensusRpcHandler for LegacyHandler {
    async fn handle(
        &self,
        sender: ConfigConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        // Pre-extension receivers dispatched engine requests after scope and
        // sender validation. Retain that behavior while using the real engine.
        self.0
            .handle_with_compatibility(sender, request, self.0.compatibility())
            .await
    }
}

struct RetainedFleet {
    directory: tempfile::TempDir,
    identity: ConfigConsensusIdentity,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
    stores: Vec<Option<ConsensusConfigStore>>,
    head: TxId,
    version: u64,
}

impl RetainedFleet {
    async fn start() -> Self {
        let cluster =
            ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedNew)
                .await;
        let (one, two, three) = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster()
        );
        one.expect("initial first voter");
        two.expect("initial second voter");
        three.expect("initial third voter");
        let first = TxId::new();
        cluster.stores[0]
            .append_attested_commit(attested(commit(first, None, 1, 1), audit(first)))
            .await
            .expect("initial retained history");
        let fleet = Self {
            directory: cluster._directory,
            identity: cluster.identity,
            paths: cluster.paths,
            stores: cluster.stores.into_iter().map(Some).collect(),
            head: first,
            version: 1,
        };
        fleet.assert_reads(&[0, 1, 2]).await;
        fleet
    }

    fn store(&self, index: usize) -> &ConsensusConfigStore {
        self.stores[index].as_ref().expect("running voter")
    }

    fn topology(&self, index: usize) -> ConfigConsensusTopology {
        let nodes = [1, 2, 3].map(|id| ConfigConsensusNodeId::new(id).unwrap());
        ConfigConsensusTopology::try_new(self.identity, nodes[index], nodes.into_iter().collect())
            .unwrap()
    }

    fn options(&self, index: usize) -> RetainedConfigOptions {
        retained_options(
            &self.directory.path().join(format!("node-{index}.sqlite")),
            self.topology(index),
            index as u8 + 1,
        )
    }

    async fn stop(&mut self, index: usize) {
        if let Some(store) = self.stores[index].take() {
            store.shutdown().await.expect("join retained engine");
            for ((_, target), peer) in &self.paths {
                if *target == index {
                    *peer.handler.write().await = None;
                }
            }
            drop(store);
        }
    }

    async fn stop_all(&mut self) {
        for index in 0..3 {
            self.stop(index).await;
        }
    }

    async fn open(&mut self, index: usize, protocol: Protocol, timeout: Duration) {
        assert!(self.stores[index].is_none());
        let backend = SqliteBackend::reopen_config_authority(self.options(index), audit_key())
            .await
            .expect("same retained store");
        let peers = (0..3)
            .filter(|target| *target != index)
            .map(|target| {
                let path = self.paths[&(index, target)].clone();
                let peer: Arc<dyn ConsensusPeer> = match protocol {
                    Protocol::Current => path,
                    Protocol::Legacy => Arc::new(LegacyPeer(path)),
                    Protocol::Incompatible => Arc::new(IncompatiblePeer(path)),
                };
                (peer.node_id(), peer)
            })
            .collect();
        let store = ConsensusConfigStore::open_with_operation_timeout(
            self.topology(index),
            backend,
            self.directory.path().join(format!("snapshots-{index}")),
            peers,
            timeout,
        )
        .await
        .expect("returning store");
        let handler: Arc<dyn ConsensusRpcHandler> = match protocol {
            Protocol::Current => store.rpc_handler(),
            Protocol::Legacy => Arc::new(LegacyHandler(store.rpc_handler())),
            Protocol::Incompatible => Arc::new(IncompatibleHandler(store.rpc_handler())),
        };
        for ((_, target), peer) in &self.paths {
            if *target == index {
                peer.install(handler.clone()).await;
            }
        }
        self.stores[index] = Some(store);
    }

    async fn admit(&self, indices: &[usize]) {
        for &index in indices {
            self.store(index)
                .initialize_cluster()
                .await
                .expect("admit returning voter");
        }
    }

    async fn assert_reads(&self, indices: &[usize]) {
        for &index in indices {
            assert_eq!(
                self.store(index)
                    .load_latest()
                    .await
                    .expect("linearizable read")
                    .expect("head")
                    .record
                    .tx_id,
                self.head
            );
        }
    }

    async fn append(&mut self, index: usize) {
        let next = TxId::new();
        self.store(index)
            .append_attested_commit(attested(
                commit(next, Some(self.head), self.version + 1, 2),
                audit(next),
            ))
            .await
            .unwrap_or_else(|error| {
                let states = self.stores.iter().map(|store| store.as_ref().map(ConsensusConfigStore::status)).collect::<Vec<_>>();
                panic!("linearizable quorum write from voter {index} after version {}: {error:?}; states={states:?}", self.version);
            });
        self.head = next;
        self.version += 1;
    }
}

#[tokio::test]
async fn retained_majority_reopens_without_the_third_voter() {
    let mut fleet = RetainedFleet::start().await;
    fleet.stop_all().await;
    for index in [0, 1] {
        fleet
            .open(index, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
            .await;
    }
    fleet.admit(&[0, 1]).await;
    fleet.assert_reads(&[0, 1]).await;
    fleet.append(1).await;
    fleet.assert_reads(&[0, 1]).await;
    // The third member still has the older retained history. It must verify
    // its new connections and catch up before its linearizable read succeeds.
    fleet
        .open(2, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    fleet.admit(&[2]).await;
    fleet.assert_reads(&[0, 1, 2]).await;
    fleet.append(2).await;
    fleet.assert_reads(&[0, 1, 2]).await;
    fleet.stop_all().await;
}

#[tokio::test]
async fn lone_retained_voter_retries_admission_without_restarting() {
    let mut fleet = RetainedFleet::start().await;
    fleet.stop_all().await;
    fleet
        .open(0, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    let error = fleet
        .store(0)
        .initialize_cluster()
        .await
        .expect_err("one voter is not a quorum");
    assert_eq!(
        error,
        opc_persist::ConfigConsensusOpenError::CompatibleQuorumUnavailable
    );
    assert_eq!(
        error.to_string(),
        "config consensus compatible voter quorum is unavailable"
    );
    assert!(!fleet.store(0).status().admitted);
    assert!(fleet.store(0).load_latest().await.is_err());
    assert!(fleet.store(0).load_committed_latest().await.is_err());
    fleet
        .open(1, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    fleet.admit(&[0, 1]).await;
    // Either store may lead and cap a forwarded request. Both keep the normal
    // operation bound, and the first store was never replaced.
    fleet.append(1).await;
    fleet.assert_reads(&[0, 1]).await;
    fleet.stop_all().await;
}

#[tokio::test]
async fn incompatible_retained_key_scope_is_refused_while_the_majority_serves() {
    let mut fleet = RetainedFleet::start().await;
    fleet.stop_all().await;
    for index in [0, 1] {
        fleet
            .open(index, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
            .await;
    }
    fleet.admit(&[0, 1]).await;
    assert!(SqliteBackend::reopen_config_authority(
        fleet.options(2),
        AuditKey::new([0x56; 32]).unwrap()
    )
    .await
    .is_err());
    fleet.append(1).await;
    fleet.assert_reads(&[0, 1]).await;
    fleet.stop_all().await;
}

#[tokio::test]
async fn incompatible_returning_connection_is_refused_while_the_majority_serves() {
    let mut fleet = RetainedFleet::start().await;
    fleet.stop_all().await;
    for index in [0, 1] {
        fleet
            .open(index, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
            .await;
    }
    fleet.admit(&[0, 1]).await;
    fleet
        .open(2, Protocol::Incompatible, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    assert_eq!(
        fleet.store(2).initialize_cluster().await,
        Err(opc_persist::ConfigConsensusOpenError::ClusterFormationRejected)
    );
    assert!(!fleet.store(2).status().admitted);
    assert!(fleet.store(2).load_latest().await.is_err());
    assert!(fleet.store(2).load_committed_latest().await.is_err());
    fleet.append(0).await;
    fleet.assert_reads(&[0, 1]).await;
    fleet.stop(2).await;
    fleet
        .open(2, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    fleet.admit(&[2]).await;
    fleet.assert_reads(&[0, 1, 2]).await;
    fleet.stop_all().await;
}

#[tokio::test]
async fn mixed_voters_roll_in_both_directions_and_legacy_never_counts_as_verified() {
    let mut fleet = RetainedFleet::start().await;
    fleet.stop_all().await;
    for index in 0..3 {
        fleet
            .open(index, Protocol::Legacy, CLUSTER_TRANSITION_TIMEOUT)
            .await;
    }
    fleet.admit(&[0, 1, 2]).await;
    // Each stopping voter leaves a serving quorum, including a leader stop.
    // This visits 1-new/2-old and 2-new/1-old in both directions.
    for (index, protocol) in [
        (0, Protocol::Current),
        (1, Protocol::Current),
        (2, Protocol::Current),
        (2, Protocol::Legacy),
        (1, Protocol::Legacy),
        (0, Protocol::Legacy),
    ] {
        fleet.stop(index).await;
        let live = (0..3).filter(|node| *node != index).collect::<Vec<_>>();
        fleet.append(live[0]).await;
        fleet.assert_reads(&live).await;
        fleet
            .open(index, protocol, CLUSTER_TRANSITION_TIMEOUT)
            .await;
        fleet.admit(&[index]).await;
        fleet.append(index).await;
        fleet.assert_reads(&[0, 1, 2]).await;
    }
    fleet.stop_all().await;
    // With only one new and one old voter back, neither has a verified
    // majority; both need the third member for the old all-peer fallback.
    fleet
        .open(0, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    fleet
        .open(1, Protocol::Legacy, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    for index in [0, 1] {
        assert_eq!(
            fleet.store(index).initialize_cluster().await,
            Err(opc_persist::ConfigConsensusOpenError::CompatibleQuorumUnavailable)
        );
        assert!(!fleet.store(index).status().admitted);
    }
    fleet
        .open(2, Protocol::Legacy, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    fleet.admit(&[0, 1, 2]).await;
    fleet.append(2).await;
    fleet.assert_reads(&[0, 1, 2]).await;
    fleet.stop_all().await;
    // Two new voters can recover while an old third member is absent.
    for index in [0, 1] {
        fleet
            .open(index, Protocol::Current, CLUSTER_TRANSITION_TIMEOUT)
            .await;
    }
    fleet.admit(&[0, 1]).await;
    fleet.append(0).await;
    fleet.assert_reads(&[0, 1]).await;
    fleet
        .open(2, Protocol::Legacy, CLUSTER_TRANSITION_TIMEOUT)
        .await;
    fleet.admit(&[2]).await;
    fleet.assert_reads(&[0, 1, 2]).await;
    // After the old voter joins, taking a current voter down must leave the
    // admitted current/legacy majority serving without another all-peer gate.
    fleet.stop(1).await;
    fleet.append(0).await;
    fleet.assert_reads(&[0, 2]).await;
    fleet.stop_all().await;
}

#[tokio::test]
async fn incompatible_unadmitted_voter_cannot_reach_any_engine_family() {
    use opc_consensus::engine::{
        raft::VoteRequest, EmptyNode, LogId, SnapshotMeta, StoredMembership, Vote,
    };
    use serde::Serialize;

    #[derive(Serialize)]
    struct Wire<T> {
        revision: u16,
        value: T,
    }

    #[derive(Serialize)]
    struct Probe {
        // The existing config probe's exact postcard field order.
        compatibility: (u16, u16, u64, [u8; 32]),
        compatibility_probe: bool,
        budget: u64,
    }

    let cluster = ThreeNodeCluster::build_with_storage(
        [[0x55; 32], [0x55; 32], [0x56; 32]],
        FixtureStorage::RetainedNew,
    )
    .await;
    let sender = cluster.stores[2].status();
    assert!(!sender.admitted);
    assert_ne!(
        sender.audit_key_fingerprint,
        cluster.stores[0].status().audit_key_fingerprint
    );
    let handler = cluster.stores[0].rpc_handler();
    let probe = Wire {
        revision: opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
        value: Probe {
            compatibility: (
                opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
                opc_persist::CONFIG_CONSENSUS_COMMAND_VERSION,
                sender.audit_key_epoch,
                sender.audit_key_fingerprint,
            ),
            compatibility_probe: true,
            budget: 1_000_000_000,
        },
    };
    let probe = ConsensusWireRequest::try_new(
        cluster.identity,
        sender.node_id,
        ConsensusRpcFamily::ReadBarrier,
        opc_consensus::encode_bounded(&probe).expect("probe encoding"),
    )
    .expect("probe envelope");
    assert_eq!(
        handler.handle(sender.node_id, probe).await.result,
        Err(ConsensusPeerError::ScopeMismatch)
    );

    let vote = Wire {
        revision: opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
        value: VoteRequest {
            vote: Vote::new(42, sender.node_id),
            last_log_id: None,
        },
    };
    // Empty entry/chunk payloads retain the exact engine wire shape without
    // importing the private configuration command type.
    let append = Wire {
        revision: opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
        value: (
            Vote::new(43, sender.node_id),
            None::<LogId<ConfigConsensusNodeId>>,
            Vec::<u8>::new(),
            None::<LogId<ConfigConsensusNodeId>>,
        ),
    };
    let snapshot = Wire {
        revision: opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
        value: (
            Vote::new(44, sender.node_id),
            SnapshotMeta::<ConfigConsensusNodeId, EmptyNode> {
                last_log_id: None,
                last_membership: StoredMembership::default(),
                snapshot_id: "rejected-compatibility".into(),
            },
            0_u64,
            Vec::<u8>::new(),
            false,
        ),
    };
    let before = cluster.stores[0].status();
    for (family, payload) in [
        (
            ConsensusRpcFamily::Vote,
            opc_consensus::encode_bounded(&vote).unwrap(),
        ),
        (
            ConsensusRpcFamily::AppendEntries,
            opc_consensus::encode_bounded(&append).unwrap(),
        ),
        (
            ConsensusRpcFamily::InstallSnapshot,
            opc_consensus::encode_bounded(&snapshot).unwrap(),
        ),
    ] {
        let request =
            ConsensusWireRequest::try_new(cluster.identity, sender.node_id, family, payload)
                .unwrap();
        for proof in [None, Some([0; 32])] {
            let response = handler
                .handle_with_compatibility(sender.node_id, request.clone(), proof)
                .await;
            assert_eq!(
                response.result,
                Err(ConsensusPeerError::ScopeMismatch),
                "a rejected compatibility probe must not permit {family:?}"
            );
        }
        let after = cluster.stores[0].status();
        assert_eq!(after.term, before.term);
        assert_eq!(after.applied_index, before.applied_index);
        assert_eq!(after.committed_index, before.committed_index);
    }
    // Authentication of a local identity is not a compatibility grant either.
    let self_vote = Wire {
        revision: opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
        value: VoteRequest {
            vote: Vote::new(45, before.node_id),
            last_log_id: None,
        },
    };
    let self_vote = ConsensusWireRequest::try_new(
        cluster.identity,
        before.node_id,
        ConsensusRpcFamily::Vote,
        opc_consensus::encode_bounded(&self_vote).unwrap(),
    )
    .unwrap();
    assert_eq!(
        handler.handle(before.node_id, self_vote).await.result,
        Err(ConsensusPeerError::ScopeMismatch)
    );
    cluster.shutdown().await;
}
