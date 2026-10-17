use super::*;
use opc_consensus::engine::{
    error::RaftError,
    raft::{VoteRequest, VoteResponse},
    Vote,
};
use tokio::sync::watch;

type RecordedVote = (
    VoteRequest<ConfigConsensusNodeId>,
    VoteResponse<ConfigConsensusNodeId>,
);

/// Observe the real engine's request and its durable reply. The endpoint still
/// performs the same authenticated sender and compatibility checks as the fleet.
#[derive(Clone, Debug)]
struct RecordingPeer {
    endpoint: Arc<dyn ConsensusPeer>,
    votes: watch::Sender<Vec<RecordedVote>>,
}

#[async_trait]
impl ConsensusPeer for RecordingPeer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.endpoint.node_id()
    }

    fn with_compatibility(
        &self,
        compatibility: opc_consensus::ConsensusCompatibility,
    ) -> Option<Arc<dyn ConsensusPeer>> {
        Some(Arc::new(Self {
            endpoint: self.endpoint.with_compatibility(compatibility)?,
            votes: self.votes.clone(),
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
        let vote = (request.family == ConsensusRpcFamily::Vote).then(|| {
            let (_, vote): (u16, VoteRequest<ConfigConsensusNodeId>) =
                opc_consensus::decode_bounded(&request.payload).expect("engine vote request");
            vote
        });
        let reply = self
            .endpoint
            .call_with_compatibility(request, required, timeout)
            .await?;
        if let Some(vote) = vote {
            if let Ok(payload) = &reply.response.result {
                let (_, response): (
                    u16,
                    Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
                ) = opc_consensus::decode_bounded(payload).expect("engine vote response");
                if let Ok(response) = response {
                    self.votes.send_modify(|votes| votes.push((vote, response)));
                }
            }
        }
        Ok(reply)
    }
}

struct FiveVoterFleet {
    directory: tempfile::TempDir,
    identity: ConfigConsensusIdentity,
    nodes: [ConfigConsensusNodeId; 5],
    stores: Vec<ConsensusConfigStore>,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
    votes: BTreeMap<(usize, usize), watch::Sender<Vec<RecordedVote>>>,
}

impl FiveVoterFleet {
    async fn start() -> Self {
        let directory = tempfile::tempdir().expect("five-voter storage");
        let nodes = [1, 2, 3, 4, 5].map(|node| ConfigConsensusNodeId::new(node).unwrap());
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("five-voter-lost-vote-test").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0x93; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let mut paths = BTreeMap::new();
        let mut votes = BTreeMap::new();
        for source in 0..5 {
            for (target, node) in nodes.iter().copied().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(LoopbackPeer::new(node)));
                    votes.insert((source, target), watch::channel(Vec::new()).0);
                }
            }
        }
        let mut stores = Vec::new();
        for (index, node) in nodes.iter().copied().enumerate() {
            let topology =
                ConfigConsensusTopology::try_new(identity, node, nodes.into_iter().collect())
                    .expect("five-voter topology");
            let backend = SqliteBackend::provision_config_authority(
                retained_options(
                    &directory.path().join(format!("node-{index}.sqlite")),
                    topology.clone(),
                    index as u8 + 1,
                ),
                audit_key(),
            )
            .await
            .expect("retained voter");
            let peers = (0..5)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn ConsensusPeer> = Arc::new(RecordingPeer {
                        endpoint: paths[&(index, target)].clone(),
                        votes: votes[&(index, target)].clone(),
                    });
                    (nodes[target], peer)
                })
                .collect();
            let store = ConsensusConfigStore::open_with_operation_timeout(
                topology,
                backend,
                directory.path().join(format!("snapshots-{index}")),
                peers,
                Duration::from_secs(3),
            )
            .await
            .expect("five-voter store");
            store.disable_automatic_elections_for_test();
            stores.push(store);
        }
        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }
        let results = tokio::join!(
            stores[0].initialize_cluster(),
            stores[1].initialize_cluster(),
            stores[2].initialize_cluster(),
            stores[3].initialize_cluster(),
            stores[4].initialize_cluster(),
        );
        results.0.expect("initialize voter 1");
        results.1.expect("initialize voter 2");
        results.2.expect("initialize voter 3");
        results.3.expect("initialize voter 4");
        results.4.expect("initialize voter 5");
        let tx = TxId::new();
        stores[0]
            .append_attested_commit(attested(commit(tx, None, 1, 1), audit(tx)))
            .await
            .expect("commit common prefix");
        for store in &stores {
            store
                .wait_for_committed_change(ConfigVersion::INITIAL)
                .await
                .expect("every voter applies the common prefix");
            assert_eq!(store.status().leader_id, Some(nodes[0]));
        }
        Self {
            directory,
            identity,
            nodes,
            stores,
            paths,
            votes,
        }
    }

    fn partition(&self) {
        for ((source, target), path) in &self.paths {
            path.set_enabled((*source < 3) == (*target < 3));
        }
    }
}

fn persisted_vote(path: &std::path::Path) -> Vote<ConfigConsensusNodeId> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read durable vote");
    let encoded: Vec<u8> = connection
        .query_row(
            "SELECT vote_json FROM config_raft_vote WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("persisted vote row");
    serde_json::from_slice(&encoded).expect("persisted vote encoding")
}

#[tokio::test]
async fn lost_vote_repair_never_grants_a_second_vote_under_the_same_identity() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fleet = FiveVoterFleet::start().await;
        let source_term = fleet.stores[0].status().term;
        fleet.partition();
        // Wait for the engine's actual lease boundary. No randomized campaign,
        // guessed sleep, synthetic term advance, or paused storage clock is used.
        let (candidate, voter) = tokio::join!(
            fleet.stores[3].wait_for_vote_lease_expiry_for_test(),
            fleet.stores[4].wait_for_vote_lease_expiry_for_test(),
        );
        candidate.expect("candidate's old lease expires");
        voter.expect("voter's old lease expires");
        fleet.stores[3]
            .trigger_election_for_test()
            .await
            .expect("candidate 4 starts a real campaign");
        let first = fleet.votes[&(3, 4)]
            .subscribe()
            .wait_for(|votes| votes.iter().any(|(_, response)| response.vote_granted))
            .await
            .expect("voter 5 replies")
            .iter()
            .find(|(_, response)| response.vote_granted)
            .cloned()
            .expect("record original grant");
        assert_eq!(first.0.vote, Vote::new(source_term + 1, fleet.nodes[3]));
        assert_eq!(first.1.vote, first.0.vote);
        assert_eq!(
            first.0.last_log_id.map(|log| log.index),
            fleet.stores[2].status().applied_index,
            "candidate 3 has the same committed log as candidate 4",
        );
        assert_eq!(fleet.stores[3].status().leader_id, None);
        assert_eq!(fleet.stores[4].status().leader_id, None);
        let original_path = fleet.directory.path().join("node-4.sqlite");
        assert_eq!(persisted_vote(&original_path), first.0.vote);

        fleet.stores[0]
            .probe_durable_readiness()
            .await
            .expect("source proves a fresh quorum consisting only of voters 1, 2, 3");
        for store in &fleet.stores[..3] {
            assert_eq!(store.status().term, source_term);
            assert_eq!(store.status().leader_id, Some(fleet.nodes[0]));
        }

        // Candidate 3 has the same committed prefix, but a distinct candidate
        // ID in the exact unfinished term whose original grant will be lost.
        let second_vote = VoteRequest {
            vote: Vote::new(first.0.vote.leader_id.term, fleet.nodes[2]),
            last_log_id: first.0.last_log_id,
        };
        let payload = opc_consensus::encode_bounded(&(
            opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
            &second_vote,
        ))
        .expect("second candidate vote payload");
        let request = ConsensusWireRequest::try_new(
            fleet.identity,
            fleet.nodes[2],
            ConsensusRpcFamily::Vote,
            payload,
        )
        .expect("second authenticated candidate");
        let compatibility = fleet.stores[2].rpc_handler().compatibility().unwrap();
        let endpoint = &fleet.paths[&(2, 4)];
        endpoint.set_enabled(true);
        let control = endpoint
            .with_compatibility(compatibility)
            .expect("bound original endpoint")
            .call_with_compatibility(request.clone(), Some(compatibility), Duration::from_secs(3))
            .await
            .expect("deliver control request to the original voter");
        let (_, control): (
            u16,
            Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(control.response.result.as_ref().expect("control reply"))
            .expect("control vote encoding");
        let control = control.expect("control vote response");
        assert!(
            !control.vote_granted,
            "retained vote rejects a second candidate"
        );
        assert_eq!(control.vote, first.0.vote);
        endpoint.set_enabled(false);

        fleet.stores[4].shutdown().await.expect("lose voter 5");
        for ((_, target), peer) in &fleet.paths {
            if *target == 4 {
                *peer.handler.write().await = None;
            }
        }
        // The old volume is inaccessible to the replacement. Keep it only as
        // immutable test evidence of the vote that the repair cannot recover.
        let repair_path = fleet.directory.path().join("replacement.sqlite");
        let topology = ConfigConsensusTopology::try_new(
            fleet.identity,
            fleet.nodes[4],
            fleet.nodes.into_iter().collect(),
        )
        .expect("same-identity repair topology");
        let backend = SqliteBackend::provision_config_member_repair(
            retained_options(&repair_path, topology.clone(), 9),
            audit_key(),
        )
        .await
        .expect("provision the existing repair path");
        let peers = (0..4)
            .map(|target| {
                let peer: Arc<dyn ConsensusPeer> = fleet.paths[&(4, target)].clone();
                (fleet.nodes[target], peer)
            })
            .collect();
        let replacement = ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend,
            fleet.directory.path().join("replacement-snapshots"),
            peers,
            Duration::from_secs(30),
        )
        .await
        .expect("open the existing repair path");
        replacement.disable_automatic_elections_for_test();
        assert!(!replacement.status().admitted);
        endpoint.install(replacement.rpc_handler()).await;
        endpoint.set_enabled(true);
        let response = endpoint
            .with_compatibility(compatibility)
            .expect("bound candidate endpoint")
            .call_with_compatibility(request, Some(compatibility), Duration::from_secs(3))
            .await
            .expect("deliver second candidate's vote request");
        let second_granted = response.response.result.as_ref().is_ok_and(|payload| {
            let (_, vote): (
                u16,
                Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
            ) = opc_consensus::decode_bounded(payload).expect("second engine response");
            vote.is_ok_and(|vote| vote.vote_granted && vote.vote == second_vote.vote)
        });
        if second_granted {
            assert_eq!(persisted_vote(&repair_path), second_vote.vote);
        }
        assert_eq!(persisted_vote(&original_path), first.0.vote);
        replacement.shutdown().await.expect("stop replacement");
        for store in &fleet.stores[..4] {
            store.shutdown().await.expect("stop surviving voter");
        }
        assert!(
            !second_granted,
            "identity 5 durably granted candidate 4 and candidate 3 votes in term {}; \
             a voter with lost vote state must be replaced under a new identity",
            first.0.vote.leader_id.term,
        );
    })
    .await
    .expect("five-voter lost-vote regression stays within the existing repair bound");
}

#[tokio::test]
async fn completed_same_identity_repair_never_grants_a_second_vote() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fleet = FiveVoterFleet::start().await;
        let source_term = fleet.stores[0].status().term;
        fleet.partition();
        // Wait for the engine's actual lease boundary. No randomized campaign,
        // guessed sleep, synthetic term advance, or paused storage clock is used.
        let (candidate, voter) = tokio::join!(
            fleet.stores[3].wait_for_vote_lease_expiry_for_test(),
            fleet.stores[4].wait_for_vote_lease_expiry_for_test(),
        );
        candidate.expect("candidate's old lease expires");
        voter.expect("voter's old lease expires");
        fleet.stores[3]
            .trigger_election_for_test()
            .await
            .expect("candidate 4 starts a real campaign");
        let first = fleet.votes[&(3, 4)]
            .subscribe()
            .wait_for(|votes| votes.iter().any(|(_, response)| response.vote_granted))
            .await
            .expect("voter 5 replies")
            .iter()
            .find(|(_, response)| response.vote_granted)
            .cloned()
            .expect("record original grant");
        assert_eq!(first.0.vote, Vote::new(source_term + 1, fleet.nodes[3]));
        assert_eq!(first.1.vote, first.0.vote);
        assert_eq!(
            first.0.last_log_id.map(|log| log.index),
            fleet.stores[2].status().applied_index,
            "candidate 3 has the same committed log as candidate 4",
        );
        assert_eq!(fleet.stores[3].status().leader_id, None);
        assert_eq!(fleet.stores[4].status().leader_id, None);
        let original_path = fleet.directory.path().join("node-4.sqlite");
        assert_eq!(persisted_vote(&original_path), first.0.vote);

        fleet.stores[0]
            .probe_durable_readiness()
            .await
            .expect("source proves a fresh quorum consisting only of voters 1, 2, 3");
        for store in &fleet.stores[..3] {
            assert_eq!(store.status().term, source_term);
            assert_eq!(store.status().leader_id, Some(fleet.nodes[0]));
        }

        // Candidate 3 has the same committed prefix, but a distinct candidate
        // ID in the exact unfinished term whose original grant will be lost.
        let second_vote = VoteRequest {
            vote: Vote::new(first.0.vote.leader_id.term, fleet.nodes[2]),
            last_log_id: first.0.last_log_id,
        };
        let payload = opc_consensus::encode_bounded(&(
            opc_persist::CONFIG_CONSENSUS_WIRE_VERSION,
            &second_vote,
        ))
        .expect("second candidate vote payload");
        let request = ConsensusWireRequest::try_new(
            fleet.identity,
            fleet.nodes[2],
            ConsensusRpcFamily::Vote,
            payload,
        )
        .expect("second authenticated candidate");
        let compatibility = fleet.stores[2].rpc_handler().compatibility().unwrap();
        let endpoint = &fleet.paths[&(2, 4)];
        endpoint.set_enabled(true);
        let control = endpoint
            .with_compatibility(compatibility)
            .expect("bound original endpoint")
            .call_with_compatibility(request.clone(), Some(compatibility), Duration::from_secs(3))
            .await
            .expect("deliver control request to the original voter");
        let (_, control): (
            u16,
            Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
        ) = opc_consensus::decode_bounded(control.response.result.as_ref().expect("control reply"))
            .expect("control vote encoding");
        let control = control.expect("control vote response");
        assert!(
            !control.vote_granted,
            "retained vote rejects a second candidate"
        );
        assert_eq!(control.vote, first.0.vote);
        endpoint.set_enabled(false);

        fleet.stores[4].shutdown().await.expect("lose voter 5");
        for ((_, target), peer) in &fleet.paths {
            if *target == 4 {
                *peer.handler.write().await = None;
            }
        }
        // The old volume is inaccessible to the replacement. Keep it only as
        // immutable test evidence of the vote that the repair cannot recover.
        let repair_path = fleet.directory.path().join("replacement.sqlite");
        let topology = ConfigConsensusTopology::try_new(
            fleet.identity,
            fleet.nodes[4],
            fleet.nodes.into_iter().collect(),
        )
        .expect("same-identity repair topology");
        let backend = SqliteBackend::provision_config_member_repair(
            retained_options(&repair_path, topology.clone(), 9),
            audit_key(),
        )
        .await
        .expect("provision the existing repair path");
        let peers = (0..4)
            .map(|target| {
                let peer: Arc<dyn ConsensusPeer> = fleet.paths[&(4, target)].clone();
                (fleet.nodes[target], peer)
            })
            .collect();
        let replacement = ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend,
            fleet.directory.path().join("replacement-snapshots"),
            peers,
            Duration::from_secs(30),
        )
        .await
        .expect("open the existing repair path");
        replacement.disable_automatic_elections_for_test();
        assert!(!replacement.status().admitted);
        // Recover only from the lower-term quorum. No original volume or
        // candidate 4 response can reconstruct voter 5's lost unfinished vote.
        for ((source, target), peer) in &fleet.paths {
            if *target == 4 {
                peer.install(replacement.rpc_handler()).await;
                peer.set_enabled(false);
            } else if *source == 4 {
                peer.set_enabled(*target < 3);
            }
        }
        match replacement.initialize_cluster().await {
            Ok(()) => {
                replacement.disable_automatic_elections_for_test();
                assert!(replacement.status().admitted);
                assert_eq!(replacement.status().node_id, fleet.nodes[4]);
                assert_eq!(
                    replacement.status().applied_index,
                    first.0.last_log_id.map(|log| log.index)
                );
                let restored = persisted_vote(&repair_path);
                assert_eq!(restored, Vote::new_committed(source_term, fleet.nodes[0]));
                assert!(restored.leader_id.term < first.0.vote.leader_id.term);
                assert_eq!(persisted_vote(&original_path), first.0.vote);
                for store in &fleet.stores[..3] {
                    assert_eq!(store.status().term, source_term);
                    assert_eq!(store.status().leader_id, Some(fleet.nodes[0]));
                }
                // The restored leader lease only delays the conflicting vote.
                // Wait on the real engine boundary, without altering the term.
                replacement
                    .wait_for_vote_lease_expiry_for_test()
                    .await
                    .expect("restored lower-term leader lease expires");
            }
            Err(error) => {
                // A safe implementation can refuse legacy restoration, but a
                // timeout or fixture failure must never turn this test green.
                assert_eq!(
                    error.to_string(),
                    "config consensus repair requires a new voter identity",
                    "legacy recovery must complete or explicitly require replacement",
                );
                assert!(!replacement.status().admitted);
            }
        }
        endpoint.set_enabled(true);
        let response = endpoint
            .with_compatibility(compatibility)
            .expect("bound candidate endpoint")
            .call_with_compatibility(request, Some(compatibility), Duration::from_secs(3))
            .await
            .expect("deliver second candidate's vote request");
        let second_granted = response.response.result.as_ref().is_ok_and(|payload| {
            let (_, vote): (
                u16,
                Result<VoteResponse<ConfigConsensusNodeId>, RaftError<ConfigConsensusNodeId>>,
            ) = opc_consensus::decode_bounded(payload).expect("second engine response");
            vote.is_ok_and(|vote| vote.vote_granted && vote.vote == second_vote.vote)
        });
        if second_granted {
            assert_eq!(persisted_vote(&repair_path), second_vote.vote);
        }
        assert_eq!(persisted_vote(&original_path), first.0.vote);
        replacement.shutdown().await.expect("stop replacement");
        for store in &fleet.stores[..4] {
            store.shutdown().await.expect("stop surviving voter");
        }
        assert!(
            !second_granted,
            "identity 5 durably granted candidate 4 and candidate 3 votes in term {}; \
             a voter with lost vote state must be replaced under a new identity",
            first.0.vote.leader_id.term,
        );
    })
    .await
    .expect("completed five-voter repair regression stays within the existing repair bound");
}
