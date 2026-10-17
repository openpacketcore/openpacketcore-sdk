use super::*;
use opc_consensus::engine::raft::{AppendEntriesRequest, PreVoteRequest, VoteRequest};
use opc_consensus::engine::{CommittedLeaderId, Vote};

#[derive(Debug)]
struct UnavailablePeer(ConsensusNodeId);

#[async_trait]
impl ConsensusPeer for UnavailablePeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.0
    }

    async fn call(
        &self,
        _request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        Err(ConsensusPeerError::Unavailable)
    }
}

async fn empty_repair() -> (ConsensusConfigStore, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let nodes = [1, 2, 3].map(|id| ConsensusNodeId::new(id).unwrap());
    let identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::new("member-repair-admission").unwrap(),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x71; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, nodes[0], nodes.into_iter().collect()).unwrap();
    let options = crate::RetainedConfigOptions::new(
        directory.path().join("replacement.sqlite"),
        crate::RetainedConfigBinding::new(topology.clone(), [9; 32], [2; 32]).unwrap(),
        crate::RetainedConfigDurability::Ephemeral,
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    let backend = SqliteBackend::provision_config_member_repair(
        options,
        crate::AuditKey::new([0x55; 32]).unwrap(),
    )
    .await
    .unwrap();
    let peers = nodes[1..]
        .iter()
        .map(|node| {
            (
                *node,
                Arc::new(UnavailablePeer(*node)) as Arc<dyn ConsensusPeer>,
            )
        })
        .collect();
    let store =
        ConsensusConfigStore::open(topology, backend, directory.path().join("snapshots"), peers)
            .await
            .unwrap();
    (store, directory)
}

async fn assert_repair_rejects_engine_request(family: ConsensusRpcFamily, payload: Vec<u8>) {
    let (store, _directory) = empty_repair().await;
    let sender = ConsensusNodeId::new(2).unwrap();
    let before = store.status();
    let request =
        ConsensusWireRequest::try_new(store.inner.identity, sender, family, payload).unwrap();
    let response = store
        .rpc_handler()
        .handle_with_compatibility(sender, request, Some(store.inner.compatibility.digest()))
        .await;
    let after = store.status();
    store.shutdown().await.unwrap();
    assert_eq!(
        response.result,
        Err(ConsensusPeerError::Unavailable),
        "empty replacement must not expose the previous voter's lost log or vote"
    );
    assert_eq!(
        after.term, before.term,
        "unrecovered storage must not persist a vote"
    );
    assert_eq!(after.applied_index, None);
    assert!(!after.admitted);
}

#[tokio::test]
async fn empty_repair_cannot_vote_before_quorum_recovery() {
    let sender = ConsensusNodeId::new(2).unwrap();
    let request = VoteRequest {
        vote: Vote::new(7, sender),
        last_log_id: Some(LogId::new(CommittedLeaderId::new(6, sender), 3)),
    };
    assert_repair_rejects_engine_request(
        ConsensusRpcFamily::Vote,
        encode_config_wire(&request).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn empty_repair_cannot_pre_vote_before_quorum_recovery() {
    let sender = ConsensusNodeId::new(2).unwrap();
    let request = PreVoteRequest {
        vote: Vote::new(7, sender),
        last_log_id: Some(LogId::new(CommittedLeaderId::new(6, sender), 3)),
    };
    assert_repair_rejects_engine_request(
        ConsensusRpcFamily::PreVote,
        encode_config_wire(&request).unwrap(),
    )
    .await;
}

#[tokio::test]
async fn empty_repair_cannot_report_log_reversion_before_quorum_recovery() {
    let sender = ConsensusNodeId::new(2).unwrap();
    let request = AppendEntriesRequest::<ConfigRaftTypeConfig> {
        vote: Vote::new_committed(7, sender),
        prev_log_id: Some(LogId::new(CommittedLeaderId::new(6, sender), 3)),
        entries: vec![],
        leader_commit: None,
    };
    assert_repair_rejects_engine_request(
        ConsensusRpcFamily::AppendEntries,
        encode_config_wire(&request).unwrap(),
    )
    .await;
}
