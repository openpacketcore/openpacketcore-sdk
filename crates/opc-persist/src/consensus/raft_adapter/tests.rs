use std::future::Future;
use std::pin::{pin, Pin};
use std::str::FromStr;
use std::sync::Mutex;
use std::task::{Context, Waker};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusRequestId,
    DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use tokio::sync::Notify;

use super::*;
use crate::consensus::{
    ConfigConsensusCommand, ConfigMutationIntent, PreparedConfigCommit,
    CONFIG_CONSENSUS_COMMAND_VERSION,
};
use crate::{CommitRecord, CommitSource};

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        ConsensusClusterId::new("append-retirement-test").expect("cluster"),
        ConsensusConfigurationId::from_bytes([0x31; 32]),
        ConsensusConfigurationEpoch::new(1).expect("epoch"),
    )
}

fn node(value: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(value).expect("node")
}

fn log_id(index: u64) -> LogId<ConsensusNodeId> {
    LogId::new(CommittedLeaderId::new(1, node(1)), index)
}

fn append_request() -> AppendEntriesRequest<ConfigRaftTypeConfig> {
    let timestamp = Timestamp::from_str("2026-01-01T00:00:00Z").expect("timestamp");
    // This codec fixture owns a real Box, String and nonempty Vec payloads;
    // it is not submitted to a state machine or used as encryption evidence.
    let commit = PreparedConfigCommit {
        record: CommitRecord {
            tx_id: TxId::new(),
            parent_tx_id: None,
            version: ConfigVersion::new(1),
            committed_at: timestamp,
            principal: "spiffe://test.invalid/tenant/test/config".to_owned(),
            source: CommitSource::Gnmi,
            schema_digest: SchemaDigest::from_bytes([0x32; 32]),
            plaintext_digest: vec![0x33; 32],
            encrypted_blob: vec![0x34; 4096],
            rollback_point: false,
            confirmed_deadline: None,
        },
        audit: Vec::new(),
    };
    AppendEntriesRequest {
        vote: Vote::new_committed(1, node(1)),
        prev_log_id: Some(log_id(0)),
        entries: vec![Entry {
            log_id: log_id(1),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity: identity(),
                request_id: ConsensusRequestId::from_bytes([0x35; 16]),
                logical_time: timestamp,
                intent: ConfigMutationIntent::AppendCommit(Box::new(commit)),
            }),
        }],
        leader_commit: Some(log_id(0)),
    }
}

fn response() -> AppendEntriesResponse<ConsensusNodeId> {
    AppendEntriesResponse::PartialSuccess(Some(log_id(1)))
}

fn rpc_option() -> RPCOption {
    RPCOption::new(Duration::from_millis(
        DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
    ))
}

#[derive(Debug, Default)]
struct HeldAppendPeer {
    received: Mutex<Option<ConsensusWireRequest>>,
    release: Notify,
}

impl HeldAppendPeer {
    fn assert_received(&self, expected_payload: &[u8]) {
        let received = self.received.lock().expect("received request");
        let wire = received.as_ref().expect("peer call reached the IO hold");
        wire.validate().expect("valid wire request");
        assert_eq!(wire.identity, identity());
        assert_eq!(wire.sender, node(1));
        assert_eq!(wire.family, ConsensusRpcFamily::AppendEntries);
        assert_eq!(wire.payload, expected_payload);
    }
}

#[async_trait]
impl ConsensusPeer for HeldAppendPeer {
    fn node_id(&self) -> ConsensusNodeId {
        node(2)
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        assert!(self
            .received
            .lock()
            .expect("received request")
            .replace(request)
            .is_none());
        self.release.notified().await;
        let result: Result<_, RaftError<ConsensusNodeId>> = Ok(response());
        Ok(ConsensusWireResponse {
            result: Ok(encode_engine_result(&result).expect("encode response")),
        })
    }
}

async fn network(peer: Arc<HeldAppendPeer>) -> ConfigRaftNetwork {
    let peer: Arc<dyn ConsensusPeer> = peer;
    let mut factory =
        ConfigRaftNetworkFactory::try_new(identity(), node(1), BTreeMap::from([(node(2), peer)]))
            .expect("network factory");
    factory.new_client(node(2), &EmptyNode::new()).await
}

fn assert_pending(future: Pin<&mut impl Future>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}

#[tokio::test]
async fn append_retires_typed_payload_before_peer_io_completes() {
    let expected_payload = encode_config_wire(&append_request()).expect("encode fixture");
    let request = Arc::new(
        decode_config_wire::<AppendEntriesRequest<ConfigRaftTypeConfig>>(&expected_payload)
            .expect("decode independently owned typed payload"),
    );
    // Weak retains only the Arc backing allocation, not the live DTO or its
    // nested allocations. There is no separate drop token or retirement hook.
    let original_payload = Arc::downgrade(&request);
    assert_eq!(original_payload.strong_count(), 1);
    let peer = Arc::new(HeldAppendPeer::default());
    let network = network(peer.clone()).await;
    let mut append = pin!(network.append(request, rpc_option()));

    assert_pending(append.as_mut());
    peer.assert_received(&expected_payload);
    assert!(
        original_payload.upgrade().is_none(),
        "typed append payload must be physically retired while peer IO is held"
    );

    peer.release.notify_one();
    assert_eq!(append.await.expect("append response"), response());
}

#[tokio::test]
async fn append_entries_preserves_wire_request_and_response() {
    let request = append_request();
    let expected_payload = encode_config_wire(&request).expect("encode fixture");
    let peer = Arc::new(HeldAppendPeer::default());
    let mut network = network(peer.clone()).await;
    let mut append = pin!(network.append_entries(request, rpc_option()));

    assert_pending(append.as_mut());
    peer.assert_received(&expected_payload);
    peer.release.notify_one();
    assert_eq!(append.await.expect("append response"), response());
}

#[test]
fn append_entries_split_hint_never_retries_a_singleton_as_payload_too_large() {
    assert_eq!(append_entries_split_hint(0), None);
    assert_eq!(append_entries_split_hint(1), None);
    assert_eq!(append_entries_split_hint(2), Some(1));
    assert_eq!(append_entries_split_hint(64), Some(32));
}
