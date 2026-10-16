//! Incarnation-authenticated replication passes the complete log-pressure window.

use super::*;
use futures_util::FutureExt;
use opc_consensus::engine::raft::{AppendEntriesRequest, AppendEntriesResponse};
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};
use std::panic::AssertUnwindSafe;

async fn send(
    fleet: &Fleet,
    source: &ConsensusSessionStore,
    target: &ConsensusSessionStore,
    rpc: AppendEntriesRequest<SessionRaftTypeConfig>,
) -> SessionConsensusWireResponse {
    let request = SessionConsensusWireRequest::try_new(
        source.current_scope().unwrap().0,
        source.inner.local_node_id,
        SessionConsensusRpcFamily::AppendEntries,
        encode_bounded(&rpc).unwrap(),
    )
    .unwrap();
    fleet
        .network
        .allow_paused_requests
        .lock()
        .unwrap()
        .insert(voter_rpc_request_digest(&request).unwrap());
    source
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .transport
        .peer(target.inner.local_node_id)
        .call_with_timeout(request, Duration::from_secs(5))
        .await
        .unwrap()
}

fn success(response: SessionConsensusWireResponse) {
    let result: Result<
        AppendEntriesResponse<SessionConsensusNodeId>,
        RaftError<SessionConsensusNodeId>,
    > = decode_bounded(&response.result.unwrap()).unwrap();
    assert_eq!(result, Ok(AppendEntriesResponse::Success));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_admission_voter_slot_ingress_applies_growth_and_preserves_control() {
    let fleet = Fleet::open().await;
    let result = AssertUnwindSafe(async {
        let source = &fleet.nodes[0];
        let target = &fleet.nodes[1];
        target.inner.raft.runtime_config().elect(false);
        let previous = source.inner.raft.metrics().borrow().last_applied.unwrap();
        target
            .inner
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(previous.index), "slot follower initial application")
            .await
            .unwrap();
        fleet
            .network
            .paused_replication_to
            .store(target.inner.local_node_id.get(), Ordering::SeqCst);
        let window = target.log_pressure_snapshot().retained_rows;
        target
            .inner
            .raft_handler
            .set_log_admission_window_for_test(window);
        let vote = source.inner.raft.metrics().borrow().vote;
        let log_id = |index| {
            LogId::new(
                CommittedLeaderId::new(vote.leader_id.term, source.inner.local_node_id),
                index,
            )
        };
        let mut rpc = AppendEntriesRequest {
            vote,
            prev_log_id: Some(previous),
            leader_commit: Some(previous),
            entries: vec![],
        };
        let heartbeat = send(&fleet, source, target, rpc.clone()).await;
        let heartbeat: Result<
            AppendEntriesResponse<SessionConsensusNodeId>,
            RaftError<SessionConsensusNodeId>,
        > = decode_bounded(&heartbeat.result.unwrap()).unwrap();
        assert_eq!(
            heartbeat,
            Ok(AppendEntriesResponse::PartialSuccess(Some(previous))),
            "the slot profile preserves its existing heartbeat prefix acknowledgement"
        );
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: source.inner.storage_identity,
            request_id: SessionConsensusRequestId::from_bytes([0xD9; 16]),
            logical_time: source.inner.clock.now_utc(),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        };
        rpc.entries = vec![Entry {
            log_id: log_id(previous.index + 1),
            payload: EntryPayload::Normal(command),
        }];
        success(send(&fleet, source, target, rpc.clone()).await);
        assert_eq!(
            target.inner.raft.metrics().borrow().last_log_index,
            Some(previous.index + 1)
        );
        rpc.prev_log_id = Some(log_id(previous.index + 1));
        rpc.entries[0].log_id = log_id(previous.index + 2);
        rpc.entries[0].payload = EntryPayload::Blank;
        success(send(&fleet, source, target, rpc.clone()).await);
        rpc.prev_log_id = Some(log_id(previous.index + 2));
        rpc.entries = vec![Entry {
            log_id: log_id(previous.index + 3),
            payload: EntryPayload::Normal(probe_marker(source, 0xD9, 1)),
        }];
        success(send(&fleet, source, target, rpc).await);
        assert_eq!(
            target.inner.raft.metrics().borrow().last_log_index,
            Some(previous.index + 3)
        );
        assert_eq!(target.log_pressure_snapshot().pending_entries, 0);
        assert!(target.inner.raft.metrics().borrow().running_state.is_ok());
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
