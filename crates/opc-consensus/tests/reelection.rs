use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_consensus::engine::{
    self,
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable},
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    EmptyNode, Raft, ServerState, Vote,
};
use opc_consensus::{
    durable_openraft_config, DurableOpenraftDomain, DurableOpenraftRuntime,
    DURABLE_CONSENSUS_TIMING_PROFILE,
};
use tokio::sync::{watch, Barrier};

#[path = "reelection/memory_store.rs"]
mod memory_store;
use memory_store::{MemoryLog, MemoryStateMachine};

engine::declare_raft_types!(
    ElectionConfig:
        D = u64,
        R = u64,
        NodeId = u64,
        Node = EmptyNode,
        AsyncRuntime = DurableOpenraftRuntime,
);

#[derive(Clone, Debug)]
struct VoteExchange {
    source: u64,
    target: u64,
    request: VoteRequest<u64>,
    response: VoteResponse<u64>,
}

struct SplitGate {
    arrivals: Mutex<BTreeMap<u64, VoteRequest<u64>>>,
    both_candidates: Barrier,
}

struct NetworkState {
    nodes: Mutex<BTreeMap<u64, Raft<ElectionConfig>>>,
    split: Mutex<Option<Arc<SplitGate>>>,
    votes: watch::Sender<Vec<VoteExchange>>,
}

#[derive(Clone)]
struct Network {
    source: u64,
    state: Arc<NetworkState>,
}

struct Connection {
    network: Network,
    target: u64,
}

impl RaftNetworkFactory<ElectionConfig> for Network {
    type Network = Connection;

    async fn new_client(&mut self, target: u64, _node: &EmptyNode) -> Connection {
        Connection {
            network: self.clone(),
            target,
        }
    }
}

impl Connection {
    fn target(&self) -> Result<Raft<ElectionConfig>, Unreachable> {
        self.network
            .state
            .nodes
            .lock()
            .unwrap()
            .get(&self.target)
            .cloned()
            .ok_or_else(|| Unreachable::new(&std::io::Error::other("voter is offline")))
    }
}

impl RaftNetwork<ElectionConfig> for Connection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ElectionConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, EmptyNode, RaftError<u64>>> {
        self.target()
            .map_err(RPCError::Unreachable)?
            .append_entries(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, EmptyNode, RaftError<u64>>> {
        let target = self.target().map_err(RPCError::Unreachable)?;
        let split = self.network.state.split.lock().unwrap().clone();
        if let Some(split) = split {
            let first = split
                .arrivals
                .lock()
                .unwrap()
                .insert(self.network.source, rpc.clone())
                .is_none();
            assert!(
                first,
                "each survivor sends exactly one initial vote request"
            );
            // Each request exists only after its source has saved its self-vote.
            // Deliver neither request until both real candidates are present.
            split.both_candidates.wait().await;
        }
        let response = target
            .vote(rpc.clone())
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))?;
        self.network.state.votes.send_modify(|votes| {
            votes.push(VoteExchange {
                source: self.network.source,
                target: self.target,
                request: rpc,
                response: response.clone(),
            });
        });
        Ok(response)
    }

    async fn install_snapshot(
        &mut self,
        _rpc: InstallSnapshotRequest<ElectionConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, EmptyNode, RaftError<u64, InstallSnapshotError>>,
    > {
        panic!("the small election fixture must not transfer snapshots")
    }
}

#[tokio::test(start_paused = true)]
async fn automatic_re_election_after_forced_split_vote() {
    let profile = DURABLE_CONSENSUS_TIMING_PROFILE;
    // Retain the original AMF fixture's bound, but measure the retry from the
    // observed split, without spending it on unrelated startup/leader loss.
    let guard = Duration::from_millis(2 * profile.election_timeout_max_millis)
        + profile.operation_timeout();
    let state = Arc::new(NetworkState {
        nodes: Mutex::new(BTreeMap::new()),
        split: Mutex::new(None),
        votes: watch::channel(Vec::new()).0,
    });
    let config =
        Arc::new(durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap());
    assert!(config.enable_elect && config.enable_tick);
    let mut nodes = Vec::new();
    let mut machines = Vec::new();
    for id in 0..3 {
        if id == 2 {
            // Keep the production timers and random sampling. Offset the last
            // ticker by one virtual second so automatic retries cannot arrive
            // in the same tick. Paused time drains runnable RPC/storage tasks
            // before advancing to the next timer, regardless of host load.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let machine = MemoryStateMachine::default();
        let node = Raft::new(
            id,
            config.clone(),
            Network {
                source: id,
                state: state.clone(),
            },
            MemoryLog::default(),
            machine.clone(),
        )
        .await
        .unwrap();
        node.runtime_config().elect(false);
        state.nodes.lock().unwrap().insert(id, node.clone());
        nodes.push(node);
        machines.push(machine);
    }
    nodes[0]
        .initialize(BTreeMap::from([
            (0, EmptyNode {}),
            (1, EmptyNode {}),
            (2, EmptyNode {}),
        ]))
        .await
        .unwrap();
    nodes[0]
        .wait(Some(guard))
        .state(ServerState::Leader, "initial leader")
        .await
        .unwrap();
    let before = nodes[0].client_write(41).await.unwrap();
    for node in &nodes {
        node.wait(Some(guard))
            .applied_index(Some(before.log_id.index), "same log before split")
            .await
            .unwrap();
    }
    let original_term = nodes[0].metrics().borrow().current_term;
    state.nodes.lock().unwrap().remove(&0);
    nodes[0].shutdown().await.unwrap();
    state.votes.send_replace(Vec::new());
    *state.split.lock().unwrap() = Some(Arc::new(SplitGate {
        arrivals: Mutex::new(BTreeMap::new()),
        both_candidates: Barrier::new(2),
    }));

    // These are the only forced campaigns: they construct the failed round.
    let first_trigger = nodes[1].trigger();
    let second_trigger = nodes[2].trigger();
    let (first, second) = tokio::join!(first_trigger.elect(), second_trigger.elect());
    first.unwrap();
    second.unwrap();
    let mut votes = state.votes.subscribe();
    let split = tokio::time::timeout(guard, votes.wait_for(|votes| votes.len() >= 2))
        .await
        .expect("both split-vote responses arrive")
        .unwrap()
        .clone();
    assert_eq!(
        split.len(),
        2,
        "exactly two conflicting campaigns: {split:?}"
    );
    let split_term = original_term + 1;
    for exchange in &split {
        assert_eq!(
            exchange.request.vote,
            Vote::new(split_term, exchange.source)
        );
        assert_eq!(
            exchange.response.vote,
            Vote::new(split_term, exchange.target)
        );
        assert!(!exchange.response.vote_granted, "{exchange:?}");
        assert_eq!(exchange.request.last_log_id, Some(before.log_id));
    }
    for node in &nodes[1..] {
        let metrics = node.metrics().borrow().clone();
        assert_eq!(metrics.state, ServerState::Candidate, "{metrics:?}");
        assert_eq!(metrics.current_term, split_term);
        assert!(!metrics.vote.is_committed());
        assert_eq!(metrics.current_leader, None);
    }
    *state.split.lock().unwrap() = None;
    for node in &nodes[1..] {
        node.runtime_config().elect(true);
    }

    // Only the real engine's timer can initiate a new campaign from here.
    let retry = tokio::time::timeout(
        guard,
        votes.wait_for(|votes| {
            votes.iter().any(|vote| {
                vote.request.vote.leader_id.term > split_term && vote.response.vote_granted
            })
        }),
    )
    .await
    .expect("automatic re-election must obtain a peer vote after the forced split")
    .unwrap()
    .iter()
    .find(|vote| vote.request.vote.leader_id.term > split_term && vote.response.vote_granted)
    .unwrap()
    .clone();
    let leader = retry.source as usize;
    assert_ne!(leader, 0);
    assert_eq!(retry.request.vote.leader_id.term, split_term + 1);
    assert_eq!(retry.response.vote, retry.request.vote);
    assert_eq!(state.votes.borrow().len(), 3, "one automatic retry wins");
    nodes[leader]
        .wait(Some(guard))
        .state(ServerState::Leader, "automatic winner")
        .await
        .unwrap();
    let after = nodes[leader].client_write(42).await.unwrap();
    assert_eq!(after.data, 42);
    for index in 1..3 {
        nodes[index]
            .wait(Some(guard))
            .applied_index(
                Some(after.log_id.index),
                "new leader commits on both survivors",
            )
            .await
            .unwrap();
        let metrics = nodes[index].metrics().borrow().clone();
        assert_eq!(metrics.current_leader, Some(leader as u64));
        assert!(metrics.vote.is_committed());
        assert!(metrics.current_term > split_term);
        assert_eq!(machines[index].values(), vec![41, 42]);
    }
    for node in &nodes[1..] {
        node.shutdown().await.unwrap();
    }
    state.nodes.lock().unwrap().clear();
}
