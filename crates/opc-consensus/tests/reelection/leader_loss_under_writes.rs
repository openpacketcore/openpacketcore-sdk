//! Automatic recovery with divergent logs left by an active write workload.
//!
//! These tests run the real engine, log acknowledgements and RPC handlers with
//! paused protocol time. The network delays replication to a minority; it does
//! not intercept votes, synchronize log prefixes or trigger an election. Killing
//! the leader closes its network endpoint and engine without draining its writes.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use opc_consensus::engine::storage::RaftLogStorage;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::*;

struct LossNetworkState {
    nodes: Mutex<BTreeMap<u64, Raft<ElectionConfig>>>,
    writing: AtomicBool,
    slow_through: u64,
    votes: Mutex<Vec<VoteExchange>>,
}

#[derive(Clone)]
struct LossNetwork {
    source: u64,
    state: Arc<LossNetworkState>,
}

struct LossConnection {
    network: LossNetwork,
    target: u64,
}

impl RaftNetworkFactory<ElectionConfig> for LossNetwork {
    type Network = LossConnection;

    async fn new_client(&mut self, target: u64, _node: &EmptyNode) -> LossConnection {
        LossConnection {
            network: self.clone(),
            target,
        }
    }
}

impl LossConnection {
    async fn deliver(&self, delay: Duration) -> Result<Raft<ElectionConfig>, Unreachable> {
        tokio::time::sleep(delay).await;
        let nodes = self.network.state.nodes.lock().unwrap();
        // Check both endpoints after the delay: an RPC in flight from the killed
        // leader cannot quietly finish synchronizing the survivors after death.
        if !nodes.contains_key(&self.network.source) {
            return Err(Unreachable::new(&std::io::Error::other("source is dead")));
        }
        nodes
            .get(&self.target)
            .cloned()
            .ok_or_else(|| Unreachable::new(&std::io::Error::other("target is dead")))
    }
}

impl RaftNetwork<ElectionConfig> for LossConnection {
    async fn pre_vote(
        &mut self,
        rpc: PreVoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<PreVoteResponse<u64>, RPCError<u64, EmptyNode, RaftError<u64>>> {
        self.deliver(Duration::from_millis(20))
            .await
            .map_err(RPCError::Unreachable)?
            .pre_vote(rpc)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ElectionConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, EmptyNode, RaftError<u64>>> {
        let lagging = self.network.source == 0
            && self.target <= self.network.state.slow_through
            && !rpc.entries.is_empty()
            && self.network.state.writing.load(Ordering::SeqCst);
        let delay = Duration::from_millis(if lagging { 250 } else { 20 });
        self.deliver(delay)
            .await
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
        let sent_at = Instant::now();
        let response = self
            .deliver(Duration::from_millis(20))
            .await
            .map_err(RPCError::Unreachable)?
            .vote(rpc.clone())
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))?;
        self.network.state.votes.lock().unwrap().push(VoteExchange {
            source: self.network.source,
            target: self.target,
            request: rpc,
            response: response.clone(),
            sent_at,
            replied_at: Instant::now(),
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
        panic!("the small leader-loss fixture must not transfer snapshots")
    }
}

#[tokio::test(start_paused = true)]
async fn three_voters_recover_within_slo_after_leader_loss_under_writes() {
    leader_loss_under_writes(3).await;
}

#[tokio::test(start_paused = true)]
async fn five_voters_recover_within_slo_after_leader_loss_under_writes() {
    leader_loss_under_writes(5).await;
}

async fn leader_loss_under_writes(voters: u64) {
    let profile = DURABLE_CONSENSUS_TIMING_PROFILE;
    let recovery_bound = Duration::from_millis(2 * profile.election_timeout_max_millis)
        + profile.operation_timeout();
    assert_eq!(recovery_bound, Duration::from_secs(26));
    let config =
        Arc::new(durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap());
    assert!(config.enable_elect && config.enable_tick);
    let state = Arc::new(LossNetworkState {
        nodes: Mutex::new(BTreeMap::new()),
        writing: AtomicBool::new(false),
        slow_through: voters / 2,
        votes: Mutex::new(Vec::new()),
    });
    let start = Instant::now();
    let mut nodes = Vec::new();
    let mut logs = Vec::new();
    let mut machines = Vec::new();
    let mut scripts = Vec::new();
    for id in 0..voters {
        // Legal samples put the shorter logs first. No vote or timeout is
        // synthesized: the engine consumes these through its actual RNG.
        let sample = if id <= state.slow_through {
            if id == 2 {
                1_u64 << 62
            } else {
                0
            }
        } else if id == voters - 1 && voters == 5 {
            7_u64 << 61
        } else {
            3_u64 << 62
        };
        let script = test_runtime::ElectionRngScript::new([sample; 16]);
        let log = MemoryLog::default();
        let machine = MemoryStateMachine::default();
        let node = script
            .scope(Raft::new(
                id,
                config.clone(),
                LossNetwork {
                    source: id,
                    state: state.clone(),
                },
                log.clone(),
                machine.clone(),
            ))
            .await
            .unwrap();
        state.nodes.lock().unwrap().insert(id, node.clone());
        nodes.push(node);
        logs.push(log);
        machines.push(machine);
        scripts.push(script);
    }
    nodes[0]
        .initialize(
            (0..voters)
                .map(|id| (id, EmptyNode {}))
                .collect::<BTreeMap<_, _>>(),
        )
        .await
        .unwrap();
    nodes[0]
        .wait(Some(recovery_bound))
        .state(ServerState::Leader, "initial leader")
        .await
        .unwrap();
    nodes[0].ensure_linearizable().await.unwrap();

    let acknowledged = Arc::new(Mutex::new(BTreeMap::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));
    state.writing.store(true, Ordering::SeqCst);
    let writer = tokio::spawn({
        let leader = nodes[0].clone();
        let acknowledged = acknowledged.clone();
        let in_flight = in_flight.clone();
        async move {
            let mut writes = JoinSet::new();
            for value in 1_u64.. {
                let leader = leader.clone();
                let acknowledged = acknowledged.clone();
                let in_flight = in_flight.clone();
                in_flight.fetch_add(1, Ordering::SeqCst);
                writes.spawn(async move {
                    if let Ok(response) = leader.client_write(value).await {
                        acknowledged
                            .lock()
                            .unwrap()
                            .insert(response.log_id.index, value);
                    }
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                });
                while let Some(result) = writes.try_join_next() {
                    result.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });

    // Fixed workload duration, with no applied-prefix barrier, RPC drain,
    // election suppression or deliberate campaign before or after the fault.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let fault = Instant::now();
    let outstanding_at_fault = in_flight.load(Ordering::SeqCst);
    let acknowledged_at_fault = acknowledged.lock().unwrap().clone();
    let applied_at_fault = machines[0].values();
    state.nodes.lock().unwrap().remove(&0);
    writer.abort();
    let _ = writer.await;
    nodes[0].shutdown().await.unwrap();
    let mut survivor_heads = Vec::new();
    for log in &mut logs[1..] {
        survivor_heads.push(log.get_log_state().await.unwrap().last_log_id.unwrap());
    }
    let original_term = nodes[0].metrics().borrow().current_term;
    state.votes.lock().unwrap().clear();

    let recovery = tokio::time::timeout_at(fault + recovery_bound, async {
        let leader = loop {
            if let Some((id, _)) = nodes
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, node)| node.metrics().borrow().state == ServerState::Leader)
            {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        nodes[leader]
            .ensure_linearizable()
            .await
            .map_err(|error| format!("fresh authority: {error}"))?;
        let marker = nodes[leader]
            .client_write(u64::MAX)
            .await
            .map_err(|error| format!("new write: {error}"))?;
        for node in &nodes[1..] {
            node.wait(Some(recovery_bound))
                .applied_index(Some(marker.log_id.index), "survivor reconciliation")
                .await
                .map_err(|error| format!("reconciliation: {error}"))?;
        }
        Ok::<_, String>(leader)
    })
    .await;
    let recovered_after = fault.elapsed();
    let metrics = nodes
        .iter()
        .map(|node| node.metrics().borrow().clone())
        .collect::<Vec<_>>();
    let votes = state.votes.lock().unwrap().clone();
    for node in &nodes[1..] {
        node.shutdown().await.unwrap();
    }
    state.nodes.lock().unwrap().clear();

    eprintln!(
        "leader_loss_under_writes voters={voters} fault_at={:?} outstanding={outstanding_at_fault} acknowledged={} survivor_heads={survivor_heads:?} recovery_after={recovered_after:?} outcome={recovery:?}",
        fault - start,
        acknowledged_at_fault.len(),
    );
    for vote in &votes {
        eprintln!(
            "vote {}->{} sent={:?} replied={:?} request={:?} response={:?}",
            vote.source,
            vote.target,
            vote.sent_at - fault,
            vote.replied_at - fault,
            vote.request,
            vote.response,
        );
    }
    for (id, script) in scripts.iter().enumerate() {
        eprintln!(
            "voter={id} samples={:?}",
            script
                .draws()
                .iter()
                .map(|(at, sample)| (*at - start, sample))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        outstanding_at_fault > 0,
        "leader must die with writes in flight"
    );
    assert!(
        acknowledged_at_fault.len() >= 10,
        "sustained successful pre-fault workload"
    );
    let (stale_heads, fresh_heads) = survivor_heads.split_at((voters / 2) as usize);
    let newest_stale = stale_heads.iter().max().unwrap();
    // Active replication can leave the fresh survivors at different indices.
    // Require both to be ahead of the stale minority, without synchronizing them.
    for head in fresh_heads {
        assert!(
            head > newest_stale,
            "one fresh survivor in three voters, two in five; earlier election samples belong to stale survivors"
        );
    }
    let leader = recovery
        .expect("automatic leader loss recovery, fresh authority, write and reconciliation must finish within the unchanged 26-second SLO")
        .expect("recovery must establish fresh quorum authority and reconcile every survivor");
    assert!(metrics[leader].current_term > original_term);
    for machine in &machines[1..] {
        let values = machine.values();
        assert!(
            values.starts_with(&applied_at_fault),
            "committed pre-fault prefix is preserved"
        );
        for value in acknowledged_at_fault.values() {
            assert!(
                values.contains(value),
                "acknowledged write {value} survived leader loss"
            );
        }
        assert_eq!(values.last(), Some(&u64::MAX));
    }
}
