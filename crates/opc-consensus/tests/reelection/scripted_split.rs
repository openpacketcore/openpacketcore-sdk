use super::*;
use schedule::ElectionSchedule;
use test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use tokio::time::Instant;

#[tokio::test(start_paused = true)]
async fn automatic_one_split_election_obeys_its_computed_schedule() {
    schedule::with_frozen_time(one_split_schedule()).await;
}

async fn one_split_schedule() {
    let config =
        Arc::new(durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap());
    // This raw sample goes through the engine's real rand 0.8 gen_range.
    let sample = 3_u64 << 62;
    let calibration = ElectionRngScript::new([sample]);
    let sampled_timeout = calibration
        .scope(async {
            Duration::from_millis(config.new_rand_election_timeout::<ScriptedElectionRuntime>())
        })
        .await;
    calibration.assert_exhausted();
    let schedule = ElectionSchedule::new(&config, sampled_timeout);
    let offset = Duration::from_millis(u64::try_from(schedule.tick.as_millis()).unwrap() / 6);
    let guard =
        Duration::from_millis(2 * DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis)
            + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout();
    let scripts = [
        ElectionRngScript::new([sample; 2]),
        ElectionRngScript::new([sample]),
        ElectionRngScript::new([sample]),
    ];
    let started = Instant::now();
    let state = Arc::new(NetworkState {
        nodes: Mutex::new(BTreeMap::new()),
        split: Mutex::new(None),
        votes: watch::channel(Vec::new()).0,
    });
    let mut nodes = Vec::new();
    let mut machines = Vec::new();
    for (id, script) in scripts.iter().enumerate() {
        if id == 2 {
            for script in &scripts[..2] {
                schedule::tick_registered(&mut script.sleeps(), started, schedule.tick).await;
            }
            tokio::time::advance(offset).await;
        }
        let machine = MemoryStateMachine::default();
        let node = script
            .scope(Raft::new(
                id as u64,
                config.clone(),
                Network {
                    source: id as u64,
                    state: state.clone(),
                },
                MemoryLog::default(),
                machine.clone(),
            ))
            .await
            .unwrap();
        node.runtime_config().elect(false);
        state.nodes.lock().unwrap().insert(id as u64, node.clone());
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
    assert_eq!(before.data, 41);
    for node in &nodes {
        node.wait(Some(guard))
            .applied_index(Some(before.log_id.index), "equal logs before partition")
            .await
            .unwrap();
    }
    let old_term = nodes[0].metrics().borrow().current_term;
    // Later phases supply future draws without replacing the engine's
    // timeout already sampled during construction.
    scripts[1].plan_next([sample; 2]);
    scripts[2].plan_next([sample]);
    state.nodes.lock().unwrap().remove(&0);
    nodes[0].shutdown().await.unwrap();
    state.votes.send_replace(Vec::new());
    let split_gate = Arc::new(SplitGate {
        pre_votes: watch::channel(BTreeMap::new()).0,
        both_pre_votes: Barrier::new(2),
        arrivals: watch::channel(BTreeMap::new()).0,
        both_candidates: Barrier::new(2),
        term: Some(old_term + 1),
    });
    *state.split.lock().unwrap() = Some(split_gate.clone());
    let isolated = Instant::now();
    assert_eq!(isolated - started, offset);
    for (index, script) in scripts.iter().enumerate() {
        let phase = if index == 2 { offset } else { Duration::ZERO };
        assert!(script.sleeps().borrow().iter().any(|(at, deadline)| {
            *at == started + phase && *deadline == started + phase + schedule.tick
        }));
    }
    let first = schedule.campaign(offset, Duration::ZERO, true);
    let second = schedule.campaign(offset, offset, true);
    let retry = schedule.campaign(second, Duration::ZERO, false);
    assert!(second - first < Duration::from_millis(config.election_timeout_max));
    assert!(
        second - first
            < DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(opc_consensus::ConsensusRpcFamily::Vote)
    );
    assert!(retry < schedule.campaign(second, offset, false));
    let election_bound = retry - offset;
    // Precise deadline evaluation puts this one-split schedule inside the
    // unchanged acceptance budget. Repeated-split controls test exhaustion.
    assert!(election_bound < guard);
    for node in &nodes[1..] {
        node.runtime_config().elect(true);
    }
    let mut instants = Vec::new();
    for index in 1..3 {
        let phase = if index == 2 { offset } else { Duration::ZERO };
        let mut tick = phase + schedule.tick;
        while tick <= retry {
            instants.push((tick, index));
            tick += schedule.tick;
        }
    }
    instants.sort_unstable();
    for (tick, index) in instants {
        tokio::time::advance(started + tick - Instant::now()).await;
        schedule::tick_registered(&mut scripts[index].sleeps(), started + tick, schedule.tick)
            .await;
        if tick == first {
            split_gate
                .pre_votes
                .subscribe()
                .wait_for(|arrivals| arrivals.len() == 1)
                .await
                .unwrap();
        }
        if tick == second {
            state
                .votes
                .subscribe()
                .wait_for(|votes| votes.len() == 2)
                .await
                .unwrap();
        }
    }
    let mut one = nodes[1].metrics();
    let mut two = nodes[2].metrics();
    let (leader, term) = async {
        loop {
            let first = one.borrow().clone();
            let second = two.borrow().clone();
            if let Some(leader) = first.current_leader {
                if leader != 0
                    && first.current_term > old_term
                    && second.current_leader == Some(leader)
                    && second.current_term == first.current_term
                {
                    return (leader, first.current_term);
                }
            }
            tokio::select! {
                changed = one.changed() => changed.unwrap(),
                changed = two.changed() => changed.unwrap(),
            }
        }
    }
    .await;
    assert_eq!(isolated.elapsed(), election_bound);
    assert_eq!(leader, 1);
    assert_eq!(term, old_term + 2);
    let votes = state.votes.borrow().clone();
    assert_eq!(
        votes.len(),
        3,
        "one split and one successful automatic retry"
    );
    let split: Vec<_> = votes
        .iter()
        .filter(|vote| vote.request.vote.leader_id.term == old_term + 1)
        .collect();
    assert_eq!(split.len(), 2);
    for exchange in split {
        assert_eq!(
            exchange.request.vote,
            Vote::new(old_term + 1, exchange.source)
        );
        assert_eq!(
            exchange.response.vote,
            Vote::new(old_term + 1, exchange.target)
        );
        assert!(!exchange.response.vote_granted);
        assert_eq!(exchange.request.last_log_id, Some(before.log_id));
        assert_eq!(exchange.sent_at - started, second);
        assert_eq!(exchange.replied_at - started, second);
    }
    let winning = votes
        .iter()
        .find(|vote| vote.response.vote_granted)
        .unwrap();
    assert_eq!(winning.request.vote, Vote::new(old_term + 2, leader));
    assert_eq!(winning.response.vote, winning.request.vote);
    assert_eq!(winning.sent_at - started, retry);
    assert_eq!(winning.replied_at - started, retry);
    let after = nodes[leader as usize].client_write(42).await.unwrap();
    assert_eq!(after.data, 42);
    for index in 1..3 {
        nodes[index]
            .wait(Some(guard))
            .applied_index(
                Some(after.log_id.index),
                "both survivors apply the full state",
            )
            .await
            .unwrap();
        let metrics = nodes[index].metrics().borrow().clone();
        assert_eq!(metrics.current_leader, Some(leader));
        assert_eq!(metrics.current_term, term);
        assert!(metrics.vote.is_committed());
        assert_eq!(machines[index].values(), vec![41, 42]);
    }
    for node in &nodes[1..] {
        node.shutdown().await.unwrap();
    }
    state.nodes.lock().unwrap().clear();
    for script in scripts {
        script.finish();
    }
    assert_eq!(calibration.draws().len(), 1);
}
