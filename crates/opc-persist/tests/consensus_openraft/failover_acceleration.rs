//! Deterministic unplanned-leader-loss failover regressions (#1037).
//!
//! Linux-only lane: needs CI/qualification run. The tests use the real
//! configuration-consensus fixture with the paused protocol clock; this
//! macOS analysis host cannot open the fixed-quorum fixture stores, so hosted
//! Linux e2e is the execution gate.

use super::*;

use opc_consensus::DURABLE_CONSENSUS_FAILOVER_PATIENCE;
use opc_persist::{ConfigFailoverState, CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND};

fn heartbeat() -> Duration {
    Duration::from_millis(
        opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE.append_entries_timeout_millis,
    )
}

fn detection_bound() -> Duration {
    CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND
}

fn survivors_of(leader: usize) -> Vec<usize> {
    (0..3).filter(|node| *node != leader).collect()
}

/// A successor is established once at least two stores report the same new
/// leader at the same higher term.
fn agreed_new_leader(
    cluster: &ThreeNodeCluster,
    old_leader: ConfigConsensusNodeId,
    old_term: u64,
) -> Option<usize> {
    let statuses = cluster
        .stores
        .iter()
        .map(|store| store.status())
        .collect::<Vec<_>>();
    statuses.iter().enumerate().find_map(|(index, status)| {
        let leader = status.leader_id.filter(|leader| *leader != old_leader)?;
        if status.term <= old_term {
            return None;
        }
        let agreeing = statuses
            .iter()
            .filter(|peer| peer.leader_id == Some(leader) && peer.term == status.term)
            .count();
        (agreeing >= 2).then_some(index)
    })
}

fn accelerated_campaigns(cluster: &ThreeNodeCluster) -> u64 {
    cluster
        .stores
        .iter()
        .map(|store| store.failover_status().accelerated_campaigns)
        .sum()
}

#[tokio::test(start_paused = true)]
async fn unplanned_leader_loss_requests_a_campaign_within_the_derived_bound() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let old_leader = cluster.leader();
    let old_leader_id = cluster.stores[old_leader].status().node_id;
    let old_term = cluster.stores[old_leader].status().term;
    let survivor = survivors_of(old_leader)[0];

    // Observe at least one complete heartbeat cycle so every follower has a
    // recorded authenticated contact before the loss.
    tokio::time::sleep(heartbeat() + Duration::from_millis(100)).await;
    assert_eq!(0, accelerated_campaigns(&cluster));
    let silence_before = cluster.stores[survivor]
        .leader_silence_millis_for_test()
        .map(Duration::from_millis)
        .expect("followers record authenticated leader contact");

    let isolated_at = tokio::time::Instant::now();
    cluster.isolate(old_leader);
    let search_until = isolated_at + detection_bound() + heartbeat() * 2;
    let mut successor = None;
    while tokio::time::Instant::now() <= search_until {
        if let Some(found) = agreed_new_leader(&cluster, old_leader_id, old_term) {
            successor = Some(found);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let elapsed = tokio::time::Instant::now() - isolated_at;
    let contact_elapsed = silence_before + elapsed;
    let successor = successor.expect("a bounded ordinary campaign must elect a successor");

    assert!(
        contact_elapsed >= DURABLE_CONSENSUS_FAILOVER_PATIENCE,
        "no campaign may start before one complete declared lease plus stale-route grace: {contact_elapsed:?}"
    );
    assert!(
        contact_elapsed <= detection_bound() + heartbeat(),
        "the first campaign must stay inside the derived bound plus one campaign/heartbeat allowance: {contact_elapsed:?}"
    );
    let requesters = survivors_of(old_leader)
        .into_iter()
        .filter(|node| {
            cluster.stores[*node]
                .failover_status()
                .accelerated_campaigns
                >= 1
        })
        .count();
    assert!(
        requesters >= 1,
        "typed failover evidence must record the accelerated ordinary campaign"
    );
    let silent = survivors_of(old_leader)
        .into_iter()
        .filter_map(|node| match cluster.stores[node].failover_status().state {
            ConfigFailoverState::LeaderSilent { .. } => Some(node),
            _ => None,
        })
        .count();
    assert!(
        silent <= survivors_of(old_leader).len(),
        "typed silence evidence is bounded"
    );
    for node in survivors_of(old_leader) {
        assert_ne!(
            Some(old_leader_id),
            cluster.stores[node].status().leader_id,
            "survivors must not keep the lost leader as current"
        );
    }
    assert_ne!(
        Some(old_leader_id),
        cluster.stores[successor].status().leader_id,
        "the agreed successor is a live survivor, not the lost leader"
    );

    // A mutation issued after the replacement leader is established commits
    // exactly once on the surviving quorum.
    let request = ConfigConsensusRequestId::from_bytes([0xB7; 16]);
    let tx_id = TxId::new();
    cluster.stores[successor]
        .append_commit_idempotent(
            request,
            attested(commit(tx_id, None, 1, 0xB7), audit(tx_id)),
        )
        .await
        .expect("replacement leader commits a post-failover mutation");
    for node in survivors_of(old_leader) {
        assert_eq!(
            tx_id,
            cluster.stores[node]
                .load_latest()
                .await
                .expect("survivor read")
                .expect("survivor head")
                .record
                .tx_id
        );
    }
    cluster.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn delayed_heartbeats_request_one_campaign_but_never_depose_a_healthy_leader() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let leader = cluster.leader();
    let leader_id = cluster.stores[leader].status().node_id;
    let term = cluster.stores[leader].status().term;
    let delayed = survivors_of(leader)[0];
    let healthy = survivors_of(leader)[1];
    cluster
        .paths
        .get(&(leader, delayed))
        .expect("leader-to-follower path")
        .delay_append_entries(DURABLE_CONSENSUS_FAILOVER_PATIENCE + heartbeat() * 2);

    let started = tokio::time::Instant::now();
    let mut requested = false;
    while started.elapsed() < DURABLE_CONSENSUS_FAILOVER_PATIENCE + heartbeat() {
        if cluster.stores[delayed]
            .failover_status()
            .accelerated_campaigns
            >= 1
        {
            requested = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        requested,
        "a follower starved past the declared leader lease requests one bounded ordinary campaign"
    );

    // The healthy leader keeps quorum through the other follower, so the
    // inquiry cannot depose it and no term is consumed.
    for node in 0..3 {
        let status = cluster.stores[node].status();
        assert_eq!(
            Some(leader_id),
            status.leader_id,
            "healthy leader stays current"
        );
        assert_eq!(term, status.term, "no speculative campaign consumes a term");
    }
    for node in survivors_of(leader) {
        if node != delayed {
            assert_eq!(
                0,
                cluster.stores[node].failover_status().accelerated_campaigns,
                "an unstressed follower never requests a campaign"
            );
        }
    }
    let request = ConfigConsensusRequestId::from_bytes([0xB8; 16]);
    let tx_id = TxId::new();
    cluster.stores[healthy]
        .append_commit_idempotent(
            request,
            attested(commit(tx_id, None, 1, 0xB8), audit(tx_id)),
        )
        .await
        .expect("healthy leader keeps committing through the accelerated observation");
    assert_eq!(
        1,
        cluster.stores[delayed]
            .failover_status()
            .accelerated_campaigns,
        "the starved follower requested exactly one ordinary campaign for its silence episode"
    );

    cluster
        .paths
        .get(&(leader, delayed))
        .expect("leader-to-follower path")
        .delay_append_entries(Duration::ZERO);
    // Let pending deliveries land so the silence episode closes cleanly.
    tokio::time::sleep(heartbeat() * 2).await;
    assert_eq!(
        Some(leader_id),
        cluster.stores[leader].status().leader_id,
        "the healthy leader remains after delivery resumes"
    );
    cluster.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn steady_healthy_cluster_never_requests_failover_acceleration() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let leader = cluster.leader();
    let leader_id = cluster.stores[leader].status().node_id;
    let term = cluster.stores[leader].status().term;
    let window = DURABLE_CONSENSUS_FAILOVER_PATIENCE * 3;
    let mut elapsed = Duration::ZERO;
    while elapsed < window {
        tokio::time::sleep(Duration::from_millis(100)).await;
        elapsed += Duration::from_millis(100);
        assert_eq!(
            0,
            accelerated_campaigns(&cluster),
            "a steady healthy cluster never requests a campaign"
        );
    }
    for node in 0..3 {
        let status = cluster.stores[node].status();
        assert_eq!(Some(leader_id), status.leader_id);
        assert_eq!(term, status.term);
    }
    let request = ConfigConsensusRequestId::from_bytes([0xB9; 16]);
    let tx_id = TxId::new();
    cluster.stores[leader]
        .append_commit_idempotent(
            request,
            attested(commit(tx_id, None, 1, 0xB9), audit(tx_id)),
        )
        .await
        .expect("the healthy path keeps accepting mutations");
    cluster.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn automatic_elections_disabled_store_never_requests_a_campaign() {
    tokio::time::resume();
    let cluster = ThreeNodeCluster::start().await;
    tokio::time::pause();

    let leader = cluster.leader();
    let old_leader_id = cluster.stores[leader].status().node_id;
    let old_term = cluster.stores[leader].status().term;
    let survivors = survivors_of(leader);
    // Route the fixture through the same mirror-mutating helper the SDK uses:
    // the pinned fork exposes no enable_elect getter, and its public
    // Trigger::elect ignores that flag, so a disabled store must be gated by
    // the mirror before the request is ever issued.
    for node in &survivors {
        cluster.stores[*node].disable_automatic_elections_for_test();
    }
    tokio::time::sleep(heartbeat() + Duration::from_millis(100)).await;
    cluster.isolate(leader);
    tokio::time::sleep(DURABLE_CONSENSUS_FAILOVER_PATIENCE + heartbeat()).await;

    for node in &survivors {
        assert_eq!(
            0,
            cluster.stores[*node]
                .failover_status()
                .accelerated_campaigns,
            "an election-disabled store must never request an external campaign"
        );
        let status = cluster.stores[*node].status();
        assert_eq!(Some(old_leader_id), status.leader_id);
        assert_eq!(old_term, status.term);
    }
    assert!(
        agreed_new_leader(&cluster, old_leader_id, old_term).is_none(),
        "external campaigns stay gated while automatic elections are disabled"
    );
    cluster.shutdown().await;
}
