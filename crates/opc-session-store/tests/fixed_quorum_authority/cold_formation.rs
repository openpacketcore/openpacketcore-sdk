//! A missed initial campaign must not strand pristine fixed-quorum peers.

use super::*;
use futures_util::{future::join_all, FutureExt};
use opc_session_store::SessionConsensusRpcFamily;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicUsize;

#[cfg(feature = "test-control")]
#[path = "disk_loss.rs"]
mod disk_loss;

#[derive(Debug)]
struct ObservedPeer {
    transport: ScopedLoopbackPeer,
    missed_votes: AtomicUsize,
    pre_votes: AtomicUsize,
}

#[async_trait]
impl SessionConsensusPeer for ObservedPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.transport.node_id()
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        self.transport.scope_identity()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let family = request.family;
        if family == SessionConsensusRpcFamily::PreVote {
            self.pre_votes.fetch_add(1, Ordering::SeqCst);
        }
        let result = self.transport.call(request).await;
        if family == SessionConsensusRpcFamily::Vote
            && matches!(result, Err(SessionConsensusPeerError::Unavailable))
        {
            self.missed_votes.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

struct ColdFleet {
    directory: tempfile::TempDir,
    topologies: Vec<ValidatedQuorumTopology>,
    peers: Vec<Arc<ObservedPeer>>,
}

impl ColdFleet {
    fn new() -> Self {
        let members = fixed_members(3);
        let placement = PlacementResiliencePolicy::AllowReducedResilience;
        let identity = fixed_consensus_identity(&members, placement);
        let mut topologies = (0..3)
            .map(|index| {
                fixed_topology_for_local(index, members.clone(), placement)
                    .expect("exact fixed topology")
            })
            .collect::<Vec<_>>();
        topologies.sort_by_key(|topology| topology.local_consensus_node_id());
        let peers = topologies
            .iter()
            .map(|topology| {
                Arc::new(ObservedPeer {
                    transport: ScopedLoopbackPeer::new(
                        topology.local_consensus_node_id().expect("fixed node ID"),
                        identity,
                    ),
                    missed_votes: AtomicUsize::new(0),
                    pre_votes: AtomicUsize::new(0),
                })
            })
            .collect();
        Self {
            directory: tempfile::tempdir().expect("cold formation directory"),
            topologies,
            peers,
        }
    }

    async fn open(&self, index: usize) -> ConsensusSessionStore {
        let peers = self
            .peers
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, peer)| {
                let transport: Arc<dyn SessionConsensusPeer> = peer.clone();
                (peer.node_id(), transport)
            })
            .collect();
        let store = ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
            self.topologies[index].clone(),
            SqliteSessionBackend::open(self.directory.path().join(format!("voter-{index}.sqlite")))
                .expect("file-backed fixed voter"),
            self.directory.path().join(format!("snapshots-{index}")),
            peers,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await
        .expect("open fixed voter");
        self.peers[index]
            .transport
            .install(store.rpc_handler())
            .await;
        store
    }
}

async fn missed_bootstrap_campaign(restart_canonical: bool) {
    let fleet = ColdFleet::new();
    let mut stores = vec![fleet.open(0).await];
    let outcome = AssertUnwindSafe(async {
        // Both peer stores and listeners are absent, not merely delayed RPCs.
        // Observe the real campaigns while initialization is pending, within
        // its existing operation budget rather than starting another timeout.
        let campaign_deadline = tokio::time::Instant::now()
            + opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT;
        let (initialization, campaigns) = tokio::join!(
            stores[0].initialize_cluster(),
            tokio::time::timeout_at(campaign_deadline, async {
                while !fleet.peers[1..].iter().all(|peer| {
                    peer.missed_votes.load(Ordering::SeqCst) > 0
                        && peer.pre_votes.load(Ordering::SeqCst) > 0
                }) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }),
        );
        assert_eq!(
            initialization,
            Err(ConsensusSessionStoreOpenError::ClusterFormationRejected),
            "a lone voter cannot admit itself"
        );
        campaigns
            .expect("observe missed real votes and automatic Pre-Votes within the operation bound");
        for peer in &fleet.peers[1..] {
            assert!(
                peer.missed_votes.load(Ordering::SeqCst) > 0,
                "the canonical member's real bootstrap campaign missed this peer"
            );
            assert!(
                peer.pre_votes.load(Ordering::SeqCst) > 0,
                "automatic elections have reached Pre-Vote before peers start"
            );
        }
        let before = stores[0].status();
        assert_eq!(before.leader_id, None);
        assert!(!before.admitted);
        assert_eq!(before.last_log_index, Some(0));
        assert!(before.term > 0);
        assert_eq!(
            stores[0]
                .probe_fixed_durable_quorum_readiness()
                .await
                .traffic_authority(),
            FixedQuorumTrafficAuthority::NoQuorum
        );

        if restart_canonical {
            fleet.peers[0].transport.clear().await;
            stores.remove(0).shutdown().await.expect("drain lone voter");
            let reopened = fleet.open(0).await;
            // Opening returns before Raft publishes its recovered metrics.
            // Observe that publication before comparing the retained state.
            tokio::time::timeout(
                opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                async {
                    while reopened.status().last_log_index.is_none() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                },
            )
            .await
            .expect("reopened voter publishes its retained log");
            assert_eq!(reopened.status().last_log_index, before.last_log_index);
            assert_eq!(reopened.status().term, before.term);
            assert!(!reopened.status().admitted);
            stores.push(reopened);
        }
        // Opening installs the handler. Keep both routes unavailable until
        // their pristine-state assertions finish so replication cannot race
        // the second store's open or those assertions.
        for peer in &fleet.peers[1..] {
            peer.transport.set_enabled(false);
        }
        stores.push(fleet.open(1).await);
        stores.push(fleet.open(2).await);
        for store in &stores[1..] {
            assert_eq!(store.status().last_log_index, None);
            assert!(!store.status().admitted);
        }
        for peer in &fleet.peers[1..] {
            peer.transport.set_enabled(true);
        }

        // Retain the existing fixed-quorum 30-second readiness bound and every
        // initializer's production operation deadline. No forced election or
        // controlled clock can manufacture progress after the missed campaign.
        let formed = tokio::time::timeout(Duration::from_secs(30), async {
            join_all(stores.iter().map(|store| async {
                loop {
                    match store.initialize_cluster().await {
                        Ok(()) => break,
                        Err(ConsensusSessionStoreOpenError::ClusterFormationRejected) => {}
                        other => panic!("unexpected formation result: {other:?}"),
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }))
            .await;
            loop {
                let reports = join_all(
                    stores
                        .iter()
                        .map(|store| store.probe_fixed_durable_quorum_readiness()),
                )
                .await;
                if reports
                    .iter()
                    .all(|report| report.traffic_authority().is_granted())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            formed.is_ok(),
            "delayed pristine peers must form after a missed bootstrap campaign: {:?}",
            stores
                .iter()
                .map(ConsensusSessionStore::status)
                .collect::<Vec<_>>()
        );
        let leader = stores[0].status().leader_id.expect("elected leader");
        for store in &stores {
            assert!(store.status().admitted);
            assert_eq!(store.status().leader_id, Some(leader));
            assert!(store.status().applied_index.is_some());
            store
                .max_replication_sequence()
                .await
                .expect("live quorum operation");
        }
    })
    .catch_unwind()
    .await;
    for peer in &fleet.peers {
        peer.transport.clear().await;
    }
    for result in join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await {
        result.expect("drain cold formation voter");
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn delayed_pristine_peers_recover_a_missed_bootstrap_campaign() {
    missed_bootstrap_campaign(false).await;
}

#[tokio::test]
async fn delayed_pristine_peers_recover_after_the_bootstrap_voter_restarts() {
    missed_bootstrap_campaign(true).await;
}

#[tokio::test]
async fn isolated_fixed_voters_never_gain_authority_or_repeat_real_campaigns() {
    let fleet = ColdFleet::new();
    for peer in &fleet.peers {
        peer.transport.set_enabled(false);
    }
    let stores = join_all((0..3).map(|index| fleet.open(index))).await;
    let outcome = AssertUnwindSafe(async {
        let mut initial_terms = Vec::new();
        for attempt in 0..2 {
            let results =
                join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster)).await;
            for (index, (store, result)) in stores.iter().zip(results).enumerate() {
                assert_eq!(
                    result,
                    Err(ConsensusSessionStoreOpenError::ClusterFormationRejected)
                );
                let status = store.status();
                assert_eq!(status.last_log_index, (index == 0).then_some(0));
                assert_eq!(status.applied_index, None);
                assert_eq!(status.leader_id, None);
                assert!(!status.admitted);
                assert_eq!(status.term, u64::from(index == 0));
                if attempt == 0 {
                    initial_terms.push(status.term);
                } else {
                    assert_eq!(
                        status.term, initial_terms[index],
                        "retrying initialization cannot bypass Pre-Vote or consume a term"
                    );
                }
            }
        }
    })
    .catch_unwind()
    .await;
    for peer in &fleet.peers {
        peer.transport.clear().await;
    }
    for result in join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await {
        result.expect("drain isolated voter");
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
