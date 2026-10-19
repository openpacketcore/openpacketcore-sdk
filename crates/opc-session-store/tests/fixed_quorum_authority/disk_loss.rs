//! An erased voter must not make a shorter history authoritative.

use super::*;
use opc_session_store::test_support::{
    append_consensus_padding_entry_for_test, consensus_padding_receipt_status_for_test,
    ConsensusPaddingReceiptStatusForTest,
};

const BEFORE_LOSS: [u8; 16] = [0x71; 16];
const COMMITTED: [u8; 16] = [0x72; 16];
const AFTER_LOSS: [u8; 16] = [0x73; 16];

fn volume(fleet: &ColdFleet, index: usize) -> PathBuf {
    fleet.directory.path().join(format!("volume-{index}"))
}

async fn open(fleet: &ColdFleet, index: usize) -> ConsensusSessionStore {
    let directory = volume(fleet, index);
    std::fs::create_dir_all(&directory).expect("private voter volume");
    let peers = fleet
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
        fleet.topologies[index].clone(),
        SqliteSessionBackend::open(directory.join("voter.sqlite"))
            .expect("file-backed voter volume"),
        directory.join("snapshots"),
        peers,
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .expect("open voter under its configured identity");
    fleet.peers[index]
        .transport
        .install(store.rpc_handler())
        .await;
    store
}

async fn initialize(stores: &[Option<ConsensusSessionStore>]) {
    join_all(stores.iter().flatten().map(|store| async {
        loop {
            match store.initialize_cluster().await {
                Ok(()) => return,
                Err(ConsensusSessionStoreOpenError::ClusterFormationRejected) => {}
                other => panic!("unexpected voter admission result: {other:?}"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }))
    .await;
}

async fn wait_for_receipt(store: &ConsensusSessionStore, request: [u8; 16], index: u64) {
    tokio::time::timeout(
        opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        async {
            loop {
                match consensus_padding_receipt_status_for_test(store, request)
                    .await
                    .expect("read exact voter-local durable receipt")
                {
                    ConsensusPaddingReceiptStatusForTest::NotFound => {}
                    actual => {
                        assert_eq!(
                            actual,
                            ConsensusPaddingReceiptStatusForTest::Recorded {
                                raft_log_index: index,
                            }
                        );
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        },
    )
    .await
    .expect("voter applies the exact committed receipt");
}

async fn drain(fleet: &ColdFleet, stores: &mut [Option<ConsensusSessionStore>]) {
    for peer in &fleet.peers {
        peer.transport.clear().await;
    }
    for result in join_all(stores.iter().flatten().map(ConsensusSessionStore::shutdown)).await {
        result.expect("drain voter before removing its volume");
    }
    for store in stores {
        *store = None;
    }
}

async fn lost_voter_cannot_erase_committed_history(wipe_canonical: bool) {
    let fleet = ColdFleet::new();
    let mut stores = Vec::new();
    for index in 0..3 {
        stores.push(Some(open(&fleet, index).await));
    }
    let outcome = AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(30), initialize(&stores))
            .await
            .expect("initial fleet forms within the existing readiness bound");
        let leader = stores[0]
            .as_ref()
            .unwrap()
            .status()
            .leader_id
            .expect("initial fleet has a leader");
        let leader_index = fleet
            .peers
            .iter()
            .position(|peer| peer.node_id() == leader)
            .unwrap();
        let wiped = if wipe_canonical {
            0
        } else {
            (1..3)
                .find(|index| *index != leader_index)
                .expect("noncanonical follower to lose its disk")
        };
        let lagging = (0..3)
            .find(|index| *index != wiped && *index != leader_index)
            .expect("a separate member can lag the committed entry");
        let intact = (0..3)
            .find(|index| *index != wiped && *index != lagging)
            .unwrap();

        let before = append_consensus_padding_entry_for_test(
            stores[leader_index].as_ref().unwrap(),
            BEFORE_LOSS,
        )
        .await
        .expect("commit a common prefix");
        for store in stores.iter().flatten() {
            wait_for_receipt(store, BEFORE_LOSS, before).await;
        }
        fleet.peers[lagging].transport.set_enabled(false);
        let committed = append_consensus_padding_entry_for_test(
            stores[leader_index].as_ref().unwrap(),
            COMMITTED,
        )
        .await
        .expect("acknowledge the entry with the two-member durable majority");
        assert!(committed > before);
        for index in [wiped, intact] {
            wait_for_receipt(stores[index].as_ref().unwrap(), COMMITTED, committed).await;
        }
        assert_eq!(
            consensus_padding_receipt_status_for_test(stores[lagging].as_ref().unwrap(), COMMITTED)
                .await
                .unwrap(),
            ConsensusPaddingReceiptStatusForTest::NotFound,
            "the lagging member does not contain the acknowledged entry"
        );

        // Remove the entire closed volume, including the native WAL and
        // snapshots. Reuse exactly the same authenticated topology identity.
        // The intact holder stays offline while the lagging member campaigns.
        drain(&fleet, &mut stores).await;
        std::fs::remove_dir_all(volume(&fleet, wiped)).expect("simulate total voter disk loss");
        for (index, peer) in fleet.peers.iter().enumerate() {
            peer.transport.set_enabled(index != intact);
        }
        stores[lagging] = Some(open(&fleet, lagging).await);
        stores[wiped] = Some(open(&fleet, wiped).await);
        let pre_votes_before: usize = fleet
            .peers
            .iter()
            .map(|peer| peer.pre_votes.load(Ordering::SeqCst))
            .sum();

        let admitted = tokio::time::timeout(Duration::from_secs(30), async {
            initialize(&stores).await;
            append_consensus_padding_entry_for_test(stores[lagging].as_ref().unwrap(), AFTER_LOSS)
                .await
                .expect("new majority commits after the same-identity disk loss");
        })
        .await;
        if admitted.is_ok() {
            assert_eq!(
                consensus_padding_receipt_status_for_test(
                    stores[lagging].as_ref().unwrap(),
                    COMMITTED,
                )
                .await
                .unwrap(),
                ConsensusPaddingReceiptStatusForTest::Recorded {
                    raft_log_index: committed,
                },
                "a new quorum must not lose the previously acknowledged committed entry"
            );
        } else {
            assert!(
                fleet
                    .peers
                    .iter()
                    .map(|peer| peer.pre_votes.load(Ordering::SeqCst))
                    .sum::<usize>()
                    > pre_votes_before,
                "the safety check must cover real attempted elections"
            );
            for store in stores.iter().flatten() {
                assert!(!store.status().admitted);
            }
        }

        // The two retained voters can recover the committed history without
        // counting the erased identity. Replacing that voter is a separate
        // identity transition, never a fresh open under its old identity.
        fleet.peers[wiped].transport.clear().await;
        fleet.peers[wiped].transport.set_enabled(false);
        stores[wiped]
            .take()
            .unwrap()
            .shutdown()
            .await
            .expect("retire the erased identity");
        fleet.peers[intact].transport.set_enabled(true);
        stores[intact] = Some(open(&fleet, intact).await);
        tokio::time::timeout(Duration::from_secs(30), initialize(&stores))
            .await
            .expect("retained majority recovers within the existing readiness bound");
        for store in stores.iter().flatten() {
            wait_for_receipt(store, COMMITTED, committed).await;
        }
    })
    .catch_unwind()
    .await;
    drain(&fleet, &mut stores).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn lost_noncanonical_voter_cannot_erase_a_committed_entry() {
    lost_voter_cannot_erase_committed_history(false).await;
}

#[tokio::test]
async fn lost_canonical_voter_cannot_erase_a_committed_entry() {
    lost_voter_cannot_erase_committed_history(true).await;
}
