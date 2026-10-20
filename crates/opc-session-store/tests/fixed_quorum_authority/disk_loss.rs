//! An erased voter must not make a shorter history authoritative.

use super::enrolled::{EnrolledFleet as ColdFleet, OpenVoter};
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

async fn open(fleet: &ColdFleet, index: usize) -> OpenVoter {
    fleet.open(index).await
}

async fn initialize(stores: &[Option<OpenVoter>]) {
    join_all(stores.iter().flatten().map(|store| async {
        loop {
            match store.initialize_cluster().await {
                Ok(()) => return,
                Err(ConsensusSessionStoreOpenError::ClusterFormationRejected) => {}
                Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired) => {
                    assert!(store.refused(), "replacement refusal has no running engine");
                }
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

async fn drain(fleet: &ColdFleet, stores: &mut [Option<OpenVoter>]) {
    for peer in &fleet.peers {
        peer.transport.clear().await;
    }
    for result in join_all(stores.iter().flatten().map(OpenVoter::shutdown)).await {
        result.expect("drain voter before removing its volume");
    }
    fleet.forget_signers();
    for store in stores {
        *store = None;
    }
}

async fn lost_voter_cannot_erase_committed_history(wipe_canonical: bool) {
    let fleet = ColdFleet::new().await;
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
        assert!(
            stores[wiped].as_ref().unwrap().refused(),
            "the erased volume must refuse its enrolled identity before starting Raft"
        );
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

#[tokio::test]
async fn genesis_survivor_and_erased_voter_stall_until_the_committed_holder_returns() {
    let fleet = ColdFleet::new().await;
    let mut stores: Vec<Option<OpenVoter>> = (0..3).map(|_| None).collect();
    let outcome = AssertUnwindSafe(async {
        let wiped = 0;
        let genesis = 1;
        let holder = 2;

        // The nonpreferred member is genuinely enrolled and has exactly the
        // genesis entry. It never receives the subsequently committed history.
        stores[genesis] = Some(open(&fleet, genesis).await);
        assert_eq!(
            stores[genesis].as_ref().unwrap().initialize_cluster().await,
            Err(ConsensusSessionStoreOpenError::ClusterFormationRejected)
        );
        assert_eq!(
            stores[genesis].as_ref().unwrap().status().last_log_index,
            Some(0)
        );
        assert!(stores[genesis].as_ref().unwrap().status().term > 0);
        assert!(!stores[genesis].as_ref().unwrap().status().admitted);
        drain(&fleet, &mut stores).await;

        fleet.peers[genesis].transport.set_enabled(false);
        stores[wiped] = Some(open(&fleet, wiped).await);
        stores[holder] = Some(open(&fleet, holder).await);
        tokio::time::timeout(Duration::from_secs(30), initialize(&stores))
            .await
            .expect("the enrolled majority forms while the genesis-only voter is offline");
        let leader = stores[wiped].as_ref().unwrap().status().leader_id.unwrap();
        let leader_index = fleet
            .peers
            .iter()
            .position(|peer| peer.node_id() == leader)
            .unwrap();
        let committed = append_consensus_padding_entry_for_test(
            stores[leader_index].as_ref().unwrap(),
            COMMITTED,
        )
        .await
        .expect("acknowledge history on both available volumes");
        assert!(committed > 0);
        for index in [wiped, holder] {
            wait_for_receipt(stores[index].as_ref().unwrap(), COMMITTED, committed).await;
        }
        drain(&fleet, &mut stores).await;
        std::fs::remove_dir_all(volume(&fleet, wiped)).unwrap();
        fleet.peers[holder].transport.set_enabled(false);
        fleet.peers[genesis].transport.set_enabled(true);
        stores[genesis] = Some(open(&fleet, genesis).await);
        stores[wiped] = Some(open(&fleet, wiped).await);
        assert!(stores[wiped].as_ref().unwrap().refused());
        assert_eq!(consensus_padding_receipt_status_for_test(
            stores[genesis].as_ref().unwrap(), COMMITTED,
        ).await.unwrap(), ConsensusPaddingReceiptStatusForTest::NotFound);
        let inquiries: usize = fleet
            .peers
            .iter()
            .map(|peer| peer.pre_votes.load(Ordering::SeqCst))
            .sum();
        let admitted = tokio::time::timeout(Duration::from_secs(30), async {
            initialize(&stores).await;
            append_consensus_padding_entry_for_test(stores[genesis].as_ref().unwrap(), AFTER_LOSS)
                .await
                .expect("an admitted majority could write");
        })
        .await;
        assert!(
            admitted.is_err(),
            "genesis plus an erased volume must stall"
        );
        assert!(
            fleet
                .peers
                .iter()
                .map(|peer| peer.pre_votes.load(Ordering::SeqCst))
                .sum::<usize>()
                > inquiries,
            "real automatic campaigns must exercise the safety boundary"
        );
        for store in stores.iter().flatten() {
            assert!(!store.status().admitted);
        }
        assert_eq!(
            stores[genesis].as_ref().unwrap().status().last_log_index,
            Some(0)
        );

        fleet.peers[wiped].transport.clear().await;
        fleet.peers[wiped].transport.set_enabled(false);
        stores[wiped].take().unwrap().shutdown().await.unwrap();
        fleet.peers[holder].transport.set_enabled(true);
        stores[holder] = Some(open(&fleet, holder).await);
        tokio::time::timeout(Duration::from_secs(30), initialize(&stores))
            .await
            .expect("the retained majority heals within the existing readiness bound");
        for store in stores.iter().flatten() {
            wait_for_receipt(store, COMMITTED, committed).await;
        }
        assert_eq!(
            stores[genesis].as_ref().unwrap().status().leader_id,
            Some(fleet.peers[holder].node_id()),
            "the retained longer log wins"
        );
        let after =
            append_consensus_padding_entry_for_test(stores[holder].as_ref().unwrap(), AFTER_LOSS)
                .await
                .expect("the healed majority accepts new durable work");
        assert!(after > committed);
        wait_for_receipt(stores[genesis].as_ref().unwrap(), AFTER_LOSS, after).await;
    })
    .catch_unwind()
    .await;
    drain(&fleet, &mut stores).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn enrolled_majority_forms_without_the_preferred_genesis_initiator() {
    let fleet = ColdFleet::new().await;
    let mut stores: Vec<Option<OpenVoter>> = (0..3).map(|_| None).collect();
    let outcome = AssertUnwindSafe(async {
        fleet.peers[0].transport.set_enabled(false);
        stores[1] = Some(open(&fleet, 1).await);
        stores[2] = Some(open(&fleet, 2).await);
        tokio::time::timeout(Duration::from_secs(30), initialize(&stores))
            .await
            .expect("any enrolled genesis majority can initialize the exact manifest");
        let leader = stores[1].as_ref().unwrap().status().leader_id.unwrap();
        let leader_index = fleet
            .peers
            .iter()
            .position(|peer| peer.node_id() == leader)
            .unwrap();
        assert_ne!(leader_index, 0);
        let committed = append_consensus_padding_entry_for_test(
            stores[leader_index].as_ref().unwrap(),
            COMMITTED,
        )
        .await
        .expect("the majority commits without the preferred initiator");
        for store in stores.iter().flatten() {
            assert!(store.status().admitted);
            wait_for_receipt(store, COMMITTED, committed).await;
            assert_eq!(
                store.voter_slot_state().await.unwrap().table(),
                &fleet.genesis
            );
        }
    })
    .catch_unwind()
    .await;
    drain(&fleet, &mut stores).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
