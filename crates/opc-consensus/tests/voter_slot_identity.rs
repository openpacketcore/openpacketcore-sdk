use opc_consensus::voter_slots::{
    SlotId, VoterIncarnation, VoterSlotIdentity, MAX_VOTER_INCARNATION,
};
use opc_consensus::{ConsensusClusterId, ConsensusNodeId};

#[test]
fn literal_engine_ids_fit_sqlite_and_reverse_without_collisions() {
    for (slot, incarnation, node_id) in [
        (1, 1, 1),
        (65535, 1, 65535),
        (1, 2, 65537),
        (65535, MAX_VOTER_INCARNATION, i64::MAX as u64),
    ] {
        let identity = VoterSlotIdentity::new(
            SlotId::new(slot).expect("slot"),
            VoterIncarnation::new(incarnation).expect("incarnation"),
        );
        assert_eq!(identity.node_id().get(), node_id);
        assert_eq!(
            VoterSlotIdentity::from_node_id(identity.node_id()).expect("reverse"),
            identity
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    for incarnation in [1, 2, 3, MAX_VOTER_INCARNATION] {
        for slot in 1..=65535 {
            let identity = VoterSlotIdentity::new(
                SlotId::new(slot).expect("slot"),
                VoterIncarnation::new(incarnation).expect("incarnation"),
            );
            assert!(ids.insert(identity.node_id()));
        }
    }
    assert!(
        VoterSlotIdentity::from_node_id(ConsensusNodeId::new(65536).expect("legacy ID")).is_err()
    );
    assert!(VoterSlotIdentity::from_node_id(ConsensusNodeId::default()).is_err());
}

#[test]
fn identity_construction_and_deserialization_enforce_bounds() {
    assert!(SlotId::new(0).is_err());
    assert!(VoterIncarnation::new(0).is_err());
    assert!(VoterIncarnation::new(MAX_VOTER_INCARNATION + 1).is_err());
    assert!(VoterIncarnation::new(u64::MAX).is_err());
    assert!(serde_json::from_str::<SlotId>("0").is_err());
    assert!(serde_json::from_str::<SlotId>("65536").is_err());
    assert!(serde_json::from_str::<VoterIncarnation>("0").is_err());
    assert!(serde_json::from_str::<VoterIncarnation>(&u64::MAX.to_string()).is_err());
    assert_eq!(
        VoterIncarnation::new(1)
            .expect("genesis")
            .next()
            .expect("next")
            .get(),
        2
    );
    assert!(VoterIncarnation::new(MAX_VOTER_INCARNATION)
        .expect("last")
        .next()
        .is_err());
}

#[test]
fn installation_nonce_separates_reused_cluster_names() {
    let first = ConsensusClusterId::for_installation("cluster-a", [1; 32]).expect("installation");
    assert_eq!(
        first,
        ConsensusClusterId::for_installation("cluster-a", [1; 32]).expect("same")
    );
    assert_ne!(
        first,
        ConsensusClusterId::for_installation("cluster-a", [2; 32]).expect("fresh")
    );
    assert_ne!(
        first,
        ConsensusClusterId::for_installation("cluster-b", [1; 32]).expect("other")
    );
    assert_ne!(first, ConsensusClusterId::new("cluster-a").expect("legacy"));
    assert!(ConsensusClusterId::for_installation("cluster-a", [0; 32]).is_err());
    assert!(ConsensusClusterId::for_installation(" cluster-a", [1; 32]).is_err());
}
