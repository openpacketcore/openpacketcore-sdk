use super::*;
use opc_consensus::engine::{
    CommittedLeaderId, EmptyNode, Membership, SnapshotMeta, StoredMembership,
};

fn log(term: u64, node: u64, index: u64) -> LogId<SessionConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(term, SessionConsensusNodeId::new(node).unwrap()),
        index,
    )
}

fn candidate(voters: u64) -> CurrentSnapshot {
    let nodes: BTreeSet<_> = (1..=voters)
        .map(|node| SessionConsensusNodeId::new(node).unwrap())
        .collect();
    (
        SnapshotMeta::<SessionConsensusNodeId, EmptyNode> {
            last_log_id: Some(log(7, 1, 24_813)),
            last_membership: StoredMembership::new(
                Some(log(3, 1, 10)),
                Membership::new(vec![nodes.clone()], nodes),
            ),
            snapshot_id: "741-handoff".to_owned(),
        },
        "snapshot-00000000-0000-0000-0000-000000000001.opc".to_owned(),
        [19; 32],
        32 * 1024 * 1024,
    )
}

#[test]
fn snapshot_handoff_candidate_clones_retain_one_metadata_owner() {
    for voters in [3, 5, 127] {
        let handoff = Handoff {
            candidate: candidate(voters).into(),
            transform: Transform::Metadata,
            installation: None,
            phase: Phase::Requested,
        };
        let mut retained = None;
        let allocation = allocation_counter::measure(|| {
            retained = Some(std::hint::black_box(handoff.candidate.clone()));
        });
        assert!(same_snapshot_candidate(
            &handoff.candidate,
            retained.as_ref().unwrap(),
        ));
        assert_eq!(
            allocation.bytes_max, 0,
            "handoff cloning duplicated immutable metadata for {voters} voters: {allocation:?}"
        );
        assert_eq!(allocation.bytes_current, 0);
        drop(retained);
    }
}

#[test]
fn snapshot_handoff_candidate_comparison_preserves_every_original_field() {
    for voters in [3, 5] {
        let original = candidate(voters);
        assert!(same_snapshot_candidate(&original, &original));
        assert!(same_snapshot_candidate(&original, &original.clone()));
        for difference in 0..13 {
            let mut changed = original.clone();
            match difference {
                0 => changed.0.last_log_id = None,
                1 => changed.0.last_log_id = Some(log(8, 1, 24_813)),
                2 => {
                    changed.0.last_membership = StoredMembership::new(
                        None,
                        original.0.last_membership.membership().clone(),
                    );
                }
                3 => changed.0.last_log_id = Some(log(7, 1, 24_814)),
                4 => {
                    changed.0.last_membership = StoredMembership::new(
                        Some(log(4, 1, 10)),
                        original.0.last_membership.membership().clone(),
                    );
                }
                5 => {
                    changed.0.last_membership = StoredMembership::new(
                        Some(log(3, 1, 11)),
                        original.0.last_membership.membership().clone(),
                    );
                }
                6 | 7 => {
                    let nodes: BTreeSet<_> = (1..=voters)
                        .map(|node| SessionConsensusNodeId::new(node).unwrap())
                        .collect();
                    let mut members = nodes.clone();
                    members.remove(&SessionConsensusNodeId::new(voters).unwrap());
                    let configs = if difference == 6 {
                        vec![members]
                    } else {
                        vec![nodes.clone(), members]
                    };
                    changed.0.last_membership = StoredMembership::new(
                        *original.0.last_membership.log_id(),
                        Membership::new(configs, nodes),
                    );
                }
                8 => changed.0.snapshot_id.push('x'),
                9 => changed.1.push('x'),
                10 => changed.2[31] ^= 1,
                11 => changed.3 += 1,
                _ => {
                    let mut nodes: BTreeSet<_> = original.0.last_membership.voter_ids().collect();
                    let voters = nodes.clone();
                    nodes.insert(SessionConsensusNodeId::new(128).unwrap());
                    changed.0.last_membership = StoredMembership::new(
                        *original.0.last_membership.log_id(),
                        Membership::new(vec![voters], nodes),
                    );
                }
            }
            assert_ne!(original, changed, "fixture difference {difference}");
            assert!(
                !same_snapshot_candidate(&original, &changed),
                "handoff accepted metadata difference {difference} with {voters} voters"
            );
        }
    }
}

#[test]
fn snapshot_handoff_candidate_replacement_cannot_change_retained_metadata() {
    let mut handoff = Handoff {
        candidate: Arc::new(candidate(5)),
        transform: Transform::Metadata,
        installation: None,
        phase: Phase::Requested,
    };
    let retained = Arc::clone(&handoff.candidate);
    assert!(std::ptr::eq(handoff.candidate.as_ref(), retained.as_ref(),));
    let original_checksum = retained.2;
    Arc::make_mut(&mut handoff.candidate).2[31] ^= 1;
    assert_eq!(retained.2, original_checksum);
    assert!(!same_snapshot_candidate(&handoff.candidate, &retained));

    handoff.candidate = Arc::new(retained.as_ref().clone());
    assert!(!std::ptr::eq(handoff.candidate.as_ref(), retained.as_ref(),));
    assert!(same_snapshot_candidate(&handoff.candidate, &retained));
}
