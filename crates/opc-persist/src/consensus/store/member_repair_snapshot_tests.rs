use super::*;
use opc_consensus::engine::{CommittedLeaderId, Membership};

fn node(id: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(id).expect("node ID")
}

fn members() -> BTreeSet<ConsensusNodeId> {
    [1, 2, 3].map(node).into_iter().collect()
}

fn first_chunk() -> RepairChunk {
    RepairChunk {
        vote: Vote::new_committed(7, node(1)),
        meta: SnapshotMeta {
            last_log_id: Some(LogId::new(CommittedLeaderId::new(7, node(1)), 9)),
            last_membership: StoredMembership::new(
                Some(LogId::new(CommittedLeaderId::new(1, node(1)), 0)),
                Membership::new(vec![members()], members()),
            ),
            snapshot_id: "verified-snapshot".to_owned(),
        },
        offset: 0,
        bytes: vec![0x53; CHUNK_BYTES],
        done: false,
    }
}

#[tokio::test]
async fn checkpoint_reuse_requires_exact_source_vote_and_complete_snapshot_metadata() {
    let directory = tempfile::tempdir().expect("snapshot directory");
    let first = first_chunk();
    let download = RepairDownload {
        source: node(1),
        vote: first.vote,
        meta: first.meta,
        snapshot: Box::new(
            crate::consensus::snapshot_file::ConfigSnapshotFile::create(
                directory.path().join("checkpoint.part"),
            )
            .await
            .expect("checkpoint file"),
        ),
        offset: CHUNK_BYTES as u64,
        chunk: None,
        done: false,
        rediscover: true,
    };
    assert!(same_repair_snapshot(&download, node(1), &first_chunk()));
    assert!(!same_repair_snapshot(&download, node(2), &first_chunk()));

    for vote in [
        Vote::new_committed(8, node(1)),
        Vote::new_committed(7, node(2)),
        Vote::new(7, node(1)),
    ] {
        let mut changed = first_chunk();
        changed.vote = vote;
        assert!(!same_repair_snapshot(&download, node(1), &changed));
    }
    let mut changed = first_chunk();
    changed.meta.snapshot_id = "replacement-snapshot".to_owned();
    assert!(!same_repair_snapshot(&download, node(1), &changed));
    changed = first_chunk();
    changed.meta.last_log_id = Some(LogId::new(CommittedLeaderId::new(7, node(1)), 10));
    assert!(!same_repair_snapshot(&download, node(1), &changed));
    changed = first_chunk();
    changed.meta.last_membership = StoredMembership::new(
        Some(LogId::new(CommittedLeaderId::new(2, node(1)), 1)),
        Membership::new(vec![members()], members()),
    );
    assert!(!same_repair_snapshot(&download, node(1), &changed));
    changed = first_chunk();
    let replaced_members = BTreeSet::from([node(1), node(2), node(4)]);
    changed.meta.last_membership = StoredMembership::new(
        *changed.meta.last_membership.log_id(),
        Membership::new(vec![replaced_members.clone()], replaced_members),
    );
    assert!(!same_repair_snapshot(&download, node(1), &changed));
}

#[test]
fn discovery_rejects_invalid_authority_membership_and_first_chunk_shape() {
    assert!(valid_first_repair_chunk(
        node(1),
        &first_chunk(),
        &members()
    ));
    assert!(!valid_first_repair_chunk(
        node(2),
        &first_chunk(),
        &members()
    ));

    let mut invalid = first_chunk();
    invalid.vote = Vote::new(7, node(1));
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.meta.last_log_id = None;
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.meta.last_membership = StoredMembership::new(
        *invalid.meta.last_membership.log_id(),
        Membership::new(
            vec![members(), BTreeSet::from([node(1), node(2)])],
            members(),
        ),
    );
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.offset = 1;
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.bytes.push(0x53);
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid = first_chunk();
    invalid.bytes.clear();
    assert!(!valid_first_repair_chunk(node(1), &invalid, &members()));
    invalid.done = true;
    assert!(valid_first_repair_chunk(node(1), &invalid, &members()));
}
