use super::*;
use crate::consensus::capacity_tests::support::*;

fn node(id: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(id).unwrap()
}
fn members(count: usize) -> Membership<ConsensusNodeId, EmptyNode> {
    Membership::new(
        vec![(1..=count as u64).map(node).collect::<BTreeSet<_>>()],
        None,
    )
}
fn blank() -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: LogId::new(opc_consensus::engine::CommittedLeaderId::new(1, node(1)), 1),
        payload: EntryPayload::Blank,
    }
}

#[test]
fn append_count_is_inclusive_in_json_and_binary() {
    for count in [
        0,
        opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
        opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES + 1,
    ] {
        let value = AppendEntriesRequest::<ConfigRaftTypeConfig> {
            vote: Vote::new(1, node(1)),
            prev_log_id: None,
            entries: vec![blank(); count],
            leader_commit: None,
        };
        assert_eq!(
            serde_json::from_slice::<Append>(&serde_json::to_vec(&value).unwrap()).is_ok(),
            count <= opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES
        );
        assert_eq!(
            opc_consensus::decode_bounded::<Append>(
                &opc_consensus::encode_bounded(&value).unwrap()
            )
            .is_ok(),
            count <= opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES
        );
    }
}

#[test]
fn native_membership_bounds_roster_without_normalizing_it() {
    for count in [1, MEMBERS, MEMBERS + 1] {
        let value = StoredMembership::new(Some(blank().log_id), members(count));
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(native_json::membership(&json).is_ok(), count <= MEMBERS);
        if count <= MEMBERS {
            assert_eq!(native_json::membership(&json).unwrap(), value);
        }
    }
    let value = StoredMembership::new(Some(blank().log_id), members(1));
    let mut json = serde_json::to_value(&value).unwrap();
    json["membership"]["nodes"] = serde_json::json!({});
    assert!(native_json::membership(&serde_json::to_vec(&json).unwrap()).is_err());
    let mut json = serde_json::to_value(&value).unwrap();
    json["membership"]["configs"] = serde_json::json!([[1, 1]]);
    assert!(native_json::membership(&serde_json::to_vec(&json).unwrap()).is_err());
}

#[test]
fn node_map_and_joint_count_are_bounded_independently() {
    for count in [MEMBERS, MEMBERS + 1] {
        let nodes: BTreeMap<_, _> = (1..=count as u64)
            .map(|id| (node(id), EmptyNode {}))
            .collect();
        assert_eq!(
            serde_json::from_slice::<Nodes>(&serde_json::to_vec(&nodes).unwrap()).is_ok(),
            count <= MEMBERS
        );
        assert_eq!(
            opc_consensus::decode_bounded::<Nodes>(&opc_consensus::encode_bounded(&nodes).unwrap())
                .is_ok(),
            count <= MEMBERS
        );
    }
    let declared = opc_consensus::encode_bounded(&u64::MAX).unwrap();
    assert!(opc_consensus::decode_bounded::<Nodes>(&declared).is_err());
    let membership = members(1);
    let mut json = serde_json::to_value(membership).unwrap();
    json["configs"] = serde_json::json!([[1], [1]]);
    assert!(
        serde_json::from_slice::<FixedMembership>(&serde_json::to_vec(&json).unwrap()).is_err()
    );
}

#[test]
fn native_entry_does_not_open_retained_serde_decoder() {
    for audited in [false, true] {
        let value = Entry::<ConfigRaftTypeConfig> {
            payload: EntryPayload::Normal(bounded_command(audited, None)),
            ..blank()
        };
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(native_json::entry(&json).unwrap(), value);
        let error = serde_json::from_slice::<Entry<ConfigRaftTypeConfig>>(&json).unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown variant `BoundedAppend`"));
    }
}

#[test]
fn snapshot_id_and_chunk_have_independent_inclusive_bounds() {
    let meta = SnapshotMeta {
        last_log_id: Some(blank().log_id),
        last_membership: StoredMembership::new(Some(blank().log_id), members(1)),
        snapshot_id: "s".repeat(SNAPSHOT_ID_BYTES),
    };
    assert_eq!(
        native_json::snapshot_meta(&serde_json::to_vec(&meta).unwrap()).unwrap(),
        meta
    );
    let mut over = meta.clone();
    over.snapshot_id.push('s');
    assert!(native_json::snapshot_meta(&serde_json::to_vec(&over).unwrap()).is_err());
    for length in [SNAPSHOT_CHUNK_BYTES, SNAPSHOT_CHUNK_BYTES + 1] {
        let value = InstallSnapshotRequest::<ConfigRaftTypeConfig> {
            vote: Vote::new(1, node(1)),
            meta: meta.clone(),
            offset: 0,
            data: vec![7; length],
            done: true,
        };
        let binary = opc_consensus::encode_bounded(&value).unwrap();
        assert_eq!(
            opc_consensus::decode_bounded::<Snapshot>(&binary).is_ok(),
            length <= SNAPSHOT_CHUNK_BYTES
        );
    }
}
