//! Real engine DTO compatibility and rejection before engine handoff. These
//! codec controls do not qualify a live cluster, retained reopen or snapshots.

use super::*;
use crate::consensus::config_capacity_decode::engine;
use crate::consensus::types::encode_config_wire_for_profile;
use opc_consensus::engine::raft::InstallSnapshotRequest;
use opc_consensus::engine::{EmptyNode, Membership, SnapshotMeta, StoredMembership};
use std::collections::BTreeSet;

fn node() -> ConsensusNodeId {
    ConsensusNodeId::new(1).unwrap()
}
fn log_id() -> LogId<ConsensusNodeId> {
    LogId::new(CommittedLeaderId::new(2, node()), 3)
}

fn membership(count: u64) -> Membership<ConsensusNodeId, EmptyNode> {
    let voters: BTreeSet<_> = (1..=count)
        .map(|id| ConsensusNodeId::new(id).unwrap())
        .collect();
    Membership::new(vec![voters], ())
}

fn append(entries: Vec<Entry<ConfigRaftTypeConfig>>) -> AppendEntriesRequest<ConfigRaftTypeConfig> {
    AppendEntriesRequest {
        vote: Vote::new_committed(2, node()),
        prev_log_id: Some(log_id()),
        entries,
        leader_commit: Some(log_id()),
    }
}

fn entry(payload: EntryPayload<ConfigRaftTypeConfig>) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: log_id(),
        payload,
    }
}

#[test]
fn capacity_engine_append_preserves_real_dtos_and_exact_binary_capacities() {
    let large = command(1_572_864);
    large
        .intent
        .validate_capacity(identity(), &key(), PROFILE)
        .unwrap();
    let scenarios = [
        append(Vec::new()),
        append(vec![
            entry(EntryPayload::Blank),
            entry(EntryPayload::Membership(membership(9))),
            entry(EntryPayload::Normal(command(128))),
        ]),
        append(vec![entry(EntryPayload::Normal(large))]),
        append(
            (0..64)
                .map(|_| entry(EntryPayload::Normal(command(128))))
                .collect(),
        ),
    ];
    for source in scenarios {
        for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
            let bytes = encode_config_wire_for_profile(profile, &source).unwrap();
            let decoded = engine::append(profile, &bytes).unwrap();
            assert_eq!(
                encode_config_wire_for_profile(profile, &decoded).unwrap(),
                bytes
            );
            assert_eq!(
                serde_json::to_vec(&decoded).unwrap(),
                serde_json::to_vec(&source).unwrap()
            );
            if profile == PROFILE {
                for entry in &decoded.entries {
                    if let EntryPayload::Normal(command) = &entry.payload {
                        command
                            .intent
                            .validate_capacity(identity(), &key(), PROFILE)
                            .unwrap();
                        let ConfigMutationIntent::BoundedAppend { commit, .. } = &command.intent
                        else {
                            unreachable!()
                        };
                        assert_eq!(
                            commit.record.encrypted_blob.capacity(),
                            commit.record.encrypted_blob.len()
                        );
                        assert_eq!(commit.audit.capacity(), 0);
                    }
                }
            }
        }
    }
}

#[test]
fn capacity_engine_append_rejects_count_roster_and_record_overflow() {
    let too_many = append((0..65).map(|_| entry(EntryPayload::Blank)).collect());
    let roster_over = append(vec![entry(EntryPayload::Membership(membership(10)))]);
    let mut oversized = command(128);
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut oversized.intent else {
        unreachable!()
    };
    commit.record.encrypted_blob.resize(1_704_493, 0);
    for source in [
        too_many,
        roster_over,
        append(vec![entry(EntryPayload::Normal(oversized))]),
    ] {
        let bounded = encode_config_wire_for_profile(PROFILE, &source).unwrap();
        assert!(engine::append(PROFILE, &bounded).is_err());
        let legacy =
            encode_config_wire_for_profile(ConfigCapacityProfile::Legacy, &source).unwrap();
        assert!(
            engine::append(ConfigCapacityProfile::Legacy, &legacy).is_ok(),
            "legacy decoding retains its old behavior; later validation is separate"
        );
        assert!(engine::append(PROFILE, &legacy).is_err());
        assert!(engine::append(ConfigCapacityProfile::Legacy, &bounded).is_err());
    }
    // A missing node must be rejected before Membership::new could fill it.
    #[derive(serde::Serialize)]
    struct RawMembership {
        configs: Vec<BTreeSet<ConsensusNodeId>>,
        nodes: std::collections::BTreeMap<ConsensusNodeId, EmptyNode>,
    }
    #[derive(serde::Serialize)]
    enum RawPayload {
        Blank,
        Normal(Box<ConfigConsensusCommand>),
        Membership(RawMembership),
    }
    #[derive(serde::Serialize)]
    struct RawEntry {
        log_id: LogId<ConsensusNodeId>,
        payload: RawPayload,
    }
    #[derive(serde::Serialize)]
    struct RawAppend {
        vote: Vote<ConsensusNodeId>,
        prev_log_id: Option<LogId<ConsensusNodeId>>,
        entries: Vec<RawEntry>,
        leader_commit: Option<LogId<ConsensusNodeId>>,
    }
    // Construct the other indices too, so this fixture's enum layout remains
    // explicit without suppressing dead-code checks on unused variants.
    let raw = RawAppend {
        vote: Vote::new_committed(2, node()),
        prev_log_id: Some(log_id()),
        leader_commit: Some(log_id()),
        entries: vec![
            RawEntry {
                log_id: log_id(),
                payload: RawPayload::Blank,
            },
            RawEntry {
                log_id: log_id(),
                payload: RawPayload::Normal(Box::new(command(128))),
            },
            RawEntry {
                log_id: log_id(),
                payload: RawPayload::Membership(RawMembership {
                    configs: vec![BTreeSet::from([node()])],
                    nodes: Default::default(),
                }),
            },
        ],
    };
    let bytes = encode_config_wire_for_profile(PROFILE, &raw).unwrap();
    assert!(engine::append(PROFILE, &bytes).is_err());
}

#[test]
fn capacity_engine_snapshot_preserves_chunk_offsets_and_bounds_owned_fields() {
    let source = InstallSnapshotRequest::<ConfigRaftTypeConfig> {
        vote: Vote::new_committed(2, node()),
        meta: SnapshotMeta {
            last_log_id: Some(log_id()),
            last_membership: StoredMembership::new(Some(log_id()), membership(9)),
            snapshot_id: "x".repeat(128),
        },
        offset: 1_048_576,
        data: vec![0x51; 1_048_576],
        done: true,
    };
    for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
        let bytes = encode_config_wire_for_profile(profile, &source).unwrap();
        let decoded = engine::snapshot(profile, &bytes).unwrap();
        assert_eq!(decoded, source);
        if profile == PROFILE {
            assert_eq!(decoded.data.capacity(), source.data.len());
        }
    }
    for field in 0..3 {
        let mut over = source.clone();
        match field {
            0 => over.data.push(0x51),
            1 => over.meta.snapshot_id.push('x'),
            _ => over.meta.last_membership = StoredMembership::new(Some(log_id()), membership(10)),
        }
        let bytes = encode_config_wire_for_profile(PROFILE, &over).unwrap();
        assert!(engine::snapshot(PROFILE, &bytes).is_err());
        let legacy = encode_config_wire_for_profile(ConfigCapacityProfile::Legacy, &over).unwrap();
        assert_eq!(
            engine::snapshot(ConfigCapacityProfile::Legacy, &legacy).unwrap(),
            over
        );
    }
}

#[test]
fn capacity_native_json_preserves_encrypted_entries_and_independent_profiles() {
    let source = entry(EntryPayload::Normal(command(1_572_864)));
    let encoded = serde_json::to_vec(&source).unwrap();
    for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
        let decoded = engine::native_entry(profile, &encoded).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
        let EntryPayload::Normal(command) = &decoded.payload else {
            unreachable!()
        };
        command
            .intent
            .validate_capacity(identity(), &key(), PROFILE)
            .unwrap();
    }
    let mut over = source.clone();
    let EntryPayload::Normal(command) = &mut over.payload else {
        unreachable!()
    };
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut command.intent else {
        unreachable!()
    };
    commit.record.encrypted_blob.resize(1_704_493, 0);
    // Selecting an older command revision in the row cannot select Legacy.
    command.schema_version = 1;
    let encoded = serde_json::to_vec(&over).unwrap();
    assert!(engine::native_entry(PROFILE, &encoded).is_err());
    assert!(engine::native_entry(ConfigCapacityProfile::Legacy, &encoded).is_ok());

    let mut padded = serde_json::to_vec(&entry(EntryPayload::Blank)).unwrap();
    padded.resize(16_777_216, b' ');
    engine::native_entry(PROFILE, &padded).expect("inclusive native JSON byte ceiling");
    padded.push(b' ');
    assert!(engine::native_entry(PROFILE, &padded).is_err());
}

#[test]
fn capacity_native_json_bounds_membership_and_snapshot_metadata() {
    let stored = StoredMembership::new(Some(log_id()), membership(9));
    let mut meta = SnapshotMeta {
        last_log_id: Some(log_id()),
        last_membership: stored.clone(),
        snapshot_id: "x".repeat(128),
    };
    for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
        assert_eq!(
            engine::native_membership(profile, &serde_json::to_vec(&stored).unwrap()).unwrap(),
            stored
        );
        assert_eq!(
            engine::native_snapshot_meta(profile, &serde_json::to_vec(&meta).unwrap()).unwrap(),
            meta
        );
    }
    let pristine = StoredMembership::<ConsensusNodeId, EmptyNode>::default();
    assert_eq!(
        engine::native_membership(PROFILE, &serde_json::to_vec(&pristine).unwrap()).unwrap(),
        pristine
    );
    meta.snapshot_id.push('x');
    let encoded = serde_json::to_vec(&meta).unwrap();
    assert!(engine::native_snapshot_meta(PROFILE, &encoded).is_err());
    assert_eq!(
        engine::native_snapshot_meta(ConfigCapacityProfile::Legacy, &encoded).unwrap(),
        meta
    );
    let mut missing: serde_json::Value = serde_json::to_value(&stored).unwrap();
    missing["membership"]["nodes"]
        .as_object_mut()
        .unwrap()
        .clear();
    assert!(engine::native_membership(PROFILE, &serde_json::to_vec(&missing).unwrap()).is_err());
    let over = StoredMembership::new(Some(log_id()), membership(10));
    assert!(engine::native_membership(PROFILE, &serde_json::to_vec(&over).unwrap()).is_err());
}

#[path = "config_capacity_native_batch_allocation_tests.rs"]
mod native_batch_allocations;

#[path = "config_capacity_native_commit_prefix_tests.rs"]
mod native_commit_prefix;
