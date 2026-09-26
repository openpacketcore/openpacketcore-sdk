//! Complete snapshot wire extents, including both supported discriminators.
//! Native storage and transport effects are qualified by the mTLS fixture.

use super::*;
use crate::consensus::types::encode_config_wire_for_profile;

const MAX_WIRE: u64 = 68_719_476_786;

fn request(offset: u64, bytes: usize, done: bool) -> InstallSnapshotRequest<ConfigRaftTypeConfig> {
    InstallSnapshotRequest {
        vote: Vote::new_committed(2, ConsensusNodeId::new(1).unwrap()),
        meta: SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "synthetic-extent".into(),
        },
        offset,
        data: vec![0xA6; bytes],
        done,
    }
}

#[test]
fn capacity_snapshot_extent_at_limit_preserves_both_profiles() {
    assert_eq!(crate::consensus::storage::SNAPSHOT_MAX_WIRE_BYTES, MAX_WIRE);
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        for done in [false, true] {
            for (offset, len) in [
                (0, 0),
                (MAX_WIRE, 0),
                (MAX_WIRE - 1, 1),
                (MAX_WIRE - SNAPSHOT_CHUNK_BYTES as u64, SNAPSHOT_CHUNK_BYTES),
            ] {
                let source = request(offset, len, done);
                let bytes = encode_config_wire_for_profile(profile, &source).unwrap();
                let decoded = snapshot(profile, &bytes).expect("exact supported snapshot extent");
                assert!(
                    encode_config_wire_for_profile(profile, &decoded).unwrap() == bytes,
                    "complete extent preserves original wire encoding"
                );
            }
        }
    }
}

#[test]
fn capacity_snapshot_extent_one_over_and_overflow_reject_both_profiles() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        for done in [false, true] {
            for (offset, len) in [
                (MAX_WIRE, 1),
                (MAX_WIRE + 1, 0),
                (
                    MAX_WIRE - SNAPSHOT_CHUNK_BYTES as u64 + 1,
                    SNAPSHOT_CHUNK_BYTES,
                ),
                (u64::MAX, 1),
                (u64::MAX, 0),
            ] {
                let bytes =
                    encode_config_wire_for_profile(profile, &request(offset, len, done)).unwrap();
                assert!(
                    matches!(snapshot(profile, &bytes), Err(ConsensusCodecError::Decode)),
                    "CONFIG_CAPACITY_SNAPSHOT_EXTENT_DECODE_RED: refuse unsupported complete extent"
                );
            }
        }
    }
}
