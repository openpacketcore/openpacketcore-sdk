//! Snapshot extent validation through the actual inbound adapter boundary.
//! Restoring the Legacy direct-decode bypass must fail the refusal tests.

use super::*;
use crate::consensus::RetainedConfigMode;
use opc_consensus::engine::{SnapshotMeta, StoredMembership};

const MAX_WIRE: u64 = 68_719_476_786;
const CHUNK_BYTES: usize = 1_048_576;
const MODES: [RetainedConfigMode; 4] = [
    RetainedConfigMode::Legacy,
    RetainedConfigMode::BoundedV1,
    RetainedConfigMode::NetconfTargetsV1,
    RetainedConfigMode::NetconfRunningV1,
];

type Request = InstallSnapshotRequest<ConfigRaftTypeConfig>;

fn request(offset: u64, len: usize, done: bool) -> Request {
    Request {
        vote: Vote::new_committed(2, ConsensusNodeId::new(1).unwrap()),
        meta: SnapshotMeta {
            last_log_id: None,
            last_membership: StoredMembership::default(),
            snapshot_id: "synthetic-adapter-extent".into(),
        },
        offset,
        data: vec![0xA6; len],
        done,
    }
}

fn decode(mode: RetainedConfigMode, source: &Request) -> Result<Request, ConsensusPeerError> {
    let payload = encode_config_wire_for_profile(mode, source).expect("synthetic wire request");
    decode_and_bind_sender::<Request>(&payload, ConsensusNodeId::new(1).unwrap(), mode)
}

#[test]
fn snapshot_adapter_accepts_at_limit_extents_for_all_retained_modes() {
    for mode in MODES {
        for done in [false, true] {
            for (offset, len) in [
                (0, 0),
                (MAX_WIRE, 0),
                (MAX_WIRE - 1, 1),
                (MAX_WIRE - CHUNK_BYTES as u64, CHUNK_BYTES),
            ] {
                let source = request(offset, len, done);
                let decoded =
                    decode(mode, &source).expect("supported extent reaches native handoff");
                assert!(
                    encode_config_wire_for_profile(mode, &decoded).unwrap()
                        == encode_config_wire_for_profile(mode, &source).unwrap(),
                    "adapter preserves the exact accepted snapshot request"
                );
            }
        }
    }
}

#[test]
fn snapshot_adapter_rejects_one_over_extents_for_all_retained_modes() {
    for mode in MODES {
        for done in [false, true] {
            for (offset, len) in [
                (MAX_WIRE, 1),
                (MAX_WIRE + 1, 0),
                (MAX_WIRE - CHUNK_BYTES as u64 + 1, CHUNK_BYTES),
            ] {
                assert!(
                    matches!(
                        decode(mode, &request(offset, len, done)),
                        Err(ConsensusPeerError::Protocol)
                    ),
                    "SNAPSHOT_ADAPTER_EXTENT_RED: one-over extent must fail before native handoff; mode={mode:?} done={done} offset={offset} len={len}"
                );
            }
        }
    }
}

#[test]
fn snapshot_adapter_rejects_overflow_and_extreme_offsets_for_all_retained_modes() {
    for mode in MODES {
        for done in [false, true] {
            for len in [1, 0] {
                assert!(
                    matches!(
                        decode(mode, &request(u64::MAX, len, done)),
                        Err(ConsensusPeerError::Protocol)
                    ),
                    "SNAPSHOT_ADAPTER_OVERFLOW_RED: overflowing or extreme extent must fail before native handoff; mode={mode:?} done={done} len={len}"
                );
            }
        }
    }
}

#[test]
fn snapshot_adapter_preserves_profile_and_sender_refusals() {
    let source = request(0, 1, false);
    for mode in MODES {
        let payload = encode_config_wire_for_profile(mode, &source).unwrap();
        for receiver_mode in MODES {
            if receiver_mode == mode {
                continue;
            }
            assert!(
                matches!(
                    decode_and_bind_sender::<Request>(
                        &payload,
                        ConsensusNodeId::new(1).unwrap(),
                        receiver_mode,
                    ),
                    Err(ConsensusPeerError::Protocol)
                ),
                "the adapter rejects a mismatched snapshot discriminator"
            );
        }
        assert!(
            matches!(
                decode_and_bind_sender::<Request>(&payload, ConsensusNodeId::new(2).unwrap(), mode,),
                Err(ConsensusPeerError::ScopeMismatch)
            ),
            "the adapter preserves authenticated vote/sender binding"
        );
    }
}

#[test]
fn snapshot_adapter_preserves_legacy_field_compatibility() {
    for (legacy, bounded) in [
        (RetainedConfigMode::Legacy, RetainedConfigMode::BoundedV1),
        (
            RetainedConfigMode::NetconfTargetsV1,
            RetainedConfigMode::NetconfRunningV1,
        ),
    ] {
        for (id_bytes, chunk_bytes) in [(129, 0), (128, CHUNK_BYTES + 1)] {
            let mut source = request(0, chunk_bytes, false);
            source.meta.snapshot_id = "x".repeat(id_bytes);
            let decoded = decode(legacy, &source).expect("Legacy retains native field decoding");
            assert!(
                encode_config_wire_for_profile(legacy, &decoded).unwrap()
                    == encode_config_wire_for_profile(legacy, &source).unwrap(),
                "complete extent validation does not add BoundedV1 field limits to Legacy"
            );
            assert!(
                matches!(decode(bounded, &source), Err(ConsensusPeerError::Protocol)),
                "BoundedV1 retains its snapshot field limits"
            );
        }
    }
}
