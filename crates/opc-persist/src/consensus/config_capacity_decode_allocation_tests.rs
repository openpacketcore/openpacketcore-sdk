//! Decoder allocation controls, including small retained records and exact
//! field ceilings. These are component observations, not a whole-store peak.

use super::*;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DecodeWork {
    bulk_copies: usize,
    copied_bytes: usize,
    allocated_bytes: usize,
    sequence_elements: usize,
}

thread_local! {
    static WORK: Cell<Option<DecodeWork>> = const { Cell::new(None) };
}

pub(super) fn observe_bulk_copy(bytes: usize, capacity: usize) {
    WORK.with(|work| {
        if let Some(mut value) = work.get() {
            value.bulk_copies += 1;
            value.copied_bytes += bytes;
            value.allocated_bytes += capacity;
            work.set(Some(value));
        }
    });
}

pub(super) fn observe_sequence_element() {
    WORK.with(|work| {
        if let Some(mut value) = work.get() {
            value.sequence_elements += 1;
            work.set(Some(value));
        }
    });
}

fn observe<T>(run: impl FnOnce() -> T) -> (T, DecodeWork) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WORK.with(|work| work.set(None));
        }
    }
    WORK.with(|work| {
        assert!(work.get().is_none());
        work.set(Some(DecodeWork::default()));
    });
    let reset = Reset;
    let result = run();
    let work = WORK.with(|work| work.get().unwrap());
    drop(reset);
    (result, work)
}

#[test]
fn capacity_decode_binary_bytes_copy_once_without_per_element_dispatch() {
    const MAX: usize = CONFIG_CAPACITY_V1_ENVELOPE_BYTES;
    for length in [0, 1, 127, 128, 255, 256, 16_383, 16_384, MAX] {
        let source: Vec<u8> = (0..=255).cycle().take(length).collect();
        // The independent original Vec encoder still determines the wire.
        let wire = opc_consensus::encode_bounded(&source).unwrap();
        let (decoded, work) = observe(|| opc_consensus::decode_bounded::<Bytes<MAX>>(&wire));
        let decoded = decoded.unwrap();
        assert_eq!(decoded.0, source);
        assert_eq!(decoded.0.capacity(), length);
        assert_eq!(
            work,
            DecodeWork {
                bulk_copies: 1,
                copied_bytes: length,
                allocated_bytes: length,
                sequence_elements: 0,
            },
            "CONFIG_CAPACITY_BINARY_BULK_DECODE_RED"
        );
    }
}

#[test]
fn capacity_decode_binary_rejects_incomplete_and_oversized_bodies_before_copy() {
    let source: Vec<u8> = (0..=255).collect();
    let wire = opc_consensus::encode_bounded(&source).unwrap();
    for end in 0..wire.len() {
        let (decoded, work) = observe(|| opc_consensus::decode_bounded::<Bytes<256>>(&wire[..end]));
        assert!(decoded.is_err());
        assert_eq!(work, DecodeWork::default());
    }
    for wire in [
        opc_consensus::encode_bounded(&vec![0x55_u8; 257]).unwrap(),
        vec![0xff, 0xff, 0xff, 0xff, 0x0f],
    ] {
        let (decoded, work) = observe(|| opc_consensus::decode_bounded::<Bytes<256>>(&wire));
        assert!(decoded.is_err(), "CONFIG_CAPACITY_BINARY_FIELD_LIMIT_RED");
        assert_eq!(work, DecodeWork::default());
    }
    let mut trailing = wire;
    trailing.push(0);
    assert!(opc_consensus::decode_bounded::<Bytes<256>>(&trailing).is_err());
}

#[test]
fn capacity_decode_bulk_binary_path_does_not_accept_json_strings() {
    for malformed in [
        "\"\"",
        "\"abc\"",
        "\"\\u0000\"",
        "null",
        "{}",
        "[-1]",
        "[256]",
        "[1.0]",
        "[true]",
        "[\"1\"]",
        "[[1]]",
        "[0]0",
    ] {
        assert!(serde_json::from_str::<Vec<u8>>(malformed).is_err());
        assert!(
            serde_json::from_str::<Bytes<256>>(malformed).is_err(),
            "CONFIG_CAPACITY_JSON_BYTE_TYPE_RED"
        );
    }
    let source: Vec<u8> = (0..=255).collect();
    let json = serde_json::to_vec(&source).unwrap();
    let (decoded, work) = observe(|| serde_json::from_slice::<Bytes<256>>(&json));
    assert_eq!(decoded.unwrap().0, source);
    assert_eq!(work.sequence_elements, 256);
    assert_eq!(work.bulk_copies, 0);
}

#[test]
fn capacity_decode_json_bytes_do_not_allocate_the_ceiling_for_small_values() {
    const MAX: usize = CONFIG_CAPACITY_V1_ENVELOPE_BYTES;
    for length in [0, 1, 4095, 4096, 4097, 8193, MAX - 1, MAX] {
        let source = vec![0xCBu8; length];
        let json = serde_json::to_vec(&source).unwrap();
        let decoded = serde_json::from_slice::<Bytes<MAX>>(&json).unwrap();
        assert_eq!(decoded.0, source);
        let allowance = if length == 0 {
            0
        } else {
            length.saturating_add(4095).min(MAX)
        };
        assert!(
            decoded.0.capacity() <= allowance,
            "JSON byte backing capacity exceeds initialized bytes plus one bounded increment"
        );
        let binary = opc_consensus::encode_bounded(&source).unwrap();
        let binary = opc_consensus::decode_bounded::<Bytes<MAX>>(&binary).unwrap();
        assert_eq!(binary.0, source);
        assert_eq!(binary.0.capacity(), length);
    }
    let over = serde_json::to_vec(&vec![0xCBu8; MAX + 1]).unwrap();
    assert!(serde_json::from_slice::<Bytes<MAX>>(&over).is_err());
}

fn audit_record(sequence: u32) -> AuditRecord {
    AuditRecord {
        tx_id: "cbcbcbcb-cbcb-4bcb-8bcb-cbcbcbcbcbcb".parse().unwrap(),
        sequence,
        yang_path: "/test:configuration".to_owned(),
        op_type: crate::types::AuditOpType::Update,
        previous_value: None,
        new_value: Some("\"<redacted>\"".to_owned()),
        redaction_applied: true,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    }
}

#[test]
fn capacity_decode_json_audit_does_not_allocate_the_ceiling_for_small_lists() {
    for count in [0, 1, 15, 16, 17, 63, 64, 65, 129, 1025] {
        let source: Vec<_> = (0..count).map(audit_record).collect();
        let json = serde_json::to_vec(&source).unwrap();
        let decoded = serde_json::from_slice::<Audit>(&json).unwrap();
        assert_eq!(decoded.0, source);
        let allowance = if count == 0 { 0 } else { count as usize + 15 };
        assert!(
            decoded.0.capacity() <= allowance,
            "JSON audit backing capacity exceeds initialized items plus one bounded increment"
        );
        let binary = opc_consensus::encode_bounded(&source).unwrap();
        let binary = opc_consensus::decode_bounded::<Audit>(&binary).unwrap();
        assert_eq!(binary.0, source);
        assert_eq!(binary.0.capacity(), count as usize);
    }
    // A bounded increment cannot bypass the existing aggregate metadata limit.
    let over: Vec<_> = (0..3000).map(audit_record).collect();
    let binary = opc_consensus::encode_bounded(&over).unwrap();
    assert!(binary.len() > CONFIG_CAPACITY_V1_METADATA_BYTES);
    assert!(opc_consensus::decode_bounded::<Audit>(&binary).is_err());
    let json = serde_json::to_vec(&over).unwrap();
    assert!(serde_json::from_slice::<Audit>(&json).is_err());
}
