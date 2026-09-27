//! Decoder allocation controls, including small retained records and exact
//! field ceilings. These are component observations, not a whole-store peak.

use super::*;

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
