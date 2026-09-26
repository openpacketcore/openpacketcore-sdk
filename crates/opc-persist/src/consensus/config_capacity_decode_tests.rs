//! Typed decoder boundaries and malformed input controls.

use super::*;

#[test]
fn capacity_decode_bounds_byte_arrays_before_hints_or_growth() {
    for length in [0, 1, 32] {
        let bytes = vec![0x51u8; length];
        let json = serde_json::to_vec(&bytes).unwrap();
        let binary = opc_consensus::encode_bounded(&bytes).unwrap();
        assert_eq!(
            opc_consensus::decode_bounded::<Bytes<32>>(&binary)
                .unwrap()
                .0
                .capacity(),
            length,
            "binary size hints reserve the exact admitted extent",
        );
        for decoded in [
            serde_json::from_slice::<Bytes<32>>(&json).unwrap(),
            opc_consensus::decode_bounded::<Bytes<32>>(&binary).unwrap(),
        ] {
            assert_eq!(decoded.0, bytes);
            assert!(decoded.0.capacity() <= 32);
        }
    }
    let oversized = vec![0u8; 33];
    assert!(serde_json::from_slice::<Bytes<32>>(&serde_json::to_vec(&oversized).unwrap()).is_err());
    assert!(opc_consensus::decode_bounded::<Bytes<32>>(
        &opc_consensus::encode_bounded(&oversized).unwrap()
    )
    .is_err());
    // A huge declared postcard length with no elements must be rejected; it
    // must never be passed to Vec's default size-hint allocation.
    assert!(opc_consensus::decode_bounded::<Bytes<32>>(&[0xff, 0xff, 0xff, 0xff, 0x0f]).is_err());
    for malformed in [b"[0,256]".as_slice(), b"[0,\"x\"]", b"[0", b"[0]0"] {
        assert!(serde_json::from_slice::<Bytes<32>>(malformed).is_err());
    }
}

#[test]
fn capacity_decode_bounds_raw_json_scratch_and_decoded_text_independently() {
    let escaped = format!("\"{}\"", "\\u0000".repeat(CONFIG_PRINCIPAL_MAX_BYTES));
    json_string_preflight(escaped.as_bytes()).unwrap();
    let text = serde_json::from_str::<Text<CONFIG_PRINCIPAL_MAX_BYTES>>(&escaped).unwrap();
    assert_eq!(text.0.len(), CONFIG_PRINCIPAL_MAX_BYTES);
    assert_eq!(text.0.capacity(), CONFIG_PRINCIPAL_MAX_BYTES);
    let over = format!("\"{}\"", "\\u0000".repeat(CONFIG_PRINCIPAL_MAX_BYTES + 1));
    assert!(json_string_preflight(over.as_bytes()).is_err());
    let unescaped = format!("\"{}\"", "x".repeat(CONFIG_PRINCIPAL_MAX_BYTES + 1));
    json_string_preflight(unescaped.as_bytes()).unwrap();
    assert!(serde_json::from_str::<Text<CONFIG_PRINCIPAL_MAX_BYTES>>(&unescaped).is_err());
    for value in ["\\\"", "é😀", "\n\t\0", "\\u1234"] {
        let encoded = serde_json::to_vec(value).unwrap();
        json_string_preflight(&encoded).unwrap();
        assert_eq!(
            serde_json::from_slice::<Text<128>>(&encoded).unwrap().0,
            value
        );
    }
    for malformed in [b"\"unterminated".as_slice(), b"\"\\", b"\"\\q\""] {
        assert!(
            json_string_preflight(malformed).is_err()
                || serde_json::from_slice::<Text<128>>(malformed).is_err()
        );
    }
}

fn record(sequence: u32) -> AuditRecord {
    AuditRecord {
        tx_id: "51515151-5151-4515-8515-515151515151".parse().unwrap(),
        sequence,
        yang_path: "/test:x".to_owned(),
        op_type: crate::types::AuditOpType::Update,
        previous_value: Some("\"<redacted>\"".to_owned()),
        new_value: None,
        redaction_applied: true,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    }
}

#[test]
fn capacity_decode_counts_audit_after_replication_count_boundary() {
    let input: Vec<_> = (0..1025).map(record).collect();
    let encoded = opc_consensus::encode_bounded(&input).unwrap();
    assert!(encoded.len() < 196_608);
    let decoded = opc_consensus::decode_bounded::<Audit>(&encoded).unwrap();
    assert_eq!(decoded.0, input);
    assert_eq!(decoded.0.capacity(), input.len());
    let mut large = input;
    while opc_consensus::encode_bounded(&large).unwrap().len() <= 196_608 + 8 {
        large.push(record(large.len() as u32));
    }
    assert!(large.len() > 1024 && large.len() < AUDIT_ITEMS);
    assert!(opc_consensus::decode_bounded::<Audit>(
        &opc_consensus::encode_bounded(&large).unwrap()
    )
    .is_err());
    assert!(serde_json::from_slice::<Audit>(&serde_json::to_vec(&large).unwrap()).is_err());
}

#[test]
fn capacity_decode_caps_individual_audit_fields_and_collection_count() {
    let mut value = record(0);
    value.yang_path = "x".repeat(8192);
    value.previous_value = Some("x".repeat(12));
    value.new_value = Some("x".repeat(12));
    let at = serde_json::to_vec(&vec![value.clone()]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Audit>(&at).unwrap().0,
        vec![value.clone()]
    );
    for field in 0..3 {
        let mut over = value.clone();
        match field {
            0 => over.yang_path.push('x'),
            1 => over.previous_value.as_mut().unwrap().push('x'),
            _ => over.new_value.as_mut().unwrap().push('x'),
        }
        assert!(
            serde_json::from_slice::<Audit>(&serde_json::to_vec(&vec![over]).unwrap()).is_err()
        );
    }
    let many: Vec<_> = (0..=AUDIT_ITEMS)
        .map(|index| record(index as u32))
        .collect();
    let bytes = opc_consensus::encode_bounded(&many).unwrap();
    assert!(opc_consensus::decode_bounded::<Audit>(&bytes).is_err());
}
