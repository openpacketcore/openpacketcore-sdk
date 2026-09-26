//! Original bounded Serde decoding is the independent compatibility oracle.
//! Synthetic envelopes exercise only codec ownership/format, not authority.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::types::{ConfigConsensusCommand, PreparedConfigCommit};
use crate::types::CommitSource;
use crate::CommitRecord;
use opc_consensus::engine::{CommittedLeaderId, LogId};
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusIdentity,
    ConsensusNodeId, ConsensusRequestId,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use std::str::FromStr;

fn fixture(length: usize, byte: Option<u8>) -> Entry<ConfigRaftTypeConfig> {
    let identity = ConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x91; 32]),
        ConsensusConfigurationId::from_bytes([0x92; 32]),
        ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(1, ConsensusNodeId::new(1).unwrap()),
            3,
        ),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: 5,
            identity,
            request_id: ConsensusRequestId::new(),
            logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
            intent: ConfigMutationIntent::BoundedAppend {
                commit: Box::new(PreparedConfigCommit {
                    record: CommitRecord {
                        tx_id: TxId::new(),
                        parent_tx_id: Some(TxId::new()),
                        version: ConfigVersion::new(2),
                        committed_at: Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
                        principal: "synthetic\0\n\"\\é🦀".to_owned(),
                        source: CommitSource::LocalOperator,
                        schema_digest: SchemaDigest::from_bytes([0x93; 32]),
                        plaintext_digest: vec![0x94; 32],
                        encrypted_blob: (0..=255)
                            .cycle()
                            .take(length)
                            .map(|v| byte.unwrap_or(v))
                            .collect(),
                        rollback_point: true,
                        confirmed_deadline: Some(
                            Timestamp::from_str("2026-01-02T00:00:00Z").unwrap(),
                        ),
                    },
                    audit: Vec::new(),
                }),
                binding: CapacityRecordBinding::decode(
                    &[0; crate::consensus::capacity_record::RECORD_CAPACITY_BYTES],
                )
                .unwrap(),
                resolution: None,
            },
        }),
    }
}

fn original(bytes: &[u8]) -> io::Result<Entry<ConfigRaftTypeConfig>> {
    super::super::native::<EntryFields>(bytes).map(Into::into)
}

fn require_compatible(bytes: &[u8]) {
    let expected = original(bytes);
    let actual = entry(bytes);
    assert!(
        expected.is_ok() == actual.is_ok(),
        "CONFIG_CAPACITY_NATIVE_JSON_ACCEPTANCE_RED"
    );
    if let (Ok(expected), Ok(actual)) = (expected, actual) {
        assert!(
            actual == expected,
            "CONFIG_CAPACITY_NATIVE_JSON_COMPATIBILITY_RED"
        );
    }
}

#[test]
fn config_capacity_native_json_matches_original_at_byte_and_envelope_boundaries() {
    for length in [
        0,
        1,
        255,
        256,
        4095,
        4096,
        4097,
        16_383,
        16_384,
        CONFIG_CAPACITY_V1_ENVELOPE_BYTES,
        CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1,
    ] {
        let source = fixture(length, None);
        let bytes = serde_json::to_vec(&source).unwrap();
        require_compatible(&bytes);
        if (MIN_FAST_BYTES..=CONFIG_CAPACITY_V1_ENVELOPE_BYTES).contains(&length) {
            let fast = canonical_entry(&bytes)
                .unwrap()
                .expect("canonical bounded ordinary append");
            let EntryPayload::Normal(command) = fast.payload else {
                unreachable!()
            };
            let ConfigMutationIntent::BoundedAppend { commit, .. } = command.intent else {
                unreachable!()
            };
            assert_eq!(commit.record.encrypted_blob.len(), length);
            assert_eq!(commit.record.encrypted_blob.capacity(), length);
        }
    }
    for byte in [0, 9, 10, 99, 100, 255] {
        let source = fixture(4096, Some(byte));
        require_compatible(&serde_json::to_vec(&source).unwrap());
    }
}

#[test]
fn config_capacity_native_json_retains_noncanonical_and_malformed_input_behavior() {
    let source = fixture(4096, None);
    let bytes = serde_json::to_vec(&source).unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    let field = body.find("\"encrypted_blob\":").unwrap() + FIELD.len();
    let (_, count) = array_extent(&bytes[field..]).unwrap();
    assert_eq!(count, 4096);
    require_compatible(&serde_json::to_vec_pretty(&source).unwrap());
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    require_compatible(&serde_json::to_vec(&value).unwrap());
    let mut unknown = value.clone();
    unknown.as_object_mut().unwrap().insert(
        "unused".to_owned(),
        serde_json::json!({"encrypted_blob": [1, 2, 3]}),
    );
    require_compatible(&serde_json::to_vec(&unknown).unwrap());
    let mut duplicate = body.to_owned();
    duplicate.insert_str(1, "\"log_id\":null,");
    require_compatible(duplicate.as_bytes());
    let mut wrong_span = body.to_owned();
    wrong_span.insert_str(
        1,
        &format!(
            "\"unused\":{{\"encrypted_blob\":[{}]}},",
            vec!["1"; 4096].join(",")
        ),
    );
    require_compatible(wrong_span.as_bytes());
    for replacement in [
        "256", "-1", "1.0", "1e2", "01", "+1", "null", "true", "\"1\"", "{}", "[]", " 0 ",
    ] {
        let mut changed = body.to_owned();
        changed.replace_range(field + 1..field + 2, replacement);
        require_compatible(changed.as_bytes());
    }
    for cut in [0, 1, field, field + 1, field + 2, bytes.len() - 1] {
        require_compatible(&bytes[..cut]);
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b" true");
    require_compatible(&trailing);
    let mut whitespace = bytes.clone();
    whitespace.extend_from_slice(b" \n\t");
    require_compatible(&whitespace);
}

#[test]
fn config_capacity_native_json_observes_original_and_canonical_decode_work() {
    let source = fixture(CONFIG_CAPACITY_V1_ENVELOPE_BYTES, None);
    let bytes = serde_json::to_vec(&source).unwrap();
    let start = std::time::Instant::now();
    let expected = original(&bytes).unwrap();
    let original_us = start.elapsed().as_micros();
    let start = std::time::Instant::now();
    let actual = entry(&bytes).unwrap();
    let current_us = start.elapsed().as_micros();
    assert!(
        actual == expected,
        "CONFIG_CAPACITY_NATIVE_JSON_COMPATIBILITY_RED"
    );
    println!("CONFIG_CAPACITY_NATIVE_JSON encoded_bytes={} original_us={} current_us={} canonical_equality=true", bytes.len(), original_us, current_us);
    // This timing is an observation. The unchanged native eight-operation
    // deadline, not a new component timing allowance, qualifies progress.
}

fn previous_decimal_byte(bytes: &[u8], index: &mut usize) -> Option<u8> {
    let first = *bytes.get(*index)?;
    if !first.is_ascii_digit() {
        return None;
    }
    *index += 1;
    let mut value = u16::from(first - b'0');
    if first != b'0' {
        for _ in 0..2 {
            let next = *bytes.get(*index)?;
            if !next.is_ascii_digit() {
                break;
            }
            value = value * 10 + u16::from(next - b'0');
            *index += 1;
        }
    }
    u8::try_from(value).ok()
}

fn previous_array_extent(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.first().copied()? != b'[' {
        return None;
    }
    if bytes.get(1) == Some(&b']') {
        return Some((2, 0));
    }
    let mut index = 1;
    let mut count = 0;
    loop {
        previous_decimal_byte(bytes, &mut index)?;
        count += 1;
        if count > CONFIG_CAPACITY_V1_ENVELOPE_BYTES {
            return None;
        }
        match bytes.get(index).copied()? {
            b']' => return Some((index + 1, count)),
            b',' => index += 1,
            _ => return None,
        }
    }
}

#[test]
fn config_capacity_native_json_tokens_preserve_complete_array_preflight() {
    for number in 0..=1024 {
        for tail in [",0]", "]", "x]", ".0]", "e2]", " ", ""] {
            let bytes = format!("[{number}{tail}");
            assert!(
                previous_array_extent(bytes.as_bytes()) == array_extent(bytes.as_bytes()),
                "CONFIG_CAPACITY_NATIVE_JSON_TOKEN_PREFLIGHT_RED"
            );
        }
    }
    for prefix in ["", "0", "00", "-", "+", " ", "\"", "[", "null", "true"] {
        for number in 0..=255 {
            let bytes = format!("[{prefix}{number}]");
            assert!(
                previous_array_extent(bytes.as_bytes()) == array_extent(bytes.as_bytes()),
                "CONFIG_CAPACITY_NATIVE_JSON_TOKEN_PREFLIGHT_RED"
            );
        }
    }
    let source = fixture(CONFIG_CAPACITY_V1_ENVELOPE_BYTES, None);
    let bytes = serde_json::to_vec(&source).unwrap();
    let key = bytes
        .windows(FIELD.len())
        .position(|part| part == FIELD)
        .unwrap();
    let array = &bytes[key + FIELD.len()..];
    assert!(
        previous_array_extent(array) == array_extent(array),
        "CONFIG_CAPACITY_NATIVE_JSON_TOKEN_PREFLIGHT_RED"
    );
    let source = fixture(CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1, None);
    let bytes = serde_json::to_vec(&source).unwrap();
    let key = bytes
        .windows(FIELD.len())
        .position(|part| part == FIELD)
        .unwrap();
    let array = &bytes[key + FIELD.len()..];
    assert!(
        previous_array_extent(array).is_none() && array_extent(array).is_none(),
        "CONFIG_CAPACITY_NATIVE_JSON_TOKEN_PREFLIGHT_RED"
    );
}
