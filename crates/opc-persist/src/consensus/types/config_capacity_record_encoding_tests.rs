//! The original CommitRecord encoder is the compatibility oracle. Changing a
//! field, its order, option representation or any encrypted byte must fail.
//! These synthetic codec cases confer no encryption or capacity authority.

use super::super::PreparedConfigCommit;
use crate::types::{AuditOpType, CommitSource};
use crate::{AuditRecord, CommitRecord};
use opc_consensus::{decode_bounded, encode_bounded, AppendEntriesBatchAccumulator};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use serde::Serialize;
use std::str::FromStr;

#[derive(Serialize)]
#[serde(rename = "PreparedConfigCommit")]
struct OriginalPrepared<'a> {
    record: &'a CommitRecord,
    audit: &'a [AuditRecord],
}

fn prepared(bytes: Vec<u8>, source: CommitSource, options: bool) -> PreparedConfigCommit {
    let tx_id = TxId::new();
    let time = Timestamp::from_str("2026-01-01T00:00:00.123456789Z").unwrap();
    PreparedConfigCommit {
        record: CommitRecord {
            tx_id,
            parent_tx_id: options.then(TxId::new),
            version: ConfigVersion::new(u64::MAX),
            committed_at: time,
            principal: "synthetic\0\n\"\\é🦀".to_owned(),
            source,
            schema_digest: SchemaDigest::from_bytes([0xa5; 32]),
            plaintext_digest: (0..32).collect(),
            encrypted_blob: bytes,
            rollback_point: options,
            confirmed_deadline: options.then_some(time),
        },
        audit: vec![AuditRecord {
            tx_id,
            sequence: 0,
            yang_path: "/synthetic:path".to_owned(),
            op_type: AuditOpType::Replace,
            previous_value: options.then(|| "\"<redacted>\"".to_owned()),
            new_value: Some("\"<redacted>\"".to_owned()),
            redaction_applied: true,
            previous_hash: [0; 32],
            entry_hmac: [0xb6; 32],
        }],
    }
}

fn require_original_encoding(value: &PreparedConfigCommit, pretty: bool) {
    let original = OriginalPrepared {
        record: &value.record,
        audit: &value.audit,
    };
    let json = serde_json::to_vec(&original).unwrap();
    assert!(
        serde_json::to_vec(value).unwrap() == json,
        "CONFIG_CAPACITY_RECORD_JSON_COMPATIBILITY_RED"
    );
    let mut batched = Vec::new();
    crate::consensus::config_capacity_json::to_writer(&mut batched, value).unwrap();
    assert!(
        batched == json,
        "CONFIG_CAPACITY_BATCH_JSON_COMPATIBILITY_RED"
    );
    assert!(serde_json::from_slice::<PreparedConfigCommit>(&json).unwrap() == *value);
    if pretty {
        assert_eq!(
            serde_json::to_vec_pretty(value).unwrap(),
            serde_json::to_vec_pretty(&original).unwrap()
        );
    }
    let encoded = encode_bounded(&original).unwrap();
    assert!(
        encode_bounded(value).unwrap() == encoded,
        "CONFIG_CAPACITY_RECORD_POSTCARD_COMPATIBILITY_RED"
    );
    assert!(decode_bounded::<PreparedConfigCommit>(&encoded).unwrap() == *value);
    let mut count = AppendEntriesBatchAccumulator::new();
    count.consider(value).unwrap();
    assert_eq!(count.serialized_entry_bytes(), encoded.len());
}

#[test]
fn config_capacity_record_encoding_preserves_all_bytes_fields_and_options() {
    for source in [
        CommitSource::Gnmi,
        CommitSource::Netconf,
        CommitSource::LocalOperator,
        CommitSource::StartupRestore,
        CommitSource::Rollback,
        CommitSource::CommitConfirmedRestore,
    ] {
        for options in [false, true] {
            for length in [0, 1, 9, 10, 99, 100, 127, 128, 255, 256, 16_383, 16_384] {
                let bytes = (0..=255).cycle().take(length).collect();
                require_original_encoding(&prepared(bytes, source.clone(), options), true);
            }
        }
    }
}

#[test]
fn config_capacity_record_encoding_preserves_large_decimal_expansion_and_binary_length() {
    for byte in [0, 99, 255] {
        require_original_encoding(
            &prepared(
                vec![byte; opc_crypto::CONFIG_CAPACITY_V1_ENVELOPE_BYTES],
                CommitSource::LocalOperator,
                true,
            ),
            false,
        );
    }
}
