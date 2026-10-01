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

#[test]
fn config_capacity_audited_effect_preserves_original_mac_and_tamper_rejection() {
    use crate::consensus::audit_mutation::AuditedConfigEffect;
    use crate::consensus::capacity_record::{CapacityRecordBinding, RECORD_CAPACITY_BYTES};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let key = crate::AuditKey::new([0xa7; 32]).unwrap();
    let wrong_key = crate::AuditKey::new([0xb8; 32]).unwrap();
    for length in [0, 4096, opc_crypto::CONFIG_CAPACITY_V1_ENVELOPE_BYTES] {
        for bounded in [false, true] {
            let commit = Box::new(prepared(
                (0..=255).cycle().take(length).collect(),
                CommitSource::LocalOperator,
                true,
            ));
            let effect = if bounded {
                AuditedConfigEffect::BoundedAppend {
                    commit,
                    binding: CapacityRecordBinding::decode(&[0; RECORD_CAPACITY_BYTES]).unwrap(),
                    resolution: None,
                }
            } else {
                AuditedConfigEffect::Append {
                    commit,
                    resolution: None,
                }
            };
            // Original compact JSON and independent domain/length transcript.
            // Dummy bounded bindings are codec fixtures, not capacity authority.
            let original = serde_json::to_vec(&effect).unwrap();
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
            mac.update(b"openpacketcore/management-audit/config-mutation/v1\0");
            mac.update(&(original.len() as u64).to_be_bytes());
            mac.update(&original);
            let expected: [u8; 32] = mac.finalize().into_bytes().into();
            assert_eq!(effect.digest(&key).unwrap(), expected);
            effect.verify(&key, &expected).unwrap();
            assert!(effect.verify(&wrong_key, &expected).is_err());
            let mut changed = effect.clone();
            match &mut changed {
                AuditedConfigEffect::Append { commit, .. }
                | AuditedConfigEffect::BoundedAppend { commit, .. } => {
                    commit.record.encrypted_blob.push(255);
                }
                _ => unreachable!(),
            }
            assert!(changed.verify(&key, &expected).is_err());
        }
    }
}

#[test]
fn config_capacity_audited_effect_retains_exact_original_size_ceiling() {
    use crate::consensus::audit_mutation::AuditedConfigEffect;

    let key = crate::AuditKey::new([0xa7; 32]).unwrap();
    let mut commit = Box::new(prepared(Vec::new(), CommitSource::LocalOperator, false));
    let empty = AuditedConfigEffect::Append {
        commit: commit.clone(),
        resolution: None,
    };
    let overhead = serde_json::to_vec(&empty).unwrap().len();
    let ceiling = crate::audit_authority::ledger::MAX_STATE_BYTES;
    // Every 255 adds four bytes, except the missing leading comma. Adjust
    // principal ASCII bytes to reach the exact preexisting limit.
    let length = (ceiling - overhead + 1) / 4;
    commit.record.encrypted_blob = vec![255; length];
    let exact = overhead + length * 4 - 1;
    commit
        .record
        .principal
        .push_str(&"x".repeat(ceiling - exact));
    let mut effect = AuditedConfigEffect::Append {
        commit,
        resolution: None,
    };
    assert_eq!(serde_json::to_vec(&effect).unwrap().len(), ceiling);
    assert!(effect.digest(&key).is_ok());
    if let AuditedConfigEffect::Append { commit, .. } = &mut effect {
        commit.record.principal.push('x');
    }
    assert_eq!(serde_json::to_vec(&effect).unwrap().len(), ceiling + 1);
    assert!(matches!(
        effect.digest(&key),
        Err(crate::audit_authority::AuditAuthorityError::InvalidInput)
    ));
}
