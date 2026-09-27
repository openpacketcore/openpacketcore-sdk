//! Original bounded Serde decoding is the independent compatibility oracle.
//! Synthetic envelopes exercise only codec ownership/format, not authority.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::types::{ConfigConsensusCommand, PreparedConfigCommit};
use crate::types::CommitSource;
use crate::CommitRecord;
use opc_consensus::engine::{CommittedLeaderId, EntryPayload, LogId};
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

// Synthetic codec input only. Native cost tests separately require a real
// encryption claim, intent receipt, authenticated result and retained reopen.
fn audited_fixture(length: usize) -> Entry<ConfigRaftTypeConfig> {
    use crate::audit_authority::ledger::HandleBody;
    use crate::audit_authority::{
        AuditCaller, AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, AuditToken,
        ProjectedAuditEvent,
    };
    use crate::consensus::audit_mutation::{AuditedConfigEffect, PreparedAuditedMutation};

    let Entry { log_id, payload } = fixture(length, None);
    let EntryPayload::Normal(mut command) = payload else {
        unreachable!()
    };
    let ConfigMutationIntent::BoundedAppend {
        commit,
        binding,
        resolution,
    } = command.intent
    else {
        unreachable!()
    };
    let effect = AuditedConfigEffect::BoundedAppend {
        commit,
        binding,
        resolution,
    };
    let key = crate::AuditKey::new([0x95; 32]).unwrap();
    let privacy = AuditPrivacyKey::new([0x96; 32]).unwrap();
    let caller = AuditCaller::project(&privacy, "test", "synthetic").unwrap();
    let token = AuditToken::from_keyed_projection([0x97; 32]).unwrap();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: command.identity,
            binding: AuditOperationBinding {
                caller,
                request: token,
                operation: token,
                base_version: 1,
            },
            event: ProjectedAuditEvent {
                projection: token,
                caller,
                request: token,
                transaction: None,
                paths: token,
                reason: None,
                transport: crate::ManagementAuditTransportCode::Gnmi,
                operation: crate::ManagementAuditOperationCode::Update,
                outcome: crate::ManagementAuditOutcomeCode::Intent,
                utc_seconds: 100,
                nanosecond: 0,
            },
            issued_at: 100,
            expires_at: 160,
            nonce: [0x98; 16],
            key_epoch: key.epoch(),
            mutation: Some(effect.digest(&key).unwrap()),
        },
        &key,
    )
    .unwrap();
    command.schema_version = 8;
    command.intent = ConfigMutationIntent::AuditedMutation(
        PreparedAuditedMutation::new(handle, effect, None)
            .command()
            .clone(),
    );
    Entry {
        log_id,
        payload: EntryPayload::Normal(command),
    }
}

#[test]
fn config_capacity_native_json_audited_matches_original_at_envelope_boundaries() {
    for length in [
        4095,
        4096,
        4097,
        CONFIG_CAPACITY_V1_ENVELOPE_BYTES,
        CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1,
    ] {
        let source = audited_fixture(length);
        let bytes = serde_json::to_vec(&source).unwrap();
        require_compatible(&bytes);
        if (MIN_FAST_BYTES..=CONFIG_CAPACITY_V1_ENVELOPE_BYTES).contains(&length) {
            let fast = canonical_entry(&bytes)
                .unwrap()
                .expect("canonical bounded audited append");
            assert!(fast == source, "exact audited command, handle and binding");
            let EntryPayload::Normal(command) = fast.payload else {
                unreachable!()
            };
            let ConfigMutationIntent::AuditedMutation(prepared) = command.intent else {
                unreachable!()
            };
            let crate::consensus::audit_mutation::AuditedConfigEffect::BoundedAppend {
                commit, ..
            } = &prepared.effect
            else {
                unreachable!()
            };
            assert_eq!(commit.record.encrypted_blob.len(), length);
            assert_eq!(commit.record.encrypted_blob.capacity(), length);
        }
    }
}

#[test]
fn config_capacity_native_json_audited_preserves_fallback_and_wrong_span_rejection() {
    let source = audited_fixture(4096);
    let bytes = serde_json::to_vec(&source).unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    let field = body.find("\"encrypted_blob\":").unwrap() + FIELD.len();
    require_compatible(&serde_json::to_vec_pretty(&source).unwrap());
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    require_compatible(&serde_json::to_vec(&value).unwrap());
    let mut wrong_span = body.to_owned();
    wrong_span.insert_str(
        1,
        &format!(
            "\"unused\":{{\"encrypted_blob\":[{}]}},",
            vec!["1"; 4096].join(",")
        ),
    );
    assert!(canonical_entry(wrong_span.as_bytes()).unwrap().is_none());
    require_compatible(wrong_span.as_bytes());
    let mut duplicate = body.to_owned();
    duplicate.insert_str(1, "\"log_id\":null,");
    require_compatible(duplicate.as_bytes());
    for replacement in ["256", "-1", "1.0", "01", "null", "true", "\"1\"", " 0 "] {
        let mut changed = body.to_owned();
        changed.replace_range(field + 1..field + 2, replacement);
        require_compatible(changed.as_bytes());
    }
    let legacy_effect = body.replacen("\"BoundedAppend\":", "\"Append\":", 1);
    assert!(canonical_entry(legacy_effect.as_bytes()).unwrap().is_none());
    require_compatible(legacy_effect.as_bytes());
    for cut in [0, 1, field, field + 1, field + 2, bytes.len() - 1] {
        require_compatible(&bytes[..cut]);
    }
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b" true");
    require_compatible(&trailing);
    let mut whitespace = bytes;
    whitespace.extend_from_slice(b" \n\t");
    require_compatible(&whitespace);
}

// These are codec compatibility checks, not fabricated authority successes.
// The request-specific native cost tests exercise encryption, authentication,
// committed readback, original recovery and retained reopen before this bound.
#[cfg(target_os = "linux")]
#[test]
fn config_capacity_native_json_comparison_reuses_validated_ciphertext_span() {
    use crate::consensus::store::config_capacity_cost_observation::Observation;

    for source in [fixture(16_384, None), audited_fixture(16_384)] {
        let EntryPayload::Normal(command) = &source.payload else {
            unreachable!()
        };
        let observation = Observation::new(command.request_id);
        let bytes = serde_json::to_vec(&source).unwrap();
        let key = bytes
            .windows(FIELD.len())
            .position(|part| part == FIELD)
            .unwrap();
        let (extent, count) = array_extent(&bytes[key + FIELD.len()..]).unwrap();
        assert_eq!(count, 16_384);
        let actual = entry(&bytes).expect("canonical bounded native entry");
        assert!(actual == original(&bytes).unwrap());
        assert_eq!(serde_json::to_vec(&actual).unwrap(), bytes);
        let counts = observation.snapshot();
        assert_eq!(counts.native_canonical_decodes, 1);
        assert_eq!(counts.native_fallback_decodes, 0);
        assert_eq!(counts.native_canonical_compares, 1);
        assert!(counts.native_canonical_compare_writes > 0);
        assert_eq!(counts.native_canonical_compare_ciphertext_bytes, extent);
        assert_eq!(
            counts.native_canonical_compare_largest_writes,
            extent,
            "CONFIG_CAPACITY_NATIVE_CANONICAL_SPAN_RED: observe the actual comparison write, after independent full-value and exact-byte equality"
        );
    }
}

#[test]
fn config_capacity_native_json_span_reuse_preserves_all_fields_and_tokens() {
    for source in [fixture(16_384, None), audited_fixture(16_384)] {
        let bytes = serde_json::to_vec(&source).unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        let start = body.find("\"encrypted_blob\":").unwrap() + FIELD.len();
        let (extent, _) = array_extent(&bytes[start..]).unwrap();
        let end = start + extent;

        // Valid changed ciphertext remains changed data; the codec confers no
        // authentication. Native proof tests separately reject forged bindings.
        let mut changed_value = body.to_owned();
        changed_value.replace_range(start + 1..start + 2, "1");
        require_compatible(changed_value.as_bytes());
        let decoded = entry(changed_value.as_bytes()).unwrap();
        assert!(decoded != source);
        assert_eq!(
            serde_json::to_vec(&decoded).unwrap(),
            changed_value.as_bytes()
        );

        // This field follows the ciphertext. Every suffix byte must still be
        // compared against the bounded DTO's canonical representation.
        let changed_metadata =
            body.replacen("\"rollback_point\":true", "\"rollback_point\":false", 1);
        assert_ne!(changed_metadata, body);
        require_compatible(changed_metadata.as_bytes());
        let decoded = entry(changed_metadata.as_bytes()).unwrap();
        assert!(decoded != source);
        assert_eq!(
            serde_json::to_vec(&decoded).unwrap(),
            changed_metadata.as_bytes()
        );

        // A fully canonical but unrelated equal-sized span cannot bind the
        // selected typed ciphertext; preserve the original fallback behavior.
        let mut wrong_span = body.to_owned();
        wrong_span.insert_str(
            1,
            &format!("\"unused\":{{\"encrypted_blob\":{}}},", &body[start..end]),
        );
        assert!(canonical_entry(wrong_span.as_bytes()).unwrap().is_none());
        require_compatible(wrong_span.as_bytes());

        // Exercise malformed tokens at the end, beyond a long valid prefix.
        let last = body[..end - 1].rfind(',').unwrap() + 1;
        for token in ["256", "-1", "00", "1.0", "null", "\"1\"", "[]"] {
            let mut malformed = body.to_owned();
            malformed.replace_range(last..end - 1, token);
            assert!(entry(malformed.as_bytes()).is_err());
            require_compatible(malformed.as_bytes());
        }
        let mut duplicate_suffix = body.to_owned();
        duplicate_suffix.insert_str(end, ",\"encrypted_blob\":[]");
        assert!(entry(duplicate_suffix.as_bytes()).is_err());
        require_compatible(duplicate_suffix.as_bytes());
        require_compatible(&serde_json::to_vec_pretty(&source).unwrap());
    }
}

#[test]
fn config_capacity_joint_digests_cover_ordinary_and_audited_native_transcripts() {
    use crate::consensus::types::ConfigConsensusEntryDigest;
    use sha2::{Digest, Sha256};

    // These existing fixtures are codec inputs, not admission authorities.
    // Actual authenticated readback/recovery/reopen remains in native cost tests.
    let mut emissions = Vec::new();
    for (family, source) in [
        ("ordinary", fixture(16_384, None)),
        ("audited", audited_fixture(16_384)),
    ] {
        let expected_emission = serde_json::to_vec(ciphertext(&source).expect("ciphertext"))
            .expect("independent byte array")
            .len()
            - 2;
        let EntryPayload::Normal(command) = source.payload else {
            unreachable!()
        };
        let previous = ConfigConsensusEntryDigest::from_bytes([0xB3; 32]);
        let effective_time = Timestamp::from_str("2026-01-01T00:00:02Z").expect("synthetic time");
        let (result, emitted) =
            crate::consensus::config_capacity_json::tests::observe_emission(|| {
                command.payload_and_applied_digests(29, previous, effective_time)
            });
        let (outcome, applied) = result.expect("paired digests");
        let mut expected_outcome = Sha256::new();
        expected_outcome.update(b"openpacketcore/config-consensus/outcome/v1\0");
        expected_outcome.update(
            serde_json::to_vec(&(8_u16, command.identity, &command.intent))
                .expect("independent semantic revision-8 outcome"),
        );
        let expected_outcome: [u8; 32] = expected_outcome.finalize().into();
        assert_eq!(outcome, expected_outcome, "exact ordinary/audited outcome");
        assert_eq!(
            command.payload_digest().expect("old outcome calculator"),
            expected_outcome
        );
        let mut expected_applied = Sha256::new();
        expected_applied.update(b"openpacketcore/config-consensus/command/v1\0");
        expected_applied.update(
            serde_json::to_vec(&(29_u64, previous, effective_time, &command))
                .expect("independent complete applied command"),
        );
        let expected_applied =
            ConfigConsensusEntryDigest::from_bytes(expected_applied.finalize().into());
        assert_eq!(applied, expected_applied);
        assert_eq!(
            command
                .calculate_applied_digest(29, previous, effective_time)
                .expect("old applied calculator"),
            expected_applied
        );
        emissions.push((family, emitted, expected_emission));
    }
    assert!(
        emissions.iter().all(|(_, emitted, expected)| emitted == expected),
        "CONFIG_CAPACITY_JOINT_DIGEST_EMISSION_RED: ordinary and audited byte/hash oracles completed before emission comparison; observations={emissions:?}"
    );
}
