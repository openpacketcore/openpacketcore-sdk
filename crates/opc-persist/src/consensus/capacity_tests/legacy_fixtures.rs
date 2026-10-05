use serde::Serialize;

use super::legacy_support::*;
use crate::audit_authority::continuity::{
    checkpoint::CheckpointBody, AuditCheckpoint, AuditKeyRing, AuditKeyTransition, AuditSigningKey,
};
use crate::audit_authority::{AuditLedgerLimits, AuditToken};
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::types::*;
use crate::consensus::PreparedAuditedMutation;
use crate::*;

fn genesis_record() -> CommitRecord {
    let mut record = record();
    record.parent_tx_id = None;
    record.version = opc_types::ConfigVersion::new(1);
    record.rollback_point = false;
    record.encrypted_blob = opc_crypto::encrypt_envelope_with_handle_and_nonce(
        &handle_key(),
        &aad(&record, "running"),
        b"null",
        [0x33; 12],
    )
    .unwrap();
    record
}

fn audit_shapes() -> Vec<AuditRecord> {
    [
        (AuditOpType::Create, None, Some("456")),
        (AuditOpType::Update, Some("123"), Some("456")),
        (AuditOpType::Delete, Some("123"), None),
        (AuditOpType::Replace, None, None),
    ]
    .into_iter()
    .enumerate()
    .map(|(sequence, (op_type, previous, new))| {
        let mut entry = audit().remove(0);
        entry.sequence = sequence as u32;
        entry.op_type = op_type;
        entry.previous_value = previous.map(str::to_owned);
        entry.new_value = new.map(str::to_owned);
        entry
    })
    .collect()
}

pub(super) fn commands() -> Vec<(&'static str, ConfigConsensusCommand)> {
    let prepared = prepared();
    let label = Some(ValidatedRollbackLabel::try_new("synthetic-point".into()).unwrap());
    let mut intents = vec![
        (
            "append",
            ConfigMutationIntent::AppendCommit(Box::new(prepared.clone())),
        ),
        (
            "confirm",
            ConfigMutationIntent::MarkConfirmed { tx_id: tx() },
        ),
        (
            "rollback-point",
            ConfigMutationIntent::CreateRollbackPoint {
                tx_id: tx(),
                label: label.clone(),
            },
        ),
        (
            "resolve-confirm",
            ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: Box::new(prepared.clone()),
                resolution: ConfirmedCommitResolution::Confirm {
                    pending_tx_id: parent(),
                },
            },
        ),
        (
            "resolve-rollback",
            ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: Box::new(prepared.clone()),
                resolution: ConfirmedCommitResolution::Rollback {
                    pending_tx_id: parent(),
                },
            },
        ),
        (
            "clear-recovery",
            ConfigMutationIntent::ClearRecoveryRequired { tx_id: tx() },
        ),
        (
            "retain-history",
            ConfigMutationIntent::RetainHistory(
                ConfigHistoryRetention::new(
                    tx(),
                    opc_types::ConfigVersion::new(6),
                    opc_types::ConfigVersion::new(3),
                    opc_types::ConfigVersion::new(3),
                    ConfigHistoryLimits::new(8, 8192).unwrap(),
                )
                .unwrap(),
            ),
        ),
    ];
    let token = AuditToken::from_keyed_projection([9; 32]).unwrap();
    let limits = AuditLedgerLimits::new(12, 4).unwrap();
    let keys = AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [10; 32]).unwrap(),
        AuditSigningKey::new(2, [11; 32]).unwrap(),
    ])
    .unwrap();
    let checkpoint = AuditCheckpoint::issue(
        &keys,
        CheckpointBody {
            version: 1,
            identity: identity(),
            sequence: 1,
            root_anchor: [12; 32],
            anchor: [13; 32],
            epoch_at_sequence: 1,
            signing_epoch: 1,
            acknowledged_export: [14; 32],
        },
    )
    .unwrap();
    for (name, audit) in [
        (
            "initialize",
            AuditCommand::Initialize {
                projection: token,
                limits,
            },
        ),
        ("intent", AuditCommand::Intent(handle(None))),
        ("reject", AuditCommand::Reject(handle(None))),
        ("terminal", AuditCommand::Terminal(handle(None))),
        (
            "initialize-continuity",
            AuditCommand::InitializeWithContinuity {
                projection: token,
                limits,
                initial_epoch: 1,
            },
        ),
        (
            "transition",
            AuditCommand::Transition(
                AuditKeyTransition::prepare(&keys, identity(), 1, [15; 32], 1, 2).unwrap(),
            ),
        ),
        ("checkpoint", AuditCommand::Checkpoint(checkpoint.clone())),
        (
            "prune",
            AuditCommand::Prune {
                through: 1,
                checkpoint: checkpoint.clone(),
            },
        ),
        (
            "acknowledge-export",
            AuditCommand::AcknowledgeExport(checkpoint),
        ),
    ] {
        intents.push((name, ConfigMutationIntent::ManagementAudit(audit)));
    }
    for (name, effect) in [
        (
            "audited-append",
            AuditedConfigEffect::Append {
                commit: Box::new(prepared.clone()),
                resolution: None,
            },
        ),
        (
            "audited-resolve-confirm",
            AuditedConfigEffect::Append {
                commit: Box::new(prepared.clone()),
                resolution: Some(ConfirmedCommitResolution::Confirm {
                    pending_tx_id: parent(),
                }),
            },
        ),
        (
            "audited-resolve-rollback",
            AuditedConfigEffect::Append {
                commit: Box::new(prepared),
                resolution: Some(ConfirmedCommitResolution::Rollback {
                    pending_tx_id: parent(),
                }),
            },
        ),
        (
            "audited-confirm",
            AuditedConfigEffect::Confirm { tx_id: tx() },
        ),
        (
            "audited-rollback-point",
            AuditedConfigEffect::RollbackPoint { tx_id: tx(), label },
        ),
    ] {
        intents.push((
            name,
            ConfigMutationIntent::AuditedMutation(PreparedAuditedMutation {
                handle: handle(Some(&effect)),
                effect,
            }),
        ));
    }
    intents.push((
        "rollback-point-no-label",
        ConfigMutationIntent::CreateRollbackPoint {
            tx_id: tx(),
            label: None,
        },
    ));
    let effect = AuditedConfigEffect::RollbackPoint {
        tx_id: tx(),
        label: None,
    };
    intents.push((
        "audited-rollback-point-no-label",
        ConfigMutationIntent::AuditedMutation(PreparedAuditedMutation {
            handle: handle(Some(&effect)),
            effect,
        }),
    ));
    for (ordinary_name, audited_name, record, audit) in [
        (
            "append-genesis-empty-audit",
            "audited-genesis-empty-audit",
            genesis_record(),
            vec![],
        ),
        (
            "append-empty-audit",
            "audited-empty-audit",
            record(),
            vec![],
        ),
        (
            "append-multiple-audit",
            "audited-multiple-audit",
            record(),
            audit_shapes(),
        ),
    ] {
        let commit = Box::new(PreparedConfigCommit::prepare(record, audit, &key()).unwrap());
        intents.push((
            ordinary_name,
            ConfigMutationIntent::AppendCommit(commit.clone()),
        ));
        let effect = AuditedConfigEffect::Append {
            commit,
            resolution: None,
        };
        intents.push((
            audited_name,
            ConfigMutationIntent::AuditedMutation(PreparedAuditedMutation {
                handle: handle(Some(&effect)),
                effect,
            }),
        ));
    }
    intents
        .into_iter()
        .map(|(name, intent)| (name, command(intent)))
        .collect()
}

fn encoded(name: &str, value: &impl Serialize) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "json": String::from_utf8(serde_json::to_vec(value).unwrap()).unwrap(),
        "postcard": hex(&opc_consensus::encode_bounded(value).unwrap()),
    })
}

pub(super) fn capture() -> Vec<serde_json::Value> {
    let mut actual = vec![
        encoded("record", &record()),
        encoded("prepared", &prepared()),
    ];
    for (name, source) in [
        ("gnmi", CommitSource::Gnmi),
        ("netconf", CommitSource::Netconf),
        ("local-operator", CommitSource::LocalOperator),
        ("startup-restore", CommitSource::StartupRestore),
        ("rollback", CommitSource::Rollback),
        ("confirmed-restore", CommitSource::CommitConfirmedRestore),
    ] {
        let mut record = record();
        record.source = source;
        record.confirmed_deadline = Some(timestamp());
        actual.push(encoded(name, &record));
    }
    for (name, command) in commands() {
        command.validate(identity()).unwrap();
        let mut row = encoded(name, &command);
        row["payload_digest"] = hex(&command.payload_digest().unwrap()).into();
        row["applied_digest"] = hex(command
            .calculate_applied_digest(
                17,
                ConfigConsensusEntryDigest::from_bytes([16; 32]),
                timestamp(),
            )
            .unwrap()
            .as_bytes())
        .into();
        if let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent {
            row["effect_digest"] = hex(&prepared.effect.digest(&key()).unwrap()).into();
            row["recovery"] = String::from_utf8(prepared.encode().unwrap())
                .unwrap()
                .into();
        }
        let json = serde_json::to_vec(&command).unwrap();
        assert_eq!(
            serde_json::from_slice::<ConfigConsensusCommand>(&json).unwrap(),
            command
        );
        let binary = opc_consensus::encode_bounded(&command).unwrap();
        assert_eq!(
            opc_consensus::decode_bounded::<ConfigConsensusCommand>(&binary).unwrap(),
            command
        );
        actual.push(row);
    }
    actual.push(encoded("genesis-record", &genesis_record()));
    let mut ordinary_record = record();
    ordinary_record.rollback_point = false;
    actual.push(encoded("record-without-rollback-point", &ordinary_record));
    actual.push(encoded("audit-empty", &Vec::<AuditRecord>::new()));
    actual.push(encoded("audit-multiple", &audit_shapes()));
    actual.extend(principal_shapes());
    actual
}

fn principal_shapes() -> Vec<serde_json::Value> {
    let mut inputs = vec![
        ("plain", "writer".to_owned()),
        ("spiffe", "spiffe://example.test/tenant/t1/sa/admin".to_owned()),
        ("tenant", r#"{"tenant":"t1"}"#.to_owned()),
        ("nested", r#"{"tenant":"t1","identity":{"Internal":"spiffe://example.test/tenant/t1/sa/admin"},"roles":["reader",null,4],"groups":["operators",false]}"#.to_owned()),
        ("wrapped", r#"{"principal":"{\"tenant\":\"t1\"}","recovery_required":false}"#.to_owned()),
        ("wrapped-policy", r#"{"principal":{"identity":{"Spiffe":"spiffe://example.test/tenant/t1/sa/user"},"roles":["reader"],"groups":["operators"]}}"#.to_owned()),
        ("unknown", r#"{"principal":"writer","recovery_required":false,"unknown":0}"#.to_owned()),
        ("unknown-overflow", r#"{"principal":"writer","recovery_required":false,"unknown":1e999}"#.to_owned()),
        ("duplicate-principal", r#"{"principal":"one","principal":"two","recovery_required":false}"#.to_owned()),
        ("duplicate-tenant", r#"{"tenant":"one","tenant":"two"}"#.to_owned()),
        ("duplicate-tenant-nonstring", r#"{"tenant":"one","tenant":null}"#.to_owned()),
        ("duplicate-nested", r#"{"tenant":"t1","x":{"a":1,"a":2}}"#.to_owned()),
        ("empty", String::new()),
        ("trailing", r#"{"tenant":"t1"} false"#.to_owned()),
        ("unicode", r#""\u0073\u0075\u0070\u0069-x""#.to_owned()),
        ("raw-principal", r#"{"principal":{"$serde_json::private::RawValue":"\"writer\""},"recovery_required":false}"#.to_owned()),
        ("raw-tenant", r#"{"$serde_json::private::RawValue":"{\"tenant\":\"t1\"}"}"#.to_owned()),
        ("raw-redaction", r#"{"$serde_json::private::RawValue":"\"\\u0073\\u0075\\u0070\\u0069-x\""}"#.to_owned()),
        ("raw-policy", r#"{"$serde_json::private::RawValue":"{\"spiffe_id\":\"spiffe://example.test/tenant/t1/sa/admin\"}"}"#.to_owned()),
        ("raw-after-tenant", r#"{"tenant":"t1","$serde_json::private::RawValue":"{\"tenant\":\"other\"}"}"#.to_owned()),
        ("raw-invalid", r#"{"$serde_json::private::RawValue":"not json","tenant":"t1"}"#.to_owned()),
        ("raw-bool", r#"{"recovery_required":{"$serde_json::private::RawValue":"false"},"principal":"writer"}"#.to_owned()),
        ("number-principal-marker", r#"{"principal":{"$serde_json::private::Number":"0"},"recovery_required":false}"#.to_owned()),
        ("number-marker", r#"{"tenant":"t1","extra":{"$serde_json::private::Number":"1e999"}}"#.to_owned()),
        ("invalid-number", r#"{"tenant":"t1","extra":01}"#.to_owned()),
        ("invalid-escape", r#"{"tenant":"t1","extra":"\uD800"}"#.to_owned()),
        ("invalid-duplicate-value", r#"{"tenant":1e999,"tenant":"t1"}"#.to_owned()),
        ("sorted-fields", r#"{"z":0,"tenant":"t1","a":false}"#.to_owned()),
        ("canonical-spiffe", "spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0".to_owned()),
        ("canonical-policy", r#"{"tenant":"t1","identity":{"Internal":"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0"},"roles":["reader",null],"groups":["operators",4]}"#.to_owned()),
        ("canonical-wrapped-policy", r#"{"principal":{"identity":{"Spiffe":"spiffe://example.test/tenant/t1/ns/default/sa/user/nf/amf/instance/0"},"roles":["reader"],"groups":["operators"]}}"#.to_owned()),
        ("canonical-raw-policy", r#"{"$serde_json::private::RawValue":"{\"spiffe_id\":\"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0\"}"}"#.to_owned()),
    ];
    for number in [
        "0",
        "-0",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "18446744073709551616",
        "0.1",
        "1.000000000000000111022302462515654",
        "1.7976931348623157e308",
        "1.7976931348623159e308",
        "1e309",
        "1e-999",
        "0e999999999999",
        "1e999999999999",
        "1e-999999999999",
    ] {
        inputs.push(("number", number.to_owned()));
        inputs.push((
            "principal-number",
            format!(r#"{{"principal":{number},"recovery_required":false}}"#),
        ));
        inputs.push((
            "tenant-number",
            format!(r#"{{"tenant":"t1","extra":{number}}}"#),
        ));
    }
    for depth in [125, 126, 127, 128, 129] {
        let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        inputs.push((
            "deep-tenant",
            format!(r#"{{"tenant":"t1","extra":{nested}}}"#),
        ));
        inputs.push((
            "deep-principal",
            format!(r#"{{"principal":{nested},"recovery_required":false}}"#),
        ));
        inputs.push((
            "deep-unknown",
            format!(r#"{{"principal":"writer","recovery_required":false,"extra":{nested}}}"#),
        ));
    }
    inputs.extend([
        ("recovery-true", r#"{"principal":"writer","recovery_required":true}"#.to_owned()),
        ("duplicate-recovery", r#"{"principal":"writer","recovery_required":false,"recovery_required":true}"#.to_owned()),
        ("duplicate-digest", r#"{"principal":"writer","recovery_required":false,"replay_lookup_digest":null,"replay_lookup_digest":null}"#.to_owned()),
        ("duplicate-label", r#"{"principal":"writer","recovery_required":false,"rollback_label":"one","rollback_label":"two"}"#.to_owned()),
        ("digest-null", r#"{"principal":"writer","recovery_required":false,"replay_lookup_digest":null}"#.to_owned()),
        ("digest-wrong-type", r#"{"principal":"writer","recovery_required":false,"replay_lookup_digest":0}"#.to_owned()),
        ("label-valid", r#"{"principal":"writer","recovery_required":true,"rollback_label":"release-1"}"#.to_owned()),
        ("label-null", r#"{"principal":"writer","recovery_required":false,"rollback_label":null}"#.to_owned()),
        ("label-wrong-type", r#"{"principal":"writer","recovery_required":false,"rollback_label":false}"#.to_owned()),
        ("label-empty", r#"{"principal":"writer","recovery_required":false,"rollback_label":""}"#.to_owned()),
        ("label-whitespace", r#"{"principal":"writer","recovery_required":false,"rollback_label":" release-1"}"#.to_owned()),
        ("label-control", r#"{"principal":"writer","recovery_required":false,"rollback_label":"release\u0000"}"#.to_owned()),
        ("raw-label", r#"{"principal":"writer","recovery_required":false,"rollback_label":{"$serde_json::private::RawValue":"\"release-1\""}}"#.to_owned()),
        ("whitespace", " \t\r\n { \"principal\" : \"writer\" , \"recovery_required\" : true } \n\r \t".to_owned()),
        ("escaped-tenant-key", r#"{"te\u006eant":"t1"}"#.to_owned()),
        ("escaped-metadata-keys", r#"{"princ\u0069pal":"writer","recovery_re\u0071uired":true}"#.to_owned()),
        ("surrogate-pair", r#""\ud83d\ude00""#.to_owned()),
        ("wrapped-surrogate-pair", r#"{"principal":"\ud83d\ude00","recovery_required":true}"#.to_owned()),
        ("escaped-nul", r#"{"tenant":"t1","extra":"\u0000"}"#.to_owned()),
        ("raw-nul", "\"\0\"".to_owned()),
        ("byte-order-mark", "\u{feff}{\"tenant\":\"t1\"}".to_owned()),
        ("array", r#"[{"tenant":"t1"}]"#.to_owned()),
        ("null", "null".to_owned()),
        ("true", "true".to_owned()),
        ("false", "false".to_owned()),
        ("tenant-wrong-type", r#"{"tenant":5}"#.to_owned()),
        ("policy-identity-string", r#"{"identity":"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0"}"#.to_owned()),
        ("policy-roles-object", r#"{"spiffe_id":"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0","roles":{"reader":true}}"#.to_owned()),
        ("policy-groups-string", r#"{"spiffe_id":"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0","groups":"operators"}"#.to_owned()),
        ("policy-principal-string", r#"{"principal":"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0"}"#.to_owned()),
        ("policy-principal-null", r#"{"principal":null,"spiffe_id":"spiffe://example.test/tenant/t1/ns/default/sa/admin/nf/amf/instance/0"}"#.to_owned()),
    ]);
    for (name, digest) in [
        ("digest-valid", "a".repeat(64)),
        ("digest-short", "a".repeat(63)),
        ("digest-uppercase", "A".repeat(64)),
    ] {
        inputs.push((
            name,
            format!(r#"{{"principal":"writer","recovery_required":true,"replay_lookup_digest":"{digest}"}}"#),
        ));
    }
    inputs.push((
        "raw-digest",
        format!(r#"{{"principal":"writer","recovery_required":false,"replay_lookup_digest":{{"$serde_json::private::RawValue":"\"{}\""}}}}"#, "a".repeat(64)),
    ));
    for size in [
        crate::types::CONFIG_ROLLBACK_LABEL_MAX_BYTES,
        crate::types::CONFIG_ROLLBACK_LABEL_MAX_BYTES + 1,
    ] {
        inputs.push((
            "label-boundary",
            format!(
                r#"{{"principal":"writer","recovery_required":false,"rollback_label":"{}"}}"#,
                "x".repeat(size)
            ),
        ));
    }
    for depth in [125, 126, 127, 128, 129] {
        let nested = format!("{}0{}", r#"{"x":"#.repeat(depth), "}".repeat(depth));
        inputs.push((
            "deep-object-tenant",
            format!(r#"{{"tenant":"t1","extra":{nested}}}"#),
        ));
        inputs.push((
            "deep-object-principal",
            format!(r#"{{"principal":{nested},"recovery_required":false}}"#),
        ));
        inputs.push((
            "deep-object-unknown",
            format!(r#"{{"principal":"writer","recovery_required":false,"extra":{nested}}}"#),
        ));
    }
    inputs.into_iter().map(|(name, input)| {
        let mut redacted = Some(input.clone());
        let mut applied = false;
        redact_entry("/example:value", &mut redacted, &mut applied);
        serde_json::json!({
            "name": format!("principal-{name}"),
            "input": input,
            "valid": crate::types::config_principal_metadata_is_valid(&input),
            "tenant": extract_tenant(&input),
            "rollback": format!("{:?}", crate::types::config_rollback_label(&input)),
            "recovery": format!("{:?}", crate::types::config_recovery_required(&input)),
            "replay": format!("{:?}", crate::types::config_replay_lookup_digest(&input)),
            "clear_recovery": format!("{:?}", crate::types::clear_config_recovery_required(&input)),
            "aad_matches": {
                "same_input": crate::types::config_principal_matches_aad(&input, &input),
                "writer": crate::types::config_principal_matches_aad(&input, "writer"),
                "other": crate::types::config_principal_matches_aad(&input, "other"),
                "nested_tenant": crate::types::config_principal_matches_aad(&input, r#"{"tenant":"t1"}"#),
            },
            "policy": format!("{:?}", crate::security_policy::validate_principal_tenant_and_roles(&input, "t1")),
            "redacted": redacted,
            "redaction_applied": applied,
        })
    }).collect()
}

#[test]
fn private_json_marker_does_not_admit_a_legacy_command() {
    let mut commit = prepared();
    commit.record.principal = r#"{"principal":{"$serde_json::private::RawValue":"\"writer\""},"recovery_required":false}"#.to_owned();
    let command = command(ConfigMutationIntent::AppendCommit(Box::new(commit)));
    let wire = encode_config_wire(&command).unwrap();
    let decoded: ConfigConsensusCommand = decode_config_wire(&wire).unwrap();
    assert!(matches!(
        decoded.validate(identity()).unwrap_err().kind(),
        PersistErrorKind::CorruptBlob
    ));
}

#[test]
#[ignore = "writes the legacy fixture only when explicitly requested"]
fn capture_legacy_bytes() {
    let destination = std::env::var("OPC_PERSIST_LEGACY_CAPTURE").expect("capture destination");
    let bytes = serde_json::to_string_pretty(&capture()).unwrap() + "\n";
    std::fs::write(destination, bytes).unwrap();
}
