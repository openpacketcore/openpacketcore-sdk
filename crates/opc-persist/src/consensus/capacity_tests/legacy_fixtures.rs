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
    actual
}

#[test]
#[ignore = "writes the legacy fixture only when explicitly requested"]
fn capture_legacy_bytes() {
    let destination = std::env::var("OPC_PERSIST_LEGACY_CAPTURE").expect("capture destination");
    let bytes = serde_json::to_string_pretty(&capture()).unwrap() + "\n";
    std::fs::write(destination, bytes).unwrap();
}
