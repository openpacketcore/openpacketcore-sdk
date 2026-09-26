//! Private command layout and historical wire/digest compatibility. The inline
//! size assertion excludes the separately allocated payload and is not a claim
//! about total mutation memory, storage or transport qualification.

use super::*;
use crate::audit_authority::{AuditLedgerLimits, AuditToken};
use crate::consensus::audit::AuditCommand;
use opc_consensus::{decode_bounded, encode_bounded};
use serde::Serializer;
use std::str::FromStr;

// The original unboxed newtype variant has index6 and this exact JSON name.
// Borrow its payload directly so the compatibility oracle contains no Box.
struct LegacyManagementIntent<'a>(&'a AuditCommand);

impl Serialize for LegacyManagementIntent<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_variant("ConfigMutationIntent", 6, "ManagementAudit", self.0)
    }
}

#[derive(Serialize)]
#[serde(rename = "ConfigConsensusCommand")]
struct LegacyCommand<'a> {
    schema_version: u16,
    identity: ConfigConsensusIdentity,
    request_id: ConfigConsensusRequestId,
    logical_time: Timestamp,
    intent: LegacyManagementIntent<'a>,
}

#[test]
fn config_capacity_957_management_payload_is_outside_inline_intent() {
    assert!(
        std::mem::size_of::<ConfigMutationIntent>() <= 128,
        "inline intent must not retain the full management command"
    );
}

#[test]
fn config_capacity_957_boxed_management_preserves_original_encoding_and_digests() {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("synthetic-command-layout").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x71; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let logical_time = Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time");
    let request_id = ConfigConsensusRequestId::from_bytes([0x72; 16]);
    let projection = AuditToken::from_keyed_projection([0x73; 32]).expect("projection");
    let limits = AuditLedgerLimits::new(3, 1).expect("limits");
    let keys = crate::audit_authority::continuity::AuditKeyRing::new(vec![
        crate::audit_authority::continuity::AuditSigningKey::new(1, [0x74; 32])
            .expect("synthetic signing key"),
    ])
    .expect("synthetic key ring");
    let checkpoint = crate::audit_authority::continuity::AuditCheckpoint::issue(
        &keys,
        crate::audit_authority::continuity::checkpoint::CheckpointBody {
            version: 1,
            identity,
            sequence: 0,
            root_anchor: [0; 32],
            anchor: [0; 32],
            epoch_at_sequence: 1,
            signing_epoch: 1,
            acknowledged_export: [0x75; 32],
        },
    )
    .expect("synthetic authenticated checkpoint");

    for (revision, audit) in [
        (5, AuditCommand::Initialize { projection, limits }),
        (
            6,
            AuditCommand::InitializeWithContinuity {
                projection,
                limits,
                initial_epoch: 1,
            },
        ),
        (
            6,
            AuditCommand::Prune {
                through: 0,
                checkpoint: checkpoint.clone(),
            },
        ),
        (7, AuditCommand::AcknowledgeExport(checkpoint)),
    ] {
        let legacy = LegacyCommand {
            schema_version: revision,
            identity,
            request_id,
            logical_time,
            intent: LegacyManagementIntent(&audit),
        };
        let command = ConfigConsensusCommand {
            schema_version: revision,
            identity,
            request_id,
            logical_time,
            intent: ConfigMutationIntent::ManagementAudit(Box::new(audit.clone())),
        };
        assert_eq!(command.intent.minimum_command_version(), revision);
        let json = serde_json::to_vec(&legacy).expect("original JSON representation");
        assert_eq!(serde_json::to_vec(&command).expect("current JSON"), json);
        assert_eq!(
            serde_json::from_slice::<ConfigConsensusCommand>(&json).expect("legacy JSON decode"),
            command
        );
        let wire = encode_bounded(&legacy).expect("original postcard representation");
        assert_eq!(encode_bounded(&command).expect("current postcard"), wire);
        assert_eq!(
            decode_bounded::<ConfigConsensusCommand>(&wire).expect("legacy postcard decode"),
            command
        );

        let mut expected_payload = Sha256::new();
        expected_payload.update(b"openpacketcore/config-consensus/outcome/v1\0");
        expected_payload.update(
            serde_json::to_vec(&(revision, identity, &legacy.intent))
                .expect("original payload digest transcript"),
        );
        let expected_payload: [u8; 32] = expected_payload.finalize().into();
        assert_eq!(
            command.payload_digest().expect("payload digest"),
            expected_payload
        );

        let previous = ConfigConsensusEntryDigest::from_bytes([0x76; 32]);
        let mut expected_applied = Sha256::new();
        expected_applied.update(b"openpacketcore/config-consensus/command/v1\0");
        expected_applied.update(
            serde_json::to_vec(&(7_u64, previous, logical_time, &legacy))
                .expect("original applied digest transcript"),
        );
        assert_eq!(
            command
                .calculate_applied_digest(7, previous, logical_time)
                .expect("applied digest"),
            ConfigConsensusEntryDigest::from_bytes(expected_applied.finalize().into())
        );
    }
}
