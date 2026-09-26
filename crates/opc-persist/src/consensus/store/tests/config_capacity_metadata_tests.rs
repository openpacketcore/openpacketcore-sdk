//! Exact metadata component boundaries below the unchanged total-command fence.
//! These pure format controls do not open or qualify a larger-profile store.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::types::CONFIG_AUDIT_PATH_MAX_BYTES;
use crate::consensus::{ConfigConsensusCommand, ConfigConsensusIdentity};
use crate::{AuditKey, ConfirmedCommitResolution};
use opc_crypto::ConfigCapacityProfile;

// RFC component limit, independently expressed by the detector. Do not derive
// this expectation from the admission implementation under test.
const METADATA_LIMIT: usize = 196_608;
const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xC3; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xC4; 32]),
        ConfigConsensusConfigurationEpoch::new(3).expect("synthetic epoch"),
    )
}

fn key() -> AuditKey {
    AuditKey::new_with_epoch([0xC5; 32], 4).expect("synthetic audit key")
}

fn parent() -> opc_types::TxId {
    "c6c6c6c6-c6c6-4c6c-8c6c-c6c6c6c6c6c6"
        .parse()
        .expect("synthetic parent")
}

fn parts(last_path_bytes: usize) -> (PreparedConfigCommit, CapacityRecordBinding) {
    let (mut record, _, _) = sized_attested_commit(32).into_parts();
    record.parent_tx_id = Some(parent());
    record.version = opc_types::ConfigVersion::new(2);
    let aad = opc_key::EnvelopeAad::config(
        opc_types::TenantId::from_static("test"),
        record.version.get(),
        opc_key::ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            "running",
        )
        .expect("synthetic bound AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-metadata-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        opc_types::TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xC7; 32]),
    );
    let plaintext = br#"{"capacity":"metadata"}"#;
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle, &aad, plaintext, [0xC8; 12],
    )
    .expect("genuine bounded encryption");
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(plaintext).to_vec();
    let audit = (0..24)
        .map(|sequence| {
            let path_bytes = if sequence == 23 {
                last_path_bytes
            } else {
                CONFIG_AUDIT_PATH_MAX_BYTES
            };
            let prefix = "/fixture:";
            AuditRecord {
                tx_id: record.tx_id,
                sequence,
                yang_path: format!("{prefix}{}", "x".repeat(path_bytes - prefix.len())),
                op_type: crate::types::AuditOpType::Update,
                previous_value: Some("synthetic-before".to_owned()),
                new_value: Some("synthetic-after".to_owned()),
                redaction_applied: false,
                previous_hash: [0; 32],
                entry_hmac: [0; 32],
            }
        })
        .collect();
    let attested = AttestedConfigCommit::try_new(
        record,
        audit,
        envelope.claim().expect("paired encryption evidence"),
    )
    .expect("genuine paired record");
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE)
        .expect("scoped record proof");
    let (record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    let commit = PreparedConfigCommit::prepare(record, audit, &key())
        .expect("valid finalized audit below the existing component ceiling");
    StoredConfig {
        record: commit.record.clone(),
        audit: commit.audit.clone(),
    }
    .verify_audit_chain(&key())
    .expect("the complete finalized chain is authenticated");
    (commit, binding)
}

fn audited(effect: AuditedConfigEffect) -> ConfigMutationIntent {
    let privacy = AuditPrivacyKey::new([0xC9; 32]).expect("synthetic privacy key");
    let event = crate::ManagementAuditEventRecord::try_new(
        [0xCA; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic time"),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-metadata-boundary"),
    )
    .expect("synthetic event");
    let event = ProjectedAuditEvent::project(&privacy, &event).expect("project event");
    let digest = effect.digest(&key()).expect("exact effect MAC");
    let binding =
        AuditOperationBinding::project(&privacy, &event, 6, &digest).expect("exact effect binding");
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0xCB; 16],
            key_epoch: key().epoch(),
            mutation: Some(digest),
        },
        &key(),
    )
    .expect("valid operation MAC, not a ledger admission receipt");
    let prepared = crate::consensus::PreparedAuditedMutation::new(handle, effect, None);
    prepared
        .command()
        .verify_effect(&key())
        .expect("authenticated exact audited effect");
    ConfigMutationIntent::AuditedMutation(prepared.command().clone())
}

fn command(audit: bool, resolution: Option<bool>, path_bytes: usize) -> ConfigConsensusCommand {
    let (commit, binding) = parts(path_bytes);
    let resolution = resolution.map(|confirm| {
        if confirm {
            ConfirmedCommitResolution::Confirm {
                pending_tx_id: parent(),
            }
        } else {
            ConfirmedCommitResolution::Rollback {
                pending_tx_id: parent(),
            }
        }
    });
    ConfigConsensusCommand {
        schema_version: 8,
        identity: identity(),
        request_id: opc_consensus::ConsensusRequestId::from_bytes([0xCC; 16]),
        logical_time: maximum_encoded_config_timestamp().expect("longest leader timestamp"),
        intent: if audit {
            audited(AuditedConfigEffect::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution,
            })
        } else {
            ConfigMutationIntent::prepared_append(commit, resolution, Some(binding))
        },
    }
}

fn actual_metadata(command: &ConfigConsensusCommand) -> usize {
    let commit = match &command.intent {
        ConfigMutationIntent::BoundedAppend { commit, .. } => commit,
        ConfigMutationIntent::AuditedMutation(prepared) => match &prepared.effect {
            AuditedConfigEffect::BoundedAppend { commit, .. } => commit,
            _ => panic!("bounded audited fixture"),
        },
        _ => panic!("bounded ordinary fixture"),
    };
    let wire = encode_bounded(command).expect("real postcard encoding below RPC limit");
    assert_eq!(
        config_command_encoded_size(command).expect("count"),
        wire.len()
    );
    assert!(
        wire.len() < DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES,
        "the existing total-command fence must not mask the metadata detector",
    );
    // Exclude exactly one envelope's byte content. Retain its length prefix,
    // every audit/proof/handle field, and the real command/scope/time framing.
    wire.len()
        .checked_sub(commit.record.encrypted_blob.len())
        .expect("command contains its envelope")
}

#[derive(Clone, Copy)]
enum Boundary {
    DecodedProfile,
    Preparation,
}

fn assert_boundary(audit: bool, resolution: Option<bool>, boundary: Boundary) {
    // Both endpoints remain within the same postcard string-length width.
    let baseline_path = 128;
    let baseline = actual_metadata(&command(audit, resolution, baseline_path));
    let at_limit_path = baseline_path
        + METADATA_LIMIT
            .checked_sub(baseline)
            .expect("baseline metadata below the declared component ceiling");
    assert!((baseline_path..CONFIG_AUDIT_PATH_MAX_BYTES).contains(&at_limit_path));
    for extra in [0, 1] {
        let value = command(audit, resolution, at_limit_path + extra);
        value
            .validate(identity())
            .expect("structurally valid input");
        assert_eq!(actual_metadata(&value), METADATA_LIMIT + extra);
        match boundary {
            Boundary::DecodedProfile => {
                let wire = encode_bounded(&value).expect("real input bytes");
                let decoded: ConfigConsensusCommand =
                    opc_consensus::decode_bounded(&wire).expect("untrusted command decoding");
                assert_eq!(
                    decoded.validate_for_profile(identity(), &key(), PROFILE).is_ok(),
                    extra == 0,
                    "CONFIG_CAPACITY_METADATA_PROFILE: complete metadata at/over the declared ceiling",
                );
            }
            Boundary::Preparation => {
                assert_eq!(
                    preflight_config_command_replication_budget(
                        identity(),
                        value.request_id,
                        &value.intent,
                        PROFILE,
                    ),
                    if extra == 0 {
                        Ok(())
                    } else {
                        Err(ForwardMutationRejection::CommandTooLarge)
                    },
                    "CONFIG_CAPACITY_METADATA_PREPARATION: complete metadata before any proposal or Intent",
                );
            }
        }
    }
}

macro_rules! metadata_cases {
    ($ordinary:ident, $audited:ident, $resolution:expr, $boundary:expr) => {
        #[test]
        fn $ordinary() {
            assert_boundary(false, $resolution, $boundary);
        }
        #[test]
        fn $audited() {
            assert_boundary(true, $resolution, $boundary);
        }
    };
}

metadata_cases!(
    config_capacity_957_metadata_plain_append_profile,
    config_capacity_957_metadata_audited_append_profile,
    None,
    Boundary::DecodedProfile
);
metadata_cases!(
    config_capacity_957_metadata_plain_confirm_append_profile,
    config_capacity_957_metadata_audited_confirm_append_profile,
    Some(true),
    Boundary::DecodedProfile
);
metadata_cases!(
    config_capacity_957_metadata_plain_rollback_append_profile,
    config_capacity_957_metadata_audited_rollback_append_profile,
    Some(false),
    Boundary::DecodedProfile
);
metadata_cases!(
    config_capacity_957_metadata_plain_append_preparation,
    config_capacity_957_metadata_audited_append_preparation,
    None,
    Boundary::Preparation
);
metadata_cases!(
    config_capacity_957_metadata_plain_confirm_append_preparation,
    config_capacity_957_metadata_audited_confirm_append_preparation,
    Some(true),
    Boundary::Preparation
);
metadata_cases!(
    config_capacity_957_metadata_plain_rollback_append_preparation,
    config_capacity_957_metadata_audited_rollback_append_preparation,
    Some(false),
    Boundary::Preparation
);

#[path = "config_capacity_joint_metadata_tests.rs"]
mod joint;
