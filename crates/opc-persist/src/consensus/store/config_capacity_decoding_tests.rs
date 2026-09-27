//! Real encrypted DTO compatibility and reserved decoder rejection boundaries.
//! These component tests do not establish native store or cluster admission.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditLedgerLimits, AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey,
    ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{AuditedConfigEffect, PreparedAuditedMutation};
use crate::consensus::types::ValidatedRollbackLabel;
use crate::consensus::{config_capacity_decode, ConfigHistoryLimits, ConfigHistoryRetention};

pub(super) fn audited(effect: AuditedConfigEffect) -> PreparedAuditedMutation {
    let privacy = AuditPrivacyKey::new([0x52; 32]).unwrap();
    let source = crate::ManagementAuditEventRecord::try_new(
        [0x53; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-decoding-boundary"),
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &source).unwrap();
    let digest = effect.digest(&key()).unwrap();
    let binding = AuditOperationBinding::project(&privacy, &event, 6, &digest).unwrap();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0x54; 16],
            key_epoch: key().epoch(),
            mutation: Some(digest),
        },
        &key(),
    )
    .unwrap();
    PreparedAuditedMutation::new(handle, effect, None)
}

fn forward(intent: ConfigMutationIntent) -> super::super::super::ForwardMutationRequest {
    super::super::super::ForwardMutationRequest {
        request_id: ConsensusRequestId::from_bytes([0x55; 16]),
        intent,
        compatibility: ConfigPeerCompatibility {
            wire_version: 8,
            command_version: 8,
            audit_key_epoch: key().epoch(),
            audit_key_fingerprint: key().fingerprint(),
        },
        budget: ForwardedBudget {
            remaining_nanos: 60_000_000_000,
        },
    }
}

fn roundtrip(intent: ConfigMutationIntent) {
    let json = serde_json::to_vec(&intent).unwrap();
    let typed: ConfigMutationIntent =
        serde_json::from_slice::<config_capacity_decode::Intent>(&json)
            .unwrap()
            .into();
    assert_eq!(serde_json::to_vec(&typed).unwrap(), json);
    let request = forward(intent);
    for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
        let binary =
            crate::consensus::types::encode_config_wire_for_profile(profile, &request).unwrap();
        let decoded = super::super::super::decode_forward_mutation(profile, &binary).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(
            crate::consensus::types::encode_config_wire_for_profile(profile, &decoded).unwrap(),
            binary
        );
    }
}

#[test]
fn capacity_decode_preserves_all_intent_and_effect_representations() {
    let ConfigMutationIntent::BoundedAppend {
        commit, binding, ..
    } = command(128).intent
    else {
        panic!("bounded fixture");
    };
    let tx_id = commit.record.tx_id;
    let resolution = crate::ConfirmedCommitResolution::Confirm {
        pending_tx_id: tx_id,
    };
    let label = Some(ValidatedRollbackLabel::try_new("fixture-label".to_owned()).unwrap());
    let effects = [
        AuditedConfigEffect::Append {
            commit: commit.clone(),
            resolution: Some(resolution),
        },
        AuditedConfigEffect::Confirm { tx_id },
        AuditedConfigEffect::RollbackPoint {
            tx_id,
            label: label.clone(),
        },
        AuditedConfigEffect::BoundedAppend {
            commit: commit.clone(),
            binding,
            resolution: None,
        },
    ];
    for effect in effects {
        let prepared = audited(effect);
        let encoded = prepared.encode().unwrap();
        for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
            let decoded = config_capacity_decode::recovery(&encoded, profile).unwrap();
            assert!(prepared == decoded);
            decoded.command().verify_effect(&key()).unwrap();
            assert_eq!(decoded.encode().unwrap(), encoded);
        }
        roundtrip(ConfigMutationIntent::AuditedMutation(
            prepared.command().clone(),
        ));
        roundtrip(ConfigMutationIntent::ManagementAudit(Box::new(
            crate::consensus::audit::AuditCommand::Intent(prepared.handle().clone()),
        )));
    }
    roundtrip(ConfigMutationIntent::AppendCommit(commit.clone()));
    roundtrip(ConfigMutationIntent::MarkConfirmed { tx_id });
    roundtrip(ConfigMutationIntent::CreateRollbackPoint { tx_id, label });
    roundtrip(ConfigMutationIntent::ResolveConfirmedAndAppend {
        commit: commit.clone(),
        resolution,
    });
    roundtrip(ConfigMutationIntent::ClearRecoveryRequired { tx_id });
    roundtrip(ConfigMutationIntent::RetainHistory(
        ConfigHistoryRetention::new(
            tx_id,
            opc_types::ConfigVersion::new(4),
            opc_types::ConfigVersion::new(2),
            opc_types::ConfigVersion::new(2),
            ConfigHistoryLimits::new(16, 8_388_608).unwrap(),
        )
        .unwrap(),
    ));
    roundtrip(ConfigMutationIntent::BoundedAppend {
        commit,
        binding,
        resolution: None,
    });
    // Fixed metadata constructors remain available in this decoder's schema.
    assert!(AuditLedgerLimits::new(4096, 1024).is_ok());
}

#[test]
fn capacity_decode_at_limit_encryption_preserves_scoped_proof_and_forwarding() {
    let command = command(1_572_864);
    let ConfigMutationIntent::BoundedAppend {
        commit, binding, ..
    } = &command.intent
    else {
        panic!("bounded fixture");
    };
    let prepared = audited(AuditedConfigEffect::BoundedAppend {
        commit: commit.clone(),
        binding: *binding,
        resolution: None,
    });
    let recovery = prepared.encode().unwrap();
    let decoded = config_capacity_decode::recovery(&recovery, PROFILE).unwrap();
    decoded.command().verify_effect(&key()).unwrap();
    decoded
        .command()
        .effect
        .verify_capacity(identity(), &key(), PROFILE)
        .unwrap();
    assert_eq!(decoded.encode().unwrap(), recovery);
    let request = forward(command.intent);
    let binary =
        crate::consensus::types::encode_config_wire_for_profile(PROFILE, &request).unwrap();
    let decoded = super::super::super::decode_forward_mutation(PROFILE, &binary).unwrap();
    decoded
        .intent
        .validate_capacity(identity(), &key(), PROFILE)
        .unwrap();
    assert_eq!(decoded, request);
    let other = crate::consensus::types::encode_config_wire_for_profile(
        ConfigCapacityProfile::Legacy,
        &request,
    )
    .unwrap();
    assert!(super::super::super::decode_forward_mutation(PROFILE, &other).is_err());
    assert!(
        super::super::super::decode_forward_mutation(ConfigCapacityProfile::Legacy, &binary)
            .is_err()
    );
}

#[test]
fn capacity_decode_rejects_oversized_record_before_admission_without_reinterpreting_legacy() {
    for field in 0..3 {
        let ConfigMutationIntent::BoundedAppend {
            mut commit,
            binding,
            ..
        } = command(128).intent
        else {
            panic!("bounded fixture");
        };
        match field {
            0 => commit.record.encrypted_blob.resize(1_704_493, 0),
            1 => commit.record.plaintext_digest.push(0),
            _ => commit.record.principal = "x".repeat(16_385),
        }
        let prepared = audited(AuditedConfigEffect::BoundedAppend {
            commit,
            binding,
            resolution: None,
        });
        let json = prepared.encode().unwrap();
        // A valid operation MAC cannot waive an independent input bound. The
        // old decoder still parses these bytes; it does not authenticate them.
        assert!(PreparedAuditedMutation::decode(&json).is_ok());
        assert!(config_capacity_decode::recovery(&json, ConfigCapacityProfile::Legacy).is_ok());
        assert!(config_capacity_decode::recovery(&json, PROFILE).is_err());
        let request = forward(ConfigMutationIntent::AuditedMutation(
            prepared.command().clone(),
        ));
        let wire =
            crate::consensus::types::encode_config_wire_for_profile(PROFILE, &request).unwrap();
        assert!(crate::consensus::types::decode_config_wire_for_profile::<
            super::super::super::ForwardMutationRequest,
        >(PROFILE, &wire)
        .is_ok());
        assert!(super::super::super::decode_forward_mutation(PROFILE, &wire).is_err());
    }
}
