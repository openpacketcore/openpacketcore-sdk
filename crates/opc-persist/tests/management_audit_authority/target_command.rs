// RFC 019 target-command allocation and strict closed recovery input.
// This is a codec detector; parsing an untrusted handle proves no admission.
use super::AuditCommand;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ManagementAuditEventRecord,
    ManagementAuditInstant, ManagementAuditOperationCode, ManagementAuditOutcomeCode,
    ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};
use serde_json::{json, Value};

fn discard_command() -> Value {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x21; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x22; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let privacy = AuditPrivacyKey::new([0x23; 32]).unwrap();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let event = ManagementAuditEventRecord::try_new(
        [0x25; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        "fixture-tenant",
        "fixture-principal",
        ManagementAuditTransportCode::NetconfSsh,
        ManagementAuditOperationCode::Exec,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:configuration"],
        Some("fixture-transaction"),
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &event).unwrap();
    let binding = AuditOperationBinding::project(&privacy, &event, 0, b"fixture-discard").unwrap();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity,
            binding,
            event: event.clone(),
            issued_at: 100,
            expires_at: 160,
            nonce: [0x26; 16],
            key_epoch: key.epoch(),
            mutation: Some([0x27; 32]),
        },
        &key,
    )
    .unwrap();
    json!({"netconf-target": {
        "handle": handle,
        "effect": {
            "format": 1,
            "authority": identity,
            "profile_incarnation": vec![0x31u8; 16],
            "device_incarnation": vec![0x32u8; 16],
            "caller": event.caller,
            "request": event.request,
            "action": 5,
            "destination": {"candidate": {"generation": {"authority": identity, "value": 0}}},
            "source": null,
            "lock": {"datastore": 1, "incarnation": 1, "session": vec![0x33u8; 16]},
            "expires_at": 160,
            "encrypted_payload": null,
            "resolution": null
        }
    }})
}

#[test]
fn target_command_uses_the_allocated_nested_tag_and_round_trips() {
    let fixture = discard_command();
    let parsed = serde_json::from_value::<AuditCommand>(fixture.clone());
    assert!(parsed.is_ok(), "closed target command is not representable");
    let parsed = parsed.unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), fixture);
    let encoded = opc_consensus::encode_bounded(&parsed).unwrap();
    assert_eq!(encoded[0], 9, "target command changed its allocated tag");
    let decoded: AuditCommand = opc_consensus::decode_bounded(&encoded).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), fixture);
    for end in 0..encoded.len() {
        assert!(opc_consensus::decode_bounded::<AuditCommand>(&encoded[..end]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(opc_consensus::decode_bounded::<AuditCommand>(&trailing).is_err());
}

#[test]
fn target_command_rejects_unknown_fields_and_unallocated_action_tags() {
    // These refusals are meaningful only alongside the positive decoder above.
    for path in [
        "/netconf-target",
        "/netconf-target/effect",
        "/netconf-target/effect/lock",
    ] {
        let mut fixture = discard_command();
        fixture
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(0));
        assert!(serde_json::from_value::<AuditCommand>(fixture).is_err());
    }
    for tag in [16, 17, 255, 256, -1] {
        let mut fixture = discard_command();
        fixture["netconf-target"]["effect"]["action"] = json!(tag);
        assert!(serde_json::from_value::<AuditCommand>(fixture).is_err());
    }
}

fn signed_discard() -> crate::consensus::audit_mutation::PreparedTargetMutation {
    use crate::audit_authority::ledger::authenticate;
    let command: AuditCommand = serde_json::from_value(discard_command()).unwrap();
    let AuditCommand::NetconfTarget(mut prepared) = command else {
        panic!("target fixture decoded as another action");
    };
    let key = AuditKey::new([0x24; 32]).unwrap();
    let mut body = prepared.handle.body.clone();
    body.mutation = Some(
        authenticate(
            &key,
            b"openpacketcore/management-audit/netconf-target/v1\0",
            &prepared.effect,
        )
        .unwrap(),
    );
    prepared.handle = AuditOperationHandle::issue(body, &key).unwrap();
    *prepared
}

#[test]
fn target_binding_authenticates_every_common_field_and_preserves_original_handle() {
    use crate::consensus::audit_mutation::PreparedTargetMutation;
    let key = AuditKey::new([0x24; 32]).unwrap();
    let prepared = signed_discard();
    prepared.verify_effect(&key).unwrap();
    let encoded = prepared.encode().unwrap();
    let restored = PreparedTargetMutation::decode(&encoded).unwrap();
    restored.verify_effect(&key).unwrap();
    assert_eq!(restored.handle(), prepared.handle());
    assert_eq!(restored.encode().unwrap(), encoded);
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedTargetMutation(<redacted>)"
    );
    assert!(prepared
        .verify_effect(&AuditKey::new([0x45; 32]).unwrap())
        .is_err());
    let changes = [
        ("/effect/format", json!(2)),
        ("/effect/authority/configuration_epoch", json!(2)),
        ("/effect/profile_incarnation", json!(vec![0x41u8; 16])),
        ("/effect/device_incarnation", json!(vec![0x42u8; 16])),
        ("/effect/caller/principal", json!(vec![0x43u8; 32])),
        ("/effect/request", json!(vec![0x44u8; 32])),
        ("/effect/action", json!(8)),
        ("/effect/destination/candidate/generation/value", json!(1)),
        ("/effect/lock/incarnation", json!(2)),
        ("/effect/lock/session", json!(vec![0x46u8; 16])),
        ("/effect/expires_at", json!(161)),
    ];
    for (path, value) in changes {
        let mut altered = serde_json::to_value(&prepared).unwrap();
        *altered.pointer_mut(path).expect("fixture field") = value;
        let altered: PreparedTargetMutation = serde_json::from_value(altered).unwrap();
        assert!(
            altered.verify_effect(&key).is_err(),
            "substituted target binding admitted"
        );
    }
    // A freshly valid handle MAC cannot conceal a changed effect under its
    // original effect digest, nor can changing only the effect extend expiry.
    let mut delayed = prepared.clone();
    delayed.effect.expires_at = 161;
    let mut body = delayed.handle.body.clone();
    body.expires_at = 161;
    delayed.handle = AuditOperationHandle::issue(body, &key).unwrap();
    assert!(delayed.verify_effect(&key).is_err());
    prepared.verify_effect(&key).unwrap();
}

#[test]
fn target_command_cannot_enter_any_legacy_command_revision() {
    use crate::consensus::{ConfigConsensusCommand, ConfigMutationIntent};
    let prepared = signed_discard();
    let identity = prepared.handle.body.identity;
    for revision in 1..=9 {
        let command = ConfigConsensusCommand {
            schema_version: revision,
            identity,
            request_id: crate::ConfigConsensusRequestId::from_bytes([0x51; 16]),
            logical_time: "2026-01-01T00:00:00Z".parse().unwrap(),
            intent: ConfigMutationIntent::ManagementAudit(AuditCommand::NetconfTarget(Box::new(
                prepared.clone(),
            ))),
        };
        assert!(
            command.validate(identity).is_err(),
            "target effect admitted under the legacy profile"
        );
        let bytes = opc_consensus::encode_bounded(&command.intent).unwrap();
        assert_eq!(&bytes[..2], &[6, 9]);
    }
}

#[test]
fn target_recovery_bounds_and_shape_fail_without_exposing_values() {
    use crate::consensus::audit_mutation::PreparedTargetMutation;
    let prepared = signed_discard();
    let encoded = prepared.encode().unwrap();
    for end in 0..encoded.len() {
        assert!(PreparedTargetMutation::decode(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.extend_from_slice(b"null");
    assert!(PreparedTargetMutation::decode(&trailing).is_err());
    let oversized = vec![b' '; crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES + 1];
    assert!(PreparedTargetMutation::decode(&oversized).is_err());
    for (path, value) in [
        ("/effect/profile_incarnation", json!(vec![0u8; 16])),
        ("/effect/device_incarnation", json!(vec![0u8; 16])),
        (
            "/effect/destination/candidate/generation/value",
            json!(u64::MAX),
        ),
        ("/effect/lock/datastore", json!(3)),
        ("/effect/lock/session", json!(vec![0u8; 16])),
        ("/effect/lock/incarnation", json!(0)),
        ("/handle/body/event/transport", json!("gnmi")),
        ("/handle/body/event/transport", json!("internal")),
        ("/handle/body/event/outcome", json!("success")),
        ("/handle/body/mutation", Value::Null),
    ] {
        let mut invalid = serde_json::to_value(&prepared).unwrap();
        *invalid.pointer_mut(path).unwrap() = value;
        let error =
            PreparedTargetMutation::decode(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert_eq!(
            error,
            crate::audit_authority::AuditAuthorityError::BindingMismatch
        );
        assert_eq!(error.to_string(), "audit authority binding mismatch");
    }
}

#[test]
fn target_action_bytes_are_explicit_and_do_not_reuse_unallocated_tags() {
    use crate::consensus::audit_mutation::TargetActionV1;
    for action in 0u8..=15 {
        let decoded: TargetActionV1 = serde_json::from_value(json!(action)).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json!(action));
        assert_eq!(opc_consensus::encode_bounded(&decoded).unwrap(), [action]);
        let binary: TargetActionV1 = opc_consensus::decode_bounded(&[action]).unwrap();
        assert_eq!(serde_json::to_value(binary).unwrap(), json!(action));
    }
    for action in 16u8..=255 {
        assert!(serde_json::from_value::<TargetActionV1>(json!(action)).is_err());
        assert!(opc_consensus::decode_bounded::<TargetActionV1>(&[action]).is_err());
    }
}

#[test]
fn target_nested_identity_and_caller_fields_are_closed() {
    use crate::consensus::audit_mutation::PreparedTargetMutation;
    let prepared = signed_discard();
    for path in [
        "/effect/authority",
        "/effect/caller",
        "/effect/destination/candidate/generation",
        "/effect/destination/candidate/generation/authority",
    ] {
        let mut value = serde_json::to_value(&prepared).unwrap();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(0));
        assert!(PreparedTargetMutation::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert_eq!(
        PreparedTargetMutation::decode(&prepared.encode().unwrap()).unwrap(),
        prepared
    );
}
