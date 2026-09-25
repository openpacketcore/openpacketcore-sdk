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
