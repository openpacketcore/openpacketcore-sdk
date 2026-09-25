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
    json!({"netconf-target": {"apply": {
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
    }}})
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
        "/netconf-target/apply/effect",
        "/netconf-target/apply/effect/lock",
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
        fixture["netconf-target"]["apply"]["effect"]["action"] = json!(tag);
        assert!(serde_json::from_value::<AuditCommand>(fixture).is_err());
    }
}

fn signed_discard() -> crate::consensus::audit_mutation::PreparedTargetMutation {
    use crate::audit_authority::ledger::authenticate;
    let command: AuditCommand = serde_json::from_value(discard_command()).unwrap();
    let AuditCommand::NetconfTarget(command) = command else {
        panic!("target fixture decoded as another action");
    };
    let crate::consensus::audit_mutation::TargetAuditCommandV1::Apply(mut prepared) = *command
    else {
        panic!("target fixture decoded as admission");
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
    prepared
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
                crate::consensus::audit_mutation::TargetAuditCommandV1::Apply(prepared.clone()),
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

fn retained_target_fixture() -> (
    tempfile::TempDir,
    rusqlite::Connection,
    crate::audit_authority::continuity::AuditKeyRing,
) {
    use crate::audit_authority::continuity::{AuditKeyRing, AuditSigningKey};
    let root = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open(root.path().join("authority.db")).unwrap();
    let prepared = signed_discard();
    let identity = prepared.handle.body.identity;
    let key = AuditKey::new([0x24; 32]).unwrap();
    conn.execute_batch("CREATE TABLE config_raft_identity (singleton INTEGER PRIMARY KEY, cluster_id BLOB, configuration_id BLOB, configuration_epoch INTEGER); CREATE TABLE config_raft_management_audit (singleton INTEGER PRIMARY KEY, state_json BLOB, state_hmac BLOB);").unwrap();
    conn.execute(
        "INSERT INTO config_raft_identity VALUES (1,?1,?2,?3)",
        rusqlite::params![
            identity.cluster_id().as_bytes().as_slice(),
            identity.configuration_id().as_bytes().as_slice(),
            identity.configuration_epoch().get() as i64
        ],
    )
    .unwrap();
    super::initialize_sync(&conn, &key, identity).unwrap();
    crate::consensus::audit_targets::initialize_inactive_sync(&conn, &key, identity).unwrap();
    let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x61; 32]).unwrap()]).unwrap();
    super::apply_sync(
        &conn,
        &key,
        identity,
        &AuditCommand::InitializeWithContinuity {
            projection: prepared.handle.body.event.projection,
            limits: crate::audit_authority::AuditLedgerLimits::new(12, 4).unwrap(),
            initial_epoch: 1,
        },
        100,
        Some(&keys),
    )
    .unwrap()
    .unwrap();
    (root, conn, keys)
}

fn target_admission_command(
    prepared: &crate::consensus::audit_mutation::PreparedTargetMutation,
) -> AuditCommand {
    let parsed = serde_json::from_value(json!({"netconf-target": {"admit": prepared}}));
    assert!(
        parsed.is_ok(),
        "retained target admission phase is unavailable"
    );
    parsed.unwrap()
}

#[test]
fn retained_target_admission_preserves_the_exact_closed_description_after_reopen() {
    use crate::audit_authority::AuditOperationState;
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let (root, conn, keys) = retained_target_fixture();
    let command = target_admission_command(&prepared);
    super::apply_sync(&conn, &key, identity, &command, 100, Some(&keys))
        .unwrap()
        .unwrap();
    let retained = super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
    assert_eq!(retained.sequence, 1);
    let receipt = retained
        .lookup(&key, prepared.handle(), prepared.handle.body.binding.caller)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Intent);
    assert!(!receipt.terminal_recorded());
    let encoded = serde_json::to_value(&retained).unwrap();
    let exact = String::from_utf8(prepared.encode().unwrap()).unwrap();
    assert_eq!(
        encoded["entries"][0]["payload"]["target-intent"]["recovery"],
        exact
    );
    assert_eq!(
        encoded["entries"][0]["payload"]["target-intent"]["handle"],
        serde_json::to_value(prepared.handle()).unwrap()
    );
    drop(conn);
    let reopened = rusqlite::Connection::open(root.path().join("authority.db")).unwrap();
    let restored = super::read_with_keys_sync(&reopened, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&retained).unwrap()
    );
    // Recovery of an already-admitted request is allowed after its original
    // expiry; this does not permit application of an expired effect.
    super::apply_sync(&reopened, &key, identity, &command, 200, Some(&keys))
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(
            super::read_with_keys_sync(&reopened, &key, Some(&keys), identity)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        encoded
    );
    let raw = prepared.encode().unwrap();
    let recovered = crate::consensus::audit_mutation::PreparedTargetMutation::decode(&raw).unwrap();
    assert_eq!(recovered.handle(), prepared.handle());
    recovered.verify_effect(&key).unwrap();
}

fn resign_target(prepared: &mut crate::consensus::audit_mutation::PreparedTargetMutation) {
    let key = AuditKey::new([0x24; 32]).unwrap();
    let mut body = prepared.handle.body.clone();
    body.mutation = Some(
        crate::audit_authority::ledger::authenticate(
            &key,
            b"openpacketcore/management-audit/netconf-target/v1\0",
            &prepared.effect,
        )
        .unwrap(),
    );
    prepared.handle = AuditOperationHandle::issue(body, &key).unwrap();
}

#[test]
fn retained_target_admission_rejects_conflicts_and_handle_only_recovery() {
    use crate::audit_authority::{AuditAuthorityError, AuditOperationState};
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let (_root, conn, keys) = retained_target_fixture();
    let mut ledger = super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
    ledger.admit_target(&key, &prepared, 100).unwrap();
    ledger.seal_continuity(Some(&keys)).unwrap();
    ledger.validate(&key, identity).unwrap();
    ledger.validate_continuity(Some(&keys)).unwrap();
    let unchanged = serde_json::to_vec(&ledger).unwrap();
    let mut different = prepared.clone();
    different.effect.lock.as_mut().unwrap().incarnation = 2;
    resign_target(&mut different);
    assert_eq!(
        ledger.admit_target(&key, &different, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert_eq!(
        ledger.admit(&key, prepared.handle(), 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), unchanged);
    let mut caller = serde_json::to_value(prepared.handle.body.binding.caller).unwrap();
    caller["principal"] = json!(vec![0x71u8; 32]);
    assert!(ledger
        .recover_target(
            &key,
            prepared.handle(),
            serde_json::from_value(caller).unwrap()
        )
        .is_err());
    assert_eq!(
        ledger
            .recover_target(&key, prepared.handle(), prepared.handle.body.binding.caller)
            .unwrap()
            .encode()
            .unwrap(),
        prepared.encode().unwrap()
    );
    ledger
        .resolve(&key, prepared.handle(), AuditOperationState::Rejected)
        .unwrap();
    ledger
        .acknowledge_terminal(&key, prepared.handle())
        .unwrap();
    ledger.seal_continuity(Some(&keys)).unwrap();
    let settled = serde_json::to_vec(&ledger).unwrap();
    ledger.admit_target(&key, &prepared, 200).unwrap();
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), settled);
    assert_eq!(
        ledger
            .lookup(&key, prepared.handle(), prepared.handle.body.binding.caller)
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
    assert_eq!(
        ledger
            .recover_target(&key, prepared.handle(), prepared.handle.body.binding.caller)
            .unwrap()
            .encode()
            .unwrap(),
        prepared.encode().unwrap()
    );

    let mut ordinary = super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
    ordinary.admit(&key, prepared.handle(), 100).unwrap();
    let before = serde_json::to_vec(&ordinary).unwrap();
    assert!(ordinary
        .recover_target(&key, prepared.handle(), prepared.handle.body.binding.caller)
        .is_err());
    assert_eq!(
        ordinary.admit_target(&key, &prepared, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert_eq!(serde_json::to_vec(&ordinary).unwrap(), before);
}

#[test]
fn retained_target_admission_requires_live_original_and_independent_continuity() {
    use crate::audit_authority::ledger::LedgerState;
    use crate::audit_authority::{AuditAuthorityError, AuditLedgerLimits};
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let mut ledger = LedgerState::new(
        identity,
        prepared.handle.body.event.projection,
        AuditLedgerLimits::new(12, 4).unwrap(),
    );
    let original = serde_json::to_vec(&ledger).unwrap();
    assert_eq!(
        ledger.admit_target(&key, &prepared, 100),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), original);
    ledger.continuity = Some(crate::audit_authority::continuity::chain::ContinuityState::new(1));
    for time in [99, 160, 200] {
        let original = serde_json::to_vec(&ledger).unwrap();
        assert_eq!(
            ledger.admit_target(&key, &prepared, time),
            Err(AuditAuthorityError::Expired)
        );
        assert_eq!(serde_json::to_vec(&ledger).unwrap(), original);
    }
}

#[test]
fn retained_target_admission_rejects_tampered_truncated_and_substituted_descriptions() {
    use crate::audit_authority::ledger::{authenticate, EntryPayload, LedgerState};
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let (_root, conn, keys) = retained_target_fixture();
    let mut ledger = super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
    ledger.admit_target(&key, &prepared, 100).unwrap();
    ledger.seal_continuity(Some(&keys)).unwrap();
    let recovery = String::from_utf8(prepared.encode().unwrap()).unwrap();
    let mut changed = serde_json::to_value(&prepared).unwrap();
    changed["effect"]["lock"]["incarnation"] = json!(2);
    let changed = crate::consensus::audit_mutation::PreparedTargetMutation::decode(
        &serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    let changed = String::from_utf8(changed.encode().unwrap()).unwrap();
    let mut foreign = prepared.clone();
    foreign.handle.body.nonce = [0x76; 16];
    resign_target(&mut foreign);
    for replacement in [
        String::new(),
        recovery[..recovery.len() - 1].into(),
        format!(" {recovery}"),
        changed.clone(),
        String::from_utf8(foreign.encode().unwrap()).unwrap(),
        " ".repeat(crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES + 1),
    ] {
        let mut value = serde_json::to_value(&ledger).unwrap();
        value["entries"][0]["payload"]["target-intent"]["recovery"] = json!(replacement);
        let altered: LedgerState = serde_json::from_value(value).unwrap();
        assert!(
            altered.validate(&key, identity).is_err(),
            "altered retained description admitted"
        );
        assert!(
            altered.validate_continuity(Some(&keys)).is_err(),
            "portable chain ignored the retained description"
        );
    }
    // Recompute the outer row chain to isolate validation of the original
    // handle/effect binding, rather than relying only on an enclosing MAC.
    let mut forged = ledger.clone();
    let EntryPayload::TargetIntent(retained) = &mut forged.entries[0].payload else {
        panic!("missing target intent");
    };
    retained.recovery = changed;
    let entry = &mut forged.entries[0];
    entry.mac = authenticate(
        &key,
        b"openpacketcore/management-audit/replicated-entry/v1\0",
        &(
            identity,
            entry.sequence,
            entry.previous,
            entry.key_epoch,
            &entry.payload,
        ),
    )
    .unwrap();
    forged.terminal = entry.mac;
    assert!(
        forged.validate(&key, identity).is_err(),
        "re-signed outer row hid substituted target content"
    );
    ledger.validate(&key, identity).unwrap();
}

#[test]
fn retained_target_admission_reserves_aggregate_capacity_for_terminal_recovery() {
    use crate::audit_authority::ledger::{LedgerState, MAX_STATE_BYTES};
    use crate::audit_authority::{AuditAuthorityError, AuditLedgerLimits, AuditOperationState};
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let (_root, _conn, keys) = retained_target_fixture();
    let mut ledger = LedgerState::new(
        identity,
        prepared.handle.body.event.projection,
        AuditLedgerLimits::new(4096, 1024).unwrap(),
    );
    ledger.continuity = Some(crate::audit_authority::continuity::chain::ContinuityState::new(1));
    let mut admitted = Vec::new();
    let mut full = false;
    for index in 1u32..=1024 {
        let mut next = prepared.clone();
        let mut request = [0x79u8; 32];
        request[..4].copy_from_slice(&index.to_le_bytes());
        let request = serde_json::from_value(json!(request)).unwrap();
        next.effect.request = request;
        next.handle.body.binding.request = request;
        next.handle.body.event.request = request;
        resign_target(&mut next);
        let unchanged = serde_json::to_vec(&ledger).unwrap();
        match ledger.admit_target(&key, &next, 100) {
            Ok(()) => admitted.push(next),
            Err(AuditAuthorityError::Full) => {
                assert_eq!(serde_json::to_vec(&ledger).unwrap(), unchanged);
                full = true;
                break;
            }
            Err(error) => panic!("unexpected admission error: {error}"),
        }
    }
    assert!(full && !admitted.is_empty() && admitted.len() < 1024);
    ledger.seal_continuity(Some(&keys)).unwrap();
    ledger.validate(&key, identity).unwrap();
    // Every reserved terminal remains appendable without deleting recovery
    // descriptions, increasing the aggregate bound, or extending expiry.
    for original in &admitted {
        ledger
            .resolve(&key, original.handle(), AuditOperationState::Rejected)
            .unwrap();
        ledger
            .acknowledge_terminal(&key, original.handle())
            .unwrap();
    }
    ledger.seal_continuity(Some(&keys)).unwrap();
    ledger.validate(&key, identity).unwrap();
    ledger.validate_continuity(Some(&keys)).unwrap();
    assert!(serde_json::to_vec(&ledger).unwrap().len() < MAX_STATE_BYTES);
    for original in &admitted {
        assert_eq!(
            ledger
                .recover_target(&key, original.handle(), original.handle.body.binding.caller)
                .unwrap()
                .encode()
                .unwrap(),
            original.encode().unwrap()
        );
    }
}

#[test]
fn retained_target_admission_and_application_have_distinct_closed_phase_tags() {
    let prepared = signed_discard();
    for (name, tag) in [("admit", 0), ("apply", 1)] {
        let value = json!({"netconf-target": {name: prepared}});
        let command: AuditCommand = serde_json::from_value(value.clone()).unwrap();
        let bytes = opc_consensus::encode_bounded(&command).unwrap();
        assert_eq!(&bytes[..2], &[9, tag]);
        let restored: AuditCommand = opc_consensus::decode_bounded(&bytes).unwrap();
        assert_eq!(serde_json::to_value(restored).unwrap(), value);
        let mut unknown = bytes.clone();
        unknown[1] = 2;
        assert!(opc_consensus::decode_bounded::<AuditCommand>(&unknown).is_err());
        for end in 0..bytes.len() {
            assert!(opc_consensus::decode_bounded::<AuditCommand>(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(opc_consensus::decode_bounded::<AuditCommand>(&trailing).is_err());
    }
}

#[test]
fn retained_target_admission_rejects_unknown_stored_intent_fields() {
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let (_root, conn, keys) = retained_target_fixture();
    super::apply_sync(
        &conn,
        &key,
        identity,
        &target_admission_command(&prepared),
        100,
        Some(&keys),
    )
    .unwrap()
    .unwrap();
    super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
    let original: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut altered: Value = serde_json::from_slice(&original).unwrap();
    altered["ledger"]["entries"][0]["payload"]["target-intent"]["unknown"] = json!(0);
    conn.execute(
        "UPDATE config_raft_management_audit SET state_json=?1 WHERE singleton=1",
        [serde_json::to_vec(&altered).unwrap()],
    )
    .unwrap();
    assert!(
        super::read_with_keys_sync(&conn, &key, Some(&keys), identity).is_err(),
        "unknown retained intent field bypassed authentication"
    );
    conn.execute(
        "UPDATE config_raft_management_audit SET state_json=?1 WHERE singleton=1",
        [original],
    )
    .unwrap();
    super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
}

#[test]
fn retained_target_admission_rejects_unknown_nested_handle_fields() {
    let prepared = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let identity = prepared.handle.body.identity;
    let (_root, conn, keys) = retained_target_fixture();
    super::apply_sync(
        &conn,
        &key,
        identity,
        &target_admission_command(&prepared),
        100,
        Some(&keys),
    )
    .unwrap()
    .unwrap();
    let original: Vec<u8> = conn
        .query_row(
            "SELECT state_json FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for path in [
        "/handle",
        "/handle/body",
        "/handle/body/identity",
        "/handle/body/binding",
        "/handle/body/binding/caller",
        "/handle/body/event",
        "/handle/body/event/caller",
    ] {
        let mut recovery = serde_json::to_value(&prepared).unwrap();
        recovery
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(0));
        assert!(
            crate::consensus::audit_mutation::PreparedTargetMutation::decode(
                &serde_json::to_vec(&recovery).unwrap()
            )
            .is_err(),
            "unknown target recovery handle field admitted"
        );
        let mut stored: Value = serde_json::from_slice(&original).unwrap();
        let root = &mut stored["ledger"]["entries"][0]["payload"]["target-intent"];
        root.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(0));
        conn.execute(
            "UPDATE config_raft_management_audit SET state_json=?1 WHERE singleton=1",
            [serde_json::to_vec(&stored).unwrap()],
        )
        .unwrap();
        assert!(
            super::read_with_keys_sync(&conn, &key, Some(&keys), identity).is_err(),
            "unknown stored target handle field admitted"
        );
    }
    conn.execute(
        "UPDATE config_raft_management_audit SET state_json=?1 WHERE singleton=1",
        [original],
    )
    .unwrap();
    super::read_with_keys_sync(&conn, &key, Some(&keys), identity)
        .unwrap()
        .unwrap();
}
