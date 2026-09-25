mod target_results;

use super::ledger::*;
use super::*;
use crate::*;

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("audit-fixture").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([3; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn key() -> AuditKey {
    AuditKey::new([4; 32]).unwrap()
}

fn event() -> ProjectedAuditEvent {
    let event = ManagementAuditEventRecord::try_new(
        [0x51; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        "tenant-fixture-private",
        "principal-fixture-private",
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:system/fixture:name"],
        Some("transaction-fixture-private"),
    )
    .unwrap();
    ProjectedAuditEvent::project(&AuditPrivacyKey::new([5; 32]).unwrap(), &event).unwrap()
}

fn handle(nonce: u8) -> AuditOperationHandle {
    let event = event();
    let binding = AuditOperationBinding::project(
        &AuditPrivacyKey::new([5; 32]).unwrap(),
        &event,
        7,
        b"sdk-canonical-operation-fixture",
    )
    .unwrap();
    AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 200,
            nonce: [nonce; 16],
            key_epoch: 1,
            mutation: None,
        },
        &key(),
    )
    .unwrap()
}

#[test]
fn applied_receipt_authenticates_outcome_sequence_and_exact_operation() {
    use super::receipt::AuthenticatedAuditReceipt;

    let operation = handle(31);
    let caller = operation.body.binding.caller;
    let receipt = AuditOperationReceipt {
        handle: operation.clone(),
        state: AuditOperationState::Committed { version: 8 },
        terminal_recorded: false,
        sequence: 2,
    };
    let proof = AuthenticatedAuditReceipt::seal(&key(), &receipt).unwrap();
    let encoded = serde_json::to_vec(&proof).unwrap();
    let decoded: AuthenticatedAuditReceipt = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        decoded
            .read_back(&key(), identity(), &operation, caller)
            .unwrap(),
        receipt
    );
    assert!(decoded
        .read_back(&key(), identity(), &handle(32), caller)
        .is_err());
    assert!(decoded
        .read_back(
            &AuditKey::new([9; 32]).unwrap(),
            identity(),
            &operation,
            caller
        )
        .is_err());
    let wrong_caller =
        AuditCaller::project(&AuditPrivacyKey::new([5; 32]).unwrap(), "other", "caller").unwrap();
    assert!(decoded
        .read_back(&key(), identity(), &operation, wrong_caller)
        .is_err());
    let other_fleet = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("other-audit-fixture").unwrap(),
        identity().configuration_id(),
        identity().configuration_epoch(),
    );
    assert!(decoded
        .read_back(&key(), other_fleet, &operation, caller)
        .is_err());
    for field in [
        "state",
        "terminal_recorded",
        "sequence",
        "operation",
        "identity",
        "mac",
    ] {
        let mut value = serde_json::to_value(&proof).unwrap();
        match field {
            "state" => value["body"][field] = serde_json::json!("rejected"),
            "terminal_recorded" => value["body"][field] = serde_json::json!(true),
            "sequence" => value["body"][field] = serde_json::json!(3),
            "operation" => {
                value["body"][field][0] =
                    serde_json::json!(255 - value["body"][field][0].as_u64().unwrap())
            }
            "identity" => value["body"][field] = serde_json::to_value(other_fleet).unwrap(),
            "mac" => value[field][0] = serde_json::json!(255 - value[field][0].as_u64().unwrap()),
            _ => unreachable!(),
        }
        let tampered: AuthenticatedAuditReceipt = serde_json::from_value(value).unwrap();
        assert!(
            tampered
                .read_back(&key(), identity(), &operation, caller)
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(
        format!("{proof:?}"),
        "AuthenticatedAuditReceipt(<redacted>)"
    );
}

#[test]
fn projection_separates_purposes_tuples_and_callers_before_serialization() {
    let privacy = AuditPrivacyKey::new([5; 32]).unwrap();
    assert_ne!(
        privacy
            .project(AuditPrivacyPurpose::Tenant, &[b"ab", b"c"])
            .unwrap(),
        privacy
            .project(AuditPrivacyPurpose::Tenant, &[b"a", b"bc"])
            .unwrap()
    );
    assert_ne!(
        privacy
            .project(AuditPrivacyPurpose::Tenant, &[b"x"])
            .unwrap(),
        privacy
            .project(AuditPrivacyPurpose::Principal, &[b"x"])
            .unwrap()
    );
    assert_ne!(
        AuditCaller::project(&privacy, "first", "same").unwrap(),
        AuditCaller::project(&privacy, "second", "same").unwrap()
    );
    let event = event();
    let encoded = serde_json::to_string(&event).unwrap();
    for private in [
        "tenant-fixture-private",
        "principal-fixture-private",
        "transaction-fixture-private",
        "/fixture:system/fixture:name",
    ] {
        assert!(!encoded.contains(private));
        assert!(!format!("{event:?}").contains(private));
    }
    let long = vec![0; AUDIT_OPERATION_MAX_BYTES + 1];
    assert_eq!(
        privacy.project(AuditPrivacyPurpose::Operation, &[&long]),
        Err(AuditAuthorityError::InvalidInput)
    );
    assert!(AuditPrivacyKey::new([0; 32]).is_err());
}

#[test]
fn handle_authenticates_every_field_and_expiry_without_exposing_identity() {
    let original = handle(1);
    let caller = original.body.binding.caller;
    assert!(original.verify(&key(), identity(), caller).is_ok());
    assert!(AuditOperationHandle::decode(&original.encode().unwrap())
        .unwrap()
        .verify(&key(), identity(), caller)
        .is_ok());
    assert!(original.require_live(199).is_ok());
    assert_eq!(
        original.require_live(200),
        Err(AuditAuthorityError::Expired)
    );
    assert_eq!(original.require_live(99), Err(AuditAuthorityError::Expired));
    for field in ["issued_at", "expires_at", "key_epoch", "version"] {
        let mut value = serde_json::to_value(&original).unwrap();
        let old = value["body"][field].as_i64().unwrap();
        value["body"][field] = serde_json::json!(old + 1);
        let tampered: AuditOperationHandle = serde_json::from_value(value).unwrap();
        assert!(tampered.verify(&key(), identity(), caller).is_err());
    }
    let other =
        AuditCaller::project(&AuditPrivacyKey::new([5; 32]).unwrap(), "other", "other").unwrap();
    assert!(original.verify(&key(), identity(), other).is_err());
    assert!(original
        .verify(&AuditKey::new([6; 32]).unwrap(), identity(), caller)
        .is_err());
    assert_eq!(format!("{original:?}"), "AuditOperationHandle(<redacted>)");
}

#[test]
fn full_ledger_preserves_reserved_outcomes_and_idempotent_receipts() {
    let handle = handle(1);
    let mut ledger = LedgerState::new(
        identity(),
        event().projection,
        AuditLedgerLimits::new(3, 1).unwrap(),
    );
    ledger.admit(&key(), &handle, 110).unwrap();
    assert_eq!(
        ledger.append_event(&key(), event()),
        Err(AuditAuthorityError::Full)
    );
    assert_eq!(ledger.sequence, 1);
    ledger.admit(&key(), &handle, 150).unwrap();
    assert_eq!(ledger.sequence, 1);
    // Outcome and terminal acknowledgement consume capacity reserved by Intent.
    ledger
        .resolve(
            &key(),
            &handle,
            AuditOperationState::Committed { version: 8 },
        )
        .unwrap();
    ledger.acknowledge_terminal(&key(), &handle).unwrap();
    assert_eq!(ledger.sequence, 3);
    ledger
        .resolve(
            &key(),
            &handle,
            AuditOperationState::Committed { version: 8 },
        )
        .unwrap();
    ledger.acknowledge_terminal(&key(), &handle).unwrap();
    assert_eq!(ledger.sequence, 3);
    assert!(ledger
        .resolve(&key(), &handle, AuditOperationState::Rejected)
        .is_err());
    ledger.validate(&key(), identity()).unwrap();
    let receipt = ledger
        .lookup(&key(), &handle, handle.body.binding.caller)
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 8 }
    );
    assert!(receipt.terminal_recorded());
    assert_eq!(
        ledger.admit(&key(), &super::tests::handle(2), 150),
        Err(AuditAuthorityError::BindingMismatch)
    );
}

#[test]
fn expired_unadmitted_handle_cannot_become_fresh_after_restart() {
    let handle = handle(1);
    let ledger = LedgerState::new(
        identity(),
        event().projection,
        AuditLedgerLimits::new(3, 1).unwrap(),
    );
    let bytes = serde_json::to_vec(&ledger).unwrap();
    let mut restored: LedgerState = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        restored.admit(&key(), &handle, 200),
        Err(AuditAuthorityError::Expired)
    );
    assert_eq!(restored.sequence, 0);
    assert!(restored
        .lookup(&key(), &handle, handle.body.binding.caller)
        .unwrap()
        .is_none());
}

#[test]
fn chain_rejects_omission_reorder_and_tail_truncation() {
    let mut ledger = LedgerState::new(
        identity(),
        event().projection,
        AuditLedgerLimits::new(6, 1).unwrap(),
    );
    let handle = handle(1);
    ledger.admit(&key(), &handle, 110).unwrap();
    ledger.append_event(&key(), event()).unwrap();
    ledger
        .resolve(&key(), &handle, AuditOperationState::Rejected)
        .unwrap();
    ledger.acknowledge_terminal(&key(), &handle).unwrap();
    ledger.validate(&key(), identity()).unwrap();
    let mut missing = ledger.clone();
    missing.entries.remove(1);
    assert!(missing.validate(&key(), identity()).is_err());
    let mut reordered = ledger.clone();
    reordered.entries.swap(0, 1);
    assert!(reordered.validate(&key(), identity()).is_err());
    let mut truncated = ledger.clone();
    truncated.entries.pop();
    assert!(truncated.validate(&key(), identity()).is_err());
}
