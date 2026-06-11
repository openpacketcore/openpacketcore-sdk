#![cfg(all(feature = "nacm", feature = "persist"))]

use opc_alarm::prelude::*;
use opc_alarm::{NacmAlarmAuthorizer, PersistAlarmAuditSink};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_persist::SqliteBackend;
use tempfile::tempdir;
use time::OffsetDateTime;

// Helper to set up module registry for tests
fn make_registry() -> ModuleRegistry {
    let mut reg = ModuleRegistry::new();
    reg.register_module("ietf-alarms", "ietf-alarms")
        .expect("register ietf-alarms");
    reg
}

fn make_authorizer(
    policy: NacmPolicy,
    registry: ModuleRegistry,
    principals: &[&str],
) -> NacmAlarmAuthorizer {
    NacmAlarmAuthorizer::with_allowed_principals(policy, registry, principals.iter().copied())
}

// Helper to create an active alarm for testing
fn make_test_alarm(alarm_id: &str, severity: Severity) -> Alarm {
    let now = OffsetDateTime::now_utc();
    Alarm {
        alarm_id: AlarmId::new(alarm_id),
        alarm_type: AlarmType::new("link.down"),
        severity,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: Some("tenant-a".to_string()),
        slice: Some("slice-1".to_string()),
        region: None,
        text: RedactedText::new("Link down"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: now,
        updated_at: now,
        cleared_at: None,
        correlation_id: None,
    }
}

// Helper to create a security-critical alarm (e.g., identity unavailable probable cause)
fn make_security_critical_alarm(alarm_id: &str) -> Alarm {
    let now = OffsetDateTime::now_utc();
    Alarm {
        alarm_id: AlarmId::new(alarm_id),
        alarm_type: AlarmType::new("sec.violation"),
        severity: Severity::Major,
        probable_cause: ProbableCause::IdentityUnavailable,
        affected_object: AffectedObject::NfInstance {
            kind: "amf".to_string(),
            instance: "amf-1".to_string(),
        },
        tenant: Some("tenant-a".to_string()),
        slice: Some("slice-1".to_string()),
        region: None,
        text: RedactedText::new("Identity unavailable"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: now,
        updated_at: now,
        cleared_at: None,
        correlation_id: None,
    }
}

// Helper to create the default action context
fn make_context(alarm_id: &AlarmId, principal: &str) -> AlarmActionContext {
    AlarmActionContext::new(
        principal,
        "operator maintenance activity",
        AlarmActionScope::Alarm {
            alarm_id: alarm_id.clone(),
        },
    )
    .with_tenant("tenant-a")
}

// ─────────────────────────────────────────────────────────────────────────────
// NACM Authorizer Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nacm_authorizer_allows_ack_when_policy_permits() {
    let registry = make_registry();
    let ack_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
        &registry,
    )
    .unwrap();

    // Policy permits Exec on the acknowledge-alarm path
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, ack_pattern))
        .build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user");

    let result = authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &alarm, &context);
    assert!(result.is_ok());
}

#[test]
fn nacm_authorizer_denies_principal_not_in_allowlist_even_when_path_permits() {
    let registry = make_registry();
    let ack_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
        &registry,
    )
    .unwrap();

    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, ack_pattern))
        .build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "intruder-user");

    let result = authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &alarm, &context);
    let err = result.unwrap_err();
    assert!(err.message.contains("not allowed to administer alarms"));
}

#[test]
fn nacm_authorizer_new_denies_until_principals_are_configured() {
    let registry = make_registry();
    let ack_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
        &registry,
    )
    .unwrap();

    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, ack_pattern))
        .build();

    let authorizer = NacmAlarmAuthorizer::new(policy, registry);
    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user");

    let result = authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &alarm, &context);
    let err = result.unwrap_err();
    assert!(err.message.contains("not allowed to administer alarms"));
}

#[test]
fn nacm_authorizer_denies_ack_when_no_rule_matches() {
    let registry = make_registry();
    // Empty policy defaults to deny
    let policy = NacmPolicy::builder(PolicyVersion::new(1)).build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user");

    let result = authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &alarm, &context);
    let err = result.unwrap_err();
    assert!(err.message.to_lowercase().contains("authorization denied"));
}

#[test]
fn nacm_authorizer_allows_suppression_when_policy_permits() {
    let registry = make_registry();
    let suppress_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/suppress-alarm",
        &registry,
    )
    .unwrap();

    // Policy permits Exec on the suppress-alarm path
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, suppress_pattern))
        .build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user");

    let result = authorizer.authorize_alarm_action(AlarmAction::Suppress, &alarm, &context);
    assert!(result.is_ok());
}

#[test]
fn nacm_authorizer_denies_suppression_when_no_rule_matches() {
    let registry = make_registry();
    // Empty policy defaults to deny
    let policy = NacmPolicy::builder(PolicyVersion::new(1)).build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user");

    let result = authorizer.authorize_alarm_action(AlarmAction::Suppress, &alarm, &context);
    let err = result.unwrap_err();
    assert!(err.message.to_lowercase().contains("authorization denied"));
}

#[test]
fn security_critical_suppression_denied_by_default() {
    let registry = make_registry();
    let suppress_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/suppress-alarm",
        &registry,
    )
    .unwrap();

    // Policy permits generic suppression, but does NOT override security-critical
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, suppress_pattern))
        .build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_security_critical_alarm("alarm-critical-1");
    let context = make_context(&alarm.alarm_id, "admin-user");

    // authorize_alarm_action would succeed for generic suppress
    assert!(authorizer
        .authorize_alarm_action(AlarmAction::Suppress, &alarm, &context)
        .is_ok());

    // But allow_security_critical_suppression must return false
    assert!(!authorizer.allow_security_critical_suppression(&alarm, &context));
}

#[test]
fn security_critical_suppression_succeeds_with_explicit_override() {
    let registry = make_registry();
    let suppress_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/suppress-alarm",
        &registry,
    )
    .unwrap();
    let override_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/security-critical-suppression",
        &registry,
    )
    .unwrap();

    // Policy permits both suppress and the explicit security-critical override
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, suppress_pattern))
        .add_rule(NacmRule::allow(NacmAction::Exec, override_pattern))
        .build();

    let authorizer = make_authorizer(policy, registry, &["admin-user"]);
    let alarm = make_security_critical_alarm("alarm-critical-1");
    let context = make_context(&alarm.alarm_id, "admin-user");

    // Both authorize and override checks should succeed
    assert!(authorizer
        .authorize_alarm_action(AlarmAction::Suppress, &alarm, &context)
        .is_ok());
    assert!(authorizer.allow_security_critical_suppression(&alarm, &context));
}

#[test]
fn nacm_authorizer_scope_and_tenant_validation() {
    let registry = make_registry();
    let ack_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
        &registry,
    )
    .unwrap();
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, ack_pattern))
        .build();
    let authorizer = make_authorizer(policy, registry, &["admin-user"]);

    let alarm = make_test_alarm("alarm-1", Severity::Major);

    // 1. Principal empty
    let context_empty_principal = make_context(&alarm.alarm_id, "");
    let res = authorizer.authorize_alarm_action(
        AlarmAction::Acknowledge,
        &alarm,
        &context_empty_principal,
    );
    assert!(res
        .unwrap_err()
        .message
        .contains("principal identity cannot be empty"));

    // 2. Alarm ID mismatch
    let context_id_mismatch = AlarmActionContext::new(
        "admin-user",
        "reason",
        AlarmActionScope::Alarm {
            alarm_id: AlarmId::new("different-alarm"),
        },
    );
    let res =
        authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &alarm, &context_id_mismatch);
    assert!(res.unwrap_err().message.contains("Scope alarm_id"));

    // 3. Tenant mismatch: tenant-a alarm vs tenant-b context
    let context_tenant_mismatch = AlarmActionContext::new(
        "admin-user",
        "reason",
        AlarmActionScope::Alarm {
            alarm_id: alarm.alarm_id.clone(),
        },
    )
    .with_tenant("tenant-b");
    let res = authorizer.authorize_alarm_action(
        AlarmAction::Acknowledge,
        &alarm,
        &context_tenant_mismatch,
    );
    assert!(res.unwrap_err().message.contains("Tenant mismatch"));

    // 4. Tenant mismatch: global alarm vs tenant-a context
    let mut global_alarm = alarm.clone();
    global_alarm.tenant = None;
    let context_tenant = make_context(&global_alarm.alarm_id, "admin-user");
    let res =
        authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &global_alarm, &context_tenant);
    assert!(res
        .unwrap_err()
        .message
        .contains("cannot touch global alarm"));
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite Persistence Audit Sink Tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn persist_audit_sink_records_authorized_ack() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_audit.db");
    let backend = SqliteBackend::open(&db_path, true, 0).await.unwrap();

    let alarm = make_test_alarm("alarm-1", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user").with_correlation_id("corr-123");

    let event = AlarmAuditEvent {
        action: AlarmAction::Acknowledge,
        outcome: AlarmAuditOutcome::Authorized,
        alarm_id: alarm.alarm_id.clone(),
        alarm_type: alarm.alarm_type.clone(),
        probable_cause: alarm.probable_cause.clone(),
        principal: context.principal.clone(),
        tenant: context.tenant.clone(),
        reason: context.reason.clone(),
        scope: context.scope.clone(),
        correlation_id: context.correlation_id.clone(),
        occurred_at: OffsetDateTime::now_utc(),
    };

    let mut sink = PersistAlarmAuditSink::new(backend.clone());
    sink.record_alarm_action(event).unwrap();

    // Query recorded audits from SQLite backend
    let records = backend.query_alarm_audits().await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.action, "acknowledge");
    assert_eq!(record.outcome, "authorized");
    assert_eq!(record.alarm_id, "alarm-1");
    assert_eq!(record.alarm_type, "link.down");
    assert_eq!(record.probable_cause, "peer-unreachable");
    assert_eq!(record.principal, "admin-user");
    assert_eq!(record.tenant.as_deref(), Some("tenant-a"));
    assert_eq!(record.reason, "operator maintenance activity");
    assert_eq!(record.scope, "alarm:alarm-1");
    assert_eq!(record.correlation_id.as_deref(), Some("corr-123"));
}

#[tokio::test]
async fn persist_audit_sink_records_authorized_suppress() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_audit.db");
    let backend = SqliteBackend::open(&db_path, true, 0).await.unwrap();

    let alarm = make_test_alarm("alarm-2", Severity::Major);
    let context = make_context(&alarm.alarm_id, "admin-user");

    let event = AlarmAuditEvent {
        action: AlarmAction::Suppress,
        outcome: AlarmAuditOutcome::Authorized,
        alarm_id: alarm.alarm_id.clone(),
        alarm_type: alarm.alarm_type.clone(),
        probable_cause: alarm.probable_cause.clone(),
        principal: context.principal.clone(),
        tenant: context.tenant.clone(),
        reason: context.reason.clone(),
        scope: context.scope.clone(),
        correlation_id: context.correlation_id.clone(),
        occurred_at: OffsetDateTime::now_utc(),
    };

    let mut sink = PersistAlarmAuditSink::new(backend.clone());
    sink.record_alarm_action(event).unwrap();

    let records = backend.query_alarm_audits().await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.action, "suppress");
    assert_eq!(record.outcome, "authorized");
    assert_eq!(record.alarm_id, "alarm-2");
}

#[tokio::test]
async fn persist_audit_sink_records_denied_events() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_audit.db");
    let backend = SqliteBackend::open(&db_path, true, 0).await.unwrap();

    let alarm = make_test_alarm("alarm-3", Severity::Major);
    let context = make_context(&alarm.alarm_id, "intruder-user");

    let event = AlarmAuditEvent {
        action: AlarmAction::Acknowledge,
        outcome: AlarmAuditOutcome::Denied,
        alarm_id: alarm.alarm_id.clone(),
        alarm_type: alarm.alarm_type.clone(),
        probable_cause: alarm.probable_cause.clone(),
        principal: context.principal.clone(),
        tenant: context.tenant.clone(),
        reason: context.reason.clone(),
        scope: context.scope.clone(),
        correlation_id: context.correlation_id.clone(),
        occurred_at: OffsetDateTime::now_utc(),
    };

    let mut sink = PersistAlarmAuditSink::new(backend.clone());
    sink.record_alarm_action(event).unwrap();

    let records = backend.query_alarm_audits().await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.action, "acknowledge");
    assert_eq!(record.outcome, "denied");
    assert_eq!(record.principal, "intruder-user");
}

#[tokio::test]
#[cfg(feature = "persist-test-hooks")]
async fn audit_append_failure_causes_fail_closed() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_fail_closed.db");
    let backend = SqliteBackend::open(&db_path, true, 0).await.unwrap();

    // Drop the alarm_audit table to force SQL execution errors
    backend
        .execute_raw_for_test("DROP TABLE alarm_audit")
        .await
        .unwrap();

    let registry = make_registry();
    let ack_pattern = YangPathPattern::parse(
        "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
        &registry,
    )
    .unwrap();
    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Exec, ack_pattern))
        .build();
    let authorizer = make_authorizer(policy, registry, &["admin-user"]);

    // Create a manager with an active alarm
    let store = InMemoryStore::new();
    let mut manager = AlarmManager::new(store);
    let alarm_op = manager.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        Some("slice-1".to_string()),
        None,
        RedactedText::new("Link down"),
        AlarmDetails::empty(),
    );

    let AlarmOpResult::Raised { alarm } = alarm_op else {
        panic!("expected alarm raised");
    };

    let context = make_context(&alarm.alarm_id, "admin-user");
    let mut sink = PersistAlarmAuditSink::new(backend);

    // Try acknowledging the alarm. Even though authorized, the audit write will fail (since the table is dropped).
    // The alarm must remain active and match AuditFailed status.
    let result = manager.acknowledge_with_policy(&alarm.alarm_id, &context, &authorizer, &mut sink);

    assert!(matches!(result, AlarmOpResult::AuditFailed { .. }));

    // Check that the alarm is still active in the manager
    let active = manager.active_alarms();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].state, AlarmState::Raised); // remains Raised, not Acknowledged
}

#[tokio::test]
async fn audit_redaction_removes_sensitive_data() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test_redaction.db");
    let backend = SqliteBackend::open(&db_path, true, 0).await.unwrap();

    let alarm = make_test_alarm("alarm-1", Severity::Major);
    // principal contains an IP address, reason contains a subscriber ID (15 digits SUPI/IMSI)
    let context = AlarmActionContext::new(
        "operator-192.168.1.100",
        "fixing issue for SUPI 208950000000001",
        AlarmActionScope::Alarm {
            alarm_id: alarm.alarm_id.clone(),
        },
    )
    .with_correlation_id("msisdn-123456789012"); // 12-digit MSISDN

    let event = AlarmAuditEvent {
        action: AlarmAction::Acknowledge,
        outcome: AlarmAuditOutcome::Authorized,
        alarm_id: alarm.alarm_id.clone(),
        alarm_type: alarm.alarm_type.clone(),
        probable_cause: alarm.probable_cause.clone(),
        principal: context.principal.clone(),
        tenant: context.tenant.clone(),
        reason: context.reason.clone(),
        scope: context.scope.clone(),
        correlation_id: context.correlation_id.clone(),
        occurred_at: OffsetDateTime::now_utc(),
    };

    let mut sink = PersistAlarmAuditSink::new(backend.clone());
    sink.record_alarm_action(event).unwrap();

    let records = backend.query_alarm_audits().await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];

    // Verify IP is redacted in principal
    assert_eq!(record.principal, "operator-[REDACTED]");

    // Verify SUPI/IMSI is redacted in reason
    assert_eq!(record.reason, "fixing issue for SUPI [REDACTED]");

    // Verify MSISDN is redacted in correlation_id
    assert_eq!(record.correlation_id.as_deref(), Some("msisdn-[REDACTED]"));
}
