#![allow(deprecated)]

use super::*;
use crate::model::*;
use time::OffsetDateTime;

fn make_manager() -> AlarmManager<InMemoryStore> {
    AlarmManager::new(InMemoryStore::new())
}

#[derive(Default)]
struct TestAuthorizer {
    allow: bool,
    allow_security_critical: bool,
}

impl AlarmActionAuthorizer for TestAuthorizer {
    fn authorize_alarm_action(
        &self,
        _action: AlarmAction,
        _alarm: &Alarm,
        _context: &AlarmActionContext,
    ) -> Result<(), AlarmActionDenied> {
        if self.allow {
            Ok(())
        } else {
            Err(AlarmActionDenied::new("policy denied"))
        }
    }

    fn allow_security_critical_suppression(
        &self,
        _alarm: &Alarm,
        _context: &AlarmActionContext,
    ) -> bool {
        self.allow_security_critical
    }
}

#[derive(Default)]
struct CapturingAuditSink {
    events: Vec<AlarmAuditEvent>,
    fail: bool,
}

impl AlarmAuditSink for CapturingAuditSink {
    fn record_alarm_action(&mut self, event: AlarmAuditEvent) -> Result<(), String> {
        if self.fail {
            return Err("audit sink unavailable".to_string());
        }
        self.events.push(event);
        Ok(())
    }
}

fn alarm_action_context(alarm_id: &AlarmId) -> AlarmActionContext {
    AlarmActionContext::new(
        "admin-a",
        "maintenance window",
        AlarmActionScope::Alarm {
            alarm_id: alarm_id.clone(),
        },
    )
    .with_tenant("tenant-a")
    .with_correlation_id("change-123")
}

fn make_alarm_with_state(alarm_id: &str, state: AlarmState) -> Alarm {
    let now = OffsetDateTime::now_utc();
    Alarm {
        alarm_id: AlarmId::new(alarm_id),
        alarm_type: AlarmType::new("link.down"),
        severity: match state {
            AlarmState::Cleared => Severity::Cleared,
            _ => Severity::Major,
        },
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: alarm_id.to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Peer unreachable"),
        details: AlarmDetails::empty(),
        state,
        raised_at: now,
        updated_at: now,
        cleared_at: (!state.is_active()).then_some(now),
        correlation_id: None,
    }
}

#[test]
fn shared_alarm_manager_clones_share_raise_clear_and_history() {
    let writer = SharedAlarmManager::default();
    let reader = writer.clone();
    let clearer = writer.clone();
    let alarm_type = AlarmType::new("runtime.task.failure");
    let object = AffectedObject::NfInstance {
        kind: "amf".to_string(),
        instance: "amf-1".to_string(),
    };

    let raised = writer.raise(
        alarm_type.clone(),
        Severity::Critical,
        ProbableCause::Other("opc-runtime.task-failure".to_string()),
        object.clone(),
        None,
        None,
        None,
        RedactedText::new("Runtime task failed"),
        AlarmDetails::empty(),
    );
    assert!(matches!(raised, AlarmOpResult::Raised { .. }));
    assert_eq!(reader.active_count(), 1);

    let updated = reader.raise(
        alarm_type.clone(),
        Severity::Critical,
        ProbableCause::Other("opc-runtime.task-failure".to_string()),
        object.clone(),
        None,
        None,
        None,
        RedactedText::new("Runtime task failed again"),
        AlarmDetails::empty(),
    );
    assert!(matches!(updated, AlarmOpResult::Updated { .. }));
    assert_eq!(writer.active_count(), 1);

    let cleared = clearer.clear(
        &alarm_type,
        ProbableCause::Other("opc-runtime.task-failure".to_string()),
        &object,
        None,
        None,
        None,
    );
    assert!(matches!(cleared, AlarmOpResult::Cleared { .. }));
    assert_eq!(reader.active_count(), 0);
    assert_eq!(
        writer
            .all_alarms()
            .iter()
            .map(|alarm| alarm.state)
            .collect::<Vec<_>>(),
        vec![AlarmState::Raised, AlarmState::Updated, AlarmState::Cleared]
    );
}

// ── Dedup key stability ──────────────────────────────────────────────────

#[test]
fn dedup_key_stable_for_same_inputs() {
    let obj = AffectedObject::NfInstance {
        kind: "amf".to_string(),
        instance: "amf-1".to_string(),
    };

    let key1 = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &obj,
        Some("tenant-a"),
        Some("slice-1"),
        None,
    );

    let key2 = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &obj,
        Some("tenant-a"),
        Some("slice-1"),
        None,
    );

    assert_eq!(key1, key2, "dedup key must be stable across calls");
}

#[test]
fn dedup_key_differs_with_different_tenant() {
    let obj = AffectedObject::NfInstance {
        kind: "amf".to_string(),
        instance: "amf-1".to_string(),
    };

    let key1 = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &obj,
        Some("tenant-a"),
        None,
        None,
    );

    let key2 = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &obj,
        Some("tenant-b"),
        None,
        None,
    );

    assert_ne!(key1, key2, "dedup key must differ by tenant");
}

#[test]
fn dedup_key_differs_with_different_slice() {
    let obj = AffectedObject::NfInstance {
        kind: "smf".to_string(),
        instance: "smf-1".to_string(),
    };

    let key1 = DedupKey::compute(
        &AlarmType::new("sbi.failure"),
        &ProbableCause::BackendTimeout,
        &obj,
        Some("tenant-a"),
        Some("eMBB"),
        None,
    );

    let key2 = DedupKey::compute(
        &AlarmType::new("sbi.failure"),
        &ProbableCause::BackendTimeout,
        &obj,
        Some("tenant-a"),
        Some("URLLC"),
        None,
    );

    assert_ne!(key1, key2, "dedup key must differ by slice");
}

#[test]
fn dedup_key_no_collision_with_pipe_in_values() {
    // Regression test: values containing '|' must not collide with
    // length-prefixed encoding since we now use length-prefixing.
    let obj = AffectedObject::NfInstance {
        kind: "nf".to_string(),
        instance: "inst".to_string(),
    };

    // AlarmType "a|b" must not collide with AlarmType "a" + probcause with "|b"
    let key1 = DedupKey::compute(
        &AlarmType::new("a|b"),
        &ProbableCause::PeerUnreachable,
        &obj,
        Some("tenant"),
        None,
        None,
    );

    let key2 = DedupKey::compute(
        &AlarmType::new("a"),
        &ProbableCause::Other("b|peer-unreachable".to_string()),
        &obj,
        Some("tenant"),
        None,
        None,
    );

    assert_ne!(key1, key2, "pipe-containing values must not collide");
}

#[test]
fn dedup_key_none_vs_empty_string_differ() {
    let nf_object = AffectedObject::NfInstance {
        kind: "amf".to_string(),
        instance: "amf-1".to_string(),
    };

    let none_tenant = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &nf_object,
        None,
        None,
        None,
    );

    let empty_tenant = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &nf_object,
        Some(""),
        None,
        None,
    );

    assert_ne!(
        none_tenant, empty_tenant,
        "None tenant and Some(\"\") tenant must not alias"
    );

    let none_shard = DedupKey::compute(
        &AlarmType::new("session-store.error"),
        &ProbableCause::SessionStoreUnavailable,
        &AffectedObject::SessionStore {
            nf: "smf-1".to_string(),
            shard: None,
        },
        None,
        None,
        None,
    );

    let empty_shard = DedupKey::compute(
        &AlarmType::new("session-store.error"),
        &ProbableCause::SessionStoreUnavailable,
        &AffectedObject::SessionStore {
            nf: "smf-1".to_string(),
            shard: Some(String::new()),
        },
        None,
        None,
        None,
    );

    assert_ne!(
        none_shard, empty_shard,
        "None shard and Some(\"\") shard must not alias"
    );
}

#[test]
fn affected_object_fields_with_colon_do_not_collide() {
    // Regression test: `NfInstance { kind: "a:b", instance: "c" }` and
    // `NfInstance { kind: "a", instance: "b:c" }` both stringify to "nf:a:b:c"
    // but must produce different dedup keys since we encode structurally.
    let key1 = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "a:b".to_string(),
            instance: "c".to_string(),
        },
        None,
        None,
        None,
    );

    let key2 = DedupKey::compute(
        &AlarmType::new("link.down"),
        &ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "a".to_string(),
            instance: "b:c".to_string(),
        },
        None,
        None,
        None,
    );

    assert_ne!(
        key1, key2,
        "colon-split fields must not collide in dedup key"
    );
}

// ── Cross-region alarm isolation (RFC 010 §9) ──────────────────────────────────

#[test]
fn same_fault_different_regions_do_not_merge_or_clear_each_other() {
    let mut mgr = make_manager();

    // Raise alarm in region-east
    let east = RegionId::new("region-east");
    let r1 = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        Some(east.clone()),
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );
    let AlarmOpResult::Raised { alarm: alarm_east } = r1 else {
        panic!("expected Raised");
    };

    // Raise same fault in region-west — must create a SEPARATE alarm (not update east)
    let west = RegionId::new("region-west");
    let r2 = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        Some(west.clone()),
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );
    let AlarmOpResult::Raised { alarm: alarm_west } = r2 else {
        panic!("expected Raised");
    };

    // Both alarms must be active with different IDs
    assert_ne!(alarm_east.alarm_id, alarm_west.alarm_id);
    assert_eq!(mgr.active_count(), 2, "both region alarms must be active");

    // Clearing east's fault must NOT clear west's fault
    mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        Some(east.as_str()),
    );

    // West alarm must still be active
    assert_eq!(
        mgr.active_count(),
        1,
        "west alarm must remain active after clearing east"
    );
}

// ── Severity transition ─────────────────────────────────────────────────

#[test]
fn severity_transition_raises_alarm() {
    let mut mgr = make_manager();

    let result = mgr.raise(
        AlarmType::new("link.degraded"),
        Severity::Warning,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );

    match result {
        AlarmOpResult::Raised { alarm } => {
            assert_eq!(alarm.severity, Severity::Warning);
            assert_eq!(alarm.state, AlarmState::Raised);
        }
        other => panic!("expected Raised, got {other:?}"),
    }
}

#[test]
fn severity_transition_updates_existing_alarm() {
    let mut mgr = make_manager();

    // Raise initial alarm
    mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );

    // Escalate to Critical
    let result = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable — CRITICAL"),
        AlarmDetails::empty(),
    );

    match result {
        AlarmOpResult::Updated { alarm } => {
            assert_eq!(alarm.severity, Severity::Critical);
            assert_eq!(alarm.state, AlarmState::Updated);
        }
        other => panic!("expected Updated, got {other:?}"),
    }

    assert_eq!(mgr.active_count(), 1, "same dedup key must not duplicate");
}

// ── Append-only history and scoped queries ──────────────────────────────

#[test]
fn history_preserves_raise_update_clear_lifecycle_and_scope_queries() {
    let mut mgr = make_manager();

    let alarm_type = AlarmType::new("link.down");
    let affected_object = AffectedObject::NfInstance {
        kind: "upf".to_string(),
        instance: "upf-1".to_string(),
    };
    let tenant = Some("tenant-a".to_string());
    let slice = Some("slice-1".to_string());

    let alarm_id = match mgr.raise(
        alarm_type.clone(),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        affected_object.clone(),
        tenant.clone(),
        slice.clone(),
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let updated = mgr.raise(
        alarm_type.clone(),
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        affected_object.clone(),
        tenant.clone(),
        slice.clone(),
        None,
        RedactedText::new("Peer unreachable — critical"),
        AlarmDetails::empty(),
    );
    assert!(matches!(updated, AlarmOpResult::Updated { .. }));

    let cleared = mgr.clear(
        &alarm_type,
        ProbableCause::PeerUnreachable,
        &affected_object,
        tenant.as_deref(),
        slice.as_deref(),
        None,
    );
    assert!(matches!(cleared, AlarmOpResult::Cleared { .. }));

    let history = mgr.all_alarms();
    assert_eq!(history.len(), 3, "raise/update/clear must append history");
    assert_eq!(
        mgr.active_count(),
        0,
        "cleared alarm must not remain active"
    );
    assert!(history.iter().all(|alarm| alarm.alarm_id == alarm_id));
    assert_eq!(
        history
            .iter()
            .map(|alarm| alarm.state)
            .collect::<Vec<AlarmState>>(),
        vec![AlarmState::Raised, AlarmState::Updated, AlarmState::Cleared,]
    );
    assert_eq!(
        history
            .iter()
            .map(|alarm| alarm.severity)
            .collect::<Vec<Severity>>(),
        vec![Severity::Major, Severity::Critical, Severity::Cleared]
    );

    assert_eq!(
        mgr.alarm_history_by_scope(Some("tenant-a"), Some("slice-1"))
            .len(),
        3
    );
    assert_eq!(mgr.alarm_history_by_scope(Some("tenant-a"), None).len(), 3);
    assert_eq!(mgr.alarm_history_by_scope(None, Some("slice-1")).len(), 3);
    assert_eq!(
        mgr.alarm_history_by_scope(Some("tenant-b"), Some("slice-1"))
            .len(),
        0
    );
    assert_eq!(
        mgr.alarm_history_by_scope(Some("tenant-a"), Some("slice-2"))
            .len(),
        0
    );
}

#[test]
fn duplicate_storm_keeps_history_bounded_and_preserves_lifecycle_evidence() {
    let mut mgr = AlarmManager::new(InMemoryStore::new_with_history_limit(3));

    let alarm_type = AlarmType::new("link.down");
    let affected_object = AffectedObject::NfInstance {
        kind: "upf".to_string(),
        instance: "upf-1".to_string(),
    };

    let first = mgr.raise(
        alarm_type.clone(),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        affected_object.clone(),
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );
    assert!(matches!(first, AlarmOpResult::Raised { .. }));

    for _ in 0..10_000 {
        let result = mgr.raise(
            alarm_type.clone(),
            Severity::Major,
            ProbableCause::PeerUnreachable,
            affected_object.clone(),
            None,
            None,
            None,
            RedactedText::new("Peer unreachable"),
            AlarmDetails::empty(),
        );
        assert!(matches!(result, AlarmOpResult::Updated { .. }));
    }

    let clear = mgr.clear(
        &alarm_type,
        ProbableCause::PeerUnreachable,
        &affected_object,
        None,
        None,
        None,
    );
    assert!(matches!(clear, AlarmOpResult::Cleared { .. }));

    let history = mgr.all_alarms();
    assert_eq!(
        history.len(),
        3,
        "duplicate storms must remain bounded while preserving lifecycle states"
    );
    assert_eq!(
        history
            .iter()
            .map(|alarm| alarm.state)
            .collect::<Vec<AlarmState>>(),
        vec![AlarmState::Raised, AlarmState::Updated, AlarmState::Cleared]
    );
}

#[test]
fn distinct_alarm_flood_is_capped_with_overflow_signal() {
    let mut mgr = AlarmManager::new(InMemoryStore::new_with_limits(16, 3));
    let alarm_type = AlarmType::new("link.down");

    for index in 0..3 {
        let result = mgr.raise(
            alarm_type.clone(),
            Severity::Major,
            ProbableCause::PeerUnreachable,
            AffectedObject::NfInstance {
                kind: "upf".to_string(),
                instance: format!("upf-{index}"),
            },
            None,
            None,
            None,
            RedactedText::new("Peer unreachable"),
            AlarmDetails::empty(),
        );
        assert!(matches!(result, AlarmOpResult::Raised { .. }));
    }

    let overflow = mgr.raise(
        alarm_type,
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-overflow".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );

    match overflow {
        AlarmOpResult::ActiveLimitExceeded {
            max_active_alarms,
            ..
        } => assert_eq!(max_active_alarms, 3),
        other => panic!("expected active-limit overflow signal, got {other:?}"),
    }
    assert_eq!(mgr.active_count(), 3);
    assert_eq!(mgr.store.by_id.len(), 3);
    assert_eq!(mgr.store.by_dedup_key.len(), 3);
}

#[test]
fn stale_active_alarms_expire_out_of_current_indexes() {
    let mut mgr = AlarmManager::new(InMemoryStore::new_with_limits(16, 8));
    let alarm_type = AlarmType::new("link.down");
    let affected_object = AffectedObject::NfInstance {
        kind: "upf".to_string(),
        instance: "upf-1".to_string(),
    };

    let raised = mgr.raise(
        alarm_type,
        Severity::Major,
        ProbableCause::PeerUnreachable,
        affected_object,
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );
    assert!(matches!(raised, AlarmOpResult::Raised { .. }));
    assert_eq!(mgr.active_count(), 1);

    let expired = mgr.expire_before(OffsetDateTime::now_utc() + time::Duration::seconds(1));

    assert_eq!(expired, 1);
    assert_eq!(mgr.active_count(), 0);
    assert_eq!(mgr.store.by_id.len(), 0);
    assert_eq!(mgr.store.by_dedup_key.len(), 0);
    assert!(
        mgr.all_alarms()
            .iter()
            .any(|alarm| alarm.state == AlarmState::Expired),
        "expiry sweep must retain terminal Expired lifecycle evidence"
    );
}

#[test]
fn clear_re_raise_cycles_do_not_grow_current_state_indexes() {
    let mut mgr = AlarmManager::new(InMemoryStore::new_with_history_limit(16));

    let alarm_type = AlarmType::new("link.down");
    let affected_object = AffectedObject::NfInstance {
        kind: "upf".to_string(),
        instance: "upf-1".to_string(),
    };

    for cycle in 0..128 {
        let raise = mgr.raise(
            alarm_type.clone(),
            Severity::Major,
            ProbableCause::PeerUnreachable,
            affected_object.clone(),
            None,
            None,
            None,
            RedactedText::new(format!("Peer unreachable {cycle}")),
            AlarmDetails::empty(),
        );
        assert!(matches!(raise, AlarmOpResult::Raised { .. }));
        assert_eq!(
            mgr.store.by_id.len(),
            1,
            "only one active alarm should remain indexed"
        );
        assert_eq!(
            mgr.store.by_dedup_key.len(),
            1,
            "dedup index should track only the active alarm"
        );
        assert_eq!(
            mgr.active_count(),
            mgr.store.by_id.len(),
            "active alarm count should match the active alarm index"
        );

        let clear = mgr.clear(
            &alarm_type,
            ProbableCause::PeerUnreachable,
            &affected_object,
            None,
            None,
            None,
        );
        assert!(matches!(clear, AlarmOpResult::Cleared { .. }));
        assert_eq!(
            mgr.store.by_id.len(),
            0,
            "terminal alarms must be removed from current-state index"
        );
        assert_eq!(
            mgr.store.by_dedup_key.len(),
            0,
            "terminal alarms must be removed from dedup index"
        );
        assert_eq!(
            mgr.active_count(),
            mgr.store.by_id.len(),
            "active alarm count should drop with the current-state index"
        );
    }
}

#[test]
fn direct_terminal_insert_does_not_pollute_active_indexes() {
    let mut store = InMemoryStore::new();

    for (index, state) in [AlarmState::Cleared, AlarmState::Expired]
        .into_iter()
        .enumerate()
    {
        let alarm = make_alarm_with_state(&format!("terminal-{index}"), state);
        let dedup_key = alarm.dedup_key();

        AlarmStore::insert(&mut store, alarm.clone());

        assert_eq!(
            store.active_alarms().len(),
            0,
            "terminal alarms must not appear in active listings"
        );
        assert_eq!(
            store.active_count(),
            0,
            "terminal alarms must not contribute to active_count"
        );
        assert!(
            store.get_by_id(&alarm.alarm_id).is_none(),
            "terminal alarms must not remain in current-state id index"
        );
        assert!(
            store.get_by_dedup_key(&dedup_key).is_none(),
            "terminal alarms must not remain in current-state dedup index"
        );
    }

    let history = store.all();
    assert_eq!(
        history.len(),
        2,
        "terminal inserts must still retain history"
    );
    assert_eq!(history[0].state, AlarmState::Cleared);
    assert_eq!(history[1].state, AlarmState::Expired);
}

// ── Clear→re-raise lifecycle (RFC 013 §8) ────────────────────────────────

#[test]
fn clear_re_raise_creates_new_alarm_with_new_id() {
    let mut mgr = make_manager();

    // Raise initial alarm
    let raised_result = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );

    let AlarmOpResult::Raised { alarm: alarm1 } = raised_result else {
        panic!("expected Raised");
    };
    let original_id = alarm1.alarm_id.clone();

    // Clear the alarm
    let clear_result = mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );

    assert!(matches!(clear_result, AlarmOpResult::Cleared { .. }));
    assert_eq!(mgr.active_count(), 0);

    // Re-raise the same fault
    let re_raise_result = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable again"),
        AlarmDetails::empty(),
    );

    match re_raise_result {
        AlarmOpResult::Raised { alarm } => {
            // Must be a new alarm instance, not an update of the cleared one
            assert_ne!(
                alarm.alarm_id, original_id,
                "re-raised alarm must have new ID"
            );
            assert_eq!(alarm.state, AlarmState::Raised);
            assert_eq!(alarm.severity, Severity::Major);
        }
        other => panic!("expected Raised after clear, got {other:?}"),
    }
}

// ── Clear inactive-state regression ────────────────────────────────────────

#[test]
fn clear_after_clear_returns_clear_without_active() {
    let mut mgr = make_manager();

    mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );

    // First clear
    let r1 = mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );
    assert!(matches!(r1, AlarmOpResult::Cleared { .. }));

    // Second clear — must return ClearWithoutActive, not re-clear
    let r2 = mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );
    match r2 {
        AlarmOpResult::ClearWithoutActive { .. } => {}
        other => panic!("expected ClearWithoutActive on second clear, got {other:?}"),
    }
}

#[test]
fn acknowledge_cleared_alarm_returns_not_found() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );

    // Attempt to acknowledge the cleared alarm
    let result = mgr.acknowledge(
        &alarm_id,
        &SuppressionAuth {
            authorized: true,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::NotFound { .. } => {}
        other => panic!("expected NotFound for cleared alarm, got {other:?}"),
    }
}

#[test]
fn suppress_cleared_alarm_returns_not_found() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );

    // Attempt to suppress the cleared alarm
    let result = mgr.suppress(
        &alarm_id,
        &SuppressionAuth {
            authorized: true,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::NotFound { .. } => {}
        other => panic!("expected NotFound for cleared alarm, got {other:?}"),
    }
}

// ── Clear without active alarm ────────────────────────────────────────────

#[test]
fn clear_without_active_alarm_returns_no_op_metric() {
    let mut mgr = make_manager();

    let result = mgr.clear(
        &AlarmType::new("nonexistent"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );

    match result {
        AlarmOpResult::ClearWithoutActive { dedup_key, cause } => {
            assert_eq!(cause, ProbableCause::PeerUnreachable);
            let _ = dedup_key.as_str();
        }
        other => panic!("expected ClearWithoutActive, got {other:?}"),
    }
}

#[test]
fn clear_clears_active_alarm() {
    let mut mgr = make_manager();

    mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    );

    let result = mgr.clear(
        &AlarmType::new("link.down"),
        ProbableCause::PeerUnreachable,
        &AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
    );

    match result {
        AlarmOpResult::Cleared { alarm_id } => {
            assert_eq!(mgr.active_count(), 0);
            let _ = alarm_id.as_str();
        }
        other => panic!("expected Cleared, got {other:?}"),
    }
}

// ── Suppression authorization placeholder ──────────────────────────────────

#[test]
fn suppress_requires_authorization() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    // Unauthorized suppress attempt
    let result = mgr.suppress(
        &alarm_id,
        &SuppressionAuth {
            authorized: false,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::Unauthorized { message } => {
            assert!(message.contains("not authorized"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn acknowledge_requires_authorization() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let result = mgr.acknowledge(
        &alarm_id,
        &SuppressionAuth {
            authorized: false,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::Unauthorized { message } => {
            assert!(message.contains("not authorized"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn policy_acknowledge_denied_records_denied_audit_event() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let auth = TestAuthorizer {
        allow: false,
        allow_security_critical: false,
    };
    let mut audit = CapturingAuditSink::default();
    let result = mgr.acknowledge_with_policy(
        &alarm_id,
        &alarm_action_context(&alarm_id),
        &auth,
        &mut audit,
    );

    assert_eq!(
        result,
        AlarmOpResult::Unauthorized {
            message: "policy denied".to_string()
        }
    );
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].action, AlarmAction::Acknowledge);
    assert_eq!(audit.events[0].outcome, AlarmAuditOutcome::Denied);
    assert_eq!(audit.events[0].principal, "admin-a");
}

#[test]
fn policy_suppress_authorized_records_audit_event() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let auth = TestAuthorizer {
        allow: true,
        allow_security_critical: false,
    };
    let mut audit = CapturingAuditSink::default();
    let result = mgr.suppress_with_policy(
        &alarm_id,
        &alarm_action_context(&alarm_id),
        &auth,
        &mut audit,
    );

    match result {
        AlarmOpResult::Suppressed { alarm } => {
            assert_eq!(alarm.state, AlarmState::Suppressed);
        }
        other => panic!("expected Suppressed, got {other:?}"),
    }
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].action, AlarmAction::Suppress);
    assert_eq!(audit.events[0].outcome, AlarmAuditOutcome::Authorized);
    assert_eq!(audit.events[0].reason, "maintenance window");
    assert_eq!(audit.events[0].tenant.as_deref(), Some("tenant-a"));
}

#[test]
fn policy_suppress_security_critical_denied_by_default() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("security.key.unavailable"),
        Severity::Critical,
        ProbableCause::KeyUnavailable,
        AffectedObject::NfInstance {
            kind: "amf".to_string(),
            instance: "amf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Key provider unavailable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let auth = TestAuthorizer {
        allow: true,
        allow_security_critical: false,
    };
    let mut audit = CapturingAuditSink::default();
    let result = mgr.suppress_with_policy(
        &alarm_id,
        &alarm_action_context(&alarm_id),
        &auth,
        &mut audit,
    );

    assert!(matches!(result, AlarmOpResult::Unauthorized { .. }));
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].outcome, AlarmAuditOutcome::Denied);
    assert_eq!(mgr.active_alarms()[0].state, AlarmState::Raised);
}

#[test]
fn policy_suppress_major_break_glass_alarm_requires_explicit_override() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("security.break-glass"),
        Severity::Major,
        ProbableCause::SecurityBreakGlass,
        AffectedObject::NfInstance {
            kind: "amf".to_string(),
            instance: "amf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Break-glass override exercised"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let auth = TestAuthorizer {
        allow: true,
        allow_security_critical: false,
    };
    let mut audit = CapturingAuditSink::default();
    let result = mgr.suppress_with_policy(
        &alarm_id,
        &alarm_action_context(&alarm_id),
        &auth,
        &mut audit,
    );

    assert!(matches!(result, AlarmOpResult::Unauthorized { .. }));
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].action, AlarmAction::Suppress);
    assert_eq!(audit.events[0].outcome, AlarmAuditOutcome::Denied);
    assert_eq!(mgr.active_alarms()[0].state, AlarmState::Raised);
}

#[test]
fn policy_suppress_security_critical_requires_explicit_override() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("security.key.unavailable"),
        Severity::Critical,
        ProbableCause::KeyUnavailable,
        AffectedObject::NfInstance {
            kind: "amf".to_string(),
            instance: "amf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Key provider unavailable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let auth = TestAuthorizer {
        allow: true,
        allow_security_critical: true,
    };
    let mut audit = CapturingAuditSink::default();
    let result = mgr.suppress_with_policy(
        &alarm_id,
        &alarm_action_context(&alarm_id),
        &auth,
        &mut audit,
    );

    assert!(matches!(result, AlarmOpResult::Suppressed { .. }));
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].outcome, AlarmAuditOutcome::Authorized);
}

#[test]
fn policy_action_fails_closed_when_audit_fails() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let auth = TestAuthorizer {
        allow: true,
        allow_security_critical: false,
    };
    let mut audit = CapturingAuditSink {
        events: Vec::new(),
        fail: true,
    };
    let result = mgr.acknowledge_with_policy(
        &alarm_id,
        &alarm_action_context(&alarm_id),
        &auth,
        &mut audit,
    );

    assert_eq!(
        result,
        AlarmOpResult::AuditFailed {
            message: "audit sink unavailable".to_string()
        }
    );
    assert_eq!(mgr.active_alarms()[0].state, AlarmState::Raised);
}

#[test]
fn suppress_succeeds_with_authorization() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let result = mgr.suppress(
        &alarm_id,
        &SuppressionAuth {
            authorized: true,
            reason: Some("maintenance window".to_string()),
        },
    );

    match result {
        AlarmOpResult::Suppressed { alarm } => {
            assert_eq!(alarm.state, AlarmState::Suppressed);
        }
        other => panic!("expected Suppressed, got {other:?}"),
    }
}

#[test]
fn repeated_raise_preserves_suppressed_state() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let suppressed = mgr.suppress(
        &alarm_id,
        &SuppressionAuth {
            authorized: true,
            reason: Some("maintenance window".to_string()),
        },
    );
    assert!(matches!(
        suppressed,
        AlarmOpResult::Suppressed {
            alarm: Alarm {
                state: AlarmState::Suppressed,
                ..
            }
        }
    ));

    let raised_again = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable still failing"),
        AlarmDetails::empty(),
    );

    match raised_again {
        AlarmOpResult::Updated { alarm } => {
            assert_eq!(alarm.alarm_id, alarm_id);
            assert_eq!(alarm.severity, Severity::Critical);
            assert_eq!(alarm.state, AlarmState::Suppressed);
        }
        other => panic!("expected Updated with preserved state, got {other:?}"),
    }
}

// ── Acknowledge method ───────────────────────────────────────────────────

#[test]
fn acknowledge_succeeds_with_authorization() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let result = mgr.acknowledge(
        &alarm_id,
        &SuppressionAuth {
            authorized: true,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::Acknowledged { alarm } => {
            assert_eq!(alarm.state, AlarmState::Acknowledged);
        }
        other => panic!("expected Acknowledged, got {other:?}"),
    }
}

#[test]
fn repeated_raise_preserves_acknowledged_state() {
    let mut mgr = make_manager();

    let alarm_id = match mgr.raise(
        AlarmType::new("link.down"),
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable"),
        AlarmDetails::empty(),
    ) {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        other => panic!("expected Raised, got {other:?}"),
    };

    let acknowledged = mgr.acknowledge(
        &alarm_id,
        &SuppressionAuth {
            authorized: true,
            reason: None,
        },
    );
    assert!(matches!(
        acknowledged,
        AlarmOpResult::Acknowledged {
            alarm: Alarm {
                state: AlarmState::Acknowledged,
                ..
            }
        }
    ));

    let raised_again = mgr.raise(
        AlarmType::new("link.down"),
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        None,
        None,
        None,
        RedactedText::new("Peer unreachable still failing"),
        AlarmDetails::empty(),
    );

    match raised_again {
        AlarmOpResult::Updated { alarm } => {
            assert_eq!(alarm.alarm_id, alarm_id);
            assert_eq!(alarm.severity, Severity::Critical);
            assert_eq!(alarm.state, AlarmState::Acknowledged);
        }
        other => panic!("expected Updated with preserved state, got {other:?}"),
    }
}

#[test]
fn acknowledge_not_found_returns_not_found() {
    let mut mgr = make_manager();

    let result = mgr.acknowledge(
        &AlarmId::new("nonexistent-id"),
        &SuppressionAuth {
            authorized: true,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::NotFound { alarm_id } => {
            assert_eq!(alarm_id.as_str(), "nonexistent-id");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn suppress_not_found_returns_not_found() {
    let mut mgr = make_manager();

    let result = mgr.suppress(
        &AlarmId::new("nonexistent-id"),
        &SuppressionAuth {
            authorized: true,
            reason: None,
        },
    );

    match result {
        AlarmOpResult::NotFound { alarm_id } => {
            assert_eq!(alarm_id.as_str(), "nonexistent-id");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ── Redacted alarm text ───────────────────────────────────────────────────

#[test]
fn redacted_alarm_text_stored_as_provided() {
    let mut mgr = make_manager();

    // Pass text that is already in a redacted form (no raw identifiers).
    // Per RFC 010, callers are responsible for pre-redaction.
    let redacted = RedactedText::new("Backend timeout for session [REDACTED]");

    let result = mgr.raise(
        AlarmType::new("session.error"),
        Severity::Warning,
        ProbableCause::BackendTimeout,
        AffectedObject::NfInstance {
            kind: "smf".to_string(),
            instance: "smf-1".to_string(),
        },
        None,
        None,
        None,
        redacted,
        AlarmDetails::empty(),
    );

    match result {
        AlarmOpResult::Raised { alarm } => {
            // The text is stored as provided (pre-redacted by caller).
            // Verify the redacted marker is present and no raw digits remain.
            assert!(alarm.text.as_str().contains("[REDACTED]"));
            assert!(
                !alarm.text.as_str().contains("12345"),
                "raw identifier must not appear in stored alarm text"
            );
        }
        other => panic!("expected Raised, got {other:?}"),
    }
}

// ── Readiness impact policy ────────────────────────────────────────────────

#[test]
fn readiness_impact_critical_forces_not_ready() {
    let alarm = Alarm {
        alarm_id: AlarmId::new("test-1"),
        alarm_type: AlarmType::new("link.down"),
        severity: Severity::Critical,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Link down"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    };

    assert_eq!(
        alarm.readiness_impact(),
        crate::model::ReadinessImpact::ForceNotReady
    );
}

#[test]
fn readiness_impact_major_sets_degraded_only() {
    let alarm = Alarm {
        alarm_id: AlarmId::new("test-2"),
        alarm_type: AlarmType::new("link.degraded"),
        severity: Severity::Major,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Link degraded"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    };

    assert_eq!(
        alarm.readiness_impact(),
        crate::model::ReadinessImpact::DegradedOnly
    );
}

#[test]
fn readiness_impact_minor_has_no_impact() {
    let alarm = Alarm {
        alarm_id: AlarmId::new("test-3"),
        alarm_type: AlarmType::new("link.degraded"),
        severity: Severity::Minor,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Minor issue"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    };

    assert_eq!(
        alarm.readiness_impact(),
        crate::model::ReadinessImpact::NoImpact
    );
}

#[test]
fn readiness_impact_warning_has_no_impact() {
    let alarm = Alarm {
        alarm_id: AlarmId::new("test-4"),
        alarm_type: AlarmType::new("threshold.approaching"),
        severity: Severity::Warning,
        probable_cause: ProbableCause::BackendTimeout,
        affected_object: AffectedObject::NfInstance {
            kind: "smf".to_string(),
            instance: "smf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Approaching threshold"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    };

    assert_eq!(
        alarm.readiness_impact(),
        crate::model::ReadinessImpact::NoImpact
    );
}

#[test]
fn expired_major_alarm_has_no_readiness_impact() {
    // Expired alarms must not drive readiness regardless of severity.
    let alarm = Alarm {
        alarm_id: AlarmId::new("test-expired"),
        alarm_type: AlarmType::new("link.down"),
        severity: Severity::Major,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Link down"),
        details: AlarmDetails::empty(),
        state: AlarmState::Expired,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: Some(OffsetDateTime::now_utc()),
        correlation_id: None,
    };

    assert_eq!(
        alarm.readiness_impact(),
        crate::model::ReadinessImpact::NoImpact,
        "expired alarms must not drive readiness"
    );
}

#[test]
fn cleared_critical_alarm_has_no_readiness_impact() {
    // Cleared alarms must not drive readiness regardless of severity.
    let alarm = Alarm {
        alarm_id: AlarmId::new("test-cleared"),
        alarm_type: AlarmType::new("link.down"),
        severity: Severity::Critical,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("Link down"),
        details: AlarmDetails::empty(),
        state: AlarmState::Cleared,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: Some(OffsetDateTime::now_utc()),
        correlation_id: None,
    };

    assert_eq!(
        alarm.readiness_impact(),
        crate::model::ReadinessImpact::NoImpact,
        "cleared alarms must not drive readiness"
    );
}

// ── ProbableCause serde round-trip ───────────────────────────────────────

#[test]
fn probable_cause_round_trips_through_json() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Wrapper {
        cause: crate::model::ProbableCause,
    }

    let cases = [
        (
            crate::model::ProbableCause::PeerUnreachable,
            "peer-unreachable",
        ),
        (
            crate::model::ProbableCause::BackendTimeout,
            "backend-timeout",
        ),
        (
            crate::model::ProbableCause::CertificateExpired,
            "certificate-expired",
        ),
        (
            crate::model::ProbableCause::Other("upf.gtp.PortExhaustion".to_string()),
            "other:upf.gtp.PortExhaustion",
        ),
    ];

    for (cause, expected_str) in cases {
        let w = Wrapper {
            cause: cause.clone(),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(
            json.contains(expected_str),
            "JSON should contain '{expected_str}', got: {json}"
        );
        let round_tripped: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(
            round_tripped.cause, cause,
            "round-trip failed for {cause:?}"
        );
    }
}

#[test]
fn probable_cause_other_requires_namespace_suffix() {
    let err = "other:"
        .parse::<crate::model::ProbableCause>()
        .expect_err("blank custom probable cause must be rejected");
    assert_eq!(err.as_str(), "other:");

    let err = "other:foo"
        .parse::<crate::model::ProbableCause>()
        .expect_err("unnamespaced custom probable cause must be rejected");
    assert_eq!(err.as_str(), "other:foo");

    let normalized = "other: upf.gtp.PortExhaustion "
        .parse::<crate::model::ProbableCause>()
        .expect("whitespace around a namespaced probable cause should normalize");
    assert_eq!(
        normalized,
        crate::model::ProbableCause::Other("upf.gtp.PortExhaustion".to_string())
    );

    for invalid in [
        "other:upf .gtp.PortExhaustion",
        "other:upf. gtp.PortExhaustion",
        "other:upf.gtp. PortExhaustion",
        "other:upf.gtp.Port Exhaustion",
    ] {
        let err = invalid
            .parse::<crate::model::ProbableCause>()
            .expect_err("embedded whitespace must be rejected");
        assert_eq!(err.as_str(), invalid);

        let json = format!("\"{invalid}\"");
        let serde_err = serde_json::from_str::<crate::model::ProbableCause>(&json)
            .expect_err("serde must reject embedded whitespace in custom probable causes");
        assert!(
            serde_err.to_string().contains(invalid),
            "unexpected error: {serde_err}"
        );
    }

    let serde_err = serde_json::from_str::<crate::model::ProbableCause>("\"other:\"")
        .expect_err("serde must reject blank custom probable cause");
    assert!(
        serde_err.to_string().contains("other:"),
        "unexpected error: {serde_err}"
    );

    let serde_err = serde_json::from_str::<crate::model::ProbableCause>("\"other:foo\"")
        .expect_err("serde must reject unnamespaced custom probable cause");
    assert!(
        serde_err.to_string().contains("other:foo"),
        "unexpected error: {serde_err}"
    );
}
