use opc_alarm::prelude::*;
use opc_alarm_testkit::*;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

fn make_alarm(id: &str, severity: Severity, cause: ProbableCause, state: AlarmState) -> Alarm {
    Alarm {
        alarm_id: AlarmId::new(id),
        alarm_type: AlarmType::new("test-type"),
        severity,
        probable_cause: cause,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: Some("tenant-1".to_string()),
        slice: None,
        region: None,
        text: RedactedText::new("Alarm cleared or raised correctly"),
        details: AlarmDetails::empty(),
        state,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    }
}

#[test]
fn test_alarm_asserter_success() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    let alarms = vec![alarm.clone()];

    let asserter = AlarmAsserter::new(&alarms);
    asserter
        .has_severity(Severity::Critical)
        .has_cause(ProbableCause::PeerUnreachable)
        .has_tenant(Some("tenant-1"))
        .has_state(AlarmState::Raised);
}

#[test]
#[should_panic(expected = "Expected alarm with severity 'critical'")]
fn test_alarm_asserter_misclassified_severity() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Major,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    let alarms = vec![alarm];

    AlarmAsserter::new(&alarms).has_severity(Severity::Critical);
}

#[test]
#[should_panic(expected = "Expected alarm with probable cause 'LeaseLost'")]
fn test_alarm_asserter_misclassified_cause() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    let alarms = vec![alarm];

    AlarmAsserter::new(&alarms).has_cause(ProbableCause::LeaseLost);
}

#[test]
#[should_panic(expected = "Expected no alarms with severity 'critical'")]
fn test_alarm_asserter_not_raised_fails() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    let alarms = vec![alarm];

    AlarmAsserter::new(&alarms)
        .assert_not_raised(Severity::Critical, ProbableCause::PeerUnreachable);
}

#[test]
#[should_panic(expected = "Expected alarm 'alarm-1' to be cleared")]
fn test_alarm_asserter_uncleared_fails() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    let alarms = vec![alarm];

    AlarmAsserter::new(&alarms).assert_cleared(&AlarmId::new("alarm-1"));
}

#[test]
fn test_alarm_asserter_cleared_success() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Cleared,
    );
    let alarms = vec![alarm];

    AlarmAsserter::new(&alarms).assert_cleared(&AlarmId::new("alarm-1"));
}

#[test]
fn test_alarm_asserter_deduplicated_success() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Updated,
    );
    alarm.updated_at = alarm.raised_at + Duration::from_secs(1);
    let alarms = vec![alarm.clone()];

    AlarmAsserter::new(&alarms).assert_deduplicated(&alarm.dedup_key());
}

#[tokio::test]
async fn test_eventually_helpers() {
    let alarms = Arc::new(std::sync::Mutex::new(Vec::new()));

    let fetch_alarms = {
        let alarms = Arc::clone(&alarms);
        move || {
            let guard = alarms.lock().unwrap();
            std::future::ready(guard.clone())
        }
    };

    // Spawn task to raise alarm after delay
    let alarms_clone = Arc::clone(&alarms);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let alarm = make_alarm(
            "alarm-1",
            Severity::Major,
            ProbableCause::PeerUnreachable,
            AlarmState::Raised,
        );
        alarms_clone.lock().unwrap().push(alarm);
    });

    assert_eventually_raised(
        fetch_alarms,
        Severity::Major,
        ProbableCause::PeerUnreachable,
        Duration::from_millis(200),
    )
    .await;
}

#[test]
fn test_redaction_checks_clean() {
    let alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    assert_redacted(&alarm);
}

#[test]
#[should_panic(expected = "contains raw subscriber identifier (8+ naked digits)")]
fn test_redaction_checks_naked_imsi() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    alarm.text = RedactedText::new("Subscriber 208950000000001 connected");
    assert_redacted(&alarm);
}

#[test]
#[should_panic(expected = "contains unredacted subscriber identifier prefix 'imsi'")]
fn test_redaction_checks_imsi_prefix() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    alarm.text = RedactedText::new("Failed for imsi-123456");
    assert_redacted(&alarm);
}

#[test]
#[should_panic(expected = "contains a JWT-like string")]
fn test_redaction_checks_jwt() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    alarm.text = RedactedText::new("Token is abcde.fghij12345.klmno");
    assert_redacted(&alarm);
}

#[test]
#[should_panic(expected = "contains raw SUCI identifier")]
fn test_redaction_checks_suci_prefix() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    alarm.text = RedactedText::new("Failed for suci-0-001-01-0000-0-0-1-2-3-4-5");
    assert_redacted(&alarm);
}

#[test]
fn test_redaction_checks_redacted_suci_prefix() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    alarm.text = RedactedText::new("Failed for suci-[redacted]");
    assert_redacted(&alarm);
}

#[test]
#[should_panic(expected = "contains an IPv4 address")]
fn test_redaction_checks_ipv4_address() {
    let mut alarm = make_alarm(
        "alarm-1",
        Severity::Critical,
        ProbableCause::PeerUnreachable,
        AlarmState::Raised,
    );
    alarm.text = RedactedText::new("Peer reachable at 10.42.0.19");
    assert_redacted(&alarm);
}
