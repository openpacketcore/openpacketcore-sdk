//! Deterministic testing and assertions testkit for OpenPacketCore alarms (RFC 013).
//!
//! Provides fluent assertion builders and test fixtures for alarm validation.

use opc_alarm::prelude::*;
use std::time::Duration;

/// Fluent test assertion builder for collections of `Alarm` records.
pub struct AlarmAsserter<'a> {
    alarms: &'a [Alarm],
}

impl<'a> AlarmAsserter<'a> {
    /// Creates a new asserter for a slice of alarms.
    pub fn new(alarms: &'a [Alarm]) -> Self {
        Self { alarms }
    }

    /// Asserts that at least one alarm matches the given severity.
    pub fn has_severity(self, severity: Severity) -> Self {
        assert!(
            self.alarms.iter().any(|a| a.severity == severity),
            "Expected alarm with severity '{severity}', but found none in: {:?}",
            self.alarms
        );
        self
    }

    /// Asserts that at least one alarm matches the given probable cause.
    pub fn has_cause(self, cause: ProbableCause) -> Self {
        assert!(
            self.alarms.iter().any(|a| a.probable_cause == cause),
            "Expected alarm with probable cause '{cause:?}', but found none in: {:?}",
            self.alarms
        );
        self
    }

    /// Asserts that at least one alarm matches the given resource (affected object).
    pub fn has_resource(self, resource: &AffectedObject) -> Self {
        assert!(
            self.alarms.iter().any(|a| &a.affected_object == resource),
            "Expected alarm affecting resource '{resource:?}', but found none in: {:?}",
            self.alarms
        );
        self
    }

    /// Asserts that at least one alarm matches the given tenant.
    pub fn has_tenant(self, tenant: Option<&str>) -> Self {
        assert!(
            self.alarms.iter().any(|a| a.tenant.as_deref() == tenant),
            "Expected alarm for tenant '{tenant:?}', but found none in: {:?}",
            self.alarms
        );
        self
    }

    /// Asserts that at least one alarm matches the given lifecycle state.
    pub fn has_state(self, state: AlarmState) -> Self {
        assert!(
            self.alarms.iter().any(|a| a.state == state),
            "Expected alarm in lifecycle state '{state:?}', but found none in: {:?}",
            self.alarms
        );
        self
    }

    /// Asserts that no alarms in the collection match the given severity and cause.
    pub fn assert_not_raised(self, severity: Severity, cause: ProbableCause) {
        let matches: Vec<_> = self
            .alarms
            .iter()
            .filter(|a| a.severity == severity && a.probable_cause == cause)
            .collect();
        assert!(
            matches.is_empty(),
            "Expected no alarms with severity '{severity}' and cause '{cause:?}', but found: {matches:?}"
        );
    }

    /// Asserts that a specific alarm by ID is cleared.
    pub fn assert_cleared(self, alarm_id: &AlarmId) {
        let alarm = self
            .alarms
            .iter()
            .rfind(|a| &a.alarm_id == alarm_id)
            .unwrap_or_else(|| panic!("Alarm ID '{alarm_id}' not found"));
        assert!(
            !alarm.state.is_active(),
            "Expected alarm '{alarm_id}' to be cleared, but state is '{:?}'",
            alarm.state
        );
    }

    /// Asserts that an alarm with the given dedup key was deduplicated.
    /// Deduplication means there is exactly one active alarm with that key,
    /// and its state is `AlarmState::Updated` or its updated_at timestamp is later than raised_at.
    pub fn assert_deduplicated(self, dedup_key: &DedupKey) {
        let matching: Vec<_> = self
            .alarms
            .iter()
            .filter(|a| &a.dedup_key() == dedup_key)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "Expected exactly 1 alarm for dedup key '{dedup_key:?}', but found: {matching:?}"
        );
        let alarm = matching[0];
        assert!(
            alarm.state == AlarmState::Updated || alarm.updated_at > alarm.raised_at,
            "Expected alarm for dedup key '{:?}' to be deduplicated (updated), but state is {:?}",
            dedup_key,
            alarm.state
        );
    }
}

/// Fluent test assertion builder for collections of `AlarmAuditEvent` records.
pub struct AuditAsserter<'a> {
    events: &'a [AlarmAuditEvent],
}

impl<'a> AuditAsserter<'a> {
    /// Creates a new asserter for audit events.
    pub fn new(events: &'a [AlarmAuditEvent]) -> Self {
        Self { events }
    }

    /// Asserts that at least one event has the given audit outcome.
    pub fn has_outcome(self, outcome: AlarmAuditOutcome) -> Self {
        assert!(
            self.events.iter().any(|e| e.outcome == outcome),
            "Expected audit event with outcome '{outcome:?}', but found none in: {:?}",
            self.events
        );
        self
    }

    /// Asserts that at least one event has the given action.
    pub fn has_action(self, action: AlarmAction) -> Self {
        assert!(
            self.events.iter().any(|e| e.action == action),
            "Expected audit event with action '{action:?}', but found none in: {:?}",
            self.events
        );
        self
    }
}

/// Polls `fetch` until an alarm matching the severity and cause is raised.
pub async fn assert_eventually_raised<F, Fut, S>(
    mut fetch: F,
    severity: Severity,
    cause: ProbableCause,
    timeout: Duration,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = S>,
    S: AsRef<[Alarm]>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let alarms = fetch().await;
        if alarms
            .as_ref()
            .iter()
            .any(|a| a.severity == severity && a.probable_cause == cause && a.state.is_active())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("Timed out waiting for alarm with severity '{severity}', cause '{cause:?}' to be eventually raised");
}

/// Polls `fetch` until the alarm with the given ID is cleared (inactive).
pub async fn assert_eventually_cleared<F, Fut, S>(
    mut fetch: F,
    alarm_id: AlarmId,
    timeout: Duration,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = S>,
    S: AsRef<[Alarm]>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let alarms = fetch().await;
        if let Some(a) = alarms.as_ref().iter().rfind(|a| a.alarm_id == alarm_id) {
            if !a.state.is_active() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("Timed out waiting for alarm ID '{alarm_id}' to be eventually cleared");
}

/// Polls `fetch` for a duration to verify that no matching alarm is ever raised.
pub async fn assert_eventually_not_raised<F, Fut, S>(
    mut fetch: F,
    severity: Severity,
    cause: ProbableCause,
    duration: Duration,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = S>,
    S: AsRef<[Alarm]>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < duration {
        let alarms = fetch().await;
        assert!(
            !alarms.as_ref().iter().any(|a| a.severity == severity
                && a.probable_cause == cause
                && a.state.is_active()),
            "Alarm with severity '{severity}', cause '{cause:?}' was raised, but expected none."
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Polls `fetch` until an alarm for the given dedup key shows deduplication.
pub async fn assert_eventually_deduplicated<F, Fut, S>(
    mut fetch: F,
    dedup_key: DedupKey,
    timeout: Duration,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = S>,
    S: AsRef<[Alarm]>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let alarms = fetch().await;
        let matching: Vec<_> = alarms
            .as_ref()
            .iter()
            .filter(|a| a.dedup_key() == dedup_key)
            .collect();
        if matching.len() == 1 {
            let alarm = matching[0];
            if alarm.state == AlarmState::Updated || alarm.updated_at > alarm.raised_at {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("Timed out waiting for alarm dedup key '{dedup_key:?}' to be eventually deduplicated");
}

/// Scans all alarm fields to prove that raw subscriber identifiers and sensitive values
/// (IMSI, SUCI, GPSI, MSISDN, PEI, GUTI, and JWTs) have been successfully redacted.
///
/// Panics if any unredacted sensitive values are detected.
pub fn assert_redacted(alarm: &Alarm) {
    // Check alarm.text
    assert_no_sensitive_patterns(alarm.text.as_str(), "alarm.text");

    // Check alarm.tenant
    if let Some(ref t) = alarm.tenant {
        assert_no_sensitive_patterns(t, "alarm.tenant");
    }

    // Check alarm.slice
    if let Some(ref s) = alarm.slice {
        assert_no_sensitive_patterns(s, "alarm.slice");
    }

    // Check alarm.affected_object (convert to string representation)
    let affected_str = format!("{:?}", alarm.affected_object);
    assert_no_sensitive_patterns(&affected_str, "alarm.affected_object");

    // Check alarm.details (JSON stringification)
    let details_json = serde_json::to_string(&alarm.details).unwrap_or_default();
    assert_no_sensitive_patterns(&details_json, "alarm.details");
}

fn assert_no_sensitive_patterns(val: &str, field_name: &str) {
    let lower = val.to_ascii_lowercase();

    // 1. Check for standard subscriber identifier prefixes followed by numbers or raw identifiers
    const MARKERS: [&str; 6] = ["supi", "gpsi", "imsi", "msisdn", "guti", "pei"];
    for marker in MARKERS {
        // If it starts with or contains "imsi-", check that it does not have raw digits following it
        if let Some(idx) = lower.find(marker) {
            let suffix = &lower[idx + marker.len()..];
            let normalized_suffix = suffix.trim_start_matches(['-', '_', ':', '=']);
            // If the suffix has digits, verify they are redacted/masked.
            // Standard check: if it contains a sequence of 5+ digits, it's considered unredacted.
            let digits_count = normalized_suffix
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .count();
            assert!(
                digits_count < 5,
                "Field '{field_name}' contains unredacted subscriber identifier prefix '{marker}' with raw digits: '{val}'"
            );
        }
    }

    // 2. Check for raw subscriber identifiers (naked numeric sequences of length 8 to 15 digits)
    let mut consecutive_digits = 0;
    for c in val.chars() {
        if c.is_ascii_digit() {
            consecutive_digits += 1;
            assert!(
                consecutive_digits < 8,
                "Field '{field_name}' contains raw subscriber identifier (8+ naked digits): '{val}'"
            );
        } else {
            consecutive_digits = 0;
        }
    }

    // 3. Check for JWT tokens (three base64-like blocks separated by dots)
    if contains_jwt_like(val) {
        panic!("Field '{field_name}' contains a JWT-like string: '{val}'");
    }

    // 4. Check for IP addresses that identify hosts, pods, or subscribers.
    if contains_ipv4_like(val) {
        panic!("Field '{field_name}' contains an IPv4 address: '{val}'");
    }

    // 5. Check for SUCI format (e.g., suci-0-0-...)
    if let Some(idx) = lower.find("suci-") {
        let suffix = &lower[idx + 5..];
        let raw_digit_count = suffix.chars().filter(|c| c.is_ascii_digit()).count();
        let redacted = suffix.contains("redacted")
            || suffix.contains("***")
            || suffix.contains("<redacted>")
            || suffix.contains("[redacted]");
        assert!(
            raw_digit_count < 5 || redacted,
            "Field '{field_name}' contains raw SUCI identifier: '{val}'"
        );
    }
}

fn contains_jwt_like(val: &str) -> bool {
    for word in val.split_whitespace() {
        // Strip trailing punctuation from the word
        let clean_word = word
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_');
        let parts: Vec<&str> = clean_word.split('.').collect();
        if parts.len() == 3 {
            let ok = parts.iter().all(|part| {
                part.len() >= 4
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            });
            if ok {
                return true;
            }
        }
    }
    false
}

fn contains_ipv4_like(val: &str) -> bool {
    val.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | ';' | '=' | '\'' | '"' | '[' | ']' | '(' | ')' | '{' | '}'
            )
    })
    .map(|token| {
        token
            .trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
            .trim_end_matches('.')
    })
    .any(is_ipv4_token)
}

fn is_ipv4_token(token: &str) -> bool {
    let mut parts = token.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    let Some(fourth) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    [first, second, third, fourth].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 3
            && part.chars().all(|c| c.is_ascii_digit())
            && part.parse::<u8>().is_ok()
    })
}
