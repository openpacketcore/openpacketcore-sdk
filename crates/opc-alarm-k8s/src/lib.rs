//! Kubernetes condition and event mappings for OpenPacketCore alarms (RFC 013).
//!
//! Converts OPC alarm records into Kubernetes-style status conditions and
//! events for operator integration.

use opc_alarm::{Alarm, AlarmState, ProbableCause, Severity};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

/// A Kubernetes status condition representation mapped from an active OPC alarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sCondition {
    /// Type of condition, derived from the alarm type (e.g. "ConfigApplyFailed").
    #[serde(rename = "type")]
    pub type_: String,

    /// Status of the condition, either "True", "False", or "Unknown".
    pub status: String,

    /// Last time the condition transitioned from one status to another.
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,

    /// Unique, one-word, CamelCase reason for the condition's last transition.
    pub reason: String,

    /// OPC alarm severity preserved for consumers that distinguish major/critical.
    pub severity: String,

    /// A human-readable message indicating details about the transition.
    pub message: String,
}

/// A Kubernetes event representation mapped from an OPC alarm lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sEvent {
    /// The reason for this event, e.g. "PeerUnreachable".
    pub reason: String,

    /// The human-readable description of the status change.
    pub message: String,

    /// Event type, either "Normal" or "Warning".
    #[serde(rename = "type")]
    pub type_: String,

    /// The action taken (e.g., "Raised", "Updated", "Cleared").
    pub action: String,

    /// OPC alarm severity preserved for consumers that distinguish major/critical.
    pub severity: String,

    /// The component reporting this event.
    #[serde(rename = "sourceComponent")]
    pub source_component: String,

    /// The time at which the event was first recorded.
    #[serde(rename = "firstTimestamp")]
    pub first_timestamp: String,

    /// The time at which the most recent occurrence of this event was recorded.
    #[serde(rename = "lastTimestamp")]
    pub last_timestamp: String,

    /// The number of times this event has occurred.
    pub count: i32,
}

/// Projects an active or cleared alarm to a Kubernetes condition.
pub fn alarm_to_condition(alarm: &Alarm) -> K8sCondition {
    alarm_to_condition_with_previous(alarm, None)
}

/// Projects an alarm while preserving transition time if status is unchanged.
pub fn alarm_to_condition_with_previous(
    alarm: &Alarm,
    previous: Option<&K8sCondition>,
) -> K8sCondition {
    let type_ = condition_type_for_alarm_type(alarm.alarm_type.as_str());

    // Status is True if the alarm is active, False if cleared or expired
    let status = if alarm.state.is_active() {
        "True".to_string()
    } else {
        "False".to_string()
    };

    let last_transition_time = previous
        .filter(|condition| condition.status == status)
        .map(|condition| condition.last_transition_time.clone())
        .unwrap_or_else(|| alarm.updated_at.format(&Rfc3339).unwrap_or_default());

    let reason = probable_cause_reason(&alarm.probable_cause);

    K8sCondition {
        type_,
        status,
        last_transition_time,
        reason,
        severity: alarm.severity.to_string(),
        message: alarm.text.redacted_for_export(),
    }
}

/// Projects an alarm state change to a Kubernetes event.
pub fn alarm_to_event(alarm: &Alarm) -> K8sEvent {
    alarm_to_event_with_count(alarm, 1)
}

/// Projects an alarm state change to a Kubernetes event with a deduplicated count.
pub fn alarm_to_event_with_count(alarm: &Alarm, count: i32) -> K8sEvent {
    let reason = probable_cause_reason(&alarm.probable_cause);

    let type_ = match alarm.severity {
        Severity::Cleared => "Normal",
        Severity::Indeterminate | Severity::Warning | Severity::Minor => "Normal",
        Severity::Major | Severity::Critical => "Warning",
    }
    .to_string();

    let action = match alarm.state {
        AlarmState::Raised => "Raised",
        AlarmState::Updated => "Updated",
        AlarmState::Cleared => "Cleared",
        AlarmState::Expired => "Expired",
        AlarmState::Acknowledged => "Acknowledged",
        AlarmState::Suppressed => "Suppressed",
    }
    .to_string();

    let first_ts = alarm.raised_at.format(&Rfc3339).unwrap_or_default();
    let last_ts = alarm.updated_at.format(&Rfc3339).unwrap_or_default();

    let source_component = alarm.affected_object.to_string();

    K8sEvent {
        reason,
        message: alarm.text.redacted_for_export(),
        type_,
        action,
        severity: alarm.severity.to_string(),
        source_component,
        first_timestamp: first_ts,
        last_timestamp: last_ts,
        count,
    }
}

fn probable_cause_reason(probable_cause: &ProbableCause) -> String {
    match probable_cause {
        ProbableCause::Other(value) => custom_probable_cause_reason(value),
        _ => to_camel_case(&probable_cause.to_string()),
    }
}

fn custom_probable_cause_reason(value: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;

    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            if capitalize {
                out.push(c.to_ascii_uppercase());
                capitalize = false;
            } else {
                out.push(c);
            }
        } else {
            capitalize = true;
        }
    }

    if out.is_empty() {
        "Other".to_string()
    } else {
        out
    }
}

fn condition_type_for_alarm_type(value: &str) -> String {
    let base = sanitized_camel_case(value, "Alarm");
    format!("{base}-{:08x}", stable_hash32(value.as_bytes()))
}

fn sanitized_camel_case(value: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;

    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            if capitalize {
                out.push(c.to_ascii_uppercase());
                capitalize = false;
            } else {
                out.push(c);
            }
        } else {
            capitalize = true;
        }
    }

    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

fn stable_hash32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn to_camel_case(s: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for c in s.chars() {
        if c == '-' || c == '_' || c == '.' || c == '/' {
            capitalize = true;
        } else if capitalize {
            out.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_alarm::prelude::*;
    use time::OffsetDateTime;

    fn alarm_with_cause(probable_cause: ProbableCause) -> Alarm {
        Alarm {
            alarm_id: AlarmId::new("alarm-123"),
            alarm_type: AlarmType::new("peer.disconnected"),
            severity: Severity::Critical,
            probable_cause,
            affected_object: AffectedObject::NfInstance {
                kind: "upf".to_string(),
                instance: "upf-1".to_string(),
            },
            tenant: None,
            slice: None,
            region: None,
            text: RedactedText::new("UPF link down"),
            details: AlarmDetails::empty(),
            state: AlarmState::Raised,
            raised_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            cleared_at: None,
            correlation_id: None,
        }
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("config-apply-failed"), "ConfigApplyFailed");
        assert_eq!(
            to_camel_case("config-bus.commit.failure"),
            "ConfigBusCommitFailure"
        );
    }

    #[test]
    fn test_conversion_mappings() {
        let alarm = alarm_with_cause(ProbableCause::PeerUnreachable);

        let cond = alarm_to_condition(&alarm);
        assert!(cond.type_.starts_with("PeerDisconnected-"));
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "PeerUnreachable");
        assert_eq!(cond.message, "UPF link down");

        let event = alarm_to_event(&alarm);
        assert_eq!(event.reason, "PeerUnreachable");
        assert_eq!(event.type_, "Warning");
        assert_eq!(event.action, "Raised");
        assert_eq!(event.source_component, "nf:upf:upf-1");
    }

    #[test]
    fn condition_and_event_messages_redact_sensitive_alarm_text() {
        let mut alarm = alarm_with_cause(ProbableCause::PeerUnreachable);
        alarm.text = RedactedText::new("peer 10.0.0.1 imsi 208950000000001 down");

        let cond = alarm_to_condition(&alarm);
        let event = alarm_to_event(&alarm);

        for message in [&cond.message, &event.message] {
            assert!(!message.contains("208950000000001"));
            assert!(!message.contains("10.0.0.1"));
        }
    }

    #[test]
    fn custom_probable_causes_drop_other_prefix_and_camel_case_reason() {
        let alarm = alarm_with_cause(ProbableCause::Other(
            "epdg.config.workflow-required".to_string(),
        ));

        let cond = alarm_to_condition(&alarm);
        assert_eq!(cond.reason, "EpdgConfigWorkflowRequired");
    }

    #[test]
    fn custom_probable_cause_separator_normalization_is_k8s_safe() {
        assert_eq!(
            custom_probable_cause_reason("upf.path-failure"),
            "UpfPathFailure"
        );
        assert_eq!(
            custom_probable_cause_reason("smf/session_rebind"),
            "SmfSessionRebind"
        );
        assert_eq!(
            custom_probable_cause_reason("amf  peer__timeout///retry"),
            "AmfPeerTimeoutRetry"
        );
    }

    #[test]
    fn condition_type_disambiguates_separator_collisions() {
        let mut dotted = alarm_with_cause(ProbableCause::PeerUnreachable);
        dotted.alarm_type = AlarmType::new("peer.disconnected");
        let mut dashed = alarm_with_cause(ProbableCause::PeerUnreachable);
        dashed.alarm_type = AlarmType::new("peer-disconnected");

        assert_ne!(
            alarm_to_condition(&dotted).type_,
            alarm_to_condition(&dashed).type_
        );
    }

    #[test]
    fn condition_type_removes_invalid_characters() {
        let mut alarm = alarm_with_cause(ProbableCause::PeerUnreachable);
        alarm.alarm_type = AlarmType::new("peer disconnected:☃");

        let condition_type = alarm_to_condition(&alarm).type_;

        assert!(condition_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-'));
        assert!(!condition_type.contains(' '));
        assert!(!condition_type.contains(':'));
        assert!(!condition_type.contains('☃'));
    }

    #[test]
    fn custom_probable_cause_empty_fallback_is_deterministic() {
        assert_eq!(custom_probable_cause_reason(""), "Other");
        assert_eq!(custom_probable_cause_reason("...---///___   "), "Other");
    }

    #[test]
    fn custom_probable_cause_condition_and_event_reasons_match() {
        let alarm = alarm_with_cause(ProbableCause::Other("smf/session_rebind".to_string()));

        let cond = alarm_to_condition(&alarm);
        let event = alarm_to_event(&alarm);

        assert_eq!(cond.reason, "SmfSessionRebind");
        assert_eq!(event.reason, cond.reason);
    }

    #[test]
    fn standard_probable_cause_reason_is_unchanged() {
        let alarm = alarm_with_cause(ProbableCause::PeerUnreachable);

        assert_eq!(alarm_to_condition(&alarm).reason, "PeerUnreachable");
        assert_eq!(alarm_to_event(&alarm).reason, "PeerUnreachable");
    }

    #[test]
    fn critical_and_major_events_preserve_distinct_severity() {
        let mut major = alarm_with_cause(ProbableCause::PeerUnreachable);
        major.severity = Severity::Major;
        let mut critical = alarm_with_cause(ProbableCause::PeerUnreachable);
        critical.severity = Severity::Critical;

        assert_ne!(
            alarm_to_event(&major).severity,
            alarm_to_event(&critical).severity
        );
        assert_ne!(
            alarm_to_condition(&major).severity,
            alarm_to_condition(&critical).severity
        );
    }

    #[test]
    fn event_with_count_preserves_deduplicated_occurrences() {
        let alarm = alarm_with_cause(ProbableCause::PeerUnreachable);

        assert_eq!(alarm_to_event_with_count(&alarm, 7).count, 7);
    }

    #[test]
    fn condition_with_previous_keeps_transition_time_when_status_unchanged() {
        let mut alarm = alarm_with_cause(ProbableCause::PeerUnreachable);
        let mut previous = alarm_to_condition(&alarm);
        previous.last_transition_time = "2026-06-09T10:00:00Z".to_string();
        alarm.updated_at += time::Duration::minutes(5);

        let projected = alarm_to_condition_with_previous(&alarm, Some(&previous));

        assert_eq!(projected.status, previous.status);
        assert_eq!(
            projected.last_transition_time,
            previous.last_transition_time
        );
    }
}
