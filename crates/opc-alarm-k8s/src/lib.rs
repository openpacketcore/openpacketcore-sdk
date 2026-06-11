//! Kubernetes condition and event mappings for OpenPacketCore alarms (RFC 013).
//!
//! Converts OPC alarm records into Kubernetes-style status conditions and
//! events for operator integration.

use opc_alarm::{Alarm, AlarmState, Severity};
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
    // Standard CamelCase format for Condition Type: e.g., "config-bus.commit.failure" -> "ConfigBusCommitFailure"
    let type_ = to_camel_case(alarm.alarm_type.as_str());

    // Status is True if the alarm is active, False if cleared or expired
    let status = if alarm.state.is_active() {
        "True".to_string()
    } else {
        "False".to_string()
    };

    let last_transition_time = alarm.updated_at.format(&Rfc3339).unwrap_or_default();

    // Reason is CamelCase representation of probable cause
    let reason = to_camel_case(&alarm.probable_cause.to_string());

    K8sCondition {
        type_,
        status,
        last_transition_time,
        reason,
        message: alarm.text.as_str().to_string(),
    }
}

/// Projects an alarm state change to a Kubernetes event.
pub fn alarm_to_event(alarm: &Alarm) -> K8sEvent {
    let reason = to_camel_case(&alarm.probable_cause.to_string());

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
        message: alarm.text.as_str().to_string(),
        type_,
        action,
        source_component,
        first_timestamp: first_ts,
        last_timestamp: last_ts,
        // Since OPC manages deduplication internally, a mapped event reflects the deduplicated stream
        count: 1,
    }
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
        let alarm = Alarm {
            alarm_id: AlarmId::new("alarm-123"),
            alarm_type: AlarmType::new("peer.disconnected"),
            severity: Severity::Critical,
            probable_cause: ProbableCause::PeerUnreachable,
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
        };

        let cond = alarm_to_condition(&alarm);
        assert_eq!(cond.type_, "PeerDisconnected");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "PeerUnreachable");
        assert_eq!(cond.message, "UPF link down");

        let event = alarm_to_event(&alarm);
        assert_eq!(event.reason, "PeerUnreachable");
        assert_eq!(event.type_, "Warning");
        assert_eq!(event.action, "Raised");
        assert_eq!(event.source_component, "nf:upf:upf-1");
    }
}
