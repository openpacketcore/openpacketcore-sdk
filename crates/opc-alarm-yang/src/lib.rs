//! YANG schema and operational projections for OpenPacketCore alarms (RFC 013).
//!
//! Defines the canonical YANG module for alarm state and operational data.

use opc_alarm::{Alarm, Severity};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;

/// The YANG module definition for OpenPacketCore alarms aligned with RFC 013.
pub const YANG_ALARM_SCHEMA: &str = r#"
module openpacketcore-alarm {
    yang-version 1.1;
    namespace "urn:openpacketcore:params:xml:ns:yang:openpacketcore-alarm";
    prefix opc-alarm;

    import ietf-yang-types {
        prefix yang;
    }

    organization "OpenPacketCore Project";

    contact "support@openpacketcore.org";

    description
      "This module defines the alarm model, severity taxonomy, and probable causes
       used across OpenPacketCore NFs per RFC 013.";

    revision 2026-06-09 {
        description "Initial revision.";
    }

    typedef severity {
        type enumeration {
            enum cleared {
                value 0;
                description "Fault is no longer active.";
            }
            enum indeterminate {
                value 1;
                description "Fault detected but impact is unknown.";
            }
            enum warning {
                value 2;
                description "Approaching a fault threshold.";
            }
            enum minor {
                value 3;
                description "Limited impairment with a workaround.";
            }
            enum major {
                value 4;
                description "Serious degradation or redundancy loss.";
            }
            enum critical {
                value 5;
                description "Service outage or security boundary failure.";
            }
        }
    }

    container alarms {
        config false;

        list active-alarm {
            key "alarm-id";
            leaf alarm-id {
                type string;
            }
            leaf alarm-type {
                type string;
            }
            leaf severity {
                type severity;
            }
            leaf probable-cause {
                type string;
            }
            leaf affected-object {
                type string;
            }
            leaf tenant {
                type string;
            }
            leaf slice {
                type string;
            }
            leaf region {
                type string;
            }
            leaf text {
                type string;
            }
            leaf raised-at {
                type yang:date-and-time;
            }
            leaf updated-at {
                type yang:date-and-time;
            }
        }
    }

    notification alarm-notification {
        description "Sent when an alarm is raised, updated, or cleared.";
        leaf event-type {
            type enumeration {
                enum raise;
                enum update;
                enum clear;
            }
        }
        leaf alarm-id {
            type string;
        }
        leaf severity {
            type severity;
        }
        leaf probable-cause {
            type string;
        }
        leaf text {
            type string;
        }
    }
}
"#;

/// Projects an OPC `Alarm` into a JSON representation conforming to RFC 7951 YANG JSON encoding.
pub fn alarm_to_yang_json(alarm: &Alarm) -> Value {
    let severity_str = match alarm.severity {
        Severity::Cleared => "cleared",
        Severity::Indeterminate => "indeterminate",
        Severity::Warning => "warning",
        Severity::Minor => "minor",
        Severity::Major => "major",
        Severity::Critical => "critical",
    };

    let raised_ts = alarm.raised_at.format(&Rfc3339).unwrap_or_default();
    let updated_ts = alarm.updated_at.format(&Rfc3339).unwrap_or_default();

    json!({
        "alarm-id": alarm.alarm_id.as_str(),
        "alarm-type": alarm.alarm_type.as_str(),
        "severity": severity_str,
        "probable-cause": alarm.probable_cause.to_string(),
        "affected-object": alarm.affected_object.to_string(),
        "tenant": alarm.tenant.as_deref().unwrap_or(""),
        "slice": alarm.slice.as_deref().unwrap_or(""),
        "region": alarm.region.as_ref().map(|r| r.as_str()).unwrap_or(""),
        "text": alarm.text.redacted_for_export(),
        "raised-at": raised_ts,
        "updated-at": updated_ts
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_alarm::prelude::*;
    use time::OffsetDateTime;

    #[test]
    fn test_alarm_to_yang_json() {
        let alarm = Alarm {
            alarm_id: AlarmId::new("alarm-123"),
            alarm_type: AlarmType::new("peer.disconnected"),
            severity: Severity::Critical,
            probable_cause: ProbableCause::PeerUnreachable,
            affected_object: AffectedObject::NfInstance {
                kind: "upf".to_string(),
                instance: "upf-1".to_string(),
            },
            tenant: Some("tenant-a".to_string()),
            slice: Some("slice-1".to_string()),
            region: Some(RegionId::try_new("us-east-1").expect("valid region")),
            text: RedactedText::new("UPF link down"),
            details: AlarmDetails::empty(),
            state: AlarmState::Raised,
            raised_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            cleared_at: None,
            correlation_id: None,
        };

        let yang_val = alarm_to_yang_json(&alarm);
        assert_eq!(yang_val["alarm-id"], "alarm-123");
        assert_eq!(yang_val["alarm-type"], "peer.disconnected");
        assert_eq!(yang_val["severity"], "critical");
        assert_eq!(yang_val["probable-cause"], "peer-unreachable");
        assert_eq!(yang_val["tenant"], "tenant-a");
        assert_eq!(yang_val["slice"], "slice-1");
        assert_eq!(yang_val["region"], "us-east-1");
        assert_eq!(yang_val["text"], "UPF link down");
        assert!(!yang_val["raised-at"].as_str().unwrap().is_empty());
    }

    #[test]
    fn alarm_to_yang_json_redacts_sensitive_text() {
        let alarm = Alarm {
            alarm_id: AlarmId::new("alarm-123"),
            alarm_type: AlarmType::new("peer.disconnected"),
            severity: Severity::Critical,
            probable_cause: ProbableCause::PeerUnreachable,
            affected_object: AffectedObject::NfInstance {
                kind: "upf".to_string(),
                instance: "upf-1".to_string(),
            },
            tenant: Some("tenant-a".to_string()),
            slice: Some("slice-1".to_string()),
            region: Some(RegionId::try_new("us-east-1").expect("valid region")),
            text: RedactedText::new("peer 10.0.0.1 imsi 208950000000001 down"),
            details: AlarmDetails::empty(),
            state: AlarmState::Raised,
            raised_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            cleared_at: None,
            correlation_id: None,
        };

        let text = alarm_to_yang_json(&alarm)["text"]
            .as_str()
            .expect("text is string")
            .to_string();

        assert!(!text.contains("208950000000001"));
        assert!(!text.contains("10.0.0.1"));
    }
}
