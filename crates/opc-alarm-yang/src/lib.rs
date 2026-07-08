//! YANG schema and operational projections for OpenPacketCore alarms (RFC 013).
//!
//! Defines the canonical YANG module for alarm state and operational data.

use opc_alarm::{Alarm, Severity};
use serde_json::{json, Map, Value};
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

    let mut object = Map::new();
    object.insert("alarm-id".to_string(), json!(alarm.alarm_id.as_str()));
    object.insert("alarm-type".to_string(), json!(alarm.alarm_type.as_str()));
    object.insert("severity".to_string(), json!(severity_str));
    object.insert(
        "probable-cause".to_string(),
        json!(alarm.probable_cause.to_string()),
    );
    object.insert(
        "affected-object".to_string(),
        json!(alarm.affected_object.to_string()),
    );
    if let Some(tenant) = &alarm.tenant {
        object.insert("tenant".to_string(), json!(tenant));
    }
    if let Some(slice) = &alarm.slice {
        object.insert("slice".to_string(), json!(slice));
    }
    if let Some(region) = &alarm.region {
        object.insert("region".to_string(), json!(region.as_str()));
    }
    object.insert("text".to_string(), json!(alarm.text.redacted_for_export()));
    object.insert("raised-at".to_string(), json!(raised_ts));
    object.insert("updated-at".to_string(), json!(updated_ts));
    Value::Object(object)
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
    fn alarm_to_yang_json_omits_absent_scope_leaves() {
        let alarm = Alarm {
            alarm_id: AlarmId::new("alarm-global"),
            alarm_type: AlarmType::new("peer.disconnected"),
            severity: Severity::Major,
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

        let yang_val = alarm_to_yang_json(&alarm);
        let object = yang_val.as_object().expect("yang alarm object");

        assert!(!object.contains_key("tenant"));
        assert!(!object.contains_key("slice"));
        assert!(!object.contains_key("region"));
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
