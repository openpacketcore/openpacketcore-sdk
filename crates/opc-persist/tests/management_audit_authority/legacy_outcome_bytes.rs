//! Frozen RFC 019 predecessor outcomes; these bytes predate retained targets.
//! This verifies codec compatibility only, not authentication or audit admission.

use opc_persist::audit_authority::AuditOperationState;
use opc_persist::ManagementAuditOutcomeCode;

struct LegacyOutcome {
    value: AuditOperationState,
    json: &'static [u8],
    binary: &'static [u8],
}

fn legacy_outcomes() -> [LegacyOutcome; 9] {
    [
        LegacyOutcome {
            value: AuditOperationState::Intent,
            json: br#""intent""#,
            binary: &[0],
        },
        LegacyOutcome {
            value: AuditOperationState::Committed { version: 0 },
            json: br#"{"committed":{"version":0}}"#,
            binary: &[1, 0],
        },
        LegacyOutcome {
            value: AuditOperationState::Committed { version: 1 },
            json: br#"{"committed":{"version":1}}"#,
            binary: &[1, 1],
        },
        LegacyOutcome {
            value: AuditOperationState::Committed { version: 128 },
            json: br#"{"committed":{"version":128}}"#,
            binary: &[1, 0x80, 0x01],
        },
        LegacyOutcome {
            value: AuditOperationState::Committed { version: u64::MAX },
            json: br#"{"committed":{"version":18446744073709551615}}"#,
            binary: &[1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1],
        },
        LegacyOutcome {
            value: AuditOperationState::Rejected,
            json: br#""rejected""#,
            binary: &[2],
        },
        LegacyOutcome {
            value: AuditOperationState::Observed {
                outcome: ManagementAuditOutcomeCode::Success,
            },
            json: br#"{"observed":{"outcome":"success"}}"#,
            binary: &[3, 1],
        },
        LegacyOutcome {
            value: AuditOperationState::Observed {
                outcome: ManagementAuditOutcomeCode::Denied,
            },
            json: br#"{"observed":{"outcome":"denied"}}"#,
            binary: &[3, 2],
        },
        LegacyOutcome {
            value: AuditOperationState::Observed {
                outcome: ManagementAuditOutcomeCode::Failed,
            },
            json: br#"{"observed":{"outcome":"failed"}}"#,
            binary: &[3, 3],
        },
    ]
}

#[test]
fn legacy_audit_outcomes_preserve_exact_json_and_binary_bytes() {
    // Keep the predecessor bytes literal: regenerating expectations through
    // the current encoder would hide a tag, field-name or integer change.
    for fixture in legacy_outcomes() {
        assert_eq!(serde_json::to_vec(&fixture.value).unwrap(), fixture.json);
        assert_eq!(
            serde_json::from_slice::<AuditOperationState>(fixture.json).unwrap(),
            fixture.value
        );
        assert_eq!(
            opc_consensus::encode_bounded(&fixture.value).unwrap(),
            fixture.binary
        );
        assert_eq!(
            opc_consensus::decode_bounded::<AuditOperationState>(fixture.binary).unwrap(),
            fixture.value
        );
    }
}

#[test]
fn legacy_audit_outcome_boundaries_refuse_truncation_and_trailing_data() {
    for fixture in legacy_outcomes() {
        for end in 0..fixture.json.len() {
            assert!(serde_json::from_slice::<AuditOperationState>(&fixture.json[..end]).is_err());
        }
        for end in 0..fixture.binary.len() {
            assert!(
                opc_consensus::decode_bounded::<AuditOperationState>(&fixture.binary[..end])
                    .is_err()
            );
        }
        let mut trailing_json = fixture.json.to_vec();
        trailing_json.extend_from_slice(b"null");
        assert!(serde_json::from_slice::<AuditOperationState>(&trailing_json).is_err());
        let mut trailing_binary = fixture.binary.to_vec();
        trailing_binary.push(0);
        assert!(opc_consensus::decode_bounded::<AuditOperationState>(&trailing_binary).is_err());
    }
}
