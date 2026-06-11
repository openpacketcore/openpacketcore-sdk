mod evidence_common;
use evidence_common::*;

#[test]
fn fixture_evidence_record_passes_format_validation() {
    let raw = include_str!("fixtures/evidence_record.json");
    validate_fixture_formats(raw).expect("evidence_record.json should pass format validation");
}

#[test]
fn fixture_gap_record_passes_format_validation() {
    let raw = include_str!("fixtures/gap_record.json");
    validate_fixture_formats(raw).expect("gap_record.json should pass format validation");
}

#[test]
fn fixture_manifest_passes_format_validation() {
    let raw = include_str!("fixtures/manifest.json");
    validate_fixture_formats(raw).expect("manifest.json should pass format validation");
}

#[test]
fn format_validator_rejects_invalid_date() {
    let bad = r#"{"created": "2026-05"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date"));
}

#[test]
fn format_validator_rejects_invalid_datetime() {
    let bad = r#"{"last_updated": "2026-05-19T17:25:13"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date-time"));
}

#[test]
fn format_validator_rejects_empty_date_field() {
    let bad = r#"{"created": ""}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("created"));
    assert!(err.contains("validation failed"));
}

#[test]
fn format_validator_accepts_valid_date() {
    let good = r#"{"created": "2026-05-19"}"#;
    assert!(validate_fixture_formats(good).is_ok());
}

#[test]
fn format_validator_accepts_valid_datetime_with_fraction_and_z() {
    let good = r#"{"last_updated": "2026-05-19T17:25:13.123Z"}"#;
    assert!(validate_fixture_formats(good).is_ok());
}

#[test]
fn format_validator_accepts_valid_datetime_with_offset() {
    let good = r#"{"last_updated": "2026-05-19T17:25:13+00:00"}"#;
    assert!(validate_fixture_formats(good).is_ok());
}

#[test]
fn format_validator_rejects_datetime_with_wrong_format() {
    let bad = r#"{"last_updated": "2026-05-19 17:25:13Z"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date-time"));
}

#[test]
fn format_validator_rejects_out_of_range_month() {
    let bad = r#"{"created": "2026-13-19"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date"));
}

#[test]
fn format_validator_rejects_out_of_range_day() {
    let bad = r#"{"created": "2026-05-32"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date"));
}

#[test]
fn format_validator_rejects_invalid_february_day() {
    let bad = r#"{"created": "2026-02-30"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date"));
}

#[test]
fn format_validator_rejects_out_of_range_hour() {
    let bad = r#"{"last_updated": "2026-05-19T25:25:13Z"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date-time"));
}

#[test]
fn format_validator_rejects_out_of_range_minute() {
    let bad = r#"{"last_updated": "2026-05-19T17:61:13Z"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date-time"));
}

#[test]
fn format_validator_rejects_out_of_range_second() {
    let bad = r#"{"last_updated": "2026-05-19T17:25:61Z"}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("date-time"));
}

#[test]
fn format_validator_checks_arrays_recursively() {
    let bad = r#"{"some_array": [{"created": "2026-02-30"}]}"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("some_array[0].created"));
}

#[test]
fn format_validator_checks_top_level_arrays() {
    let bad = r#"[{"created": "2026-02-30"}]"#;
    let err = validate_fixture_formats(bad).unwrap_err();
    assert!(err.contains("<root>[0].created"));
}

#[test]
fn evidence_fixture_roundtrips() {
    let raw = include_str!("fixtures/evidence_record.json");
    let record: EvidenceRecord = serde_json::from_str(raw).unwrap();
    assert_eq!(
        record.requirement_id.to_string(),
        "REQ-3GPP-TS29281-R18-5.1-001"
    );
    assert_eq!(record.status, ConformanceStatus::Partial);
    assert_eq!(record.gap_refs, vec!["GAP-000123"]);

    let back = serde_json::to_string_pretty(&record).unwrap();
    let round: EvidenceRecord = serde_json::from_str(&back).unwrap();
    assert_eq!(round.requirement_id, record.requirement_id);
    assert_eq!(round.status, record.status);
}
