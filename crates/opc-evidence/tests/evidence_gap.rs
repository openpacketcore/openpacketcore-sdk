mod evidence_common;
use evidence_common::*;

#[test]
fn gap_new_passes_valid_gap() {
    use time::Date;
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec!["REQ-3GPP-TS29281-R18-5.1-001".into()],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        valid_gap_options(),
    )
    .unwrap();
    assert_eq!(gap.id(), "GAP-000001");
    assert_eq!(gap.title(), "Test gap");
    assert_eq!(gap.severity(), GapSeverity::Medium);
}

#[test]
fn gap_new_rejects_blank_id() {
    use time::Date;
    let err = Gap::new(
        "   ",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, GapError::InvalidGap(_)));
    assert!(err.to_string().contains("id"));
}

#[test]
fn gap_new_rejects_empty_id() {
    use time::Date;
    let err = Gap::new(
        "",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, GapError::InvalidGap(_)));
}

#[test]
fn gap_new_rejects_blank_title() {
    use time::Date;
    let err = Gap::new(
        "GAP-000001",
        "   ",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, GapError::InvalidGap(_)));
    assert!(err.to_string().contains("title"));
}

#[test]
fn gap_new_rejects_blank_owner() {
    use time::Date;
    let options = GapOptions {
        owner: Some("   ".into()),
        ..Default::default()
    };
    let err = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        options,
    )
    .unwrap_err();
    assert!(matches!(err, GapError::InvalidGap(_)));
    assert!(err.to_string().contains("owner"));
}

#[test]
fn gap_new_allows_missing_owner() {
    use time::Date;
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions::default(),
    )
    .unwrap();
    assert_eq!(gap.owner(), None);
}

#[test]
fn gap_new_trims_whitespace() {
    use time::Date;
    let gap = Gap::new(
        "  GAP-000001  ",
        "  Test gap  ",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("  alice  ".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(gap.id(), "GAP-000001");
    assert_eq!(gap.title(), "Test gap");
    assert_eq!(gap.owner(), Some("alice"));
}

#[test]
fn gap_deserialize_rejects_blank_id() {
    let json = r#"{
        "id": "   ",
        "title": "Test gap",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19"
    }"#;
    let result: Result<Gap, _> = serde_json::from_str(json);
    assert!(result.is_err());

    let json_empty = r#"{
        "id": "",
        "title": "Test gap",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19"
    }"#;
    let result_empty: Result<Gap, _> = serde_json::from_str(json_empty);
    assert!(result_empty.is_err());
}

#[test]
fn gap_deserialize_rejects_blank_title() {
    let json = r#"{
        "id": "GAP-000001",
        "title": "  ",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19"
    }"#;
    let result: Result<Gap, _> = serde_json::from_str(json);
    assert!(result.is_err());

    let json_empty = r#"{
        "id": "GAP-000001",
        "title": "",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19"
    }"#;
    let result_empty: Result<Gap, _> = serde_json::from_str(json_empty);
    assert!(result_empty.is_err());
}

#[test]
fn gap_deserialize_rejects_blank_owner() {
    let json = r#"{
        "id": "GAP-000001",
        "title": "Test gap",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19",
        "owner": ""
    }"#;
    let result: Result<Gap, _> = serde_json::from_str(json);
    assert!(result.is_err());

    let json_ws = r#"{
        "id": "GAP-000001",
        "title": "Test gap",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19",
        "owner": "   "
    }"#;
    let result_ws: Result<Gap, _> = serde_json::from_str(json_ws);
    assert!(result_ws.is_err());
}

#[test]
fn gap_deserialize_trims_whitespace() {
    let json = r#"{
        "id": "  GAP-000001  ",
        "title": "  Test gap  ",
        "status": "open",
        "severity": "medium",
        "applies_to": [],
        "created": "2026-05-19",
        "owner": "  alice  "
    }"#;
    let gap: Gap = serde_json::from_str(json).unwrap();
    assert_eq!(gap.id(), "GAP-000001");
    assert_eq!(gap.title(), "Test gap");
    assert_eq!(gap.owner(), Some("alice"));
}

#[test]
fn gap_fixture_roundtrips() {
    let raw = include_str!("fixtures/gap_record.json");
    let gap: Gap = serde_json::from_str(raw).unwrap();
    assert_eq!(gap.id(), "GAP-000123");
    assert_eq!(gap.severity(), GapSeverity::Medium);
    assert_eq!(gap.status(), GapStatus::Open);
    gap.validate_gate("0.3.0").unwrap();

    let back = serde_json::to_string_pretty(&gap).unwrap();
    let round: Gap = serde_json::from_str(&back).unwrap();
    assert_eq!(round.id(), gap.id());
}
