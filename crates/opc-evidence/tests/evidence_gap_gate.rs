mod evidence_common;
use evidence_common::*;

#[test]
fn gap_gate_passes_valid_gap() {
    valid_gap().validate_gate("0.3.0").unwrap();
}

#[test]
fn gap_gate_fails_missing_owner() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions::default(),
    )
    .unwrap();
    assert!(gap.validate_gate("0.3.0").is_err());
}

#[test]
fn gap_gate_fails_missing_mitigation() {
    // Mitigation is None
    {
        let gap = Gap::new(
            "GAP-000001",
            "Test gap",
            GapStatus::Open,
            GapSeverity::Medium,
            vec![],
            time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
            GapOptions {
                owner: Some("owner".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gap.validate_gate("0.3.0").is_err());
    }
    // Mitigation is blank
    {
        let gap = Gap::new(
            "GAP-000001",
            "Test gap",
            GapStatus::Open,
            GapSeverity::Medium,
            vec![],
            time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
            GapOptions {
                owner: Some("owner".into()),
                mitigation: Some("".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gap.validate_gate("0.3.0").is_err());
    }
}

#[test]
fn gap_gate_allows_explicit_no_mitigation() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("no mitigation".into()),
            ..Default::default()
        },
    )
    .unwrap();
    gap.validate_gate("0.3.0").unwrap();
}

#[test]
fn gap_gate_fails_empty_target_release() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("mitigation".into()),
            target_release: Some("   ".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(gap.validate_gate("0.3.0").is_err());
}

#[test]
fn gap_gate_fails_critical_without_security_impact() {
    // Without security_impact
    {
        let gap = Gap::new(
            "GAP-000001",
            "Test gap",
            GapStatus::Open,
            GapSeverity::Critical,
            vec![],
            time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
            GapOptions {
                owner: Some("owner".into()),
                mitigation: Some("mitigation".into()),
                security_approval: Some("Approved".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gap.validate_gate("0.3.0").is_err());
    }
    // With security_impact passes
    {
        let gap = Gap::new(
            "GAP-000001",
            "Test gap",
            GapStatus::Open,
            GapSeverity::Critical,
            vec![],
            time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
            GapOptions {
                owner: Some("owner".into()),
                mitigation: Some("mitigation".into()),
                security_impact: Some("High.".into()),
                security_approval: Some("Approved".into()),
                ..Default::default()
            },
        )
        .unwrap();
        gap.validate_gate("0.3.0").unwrap();
    }
}

#[test]
fn gap_gate_fails_critical_with_whitespace_only_security_impact() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Critical,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("mitigation".into()),
            security_approval: Some("Approved".into()),
            security_impact: Some("   ".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        gap.validate_gate("0.3.0").is_err(),
        "whitespace-only security_impact should fail for critical gaps"
    );
}

#[test]
fn gap_gate_fails_critical_without_security_approval() {
    // Without security_approval
    {
        let gap = Gap::new(
            "GAP-000001",
            "Test gap",
            GapStatus::Open,
            GapSeverity::Critical,
            vec![],
            time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
            GapOptions {
                owner: Some("owner".into()),
                mitigation: Some("mitigation".into()),
                security_impact: Some("High.".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gap.validate_gate("0.3.0").is_err());
    }
    // With whitespace-only approval
    {
        let gap = Gap::new(
            "GAP-000001",
            "Test gap",
            GapStatus::Open,
            GapSeverity::Critical,
            vec![],
            time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
            GapOptions {
                owner: Some("owner".into()),
                mitigation: Some("mitigation".into()),
                security_impact: Some("High.".into()),
                security_approval: Some("  ".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gap.validate_gate("0.3.0").is_err());
    }
}

#[test]
fn gap_gate_passes_critical_with_security_approval() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Critical,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("mitigation".into()),
            security_impact: Some("High.".into()),
            security_approval: Some("Approved by SecTeam".into()),
            ..Default::default()
        },
    )
    .unwrap();
    gap.validate_gate("0.3.0").unwrap();
}

#[test]
fn gap_gate_fails_overdue_target_release() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("mitigation".into()),
            target_release: Some("0.3.0".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(gap.validate_gate("0.4.0").is_err());
    assert!(gap.validate_gate("0.3.1").is_err());
    assert!(gap.validate_gate("1.0.0").is_err());
}

#[test]
fn gap_gate_passes_future_or_current_target_release() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("mitigation".into()),
            target_release: Some("0.3.0".into()),
            ..Default::default()
        },
    )
    .unwrap();
    gap.validate_gate("0.3.0").unwrap();
    gap.validate_gate("0.2.9").unwrap();
    gap.validate_gate("0.1.0").unwrap();
}

#[test]
fn gap_gate_ignores_overdue_on_closed_gaps() {
    let gap = Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Closed,
        GapSeverity::Medium,
        vec![],
        time::Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("owner".into()),
            mitigation: Some("mitigation".into()),
            target_release: Some("0.2.0".into()),
            ..Default::default()
        },
    )
    .unwrap();
    gap.validate_gate("0.3.0").unwrap();
}

#[test]
fn gap_gate_rejects_full_status_with_open_gap() {
    let gaps = vec![make_open_gap()];
    let result = validate_status_for_gaps(&gaps, ConformanceStatus::Full);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, EvidenceError::GapGateFailed(_)));
    assert!(err.to_string().contains("Full"));
}

#[test]
fn gap_gate_rejects_implemented_untested_with_open_gap() {
    let gaps = vec![make_open_gap()];
    let result = validate_status_for_gaps(&gaps, ConformanceStatus::ImplementedUntested);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, EvidenceError::GapGateFailed(_)));
    assert!(err.to_string().contains("ImplementedUntested"));
}

#[test]
fn gap_gate_allows_partial_with_open_gap() {
    let gaps = vec![make_open_gap()];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Partial).is_ok());
}

#[test]
fn gap_gate_allows_not_implemented_with_open_gap() {
    let gaps = vec![make_open_gap()];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::NotImplemented).is_ok());
}

#[test]
fn gap_gate_allows_full_with_only_closed_gaps() {
    let gaps = vec![make_closed_gap()];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Full).is_ok());
}

#[test]
fn gap_gate_allows_full_with_no_gaps() {
    let gaps: Vec<Gap> = vec![];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Full).is_ok());
}

#[test]
fn gap_gate_rejects_full_with_mixed_open_and_closed_gaps() {
    let gaps = vec![make_closed_gap(), make_open_gap()];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Full).is_err());
}

#[test]
fn gap_gate_waived_and_not_applicable_allowed_with_open_gap() {
    let gaps = vec![make_open_gap()];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Waived).is_ok());
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::NotApplicable).is_ok());
}

#[test]
fn gap_gate_status_matches_calculator_behavior() {
    let computed_status = ConformanceStatus::Full;
    let gaps = vec![make_open_gap()];
    assert!(validate_status_for_gaps(&gaps, computed_status).is_err());

    let correct_status = calculate_status(&StatusInputs {
        has_gap: true,
        has_code: true,
        has_tests: false,
        ..StatusInputs::default()
    });
    assert_eq!(correct_status, ConformanceStatus::Partial);
    assert!(validate_status_for_gaps(&gaps, correct_status).is_ok());
}

#[test]
fn gap_gate_rejects_full_status_with_deferred_gap() {
    let gaps = vec![make_deferred_gap()];
    let result = validate_status_for_gaps(&gaps, ConformanceStatus::Full);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, EvidenceError::GapGateFailed(_)));
    assert!(err.to_string().contains("Full"));
}

#[test]
fn gap_gate_rejects_implemented_untested_with_deferred_gap() {
    let gaps = vec![make_deferred_gap()];
    let result = validate_status_for_gaps(&gaps, ConformanceStatus::ImplementedUntested);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, EvidenceError::GapGateFailed(_)));
    assert!(err.to_string().contains("ImplementedUntested"));
}

#[test]
fn gap_gate_allows_implemented_tested_gap_variants_with_gaps() {
    let gaps = vec![make_open_gap()];
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Implemented).is_ok());
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Tested).is_ok());
    assert!(validate_status_for_gaps(&gaps, ConformanceStatus::Gap).is_ok());
}
