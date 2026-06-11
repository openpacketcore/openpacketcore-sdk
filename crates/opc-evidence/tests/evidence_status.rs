mod evidence_common;
use evidence_common::*;

#[test]
fn status_calculates_full() {
    let status = calculate_status(&StatusInputs {
        has_code: true,
        has_tests: true,
        has_blocking_gap: false,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::Full);
}

#[test]
fn status_calculates_partial_with_blocking_gap() {
    let status = calculate_status(&StatusInputs {
        has_code: true,
        has_tests: true,
        has_blocking_gap: true,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::Partial);
}

#[test]
fn status_calculates_implemented_untested() {
    let status = calculate_status(&StatusInputs {
        has_code: true,
        has_tests: false,
        has_blocking_gap: false,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::ImplementedUntested);
}

#[test]
fn status_calculates_partial_with_nonblocking_gap() {
    let status = calculate_status(&StatusInputs {
        has_code: true,
        has_tests: false,
        has_gap: true,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::Partial);
}

#[test]
fn status_calculates_not_implemented_no_code() {
    let status = calculate_status(&StatusInputs {
        has_code: false,
        has_gap: true,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::NotImplemented);
}

#[test]
fn status_calculates_not_applicable() {
    let status = calculate_status(&StatusInputs {
        reviewed_na: true,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::NotApplicable);
}

#[test]
fn status_waived_overrides() {
    let status = calculate_status(&StatusInputs {
        has_waiver: true,
        has_code: true,
        has_tests: true,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::Waived);
}

#[test]
fn status_calculates_partial_when_gap_exists_with_tests() {
    let status = calculate_status(&StatusInputs {
        has_code: true,
        has_tests: true,
        has_gap: true,
        has_blocking_gap: false,
        ..Default::default()
    });
    assert_eq!(status, ConformanceStatus::Partial);
}
