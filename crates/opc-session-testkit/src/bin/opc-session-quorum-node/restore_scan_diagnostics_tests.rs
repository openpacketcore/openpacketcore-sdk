//! Qualification failures identify the failed contract without record values.

use super::*;
use opc_session_store::{RestoreScanCursor, RestoreScanPage};

const PHASES: [&str; 2] = ["traffic_restore_scan", "recovery_restore_scan"];

fn exact_page() -> (StoredSessionRecord, RestoreScanPage) {
    let key = qualification_traffic_key(0).unwrap();
    let expected = expected_traffic_record(&key, 37, 3, 0, 1, 1).unwrap();
    let mut page = RestoreScanPage::new(vec![expected.clone()], 0, None);
    page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
    (expected, page)
}

#[tokio::test(start_paused = true)]
async fn qualification_restore_scan_diagnostics_identify_each_page_check() {
    let (expected, page) = exact_page();
    let mut malformed = Vec::new();
    let mut incomplete = page.clone();
    incomplete.complete = false;
    malformed.push(("complete", incomplete));
    let mut continued = page.clone();
    continued.next_cursor = Some(RestoreScanCursor::from_offset(1));
    malformed.push(("next_cursor", continued));
    let mut legacy = page.clone();
    legacy.cursor_profile = RestoreScanCursorProfile::LegacyCompatibility;
    malformed.push(("cursor_profile", legacy));
    let mut wrong_count = page.clone();
    wrong_count.loaded_count += 1;
    malformed.push(("loaded_count", wrong_count));
    let mut over_limit = page.clone();
    over_limit.records = vec![expected.clone(); QUALIFICATION_TRAFFIC_RESTORE_LIMIT + 1];
    over_limit.loaded_count = over_limit.records.len();
    malformed.push(("page_limit", over_limit));
    let mut wrong_record = page;
    wrong_record.records[0].generation = Generation::new(2);
    malformed.push(("expected_record", wrong_record));

    for phase in PHASES {
        for (check, page) in &malformed {
            let started = tokio::time::Instant::now();
            tokio::time::advance(Duration::from_millis(7)).await;
            let mut diagnostics = Vec::new();
            let result = validate_qualification_restore_scan(
                &mut diagnostics,
                Ok(page.clone()),
                &expected,
                phase,
                started,
            );
            let failure = QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::RestoreScanRejected,
                QualificationTrafficFailureStage::RestoreScan,
            );
            assert_eq!(result, Err(failure), "{phase}: {check}");
            assert!(!traffic_failure_is_recoverable(failure));
            assert_eq!(
                String::from_utf8(diagnostics).unwrap(),
                format!(
                    "qualification restore scan rejected: phase={phase} check={check} elapsed_ms=7\n"
                ),
                "identify the failed page check without recording its values"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn qualification_restore_scan_diagnostics_identify_store_variants_without_values() {
    let (expected, _) = exact_page();
    let cases = [
        (
            "Crypto",
            StoreError::Crypto("synthetic-payload-secret".into()),
            false,
        ),
        (
            "Serialization",
            StoreError::Serialization("synthetic-record-secret".into()),
            false,
        ),
        (
            "RestoreScanCursorStale",
            StoreError::RestoreScanCursorStale,
            false,
        ),
        (
            "InvalidRestoreScanResponse",
            StoreError::InvalidRestoreScanResponse("synthetic-cursor-secret".into()),
            false,
        ),
        (
            "RestoreScanWorkBudgetExceeded",
            StoreError::RestoreScanWorkBudgetExceeded,
            false,
        ),
        (
            "BackendUnavailable",
            StoreError::BackendUnavailable("synthetic-backend-secret".into()),
            true,
        ),
        (
            "KeyProviderUnavailable",
            StoreError::KeyProviderUnavailable("synthetic-provider-secret".into()),
            true,
        ),
    ];
    for phase in PHASES {
        for (variant, error, recoverable) in &cases {
            let started = tokio::time::Instant::now();
            tokio::time::advance(Duration::from_millis(11)).await;
            let mut diagnostics = Vec::new();
            let result = validate_qualification_restore_scan(
                &mut diagnostics,
                Err(error.clone()),
                &expected,
                phase,
                started,
            );
            let failure = QualificationTrafficFailure::store(
                QualificationTrafficFailureCode::RestoreScanRejected,
                QualificationTrafficFailureStage::RestoreScan,
                error,
            );
            assert_eq!(result, Err(failure), "{phase}: {variant}");
            assert_eq!(traffic_failure_is_recoverable(failure), *recoverable);
            let diagnostic = String::from_utf8(diagnostics).unwrap();
            assert!(!diagnostic.contains("secret"));
            assert_eq!(
                diagnostic,
                format!(
                    "qualification restore scan rejected: phase={phase} variant={variant} elapsed_ms=11\n"
                ),
                "the exact closed variant must survive the coarse retry class"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn qualification_restore_scan_diagnostics_accept_valid_page_without_output() {
    let (expected, page) = exact_page();
    for phase in PHASES {
        let started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(7)).await;
        let mut diagnostics = Vec::new();
        assert_eq!(
            validate_qualification_restore_scan(
                &mut diagnostics,
                Ok(page.clone()),
                &expected,
                phase,
                started,
            ),
            Ok(())
        );
        assert!(diagnostics.is_empty());
    }
}

struct UnavailableDiagnostics {
    writes: usize,
}

impl io::Write for UnavailableDiagnostics {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        Err(io::Error::other("synthetic diagnostic write failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn qualification_restore_scan_diagnostics_write_failure_preserves_rejection() {
    let (expected, mut page) = exact_page();
    page.complete = false;
    for phase in PHASES {
        for result in [
            Ok(page.clone()),
            Err(StoreError::Crypto("synthetic-error-secret".into())),
        ] {
            let mut diagnostics = UnavailableDiagnostics { writes: 0 };
            let started = tokio::time::Instant::now();
            let failure = validate_qualification_restore_scan(
                &mut diagnostics,
                result,
                &expected,
                phase,
                started,
            )
            .expect_err("diagnostic I/O must not mask the original rejection");
            assert_eq!(
                failure,
                QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::RestoreScanRejected,
                    QualificationTrafficFailureStage::RestoreScan,
                )
            );
            assert!(!traffic_failure_is_recoverable(failure));
            assert!(
                diagnostics.writes > 0,
                "exercise actual diagnostic I/O failure"
            );
        }
    }
}
