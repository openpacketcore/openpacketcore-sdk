//! Original SQL reads are the oracle for the detached native adapter.

use super::*;
use crate::restore::{RestoreScanPage, RestoreScanRequest, RestoreScanScope};
use std::time::Instant;

fn scan(
    wal: &Wal,
    request: RestoreScanRequest,
    now: Timestamp,
) -> Result<RestoreScanPage, StoreError> {
    wal.native_public_read(&|| Ok(()), |state, check| {
        state.scan_restore_records(request, now, check)
    })
    .unwrap()
}

fn sql_scan(
    backend: &SqliteSessionBackend,
    request: RestoreScanRequest,
    now: Timestamp,
) -> Result<RestoreScanPage, StoreError> {
    ops::scan_restore_records_sync(
        &backend.conn.blocking_lock(),
        request,
        now,
        Arc::new(AtomicBool::new(false)),
        Instant::now() + Duration::from_secs(5),
        crate::sqlite::RestoreScanValidationProfile::Consensus,
    )
}

#[test]
fn native_public_record_journal_and_restore_pages_preserve_sql_cursors_across_cold_reopen() {
    let fixture = Fixture::new();
    let first = fenced_transition_v2_request(0xB1, 1, "native-public-read-first");
    let requests = (0..8)
        .map(|slot| sdk741_component_request(Sdk741Payload::Create, 101, slot, None))
        .collect::<Vec<_>>();
    fixture.parity(&[
        formation(),
        activation(1, first.clone(), timestamp(1)),
        fenced_transition_v2_batch_entry(2, requests.clone(), timestamp(2)),
    ]);
    for request in std::iter::once(&first).chain(&requests) {
        let key = request.lease().key();
        let expected =
            ops::get_sync(&fixture.oracle.conn.blocking_lock(), key, timestamp(3)).unwrap();
        let actual = fixture
            .wal
            .native_public_read(&|| Ok(()), |state, _| state.get_at(key, timestamp(3)))
            .unwrap()
            .unwrap();
        assert_eq!(actual, expected);
        let observed = fixture
            .wal
            .native_public_read(&|| Ok(()), |state, _| state.observe_at(key, timestamp(3)))
            .unwrap()
            .unwrap();
        let fence = ops::current_fence_sync(&fixture.oracle.conn.blocking_lock(), key).unwrap();
        assert_eq!(
            observed,
            crate::FencedTransitionObservation::new(expected, FenceToken::new(fence)).unwrap()
        );
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let expected_journal = runtime
        .block_on(fixture.oracle.consensus_get_replication_log(0, 64))
        .unwrap();
    let journal = fixture
        .wal
        .native_public_read(&|| Ok(()), |state, check| {
            state.replication_log(0, 64, check)
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        encode_json(&journal).unwrap(),
        encode_json(&expected_journal).unwrap()
    );
    let first_page = scan(&fixture.wal, RestoreScanRequest::all(2), timestamp(3)).unwrap();
    assert_eq!(
        first_page,
        sql_scan(&fixture.oracle, RestoreScanRequest::all(2), timestamp(3)).unwrap()
    );
    assert_eq!(first_page.loaded_count, 2);
    assert!(!first_page.complete);
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    assert!(reopened.native_cold_counts_for_test().unwrap()[1] > 0);
    let cold_journal = reopened
        .native_public_read(&|| Ok(()), |state, check| {
            state.replication_log(0, 64, check)
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        encode_json(&cold_journal).unwrap(),
        encode_json(&expected_journal).unwrap()
    );
    let mut cursor = first_page.next_cursor;
    let mut total = 2;
    while let Some(next) = cursor {
        let request = RestoreScanRequest {
            scope: RestoreScanScope::all(),
            cursor: Some(next),
            limit: 2,
        };
        // A continuation retains the original scan timestamp, even when the
        // caller supplies a later clock value after reopening.
        let page = scan(&reopened, request.clone(), timestamp(20)).unwrap();
        assert_eq!(
            page,
            sql_scan(&fixture.oracle, request, timestamp(20)).unwrap()
        );
        total += page.loaded_count;
        cursor = page.next_cursor;
    }
    assert_eq!(total, 9);
    assert_eq!(reopened.native_sql_fallback_count().unwrap(), 0);
    reopened.shutdown().unwrap();
    assert!(reopened
        .native_public_read(&|| Ok(()), |state, _| state
            .get_at(first.lease().key(), timestamp(3)))
        .is_err());
}

#[test]
fn native_public_restore_filtered_progress_and_stale_revision_match_original_page_limits() {
    let fixture = Fixture::new();
    let first = fenced_transition_v2_request(0xB2, 1, "native-filtered-restore-first");
    fixture.parity(&[formation(), activation(1, first.clone(), timestamp(1))]);
    let entries = (0..16)
        .map(|batch| {
            let requests = (0..256)
                .map(|slot| {
                    sdk741_component_request(Sdk741Payload::Create, 102 + batch, slot, None)
                })
                .collect();
            fenced_transition_v2_batch_entry(2 + batch, requests, timestamp(2))
        })
        .collect::<Vec<_>>();
    fixture.parity(&entries);
    let scope = RestoreScanScope {
        owner: Some(OwnerId::new("unrepresented-restore-owner").unwrap()),
        ..RestoreScanScope::all()
    };
    let request = RestoreScanRequest {
        scope,
        cursor: None,
        limit: 1,
    };
    let first_page = scan(&fixture.wal, request.clone(), timestamp(3)).unwrap();
    assert_eq!(
        first_page,
        sql_scan(&fixture.oracle, request.clone(), timestamp(3)).unwrap()
    );
    assert!(first_page.records.is_empty());
    assert_eq!(
        first_page.excluded_count,
        crate::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
    );
    assert!(!first_page.complete);
    let request = RestoreScanRequest {
        cursor: first_page.next_cursor,
        ..request
    };
    let last = scan(&fixture.wal, request.clone(), timestamp(3)).unwrap();
    assert_eq!(
        last,
        sql_scan(&fixture.oracle, request.clone(), timestamp(3)).unwrap()
    );
    assert!(last.complete);
    assert_eq!(last.excluded_count, 1);
    let new_record = sdk741_component_request(Sdk741Payload::Create, 150, 0, None);
    fixture.parity(&[fenced_transition_v2_entry(18, new_record, timestamp(4))]);
    assert_eq!(
        scan(&fixture.wal, request.clone(), timestamp(4)),
        Err(StoreError::RestoreScanCursorStale)
    );
    assert_eq!(
        sql_scan(&fixture.oracle, request, timestamp(4)),
        Err(StoreError::RestoreScanCursorStale)
    );
}
