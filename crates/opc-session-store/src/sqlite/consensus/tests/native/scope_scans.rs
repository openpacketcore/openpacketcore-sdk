//! Real file-WAL ownership tests for retained coherent scope captures.

use super::*;
use std::cell::Cell;
use std::ops::Bound::Unbounded;

fn fixture() -> Fixture {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    fixture
}

fn open(wal: &Wal) -> crate::sqlite::consensus::wal::native::NativeScopeScan {
    wal.native_scope_capture(&|| Ok(()), |_| Ok(true))
        .unwrap()
        .unwrap()
}

fn cancelled() -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"))
}

#[test]
fn native_scope_scan_reserves_exact_cost_before_retaining_the_cut() {
    let fixture = fixture();
    let cost = fixture.wal.native_scope_cost(&|| Ok(())).unwrap();
    assert_eq!(
        cost,
        64 * 1024 + 2 * crate::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
        "scope preflight reserves context and bounded pages"
    );
    let charged = Cell::new(None);
    let scan = fixture
        .wal
        .native_scope_capture(&|| Ok(()), |bytes| {
            charged.set(Some(bytes));
            Ok(true)
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        charged.get(),
        Some(cost),
        "reservation must precede root retention"
    );
    assert!(
        scan.retained_bytes().unwrap() < cost,
        "the empty shared index's reachability is distinct from the page reservation"
    );
    assert_eq!(scan.applied(), Some(formation().log_id));
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
}

#[test]
fn native_scope_scan_refused_or_failed_reservation_keeps_no_capture() {
    let fixture = fixture();
    assert!(
        fixture
            .wal
            .native_scope_capture(&|| Ok(()), |_| Ok(false))
            .unwrap()
            .is_none(),
        "refused cost must not retain a capture"
    );
    assert!(fixture
        .wal
        .native_scope_capture(&|| Ok(()), |_| cancelled().map(|()| true))
        .is_err());
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
}

#[test]
fn native_scope_scan_cancelled_open_never_charges_or_returns_a_cut() {
    let fixture = fixture();
    assert!(
        fixture.wal.native_scope_cost(&cancelled).is_err(),
        "preflight must check cancellation"
    );
    let charged = Cell::new(false);
    assert!(fixture
        .wal
        .native_scope_capture(&cancelled, |_| {
            charged.set(true);
            Ok(true)
        })
        .is_err());
    assert!(!charged.get());
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
}

#[test]
fn native_scope_scan_shutdown_refuses_open_preflight_and_old_pages() {
    let fixture = fixture();
    let scan = open(&fixture.wal);
    fixture.wal.shutdown().unwrap();
    assert!(
        fixture.wal.native_scope_cost(&|| Ok(())).is_err(),
        "closed owner cannot quote a capture"
    );
    assert!(fixture
        .wal
        .native_scope_capture(&|| Ok(()), |_| Ok(true))
        .is_err());
    assert!(fixture
        .wal
        .native_scope_read(&scan, &|| Ok(()), |_, _| Ok(()))
        .is_err());
}

#[test]
fn native_scope_scan_rejects_a_different_wal_owner() {
    let first = fixture();
    let second = fixture();
    let scan = open(&first.wal);
    assert!(
        second
            .wal
            .native_scope_read(&scan, &|| Ok(()), |_, _| Ok(()))
            .is_err(),
        "another WAL cannot adopt a retained cut"
    );
    assert_eq!(second.wal.retirement_wait_state_for_test().unwrap().1, 0);
}

#[test]
fn native_scope_scan_page_takes_only_a_short_permit_and_releases_the_mutex() {
    let fixture = fixture();
    let scan = open(&fixture.wal);
    let rows = fixture
        .wal
        .native_scope_read(&scan, &|| Ok(()), |capture, check| {
            // This locks State again: page work must run outside that mutex.
            assert_eq!(
                fixture.wal.retirement_wait_state_for_test().unwrap().1,
                1,
                "page must hold one operation permit"
            );
            check()?;
            Ok(capture.records().range(Unbounded, Unbounded).count())
        })
        .unwrap();
    assert_eq!(rows, 0);
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
    assert_eq!(fixture.wal.native_sql_fallback_count().unwrap(), 0);
}

#[test]
fn native_scope_scan_page_checks_cancellation_before_and_after_work() {
    let fixture = fixture();
    let scan = open(&fixture.wal);
    let entered = Cell::new(false);
    assert!(
        fixture
            .wal
            .native_scope_read(&scan, &cancelled, |_, _| {
                entered.set(true);
                Ok(())
            })
            .is_err(),
        "cancelled page must not execute"
    );
    assert!(!entered.get());
    let done = Cell::new(false);
    let check = || if done.get() { cancelled() } else { Ok(()) };
    assert!(
        fixture
            .wal
            .native_scope_read(&scan, &check, |_, _| {
                done.set(true);
                Ok(())
            })
            .is_err(),
        "cancelled result must not escape"
    );
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
    assert!(
        fixture.wal.native_scope_cost(&|| Ok(())).is_ok(),
        "cancellation must not fence the backend"
    );
}

#[test]
fn native_scope_scan_install_admission_remains_cancellable_without_a_permit() {
    let fixture = fixture();
    let scan = open(&fixture.wal);
    fixture.wal.retirement_install_for_test(true).unwrap();
    let calls = Cell::new(0);
    let check = || {
        calls.set(calls.get() + 1);
        if calls.get() >= 3 {
            cancelled()
        } else {
            Ok(())
        }
    };
    let result = fixture.wal.native_scope_read(&scan, &check, |_, _| Ok(()));
    fixture.wal.retirement_install_for_test(false).unwrap();
    assert!(
        result.is_err(),
        "page must wait for installation or cancellation"
    );
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
    assert!(fixture
        .wal
        .native_scope_read(&scan, &|| Ok(()), |_, _| Ok(()))
        .is_ok());
}

#[test]
fn native_scope_scan_retains_applied_position_while_application_and_checkpoint_advance() {
    let fixture = fixture();
    let scan = open(&fixture.wal);
    let first = fenced_transition_v2_request(0xC7, 1, "retained-scope-ordinary-write");
    fixture.parity(&[activation(1, first, timestamp(1))]);
    fixture.wal.checkpoint().unwrap();
    let applied = fixture
        .wal
        .native_scope_read(&scan, &|| Ok(()), |capture, _| Ok(capture.applied()))
        .unwrap();
    assert_eq!(applied, Some(formation().log_id));
    assert_eq!(open(&fixture.wal).applied().unwrap().index, 1);
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
}

#[test]
fn native_scope_scan_item_errors_do_not_fence_the_backend_or_keep_permits() {
    let fixture = fixture();
    let scan = open(&fixture.wal);
    assert!(fixture
        .wal
        .native_scope_read(&scan, &|| Ok(()), |_, _| cancelled())
        .is_err());
    assert_eq!(fixture.wal.retirement_wait_state_for_test().unwrap().1, 0);
    assert!(fixture
        .wal
        .native_scope_read(&scan, &|| Ok(()), |_, _| Ok(()))
        .is_ok());
}
