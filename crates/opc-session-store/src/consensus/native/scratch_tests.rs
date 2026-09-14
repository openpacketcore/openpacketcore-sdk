use super::*;
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};

#[test]
fn native_scratch_denial_and_precancel_precede_verification_allocation() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    let entered = Cell::new(false);
    let reserved = Cell::new(false);
    let result = run_reserved(
        17,
        &|| Ok(()),
        |bytes| {
            reserved.set(true);
            VerificationMemory::reserve_for_test(&USED, bytes, 16)
        },
        || {
            entered.set(true);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(reserved.get());
    assert!(!entered.get());
    assert_eq!(USED.load(Ordering::Acquire), 0);
    reserved.set(false);
    assert!(run_reserved(
        1,
        &|| Err(invalid("cancelled")),
        |bytes| {
            reserved.set(true);
            VerificationMemory::reserve_for_test(&USED, bytes, 16)
        },
        || {
            entered.set(true);
            Ok(())
        }
    )
    .is_err());
    assert!(!reserved.get());
    assert!(!entered.get());
}

#[test]
fn native_scratch_frees_owned_temporary_before_refund_on_every_exit() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    struct Owned<'a> {
        bytes: Option<Vec<u8>>,
        dropped: &'a Cell<bool>,
    }
    impl Drop for Owned<'_> {
        fn drop(&mut self) {
            drop(self.bytes.take());
            assert_eq!(USED.load(Ordering::Acquire), 8192);
            self.dropped.set(true);
        }
    }
    for exit in [0, 1, 2, 3] {
        let dropped = Cell::new(false);
        let checks = Cell::new(0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            run_reserved(
                8192,
                &|| {
                    checks.set(checks.get() + 1);
                    if checks.get() == 2 {
                        assert!(dropped.get(), "worker temporary must precede post-check");
                        assert_eq!(USED.load(Ordering::Acquire), 8192);
                        if exit == 2 {
                            return Err(invalid("cancelled after row"));
                        }
                    }
                    Ok(())
                },
                |bytes| VerificationMemory::reserve_for_test(&USED, bytes, 8192),
                || {
                    let _owned = Owned {
                        bytes: Some(vec![0; 8192]),
                        dropped: &dropped,
                    };
                    match exit {
                        1 => Err(invalid("decoder failure")),
                        3 => panic!("decoder unwind"),
                        _ => Ok(()),
                    }
                },
            )
        }));
        match exit {
            0 => assert!(result.unwrap().is_ok()),
            1 | 2 => assert!(result.unwrap().is_err()),
            _ => assert!(result.is_err()),
        }
        assert!(dropped.get());
        assert_eq!(USED.load(Ordering::Acquire), 0);
    }
}

#[test]
fn native_scratch_concurrent_voters_share_one_reservation_and_join_before_reuse() {
    static USED: AtomicUsize = AtomicUsize::new(0);
    const LIMIT: usize = 128 * 1024 * 1024;
    const CHARGE: usize = 48 * 1024 * 1024;
    let release = Arc::new(Barrier::new(3));
    let (send, ready) = mpsc::channel();
    let workers = (0..2)
        .map(|voter| {
            let release = Arc::clone(&release);
            let send = send.clone();
            std::thread::spawn(move || {
                run_reserved(
                    CHARGE,
                    &|| Ok(()),
                    |bytes| VerificationMemory::reserve_for_test(&USED, bytes, LIMIT),
                    || {
                        send.send(voter).unwrap();
                        release.wait();
                        Ok(())
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    drop(send);
    assert_ne!(ready.recv().unwrap(), ready.recv().unwrap());
    assert_eq!(USED.load(Ordering::Acquire), 2 * CHARGE);
    let entered = Cell::new(false);
    let denied = run_reserved(
        CHARGE,
        &|| Ok(()),
        |bytes| VerificationMemory::reserve_for_test(&USED, bytes, LIMIT),
        || {
            entered.set(true);
            Ok(())
        },
    );
    // Always release and join before assertions could unwind the owner.
    release.wait();
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
    assert!(denied.is_err());
    assert!(!entered.get());
    assert_eq!(USED.load(Ordering::Acquire), 0);
    run_reserved(
        CHARGE,
        &|| Ok(()),
        |bytes| VerificationMemory::reserve_for_test(&USED, bytes, LIMIT),
        || {
            entered.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(entered.get());
    assert_eq!(USED.load(Ordering::Acquire), 0);
}

#[test]
fn native_scratch_production_path_uses_existing_global_budget() {
    small(&|| Ok(()), || {
        // Do not fill the shared budget or interfere with parallel tests.
        // A full-budget request must fail while this real guard is alive.
        assert!(VerificationMemory::reserve(128 * 1024 * 1024).is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn native_scratch_original_row_and_public_batch_bounds_fit_without_new_caps() {
    let row_limit = crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES;
    let batch_limit = MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS;
    assert_eq!(row_limit, 16 * 1024 * 1024);
    assert_eq!(batch_limit, 256);
    // Even this conservative combination (larger than the binary batch
    // profile actually permits) fits one available process budget.
    let bytes = log_peak(row_limit, batch_limit, row_limit / 2).unwrap();
    assert!(bytes < 128 * 1024 * 1024);
    assert!(log_peak(usize::MAX, 1, 0).is_err());
    assert!(log_peak(1, usize::MAX, 0).is_err());
    assert!(log_peak(1, 1, usize::MAX).is_err());
}
