use super::*;
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

#[test]
fn native_scratch_large_decoders_wait_without_reserving_and_small_work_proceeds() {
    static GATE: LargeLogGate = LargeLogGate::new();
    static USED: AtomicUsize = AtomicUsize::new(0);
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);
    const CHARGE: usize = 80 * 1024 * 1024;
    let reserve =
        |bytes| VerificationMemory::reserve_for_test(&USED, bytes, PROCESS_VERIFICATION_BYTES);
    let first = LogMemory::reserve_with(&GATE, CHARGE, &|| Ok(()), reserve).unwrap();
    let (send, waiting) = mpsc::channel();
    let workers = (0..4)
        .map(|_| {
            let send = send.clone();
            std::thread::spawn(move || {
                let checks = Cell::new(0);
                let _memory = LogMemory::reserve_with(
                    &GATE,
                    CHARGE,
                    &|| {
                        checks.set(checks.get() + 1);
                        if checks.get() == 3 {
                            // reserve_with's first check and acquire's first
                            // iteration preceded an actual condition wait.
                            send.send(()).unwrap();
                        }
                        Ok(())
                    },
                    reserve,
                )?;
                PEAK.fetch_max(ACTIVE.fetch_add(1, Ordering::AcqRel) + 1, Ordering::AcqRel);
                std::thread::yield_now();
                ACTIVE.fetch_sub(1, Ordering::AcqRel);
                Ok::<_, io::Error>(())
            })
        })
        .collect::<Vec<_>>();
    drop(send);
    let observed = (0..4)
        .map(|_| waiting.recv_timeout(Duration::from_secs(2)))
        .collect::<Result<Vec<_>, _>>();
    let used_while_waiting = USED.load(Ordering::Acquire);
    let small = LogMemory::reserve_with(&GATE, 64 * 1024, &|| Ok(()), reserve);
    let used_with_small = USED.load(Ordering::Acquire);
    drop(small);
    drop(first);
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join())
        .collect::<Vec<_>>();
    assert!(
        observed.is_ok(),
        "all decoders must reach the occupied admission wait"
    );
    assert_eq!(used_while_waiting, CHARGE);
    assert_eq!(used_with_small, CHARGE + 64 * 1024);
    for outcome in outcomes {
        outcome.unwrap().unwrap();
    }
    assert_eq!(PEAK.load(Ordering::Acquire), 1);
    assert_eq!(USED.load(Ordering::Acquire), 0);
}

#[test]
fn native_scratch_large_admission_honors_cancellation_before_and_during_wait() {
    static GATE: LargeLogGate = LargeLogGate::new();
    static USED: AtomicUsize = AtomicUsize::new(0);
    const CHARGE: usize = 80 * 1024 * 1024;
    let reserved = Cell::new(false);
    assert!(LogMemory::reserve_with(
        &GATE,
        CHARGE,
        &|| Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")),
        |bytes| {
            reserved.set(true);
            VerificationMemory::reserve_for_test(&USED, bytes, PROCESS_VERIFICATION_BYTES)
        },
    )
    .is_err());
    assert!(!reserved.get());
    let first = LogMemory::reserve_with(&GATE, CHARGE, &|| Ok(()), |bytes| {
        VerificationMemory::reserve_for_test(&USED, bytes, PROCESS_VERIFICATION_BYTES)
    })
    .unwrap();
    let checks = Cell::new(0);
    let cancelled = LogMemory::reserve_with(
        &GATE,
        CHARGE,
        &|| {
            checks.set(checks.get() + 1);
            if checks.get() == 3 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled while waiting",
                ))
            } else {
                Ok(())
            }
        },
        |bytes| {
            reserved.set(true);
            VerificationMemory::reserve_for_test(&USED, bytes, PROCESS_VERIFICATION_BYTES)
        },
    );
    assert_eq!(cancelled.err().unwrap().kind(), io::ErrorKind::Interrupted);
    assert!(!reserved.get());
    assert_eq!(USED.load(Ordering::Acquire), CHARGE);
    assert!(*GATE.busy.lock().unwrap());
    drop(first);
    assert_eq!(USED.load(Ordering::Acquire), 0);
    assert!(!*GATE.busy.lock().unwrap());
}

#[test]
fn native_scratch_large_decoder_destroys_temporaries_before_refund_on_all_exits() {
    static GATE: LargeLogGate = LargeLogGate::new();
    static USED: AtomicUsize = AtomicUsize::new(0);
    const CHARGE: usize = 80 * 1024 * 1024;
    struct Owned<'a>(&'a Cell<bool>);
    impl Drop for Owned<'_> {
        fn drop(&mut self) {
            assert_eq!(USED.load(Ordering::Acquire), CHARGE);
            assert!(*GATE.busy.lock().unwrap());
            self.0.set(true);
        }
    }
    for exit in 0..4 {
        let dropped = Cell::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| {
            super::super::run_reserved(
                CHARGE,
                &|| {
                    if exit == 3 && dropped.get() {
                        return Err(io::Error::other("cancelled after decoding"));
                    }
                    Ok(())
                },
                |bytes| {
                    LogMemory::reserve_with(&GATE, bytes, &|| Ok(()), |bytes| {
                        VerificationMemory::reserve_for_test(
                            &USED,
                            bytes,
                            PROCESS_VERIFICATION_BYTES,
                        )
                    })
                },
                || {
                    let _owned = Owned(&dropped);
                    match exit {
                        1 => Err(io::Error::other("decoder rejected bytes")),
                        2 => panic!("decoder unwind"),
                        _ => Ok(()),
                    }
                },
            )
        }));
        assert!(dropped.get());
        assert_eq!(USED.load(Ordering::Acquire), 0);
        assert!(!*GATE.busy.lock().unwrap());
        match exit {
            0 => result.unwrap().unwrap(),
            1 | 3 => assert!(result.unwrap().is_err()),
            _ => assert!(result.is_err()),
        }
    }
}

#[test]
fn native_scratch_large_admission_preserves_global_denial_and_releases_failed_permit() {
    static GATE: LargeLogGate = LargeLogGate::new();
    static USED: AtomicUsize = AtomicUsize::new(0);
    let other =
        VerificationMemory::reserve_for_test(&USED, 100 * 1024 * 1024, PROCESS_VERIFICATION_BYTES)
            .unwrap();
    let reserve =
        |bytes| VerificationMemory::reserve_for_test(&USED, bytes, PROCESS_VERIFICATION_BYTES);
    assert!(LogMemory::reserve_with(&GATE, 80 * 1024 * 1024, &|| Ok(()), reserve).is_err());
    assert!(!*GATE.busy.lock().unwrap());
    assert_eq!(USED.load(Ordering::Acquire), 100 * 1024 * 1024);
    drop(other);
    let next = LogMemory::reserve_with(&GATE, 80 * 1024 * 1024, &|| Ok(()), reserve).unwrap();
    drop(next);
    assert_eq!(USED.load(Ordering::Acquire), 0);
}

#[test]
fn native_scratch_retained_log_copy_releases_admission_but_keeps_its_memory_charge() {
    static GATE: LargeLogGate = LargeLogGate::new();
    static USED: AtomicUsize = AtomicUsize::new(0);
    const CHARGE: usize = 80 * 1024 * 1024;
    let reserve =
        |bytes| VerificationMemory::reserve_for_test(&USED, bytes, PROCESS_VERIFICATION_BYTES);
    let mut memory = LogMemory::reserve_with(&GATE, CHARGE, &|| Ok(()), reserve).unwrap();
    assert!(memory.shrink_to(CHARGE + 1).is_err());
    assert_eq!(USED.load(Ordering::Acquire), CHARGE);
    assert!(*GATE.busy.lock().unwrap());
    memory.shrink_to(64 * 1024).unwrap();
    let retained = memory.into_memory();
    assert!(!*GATE.busy.lock().unwrap());
    assert_eq!(USED.load(Ordering::Acquire), 64 * 1024);
    let next = LogMemory::reserve_with(&GATE, CHARGE, &|| Ok(()), reserve).unwrap();
    assert_eq!(USED.load(Ordering::Acquire), CHARGE + 64 * 1024);
    drop(next);
    assert_eq!(USED.load(Ordering::Acquire), 64 * 1024);
    drop(retained);
    assert_eq!(USED.load(Ordering::Acquire), 0);
}
