use super::*;

fn counters() -> (&'static AtomicUsize, &'static AtomicUsize) {
    (
        Box::leak(Box::new(AtomicUsize::new(0))),
        Box::leak(Box::new(AtomicUsize::new(0))),
    )
}

fn page(
    pages: &'static AtomicUsize,
    process: &'static AtomicUsize,
    bytes: usize,
) -> io::Result<JournalPageMemory> {
    JournalPageMemory::reserve_with(pages, bytes, |bytes| {
        VerificationMemory::reserve_for_test(process, bytes, PROCESS_VERIFICATION_BYTES)
    })
}

#[test]
fn journal_page_memory_preserves_both_limits_and_refunds_failed_admission() {
    let (pages, process) = counters();
    let first = page(pages, process, JOURNAL_PAGE_BYTES - 1).unwrap();
    let progress = VerificationMemory::reserve_for_test(
        process,
        PROCESS_VERIFICATION_BYTES - JOURNAL_PAGE_BYTES,
        PROCESS_VERIFICATION_BYTES,
    )
    .unwrap();
    let last = page(pages, process, 1).unwrap();
    assert_eq!(process.load(Ordering::Acquire), PROCESS_VERIFICATION_BYTES);
    assert!(page(pages, process, 1).is_err());
    drop(first);
    drop(last);
    assert_eq!(pages.load(Ordering::Acquire), 0);
    assert_eq!(
        process.load(Ordering::Acquire),
        PROCESS_VERIFICATION_BYTES - JOURNAL_PAGE_BYTES
    );
    drop(progress);
    let all = VerificationMemory::reserve_for_test(
        process,
        PROCESS_VERIFICATION_BYTES,
        PROCESS_VERIFICATION_BYTES,
    )
    .unwrap();
    assert!(page(pages, process, 1).is_err());
    assert_eq!(
        pages.load(Ordering::Acquire),
        0,
        "global denial refunds optional admission"
    );
    assert_eq!(process.load(Ordering::Acquire), PROCESS_VERIFICATION_BYTES);
    drop(all);
    let invoked = std::cell::Cell::new(false);
    for bytes in [JOURNAL_PAGE_BYTES + 1, usize::MAX] {
        assert!(JournalPageMemory::reserve_with(pages, bytes, |_| {
            invoked.set(true);
            Err(io::Error::other("not reached"))
        })
        .is_err());
    }
    assert!(
        !invoked.get(),
        "oversized pages cannot touch process admission"
    );
    drop(page(pages, process, JOURNAL_PAGE_BYTES).unwrap());
    assert_eq!(pages.load(Ordering::Acquire), 0);
    assert_eq!(process.load(Ordering::Acquire), 0);
}

#[test]
fn journal_page_memory_bounds_concurrent_reads_and_returns_every_guard() {
    let (pages, process) = counters();
    let barrier = std::sync::Barrier::new(9);
    let mut observed = (0, 0);
    let successes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = &barrier;
            handles.push(scope.spawn(move || {
                let admitted = page(pages, process, JOURNAL_PAGE_BYTES / 2);
                barrier.wait();
                barrier.wait();
                admitted.is_ok()
            }));
        }
        barrier.wait();
        observed = (
            pages.load(Ordering::Acquire),
            process.load(Ordering::Acquire),
        );
        barrier.wait();
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(successes, 2);
    assert_eq!(observed, (JOURNAL_PAGE_BYTES, JOURNAL_PAGE_BYTES));
    assert_eq!(pages.load(Ordering::Acquire), 0);
    assert_eq!(process.load(Ordering::Acquire), 0);
}

#[test]
fn journal_page_memory_refunds_unwinding_without_changing_process_cap() {
    let (pages, process) = counters();
    let outcome = std::panic::catch_unwind(|| {
        let _admitted = page(pages, process, JOURNAL_PAGE_BYTES).unwrap();
        panic!("injected journal read unwind");
    });
    assert!(outcome.is_err());
    assert_eq!(pages.load(Ordering::Acquire), 0);
    assert_eq!(process.load(Ordering::Acquire), 0);
    assert_eq!(PROCESS_VERIFICATION_BYTES, 128 * 1024 * 1024);
    assert_eq!(JOURNAL_PAGE_BYTES, 32 * 1024 * 1024);
}
