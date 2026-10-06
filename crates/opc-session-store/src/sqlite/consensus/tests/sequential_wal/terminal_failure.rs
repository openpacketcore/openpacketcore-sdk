use super::*;
use futures_util::FutureExt;
use std::sync::atomic::Ordering;

#[test]
fn terminal_failure_is_latched_for_early_late_and_cancelled_waiters() {
    let fixture = fixture();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut early = Box::pin(fixture.wal.terminal_failure());
        let mut other = Box::pin(fixture.wal.terminal_failure());
        assert!(early.as_mut().now_or_never().is_none());
        assert!(other.as_mut().now_or_never().is_none());
        assert!(fixture.wal.terminal_failure().now_or_never().is_none());
        fixture.wal.fence_for_test().unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(early, other);
            fixture.wal.terminal_failure().await;
            fixture.wal.fence_for_test().unwrap();
            fixture.wal.terminal_failure().await;
        })
        .await
        .expect("all waiters observe the same permanent fence");
    });
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn terminal_failure_stays_pending_after_successful_work_and_orderly_shutdown() {
    let fixture = fixture();
    fixture
        .wal
        .submit(Operation::Barrier)
        .unwrap()
        .wait()
        .unwrap();
    assert!(fixture.wal.terminal_failure().now_or_never().is_none());
    fixture.wal.shutdown().unwrap();
    assert!(fixture.wal.terminal_failure().now_or_never().is_none());
}

#[test]
fn terminal_failure_observes_writer_errors_and_unwind() {
    for (point, panic) in [
        (Point::BeforeGroup, false),
        (Point::BeforeIntent, false),
        (Point::BeforeDataSync, true),
    ] {
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fault = Arc::clone(&armed);
        let fixture = Fixture::new(
            Limits::default(),
            IoControl {
                hook: Arc::new(move |actual| {
                    if actual == point && fault.load(Ordering::SeqCst) {
                        assert!(!panic, "intentional terminal writer unwind");
                        return Err(io::Error::from(io::ErrorKind::StorageFull));
                    }
                    Ok(())
                }),
                ..IoControl::default()
            },
            None,
            true,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut pending = Box::pin(fixture.wal.terminal_failure());
            assert!(pending.as_mut().now_or_never().is_none());
            armed.store(true, Ordering::SeqCst);
            // BeforeGroup may fence immediately before admission, or after
            // this group's successful callback. Both are terminal paths.
            if let Ok(ticket) = fixture.wal.submit(Operation::Barrier) {
                let _ = ticket.wait();
            }
            tokio::time::timeout(Duration::from_secs(1), pending)
                .await
                .expect("writer failure wakes the registered observer");
            assert!(fixture.wal.terminal_failure().now_or_never().is_some());
        });
        assert!(fixture.wal.shutdown().is_err());
        if !panic {
            let failure = fixture.wal.storage_health().1.unwrap();
            assert_eq!(
                failure.stage,
                crate::SessionStorageFailureStage::Persistence
            );
            assert_eq!(failure.kind, crate::SessionStorageFailureKind::StorageFull);
        }
    }
}
