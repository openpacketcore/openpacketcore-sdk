use super::*;

fn admitted_attempt() -> (
    tokio::runtime::Runtime,
    Arc<ReconnectGate>,
    ReconnectAttempt,
    tokio::time::Instant,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("admitting runtime");
    let policy = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(1),
        Duration::from_millis(10),
        Duration::from_millis(80),
        Duration::ZERO,
    )
    .expect("bounded lifecycle");
    let gate = ReconnectGate::new(policy);
    let (attempt, now) = runtime.block_on(async {
        let now = tokio::time::Instant::now();
        let attempt = gate
            .acquire(now + Duration::from_secs(1), 0, None)
            .await
            .expect("first attempt");
        (attempt, now)
    });
    (runtime, gate, attempt, now)
}

fn assert_cooldown(
    runtime: &tokio::runtime::Runtime,
    gate: &Arc<ReconnectGate>,
    failed_at: tokio::time::Instant,
) {
    assert_eq!(
        gate.state.lock().expect("gate state").next_attempt_at,
        Some(failed_at + Duration::from_millis(10)),
        "failure publication uses the admitting clock"
    );
    runtime.block_on(async {
        assert_eq!(tokio::time::Instant::now(), failed_at);
        let retry = gate.acquire(failed_at + Duration::from_secs(1), 0, None);
        tokio::pin!(retry);
        assert!(futures_util::poll!(&mut retry).is_pending());
        tokio::time::advance(Duration::from_millis(9)).await;
        assert!(futures_util::poll!(&mut retry).is_pending());
        tokio::time::advance(Duration::from_millis(1)).await;
        retry
            .await
            .expect("retry at exact cooldown expiry")
            .succeeded();
    });
    assert_eq!(gate.serial.available_permits(), 1);
    assert_eq!(gate.state.lock().expect("gate state").next_attempt_at, None);
}

#[test]
fn failed_and_cancelled_attempts_keep_the_admitting_clock_on_another_thread() {
    for explicit_failure in [false, true] {
        let (runtime, gate, attempt, now) = admitted_attempt();
        std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            std::thread::sleep(Duration::from_millis(50));
            if explicit_failure {
                attempt.failed();
            } else {
                drop(attempt);
            }
            assert!(tokio::runtime::Handle::try_current().is_err());
        })
        .join()
        .expect("failure outside a runtime");
        assert_cooldown(&runtime, &gate, now);
    }
}

#[test]
fn failed_and_cancelled_attempts_keep_the_admitting_clock_inside_another_runtime() {
    for explicit_failure in [false, true] {
        let (runtime, gate, attempt, now) = admitted_attempt();
        let other = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("different runtime");
        other.block_on(async {
            tokio::time::advance(Duration::from_secs(1)).await;
            let foreign_now = tokio::time::Instant::now();
            assert!(foreign_now > now + Duration::from_millis(10));
            if explicit_failure {
                attempt.failed();
            } else {
                drop(attempt);
            }
            assert_eq!(tokio::time::Instant::now(), foreign_now);
        });
        assert_cooldown(&runtime, &gate, now);
    }
}

fn drop_after_thread_local_teardown(attempt: ReconnectAttempt, handle: tokio::runtime::Handle) {
    struct ThreadExitAttempt {
        attempt: Option<ReconnectAttempt>,
        result: std::sync::mpsc::Sender<(bool, bool)>,
    }

    impl Drop for ThreadExitAttempt {
        fn drop(&mut self) {
            let destroyed = tokio::runtime::Handle::try_current()
                .is_err_and(|error| error.is_thread_local_destroyed());
            let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(self.attempt.take());
            }));
            let _ = self.result.send((destroyed, dropped.is_ok()));
        }
    }

    thread_local! {
        static AT_THREAD_EXIT: std::cell::RefCell<Option<ThreadExitAttempt>> =
            const { std::cell::RefCell::new(None) };
    }
    let (result, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Reverse destructor order puts our Drop after Tokio's context.
        AT_THREAD_EXIT.with(|slot| {
            *slot.borrow_mut() = Some(ThreadExitAttempt {
                attempt: Some(attempt),
                result,
            });
        });
        drop(handle.enter());
    })
    .join()
    .expect("no uncaught destructor panic");
    let (destroyed, dropped) = received.recv().expect("thread-local destructor ran");
    assert!(destroyed, "fixture runs after Tokio context destruction");
    assert!(
        dropped,
        "reconnect cancellation must not panic during teardown"
    );
}

#[test]
fn thread_local_teardown_publishes_cooldown_before_releasing_admission() {
    let (runtime, gate, attempt, now) = admitted_attempt();
    drop_after_thread_local_teardown(attempt, runtime.handle().clone());
    assert_eq!(
        gate.serial.available_permits(),
        0,
        "admission stays held until the owning runtime publishes the cooldown"
    );
    runtime.block_on(async {
        let published = Arc::clone(&gate.serial)
            .acquire_owned()
            .await
            .expect("cooldown publication releases the original permit");
        assert_eq!(tokio::time::Instant::now(), now);
        drop(published);
    });
    assert_cooldown(&runtime, &gate, now);
}

#[test]
fn thread_local_teardown_after_runtime_shutdown_releases_admission() {
    let (runtime, gate, attempt, _now) = admitted_attempt();
    let handle = runtime.handle().clone();
    drop(runtime);
    drop_after_thread_local_teardown(attempt, handle);
    assert_eq!(
        gate.serial.available_permits(),
        1,
        "a stopped executor cannot retain pending reconnect admission"
    );
}
