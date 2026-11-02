//! Coordinator wait protocols, with a RED-only escape for the original hangs.

use super::*;
use std::sync::mpsc::{self, Receiver};

#[derive(Default)]
struct Pause {
    released: Mutex<bool>,
    changed: Condvar,
}
impl Pause {
    fn wait(&self) {
        drop(
            self.changed
                .wait_while(self.released.lock().unwrap(), |released| !*released)
                .unwrap(),
        );
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

fn completion<T>(receiver: &Receiver<T>) -> Option<T> {
    if std::env::var_os("OPC_SESSION_STORE_HANG_ESCAPE").is_some() {
        // Only the pre-fix RED invocation enables this generous escape. GREEN
        // execution receives the completion event without a time assertion.
        receiver.recv_timeout(Duration::from_secs(10)).ok()
    } else {
        Some(receiver.recv().unwrap())
    }
}

fn head() -> PrefixIdentity {
    PrefixIdentity {
        binding: [1; 32],
        file_epoch: 2,
        checkpoint_epoch: 9,
        operation_sequence: 4,
        frontiers: [2; 32],
        length: 4 * 65536,
        block_bytes: 65536,
        digest: [3; 32],
    }
}

#[test]
fn native_rollover_coordinator_cancel_cannot_land_before_wait_registration() {
    let mut failures = Vec::new();
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let signal = Coordinator::new();
        let pause = Arc::new(Pause::default());
        let (events, observed) = mpsc::channel();
        *signal.probe.lock().unwrap() = Some(Arc::new({
            let pause = Arc::clone(&pause);
            move |point| {
                events.send(point).unwrap();
                if matches!(point, ProbePoint::BeforeTakeWait) {
                    pause.wait();
                }
            }
        }));
        let (done, completed) = mpsc::channel();
        let worker_signal = Arc::clone(&signal);
        let worker = std::thread::spawn(move || {
            let error = worker_signal.wait_take(head(), &|| Ok(())).err().unwrap();
            done.send(is_cancelled(&error)).unwrap();
        });
        assert!(matches!(
            observed.recv().unwrap(),
            ProbePoint::BeforeTakeWait
        ));
        let cancelling = Arc::clone(&signal);
        let canceller = std::thread::spawn(move || cancelling.cancel());
        // Old code publishes and notifies while the waiter still owns work.
        // Fixed code observes contention before acquiring that same mutex;
        // only then may the waiter atomically release it and register sleep.
        let ordering = observed.recv().unwrap();
        assert!(matches!(
            ordering,
            ProbePoint::CancelLockContended | ProbePoint::AfterCancelNotify
        ));
        pause.release();
        let result = completion(&completed);
        if result.is_none() {
            failures.push(format!(
                "{mode:?}: cancellation notified before wait registration"
            ));
            signal.changed.notify_all(); // RED cleanup only; never a success witness.
            assert!(completed.recv().unwrap());
        } else {
            assert_eq!(result, Some(true));
        }
        canceller.join().unwrap();
        worker.join().unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn native_rollover_coordinator_capacity_restart_returns_to_its_owner() {
    let mut failures = Vec::new();
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for live_context in [None, Some(head().frontiers)] {
            let signal = Coordinator::new();
            let pause = Arc::new(Pause::default());
            let (events, observed) = mpsc::channel();
            *signal.probe.lock().unwrap() = Some(Arc::new({
                let pause = Arc::clone(&pause);
                move |point| {
                    if matches!(point, ProbePoint::BeforeTakeWait) {
                        events.send(()).unwrap();
                        pause.wait();
                    }
                }
            }));
            let (done, completed) = mpsc::channel();
            let waiting = Arc::clone(&signal);
            let worker = std::thread::spawn(move || {
                done.send(
                    waiting
                        .wait_take(head(), &|| Ok(()))
                        .map(|value| value.is_none()),
                )
                .unwrap();
            });
            observed.recv().unwrap();
            pause.release();
            {
                // This is the exact scheduling transition published by a failed
                // candidate rebase, independently of the capacity arithmetic.
                let mut work = signal.work.lock().unwrap();
                let mut older = head();
                older.checkpoint_epoch -= 1;
                work.restart_after = Some(older);
                work.live_context = live_context;
                work.active = false;
                work.finished = true;
                signal.changed.notify_all();
            }
            let result = completion(&completed);
            if let Some(result) = result {
                assert_eq!(result.unwrap(), live_context.is_some());
            } else {
                failures.push(format!(
                    "{mode:?}, live_context={}: finished restart cannot return owner control",
                    live_context.is_some()
                ));
                signal.cancel();
                assert!(completed.recv().unwrap().is_err());
            }
            worker.join().unwrap();
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn native_rollover_cancelled_join_clears_the_previous_attempt_lifecycle() {
    let mut failures = Vec::new();
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let signal = Coordinator::new();
        {
            let mut work = signal.work.lock().unwrap();
            work.restart_after = Some(head());
            work.live_context = Some(head().frontiers);
            work.error = Some(Failure {
                kind: io::ErrorKind::Other,
                message: "previous attempt".into(),
                cancelled: true,
            });
            work.stop = true;
            work.attempt_file = head().file_epoch;
            work.attempts = 3;
        }
        let mut job = Job {
            worker: Some(std::thread::spawn(|| ())),
            owned: PathBuf::from("unused-test-preparing-name"),
            signal: Arc::clone(&signal),
        };
        job.cancel_and_join().unwrap();
        let work = signal.work.lock().unwrap();
        if work.restart_after.is_some()
            || work.live_context.is_some()
            || work.error.is_some()
            || work.stop
            || signal.cancel.load(Ordering::Acquire)
        {
            failures.push(format!(
                "{mode:?}: cancelled attempt lifecycle survived join"
            ));
        }
        assert!(job.worker.is_none());
        assert_eq!(work.attempt_file, head().file_epoch);
        assert_eq!(
            work.attempts, 3,
            "cancellation must retain attempt accounting for pending recovery"
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn native_rollover_durable_restart_wait_returns_a_completed_capacity_outcome() {
    let mut failures = Vec::new();
    for older in [false, true] {
        let signal = Coordinator::new();
        {
            // A new attempt may already have finished Full before the previous
            // restart waiter registers. Neither that terminal outcome nor an
            // older full base with identical context needs another selected cut.
            let mut work = signal.work.lock().unwrap();
            let mut after = head();
            if older {
                after.checkpoint_epoch -= 1;
            }
            work.finished = true;
            work.active = false;
            work.restart_after = Some(after);
            work.live_context = Some(head().frontiers);
            work.attempt_file = head().file_epoch;
            work.attempts = 2;
        }
        let waiting = Arc::clone(&signal);
        let (done, received) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            done.send(waiting.wait_restart(head(), &|| Ok(()))).unwrap();
        });
        let result = completion(&received);
        if let Some(result) = result {
            result.unwrap();
        } else {
            failures.push(format!(
                "older={older}: completed Full outcome still waits for a restart"
            ));
            signal.cancel();
            assert!(received.recv().unwrap().is_err());
        }
        worker.join().unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
