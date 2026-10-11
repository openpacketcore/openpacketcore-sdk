//! Functional protocol time, with a separate watchdog for real I/O and scheduling.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use futures_util::FutureExt;

/// Open stores on the caller's runtime, then invoke an operation once on a
/// paused clock. Deadline controls may advance that clock explicitly. The
/// operation retains its production timeout; this is not a latency test.
///
/// Accepted tasks can outlive their caller. After the operation returns, panics,
/// or is cancelled, resume time and join all tasks this scope owns before its
/// runtime exits. The same wall-clock watchdog bounds both phases.
pub(crate) async fn run<F>(operation: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let deadline = Instant::now() + Duration::from_secs(30);
    let (lifetime, cancelled) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("test operation runtime");
        runtime.block_on(async move {
            let (release, held) = std::sync::mpsc::channel::<()>();
            // The blocking task also inhibits automatic protocol-clock advance.
            let mut watchdog = tokio::task::spawn_blocking(move || {
                held.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            });
            let (result, mut watchdog_finished) = tokio::select! {
                biased;
                _ = cancelled => (Err("test operation caller was cancelled"), false),
                result = AssertUnwindSafe(operation).catch_unwind() => (Ok(result), false),
                expired = &mut watchdog => {
                    let _ = expired.expect("test operation watchdog task");
                    (Err("test operation wall-clock watchdog expired"), true)
                }
            };
            tokio::time::resume();
            if !watchdog_finished {
                let joined = tokio::select! {
                    () = async {
                        // This isolated current-thread runtime counts exactly
                        // its spawned async tasks, excluding this root future
                        // and the blocking watchdog.
                        while tokio::runtime::Handle::current().metrics().num_alive_tasks() != 0 {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    } => true,
                    expired = &mut watchdog => {
                        let _ = expired.expect("test operation drain watchdog");
                        watchdog_finished = true;
                        false
                    }
                };
                assert!(joined, "accepted test operation tasks did not finish");
            }
            drop(release);
            if !watchdog_finished {
                let _ = watchdog.await.expect("retire test operation watchdog");
            }
            result
        })
    });
    let result = task.await.expect("test operation task");
    drop(lifetime);
    match result.expect("complete test operation") {
        Ok(output) => output,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepted_task_outlives_return_until_its_real_completion() {
        let (entered, started) = oneshot::channel();
        let (release, held) = oneshot::channel();
        let (completed, finished) = oneshot::channel();
        let scope = tokio::spawn(run(async move {
            tokio::spawn(async move {
                entered.send(()).unwrap();
                held.await.unwrap();
                completed.send(()).unwrap();
            });
            7
        }));
        started.await.unwrap();
        assert!(!scope.is_finished());
        release.send(()).unwrap();
        assert_eq!(scope.await.unwrap(), 7);
        finished.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_the_caller_does_not_cancel_its_accepted_task() {
        let (entered, started) = oneshot::channel();
        let (release, held) = oneshot::channel();
        let (completed, finished) = oneshot::channel();
        let scope = tokio::spawn(run(async move {
            tokio::spawn(async move {
                entered.send(()).unwrap();
                held.await.unwrap();
                completed.send(()).unwrap();
            });
            std::future::pending::<()>().await;
        }));
        started.await.unwrap();
        scope.abort();
        assert!(scope.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(30), finished)
            .await
            .unwrap()
            .unwrap();
    }
}
