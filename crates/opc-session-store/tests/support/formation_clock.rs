//! Keep functional fixture formation independent of host scheduling delays.

use std::future::Future;
#[path = "controlled_clock.rs"]
pub(crate) mod controlled_clock;

/// Poll only formation on a controlled clock, preserving the caller's runtime.
///
/// Open stores before calling this helper: their Raft and transport tasks must
/// remain on the original runtime. The helper calls the ordinary initializer
/// once, with its original operation timeout and authority checks. It must not
/// wrap tests of initialization deadlines or cold recovery.
pub(crate) async fn run<F>(formation: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    controlled_clock::run(formation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[tokio::test(start_paused = true)]
    async fn formation_clock_is_independent_of_the_callers_clock() {
        let (entered, started) = oneshot::channel();
        let (release, held) = oneshot::channel();
        let formation = tokio::spawn(run(async move {
            let before = tokio::time::Instant::now();
            entered.send(()).unwrap();
            held.await.unwrap();
            assert_eq!(tokio::time::Instant::now(), before);
        }));
        started.await.unwrap();

        let before = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(200)).await;
        assert_eq!(before.elapsed(), Duration::from_millis(200));
        assert!(!formation.is_finished());
        release.send(()).unwrap();
        formation.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_cancellation_drops_pending_formation() {
        struct Dropped(Option<oneshot::Sender<()>>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (entered, started) = oneshot::channel();
        let (dropped, finished) = oneshot::channel();
        let formation = tokio::spawn(run(async move {
            let _dropped = Dropped(Some(dropped));
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        tokio::time::timeout(Duration::from_secs(30), started)
            .await
            .expect("formation starts before the test watchdog")
            .unwrap();
        formation.abort();
        assert!(formation.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(30), finished)
            .await
            .expect("cancelled formation releases its resources")
            .unwrap();
    }
}
