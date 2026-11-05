//! Keep functional consensus work and supervised requests on the same clock.

use std::future::Future;

use super::*;

/// Pause the current-thread fixture runtime, including its existing logical
/// read supervisor. Moving only the caller to another paused runtime would
/// leave that supervisor comparing the caller's deadline to advancing time.
pub(super) async fn with_paused_protocol_time<F: Future>(operation: F) -> F::Output {
    struct ResumeTime;

    impl Drop for ResumeTime {
        fn drop(&mut self) {
            tokio::time::resume();
        }
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    let (release, held) = std::sync::mpsc::channel::<()>();
    // As in the shared controlled-clock fixture, a blocking watchdog both
    // bounds real I/O and inhibits automatic protocol-clock advancement.
    let mut watchdog = tokio::task::spawn_blocking(move || {
        held.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    });
    tokio::time::pause();
    let resume = ResumeTime;
    let result = tokio::select! {
        biased;
        result = operation => result,
        expired = &mut watchdog => {
            let _ = expired.expect("consensus fixture watchdog task");
            panic!("consensus fixture wall-clock watchdog expired");
        }
    };
    assert!(
        Instant::now() <= deadline,
        "consensus fixture completed after its wall-clock watchdog"
    );
    drop(resume);
    drop(release);
    let _ = watchdog.await.expect("retire consensus fixture watchdog");
    result
}

#[tokio::test]
async fn logical_read_still_expires_at_its_original_protocol_deadline() {
    let cluster = TestCluster::start().await;
    let key = session_key(b"late-result-read-deadline");
    let (leader, _, _) = cluster.observed_leader();
    let source = (leader + 1) % MEMBER_COUNT;
    let forwards_before = cluster.forward_mutation_calls(source);
    with_paused_protocol_time(async {
        let started = tokio::time::Instant::now();
        let read = cluster.stores[source].get(&key);
        tokio::pin!(read);
        assert!(
            futures_util::poll!(&mut read).is_pending(),
            "the read is admitted before its deadline advances"
        );
        tokio::time::advance(OPERATION_TIMEOUT).await;
        assert_eq!(started.elapsed(), OPERATION_TIMEOUT);
        assert!(
            matches!(read.await, Err(StoreError::BackendUnavailable(_))),
            "the original complete read deadline still rejects queued work"
        );
        assert_eq!(
            cluster.forward_mutation_calls(source),
            forwards_before,
            "an expired queued read cannot receive a fresh proposal budget"
        );
    })
    .await;
}
