use super::election_progress::wait;
use std::time::Duration;
use tokio::sync::watch;

async fn next_term(mut terms: watch::Receiver<u64>, previous: u64) -> u64 {
    let term = *terms.wait_for(|term| *term > previous).await.unwrap();
    term
}

#[tokio::test(start_paused = true)]
async fn unchanged_term_publications_do_not_extend_the_watchdog() {
    let bound = Duration::from_secs(26);
    let (published, terms) = watch::channel(7);
    let wait = wait(bound, 7, std::future::pending::<()>(), |term| {
        next_term(terms.clone(), term)
    });
    tokio::pin!(wait);
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(10)).await;
        published.send_replace(7);
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
    }
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(wait.await.is_err());
}

#[tokio::test(start_paused = true)]
async fn higher_terms_preserve_the_interval_without_a_total_retry_ceiling() {
    let bound = Duration::from_secs(26);
    let (published, terms) = watch::channel(1);
    let (done, completion) = tokio::sync::oneshot::channel();
    let wait = wait(bound, 1, completion, |term| next_term(terms.clone(), term));
    tokio::pin!(wait);
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    for term in 2..=4 {
        tokio::time::advance(bound - Duration::from_secs(1)).await;
        published.send_replace(term);
        assert!(futures_util::poll!(wait.as_mut()).is_pending());
    }
    done.send(17).unwrap();
    assert_eq!(wait.await.unwrap().unwrap(), 17);
}

#[tokio::test(start_paused = true)]
async fn a_stalled_later_term_expires_at_the_same_watchdog_interval() {
    let bound = Duration::from_secs(26);
    let (published, terms) = watch::channel(1);
    let wait = wait(bound, 1, std::future::pending::<()>(), |term| {
        next_term(terms.clone(), term)
    });
    tokio::pin!(wait);
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    tokio::time::advance(bound - Duration::from_secs(1)).await;
    published.send_replace(2);
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    tokio::time::advance(bound - Duration::from_secs(1)).await;
    assert!(futures_util::poll!(wait.as_mut()).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(wait.await.is_err());
}
