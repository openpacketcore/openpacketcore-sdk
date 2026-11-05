//! Election acquisition has no fixed count of randomized split-vote retries.

use std::future::Future;
use std::time::Duration;

/// Retain the fixture's watchdog interval, restarting it only when a real
/// higher term is published. `next_term` waits for a term above its argument;
/// heartbeats, failed readiness probes and unchanged metrics are not progress.
/// The operation still has to establish its complete readiness predicate.
pub(crate) async fn wait<T, F, N, P>(
    watchdog: Duration,
    initial_term: u64,
    operation: F,
    mut next_term: N,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: Future<Output = T>,
    N: FnMut(u64) -> P,
    P: Future<Output = u64>,
{
    let mut highest_term = initial_term;
    let mut deadline = tokio::time::Instant::now() + watchdog;
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            result = operation.as_mut() => return Ok(result),
            term = tokio::time::timeout_at(deadline, next_term(highest_term)) => {
                let term = term?;
                if term > highest_term {
                    highest_term = term;
                    deadline = tokio::time::Instant::now() + watchdog;
                }
            }
        }
    }
}
