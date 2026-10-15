//! Waits bounded by an absolute standard-clock deadline.

use std::future::Future;
use std::time::Instant;

pub(crate) async fn timeout<F: Future>(
    deadline: Instant,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    // Blocking I/O uses this same standard-clock deadline. Tokio's clock can
    // advance independently, so carry only the remaining duration across the
    // boundary, without granting another full operation budget.
    tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), future).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn advanced_tokio_clock_preserves_standard_clock_budget() {
        tokio::time::advance(Duration::from_secs(60)).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        let result = timeout(deadline, async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            42
        })
        .await;
        assert_eq!(result.expect("unexpired standard-clock budget"), 42);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_standard_clock_budget_does_not_wait_for_pending_work() {
        tokio::time::advance(Duration::from_secs(60)).await;
        let deadline = Instant::now() - Duration::from_secs(1);
        assert!(timeout(deadline, std::future::pending::<()>())
            .await
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn remaining_budget_still_bounds_pending_work() {
        tokio::time::advance(Duration::from_secs(60)).await;
        let budget = Duration::from_secs(1);
        let deadline = Instant::now() + budget;
        let started = tokio::time::Instant::now();
        assert!(timeout(deadline, std::future::pending::<()>())
            .await
            .is_err());
        assert!(started.elapsed() <= budget);
        assert!(started.elapsed() > Duration::ZERO);
    }
}
