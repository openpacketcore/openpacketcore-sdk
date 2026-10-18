//! Remaining budgets for absolute standard-clock deadlines.
//!
//! An absolute [`std::time::Instant`] must not be treated as a Tokio instant:
//! Tokio's clock may be paused or advanced independently. Carry the remaining
//! duration across that boundary once, retaining the original operation budget.
//! These waits bound work; they do not establish lease or fencing authority.
//!
//! The `async-time` feature enables the Tokio wait adapters. An armed adapter
//! follows ordinary Tokio timer semantics, including virtual-time advancement.

use std::time::{Duration, Instant};

/// Return the unspent portion of an absolute standard-clock deadline.
///
/// An expired deadline returns zero. Repeated calls retain the same absolute
/// budget rather than granting a fresh timeout on retries.
pub fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Wait for the remaining standard-clock budget using a Tokio timer.
///
/// The remaining duration is captured when this function is called. An expired
/// deadline creates a zero-duration timer. Requires a running Tokio time driver.
#[cfg(feature = "async-time")]
pub fn sleep_until(deadline: Instant) -> tokio::time::Sleep {
    tokio::time::sleep(remaining(deadline))
}

/// Bound a future by the remaining portion of a standard-clock deadline.
///
/// The remaining duration is captured when this future is first polled. This
/// retains Tokio's timeout behavior, including polling ready work at expiry.
///
/// # Errors
///
/// Returns [`tokio::time::error::Elapsed`] when the pending future exceeds the
/// remaining budget. Requires a running Tokio time driver.
#[cfg(feature = "async-time")]
pub async fn timeout<F: std::future::Future>(
    deadline: Instant,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    // Shared with blocking I/O budgets. Never carry an absolute standard
    // instant into Tokio's independently adjustable clock.
    tokio::time::timeout(remaining(deadline), future).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_budget_is_zero() {
        assert_eq!(
            remaining(Instant::now() - Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn remaining_budget_never_grants_a_fresh_deadline() {
        let budget = Duration::from_secs(30);
        let deadline = Instant::now() + budget;
        let first = remaining(deadline);
        let second = remaining(deadline);
        assert!(first <= budget);
        assert!(second <= first);
    }
}
