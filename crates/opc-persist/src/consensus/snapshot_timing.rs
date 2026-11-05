//! Size-derived bounds for snapshot operations without per-chunk progress.
//!
//! Fixed whole-operation budgets cannot cover a large but healthy snapshot
//! (#1339). Chunked file work has its own progress deadlines; whole-file sync
//! and the final transfer RPC use the size-derived bounds here. Each retains
//! its configured baseline floor, adds one second per complete throughput
//! quantum, and has a fixed ceiling. Repair callers keep their own deadlines.

use std::time::Duration;

/// Preserved per-stage budget for ordinary snapshot build/install work.
///
/// This is the existing fixed stage budget (`SNAPSHOT_OPERATION_TIMEOUT`).
/// Snapshots small enough to fit it keep exactly the previous deadline.
pub(crate) const SNAPSHOT_WORK_BASE_BUDGET: Duration = Duration::from_secs(60);

/// Minimum healthy throughput used to derive additional budget.
///
/// A healthy local SQLite backup or file copy comfortably exceeds this floor;
/// a saturated link or stalled disk still fails at the derived bound instead of
/// waiting forever.
pub(crate) const SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC: u64 = 8 * 1024 * 1024;

/// Hard ceiling on any derived snapshot budget.
///
/// It covers the largest admissible artifact ([`super::storage::SNAPSHOT_MAX_BYTES`],
/// 64 GiB) at the minimum throughput (about 2.3 h) with ample headroom. It is a
/// finite operation bound, never an unbounded extension.
pub(crate) const SNAPSHOT_WORK_CEILING_BUDGET: Duration = Duration::from_secs(8 * 60 * 60);

/// Budget for syncing `bytes` of snapshot data: the existing stage floor plus
/// one second per complete 8 MiB, capped.
pub(crate) fn snapshot_work_budget(bytes: u64) -> Duration {
    derived_budget(SNAPSHOT_WORK_BASE_BUDGET, bytes)
}

/// Budget for a final snapshot-chunk RPC over `bytes` of envelope. Preserve
/// the caller's configured floor and add one second per complete 8 MiB, capped.
/// Receiver-owned installation can continue after an RPC waiter expires.
pub(crate) fn snapshot_transfer_budget(floor: Duration, bytes: u64) -> Duration {
    derived_budget(floor, bytes)
}

fn derived_budget(base: Duration, bytes: u64) -> Duration {
    // A started quantum only adds budget once it is actually reached, so every
    // artifact below one quantum keeps exactly the existing floor.
    let additional_seconds = bytes / SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC;
    base.saturating_add(Duration::from_secs(additional_seconds))
        .min(SNAPSHOT_WORK_CEILING_BUDGET)
}

/// Return `now + budget`, or a bounded error when the instant would overflow.
pub(crate) fn derived_deadline(
    now: tokio::time::Instant,
    budget: Duration,
) -> std::io::Result<tokio::time::Instant> {
    now.checked_add(budget)
        .ok_or_else(|| std::io::Error::other("config snapshot derived deadline overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT_TRANSFER_BASE_BUDGET: Duration = Duration::from_secs(10);

    #[test]
    fn ordinary_snapshots_keep_the_existing_budgets() {
        assert_eq!(SNAPSHOT_WORK_BASE_BUDGET, snapshot_work_budget(0));
        assert_eq!(SNAPSHOT_WORK_BASE_BUDGET, snapshot_work_budget(1));
        assert_eq!(
            SNAPSHOT_WORK_BASE_BUDGET,
            snapshot_work_budget(SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC - 1)
        );
        assert_eq!(
            SNAPSHOT_TRANSFER_BASE_BUDGET,
            snapshot_transfer_budget(SNAPSHOT_TRANSFER_BASE_BUDGET, 0)
        );
        assert_eq!(
            SNAPSHOT_TRANSFER_BASE_BUDGET,
            snapshot_transfer_budget(
                SNAPSHOT_TRANSFER_BASE_BUDGET,
                SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC - 1
            )
        );
    }

    #[test]
    fn short_configured_transfer_deadlines_keep_their_own_floor() {
        let configured = Duration::from_secs(1);
        assert_eq!(configured, snapshot_transfer_budget(configured, 0));
        assert_eq!(
            configured,
            snapshot_transfer_budget(configured, SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC - 1)
        );
        assert_eq!(
            Duration::from_secs(2),
            snapshot_transfer_budget(configured, SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC)
        );
    }

    #[test]
    fn derived_budget_adds_one_second_per_started_throughput_quantum() {
        assert_eq!(
            SNAPSHOT_WORK_BASE_BUDGET + Duration::from_secs(1),
            snapshot_work_budget(SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC)
        );
        assert_eq!(
            SNAPSHOT_WORK_BASE_BUDGET + Duration::from_secs(1),
            snapshot_work_budget(SNAPSHOT_MIN_THROUGHPUT_BYTES_PER_SEC + 1)
        );
        assert_eq!(
            SNAPSHOT_WORK_BASE_BUDGET + Duration::from_secs(128),
            snapshot_work_budget(1024 * 1024 * 1024)
        );
        assert_eq!(
            SNAPSHOT_TRANSFER_BASE_BUDGET + Duration::from_secs(128),
            snapshot_transfer_budget(SNAPSHOT_TRANSFER_BASE_BUDGET, 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn largest_admissible_artifact_stays_below_the_ceiling() {
        let largest = super::super::storage::SNAPSHOT_MAX_ENVELOPE_BYTES;
        let derived = snapshot_work_budget(largest);
        assert!(derived > SNAPSHOT_WORK_BASE_BUDGET);
        assert!(derived < SNAPSHOT_WORK_CEILING_BUDGET);
        // 64 GiB at 8 MiB/s is 8192 s; the ceiling is much larger.
        assert!(derived >= Duration::from_secs(8192 + 60));
    }

    #[test]
    fn budgets_are_finite_and_capped_for_any_size() {
        assert_eq!(SNAPSHOT_WORK_CEILING_BUDGET, snapshot_work_budget(u64::MAX));
        assert_eq!(
            SNAPSHOT_WORK_CEILING_BUDGET,
            snapshot_transfer_budget(SNAPSHOT_TRANSFER_BASE_BUDGET, u64::MAX)
        );
        assert!(snapshot_work_budget(u64::MAX).as_secs() <= 8 * 60 * 60);
        let now = tokio::time::Instant::now();
        assert!(derived_deadline(now, snapshot_work_budget(u64::MAX)).is_ok());
    }
}
