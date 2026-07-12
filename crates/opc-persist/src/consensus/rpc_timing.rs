//! Shared timing parameters for the consensus TCP transport.

pub(crate) const RPC_MAX_ATTEMPTS: u32 = 3;
pub(crate) const RPC_INITIAL_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_millis(50);

// connect, TLS handshake, write, response-length read, and response-body read
#[cfg(test)]
const RPC_TIMED_IO_STAGES_PER_ATTEMPT: u32 = 5;

/// Returns the cumulative configured I/O-stage timeout and retry-backoff budget for one RPC.
///
/// This does not bound serialization, lock acquisition, scheduler delay, or other untimed work.
#[cfg(test)]
pub(crate) fn rpc_io_timeout_and_backoff_budget(
    timeout: std::time::Duration,
) -> std::time::Duration {
    let timed_stage_budget =
        timeout.saturating_mul(RPC_TIMED_IO_STAGES_PER_ATTEMPT.saturating_mul(RPC_MAX_ATTEMPTS));
    let mut retry_delay_budget = std::time::Duration::ZERO;
    let mut retry_delay = RPC_INITIAL_RETRY_DELAY;
    for _ in 1..RPC_MAX_ATTEMPTS {
        retry_delay_budget = retry_delay_budget.saturating_add(retry_delay);
        retry_delay = retry_delay.saturating_mul(2);
    }

    timed_stage_budget.saturating_add(retry_delay_budget)
}
