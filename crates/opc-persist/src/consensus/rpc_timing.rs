//! Shared timing parameters for the consensus TCP transport.

pub(crate) const RPC_MAX_ATTEMPTS: u32 = 3;
pub(crate) const RPC_INITIAL_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_millis(50);
pub(crate) const RPC_CATCH_UP_MAX_ROUNDS: usize = 64;
#[cfg(test)]
pub(crate) const RPC_CATCH_UP_MAX_RPCS_PER_ROUND: u32 = 2;

/// Returns the end-to-end deadline budget for one logical peer RPC.
///
/// Connector/authentication locks, request framing, TCP, TLS, writes, response
/// reads, decoding, retries, and retry backoff all share this one budget.
#[cfg(test)]
pub(crate) const fn rpc_logical_deadline_budget(
    timeout: std::time::Duration,
) -> std::time::Duration {
    timeout
}

/// Returns the transport-wait ceiling for one bounded per-peer catch-up pass.
///
/// A round normally sends one append or snapshot RPC. When a snapshot is
/// rejected without a transport error, the implementation can fall through to
/// one append RPC in the same round, so the exact ceiling is two logical RPCs
/// per round.
#[cfg(test)]
pub(crate) fn catch_up_rpc_deadline_budget(timeout: std::time::Duration) -> std::time::Duration {
    let rounds = u32::try_from(RPC_CATCH_UP_MAX_ROUNDS).unwrap_or(u32::MAX);
    rpc_logical_deadline_budget(timeout)
        .saturating_mul(rounds.saturating_mul(RPC_CATCH_UP_MAX_RPCS_PER_ROUND))
}
