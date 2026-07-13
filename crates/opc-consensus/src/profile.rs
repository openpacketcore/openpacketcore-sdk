//! One fixed Openraft runtime configuration for SDK-owned durable consensus.
//!
//! Production-intended adapters use this code path, but its HA profile and
//! maturity remain experimental until the acceptance work tracked by issue
//! #143 is complete.

use openraft::{Config, SnapshotPolicy};
use thiserror::Error;

/// SDK durable state-machine domain selecting only the non-secret Openraft
/// cluster label. Timing, replication, and snapshot authority remain common.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableOpenraftDomain {
    /// Replicated session and lease authority.
    SessionState,
    /// Replicated encrypted configuration authority.
    ConfigurationState,
}

impl DurableOpenraftDomain {
    fn cluster_name(self) -> &'static str {
        match self {
            Self::SessionState => "opc-session-store",
            Self::ConfigurationState => "opc-config-store",
        }
    }
}

/// Fixed, non-operator-tunable runtime configuration shared by every durable
/// Openraft consumer in the SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableOpenraftProfile {
    /// Leader heartbeat interval in milliseconds.
    pub heartbeat_interval_millis: u64,
    /// Inclusive lower election-timeout bound in milliseconds.
    pub election_timeout_min_millis: u64,
    /// Exclusive upper election-timeout bound in milliseconds.
    pub election_timeout_max_millis: u64,
    /// Snapshot installation deadline in milliseconds.
    pub install_snapshot_timeout_millis: u64,
    /// Maximum log entries sent in one replication payload.
    pub max_payload_entries: u64,
    /// Committed-log distance that triggers snapshot creation and lag repair.
    pub logs_per_snapshot: u64,
    /// Maximum snapshot transfer chunk size in bytes.
    pub snapshot_chunk_bytes: u64,
    /// Maximum applied log entries retained behind a snapshot.
    pub retained_logs: u64,
}

/// The one SDK-owned runtime configuration used by durable Openraft consumers.
pub const DURABLE_OPENRAFT_PROFILE: DurableOpenraftProfile = DurableOpenraftProfile {
    heartbeat_interval_millis: 250,
    election_timeout_min_millis: 1_000,
    election_timeout_max_millis: 2_000,
    install_snapshot_timeout_millis: 10_000,
    max_payload_entries: 1,
    logs_per_snapshot: 4_096,
    snapshot_chunk_bytes: 1024 * 1024,
    retained_logs: 1_024,
};

/// Opaque fail-closed error returned if the fixed SDK profile is incompatible
/// with the exact-pinned Openraft release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the fixed SDK Openraft profile is invalid")]
pub struct DurableOpenraftProfileError;

/// Build and validate the one Openraft configuration for a durable SDK
/// state-machine domain.
pub fn durable_openraft_config(
    domain: DurableOpenraftDomain,
) -> Result<Config, DurableOpenraftProfileError> {
    let profile = DURABLE_OPENRAFT_PROFILE;
    Config {
        cluster_name: domain.cluster_name().into(),
        heartbeat_interval: profile.heartbeat_interval_millis,
        election_timeout_min: profile.election_timeout_min_millis,
        election_timeout_max: profile.election_timeout_max_millis,
        install_snapshot_timeout: profile.install_snapshot_timeout_millis,
        max_payload_entries: profile.max_payload_entries,
        replication_lag_threshold: profile.logs_per_snapshot,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(profile.logs_per_snapshot),
        snapshot_max_chunk_size: profile.snapshot_chunk_bytes,
        max_in_snapshot_log_to_keep: profile.retained_logs,
        ..Config::default()
    }
    .validate()
    .map_err(|_| DurableOpenraftProfileError)
}

/// The only asynchronous runtime used by durable SDK Openraft adapters.
pub type DurableOpenraftRuntime = openraft::TokioRuntime;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_profile_validates_for_every_durable_domain() {
        for (domain, cluster_name) in [
            (DurableOpenraftDomain::SessionState, "opc-session-store"),
            (
                DurableOpenraftDomain::ConfigurationState,
                "opc-config-store",
            ),
        ] {
            let config = durable_openraft_config(domain).expect("fixed profile must validate");
            assert_eq!(config.cluster_name, cluster_name);
            assert_eq!(
                config.heartbeat_interval,
                DURABLE_OPENRAFT_PROFILE.heartbeat_interval_millis
            );
            assert_eq!(
                config.election_timeout_min,
                DURABLE_OPENRAFT_PROFILE.election_timeout_min_millis
            );
            assert_eq!(
                config.election_timeout_max,
                DURABLE_OPENRAFT_PROFILE.election_timeout_max_millis
            );
            assert_eq!(
                config.snapshot_policy,
                SnapshotPolicy::LogsSinceLast(DURABLE_OPENRAFT_PROFILE.logs_per_snapshot)
            );
        }
    }
}
