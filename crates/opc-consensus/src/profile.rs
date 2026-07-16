//! One fixed Openraft runtime configuration for SDK-owned durable consensus.
//!
//! Production-intended adapters use this code path, but its HA profile and
//! maturity remain experimental until the acceptance work tracked by issue
//! #143 is complete.

use std::time::Duration;

use openraft::{Config, SnapshotPolicy};
use thiserror::Error;

use crate::ConsensusRpcFamily;

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

/// Fixed end-to-end timing contract shared by every durable consensus domain.
///
/// All values are outer-hard/direct complete-call ceilings. A deadline-aware
/// Openraft network call uses its supplied soft TTL, never more than the
/// corresponding family ceiling. The cold-connection value is a contained
/// sub-bound of the selected call ceiling, never additional time. The fixed
/// server ceilings remain above every client family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableConsensusTimingProfile {
    /// Resolver, TCP, mutual-TLS, identity, and application-bootstrap ceiling.
    pub cold_connect_timeout_millis: u64,
    /// Openraft heartbeat interval and AppendEntries/read-index call ceiling.
    pub append_entries_timeout_millis: u64,
    /// Vote RPC ceiling.
    pub vote_timeout_millis: u64,
    /// InstallSnapshot RPC ceiling.
    pub install_snapshot_timeout_millis: u64,
    /// Forwarded mutation RPC ceiling.
    pub forward_mutation_timeout_millis: u64,
    /// Consumer linearizable read-barrier RPC ceiling.
    pub read_barrier_timeout_millis: u64,
    /// Inclusive lower election-timeout bound.
    pub election_timeout_min_millis: u64,
    /// Exclusive upper election-timeout bound.
    pub election_timeout_max_millis: u64,
    /// Complete session/config operation ceiling.
    pub operation_timeout_millis: u64,
    /// Consensus listener frame-idle ceiling.
    pub server_idle_timeout_millis: u64,
    /// Consensus listener handler ceiling.
    pub server_handler_timeout_millis: u64,
}

impl DurableConsensusTimingProfile {
    /// Return the complete deadline for one bounded RPC family.
    pub const fn rpc_timeout(self, family: ConsensusRpcFamily) -> Duration {
        Duration::from_millis(match family {
            ConsensusRpcFamily::Vote => self.vote_timeout_millis,
            ConsensusRpcFamily::AppendEntries => self.append_entries_timeout_millis,
            ConsensusRpcFamily::InstallSnapshot => self.install_snapshot_timeout_millis,
            ConsensusRpcFamily::ForwardMutation => self.forward_mutation_timeout_millis,
            ConsensusRpcFamily::ReadBarrier => self.read_barrier_timeout_millis,
        })
    }

    /// Return the contained cold-connection sub-deadline.
    pub const fn cold_connect_timeout(self) -> Duration {
        Duration::from_millis(self.cold_connect_timeout_millis)
    }

    /// Return the complete session/config operation deadline.
    pub const fn operation_timeout(self) -> Duration {
        Duration::from_millis(self.operation_timeout_millis)
    }

    /// Return the consensus listener frame-idle ceiling.
    pub const fn server_idle_timeout(self) -> Duration {
        Duration::from_millis(self.server_idle_timeout_millis)
    }

    /// Return the consensus listener handler ceiling.
    pub const fn server_handler_timeout(self) -> Duration {
        Duration::from_millis(self.server_handler_timeout_millis)
    }
}

/// The one fixed timing contract for SDK-owned durable consensus.
pub const DURABLE_CONSENSUS_TIMING_PROFILE: DurableConsensusTimingProfile =
    DurableConsensusTimingProfile {
        cold_connect_timeout_millis: 1_500,
        append_entries_timeout_millis: 2_000,
        vote_timeout_millis: 5_000,
        install_snapshot_timeout_millis: 10_000,
        forward_mutation_timeout_millis: 10_000,
        read_barrier_timeout_millis: 10_000,
        election_timeout_min_millis: 5_000,
        election_timeout_max_millis: 8_000,
        operation_timeout_millis: 10_000,
        server_idle_timeout_millis: 30_000,
        server_handler_timeout_millis: 30_000,
    };

/// Shared default complete operation deadline for session and configuration
/// consensus adapters.
pub const DURABLE_CONSENSUS_OPERATION_TIMEOUT: Duration =
    DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout();

/// Maximum number of log entries admitted to one durable AppendEntries batch.
pub const DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES: usize = 64;

/// Maximum number of accepted application proposals supervised concurrently
/// by each durable Openraft adapter.
///
/// A permit remains owned until Openraft resolves the accepted proposal, even
/// when the originating caller is cancelled or its operation deadline elapses.
pub const DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS: usize = 8;

/// The one SDK-owned runtime configuration used by durable Openraft consumers.
pub const DURABLE_OPENRAFT_PROFILE: DurableOpenraftProfile = DurableOpenraftProfile {
    heartbeat_interval_millis: DURABLE_CONSENSUS_TIMING_PROFILE.append_entries_timeout_millis,
    election_timeout_min_millis: DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_min_millis,
    election_timeout_max_millis: DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis,
    install_snapshot_timeout_millis: DURABLE_CONSENSUS_TIMING_PROFILE
        .install_snapshot_timeout_millis,
    max_payload_entries: DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES as u64,
    logs_per_snapshot: 4_096,
    snapshot_chunk_bytes: 1024 * 1024,
    retained_logs: 1_024,
};

/// Opaque fail-closed error returned if the fixed SDK profile is incompatible
/// with the exact-pinned Openraft release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the fixed SDK Openraft profile is invalid")]
pub struct DurableOpenraftProfileError;

/// Opaque fail-closed error returned when a timing profile violates the shared
/// production invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the fixed SDK consensus timing profile is invalid")]
pub struct DurableConsensusTimingProfileError;

/// Validate the cross-family timing relationships required by the fixed
/// production profile.
pub fn validate_durable_consensus_timing_profile(
    profile: DurableConsensusTimingProfile,
) -> Result<(), DurableConsensusTimingProfileError> {
    let doubled_heartbeat = profile
        .append_entries_timeout_millis
        .checked_mul(2)
        .ok_or(DurableConsensusTimingProfileError)?;
    let largest_rpc_timeout = profile
        .append_entries_timeout_millis
        .max(profile.vote_timeout_millis)
        .max(profile.install_snapshot_timeout_millis)
        .max(profile.forward_mutation_timeout_millis)
        .max(profile.read_barrier_timeout_millis);
    let smallest_rpc_timeout = profile
        .append_entries_timeout_millis
        .min(profile.vote_timeout_millis)
        .min(profile.install_snapshot_timeout_millis)
        .min(profile.forward_mutation_timeout_millis)
        .min(profile.read_barrier_timeout_millis);
    if profile.cold_connect_timeout_millis == 0
        || profile.cold_connect_timeout_millis > smallest_rpc_timeout
        || profile.append_entries_timeout_millis == 0
        || profile.vote_timeout_millis == 0
        || profile.install_snapshot_timeout_millis == 0
        || profile.forward_mutation_timeout_millis == 0
        || profile.read_barrier_timeout_millis == 0
        || profile.operation_timeout_millis == 0
        || profile.append_entries_timeout_millis >= profile.election_timeout_min_millis
        || profile.election_timeout_min_millis < doubled_heartbeat
        || profile.election_timeout_min_millis >= profile.election_timeout_max_millis
        || profile.election_timeout_max_millis >= profile.operation_timeout_millis
        || profile.vote_timeout_millis != profile.election_timeout_min_millis
        || profile.forward_mutation_timeout_millis > profile.operation_timeout_millis
        || profile.read_barrier_timeout_millis > profile.operation_timeout_millis
        || profile.server_idle_timeout_millis < largest_rpc_timeout
        || profile.server_handler_timeout_millis < largest_rpc_timeout
    {
        return Err(DurableConsensusTimingProfileError);
    }
    Ok(())
}

/// Build and validate the one Openraft configuration for a durable SDK
/// state-machine domain.
pub fn durable_openraft_config(
    domain: DurableOpenraftDomain,
) -> Result<Config, DurableOpenraftProfileError> {
    let profile = DURABLE_OPENRAFT_PROFILE;
    let timing = DURABLE_CONSENSUS_TIMING_PROFILE;
    validate_durable_consensus_timing_profile(timing).map_err(|_| DurableOpenraftProfileError)?;
    if profile.heartbeat_interval_millis != timing.append_entries_timeout_millis
        || profile.election_timeout_min_millis != timing.election_timeout_min_millis
        || profile.election_timeout_max_millis != timing.election_timeout_max_millis
        || profile.install_snapshot_timeout_millis != timing.install_snapshot_timeout_millis
    {
        return Err(DurableOpenraftProfileError);
    }
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
                DURABLE_OPENRAFT_PROFILE.max_payload_entries,
                DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES as u64
            );
            assert_eq!(
                config.max_payload_entries,
                DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES as u64
            );
            assert_eq!(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS, 8);
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

    #[test]
    fn fixed_timing_profile_has_exact_family_deadlines_and_valid_ordering() {
        let profile = DURABLE_CONSENSUS_TIMING_PROFILE;
        assert_eq!(profile.cold_connect_timeout(), Duration::from_millis(1_500));
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::AppendEntries),
            Duration::from_millis(2_000)
        );
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::Vote),
            Duration::from_millis(5_000)
        );
        for family in [
            ConsensusRpcFamily::InstallSnapshot,
            ConsensusRpcFamily::ForwardMutation,
            ConsensusRpcFamily::ReadBarrier,
        ] {
            assert_eq!(profile.rpc_timeout(family), Duration::from_millis(10_000));
        }
        assert_eq!(profile.election_timeout_min_millis, 5_000);
        assert_eq!(profile.election_timeout_max_millis, 8_000);
        assert_eq!(profile.operation_timeout(), Duration::from_millis(10_000));
        assert_eq!(profile.server_idle_timeout(), Duration::from_millis(30_000));
        assert_eq!(
            profile.server_handler_timeout(),
            Duration::from_millis(30_000)
        );
        assert!(
            crate::DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE
                <= Duration::from_millis(DURABLE_OPENRAFT_PROFILE.heartbeat_interval_millis)
        );
        assert!(
            crate::DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE
                <= profile.rpc_timeout(ConsensusRpcFamily::ReadBarrier)
        );
        assert!(
            crate::DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE
                < Duration::from_millis(profile.election_timeout_min_millis)
        );
        validate_durable_consensus_timing_profile(profile).expect("fixed timing profile");
    }

    #[test]
    fn timing_profile_rejects_representative_cross_boundary_violations() {
        let fixed = DURABLE_CONSENSUS_TIMING_PROFILE;
        let invalid = [
            DurableConsensusTimingProfile {
                cold_connect_timeout_millis: 0,
                ..fixed
            },
            DurableConsensusTimingProfile {
                cold_connect_timeout_millis: fixed.append_entries_timeout_millis + 1,
                ..fixed
            },
            DurableConsensusTimingProfile {
                forward_mutation_timeout_millis: fixed.cold_connect_timeout_millis - 1,
                ..fixed
            },
            DurableConsensusTimingProfile {
                election_timeout_min_millis: fixed.append_entries_timeout_millis * 2 - 1,
                ..fixed
            },
            DurableConsensusTimingProfile {
                election_timeout_max_millis: fixed.election_timeout_min_millis,
                ..fixed
            },
            DurableConsensusTimingProfile {
                election_timeout_max_millis: fixed.operation_timeout_millis,
                ..fixed
            },
            DurableConsensusTimingProfile {
                vote_timeout_millis: fixed.vote_timeout_millis + 1,
                ..fixed
            },
            DurableConsensusTimingProfile {
                install_snapshot_timeout_millis: 0,
                ..fixed
            },
            DurableConsensusTimingProfile {
                server_idle_timeout_millis: fixed.install_snapshot_timeout_millis - 1,
                ..fixed
            },
            DurableConsensusTimingProfile {
                server_handler_timeout_millis: fixed.install_snapshot_timeout_millis - 1,
                ..fixed
            },
        ];
        for profile in invalid {
            assert_eq!(
                validate_durable_consensus_timing_profile(profile),
                Err(DurableConsensusTimingProfileError)
            );
        }
    }
}
