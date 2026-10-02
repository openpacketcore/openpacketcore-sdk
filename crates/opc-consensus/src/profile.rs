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
    /// Openraft heartbeat interval. A leader sends heartbeats on its engine
    /// tick, every three halves of this interval.
    pub heartbeat_interval_millis: u64,
    /// AppendEntries and read-index call ceiling, separate from the heartbeat
    /// interval.
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
            ConsensusRpcFamily::PreVote => self.vote_timeout_millis,
            ConsensusRpcFamily::LeadershipTransfer => self.vote_timeout_millis,
            ConsensusRpcFamily::AppendEntries => self.append_entries_timeout_millis,
            ConsensusRpcFamily::AppendEntriesRoster => self.append_entries_timeout_millis,
            ConsensusRpcFamily::InstallSnapshot => self.install_snapshot_timeout_millis,
            ConsensusRpcFamily::ForwardMutation => self.forward_mutation_timeout_millis,
            ConsensusRpcFamily::ForwardRosterMutation => self.forward_mutation_timeout_millis,
            ConsensusRpcFamily::ReadBarrier => self.read_barrier_timeout_millis,
            ConsensusRpcFamily::TopologyAdmissionBarrier => self.read_barrier_timeout_millis,
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

    /// Return the maximum client-observed idle age allowed for a cached
    /// consensus connection.
    ///
    /// A reconnect has to begin before the listener's fixed frame-idle
    /// ceiling. Reserving the complete cold-connect allowance gives resolver,
    /// TCP, mutual-TLS, and bootstrap work a profile-owned reconnection
    /// margin instead of coupling callers to a deployment-specific timeout.
    /// It is not a proof about response timing or client/server clock skew:
    /// the transport records a successful use from an instant captured no
    /// later than request dispatch.
    pub const fn client_connection_reuse_limit(self) -> Duration {
        Duration::from_millis(
            self.server_idle_timeout_millis
                .saturating_sub(self.cold_connect_timeout_millis),
        )
    }

    /// Return the consensus listener handler ceiling.
    pub const fn server_handler_timeout(self) -> Duration {
        Duration::from_millis(self.server_handler_timeout_millis)
    }

    /// Return the Openraft heartbeat interval.
    pub const fn heartbeat_interval(self) -> Duration {
        Duration::from_millis(self.heartbeat_interval_millis)
    }

    /// Return the engine tick derived from the heartbeat interval.
    ///
    /// The pinned Openraft engine evaluates both a leader's idle heartbeat and
    /// every follower's election timer only on this tick, which it fixes at
    /// three halves of the heartbeat interval.
    pub const fn engine_tick(self) -> Duration {
        Duration::from_millis(self.engine_tick_millis())
    }

    const fn engine_tick_millis(self) -> u64 {
        self.heartbeat_interval_millis.saturating_mul(3) / 2
    }

    /// Return how long a replica keeps waiting for a leader-routed call after
    /// its own engine names a different leader.
    ///
    /// A lost leader that black-holes a connection never answers. Once the
    /// replica observes the successor, the call is abandoned after this grace
    /// and reported as possibly transmitted.
    pub const fn stale_leader_route_grace(self) -> Duration {
        Duration::from_millis(self.heartbeat_interval_millis)
    }

    /// Return the bound on the first successful campaign after an unplanned
    /// leader loss, measured from the loss.
    ///
    /// Every survivor's leader lease (`election_timeout_min_millis`) runs out
    /// within the lease of the loss. A survivor starts its first Pre-Vote
    /// round once the longer of its lease and its sampled election timeout
    /// (below `election_timeout_max_millis`) has passed since its last leader
    /// contact, on its next engine tick. A round that a still-running lease
    /// rejects is retried after the width of the election-timeout window
    /// (`election_timeout_max_millis - election_timeout_min_millis`), on a
    /// later tick. So the survivor with the most up-to-date log starts a round
    /// that no lease rejects within the lease, the window and one tick of the
    /// loss, that is within the maximum election timeout and one tick, and that
    /// round and its vote are granted.
    pub const fn leader_loss_first_campaign_bound(self) -> Duration {
        Duration::from_millis(self.leader_loss_first_campaign_bound_millis())
    }

    const fn leader_loss_first_campaign_bound_millis(self) -> u64 {
        self.election_timeout_max_millis
            .saturating_add(self.engine_tick_millis())
    }

    /// Return the documented maximum write stall for an unplanned leader
    /// loss.
    ///
    /// The bound adds, to the first successful campaign, six round trips each
    /// answered within one heartbeat interval (Pre-Vote, vote, the
    /// successor's first commit, the forwarded write, the successor's
    /// linearizable admission round and the write's own commit), the stale
    /// leader-route grace for a black-holed lost leader, and one new
    /// connection to the successor within the cold-connect allowance. It
    /// assumes a reachable majority whose processes are not suspended or
    /// CPU-throttled. A split vote is probabilistic and outside the bound; it
    /// adds at most one further election timeout and tick.
    pub const fn unplanned_leader_loss_write_stall(self) -> Duration {
        Duration::from_millis(self.unplanned_leader_loss_write_stall_millis())
    }

    const fn unplanned_leader_loss_write_stall_millis(self) -> u64 {
        self.leader_loss_first_campaign_bound_millis()
            .saturating_add(self.heartbeat_interval_millis.saturating_mul(6))
            .saturating_add(self.heartbeat_interval_millis)
            .saturating_add(self.cold_connect_timeout_millis)
    }
}

/// The one fixed timing contract for SDK-owned durable consensus.
///
/// After an unplanned leader loss, a surviving voter campaigns once the longer
/// of its leader lease (the minimum election timeout) and its sampled election
/// timeout has passed since its last leader contact, checked on a 300 ms
/// engine tick. Pre-Vote keeps a voter that cannot win from raising its term,
/// and a Pre-Vote round that a still-running lease rejects is retried after
/// the 1,500 ms width of the election-timeout window. With these values the
/// first successful campaign starts within 6,800 ms of the loss and the
/// documented write stall is 9,700 ms, inside the unchanged 10,000 ms
/// operation timeout. A voter campaigns only after 5,000 ms without
/// any AppendEntries, more than sixteen missed 300 ms ticks of a leader that is
/// neither suspended nor CPU-throttled.
pub const DURABLE_CONSENSUS_TIMING_PROFILE: DurableConsensusTimingProfile =
    DurableConsensusTimingProfile {
        // Contained in every family ceiling.
        cold_connect_timeout_millis: 1_500,
        // Heartbeats go out on a 300 ms engine tick, sixteen of them within
        // one follower lease.
        heartbeat_interval_millis: 200,
        // AppendEntries/read-index ceiling, independent of the heartbeat.
        append_entries_timeout_millis: 2_000,
        // The engine uses the minimum election timeout as the Vote and
        // Pre-Vote deadline.
        vote_timeout_millis: 5_000,
        install_snapshot_timeout_millis: 10_000,
        forward_mutation_timeout_millis: 10_000,
        read_barrier_timeout_millis: 10_000,
        // Also the follower lease. At least twice the AppendEntries ceiling,
        // so one slow AppendEntries never lets it expire.
        election_timeout_min_millis: 5_000,
        // Bounds the first campaign. Leaves 300 ms of the operation timeout
        // above the documented write stall.
        election_timeout_max_millis: 6_500,
        operation_timeout_millis: 10_000,
        server_idle_timeout_millis: 30_000,
        server_handler_timeout_millis: 30_000,
    };

/// Shared default complete operation deadline for session and configuration
/// consensus adapters.
pub const DURABLE_CONSENSUS_OPERATION_TIMEOUT: Duration =
    DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout();

/// Fixed interval between authenticated remote-retirement setup probes for one
/// exact durable-consensus peer and local authentication epoch.
///
/// This is deliberately independent from Openraft election/vote timing and
/// from generic transport reconnect backoff: it bounds negative admission
/// probes after a remote peer has authenticated and declined bootstrap.
pub const DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL: Duration = Duration::from_secs(5);

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
    heartbeat_interval_millis: DURABLE_CONSENSUS_TIMING_PROFILE.heartbeat_interval_millis,
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
///
/// Besides the family ordering, a follower's lease (the minimum election
/// timeout) must span two engine ticks and two AppendEntries ceilings, and the
/// documented unplanned leader-loss write stall must stay below the operation
/// timeout, so a write in flight at an unplanned leader loss can reach its
/// outcome within one operation.
pub fn validate_durable_consensus_timing_profile(
    profile: DurableConsensusTimingProfile,
) -> Result<(), DurableConsensusTimingProfileError> {
    let doubled_append_entries = profile
        .append_entries_timeout_millis
        .checked_mul(2)
        .ok_or(DurableConsensusTimingProfileError)?;
    // Two engine ticks, each three halves of the heartbeat interval.
    let two_engine_ticks = profile
        .heartbeat_interval_millis
        .checked_mul(3)
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
        || profile.heartbeat_interval_millis == 0
        || profile.heartbeat_interval_millis > profile.append_entries_timeout_millis
        || profile.election_timeout_min_millis < two_engine_ticks
        || profile.append_entries_timeout_millis == 0
        || profile.vote_timeout_millis == 0
        || profile.install_snapshot_timeout_millis == 0
        || profile.forward_mutation_timeout_millis == 0
        || profile.read_barrier_timeout_millis == 0
        || profile.operation_timeout_millis == 0
        || profile.append_entries_timeout_millis >= profile.election_timeout_min_millis
        || profile.election_timeout_min_millis < doubled_append_entries
        || profile.election_timeout_min_millis >= profile.election_timeout_max_millis
        || profile.election_timeout_max_millis >= profile.operation_timeout_millis
        || profile.vote_timeout_millis != profile.election_timeout_min_millis
        || profile.forward_mutation_timeout_millis > profile.operation_timeout_millis
        || profile.read_barrier_timeout_millis > profile.operation_timeout_millis
        || profile.server_idle_timeout_millis <= profile.cold_connect_timeout_millis
        || profile.server_idle_timeout_millis < largest_rpc_timeout
        || profile.server_handler_timeout_millis < largest_rpc_timeout
        || profile.unplanned_leader_loss_write_stall_millis() >= profile.operation_timeout_millis
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
    if profile.heartbeat_interval_millis != timing.heartbeat_interval_millis
        || profile.election_timeout_min_millis != timing.election_timeout_min_millis
        || profile.election_timeout_max_millis != timing.election_timeout_max_millis
        || profile.install_snapshot_timeout_millis != timing.install_snapshot_timeout_millis
    {
        return Err(DurableOpenraftProfileError);
    }
    Config {
        cluster_name: domain.cluster_name().into(),
        heartbeat_interval: profile.heartbeat_interval_millis,
        // AppendEntries, heartbeats and read-index rounds use their own
        // ceiling instead of the heartbeat interval.
        append_entries_timeout: Some(timing.append_entries_timeout_millis),
        election_timeout_min: profile.election_timeout_min_millis,
        election_timeout_max: profile.election_timeout_max_millis,
        install_snapshot_timeout: profile.install_snapshot_timeout_millis,
        max_payload_entries: profile.max_payload_entries,
        replication_lag_threshold: profile.logs_per_snapshot,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(profile.logs_per_snapshot),
        snapshot_max_chunk_size: profile.snapshot_chunk_bytes,
        max_in_snapshot_log_to_keep: profile.retained_logs,
        // A voter that cannot win, such as one cut off from the others, keeps its
        // term instead of deposing a healthy leader when it is reachable again.
        enable_pre_vote: Some(true),
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
                config.heartbeat_interval,
                DURABLE_CONSENSUS_TIMING_PROFILE.heartbeat_interval_millis
            );
            assert_eq!(
                config.append_entries_timeout(),
                DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(ConsensusRpcFamily::AppendEntries)
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
            assert_eq!(config.enable_pre_vote, Some(true));
        }
    }

    #[test]
    fn fixed_timing_profile_has_exact_family_deadlines_and_valid_ordering() {
        let profile = DURABLE_CONSENSUS_TIMING_PROFILE;
        assert_eq!(profile.cold_connect_timeout(), Duration::from_millis(1_500));
        assert_eq!(profile.heartbeat_interval(), Duration::from_millis(200));
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::AppendEntries),
            Duration::from_millis(2_000)
        );
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::AppendEntriesRoster),
            Duration::from_millis(2_000)
        );
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::Vote),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::PreVote),
            profile.rpc_timeout(ConsensusRpcFamily::Vote)
        );
        assert_eq!(
            profile.rpc_timeout(ConsensusRpcFamily::LeadershipTransfer),
            Duration::from_millis(5_000)
        );
        for family in [
            ConsensusRpcFamily::InstallSnapshot,
            ConsensusRpcFamily::ForwardMutation,
            ConsensusRpcFamily::ForwardRosterMutation,
            ConsensusRpcFamily::ReadBarrier,
            ConsensusRpcFamily::TopologyAdmissionBarrier,
        ] {
            assert_eq!(profile.rpc_timeout(family), Duration::from_millis(10_000));
        }
        assert_eq!(profile.election_timeout_min_millis, 5_000);
        assert_eq!(profile.election_timeout_max_millis, 6_500);
        assert_eq!(profile.operation_timeout(), Duration::from_millis(10_000));
        assert_eq!(profile.engine_tick(), Duration::from_millis(300));
        assert_eq!(
            profile.stale_leader_route_grace(),
            Duration::from_millis(200)
        );
        assert_eq!(
            profile.leader_loss_first_campaign_bound(),
            Duration::from_millis(6_800)
        );
        assert_eq!(
            profile.unplanned_leader_loss_write_stall(),
            Duration::from_millis(9_700)
        );
        assert_eq!(
            DURABLE_CONSENSUS_REMOTE_RETIREMENT_PROBE_INTERVAL,
            Duration::from_secs(5)
        );
        assert_eq!(profile.server_idle_timeout(), Duration::from_millis(30_000));
        assert_eq!(
            profile.client_connection_reuse_limit(),
            Duration::from_millis(28_500)
        );
        assert!(profile.client_connection_reuse_limit() < profile.server_idle_timeout());
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
    fn leader_loss_bounds_follow_the_overlapping_lease_and_tick() {
        let profile = DurableConsensusTimingProfile {
            cold_connect_timeout_millis: 70,
            heartbeat_interval_millis: 100,
            append_entries_timeout_millis: 150,
            election_timeout_min_millis: 400,
            election_timeout_max_millis: 1_000,
            ..DURABLE_CONSENSUS_TIMING_PROFILE
        };
        assert_eq!(profile.engine_tick(), Duration::from_millis(150));
        // The longer of the lease (min) and the sampled timeout (< max), then
        // one tick: never their sum.
        assert_eq!(
            profile.leader_loss_first_campaign_bound(),
            Duration::from_millis(1_150)
        );
        // A rejected Pre-Vote round is retried after the window's width on a
        // later tick, so the first round after every lease (min) has run out
        // starts within the same bound.
        let window = Duration::from_millis(
            profile.election_timeout_max_millis - profile.election_timeout_min_millis,
        );
        assert_eq!(
            profile.leader_loss_first_campaign_bound(),
            Duration::from_millis(profile.election_timeout_min_millis)
                + window
                + profile.engine_tick()
        );
        // Six heartbeat round trips, the stale-route grace and one cold
        // connection.
        assert_eq!(
            profile.unplanned_leader_loss_write_stall(),
            Duration::from_millis(1_920)
        );
        // The AppendEntries ceiling does not enter the bound.
        assert_eq!(
            DurableConsensusTimingProfile {
                append_entries_timeout_millis: 200,
                ..profile
            }
            .unplanned_leader_loss_write_stall(),
            profile.unplanned_leader_loss_write_stall()
        );
    }

    #[test]
    fn unplanned_leader_loss_write_stall_fits_inside_the_operation_timeout() {
        let profile = DURABLE_CONSENSUS_TIMING_PROFILE;
        assert!(
            profile.unplanned_leader_loss_write_stall() < profile.operation_timeout(),
            "a write in flight at an unplanned leader loss must reach a definite \
             outcome inside one operation timeout: stall bound {:?}, operation \
             timeout {:?}",
            profile.unplanned_leader_loss_write_stall(),
            profile.operation_timeout()
        );
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
            // Each of these keeps every family ordering valid, but its
            // unplanned leader-loss write stall reaches the operation timeout.
            DurableConsensusTimingProfile {
                election_timeout_max_millis: 6_800,
                ..fixed
            },
            DurableConsensusTimingProfile {
                heartbeat_interval_millis: 250,
                ..fixed
            },
            DurableConsensusTimingProfile {
                forward_mutation_timeout_millis: fixed.unplanned_leader_loss_write_stall_millis(),
                read_barrier_timeout_millis: fixed.unplanned_leader_loss_write_stall_millis(),
                operation_timeout_millis: fixed.unplanned_leader_loss_write_stall_millis(),
                ..fixed
            },
            DurableConsensusTimingProfile {
                vote_timeout_millis: fixed.vote_timeout_millis + 1,
                ..fixed
            },
            DurableConsensusTimingProfile {
                heartbeat_interval_millis: 0,
                ..fixed
            },
            DurableConsensusTimingProfile {
                heartbeat_interval_millis: fixed.append_entries_timeout_millis + 1,
                ..fixed
            },
            // A follower lease that spans fewer than two engine ticks.
            DurableConsensusTimingProfile {
                heartbeat_interval_millis: fixed.election_timeout_min_millis / 3 + 1,
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
                server_idle_timeout_millis: fixed.cold_connect_timeout_millis,
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
