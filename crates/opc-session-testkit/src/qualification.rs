//! Experimental qualification profile and multi-process node protocol.
//!
//! The node protocol supports a production-constructor projected-SVID mTLS
//! candidate path. Its older loopback plaintext foundation remains available
//! only behind the testkit's explicit `foundation-insecure` feature and never
//! counts as TLS-rotation evidence.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use opc_consensus::{
    DURABLE_CONSENSUS_TIMING_PROFILE, DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY,
    DURABLE_OPENRAFT_LINEARIZABILITY_WORKER_COUNT, DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use opc_identity::projected_svid::{
    ProjectedSvidAvailability, ProjectedSvidReloadReason, ProjectedSvidReloadStatus,
    MAX_PROJECTED_SVID_BUNDLE_FILES, MIN_PROJECTED_SVID_POLL_INTERVAL,
};
use opc_redaction::metrics::{
    SecurityMetricsSnapshot, SecurityRotationKind, SecurityRotationOutcome,
};
use opc_session_net::{
    ConnectionLifecyclePolicy, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, DEFAULT_RECONNECT_BACKOFF_MAX,
};
use opc_session_store::{
    validate_session_ttl, OwnerId, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, MAX_REPLICATION_LOG_PAGE_ENTRIES, STABLE_ID_MAX_BYTES,
};
use opc_tls::{TlsMaterialAvailability, TlsMaterialReloadReason, TlsMaterialStatus};
use opc_types::{SpiffeId, Timestamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Exact profile inventory consumed by qualification tooling.
pub const SESSION_HA_PROFILE_JSON: &str =
    include_str!("../qualification/v2/session-ha-profile.json");
/// JSON Schema for the exact experimental profile inventory.
pub const SESSION_HA_PROFILE_SCHEMA_JSON: &str =
    include_str!("../qualification/v2/session-ha-profile.schema.json");
/// JSON Schema for one independent history-checker input operation.
pub const SESSION_HA_HISTORY_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-ha-history.schema.json");
/// JSON Schema for one immutable qualification workload invocation.
pub const SESSION_HA_SCHEDULE_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-ha-schedule.schema.json");
/// JSON Schema for one experimental qualification evidence record.
pub const SESSION_HA_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../qualification/v2/session-ha-evidence.schema.json");
/// Strict schema for one incomplete production-mTLS harness checkpoint.
pub const SESSION_MTLS_CANDIDATE_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-mtls-candidate-evidence.schema.json");

/// Version of the private node-control protocol.
pub const QUALIFICATION_NODE_SCHEMA_VERSION: u16 = 2;
/// Maximum accepted node configuration document.
pub const QUALIFICATION_MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Maximum accepted control request or response line.
pub const QUALIFICATION_MAX_CONTROL_LINE_BYTES: usize = 16 * 1024;
/// Maximum number of synthetic payload bytes admitted by the node harness.
pub const QUALIFICATION_MAX_VALUE_BYTES: usize = 512;
/// Maximum retained lease handles in one qualification child.
pub const QUALIFICATION_MAX_LEASE_HANDLES: usize = 1024;
/// Explicit inbound consensus connection-slot limit used by fleet resource
/// qualification. Keeping the value here makes the process budget and the
/// listener configuration one contract rather than an inferred default.
pub const QUALIFICATION_INBOUND_CONNECTION_SLOTS: usize = 128;
/// Domain-separated deterministic seed for the repeated-rotation workload.
pub const QUALIFICATION_TRAFFIC_SEED_BASE: u64 = 0x0164_7A11_C0DE_2026;
/// Number of same-issuer leaf rotations applied to every voter.
pub const QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER: usize = 2;
/// Maximum wall-clock budget for one repeated valid-leaf transition and its
/// complete fresh directed-connection proof. Semantic progress, not sleeping
/// for this duration, determines completion.
pub const QUALIFICATION_TRAFFIC_TRANSITION_MILLIS: u64 = 90_000;
/// Fleet-wide explicit reauthentication generations proved in every round.
pub const QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND: usize = 2;
/// `/proc` sampling interval used by the Linux resource qualification.
pub const QUALIFICATION_RESOURCE_SAMPLE_MILLIS: u64 = 25;
/// Maximum semantic-settle bound before final FD/RSS/lifecycle assertions.
pub const QUALIFICATION_RESOURCE_SETTLE_MILLIS: u64 = 40_000;
/// Consecutive equal FD/socket/thread samples required after every connection
/// drain has completed.
pub const QUALIFICATION_RESOURCE_STABLE_SAMPLES: usize = 8;
/// Non-transport FD allowance above listener slots and peer routes.
pub const QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE: usize = 8;
/// Final FD allowance above the warmed process baseline.
pub const QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE: usize = 4;
/// Thread high-water allowance above the warmed process baseline.
pub const QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE: usize = 8;
/// VmHWM growth allowance in KiB.
pub const QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB: u64 = 128 * 1024;
/// Settled VmRSS growth allowance in KiB.
pub const QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB: u64 = 32 * 1024;
/// Per-round connection/reconnect budget coefficient and fixed allowance.
pub const QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR: u64 = 8;
/// Fixed per-round connection/reconnect allowance after the peer coefficient.
pub const QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE: u64 = 8;
/// Fixed authenticated consensus client lanes per configured remote peer.
pub const QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER: usize = 2;
/// Maximum admitted Openraft proposal tasks per node. This is a task/memory
/// pipeline bound and does not add a socket or file-descriptor allowance.
pub const QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE: usize =
    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS;
/// Maximum concurrent fresh Openraft linearizability checks per node.
pub const QUALIFICATION_MAX_CONCURRENT_LINEARIZABILITY_CHECKS_PER_OPENRAFT_NODE: usize =
    DURABLE_OPENRAFT_LINEARIZABILITY_WORKER_COUNT;
/// Maximum total callers admitted to the fixed Openraft linearizability
/// supervisor, including the active cohort and the queued cohort.
pub const QUALIFICATION_LINEARIZABILITY_ADMISSION_CAPACITY_PER_OPENRAFT_NODE: usize =
    DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY;
/// Final lifecycle-gauge bound coefficient over configured remote peers: two
/// client lanes plus the corresponding two inbound server lifecycles.
pub const QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR: i64 =
    2 * QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER as i64;
/// Real-mTLS completion upper bound for the isolated resolver retry proof.
pub const QUALIFICATION_RESOLVER_PROOF_MILLIS: u64 = 1_500;
/// Exact exponential reconnect lower bounds proved after three failures.
pub const QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS: [u64; 3] = [50, 100, 200];
/// Complete first-page restore bound for the 3/5-voter synthetic workload.
pub const QUALIFICATION_TRAFFIC_RESTORE_LIMIT: usize = 16;
/// Lower bound for deterministic mutation-task pacing.
pub const QUALIFICATION_TRAFFIC_MUTATION_DELAY_MIN_MILLIS: u64 = 5;
/// Number of deterministic millisecond values above the minimum.
pub const QUALIFICATION_TRAFFIC_MUTATION_DELAY_SPAN_MILLIS: u64 = 11;
/// Lease TTL used by the deterministic mutation workload.
pub const QUALIFICATION_TRAFFIC_TTL_MILLIS: u64 = 60 * 60 * 1_000;
/// Maximum typed availability interruptions one mutation task may reconcile
/// before the qualification run fails closed.
pub const QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE: u64 = 8;
/// Maximum wall-clock interval for one authority-and-record reconciliation.
/// Ambiguous mutation outcomes advance same-owner fencing authority; read-only
/// checkpoints retain the already-proven guard and validate its exact record.
/// The bound covers the fixed two-election cluster transition plus one complete
/// consensus operation and remains large enough for the reconciliation's
/// sequential acquire and linearizable get plus one retry delay. An accepted
/// backend operation is still allowed to reach its terminal outcome; a success
/// observed after this deadline fails the qualification.
pub const QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS: u64 =
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis;
/// Fixed retry delay between terminal recoverable backend outcomes.
pub const QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS: u64 = 50;
/// Versioned, qualification-only response-loss injection that deterministically
/// exercises same-owner recovery after one successful lease release.
pub const QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_PROFILE: &str =
    "post-release-response-loss/v1";
/// Process-restart policy for the qualification-only synthetic interruption.
/// A recovered committed mutation generation proves the logical mutator
/// already passed its first release checkpoint, so restart must not inject the
/// once-per-mutator fault again.
pub const QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_RESTART_PROFILE: &str =
    "committed-generation-does-not-rearm/v1";
/// Versioned terminal recovery-deadline diagnostic bound into the schedule.
/// The fixed code, terminal operation stage, and elapsed milliseconds expose
/// an overrun without forwarding backend or identity-bearing error text.
pub const QUALIFICATION_TRAFFIC_RECOVERY_DEADLINE_DIAGNOSTIC_PROFILE: &str =
    "terminal-stage-elapsed-millis/v1";
/// Versioned authority reconciliation algorithm bound into the schedule.
pub const QUALIFICATION_TRAFFIC_AUTHORITY_RECONCILIATION_PROFILE: &str =
    "stage-aware-known-authority/v1";
/// Maximum wall-clock budget for one stopped watch's journal reconciliation.
pub const QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS: u64 = 25_000;
/// Maximum journal entries one stopped watch may reconcile.
pub const QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES: u64 = 262_144;
/// Maximum entries requested in one journal reconciliation page.
pub const QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PAGE_ENTRIES: usize =
    MAX_REPLICATION_LOG_PAGE_ENTRIES;
/// Versioned stopped-watch reconciliation algorithm bound into the schedule.
pub const QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PROFILE: &str = "bounded-durable-journal/v1";
/// Versioned unclean restart scenario covered by the projected-mTLS fault
/// campaign. This is one same-disk, exact-address active-mutator restart, not
/// a deployed host or network-partition matrix.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_PROFILE: &str =
    "same-disk-exact-address-active-mutator/v2";
/// Maximum time for SIGKILL and process reaping before the exact manifest
/// address is reused.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS: u64 = 5_000;
/// Maximum time for the survivor majority to commit and expose semantic
/// traffic progress while the selected member is absent.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS: u64 =
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis;
/// Maximum time for one replacement child to bind, open its durable state,
/// initialize its existing membership, and enable its consensus RPC path.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS: u64 =
    QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS;
/// Maximum time after replacement startup for Openraft to regain all-voter
/// readiness and apply the committed state on the restarted member.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS: u64 =
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis;
/// Maximum time after journal reconciliation for the restarted mutator to
/// commit under a strictly higher same-owner fence.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS: u64 =
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis;
/// Composed crash-to-resume ceiling. Each constituent stage is checked
/// independently; this total must never be used as a substitute stage timer.
pub const QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS: u64 =
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS
        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS
        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS
        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS
        + QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS
        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS;
/// Versioned post-expiry recovery proof. Fault-era attempt outcomes first
/// settle beyond the complete server/connect/backoff horizon; only then does
/// the recovered member advance explicit reauthentication, reprove every
/// incident directed path, and establish the next lifecycle baseline.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROFILE: &str =
    "member-scoped-reauth-settled-baseline/v2";
/// Fault-attempt settlement horizon after replacement publication. One
/// pre-admission read/handshake stage and its bounded retirement response may
/// each consume the larger server timeout; cold connect and maximum reconnect
/// backoff then define the required outbound-ledger quiet tail.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_MILLIS: u64 = {
    let server_timeout = if DURABLE_CONSENSUS_TIMING_PROFILE.server_idle_timeout_millis
        > DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout_millis
    {
        DURABLE_CONSENSUS_TIMING_PROFILE.server_idle_timeout_millis
    } else {
        DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout_millis
    };
    server_timeout * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout_millis
        + DEFAULT_RECONNECT_BACKOFF_MAX.as_millis() as u64
};
/// Absolute fail-safe for the fault-tail checkpoint. The availability
/// recovery envelope provides bounded room for a final cold attempt to settle
/// after the complete two-stage server tail.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS: u64 = {
    let server_timeout = if DURABLE_CONSENSUS_TIMING_PROFILE.server_idle_timeout_millis
        > DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout_millis
    {
        DURABLE_CONSENSUS_TIMING_PROFILE.server_idle_timeout_millis
    } else {
        DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout_millis
    };
    server_timeout * 2 + QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
};
/// Maximum interval between survivor-traffic progress observations during the
/// recovered-member checkpoint. Requiring a semantic delta in every half-SLO
/// interval bounds the worst-case gap between two actual progress events by
/// the full availability-recovery SLO even though each event occurs somewhere
/// between two observations.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS: u64 =
    QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS / 2;
/// Maximum recoverable workload-availability episode introduced on each
/// survivor while one expired member rejoins. The episode must still settle
/// inside the existing availability-recovery SLO before the clean lifecycle
/// baseline is captured.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE: u64 = 1;
/// Exact operation timeout pinned by the experimental profile.
pub const QUALIFICATION_OPERATION_TIMEOUT_MILLIS: u64 =
    DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis;
/// Parent-side bound for one child command response. Mutation shutdown retains
/// a stricter 30-second campaign SLO; this additional 15 seconds lets the
/// parent receive a typed terminal failure after one already-accepted backend
/// operation reaches its fixed 10-second terminal bound.
pub const QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS: u64 = 45_000;
/// Remaining-validity budget of the same-issuer SVID used by the bounded
/// fault/expiry campaign.
pub const QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS: u64 = 75_000;
/// Maximum spacing between explicit directed-path refresh rounds before the
/// short-lived SVID soft-retirement boundary.
pub const QUALIFICATION_FAULT_PATH_REFRESH_MILLIS: u64 = 5_000;
/// Outbound and inbound qualification paths exercised for every remote peer.
pub const QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR: u64 = 2;
/// Lead between stopping all expiring-member traffic and that member's
/// connection soft-retirement boundary.
pub const QUALIFICATION_FAULT_TRAFFIC_STOP_LEAD_MILLIS: u64 = 1_000;
/// Mutation-shutdown lead and campaign SLO. The parent response timeout is
/// deliberately larger, so an SLO miss still returns typed terminal evidence.
pub const QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS: u64 = 30_000;
/// Versioned cancellation discipline covered by the traffic schedule digest.
/// Accepted backend operations run to completion; cancellation is observed at
/// the next terminal operation checkpoint.
pub const QUALIFICATION_TRAFFIC_CANCELLATION_PROFILE: &str =
    "accepted-operation-terminal-checkpoints/v1";
/// Largest accepted finite lifecycle field in the private harness config.
pub const QUALIFICATION_MAX_LIFECYCLE_MILLIS: u64 = 24 * 60 * 60 * 1_000;

/// Machine-readable experimental session-HA profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHaQualificationProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub maturity: String,
    pub qualification_complete: bool,
    pub workspace: QualificationWorkspace,
    pub source_build_gate: QualificationSourceBuildGate,
    pub artifacts: Vec<QualificationArtifact>,
    pub platforms: Vec<QualificationPlatform>,
    pub topology: QualificationTopology,
    pub protocol: QualificationProtocol,
    pub consensus_timing: QualificationConsensusTiming,
    pub bounds: QualificationBounds,
    pub provisional_test_thresholds: QualificationThresholds,
    pub evidence: QualificationEvidenceRequirements,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationWorkspace {
    pub version: String,
    pub rust_msrv: String,
    pub source_revision: String,
}

/// Exact interim source and publication gate for the patched consensus engine.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSourceBuildGate {
    pub tracking_issue: u64,
    pub openraft_git: String,
    pub openraft_rev: String,
    pub affected_workspace_crates: Vec<String>,
    pub crates_io_check_date: String,
    pub crates_io_exact_matches: Vec<String>,
    pub removal_condition: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifact {
    pub crate_name: String,
    pub version: String,
    pub publish: bool,
    pub required_features: Vec<String>,
    pub excluded_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPlatform {
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTopology {
    pub member_counts: Vec<usize>,
    pub maximum_members: usize,
    pub quorum_rule: String,
    pub distinct_failure_domain_per_voter: bool,
    pub distinct_backing_store_per_voter: bool,
    pub stable_identity_independent_of_route: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProtocol {
    pub consensus_alpn: String,
    pub transport_revision: u16,
    pub wire_schema_revision: u16,
    pub error_set_revision: u16,
    pub consensus_schema_version: u16,
    pub min_frame_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_rpc_payload_bytes: usize,
    pub legacy_direct_backend_enabled: bool,
}

/// Fixed non-operator-tunable consensus timing inventory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConsensusTiming {
    pub cold_connect_budget_composition: String,
    pub cold_connect_timeout_millis: u64,
    pub append_entries_timeout_millis: u64,
    pub heartbeat_interval_millis: u64,
    pub vote_timeout_millis: u64,
    pub election_timeout_min_millis: u64,
    pub election_timeout_max_millis: u64,
    pub install_snapshot_timeout_millis: u64,
    pub forward_mutation_timeout_millis: u64,
    pub read_barrier_timeout_millis: u64,
    pub server_idle_timeout_millis: u64,
    pub server_handler_timeout_millis: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationBounds {
    pub operation_timeout_millis: u64,
    pub max_session_ttl_seconds: u64,
    pub max_stable_id_bytes: usize,
    pub max_replication_transaction_id_bytes: usize,
    pub max_replication_operation_depth: usize,
    pub max_replication_operations_per_entry: usize,
    pub max_replication_log_page_entries: usize,
    pub max_watch_backlog_entries: usize,
    pub max_restore_page_records: usize,
    pub max_restore_page_payload_bytes: usize,
    pub max_restore_examined_rows: usize,
    pub max_restore_sqlite_work_millis: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationThresholds {
    pub acknowledged_write_loss: u64,
    pub stale_owner_mutation_successes: u64,
    pub conflicting_committed_entries: u64,
    pub watch_gaps: u64,
    pub max_startup_millis: u64,
    pub max_single_member_stop_service_continuity_millis: u64,
    pub max_restart_catchup_millis: u64,
    pub max_leader_failover_millis: u64,
    pub max_leader_restart_catchup_millis: u64,
    pub minimum_soak_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidenceRequirements {
    pub schedule_schema: String,
    pub history_schema: String,
    pub evidence_schema: String,
    pub independent_checker: String,
    pub required_topologies: Vec<usize>,
    pub required_transport_modes: Vec<String>,
    pub foundation_transport_mode: String,
    pub foundation_counts_for_tls_rotation: bool,
    pub foundation_payload_protection: String,
    pub foundation_counts_for_production_encryption: bool,
    pub unresolved_dependencies: Vec<u64>,
}

/// Configuration for one real process in the qualification fleet.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationNodeConfig {
    pub schema_version: u16,
    pub node_index: usize,
    pub cluster_id: String,
    pub configuration_generation: String,
    pub configuration_epoch: u64,
    pub backend_namespace: String,
    pub workload_schedule_sha256: String,
    pub members: Vec<QualificationMember>,
    pub workspace_directory: PathBuf,
    pub database_path: PathBuf,
    pub snapshot_directory: PathBuf,
    pub operation_timeout_millis: u64,
    #[serde(default)]
    pub transport: QualificationTransportConfig,
}

impl QualificationNodeConfig {
    /// Validate all allocation, path, topology, and transport boundaries.
    pub fn validate(&self) -> Result<(), QualificationConfigError> {
        if self.schema_version != QUALIFICATION_NODE_SCHEMA_VERSION {
            return Err(QualificationConfigError::Schema);
        }
        if !matches!(self.members.len(), 3 | 5) {
            return Err(QualificationConfigError::Topology);
        }
        if self.node_index >= self.members.len()
            || self.operation_timeout_millis != QUALIFICATION_OPERATION_TIMEOUT_MILLIS
            || self.configuration_epoch == 0
            || !is_bounded_label(&self.backend_namespace, 128)
            || !is_exact_sha256(&self.workload_schedule_sha256)
            || SessionClusterId::new(self.cluster_id.clone()).is_err()
            || SessionConfigurationGeneration::new(self.configuration_generation.clone()).is_err()
            || SessionConfigurationEpoch::new(self.configuration_epoch).is_err()
            || !self.workspace_directory.is_absolute()
            || !self.database_path.is_absolute()
            || !self.snapshot_directory.is_absolute()
            || self.workspace_directory.parent().is_none()
            || self.database_path == self.snapshot_directory
            || !self.database_path.starts_with(&self.workspace_directory)
            || !self
                .snapshot_directory
                .starts_with(&self.workspace_directory)
            || self
                .transport
                .validate(&self.workspace_directory, self.operation_timeout_millis)
                .is_err()
        {
            return Err(QualificationConfigError::Configuration);
        }

        let mut replica_ids = HashSet::<ReplicaId>::with_capacity(self.members.len());
        let mut endpoints = HashSet::<ReplicaEndpoint>::with_capacity(self.members.len());
        let mut routes = HashSet::with_capacity(self.members.len());
        let mut tls_identities = HashSet::<ReplicaTlsIdentity>::with_capacity(self.members.len());
        let mut failure_domains =
            HashSet::<ReplicaFailureDomain>::with_capacity(self.members.len());
        let mut backing_identities =
            HashSet::<ReplicaBackingIdentity>::with_capacity(self.members.len());
        for (expected_index, member) in self.members.iter().enumerate() {
            let replica_id = ReplicaId::new(member.replica_id.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            let endpoint = ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                .map_err(|_| QualificationConfigError::Member)?;
            let tls_identity = ReplicaTlsIdentity::new(member.tls_identity.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            SpiffeId::new(member.tls_identity.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            let failure_domain = ReplicaFailureDomain::new(member.failure_domain.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            let backing_identity = ReplicaBackingIdentity::new(member.backing_identity.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            if member.node_index != expected_index
                || member.endpoint_port == 0
                || member.dial_addr.port() == 0
                || !member.dial_addr.ip().is_loopback()
                || member.replica_id.is_empty()
                || member.endpoint_host.is_empty()
                || member.tls_identity.is_empty()
                || member.failure_domain.is_empty()
                || member.backing_identity.is_empty()
                || !replica_ids.insert(replica_id)
                || !endpoints.insert(endpoint)
                || !routes.insert(member.dial_addr)
                || !tls_identities.insert(tls_identity)
                || !failure_domains.insert(failure_domain)
                || !backing_identities.insert(backing_identity)
            {
                return Err(QualificationConfigError::Member);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for QualificationNodeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationNodeConfig")
            .field("schema_version", &self.schema_version)
            .field("node_index", &self.node_index)
            .field("configured_members", &self.members.len())
            .field("cluster_scope", &"<redacted>")
            .field("workload_schedule", &"<redacted>")
            .field("workspace_directory", &"<redacted>")
            .field("database_path", &"<redacted>")
            .field("snapshot_directory", &"<redacted>")
            .field("operation_timeout_millis", &self.operation_timeout_millis)
            .field("transport", &self.transport)
            .finish()
    }
}

/// Transport selected by one qualification node.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "configuration",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum QualificationTransportConfig {
    /// Historical loopback-only foundation. Runtime support is feature-gated.
    #[default]
    LoopbackPlaintextTestOnly,
    /// Production mTLS constructors backed by one coherent projected source.
    ProjectedMtls(QualificationProjectedMtlsConfig),
}

impl fmt::Debug for QualificationTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoopbackPlaintextTestOnly => {
                formatter.write_str("QualificationTransportConfig::LoopbackPlaintextTestOnly")
            }
            Self::ProjectedMtls(config) => formatter
                .debug_tuple("QualificationTransportConfig::ProjectedMtls")
                .field(config)
                .finish(),
        }
    }
}

impl QualificationTransportConfig {
    fn validate(
        &self,
        workspace_directory: &Path,
        operation_timeout_millis: u64,
    ) -> Result<(), QualificationConfigError> {
        match self {
            Self::LoopbackPlaintextTestOnly => Ok(()),
            Self::ProjectedMtls(config) => {
                config.validate(workspace_directory, operation_timeout_millis)
            }
        }
    }
}

/// Bounded projected-SVID and connection-lifecycle settings for mTLS.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProjectedMtlsConfig {
    pub projected_volume_root: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_bundle_files: Vec<PathBuf>,
    pub poll_interval_millis: u64,
    pub lifecycle: QualificationConnectionLifecycleConfig,
}

impl fmt::Debug for QualificationProjectedMtlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationProjectedMtlsConfig")
            .field("projected_volume_root", &"<redacted>")
            .field("certificate_file", &"<redacted>")
            .field("private_key_file", &"<redacted>")
            .field("trust_bundle_file_count", &self.trust_bundle_files.len())
            .field("poll_interval_millis", &self.poll_interval_millis)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

impl QualificationProjectedMtlsConfig {
    fn validate(
        &self,
        workspace_directory: &Path,
        operation_timeout_millis: u64,
    ) -> Result<(), QualificationConfigError> {
        let poll_interval = Duration::from_millis(self.poll_interval_millis);
        if !self.projected_volume_root.is_absolute()
            || !self.projected_volume_root.starts_with(workspace_directory)
            || self.projected_volume_root == workspace_directory
            || !is_normalized_relative_path(&self.certificate_file)
            || !is_normalized_relative_path(&self.private_key_file)
            || self.trust_bundle_files.is_empty()
            || self.trust_bundle_files.len() > MAX_PROJECTED_SVID_BUNDLE_FILES
            || self
                .trust_bundle_files
                .iter()
                .any(|path| !is_normalized_relative_path(path))
            || self.certificate_file == self.private_key_file
            || self
                .trust_bundle_files
                .iter()
                .any(|path| path == &self.certificate_file || path == &self.private_key_file)
            || self.trust_bundle_files.iter().collect::<HashSet<_>>().len()
                != self.trust_bundle_files.len()
            || poll_interval < MIN_PROJECTED_SVID_POLL_INTERVAL
            || self.poll_interval_millis > operation_timeout_millis
            || self.lifecycle.to_policy().is_err()
        {
            return Err(QualificationConfigError::Transport);
        }
        Ok(())
    }
}

/// Exact finite connection retirement and reconnect policy used by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConnectionLifecycleConfig {
    pub maximum_authentication_age_millis: u64,
    pub rotation_drain_window_millis: u64,
    pub reconnect_backoff_min_millis: u64,
    pub reconnect_backoff_max_millis: u64,
    pub rotation_jitter_millis: u64,
}

impl QualificationConnectionLifecycleConfig {
    /// Validate and construct the production transport lifecycle policy.
    pub fn to_policy(self) -> Result<ConnectionLifecyclePolicy, QualificationConfigError> {
        let values = [
            self.maximum_authentication_age_millis,
            self.rotation_drain_window_millis,
            self.reconnect_backoff_min_millis,
            self.reconnect_backoff_max_millis,
            self.rotation_jitter_millis,
        ];
        if values
            .into_iter()
            .any(|value| value > QUALIFICATION_MAX_LIFECYCLE_MILLIS)
        {
            return Err(QualificationConfigError::Transport);
        }
        ConnectionLifecyclePolicy::try_new(
            Duration::from_millis(self.maximum_authentication_age_millis),
            Duration::from_millis(self.rotation_drain_window_millis),
            Duration::from_millis(self.reconnect_backoff_min_millis),
            Duration::from_millis(self.reconnect_backoff_max_millis),
            Duration::from_millis(self.rotation_jitter_millis),
        )
        .map_err(|_| QualificationConfigError::Transport)
    }
}

fn is_normalized_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_bounded_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Return the exact evidence digest for one synthetic qualification key.
pub fn qualification_key_sha256(value: &str) -> String {
    qualification_digest("key", value.as_bytes())
}

/// Return the exact evidence digest for one synthetic qualification owner.
pub fn qualification_owner_sha256(value: &str) -> String {
    qualification_digest("owner", value.as_bytes())
}

/// Return the exact evidence digest for a synthetic qualification value.
pub fn qualification_value_sha256(value: &[u8]) -> String {
    qualification_digest("value", value)
}

/// Exact deterministic seed for the 3/5-voter traffic/resource workload.
pub fn qualification_traffic_seed(member_count: usize) -> Option<u64> {
    matches!(member_count, 3 | 5)
        .then_some(QUALIFICATION_TRAFFIC_SEED_BASE ^ u64::try_from(member_count).ok()?)
}

/// Digest binding every fixed traffic/resource schedule value to a node's
/// existing `workload_schedule_sha256` configuration field.
pub fn qualification_traffic_schedule_sha256(member_count: usize) -> Option<String> {
    let seed = qualification_traffic_seed(member_count)?;
    let schedule = format!(
        concat!(
            "opc-session-ha/traffic-resource/v4\n",
            "member_count={member_count}\n",
            "seed={seed}\n",
            "rotations_per_member={}\n",
            "transition_millis={}\n",
            "reauthentications_per_round={}\n",
            "baseline_reauthentications={}\n",
            "resource_sample_millis={}\n",
            "resource_settle_millis={}\n",
            "resource_stable_samples={}\n",
            "inbound_connection_slots={}\n",
            "resource_fd_misc_allowance={}\n",
            "resource_final_fd_allowance={}\n",
            "resource_thread_growth_allowance={}\n",
            "resource_vmhwm_growth_kib={}\n",
            "resource_settled_rss_growth_kib={}\n",
            "connection_bound_factor={}\n",
            "connection_bound_allowance={}\n",
            "consensus_connection_lanes_per_peer={}\n",
            "active_connection_factor={}\n",
            "max_in_flight_proposals_per_openraft_node={}\n",
            "max_concurrent_linearizability_checks_per_openraft_node={}\n",
            "linearizability_admission_capacity_per_openraft_node={}\n",
            "resolver_proof_millis={}\n",
            "resolver_backoff_lower_bounds_millis=50,100,200\n",
            "restore_limit={}\n",
            "mutation_delay_min_millis={}\n",
            "mutation_delay_span_millis={}\n",
            "traffic_ttl_millis={}\n",
            "availability_interruption_budget_per_node={}\n",
            "availability_recovery_millis={}\n",
            "availability_retry_millis={}\n",
            "authority_reconciliation_profile={}\n",
            "synthetic_interruption_profile={}\n",
            "synthetic_interruption_restart_profile={}\n",
            "recovery_deadline_diagnostic_profile={}\n",
            "watch_reconciliation_millis={}\n",
            "watch_reconciliation_max_entries={}\n",
            "watch_reconciliation_page_entries={}\n",
            "watch_reconciliation_profile={}\n",
            "unclean_restart_count=1\n",
            "unclean_restart_profile={}\n",
            "unclean_restart_termination_millis={}\n",
            "unclean_restart_outage_millis={}\n",
            "unclean_restart_startup_millis={}\n",
            "unclean_restart_catchup_millis={}\n",
            "unclean_restart_resume_millis={}\n",
            "unclean_restart_total_millis={}\n",
            "member_recovery_profile={}\n",
            "member_recovery_settlement_millis={}\n",
            "member_recovery_settlement_deadline_millis={}\n",
            "member_recovery_progress_checkpoint_millis={}\n",
            "member_recovery_availability_interruption_budget_per_node={}\n",
            "operation_timeout_millis={}\n",
            "child_response_timeout_millis={}\n",
            "fault_expiry_validity_millis={}\n",
            "fault_path_refresh_millis={}\n",
            "fault_directed_path_factor={}\n",
            "fault_traffic_stop_lead_millis={}\n",
            "fault_mutation_shutdown_lead_millis={}\n",
            "traffic_cancellation_profile={}\n",
            "owned_mutation_tasks_per_node=1\n",
            "owned_watch_tasks_per_node=1\n",
            "rotation_order=seed_mod_member_count_then_round_robin\n",
            "leaf_issuer=unchanged\n"
        ),
        QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER,
        QUALIFICATION_TRAFFIC_TRANSITION_MILLIS,
        QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND,
        QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND,
        QUALIFICATION_RESOURCE_SAMPLE_MILLIS,
        QUALIFICATION_RESOURCE_SETTLE_MILLIS,
        QUALIFICATION_RESOURCE_STABLE_SAMPLES,
        QUALIFICATION_INBOUND_CONNECTION_SLOTS,
        QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE,
        QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE,
        QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE,
        QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB,
        QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB,
        QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR,
        QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE,
        QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER,
        QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR,
        QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE,
        QUALIFICATION_MAX_CONCURRENT_LINEARIZABILITY_CHECKS_PER_OPENRAFT_NODE,
        QUALIFICATION_LINEARIZABILITY_ADMISSION_CAPACITY_PER_OPENRAFT_NODE,
        QUALIFICATION_RESOLVER_PROOF_MILLIS,
        QUALIFICATION_TRAFFIC_RESTORE_LIMIT,
        QUALIFICATION_TRAFFIC_MUTATION_DELAY_MIN_MILLIS,
        QUALIFICATION_TRAFFIC_MUTATION_DELAY_SPAN_MILLIS,
        QUALIFICATION_TRAFFIC_TTL_MILLIS,
        QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
        QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS,
        QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS,
        QUALIFICATION_TRAFFIC_AUTHORITY_RECONCILIATION_PROFILE,
        QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_PROFILE,
        QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_RESTART_PROFILE,
        QUALIFICATION_TRAFFIC_RECOVERY_DEADLINE_DIAGNOSTIC_PROFILE,
        QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS,
        QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES,
        QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PAGE_ENTRIES,
        QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PROFILE,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_PROFILE,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS,
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROFILE,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_MILLIS,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
        QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
        QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS,
        QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS,
        QUALIFICATION_FAULT_PATH_REFRESH_MILLIS,
        QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR,
        QUALIFICATION_FAULT_TRAFFIC_STOP_LEAD_MILLIS,
        QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS,
        QUALIFICATION_TRAFFIC_CANCELLATION_PROFILE,
        member_count = member_count,
        seed = seed,
    );
    Some(qualification_digest(
        "traffic-schedule",
        schedule.as_bytes(),
    ))
}

/// Exact redaction-safe synthetic payload used by one mutation-task cycle.
pub fn qualification_traffic_value(
    seed: u64,
    member_count: usize,
    node_index: usize,
    generation: u64,
) -> String {
    format!("opc-rotation-traffic-canary/{seed:016x}/{member_count}/{node_index}/{generation}")
}

fn qualification_digest(kind: &str, value: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-ha/");
    hasher.update(kind.as_bytes());
    hasher.update(b"/v1\0");
    hasher.update(value);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn is_exact_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// One immutable fleet member descriptor plus its local test dial route.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationMember {
    pub node_index: usize,
    pub replica_id: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub dial_addr: SocketAddr,
    pub tls_identity: String,
    pub failure_domain: String,
    pub backing_identity: String,
}

impl fmt::Debug for QualificationMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationMember")
            .field("node_index", &self.node_index)
            .field("descriptor", &"<redacted>")
            .field("dial_route", &"<redacted>")
            .finish()
    }
}

/// Fixed, non-sensitive configuration failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationConfigError {
    #[error("qualification configuration schema is unsupported")]
    Schema,
    #[error("qualification topology is unsupported")]
    Topology,
    #[error("qualification configuration is invalid")]
    Configuration,
    #[error("qualification member descriptor is invalid")]
    Member,
    #[error("qualification transport configuration is invalid")]
    Transport,
}

/// Bounded commands accepted by one qualification child process.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationNodeCommand {
    Configure,
    Initialize,
    Probe,
    ProjectedSourceStatus,
    MaterialStatus,
    /// Return the process-local connection reauthentication generation.
    ReauthenticationGeneration,
    RequestReauthentication,
    /// Prove one fresh authenticated TLS connection and exact manifest-bound
    /// consensus bootstrap to a configured remote node.
    ///
    /// An exact authenticated `Protocol` application result also satisfies
    /// this transport proof; this command does not claim valid private
    /// ReadBarrier handler execution.
    DirectedHandshake {
        remote_node_index: usize,
    },
    LifecycleMetrics,
    /// Enable or fail closed every consensus RPC path owned by this child.
    /// The stdin control channel remains available while RPCs are disabled.
    SetConsensusRpcAvailability {
        availability: QualificationConsensusRpcAvailability,
    },
    /// Return a redacted fixed-cardinality security telemetry snapshot.
    SecurityMetrics,
    /// Register exactly one protected applied-state watch before any traffic
    /// mutation can begin. All schedule values are bound by the node
    /// configuration digest; this frame intentionally carries no free-form
    /// workload input.
    StartTrafficWatch,
    /// Reconcile a stopped or process-restarted traffic watch through an exact
    /// bounded application-journal prefix, then subscribe at `head + 1`.
    ReconcileTrafficWatch,
    /// Start exactly one deterministic mutation task after every fleet member
    /// has registered its watch.
    StartTrafficMutation,
    /// Cooperatively stop and join only the mutation task.
    StopTrafficMutation,
    /// Cooperatively stop and join the remaining applied-state watch task.
    StopTrafficWatch,
    /// Return bounded, plaintext-free workload progress and the local
    /// linearizable replication head.
    TrafficStatus,
    /// Return only the existing bounded, plaintext-free workload observation
    /// without issuing a new backend operation. Recovery continuity polling
    /// uses this non-intrusive view; authoritative watch-head settlement keeps
    /// using `TrafficStatus`.
    TrafficStatusSnapshot,
    Acquire {
        lease_handle: String,
        stable_id: String,
        owner: String,
        ttl_millis: u64,
    },
    CompareAndSet {
        lease_handle: String,
        stable_id: String,
        expected_generation: Option<u64>,
        new_generation: u64,
        value: String,
    },
    Get {
        stable_id: String,
    },
    Release {
        lease_handle: String,
    },
    Shutdown,
}

impl fmt::Debug for QualificationNodeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configure => formatter.write_str("QualificationNodeCommand::Configure"),
            Self::Initialize => formatter.write_str("QualificationNodeCommand::Initialize"),
            Self::Probe => formatter.write_str("QualificationNodeCommand::Probe"),
            Self::ProjectedSourceStatus => {
                formatter.write_str("QualificationNodeCommand::ProjectedSourceStatus")
            }
            Self::MaterialStatus => formatter.write_str("QualificationNodeCommand::MaterialStatus"),
            Self::ReauthenticationGeneration => {
                formatter.write_str("QualificationNodeCommand::ReauthenticationGeneration")
            }
            Self::RequestReauthentication => {
                formatter.write_str("QualificationNodeCommand::RequestReauthentication")
            }
            Self::DirectedHandshake { remote_node_index } => formatter
                .debug_struct("QualificationNodeCommand::DirectedHandshake")
                .field("remote_node_index", remote_node_index)
                .finish(),
            Self::LifecycleMetrics => {
                formatter.write_str("QualificationNodeCommand::LifecycleMetrics")
            }
            Self::SetConsensusRpcAvailability { availability } => formatter
                .debug_struct("QualificationNodeCommand::SetConsensusRpcAvailability")
                .field("availability", availability)
                .finish(),
            Self::SecurityMetrics => {
                formatter.write_str("QualificationNodeCommand::SecurityMetrics")
            }
            Self::StartTrafficWatch => {
                formatter.write_str("QualificationNodeCommand::StartTrafficWatch")
            }
            Self::ReconcileTrafficWatch => {
                formatter.write_str("QualificationNodeCommand::ReconcileTrafficWatch")
            }
            Self::StartTrafficMutation => {
                formatter.write_str("QualificationNodeCommand::StartTrafficMutation")
            }
            Self::StopTrafficMutation => {
                formatter.write_str("QualificationNodeCommand::StopTrafficMutation")
            }
            Self::StopTrafficWatch => {
                formatter.write_str("QualificationNodeCommand::StopTrafficWatch")
            }
            Self::TrafficStatus => formatter.write_str("QualificationNodeCommand::TrafficStatus"),
            Self::TrafficStatusSnapshot => {
                formatter.write_str("QualificationNodeCommand::TrafficStatusSnapshot")
            }
            Self::Acquire { .. } => formatter.write_str("QualificationNodeCommand::Acquire"),
            Self::CompareAndSet { value, .. } => formatter
                .debug_struct("QualificationNodeCommand::CompareAndSet")
                .field("value_bytes", &value.len())
                .finish(),
            Self::Get { .. } => formatter.write_str("QualificationNodeCommand::Get"),
            Self::Release { .. } => formatter.write_str("QualificationNodeCommand::Release"),
            Self::Shutdown => formatter.write_str("QualificationNodeCommand::Shutdown"),
        }
    }
}

impl QualificationNodeCommand {
    /// Validate all attacker-controlled fields before a backend or provider is
    /// consulted by the child process.
    pub fn validate(&self) -> Result<(), QualificationCommandError> {
        match self {
            Self::Configure
            | Self::Initialize
            | Self::Probe
            | Self::ProjectedSourceStatus
            | Self::MaterialStatus
            | Self::ReauthenticationGeneration
            | Self::RequestReauthentication
            | Self::LifecycleMetrics
            | Self::SetConsensusRpcAvailability { .. }
            | Self::SecurityMetrics
            | Self::StartTrafficWatch
            | Self::ReconcileTrafficWatch
            | Self::StartTrafficMutation
            | Self::StopTrafficMutation
            | Self::StopTrafficWatch
            | Self::TrafficStatus
            | Self::TrafficStatusSnapshot
            | Self::Shutdown => Ok(()),
            Self::DirectedHandshake { remote_node_index } => {
                if *remote_node_index < 5 {
                    Ok(())
                } else {
                    Err(QualificationCommandError::NodeIndex)
                }
            }
            Self::Acquire {
                lease_handle,
                stable_id,
                owner,
                ttl_millis,
            } => {
                validate_handle(lease_handle)?;
                validate_stable_id(stable_id)?;
                OwnerId::new(owner.clone()).map_err(|_| QualificationCommandError::Owner)?;
                validate_session_ttl(Duration::from_millis(*ttl_millis))
                    .map_err(|_| QualificationCommandError::Ttl)
            }
            Self::CompareAndSet {
                lease_handle,
                stable_id,
                expected_generation,
                new_generation,
                value,
            } => {
                validate_handle(lease_handle)?;
                validate_stable_id(stable_id)?;
                if *new_generation == 0
                    || expected_generation.is_some_and(|current| current >= *new_generation)
                {
                    return Err(QualificationCommandError::Generation);
                }
                if value.len() > QUALIFICATION_MAX_VALUE_BYTES {
                    return Err(QualificationCommandError::Value);
                }
                Ok(())
            }
            Self::Get { stable_id } => validate_stable_id(stable_id),
            Self::Release { lease_handle } => validate_handle(lease_handle),
        }
    }
}

fn validate_handle(value: &str) -> Result<(), QualificationCommandError> {
    if value.is_empty()
        || value.len() > 64
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(QualificationCommandError::LeaseHandle);
    }
    Ok(())
}

fn validate_stable_id(value: &str) -> Result<(), QualificationCommandError> {
    if value.is_empty() || value.len() > STABLE_ID_MAX_BYTES {
        return Err(QualificationCommandError::StableId);
    }
    Ok(())
}

/// Fixed validation failures for the child control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationCommandError {
    #[error("qualification node index is invalid")]
    NodeIndex,
    #[error("qualification lease handle is invalid")]
    LeaseHandle,
    #[error("qualification stable ID is invalid")]
    StableId,
    #[error("qualification owner is invalid")]
    Owner,
    #[error("qualification TTL is invalid")]
    Ttl,
    #[error("qualification generation is invalid")]
    Generation,
    #[error("qualification value is invalid")]
    Value,
}

/// Fixed response categories emitted by a qualification child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationNodeReply {
    Bound {
        node_index: usize,
        bind_addr: SocketAddr,
    },
    Started {
        node_index: usize,
    },
    Initialized,
    Readiness {
        ready: bool,
        reason_code: QualificationReadinessCode,
        node_id: u64,
        term: u64,
        leader_id: Option<u64>,
        configured_voters: usize,
        /// Minimum distinct voters proven reachable by the successful
        /// Openraft barrier, or zero when no barrier succeeded.
        fresh_reachable_voters: usize,
        /// Minimum distinct voters whose agreement was proven by Openraft
        /// commit, or zero when no barrier succeeded.
        agreeing_voters: usize,
        required_quorum: usize,
        committed_index: Option<u64>,
        applied_index: Option<u64>,
    },
    ProjectedSourceStatus {
        status: QualificationProjectedSvidStatus,
    },
    MaterialStatus {
        status: QualificationTlsMaterialStatus,
    },
    ReauthenticationGeneration {
        generation: u64,
    },
    ReauthenticationRequested {
        generation: u64,
    },
    /// Successful authenticated TLS plus exact manifest-bootstrap proof.
    /// This reply does not attest to valid ReadBarrier handler execution.
    DirectedHandshake {
        remote_node_index: usize,
        reauthentication_generation: u64,
    },
    LifecycleMetrics {
        metrics: QualificationConnectionLifecycleMetrics,
    },
    ConsensusRpcAvailability {
        availability: QualificationConsensusRpcAvailability,
    },
    SecurityMetrics {
        metrics: QualificationSecurityMetricsSnapshot,
    },
    TrafficStatus {
        status: QualificationTrafficStatus,
    },
    LeaseAcquired {
        fence: u64,
    },
    CompareAndSet {
        applied: bool,
        current_generation: Option<u64>,
    },
    Record {
        present: bool,
        generation: Option<u64>,
        owner_sha256: Option<String>,
        fence: Option<u64>,
        value_sha256: Option<String>,
    },
    Released,
    ShuttingDown,
    Error {
        code: QualificationNodeErrorCode,
    },
}

/// Closed availability state for the qualification-only consensus RPC gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationConsensusRpcAvailability {
    Available,
    Unavailable,
}

/// Fixed four-outcome snapshot for one closed security-material class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSecurityRotationSnapshot {
    pub success: u64,
    pub retained_last_good: u64,
    pub rejected: u64,
    pub expired: u64,
    pub success_saturated: bool,
    pub retained_last_good_saturated: bool,
    pub rejected_saturated: bool,
    pub expired_saturated: bool,
}

/// Redacted, fixed-cardinality security telemetry exposed to qualification.
///
/// The shape deliberately contains no labels, identities, paths, certificate
/// material, or dynamically sized collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSecurityMetricsSnapshot {
    pub svid_expires_seconds: i64,
    pub bundle_version: u64,
    pub saturated_series: usize,
    pub tls_material: QualificationSecurityRotationSnapshot,
    pub svid: QualificationSecurityRotationSnapshot,
    pub trust_bundle: QualificationSecurityRotationSnapshot,
}

impl From<SecurityMetricsSnapshot> for QualificationSecurityMetricsSnapshot {
    fn from(snapshot: SecurityMetricsSnapshot) -> Self {
        Self {
            svid_expires_seconds: snapshot.svid_expires_seconds(),
            bundle_version: snapshot.bundle_version(),
            saturated_series: snapshot.saturated_series(),
            tls_material: qualification_security_rotation_snapshot(
                snapshot,
                SecurityRotationKind::TlsMaterial,
            ),
            svid: qualification_security_rotation_snapshot(snapshot, SecurityRotationKind::Svid),
            trust_bundle: qualification_security_rotation_snapshot(
                snapshot,
                SecurityRotationKind::TrustBundle,
            ),
        }
    }
}

fn qualification_security_rotation_snapshot(
    snapshot: SecurityMetricsSnapshot,
    kind: SecurityRotationKind,
) -> QualificationSecurityRotationSnapshot {
    QualificationSecurityRotationSnapshot {
        success: snapshot.rotation(kind, SecurityRotationOutcome::Success),
        retained_last_good: snapshot.rotation(kind, SecurityRotationOutcome::RetainedLastGood),
        rejected: snapshot.rotation(kind, SecurityRotationOutcome::Rejected),
        expired: snapshot.rotation(kind, SecurityRotationOutcome::Expired),
        success_saturated: snapshot.rotation_saturated(kind, SecurityRotationOutcome::Success),
        retained_last_good_saturated: snapshot
            .rotation_saturated(kind, SecurityRotationOutcome::RetainedLastGood),
        rejected_saturated: snapshot.rotation_saturated(kind, SecurityRotationOutcome::Rejected),
        expired_saturated: snapshot.rotation_saturated(kind, SecurityRotationOutcome::Expired),
    }
}

/// Redaction-safe status from the projected-volume source, kept separate from
/// the TLS controller status so a coherent file publication cannot be
/// mistaken for handshake-ready material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProjectedSvidStatus {
    pub generation: u64,
    pub availability: QualificationProjectedSvidAvailability,
    pub reason: Option<QualificationProjectedSvidReason>,
}

impl From<ProjectedSvidReloadStatus> for QualificationProjectedSvidStatus {
    fn from(status: ProjectedSvidReloadStatus) -> Self {
        Self {
            generation: status.generation(),
            availability: status.availability().into(),
            reason: status.reason().map(Into::into),
        }
    }
}

/// Closed projected-volume source availability vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationProjectedSvidAvailability {
    Initializing,
    Ready,
    RetainingLastGood,
    Unavailable,
}

impl From<ProjectedSvidAvailability> for QualificationProjectedSvidAvailability {
    fn from(availability: ProjectedSvidAvailability) -> Self {
        match availability {
            ProjectedSvidAvailability::Initializing => Self::Initializing,
            ProjectedSvidAvailability::Ready => Self::Ready,
            ProjectedSvidAvailability::RetainingLastGood => Self::RetainingLastGood,
            ProjectedSvidAvailability::Unavailable => Self::Unavailable,
        }
    }
}

/// Closed, redaction-safe projected-volume reload reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationProjectedSvidReason {
    AwaitingInitialMaterial,
    GenerationUnavailable,
    InvalidGenerationLink,
    GenerationChanged,
    GenerationRetryLimit,
    ReadAttemptTimeout,
    MaterialUnavailable,
    MaterialNotRegular,
    MaterialFileTooLarge,
    TotalMaterialTooLarge,
    CertificateCountExceeded,
    TrustAnchorCountExceeded,
    MalformedCertificate,
    MalformedPrivateKey,
    MalformedTrustBundle,
    InvalidCertificateChain,
    PrivateKeyMismatch,
    ExpiredSvid,
    NotYetValidSvid,
    InvalidWorkloadIdentity,
    LastGoodExpired,
    GenerationExhausted,
}

impl From<ProjectedSvidReloadReason> for QualificationProjectedSvidReason {
    fn from(reason: ProjectedSvidReloadReason) -> Self {
        match reason {
            ProjectedSvidReloadReason::AwaitingInitialMaterial => Self::AwaitingInitialMaterial,
            ProjectedSvidReloadReason::GenerationUnavailable => Self::GenerationUnavailable,
            ProjectedSvidReloadReason::InvalidGenerationLink => Self::InvalidGenerationLink,
            ProjectedSvidReloadReason::GenerationChanged => Self::GenerationChanged,
            ProjectedSvidReloadReason::GenerationRetryLimit => Self::GenerationRetryLimit,
            ProjectedSvidReloadReason::ReadAttemptTimeout => Self::ReadAttemptTimeout,
            ProjectedSvidReloadReason::MaterialUnavailable => Self::MaterialUnavailable,
            ProjectedSvidReloadReason::MaterialNotRegular => Self::MaterialNotRegular,
            ProjectedSvidReloadReason::MaterialFileTooLarge => Self::MaterialFileTooLarge,
            ProjectedSvidReloadReason::TotalMaterialTooLarge => Self::TotalMaterialTooLarge,
            ProjectedSvidReloadReason::CertificateCountExceeded => Self::CertificateCountExceeded,
            ProjectedSvidReloadReason::TrustAnchorCountExceeded => Self::TrustAnchorCountExceeded,
            ProjectedSvidReloadReason::MalformedCertificate => Self::MalformedCertificate,
            ProjectedSvidReloadReason::MalformedPrivateKey => Self::MalformedPrivateKey,
            ProjectedSvidReloadReason::MalformedTrustBundle => Self::MalformedTrustBundle,
            ProjectedSvidReloadReason::InvalidCertificateChain => Self::InvalidCertificateChain,
            ProjectedSvidReloadReason::PrivateKeyMismatch => Self::PrivateKeyMismatch,
            ProjectedSvidReloadReason::ExpiredSvid => Self::ExpiredSvid,
            ProjectedSvidReloadReason::NotYetValidSvid => Self::NotYetValidSvid,
            ProjectedSvidReloadReason::InvalidWorkloadIdentity => Self::InvalidWorkloadIdentity,
            ProjectedSvidReloadReason::LastGoodExpired => Self::LastGoodExpired,
            ProjectedSvidReloadReason::GenerationExhausted => Self::GenerationExhausted,
        }
    }
}

/// Closed durable-readiness result carried across the test control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationReadinessCode {
    Ready,
    NoQuorum,
    TopologyInvalid,
    RecoveryRequired,
}

/// Redaction-safe TLS material state emitted by a qualification child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTlsMaterialStatus {
    pub epoch: u64,
    pub availability: QualificationTlsMaterialAvailability,
    pub reason: Option<QualificationTlsMaterialReason>,
    pub leaf_expires_at: Option<Timestamp>,
    pub certificate_chain_expires_at: Option<Timestamp>,
}

impl From<TlsMaterialStatus> for QualificationTlsMaterialStatus {
    fn from(status: TlsMaterialStatus) -> Self {
        Self {
            epoch: status.epoch().get(),
            availability: status.availability().into(),
            reason: status.reason().map(Into::into),
            leaf_expires_at: status.leaf_expires_at(),
            certificate_chain_expires_at: status.certificate_chain_expires_at(),
        }
    }
}

/// Closed TLS material availability vocabulary for qualification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTlsMaterialAvailability {
    Initializing,
    Ready,
    RetainingLastGood,
    Unavailable,
}

impl From<TlsMaterialAvailability> for QualificationTlsMaterialAvailability {
    fn from(availability: TlsMaterialAvailability) -> Self {
        match availability {
            TlsMaterialAvailability::Initializing => Self::Initializing,
            TlsMaterialAvailability::Ready => Self::Ready,
            TlsMaterialAvailability::RetainingLastGood => Self::RetainingLastGood,
            TlsMaterialAvailability::Unavailable => Self::Unavailable,
        }
    }
}

/// Closed TLS material reason vocabulary for qualification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTlsMaterialReason {
    AwaitingInitialMaterial,
    MaterialUnavailable,
    SourceClosed,
    MaterialLimitExceeded,
    InvalidCertificateChain,
    PrivateKeyMismatch,
    ExpiredMaterial,
    NotYetValidMaterial,
    InvalidWorkloadIdentity,
    LocalIdentityChanged,
    LastGoodExpired,
    EpochExhausted,
}

impl From<TlsMaterialReloadReason> for QualificationTlsMaterialReason {
    fn from(reason: TlsMaterialReloadReason) -> Self {
        match reason {
            TlsMaterialReloadReason::AwaitingInitialMaterial => Self::AwaitingInitialMaterial,
            TlsMaterialReloadReason::MaterialUnavailable => Self::MaterialUnavailable,
            TlsMaterialReloadReason::SourceClosed => Self::SourceClosed,
            TlsMaterialReloadReason::MaterialLimitExceeded => Self::MaterialLimitExceeded,
            TlsMaterialReloadReason::InvalidCertificateChain => Self::InvalidCertificateChain,
            TlsMaterialReloadReason::PrivateKeyMismatch => Self::PrivateKeyMismatch,
            TlsMaterialReloadReason::ExpiredMaterial => Self::ExpiredMaterial,
            TlsMaterialReloadReason::NotYetValidMaterial => Self::NotYetValidMaterial,
            TlsMaterialReloadReason::InvalidWorkloadIdentity => Self::InvalidWorkloadIdentity,
            TlsMaterialReloadReason::LocalIdentityChanged => Self::LocalIdentityChanged,
            TlsMaterialReloadReason::LastGoodExpired => Self::LastGoodExpired,
            TlsMaterialReloadReason::EpochExhausted => Self::EpochExhausted,
        }
    }
}

/// Fixed-cardinality process-local lifecycle metrics captured at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConnectionLifecycleMetrics {
    pub retirement_maximum_age: u64,
    pub retirement_local_leaf_expiry: u64,
    pub retirement_peer_leaf_expiry: u64,
    pub retirement_local_certificate_chain_expiry: u64,
    pub retirement_peer_certificate_chain_expiry: u64,
    pub retirement_material_epoch: u64,
    pub retirement_explicit: u64,
    pub retirement_idle_timeout: u64,
    pub active_connections: i64,
    pub draining_connections: i64,
    pub drain_started: u64,
    pub drain_completed: u64,
    pub drain_overruns: u64,
    pub connection_attempts: u64,
    pub connection_successes: u64,
    pub connection_failure_transport: u64,
    pub connection_failure_authentication: u64,
    pub connection_failure_timeout: u64,
    pub connection_superseded: u64,
    pub connection_abandoned: u64,
    pub connection_failure_protocol: u64,
    pub connection_failure_backend: u64,
    pub reconnect_attempts: u64,
    pub reconnect_failures: u64,
    /// Invalid empty Vote requests that reached the application handler.
    /// Qualification uses this fixed probe shape to prove stale credentials
    /// fail before consensus dispatch.
    pub empty_vote_dispatches: u64,
}

/// Closed lifecycle state for the two qualification-owned workload tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTrafficState {
    WatchReady,
    Running,
    MutationStopped,
    Stopped,
    Failed,
}

/// Fixed, non-sensitive failure categories for background qualification work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTrafficFailureCode {
    BackendUnavailable,
    LeaseRejected,
    WatchUnavailable,
    RestoreScanRejected,
    ReadinessUnavailable,
    AvailabilityRecoveryDeadlineExceeded,
    InvariantViolation,
    TaskJoinUnavailable,
}

/// Fixed operation stage at which background qualification work first failed.
///
/// The values intentionally contain no key, owner, peer, request, or payload
/// identity. Together with [`QualificationTrafficErrorClass`], this preserves
/// actionable failure evidence without forwarding backend error text across the
/// child-process control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTrafficFailureStage {
    LeaseRenew,
    CompareAndSet,
    Get,
    RestoreScan,
    ReadinessProbe,
    LeaseRelease,
    LeaseAcquire,
    Watch,
    TaskJoin,
}

/// Redaction-safe closed classification of the first traffic-task error.
///
/// Raw `StoreError`/`LeaseError` strings never enter this model. `Other` is the
/// fixed fail-closed bucket for invariant, stream-closure, and unclassified
/// errors and does not carry source data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTrafficErrorClass {
    BackendUnavailable,
    CasIdempotencyOutcomeUnavailable,
    BackendOperationOutcomeUnavailable,
    LeaseLostOrInvalid,
    Other,
}

/// Plaintext-free progress from one node's deterministic traffic workload.
///
/// `owned_async_tasks` counts only the watch and mutation tasks created by the
/// two traffic-start commands; it does not pretend to inventory Openraft, TLS,
/// or Tokio internal tasks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTrafficStatus {
    pub state: QualificationTrafficState,
    pub failure: Option<QualificationTrafficFailureCode>,
    pub failure_stage: Option<QualificationTrafficFailureStage>,
    pub failure_error_class: Option<QualificationTrafficErrorClass>,
    /// Elapsed milliseconds from the start of a bounded availability-recovery
    /// episode when `failure` is `availability_recovery_deadline_exceeded`.
    /// Other failures report no value. This duration is identity-free and
    /// never contains backend error text.
    pub failure_recovery_elapsed_millis: Option<u64>,
    pub seed: u64,
    pub owned_async_tasks: u8,
    pub mutation_cycles: u64,
    pub linearizable_reads: u64,
    pub lease_renewals: u64,
    pub lease_reacquisitions: u64,
    /// Typed, recoverable availability outcomes observed at terminal backend
    /// checkpoints. This never includes semantic or invariant failures.
    pub availability_interruptions: u64,
    /// Typed interruption outcomes closed by a completed authority-and-record
    /// reconciliation. Ambiguous mutation outcomes advance the fence; read-only
    /// checkpoints retain and revalidate the already-proven guard. Equality
    /// with `availability_interruptions` proves no recovery episode is still
    /// unresolved.
    pub availability_recoveries: u64,
    /// Largest uninterrupted run of typed availability outcomes before a
    /// successful reconciliation.
    pub max_consecutive_availability_interruptions: u64,
    pub complete_restore_scans: u64,
    pub durable_readiness_probes: u64,
    /// Exact committed generation recovered before a restarted mutation task
    /// is admitted. Zero means this process did not resume prior mutation
    /// state.
    pub mutation_resume_generation: u64,
    /// Exact committed record fence recovered with
    /// `mutation_resume_generation`. A resumed mutation must acquire and write
    /// under a strictly higher fence.
    pub mutation_resume_record_fence: u64,
    pub last_generation: u64,
    pub last_record_fence: u64,
    pub watch_entries: u64,
    pub watch_applied_records: u64,
    pub watch_sequence: u64,
    /// Number of bounded application-journal reconciliations used before an
    /// exact watch resubscription.
    pub watch_reconciliations: u64,
    /// Applied head bound to the most recent reconciliation, or zero when the
    /// initial watch has never required reconciliation.
    pub watch_reconciled_sequence: u64,
    /// Last generation either observed gap-free or restored at a proven
    /// reconciliation handoff for each topology-ordered synthetic traffic
    /// key. The vector is bounded to the validated 3/5-member fleet.
    pub watch_traffic_generations: Vec<u64>,
    /// Most recent successfully proven linearizable replication head. Stop
    /// replies reuse this cached proof and do not launch a new backend
    /// operation after their owned task has joined.
    pub replication_head: u64,
}

/// Low-cardinality child-process error codes; raw backend errors never cross
/// the control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationNodeErrorCode {
    InvalidRequest,
    InitializationUnavailable,
    BackendUnavailable,
    LeaseRejected,
    LeaseHandleDuplicate,
    LeaseHandleMissing,
    MutationRejected,
    TransportUnavailable,
    MaterialUnavailable,
    DirectedHandshakeUnavailable,
    TrafficUnavailable,
}

/// Bounded JSON-line decoding failure.
#[derive(Debug, thiserror::Error)]
pub enum QualificationLineError {
    #[error("qualification control I/O failed")]
    Io(#[from] io::Error),
    #[error("qualification control line exceeds its bound")]
    TooLarge,
    #[error("qualification control line is invalid")]
    Invalid,
}

/// Read and strictly decode one bounded JSON line.
pub fn read_bounded_json_line<R, T>(reader: &mut R) -> Result<Option<T>, QualificationLineError>
where
    R: BufRead,
    T: DeserializeOwned,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len().saturating_add(newline) > QUALIFICATION_MAX_CONTROL_LINE_BYTES {
                reader.consume(newline + 1);
                return Err(QualificationLineError::TooLarge);
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            break;
        }

        if line.len().saturating_add(available.len()) > QUALIFICATION_MAX_CONTROL_LINE_BYTES {
            let consumed = available.len();
            reader.consume(consumed);
            drain_to_newline(reader)?;
            return Err(QualificationLineError::TooLarge);
        }
        line.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }

    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.is_empty() {
        return Err(QualificationLineError::Invalid);
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|_| QualificationLineError::Invalid)
}

fn drain_to_newline<R: BufRead>(reader: &mut R) -> Result<(), io::Error> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            reader.consume(newline + 1);
            return Ok(());
        }
        let consumed = available.len();
        reader.consume(consumed);
    }
}

/// Encode and flush one bounded control response.
pub fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<(), QualificationLineError>
where
    W: Write,
    T: Serialize,
{
    let encoded = serde_json::to_vec(value).map_err(|_| QualificationLineError::Invalid)?;
    if encoded.len() > QUALIFICATION_MAX_CONTROL_LINE_BYTES {
        return Err(QualificationLineError::TooLarge);
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_line_reader_rejects_oversize_before_next_frame() {
        let input = format!(
            "{}\n{{\"command\":\"probe\"}}\n",
            "x".repeat(QUALIFICATION_MAX_CONTROL_LINE_BYTES + 1)
        );
        let mut reader = io::BufReader::new(input.as_bytes());
        let first = read_bounded_json_line::<_, QualificationNodeCommand>(&mut reader);
        assert!(matches!(first, Err(QualificationLineError::TooLarge)));
        let second = read_bounded_json_line::<_, QualificationNodeCommand>(&mut reader)
            .expect("read bounded frame")
            .expect("frame present");
        assert!(matches!(second, QualificationNodeCommand::Probe));
    }

    #[test]
    fn projected_source_status_has_a_distinct_strict_control_frame() {
        let reply = QualificationNodeReply::ProjectedSourceStatus {
            status: QualificationProjectedSvidStatus {
                generation: 7,
                availability: QualificationProjectedSvidAvailability::Ready,
                reason: None,
            },
        };
        let mut encoded = Vec::new();
        write_json_line(&mut encoded, &reply).expect("encode projected status");
        let text = std::str::from_utf8(&encoded).expect("status is JSON");
        assert!(text.contains("projected_source_status"));
        assert!(!text.contains("material_status"));
        assert!(!text.contains("tls.crt"));
        assert!(!text.contains("..data"));

        let mut reader = io::BufReader::new(encoded.as_slice());
        let decoded = read_bounded_json_line::<_, QualificationNodeReply>(&mut reader)
            .expect("decode projected status")
            .expect("projected status frame");
        assert!(matches!(
            decoded,
            QualificationNodeReply::ProjectedSourceStatus {
                status: QualificationProjectedSvidStatus {
                    generation: 7,
                    availability: QualificationProjectedSvidAvailability::Ready,
                    reason: None,
                },
            }
        ));

        let with_unknown = text
            .trim_end()
            .replace("\"reason\":null}", "\"reason\":null,\"path\":\"secret\"}");
        assert!(serde_json::from_str::<QualificationNodeReply>(&with_unknown).is_err());
    }

    #[test]
    fn rpc_gate_and_security_metrics_have_closed_redacted_control_frames() {
        let command = QualificationNodeCommand::SetConsensusRpcAvailability {
            availability: QualificationConsensusRpcAvailability::Unavailable,
        };
        let encoded = serde_json::to_string(&command).expect("encode RPC gate command");
        assert_eq!(
            encoded,
            r#"{"command":"set_consensus_rpc_availability","availability":"unavailable"}"#
        );
        assert!(command.validate().is_ok());
        assert!(serde_json::from_str::<QualificationNodeCommand>(
            r#"{"command":"set_consensus_rpc_availability","availability":"unavailable","node":"secret"}"#
        )
        .is_err());

        let zero_rotation = QualificationSecurityRotationSnapshot {
            success: 0,
            retained_last_good: 0,
            rejected: 0,
            expired: 0,
            success_saturated: false,
            retained_last_good_saturated: false,
            rejected_saturated: false,
            expired_saturated: false,
        };
        let reply = QualificationNodeReply::SecurityMetrics {
            metrics: QualificationSecurityMetricsSnapshot {
                svid_expires_seconds: 0,
                bundle_version: 0,
                saturated_series: 0,
                tls_material: zero_rotation,
                svid: zero_rotation,
                trust_bundle: zero_rotation,
            },
        };
        let encoded = serde_json::to_string(&reply).expect("encode security metrics");
        for forbidden in ["spiffe://", "tls.crt", "ca.crt", "private_key", "identity"] {
            assert!(!encoded.contains(forbidden));
        }
        let with_unknown = encoded.replacen(
            "\"bundle_version\":0,",
            "\"bundle_version\":0,\"certificate\":\"secret\",",
            1,
        );
        assert!(serde_json::from_str::<QualificationNodeReply>(&with_unknown).is_err());

        let source = opc_redaction::metrics::SecurityMetricsReader::global().snapshot();
        let mapped = QualificationSecurityMetricsSnapshot::from(source);
        assert_eq!(mapped.svid_expires_seconds, source.svid_expires_seconds());
        assert_eq!(mapped.bundle_version, source.bundle_version());
        assert_eq!(mapped.saturated_series, source.saturated_series());
        for (kind, actual) in [
            (SecurityRotationKind::TlsMaterial, mapped.tls_material),
            (SecurityRotationKind::Svid, mapped.svid),
            (SecurityRotationKind::TrustBundle, mapped.trust_bundle),
        ] {
            assert_eq!(
                actual.success,
                source.rotation(kind, SecurityRotationOutcome::Success)
            );
            assert_eq!(
                actual.retained_last_good,
                source.rotation(kind, SecurityRotationOutcome::RetainedLastGood)
            );
            assert_eq!(
                actual.rejected,
                source.rotation(kind, SecurityRotationOutcome::Rejected)
            );
            assert_eq!(
                actual.expired,
                source.rotation(kind, SecurityRotationOutcome::Expired)
            );
            assert_eq!(
                actual.success_saturated,
                source.rotation_saturated(kind, SecurityRotationOutcome::Success)
            );
            assert_eq!(
                actual.retained_last_good_saturated,
                source.rotation_saturated(kind, SecurityRotationOutcome::RetainedLastGood)
            );
            assert_eq!(
                actual.rejected_saturated,
                source.rotation_saturated(kind, SecurityRotationOutcome::Rejected)
            );
            assert_eq!(
                actual.expired_saturated,
                source.rotation_saturated(kind, SecurityRotationOutcome::Expired)
            );
        }
    }

    #[test]
    fn traffic_schedule_is_topology_bound_and_status_is_strict() {
        assert_eq!(QUALIFICATION_OPERATION_TIMEOUT_MILLIS, 10_000);
        assert_eq!(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS, 45_000);
        assert_eq!(QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS, 75_000);
        assert_eq!(QUALIFICATION_FAULT_PATH_REFRESH_MILLIS, 5_000);
        assert_eq!(QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR, 2);
        assert_eq!(QUALIFICATION_FAULT_TRAFFIC_STOP_LEAD_MILLIS, 1_000);
        assert_eq!(QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS, 30_000);
        assert_eq!(
            QUALIFICATION_TRAFFIC_CANCELLATION_PROFILE,
            "accepted-operation-terminal-checkpoints/v1"
        );
        assert_eq!(QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER, 2);
        assert_eq!(QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR, 4);
        assert_eq!(
            QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE,
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS
        );
        assert_eq!(QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE, 8);
        assert_eq!(
            QUALIFICATION_MAX_CONCURRENT_LINEARIZABILITY_CHECKS_PER_OPENRAFT_NODE,
            DURABLE_OPENRAFT_LINEARIZABILITY_WORKER_COUNT
        );
        assert_eq!(
            QUALIFICATION_MAX_CONCURRENT_LINEARIZABILITY_CHECKS_PER_OPENRAFT_NODE,
            1
        );
        assert_eq!(
            QUALIFICATION_LINEARIZABILITY_ADMISSION_CAPACITY_PER_OPENRAFT_NODE,
            DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY
        );
        assert_eq!(
            QUALIFICATION_LINEARIZABILITY_ADMISSION_CAPACITY_PER_OPENRAFT_NODE,
            64
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
            8
        );
        assert_eq!(QUALIFICATION_TRAFFIC_TTL_MILLIS, 3_600_000);
        assert_eq!(QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS, 26_000);
        assert_eq!(
            QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS,
            DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
                + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis
        );
        const {
            assert!(
                QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
                    >= DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis
            );
            assert!(
                QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
                    >= DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis * 2
                        + QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS
            );
            assert!(
                QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
                    < QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS
            );
            assert!(
                QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
                    + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis
                    <= QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS
            );
        }
        assert_eq!(QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS, 50);
        assert_eq!(
            QUALIFICATION_TRAFFIC_AUTHORITY_RECONCILIATION_PROFILE,
            "stage-aware-known-authority/v1"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_PROFILE,
            "post-release-response-loss/v1"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_RESTART_PROFILE,
            "committed-generation-does-not-rearm/v1"
        );
        assert_eq!(QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS, 25_000);
        assert_eq!(
            QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES,
            262_144
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PAGE_ENTRIES,
            MAX_REPLICATION_LOG_PAGE_ENTRIES
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PROFILE,
            "bounded-durable-journal/v1"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_PROFILE,
            "same-disk-exact-address-active-mutator/v2"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS,
            5_000
        );
        assert_eq!(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS, 26_000);
        assert_eq!(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS, 45_000);
        assert_eq!(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS, 26_000);
        assert_eq!(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS, 26_000);
        assert_eq!(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS, 153_000);
        const {
            assert!(
                QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS
                    == QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS
                        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS
                        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS
                        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS
                        + QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS
                        + QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS
            );
        }
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROFILE,
            "member-scoped-reauth-settled-baseline/v2"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_MILLIS,
            62_500
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS,
            86_000
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS,
            13_000
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
            1
        );
        assert_eq!(
            qualification_traffic_seed(3),
            Some(QUALIFICATION_TRAFFIC_SEED_BASE ^ 3)
        );
        assert_eq!(
            qualification_traffic_seed(5),
            Some(QUALIFICATION_TRAFFIC_SEED_BASE ^ 5)
        );
        assert_eq!(qualification_traffic_seed(4), None);
        let three = qualification_traffic_schedule_sha256(3).expect("three-voter schedule");
        let five = qualification_traffic_schedule_sha256(5).expect("five-voter schedule");
        assert_eq!(
            (three.as_str(), five.as_str()),
            (
                "sha256:5af6a9eb10a034fc5fedbbfc160be693b9c404aa86872d1f72db1bf6cb095d37",
                "sha256:6d949427f1d5d459afa408424af5b6ee995f15945759f3f9b8a4be093d3f6ec3",
            )
        );
        assert!(is_exact_sha256(&three));
        assert!(is_exact_sha256(&five));
        assert_ne!(three, five);
        assert_eq!(qualification_traffic_schedule_sha256(4), None);

        let reply = QualificationNodeReply::TrafficStatus {
            status: QualificationTrafficStatus {
                state: QualificationTrafficState::Running,
                failure: None,
                failure_stage: None,
                failure_error_class: None,
                failure_recovery_elapsed_millis: None,
                seed: QUALIFICATION_TRAFFIC_SEED_BASE ^ 3,
                owned_async_tasks: 2,
                mutation_cycles: 7,
                linearizable_reads: 7,
                lease_renewals: 7,
                lease_reacquisitions: 7,
                availability_interruptions: 1,
                availability_recoveries: 1,
                max_consecutive_availability_interruptions: 1,
                complete_restore_scans: 7,
                durable_readiness_probes: 7,
                mutation_resume_generation: 0,
                mutation_resume_record_fence: 0,
                last_generation: 7,
                last_record_fence: 8,
                watch_entries: 43,
                watch_applied_records: 21,
                watch_sequence: 44,
                watch_reconciliations: 0,
                watch_reconciled_sequence: 0,
                watch_traffic_generations: vec![7, 8, 9],
                replication_head: 44,
            },
        };
        let encoded = serde_json::to_string(&reply).expect("encode strict traffic status");
        assert!(!encoded.contains("opc-rotation-traffic-canary"));
        assert!(!encoded.contains("rotation-traffic-owner"));
        let with_unknown = encoded.replacen(
            "\"replication_head\":44}",
            "\"replication_head\":44,\"payload\":\"secret\"}",
            1,
        );
        assert!(serde_json::from_str::<QualificationNodeReply>(&with_unknown).is_err());
    }

    #[test]
    fn config_rejects_non_loopback_plaintext_routes() {
        let members = (0..3)
            .map(|node_index| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: 7443 + node_index as u16,
                dial_addr: format!("192.0.2.1:{}", 7443 + node_index as u16)
                    .parse()
                    .expect("test address"),
                tls_identity: format!("spiffe://qualification.invalid/node/{node_index}"),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect();
        let config = QualificationNodeConfig {
            schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            node_index: 0,
            cluster_id: "qualification-cluster".to_owned(),
            configuration_generation: "v1".to_owned(),
            configuration_epoch: 1,
            backend_namespace: "qualification-cluster".to_owned(),
            workload_schedule_sha256: format!("sha256:{}", "a".repeat(64)),
            members,
            workspace_directory: PathBuf::from("/qualification"),
            database_path: PathBuf::from("/qualification/node.sqlite"),
            snapshot_directory: PathBuf::from("/qualification/snapshots"),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
        };
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
    }

    fn valid_config() -> QualificationNodeConfig {
        let members = (0..3)
            .map(|node_index| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: 7443 + node_index as u16,
                dial_addr: format!("127.0.0.1:{}", 7443 + node_index as u16)
                    .parse()
                    .expect("test address"),
                tls_identity: format!(
                    "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
                ),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect();
        QualificationNodeConfig {
            schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            node_index: 0,
            cluster_id: "qualification-cluster".to_owned(),
            configuration_generation: "v1".to_owned(),
            configuration_epoch: 1,
            backend_namespace: "qualification-cluster".to_owned(),
            workload_schedule_sha256: format!("sha256:{}", "a".repeat(64)),
            members,
            workspace_directory: PathBuf::from("/qualification"),
            database_path: PathBuf::from("/qualification/node.sqlite"),
            snapshot_directory: PathBuf::from("/qualification/snapshots"),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
        }
    }

    #[test]
    fn node_control_schema_rejects_pre_lifecycle_outcome_version() {
        assert_eq!(QUALIFICATION_NODE_SCHEMA_VERSION, 2);
        let mut config = valid_config();
        config.schema_version = 1;
        assert_eq!(config.validate(), Err(QualificationConfigError::Schema));
    }

    #[test]
    fn config_requires_distinct_vote_and_route_identities() {
        let mut config = valid_config();
        assert_eq!(config.validate(), Ok(()));

        config.members[2].dial_addr = config.members[1].dial_addr;
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
        config = valid_config();
        config.members[2].failure_domain = config.members[1].failure_domain.clone();
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
        config = valid_config();
        config.members[2].backing_identity = config.members[1].backing_identity.clone();
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
        config = valid_config();
        config.members[2].endpoint_host = config.members[1].endpoint_host.to_uppercase();
        config.members[2].endpoint_port = config.members[1].endpoint_port;
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
    }

    #[test]
    fn commands_fail_before_backend_on_every_bounded_field() {
        let valid = QualificationNodeCommand::Acquire {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            owner: "owner-1".to_owned(),
            ttl_millis: 60_000,
        };
        assert_eq!(valid.validate(), Ok(()));

        let oversized_value = QualificationNodeCommand::CompareAndSet {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            expected_generation: None,
            new_generation: 1,
            value: "x".repeat(QUALIFICATION_MAX_VALUE_BYTES + 1),
        };
        assert_eq!(
            oversized_value.validate(),
            Err(QualificationCommandError::Value)
        );
        let oversized_ttl = QualificationNodeCommand::Acquire {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            owner: "owner-1".to_owned(),
            ttl_millis: (opc_session_store::MAX_SESSION_TTL.as_millis() as u64) + 1,
        };
        assert_eq!(
            oversized_ttl.validate(),
            Err(QualificationCommandError::Ttl)
        );
        let invalid_generation = QualificationNodeCommand::CompareAndSet {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            expected_generation: Some(1),
            new_generation: 1,
            value: String::new(),
        };
        assert_eq!(
            invalid_generation.validate(),
            Err(QualificationCommandError::Generation)
        );

        assert_eq!(
            QualificationNodeCommand::DirectedHandshake {
                remote_node_index: 5,
            }
            .validate(),
            Err(QualificationCommandError::NodeIndex)
        );
    }

    #[test]
    fn projected_mtls_config_is_bounded_and_redacts_material_paths() {
        let mut config = valid_config();
        config.transport =
            QualificationTransportConfig::ProjectedMtls(QualificationProjectedMtlsConfig {
                projected_volume_root: PathBuf::from("/qualification/projected"),
                certificate_file: PathBuf::from("tls.crt"),
                private_key_file: PathBuf::from("tls.key"),
                trust_bundle_files: vec![PathBuf::from("ca.crt")],
                poll_interval_millis: 100,
                lifecycle: QualificationConnectionLifecycleConfig {
                    maximum_authentication_age_millis: 60_000,
                    rotation_drain_window_millis: 5_000,
                    reconnect_backoff_min_millis: 25,
                    reconnect_backoff_max_millis: 250,
                    rotation_jitter_millis: 1_000,
                },
            });
        assert_eq!(config.validate(), Ok(()));
        let rendered = format!("{config:?}");
        for path in ["/qualification/projected", "tls.crt", "tls.key", "ca.crt"] {
            assert!(!rendered.contains(path));
        }

        let QualificationTransportConfig::ProjectedMtls(projected) = &mut config.transport else {
            panic!("projected transport")
        };
        projected.certificate_file = PathBuf::from("../tls.crt");
        assert_eq!(
            config.validate(),
            Err(QualificationConfigError::Configuration)
        );
    }

    #[test]
    fn config_debug_redacts_paths_routes_and_identities() {
        let config = valid_config();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("qualification.invalid"));
        assert!(!rendered.contains("node.sqlite"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn command_debug_never_exposes_control_fields_or_values() {
        let command = QualificationNodeCommand::CompareAndSet {
            lease_handle: "private-lease".to_owned(),
            stable_id: "private-session".to_owned(),
            expected_generation: Some(1),
            new_generation: 2,
            value: "private-payload".to_owned(),
        };
        let rendered = format!("{command:?}");
        assert!(rendered.contains("CompareAndSet"));
        for secret in [
            "private-lease",
            "private-session",
            "private-payload",
            "expected_generation",
            "new_generation",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn qualification_digests_match_the_independent_checker_domains() {
        assert_eq!(
            qualification_key_sha256("session-a"),
            "sha256:7689422ed433cc7ee36ce78ed7f5b7d30e3c1d39a6a2a2c72df5b7260ffb8c73"
        );
        assert_eq!(
            qualification_owner_sha256("owner-a"),
            "sha256:12a3b845112c3df86bd8f7658d6c9394622c66b4f50f3bdb951b7185b253f4ba"
        );
        assert_eq!(
            qualification_value_sha256(b"value-1"),
            "sha256:eec72ba1a373f38b17ec083cb92efdef4e526cc8d2d987079d3f336a4ec2f7f5"
        );
    }
}
