//! Experimental qualification profile and multi-process node protocol.
//!
//! The node protocol supports a production-constructor projected-SVID mTLS
//! candidate path. Its older loopback plaintext foundation remains available
//! only behind the testkit's explicit `foundation-insecure` feature and never
//! counts as TLS-rotation evidence.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
/// Closed schema for one bounded concurrent batch/watch/restore/readiness
/// history. This v3 candidate contract does not graduate the experimental HA
/// profile.
pub const SESSION_HA_CONCURRENT_HISTORY_SCHEMA_JSON: &str =
    include_str!("../qualification/v3/session-ha-concurrent-history.schema.json");
/// Closed schema for digest-binding one v3 concurrent-history candidate to an
/// exact artifact, fault schedule, independent checker, and remaining
/// production acceptance. The schema fixes both production-credit fields to
/// false.
pub const SESSION_HA_CANDIDATE_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../qualification/v3/session-ha-candidate-evidence.schema.json");
/// Exact additive v4 profile that binds both independent history-checker
/// families without making a production claim.
pub const SESSION_HA_CANDIDATE_PROFILE_V4_JSON: &str =
    include_str!("../qualification/v4/session-ha-profile.json");
/// JSON Schema for the additive v4 combined-evidence candidate profile.
pub const SESSION_HA_CANDIDATE_PROFILE_V4_SCHEMA_JSON: &str =
    include_str!("../qualification/v4/session-ha-profile.schema.json");
/// Closed manifest schema that digest-binds one v1 sequential history and one
/// v3 concurrent history to the same candidate campaign.
pub const SESSION_HA_CANDIDATE_MANIFEST_V4_SCHEMA_JSON: &str =
    include_str!("../qualification/v4/session-ha-candidate-manifest.schema.json");
/// Maximum accepted size of one v4 candidate profile document.
pub const SESSION_HA_CANDIDATE_PROFILE_V4_MAX_BYTES: usize = 128 * 1024;
/// Maximum accepted size of one v4 combined candidate manifest.
pub const SESSION_HA_CANDIDATE_MANIFEST_V4_MAX_BYTES: usize = 256 * 1024;
/// Complete fixed production-acceptance inventory retained by the v4
/// non-production candidate contract.
pub const SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V4: [&str; 8] = [
    "deployed_kubernetes_3_5",
    "real_network_and_storage_faults",
    "crash_point_matrix",
    "version_migration_and_rollback",
    "platform_resource_soak",
    "remote_hkms_rotation",
    "live_alert_fire_and_clear",
    "signed_release_bundle",
];
/// Strict schema for one incomplete production-mTLS harness checkpoint.
pub const SESSION_MTLS_CANDIDATE_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-mtls-candidate-evidence.schema.json");
/// Closed schema for one digest-bound synthetic projected-mTLS campaign.
///
/// The v2 contract always remains experimental and cannot claim either
/// completed qualification or seamless-rotation production credit.
pub const SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_JSON: &str =
    include_str!("../qualification/v2/session-mtls-candidate-evidence.schema.json");
/// Maximum accepted size of one v2 projected-mTLS candidate evidence document.
///
/// [`SessionMtlsCandidateEvidenceV2::from_json`] applies this bound before
/// deserializing any untrusted JSON.
pub const SESSION_MTLS_CANDIDATE_EVIDENCE_V2_MAX_BYTES: usize = 64 * 1024;

/// Version of the private node configuration and control protocol.
pub const QUALIFICATION_NODE_SCHEMA_VERSION: u16 = 3;
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
    "member-scoped-reauth-settled-baseline/v3";
/// Versioned rolling survivor-progress proof used while an expired member is
/// replaced. Every half-SLO pulse must carry one common committed key through
/// every survivor observer, while an independent full-SLO checkpoint requires
/// coverage of every active survivor key.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_PROFILE: &str =
    "common-key-pulse-all-active-key-coverage/v1";
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
/// Maximum interval between survivor-traffic pulse observations during the
/// recovered-member checkpoint. Requiring one common active key to advance on
/// every survivor observer in each half-SLO interval bounds the worst-case gap
/// between two actual pulse events by the full availability-recovery SLO even
/// though each event occurs somewhere between two observations.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS: u64 =
    QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS / 2;
/// Maximum rolling observation interval in which every active survivor key
/// must advance on every survivor observer. Common-key pulse observations do
/// not reset this independent coverage checkpoint.
pub const QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS: u64 =
    QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS;
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
/// Per-node connection-attempt contribution from the scheduled hard-expiry
/// negative probe. The expired caller fails local material preflight without
/// dialing; the survivor-to-expired probe contributes one outbound attempt on
/// the survivor and, when accepted, one inbound attempt on the expired member.
pub const QUALIFICATION_TRAFFIC_FAULT_POST_HARD_EXPIRY_NETWORK_PROBE_ATTEMPTS_PER_NODE: u64 = 1;
/// Versioned interval-accounting rule for the fault-era connection ledger.
/// Scheduled new attempts and reconnects use the fixed topology/probe bound;
/// terminal outcomes additionally admit only the exact attempts already
/// outstanding at the baseline, as required by the connection conservation
/// equation.
pub const QUALIFICATION_TRAFFIC_FAULT_CONNECTION_ACCOUNTING_PROFILE: &str =
    "new-attempts-plus-baseline-outstanding/v1";
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

const SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_VERSION: &str =
    "opc-session-mtls-candidate-evidence/v2";
const SESSION_MTLS_CANDIDATE_ARTIFACT_NAME: &str = "opc-session-quorum-node";
const SESSION_MTLS_CANDIDATE_HARNESS_NAME: &str = "qualification_mtls_multiprocess";

/// Source-tree state bound into one synthetic mTLS candidate record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMtlsCandidateSourceTreeStatus {
    /// No staged, modified, or nonignored untracked source change was present.
    Clean,
    /// A staged, modified, or nonignored untracked change was present.
    DirtyUnqualified,
}

/// Closed synthetic projected-mTLS campaign vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMtlsCandidateCampaign {
    /// Leaf/intermediate/root rotation, trust removal, and rollback core.
    RotationCore,
    /// Unavailable-member, malformed-last-good, restart, and expiry recovery.
    FaultExpiryRecovery,
    /// Continuous mixed workload plus Linux process-resource bounds.
    TrafficResourceBounds,
}

impl SessionMtlsCandidateCampaign {
    /// Stable serialized campaign label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RotationCore => "rotation_core",
            Self::FaultExpiryRecovery => "fault_expiry_recovery",
            Self::TrafficResourceBounds => "traffic_resource_bounds",
        }
    }

    /// Exact ordered coverage admitted by this synthetic campaign.
    pub fn coverage(self) -> &'static [SessionMtlsCandidateCoverage] {
        session_mtls_candidate_coverage(self)
    }
}

/// Closed coverage claims admitted by the synthetic v2 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMtlsCandidateCoverage {
    /// Every member publishes a renewed leaf.
    LeafRenewal,
    /// Presented intermediate chains rotate and roll back.
    IntermediateRotationRollback,
    /// Root overlap, removal, and both rollback paths are exercised.
    RootOverlapRemovalRollback,
    /// Stale old-root client chains are rejected after removal.
    RemovedRootRejected,
    /// Every directed path performs a resolver-fresh authenticated bootstrap.
    FreshDirectedHandshakes,
    /// Every voter completes fresh durable readiness checkpoints.
    DurableReadiness,
    /// An acknowledged encrypted canary progresses and plaintext stays absent.
    EncryptedCanaryBoundary,
    /// One member loses synthetic consensus-RPC admission.
    SyntheticConsensusAdmissionLoss,
    /// A different member retains last-good after malformed trust publication.
    MalformedTrustRetainsLastGood,
    /// One active mutator restarts on the same disk and exact address.
    ExactAddressActiveMutatorRestart,
    /// A short-lived SVID crosses soft retirement and hard expiry.
    ShortLivedSvidExpiry,
    /// The expired member recovers in the same process with fresh material.
    SameProcessMaterialRecovery,
    /// Survivor mixed traffic remains bounded through the fault campaign.
    SurvivorTrafficContinuity,
    /// Repeated same-issuer leaf rotations run under continuous traffic.
    RepeatedLeafRotationUnderTraffic,
    /// Request, CAS, lease, watch, restore, and readiness traffic remain active.
    MixedWorkloadContinuity,
    /// Connection, reconnect, and lifecycle accounting stays within fixed bounds.
    BoundedConnectionLifecycle,
    /// Linux file-descriptor, thread, RSS, and high-water bounds are checked.
    LinuxProcessResourceBounds,
}

impl SessionMtlsCandidateCoverage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LeafRenewal => "leaf_renewal",
            Self::IntermediateRotationRollback => "intermediate_rotation_rollback",
            Self::RootOverlapRemovalRollback => "root_overlap_removal_rollback",
            Self::RemovedRootRejected => "removed_root_rejected",
            Self::FreshDirectedHandshakes => "fresh_directed_handshakes",
            Self::DurableReadiness => "durable_readiness",
            Self::EncryptedCanaryBoundary => "encrypted_canary_boundary",
            Self::SyntheticConsensusAdmissionLoss => "synthetic_consensus_admission_loss",
            Self::MalformedTrustRetainsLastGood => "malformed_trust_retains_last_good",
            Self::ExactAddressActiveMutatorRestart => "exact_address_active_mutator_restart",
            Self::ShortLivedSvidExpiry => "short_lived_svid_expiry",
            Self::SameProcessMaterialRecovery => "same_process_material_recovery",
            Self::SurvivorTrafficContinuity => "survivor_traffic_continuity",
            Self::RepeatedLeafRotationUnderTraffic => "repeated_leaf_rotation_under_traffic",
            Self::MixedWorkloadContinuity => "mixed_workload_continuity",
            Self::BoundedConnectionLifecycle => "bounded_connection_lifecycle",
            Self::LinuxProcessResourceBounds => "linux_process_resource_bounds",
        }
    }
}

/// Closed production acceptance that synthetic local evidence cannot satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMtlsRemainingAcceptance {
    /// Real deployed network and storage fault campaigns.
    RealNetworkStorageFaults,
    /// Deployed CNF/Kubernetes rotation and rollback evidence.
    DeployedCnfKubernetes,
    /// Supported-platform sizing, pressure, and soak evidence.
    SupportedPlatformResourceSoak,
    /// Remote-HKMS continuity and rotation evidence.
    RemoteHkms,
    /// Live fixed-label metrics and alert behavior in a deployed fleet.
    LiveMetricsAlertsQualification,
    /// Independently checked and externally signed candidate evidence.
    SignedIndependentCandidate,
    /// Final consumption by the networked HA production profile.
    HaProfileGraduation,
}

const ROTATION_CORE_COVERAGE: &[SessionMtlsCandidateCoverage] = &[
    SessionMtlsCandidateCoverage::LeafRenewal,
    SessionMtlsCandidateCoverage::IntermediateRotationRollback,
    SessionMtlsCandidateCoverage::RootOverlapRemovalRollback,
    SessionMtlsCandidateCoverage::RemovedRootRejected,
    SessionMtlsCandidateCoverage::FreshDirectedHandshakes,
    SessionMtlsCandidateCoverage::DurableReadiness,
    SessionMtlsCandidateCoverage::EncryptedCanaryBoundary,
];
const FAULT_EXPIRY_COVERAGE: &[SessionMtlsCandidateCoverage] = &[
    SessionMtlsCandidateCoverage::SyntheticConsensusAdmissionLoss,
    SessionMtlsCandidateCoverage::MalformedTrustRetainsLastGood,
    SessionMtlsCandidateCoverage::ExactAddressActiveMutatorRestart,
    SessionMtlsCandidateCoverage::ShortLivedSvidExpiry,
    SessionMtlsCandidateCoverage::SameProcessMaterialRecovery,
    SessionMtlsCandidateCoverage::SurvivorTrafficContinuity,
    SessionMtlsCandidateCoverage::DurableReadiness,
    SessionMtlsCandidateCoverage::EncryptedCanaryBoundary,
];
const TRAFFIC_RESOURCE_COVERAGE: &[SessionMtlsCandidateCoverage] = &[
    SessionMtlsCandidateCoverage::RepeatedLeafRotationUnderTraffic,
    SessionMtlsCandidateCoverage::MixedWorkloadContinuity,
    SessionMtlsCandidateCoverage::RootOverlapRemovalRollback,
    SessionMtlsCandidateCoverage::RemovedRootRejected,
    SessionMtlsCandidateCoverage::FreshDirectedHandshakes,
    SessionMtlsCandidateCoverage::DurableReadiness,
    SessionMtlsCandidateCoverage::BoundedConnectionLifecycle,
    SessionMtlsCandidateCoverage::LinuxProcessResourceBounds,
    SessionMtlsCandidateCoverage::EncryptedCanaryBoundary,
];
const SESSION_MTLS_REMAINING_ACCEPTANCE: &[SessionMtlsRemainingAcceptance] = &[
    SessionMtlsRemainingAcceptance::RealNetworkStorageFaults,
    SessionMtlsRemainingAcceptance::DeployedCnfKubernetes,
    SessionMtlsRemainingAcceptance::SupportedPlatformResourceSoak,
    SessionMtlsRemainingAcceptance::RemoteHkms,
    SessionMtlsRemainingAcceptance::LiveMetricsAlertsQualification,
    SessionMtlsRemainingAcceptance::SignedIndependentCandidate,
    SessionMtlsRemainingAcceptance::HaProfileGraduation,
];

const ROTATION_CORE_ORCHESTRATION_PLAN: &str = concat!(
    "initial-old-chain;ascending-members:",
    "initial+overlap,renewed-leaf+overlap,rotated-intermediate+overlap,",
    "renewed-leaf+overlap-rollback,new-root+overlap,",
    "renewed-leaf+overlap-rollback,new-root+overlap-resume,",
    "new-root+new-only-remove-old,new-root+overlap-restore,",
    "renewed-leaf+overlap-post-removal-rollback,new-root+overlap-final,",
    "new-root+new-only-final;each-member:",
    "publish-coherent-generation,source-and-controller-ready,",
    "fresh-incident-paths,durable-readiness,canary-read;each-phase:",
    "fresh-all-directed-paths,durable-readiness,acknowledged-canary;",
    "removed-root-negative-client-probe;plaintext-sqlite-family-scan"
);
const FAULT_EXPIRY_ORCHESTRATION_PLAN: &str = concat!(
    "initial-traffic;stable-nonzero-consensus-admission-loss+",
    "node-zero-malformed-trust-retains-last-good;survivor-readiness-canary-traffic;",
    "exact-address-restart-catchup;valid-trust-repair+fresh-all-paths;",
    "one-same-disk-exact-address-active-mutator-unclean-restart+",
    "survivor-commit+journal-reconcile+higher-fence-resume;",
    "stable-nonzero-same-issuer-short-lived-svid;fresh-all-paths+readiness+canary;",
    "pre-soft-retirement-mutation-and-watch-stop;soft-retirement;hard-expiry+",
    "zero-active-draining+survivor-readiness-canary-traffic;",
    "bidirectional-expired-path-rejection;same-process-valid-leaf-replacement+",
    "member-scoped-reauth+fresh-incident-paths+all-voter-readiness+canary;",
    "watch-reconcile+final-traffic-convergence+plaintext-sqlite-family-scan"
);
const TRAFFIC_RESOURCE_ORCHESTRATION_PLAN: &str = concat!(
    "initial-all-member-mixed-traffic+resolver-backoff-proof-when-three;",
    "baseline-fresh-generations+readiness+progress+lifecycle-ledger;",
    "seeded-round-robin-same-issuer-leaf-rotations+fresh-generations+",
    "readiness+progress+lifecycle-bounds;rotation-core-plan-under-continuous-traffic;",
    "stop-mutations+watch-heads+final-fresh-generation+record-convergence;",
    "stop-watches+resource-settle+fd-thread-rss-high-water-bounds+",
    "terminal-lifecycle-ledger+plaintext-sqlite-family-scan"
);

fn session_mtls_candidate_orchestration_plan(
    campaign: SessionMtlsCandidateCampaign,
) -> &'static str {
    match campaign {
        SessionMtlsCandidateCampaign::RotationCore => ROTATION_CORE_ORCHESTRATION_PLAN,
        SessionMtlsCandidateCampaign::FaultExpiryRecovery => FAULT_EXPIRY_ORCHESTRATION_PLAN,
        SessionMtlsCandidateCampaign::TrafficResourceBounds => TRAFFIC_RESOURCE_ORCHESTRATION_PLAN,
    }
}

fn session_mtls_candidate_coverage(
    campaign: SessionMtlsCandidateCampaign,
) -> &'static [SessionMtlsCandidateCoverage] {
    match campaign {
        SessionMtlsCandidateCampaign::RotationCore => ROTATION_CORE_COVERAGE,
        SessionMtlsCandidateCampaign::FaultExpiryRecovery => FAULT_EXPIRY_COVERAGE,
        SessionMtlsCandidateCampaign::TrafficResourceBounds => TRAFFIC_RESOURCE_COVERAGE,
    }
}

/// Exact source binding for one candidate record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMtlsCandidateSource {
    /// Exact lowercase Git commit observed by the producer.
    revision: String,
    /// Whether tracked and nonignored untracked inputs were clean at emission.
    tree_status: SessionMtlsCandidateSourceTreeStatus,
    /// Domain-separated digest of exact tracked changes and nonignored
    /// untracked source bytes observed before execution.
    worktree_sha256: String,
}

impl SessionMtlsCandidateSource {
    /// Exact lowercase Git revision carried by the decoded record.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Source-tree qualification state carried by the decoded record.
    pub const fn tree_status(&self) -> SessionMtlsCandidateSourceTreeStatus {
        self.tree_status
    }

    /// Digest of the exact working-tree source bytes used for the build.
    pub fn worktree_sha256(&self) -> &str {
        &self.worktree_sha256
    }
}

impl fmt::Debug for SessionMtlsCandidateSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMtlsCandidateSource")
            .field("revision", &"<git-revision>")
            .field("tree_status", &self.tree_status)
            .field("worktree_sha256", &"<sha256>")
            .finish()
    }
}

/// Exact test-binary binding for one candidate record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMtlsCandidateArtifact {
    /// Fixed qualification child binary name.
    name: String,
    /// SDK crate version used to build the child.
    version: String,
    /// SHA-256 of the exact child binary.
    sha256: String,
    /// Fixed qualification harness artifact name.
    harness_name: String,
    /// SHA-256 of the exact parent harness that enforced the assertions.
    harness_sha256: String,
    /// The plaintext test-only transport feature must remain disabled.
    insecure_test_enabled: bool,
}

impl SessionMtlsCandidateArtifact {
    /// Fixed child-artifact name carried by the decoded record.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// SDK version carried by the decoded record.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Digest of the exact child executable.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Fixed parent-harness artifact name.
    pub fn harness_name(&self) -> &str {
        &self.harness_name
    }

    /// Digest of the exact parent harness executable.
    pub fn harness_sha256(&self) -> &str {
        &self.harness_sha256
    }

    /// Whether the plaintext test-only transport feature was compiled in.
    pub const fn insecure_test_enabled(&self) -> bool {
        self.insecure_test_enabled
    }
}

impl fmt::Debug for SessionMtlsCandidateArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMtlsCandidateArtifact")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("sha256", &"<sha256>")
            .field("harness_name", &self.harness_name)
            .field("harness_sha256", &"<sha256>")
            .field("insecure_test_enabled", &self.insecure_test_enabled)
            .finish()
    }
}

/// Digest bindings that identify one exact synthetic execution input set.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMtlsCandidateBindings {
    /// SHA-256 of this immutable v2 schema.
    evidence_schema_sha256: String,
    /// Domain-separated digest of every generated node configuration.
    configuration_sha256: String,
    /// Domain-separated digest of every exact public certificate/trust input,
    /// publication epoch, and phase label consumed by the campaign.
    public_material_manifest_sha256: String,
    /// Domain-separated digest of the fixed campaign schedule and bounds.
    workload_schedule_sha256: String,
}

impl SessionMtlsCandidateBindings {
    /// Digest of the immutable evidence schema.
    pub fn evidence_schema_sha256(&self) -> &str {
        &self.evidence_schema_sha256
    }

    /// Digest of the exact generated node configurations.
    pub fn configuration_sha256(&self) -> &str {
        &self.configuration_sha256
    }

    /// Digest of the ordered public-certificate and trust publication manifest.
    pub fn public_material_manifest_sha256(&self) -> &str {
        &self.public_material_manifest_sha256
    }

    /// Digest of the exact declared campaign schedule.
    pub fn workload_schedule_sha256(&self) -> &str {
        &self.workload_schedule_sha256
    }
}

impl fmt::Debug for SessionMtlsCandidateBindings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMtlsCandidateBindings")
            .field("evidence_schema_sha256", &"<sha256>")
            .field("configuration_sha256", &"<sha256>")
            .field("public_material_manifest_sha256", &"<sha256>")
            .field("workload_schedule_sha256", &"<sha256>")
            .finish()
    }
}

/// Closed topology description without identities, routes, or addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMtlsCandidateTopology {
    /// Exact supported voter count.
    members: usize,
    /// Every voter runs in its own process.
    distinct_processes: bool,
    /// Every voter uses a distinct SQLite database.
    distinct_sqlite_databases: bool,
    /// Fixed local candidate transport label.
    transport_mode: String,
    /// Number of ordered source-to-target fresh connection proofs.
    directed_path_count: usize,
    /// Synthetic local evidence never counts as seamless production rotation.
    counts_for_seamless_tls_rotation: bool,
}

impl SessionMtlsCandidateTopology {
    /// Number of distinct synthetic voter processes.
    pub const fn members(&self) -> usize {
        self.members
    }

    /// Whether every voter used a distinct process.
    pub const fn distinct_processes(&self) -> bool {
        self.distinct_processes
    }

    /// Whether every voter used a distinct SQLite database.
    pub const fn distinct_sqlite_databases(&self) -> bool {
        self.distinct_sqlite_databases
    }

    /// Fixed redaction-safe transport profile label.
    pub fn transport_mode(&self) -> &str {
        &self.transport_mode
    }

    /// Number of directed fresh-handshake paths.
    pub const fn directed_path_count(&self) -> usize {
        self.directed_path_count
    }

    /// Whether this synthetic evidence counts for seamless TLS rotation.
    pub const fn counts_for_seamless_tls_rotation(&self) -> bool {
        self.counts_for_seamless_tls_rotation
    }
}

/// Closed successful observations emitted only after a campaign completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMtlsCandidateObservations {
    /// Projected-source and TLS-controller status was collected.
    material_status_collected: bool,
    /// Every required voter reached fresh durable readiness.
    durable_readiness_reached: bool,
    /// Every scheduled directed fresh handshake completed.
    directed_fresh_handshakes_succeeded: bool,
    /// Lifecycle counters were collected and checked.
    lifecycle_metrics_collected: bool,
    /// The encrypted acknowledged canary completed its scheduled progress.
    encrypted_canary_verified: bool,
    /// Exact plaintext canary prefixes were absent from SQLite/WAL/SHM bytes.
    plaintext_canary_absent_from_sqlite_family: bool,
}

impl SessionMtlsCandidateObservations {
    /// Whether projected-material status was collected.
    pub const fn material_status_collected(&self) -> bool {
        self.material_status_collected
    }

    /// Whether durable readiness reached the campaign boundary.
    pub const fn durable_readiness_reached(&self) -> bool {
        self.durable_readiness_reached
    }

    /// Whether all scheduled fresh handshakes succeeded.
    pub const fn directed_fresh_handshakes_succeeded(&self) -> bool {
        self.directed_fresh_handshakes_succeeded
    }

    /// Whether lifecycle metrics were collected and checked.
    pub const fn lifecycle_metrics_collected(&self) -> bool {
        self.lifecycle_metrics_collected
    }

    /// Whether the acknowledged encrypted canary was verified.
    pub const fn encrypted_canary_verified(&self) -> bool {
        self.encrypted_canary_verified
    }

    /// Whether plaintext canary prefixes were absent from SQLite-family bytes.
    pub const fn plaintext_canary_absent_from_sqlite_family(&self) -> bool {
        self.plaintext_canary_absent_from_sqlite_family
    }
}

/// One typed, digest-bound synthetic projected-mTLS candidate record.
///
/// The model contains no certificate material, keys, peer addresses, SPIFFE
/// IDs, filesystem paths, session payloads, or backend error text. Its claim
/// fields are fixed to incomplete experimental evidence by [`Self::validate`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMtlsCandidateEvidenceV2 {
    /// Exact immutable schema version.
    schema_version: String,
    /// Always true for this local candidate contract.
    experimental: bool,
    /// Always false for this local candidate contract.
    qualification_complete: bool,
    /// Exact source binding.
    source: SessionMtlsCandidateSource,
    /// Exact qualification-child artifact binding.
    artifact: SessionMtlsCandidateArtifact,
    /// Synthetic campaign that produced the record.
    campaign: SessionMtlsCandidateCampaign,
    /// Closed topology facts.
    topology: SessionMtlsCandidateTopology,
    /// Exact schema, configuration, and schedule bindings.
    bindings: SessionMtlsCandidateBindings,
    /// Successful bounded observations.
    observations: SessionMtlsCandidateObservations,
    /// Exact ordered coverage admitted for this campaign.
    coverage: Vec<SessionMtlsCandidateCoverage>,
    /// Exact ordered external acceptance that remains open.
    remaining_acceptance: Vec<SessionMtlsRemainingAcceptance>,
}

impl fmt::Debug for SessionMtlsCandidateEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMtlsCandidateEvidenceV2")
            .field("schema_version", &self.schema_version)
            .field("experimental", &self.experimental)
            .field("qualification_complete", &self.qualification_complete)
            .field("source", &"<digest-bound>")
            .field("artifact", &"<digest-bound>")
            .field("campaign", &self.campaign)
            .field("members", &self.topology.members)
            .field("bindings", &"<sha256>")
            .field("coverage", &self.coverage)
            .field("remaining_acceptance", &self.remaining_acceptance)
            .finish()
    }
}

/// Stable candidate-evidence validation failures that never echo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionMtlsCandidateEvidenceError {
    /// The encoded document exceeded its fixed pre-decode size bound.
    #[error("mTLS candidate evidence document exceeds the supported size")]
    DocumentTooLarge,
    /// The document is not valid closed JSON for the typed v2 contract.
    #[error("mTLS candidate evidence document is invalid")]
    InvalidDocument,
    /// Schema version is unsupported.
    #[error("mTLS candidate evidence schema is unsupported")]
    Schema,
    /// A production or qualification claim was attempted.
    #[error("mTLS candidate evidence claim is invalid")]
    Claim,
    /// Source provenance is malformed.
    #[error("mTLS candidate source binding is invalid")]
    Source,
    /// Artifact provenance is malformed.
    #[error("mTLS candidate artifact binding is invalid")]
    Artifact,
    /// Topology facts are inconsistent.
    #[error("mTLS candidate topology is invalid")]
    Topology,
    /// A digest does not bind the expected exact input.
    #[error("mTLS candidate digest binding is invalid")]
    Binding,
    /// A required successful observation is absent.
    #[error("mTLS candidate observations are incomplete")]
    Observations,
    /// Campaign coverage is missing, duplicated, or inconsistent.
    #[error("mTLS candidate coverage is invalid")]
    Coverage,
    /// External remaining acceptance is incomplete or inconsistent.
    #[error("mTLS candidate remaining acceptance is invalid")]
    RemainingAcceptance,
}

impl SessionMtlsCandidateEvidenceV2 {
    /// Decode and validate one bounded, closed v2 candidate evidence document.
    ///
    /// The byte-size limit is enforced before JSON parsing. Decode and
    /// validation failures are stable and never include input bytes.
    pub fn from_json(document: &[u8]) -> Result<Self, SessionMtlsCandidateEvidenceError> {
        if document.len() > SESSION_MTLS_CANDIDATE_EVIDENCE_V2_MAX_BYTES {
            return Err(SessionMtlsCandidateEvidenceError::DocumentTooLarge);
        }
        let evidence: Self = serde_json::from_slice(document)
            .map_err(|_| SessionMtlsCandidateEvidenceError::InvalidDocument)?;
        evidence.validate()?;
        Ok(evidence)
    }

    /// Immutable schema-version label carried by the decoded record.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Whether the record is explicitly experimental.
    pub const fn experimental(&self) -> bool {
        self.experimental
    }

    /// Whether the record claims completed qualification.
    pub const fn qualification_complete(&self) -> bool {
        self.qualification_complete
    }

    /// Redaction-safe source binding.
    pub const fn source(&self) -> &SessionMtlsCandidateSource {
        &self.source
    }

    /// Redaction-safe child and harness artifact bindings.
    pub const fn artifact(&self) -> &SessionMtlsCandidateArtifact {
        &self.artifact
    }

    /// Synthetic campaign carried by the decoded record.
    pub const fn campaign(&self) -> SessionMtlsCandidateCampaign {
        self.campaign
    }

    /// Closed topology facts carried by the decoded record.
    pub const fn topology(&self) -> &SessionMtlsCandidateTopology {
        &self.topology
    }

    /// Redacted digest bindings carried by the decoded record.
    pub const fn bindings(&self) -> &SessionMtlsCandidateBindings {
        &self.bindings
    }

    /// Successful bounded observations carried by the decoded record.
    pub const fn observations(&self) -> &SessionMtlsCandidateObservations {
        &self.observations
    }

    /// Exact ordered coverage carried by the decoded record.
    pub fn coverage(&self) -> &[SessionMtlsCandidateCoverage] {
        &self.coverage
    }

    /// Exact ordered external acceptance that remains open.
    pub fn remaining_acceptance(&self) -> &[SessionMtlsRemainingAcceptance] {
        &self.remaining_acceptance
    }

    /// Canonical ordered external acceptance required by every v2 record.
    pub fn required_remaining_acceptance() -> &'static [SessionMtlsRemainingAcceptance] {
        SESSION_MTLS_REMAINING_ACCEPTANCE
    }

    /// Validate an untrusted decoded record without echoing any input value.
    pub fn validate(&self) -> Result<(), SessionMtlsCandidateEvidenceError> {
        if self.schema_version != SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_VERSION {
            return Err(SessionMtlsCandidateEvidenceError::Schema);
        }
        if !self.experimental
            || self.qualification_complete
            || self.topology.counts_for_seamless_tls_rotation
        {
            return Err(SessionMtlsCandidateEvidenceError::Claim);
        }
        if !is_lower_hex_exact(&self.source.revision, 40)
            || !is_exact_sha256(&self.source.worktree_sha256)
        {
            return Err(SessionMtlsCandidateEvidenceError::Source);
        }
        if self.artifact.name != SESSION_MTLS_CANDIDATE_ARTIFACT_NAME
            || self.artifact.version != env!("CARGO_PKG_VERSION")
            || self.artifact.harness_name != SESSION_MTLS_CANDIDATE_HARNESS_NAME
            || self.artifact.insecure_test_enabled
            || !is_exact_sha256(&self.artifact.sha256)
            || !is_exact_sha256(&self.artifact.harness_sha256)
        {
            return Err(SessionMtlsCandidateEvidenceError::Artifact);
        }
        let directed_path_count = self
            .topology
            .members
            .checked_mul(self.topology.members.saturating_sub(1))
            .ok_or(SessionMtlsCandidateEvidenceError::Topology)?;
        if !matches!(self.topology.members, 3 | 5)
            || !self.topology.distinct_processes
            || !self.topology.distinct_sqlite_databases
            || self.topology.transport_mode != "projected_svid_mtls_pinned_loopback"
            || self.topology.directed_path_count != directed_path_count
        {
            return Err(SessionMtlsCandidateEvidenceError::Topology);
        }
        let expected_schedule =
            session_mtls_candidate_schedule_sha256(self.campaign, self.topology.members)
                .ok_or(SessionMtlsCandidateEvidenceError::Topology)?;
        if !is_exact_sha256(&self.bindings.evidence_schema_sha256)
            || !is_exact_sha256(&self.bindings.configuration_sha256)
            || !is_exact_sha256(&self.bindings.public_material_manifest_sha256)
            || !is_exact_sha256(&self.bindings.workload_schedule_sha256)
            || self.bindings.evidence_schema_sha256
                != session_mtls_candidate_evidence_v2_schema_sha256()
            || self.bindings.workload_schedule_sha256 != expected_schedule
        {
            return Err(SessionMtlsCandidateEvidenceError::Binding);
        }
        if !self.observations.material_status_collected
            || !self.observations.durable_readiness_reached
            || !self.observations.directed_fresh_handshakes_succeeded
            || !self.observations.lifecycle_metrics_collected
            || !self.observations.encrypted_canary_verified
            || !self.observations.plaintext_canary_absent_from_sqlite_family
        {
            return Err(SessionMtlsCandidateEvidenceError::Observations);
        }
        if self.coverage != session_mtls_candidate_coverage(self.campaign) {
            return Err(SessionMtlsCandidateEvidenceError::Coverage);
        }
        if self.remaining_acceptance != SESSION_MTLS_REMAINING_ACCEPTANCE {
            return Err(SessionMtlsCandidateEvidenceError::RemainingAcceptance);
        }
        Ok(())
    }
}

/// SHA-256 of the immutable v2 candidate-evidence schema bytes.
pub fn session_mtls_candidate_evidence_v2_schema_sha256() -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_JSON.as_bytes());
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

/// Domain-separated digest of one exact local mTLS campaign schedule.
pub fn session_mtls_candidate_schedule_sha256(
    campaign: SessionMtlsCandidateCampaign,
    member_count: usize,
) -> Option<String> {
    let traffic_schedule = qualification_traffic_schedule_sha256(member_count)?;
    let coverage = session_mtls_candidate_coverage(campaign)
        .iter()
        .map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let orchestration_plan = session_mtls_candidate_orchestration_plan(campaign);
    let schedule = format!(
        concat!(
            "opc-session-mtls-candidate/v2\n",
            "campaign={}\n",
            "members={}\n",
            "directed_paths={}\n",
            "traffic_schedule={}\n",
            "orchestration_plan={}\n",
            "rotation_core_plan={}\n",
            "harness_artifact_binding=required\n",
            "coverage={}\n",
            "transport=projected_svid_mtls_pinned_loopback\n",
            "qualification_complete=false\n",
            "counts_for_seamless_tls_rotation=false\n"
        ),
        campaign.as_str(),
        member_count,
        member_count.checked_mul(member_count.saturating_sub(1))?,
        traffic_schedule,
        orchestration_plan,
        ROTATION_CORE_ORCHESTRATION_PLAN,
        coverage,
    );
    Some(qualification_digest(
        "mtls-candidate-schedule",
        schedule.as_bytes(),
    ))
}

fn is_lower_hex_exact(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Machine-readable experimental session-HA profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationWorkspace {
    pub version: String,
    pub rust_msrv: String,
    pub source_revision: String,
}

/// Exact interim source and publication gate for the patched consensus engine.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifact {
    pub crate_name: String,
    pub version: String,
    pub publish: bool,
    pub required_features: Vec<String>,
    pub excluded_features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPlatform {
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTopology {
    pub member_counts: Vec<usize>,
    pub maximum_members: usize,
    pub quorum_rule: String,
    pub distinct_failure_domain_per_voter: bool,
    pub distinct_backing_store_per_voter: bool,
    pub stable_identity_independent_of_route: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

/// Additive, non-production v4 profile that combines the existing sequential
/// and concurrent qualification evidence contracts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHaCandidateQualificationProfileV4 {
    /// Frozen profile schema identifier.
    pub schema_version: String,
    /// Frozen candidate profile identifier.
    pub profile_id: String,
    /// Candidate maturity, which remains experimental.
    pub maturity: String,
    /// Whether the profile has completed production qualification.
    pub qualification_complete: bool,
    /// Workspace and toolchain inventory.
    pub workspace: QualificationWorkspace,
    /// Interim Openraft source-build restriction.
    pub source_build_gate: QualificationSourceBuildGate,
    /// Exact crate and dependency inventory.
    pub artifacts: Vec<QualificationArtifact>,
    /// Required target-platform inventory.
    pub platforms: Vec<QualificationPlatform>,
    /// Supported quorum topology.
    pub topology: QualificationTopology,
    /// Exact consensus protocol profile.
    pub protocol: QualificationProtocol,
    /// Exact consensus timing profile.
    pub consensus_timing: QualificationConsensusTiming,
    /// Resource and data-shape bounds.
    pub bounds: QualificationBounds,
    /// Provisional qualification thresholds.
    pub provisional_test_thresholds: QualificationThresholds,
    /// Combined evidence and remaining-acceptance inventory.
    pub evidence: QualificationCandidateEvidenceRequirementsV4,
}

impl SessionHaCandidateQualificationProfileV4 {
    /// Decode and validate one bounded v4 candidate profile document.
    pub fn from_json(document: &[u8]) -> Result<Self, QualificationCandidateContractError> {
        if document.len() > SESSION_HA_CANDIDATE_PROFILE_V4_MAX_BYTES {
            return Err(QualificationCandidateContractError::DocumentTooLarge);
        }
        let profile: Self = serde_json::from_slice(document)
            .map_err(|_| QualificationCandidateContractError::InvalidDocument)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Validate the frozen v4 candidate-only claims and component inventory.
    pub fn validate(&self) -> Result<(), QualificationCandidateContractError> {
        if self.schema_version != "opc-session-ha-profile/v4-candidate"
            || self.profile_id != "opc-session-openraft-ha/v4-candidate"
            || self.maturity != "experimental"
            || self.qualification_complete
        {
            return Err(QualificationCandidateContractError::UnsupportedClaim);
        }
        let baseline: SessionHaQualificationProfile = serde_json::from_str(SESSION_HA_PROFILE_JSON)
            .map_err(|_| QualificationCandidateContractError::InvalidProfile)?;
        if self.workspace != baseline.workspace
            || self.source_build_gate != baseline.source_build_gate
            || self.artifacts != baseline.artifacts
            || self.platforms != baseline.platforms
            || self.topology != baseline.topology
            || self.protocol != baseline.protocol
            || self.consensus_timing != baseline.consensus_timing
            || self.bounds != baseline.bounds
            || self.provisional_test_thresholds != baseline.provisional_test_thresholds
        {
            return Err(QualificationCandidateContractError::InvalidProfile);
        }
        let evidence = &self.evidence;
        if evidence.sequential_schedule_schema != "qualification/v1/session-ha-schedule.schema.json"
            || evidence.sequential_history_schema
                != "qualification/v1/session-ha-history.schema.json"
            || evidence.sequential_checker != "scripts/check-session-ha-history.py"
            || evidence.concurrent_evidence_schema
                != "qualification/v3/session-ha-candidate-evidence.schema.json"
            || evidence.concurrent_history_schema
                != "qualification/v3/session-ha-concurrent-history.schema.json"
            || evidence.concurrent_checker != "scripts/check-session-ha-concurrent-history.py"
            || evidence.candidate_manifest_schema
                != "qualification/v4/session-ha-candidate-manifest.schema.json"
            || evidence.required_topologies != [3, 5]
            || evidence.required_transport_modes != ["mtls"]
            || evidence.foundation_transport_mode != "loopback-plaintext-test-only"
            || evidence.foundation_counts_for_tls_rotation
            || evidence.foundation_payload_protection
                != "fixed-memory-provider-synthetic-wrapper-only"
            || evidence.foundation_counts_for_production_encryption
            || evidence.unresolved_dependencies != [143, 158, 164]
            || !evidence
                .acceptance_gates
                .iter()
                .map(String::as_str)
                .eq(SESSION_HA_CANDIDATE_ACCEPTANCE_GATES_V4)
        {
            return Err(QualificationCandidateContractError::InvalidProfile);
        }
        Ok(())
    }
}

/// Exact component paths and unresolved gates for the combined v4 candidate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateEvidenceRequirementsV4 {
    /// Frozen sequential workload schema path.
    pub sequential_schedule_schema: String,
    /// Frozen sequential history schema path.
    pub sequential_history_schema: String,
    /// SDK-independent sequential checker path.
    pub sequential_checker: String,
    /// Frozen v3 concurrent evidence schema path.
    pub concurrent_evidence_schema: String,
    /// Frozen v3 concurrent history schema path.
    pub concurrent_history_schema: String,
    /// SDK-independent concurrent checker path.
    pub concurrent_checker: String,
    /// Closed aggregate candidate manifest schema path.
    pub candidate_manifest_schema: String,
    /// Required voter counts.
    pub required_topologies: Vec<usize>,
    /// Required authenticated transport modes.
    pub required_transport_modes: Vec<String>,
    /// Older foundation transport mode that receives no production credit.
    pub foundation_transport_mode: String,
    /// Whether the plaintext foundation counts as TLS-rotation evidence.
    pub foundation_counts_for_tls_rotation: bool,
    /// Older foundation payload-protection mode.
    pub foundation_payload_protection: String,
    /// Whether the synthetic memory provider counts as production encryption.
    pub foundation_counts_for_production_encryption: bool,
    /// Open tracking issues that still block graduation.
    pub unresolved_dependencies: Vec<u64>,
    /// Complete fixed production-acceptance inventory.
    pub acceptance_gates: Vec<String>,
}

/// Exact lowercase SHA-256 binding used by v4 candidate manifests.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct QualificationSha256(String);

impl QualificationSha256 {
    /// Parse an exact `sha256:`-prefixed lowercase digest.
    pub fn new(value: impl Into<String>) -> Result<Self, QualificationCandidateContractError> {
        let value = value.into();
        if value
            .strip_prefix("sha256:")
            .is_some_and(|digest| is_lower_hex_width(digest, 64))
        {
            Ok(Self(value))
        } else {
            Err(QualificationCandidateContractError::InvalidDigest)
        }
    }

    /// Compute the exact manifest form for a bounded byte artifact.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    /// Borrow the canonical digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for QualificationSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QualificationSha256(<sha256>)")
    }
}

impl Serialize for QualificationSha256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for QualificationSha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value)
            .map_err(|_| <D::Error as serde::de::Error>::custom("candidate digest is malformed"))
    }
}

/// Source-tree state attached to a combined candidate manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationCandidateSourceTreeStatus {
    /// Exact source tree was clean.
    Clean,
    /// Dirty source may be retained only as unqualified diagnostic evidence.
    DirtyUnqualified,
}

/// Cargo profile used to build the bound qualification artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationCandidateCargoProfile {
    /// Development/debug artifact.
    Debug,
    /// Optimized candidate-release artifact.
    Release,
}

/// Supported Linux target attached to candidate evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualificationCandidateTarget {
    /// x86-64 GNU/Linux target.
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    X86_64UnknownLinuxGnu,
    /// AArch64 GNU/Linux target.
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    Aarch64UnknownLinuxGnu,
}

/// The only transport mode admitted by the v4 combined candidate contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualificationCandidateTransportMode {
    /// Mutually authenticated TLS.
    #[serde(rename = "mtls")]
    Mtls,
}

/// A checker outcome admitted by a combined candidate manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationCandidateCheckerStatus {
    /// Complete, conclusive pass.
    Pass,
}

/// Evidence status for one unresolved production-acceptance gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationCandidateAcceptanceStatus {
    /// No candidate evidence is bound for this gate.
    Unproven,
    /// Non-production candidate evidence is digest-bound for this gate.
    CandidateEvidence,
}

/// Digest reference to the exact v4 candidate profile document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateProfileBinding {
    /// Frozen candidate profile schema identifier.
    pub schema_version: String,
    /// Digest of the exact profile document.
    pub sha256: QualificationSha256,
}

/// Exact candidate binary and image boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateArtifactBinding {
    /// Qualification binary name.
    pub name: String,
    /// Candidate artifact version.
    pub version: String,
    /// Digest of the executable bytes.
    pub binary_sha256: QualificationSha256,
    /// Digest of the immutable OCI image, when collected.
    pub container_image_sha256: Option<QualificationSha256>,
    /// Digest of the complete Cargo feature inventory.
    pub feature_inventory_sha256: QualificationSha256,
    /// Cargo build profile.
    pub cargo_profile: QualificationCandidateCargoProfile,
    /// Whether this is the exact candidate-release artifact.
    pub exact_release_artifact: bool,
    /// Whether the plaintext qualification feature was enabled.
    pub foundation_insecure_enabled: bool,
    /// Whether the legacy writable session-net surface was enabled.
    pub legacy_session_net_compat_enabled: bool,
}

/// Deployment shape and bounded campaign timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateCampaign {
    /// Domain-owned opaque campaign identifier digest.
    pub campaign_id_sha256: QualificationSha256,
    /// Voter count.
    pub topology_members: usize,
    /// Executed target platform.
    pub target: QualificationCandidateTarget,
    /// Canonical UTC start timestamp at whole-second precision.
    pub started_at_utc: String,
    /// Canonical UTC completion timestamp at whole-second precision.
    pub completed_at_utc: String,
    /// Authenticated transport mode.
    pub transport_mode: QualificationCandidateTransportMode,
    /// Whether every voter was an independent process.
    pub independent_processes: bool,
    /// Whether every voter used independent durable storage.
    pub independent_disks: bool,
    /// Whether exact canonical SPIFFE identities were enforced.
    pub canonical_spiffe_identities: bool,
    /// Whether canonical FQDN routing aliases were exercised.
    pub canonical_fqdn_routes: bool,
}

/// Digests for candidate environment, schedules, diagnostics, and resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateBindings {
    /// Environment and toolchain inventory digest.
    pub environment_sha256: QualificationSha256,
    /// Complete member-configuration digest.
    pub configuration_sha256: QualificationSha256,
    /// Complete fault-schedule digest.
    pub fault_schedule_sha256: QualificationSha256,
    /// Bounded log-manifest digest.
    pub logs_manifest_sha256: QualificationSha256,
    /// Bounded metric-manifest digest.
    pub metrics_manifest_sha256: QualificationSha256,
    /// Bounded resource-results digest.
    pub resource_results_sha256: QualificationSha256,
}

/// One exact independent checker and its retained conclusive output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateCheckerBinding {
    /// Checker filename.
    pub name: String,
    /// Checker contract version.
    pub version: String,
    /// Digest of the checker source bytes.
    pub sha256: QualificationSha256,
    /// Digest of the complete canonical checker output.
    pub output_sha256: QualificationSha256,
    /// Process exit code.
    pub exit_code: i32,
    /// Parsed checker status.
    pub status: QualificationCandidateCheckerStatus,
    /// Number of reported safety violations.
    pub violation_count: usize,
    /// Number of reported inconclusive outcomes.
    pub inconclusive_count: usize,
}

/// Bound sequential lease, fencing, CAS, and read evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateSequentialEvidence {
    /// Sequential schedule schema identifier.
    pub schedule_schema_version: String,
    /// Digest of the exact sequential workload schedule.
    pub schedule_sha256: QualificationSha256,
    /// Sequential history schema identifier.
    pub history_schema_version: String,
    /// Digest of the exact sequential history.
    pub history_sha256: QualificationSha256,
    /// Independent sequential checker binding.
    pub checker: QualificationCandidateCheckerBinding,
}

/// Bound concurrent batch, watch, restore, and readiness evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateConcurrentEvidence {
    /// v3 candidate evidence schema identifier.
    pub evidence_schema_version: String,
    /// Digest of the exact v3 candidate evidence record.
    pub evidence_sha256: QualificationSha256,
    /// Digest of the complete concurrent workload schedule.
    pub workload_schedule_sha256: QualificationSha256,
    /// Concurrent history schema identifier.
    pub history_schema_version: String,
    /// Digest of the exact concurrent history.
    pub history_sha256: QualificationSha256,
    /// Independent concurrent checker binding.
    pub checker: QualificationCandidateCheckerBinding,
}

/// Status and optional digest for one candidate-only acceptance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateAcceptanceEvidence {
    /// Whether candidate evidence has been attached.
    pub status: QualificationCandidateAcceptanceStatus,
    /// Exact candidate evidence digest, present only for candidate evidence.
    pub evidence_sha256: Option<QualificationSha256>,
}

impl QualificationCandidateAcceptanceEvidence {
    fn validate(&self) -> Result<(), QualificationCandidateContractError> {
        if matches!(
            (self.status, self.evidence_sha256.is_some()),
            (QualificationCandidateAcceptanceStatus::Unproven, false)
                | (
                    QualificationCandidateAcceptanceStatus::CandidateEvidence,
                    true
                )
        ) {
            Ok(())
        } else {
            Err(QualificationCandidateContractError::InvalidAcceptance)
        }
    }
}

/// Complete fixed acceptance-gate inventory for one candidate manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCandidateAcceptanceInventory {
    /// Deployed Kubernetes three/five-member evidence.
    pub deployed_kubernetes_3_5: QualificationCandidateAcceptanceEvidence,
    /// Real network and storage fault evidence.
    pub real_network_and_storage_faults: QualificationCandidateAcceptanceEvidence,
    /// Consensus crash-point matrix evidence.
    pub crash_point_matrix: QualificationCandidateAcceptanceEvidence,
    /// Version migration and rollback evidence.
    pub version_migration_and_rollback: QualificationCandidateAcceptanceEvidence,
    /// Supported-platform resource and soak evidence.
    pub platform_resource_soak: QualificationCandidateAcceptanceEvidence,
    /// Remote-HKMS payload-key rotation evidence.
    pub remote_hkms_rotation: QualificationCandidateAcceptanceEvidence,
    /// Live alert firing and clearing evidence.
    pub live_alert_fire_and_clear: QualificationCandidateAcceptanceEvidence,
    /// Externally signed release-bundle evidence.
    pub signed_release_bundle: QualificationCandidateAcceptanceEvidence,
}

impl QualificationCandidateAcceptanceInventory {
    fn validate(&self) -> Result<(), QualificationCandidateContractError> {
        for gate in [
            &self.deployed_kubernetes_3_5,
            &self.real_network_and_storage_faults,
            &self.crash_point_matrix,
            &self.version_migration_and_rollback,
            &self.platform_resource_soak,
            &self.remote_hkms_rotation,
            &self.live_alert_fire_and_clear,
            &self.signed_release_bundle,
        ] {
            gate.validate()?;
        }
        Ok(())
    }
}

/// Closed v4 manifest binding both independent HA history-checker families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHaCandidateManifestV4 {
    /// Frozen manifest schema identifier.
    pub schema_version: String,
    /// Frozen candidate profile identifier.
    pub profile_id: String,
    /// Whether this manifest remains experimental.
    pub experimental: bool,
    /// Whether production qualification is complete.
    pub qualification_complete: bool,
    /// Whether this manifest may count as production evidence.
    pub counts_for_production: bool,
    /// Exact lowercase source revision.
    pub source_revision: String,
    /// Source-tree cleanliness classification.
    pub source_tree_status: QualificationCandidateSourceTreeStatus,
    /// Exact candidate profile binding.
    pub profile: QualificationCandidateProfileBinding,
    /// Exact executable and image binding.
    pub artifact: QualificationCandidateArtifactBinding,
    /// Campaign topology and timing.
    pub campaign: QualificationCandidateCampaign,
    /// Environment, schedule, diagnostics, and resource bindings.
    pub bindings: QualificationCandidateBindings,
    /// Sequential state-machine evidence.
    pub sequential: QualificationCandidateSequentialEvidence,
    /// Concurrent state-machine evidence.
    pub concurrent: QualificationCandidateConcurrentEvidence,
    /// Complete candidate-only acceptance inventory.
    pub acceptance: QualificationCandidateAcceptanceInventory,
}

impl SessionHaCandidateManifestV4 {
    /// Decode and validate one bounded closed v4 candidate manifest.
    pub fn from_json(document: &[u8]) -> Result<Self, QualificationCandidateContractError> {
        if document.len() > SESSION_HA_CANDIDATE_MANIFEST_V4_MAX_BYTES {
            return Err(QualificationCandidateContractError::DocumentTooLarge);
        }
        let manifest: Self = serde_json::from_slice(document)
            .map_err(|_| QualificationCandidateContractError::InvalidDocument)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate all cross-field claims that cannot be represented by the
    /// structural JSON Schema alone.
    pub fn validate(&self) -> Result<(), QualificationCandidateContractError> {
        if self.schema_version != "opc-session-ha-candidate-manifest/v4"
            || self.profile_id != "opc-session-openraft-ha/v4-candidate"
            || !self.experimental
            || self.qualification_complete
            || self.counts_for_production
        {
            return Err(QualificationCandidateContractError::UnsupportedClaim);
        }
        if !is_lower_hex_width(&self.source_revision, 40) {
            return Err(QualificationCandidateContractError::InvalidRevision);
        }
        if self.profile.schema_version != "opc-session-ha-profile/v4-candidate"
            || self.profile.sha256
                != QualificationSha256::digest(SESSION_HA_CANDIDATE_PROFILE_V4_JSON.as_bytes())
        {
            return Err(QualificationCandidateContractError::InvalidProfile);
        }
        if self.artifact.name != "opc-session-quorum-node"
            || !is_candidate_artifact_version(&self.artifact.version)
            || self.artifact.foundation_insecure_enabled
            || self.artifact.legacy_session_net_compat_enabled
            || (self.artifact.exact_release_artifact
                && (self.source_revision.bytes().all(|byte| byte == b'0')
                    || self.source_tree_status != QualificationCandidateSourceTreeStatus::Clean
                    || self.artifact.cargo_profile != QualificationCandidateCargoProfile::Release
                    || self.artifact.container_image_sha256.is_none()))
        {
            return Err(QualificationCandidateContractError::InvalidArtifact);
        }
        if !matches!(self.campaign.topology_members, 3 | 5)
            || !is_canonical_utc_seconds(&self.campaign.started_at_utc)
            || !is_canonical_utc_seconds(&self.campaign.completed_at_utc)
            || self.campaign.started_at_utc > self.campaign.completed_at_utc
            || !self.campaign.independent_processes
            || !self.campaign.independent_disks
            || !self.campaign.canonical_spiffe_identities
            || !self.campaign.canonical_fqdn_routes
        {
            return Err(QualificationCandidateContractError::InvalidCampaign);
        }
        if self.sequential.schedule_schema_version != "opc-session-ha-schedule/v1"
            || self.sequential.history_schema_version != "opc-session-ha-history/v1"
            || self.concurrent.evidence_schema_version != "opc-session-ha-candidate-evidence/v3"
            || self.concurrent.history_schema_version != "opc-session-ha-concurrent-history/v3"
        {
            return Err(QualificationCandidateContractError::InvalidComponent);
        }
        validate_candidate_checker(&self.sequential.checker, "check-session-ha-history.py", "1")?;
        validate_candidate_checker(
            &self.concurrent.checker,
            "check-session-ha-concurrent-history.py",
            "3",
        )?;
        self.acceptance.validate()
    }
}

/// Stable, redaction-safe v4 candidate contract validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationCandidateContractError {
    /// A profile or manifest exceeded its fixed document-size bound.
    #[error("candidate document exceeds the supported size")]
    DocumentTooLarge,
    /// A profile or manifest is not valid closed JSON for the typed contract.
    #[error("candidate document is invalid")]
    InvalidDocument,
    /// A digest is not exact lowercase SHA-256.
    #[error("candidate digest is invalid")]
    InvalidDigest,
    /// The candidate profile inventory is inconsistent.
    #[error("candidate profile is invalid")]
    InvalidProfile,
    /// The manifest attempts an unsupported maturity claim.
    #[error("candidate maturity claim is invalid")]
    UnsupportedClaim,
    /// The source revision is malformed.
    #[error("candidate source revision is invalid")]
    InvalidRevision,
    /// The artifact boundary is inconsistent.
    #[error("candidate artifact binding is invalid")]
    InvalidArtifact,
    /// The campaign topology or timing is inconsistent.
    #[error("candidate campaign binding is invalid")]
    InvalidCampaign,
    /// A bound component uses an unsupported schema.
    #[error("candidate component binding is invalid")]
    InvalidComponent,
    /// An independent checker is not a conclusive pass.
    #[error("candidate checker binding is invalid")]
    InvalidChecker,
    /// An acceptance status and digest disagree.
    #[error("candidate acceptance binding is invalid")]
    InvalidAcceptance,
}

fn validate_candidate_checker(
    checker: &QualificationCandidateCheckerBinding,
    expected_name: &str,
    expected_version: &str,
) -> Result<(), QualificationCandidateContractError> {
    if checker.name == expected_name
        && checker.version == expected_version
        && checker.exit_code == 0
        && checker.status == QualificationCandidateCheckerStatus::Pass
        && checker.violation_count == 0
        && checker.inconclusive_count == 0
    {
        Ok(())
    } else {
        Err(QualificationCandidateContractError::InvalidChecker)
    }
}

fn is_lower_hex_width(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_candidate_artifact_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-'))
}

fn is_canonical_utc_seconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && [4, 7].into_iter().all(|index| bytes[index] == b'-')
        && bytes[10] == b'T'
        && [13, 16].into_iter().all(|index| bytes[index] == b':')
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
        && value.parse::<Timestamp>().is_ok()
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
                || member.replica_id.is_empty()
                || member.endpoint_host.is_empty()
                || member.tls_identity.is_empty()
                || member.failure_domain.is_empty()
                || member.backing_identity.is_empty()
                || !replica_ids.insert(replica_id)
                || !endpoints.insert(endpoint.clone())
                || !tls_identities.insert(tls_identity)
                || !failure_domains.insert(failure_domain)
                || !backing_identities.insert(backing_identity)
            {
                return Err(QualificationConfigError::Member);
            }
            match self.transport.peer_routing() {
                QualificationPeerRouting::PinnedLoopbackTestOnly => {
                    let Some(dial_addr) = member.dial_addr else {
                        return Err(QualificationConfigError::Member);
                    };
                    if !dial_addr.ip().is_loopback() || !routes.insert(dial_addr) {
                        return Err(QualificationConfigError::Member);
                    }
                }
                QualificationPeerRouting::CanonicalEndpointDns => {
                    if member.dial_addr.is_some()
                        || member.endpoint_host != endpoint.host()
                        || !is_canonical_dns_fqdn(endpoint.host())
                    {
                        return Err(QualificationConfigError::Member);
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate the process listener independently from its canonical peer
    /// routing identity.
    ///
    /// The plaintext and pinned test profiles remain exact-loopback only.
    /// Canonical endpoint DNS permits only a wildcard or non-loopback unicast
    /// listener on the local member's declared service port.
    pub fn validate_bind_addr(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<(), QualificationConfigError> {
        let member = self
            .members
            .get(self.node_index)
            .ok_or(QualificationConfigError::Member)?;
        match self.transport.peer_routing() {
            QualificationPeerRouting::PinnedLoopbackTestOnly => {
                if member.dial_addr == Some(bind_addr) && bind_addr.ip().is_loopback() {
                    Ok(())
                } else {
                    Err(QualificationConfigError::Bind)
                }
            }
            QualificationPeerRouting::CanonicalEndpointDns => {
                if bind_addr.port() == member.endpoint_port
                    && is_admissible_deployed_bind_ip(bind_addr.ip())
                {
                    Ok(())
                } else {
                    Err(QualificationConfigError::Bind)
                }
            }
        }
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

    fn peer_routing(&self) -> QualificationPeerRouting {
        match self {
            Self::LoopbackPlaintextTestOnly => QualificationPeerRouting::PinnedLoopbackTestOnly,
            Self::ProjectedMtls(config) => config.peer_routing,
        }
    }
}

/// Routing authority used by the qualification transport.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationPeerRouting {
    /// Exact loopback sockets for single-host tests only.
    #[default]
    PinnedLoopbackTestOnly,
    /// Resolve each canonical manifest endpoint for deployed mTLS peers.
    CanonicalEndpointDns,
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
    #[serde(default)]
    pub peer_routing: QualificationPeerRouting,
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
            .field("peer_routing", &self.peer_routing)
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
            "opc-session-ha/traffic-resource/v5\n",
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
            "member_recovery_progress_profile={}\n",
            "member_recovery_progress_checkpoint_millis={}\n",
            "member_recovery_coverage_millis={}\n",
            "member_recovery_availability_interruption_budget_per_node={}\n",
            "operation_timeout_millis={}\n",
            "child_response_timeout_millis={}\n",
            "fault_expiry_validity_millis={}\n",
            "fault_path_refresh_millis={}\n",
            "fault_directed_path_factor={}\n",
            "fault_connection_accounting_profile={}\n",
            "fault_post_hard_expiry_network_probe_attempts_per_node={}\n",
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
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_PROFILE,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
        QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
        QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS,
        QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS,
        QUALIFICATION_FAULT_PATH_REFRESH_MILLIS,
        QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR,
        QUALIFICATION_TRAFFIC_FAULT_CONNECTION_ACCOUNTING_PROFILE,
        QUALIFICATION_TRAFFIC_FAULT_POST_HARD_EXPIRY_NETWORK_PROBE_ATTEMPTS_PER_NODE,
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
    /// Exact route used only by the pinned loopback test profile.
    ///
    /// Deployed mTLS configuration must omit this value and resolves the
    /// canonical `endpoint_host`/`endpoint_port` pair instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_addr: Option<SocketAddr>,
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
    #[error("qualification listener address is invalid")]
    Bind,
}

fn is_canonical_dns_fqdn(host: &str) -> bool {
    host.contains('.')
        && host.parse::<IpAddr>().is_err()
        && host != "localhost"
        && !host.ends_with(".localhost")
}

fn is_admissible_deployed_bind_ip(ip: IpAddr) -> bool {
    if ip.is_unspecified() {
        return true;
    }
    if ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    !matches!(ip, IpAddr::V4(address) if address == Ipv4Addr::BROADCAST)
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
            QUALIFICATION_TRAFFIC_FAULT_CONNECTION_ACCOUNTING_PROFILE,
            "new-attempts-plus-baseline-outstanding/v1"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_FAULT_POST_HARD_EXPIRY_NETWORK_PROBE_ATTEMPTS_PER_NODE,
            1
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROFILE,
            "member-scoped-reauth-settled-baseline/v3"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_PROFILE,
            "common-key-pulse-all-active-key-coverage/v1"
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
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,
            26_000
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
                "sha256:82da3c6fc69650e902dfb84d9ada35891a769432d40d2640f259845517a6aa01",
                "sha256:1dcbd963848025c58fed0688dd55b77acc41ae26ee385d29328e4483f4f064d0",
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
                dial_addr: Some(
                    format!("192.0.2.1:{}", 7443 + node_index as u16)
                        .parse()
                        .expect("test address"),
                ),
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
                dial_addr: Some(
                    format!("127.0.0.1:{}", 7443 + node_index as u16)
                        .parse()
                        .expect("test address"),
                ),
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
    fn node_control_schema_rejects_incompatible_versions() {
        assert_eq!(QUALIFICATION_NODE_SCHEMA_VERSION, 3);
        for incompatible_version in [1, 2] {
            let mut config = valid_config();
            config.schema_version = incompatible_version;
            assert_eq!(config.validate(), Err(QualificationConfigError::Schema));
        }
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
                peer_routing: QualificationPeerRouting::PinnedLoopbackTestOnly,
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
    fn canonical_endpoint_dns_admits_only_unaliased_mtls_members() {
        let mut config = valid_config();
        for member in &mut config.members {
            member.endpoint_host = format!(
                "session-ha-{}-0.session-ha-peer.qualification.svc.cluster.local",
                member.node_index
            );
            member.endpoint_port = 7443;
            member.dial_addr = None;
        }
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
                peer_routing: QualificationPeerRouting::CanonicalEndpointDns,
            });

        assert_eq!(config.validate(), Ok(()));
        assert_eq!(
            config.validate_bind_addr("0.0.0.0:7443".parse().expect("wildcard bind")),
            Ok(())
        );
        assert_eq!(
            config.validate_bind_addr("192.0.2.10:7443".parse().expect("pod bind")),
            Ok(())
        );
        assert_eq!(
            config.validate_bind_addr("127.0.0.1:7443".parse().expect("loopback bind")),
            Err(QualificationConfigError::Bind)
        );
        assert_eq!(
            config.validate_bind_addr("0.0.0.0:7444".parse().expect("wrong port")),
            Err(QualificationConfigError::Bind)
        );

        let mut aliased = config.clone();
        aliased.members[0].endpoint_host = aliased.members[0].endpoint_host.to_uppercase();
        assert_eq!(aliased.validate(), Err(QualificationConfigError::Member));

        let mut pinned_alias = config.clone();
        pinned_alias.members[0].dial_addr = Some(
            "192.0.2.10:7443"
                .parse()
                .expect("non-loopback pinned alias"),
        );
        assert_eq!(
            pinned_alias.validate(),
            Err(QualificationConfigError::Member)
        );

        let mut ip_literal = config;
        ip_literal.members[0].endpoint_host = "192.0.2.10".to_owned();
        assert_eq!(ip_literal.validate(), Err(QualificationConfigError::Member));
    }

    #[test]
    fn plaintext_listener_admission_remains_exact_loopback_only() {
        let config = valid_config();
        assert_eq!(
            config.validate_bind_addr("127.0.0.1:7443".parse().expect("exact route")),
            Ok(())
        );
        assert_eq!(
            config.validate_bind_addr("0.0.0.0:7443".parse().expect("wildcard route")),
            Err(QualificationConfigError::Bind)
        );
        assert_eq!(
            config.validate_bind_addr("127.0.0.1:7444".parse().expect("wrong route")),
            Err(QualificationConfigError::Bind)
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

    #[test]
    fn mtls_candidate_schedule_digests_are_stable() {
        let vectors = [
            (
                SessionMtlsCandidateCampaign::RotationCore,
                3,
                "sha256:af929a4f7cdd5422eae4c3110859e7230be6b47b30a50f1bcc4b01d35c9f74fa",
            ),
            (
                SessionMtlsCandidateCampaign::RotationCore,
                5,
                "sha256:ae2815d6f6c8fa6c66fad6b0967ce9a990604fe4c07f09c0c5b61185e08f57d2",
            ),
            (
                SessionMtlsCandidateCampaign::FaultExpiryRecovery,
                3,
                "sha256:99172e01703cf31f95b9d076c35be59c1328f9bf099a3ed103c7d29c86ab2033",
            ),
            (
                SessionMtlsCandidateCampaign::FaultExpiryRecovery,
                5,
                "sha256:1bc286b52b643cb360e3e34f15499890af0a955cb70185b75ee17ed65ed79cc5",
            ),
            (
                SessionMtlsCandidateCampaign::TrafficResourceBounds,
                3,
                "sha256:de3291e3e24dd24d20096503006c9b92d3bcbffb0504ee8d5392183e5584cadf",
            ),
            (
                SessionMtlsCandidateCampaign::TrafficResourceBounds,
                5,
                "sha256:e4df715259edc1c1eb574c07bfb81594b23ab1ef2405730808a2b647a277a241",
            ),
        ];
        for (campaign, member_count, expected) in vectors {
            assert_eq!(
                session_mtls_candidate_schedule_sha256(campaign, member_count).as_deref(),
                Some(expected)
            );
        }
        assert_eq!(
            session_mtls_candidate_schedule_sha256(SessionMtlsCandidateCampaign::RotationCore, 4,),
            None
        );
    }
}
