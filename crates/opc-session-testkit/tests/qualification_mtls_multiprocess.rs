#![cfg(target_os = "linux")]

use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_identity::projected_svid::MIN_PROJECTED_SVID_POLL_INTERVAL;
use opc_identity::{
    build_identity_state, parse_certs_pem, parse_key_pem, IdentityState, TrustBundle,
    TrustBundleSet, TrustDomain,
};
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId,
    SessionConfigurationEpoch, SessionConfigurationGeneration, SessionReplicationManifest,
    DEFAULT_MAX_AUTHENTICATION_AGE, DEFAULT_RECONNECT_BACKOFF_MAX, DEFAULT_RECONNECT_BACKOFF_MIN,
    DEFAULT_ROTATION_DRAIN_WINDOW, DEFAULT_ROTATION_JITTER,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusWireRequest,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_traffic_schedule_sha256, qualification_traffic_seed,
    qualification_traffic_value, qualification_value_sha256, read_bounded_json_line,
    session_mtls_candidate_schedule_sha256, write_json_line,
    QualificationConnectionLifecycleConfig, QualificationConnectionLifecycleMetrics,
    QualificationConsensusRpcAvailability, QualificationMember, QualificationNodeCommand,
    QualificationNodeConfig, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationPeerRouting, QualificationProjectedMtlsConfig,
    QualificationProjectedSvidAvailability, QualificationProjectedSvidReason,
    QualificationProjectedSvidStatus, QualificationReadinessCode,
    QualificationSecurityMetricsSnapshot, QualificationTlsMaterialAvailability,
    QualificationTlsMaterialReason, QualificationTlsMaterialStatus, QualificationTrafficErrorClass,
    QualificationTrafficFailureCode, QualificationTrafficFailureStage, QualificationTrafficState,
    QualificationTrafficStatus, QualificationTransportConfig, SessionMtlsCandidateCampaign,
    SessionMtlsCandidateEvidenceV2, SessionMtlsCandidateSourceTreeStatus,
    QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS, QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER,
    QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS, QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS,
    QUALIFICATION_FAULT_PATH_REFRESH_MILLIS, QUALIFICATION_FAULT_TRAFFIC_STOP_LEAD_MILLIS,
    QUALIFICATION_INBOUND_CONNECTION_SLOTS, QUALIFICATION_MAX_CONFIG_BYTES,
    QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE, QUALIFICATION_NODE_SCHEMA_VERSION,
    QUALIFICATION_OPERATION_TIMEOUT_MILLIS, QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS,
    QUALIFICATION_RESOLVER_PROOF_MILLIS, QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE,
    QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE, QUALIFICATION_RESOURCE_SAMPLE_MILLIS,
    QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB, QUALIFICATION_RESOURCE_SETTLE_MILLIS,
    QUALIFICATION_RESOURCE_STABLE_SAMPLES, QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE,
    QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB, QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR,
    QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
    QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS,
    QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE,
    QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR,
    QUALIFICATION_TRAFFIC_FAULT_CONNECTION_ACCOUNTING_PROFILE,
    QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR,
    QUALIFICATION_TRAFFIC_FAULT_POST_HARD_EXPIRY_NETWORK_PROBE_ATTEMPTS_PER_NODE,
    QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
    QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,
    QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS,
    QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS,
    QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_MILLIS,
    QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND, QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER,
    QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_RESTART_PROFILE,
    QUALIFICATION_TRAFFIC_TRANSITION_MILLIS, QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_PROFILE,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS,
    QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS,
    SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_JSON,
};
use opc_types::Timestamp;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, renameat_with, unlinkat, AtFlags, FileType, Mode,
    OFlags, RenameFlags,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;

use opc_tls::TlsConfigBuilder;

const CLUSTER_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
);
const CHILD_TIMEOUT: Duration = Duration::from_millis(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS);
const CANARY_TTL_MILLIS: u64 = 60 * 60 * 1_000;
const CANARY_STABLE_ID: &str = "rotation-core-canary";
const CANARY_LEASE_HANDLE: &str = "rotation-core-lease";
const CANARY_OWNER: &str = "rotation-core-owner";
const ROTATION_PLAINTEXT_CANARY_PREFIX: &[u8] = b"opc-rotation-plaintext-canary/";
const TRAFFIC_PLAINTEXT_CANARY_PREFIX: &[u8] = b"opc-rotation-traffic-canary/";
const PLAINTEXT_CANARY_PREFIXES: [&[u8]; 2] = [
    ROTATION_PLAINTEXT_CANARY_PREFIX,
    TRAFFIC_PLAINTEXT_CANARY_PREFIX,
];
const EVIDENCE_OUTPUT_DIRECTORY_ENV: &str = "OPC_SESSION_HA_EVIDENCE_DIR";
const MAX_CANDIDATE_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CANDIDATE_EVIDENCE_BYTES: u64 = 256 * 1024;
const MAX_CANDIDATE_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

static FLEET_TEST_LOCK: Mutex<()> = Mutex::new(());
static CANDIDATE_STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

fn single_attempt_removed_root_probe_lifecycle() -> ConnectionLifecyclePolicy {
    let cold_connect_timeout = DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    ConnectionLifecyclePolicy::try_new(
        DEFAULT_MAX_AUTHENTICATION_AGE,
        DEFAULT_ROTATION_DRAIN_WINDOW,
        cold_connect_timeout,
        cold_connect_timeout,
        Duration::ZERO,
    )
    .expect("single-attempt removed-root probe lifecycle policy")
}

struct Issuer {
    certificate: Certificate,
    key: KeyPair,
}

#[derive(Debug, Clone, Copy)]
struct ProcessResourceSnapshot {
    file_descriptors: usize,
    socket_file_descriptors: usize,
    nontransport_file_descriptors: usize,
    threads: usize,
    vm_rss_kib: u64,
    vm_hwm_kib: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProcessResourceHighWater {
    samples: u64,
    file_descriptors: usize,
    threads: usize,
    vm_hwm_kib: u64,
}

struct ResourceSampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<io::Result<Vec<ProcessResourceHighWater>>>,
}

impl ResourceSampler {
    fn start(process_ids: Vec<u32>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("qualification-resource-sampler".to_owned())
            .spawn(move || {
                let mut high_water = vec![
                    ProcessResourceHighWater {
                        samples: 0,
                        file_descriptors: 0,
                        threads: 0,
                        vm_hwm_kib: 0,
                    };
                    process_ids.len()
                ];
                loop {
                    for (index, process_id) in process_ids.iter().copied().enumerate() {
                        let snapshot = read_process_resources(process_id, false)?;
                        let current = &mut high_water[index];
                        current.samples = current.samples.saturating_add(1);
                        current.file_descriptors =
                            current.file_descriptors.max(snapshot.file_descriptors);
                        current.threads = current.threads.max(snapshot.threads);
                        current.vm_hwm_kib = current.vm_hwm_kib.max(snapshot.vm_hwm_kib);
                    }
                    if stop_for_thread.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(QUALIFICATION_RESOURCE_SAMPLE_MILLIS));
                }
                Ok(high_water)
            })
            .expect("start qualification resource sampler");
        Self { stop, handle }
    }

    fn finish(self) -> Vec<ProcessResourceHighWater> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .join()
            .expect("join qualification resource sampler")
            .expect("sample live qualification processes")
    }
}

fn read_process_resources(
    process_id: u32,
    classify_file_descriptors: bool,
) -> io::Result<ProcessResourceSnapshot> {
    let process_root = PathBuf::from(format!("/proc/{process_id}"));
    let descriptor_directory = process_root.join("fd");
    let mut file_descriptors = 0_usize;
    let mut socket_file_descriptors = 0_usize;
    let mut nontransport_file_descriptors = 0_usize;
    for entry in fs::read_dir(&descriptor_directory)? {
        let entry = entry?;
        file_descriptors = file_descriptors.saturating_add(1);
        if classify_file_descriptors {
            let target = fs::read_link(entry.path())?;
            if target.to_string_lossy().starts_with("socket:[") {
                socket_file_descriptors = socket_file_descriptors.saturating_add(1);
            } else {
                nontransport_file_descriptors = nontransport_file_descriptors.saturating_add(1);
            }
        }
    }
    let threads = fs::read_dir(process_root.join("task"))?
        .collect::<Result<Vec<_>, _>>()?
        .len();
    let status = fs::read_to_string(process_root.join("status"))?;
    let vm_rss_kib = parse_status_kib(&status, "VmRSS:")?;
    let vm_hwm_kib = parse_status_kib(&status, "VmHWM:")?;
    Ok(ProcessResourceSnapshot {
        file_descriptors,
        socket_file_descriptors,
        nontransport_file_descriptors,
        threads,
        vm_rss_kib,
        vm_hwm_kib,
    })
}

fn read_classified_process_resources(process_id: u32) -> ProcessResourceSnapshot {
    let mut last_error = None;
    for _ in 0..5 {
        match read_process_resources(process_id, true) {
            Ok(snapshot) => return snapshot,
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    panic!(
        "failed to classify qualification process resources: process_id={process_id}, error={:?}",
        last_error
    );
}

fn parse_status_kib(status: &str, field: &str) -> io::Result<u64> {
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing process status field")
        })?;
    let mut values = line[field.len()..].split_whitespace();
    let value = values
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid process status value")
        })?;
    if values.next() != Some("kB") || values.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid process status unit",
        ));
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficParticipantError {
    UnsupportedMemberCount,
    EmptyObservers,
    EmptyMutators,
    NodeIndexOutOfRange,
    DuplicateNodeIndex,
    MutatorWithoutObserver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrafficParticipants {
    member_count: usize,
    observers: Vec<usize>,
    mutators: Vec<usize>,
}

impl TrafficParticipants {
    fn try_new(
        member_count: usize,
        observers: &[usize],
        mutators: &[usize],
    ) -> Result<Self, TrafficParticipantError> {
        if !matches!(member_count, 3 | 5) {
            return Err(TrafficParticipantError::UnsupportedMemberCount);
        }
        validate_traffic_indices(
            member_count,
            observers,
            TrafficParticipantError::EmptyObservers,
        )?;
        validate_traffic_indices(
            member_count,
            mutators,
            TrafficParticipantError::EmptyMutators,
        )?;
        if mutators
            .iter()
            .any(|node_index| !observers.contains(node_index))
        {
            return Err(TrafficParticipantError::MutatorWithoutObserver);
        }
        Ok(Self {
            member_count,
            observers: observers.to_vec(),
            mutators: mutators.to_vec(),
        })
    }

    fn is_mutator(&self, node_index: usize) -> bool {
        self.mutators.contains(&node_index)
    }
}

fn validate_traffic_indices(
    member_count: usize,
    indices: &[usize],
    empty_error: TrafficParticipantError,
) -> Result<(), TrafficParticipantError> {
    if indices.is_empty() {
        return Err(empty_error);
    }
    let mut seen = vec![false; member_count];
    for node_index in indices {
        let Some(was_seen) = seen.get_mut(*node_index) else {
            return Err(TrafficParticipantError::NodeIndexOutOfRange);
        };
        if *was_seen {
            return Err(TrafficParticipantError::DuplicateNodeIndex);
        }
        *was_seen = true;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct IndexedTrafficStatus {
    node_index: usize,
    status: QualificationTrafficStatus,
}

#[derive(Debug, Clone)]
struct RecoveryTrafficProgressTracker {
    pulse_checkpoint: Vec<IndexedTrafficStatus>,
    pulse_observed_at: Instant,
    pulse_recovery_extended: bool,
    coverage_checkpoint: Vec<IndexedTrafficStatus>,
    coverage_observed_at: Instant,
}

impl RecoveryTrafficProgressTracker {
    fn new(checkpoint: Vec<IndexedTrafficStatus>, observed_at: Instant) -> Self {
        Self {
            pulse_checkpoint: checkpoint.clone(),
            pulse_observed_at: observed_at,
            pulse_recovery_extended: false,
            coverage_checkpoint: checkpoint,
            coverage_observed_at: observed_at,
        }
    }

    fn pulse_deadline(&self) -> Instant {
        let interval = if self.pulse_recovery_extended {
            QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
        } else {
            QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS
        };
        self.pulse_observed_at + Duration::from_millis(interval)
    }

    fn extend_pulse_for_availability_recovery(&mut self) {
        self.pulse_recovery_extended = true;
    }

    fn record_pulse(&mut self, checkpoint: Vec<IndexedTrafficStatus>, observed_at: Instant) {
        self.pulse_checkpoint = checkpoint;
        self.pulse_observed_at = observed_at;
        self.pulse_recovery_extended = false;
    }

    fn record_coverage(&mut self, checkpoint: Vec<IndexedTrafficStatus>, observed_at: Instant) {
        self.coverage_checkpoint = checkpoint;
        self.coverage_observed_at = observed_at;
    }

    fn coverage_deadline(&self) -> Instant {
        self.coverage_observed_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS)
    }

    fn next_deadline(&self, absolute_deadline: Instant) -> Instant {
        self.pulse_deadline()
            .min(self.coverage_deadline())
            .min(absolute_deadline)
    }
}

struct RecoveryFaultSettlementContext<'a> {
    before: &'a [QualificationConnectionLifecycleMetrics],
    participants: &'a TrafficParticipants,
    phase: &'a str,
    started: Instant,
    deadline: Instant,
    traffic_before: &'a [IndexedTrafficStatus],
    traffic_progress: RecoveryTrafficProgressTracker,
}

struct RecoveredMemberPhaseContext<'a> {
    member: usize,
    participants: &'a TrafficParticipants,
    phase: &'a str,
    fault_lifecycle_before: &'a [QualificationConnectionLifecycleMetrics],
    traffic_availability_baseline: &'a [IndexedTrafficStatus],
    traffic_progress: RecoveryTrafficProgressTracker,
    recovery_started: Instant,
    recovery_deadline: Instant,
}

fn indexed_traffic_status(
    statuses: &[IndexedTrafficStatus],
    node_index: usize,
) -> Option<&QualificationTrafficStatus> {
    let mut matches = statuses
        .iter()
        .filter(|candidate| candidate.node_index == node_index);
    let status = &matches.next()?.status;
    matches.next().is_none().then_some(status)
}

fn traffic_status_snapshot_matches(
    statuses: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    statuses.len() == participants.observers.len()
        && participants
            .observers
            .iter()
            .all(|node_index| indexed_traffic_status(statuses, *node_index).is_some())
}

fn traffic_mutator_counters_advanced(
    before: &QualificationTrafficStatus,
    after: &QualificationTrafficStatus,
) -> bool {
    traffic_live_mutator_counters_are_consistent(before)
        && traffic_live_mutator_counters_are_consistent(after)
        && traffic_availability_recovery_is_resolved(after)
        && after.mutation_cycles > before.mutation_cycles
        && after.linearizable_reads > before.linearizable_reads
        && after.lease_renewals > before.lease_renewals
        && after.lease_reacquisitions > before.lease_reacquisitions
        && after.complete_restore_scans > before.complete_restore_scans
        && after.durable_readiness_probes > before.durable_readiness_probes
        && after.last_generation > before.last_generation
        && after.last_record_fence > before.last_record_fence
        && (after.mutation_resume_generation != 0 || after.availability_interruptions >= 1)
        && after.availability_interruptions >= before.availability_interruptions
        && after.availability_recoveries >= before.availability_recoveries
        && after.max_consecutive_availability_interruptions
            >= before.max_consecutive_availability_interruptions
}

fn traffic_live_mutator_counters_are_consistent(status: &QualificationTrafficStatus) -> bool {
    let Some(process_generations) = status
        .last_generation
        .checked_sub(status.mutation_resume_generation)
    else {
        return false;
    };
    let upper = status
        .mutation_cycles
        .saturating_add(status.availability_interruptions)
        .saturating_add(1);
    let ordered_stages = [
        status.lease_renewals,
        process_generations,
        status.linearizable_reads,
        status.complete_restore_scans,
        status.durable_readiness_probes,
        status.lease_reacquisitions,
        status.mutation_cycles,
    ];
    (status.mutation_resume_generation == 0) == (status.mutation_resume_record_fence == 0)
        && status.last_record_fence >= status.mutation_resume_record_fence
        && ordered_stages
            .into_iter()
            .all(|counter| counter >= status.mutation_cycles && counter <= upper)
        && ordered_stages
            .windows(2)
            .all(|stages| stages[0] >= stages[1])
        && status.availability_interruptions
            <= QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
        && status.availability_recoveries <= status.availability_interruptions
        && status.max_consecutive_availability_interruptions <= status.availability_interruptions
        && ((status.availability_interruptions == 0
            && status.max_consecutive_availability_interruptions == 0)
            || (status.availability_interruptions > 0
                && status.max_consecutive_availability_interruptions > 0))
        && traffic_failure_fields_are_coherent(status)
}

fn traffic_availability_recovery_is_resolved(status: &QualificationTrafficStatus) -> bool {
    status.availability_recoveries == status.availability_interruptions
}

fn subset_traffic_availability_is_settled(
    statuses: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    traffic_status_snapshot_matches(statuses, participants)
        && statuses.iter().all(|indexed| {
            let status = &indexed.status;
            let live_task_shape = if participants.is_mutator(indexed.node_index) {
                status.state == QualificationTrafficState::Running
                    && status.owned_async_tasks == 2
                    && traffic_live_mutator_counters_are_consistent(status)
            } else {
                matches!(
                    status.state,
                    QualificationTrafficState::WatchReady
                        | QualificationTrafficState::MutationStopped
                ) && status.owned_async_tasks == 1
            };
            live_task_shape
                && status.failure.is_none()
                && traffic_failure_fields_are_coherent(status)
                && traffic_availability_recovery_is_resolved(status)
        })
}

fn member_reauthentication_generations_are_scoped(
    before: &[u64],
    after: &[u64],
    member: usize,
) -> bool {
    before.len() == after.len()
        && member < before.len()
        && before
            .iter()
            .zip(after)
            .enumerate()
            .all(|(node_index, (before, after))| {
                if node_index == member {
                    before.checked_add(1) == Some(*after)
                } else {
                    before == after
                }
            })
}

fn member_incident_directed_paths(member_count: usize, member: usize) -> Vec<(usize, usize)> {
    assert!(member < member_count);
    (0..member_count)
        .flat_map(|source| (0..member_count).map(move |target| (source, target)))
        .filter(|(source, target)| source != target && (*source == member || *target == member))
        .collect()
}

fn unrelated_survivor_reauthentication_retirements_are_unchanged(
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    member: usize,
) -> bool {
    before.len() == after.len()
        && member < before.len()
        && before
            .iter()
            .zip(after)
            .enumerate()
            .filter(|(node_index, _)| *node_index != member)
            .all(|(_, (before, after))| {
                after.retirement_explicit == before.retirement_explicit
                    && after.retirement_material_epoch == before.retirement_material_epoch
            })
}

fn traffic_failure_fields_are_coherent(status: &QualificationTrafficStatus) -> bool {
    match (
        status.failure,
        status.failure_stage,
        status.failure_error_class,
        status.failure_recovery_elapsed_millis,
    ) {
        (None, None, None, None) => true,
        (
            Some(QualificationTrafficFailureCode::AvailabilityRecoveryDeadlineExceeded),
            Some(_),
            Some(_),
            Some(_),
        ) => true,
        (Some(code), Some(_), Some(_), None) => {
            code != QualificationTrafficFailureCode::AvailabilityRecoveryDeadlineExceeded
        }
        _ => false,
    }
}

fn traffic_nonmutator_counters_unchanged(
    before: &QualificationTrafficStatus,
    after: &QualificationTrafficStatus,
) -> bool {
    after.mutation_cycles == before.mutation_cycles
        && after.linearizable_reads == before.linearizable_reads
        && after.lease_renewals == before.lease_renewals
        && after.lease_reacquisitions == before.lease_reacquisitions
        && after.complete_restore_scans == before.complete_restore_scans
        && after.durable_readiness_probes == before.durable_readiness_probes
        && after.mutation_resume_generation == before.mutation_resume_generation
        && after.mutation_resume_record_fence == before.mutation_resume_record_fence
        && after.last_generation == before.last_generation
        && after.last_record_fence == before.last_record_fence
        && after.availability_interruptions == before.availability_interruptions
        && after.availability_recoveries == before.availability_recoveries
        && after.max_consecutive_availability_interruptions
            == before.max_consecutive_availability_interruptions
}

fn subset_traffic_availability_within_recovery_budget(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    traffic_status_snapshot_matches(before, participants)
        && traffic_status_snapshot_matches(after, participants)
        && participants.observers.iter().all(|node_index| {
            let Some(before) = indexed_traffic_status(before, *node_index) else {
                return false;
            };
            let Some(after) = indexed_traffic_status(after, *node_index) else {
                return false;
            };
            let Some(interruptions) = after
                .availability_interruptions
                .checked_sub(before.availability_interruptions)
            else {
                return false;
            };
            let Some(recoveries) = after
                .availability_recoveries
                .checked_sub(before.availability_recoveries)
            else {
                return false;
            };
            let expected_maximum = if interruptions == 0 {
                before.max_consecutive_availability_interruptions
            } else {
                before.max_consecutive_availability_interruptions.max(1)
            };
            interruptions
                <= QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
                && recoveries <= interruptions
                && after.max_consecutive_availability_interruptions == expected_maximum
        })
}

fn subset_traffic_availability_changed_since(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    participants.observers.iter().any(|node_index| {
        indexed_traffic_status(before, *node_index)
            .zip(indexed_traffic_status(after, *node_index))
            .is_some_and(|(before, after)| {
                after.availability_interruptions > before.availability_interruptions
            })
    })
}

fn subset_traffic_availability_counters_equal(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    traffic_status_snapshot_matches(before, participants)
        && traffic_status_snapshot_matches(after, participants)
        && participants.observers.iter().all(|node_index| {
            indexed_traffic_status(before, *node_index)
                .zip(indexed_traffic_status(after, *node_index))
                .is_some_and(|(before, after)| {
                    after.availability_interruptions == before.availability_interruptions
                        && after.availability_recoveries == before.availability_recoveries
                        && after.max_consecutive_availability_interruptions
                            == before.max_consecutive_availability_interruptions
                })
        })
}

fn recovery_traffic_status_is_monotonic(
    before: &QualificationTrafficStatus,
    after: &QualificationTrafficStatus,
    participants: &TrafficParticipants,
    node_index: usize,
) -> bool {
    let is_mutator = participants.is_mutator(node_index);
    let role_is_healthy = if is_mutator {
        after.state == QualificationTrafficState::Running && after.owned_async_tasks == 2
    } else {
        matches!(
            after.state,
            QualificationTrafficState::WatchReady | QualificationTrafficState::MutationStopped
        ) && after.owned_async_tasks == 1
    };
    let mutation_is_monotonic = if is_mutator {
        traffic_live_mutator_counters_are_consistent(before)
            && traffic_live_mutator_counters_are_consistent(after)
            && after.mutation_cycles >= before.mutation_cycles
            && after.linearizable_reads >= before.linearizable_reads
            && after.lease_renewals >= before.lease_renewals
            && after.lease_reacquisitions >= before.lease_reacquisitions
            && after.complete_restore_scans >= before.complete_restore_scans
            && after.durable_readiness_probes >= before.durable_readiness_probes
            && after.mutation_resume_generation == before.mutation_resume_generation
            && after.mutation_resume_record_fence == before.mutation_resume_record_fence
            && after.last_generation >= before.last_generation
            && after.last_record_fence >= before.last_record_fence
    } else {
        traffic_nonmutator_counters_unchanged(before, after)
    };

    role_is_healthy
        && mutation_is_monotonic
        && after.failure.is_none()
        && traffic_failure_fields_are_coherent(after)
        && traffic_availability_recovery_is_resolved(after)
        && after.seed == before.seed
        && after.availability_interruptions >= before.availability_interruptions
        && after.availability_recoveries >= before.availability_recoveries
        && after.max_consecutive_availability_interruptions
            >= before.max_consecutive_availability_interruptions
        && after.watch_entries >= before.watch_entries
        && after.watch_applied_records >= before.watch_applied_records
        && after.watch_sequence >= before.watch_sequence
        && after.watch_reconciliations >= before.watch_reconciliations
        && after.watch_reconciled_sequence >= before.watch_reconciled_sequence
        && after.replication_head >= before.replication_head
        && before.watch_traffic_generations.len() == participants.member_count
        && after.watch_traffic_generations.len() == participants.member_count
        && participants.mutators.iter().all(|key_index| {
            after.watch_traffic_generations[*key_index]
                >= before.watch_traffic_generations[*key_index]
        })
        && (0..participants.member_count)
            .filter(|key_index| !participants.mutators.contains(key_index))
            .all(|key_index| {
                after.watch_traffic_generations[key_index]
                    == before.watch_traffic_generations[key_index]
            })
}

fn recovery_traffic_has_common_key_pulse(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    traffic_status_snapshot_matches(before, participants)
        && traffic_status_snapshot_matches(after, participants)
        && participants.observers.iter().all(|node_index| {
            indexed_traffic_status(before, *node_index)
                .zip(indexed_traffic_status(after, *node_index))
                .is_some_and(|(before, after)| {
                    recovery_traffic_status_is_monotonic(before, after, participants, *node_index)
                })
        })
        && participants.mutators.iter().any(|key_index| {
            participants.observers.iter().all(|node_index| {
                indexed_traffic_status(before, *node_index)
                    .zip(indexed_traffic_status(after, *node_index))
                    .is_some_and(|(before, after)| {
                        after.watch_traffic_generations[*key_index]
                            > before.watch_traffic_generations[*key_index]
                    })
            })
        })
}

fn recovery_traffic_has_all_key_coverage(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    traffic_status_snapshot_matches(before, participants)
        && traffic_status_snapshot_matches(after, participants)
        && participants.observers.iter().all(|node_index| {
            indexed_traffic_status(before, *node_index)
                .zip(indexed_traffic_status(after, *node_index))
                .is_some_and(|(before, after)| {
                    recovery_traffic_status_is_monotonic(before, after, participants, *node_index)
                        && participants.mutators.iter().all(|key_index| {
                            after.watch_traffic_generations[*key_index]
                                > before.watch_traffic_generations[*key_index]
                        })
                })
        })
}

fn subset_traffic_made_semantic_progress(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
) -> bool {
    subset_traffic_made_semantic_progress_with_crashed_tail(before, after, participants, None)
}

fn subset_traffic_made_semantic_progress_with_crashed_tail(
    before: &[IndexedTrafficStatus],
    after: &[IndexedTrafficStatus],
    participants: &TrafficParticipants,
    crashed_node_index: Option<usize>,
) -> bool {
    if !traffic_status_snapshot_matches(before, participants)
        || !traffic_status_snapshot_matches(after, participants)
        || crashed_node_index.is_some_and(|node_index| {
            node_index >= participants.member_count || participants.mutators.contains(&node_index)
        })
    {
        return false;
    }
    participants.observers.iter().all(|node_index| {
        let Some(before) = indexed_traffic_status(before, *node_index) else {
            return false;
        };
        let Some(after) = indexed_traffic_status(after, *node_index) else {
            return false;
        };
        let is_mutator = participants.is_mutator(*node_index);
        let role_is_healthy = if is_mutator {
            after.state == QualificationTrafficState::Running && after.owned_async_tasks == 2
        } else {
            matches!(
                after.state,
                QualificationTrafficState::WatchReady | QualificationTrafficState::MutationStopped
            ) && after.owned_async_tasks == 1
        };
        role_is_healthy
            && after.failure.is_none()
            && traffic_failure_fields_are_coherent(after)
            && traffic_availability_recovery_is_resolved(after)
            && after.seed == before.seed
            && before.watch_traffic_generations.len() == participants.member_count
            && after.watch_traffic_generations.len() == participants.member_count
            && after.watch_entries > before.watch_entries
            && after.watch_applied_records > before.watch_applied_records
            && after.watch_sequence > before.watch_sequence
            && after.watch_reconciliations >= before.watch_reconciliations
            && after.watch_reconciled_sequence >= before.watch_reconciled_sequence
            && participants.mutators.iter().all(|key_index| {
                after.watch_traffic_generations[*key_index]
                    > before.watch_traffic_generations[*key_index]
            })
            && (0..participants.member_count)
                .filter(|key_index| !participants.mutators.contains(key_index))
                .all(|key_index| {
                    if Some(key_index) == crashed_node_index {
                        after.watch_traffic_generations[key_index]
                            >= before.watch_traffic_generations[key_index]
                    } else {
                        after.watch_traffic_generations[key_index]
                            == before.watch_traffic_generations[key_index]
                    }
                })
            && if is_mutator {
                traffic_mutator_counters_advanced(before, after)
            } else {
                traffic_nonmutator_counters_unchanged(before, after)
            }
    })
}

fn assert_completed_traffic_cycles(status: &QualificationTrafficStatus) {
    assert!(status.mutation_cycles >= 1);
    assert!(traffic_live_mutator_counters_are_consistent(status));
    assert_eq!(status.lease_reacquisitions, status.mutation_cycles);
    assert!(traffic_availability_recovery_is_resolved(status));
    assert!(status.mutation_resume_generation != 0 || status.availability_interruptions >= 1);
    assert!(
        status.availability_interruptions
            <= QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
    );
    assert!(
        status.mutation_resume_generation != 0
            || status.max_consecutive_availability_interruptions >= 1
    );
    assert!(status.last_record_fence >= 1);
    assert!(status.last_generation > status.mutation_resume_generation);
    assert!(status.last_record_fence > status.mutation_resume_record_fence);
    assert!(status.watch_entries >= 1);
    assert!(status.watch_applied_records >= 1);
    assert!(matches!(status.watch_traffic_generations.len(), 3 | 5));
}

fn traffic_status_made_semantic_progress(
    before: &QualificationTrafficStatus,
    after: &QualificationTrafficStatus,
    member_count: usize,
) -> bool {
    before.watch_traffic_generations.len() == member_count
        && after.watch_traffic_generations.len() == member_count
        && traffic_mutator_counters_advanced(before, after)
        && after.watch_entries > before.watch_entries
        && after.watch_applied_records > before.watch_applied_records
        && after.watch_sequence > before.watch_sequence
        && after
            .watch_traffic_generations
            .iter()
            .zip(&before.watch_traffic_generations)
            .all(|(after, before)| after > before)
}

fn traffic_stable_id(node_index: usize) -> String {
    format!("rotation-traffic-{node_index}")
}

fn traffic_owner(node_index: usize) -> String {
    format!("rotation-traffic-owner-{node_index}")
}

fn assert_round_lifecycle_bounds(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
) {
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    let required_successes = u64::try_from(QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND)
        .expect("bounded generation count")
        .saturating_mul(remote_peers);
    assert_epoch_changing_lifecycle_delta_bounds(member_count, before, after, required_successes);
}

fn assert_lifecycle_delta_bounds(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    minimum_successes_per_node: u64,
) {
    let expected_authentication_failures = vec![0; member_count];
    assert_lifecycle_delta_bounds_with_authentication(
        member_count,
        before,
        after,
        minimum_successes_per_node,
        &expected_authentication_failures,
    );
}

fn assert_lifecycle_delta_bounds_with_authentication(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    minimum_successes_per_node: u64,
    expected_authentication_failures: &[u64],
) {
    let superseded_bounds = vec![0; member_count];
    assert_lifecycle_delta_bounds_with_expected_outcomes(
        member_count,
        before,
        after,
        minimum_successes_per_node,
        expected_authentication_failures,
        &superseded_bounds,
    );
}

fn assert_epoch_changing_lifecycle_delta_bounds(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    minimum_successes_per_node: u64,
) {
    let expected_authentication_failures = vec![0; member_count];
    let superseded_bounds = vec![lifecycle_interval_connection_bound(member_count); member_count];
    assert_lifecycle_delta_bounds_with_expected_outcomes(
        member_count,
        before,
        after,
        minimum_successes_per_node,
        &expected_authentication_failures,
        &superseded_bounds,
    );
}

fn lifecycle_interval_connection_bound(member_count: usize) -> u64 {
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR
        .saturating_mul(remote_peers)
        .saturating_add(QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE)
}

fn recovery_fault_connection_bound(member_count: usize) -> u64 {
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    let directed_paths =
        QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR.saturating_mul(remote_peers);
    let refresh_rounds = QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS
        .div_ceil(QUALIFICATION_FAULT_PATH_REFRESH_MILLIS);
    lifecycle_interval_connection_bound(member_count)
        .saturating_add(refresh_rounds.saturating_mul(directed_paths))
        .saturating_add(
            QUALIFICATION_TRAFFIC_FAULT_POST_HARD_EXPIRY_NETWORK_PROBE_ATTEMPTS_PER_NODE,
        )
}

fn assert_lifecycle_delta_bounds_with_expected_outcomes(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    minimum_successes_per_node: u64,
    expected_authentication_failures: &[u64],
    superseded_bounds: &[u64],
) {
    assert_eq!(before.len(), member_count);
    assert_eq!(after.len(), member_count);
    assert_eq!(expected_authentication_failures.len(), member_count);
    assert_eq!(superseded_bounds.len(), member_count);
    let bound = lifecycle_interval_connection_bound(member_count);
    for (node_index, (((before, after), expected_authentication_failures), superseded_bound)) in
        before
            .iter()
            .zip(after)
            .zip(expected_authentication_failures)
            .zip(superseded_bounds)
            .enumerate()
    {
        let attempts = lifecycle_counter_delta(
            before.connection_attempts,
            after.connection_attempts,
            node_index,
            "connection_attempts",
        );
        let successes = lifecycle_counter_delta(
            before.connection_successes,
            after.connection_successes,
            node_index,
            "connection_successes",
        );
        let reconnect_attempts = lifecycle_counter_delta(
            before.reconnect_attempts,
            after.reconnect_attempts,
            node_index,
            "reconnect_attempts",
        );
        let idle_retirements = lifecycle_counter_delta(
            before.retirement_idle_timeout,
            after.retirement_idle_timeout,
            node_index,
            "retirement_idle_timeout",
        );
        assert!(
            attempts <= bound,
            "connection-attempt bound exceeded: node={node_index}, attempts={attempts}, bound={bound}"
        );
        assert!(
            reconnect_attempts <= bound,
            "reconnect-attempt bound exceeded: node={node_index}, reconnect_attempts={reconnect_attempts}, bound={bound}"
        );
        assert!(
            idle_retirements <= bound,
            "authenticated idle-retirement bound exceeded: node={node_index}, idle_retirements={idle_retirements}, bound={bound}"
        );
        // A complete authenticated bootstrap-retirement control is a
        // successful attempt and is retried before Openraft bytes are sent.
        // Zero classified failures plus exact cumulative outstanding-handler
        // accounting are the fleet regression for the pre-admission rotation
        // race fixed by #223. A live inbound persistent handler records its
        // success only when it closes, so interval attempt/success deltas are
        // intentionally not required to be equal.
        assert_connection_attempts_accounted(after, node_index);
        assert!(
            lifecycle_transition_is_settled(after, member_count),
            "connection lifecycle did not settle inside the transition: node={node_index}, metrics={after:?}"
        );
        assert!(
            successes >= minimum_successes_per_node,
            "fresh reauthentication lacked successful connections: node={node_index}, successes={successes}, required={minimum_successes_per_node}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_transport,
                after.connection_failure_transport,
                node_index,
                "connection_failure_transport",
            ),
            0,
            "transport-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_authentication,
                after.connection_failure_authentication,
                node_index,
                "connection_failure_authentication",
            ),
            *expected_authentication_failures,
            "authentication-failure ledger mismatch: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_timeout,
                after.connection_failure_timeout,
                node_index,
                "connection_failure_timeout",
            ),
            0,
            "timeout-failure budget exceeded: node={node_index}"
        );
        let superseded = lifecycle_counter_delta(
            before.connection_superseded,
            after.connection_superseded,
            node_index,
            "connection_superseded",
        );
        assert!(
            superseded <= *superseded_bound,
            "superseded-attempt budget exceeded: node={node_index}, observed={superseded}, bound={superseded_bound}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_abandoned,
                after.connection_abandoned,
                node_index,
                "connection_abandoned",
            ),
            0,
            "abandoned-attempt budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_protocol,
                after.connection_failure_protocol,
                node_index,
                "connection_failure_protocol",
            ),
            0,
            "protocol-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_backend,
                after.connection_failure_backend,
                node_index,
                "connection_failure_backend",
            ),
            0,
            "backend-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.reconnect_failures,
                after.reconnect_failures,
                node_index,
                "reconnect_failures",
            ),
            0,
            "reconnect-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.drain_overruns,
                after.drain_overruns,
                node_index,
                "drain_overruns",
            ),
            0,
            "drain-overrun budget exceeded: node={node_index}"
        );
    }
}

fn lifecycle_counter_delta(before: u64, after: u64, node_index: usize, counter: &str) -> u64 {
    after.checked_sub(before).unwrap_or_else(|| {
        panic!(
            "lifecycle counter regressed: node={node_index}, counter={counter}, before={before}, after={after}"
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionAttemptSettlementLedger {
    attempts: u64,
    successes: u64,
    transport_failures: u64,
    authentication_failures: u64,
    timeout_failures: u64,
    superseded: u64,
    abandoned: u64,
    protocol_failures: u64,
    backend_failures: u64,
    reconnect_attempts: u64,
    reconnect_failures: u64,
}

fn connection_attempt_settlement_ledger(
    metrics: &QualificationConnectionLifecycleMetrics,
) -> ConnectionAttemptSettlementLedger {
    ConnectionAttemptSettlementLedger {
        attempts: metrics.connection_attempts,
        successes: metrics.connection_successes,
        transport_failures: metrics.connection_failure_transport,
        authentication_failures: metrics.connection_failure_authentication,
        timeout_failures: metrics.connection_failure_timeout,
        superseded: metrics.connection_superseded,
        abandoned: metrics.connection_abandoned,
        protocol_failures: metrics.connection_failure_protocol,
        backend_failures: metrics.connection_failure_backend,
        reconnect_attempts: metrics.reconnect_attempts,
        reconnect_failures: metrics.reconnect_failures,
    }
}

fn connection_attempt_settlement_ledgers(
    metrics: &[QualificationConnectionLifecycleMetrics],
) -> Vec<ConnectionAttemptSettlementLedger> {
    metrics
        .iter()
        .map(connection_attempt_settlement_ledger)
        .collect()
}

fn recovery_fault_outcome_settlement_window() -> Duration {
    Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_MILLIS)
}

fn recovery_fault_server_tail_window() -> Duration {
    DURABLE_CONSENSUS_TIMING_PROFILE
        .server_idle_timeout()
        .max(DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout())
        .saturating_mul(2)
}

fn recovery_fault_outbound_quiet_window() -> Duration {
    recovery_fault_outcome_settlement_window().saturating_sub(recovery_fault_server_tail_window())
}

fn recovery_traffic_progress_deadline(
    last_progress_observed_at: Instant,
    absolute_deadline: Instant,
) -> Instant {
    (last_progress_observed_at
        + Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS))
    .min(absolute_deadline)
}

fn recovery_fault_flush_has_no_unsafe_outcomes(
    before: &QualificationConnectionLifecycleMetrics,
    after: &QualificationConnectionLifecycleMetrics,
) -> bool {
    after.connection_failure_protocol == before.connection_failure_protocol
        && after.connection_failure_backend == before.connection_failure_backend
        && after.connection_abandoned == before.connection_abandoned
        && after.drain_overruns == before.drain_overruns
}

fn assert_recovery_fault_flush_bounds(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
) {
    assert_eq!(before.len(), member_count);
    assert_eq!(after.len(), member_count);
    let bound = recovery_fault_connection_bound(member_count);
    for (node_index, (before, after)) in before.iter().zip(after).enumerate() {
        assert_connection_attempts_accounted(before, node_index);
        assert_connection_attempts_accounted(after, node_index);
        assert!(
            recovery_fault_flush_has_no_unsafe_outcomes(before, after),
            "fault-outcome flush recorded abandoned, protocol, backend, or drain-overrun evidence: node={node_index}, before={before:?}, after={after:?}"
        );
        let attempts = lifecycle_counter_delta(
            before.connection_attempts,
            after.connection_attempts,
            node_index,
            "connection_attempts",
        );
        let terminal = [
            (
                "connection_successes",
                before.connection_successes,
                after.connection_successes,
            ),
            (
                "connection_failure_transport",
                before.connection_failure_transport,
                after.connection_failure_transport,
            ),
            (
                "connection_failure_authentication",
                before.connection_failure_authentication,
                after.connection_failure_authentication,
            ),
            (
                "connection_failure_timeout",
                before.connection_failure_timeout,
                after.connection_failure_timeout,
            ),
            (
                "connection_superseded",
                before.connection_superseded,
                after.connection_superseded,
            ),
            (
                "connection_abandoned",
                before.connection_abandoned,
                after.connection_abandoned,
            ),
        ]
        .into_iter()
        .try_fold(0_u64, |total, (name, before, after)| {
            total.checked_add(lifecycle_counter_delta(before, after, node_index, name))
        })
        .expect("bounded fault terminal ledger");
        let reconnect_attempts = lifecycle_counter_delta(
            before.reconnect_attempts,
            after.reconnect_attempts,
            node_index,
            "reconnect_attempts",
        );
        let reconnect_failures = lifecycle_counter_delta(
            before.reconnect_failures,
            after.reconnect_failures,
            node_index,
            "reconnect_failures",
        );
        let (_, baseline_outstanding, _) =
            connection_attempt_accounting(before).expect("accounted fault-outcome baseline");
        let terminal_bound = bound.saturating_add(baseline_outstanding);
        assert!(
            terminal <= attempts.saturating_add(baseline_outstanding),
            "fault-outcome flush violated interval connection conservation: node={node_index}, attempts={attempts}, terminal_outcomes={terminal}, baseline_outstanding={baseline_outstanding}"
        );
        assert!(
            terminal <= terminal_bound,
            "fault-outcome flush exceeded the fixed per-node connection bound plus exact baseline carry-in: node={node_index}, counter=connection_terminal_outcomes, observed={terminal}, bound={terminal_bound}, new_attempt_bound={bound}, baseline_outstanding={baseline_outstanding}"
        );
        for (counter, observed) in [
            ("connection_attempts", attempts),
            ("reconnect_attempts", reconnect_attempts),
            ("reconnect_failures", reconnect_failures),
        ] {
            assert!(
                observed <= bound,
                "fault-outcome flush exceeded the fixed per-node connection bound: node={node_index}, counter={counter}, observed={observed}, bound={bound}"
            );
        }
    }
}

fn lifecycle_active_connection_bound(member_count: usize) -> i64 {
    QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR.saturating_mul(
        i64::try_from(member_count.saturating_sub(1)).expect("bounded member count"),
    )
}

fn outbound_consensus_socket_bound(member_count: usize) -> usize {
    QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER.saturating_mul(member_count.saturating_sub(1))
}

// One retiring plus one replacement generation for every inbound two-lane
// directed peer. The listener's hard connection cap remains authoritative.
fn server_rotation_overlap_connection_bound(member_count: usize) -> usize {
    2_usize.saturating_mul(outbound_consensus_socket_bound(member_count))
}

fn process_file_descriptor_high_water_bound(
    member_count: usize,
    warmed_nontransport_file_descriptors: usize,
) -> usize {
    warmed_nontransport_file_descriptors
        .saturating_add(QUALIFICATION_INBOUND_CONNECTION_SLOTS)
        .saturating_add(outbound_consensus_socket_bound(member_count))
        .saturating_add(QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE)
}

fn lifecycle_transition_is_settled(
    metrics: &QualificationConnectionLifecycleMetrics,
    member_count: usize,
) -> bool {
    let active_bound = lifecycle_active_connection_bound(member_count);
    metrics.active_connections >= 0
        && metrics.active_connections <= active_bound
        && metrics.draining_connections == 0
        && metrics.drain_started == metrics.drain_completed
        && metrics.drain_overruns == 0
        && connection_attempts_accounted(metrics)
}

fn deadline_allows_completion(now: Instant, deadline: Instant) -> bool {
    now <= deadline
}

fn deadline_admits_complete_operation(now: Instant, deadline: Instant) -> bool {
    now.checked_add(Duration::from_millis(
        QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
    ))
    .is_some_and(|operation_deadline| operation_deadline <= deadline)
}

fn assert_transition_completed_by(started: Instant, deadline: Instant, phase: &str) {
    let now = Instant::now();
    assert!(
        deadline_allows_completion(now, deadline),
        "qualification transition exceeded its absolute fail-safe: phase={phase}, elapsed={:?}",
        now.duration_since(started)
    );
}

fn removed_root_authentication_failure_budget(member_count: usize) -> Vec<u64> {
    let mut expected = vec![0_u64; member_count];
    for source in 0..member_count {
        expected[(source + 1) % member_count] += 1;
    }
    expected
}

fn assert_campaign_lifecycle_failure_ledger(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
) {
    assert_eq!(before.len(), member_count);
    assert_eq!(after.len(), member_count);
    let expected_authentication_failures = removed_root_authentication_failure_budget(member_count);
    for (node_index, ((before, after), expected_authentication_failures)) in before
        .iter()
        .zip(after)
        .zip(&expected_authentication_failures)
        .enumerate()
    {
        assert_connection_attempts_accounted(after, node_index);
        assert!(
            lifecycle_transition_is_settled(after, member_count),
            "campaign final lifecycle state is not settled: node={node_index}, metrics={after:?}"
        );
        for (counter, before, after) in [
            (
                "connection_failure_transport",
                before.connection_failure_transport,
                after.connection_failure_transport,
            ),
            (
                "connection_failure_timeout",
                before.connection_failure_timeout,
                after.connection_failure_timeout,
            ),
            (
                "connection_abandoned",
                before.connection_abandoned,
                after.connection_abandoned,
            ),
            (
                "connection_failure_protocol",
                before.connection_failure_protocol,
                after.connection_failure_protocol,
            ),
            (
                "connection_failure_backend",
                before.connection_failure_backend,
                after.connection_failure_backend,
            ),
            (
                "reconnect_failures",
                before.reconnect_failures,
                after.reconnect_failures,
            ),
            (
                "drain_overruns",
                before.drain_overruns,
                after.drain_overruns,
            ),
        ] {
            assert_eq!(
                lifecycle_counter_delta(before, after, node_index, counter),
                0,
                "campaign-wide zero-failure ledger rejected {counter}: node={node_index}"
            );
        }
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_authentication,
                after.connection_failure_authentication,
                node_index,
                "connection_failure_authentication",
            ),
            *expected_authentication_failures,
            "campaign authentication ledger must contain exactly the deliberate removed-root ring probe: node={node_index}"
        );
    }
}

fn assert_connection_attempts_accounted(
    metrics: &QualificationConnectionLifecycleMetrics,
    node_index: usize,
) {
    let Some((terminal, outstanding, live_handlers)) = connection_attempt_accounting(metrics)
    else {
        panic!("connection accounting overflow/underflow: node={node_index}, metrics={metrics:?}");
    };
    assert_eq!(
        metrics.connection_attempts,
        terminal + outstanding,
        "connection conservation equation failed: node={node_index}"
    );
    assert!(
        outstanding <= live_handlers,
        "connection attempts lacked a terminal outcome or live handler: node={node_index}, outstanding={outstanding}, live_handlers={live_handlers}, metrics={metrics:?}"
    );
}

fn connection_attempts_accounted(metrics: &QualificationConnectionLifecycleMetrics) -> bool {
    connection_attempt_accounting(metrics)
        .is_some_and(|(_, outstanding, live_handlers)| outstanding <= live_handlers)
}

fn connection_attempt_accounting(
    metrics: &QualificationConnectionLifecycleMetrics,
) -> Option<(u64, u64, u64)> {
    let terminal = metrics
        .connection_successes
        .checked_add(metrics.connection_failure_transport)?
        .checked_add(metrics.connection_failure_authentication)?
        .checked_add(metrics.connection_failure_timeout)?
        .checked_add(metrics.connection_superseded)?
        .checked_add(metrics.connection_abandoned)?
        .checked_add(metrics.connection_failure_protocol)?
        .checked_add(metrics.connection_failure_backend)?;
    let outstanding = metrics.connection_attempts.checked_sub(terminal)?;
    let live_handlers = u64::try_from(
        metrics
            .active_connections
            .saturating_add(metrics.draining_connections)
            .max(0),
    )
    .ok()?;
    Some((terminal, outstanding, live_handlers))
}

fn assert_process_resource_bounds(
    member_count: usize,
    warmed: &[ProcessResourceSnapshot],
    high_water: &[ProcessResourceHighWater],
    settled: &[ProcessResourceSnapshot],
) {
    assert_eq!(warmed.len(), member_count);
    assert_eq!(high_water.len(), member_count);
    assert_eq!(settled.len(), member_count);
    for (node_index, ((warmed, high_water), settled)) in
        warmed.iter().zip(high_water).zip(settled).enumerate()
    {
        assert!(high_water.samples >= 1);
        let file_descriptor_bound = process_file_descriptor_high_water_bound(
            member_count,
            warmed.nontransport_file_descriptors,
        );
        assert!(
            high_water.file_descriptors <= file_descriptor_bound,
            "FD high-water bound exceeded: node={node_index}, high_water={}, bound={file_descriptor_bound}, warmed={warmed:?}",
            high_water.file_descriptors
        );
        assert!(
            settled.file_descriptors
                <= warmed
                    .file_descriptors
                    .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE),
            "settled FD bound exceeded: node={node_index}, settled={}, warmed={}",
            settled.file_descriptors,
            warmed.file_descriptors
        );
        assert!(
            settled.socket_file_descriptors
                <= warmed
                    .socket_file_descriptors
                    .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE),
            "settled socket-FD bound exceeded: node={node_index}, settled={}, warmed={}",
            settled.socket_file_descriptors,
            warmed.socket_file_descriptors
        );
        assert!(
            high_water.threads
                <= warmed
                    .threads
                    .saturating_add(QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE),
            "thread high-water bound exceeded: node={node_index}, high_water={}, warmed={}",
            high_water.threads,
            warmed.threads
        );
        assert!(
            high_water.vm_hwm_kib
                <= warmed
                    .vm_hwm_kib
                    .saturating_add(QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB),
            "VmHWM growth bound exceeded: node={node_index}, high_water_kib={}, warmed_kib={}",
            high_water.vm_hwm_kib,
            warmed.vm_hwm_kib
        );
        assert!(
            settled.vm_rss_kib
                <= warmed
                    .vm_rss_kib
                    .saturating_add(QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB),
            "settled VmRSS growth bound exceeded: node={node_index}, settled_kib={}, warmed_kib={}",
            settled.vm_rss_kib,
            warmed.vm_rss_kib
        );
    }
}

impl Issuer {
    fn root(common_name: &str) -> Self {
        let key = KeyPair::generate().expect("generate qualification root key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let certificate = parameters
            .self_signed(&key)
            .expect("sign qualification root");
        Self { certificate, key }
    }

    fn intermediate(common_name: &str, root: &Self) -> Self {
        let key = KeyPair::generate().expect("generate qualification intermediate key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let certificate = parameters
            .signed_by(&key, &root.certificate, &root.key)
            .expect("sign qualification intermediate");
        Self { certificate, key }
    }

    fn issue_workload(&self, spiffe_id: &str) -> ProjectedCredential {
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("second-aligned qualification issuance time");
        self.issue_workload_until(spiffe_id, now + time::Duration::hours(1))
    }

    fn issue_workload_until(
        &self,
        spiffe_id: &str,
        not_after: time::OffsetDateTime,
    ) -> ProjectedCredential {
        let key = KeyPair::generate().expect("generate qualification workload key");
        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "session qualification workload");
        parameters.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("valid qualification SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("second-aligned qualification issuance time");
        assert!(
            not_after > now,
            "qualification leaf must expire in the future"
        );
        parameters.not_before = now - time::Duration::hours(1);
        parameters.not_after = not_after;
        let certificate = parameters
            .signed_by(&key, &self.certificate, &self.key)
            .expect("sign qualification workload certificate");
        ProjectedCredential {
            certificate_chain_pem: certificate.pem() + &self.certificate.pem(),
            private_key_pem: key.serialize_pem(),
        }
    }
}

struct ProjectedCredential {
    certificate_chain_pem: String,
    private_key_pem: String,
}

struct MemberCredentials {
    initial: ProjectedCredential,
    renewed_leaf: ProjectedCredential,
    rotated_intermediate: ProjectedCredential,
    new_root: ProjectedCredential,
    traffic_leaves: Vec<ProjectedCredential>,
}

#[derive(Clone, Copy)]
enum CredentialGeneration {
    Initial,
    RenewedLeaf,
    RotatedIntermediate,
    NewRoot,
    TrafficLeaf(usize),
}

#[derive(Clone, Copy)]
enum TrustGeneration {
    OldOnly,
    Overlap,
    NewOnly,
}

struct TestPki {
    old_root_pem: String,
    new_root_pem: String,
    old_intermediate: Issuer,
    members: Vec<MemberCredentials>,
}

impl TestPki {
    fn new(member_count: usize) -> Self {
        let old_root = Issuer::root("session qualification old root");
        let new_root = Issuer::root("session qualification new root");
        let old_intermediate =
            Issuer::intermediate("session qualification old intermediate", &old_root);
        let rotated_intermediate =
            Issuer::intermediate("session qualification rotated intermediate", &old_root);
        let new_intermediate =
            Issuer::intermediate("session qualification new intermediate", &new_root);
        let members = (0..member_count)
            .map(|node_index| MemberCredentials {
                initial: old_intermediate.issue_workload(&spiffe_id(node_index)),
                renewed_leaf: old_intermediate.issue_workload(&spiffe_id(node_index)),
                rotated_intermediate: rotated_intermediate.issue_workload(&spiffe_id(node_index)),
                new_root: new_intermediate.issue_workload(&spiffe_id(node_index)),
                traffic_leaves: (0..QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER)
                    .map(|_| old_intermediate.issue_workload(&spiffe_id(node_index)))
                    .collect(),
            })
            .collect();
        Self {
            old_root_pem: old_root.certificate.pem(),
            new_root_pem: new_root.certificate.pem(),
            old_intermediate,
            members,
        }
    }

    fn expiring_workload(&self, node_index: usize) -> (ProjectedCredential, time::OffsetDateTime) {
        let issuance_reference = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .expect("second-aligned qualification issuance reference");
        let not_after = issuance_reference
            + time::Duration::try_from(Duration::from_millis(
                QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS,
            ))
            .expect("fault expiry validity fits time duration");
        (
            self.old_intermediate
                .issue_workload_until(&spiffe_id(node_index), not_after),
            not_after,
        )
    }

    fn credential(
        &self,
        node_index: usize,
        generation: CredentialGeneration,
    ) -> &ProjectedCredential {
        match generation {
            CredentialGeneration::Initial => &self.members[node_index].initial,
            CredentialGeneration::RenewedLeaf => &self.members[node_index].renewed_leaf,
            CredentialGeneration::RotatedIntermediate => {
                &self.members[node_index].rotated_intermediate
            }
            CredentialGeneration::NewRoot => &self.members[node_index].new_root,
            CredentialGeneration::TrafficLeaf(rotation) => self.members[node_index]
                .traffic_leaves
                .get(rotation)
                .expect("bounded traffic leaf rotation"),
        }
    }

    fn trust_bundle(&self, generation: TrustGeneration) -> String {
        match generation {
            TrustGeneration::OldOnly => self.old_root_pem.clone(),
            TrustGeneration::Overlap => self.old_root_pem.clone() + &self.new_root_pem,
            TrustGeneration::NewOnly => self.new_root_pem.clone(),
        }
    }

    fn identity_state(
        &self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
    ) -> IdentityState {
        let credential = self.credential(node_index, credential_generation);
        let trust_domain =
            TrustDomain::new("qualification.invalid").expect("qualification trust domain is valid");
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&self.trust_bundle(trust_generation))
                .expect("parse qualification trust bundle"),
        });
        build_identity_state(
            parse_certs_pem(&credential.certificate_chain_pem)
                .expect("parse qualification certificate chain"),
            parse_key_pem(&credential.private_key_pem).expect("parse qualification private key"),
            trust_bundles,
        )
        .expect("build qualification identity state")
    }
}

enum ReaderMessage {
    Reply(Box<QualificationNodeReply>),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCommandKind {
    AwaitBound,
    Configure,
    Initialize,
    Probe,
    ProjectedSourceStatus,
    MaterialStatus,
    ReauthenticationGeneration,
    RequestReauthentication,
    DirectedHandshake,
    LifecycleMetrics,
    SetConsensusRpcAvailability,
    SecurityMetrics,
    StartTrafficWatch,
    ReconcileTrafficWatch,
    StartTrafficMutation,
    StopTrafficMutation,
    StopTrafficWatch,
    TrafficStatus,
    Acquire,
    CompareAndSet,
    Get,
    Release,
    Shutdown,
}

impl PendingCommandKind {
    fn from_command(command: &QualificationNodeCommand) -> Self {
        match command {
            QualificationNodeCommand::Configure => Self::Configure,
            QualificationNodeCommand::Initialize => Self::Initialize,
            QualificationNodeCommand::Probe => Self::Probe,
            QualificationNodeCommand::ProjectedSourceStatus => Self::ProjectedSourceStatus,
            QualificationNodeCommand::MaterialStatus => Self::MaterialStatus,
            QualificationNodeCommand::ReauthenticationGeneration => {
                Self::ReauthenticationGeneration
            }
            QualificationNodeCommand::RequestReauthentication => Self::RequestReauthentication,
            QualificationNodeCommand::DirectedHandshake { .. } => Self::DirectedHandshake,
            QualificationNodeCommand::LifecycleMetrics => Self::LifecycleMetrics,
            QualificationNodeCommand::SetConsensusRpcAvailability { .. } => {
                Self::SetConsensusRpcAvailability
            }
            QualificationNodeCommand::SecurityMetrics => Self::SecurityMetrics,
            QualificationNodeCommand::StartTrafficWatch => Self::StartTrafficWatch,
            QualificationNodeCommand::ReconcileTrafficWatch => Self::ReconcileTrafficWatch,
            QualificationNodeCommand::StartTrafficMutation => Self::StartTrafficMutation,
            QualificationNodeCommand::StopTrafficMutation => Self::StopTrafficMutation,
            QualificationNodeCommand::StopTrafficWatch => Self::StopTrafficWatch,
            QualificationNodeCommand::TrafficStatus
            | QualificationNodeCommand::TrafficStatusSnapshot => Self::TrafficStatus,
            QualificationNodeCommand::Acquire { .. } => Self::Acquire,
            QualificationNodeCommand::CompareAndSet { .. } => Self::CompareAndSet,
            QualificationNodeCommand::Get { .. } => Self::Get,
            QualificationNodeCommand::Release { .. } => Self::Release,
            QualificationNodeCommand::Shutdown => Self::Shutdown,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingCommand {
    kind: PendingCommandKind,
    sequence: u64,
    sent_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCommandDiagnostic {
    kind: PendingCommandKind,
    sequence: u64,
    send_elapsed_millis: u128,
}

impl PendingCommand {
    fn diagnostic_at(self, now: Instant) -> PendingCommandDiagnostic {
        PendingCommandDiagnostic {
            kind: self.kind,
            sequence: self.sequence,
            send_elapsed_millis: now
                .checked_duration_since(self.sent_at)
                .unwrap_or_default()
                .as_millis(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildResponseFailure {
    Invalid,
    Timeout,
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildStderrDiagnostic {
    Unavailable,
    Empty,
    QualificationNodeFailed,
    QualificationNodeTransportFailed,
    QualificationNodeSqliteFailed,
    QualificationNodeConsensusFailed,
    QualificationNodeListenerFailed,
    Redacted,
}

struct ChildNode {
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    replies: Receiver<ReaderMessage>,
    reader: Option<JoinHandle<()>>,
    node_index: usize,
    stderr_path: PathBuf,
    pending: Option<PendingCommand>,
    next_command_sequence: u64,
}

impl ChildNode {
    fn spawn(config: &Path, node_index: usize, stderr: &Path) -> (Self, SocketAddr) {
        Self::spawn_bound(
            config,
            node_index,
            stderr,
            "127.0.0.1:0".parse().expect("loopback qualification bind"),
        )
    }

    fn spawn_bound(
        config: &Path,
        node_index: usize,
        stderr_path: &Path,
        bind_addr: SocketAddr,
    ) -> (Self, SocketAddr) {
        Self::spawn_bound_until(
            config,
            node_index,
            stderr_path,
            bind_addr,
            Instant::now() + CHILD_TIMEOUT,
        )
    }

    fn spawn_bound_until(
        config: &Path,
        node_index: usize,
        stderr_path: &Path,
        bind_addr: SocketAddr,
        deadline: Instant,
    ) -> (Self, SocketAddr) {
        let stderr = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(stderr_path)
            .expect("open qualification stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
            .arg("--config")
            .arg(config)
            .arg("--node-index")
            .arg(node_index.to_string())
            .arg("--bind-addr")
            .arg(bind_addr.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn mTLS qualification node");
        let stdin = child.stdin.take().expect("qualification child stdin");
        let stdout = child.stdout.take().expect("qualification child stdout");
        let (sender, replies) = mpsc::sync_channel(32);
        let reader = thread::Builder::new()
            .name(format!("qualification-mtls-node-{node_index}"))
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let message = match read_bounded_json_line(&mut stdout) {
                        Ok(Some(reply)) => ReaderMessage::Reply(Box::new(reply)),
                        Ok(None) => break,
                        Err(_) => ReaderMessage::Invalid,
                    };
                    let invalid = matches!(message, ReaderMessage::Invalid);
                    if sender.send(message).is_err() || invalid {
                        break;
                    }
                }
            })
            .expect("start qualification stdout reader");
        let mut node = Self {
            child,
            stdin: Some(BufWriter::new(stdin)),
            replies,
            reader: Some(reader),
            node_index,
            stderr_path: stderr_path.to_path_buf(),
            pending: Some(PendingCommand {
                kind: PendingCommandKind::AwaitBound,
                sequence: 0,
                sent_at: Instant::now(),
            }),
            next_command_sequence: 1,
        };
        let reply = node.receive_until(deadline);
        let QualificationNodeReply::Bound {
            node_index: actual,
            bind_addr,
        } = reply
        else {
            panic!("qualification child did not bind")
        };
        assert_eq!(actual, node_index);
        assert!(bind_addr.ip().is_loopback());
        (node, bind_addr)
    }

    fn send(&mut self, command: &QualificationNodeCommand) {
        assert!(
            self.pending.is_none(),
            "qualification child already has one pending command"
        );
        write_json_line(
            self.stdin.as_mut().expect("qualification child stdin open"),
            command,
        )
        .expect("send qualification command");
        let sequence = self.next_command_sequence;
        self.next_command_sequence = self
            .next_command_sequence
            .checked_add(1)
            .expect("qualification command sequence exhausted");
        self.pending = Some(PendingCommand {
            kind: PendingCommandKind::from_command(command),
            sequence,
            sent_at: Instant::now(),
        });
    }

    fn receive(&mut self) -> QualificationNodeReply {
        self.receive_with_timeout(CHILD_TIMEOUT)
    }

    fn receive_until(&mut self, deadline: Instant) -> QualificationNodeReply {
        self.receive_with_timeout(deadline.saturating_duration_since(Instant::now()))
    }

    fn receive_with_timeout(&mut self, timeout: Duration) -> QualificationNodeReply {
        let pending = self
            .pending
            .expect("qualification child response requested without a pending command");
        match self.replies.recv_timeout(timeout) {
            Ok(ReaderMessage::Reply(reply)) => {
                self.pending = None;
                *reply
            }
            Ok(ReaderMessage::Invalid) => {
                self.fail_response(ChildResponseFailure::Invalid, pending)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.fail_response(ChildResponseFailure::Timeout, pending)
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.fail_response(ChildResponseFailure::Eof, pending)
            }
        }
    }

    fn fail_response(&mut self, failure: ChildResponseFailure, pending: PendingCommand) -> ! {
        let pending = pending.diagnostic_at(Instant::now());
        let status = self.child.try_wait().ok().flatten();
        let stderr = self.stderr_diagnostic();
        panic!(
            "qualification child response failed: node={}, failure={failure:?}, pending={pending:?}, status={status:?}, stderr={stderr:?}",
            self.node_index
        )
    }

    fn stderr_diagnostic(&self) -> ChildStderrDiagnostic {
        const MAX_STDERR_BYTES: u64 = 8 * 1024;

        let Ok(mut file) = File::open(&self.stderr_path) else {
            return ChildStderrDiagnostic::Unavailable;
        };
        let Ok(total_bytes) = file.metadata().map(|metadata| metadata.len()) else {
            return ChildStderrDiagnostic::Unavailable;
        };
        let start = total_bytes.saturating_sub(MAX_STDERR_BYTES);
        if file.seek(SeekFrom::Start(start)).is_err() {
            return ChildStderrDiagnostic::Unavailable;
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(total_bytes.min(MAX_STDERR_BYTES)).unwrap_or(8 * 1024),
        );
        if file.take(MAX_STDERR_BYTES).read_to_end(&mut bytes).is_err() {
            return ChildStderrDiagnostic::Unavailable;
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return ChildStderrDiagnostic::Empty;
        }
        if start != 0 {
            return ChildStderrDiagnostic::Redacted;
        }
        let lines = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        let allowed = lines.iter().all(|line| {
            *line == b"qualification node failed"
                || *line == b"qualification node open failed: transport"
                || *line == b"qualification node open failed: sqlite"
                || *line == b"qualification node open failed: consensus"
                || *line == b"qualification node open failed: listener"
        });
        if !allowed {
            return ChildStderrDiagnostic::Redacted;
        }
        if lines
            .iter()
            .rev()
            .any(|line| *line == b"qualification node open failed: listener")
        {
            ChildStderrDiagnostic::QualificationNodeListenerFailed
        } else if lines
            .iter()
            .rev()
            .any(|line| *line == b"qualification node open failed: consensus")
        {
            ChildStderrDiagnostic::QualificationNodeConsensusFailed
        } else if lines
            .iter()
            .rev()
            .any(|line| *line == b"qualification node open failed: sqlite")
        {
            ChildStderrDiagnostic::QualificationNodeSqliteFailed
        } else if lines
            .iter()
            .rev()
            .any(|line| *line == b"qualification node open failed: transport")
        {
            ChildStderrDiagnostic::QualificationNodeTransportFailed
        } else {
            ChildStderrDiagnostic::QualificationNodeFailed
        }
    }

    fn invoke(&mut self, command: &QualificationNodeCommand) -> QualificationNodeReply {
        self.send(command);
        self.receive()
    }

    fn invoke_until(
        &mut self,
        command: &QualificationNodeCommand,
        deadline: Instant,
    ) -> QualificationNodeReply {
        self.send(command);
        self.receive_until(deadline)
    }

    fn process_id(&self) -> u32 {
        self.child.id()
    }

    fn kill_unclean_by(&mut self, deadline: Instant) {
        if let Some(status) = self
            .child
            .try_wait()
            .expect("inspect qualification child before deliberate restart")
        {
            panic!(
                "qualification child exited before deliberate restart: status={status}, stderr reader remains bounded"
            );
        }
        self.child.kill().expect("kill qualification child");
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll killed child") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "killed qualification child did not exit inside the restart bound"
            );
            thread::sleep(Duration::from_millis(20));
        };
        assert!(
            !status.success(),
            "uncleanly killed child exited successfully"
        );
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .expect("join killed qualification stdout reader");
        }
    }

    fn shutdown(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let reply = self.invoke(&QualificationNodeCommand::Shutdown);
            assert!(matches!(reply, QualificationNodeReply::ShuttingDown));
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join qualification stdout reader");
        }
    }
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FleetReadiness {
    node_index: usize,
    ready: bool,
    reason_code: QualificationReadinessCode,
    node_id: u64,
    term: u64,
    leader_id: Option<u64>,
    configured_voters: usize,
    fresh_reachable_voters: usize,
    agreeing_voters: usize,
    required_quorum: usize,
    committed_index: Option<u64>,
    applied_index: Option<u64>,
}

struct CandidateEvidenceInputs {
    source_revision: String,
    source_tree_status: SessionMtlsCandidateSourceTreeStatus,
    source_worktree_sha256: String,
    child_sha256: String,
    harness_sha256: String,
    configuration_sha256: String,
}

struct CandidatePublicMaterialManifest {
    hasher: Sha256,
    publication_count: u64,
}

impl CandidatePublicMaterialManifest {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"opc-session-mtls-candidate-public-material/v2\0");
        Self {
            hasher,
            publication_count: 0,
        }
    }

    fn record(
        &mut self,
        phase: &str,
        node_index: usize,
        publication_epoch: u64,
        certificate_chain_pem: &str,
        trust_bundle_pem: &str,
    ) -> io::Result<()> {
        if phase.is_empty()
            || phase.len() > 128
            || !phase
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(io::Error::other(
                "candidate public-material phase is invalid",
            ));
        }
        let node_index = u64::try_from(node_index)
            .map_err(|_| io::Error::other("candidate material node index overflow"))?;
        let phase_length = u64::try_from(phase.len())
            .map_err(|_| io::Error::other("candidate material phase length overflow"))?;
        let certificate_length = u64::try_from(certificate_chain_pem.len())
            .map_err(|_| io::Error::other("candidate certificate length overflow"))?;
        let trust_length = u64::try_from(trust_bundle_pem.len())
            .map_err(|_| io::Error::other("candidate trust length overflow"))?;
        self.publication_count = self
            .publication_count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("candidate material publication overflow"))?;
        self.hasher.update(self.publication_count.to_be_bytes());
        self.hasher.update(node_index.to_be_bytes());
        self.hasher.update(publication_epoch.to_be_bytes());
        self.hasher.update(phase_length.to_be_bytes());
        self.hasher.update(phase.as_bytes());
        self.hasher.update(certificate_length.to_be_bytes());
        self.hasher.update(certificate_chain_pem.as_bytes());
        self.hasher.update(trust_length.to_be_bytes());
        self.hasher.update(trust_bundle_pem.as_bytes());
        Ok(())
    }

    fn sha256(&self) -> io::Result<String> {
        if self.publication_count == 0 {
            return Err(io::Error::other(
                "candidate public-material manifest is empty",
            ));
        }
        let mut hasher = self.hasher.clone();
        hasher.update(b"publication-count\0");
        hasher.update(self.publication_count.to_be_bytes());
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

impl CandidateEvidenceInputs {
    fn verify_unchanged(&self, config_paths: &[PathBuf]) -> io::Result<()> {
        let source = candidate_source_provenance()?;
        let child_sha256 = candidate_sha256_file(
            Path::new(env!("CARGO_BIN_EXE_opc-session-quorum-node")),
            MAX_CANDIDATE_ARTIFACT_BYTES,
        )?;
        let harness_path = env::current_exe()
            .map_err(|_| io::Error::other("candidate harness artifact is unavailable"))?;
        let harness_sha256 = candidate_sha256_file(&harness_path, MAX_CANDIDATE_ARTIFACT_BYTES)?;
        let configuration_sha256 = candidate_configuration_sha256(config_paths)?;
        if source.0 != self.source_revision
            || source.1 != self.source_tree_status
            || source.2 != self.source_worktree_sha256
            || child_sha256 != self.child_sha256
            || harness_sha256 != self.harness_sha256
            || configuration_sha256 != self.configuration_sha256
        {
            return Err(io::Error::other(
                "candidate execution inputs changed during the campaign",
            ));
        }
        Ok(())
    }
}

struct Fleet {
    nodes: Vec<ChildNode>,
    // Keep the workspace alive until every child has been killed on panic.
    workspace: TempDir,
    config_paths: Vec<PathBuf>,
    stderr_paths: Vec<PathBuf>,
    projected_roots: Vec<PathBuf>,
    database_paths: Vec<PathBuf>,
    projected_generation: Vec<u64>,
    pki: TestPki,
    members: Vec<QualificationMember>,
    canary_generation: u64,
    canary_values: Vec<String>,
    candidate_evidence_inputs: CandidateEvidenceInputs,
    candidate_public_material_manifest: CandidatePublicMaterialManifest,
}

impl Fleet {
    fn start(member_count: usize) -> Self {
        let schedule = session_mtls_candidate_schedule_sha256(
            SessionMtlsCandidateCampaign::RotationCore,
            member_count,
        )
        .expect("supported rotation-core candidate topology");
        Self::start_with_schedule(member_count, schedule)
    }

    fn start_traffic(member_count: usize) -> Self {
        let schedule = qualification_traffic_schedule_sha256(member_count)
            .expect("supported traffic qualification topology");
        Self::start_with_schedule(member_count, schedule)
    }

    fn start_with_schedule(member_count: usize, workload_schedule_sha256: String) -> Self {
        assert!(matches!(member_count, 3 | 5));
        let (source_revision, source_tree_status, source_worktree_sha256) =
            candidate_source_provenance().expect("capture candidate source provenance");
        let child_sha256 = candidate_sha256_file(
            Path::new(env!("CARGO_BIN_EXE_opc-session-quorum-node")),
            MAX_CANDIDATE_ARTIFACT_BYTES,
        )
        .expect("hash candidate child before execution");
        let harness_path = env::current_exe().expect("locate candidate harness artifact");
        let harness_sha256 = candidate_sha256_file(&harness_path, MAX_CANDIDATE_ARTIFACT_BYTES)
            .expect("hash candidate harness before execution");
        let workspace = tempfile::tempdir().expect("create mTLS qualification workspace");
        let root = workspace.path();
        let mut configs = Vec::with_capacity(member_count);
        let mut nodes = Vec::with_capacity(member_count);
        let mut addresses = Vec::with_capacity(member_count);
        let mut stderr_paths = Vec::with_capacity(member_count);
        for node_index in 0..member_count {
            let node_root = root.join(format!("node-{node_index}"));
            fs::create_dir(&node_root).expect("create qualification node directory");
            let config = node_root.join("config.json");
            let stderr = node_root.join("stderr.log");
            let (node, address) = ChildNode::spawn(&config, node_index, &stderr);
            configs.push(config);
            nodes.push(node);
            addresses.push(address);
            stderr_paths.push(stderr);
        }

        let members = addresses
            .iter()
            .enumerate()
            .map(|(node_index, dial_addr)| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: dial_addr.port(),
                dial_addr: Some(*dial_addr),
                tls_identity: spiffe_id(node_index),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect::<Vec<_>>();
        let pki = TestPki::new(member_count);
        let mut candidate_public_material_manifest = CandidatePublicMaterialManifest::new();
        let mut projected_roots = Vec::with_capacity(member_count);
        let mut database_paths = Vec::with_capacity(member_count);
        let mut projected_generation = vec![0_u64; member_count];
        for (node_index, config_path) in configs.iter().enumerate() {
            let node_root = root.join(format!("node-{node_index}"));
            let projected_root = node_root.join("projected");
            let snapshots = node_root.join("snapshots");
            let database_path = node_root.join("session.sqlite");
            fs::create_dir(&projected_root).expect("create projected root");
            fs::create_dir(&snapshots).expect("create snapshots root");
            let initial_credential = pki.credential(node_index, CredentialGeneration::Initial);
            let initial_trust = pki.trust_bundle(TrustGeneration::OldOnly);
            candidate_public_material_manifest
                .record(
                    "initial-old-chain",
                    node_index,
                    projected_generation[node_index].saturating_add(1),
                    &initial_credential.certificate_chain_pem,
                    &initial_trust,
                )
                .expect("bind initial public certificate and trust input");
            publish_projected_generation(
                &projected_root,
                &mut projected_generation[node_index],
                initial_credential,
                &initial_trust,
            );
            let config = QualificationNodeConfig {
                schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
                node_index,
                cluster_id: format!("qualification-mtls-{member_count}-cluster"),
                configuration_generation: "v1".to_owned(),
                configuration_epoch: 1,
                backend_namespace: format!("qualification-mtls-{member_count}-cluster"),
                workload_schedule_sha256: workload_schedule_sha256.clone(),
                members: members.clone(),
                workspace_directory: root.to_path_buf(),
                database_path: database_path.clone(),
                snapshot_directory: snapshots,
                operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
                transport: QualificationTransportConfig::ProjectedMtls(
                    QualificationProjectedMtlsConfig {
                        projected_volume_root: projected_root.clone(),
                        certificate_file: PathBuf::from("tls.crt"),
                        private_key_file: PathBuf::from("tls.key"),
                        trust_bundle_files: vec![PathBuf::from("ca.crt")],
                        poll_interval_millis: duration_millis(MIN_PROJECTED_SVID_POLL_INTERVAL),
                        lifecycle: production_lifecycle_config(),
                        peer_routing: QualificationPeerRouting::PinnedLoopbackTestOnly,
                    },
                ),
            };
            config.validate().expect("valid mTLS node configuration");
            fs::write(
                config_path,
                serde_json::to_vec_pretty(&config).expect("encode node configuration"),
            )
            .expect("write node configuration");
            projected_roots.push(projected_root);
            database_paths.push(database_path);
        }
        let candidate_evidence_inputs = CandidateEvidenceInputs {
            source_revision,
            source_tree_status,
            source_worktree_sha256,
            child_sha256,
            harness_sha256,
            configuration_sha256: candidate_configuration_sha256(&configs)
                .expect("hash candidate configurations before execution"),
        };

        // Bound the process-heavy store/transport startup to one child at a
        // time. All listeners are already bound and all immutable
        // configuration/material has already been published, so serializing
        // only Configure/Started removes the startup fan-out without changing
        // the concurrent cluster-initialization proof below. One shared
        // deadline establishes one fixed fleet-wide failure bound.
        let configure_deadline = Instant::now() + CHILD_TIMEOUT;
        for (node_index, node) in nodes.iter_mut().enumerate() {
            assert!(
                Instant::now() < configure_deadline,
                "qualification fleet Configure deadline exhausted before node={node_index}"
            );
            node.send(&QualificationNodeCommand::Configure);
            assert!(matches!(
                node.receive_until(configure_deadline),
                QualificationNodeReply::Started { node_index: actual } if actual == node_index
            ));
        }
        for node in &mut nodes {
            node.send(&QualificationNodeCommand::Initialize);
        }
        for node in &mut nodes {
            assert!(matches!(
                node.receive(),
                QualificationNodeReply::Initialized
            ));
        }

        let mut fleet = Self {
            nodes,
            workspace,
            config_paths: configs,
            stderr_paths,
            projected_roots,
            database_paths,
            projected_generation,
            pki,
            members,
            canary_generation: 0,
            canary_values: Vec::new(),
            candidate_evidence_inputs,
            candidate_public_material_manifest,
        };
        fleet.wait_ready();
        fleet.assert_all_material_ready();
        assert!(matches!(
            fleet.nodes[0].invoke(&QualificationNodeCommand::DirectedHandshake {
                remote_node_index: 1,
            }),
            QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
            }
        ));
        fleet.acquire_canary_lease();
        fleet.advance_canary("initial-old-chain");
        fleet
    }

    fn member_count(&self) -> usize {
        self.nodes.len()
    }

    fn required_quorum(&self) -> usize {
        self.member_count() / 2 + 1
    }

    fn readiness_reports(&mut self, node_indices: &[usize]) -> Vec<FleetReadiness> {
        self.readiness_reports_by(node_indices, Instant::now() + CHILD_TIMEOUT)
    }

    fn readiness_reports_by(
        &mut self,
        node_indices: &[usize],
        deadline: Instant,
    ) -> Vec<FleetReadiness> {
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::Probe);
        }
        node_indices
            .iter()
            .map(
                |node_index| match self.nodes[*node_index].receive_until(deadline) {
                    QualificationNodeReply::Readiness {
                        ready,
                        reason_code,
                        node_id,
                        term,
                        leader_id,
                        configured_voters,
                        fresh_reachable_voters,
                        agreeing_voters,
                        required_quorum,
                        committed_index,
                        applied_index,
                    } => FleetReadiness {
                        node_index: *node_index,
                        ready,
                        reason_code,
                        node_id,
                        term,
                        leader_id,
                        configured_voters,
                        fresh_reachable_voters,
                        agreeing_voters,
                        required_quorum,
                        committed_index,
                        applied_index,
                    },
                    reply => panic!("unexpected readiness response: {reply:?}"),
                },
            )
            .collect()
    }

    fn stable_nonzero_follower(&mut self) -> usize {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        let all = (0..self.member_count()).collect::<Vec<_>>();
        loop {
            let reports = self.readiness_reports(&all);
            let leader = reports
                .first()
                .and_then(|report| report.leader_id)
                .filter(|leader| {
                    reports.iter().all(|report| {
                        report.ready
                            && report.reason_code == QualificationReadinessCode::Ready
                            && report.leader_id == Some(*leader)
                            && report.term == reports[0].term
                    })
                });
            if let Some(leader) = leader {
                if let Some(follower) = reports
                    .iter()
                    .find(|report| report.node_index != 0 && report.node_id != leader)
                {
                    return follower.node_index;
                }
            }
            assert!(
                Instant::now() < deadline,
                "fleet did not expose one stable nonzero follower: reports={reports:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn set_consensus_rpc_availability(
        &mut self,
        node_index: usize,
        availability: QualificationConsensusRpcAvailability,
    ) {
        assert!(matches!(
            self.nodes[node_index].invoke(
                &QualificationNodeCommand::SetConsensusRpcAvailability { availability }
            ),
            QualificationNodeReply::ConsensusRpcAvailability { availability: actual }
                if actual == availability
        ));
    }

    fn kill_node_unclean(&mut self, node_index: usize) -> (SocketAddr, u32) {
        self.kill_node_unclean_by(
            node_index,
            Instant::now()
                + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS),
        )
    }

    fn kill_node_unclean_by(&mut self, node_index: usize, deadline: Instant) -> (SocketAddr, u32) {
        let expected_address = self.members[node_index]
            .dial_addr
            .expect("projected-mTLS test route");
        let previous_process_id = self.nodes[node_index].process_id();
        self.nodes[node_index].kill_unclean_by(deadline);
        wait_for_bind_address_release_by(expected_address, deadline);
        (expected_address, previous_process_id)
    }

    fn spawn_node_at_manifest_address(
        &mut self,
        node_index: usize,
        expected_address: SocketAddr,
        previous_process_id: u32,
    ) {
        self.spawn_node_at_manifest_address_by(
            node_index,
            expected_address,
            previous_process_id,
            Instant::now() + CHILD_TIMEOUT,
        );
    }

    fn spawn_node_at_manifest_address_by(
        &mut self,
        node_index: usize,
        expected_address: SocketAddr,
        previous_process_id: u32,
        deadline: Instant,
    ) {
        let (node, actual_address) = ChildNode::spawn_bound_until(
            &self.config_paths[node_index],
            node_index,
            &self.stderr_paths[node_index],
            expected_address,
            deadline,
        );
        assert_eq!(actual_address, expected_address);
        self.nodes[node_index] = node;
        assert_ne!(self.nodes[node_index].process_id(), previous_process_id);
        self.nodes[node_index].send(&QualificationNodeCommand::Configure);
        assert!(matches!(
            self.nodes[node_index].receive_until(deadline),
            QualificationNodeReply::Started { node_index: actual } if actual == node_index
        ));
        self.nodes[node_index].send(&QualificationNodeCommand::Initialize);
        assert!(matches!(
            self.nodes[node_index].receive_until(deadline),
            QualificationNodeReply::Initialized
        ));
        self.nodes[node_index].send(&QualificationNodeCommand::SetConsensusRpcAvailability {
            availability: QualificationConsensusRpcAvailability::Available,
        });
        assert!(matches!(
            self.nodes[node_index].receive_until(deadline),
            QualificationNodeReply::ConsensusRpcAvailability {
                availability: QualificationConsensusRpcAvailability::Available,
            }
        ));
    }

    fn restart_node_at_manifest_address(&mut self, node_index: usize) {
        let all_node_indices = (0..self.member_count()).collect::<Vec<_>>();
        let survivor_indices = all_node_indices
            .iter()
            .copied()
            .filter(|candidate| *candidate != node_index)
            .collect::<Vec<_>>();
        let readiness_before = self.readiness_reports(&all_node_indices);
        let progress_before = readiness_before
            .iter()
            .map(|report| (report.committed_index, report.applied_index))
            .collect::<Vec<_>>();
        let traffic_before = self.traffic_statuses_on(&survivor_indices);
        let source_before = self.projected_status(node_index);
        let material_before = self.material_status(node_index);
        let (expected_address, previous_process_id) = self.kill_node_unclean(node_index);
        self.spawn_node_at_manifest_address(node_index, expected_address, previous_process_id);
        let source_after = self.projected_status(node_index);
        let material_after = self.material_status(node_index);
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let reports = self.readiness_reports(&all_node_indices);
            let member_count = self.member_count();
            let required_quorum = self.required_quorum();
            if reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.configured_voters == member_count
                    && report.fresh_reachable_voters == required_quorum
                    && report.agreeing_voters == required_quorum
                    && report.required_quorum == required_quorum
            }) {
                let survivor_traffic = TrafficParticipants::try_new(
                    member_count,
                    &survivor_indices,
                    &survivor_indices,
                )
                .expect("bounded restart survivor traffic participants");
                let traffic_after_readiness = self.traffic_statuses_on(&survivor_indices);
                self.wait_for_subset_traffic_progress(
                    &traffic_after_readiness,
                    &survivor_traffic,
                    "exact-address-restart-survivors-post-readiness",
                    Instant::now() + CLUSTER_TRANSITION_TIMEOUT,
                );
                return;
            }
            if Instant::now() >= deadline {
                let progress_after = reports
                    .iter()
                    .map(|report| (report.committed_index, report.applied_index))
                    .collect::<Vec<_>>();
                let traffic_after = self.traffic_statuses_on(&survivor_indices);
                let restarted_traffic =
                    self.nodes[node_index].invoke(&QualificationNodeCommand::TrafficStatus);
                let source_at_failure = self.projected_status(node_index);
                let material_at_failure = self.material_status(node_index);
                panic!(
                    "exact-address restart did not regain readiness: restarted_node={node_index}, readiness_before={readiness_before:?}, progress_before={progress_before:?}, readiness_after={reports:?}, progress_after={progress_after:?}, traffic_before={traffic_before:?}, traffic_after={traffic_after:?}, restarted_traffic={restarted_traffic:?}, source_before={source_before:?}, source_after={source_after:?}, source_at_failure={source_at_failure:?}, material_before={material_before:?}, material_after={material_after:?}, material_at_failure={material_at_failure:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn restart_active_mutator_at_manifest_address(&mut self, node_index: usize) {
        assert_eq!(
            QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_PROFILE,
            "same-disk-exact-address-active-mutator/v2"
        );
        assert_eq!(
            QUALIFICATION_TRAFFIC_SYNTHETIC_INTERRUPTION_RESTART_PROFILE,
            "committed-generation-does-not-rearm/v1"
        );
        assert_ne!(
            node_index, 0,
            "the fixed canary writer must survive restart"
        );
        let all_node_indices = (0..self.member_count()).collect::<Vec<_>>();
        let survivor_indices = all_node_indices
            .iter()
            .copied()
            .filter(|candidate| *candidate != node_index)
            .collect::<Vec<_>>();
        let survivor_traffic =
            TrafficParticipants::try_new(self.member_count(), &survivor_indices, &survivor_indices)
                .expect("bounded active-restart survivor traffic participants");
        let all_traffic =
            TrafficParticipants::try_new(self.member_count(), &all_node_indices, &all_node_indices)
                .expect("bounded active-restart full-fleet traffic participants");
        let readiness_before = self.readiness_reports(&all_node_indices);

        let pre_restart = self
            .traffic_statuses_on(&[node_index])
            .into_iter()
            .next()
            .expect("active restart traffic status");
        assert_eq!(pre_restart.status.state, QualificationTrafficState::Running);
        assert_eq!(pre_restart.status.owned_async_tasks, 2);
        assert_eq!(pre_restart.status.failure, None);
        assert_completed_traffic_cycles(&pre_restart.status);

        let restart_started_at = Instant::now();
        let restart_total_deadline = restart_started_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS);
        let termination_deadline = restart_started_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS);
        let (expected_address, previous_process_id) =
            self.kill_node_unclean_by(node_index, termination_deadline);
        let termination_completed_at = Instant::now();
        assert!(
            termination_completed_at.duration_since(restart_started_at)
                <= Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS,),
            "active-mutator process termination exceeded its stage bound"
        );
        // Sample only after SIGKILL has completed and the exact manifest
        // address is released. Every subsequent survivor delta is therefore
        // committed while the selected process is actually absent.
        let outage_deadline = termination_completed_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS);
        let survivor_before = self.traffic_statuses_on_by(&survivor_indices, outage_deadline);
        self.advance_canary_for_survivors_by(
            node_index,
            "active-mutator-restart-outage",
            outage_deadline,
        );
        let survivor_progress = self.wait_for_subset_traffic_progress_with_crashed_tail(
            &survivor_before,
            &survivor_traffic,
            "active-mutator-restart-survivor-progress",
            outage_deadline,
            Some(node_index),
        );
        assert!(
            deadline_allows_completion(Instant::now(), outage_deadline),
            "survivor progress exceeded the active-mutator outage bound"
        );

        let startup_started_at = Instant::now();
        let startup_deadline = startup_started_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS);
        self.spawn_node_at_manifest_address_by(
            node_index,
            expected_address,
            previous_process_id,
            startup_deadline,
        );
        assert!(
            deadline_allows_completion(Instant::now(), startup_deadline),
            "active-mutator replacement startup exceeded its stage bound"
        );

        let catchup_started_at = Instant::now();
        let catchup_deadline = catchup_started_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS);
        let mut last_complete_reports: Option<Vec<FleetReadiness>> = None;
        loop {
            assert!(
                deadline_admits_complete_operation(Instant::now(), catchup_deadline),
                "active-mutator restart exhausted readiness-probe admission budget: node={node_index}, total_elapsed_millis={}, catchup_elapsed_millis={}, readiness_before={readiness_before:?}, last_complete_reports={last_complete_reports:?}, stderr={:?}",
                restart_started_at.elapsed().as_millis(),
                catchup_started_at.elapsed().as_millis(),
                self.stderr_diagnostics()
            );
            let reports = self.readiness_reports_by(&all_node_indices, catchup_deadline);
            let required_quorum = self.required_quorum();
            if reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.configured_voters == self.member_count()
                    && report.fresh_reachable_voters == required_quorum
                    && report.agreeing_voters == required_quorum
                    && report.required_quorum == required_quorum
            }) {
                assert!(
                    deadline_allows_completion(Instant::now(), catchup_deadline),
                    "active-mutator all-voter readiness completed after its catch-up bound"
                );
                break;
            }
            last_complete_reports = Some(reports);
            if !deadline_allows_completion(Instant::now(), catchup_deadline) {
                panic!(
                    "active-mutator restart did not regain all-voter readiness: node={node_index}, total_elapsed_millis={}, catchup_elapsed_millis={}, readiness_before={readiness_before:?}, last_complete_reports={last_complete_reports:?}, stderr={:?}",
                    restart_started_at.elapsed().as_millis(),
                    catchup_started_at.elapsed().as_millis(),
                    self.stderr_diagnostics()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }

        let reconciliation_started_at = Instant::now();
        let reconciliation_deadline = reconciliation_started_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS);
        let reconciled = self.reconcile_traffic_watch_on_by(node_index, reconciliation_deadline);
        assert!(
            deadline_allows_completion(Instant::now(), reconciliation_deadline),
            "active-mutator journal reconciliation exceeded its stage bound"
        );
        assert_eq!(
            reconciled.status.state,
            QualificationTrafficState::WatchReady
        );
        assert!(
            reconciled.status.mutation_resume_generation >= pre_restart.status.last_generation,
            "restart lost an acknowledged committed generation"
        );
        assert!(
            reconciled.status.mutation_resume_record_fence >= pre_restart.status.last_record_fence,
            "restart regressed the committed record fence"
        );
        assert_eq!(
            reconciled.status.last_generation,
            reconciled.status.mutation_resume_generation
        );
        assert_eq!(
            reconciled.status.last_record_fence,
            reconciled.status.mutation_resume_record_fence
        );
        assert_eq!(
            reconciled.status.watch_traffic_generations[node_index],
            reconciled.status.mutation_resume_generation
        );
        for survivor in &survivor_progress {
            assert!(
                reconciled.status.watch_traffic_generations[survivor.node_index]
                    >= survivor.status.last_generation,
                "restarted watch did not catch up a survivor's outage mutation"
            );
        }

        let resume_deadline = Instant::now()
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS);
        self.start_traffic_mutations_on_by(&[node_index], resume_deadline);
        let resumed_before = self.traffic_statuses_on_by(&all_node_indices, resume_deadline);
        let resumed = self.wait_for_subset_traffic_progress(
            &resumed_before,
            &all_traffic,
            "active-mutator-restart-higher-fence-progress",
            resume_deadline,
        );
        let resumed_node = indexed_traffic_status(&resumed, node_index)
            .expect("resumed active-mutator traffic status");
        assert_eq!(
            resumed_node.mutation_resume_generation,
            reconciled.status.mutation_resume_generation
        );
        assert_eq!(
            resumed_node.mutation_resume_record_fence,
            reconciled.status.mutation_resume_record_fence
        );
        assert!(
            resumed_node.last_generation > resumed_node.mutation_resume_generation,
            "restarted mutator did not advance the exact committed generation"
        );
        assert!(
            resumed_node.last_record_fence > resumed_node.mutation_resume_record_fence,
            "restarted mutator did not write under strictly higher fencing authority"
        );
        assert_eq!(
            (
                resumed_node.availability_interruptions,
                resumed_node.availability_recoveries,
                resumed_node.max_consecutive_availability_interruptions,
            ),
            (0, 0, 0),
            "a recovered committed generation rearmed the once-per-mutator synthetic response-loss fault"
        );
        assert!(
            deadline_allows_completion(Instant::now(), resume_deadline),
            "active-mutator higher-fence resume exceeded its stage bound"
        );
        assert!(
            deadline_allows_completion(Instant::now(), restart_total_deadline),
            "active-mutator recovery exceeded its composed crash-to-resume bound"
        );
        self.verify_canary();
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        self.wait_ready_by(deadline);
    }

    fn wait_ready_by(&mut self, deadline: Instant) {
        let node_indices = (0..self.member_count()).collect::<Vec<_>>();
        loop {
            let member_count = self.member_count();
            let required_quorum = self.required_quorum();
            let reports = self.readiness_reports_by(&node_indices, deadline);
            if reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.configured_voters == member_count
                    && report.fresh_reachable_voters == required_quorum
                    && report.agreeing_voters == required_quorum
                    && report.required_quorum == required_quorum
            }) {
                assert!(
                    deadline_allows_completion(Instant::now(), deadline),
                    "mTLS fleet became ready only after its absolute deadline: reports={reports:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return;
            }
            assert!(
                deadline_allows_completion(Instant::now(), deadline),
                "mTLS fleet readiness deadline: reports={reports:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn projected_status(&mut self, node_index: usize) -> QualificationProjectedSvidStatus {
        self.projected_status_by(node_index, Instant::now() + CHILD_TIMEOUT)
    }

    fn projected_status_by(
        &mut self,
        node_index: usize,
        deadline: Instant,
    ) -> QualificationProjectedSvidStatus {
        match self.nodes[node_index]
            .invoke_until(&QualificationNodeCommand::ProjectedSourceStatus, deadline)
        {
            QualificationNodeReply::ProjectedSourceStatus { status } => status,
            reply => panic!("unexpected projected-source response: {reply:?}"),
        }
    }

    fn material_status(&mut self, node_index: usize) -> QualificationTlsMaterialStatus {
        self.material_status_by(node_index, Instant::now() + CHILD_TIMEOUT)
    }

    fn material_status_by(
        &mut self,
        node_index: usize,
        deadline: Instant,
    ) -> QualificationTlsMaterialStatus {
        match self.nodes[node_index]
            .invoke_until(&QualificationNodeCommand::MaterialStatus, deadline)
        {
            QualificationNodeReply::MaterialStatus { status } => status,
            reply => panic!("unexpected material response: {reply:?}"),
        }
    }

    fn security_metrics(&mut self, node_index: usize) -> QualificationSecurityMetricsSnapshot {
        match self.nodes[node_index].invoke(&QualificationNodeCommand::SecurityMetrics) {
            QualificationNodeReply::SecurityMetrics { metrics } => metrics,
            reply => panic!("unexpected security metrics response: {reply:?}"),
        }
    }

    fn wait_for_malformed_trust_retention(
        &mut self,
        node_index: usize,
        source_before: QualificationProjectedSvidStatus,
        controller_before: QualificationTlsMaterialStatus,
        metrics_before: QualificationSecurityMetricsSnapshot,
    ) -> QualificationSecurityMetricsSnapshot {
        let started = Instant::now();
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let source = self.projected_status(node_index);
            let controller = self.material_status(node_index);
            let metrics = self.security_metrics(node_index);
            assert_security_metrics_unsaturated(node_index, &metrics);
            assert_eq!(
                controller, controller_before,
                "malformed projected trust must never replace or perturb the active TLS epoch: node={node_index}, source={source:?}, metrics={metrics:?}, stderr={}",
                self.node_stderr(node_index)
            );
            assert_eq!(metrics.bundle_version, metrics_before.bundle_version);
            assert_eq!(
                metrics.svid_expires_seconds,
                metrics_before.svid_expires_seconds
            );
            assert_eq!(metrics.tls_material, metrics_before.tls_material);
            assert_eq!(metrics.svid, metrics_before.svid);
            assert_eq!(
                metrics.trust_bundle.success,
                metrics_before.trust_bundle.success
            );
            assert_eq!(
                metrics.trust_bundle.rejected,
                metrics_before.trust_bundle.rejected
            );
            assert_eq!(
                metrics.trust_bundle.expired,
                metrics_before.trust_bundle.expired
            );
            assert!(
                metrics.trust_bundle.retained_last_good
                    >= metrics_before.trust_bundle.retained_last_good
            );
            if source.generation == source_before.generation
                && source.availability == QualificationProjectedSvidAvailability::RetainingLastGood
                && source.reason == Some(QualificationProjectedSvidReason::MalformedTrustBundle)
                && metrics.trust_bundle.retained_last_good
                    > metrics_before.trust_bundle.retained_last_good
            {
                let elapsed_intervals =
                    started.elapsed().as_nanos() / MIN_PROJECTED_SVID_POLL_INTERVAL.as_nanos();
                let retry_bound = u64::try_from(elapsed_intervals)
                    .unwrap_or(u64::MAX)
                    .saturating_add(3);
                assert!(
                    metrics
                        .trust_bundle
                        .retained_last_good
                        .saturating_sub(metrics_before.trust_bundle.retained_last_good)
                        <= retry_bound,
                    "malformed projected generation retried faster than its configured poll bound"
                );
                return metrics;
            }
            assert!(
                Instant::now() < deadline,
                "malformed projected trust was not rejected while retaining the exact last-good epoch: node={node_index}, source_before={source_before:?}, source={source:?}, controller={controller:?}, metrics_before={metrics_before:?}, metrics={metrics:?}, stderr={}",
                self.node_stderr(node_index)
            );
            thread::sleep(MIN_PROJECTED_SVID_POLL_INTERVAL);
        }
    }

    fn wait_for_malformed_retry_to_stop(
        &mut self,
        node_index: usize,
        minimum_retained_last_good: u64,
    ) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        let stable_for = MIN_PROJECTED_SVID_POLL_INTERVAL.saturating_mul(3);
        let mut previous = self.security_metrics(node_index);
        let mut stable_since = Instant::now();
        loop {
            thread::sleep(MIN_PROJECTED_SVID_POLL_INTERVAL);
            let current = self.security_metrics(node_index);
            assert_security_metrics_unsaturated(node_index, &current);
            assert!(
                current.trust_bundle.retained_last_good >= minimum_retained_last_good,
                "malformed trust retention counter regressed"
            );
            if current.trust_bundle.retained_last_good == previous.trust_bundle.retained_last_good {
                if stable_since.elapsed() >= stable_for {
                    return;
                }
            } else {
                stable_since = Instant::now();
            }
            assert!(
                Instant::now() < deadline,
                "malformed projected generation continued retrying after valid repair: node={node_index}, previous={previous:?}, current={current:?}, stderr={}",
                self.node_stderr(node_index)
            );
            previous = current;
        }
    }

    fn wait_for_expiry_soft_retirement(
        &mut self,
        expiring_node_index: usize,
        lifecycle_before: &[QualificationConnectionLifecycleMetrics],
        not_after: time::OffsetDateTime,
    ) -> Vec<QualificationConnectionLifecycleMetrics> {
        assert_eq!(lifecycle_before.len(), self.member_count());
        let drain_window = time::Duration::try_from(DEFAULT_ROTATION_DRAIN_WINDOW)
            .expect("rotation drain window fits time duration");
        let soft_retirement_at = not_after - drain_window;
        let early_observation_at = soft_retirement_at - time::Duration::seconds(1);
        self.keep_member_directed_paths_alive_until(expiring_node_index, early_observation_at);
        loop {
            if time::OffsetDateTime::now_utc() >= soft_retirement_at {
                break;
            }
            let early = self.all_lifecycle_metrics();
            if time::OffsetDateTime::now_utc() < soft_retirement_at {
                assert_eq!(
                    early[expiring_node_index].retirement_local_leaf_expiry,
                    lifecycle_before[expiring_node_index].retirement_local_leaf_expiry,
                    "local leaf retirement began before the fixed soft deadline"
                );
                for node_index in 0..self.member_count() {
                    if node_index != expiring_node_index {
                        assert_eq!(
                            early[node_index].retirement_peer_leaf_expiry,
                            lifecycle_before[node_index].retirement_peer_leaf_expiry,
                            "peer leaf retirement began before the fixed soft deadline: node={node_index}"
                        );
                    }
                }
            }
            let remaining = duration_until_wall_time(soft_retirement_at);
            if remaining.is_zero() {
                break;
            }
            thread::sleep(remaining.min(Duration::from_millis(20)));
        }

        let deadline =
            Instant::now() + duration_until_wall_time(not_after) + Duration::from_secs(1);
        loop {
            let current = self.all_lifecycle_metrics();
            let local_retired = current[expiring_node_index].retirement_local_leaf_expiry
                > lifecycle_before[expiring_node_index].retirement_local_leaf_expiry;
            let peer_retired = current
                .iter()
                .enumerate()
                .filter(|(node_index, _)| *node_index != expiring_node_index)
                .all(|(node_index, metrics)| {
                    metrics.retirement_peer_leaf_expiry
                        > lifecycle_before[node_index].retirement_peer_leaf_expiry
                });
            for (node_index, (before, after)) in lifecycle_before.iter().zip(&current).enumerate() {
                assert_eq!(
                    after.drain_overruns, before.drain_overruns,
                    "leaf-expiry soft retirement overran its hard deadline: node={node_index}"
                );
            }
            if local_retired && peer_retired {
                return current;
            }
            assert!(
                Instant::now() <= deadline,
                "short-lived SVID connections did not begin local/peer retirement by expiry: expiring_node={expiring_node_index}, before={lifecycle_before:?}, current={current:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_expired_member_state(
        &mut self,
        expiring_node_index: usize,
        expected_source_generation: u64,
        expected_material_epoch: u64,
        security_before: QualificationSecurityMetricsSnapshot,
        lifecycle_before: &[QualificationConnectionLifecycleMetrics],
        not_after: time::OffsetDateTime,
    ) -> (
        QualificationSecurityMetricsSnapshot,
        QualificationConnectionLifecycleMetrics,
    ) {
        let deadline =
            Instant::now() + duration_until_wall_time(not_after) + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let source = self.projected_status(expiring_node_index);
            let controller = self.material_status(expiring_node_index);
            let security = self.security_metrics(expiring_node_index);
            let lifecycle_by_node = self.all_lifecycle_metrics();
            let lifecycle = lifecycle_by_node[expiring_node_index];
            assert_security_metrics_unsaturated(expiring_node_index, &security);
            assert!(
                security.svid.expired <= security_before.svid.expired.saturating_add(1),
                "one accepted projected publication must emit at most one SVID expiry outcome"
            );
            for (node_index, (before, after)) in
                lifecycle_before.iter().zip(&lifecycle_by_node).enumerate()
            {
                assert_eq!(
                    after.drain_overruns, before.drain_overruns,
                    "leaf expiry exceeded the connection hard-drain deadline: node={node_index}"
                );
            }
            let source_expired = source.generation == expected_source_generation
                && source.availability == QualificationProjectedSvidAvailability::Unavailable
                && source.reason == Some(QualificationProjectedSvidReason::LastGoodExpired);
            let controller_expired = controller.epoch == expected_material_epoch
                && controller.availability == QualificationTlsMaterialAvailability::Unavailable
                && controller.reason == Some(QualificationTlsMaterialReason::LastGoodExpired)
                && controller.leaf_expires_at.is_none()
                && controller.certificate_chain_expires_at.is_none();
            let security_expired = security.svid_expires_seconds == 0
                && security.bundle_version == expected_material_epoch
                && security.svid.expired == security_before.svid.expired.saturating_add(1);
            let every_survivor_observed_peer_retirement = lifecycle_by_node
                .iter()
                .enumerate()
                .filter(|(node_index, _)| *node_index != expiring_node_index)
                .all(|(node_index, metrics)| {
                    metrics.retirement_peer_leaf_expiry
                        > lifecycle_before[node_index].retirement_peer_leaf_expiry
                });
            let every_drain_completed = lifecycle_by_node.iter().all(|metrics| {
                metrics.draining_connections == 0
                    && metrics.drain_started == metrics.drain_completed
            });
            let connections_drained = lifecycle.active_connections == 0
                && every_survivor_observed_peer_retirement
                && every_drain_completed;
            if source_expired && controller_expired && security_expired && connections_drained {
                return (security, lifecycle);
            }
            assert!(
                Instant::now() < deadline,
                "accepted short-lived SVID did not become unavailable and fully drain every affected endpoint inside the hard bound: node={expiring_node_index}, source={source:?}, controller={controller:?}, security={security:?}, lifecycle={lifecycle_by_node:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_isolated_member_and_survivors(
        &mut self,
        isolated_node_index: usize,
    ) -> Vec<FleetReadiness> {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        let survivors = (0..self.member_count())
            .filter(|node_index| *node_index != isolated_node_index)
            .collect::<Vec<_>>();
        loop {
            let isolated = self.readiness_reports(&[isolated_node_index]);
            let survivor_reports = self.readiness_reports(&survivors);
            let required_quorum = self.required_quorum();
            let configured_voters = self.member_count();
            let isolated_ready = isolated.iter().all(|report| {
                !report.ready
                    && report.reason_code == QualificationReadinessCode::NoQuorum
                    && report.configured_voters == configured_voters
                    && report.fresh_reachable_voters == 0
                    && report.agreeing_voters == 0
                    && report.required_quorum == required_quorum
            });
            let survivors_ready = survivor_reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.configured_voters == configured_voters
                    && report.fresh_reachable_voters == required_quorum
                    && report.agreeing_voters == required_quorum
                    && report.required_quorum == required_quorum
            });
            if isolated_ready && survivors_ready {
                return survivor_reports;
            }
            assert!(
                Instant::now() < deadline,
                "consensus RPC fault did not yield isolated/survivor readiness: isolated={isolated:?}, survivors={survivor_reports:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn lifecycle_metrics(&mut self, node_index: usize) -> QualificationConnectionLifecycleMetrics {
        match self.nodes[node_index].invoke(&QualificationNodeCommand::LifecycleMetrics) {
            QualificationNodeReply::LifecycleMetrics { metrics } => metrics,
            reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
        }
    }

    fn all_lifecycle_metrics(&mut self) -> Vec<QualificationConnectionLifecycleMetrics> {
        self.all_lifecycle_metrics_by(Instant::now() + CHILD_TIMEOUT)
    }

    fn all_lifecycle_metrics_by(
        &mut self,
        deadline: Instant,
    ) -> Vec<QualificationConnectionLifecycleMetrics> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::LifecycleMetrics);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive_until(deadline) {
                QualificationNodeReply::LifecycleMetrics { metrics } => metrics,
                reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
            })
            .collect()
    }

    fn wait_for_recovery_fault_outcomes_to_settle(
        &mut self,
        context: RecoveryFaultSettlementContext<'_>,
    ) -> (
        Vec<QualificationConnectionLifecycleMetrics>,
        Vec<IndexedTrafficStatus>,
    ) {
        let RecoveryFaultSettlementContext {
            before,
            participants,
            phase,
            started,
            deadline,
            traffic_before,
            mut traffic_progress,
        } = context;
        assert_eq!(before.len(), self.member_count());
        assert_eq!(participants.member_count, self.member_count());
        assert!(traffic_status_snapshot_matches(
            traffic_before,
            participants,
        ));
        assert!(subset_traffic_availability_is_settled(
            traffic_before,
            participants,
        ));
        assert!(traffic_status_snapshot_matches(
            &traffic_progress.pulse_checkpoint,
            participants,
        ));
        assert!(traffic_status_snapshot_matches(
            &traffic_progress.coverage_checkpoint,
            participants,
        ));
        assert_eq!(
            deadline.duration_since(started),
            Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS,),
        );
        let server_tail_window = recovery_fault_server_tail_window();
        let server_tail_deadline = started + server_tail_window;
        let outbound_quiet_window = recovery_fault_outbound_quiet_window();
        let mut stable_traffic_checkpoint = traffic_progress.pulse_checkpoint.clone();
        let mut traffic_progressed_since_stable = false;
        let mut lifecycle = self.all_lifecycle_metrics_by(traffic_progress.next_deadline(deadline));
        let mut stable_ledger = connection_attempt_settlement_ledgers(&lifecycle);
        let observed_at = Instant::now();
        let mut stable_since = observed_at;
        let mut server_tail_entered = observed_at >= server_tail_deadline;
        let node_indices = (0..self.member_count()).collect::<Vec<_>>();

        loop {
            let traffic = self.traffic_status_snapshots_on_by(
                &participants.observers,
                traffic_progress.next_deadline(deadline),
            );
            let traffic_observed_at = Instant::now();
            for indexed in &traffic {
                assert_ne!(
                    indexed.status.state,
                    QualificationTrafficState::Failed,
                    "survivor traffic failed while flushing fault-era connection outcomes: phase={phase}, node={}, status={:?}, stderr={:?}",
                    indexed.node_index,
                    indexed.status,
                    self.stderr_diagnostics()
                );
                assert_eq!(
                    indexed.status.failure,
                    None,
                    "survivor traffic recorded a terminal failure while flushing fault-era connection outcomes: phase={phase}, node={}, status={:?}, stderr={:?}",
                    indexed.node_index,
                    indexed.status,
                    self.stderr_diagnostics()
                );
            }
            assert!(
                subset_traffic_availability_within_recovery_budget(
                    traffic_before,
                    &traffic,
                    participants,
                ),
                "survivor availability exceeded the recovered-member interruption budget while flushing fault-era connection outcomes: phase={phase}, before={traffic_before:?}, current={traffic:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            let traffic_progressed = recovery_traffic_has_common_key_pulse(
                &traffic_progress.pulse_checkpoint,
                &traffic,
                participants,
            );
            let traffic_coverage_progressed = recovery_traffic_has_all_key_coverage(
                &traffic_progress.coverage_checkpoint,
                &traffic,
                participants,
            );
            let availability_changed_since_progress = subset_traffic_availability_changed_since(
                &traffic_progress.pulse_checkpoint,
                &traffic,
                participants,
            );
            if availability_changed_since_progress {
                traffic_progress.extend_pulse_for_availability_recovery();
            }
            let progress_observation_millis = if traffic_progress.pulse_recovery_extended {
                QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
            } else {
                QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS
            };
            assert!(
                traffic_observed_at.duration_since(traffic_progress.pulse_observed_at)
                    <= Duration::from_millis(progress_observation_millis),
                "survivor traffic snapshot crossed its common-key pulse deadline during the fault-outcome flush: phase={phase}, stalled_for={:?}, traffic={traffic:?}, stderr={:?}",
                traffic_observed_at.duration_since(traffic_progress.pulse_observed_at),
                self.stderr_diagnostics()
            );
            assert!(
                traffic_observed_at.duration_since(traffic_progress.coverage_observed_at)
                    <= Duration::from_millis(
                        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,
                    ),
                "survivor traffic snapshot crossed its all-active-key coverage deadline during the fault-outcome flush: phase={phase}, stalled_for={:?}, traffic={traffic:?}, stderr={:?}",
                traffic_observed_at.duration_since(traffic_progress.coverage_observed_at),
                self.stderr_diagnostics()
            );
            if traffic_progressed {
                traffic_progress.record_pulse(traffic.clone(), traffic_observed_at);
            }
            if traffic_coverage_progressed {
                traffic_progress.record_coverage(traffic.clone(), traffic_observed_at);
            }

            let member_count = self.member_count();
            let required_quorum = self.required_quorum();
            let readiness_deadline = self.recovery_readiness_probe_deadline(
                traffic_before,
                &mut traffic_progress,
                participants,
                phase,
                deadline,
            );
            let readiness = self.readiness_reports_by(&node_indices, readiness_deadline);
            assert!(
                readiness.iter().all(|report| {
                    report.ready
                        && report.reason_code == QualificationReadinessCode::Ready
                        && report.configured_voters == member_count
                        && report.fresh_reachable_voters == required_quorum
                        && report.agreeing_voters == required_quorum
                        && report.required_quorum == required_quorum
                }),
                "fleet readiness regressed while flushing fault-era connection outcomes: phase={phase}, readiness={readiness:?}, stderr={:?}",
                self.stderr_diagnostics()
            );

            lifecycle = self.all_lifecycle_metrics_by(traffic_progress.next_deadline(deadline));
            for (node_index, (fault_before, current)) in before.iter().zip(&lifecycle).enumerate() {
                assert!(
                    recovery_fault_flush_has_no_unsafe_outcomes(fault_before, current),
                    "fault-outcome flush recorded protocol, backend, or drain-overrun evidence: phase={phase}, node={node_index}, before={fault_before:?}, current={current:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
            }

            let current_ledger = connection_attempt_settlement_ledgers(&lifecycle);
            let now = Instant::now();
            if !server_tail_entered && now >= server_tail_deadline {
                server_tail_entered = true;
                stable_traffic_checkpoint = traffic.clone();
                traffic_progressed_since_stable = false;
            }
            if current_ledger != stable_ledger {
                stable_ledger = current_ledger;
                stable_since = now;
                stable_traffic_checkpoint = traffic.clone();
                traffic_progressed_since_stable = false;
            } else if subset_traffic_made_semantic_progress_with_crashed_tail(
                &stable_traffic_checkpoint,
                &traffic,
                participants,
                None,
            ) {
                traffic_progressed_since_stable = true;
            }
            let progress_observation_millis = if traffic_progress.pulse_recovery_extended {
                QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS
            } else {
                QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS
            };
            assert!(
                now.duration_since(traffic_progress.pulse_observed_at)
                    <= Duration::from_millis(progress_observation_millis),
                "survivor traffic stopped producing bounded common-key pulses during the fault-outcome flush: phase={phase}, stalled_for={:?}, traffic={traffic:?}, stderr={:?}",
                now.duration_since(traffic_progress.pulse_observed_at),
                self.stderr_diagnostics()
            );
            assert!(
                now.duration_since(traffic_progress.coverage_observed_at)
                    <= Duration::from_millis(
                        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,
                    ),
                "survivor traffic stopped covering every active key during the fault-outcome flush: phase={phase}, stalled_for={:?}, traffic={traffic:?}, stderr={:?}",
                now.duration_since(traffic_progress.coverage_observed_at),
                self.stderr_diagnostics()
            );
            let lifecycle_settled = lifecycle
                .iter()
                .all(|metrics| lifecycle_transition_is_settled(metrics, self.member_count()));
            let traffic_settled = subset_traffic_availability_is_settled(&traffic, participants);
            let outbound_stable_for = now
                .checked_duration_since(stable_since.max(server_tail_deadline))
                .unwrap_or(Duration::ZERO);
            if lifecycle_settled
                && traffic_settled
                && traffic_progressed_since_stable
                && outbound_stable_for >= outbound_quiet_window
            {
                assert!(
                    deadline_allows_completion(now, deadline),
                    "fault-era connection outcomes settled only after the absolute recovery-baseline deadline: phase={phase}, elapsed={:?}, deadline={:?}, lifecycle={lifecycle:?}, stderr={:?}",
                    now.duration_since(started),
                    Duration::from_millis(
                        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS,
                    ),
                    self.stderr_diagnostics()
                );
                assert_recovery_fault_flush_bounds(self.member_count(), before, &lifecycle);
                return (lifecycle, traffic);
            }
            assert!(
                deadline_allows_completion(now, deadline),
                "fault-era connection outcomes did not settle before the recovery baseline: phase={phase}, server_tail_window={server_tail_window:?}, outbound_quiet_window={outbound_quiet_window:?}, elapsed={:?}, outbound_stable_for={outbound_stable_for:?}, readiness={readiness:?}, traffic={traffic:?}, lifecycle={lifecycle:?}, stderr={:?}",
                now.duration_since(started),
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_for_round_lifecycle_completion(
        &mut self,
        before: &[QualificationConnectionLifecycleMetrics],
        deadline: Instant,
        phase: &str,
    ) -> Vec<QualificationConnectionLifecycleMetrics> {
        let expected_authentication_failures = vec![0; self.member_count()];
        self.wait_for_lifecycle_completion_with_authentication(
            before,
            deadline,
            phase,
            &expected_authentication_failures,
        )
    }

    fn wait_for_lifecycle_completion_with_authentication(
        &mut self,
        before: &[QualificationConnectionLifecycleMetrics],
        deadline: Instant,
        phase: &str,
        expected_authentication_failures: &[u64],
    ) -> Vec<QualificationConnectionLifecycleMetrics> {
        assert_eq!(before.len(), self.member_count());
        assert_eq!(expected_authentication_failures.len(), self.member_count());
        loop {
            let after = self.all_lifecycle_metrics();
            let unexpected_failure = before
                .iter()
                .zip(&after)
                .zip(expected_authentication_failures)
                .any(|((before, after), expected_authentication_failures)| {
                    after.connection_failure_transport > before.connection_failure_transport
                        || after.connection_failure_authentication
                            > before
                                .connection_failure_authentication
                                .saturating_add(*expected_authentication_failures)
                        || after.connection_failure_timeout > before.connection_failure_timeout
                        || after.connection_abandoned > before.connection_abandoned
                        || after.connection_failure_protocol > before.connection_failure_protocol
                        || after.connection_failure_backend > before.connection_failure_backend
                        || after.reconnect_failures > before.reconnect_failures
                        || after.drain_overruns > before.drain_overruns
                });
            let authentication_ledger_reached = before
                .iter()
                .zip(&after)
                .zip(expected_authentication_failures)
                .all(|((before, after), expected_authentication_failures)| {
                    after.connection_failure_authentication
                        == before
                            .connection_failure_authentication
                            .saturating_add(*expected_authentication_failures)
                });
            let completed = authentication_ledger_reached
                && after
                    .iter()
                    .all(|metrics| lifecycle_transition_is_settled(metrics, self.member_count()));
            let now = Instant::now();
            if completed || unexpected_failure {
                assert!(
                    deadline_allows_completion(now, deadline),
                    "connection lifecycle completed only after the absolute transition deadline: phase={phase}, before={before:?}, after={after:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return after;
            }
            assert!(
                deadline_allows_completion(now, deadline),
                "connection handlers did not complete inside the transition fail-safe: phase={phase}, before={before:?}, after={after:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn all_traffic_statuses(&mut self) -> Vec<QualificationTrafficStatus> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::TrafficStatus);
        }
        self.nodes
            .iter_mut()
            .map(|node| {
                let status = match node.receive() {
                    QualificationNodeReply::TrafficStatus { status } => status,
                    reply => panic!("unexpected traffic status response: {reply:?}"),
                };
                assert!(traffic_failure_fields_are_coherent(&status));
                status
            })
            .collect()
    }

    fn traffic_statuses_on(&mut self, node_indices: &[usize]) -> Vec<IndexedTrafficStatus> {
        self.traffic_statuses_on_by(node_indices, Instant::now() + CHILD_TIMEOUT)
    }

    fn traffic_statuses_on_by(
        &mut self,
        node_indices: &[usize],
        deadline: Instant,
    ) -> Vec<IndexedTrafficStatus> {
        validate_traffic_indices(
            self.member_count(),
            node_indices,
            TrafficParticipantError::EmptyObservers,
        )
        .expect("valid bounded traffic status participants");
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::TrafficStatus);
        }
        node_indices
            .iter()
            .map(|node_index| {
                let status = match self.nodes[*node_index].receive_until(deadline) {
                    QualificationNodeReply::TrafficStatus { status } => status,
                    reply => panic!(
                        "traffic status unavailable: node={node_index}, reply={reply:?}, stderr={}",
                        self.node_stderr(*node_index)
                    ),
                };
                assert!(
                    traffic_failure_fields_are_coherent(&status),
                    "traffic failure fields are incoherent: node={node_index}, status={status:?}"
                );
                IndexedTrafficStatus {
                    node_index: *node_index,
                    status,
                }
            })
            .collect()
    }

    fn traffic_status_snapshots_on(&mut self, node_indices: &[usize]) -> Vec<IndexedTrafficStatus> {
        self.traffic_status_snapshots_on_by(node_indices, Instant::now() + CHILD_TIMEOUT)
    }

    fn traffic_status_snapshots_on_by(
        &mut self,
        node_indices: &[usize],
        deadline: Instant,
    ) -> Vec<IndexedTrafficStatus> {
        validate_traffic_indices(
            self.member_count(),
            node_indices,
            TrafficParticipantError::EmptyObservers,
        )
        .expect("valid bounded traffic snapshot participants");
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::TrafficStatusSnapshot);
        }
        node_indices
            .iter()
            .map(|node_index| {
                let status = match self.nodes[*node_index].receive_until(deadline) {
                    QualificationNodeReply::TrafficStatus { status } => status,
                    reply => panic!(
                        "traffic status snapshot unavailable: node={node_index}, reply={reply:?}, stderr={}",
                        self.node_stderr(*node_index)
                    ),
                };
                assert!(
                    traffic_failure_fields_are_coherent(&status),
                    "traffic snapshot failure fields are incoherent: node={node_index}, status={status:?}"
                );
                IndexedTrafficStatus {
                    node_index: *node_index,
                    status,
                }
            })
            .collect()
    }

    fn start_traffic_watches_on(&mut self, node_indices: &[usize]) -> Vec<IndexedTrafficStatus> {
        validate_traffic_indices(
            self.member_count(),
            node_indices,
            TrafficParticipantError::EmptyObservers,
        )
        .expect("valid bounded traffic watch participants");
        let member_count = self.member_count();
        let seed = qualification_traffic_seed(member_count)
            .expect("supported traffic qualification topology");
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::StartTrafficWatch);
        }
        node_indices
            .iter()
            .map(|node_index| {
                let status = match self.nodes[*node_index].receive() {
                    QualificationNodeReply::TrafficStatus { status } => status,
                    reply => panic!(
                        "traffic watch did not start: node={node_index}, reply={reply:?}, stderr={}",
                        self.node_stderr(*node_index)
                    ),
                };
                assert_eq!(status.state, QualificationTrafficState::WatchReady);
                assert_eq!(status.failure, None);
                assert_eq!(status.seed, seed);
                assert_eq!(status.owned_async_tasks, 1);
                assert_eq!(status.watch_traffic_generations.len(), member_count);
                IndexedTrafficStatus {
                    node_index: *node_index,
                    status,
                }
            })
            .collect()
    }

    fn reconcile_traffic_watch_on(&mut self, node_index: usize) -> IndexedTrafficStatus {
        self.reconcile_traffic_watch_on_by(node_index, Instant::now() + CHILD_TIMEOUT)
    }

    fn reconcile_traffic_watch_on_by(
        &mut self,
        node_index: usize,
        deadline: Instant,
    ) -> IndexedTrafficStatus {
        assert!(node_index < self.member_count());
        let member_count = self.member_count();
        let seed = qualification_traffic_seed(member_count)
            .expect("supported traffic qualification topology");
        self.nodes[node_index].send(&QualificationNodeCommand::ReconcileTrafficWatch);
        let status = match self.nodes[node_index].receive_until(deadline) {
            QualificationNodeReply::TrafficStatus { status } => status,
            reply => panic!(
                "traffic watch restore handoff failed: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        };
        assert!(matches!(
            status.state,
            QualificationTrafficState::WatchReady | QualificationTrafficState::MutationStopped
        ));
        assert_eq!(status.failure, None);
        assert_eq!(status.seed, seed);
        assert_eq!(status.owned_async_tasks, 1);
        assert!(status.watch_reconciliations >= 1);
        assert!(status.watch_reconciled_sequence <= status.watch_sequence);
        assert!(status.watch_reconciled_sequence <= status.replication_head);
        assert_eq!(status.watch_traffic_generations.len(), member_count);
        IndexedTrafficStatus { node_index, status }
    }

    fn start_traffic_mutations_on(&mut self, node_indices: &[usize]) {
        self.start_traffic_mutations_on_by(node_indices, Instant::now() + CHILD_TIMEOUT);
    }

    fn start_traffic_mutations_on_by(&mut self, node_indices: &[usize], deadline: Instant) {
        validate_traffic_indices(
            self.member_count(),
            node_indices,
            TrafficParticipantError::EmptyMutators,
        )
        .expect("valid bounded traffic mutator participants");
        let seed = qualification_traffic_seed(self.member_count())
            .expect("supported traffic qualification topology");
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::StartTrafficMutation);
        }
        for node_index in node_indices {
            match self.nodes[*node_index].receive_until(deadline) {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::Running);
                    assert_eq!(status.failure, None);
                    assert!(traffic_failure_fields_are_coherent(&status));
                    assert_eq!(status.seed, seed);
                    assert_eq!(status.owned_async_tasks, 2);
                }
                reply => panic!(
                    "traffic mutation did not start: node={node_index}, reply={reply:?}, stderr={}",
                    self.node_stderr(*node_index)
                ),
            }
        }
    }

    fn start_subset_traffic_tasks(
        &mut self,
        participants: &TrafficParticipants,
        phase: &str,
    ) -> Vec<IndexedTrafficStatus> {
        assert_eq!(participants.member_count, self.member_count());
        let before = self.start_traffic_watches_on(&participants.observers);
        self.start_traffic_mutations_on(&participants.mutators);
        self.wait_for_subset_traffic_progress(
            &before,
            participants,
            phase,
            Instant::now() + CLUSTER_TRANSITION_TIMEOUT,
        )
    }

    fn wait_for_subset_traffic_progress(
        &mut self,
        before: &[IndexedTrafficStatus],
        participants: &TrafficParticipants,
        phase: &str,
        deadline: Instant,
    ) -> Vec<IndexedTrafficStatus> {
        self.wait_for_subset_traffic_progress_with_crashed_tail(
            before,
            participants,
            phase,
            deadline,
            None,
        )
    }

    fn wait_for_recovery_traffic_progress(
        &mut self,
        availability_baseline: &[IndexedTrafficStatus],
        progress: &mut RecoveryTrafficProgressTracker,
        participants: &TrafficParticipants,
        phase: &str,
        absolute_deadline: Instant,
    ) {
        assert_eq!(participants.member_count, self.member_count());
        assert!(traffic_status_snapshot_matches(
            availability_baseline,
            participants,
        ));
        assert!(subset_traffic_availability_is_settled(
            availability_baseline,
            participants,
        ));
        assert!(traffic_status_snapshot_matches(
            &progress.pulse_checkpoint,
            participants,
        ));
        assert!(traffic_status_snapshot_matches(
            &progress.coverage_checkpoint,
            participants,
        ));
        loop {
            let traffic = self.traffic_status_snapshots_on_by(
                &participants.observers,
                progress.next_deadline(absolute_deadline),
            );
            let traffic_observed_at = Instant::now();
            for indexed in &traffic {
                assert_ne!(
                    indexed.status.state,
                    QualificationTrafficState::Failed,
                    "survivor traffic failed during recovered-member continuity proof: phase={phase}, node={}, status={:?}, stderr={:?}",
                    indexed.node_index,
                    indexed.status,
                    self.stderr_diagnostics()
                );
                assert_eq!(
                    indexed.status.failure,
                    None,
                    "survivor traffic recorded a terminal failure during recovered-member continuity proof: phase={phase}, node={}, status={:?}, stderr={:?}",
                    indexed.node_index,
                    indexed.status,
                    self.stderr_diagnostics()
                );
            }
            assert!(
                subset_traffic_availability_within_recovery_budget(
                    availability_baseline,
                    &traffic,
                    participants,
                ),
                "survivor availability exceeded the recovered-member interruption budget during continuity proof: phase={phase}, baseline={availability_baseline:?}, current={traffic:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            if subset_traffic_availability_changed_since(
                &progress.pulse_checkpoint,
                &traffic,
                participants,
            ) {
                progress.extend_pulse_for_availability_recovery();
            }
            let pulse_deadline = progress.pulse_deadline().min(absolute_deadline);
            let coverage_deadline = progress.coverage_deadline();
            let coverage_progressed = recovery_traffic_has_all_key_coverage(
                &progress.coverage_checkpoint,
                &traffic,
                participants,
            );
            let pulse_progressed = recovery_traffic_has_common_key_pulse(
                &progress.pulse_checkpoint,
                &traffic,
                participants,
            );

            assert!(
                deadline_allows_completion(traffic_observed_at, absolute_deadline),
                "survivor traffic observation crossed the absolute recovered-member deadline: phase={phase}, current={traffic:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            if coverage_progressed {
                assert!(
                    deadline_allows_completion(traffic_observed_at, coverage_deadline),
                    "survivor traffic covered every active key only after its rolling recovery deadline: phase={phase}, elapsed_since_coverage={:?}, current={traffic:?}, stderr={:?}",
                    traffic_observed_at.duration_since(progress.coverage_observed_at),
                    self.stderr_diagnostics()
                );
                progress.record_coverage(traffic.clone(), traffic_observed_at);
            } else {
                assert!(
                    deadline_allows_completion(traffic_observed_at, coverage_deadline),
                    "survivor traffic did not cover every active key before its independent recovery deadline: phase={phase}, elapsed_since_coverage={:?}, checkpoint={:?}, current={traffic:?}, stderr={:?}",
                    traffic_observed_at.duration_since(progress.coverage_observed_at),
                    progress.coverage_checkpoint,
                    self.stderr_diagnostics()
                );
            }
            if pulse_progressed {
                assert!(
                    deadline_allows_completion(traffic_observed_at, pulse_deadline),
                    "survivor traffic produced a common-key pulse only after its rolling recovery deadline: phase={phase}, elapsed_since_pulse={:?}, current={traffic:?}, stderr={:?}",
                    traffic_observed_at.duration_since(progress.pulse_observed_at),
                    self.stderr_diagnostics()
                );
                // `now` is the observation boundary, not an inferred event
                // timestamp. Requiring one common committed key on every
                // observer in each half-SLO bounds the actual pulse gap by the
                // full SLO. The independent coverage checkpoint above stops a
                // fast key from masking another active survivor key.
                progress.record_pulse(traffic, traffic_observed_at);
                return;
            }
            assert!(
                deadline_allows_completion(traffic_observed_at, pulse_deadline),
                "survivor traffic did not produce a common-key pulse before its rolling recovery deadline: phase={phase}, elapsed_since_pulse={:?}, baseline={availability_baseline:?}, checkpoint={:?}, current={traffic:?}, stderr={:?}",
                traffic_observed_at.duration_since(progress.pulse_observed_at),
                progress.pulse_checkpoint,
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn recovery_readiness_probe_deadline(
        &mut self,
        availability_baseline: &[IndexedTrafficStatus],
        progress: &mut RecoveryTrafficProgressTracker,
        participants: &TrafficParticipants,
        phase: &str,
        absolute_deadline: Instant,
    ) -> Instant {
        loop {
            let now = Instant::now();
            assert!(
                deadline_admits_complete_operation(now, absolute_deadline),
                "recovered-member readiness exhausted its absolute operation budget: phase={phase}, stderr={:?}",
                self.stderr_diagnostics()
            );
            let probe_deadline = progress.next_deadline(absolute_deadline);
            if deadline_admits_complete_operation(now, probe_deadline) {
                return probe_deadline;
            }
            self.wait_for_recovery_traffic_progress(
                availability_baseline,
                progress,
                participants,
                phase,
                absolute_deadline,
            );
        }
    }

    fn wait_for_recovery_readiness(
        &mut self,
        availability_baseline: &[IndexedTrafficStatus],
        progress: &mut RecoveryTrafficProgressTracker,
        participants: &TrafficParticipants,
        phase: &str,
        absolute_deadline: Instant,
    ) {
        let node_indices = (0..self.member_count()).collect::<Vec<_>>();
        loop {
            let member_count = self.member_count();
            let required_quorum = self.required_quorum();
            let probe_deadline = self.recovery_readiness_probe_deadline(
                availability_baseline,
                progress,
                participants,
                phase,
                absolute_deadline,
            );
            let reports = self.readiness_reports_by(&node_indices, probe_deadline);
            if reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.configured_voters == member_count
                    && report.fresh_reachable_voters == required_quorum
                    && report.agreeing_voters == required_quorum
                    && report.required_quorum == required_quorum
            }) {
                assert!(
                    deadline_allows_completion(Instant::now(), probe_deadline),
                    "recovered-member readiness completed after its admitted operation deadline: phase={phase}, reports={reports:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return;
            }
            assert!(
                deadline_allows_completion(Instant::now(), absolute_deadline),
                "recovered-member readiness crossed its absolute deadline: phase={phase}, reports={reports:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            self.wait_for_recovery_traffic_progress(
                availability_baseline,
                progress,
                participants,
                phase,
                absolute_deadline,
            );
        }
    }

    fn wait_for_subset_traffic_progress_with_crashed_tail(
        &mut self,
        before: &[IndexedTrafficStatus],
        participants: &TrafficParticipants,
        phase: &str,
        deadline: Instant,
        crashed_node_index: Option<usize>,
    ) -> Vec<IndexedTrafficStatus> {
        assert_eq!(participants.member_count, self.member_count());
        assert!(traffic_status_snapshot_matches(before, participants));
        loop {
            let after = self.traffic_statuses_on_by(&participants.observers, deadline);
            for indexed in &after {
                if indexed.status.failure.is_some()
                    || indexed.status.state == QualificationTrafficState::Failed
                {
                    let all_node_indices = (0..self.member_count()).collect::<Vec<_>>();
                    let readiness = self.readiness_reports(&all_node_indices);
                    let material = all_node_indices
                        .iter()
                        .map(|node_index| self.material_status(*node_index))
                        .collect::<Vec<_>>();
                    let lifecycle = self.all_lifecycle_metrics();
                    let observed_at = Timestamp::now_utc();
                    panic!(
                        "traffic task failed during {phase}: observed_at={observed_at:?}, node={}, status={:?}, readiness={readiness:?}, material={material:?}, lifecycle={lifecycle:?}, stderr={}",
                        indexed.node_index,
                        indexed.status,
                        self.node_stderr(indexed.node_index)
                    );
                }
            }
            if subset_traffic_made_semantic_progress_with_crashed_tail(
                before,
                &after,
                participants,
                crashed_node_index,
            ) {
                assert!(
                    deadline_allows_completion(Instant::now(), deadline),
                    "subset traffic progressed only after the absolute deadline: phase={phase}, participants={participants:?}, before={before:?}, after={after:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return after;
            }
            assert!(
                deadline_allows_completion(Instant::now(), deadline),
                "subset traffic did not make semantic progress: phase={phase}, participants={participants:?}, before={before:?}, after={after:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_member_recovery_settlement(
        &mut self,
        participants: &TrafficParticipants,
        phase: &str,
        deadline: Instant,
        availability_baseline: &[IndexedTrafficStatus],
    ) -> (
        Vec<QualificationConnectionLifecycleMetrics>,
        Vec<IndexedTrafficStatus>,
    ) {
        assert_eq!(participants.member_count, self.member_count());
        assert!(traffic_status_snapshot_matches(
            availability_baseline,
            participants,
        ));
        loop {
            let traffic = self.traffic_statuses_on(&participants.observers);
            // TrafficStatus performs a protected backend observation and may
            // exercise consensus transport. Sample lifecycle only after those
            // calls so a drain or classified failure they trigger cannot be
            // hidden behind a stale pre-status snapshot.
            let lifecycle = self.all_lifecycle_metrics();
            for indexed in &traffic {
                assert_ne!(
                    indexed.status.state,
                    QualificationTrafficState::Failed,
                    "survivor traffic failed while settling recovered-member paths: phase={phase}, node={}, status={:?}, lifecycle={lifecycle:?}, stderr={:?}",
                    indexed.node_index,
                    indexed.status,
                    self.stderr_diagnostics()
                );
                assert_eq!(
                    indexed.status.failure,
                    None,
                    "survivor traffic recorded a terminal failure while settling recovered-member paths: phase={phase}, node={}, status={:?}, lifecycle={lifecycle:?}, stderr={:?}",
                    indexed.node_index,
                    indexed.status,
                    self.stderr_diagnostics()
                );
            }
            assert!(
                subset_traffic_availability_counters_equal(
                    availability_baseline,
                    &traffic,
                    participants,
                ),
                "clean recovered-member reauthentication changed survivor availability counters: phase={phase}, before={availability_baseline:?}, current={traffic:?}, lifecycle={lifecycle:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            let completed = lifecycle
                .iter()
                .all(|metrics| lifecycle_transition_is_settled(metrics, self.member_count()))
                && subset_traffic_availability_is_settled(&traffic, participants)
                && subset_traffic_made_semantic_progress_with_crashed_tail(
                    availability_baseline,
                    &traffic,
                    participants,
                    None,
                );
            let now = Instant::now();
            if completed {
                assert!(
                    deadline_allows_completion(now, deadline),
                    "recovered-member lifecycle and survivor availability settled only after the absolute transition deadline: phase={phase}, traffic={traffic:?}, lifecycle={lifecycle:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return (lifecycle, traffic);
            }
            assert!(
                deadline_allows_completion(now, deadline),
                "recovered-member lifecycle or survivor availability remained unsettled: phase={phase}, traffic={traffic:?}, lifecycle={lifecycle:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_traffic_mutations_on(&mut self, node_indices: &[usize]) -> Vec<IndexedTrafficStatus> {
        validate_traffic_indices(
            self.member_count(),
            node_indices,
            TrafficParticipantError::EmptyMutators,
        )
        .expect("valid bounded stopped mutator participants");
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::StopTrafficMutation);
        }
        node_indices
            .iter()
            .map(|node_index| {
                let status = match self.nodes[*node_index].receive() {
                    QualificationNodeReply::TrafficStatus { status } => status,
                    reply => panic!(
                        "traffic mutation did not stop: node={node_index}, reply={reply:?}, stderr={}",
                        self.node_stderr(*node_index)
                    ),
                };
                assert_eq!(
                    status.state,
                    QualificationTrafficState::MutationStopped,
                    "traffic mutation stop returned an invalid state: node={node_index}, status={status:?}, stderr={}",
                    self.node_stderr(*node_index)
                );
                assert_eq!(status.failure, None);
                assert_eq!(status.owned_async_tasks, 1);
                assert_completed_traffic_cycles(&status);
                IndexedTrafficStatus {
                    node_index: *node_index,
                    status,
                }
            })
            .collect()
    }

    fn stop_traffic_watches_on(&mut self, node_indices: &[usize]) -> Vec<IndexedTrafficStatus> {
        validate_traffic_indices(
            self.member_count(),
            node_indices,
            TrafficParticipantError::EmptyObservers,
        )
        .expect("valid bounded stopped watch participants");
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::StopTrafficWatch);
        }
        node_indices
            .iter()
            .map(|node_index| {
                let status = match self.nodes[*node_index].receive() {
                    QualificationNodeReply::TrafficStatus { status } => status,
                    reply => panic!(
                        "traffic watch did not stop: node={node_index}, reply={reply:?}, stderr={}",
                        self.node_stderr(*node_index)
                    ),
                };
                assert_eq!(
                    status.state,
                    QualificationTrafficState::Stopped,
                    "traffic watch stop returned an invalid state: node={node_index}, status={status:?}, stderr={}",
                    self.node_stderr(*node_index)
                );
                assert_eq!(status.failure, None);
                assert_eq!(status.owned_async_tasks, 0);
                IndexedTrafficStatus {
                    node_index: *node_index,
                    status,
                }
            })
            .collect()
    }

    fn start_traffic_tasks(&mut self) {
        let member_count = self.member_count();
        let seed = qualification_traffic_seed(member_count)
            .expect("supported traffic qualification topology");
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StartTrafficWatch);
        }
        for node in &mut self.nodes {
            match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::WatchReady);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.seed, seed);
                    assert_eq!(status.owned_async_tasks, 1);
                    assert_eq!(status.watch_traffic_generations, vec![0; member_count]);
                }
                reply => panic!("traffic watch did not start: {reply:?}"),
            }
        }
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StartTrafficMutation);
        }
        for node in &mut self.nodes {
            match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::Running);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.seed, seed);
                    assert_eq!(status.owned_async_tasks, 2);
                }
                reply => panic!("traffic mutation did not start: {reply:?}"),
            }
        }

        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let statuses = self.all_traffic_statuses();
            if statuses.iter().all(|status| {
                status.state == QualificationTrafficState::Running
                    && status.failure.is_none()
                    && traffic_failure_fields_are_coherent(status)
                    && traffic_live_mutator_counters_are_consistent(status)
                    && traffic_availability_recovery_is_resolved(status)
                    && status.availability_interruptions >= 1
                    && status.owned_async_tasks == 2
                    && status.mutation_cycles >= 1
                    && status.watch_entries >= 1
                    && status.watch_applied_records >= 1
            }) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "traffic tasks did not reach the warmed state: statuses={statuses:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_traffic_progress(
        &mut self,
        before: &[QualificationTrafficStatus],
        phase: &str,
        deadline: Instant,
    ) -> Vec<QualificationTrafficStatus> {
        assert_eq!(before.len(), self.member_count());
        loop {
            let statuses = self.all_traffic_statuses();
            for (node_index, status) in statuses.iter().enumerate() {
                assert_eq!(
                    status.state,
                    QualificationTrafficState::Running,
                    "traffic state failed during {phase}: node={node_index}, status={status:?}, stderr={}",
                    self.node_stderr(node_index)
                );
                assert_eq!(status.failure, None);
                assert_eq!(status.owned_async_tasks, 2);
                assert_eq!(status.watch_traffic_generations.len(), self.member_count());
            }
            if statuses.iter().zip(before).all(|(after, before)| {
                traffic_status_made_semantic_progress(before, after, self.member_count())
            }) {
                assert!(
                    deadline_allows_completion(Instant::now(), deadline),
                    "traffic made semantic progress only after the absolute transition deadline: phase={phase}, before={before:?}, after={statuses:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return statuses;
            }
            assert!(
                deadline_allows_completion(Instant::now(), deadline),
                "traffic did not make semantic progress during {phase}: before={before:?}, after={statuses:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_traffic_mutations(&mut self) -> Vec<QualificationTrafficStatus> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StopTrafficMutation);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::MutationStopped);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.owned_async_tasks, 1);
                    assert_completed_traffic_cycles(&status);
                    status
                }
                reply => panic!("traffic mutation task did not stop: {reply:?}"),
            })
            .collect()
    }

    fn wait_for_watch_heads(&mut self) -> Vec<QualificationTrafficStatus> {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let statuses = self.all_traffic_statuses();
            if statuses.iter().all(|status| {
                status.state == QualificationTrafficState::MutationStopped
                    && status.failure.is_none()
                    && status.owned_async_tasks == 1
                    && status.watch_sequence == status.replication_head
            }) {
                return statuses;
            }
            assert!(
                Instant::now() < deadline,
                "protected watches did not reach every local applied head: statuses={statuses:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_traffic_watches(&mut self) -> Vec<QualificationTrafficStatus> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StopTrafficWatch);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::Stopped);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.owned_async_tasks, 0);
                    status
                }
                reply => panic!("traffic watch task did not stop: {reply:?}"),
            })
            .collect()
    }

    fn publish_known_projected_generation(
        &mut self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
        phase: &str,
    ) -> Instant {
        let credential = self.pki.credential(node_index, credential_generation);
        let trust_bundle = self.pki.trust_bundle(trust_generation);
        self.candidate_public_material_manifest
            .record(
                phase,
                node_index,
                self.projected_generation[node_index].saturating_add(1),
                &credential.certificate_chain_pem,
                &trust_bundle,
            )
            .expect("bind public certificate and trust publication");
        publish_projected_generation(
            &self.projected_roots[node_index],
            &mut self.projected_generation[node_index],
            credential,
            &trust_bundle,
        )
    }

    fn publish_custom_projected_generation(
        &mut self,
        node_index: usize,
        credential: &ProjectedCredential,
        trust_bundle_pem: &str,
        phase: &str,
    ) -> Instant {
        self.candidate_public_material_manifest
            .record(
                phase,
                node_index,
                self.projected_generation[node_index].saturating_add(1),
                &credential.certificate_chain_pem,
                trust_bundle_pem,
            )
            .expect("bind custom public certificate and trust publication");
        publish_projected_generation(
            &self.projected_roots[node_index],
            &mut self.projected_generation[node_index],
            credential,
            trust_bundle_pem,
        )
    }

    fn publish_known_projected_generation_with_trust(
        &mut self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_bundle_pem: &str,
        phase: &str,
    ) -> Instant {
        let credential = self.pki.credential(node_index, credential_generation);
        self.candidate_public_material_manifest
            .record(
                phase,
                node_index,
                self.projected_generation[node_index].saturating_add(1),
                &credential.certificate_chain_pem,
                trust_bundle_pem,
            )
            .expect("bind public certificate and custom trust publication");
        publish_projected_generation(
            &self.projected_roots[node_index],
            &mut self.projected_generation[node_index],
            credential,
            trust_bundle_pem,
        )
    }

    fn transition_traffic_leaf(&mut self, node_index: usize, rotation: usize) {
        let source_before = self.projected_status(node_index);
        let controller_before = self.material_status(node_index);
        self.publish_known_projected_generation(
            node_index,
            CredentialGeneration::TrafficLeaf(rotation),
            TrustGeneration::OldOnly,
            "traffic-leaf-rotation",
        );
        self.wait_for_member_publication(
            node_index,
            source_before.generation,
            controller_before.epoch,
        );
    }

    fn prove_all_directed_paths_parallel(&mut self, generations: &[u64]) {
        let member_count = self.member_count();
        assert_eq!(generations.len(), member_count);
        for offset in 1..member_count {
            let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
            let mut pending = vec![true; member_count];
            while pending.iter().any(|pending| *pending) {
                for (source, node) in self.nodes.iter_mut().enumerate() {
                    if pending[source] {
                        node.send(&QualificationNodeCommand::DirectedHandshake {
                            remote_node_index: (source + offset) % member_count,
                        });
                    }
                }
                for (source, node) in self.nodes.iter_mut().enumerate() {
                    if !pending[source] {
                        continue;
                    }
                    let target = (source + offset) % member_count;
                    match node.receive() {
                        QualificationNodeReply::DirectedHandshake {
                            remote_node_index,
                            reauthentication_generation,
                        } => {
                            assert_eq!(remote_node_index, target);
                            assert_eq!(reauthentication_generation, generations[source]);
                            pending[source] = false;
                        }
                        QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
                        } if Instant::now() < deadline => {}
                        reply => panic!(
                            "parallel directed current-generation handshake {source}->{target} failed: {reply:?}, source_stderr={}, target_stderr={}",
                            self.node_stderr(source),
                            self.node_stderr(target)
                        ),
                    }
                }
                if pending.iter().any(|pending| *pending) {
                    assert!(
                        Instant::now() < deadline,
                        "parallel directed current-generation handshake deadline"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    fn fresh_all_directed_generation(&mut self) {
        let generations = self.request_fleet_reauthentication();
        self.prove_all_directed_paths_parallel(&generations);
    }

    fn keep_member_directed_paths_alive_until(
        &mut self,
        member: usize,
        cutoff: time::OffsetDateTime,
    ) {
        while time::OffsetDateTime::now_utc() < cutoff {
            if !self.keep_member_directed_paths_alive_before(member, cutoff) {
                return;
            }
            let remaining = duration_until_wall_time(cutoff);
            if remaining.is_zero() {
                return;
            }
            thread::sleep(remaining.min(Duration::from_millis(
                QUALIFICATION_FAULT_PATH_REFRESH_MILLIS,
            )));
        }
    }

    fn keep_member_directed_paths_alive_before(
        &mut self,
        member: usize,
        cutoff: time::OffsetDateTime,
    ) -> bool {
        let complete_call_bound =
            Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.read_barrier_timeout_millis);
        for remote in 0..self.member_count() {
            if remote == member {
                continue;
            }
            for (source, target) in [(remote, member), (member, remote)] {
                if duration_until_wall_time(cutoff) < complete_call_bound {
                    return false;
                }
                match self.nodes[source].invoke(&QualificationNodeCommand::DirectedHandshake {
                    remote_node_index: target,
                }) {
                    QualificationNodeReply::DirectedHandshake {
                        remote_node_index,
                        reauthentication_generation,
                    } => {
                        assert_eq!(remote_node_index, target);
                        assert!(reauthentication_generation >= 1);
                    }
                    reply => panic!(
                        "incident directed path did not remain authenticated before expiry: source={source}, target={target}, reply={reply:?}, source_stderr={}, target_stderr={}",
                        self.node_stderr(source),
                        self.node_stderr(target)
                    ),
                }
                assert!(
                    time::OffsetDateTime::now_utc() <= cutoff,
                    "incident directed keepalive exceeded its absolute cutoff: source={source}, target={target}"
                );
            }
        }
        true
    }

    fn verify_all_traffic_records(&mut self, statuses: &[QualificationTrafficStatus]) {
        assert_eq!(statuses.len(), self.member_count());
        let seed = qualification_traffic_seed(self.member_count())
            .expect("supported traffic qualification topology");
        for (source, status) in statuses.iter().enumerate() {
            let stable_id = traffic_stable_id(source);
            let owner = traffic_owner(source);
            let expected_owner = qualification_owner_sha256(&owner);
            let value = qualification_traffic_value(
                seed,
                self.member_count(),
                source,
                status.last_generation,
            );
            let expected_value = qualification_value_sha256(value.as_bytes());
            for node in &mut self.nodes {
                node.send(&QualificationNodeCommand::Get {
                    stable_id: stable_id.clone(),
                });
            }
            for node in &mut self.nodes {
                match node.receive() {
                    QualificationNodeReply::Record {
                        present: true,
                        generation: Some(generation),
                        owner_sha256: Some(ref owner_sha256),
                        fence: Some(fence),
                        value_sha256: Some(ref value_sha256),
                    } => {
                        assert_eq!(generation, status.last_generation);
                        assert_eq!(owner_sha256, &expected_owner);
                        assert_eq!(fence, status.last_record_fence);
                        assert_eq!(value_sha256, &expected_value);
                    }
                    reply => panic!("all-voter traffic read failed: {reply:?}"),
                }
            }
        }
    }

    fn retain_traffic_plaintext_canaries(&mut self, statuses: &[QualificationTrafficStatus]) {
        let member_count = self.member_count();
        let seed = qualification_traffic_seed(member_count)
            .expect("supported traffic qualification topology");
        for (node_index, status) in statuses.iter().enumerate() {
            for generation in 1..=status.last_generation {
                self.canary_values.push(qualification_traffic_value(
                    seed,
                    member_count,
                    node_index,
                    generation,
                ));
            }
        }
    }

    fn assert_all_material_ready(&mut self) {
        self.assert_all_material_ready_by(Instant::now() + CHILD_TIMEOUT);
    }

    fn assert_all_material_ready_by(&mut self, deadline: Instant) {
        for node_index in 0..self.member_count() {
            let source = self.projected_status_by(node_index, deadline);
            assert!(source.generation >= 1);
            assert_eq!(
                source.availability,
                QualificationProjectedSvidAvailability::Ready
            );
            assert!(source.reason.is_none());

            let controller = self.material_status_by(node_index, deadline);
            assert!(controller.epoch >= 1);
            assert_eq!(
                controller.availability,
                QualificationTlsMaterialAvailability::Ready
            );
            assert!(controller.reason.is_none());
            assert!(controller.leaf_expires_at.is_some());
            assert!(controller.certificate_chain_expires_at.is_some());
        }
    }

    fn wait_for_member_publication(
        &mut self,
        node_index: usize,
        previous_source_generation: u64,
        previous_material_epoch: u64,
    ) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let source = self.projected_status(node_index);
            let controller = self.material_status(node_index);
            if matches!(
                source.availability,
                QualificationProjectedSvidAvailability::RetainingLastGood
                    | QualificationProjectedSvidAvailability::Unavailable
            ) || matches!(
                controller.availability,
                QualificationTlsMaterialAvailability::RetainingLastGood
                    | QualificationTlsMaterialAvailability::Unavailable
            ) {
                panic!(
                    "valid projected candidate was rejected: node={node_index}, source={source:?}, controller={controller:?}, stderr={}",
                    self.node_stderr(node_index)
                );
            }
            if source.generation > previous_source_generation
                && source.availability == QualificationProjectedSvidAvailability::Ready
                && source.reason.is_none()
                && controller.epoch > previous_material_epoch
                && controller.availability == QualificationTlsMaterialAvailability::Ready
                && controller.reason.is_none()
                && controller.leaf_expires_at.is_some()
                && controller.certificate_chain_expires_at.is_some()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "projected source and TLS controller did not publish a new ready generation: node={node_index}, source={source:?}, controller={controller:?}, stderr={}",
                self.node_stderr(node_index)
            );
            thread::sleep(MIN_PROJECTED_SVID_POLL_INTERVAL);
        }
    }

    fn wait_for_member_recovery_publication(
        &mut self,
        node_index: usize,
        previous_source_generation: u64,
        previous_material_epoch: u64,
    ) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        self.wait_for_member_recovery_publication_by(
            node_index,
            previous_source_generation,
            previous_material_epoch,
            deadline,
        );
    }

    fn wait_for_member_recovery_publication_by(
        &mut self,
        node_index: usize,
        previous_source_generation: u64,
        previous_material_epoch: u64,
        deadline: Instant,
    ) {
        loop {
            let source = self.projected_status_by(node_index, deadline);
            let controller = self.material_status_by(node_index, deadline);
            let source_advanced = source.generation > previous_source_generation;
            let controller_advanced = controller.epoch > previous_material_epoch;
            if source_advanced
                && source.availability == QualificationProjectedSvidAvailability::Ready
                && source.reason.is_none()
                && controller_advanced
                && controller.availability == QualificationTlsMaterialAvailability::Ready
                && controller.reason.is_none()
                && controller.leaf_expires_at.is_some()
                && controller.certificate_chain_expires_at.is_some()
            {
                assert!(
                    deadline_allows_completion(Instant::now(), deadline),
                    "valid projected recovery became ready only after its absolute deadline: node={node_index}, source={source:?}, controller={controller:?}, stderr={}",
                    self.node_stderr(node_index)
                );
                return;
            }
            assert!(
                source.generation == previous_source_generation || source_advanced,
                "projected source generation regressed during recovery"
            );
            assert!(
                controller.epoch == previous_material_epoch || controller_advanced,
                "TLS material epoch regressed during recovery"
            );
            assert!(
                deadline_allows_completion(Instant::now(), deadline),
                "valid projected recovery did not publish a new ready generation: node={node_index}, source={source:?}, controller={controller:?}, stderr={}",
                self.node_stderr(node_index)
            );
            thread::sleep(MIN_PROJECTED_SVID_POLL_INTERVAL);
        }
    }

    fn transition_member(
        &mut self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
        phase: &str,
    ) {
        let source_before = self.projected_status(node_index);
        let controller_before = self.material_status(node_index);
        self.publish_known_projected_generation(
            node_index,
            credential_generation,
            trust_generation,
            phase,
        );
        self.wait_for_member_publication(
            node_index,
            source_before.generation,
            controller_before.epoch,
        );
        self.assert_all_material_ready();
        self.reauthenticate_and_prove_member_paths(node_index);
        self.wait_ready();
        self.verify_canary();
        assert!(!phase.is_empty());
    }

    fn transition_member_under_traffic(
        &mut self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
        phase: &str,
        lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        let started = Instant::now();
        let transition_deadline =
            started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        let source_before = self.projected_status(node_index);
        let controller_before = self.material_status(node_index);
        self.publish_known_projected_generation(
            node_index,
            credential_generation,
            trust_generation,
            phase,
        );
        self.wait_for_member_publication(
            node_index,
            source_before.generation,
            controller_before.epoch,
        );
        self.assert_all_material_ready();
        self.fresh_all_directed_generation();
        self.wait_ready();
        self.verify_canary();
        // Only work committed after publication, resolver-fresh directed
        // handshakes, readiness, and canary verification counts for this
        // transition's continuity proof.
        let traffic_after_reauthentication = self.all_traffic_statuses();
        self.wait_for_traffic_progress(&traffic_after_reauthentication, phase, transition_deadline);
        let lifecycle_after = self.wait_for_round_lifecycle_completion(
            lifecycle_checkpoint,
            transition_deadline,
            phase,
        );
        let remote_peers = u64::try_from(self.member_count() - 1).expect("bounded member count");
        assert_epoch_changing_lifecycle_delta_bounds(
            self.member_count(),
            lifecycle_checkpoint,
            &lifecycle_after,
            remote_peers,
        );
        assert!(!phase.is_empty());
        assert_transition_completed_by(started, transition_deadline, phase);
        *lifecycle_checkpoint = lifecycle_after;
    }

    fn request_fleet_reauthentication(&mut self) -> Vec<u64> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::RequestReauthentication);
        }
        let mut generations = Vec::with_capacity(self.member_count());
        for node in &mut self.nodes {
            let generation = match node.receive() {
                QualificationNodeReply::ReauthenticationRequested { generation } => generation,
                reply => panic!("unexpected reauthentication response: {reply:?}"),
            };
            assert!(generation >= 1);
            generations.push(generation);
        }
        generations
    }

    fn all_reauthentication_generations(&mut self) -> Vec<u64> {
        self.all_reauthentication_generations_by(Instant::now() + CHILD_TIMEOUT)
    }

    fn all_reauthentication_generations_by(&mut self, deadline: Instant) -> Vec<u64> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::ReauthenticationGeneration);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive_until(deadline) {
                QualificationNodeReply::ReauthenticationGeneration { generation } => generation,
                reply => panic!("unexpected reauthentication generation response: {reply:?}"),
            })
            .collect()
    }

    fn reauthenticate_and_prove_member_paths(&mut self, member: usize) {
        let generations = self.request_fleet_reauthentication();
        let paths = member_incident_directed_paths(self.member_count(), member);
        assert_eq!(paths.len(), 2 * (self.member_count() - 1));
        self.prove_directed_paths(&generations, paths);
    }

    fn prove_recovered_member_paths_at_current_generation(
        &mut self,
        member: usize,
        availability_baseline: &[IndexedTrafficStatus],
        participants: &TrafficParticipants,
        traffic_progress: &mut RecoveryTrafficProgressTracker,
        absolute_deadline: Instant,
    ) {
        assert!(member < self.member_count());
        let generations_before = self
            .all_reauthentication_generations_by(traffic_progress.next_deadline(absolute_deadline));
        let paths = member_incident_directed_paths(self.member_count(), member);
        assert_eq!(paths.len(), 2 * (self.member_count() - 1));
        for (source, target) in paths {
            let progress_deadline = traffic_progress.next_deadline(absolute_deadline);
            self.wait_for_directed_handshake_by(
                source,
                target,
                generations_before[source],
                progress_deadline,
            );
            self.wait_for_recovery_traffic_progress(
                availability_baseline,
                traffic_progress,
                participants,
                "existing-generation-incident-path",
                absolute_deadline,
            );
        }
        let generations_after = self
            .all_reauthentication_generations_by(traffic_progress.next_deadline(absolute_deadline));
        assert_eq!(
            generations_after, generations_before,
            "fault-boundary path proof advanced an explicit reauthentication generation"
        );
        self.wait_for_recovery_traffic_progress(
            availability_baseline,
            traffic_progress,
            participants,
            "existing-generation-path-generation-check",
            absolute_deadline,
        );
    }

    fn reauthenticate_recovered_member_and_prove_paths(&mut self, member: usize) {
        assert!(member < self.member_count());
        let generations_before = self.all_reauthentication_generations();
        let member_generation = match self.nodes[member]
            .invoke(&QualificationNodeCommand::RequestReauthentication)
        {
            QualificationNodeReply::ReauthenticationRequested { generation } => generation,
            reply => panic!(
                "failed to request recovered-member reauthentication: member={member}, reply={reply:?}"
            ),
        };
        assert_eq!(
            generations_before[member].checked_add(1),
            Some(member_generation),
            "recovered-member reauthentication generation did not advance exactly once"
        );

        for (source, target) in member_incident_directed_paths(self.member_count(), member) {
            let expected_generation = if source == member {
                member_generation
            } else {
                // The hard-expiry checkpoint already proved every incident
                // connection retired and fully drained. A successful
                // survivor-to-member call after replacement therefore uses a
                // new TLS/bootstrap connection even though that survivor's
                // process-local explicit generation intentionally did not
                // advance.
                generations_before[source]
            };
            self.wait_for_directed_handshake(source, target, expected_generation);
        }
        let generations_after = self.all_reauthentication_generations();
        assert!(
            member_reauthentication_generations_are_scoped(
                &generations_before,
                &generations_after,
                member,
            ),
            "member recovery advanced an unrelated survivor reauthentication generation: member={member}, before={generations_before:?}, after={generations_after:?}"
        );
    }

    fn complete_recovered_member_phase_under_traffic(
        &mut self,
        context: RecoveredMemberPhaseContext<'_>,
    ) -> Vec<IndexedTrafficStatus> {
        let RecoveredMemberPhaseContext {
            member,
            participants,
            phase,
            fault_lifecycle_before,
            traffic_availability_baseline,
            mut traffic_progress,
            recovery_started,
            recovery_deadline,
        } = context;
        assert!(!participants.observers.contains(&member));
        self.assert_all_material_ready_by(traffic_progress.next_deadline(recovery_deadline));
        self.wait_for_recovery_traffic_progress(
            traffic_availability_baseline,
            &mut traffic_progress,
            participants,
            "replacement-material-ready",
            recovery_deadline,
        );
        self.prove_recovered_member_paths_at_current_generation(
            member,
            traffic_availability_baseline,
            participants,
            &mut traffic_progress,
            recovery_deadline,
        );
        self.wait_for_recovery_readiness(
            traffic_availability_baseline,
            &mut traffic_progress,
            participants,
            "replacement-all-voter-readiness",
            recovery_deadline,
        );
        self.wait_for_recovery_traffic_progress(
            traffic_availability_baseline,
            &mut traffic_progress,
            participants,
            "replacement-all-voter-readiness",
            recovery_deadline,
        );
        self.verify_canary_by(traffic_progress.next_deadline(recovery_deadline));
        self.wait_for_recovery_traffic_progress(
            traffic_availability_baseline,
            &mut traffic_progress,
            participants,
            "replacement-canary-verification",
            recovery_deadline,
        );
        let (lifecycle_before, clean_traffic_baseline) = self
            .wait_for_recovery_fault_outcomes_to_settle(RecoveryFaultSettlementContext {
                before: fault_lifecycle_before,
                participants,
                phase,
                started: recovery_started,
                deadline: recovery_deadline,
                traffic_before: traffic_availability_baseline,
                traffic_progress,
            });
        let started = Instant::now();
        let deadline = started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        self.reauthenticate_recovered_member_and_prove_paths(member);
        self.wait_ready();
        self.advance_canary(phase);
        let (lifecycle_after, traffic_after) = self.wait_for_member_recovery_settlement(
            participants,
            phase,
            deadline,
            &clean_traffic_baseline,
        );
        assert_epoch_changing_lifecycle_delta_bounds(
            self.member_count(),
            &lifecycle_before,
            &lifecycle_after,
            0,
        );
        assert!(
            unrelated_survivor_reauthentication_retirements_are_unchanged(
                &lifecycle_before,
                &lifecycle_after,
                member,
            ),
            "member recovery retired unrelated survivor connections: member={member}, before={lifecycle_before:?}, after={lifecycle_after:?}"
        );
        assert_transition_completed_by(started, deadline, phase);
        traffic_after
    }

    fn complete_fleet_phase(&mut self, phase: &str) {
        let generations = self.request_fleet_reauthentication();
        let paths = (0..self.member_count())
            .flat_map(|source| (0..self.member_count()).map(move |target| (source, target)))
            .filter(|(source, target)| source != target)
            .collect::<Vec<_>>();
        assert_eq!(
            paths.len(),
            self.member_count() * (self.member_count() - 1),
            "a completed fleet phase must cover every directed path"
        );
        self.prove_directed_paths(&generations, paths);
        self.wait_ready();
        self.advance_canary(phase);
    }

    fn complete_fleet_phase_under_traffic(
        &mut self,
        phase: &str,
        lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        let started = Instant::now();
        let transition_deadline =
            started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        // The immediately preceding last member transition already proved a
        // fresh full directed generation after that exact publication. The
        // phase checkpoint adds an acknowledged canary CAS/read and sustained
        // workload progress without introducing a redundant reauthentication
        // generation that would distort the connection-rate measurement.
        self.advance_canary(phase);
        self.wait_ready();
        let traffic_after_checkpoint = self.all_traffic_statuses();
        self.wait_for_traffic_progress(&traffic_after_checkpoint, phase, transition_deadline);
        let lifecycle_after = self.wait_for_round_lifecycle_completion(
            lifecycle_checkpoint,
            transition_deadline,
            phase,
        );
        assert_lifecycle_delta_bounds(
            self.member_count(),
            lifecycle_checkpoint,
            &lifecycle_after,
            0,
        );
        assert_transition_completed_by(started, transition_deadline, phase);
        *lifecycle_checkpoint = lifecycle_after;
    }

    fn prove_directed_paths(&mut self, generations: &[u64], paths: Vec<(usize, usize)>) {
        for (source, target) in paths {
            self.wait_for_directed_handshake(source, target, generations[source]);
        }
    }

    fn wait_for_directed_handshake(
        &mut self,
        source: usize,
        target: usize,
        expected_generation: u64,
    ) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        self.wait_for_directed_handshake_by(source, target, expected_generation, deadline);
    }

    fn wait_for_directed_handshake_by(
        &mut self,
        source: usize,
        target: usize,
        expected_generation: u64,
        deadline: Instant,
    ) {
        loop {
            match self.nodes[source].invoke(&QualificationNodeCommand::DirectedHandshake {
                remote_node_index: target,
            }) {
                QualificationNodeReply::DirectedHandshake {
                    remote_node_index,
                    reauthentication_generation,
                } => {
                    assert_eq!(remote_node_index, target);
                    assert_eq!(reauthentication_generation, expected_generation);
                    assert!(
                        deadline_allows_completion(Instant::now(), deadline),
                        "directed current-generation handshake {source}->{target} completed only after its absolute deadline"
                    );
                    return;
                }
                QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
                } if deadline_allows_completion(Instant::now(), deadline) => {
                    thread::sleep(Duration::from_millis(20));
                }
                reply => panic!(
                    "directed current-generation handshake {source}->{target} failed: {reply:?}, source_stderr={}, target_stderr={}",
                    self.node_stderr(source),
                    self.node_stderr(target)
                ),
            }
        }
    }

    fn acquire_canary_lease(&mut self) {
        match self.nodes[0].invoke(&QualificationNodeCommand::Acquire {
            lease_handle: CANARY_LEASE_HANDLE.to_owned(),
            stable_id: CANARY_STABLE_ID.to_owned(),
            owner: CANARY_OWNER.to_owned(),
            ttl_millis: CANARY_TTL_MILLIS,
        }) {
            QualificationNodeReply::LeaseAcquired { fence } => assert!(fence >= 1),
            reply => panic!("failed to acquire rotation canary lease: {reply:?}"),
        }
    }

    fn advance_canary(&mut self, phase: &str) {
        let node_indices = (0..self.member_count()).collect::<Vec<_>>();
        self.advance_canary_on_nodes(0, &node_indices, phase);
    }

    fn advance_canary_for_survivors(&mut self, isolated_node_index: usize, phase: &str) {
        self.advance_canary_for_survivors_with_deadline(isolated_node_index, phase, None);
    }

    fn advance_canary_for_survivors_by(
        &mut self,
        isolated_node_index: usize,
        phase: &str,
        deadline: Instant,
    ) {
        self.advance_canary_for_survivors_with_deadline(isolated_node_index, phase, Some(deadline));
    }

    fn advance_canary_for_survivors_with_deadline(
        &mut self,
        isolated_node_index: usize,
        phase: &str,
        deadline: Option<Instant>,
    ) {
        assert_ne!(
            isolated_node_index, 0,
            "the fixed canary writer must remain in the survivor quorum"
        );
        let survivors = (0..self.member_count())
            .filter(|node_index| *node_index != isolated_node_index)
            .collect::<Vec<_>>();
        self.advance_canary_on_nodes_with_deadline(0, &survivors, phase, deadline);
    }

    fn advance_canary_on_nodes(
        &mut self,
        writer_node_index: usize,
        reader_node_indices: &[usize],
        phase: &str,
    ) {
        self.advance_canary_on_nodes_with_deadline(
            writer_node_index,
            reader_node_indices,
            phase,
            None,
        );
    }

    fn advance_canary_on_nodes_with_deadline(
        &mut self,
        writer_node_index: usize,
        reader_node_indices: &[usize],
        phase: &str,
        deadline: Option<Instant>,
    ) {
        assert!(reader_node_indices.contains(&writer_node_index));
        let expected_generation = (self.canary_generation != 0).then_some(self.canary_generation);
        self.canary_generation += 1;
        let value = format!(
            "opc-rotation-plaintext-canary/{}/{}/{phase}",
            self.member_count(),
            self.canary_generation
        );
        self.nodes[writer_node_index].send(&QualificationNodeCommand::CompareAndSet {
            lease_handle: CANARY_LEASE_HANDLE.to_owned(),
            stable_id: CANARY_STABLE_ID.to_owned(),
            expected_generation,
            new_generation: self.canary_generation,
            value: value.clone(),
        });
        let reply = match deadline {
            Some(deadline) => self.nodes[writer_node_index].receive_until(deadline),
            None => self.nodes[writer_node_index].receive(),
        };
        match reply {
            QualificationNodeReply::CompareAndSet {
                applied: true,
                current_generation: Some(actual),
            } => assert_eq!(actual, self.canary_generation),
            reply => panic!("rotation canary CAS failed: {reply:?}"),
        }

        self.canary_values.push(value);
        self.verify_canary_on_nodes_with_deadline(reader_node_indices, deadline);
    }

    fn verify_canary(&mut self) {
        let node_indices = (0..self.member_count()).collect::<Vec<_>>();
        self.verify_canary_on_nodes(&node_indices);
    }

    fn verify_canary_by(&mut self, deadline: Instant) {
        let node_indices = (0..self.member_count()).collect::<Vec<_>>();
        self.verify_canary_on_nodes_with_deadline(&node_indices, Some(deadline));
    }

    fn verify_canary_on_nodes(&mut self, node_indices: &[usize]) {
        self.verify_canary_on_nodes_with_deadline(node_indices, None);
    }

    fn verify_canary_on_nodes_with_deadline(
        &mut self,
        node_indices: &[usize],
        deadline: Option<Instant>,
    ) {
        assert!(!node_indices.is_empty());
        let expected_owner = qualification_owner_sha256(CANARY_OWNER);
        let expected_value = qualification_value_sha256(
            self.canary_values
                .last()
                .expect("seeded rotation canary")
                .as_bytes(),
        );
        for node_index in node_indices {
            self.nodes[*node_index].send(&QualificationNodeCommand::Get {
                stable_id: CANARY_STABLE_ID.to_owned(),
            });
        }
        for node_index in node_indices {
            let reply = match deadline {
                Some(deadline) => self.nodes[*node_index].receive_until(deadline),
                None => self.nodes[*node_index].receive(),
            };
            match reply {
                QualificationNodeReply::Record {
                    present: true,
                    generation: Some(actual_generation),
                    owner_sha256: Some(ref actual_owner),
                    fence: Some(fence),
                    value_sha256: Some(ref actual_value),
                } => {
                    assert_eq!(actual_generation, self.canary_generation);
                    assert_eq!(actual_owner, &expected_owner);
                    assert!(fence >= 1);
                    assert_eq!(actual_value, &expected_value);
                }
                reply => panic!(
                    "rotation canary read failed: node={node_index}, reply={reply:?}, stderr={}",
                    self.node_stderr(*node_index)
                ),
            }
        }
    }

    fn assert_old_client_chains_rejected(&mut self) {
        let descriptors = self
            .members
            .iter()
            .map(|member| {
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(member.replica_id.clone()).expect("qualification replica ID"),
                    ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                        .expect("qualification endpoint"),
                    ReplicaTlsIdentity::new(member.tls_identity.clone())
                        .expect("qualification TLS identity"),
                    ReplicaFailureDomain::new(member.failure_domain.clone())
                        .expect("qualification failure domain"),
                    ReplicaBackingIdentity::new(member.backing_identity.clone())
                        .expect("qualification backing identity"),
                )
            })
            .collect::<Vec<_>>();
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new(format!(
                    "qualification-mtls-{}-cluster",
                    self.member_count()
                ))
                .expect("qualification cluster ID"),
                SessionConfigurationGeneration::new("v1")
                    .expect("qualification configuration generation"),
                SessionConfigurationEpoch::new(1).expect("qualification configuration epoch"),
                descriptors,
            )
            .expect("qualification replication manifest"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("removed-root rejection runtime");

        for source in 0..self.member_count() {
            let target = (source + 1) % self.member_count();
            let target_metrics_before = self.lifecycle_metrics(target);
            let identity = self.pki.identity_state(
                source,
                CredentialGeneration::RenewedLeaf,
                TrustGeneration::Overlap,
            );
            let (identity_tx, identity_rx) = watch::channel(Some(identity));
            let client = TlsConfigBuilder::new(identity_rx)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("old-chain rejection client");
            let binding = manifest
                .bind_local(
                    ReplicaId::new(self.members[source].replica_id.clone())
                        .expect("old-chain local replica"),
                )
                .expect("old-chain local binding")
                .bind_remote(
                    ReplicaId::new(self.members[target].replica_id.clone())
                        .expect("old-chain remote replica"),
                )
                .expect("old-chain remote binding");
            let address = self.members[target]
                .dial_addr
                .expect("projected-mTLS test route");
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls_for_probe = Arc::clone(&resolver_calls);
            let resolver: RemoteAddrResolver = Arc::new(move || {
                resolver_calls_for_probe.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(address) })
            });
            let peer =
                RemoteSessionConsensusPeer::new_profiled_with_resolver(binding, resolver, client)
                    .with_connection_lifecycle(single_attempt_removed_root_probe_lifecycle());
            let request = SessionConsensusWireRequest::try_new(
                manifest.consensus_identity(),
                manifest
                    .consensus_node_id(
                        &ReplicaId::new(self.members[source].replica_id.clone())
                            .expect("old-chain request replica"),
                    )
                    .expect("old-chain request node ID"),
                SessionConsensusRpcFamily::Vote,
                Vec::new(),
            )
            .expect("old-chain rejection request");
            let outcome = runtime.block_on(peer.call(request));
            assert!(
                matches!(
                    outcome,
                    Err(
                        SessionConsensusPeerError::Authentication
                            | SessionConsensusPeerError::Timeout
                    )
                ),
                "new-only server trust must reject removed old-root client chain: source={source}, target={target}, outcome={outcome:?}"
            );
            assert_eq!(
                resolver_calls.load(Ordering::SeqCst),
                1,
                "qualification-only removed-root probe must make exactly one connection attempt: source={source}, target={target}"
            );
            drop(identity_tx);

            let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
            loop {
                let target_metrics_after = self.lifecycle_metrics(target);
                let authentication_failures_after =
                    target_metrics_after.connection_failure_authentication;
                if authentication_failures_after
                    > target_metrics_before.connection_failure_authentication
                {
                    assert_eq!(
                        authentication_failures_after,
                        target_metrics_before.connection_failure_authentication + 1,
                        "removed-root probe must produce exactly one target authentication failure: source={source}, target={target}"
                    );
                    assert_eq!(
                        target_metrics_after.empty_vote_dispatches,
                        target_metrics_before.empty_vote_dispatches,
                        "removed-root probe must fail before consensus application dispatch: source={source}, target={target}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "removed old-root rejection did not reach the target TLS boundary"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn assert_old_client_chains_rejected_under_traffic(
        &mut self,
        lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        let phase = "traffic-stale-old-root-rejection";
        let started = Instant::now();
        let transition_deadline =
            started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        self.assert_old_client_chains_rejected();
        let traffic_after_rejection = self.all_traffic_statuses();
        self.wait_for_traffic_progress(&traffic_after_rejection, phase, transition_deadline);
        let expected_authentication_failures =
            removed_root_authentication_failure_budget(self.member_count());
        let lifecycle_after = self.wait_for_lifecycle_completion_with_authentication(
            lifecycle_checkpoint,
            transition_deadline,
            phase,
            &expected_authentication_failures,
        );
        assert_lifecycle_delta_bounds_with_authentication(
            self.member_count(),
            lifecycle_checkpoint,
            &lifecycle_after,
            0,
            &expected_authentication_failures,
        );
        assert_transition_completed_by(started, transition_deadline, phase);
        *lifecycle_checkpoint = lifecycle_after;
    }

    fn assert_three_member_resolver_backoff_profile(&self) {
        assert_eq!(self.member_count(), 3);
        let descriptors = self
            .members
            .iter()
            .map(|member| {
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(member.replica_id.clone()).expect("qualification replica ID"),
                    ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                        .expect("qualification endpoint"),
                    ReplicaTlsIdentity::new(member.tls_identity.clone())
                        .expect("qualification TLS identity"),
                    ReplicaFailureDomain::new(member.failure_domain.clone())
                        .expect("qualification failure domain"),
                    ReplicaBackingIdentity::new(member.backing_identity.clone())
                        .expect("qualification backing identity"),
                )
            })
            .collect::<Vec<_>>();
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("qualification-mtls-3-cluster")
                    .expect("qualification cluster ID"),
                SessionConfigurationGeneration::new("v1")
                    .expect("qualification configuration generation"),
                SessionConfigurationEpoch::new(1).expect("qualification configuration epoch"),
                descriptors,
            )
            .expect("qualification replication manifest"),
        );
        let identity =
            self.pki
                .identity_state(0, CredentialGeneration::Initial, TrustGeneration::OldOnly);
        let (_identity_tx, identity_rx) = watch::channel(Some(identity));
        let client = TlsConfigBuilder::new(identity_rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("resolver proof client config");
        let calls = Arc::new(AtomicUsize::new(0));
        let timestamps = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(4)));
        let address = self.members[1]
            .dial_addr
            .expect("projected-mTLS test route");
        let resolver: RemoteAddrResolver = {
            let calls = Arc::clone(&calls);
            let timestamps = Arc::clone(&timestamps);
            Arc::new(move || {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);
                timestamps
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Instant::now());
                Box::pin(async move {
                    if attempt < QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS.len() {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "qualification resolver fault",
                        ))
                    } else {
                        Ok(address)
                    }
                })
            })
        };
        let binding = manifest
            .bind_local(
                ReplicaId::new(self.members[0].replica_id.clone())
                    .expect("resolver proof local replica"),
            )
            .expect("resolver proof local binding")
            .bind_remote(
                ReplicaId::new(self.members[1].replica_id.clone())
                    .expect("resolver proof remote replica"),
            )
            .expect("resolver proof remote binding");
        let peer =
            RemoteSessionConsensusPeer::new_profiled_with_resolver(binding, resolver, client)
                .with_connection_lifecycle(
                    production_lifecycle_config()
                        .to_policy()
                        .expect("production lifecycle policy"),
                );
        let request = SessionConsensusWireRequest::try_new(
            manifest.consensus_identity(),
            manifest
                .consensus_node_id(
                    &ReplicaId::new(self.members[0].replica_id.clone())
                        .expect("resolver proof request replica"),
                )
                .expect("resolver proof request node ID"),
            SessionConsensusRpcFamily::ReadBarrier,
            Vec::new(),
        )
        .expect("resolver proof request");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("resolver proof runtime");
        let started = Instant::now();
        let outcome = runtime.block_on(peer.call(request));
        let elapsed = started.elapsed();
        let response = outcome.expect("resolver retries must reach the real mTLS server");
        response.validate().expect("resolver proof response");
        assert!(
            response.result.is_ok()
                || matches!(&response.result, Err(SessionConsensusPeerError::Protocol)),
            "resolver proof must complete authenticated bootstrap: {response:?}"
        );
        assert!(
            elapsed < Duration::from_millis(QUALIFICATION_RESOLVER_PROOF_MILLIS),
            "resolver proof exceeded the real-mTLS completion bound: elapsed={elapsed:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        let timestamps = timestamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(timestamps.len(), 4);
        for (index, lower_bound_millis) in QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS
            .into_iter()
            .enumerate()
        {
            let actual = timestamps[index + 1].duration_since(timestamps[index]);
            assert!(
                actual >= Duration::from_millis(lower_bound_millis),
                "resolver retry {index} violated exponential backoff: actual={actual:?}, lower_bound_millis={lower_bound_millis}"
            );
        }
    }

    fn wait_for_resources_to_settle(
        &mut self,
        process_ids: &[u32],
        warmed: &[ProcessResourceSnapshot],
    ) -> (
        Vec<ProcessResourceSnapshot>,
        Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        assert_eq!(process_ids.len(), self.member_count());
        assert_eq!(warmed.len(), self.member_count());
        let deadline = Instant::now() + Duration::from_millis(QUALIFICATION_RESOURCE_SETTLE_MILLIS);
        let member_count = self.member_count();
        let mut previous = None;
        let mut stable_samples = 0_usize;
        loop {
            let metrics = self.all_lifecycle_metrics();
            let snapshots = process_ids
                .iter()
                .copied()
                .map(read_classified_process_resources)
                .collect::<Vec<_>>();
            // Openraft heartbeats intentionally remain live after the
            // qualification-owned workload tasks stop, so an inbound handler
            // may remain outstanding. It must be covered by the bounded active
            // gauge; every draining handler must have reached zero.
            let lifecycle_settled = metrics
                .iter()
                .all(|metrics| lifecycle_transition_is_settled(metrics, member_count));
            let resources_within_final_bounds =
                warmed.iter().zip(&snapshots).all(|(warmed, settled)| {
                    settled.file_descriptors
                        <= warmed
                            .file_descriptors
                            .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE)
                        && settled.socket_file_descriptors
                            <= warmed
                                .socket_file_descriptors
                                .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE)
                        && settled.threads
                            <= warmed
                                .threads
                                .saturating_add(QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE)
                        && settled.vm_rss_kib
                            <= warmed
                                .vm_rss_kib
                                .saturating_add(QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB)
                });
            let stable =
                previous
                    .as_ref()
                    .is_some_and(|previous: &Vec<ProcessResourceSnapshot>| {
                        previous.iter().zip(&snapshots).all(|(previous, current)| {
                            previous.file_descriptors == current.file_descriptors
                                && previous.socket_file_descriptors
                                    == current.socket_file_descriptors
                                && previous.threads == current.threads
                        })
                    });
            if lifecycle_settled && resources_within_final_bounds && stable {
                stable_samples = stable_samples.saturating_add(1);
                if stable_samples >= QUALIFICATION_RESOURCE_STABLE_SAMPLES {
                    return (snapshots, metrics);
                }
            } else {
                stable_samples = 0;
            }
            assert!(
                Instant::now() < deadline,
                "process resources did not semantically settle: metrics={metrics:?}, snapshots={snapshots:?}, warmed={warmed:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            previous = Some(snapshots);
            thread::sleep(Duration::from_millis(QUALIFICATION_RESOURCE_SAMPLE_MILLIS));
        }
    }

    fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown();
        }
    }

    fn assert_plaintext_canaries_absent_from_sqlite(&self) {
        assert!(
            retained_plaintext_canary_domain_counts(&self.canary_values).is_some(),
            "every retained plaintext canary must belong to exactly one fixed qualification domain"
        );
        for database_path in &self.database_paths {
            let artifacts = read_sqlite_family(database_path).unwrap_or_else(|error| {
                panic!(
                    "rotation SQLite family must be readable after shutdown: database={}, error={error}",
                    database_path.display()
                )
            });
            for (path, bytes) in artifacts {
                for prefix_present in plaintext_canary_prefix_presence(&bytes) {
                    assert!(
                        !prefix_present,
                        "plaintext canary reached SQLite persistence at {}",
                        path.display()
                    );
                }
            }
        }
    }

    fn node_stderr(&self, node_index: usize) -> String {
        let Ok(bytes) = fs::read(&self.stderr_paths[node_index]) else {
            return "unavailable".to_owned();
        };
        let tail = &bytes[bytes.len().saturating_sub(8 * 1024)..];
        String::from_utf8_lossy(tail).into_owned()
    }

    fn stderr_diagnostics(&self) -> Vec<String> {
        (0..self.member_count())
            .map(|node_index| self.node_stderr(node_index))
            .collect()
    }
}

fn production_lifecycle_config() -> QualificationConnectionLifecycleConfig {
    QualificationConnectionLifecycleConfig {
        maximum_authentication_age_millis: duration_millis(DEFAULT_MAX_AUTHENTICATION_AGE),
        rotation_drain_window_millis: duration_millis(DEFAULT_ROTATION_DRAIN_WINDOW),
        reconnect_backoff_min_millis: duration_millis(DEFAULT_RECONNECT_BACKOFF_MIN),
        reconnect_backoff_max_millis: duration_millis(DEFAULT_RECONNECT_BACKOFF_MAX),
        rotation_jitter_millis: duration_millis(DEFAULT_ROTATION_JITTER),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).expect("production duration fits milliseconds")
}

fn duration_until_wall_time(deadline: time::OffsetDateTime) -> Duration {
    let remaining_nanos = deadline
        .unix_timestamp_nanos()
        .saturating_sub(time::OffsetDateTime::now_utc().unix_timestamp_nanos());
    if remaining_nanos <= 0 {
        return Duration::ZERO;
    }
    let seconds = remaining_nanos / 1_000_000_000;
    let nanos = remaining_nanos % 1_000_000_000;
    Duration::new(
        u64::try_from(seconds).expect("bounded qualification wall-time seconds"),
        u32::try_from(nanos).expect("subsecond qualification wall-time nanos"),
    )
}

fn wait_for_bind_address_release_by(address: SocketAddr, deadline: Instant) {
    loop {
        match TcpListener::bind(address) {
            Ok(listener) => {
                assert_eq!(
                    listener.local_addr().expect("probe released bind address"),
                    address
                );
                drop(listener);
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                assert!(
                    Instant::now() < deadline,
                    "qualification manifest address remained in use after deliberate child exit: address={address}"
                );
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!(
                "qualification manifest address could not be probed after deliberate child exit: address={address}, error_kind={:?}",
                error.kind()
            ),
        }
    }
}

fn assert_security_metrics_unsaturated(
    node_index: usize,
    metrics: &QualificationSecurityMetricsSnapshot,
) {
    assert_eq!(
        metrics.saturated_series, 0,
        "security metrics saturated during bounded qualification: node={node_index}, metrics={metrics:?}"
    );
    let saturation_flags = [
        metrics.tls_material.success_saturated,
        metrics.tls_material.retained_last_good_saturated,
        metrics.tls_material.rejected_saturated,
        metrics.tls_material.expired_saturated,
        metrics.svid.success_saturated,
        metrics.svid.retained_last_good_saturated,
        metrics.svid.rejected_saturated,
        metrics.svid.expired_saturated,
        metrics.trust_bundle.success_saturated,
        metrics.trust_bundle.retained_last_good_saturated,
        metrics.trust_bundle.rejected_saturated,
        metrics.trust_bundle.expired_saturated,
    ];
    assert!(
        saturation_flags.into_iter().all(|saturated| !saturated),
        "security metric series reported saturation during bounded qualification: node={node_index}, metrics={metrics:?}"
    );
}

fn assert_fault_lifecycle_failures_unchanged(
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
) {
    assert_eq!(before.len(), after.len());
    for (node_index, (before, after)) in before.iter().zip(after).enumerate() {
        assert_eq!(
            after.connection_failure_transport, before.connection_failure_transport,
            "consensus admission loss changed the transport failure ledger: node={node_index}"
        );
        assert_eq!(
            after.connection_failure_authentication, before.connection_failure_authentication,
            "retained malformed trust changed the authentication failure ledger: node={node_index}"
        );
        assert_eq!(
            after.connection_failure_timeout, before.connection_failure_timeout,
            "consensus admission loss changed the timeout failure ledger: node={node_index}"
        );
        assert_eq!(
            after.connection_superseded, before.connection_superseded,
            "consensus admission loss changed the superseded-attempt ledger: node={node_index}"
        );
        assert_eq!(
            after.connection_abandoned, before.connection_abandoned,
            "consensus admission loss changed the abandoned-attempt ledger: node={node_index}"
        );
        assert_eq!(
            after.connection_failure_protocol, before.connection_failure_protocol,
            "consensus admission loss changed the protocol failure ledger: node={node_index}"
        );
        assert_eq!(
            after.connection_failure_backend, before.connection_failure_backend,
            "consensus admission loss changed the connection backend failure ledger: node={node_index}"
        );
        assert_eq!(
            after.reconnect_failures, before.reconnect_failures,
            "consensus admission loss produced an unexpected reconnect failure: node={node_index}"
        );
        assert_eq!(
            after.drain_overruns, before.drain_overruns,
            "consensus admission loss or malformed trust produced a drain overrun: node={node_index}"
        );
    }
}

fn publish_projected_generation(
    root: &Path,
    generation_counter: &mut u64,
    credential: &ProjectedCredential,
    trust_bundle_pem: &str,
) -> Instant {
    publish_projected_files(
        root,
        generation_counter,
        &credential.certificate_chain_pem,
        &credential.private_key_pem,
        trust_bundle_pem,
    )
}

fn publish_projected_files(
    root: &Path,
    generation_counter: &mut u64,
    certificate_chain_pem: &str,
    private_key_pem: &str,
    trust_bundle_pem: &str,
) -> Instant {
    *generation_counter += 1;
    let generation_name = format!("..2026_07_13_{generation_counter:04}");
    let generation = root.join(&generation_name);
    fs::create_dir(&generation).expect("create immutable projected generation");
    fs::write(generation.join("tls.crt"), certificate_chain_pem)
        .expect("write projected certificate chain");
    fs::write(generation.join("tls.key"), private_key_pem).expect("write projected private key");
    fs::write(generation.join("ca.crt"), trust_bundle_pem).expect("write projected trust bundle");

    let next_link = root.join(format!("..data-next-{generation_counter:04}"));
    symlink(&generation_name, &next_link).expect("stage projected generation link");
    fs::rename(&next_link, root.join("..data")).expect("atomically publish projected generation");
    Instant::now()
}

fn sqlite_family_paths(database_path: &Path) -> [PathBuf; 3] {
    let database = database_path.as_os_str().to_string_lossy();
    [
        database_path.to_path_buf(),
        PathBuf::from(format!("{database}-wal")),
        PathBuf::from(format!("{database}-shm")),
    ]
}

fn read_sqlite_family(database_path: &Path) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut artifacts = Vec::with_capacity(3);
    for (index, path) in sqlite_family_paths(database_path).into_iter().enumerate() {
        match fs::read(&path) {
            Ok(bytes) => artifacts.push((path, bytes)),
            Err(error) if index != 0 && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(artifacts)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn retained_plaintext_canary_domain_counts(values: &[String]) -> Option<[usize; 2]> {
    if values.is_empty() {
        return None;
    }
    let mut counts = [0_usize; 2];
    for value in values {
        let matches = PLAINTEXT_CANARY_PREFIXES.map(|prefix| value.as_bytes().starts_with(prefix));
        if matches.into_iter().filter(|matches| *matches).count() != 1 {
            return None;
        }
        for (index, matches) in matches.into_iter().enumerate() {
            if matches {
                counts[index] = counts[index].checked_add(1)?;
            }
        }
    }
    Some(counts)
}

fn plaintext_canary_prefix_presence(bytes: &[u8]) -> [bool; 2] {
    PLAINTEXT_CANARY_PREFIXES.map(|prefix| contains_bytes(bytes, prefix))
}

fn spiffe_id(node_index: usize) -> String {
    format!(
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
    )
}

fn candidate_sha256_file(path: &Path, maximum_bytes: u64) -> io::Result<String> {
    let mut file = open_bounded_candidate_file(path, maximum_bytes)?;
    let mut hasher = Sha256::new();
    let mut encoded = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut encoded)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| io::Error::other("read overflow"))?)
            .ok_or_else(|| io::Error::other("candidate artifact size overflow"))?;
        if total > maximum_bytes {
            return Err(io::Error::other("candidate artifact exceeds its bound"));
        }
        hasher.update(&encoded[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn candidate_configuration_sha256(config_paths: &[PathBuf]) -> io::Result<String> {
    if !matches!(config_paths.len(), 3 | 5) {
        return Err(io::Error::other("candidate topology is unsupported"));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-mtls-candidate-configuration/v2\0");
    for config_path in config_paths {
        let encoded = read_bounded_candidate_file(config_path, QUALIFICATION_MAX_CONFIG_BYTES)?;
        let length = u64::try_from(encoded.len())
            .map_err(|_| io::Error::other("candidate configuration size overflow"))?;
        hasher.update(length.to_be_bytes());
        hasher.update(encoded);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn candidate_source_provenance_at(
    repository: &Path,
) -> io::Result<(String, SessionMtlsCandidateSourceTreeStatus, String)> {
    let revision = candidate_git_output(repository, &["rev-parse", "HEAD"], 64)?;
    if revision.len() != 41 {
        return Err(io::Error::other("candidate source revision is unavailable"));
    }
    let revision = std::str::from_utf8(&revision)
        .map_err(|_| io::Error::other("candidate source revision is invalid"))?
        .trim_end()
        .to_owned();
    let source_status = candidate_git_output(
        repository,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ],
        MAX_CANDIDATE_SOURCE_BYTES,
    )?;
    let tree_status = if source_status.is_empty() {
        SessionMtlsCandidateSourceTreeStatus::Clean
    } else {
        SessionMtlsCandidateSourceTreeStatus::DirtyUnqualified
    };
    let tracked_diff = candidate_git_output(
        repository,
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--ignore-submodules=none",
            "HEAD",
            "--",
        ],
        MAX_CANDIDATE_SOURCE_BYTES,
    )?;
    let untracked_paths = candidate_git_output(
        repository,
        &["ls-files", "--others", "--exclude-standard", "-z", "--"],
        MAX_CANDIDATE_SOURCE_BYTES,
    )?;

    let mut total = u64::try_from(source_status.len())
        .ok()
        .and_then(|status| {
            u64::try_from(tracked_diff.len())
                .ok()
                .and_then(|diff| status.checked_add(diff))
        })
        .and_then(|total| {
            u64::try_from(untracked_paths.len())
                .ok()
                .and_then(|paths| total.checked_add(paths))
        })
        .ok_or_else(|| io::Error::other("candidate source size overflow"))?;
    if total > MAX_CANDIDATE_SOURCE_BYTES {
        return Err(io::Error::other("candidate source exceeds its bound"));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-mtls-candidate-source/v2\0");
    hash_candidate_source_part(&mut hasher, b"revision", revision.as_bytes())?;
    hash_candidate_source_part(&mut hasher, b"status", &source_status)?;
    hash_candidate_source_part(&mut hasher, b"tracked-diff", &tracked_diff)?;
    for encoded_path in untracked_paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = PathBuf::from(std::ffi::OsString::from_vec(encoded_path.to_vec()));
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::other(
                "candidate untracked source path is invalid",
            ));
        }
        let remaining = MAX_CANDIDATE_SOURCE_BYTES
            .checked_sub(total)
            .ok_or_else(|| io::Error::other("candidate source exceeds its bound"))?;
        let encoded = read_bounded_candidate_file(&repository.join(&relative), remaining)?;
        total = total
            .checked_add(
                u64::try_from(encoded.len())
                    .map_err(|_| io::Error::other("candidate source size overflow"))?,
            )
            .ok_or_else(|| io::Error::other("candidate source size overflow"))?;
        hash_candidate_source_part(&mut hasher, b"untracked-path", encoded_path)?;
        hash_candidate_source_part(&mut hasher, b"untracked-bytes", &encoded)?;
    }
    Ok((
        revision,
        tree_status,
        format!("sha256:{:x}", hasher.finalize()),
    ))
}

fn candidate_git_output(
    repository: &Path,
    arguments: &[&str],
    maximum_bytes: u64,
) -> io::Result<Vec<u8>> {
    let mut child = Command::new("git")
        .args(arguments)
        .env("LC_ALL", "C")
        .current_dir(repository)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("candidate source stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("candidate source stderr is unavailable"))?;
    let stderr_reader = match thread::Builder::new()
        .name("candidate-git-stderr".to_owned())
        .spawn(move || drain_candidate_git_stderr(stderr))
    {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let stdout_result = read_bounded_stream(stdout, maximum_bytes);
    if stdout_result.is_err() {
        let _ = child.kill();
    }
    let status = match child.wait() {
        Ok(status) => Ok(status),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    };
    let stderr_clean = stderr_reader
        .join()
        .map_err(|_| io::Error::other("candidate source stderr reader panicked"))??;
    let status = status?;
    let stdout = stdout_result?;
    if !status.success() || !stderr_clean {
        return Err(io::Error::other("candidate source state is unavailable"));
    }
    Ok(stdout)
}

fn read_bounded_stream<R: Read>(mut reader: R, maximum_bytes: u64) -> io::Result<Vec<u8>> {
    let initial_capacity = usize::try_from(maximum_bytes.min(64 * 1024))
        .map_err(|_| io::Error::other("candidate source size overflow"))?;
    let mut encoded = Vec::with_capacity(initial_capacity);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(encoded);
        }
        total = total
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| io::Error::other("candidate source size overflow"))?,
            )
            .ok_or_else(|| io::Error::other("candidate source size overflow"))?;
        if total > maximum_bytes {
            return Err(io::Error::other("candidate source exceeds its bound"));
        }
        encoded.extend_from_slice(&buffer[..read]);
    }
}

fn drain_candidate_git_stderr<R: Read>(mut reader: R) -> io::Result<bool> {
    let mut buffer = [0_u8; 8 * 1024];
    let mut empty = true;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(empty);
        }
        empty = false;
    }
}

fn hash_candidate_source_part(hasher: &mut Sha256, label: &[u8], encoded: &[u8]) -> io::Result<()> {
    let label_length = u64::try_from(label.len())
        .map_err(|_| io::Error::other("candidate source label overflow"))?;
    let encoded_length = u64::try_from(encoded.len())
        .map_err(|_| io::Error::other("candidate source length overflow"))?;
    hasher.update(label_length.to_be_bytes());
    hasher.update(label);
    hasher.update(encoded_length.to_be_bytes());
    hasher.update(encoded);
    Ok(())
}

fn candidate_source_provenance(
) -> io::Result<(String, SessionMtlsCandidateSourceTreeStatus, String)> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    candidate_source_provenance_at(&repository)
}

fn write_private_candidate_file(path: &Path, encoded: &[u8]) -> io::Result<()> {
    let descriptor = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    fchmod(&descriptor, Mode::from_raw_mode(0o600))?;
    let metadata = fstat(&descriptor)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "candidate evidence output is not a private regular file",
        ));
    }
    let mut file = File::from(descriptor);
    file.write_all(encoded)?;
    file.flush()?;
    file.sync_all()
}

fn open_bounded_candidate_file(path: &Path, maximum_bytes: u64) -> io::Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let metadata = fstat(&descriptor)?;
    let length = u64::try_from(metadata.st_size)
        .map_err(|_| io::Error::other("candidate evidence size is invalid"))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file() || length > maximum_bytes {
        return Err(io::Error::other(
            "candidate evidence artifact is not a bounded regular file",
        ));
    }
    Ok(File::from(descriptor))
}

fn read_bounded_candidate_file(path: &Path, maximum_bytes: u64) -> io::Result<Vec<u8>> {
    let file = open_bounded_candidate_file(path, maximum_bytes)?;
    let file_metadata = file.metadata()?;
    let capacity = usize::try_from(file_metadata.len())
        .map_err(|_| io::Error::other("candidate evidence size overflow"))?;
    let mut encoded = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut encoded)?;
    if u64::try_from(encoded.len()).map_or(true, |size| size > maximum_bytes) {
        return Err(io::Error::other("candidate evidence exceeds its bound"));
    }
    Ok(encoded)
}

fn preserve_mtls_candidate_evidence(
    campaign: SessionMtlsCandidateCampaign,
    member_count: usize,
    evidence_path: &Path,
    schema_path: &Path,
) -> io::Result<()> {
    let Some(configured_root) = env::var_os(EVIDENCE_OUTPUT_DIRECTORY_ENV) else {
        return Ok(());
    };
    preserve_mtls_candidate_evidence_at(
        &PathBuf::from(configured_root),
        campaign,
        member_count,
        evidence_path,
        schema_path,
    )
}

fn preserve_mtls_candidate_evidence_at(
    configured_root: &Path,
    campaign: SessionMtlsCandidateCampaign,
    member_count: usize,
    evidence_path: &Path,
    schema_path: &Path,
) -> io::Result<()> {
    if !configured_root.is_absolute() {
        return Err(io::Error::other("candidate evidence root must be absolute"));
    }
    if !matches!(member_count, 3 | 5) {
        return Err(io::Error::other("candidate evidence topology is invalid"));
    }
    let evidence = read_bounded_candidate_file(evidence_path, MAX_CANDIDATE_EVIDENCE_BYTES)?;
    let schema = read_bounded_candidate_file(schema_path, MAX_CANDIDATE_EVIDENCE_BYTES)?;
    let mut root_builder = DirBuilder::new();
    root_builder.recursive(true).mode(0o700);
    root_builder.create(configured_root)?;
    let canonical_root = fs::canonicalize(configured_root)?;
    if canonical_root != configured_root {
        return Err(io::Error::other("candidate evidence root is invalid"));
    }
    let root_descriptor = open(
        &canonical_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let root_metadata = fstat(&root_descriptor)?;
    if !FileType::from_raw_mode(root_metadata.st_mode).is_dir()
        || Mode::from_raw_mode(root_metadata.st_mode).bits() & 0o777 != 0o700
    {
        return Err(io::Error::other("candidate evidence root is invalid"));
    }

    let destination_name = format!("mtls-v2-{}-{member_count}-node", campaign.as_str());
    let staging_name = create_candidate_staging_directory(&root_descriptor)?;
    let staging_descriptor = match openat(
        &root_descriptor,
        staging_name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = unlinkat(&root_descriptor, staging_name.as_str(), AtFlags::REMOVEDIR);
            return Err(error.into());
        }
    };
    let mut published = false;
    let staged_result = (|| -> io::Result<()> {
        fchmod(&staging_descriptor, Mode::from_raw_mode(0o700))?;
        let staging_metadata = fstat(&staging_descriptor)?;
        if !FileType::from_raw_mode(staging_metadata.st_mode).is_dir()
            || Mode::from_raw_mode(staging_metadata.st_mode).bits() & 0o777 != 0o700
        {
            return Err(io::Error::other(
                "candidate evidence staging directory is invalid",
            ));
        }
        write_private_candidate_file_at(&staging_descriptor, "evidence.json", &evidence)?;
        write_private_candidate_file_at(&staging_descriptor, "evidence.schema.json", &schema)?;
        fsync(&staging_descriptor)?;
        renameat_with(
            &root_descriptor,
            staging_name.as_str(),
            &root_descriptor,
            destination_name.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        published = true;
        fsync(&root_descriptor)?;
        Ok(())
    })();
    if staged_result.is_err() && !published {
        cleanup_candidate_staging_directory(&root_descriptor, &staging_descriptor, &staging_name);
    }
    staged_result
}

fn create_candidate_staging_directory<Fd: AsFd>(root_descriptor: Fd) -> io::Result<String> {
    for _ in 0..32 {
        let sequence = CANDIDATE_STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(".mtls-v2-staging-{}-{sequence}", std::process::id());
        match mkdirat(&root_descriptor, name.as_str(), Mode::from_raw_mode(0o700)) {
            Ok(()) => return Ok(name),
            Err(error) if io::Error::from(error).kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::other(
        "candidate evidence staging namespace is exhausted",
    ))
}

fn write_private_candidate_file_at<Fd: AsFd>(
    directory: Fd,
    name: &str,
    encoded: &[u8],
) -> io::Result<()> {
    let descriptor = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    fchmod(&descriptor, Mode::from_raw_mode(0o600))?;
    let metadata = fstat(&descriptor)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "candidate evidence output is not a private regular file",
        ));
    }
    let mut file = File::from(descriptor);
    file.write_all(encoded)?;
    file.flush()?;
    file.sync_all()
}

fn cleanup_candidate_staging_directory<RootFd: AsFd, StagingFd: AsFd>(
    root_descriptor: RootFd,
    staging_descriptor: StagingFd,
    staging_name: &str,
) {
    for name in ["evidence.json", "evidence.schema.json"] {
        let _ = unlinkat(&staging_descriptor, name, AtFlags::empty());
    }
    let _ = unlinkat(&root_descriptor, staging_name, AtFlags::REMOVEDIR);
}

fn ensure_candidate_evidence_feature_profile() -> io::Result<()> {
    if cfg!(feature = "foundation-insecure") {
        return Err(io::Error::other(
            "candidate evidence is disabled when foundation-insecure is compiled",
        ));
    }
    Ok(())
}

fn emit_mtls_candidate_evidence(
    fleet: &Fleet,
    campaign: SessionMtlsCandidateCampaign,
) -> io::Result<()> {
    ensure_candidate_evidence_feature_profile()?;
    let member_count = fleet.member_count();
    fleet
        .candidate_evidence_inputs
        .verify_unchanged(&fleet.config_paths)?;
    let directed_path_count = member_count
        .checked_mul(member_count.saturating_sub(1))
        .ok_or_else(|| io::Error::other("candidate topology path count overflow"))?;
    let public_material_manifest_sha256 = fleet.candidate_public_material_manifest.sha256()?;
    let workload_schedule_sha256 =
        session_mtls_candidate_schedule_sha256(campaign, member_count)
            .ok_or_else(|| io::Error::other("candidate topology is unsupported"))?;
    let document = serde_json::json!({
        "schema_version": "opc-session-mtls-candidate-evidence/v2",
        "experimental": true,
        "qualification_complete": false,
        "source": {
            "revision": fleet.candidate_evidence_inputs.source_revision,
            "tree_status": fleet.candidate_evidence_inputs.source_tree_status,
            "worktree_sha256": fleet.candidate_evidence_inputs.source_worktree_sha256,
        },
        "artifact": {
            "name": "opc-session-quorum-node",
            "version": env!("CARGO_PKG_VERSION"),
            "sha256": fleet.candidate_evidence_inputs.child_sha256,
            "harness_name": "qualification_mtls_multiprocess",
            "harness_sha256": fleet.candidate_evidence_inputs.harness_sha256,
            "insecure_test_enabled": cfg!(feature = "foundation-insecure"),
        },
        "campaign": campaign,
        "topology": {
            "members": member_count,
            "distinct_processes": true,
            "distinct_sqlite_databases": true,
            "transport_mode": "projected_svid_mtls_pinned_loopback",
            "directed_path_count": directed_path_count,
            "counts_for_seamless_tls_rotation": false,
        },
        "bindings": {
            "evidence_schema_sha256": opc_session_testkit::qualification::session_mtls_candidate_evidence_v2_schema_sha256(),
            "configuration_sha256": fleet.candidate_evidence_inputs.configuration_sha256,
            "public_material_manifest_sha256": public_material_manifest_sha256,
            "workload_schedule_sha256": workload_schedule_sha256,
        },
        "observations": {
            "material_status_collected": true,
            "durable_readiness_reached": true,
            "directed_fresh_handshakes_succeeded": true,
            "lifecycle_metrics_collected": true,
            "encrypted_canary_verified": true,
            "plaintext_canary_absent_from_sqlite_family": true,
        },
        "coverage": campaign.coverage(),
        "remaining_acceptance": SessionMtlsCandidateEvidenceV2::required_remaining_acceptance(),
    });
    let evidence: SessionMtlsCandidateEvidenceV2 = serde_json::from_value(document)
        .map_err(|_| io::Error::other("candidate evidence construction failed"))?;
    evidence
        .validate()
        .map_err(|_| io::Error::other("candidate evidence validation failed"))?;
    let mut encoded = serde_json::to_vec_pretty(&evidence)
        .map_err(|_| io::Error::other("candidate evidence encoding failed"))?;
    encoded.push(b'\n');
    if u64::try_from(encoded.len()).map_or(true, |size| size > MAX_CANDIDATE_EVIDENCE_BYTES) {
        return Err(io::Error::other("candidate evidence exceeds its bound"));
    }

    let workspace = tempfile::tempdir()?;
    let evidence_path = workspace.path().join("evidence.json");
    let schema_path = workspace.path().join("evidence.schema.json");
    write_private_candidate_file(&evidence_path, &encoded)?;
    write_private_candidate_file(
        &schema_path,
        SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_JSON.as_bytes(),
    )?;
    let decoded: SessionMtlsCandidateEvidenceV2 = serde_json::from_slice(
        &read_bounded_candidate_file(&evidence_path, MAX_CANDIDATE_EVIDENCE_BYTES)?,
    )
    .map_err(|_| io::Error::other("candidate evidence round trip failed"))?;
    decoded
        .validate()
        .map_err(|_| io::Error::other("candidate evidence round trip is invalid"))?;
    preserve_mtls_candidate_evidence(campaign, member_count, &evidence_path, &schema_path)
}

fn assert_mtls_candidate_evidence_emission(fleet: &Fleet, campaign: SessionMtlsCandidateCampaign) {
    let result = emit_mtls_candidate_evidence(fleet, campaign);
    if cfg!(feature = "foundation-insecure") {
        assert!(
            result.is_err(),
            "candidate evidence must be rejected when foundation-insecure is compiled"
        );
    } else {
        result.expect("emit validated mTLS candidate evidence");
    }
}

fn run_projected_mtls_fault_and_expiry_recovery(member_count: usize) {
    const MALFORMED_TRUST_BUNDLE: &str =
        "-----BEGIN CERTIFICATE-----\nqualification-malformed\n-----END CERTIFICATE-----\n";

    let mut fleet = Fleet::start_traffic(member_count);

    // Keep node 0 in the survivor quorum because it owns the fixed canary lease.
    // A different stable follower loses consensus RPC admission while node 0
    // atomically publishes malformed trust and retains its exact last-good
    // identity. This is a test-control fault, not a network partition.
    let isolated_node_index = fleet.stable_nonzero_follower();
    let all_node_indices = (0..member_count).collect::<Vec<_>>();
    let survivor_node_indices = all_node_indices
        .iter()
        .copied()
        .filter(|node_index| *node_index != isolated_node_index)
        .collect::<Vec<_>>();
    let initial_traffic =
        TrafficParticipants::try_new(member_count, &all_node_indices, &survivor_node_indices)
            .expect("bounded fault traffic participants");
    fleet.start_subset_traffic_tasks(&initial_traffic, "fault-traffic-warmup");
    let survivor_traffic =
        TrafficParticipants::try_new(member_count, &survivor_node_indices, &survivor_node_indices)
            .expect("bounded survivor traffic participants");
    let malformed_node_index = 0;
    let malformed_source_before = fleet.projected_status(malformed_node_index);
    let malformed_controller_before = fleet.material_status(malformed_node_index);
    let malformed_security_before = fleet.security_metrics(malformed_node_index);
    assert_security_metrics_unsaturated(malformed_node_index, &malformed_security_before);
    let fault_lifecycle_before = fleet.all_lifecycle_metrics();

    fleet.set_consensus_rpc_availability(
        isolated_node_index,
        QualificationConsensusRpcAvailability::Unavailable,
    );
    fleet.wait_for_isolated_member_and_survivors(isolated_node_index);
    fleet.publish_known_projected_generation_with_trust(
        malformed_node_index,
        CredentialGeneration::Initial,
        MALFORMED_TRUST_BUNDLE,
        "malformed-trust-retain-last-good",
    );
    let malformed_security = fleet.wait_for_malformed_trust_retention(
        malformed_node_index,
        malformed_source_before,
        malformed_controller_before,
        malformed_security_before,
    );
    fleet.wait_for_isolated_member_and_survivors(isolated_node_index);
    let fault_traffic_after_boundary = fleet.traffic_statuses_on(&survivor_node_indices);
    fleet.advance_canary_for_survivors(
        isolated_node_index,
        "consensus-unavailable-malformed-retained",
    );
    fleet.wait_for_subset_traffic_progress(
        &fault_traffic_after_boundary,
        &survivor_traffic,
        "consensus-unavailable-malformed-retained",
        Instant::now() + CLUSTER_TRANSITION_TIMEOUT,
    );
    let fault_lifecycle_after = fleet.all_lifecycle_metrics();
    assert_fault_lifecycle_failures_unchanged(&fault_lifecycle_before, &fault_lifecycle_after);

    fleet.restart_node_at_manifest_address(isolated_node_index);
    let restarted_watch = fleet.reconcile_traffic_watch_on(isolated_node_index);
    assert_eq!(
        restarted_watch.status.state,
        QualificationTrafficState::WatchReady
    );
    assert_eq!(
        restarted_watch.status.watch_traffic_generations[isolated_node_index], 0,
        "the unavailable watcher-only node must not acquire hidden mutation work"
    );
    for survivor in &survivor_node_indices {
        assert!(
            restarted_watch.status.watch_traffic_generations[*survivor] > 0,
            "the exact-address restart must reconcile every survivor traffic key"
        );
    }
    fleet.start_traffic_mutations_on(&[isolated_node_index]);
    let all_traffic =
        TrafficParticipants::try_new(member_count, &all_node_indices, &all_node_indices)
            .expect("bounded full-fleet traffic participants");
    let restart_traffic_before = fleet.traffic_statuses_on(&all_node_indices);
    let restart_traffic_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    fleet.verify_canary();
    fleet.advance_canary("exact-address-restart-recovered");
    fleet.wait_for_subset_traffic_progress(
        &restart_traffic_before,
        &all_traffic,
        "exact-address-restart-reconciled",
        restart_traffic_deadline,
    );

    let repair_source_before = fleet.projected_status(malformed_node_index);
    let repair_controller_before = fleet.material_status(malformed_node_index);
    fleet.publish_known_projected_generation(
        malformed_node_index,
        CredentialGeneration::Initial,
        TrustGeneration::OldOnly,
        "malformed-trust-repair",
    );
    fleet.wait_for_member_recovery_publication(
        malformed_node_index,
        repair_source_before.generation,
        repair_controller_before.epoch,
    );
    fleet.fresh_all_directed_generation();
    fleet.wait_ready();
    fleet.wait_for_malformed_retry_to_stop(
        malformed_node_index,
        malformed_security.trust_bundle.retained_last_good,
    );
    let repair_traffic_after_boundary = fleet.traffic_statuses_on(&all_node_indices);
    let repair_traffic_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    fleet.advance_canary("malformed-trust-repaired");
    fleet.wait_for_subset_traffic_progress(
        &repair_traffic_after_boundary,
        &all_traffic,
        "malformed-trust-repaired-under-traffic",
        repair_traffic_deadline,
    );

    // Exercise exactly one unclean, same-disk, exact-address restart while the
    // selected follower owns an active mutation and watch task. The survivor
    // majority must commit during the outage; the restarted process may resume
    // only from its exact bounded journal plus linearizable record proof and
    // must then mutate under a strictly higher fence.
    let active_restart_node_index = fleet.stable_nonzero_follower();
    fleet.restart_active_mutator_at_manifest_address(active_restart_node_index);

    // Publish a same-issuer leaf with a 75-second remaining-validity/expiry
    // budget to a stable nonzero follower, establish fresh authenticated paths,
    // and retain the PID so recovery can prove a same-process material
    // replacement.
    let expiring_node_index = fleet.stable_nonzero_follower();
    let expiry_survivor_indices = all_node_indices
        .iter()
        .copied()
        .filter(|node_index| *node_index != expiring_node_index)
        .collect::<Vec<_>>();
    let expiry_survivor_traffic = TrafficParticipants::try_new(
        member_count,
        &expiry_survivor_indices,
        &expiry_survivor_indices,
    )
    .expect("bounded expiry survivor traffic participants");
    let expiring_process_id = fleet.nodes[expiring_node_index].process_id();
    let expiring_source_before = fleet.projected_status(expiring_node_index);
    let expiring_controller_before = fleet.material_status(expiring_node_index);
    let expiring_security_before = fleet.security_metrics(expiring_node_index);
    assert_security_metrics_unsaturated(expiring_node_index, &expiring_security_before);
    let (expiring_credential, not_after) = fleet.pki.expiring_workload(expiring_node_index);
    let old_trust = fleet.pki.trust_bundle(TrustGeneration::OldOnly);
    fleet.publish_custom_projected_generation(
        expiring_node_index,
        &expiring_credential,
        &old_trust,
        "short-lived-svid",
    );
    fleet.wait_for_member_publication(
        expiring_node_index,
        expiring_source_before.generation,
        expiring_controller_before.epoch,
    );
    let expiring_source = fleet.projected_status(expiring_node_index);
    let expiring_controller = fleet.material_status(expiring_node_index);
    let expected_expiry = Timestamp::from_offset_datetime(not_after);
    assert_eq!(expiring_controller.leaf_expires_at, Some(expected_expiry));
    assert_eq!(
        expiring_controller.certificate_chain_expires_at,
        Some(expected_expiry)
    );
    let security_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    let expiring_security = loop {
        let security = fleet.security_metrics(expiring_node_index);
        assert_security_metrics_unsaturated(expiring_node_index, &security);
        if security.svid_expires_seconds == not_after.unix_timestamp()
            && security.bundle_version == expiring_controller.epoch
        {
            break security;
        }
        assert!(
            Instant::now() < security_deadline,
            "accepted short-lived SVID was not reflected in fixed security gauges: node={expiring_node_index}, controller={expiring_controller:?}, security={security:?}, stderr={}",
            fleet.node_stderr(expiring_node_index)
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        expiring_security.svid.expired,
        expiring_security_before.svid.expired
    );

    let lifecycle_setup_before = fleet.all_lifecycle_metrics();
    fleet.fresh_all_directed_generation();
    fleet.wait_ready();
    fleet.advance_canary("short-lived-svid-ready");
    let lifecycle_before_expiry = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_setup_before,
        Instant::now() + CLUSTER_TRANSITION_TIMEOUT,
        "short-lived-svid-connection-setup",
    );
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    assert_epoch_changing_lifecycle_delta_bounds(
        member_count,
        &lifecycle_setup_before,
        &lifecycle_before_expiry,
        remote_peers,
    );
    let short_leaf_traffic_after_boundary = fleet.traffic_statuses_on(&all_node_indices);
    let short_leaf_traffic_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    fleet.wait_for_subset_traffic_progress(
        &short_leaf_traffic_after_boundary,
        &all_traffic,
        "short-lived-svid-published-under-traffic",
        short_leaf_traffic_deadline,
    );
    let soft_retirement_at = not_after
        - time::Duration::try_from(DEFAULT_ROTATION_DRAIN_WINDOW)
            .expect("rotation drain window fits time duration");
    assert!(
        time::OffsetDateTime::now_utc() < soft_retirement_at,
        "short-lived SVID setup did not complete before its soft-retirement deadline"
    );

    let traffic_stop_at = soft_retirement_at
        - time::Duration::try_from(Duration::from_millis(
            QUALIFICATION_FAULT_TRAFFIC_STOP_LEAD_MILLIS,
        ))
        .expect("fault traffic-stop lead fits time duration");
    let mutation_shutdown_bound = time::Duration::try_from(Duration::from_millis(
        QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS,
    ))
    .expect("fault mutation-shutdown lead fits time duration");
    let mutation_shutdown_start_at = traffic_stop_at - mutation_shutdown_bound;
    fleet.keep_member_directed_paths_alive_until(expiring_node_index, mutation_shutdown_start_at);
    let stopped_expiring_mutation = fleet.stop_traffic_mutations_on(&[expiring_node_index]);
    assert!(
        time::OffsetDateTime::now_utc() <= traffic_stop_at,
        "expiring-node mutation shutdown exceeded its fixed pre-retirement bound"
    );
    fleet.keep_member_directed_paths_alive_until(expiring_node_index, traffic_stop_at);
    let stopped_expiring_watch = fleet.stop_traffic_watches_on(&[expiring_node_index]);
    assert!(
        time::OffsetDateTime::now_utc() < soft_retirement_at,
        "expiring-node watch shutdown crossed the fixed soft-retirement boundary"
    );
    assert_eq!(
        stopped_expiring_watch[0].status.mutation_cycles,
        stopped_expiring_mutation[0].status.mutation_cycles
    );
    assert_eq!(
        stopped_expiring_watch[0].status.last_generation,
        stopped_expiring_mutation[0].status.last_generation
    );
    let stopped_expiring_status = stopped_expiring_watch[0].status.clone();
    fleet.wait_for_expiry_soft_retirement(expiring_node_index, &lifecycle_before_expiry, not_after);
    assert!(
        time::OffsetDateTime::now_utc() < not_after,
        "soft retirement was not observed strictly before hard expiry"
    );
    let traffic_after_soft_boundary = fleet.traffic_statuses_on(&expiry_survivor_indices);
    let soft_traffic_deadline = Instant::now() + duration_until_wall_time(not_after);
    fleet.wait_for_subset_traffic_progress(
        &traffic_after_soft_boundary,
        &expiry_survivor_traffic,
        "survivor-traffic-through-soft-retirement",
        soft_traffic_deadline,
    );
    assert!(
        time::OffsetDateTime::now_utc() < not_after,
        "hard-expiry work cannot satisfy soft-retirement traffic progress"
    );
    let (expired_security, _) = fleet.wait_for_expired_member_state(
        expiring_node_index,
        expiring_source.generation,
        expiring_controller.epoch,
        expiring_security,
        &lifecycle_before_expiry,
        not_after,
    );
    fleet.wait_for_isolated_member_and_survivors(expiring_node_index);
    let traffic_after_hard_expiry_boundary = fleet.traffic_statuses_on(&expiry_survivor_indices);
    let hard_traffic_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    fleet.advance_canary_for_survivors(expiring_node_index, "short-lived-svid-expired");
    fleet.wait_for_subset_traffic_progress(
        &traffic_after_hard_expiry_boundary,
        &expiry_survivor_traffic,
        "survivor-traffic-through-hard-expiry",
        hard_traffic_deadline,
    );

    let survivor_node_index = (0..member_count)
        .find(|node_index| *node_index != expiring_node_index)
        .expect("survivor member");
    assert!(matches!(
        fleet.nodes[expiring_node_index].invoke(&QualificationNodeCommand::DirectedHandshake {
            remote_node_index: survivor_node_index,
        }),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::MaterialUnavailable,
        }
    ));
    assert!(matches!(
        fleet.nodes[survivor_node_index].invoke(&QualificationNodeCommand::DirectedHandshake {
            remote_node_index: expiring_node_index,
        }),
        QualificationNodeReply::Error {
            code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
        }
    ));

    let replacement_source_before = fleet.projected_status(expiring_node_index);
    let replacement_controller_before = fleet.material_status(expiring_node_index);
    let replacement_traffic_baseline =
        fleet.traffic_status_snapshots_on(&expiry_survivor_traffic.observers);
    let mut replacement_traffic_progress =
        RecoveryTrafficProgressTracker::new(replacement_traffic_baseline.clone(), Instant::now());
    let prepublication_progress_deadline = replacement_traffic_progress.pulse_deadline();
    fleet.wait_for_recovery_traffic_progress(
        &replacement_traffic_baseline,
        &mut replacement_traffic_progress,
        &expiry_survivor_traffic,
        "replacement-prepublication-progress",
        prepublication_progress_deadline,
    );
    let publication_stage_deadline =
        replacement_traffic_progress.next_deadline(replacement_traffic_progress.pulse_deadline());
    let replacement_recovery_started = fleet.publish_known_projected_generation(
        expiring_node_index,
        CredentialGeneration::RenewedLeaf,
        TrustGeneration::OldOnly,
        "same-process-material-recovery",
    );
    assert!(
        deadline_allows_completion(replacement_recovery_started, publication_stage_deadline),
        "projected replacement staging exceeded the survivor-progress checkpoint"
    );
    let replacement_recovery_deadline = replacement_recovery_started
        + Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_SETTLEMENT_DEADLINE_MILLIS);
    fleet.wait_for_member_recovery_publication_by(
        expiring_node_index,
        replacement_source_before.generation,
        replacement_controller_before.epoch,
        replacement_traffic_progress.next_deadline(replacement_recovery_deadline),
    );
    fleet.wait_for_recovery_traffic_progress(
        &replacement_traffic_baseline,
        &mut replacement_traffic_progress,
        &expiry_survivor_traffic,
        "replacement-publication",
        replacement_recovery_deadline,
    );
    assert_eq!(
        fleet.nodes[expiring_node_index].process_id(),
        expiring_process_id,
        "short-lived SVID recovery must reload material in the same process"
    );
    let replacement_traffic_after_boundary =
        fleet.complete_recovered_member_phase_under_traffic(RecoveredMemberPhaseContext {
            member: expiring_node_index,
            participants: &expiry_survivor_traffic,
            phase: "short-lived-svid-replacement-recovered",
            fault_lifecycle_before: &lifecycle_before_expiry,
            traffic_availability_baseline: &replacement_traffic_baseline,
            traffic_progress: replacement_traffic_progress,
            recovery_started: replacement_recovery_started,
            recovery_deadline: replacement_recovery_deadline,
        });
    let replacement_traffic_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    let replacement_phase = format!(
        "survivor-traffic-through-material-replacement/active-restart-{active_restart_node_index}/expiring-{expiring_node_index}"
    );
    fleet.wait_for_subset_traffic_progress(
        &replacement_traffic_after_boundary,
        &expiry_survivor_traffic,
        &replacement_phase,
        replacement_traffic_deadline,
    );
    let reconciled_expiring_watch = fleet.reconcile_traffic_watch_on(expiring_node_index);
    assert_eq!(
        reconciled_expiring_watch.status.state,
        QualificationTrafficState::MutationStopped
    );
    assert_eq!(
        reconciled_expiring_watch.status.mutation_cycles,
        stopped_expiring_status.mutation_cycles
    );
    assert_eq!(
        reconciled_expiring_watch.status.last_generation,
        stopped_expiring_status.last_generation
    );
    assert_eq!(
        reconciled_expiring_watch.status.last_record_fence,
        stopped_expiring_status.last_record_fence
    );
    assert_eq!(
        reconciled_expiring_watch.status.watch_reconciliations,
        stopped_expiring_status.watch_reconciliations + 1
    );
    assert!(
        reconciled_expiring_watch.status.watch_reconciled_sequence
            > stopped_expiring_status.watch_sequence
    );
    assert_eq!(
        reconciled_expiring_watch.status.watch_traffic_generations[expiring_node_index],
        stopped_expiring_status.last_generation
    );
    for survivor in &expiry_survivor_indices {
        assert!(
            reconciled_expiring_watch.status.watch_traffic_generations[*survivor]
                > stopped_expiring_status.watch_traffic_generations[*survivor],
            "reconciled watcher did not catch up the active survivor key: node={survivor}"
        );
    }
    let rejoined_traffic =
        TrafficParticipants::try_new(member_count, &all_node_indices, &expiry_survivor_indices)
            .expect("bounded rejoined traffic participants");
    let rejoined_traffic_before = fleet.traffic_statuses_on(&all_node_indices);
    let rejoined_traffic_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    fleet.wait_for_subset_traffic_progress(
        &rejoined_traffic_before,
        &rejoined_traffic,
        "reconciled-watch-after-material-replacement",
        rejoined_traffic_deadline,
    );
    let recovered_controller = fleet.material_status(expiring_node_index);
    let recovered_security = fleet.security_metrics(expiring_node_index);
    assert_security_metrics_unsaturated(expiring_node_index, &recovered_security);
    assert_eq!(
        recovered_security.bundle_version,
        recovered_controller.epoch
    );
    assert_eq!(
        recovered_security.svid_expires_seconds,
        recovered_controller
            .certificate_chain_expires_at
            .expect("recovered certificate-chain expiry")
            .as_offset_datetime()
            .unix_timestamp()
    );
    assert_eq!(
        recovered_security.svid.expired,
        expired_security.svid.expired
    );

    let final_mutation_statuses = fleet.stop_traffic_mutations_on(&expiry_survivor_indices);
    let final_watch_statuses = fleet.wait_for_watch_heads();
    for stopped in &final_mutation_statuses {
        let caught_up = &final_watch_statuses[stopped.node_index];
        assert_eq!(stopped.status.last_generation, caught_up.last_generation);
        assert_eq!(
            stopped.status.last_record_fence,
            caught_up.last_record_fence
        );
    }
    fleet.verify_all_traffic_records(&final_watch_statuses);
    let expected_generations = final_watch_statuses
        .iter()
        .map(|status| status.last_generation)
        .collect::<Vec<_>>();
    for (node_index, status) in final_watch_statuses.iter().enumerate() {
        assert_eq!(
            status.watch_traffic_generations, expected_generations,
            "final watch did not converge on every exact traffic generation: node={node_index}"
        );
    }
    let stopped_watches = fleet.stop_traffic_watches();
    fleet.retain_traffic_plaintext_canaries(&stopped_watches);
    fleet.shutdown();
    fleet.assert_plaintext_canaries_absent_from_sqlite();
    assert_mtls_candidate_evidence_emission(
        &fleet,
        SessionMtlsCandidateCampaign::FaultExpiryRecovery,
    );
    assert!(fleet.workspace.path().is_dir());
}

fn run_projected_mtls_rotation_core(member_count: usize) {
    let mut fleet = Fleet::start(member_count);

    // Publish trust overlap to every member before any member changes issuer.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::Initial,
            TrustGeneration::Overlap,
            &format!("overlap-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("overlap-complete");

    // Renew only each leaf/key while retaining the old presented intermediate.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("renew-leaf-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("leaf-renewal-complete");

    // Rotate the old-root intermediate one member at a time, then perform an
    // exact fleet rollback before any trust-anchor cutover.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RotatedIntermediate,
            TrustGeneration::Overlap,
            &format!("rotate-intermediate-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("intermediate-rotation-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("rollback-intermediate-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("intermediate-rollback-complete");

    // Move to chains under the new root, roll the entire fleet back while
    // overlap remains, and move forward again before removing old trust.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("forward-new-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("new-root-forward-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("rollback-new-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("new-root-rollback-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("resume-new-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("new-root-resume-complete");

    // Remove the old root one member at a time only after every member serves
    // the new chain.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("remove-old-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("old-root-removal-complete");
    fleet.assert_old_client_chains_rejected();

    // A rollback after removal is overlap-first: restore old trust everywhere
    // while all members still present the new chain, then roll chains back one
    // member at a time. No plaintext or weakened identity mode is introduced.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("restore-overlap-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("overlap-restore-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("rollback-after-removal-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("post-removal-rollback-complete");

    // Exit in the intended new-only state after proving the rollback path.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("final-forward-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("final-forward-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("final-new-only-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("final-new-only-complete");
    assert_eq!(
        fleet.canary_generation, 13,
        "initial canary plus every completed fleet phase"
    );

    for node in &mut fleet.nodes {
        match node.invoke(&QualificationNodeCommand::LifecycleMetrics) {
            QualificationNodeReply::LifecycleMetrics { metrics } => {
                assert!(metrics.connection_attempts >= (member_count - 1) as u64);
                assert!(metrics.connection_successes >= (member_count - 1) as u64);
                assert!(
                    metrics.connection_successes > metrics.connection_failure_authentication,
                    "successful reauthentication must dominate rejected transitional attempts"
                );
            }
            reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
        }
    }

    fleet.shutdown();
    fleet.assert_plaintext_canaries_absent_from_sqlite();
    assert_mtls_candidate_evidence_emission(&fleet, SessionMtlsCandidateCampaign::RotationCore);
    assert!(fleet.workspace.path().is_dir());
}

fn run_projected_mtls_rotation_campaign_under_traffic(
    fleet: &mut Fleet,
    member_count: usize,
    lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
) {
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::Initial,
            TrustGeneration::Overlap,
            &format!("traffic-overlap-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic("traffic-overlap-complete", lifecycle_checkpoint);

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-renew-leaf-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic("traffic-leaf-renewal-complete", lifecycle_checkpoint);

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RotatedIntermediate,
            TrustGeneration::Overlap,
            &format!("traffic-rotate-intermediate-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-intermediate-rotation-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-rollback-intermediate-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-intermediate-rollback-complete",
        lifecycle_checkpoint,
    );

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-forward-new-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-new-root-forward-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-rollback-new-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-new-root-rollback-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-resume-new-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-new-root-resume-complete",
        lifecycle_checkpoint,
    );

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("traffic-remove-old-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-old-root-removal-complete",
        lifecycle_checkpoint,
    );
    fleet.assert_old_client_chains_rejected_under_traffic(lifecycle_checkpoint);

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-restore-overlap-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-overlap-restore-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-rollback-after-removal-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-post-removal-rollback-complete",
        lifecycle_checkpoint,
    );

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-final-forward-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet
        .complete_fleet_phase_under_traffic("traffic-final-forward-complete", lifecycle_checkpoint);
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("traffic-final-new-only-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-final-new-only-complete",
        lifecycle_checkpoint,
    );
    assert_eq!(
        fleet.canary_generation, 13,
        "traffic campaign must advance the same complete rotation phase set"
    );
}

fn run_projected_mtls_traffic_resources(member_count: usize) {
    let mut fleet = Fleet::start_traffic(member_count);
    if member_count == 3 {
        fleet.assert_three_member_resolver_backoff_profile();
    }
    // This post-formation snapshot is the immutable campaign ledger baseline.
    // Every subsequent lifecycle interval chains from the prior exact
    // checkpoint, so failures or attempt storms between named phases cannot
    // disappear behind a newly sampled baseline.
    let campaign_lifecycle_baseline = fleet.all_lifecycle_metrics();
    let mut lifecycle_checkpoint = campaign_lifecycle_baseline.clone();
    let warmup_started = Instant::now();
    let warmup_deadline =
        warmup_started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    fleet.start_traffic_tasks();
    for _ in 0..QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND {
        fleet.fresh_all_directed_generation();
    }
    fleet.wait_ready();
    let traffic_after_warmup_reauthentication = fleet.all_traffic_statuses();
    let warmed_statuses = fleet.wait_for_traffic_progress(
        &traffic_after_warmup_reauthentication,
        "resource-baseline-warmup",
        warmup_deadline,
    );
    let warmup_lifecycle = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_checkpoint,
        warmup_deadline,
        "resource-baseline-warmup",
    );
    assert_round_lifecycle_bounds(member_count, &lifecycle_checkpoint, &warmup_lifecycle);
    lifecycle_checkpoint = warmup_lifecycle;
    assert_transition_completed_by(warmup_started, warmup_deadline, "resource-baseline-warmup");
    assert!(warmed_statuses.iter().all(|status| {
        status.state == QualificationTrafficState::Running
            && status.failure.is_none()
            && status.owned_async_tasks == 2
    }));

    let process_ids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    let warmed = process_ids
        .iter()
        .copied()
        .map(read_classified_process_resources)
        .collect::<Vec<_>>();
    let sampler = ResourceSampler::start(process_ids.clone());
    let seed =
        qualification_traffic_seed(member_count).expect("supported traffic qualification topology");
    let transition_bound = Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    let total_rounds = member_count * QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER;
    for round in 0..total_rounds {
        let started = Instant::now();
        let round_deadline = started + transition_bound;
        let node_index = ((seed as usize) % member_count + round) % member_count;
        let rotation = round / member_count;
        fleet.transition_traffic_leaf(node_index, rotation);
        for _ in 0..QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND {
            fleet.fresh_all_directed_generation();
        }
        fleet.wait_ready();
        let traffic_after_reauthentication = fleet.all_traffic_statuses();
        fleet.wait_for_traffic_progress(
            &traffic_after_reauthentication,
            "repeated-same-issuer-leaf-rotation",
            round_deadline,
        );
        let metrics_after = fleet.wait_for_round_lifecycle_completion(
            &lifecycle_checkpoint,
            round_deadline,
            "repeated-same-issuer-leaf-rotation",
        );
        assert_round_lifecycle_bounds(member_count, &lifecycle_checkpoint, &metrics_after);
        lifecycle_checkpoint = metrics_after;
        assert_transition_completed_by(
            started,
            round_deadline,
            "repeated-same-issuer-leaf-rotation",
        );
    }

    run_projected_mtls_rotation_campaign_under_traffic(
        &mut fleet,
        member_count,
        &mut lifecycle_checkpoint,
    );

    let final_generation_started = Instant::now();
    let final_generation_deadline =
        final_generation_started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    let mutation_statuses = fleet.stop_traffic_mutations();
    let caught_up = fleet.wait_for_watch_heads();
    for (mutation, watch) in mutation_statuses.iter().zip(&caught_up) {
        assert_eq!(mutation.last_generation, watch.last_generation);
        assert_eq!(mutation.last_record_fence, watch.last_record_fence);
    }
    fleet.fresh_all_directed_generation();
    fleet.wait_ready();
    let final_watch_statuses = fleet.wait_for_watch_heads();
    fleet.verify_all_traffic_records(&final_watch_statuses);
    let expected_generations = mutation_statuses
        .iter()
        .map(|status| status.last_generation)
        .collect::<Vec<_>>();
    for (node_index, status) in final_watch_statuses.iter().enumerate() {
        assert_eq!(
            status.watch_traffic_generations, expected_generations,
            "watch did not apply each traffic generation exactly once and in order: node={node_index}"
        );
    }
    let stopped = fleet.stop_traffic_watches();
    for (before, after) in final_watch_statuses.iter().zip(&stopped) {
        assert_eq!(after.watch_sequence, before.watch_sequence);
        assert_eq!(after.replication_head, before.replication_head);
        assert_completed_traffic_cycles(after);
    }
    fleet.retain_traffic_plaintext_canaries(&stopped);
    let final_generation_lifecycle = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_checkpoint,
        final_generation_deadline,
        "final-fresh-generation-and-traffic-stop",
    );
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    assert_epoch_changing_lifecycle_delta_bounds(
        member_count,
        &lifecycle_checkpoint,
        &final_generation_lifecycle,
        remote_peers,
    );
    lifecycle_checkpoint = final_generation_lifecycle;
    assert_transition_completed_by(
        final_generation_started,
        final_generation_deadline,
        "final-fresh-generation-and-traffic-stop",
    );

    let (settled, settled_lifecycle) = fleet.wait_for_resources_to_settle(&process_ids, &warmed);
    assert_lifecycle_delta_bounds(member_count, &lifecycle_checkpoint, &settled_lifecycle, 0);
    lifecycle_checkpoint = settled_lifecycle;
    let high_water = sampler.finish();
    assert_process_resource_bounds(member_count, &warmed, &high_water, &settled);

    let final_ledger_deadline =
        Instant::now() + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    let final_lifecycle = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_checkpoint,
        final_ledger_deadline,
        "campaign-final-lifecycle-ledger",
    );
    assert_lifecycle_delta_bounds(member_count, &lifecycle_checkpoint, &final_lifecycle, 0);
    assert_campaign_lifecycle_failure_ledger(
        member_count,
        &campaign_lifecycle_baseline,
        &final_lifecycle,
    );

    fleet.shutdown();
    fleet.assert_plaintext_canaries_absent_from_sqlite();
    assert_mtls_candidate_evidence_emission(
        &fleet,
        SessionMtlsCandidateCampaign::TrafficResourceBounds,
    );
    assert!(fleet.workspace.path().is_dir());
}

#[test]
fn candidate_configuration_digest_is_order_content_and_bound_sensitive() {
    let workspace = tempfile::tempdir().expect("create candidate-configuration workspace");
    let config_paths = (0..3)
        .map(|index| {
            let path = workspace.path().join(format!("config-{index}.json"));
            fs::write(&path, format!("{{\"node_index\":{index}}}\n"))
                .expect("write candidate configuration");
            path
        })
        .collect::<Vec<_>>();
    let original =
        candidate_configuration_sha256(&config_paths).expect("hash candidate configurations");

    let mut reordered = config_paths.clone();
    reordered.reverse();
    assert_ne!(
        candidate_configuration_sha256(&reordered).expect("hash reordered configurations"),
        original
    );

    fs::write(&config_paths[0], b"{\"node_index\":30}\n").expect("change candidate configuration");
    assert_ne!(
        candidate_configuration_sha256(&config_paths).expect("hash changed configurations"),
        original
    );

    assert!(candidate_configuration_sha256(&config_paths[..2]).is_err());
    let symlink_path = workspace.path().join("config-symlink.json");
    symlink(&config_paths[0], &symlink_path).expect("create configuration symlink");
    let mut aliased = config_paths.clone();
    aliased[0] = symlink_path;
    assert!(candidate_configuration_sha256(&aliased).is_err());

    let oversized_length = usize::try_from(QUALIFICATION_MAX_CONFIG_BYTES)
        .expect("configuration bound fits usize")
        + 1;
    fs::write(&config_paths[0], vec![0_u8; oversized_length])
        .expect("write oversized candidate configuration");
    assert!(candidate_configuration_sha256(&config_paths).is_err());
}

#[test]
fn candidate_evidence_feature_gate_matches_the_compiled_transport_profile() {
    let result = ensure_candidate_evidence_feature_profile();
    assert_eq!(result.is_err(), cfg!(feature = "foundation-insecure"));
}

#[test]
fn candidate_execution_bindings_fail_when_a_preexecution_input_changes() {
    let workspace = tempfile::tempdir().expect("create candidate binding workspace");
    let config_paths = (0..3)
        .map(|index| {
            let path = workspace.path().join(format!("config-{index}.json"));
            fs::write(&path, format!("{{\"node_index\":{index}}}\n"))
                .expect("write candidate binding configuration");
            path
        })
        .collect::<Vec<_>>();
    let (source_revision, source_tree_status, source_worktree_sha256) =
        candidate_source_provenance().expect("capture candidate source binding");
    let harness_path = env::current_exe().expect("locate candidate harness artifact");
    let inputs = CandidateEvidenceInputs {
        source_revision,
        source_tree_status,
        source_worktree_sha256,
        child_sha256: candidate_sha256_file(
            Path::new(env!("CARGO_BIN_EXE_opc-session-quorum-node")),
            MAX_CANDIDATE_ARTIFACT_BYTES,
        )
        .expect("hash candidate child artifact"),
        harness_sha256: candidate_sha256_file(&harness_path, MAX_CANDIDATE_ARTIFACT_BYTES)
            .expect("hash candidate harness artifact"),
        configuration_sha256: candidate_configuration_sha256(&config_paths)
            .expect("hash preexecution configurations"),
    };
    inputs
        .verify_unchanged(&config_paths)
        .expect("unchanged preexecution bindings remain valid");

    fs::write(&config_paths[1], b"{\"node_index\":99}\n")
        .expect("change bound candidate configuration");
    assert!(inputs.verify_unchanged(&config_paths).is_err());
}

#[test]
fn candidate_public_material_manifest_binds_order_epoch_and_public_bytes() {
    let digest = |phase: &str, epoch: u64, certificate: &str, trust: &str| {
        let mut manifest = CandidatePublicMaterialManifest::new();
        manifest
            .record(phase, 1, epoch, certificate, trust)
            .expect("record public material input");
        manifest.sha256().expect("hash public material manifest")
    };
    let baseline = digest("phase-one", 1, "public-certificate-a", "public-trust-a");
    assert_eq!(
        baseline,
        digest("phase-one", 1, "public-certificate-a", "public-trust-a")
    );
    assert_ne!(
        baseline,
        digest("phase-two", 1, "public-certificate-a", "public-trust-a")
    );
    assert_ne!(
        baseline,
        digest("phase-one", 2, "public-certificate-a", "public-trust-a")
    );
    assert_ne!(
        baseline,
        digest("phase-one", 1, "public-certificate-b", "public-trust-a")
    );
    assert_ne!(
        baseline,
        digest("phase-one", 1, "public-certificate-a", "public-trust-b")
    );

    let mut invalid = CandidatePublicMaterialManifest::new();
    assert!(invalid.record("", 0, 1, "certificate", "trust").is_err());
    assert!(invalid.sha256().is_err());
}

#[test]
fn candidate_source_provenance_marks_nonignored_untracked_inputs_dirty() {
    let repository = tempfile::tempdir().expect("create provenance repository");
    let run_git = |arguments: &[&str]| {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(repository.path())
            .status()
            .expect("run provenance git command");
        assert!(status.success(), "provenance git command failed");
    };
    run_git(&["init", "--quiet"]);
    fs::write(repository.path().join("tracked.txt"), b"tracked\n")
        .expect("write tracked provenance input");
    run_git(&["add", "tracked.txt"]);
    run_git(&[
        "-c",
        "user.name=Qualification Test",
        "-c",
        "user.email=qualification@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "test fixture",
    ]);

    let (revision, status, clean_digest) =
        candidate_source_provenance_at(repository.path()).expect("read clean provenance");
    assert_eq!(revision.len(), 40);
    assert_eq!(status, SessionMtlsCandidateSourceTreeStatus::Clean);

    let untracked = repository.path().join("untracked-build-input.txt");
    fs::write(&untracked, b"untracked\n").expect("write untracked provenance input");
    let (_, status, untracked_digest) =
        candidate_source_provenance_at(repository.path()).expect("read untracked provenance");
    assert_eq!(
        status,
        SessionMtlsCandidateSourceTreeStatus::DirtyUnqualified
    );
    assert_ne!(untracked_digest, clean_digest);

    fs::write(&untracked, b"changed-untracked\n").expect("change untracked provenance input bytes");
    let (_, changed_status, changed_untracked_digest) =
        candidate_source_provenance_at(repository.path())
            .expect("read changed untracked provenance");
    assert_eq!(changed_status, status);
    assert_ne!(changed_untracked_digest, untracked_digest);

    fs::remove_file(untracked).expect("remove untracked provenance input");
    fs::write(repository.path().join("tracked.txt"), b"modified\n")
        .expect("modify tracked provenance input");
    let (_, status, modified_digest) =
        candidate_source_provenance_at(repository.path()).expect("read modified provenance");
    assert_eq!(
        status,
        SessionMtlsCandidateSourceTreeStatus::DirtyUnqualified
    );
    assert_ne!(modified_digest, clean_digest);

    fs::write(repository.path().join("tracked.txt"), vec![b'x'; 256])
        .expect("write bounded provenance diff");
    assert!(candidate_git_output(
        repository.path(),
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "HEAD",
            "--",
        ],
        64,
    )
    .is_err());
}

#[test]
fn candidate_evidence_persistence_is_bounded_private_and_create_new() {
    let workspace = tempfile::tempdir().expect("create evidence persistence workspace");
    let evidence_path = workspace.path().join("source-evidence.json");
    let schema_path = workspace.path().join("source-schema.json");
    write_private_candidate_file(&evidence_path, b"{\"experimental\":true}\n")
        .expect("write source evidence");
    write_private_candidate_file(&schema_path, b"{\"type\":\"object\"}\n")
        .expect("write source schema");
    let output_root = workspace.path().join("retained");

    preserve_mtls_candidate_evidence_at(
        &output_root,
        SessionMtlsCandidateCampaign::RotationCore,
        3,
        &evidence_path,
        &schema_path,
    )
    .expect("preserve bounded candidate evidence");
    let destination = output_root.join("mtls-v2-rotation_core-3-node");
    assert_eq!(
        fs::metadata(&output_root)
            .expect("retained evidence root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&destination)
            .expect("retained campaign directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let mut names = fs::read_dir(&destination)
        .expect("read retained candidate directory")
        .map(|entry| {
            entry
                .expect("retained candidate entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["evidence.json", "evidence.schema.json"]);
    for name in names {
        assert_eq!(
            fs::metadata(destination.join(name))
                .expect("retained candidate file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(
        preserve_mtls_candidate_evidence_at(
            &output_root,
            SessionMtlsCandidateCampaign::RotationCore,
            3,
            &evidence_path,
            &schema_path,
        )
        .is_err(),
        "an existing campaign directory must never be replaced"
    );
    let mut root_entries = fs::read_dir(&output_root)
        .expect("read retained evidence root")
        .map(|entry| {
            entry
                .expect("retained root entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    root_entries.sort();
    assert_eq!(root_entries, ["mtls-v2-rotation_core-3-node"]);

    let missing_source_root = workspace.path().join("missing-source-root");
    assert!(preserve_mtls_candidate_evidence_at(
        &missing_source_root,
        SessionMtlsCandidateCampaign::FaultExpiryRecovery,
        3,
        &evidence_path,
        &workspace.path().join("missing-schema.json"),
    )
    .is_err());
    assert!(
        !missing_source_root.exists(),
        "a source-read failure must not leave a root or partial destination"
    );

    let permissive_root = workspace.path().join("permissive-root");
    fs::create_dir(&permissive_root).expect("create permissive evidence root");
    fs::set_permissions(&permissive_root, Permissions::from_mode(0o755))
        .expect("set permissive evidence-root mode");
    assert!(
        preserve_mtls_candidate_evidence_at(
            &permissive_root,
            SessionMtlsCandidateCampaign::RotationCore,
            3,
            &evidence_path,
            &schema_path,
        )
        .is_err(),
        "a pre-existing non-private root must fail closed"
    );
    assert_eq!(
        fs::metadata(&permissive_root)
            .expect("permissive evidence-root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755,
        "the harness must not chmod a user-selected existing directory"
    );

    let private_root = workspace.path().join("private-root");
    fs::create_dir(&private_root).expect("create private evidence root");
    fs::set_permissions(&private_root, Permissions::from_mode(0o700))
        .expect("set private evidence-root mode");
    let aliased_root = workspace.path().join("aliased-root");
    symlink(&private_root, &aliased_root).expect("create evidence-root symlink");
    assert!(
        preserve_mtls_candidate_evidence_at(
            &aliased_root,
            SessionMtlsCandidateCampaign::FaultExpiryRecovery,
            3,
            &evidence_path,
            &schema_path,
        )
        .is_err(),
        "a symlinked output root must fail closed"
    );
    assert_eq!(
        fs::read_dir(&private_root)
            .expect("read private symlink target")
            .count(),
        0
    );

    let victim = workspace.path().join("victim");
    fs::write(&victim, b"unchanged").expect("write symlink victim");
    let target = workspace.path().join("target");
    symlink(&victim, &target).expect("create target symlink");
    assert!(write_private_candidate_file(&target, b"replacement").is_err());
    assert!(read_bounded_candidate_file(&target, 64).is_err());
    assert!(candidate_sha256_file(&target, 64).is_err());
    assert_eq!(fs::read(victim).expect("read symlink victim"), b"unchanged");

    let oversized = workspace.path().join("oversized");
    fs::write(&oversized, b"12345").expect("write oversized evidence");
    assert!(read_bounded_candidate_file(&oversized, 4).is_err());
    assert!(candidate_sha256_file(&oversized, 4).is_err());
}

#[test]
fn three_process_projected_mtls_unavailable_malformed_and_expiry_recovery() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_fault_and_expiry_recovery(3);
}

#[test]
fn five_process_projected_mtls_unavailable_malformed_and_expiry_recovery() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_fault_and_expiry_recovery(5);
}

#[test]
fn three_process_projected_mtls_rotation_core() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_rotation_core(3);
}

#[test]
fn five_process_projected_mtls_rotation_core() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_rotation_core(5);
}

#[test]
#[ignore = "manual long-running projected-mTLS traffic/resource qualification"]
fn three_process_projected_mtls_traffic_and_resource_bounds() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_traffic_resources(3);
}

#[test]
#[ignore = "manual long-running projected-mTLS traffic/resource qualification"]
fn five_process_projected_mtls_traffic_and_resource_bounds() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_traffic_resources(5);
}

fn lifecycle_metrics_fixture() -> QualificationConnectionLifecycleMetrics {
    QualificationConnectionLifecycleMetrics {
        retirement_maximum_age: 0,
        retirement_local_leaf_expiry: 0,
        retirement_peer_leaf_expiry: 0,
        retirement_local_certificate_chain_expiry: 0,
        retirement_peer_certificate_chain_expiry: 0,
        retirement_material_epoch: 0,
        retirement_explicit: 0,
        retirement_idle_timeout: 0,
        active_connections: 0,
        draining_connections: 0,
        drain_started: 0,
        drain_completed: 0,
        drain_overruns: 0,
        connection_attempts: 0,
        connection_successes: 0,
        connection_failure_transport: 0,
        connection_failure_authentication: 0,
        connection_failure_timeout: 0,
        connection_superseded: 0,
        connection_abandoned: 0,
        connection_failure_protocol: 0,
        connection_failure_backend: 0,
        reconnect_attempts: 0,
        reconnect_failures: 0,
        empty_vote_dispatches: 0,
    }
}

fn traffic_status_fixture(member_count: usize) -> QualificationTrafficStatus {
    QualificationTrafficStatus {
        state: QualificationTrafficState::Running,
        failure: None,
        failure_stage: None,
        failure_error_class: None,
        failure_recovery_elapsed_millis: None,
        seed: 1,
        owned_async_tasks: 2,
        mutation_cycles: 10,
        linearizable_reads: 11,
        lease_renewals: 11,
        lease_reacquisitions: 10,
        availability_interruptions: 1,
        availability_recoveries: 1,
        max_consecutive_availability_interruptions: 1,
        complete_restore_scans: 11,
        durable_readiness_probes: 11,
        mutation_resume_generation: 0,
        mutation_resume_record_fence: 0,
        last_generation: 11,
        last_record_fence: 11,
        watch_entries: 10,
        watch_applied_records: 10,
        watch_sequence: 10,
        watch_reconciliations: 0,
        watch_reconciled_sequence: 0,
        watch_traffic_generations: vec![10; member_count],
        replication_head: 10,
    }
}

#[test]
fn stopped_traffic_accepts_each_ordered_partial_final_cycle() {
    let complete = traffic_status_fixture(3);
    let mut renewed = complete.clone();
    renewed.lease_renewals += 1;
    let mut compared_and_set = renewed.clone();
    compared_and_set.last_generation += 1;
    compared_and_set.last_record_fence += 1;
    let mut read = compared_and_set.clone();
    read.linearizable_reads += 1;
    let mut restored = read.clone();
    restored.complete_restore_scans += 1;
    let mut ready = restored.clone();
    ready.durable_readiness_probes += 1;
    let mut next_cycle = ready.clone();
    next_cycle.lease_reacquisitions += 1;
    next_cycle.mutation_cycles += 1;

    for status in [
        complete,
        renewed,
        compared_and_set,
        read,
        restored,
        ready,
        next_cycle,
    ] {
        assert!(traffic_live_mutator_counters_are_consistent(&status));
        assert_completed_traffic_cycles(&status);
    }
}

#[test]
fn traffic_counter_prefix_rejects_skips_reordering_and_multiple_partial_cycles() {
    let baseline = traffic_status_fixture(3);
    let mut invalid = Vec::new();

    let mut multiple_renewals = baseline.clone();
    multiple_renewals.lease_renewals += 2;
    invalid.push(multiple_renewals);

    let mut cas_without_renewal = baseline.clone();
    cas_without_renewal.last_generation += 1;
    invalid.push(cas_without_renewal);

    let mut read_without_cas = baseline.clone();
    read_without_cas.linearizable_reads += 1;
    invalid.push(read_without_cas);

    let mut restore_without_read = baseline.clone();
    restore_without_read.complete_restore_scans += 1;
    invalid.push(restore_without_read);

    let mut readiness_without_restore = baseline.clone();
    readiness_without_restore.durable_readiness_probes += 1;
    invalid.push(readiness_without_restore);

    for status in invalid {
        assert!(!traffic_live_mutator_counters_are_consistent(&status));
    }
}

#[test]
fn traffic_progress_rejects_unresolved_or_incoherent_availability_evidence() {
    let before = traffic_status_fixture(3);
    let mut after = before.clone();
    after.mutation_cycles += 1;
    after.linearizable_reads += 1;
    after.lease_renewals += 1;
    after.lease_reacquisitions += 1;
    after.complete_restore_scans += 1;
    after.durable_readiness_probes += 1;
    after.last_generation += 1;
    after.last_record_fence += 1;
    after.watch_entries += 3;
    after.watch_applied_records += 3;
    after.watch_sequence += 3;
    for generation in &mut after.watch_traffic_generations {
        *generation += 1;
    }

    let mut unresolved = after.clone();
    unresolved.availability_interruptions += 1;
    unresolved.max_consecutive_availability_interruptions += 1;
    assert!(traffic_live_mutator_counters_are_consistent(&unresolved));
    assert!(!traffic_availability_recovery_is_resolved(&unresolved));
    assert!(!traffic_status_made_semantic_progress(
        &before,
        &unresolved,
        3
    ));

    let mut impossible = after.clone();
    impossible.availability_interruptions = 1;
    impossible.availability_recoveries = 1;
    impossible.max_consecutive_availability_interruptions = 0;
    assert!(!traffic_live_mutator_counters_are_consistent(&impossible));

    let mut incoherent = after;
    incoherent.failure = Some(QualificationTrafficFailureCode::BackendUnavailable);
    incoherent.failure_stage = Some(QualificationTrafficFailureStage::Get);
    incoherent.failure_error_class = None;
    assert!(!traffic_failure_fields_are_coherent(&incoherent));
    incoherent.failure_error_class = Some(QualificationTrafficErrorClass::BackendUnavailable);
    assert!(traffic_failure_fields_are_coherent(&incoherent));
    incoherent.failure_recovery_elapsed_millis =
        Some(QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS + 123);
    assert!(!traffic_failure_fields_are_coherent(&incoherent));
    incoherent.failure =
        Some(QualificationTrafficFailureCode::AvailabilityRecoveryDeadlineExceeded);
    assert!(traffic_failure_fields_are_coherent(&incoherent));
    incoherent.failure_recovery_elapsed_millis = None;
    assert!(!traffic_failure_fields_are_coherent(&incoherent));
}

#[test]
fn member_recovery_scope_preserves_unrelated_survivor_generations_and_retirements() {
    let member = 1;
    let generations_before = vec![4, 7, 9, 11, 13];
    let mut generations_after = generations_before.clone();
    generations_after[member] += 1;
    assert!(member_reauthentication_generations_are_scoped(
        &generations_before,
        &generations_after,
        member,
    ));
    generations_after[3] += 1;
    assert!(!member_reauthentication_generations_are_scoped(
        &generations_before,
        &generations_after,
        member,
    ));

    let paths = member_incident_directed_paths(5, member);
    assert_eq!(paths.len(), 8);
    assert!(paths
        .iter()
        .all(|(source, target)| { source != target && (*source == member || *target == member) }));
    assert!(!paths
        .iter()
        .any(|(source, target)| *source == 0 && *target == 2));

    let before = vec![lifecycle_metrics_fixture(); 5];
    let mut after = before.clone();
    after[member].retirement_explicit += 1;
    after[member].retirement_material_epoch += 1;
    assert!(
        unrelated_survivor_reauthentication_retirements_are_unchanged(&before, &after, member,)
    );
    after[4].retirement_explicit += 1;
    assert!(
        !unrelated_survivor_reauthentication_retirements_are_unchanged(&before, &after, member,)
    );
}

#[test]
fn member_recovery_settlement_rejects_an_unresolved_survivor_episode() {
    let (participants, _before, mut settled) = subset_traffic_fixture();
    assert!(subset_traffic_availability_is_settled(
        &settled,
        &participants,
    ));

    settled[0].status.availability_interruptions += 1;
    settled[0].status.max_consecutive_availability_interruptions += 1;
    assert!(traffic_live_mutator_counters_are_consistent(
        &settled[0].status
    ));
    assert!(!subset_traffic_availability_is_settled(
        &settled,
        &participants,
    ));
}

#[test]
fn member_recovery_fault_boundary_bounds_and_requires_availability_recovery() {
    let (participants, before, mut after) = subset_traffic_fixture();
    assert!(subset_traffic_availability_within_recovery_budget(
        &before,
        &after,
        &participants,
    ));
    assert!(subset_traffic_availability_counters_equal(
        &before,
        &after,
        &participants,
    ));
    assert!(!subset_traffic_availability_changed_since(
        &before,
        &after,
        &participants,
    ));

    after[0].status.availability_interruptions += 1;
    assert!(subset_traffic_availability_within_recovery_budget(
        &before,
        &after,
        &participants,
    ));
    assert!(subset_traffic_availability_changed_since(
        &before,
        &after,
        &participants,
    ));
    assert!(!subset_traffic_availability_counters_equal(
        &before,
        &after,
        &participants,
    ));
    assert!(!subset_traffic_availability_is_settled(
        &after,
        &participants,
    ));

    after[0].status.availability_recoveries += 1;
    assert!(subset_traffic_availability_is_settled(
        &after,
        &participants,
    ));
    assert!(subset_traffic_availability_within_recovery_budget(
        &before,
        &after,
        &participants,
    ));

    after[0].status.availability_interruptions += 1;
    after[0].status.availability_recoveries += 1;
    assert!(!subset_traffic_availability_within_recovery_budget(
        &before,
        &after,
        &participants,
    ));
}

#[test]
fn live_counter_snapshot_allows_reacquisition_before_cycle_publish() {
    let mut status = traffic_status_fixture(3);
    status.lease_renewals += 1;
    status.last_generation += 1;
    status.last_record_fence += 1;
    status.linearizable_reads += 1;
    status.complete_restore_scans += 1;
    status.durable_readiness_probes += 1;
    status.lease_reacquisitions += 1;

    assert!(traffic_live_mutator_counters_are_consistent(&status));
    let rejected = std::panic::catch_unwind(|| assert_completed_traffic_cycles(&status));
    assert!(rejected.is_err());
}

fn subset_traffic_fixture() -> (
    TrafficParticipants,
    Vec<IndexedTrafficStatus>,
    Vec<IndexedTrafficStatus>,
) {
    let participants =
        TrafficParticipants::try_new(3, &[0, 1, 2], &[0, 1]).expect("traffic participants");
    let mut before = Vec::new();
    let mut after = Vec::new();
    for node_index in 0..3 {
        let mut initial = traffic_status_fixture(3);
        initial.watch_traffic_generations = vec![10, 10, 0];
        if node_index == 2 {
            initial.state = QualificationTrafficState::WatchReady;
            initial.owned_async_tasks = 1;
            initial.mutation_cycles = 0;
            initial.linearizable_reads = 0;
            initial.lease_renewals = 0;
            initial.lease_reacquisitions = 0;
            initial.complete_restore_scans = 0;
            initial.durable_readiness_probes = 0;
            initial.last_generation = 0;
            initial.last_record_fence = 0;
            initial.availability_interruptions = 0;
            initial.availability_recoveries = 0;
            initial.max_consecutive_availability_interruptions = 0;
        }
        let mut progressed = initial.clone();
        progressed.watch_entries += 4;
        progressed.watch_applied_records += 2;
        progressed.watch_sequence += 4;
        progressed.replication_head += 4;
        progressed.watch_traffic_generations[0] += 1;
        progressed.watch_traffic_generations[1] += 1;
        if node_index != 2 {
            progressed.mutation_cycles += 2;
            progressed.linearizable_reads += 2;
            progressed.lease_renewals += 2;
            progressed.lease_reacquisitions += 2;
            progressed.complete_restore_scans += 2;
            progressed.durable_readiness_probes += 2;
            progressed.last_generation += 2;
            progressed.last_record_fence += 2;
        }
        before.push(IndexedTrafficStatus {
            node_index,
            status: initial,
        });
        after.push(IndexedTrafficStatus {
            node_index,
            status: progressed,
        });
    }
    (participants, before, after)
}

fn recovery_post_cas_alignment_fixture() -> (
    TrafficParticipants,
    Vec<IndexedTrafficStatus>,
    Vec<IndexedTrafficStatus>,
) {
    let (participants, before, mut after) = subset_traffic_fixture();
    after.clone_from(&before);
    for indexed in &mut after {
        indexed.status.watch_entries += 1;
        indexed.status.watch_applied_records += 1;
        indexed.status.watch_sequence += 1;
        indexed.status.replication_head += 1;
        indexed.status.watch_traffic_generations[0] += 1;
        match indexed.node_index {
            0 => {
                // Finish the cycle whose CAS was already visible in the
                // checkpoint, then publish the next cycle's CAS.
                indexed.status.mutation_cycles += 1;
                indexed.status.lease_reacquisitions += 1;
                indexed.status.lease_renewals += 1;
                indexed.status.last_generation += 1;
                indexed.status.last_record_fence += 1;
            }
            1 => {
                // The checkpoint already observed this cycle's CAS. Its
                // terminal publication is still real progress even though
                // generation and watch position do not change again yet.
                indexed.status.mutation_cycles += 1;
                indexed.status.lease_reacquisitions += 1;
            }
            2 => {}
            _ => unreachable!(),
        }
    }
    (participants, before, after)
}

#[test]
fn recovery_progress_accepts_post_cas_alignment_without_claiming_full_coverage() {
    let (participants, before, after) = recovery_post_cas_alignment_fixture();
    assert!(recovery_traffic_has_common_key_pulse(
        &before,
        &after,
        &participants,
    ));
    assert!(!recovery_traffic_has_all_key_coverage(
        &before,
        &after,
        &participants,
    ));
    assert!(!subset_traffic_made_semantic_progress(
        &before,
        &after,
        &participants,
    ));
}

#[test]
fn recovery_progress_requires_one_common_key_on_every_observer() {
    let (participants, before, mut split) = recovery_post_cas_alignment_fixture();
    split[1].status.watch_traffic_generations[0] = before[1].status.watch_traffic_generations[0];
    split[1].status.watch_traffic_generations[1] += 1;
    split[2].status.watch_traffic_generations[0] = before[2].status.watch_traffic_generations[0];
    split[2].status.watch_traffic_generations[1] += 1;
    assert!(!recovery_traffic_has_common_key_pulse(
        &before,
        &split,
        &participants,
    ));
}

#[test]
fn recovery_fast_key_pulses_do_not_reset_all_key_coverage() {
    let (participants, before, first_pulse) = recovery_post_cas_alignment_fixture();
    let observed_at = Instant::now();
    let mut tracker = RecoveryTrafficProgressTracker::new(before.clone(), observed_at);
    let coverage_deadline = tracker.coverage_deadline();
    assert!(recovery_traffic_has_common_key_pulse(
        &tracker.pulse_checkpoint,
        &first_pulse,
        &participants,
    ));
    tracker.pulse_checkpoint = first_pulse.clone();
    tracker.pulse_observed_at += Duration::from_millis(1_000);

    let mut second_pulse = first_pulse;
    for indexed in &mut second_pulse {
        indexed.status.watch_entries += 1;
        indexed.status.watch_applied_records += 1;
        indexed.status.watch_sequence += 1;
        indexed.status.replication_head += 1;
        indexed.status.watch_traffic_generations[0] += 1;
        if indexed.node_index == 0 {
            indexed.status.linearizable_reads += 1;
            indexed.status.complete_restore_scans += 1;
            indexed.status.durable_readiness_probes += 1;
            indexed.status.lease_reacquisitions += 1;
            indexed.status.mutation_cycles += 1;
            indexed.status.lease_renewals += 1;
            indexed.status.last_generation += 1;
            indexed.status.last_record_fence += 1;
        }
    }
    assert!(recovery_traffic_has_common_key_pulse(
        &tracker.pulse_checkpoint,
        &second_pulse,
        &participants,
    ));
    assert!(!recovery_traffic_has_all_key_coverage(
        &tracker.coverage_checkpoint,
        &second_pulse,
        &participants,
    ));
    assert_eq!(tracker.coverage_deadline(), coverage_deadline);
}

#[test]
fn recovery_coverage_requires_health_monotonicity_and_inactive_key_stability() {
    let (participants, before, after) = subset_traffic_fixture();
    assert!(recovery_traffic_has_all_key_coverage(
        &before,
        &after,
        &participants,
    ));

    let mut missing_observer_key = after.clone();
    missing_observer_key[2].status.watch_traffic_generations[1] =
        before[2].status.watch_traffic_generations[1];
    assert!(!recovery_traffic_has_all_key_coverage(
        &before,
        &missing_observer_key,
        &participants,
    ));

    let mut regressed = after.clone();
    regressed[0].status.replication_head = before[0].status.replication_head - 1;
    assert!(!recovery_traffic_has_all_key_coverage(
        &before,
        &regressed,
        &participants,
    ));

    let mut unhealthy = after.clone();
    unhealthy[0].status.state = QualificationTrafficState::Failed;
    assert!(!recovery_traffic_has_all_key_coverage(
        &before,
        &unhealthy,
        &participants,
    ));

    let mut unresolved = after.clone();
    unresolved[0].status.availability_interruptions += 1;
    unresolved[0]
        .status
        .max_consecutive_availability_interruptions += 1;
    assert!(!recovery_traffic_has_all_key_coverage(
        &before,
        &unresolved,
        &participants,
    ));

    let mut inactive_changed = after;
    inactive_changed[2].status.watch_traffic_generations[2] += 1;
    assert!(!recovery_traffic_has_all_key_coverage(
        &before,
        &inactive_changed,
        &participants,
    ));
}

#[test]
fn restarted_mutator_counters_are_relative_to_exact_committed_resume_state() {
    let mut resumed = traffic_status_fixture(3);
    resumed.mutation_resume_generation = 100;
    resumed.mutation_resume_record_fence = 200;
    resumed.last_generation = 111;
    resumed.last_record_fence = 211;
    resumed.availability_interruptions = 0;
    resumed.availability_recoveries = 0;
    resumed.max_consecutive_availability_interruptions = 0;
    assert!(traffic_live_mutator_counters_are_consistent(&resumed));
    assert_completed_traffic_cycles(&resumed);

    let mut generation_regressed = resumed.clone();
    generation_regressed.last_generation = 99;
    assert!(!traffic_live_mutator_counters_are_consistent(
        &generation_regressed
    ));

    let mut fence_regressed = resumed;
    fence_regressed.last_record_fence = 199;
    assert!(!traffic_live_mutator_counters_are_consistent(
        &fence_regressed
    ));
}

#[test]
fn unclean_restart_allows_only_monotonic_crashed_process_tail() {
    let (participants, mut before, mut after) = subset_traffic_fixture();
    for status in &mut before {
        status.status.watch_traffic_generations[2] = 10;
    }
    for status in &mut after {
        status.status.watch_traffic_generations[2] = 10;
    }
    assert!(subset_traffic_made_semantic_progress_with_crashed_tail(
        &before,
        &after,
        &participants,
        Some(2),
    ));

    let mut committed_tail = after.clone();
    for status in &mut committed_tail {
        status.status.watch_traffic_generations[2] += 7;
    }
    assert!(subset_traffic_made_semantic_progress_with_crashed_tail(
        &before,
        &committed_tail,
        &participants,
        Some(2),
    ));

    let mut regressed_tail = after;
    for status in &mut regressed_tail {
        status.status.watch_traffic_generations[2] = 9;
    }
    assert!(!subset_traffic_made_semantic_progress_with_crashed_tail(
        &before,
        &regressed_tail,
        &participants,
        Some(2),
    ));
}

#[test]
fn traffic_participants_reject_invalid_or_ambiguous_indices() {
    assert!(TrafficParticipants::try_new(3, &[0, 1, 2], &[0, 1]).is_ok());
    assert_eq!(
        TrafficParticipants::try_new(4, &[0, 1, 2], &[0, 1]),
        Err(TrafficParticipantError::UnsupportedMemberCount)
    );
    assert_eq!(
        TrafficParticipants::try_new(3, &[], &[0]),
        Err(TrafficParticipantError::EmptyObservers)
    );
    assert_eq!(
        TrafficParticipants::try_new(3, &[0], &[]),
        Err(TrafficParticipantError::EmptyMutators)
    );
    assert_eq!(
        TrafficParticipants::try_new(3, &[0, 3], &[0]),
        Err(TrafficParticipantError::NodeIndexOutOfRange)
    );
    assert_eq!(
        TrafficParticipants::try_new(3, &[0, 0], &[0]),
        Err(TrafficParticipantError::DuplicateNodeIndex)
    );
    assert_eq!(
        TrafficParticipants::try_new(3, &[0, 1], &[0, 0]),
        Err(TrafficParticipantError::DuplicateNodeIndex)
    );
    assert_eq!(
        TrafficParticipants::try_new(3, &[0, 1], &[2]),
        Err(TrafficParticipantError::MutatorWithoutObserver)
    );
}

#[test]
fn subset_traffic_accepts_watch_only_observer_and_requires_every_active_key() {
    let (participants, before, after) = subset_traffic_fixture();
    assert!(subset_traffic_made_semantic_progress(
        &before,
        &after,
        &participants
    ));

    let mut missing_key = after.clone();
    missing_key[2].status.watch_traffic_generations[1] =
        before[2].status.watch_traffic_generations[1];
    assert!(!subset_traffic_made_semantic_progress(
        &before,
        &missing_key,
        &participants
    ));

    let mut changed_inactive_key = after.clone();
    changed_inactive_key[0].status.watch_traffic_generations[2] += 1;
    assert!(!subset_traffic_made_semantic_progress(
        &before,
        &changed_inactive_key,
        &participants
    ));
}

#[test]
fn subset_traffic_requires_every_mutator_operation_counter() {
    let (participants, before, after) = subset_traffic_fixture();
    for counter in [
        "cycles",
        "read",
        "renew",
        "reacquire",
        "restore",
        "readiness",
        "generation",
        "fence",
    ] {
        let mut missing = after.clone();
        let status = &mut missing[0].status;
        match counter {
            "cycles" => status.mutation_cycles = before[0].status.mutation_cycles,
            "read" => status.linearizable_reads = before[0].status.linearizable_reads,
            "renew" => status.lease_renewals = before[0].status.lease_renewals,
            "reacquire" => status.lease_reacquisitions = before[0].status.lease_reacquisitions,
            "restore" => status.complete_restore_scans = before[0].status.complete_restore_scans,
            "readiness" => {
                status.durable_readiness_probes = before[0].status.durable_readiness_probes
            }
            "generation" => status.last_generation = before[0].status.last_generation,
            "fence" => status.last_record_fence = before[0].status.last_record_fence,
            _ => unreachable!(),
        }
        assert!(
            !subset_traffic_made_semantic_progress(&before, &missing, &participants),
            "missing mutator counter was accepted: {counter}"
        );
    }
}

#[test]
fn campaign_ledger_rejects_an_interstitial_failure_outside_leaf_rounds() {
    let member_count = 3;
    let before = vec![lifecycle_metrics_fixture(); member_count];
    let mut valid_after = before.clone();
    for metrics in &mut valid_after {
        metrics.connection_attempts = 2;
        metrics.connection_failure_authentication = 1;
        metrics.connection_superseded = 1;
    }
    assert_campaign_lifecycle_failure_ledger(member_count, &before, &valid_after);

    let mut failed_after = valid_after.clone();
    failed_after[1].connection_attempts += 1;
    failed_after[1].connection_failure_timeout += 1;
    let rejected = std::panic::catch_unwind(|| {
        assert_campaign_lifecycle_failure_ledger(member_count, &before, &failed_after);
    });
    assert!(rejected.is_err());
}

#[test]
fn non_epoch_lifecycle_bounds_reject_superseded_and_abandoned_attempts() {
    let member_count = 3;
    let before = vec![lifecycle_metrics_fixture(); member_count];
    let mut superseded = before.clone();
    superseded[0].connection_attempts = 1;
    superseded[0].connection_superseded = 1;

    let rejected = std::panic::catch_unwind(|| {
        assert_lifecycle_delta_bounds(member_count, &before, &superseded, 0);
    });
    assert!(rejected.is_err());

    let mut abandoned = before.clone();
    abandoned[0].connection_attempts = 1;
    abandoned[0].connection_abandoned = 1;
    let rejected = std::panic::catch_unwind(|| {
        assert_lifecycle_delta_bounds(member_count, &before, &abandoned, 0);
    });
    assert!(rejected.is_err());
}

#[test]
fn epoch_changing_bounds_cap_supersession_and_reject_abandonment_or_timeout() {
    let member_count = 3;
    let before = vec![lifecycle_metrics_fixture(); member_count];
    let bound = lifecycle_interval_connection_bound(member_count);
    assert_eq!(bound, 24);
    let mut valid_after = before.clone();
    valid_after[0].connection_attempts = bound;
    valid_after[0].connection_superseded = bound;
    assert_epoch_changing_lifecycle_delta_bounds(member_count, &before, &valid_after, 0);

    let mut excessive_supersession = valid_after;
    excessive_supersession[0].connection_superseded += 1;
    assert!(std::panic::catch_unwind(|| {
        assert_epoch_changing_lifecycle_delta_bounds(
            member_count,
            &before,
            &excessive_supersession,
            0,
        );
    })
    .is_err());

    let mut abandoned = before.clone();
    abandoned[1].connection_attempts = 1;
    abandoned[1].connection_abandoned = 1;
    assert!(std::panic::catch_unwind(|| {
        assert_epoch_changing_lifecycle_delta_bounds(member_count, &before, &abandoned, 0);
    })
    .is_err());

    let mut real_timeout = before.clone();
    real_timeout[1].connection_attempts = 1;
    real_timeout[1].connection_failure_timeout = 1;
    assert!(std::panic::catch_unwind(|| {
        assert_epoch_changing_lifecycle_delta_bounds(member_count, &before, &real_timeout, 0);
    })
    .is_err());
}

#[test]
fn recovery_fault_settlement_tracks_attempts_without_freezing_connection_gauges() {
    assert_eq!(
        recovery_fault_outcome_settlement_window(),
        Duration::from_millis(62_500)
    );
    assert_eq!(
        recovery_fault_server_tail_window(),
        Duration::from_millis(60_000)
    );
    assert_eq!(
        recovery_fault_outbound_quiet_window(),
        Duration::from_millis(2_500)
    );
    assert_eq!(recovery_fault_connection_bound(3), 85);
    assert_eq!(recovery_fault_connection_bound(5), 161);
    assert_eq!(QUALIFICATION_TRAFFIC_FAULT_DIRECTED_PATH_FACTOR, 2);
    assert_eq!(
        QUALIFICATION_TRAFFIC_FAULT_POST_HARD_EXPIRY_NETWORK_PROBE_ATTEMPTS_PER_NODE,
        1
    );
    assert_eq!(
        QUALIFICATION_TRAFFIC_FAULT_CONNECTION_ACCOUNTING_PROFILE,
        "new-attempts-plus-baseline-outstanding/v1"
    );
    assert_eq!(
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_PROGRESS_CHECKPOINT_MILLIS,
        13_000
    );
    assert_eq!(
        QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,
        26_000
    );
    let observed_at = Instant::now();
    let absolute_deadline = observed_at + Duration::from_millis(86_000);
    assert_eq!(
        recovery_traffic_progress_deadline(observed_at, absolute_deadline),
        observed_at + Duration::from_millis(13_000)
    );
    let late_observation = observed_at + Duration::from_millis(80_000);
    assert_eq!(
        recovery_traffic_progress_deadline(late_observation, absolute_deadline),
        absolute_deadline
    );
    let mut progress = RecoveryTrafficProgressTracker::new(Vec::new(), observed_at);
    assert_eq!(
        progress.next_deadline(absolute_deadline),
        observed_at + Duration::from_millis(13_000)
    );
    progress.extend_pulse_for_availability_recovery();
    assert_eq!(
        progress.next_deadline(absolute_deadline),
        observed_at + Duration::from_millis(26_000)
    );
    progress.record_pulse(Vec::new(), observed_at + Duration::from_millis(20_000));
    assert!(!progress.pulse_recovery_extended);
    assert_eq!(
        progress.next_deadline(absolute_deadline),
        observed_at + Duration::from_millis(26_000)
    );
    let operation_timeout = Duration::from_millis(QUALIFICATION_OPERATION_TIMEOUT_MILLIS);
    assert!(
        !deadline_admits_complete_operation(
            observed_at + Duration::from_millis(20_000),
            progress.next_deadline(absolute_deadline),
        ),
        "a refreshed pulse must not hide the residual independent coverage deadline"
    );
    progress.record_coverage(Vec::new(), observed_at + Duration::from_millis(20_000));
    assert!(deadline_admits_complete_operation(
        observed_at + Duration::from_millis(20_000),
        progress.next_deadline(absolute_deadline),
    ));
    assert_eq!(
        progress.next_deadline(absolute_deadline),
        observed_at
            + Duration::from_millis(20_000)
            + operation_timeout
            + Duration::from_millis(3_000)
    );

    let baseline = lifecycle_metrics_fixture();
    let baseline_ledger = connection_attempt_settlement_ledger(&baseline);
    let mut gauge_only = baseline;
    gauge_only.active_connections = 3;
    gauge_only.draining_connections = 1;
    gauge_only.retirement_peer_leaf_expiry = 1;
    assert_eq!(
        connection_attempt_settlement_ledger(&gauge_only),
        baseline_ledger
    );

    let mut started = baseline;
    started.connection_attempts = 1;
    assert_ne!(
        connection_attempt_settlement_ledger(&started),
        baseline_ledger
    );
    let mut terminal = baseline;
    terminal.connection_failure_timeout = 1;
    assert_ne!(
        connection_attempt_settlement_ledger(&terminal),
        baseline_ledger
    );
}

#[test]
fn recovery_fault_flush_bounds_incident_failures_and_rejects_abandonment() {
    let before = lifecycle_metrics_fixture();
    let mut incident = before;
    incident.connection_attempts = 3;
    incident.connection_failure_transport = 1;
    incident.connection_failure_authentication = 1;
    incident.connection_failure_timeout = 1;
    incident.reconnect_attempts = 1;
    incident.reconnect_failures = 1;
    assert!(recovery_fault_flush_has_no_unsafe_outcomes(
        &before, &incident
    ));
    let before_fleet = vec![before; 3];
    let mut incident_fleet = before_fleet.clone();
    incident_fleet[0] = incident;
    assert_recovery_fault_flush_bounds(3, &before_fleet, &incident_fleet);

    // The fixed maximum includes one per-node attempt for the scheduled
    // survivor-to-expired-member negative probe after hard expiry. The reverse
    // probe fails local material preflight and consumes no network attempt.
    let mut scheduled_maximum = before_fleet.clone();
    scheduled_maximum[0].connection_attempts = 85;
    scheduled_maximum[0].connection_successes = 85;
    assert_recovery_fault_flush_bounds(3, &before_fleet, &scheduled_maximum);

    let mut reconnect_attempt_maximum = before_fleet.clone();
    reconnect_attempt_maximum[0].reconnect_attempts = 85;
    assert_recovery_fault_flush_bounds(3, &before_fleet, &reconnect_attempt_maximum);

    let mut reconnect_failure_maximum = before_fleet.clone();
    reconnect_failure_maximum[0].reconnect_failures = 85;
    assert_recovery_fault_flush_bounds(3, &before_fleet, &reconnect_failure_maximum);

    // A connection accepted before the interval can finish during it. Its
    // terminal outcome is not a new interval attempt, so admit exactly the
    // outstanding baseline carry-in while retaining the fixed new-attempt
    // bound and the connection conservation equation.
    let mut carry_in_before = before;
    carry_in_before.connection_attempts = 1;
    carry_in_before.active_connections = 1;
    let carry_in_before_fleet = vec![carry_in_before; 3];
    let mut carry_in_after_fleet = carry_in_before_fleet.clone();
    carry_in_after_fleet[0].connection_attempts = 86;
    carry_in_after_fleet[0].connection_successes = 86;
    carry_in_after_fleet[0].active_connections = 0;
    assert_recovery_fault_flush_bounds(3, &carry_in_before_fleet, &carry_in_after_fleet);

    let mut unaccounted_terminal = carry_in_after_fleet.clone();
    unaccounted_terminal[0].connection_successes = 87;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &carry_in_before_fleet, &unaccounted_terminal);
    })
    .is_err());

    let mut new_attempt_storm = carry_in_after_fleet.clone();
    new_attempt_storm[0].connection_attempts = 87;
    new_attempt_storm[0].connection_successes = 86;
    new_attempt_storm[0].active_connections = 1;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &carry_in_before_fleet, &new_attempt_storm);
    })
    .is_err());

    let mut reconnect_attempt_storm = carry_in_after_fleet.clone();
    reconnect_attempt_storm[0].reconnect_attempts = 86;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &carry_in_before_fleet, &reconnect_attempt_storm);
    })
    .is_err());

    let mut reconnect_failure_storm = carry_in_after_fleet.clone();
    reconnect_failure_storm[0].reconnect_failures = 86;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &carry_in_before_fleet, &reconnect_failure_storm);
    })
    .is_err());

    let mut malformed_baseline = carry_in_before_fleet.clone();
    malformed_baseline[0].active_connections = 0;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &malformed_baseline, &carry_in_after_fleet);
    })
    .is_err());

    let mut storm = incident_fleet.clone();
    storm[0].connection_attempts = 86;
    storm[0].connection_successes = 83;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &before_fleet, &storm);
    })
    .is_err());

    let mut abandoned_attempt = incident_fleet;
    abandoned_attempt[0].connection_attempts = 4;
    abandoned_attempt[0].connection_abandoned = 1;
    assert!(std::panic::catch_unwind(|| {
        assert_recovery_fault_flush_bounds(3, &before_fleet, &abandoned_attempt);
    })
    .is_err());

    for unsafe_after in [
        QualificationConnectionLifecycleMetrics {
            connection_failure_protocol: 1,
            ..before
        },
        QualificationConnectionLifecycleMetrics {
            connection_failure_backend: 1,
            ..before
        },
        QualificationConnectionLifecycleMetrics {
            connection_abandoned: 1,
            ..before
        },
        QualificationConnectionLifecycleMetrics {
            drain_overruns: 1,
            ..before
        },
    ] {
        assert!(!recovery_fault_flush_has_no_unsafe_outcomes(
            &before,
            &unsafe_after
        ));
    }
}

#[test]
fn chained_interval_bounds_reject_an_attempt_storm_between_named_phases() {
    let member_count = 3;
    let before = vec![lifecycle_metrics_fixture(); member_count];
    let mut after = before.clone();
    let bound = QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR
        * u64::try_from(member_count - 1).expect("bounded member count")
        + QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE;
    after[0].connection_attempts = bound + 1;
    after[0].connection_successes = bound + 1;
    let rejected = std::panic::catch_unwind(|| {
        assert_lifecycle_delta_bounds(member_count, &before, &after, 0);
    });
    assert!(rejected.is_err());
}

#[test]
fn traffic_progress_requires_every_observer_watch_dimension_and_key_to_advance() {
    let before = traffic_status_fixture(3);
    let mut after = before.clone();
    after.mutation_cycles += 1;
    after.linearizable_reads += 1;
    after.lease_renewals += 1;
    after.lease_reacquisitions += 1;
    after.complete_restore_scans += 1;
    after.durable_readiness_probes += 1;
    after.last_generation += 1;
    after.last_record_fence += 1;
    after.watch_entries += 3;
    after.watch_applied_records += 3;
    after.watch_sequence += 3;
    for generation in &mut after.watch_traffic_generations {
        *generation += 1;
    }
    assert!(traffic_status_made_semantic_progress(&before, &after, 3));

    for stalled in [
        "mutation",
        "read",
        "renew",
        "reacquire",
        "restore",
        "readiness",
        "generation",
        "fence",
        "entries",
        "applied",
        "sequence",
        "key",
    ] {
        let mut candidate = after.clone();
        match stalled {
            "mutation" => candidate.mutation_cycles = before.mutation_cycles,
            "read" => candidate.linearizable_reads = before.linearizable_reads,
            "renew" => candidate.lease_renewals = before.lease_renewals,
            "reacquire" => candidate.lease_reacquisitions = before.lease_reacquisitions,
            "restore" => candidate.complete_restore_scans = before.complete_restore_scans,
            "readiness" => candidate.durable_readiness_probes = before.durable_readiness_probes,
            "generation" => candidate.last_generation = before.last_generation,
            "fence" => candidate.last_record_fence = before.last_record_fence,
            "entries" => candidate.watch_entries = before.watch_entries,
            "applied" => candidate.watch_applied_records = before.watch_applied_records,
            "sequence" => candidate.watch_sequence = before.watch_sequence,
            "key" => candidate.watch_traffic_generations[1] = before.watch_traffic_generations[1],
            _ => unreachable!(),
        }
        assert!(
            !traffic_status_made_semantic_progress(&before, &candidate, 3),
            "stalled semantic watch dimension was accepted: {stalled}"
        );
    }
}

#[test]
fn transition_deadline_never_accepts_a_late_success() {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(10);
    assert!(deadline_allows_completion(deadline, deadline));
    assert!(!deadline_allows_completion(
        deadline + Duration::from_nanos(1),
        deadline
    ));

    let operation_timeout = Duration::from_millis(QUALIFICATION_OPERATION_TIMEOUT_MILLIS);
    assert!(deadline_admits_complete_operation(
        started,
        started + operation_timeout
    ));
    assert!(!deadline_admits_complete_operation(
        started,
        started + operation_timeout - Duration::from_nanos(1)
    ));
}

#[test]
fn transition_completion_requires_drained_epochs_and_bounded_live_handlers() {
    let member_count = 3;
    assert_eq!(QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE, 8);
    assert_eq!(outbound_consensus_socket_bound(3), 4);
    assert_eq!(outbound_consensus_socket_bound(5), 8);
    assert_eq!(outbound_consensus_socket_bound(31), 60);
    assert_eq!(lifecycle_active_connection_bound(3), 8);
    assert_eq!(lifecycle_active_connection_bound(5), 16);
    assert_eq!(lifecycle_active_connection_bound(31), 120);
    assert_eq!(server_rotation_overlap_connection_bound(31), 120);
    assert!(server_rotation_overlap_connection_bound(31) <= QUALIFICATION_INBOUND_CONNECTION_SLOTS);
    assert_eq!(process_file_descriptor_high_water_bound(3, 0), 140);
    assert_eq!(process_file_descriptor_high_water_bound(5, 0), 144);
    let settled = lifecycle_metrics_fixture();
    assert!(lifecycle_transition_is_settled(&settled, member_count));

    let mut draining = settled;
    draining.draining_connections = 1;
    assert!(!lifecycle_transition_is_settled(&draining, member_count));
    let mut incomplete_drain = settled;
    incomplete_drain.drain_started = 1;
    assert!(!lifecycle_transition_is_settled(
        &incomplete_drain,
        member_count
    ));
    let mut overrun = settled;
    overrun.drain_started = 1;
    overrun.drain_completed = 1;
    overrun.drain_overruns = 1;
    assert!(!lifecycle_transition_is_settled(&overrun, member_count));
    let mut too_many_active = settled;
    too_many_active.active_connections = lifecycle_active_connection_bound(member_count) + 1;
    assert!(!lifecycle_transition_is_settled(
        &too_many_active,
        member_count
    ));
}

#[test]
fn pending_command_diagnostic_is_deterministic_and_payload_free() {
    let command = QualificationNodeCommand::CompareAndSet {
        lease_handle: "secret-lease-handle".to_owned(),
        stable_id: "secret-stable-id".to_owned(),
        expected_generation: Some(3),
        new_generation: 4,
        value: "secret-payload".to_owned(),
    };
    let sent_at = Instant::now();
    let pending = PendingCommand {
        kind: PendingCommandKind::from_command(&command),
        sequence: 7,
        sent_at,
    };
    let diagnostic = pending.diagnostic_at(sent_at + Duration::from_millis(42));

    assert_eq!(
        diagnostic,
        PendingCommandDiagnostic {
            kind: PendingCommandKind::CompareAndSet,
            sequence: 7,
            send_elapsed_millis: 42,
        }
    );
    assert_eq!(
        format!("{diagnostic:?}"),
        "PendingCommandDiagnostic { kind: CompareAndSet, sequence: 7, send_elapsed_millis: 42 }"
    );
}

#[test]
fn persistent_connection_attempt_accounting_is_non_overlapping() {
    let mut metrics = lifecycle_metrics_fixture();
    metrics.active_connections = 5;
    metrics.connection_attempts = 8;
    metrics.connection_successes = 5;
    assert_eq!(connection_attempt_accounting(&metrics), Some((5, 3, 5)));
    assert!(connection_attempts_accounted(&metrics));

    // Two successful outbound connections can remain active alongside three
    // unterminated inbound handlers. Adding all five active gauges to the five
    // terminal successes would double-count those outbound connections.
    metrics.active_connections = 2;
    assert!(!connection_attempts_accounted(&metrics));
    metrics.active_connections = 2;
    metrics.draining_connections = 1;
    assert!(connection_attempts_accounted(&metrics));

    metrics.connection_attempts = 4;
    assert_eq!(connection_attempt_accounting(&metrics), None);
}

#[test]
fn sqlite_family_reader_requires_primary_and_rejects_sidecar_read_errors() {
    let directory = tempfile::tempdir().expect("SQLite family helper directory");
    let database = directory.path().join("session.sqlite");

    let missing = read_sqlite_family(&database).expect_err("missing primary must fail");
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);

    fs::create_dir(&database).expect("create non-file primary fixture");
    let unreadable_primary = read_sqlite_family(&database).expect_err("non-file primary must fail");
    assert_ne!(unreadable_primary.kind(), std::io::ErrorKind::NotFound);
    fs::remove_dir(&database).expect("remove non-file primary fixture");

    fs::write(&database, b"primary").expect("write primary SQLite fixture");
    let primary_only = read_sqlite_family(&database).expect("absent sidecars are optional");
    assert_eq!(primary_only, [(database.clone(), b"primary".to_vec())]);

    let wal = PathBuf::from(format!("{}-wal", database.display()));
    fs::create_dir(&wal).expect("create unreadable WAL fixture");
    let unreadable = read_sqlite_family(&database).expect_err("non-file WAL must fail");
    assert_ne!(unreadable.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn plaintext_canary_domain_validation_covers_both_fixed_prefixes() {
    let values = vec![
        "opc-rotation-plaintext-canary/3/1/fixture".to_owned(),
        qualification_traffic_value(1, 3, 0, 1),
    ];
    assert_eq!(
        retained_plaintext_canary_domain_counts(&values),
        Some([1, 1])
    );
    assert_eq!(
        retained_plaintext_canary_domain_counts(&["unknown-canary/fixture".to_owned()]),
        None
    );
}

#[test]
fn plaintext_canary_prefix_scan_detects_each_domain() {
    for (index, prefix) in PLAINTEXT_CANARY_PREFIXES.into_iter().enumerate() {
        let mut artifact = b"bounded-prefix-fixture/".to_vec();
        artifact.extend_from_slice(prefix);
        artifact.extend_from_slice(b"suffix");
        let presence = plaintext_canary_prefix_presence(&artifact);
        assert!(presence[index]);
    }
}

#[test]
fn plaintext_canary_prefix_scan_accepts_clean_similar_artifacts() {
    assert_eq!(
        plaintext_canary_prefix_presence(
            b"opc-rotation-plaintext-canary;opc-rotation-traffic-canary;encrypted"
        ),
        [false, false]
    );
}
