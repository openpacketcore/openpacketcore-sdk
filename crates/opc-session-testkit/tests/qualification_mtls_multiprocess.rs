#![cfg(target_os = "linux")]

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::Bytes;
use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_identity::projected_svid::MIN_PROJECTED_SVID_POLL_INTERVAL;
use opc_identity::{
    build_identity_state, parse_certs_pem, parse_key_pem, IdentityState, TrustBundle,
    TrustBundleSet, TrustDomain,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_net::{
    ConnectionLifecyclePolicy, FencedMutationRosterAdmissionInput,
    FencedMutationRosterAdmissionOutcome, FencedMutationRosterAdmissionProposal,
    FencedMutationRosterAttestationTrustRootV1, FencedMutationRosterClient,
    FencedMutationRosterCompactTerminalMemberSigningInputV2,
    FencedMutationRosterEstablishedMutation, FencedMutationRosterExecutorAttestor,
    FencedMutationRosterExecutorCertificatePartsV1, FencedMutationRosterExecutorError,
    FencedMutationRosterId, FencedMutationRosterMember, FencedMutationRosterMemberCall,
    FencedMutationRosterMemberOperationId, FencedMutationRosterMemberProvider,
    FencedMutationRosterProfile, FencedMutationRosterProviderCallOutcome,
    FencedMutationRosterRecoveryInput, PersistentSessionConsumerClient,
    PersistentSessionConsumerConfig, PersistentSessionConsumerExecuteError,
    PersistentSessionConsumerV2Diagnostics, PersistentSessionConsumerV2ExecuteError,
    RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConsumerClientError, SessionConsumerLeaseMutationError,
    SessionReplicationManifest, StatelessSessionConsumerClient,
    CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE, DEFAULT_MAX_AUTHENTICATION_AGE,
    DEFAULT_RECONNECT_BACKOFF_MAX, DEFAULT_RECONNECT_BACKOFF_MIN, DEFAULT_ROTATION_DRAIN_WINDOW,
    DEFAULT_ROTATION_JITTER, SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
};
use opc_session_store::fenced_mutation_roster::{
    RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
    RosterAttestationLeafCertificateV1,
};
use opc_session_store::{
    AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet, EncryptedSessionPayload,
    FenceToken, FencedTransitionLease, FencedTransitionMutation, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionV2CallerNonce, FencedTransitionV2Capability,
    FencedTransitionV2HistoryEpoch, FencedTransitionV2Request, FencedTransitionV2RequestId,
    Generation, LeaseGuard, OwnerId, QuorumReplicaDescriptor, QuorumTopologyConfig,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionConsensusIdentity, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusWireRequest, SessionConsumerFencedTransitionError,
    SessionConsumerFencedTransitionStatus, SessionConsumerLeaseMutationOperation,
    SessionConsumerLeaseMutationRequest, SessionConsumerLeaseMutationResult,
    SessionConsumerLeaseMutationStatus, SessionConsumerOperation, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerScope, SessionConsumerStoreError, SessionConsumerV2FencedTransitionError,
    SessionConsumerV2FencedTransitionStatus, SessionConsumerV2Operation, SessionConsumerV2Request,
    SessionConsumerV2Response, SessionConsumerVoterAuthority, SessionKey, SessionKeyType,
    StateClass, StateType, StoreError, StoredSessionRecord, ValidatedQuorumTopology,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_roster_attestation_trust_root,
    qualification_traffic_schedule_sha256, qualification_traffic_seed, qualification_traffic_value,
    qualification_value_sha256, read_bounded_json_line,
    session_mtls_batch_release_gate_achieved_rate_milli,
    session_mtls_batch_release_gate_schedule_sha256, session_mtls_candidate_schedule_sha256,
    write_json_line, QualificationConnectionLifecycleConfig,
    QualificationConnectionLifecycleMetrics, QualificationConsensusRpcAvailability,
    QualificationMember, QualificationNodeCommand, QualificationNodeCommandKind,
    QualificationNodeConfig, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationPeerRouting, QualificationPersistentConsumerAuthorityV9,
    QualificationPersistentConsumerBindingsV9, QualificationPersistentConsumerInvocationV9,
    QualificationPersistentConsumerLaneV9, QualificationPersistentConsumerProcessLedgerV9,
    QualificationPersistentConsumerProvenanceV9, QualificationPersistentConsumerReleaseGateV9,
    QualificationProjectedMtlsConfig, QualificationProjectedSvidAvailability,
    QualificationProjectedSvidReason, QualificationProjectedSvidStatus, QualificationReadinessCode,
    QualificationSecurityMetricsSnapshot, QualificationTlsMaterialAvailability,
    QualificationTlsMaterialReason, QualificationTlsMaterialStatus, QualificationTrafficErrorClass,
    QualificationTrafficFailureCode, QualificationTrafficFailureStage, QualificationTrafficState,
    QualificationTrafficStatus, QualificationTransportConfig,
    SessionHaPersistentConsumerHeadEvidenceV9, SessionHaPersistentConsumerHeadEvidenceV9Error,
    SessionMtlsBatchReleaseGateBindingsV1, SessionMtlsBatchReleaseGateEvidenceV1,
    SessionMtlsBatchReleaseGatePoolEvidenceV1, SessionMtlsBatchReleaseGatePoolRoleV1,
    SessionMtlsBatchReleaseGateResourceGenerationV1,
    SessionMtlsBatchReleaseGateServerQueueDepthScopeV1, SessionMtlsCandidateCampaign,
    SessionMtlsCandidateEvidenceV2, SessionMtlsCandidateSourceTreeStatus,
    QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS, QUALIFICATION_CONSENSUS_CONNECTION_LANES_PER_PEER,
    QUALIFICATION_FAULT_EXPIRY_VALIDITY_MILLIS, QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS,
    QUALIFICATION_FAULT_PATH_REFRESH_MILLIS, QUALIFICATION_FAULT_TRAFFIC_STOP_LEAD_MILLIS,
    QUALIFICATION_INBOUND_CONNECTION_SLOTS, QUALIFICATION_MAX_CONFIG_BYTES,
    QUALIFICATION_MAX_IN_FLIGHT_PROPOSALS_PER_OPENRAFT_NODE, QUALIFICATION_NODE_SCHEMA_VERSION,
    QUALIFICATION_OPERATION_TIMEOUT_MILLIS, QUALIFICATION_PERSISTENT_CONSUMER_MIN_WARM_SAMPLES_V7,
    QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS, QUALIFICATION_RESOLVER_PROOF_MILLIS,
    QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE, QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE,
    QUALIFICATION_RESOURCE_SAMPLE_MILLIS, QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB,
    QUALIFICATION_RESOURCE_SETTLE_MILLIS, QUALIFICATION_RESOURCE_STABLE_SAMPLES,
    QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE, QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB,
    QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR,
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
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_FINAL_READINESS_PROBE_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_OUTAGE_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_PROFILE,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RECOVERY_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RESUME_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_STARTUP_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TERMINATION_MILLIS,
    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_TOTAL_MILLIS,
    QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS,
    SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_MAX_BYTES,
    SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_SCHEMA_JSON,
    SESSION_MTLS_BATCH_RELEASE_GATE_AGGREGATE_SETUP_ATTEMPT_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_AGGREGATE_SETUP_FAILURE_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_DELAYED_SETUP_ATTEMPT_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_DELAYED_SETUP_FAILURE_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_MIN_ACHIEVED_RATE_MILLI,
    SESSION_MTLS_BATCH_RELEASE_GATE_NEGATIVE_SETUP_ATTEMPT_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_NEGATIVE_SETUP_FAILURE_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_ORIGINAL_SETUP_ATTEMPT_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_ORIGINAL_SETUP_FAILURE_CEILING,
    SESSION_MTLS_BATCH_RELEASE_GATE_P999_CEILING_MILLIS,
    SESSION_MTLS_BATCH_RELEASE_GATE_P99_CEILING_MILLIS,
    SESSION_MTLS_CANDIDATE_EVIDENCE_V2_SCHEMA_JSON,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, renameat_with, unlinkat, AtFlags, FileType, Mode,
    OFlags, RenameFlags,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::{oneshot, watch};

use opc_tls::TlsConfigBuilder;

const CLUSTER_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
);
// Functional recovery bound for the stateless-consumer fault detector. This
// is deliberately not the profile's 30-second production-evidence threshold:
// the pinned engine may retain one leader lease, defer one smaller-log
// campaign, resample through one split campaign, and consume one vote plus
// readiness-operation deadline. Exceeding the profile threshold still
// withholds production evidence; this test only proves eventual consumer
// recovery through that explicitly bounded engine path.
const STATELESS_CONSUMER_LEADER_RECOVERY_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 6
        + DURABLE_CONSENSUS_TIMING_PROFILE.vote_timeout_millis
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
);
const CHILD_TIMEOUT: Duration = Duration::from_millis(QUALIFICATION_CHILD_RESPONSE_TIMEOUT_MILLIS);
/// This is intentionally shorter than the qualification child's fixed
/// post-commit response delay. It exercises the real response deadline rather
/// than creating a synthetic application outcome.
const DELAYED_CONSUMER_CLIENT_DEADLINE: Duration = Duration::from_millis(250);
// The protected roster is exercised across multiple bounded election,
// process-restart, and second-voter-loss windows. Its authority transitions
// are explicit releases and higher fences, never incidental wall-clock expiry.
const PROTECTED_ROSTER_LEASE_TTL: Duration = Duration::from_secs(60 * 60);
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
const FS_VERITY_QUALIFICATION_ENV: &str = "OPC_FS_VERITY_QUALIFICATION";
const FS_VERITY_SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";
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
    certified: rcgen::CertifiedIssuer<'static, KeyPair>,
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
    process_id: u32,
    samples: u64,
    file_descriptors: usize,
    threads: usize,
    vm_rss_kib: u64,
    vm_hwm_kib: u64,
}

struct ResourceSampler {
    stop: Arc<AtomicBool>,
    process_ids: Arc<Mutex<Vec<Option<u32>>>>,
    handle: JoinHandle<io::Result<Vec<Vec<ProcessResourceHighWater>>>>,
}

fn record_resource_generation_sample(
    high_water: &mut [Vec<ProcessResourceHighWater>],
    observed_process_ids: &mut [Option<u32>],
    node_index: usize,
    process_id: u32,
    snapshot: ProcessResourceSnapshot,
) {
    if observed_process_ids[node_index] != Some(process_id) {
        if observed_process_ids[node_index].is_some() {
            high_water[node_index].push(ProcessResourceHighWater {
                process_id,
                samples: 0,
                file_descriptors: 0,
                threads: 0,
                vm_rss_kib: 0,
                vm_hwm_kib: 0,
            });
        }
        observed_process_ids[node_index] = Some(process_id);
    }
    let current = high_water[node_index]
        .last_mut()
        .expect("logical voter has one resource generation");
    current.samples = current.samples.saturating_add(1);
    current.file_descriptors = current.file_descriptors.max(snapshot.file_descriptors);
    current.threads = current.threads.max(snapshot.threads);
    current.vm_rss_kib = current.vm_rss_kib.max(snapshot.vm_rss_kib);
    current.vm_hwm_kib = current.vm_hwm_kib.max(snapshot.vm_hwm_kib);
}

impl ResourceSampler {
    fn start(process_ids: Vec<u32>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let process_ids = Arc::new(Mutex::new(
            process_ids.into_iter().map(Some).collect::<Vec<_>>(),
        ));
        let process_ids_for_thread = Arc::clone(&process_ids);
        let handle = thread::Builder::new()
            .name("qualification-resource-sampler".to_owned())
            .spawn(move || {
                let initial_process_ids = process_ids_for_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let mut high_water = initial_process_ids
                    .iter()
                    .map(|process_id| {
                        vec![ProcessResourceHighWater {
                            process_id: process_id.expect("initial sampler PID is present"),
                            samples: 0,
                            file_descriptors: 0,
                            threads: 0,
                            vm_rss_kib: 0,
                            vm_hwm_kib: 0,
                        }]
                    })
                    .collect::<Vec<_>>();
                let mut observed_process_ids = vec![None; high_water.len()];
                loop {
                    let current_process_ids = process_ids_for_thread
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    for (index, process_id) in current_process_ids.into_iter().enumerate() {
                        let Some(process_id) = process_id else {
                            continue;
                        };
                        let snapshot = match read_process_resources(process_id, false) {
                            Ok(snapshot) => snapshot,
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                                let current = process_ids_for_thread
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)[index];
                                if current != Some(process_id) {
                                    continue;
                                }
                                return Err(error);
                            }
                            Err(error) => return Err(error),
                        };
                        record_resource_generation_sample(
                            &mut high_water,
                            &mut observed_process_ids,
                            index,
                            process_id,
                            snapshot,
                        );
                    }
                    if stop_for_thread.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(QUALIFICATION_RESOURCE_SAMPLE_MILLIS));
                }
                Ok(high_water)
            })
            .expect("start qualification resource sampler");
        Self {
            stop,
            process_ids,
            handle,
        }
    }

    fn mark_offline(&self, node_index: usize) {
        self.process_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index] = None;
    }

    fn install_restarted_process(&self, node_index: usize, process_id: u32) {
        self.process_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index] = Some(process_id);
    }

    fn finish(self) -> Vec<Vec<ProcessResourceHighWater>> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .join()
            .expect("join qualification resource sampler")
            .expect("sample live qualification processes")
    }
}

fn merge_resource_generation_high_water(
    generations: &[Vec<ProcessResourceHighWater>],
) -> Vec<ProcessResourceHighWater> {
    generations
        .iter()
        .map(|voter_generations| {
            voter_generations.iter().copied().fold(
                ProcessResourceHighWater {
                    process_id: 0,
                    samples: 0,
                    file_descriptors: 0,
                    threads: 0,
                    vm_rss_kib: 0,
                    vm_hwm_kib: 0,
                },
                |mut merged, generation| {
                    merged.samples = merged.samples.saturating_add(generation.samples);
                    merged.file_descriptors =
                        merged.file_descriptors.max(generation.file_descriptors);
                    merged.threads = merged.threads.max(generation.threads);
                    merged.vm_rss_kib = merged.vm_rss_kib.max(generation.vm_rss_kib);
                    merged.vm_hwm_kib = merged.vm_hwm_kib.max(generation.vm_hwm_kib);
                    merged
                },
            )
        })
        .collect()
}

fn cumulative_replaced_v2_diagnostics(
    released_before_shutdown: PersistentSessionConsumerV2Diagnostics,
    restored_current: PersistentSessionConsumerV2Diagnostics,
) -> PersistentSessionConsumerV2Diagnostics {
    PersistentSessionConsumerV2Diagnostics {
        setup_attempts: released_before_shutdown
            .setup_attempts
            .saturating_add(restored_current.setup_attempts),
        setup_failures: released_before_shutdown
            .setup_failures
            .saturating_add(restored_current.setup_failures),
        setup_successes: released_before_shutdown
            .setup_successes
            .saturating_add(restored_current.setup_successes),
        reused: released_before_shutdown
            .reused
            .saturating_add(restored_current.reused),
        reconnects: released_before_shutdown
            .reconnects
            .saturating_add(restored_current.reconnects),
        active: restored_current.active,
        idle: restored_current.idle,
        pool_wait_current: restored_current.pool_wait_current,
        pool_wait_max: released_before_shutdown
            .pool_wait_max
            .max(restored_current.pool_wait_max),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupAccounting {
    attempts: u64,
    failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MtlsSetupAccounting {
    original_and_restored: SetupAccounting,
    supplemental: SetupAccounting,
}

impl MtlsSetupAccounting {
    fn total(self) -> SetupAccounting {
        SetupAccounting {
            attempts: self
                .original_and_restored
                .attempts
                .saturating_add(self.supplemental.attempts),
            failures: self
                .original_and_restored
                .failures
                .saturating_add(self.supplemental.failures),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MtlsSetupCeilings {
    original_and_restored: SetupAccounting,
    supplemental: SetupAccounting,
    total: SetupAccounting,
}

fn v2_batch_release_gate_setup_ceilings() -> MtlsSetupCeilings {
    let original_and_restored = SetupAccounting {
        attempts: SESSION_MTLS_BATCH_RELEASE_GATE_ORIGINAL_SETUP_ATTEMPT_CEILING,
        failures: SESSION_MTLS_BATCH_RELEASE_GATE_ORIGINAL_SETUP_FAILURE_CEILING,
    };
    let supplemental = SetupAccounting {
        attempts: SESSION_MTLS_BATCH_RELEASE_GATE_NEGATIVE_SETUP_ATTEMPT_CEILING
            .saturating_mul(2)
            .saturating_add(SESSION_MTLS_BATCH_RELEASE_GATE_DELAYED_SETUP_ATTEMPT_CEILING),
        failures: SESSION_MTLS_BATCH_RELEASE_GATE_NEGATIVE_SETUP_FAILURE_CEILING
            .saturating_mul(2)
            .saturating_add(SESSION_MTLS_BATCH_RELEASE_GATE_DELAYED_SETUP_FAILURE_CEILING),
    };
    MtlsSetupCeilings {
        original_and_restored,
        supplemental,
        total: SetupAccounting {
            attempts: SESSION_MTLS_BATCH_RELEASE_GATE_AGGREGATE_SETUP_ATTEMPT_CEILING,
            failures: SESSION_MTLS_BATCH_RELEASE_GATE_AGGREGATE_SETUP_FAILURE_CEILING,
        },
    }
}

fn verify_mtls_setup_accounting(
    observed: MtlsSetupAccounting,
    ceilings: MtlsSetupCeilings,
) -> Result<(), String> {
    let total = observed.total();
    for (scope, observed, ceiling) in [
        (
            "original_and_restored",
            observed.original_and_restored,
            ceilings.original_and_restored,
        ),
        ("supplemental", observed.supplemental, ceilings.supplemental),
        ("total", total, ceilings.total),
    ] {
        if observed.attempts > ceiling.attempts {
            return Err(format!(
                "mTLS setup attempt ceiling exceeded: scope={scope}, observed_attempts={}, bound_attempts={}, observed_failures={}, bound_failures={}",
                observed.attempts, ceiling.attempts, observed.failures, ceiling.failures
            ));
        }
        if observed.failures > ceiling.failures {
            return Err(format!(
                "mTLS setup failure ceiling exceeded: scope={scope}, observed_attempts={}, bound_attempts={}, observed_failures={}, bound_failures={}",
                observed.attempts, ceiling.attempts, observed.failures, ceiling.failures
            ));
        }
    }
    Ok(())
}

fn assert_no_fault_v2_setup_delta(
    window: &str,
    before: &[PersistentSessionConsumerV2Diagnostics],
    after: &[PersistentSessionConsumerV2Diagnostics],
) {
    assert_eq!(
        after.len(),
        before.len(),
        "mTLS {window} diagnostic snapshot cardinality is stable"
    );
    for (client_index, (after, before)) in after.iter().zip(before).enumerate() {
        let attempts = checked_no_fault_setup_delta(
            window,
            client_index,
            "setup_attempts",
            before.setup_attempts,
            after.setup_attempts,
        );
        let failures = checked_no_fault_setup_delta(
            window,
            client_index,
            "setup_failures",
            before.setup_failures,
            after.setup_failures,
        );
        assert_eq!(
            attempts, 0,
            "mTLS {window} must not resolve, connect, negotiate TLS, or send Hello per operation: client_index={client_index}, observed_setup_attempts={attempts}, bound_setup_attempts=0, observed_setup_failures={failures}, bound_setup_failures=0"
        );
        assert_eq!(
            failures, 0,
            "mTLS {window} must not resolve, connect, negotiate TLS, or send Hello per operation: client_index={client_index}, observed_setup_attempts={attempts}, bound_setup_attempts=0, observed_setup_failures={failures}, bound_setup_failures=0"
        );
    }
}

fn checked_no_fault_setup_delta(
    window: &str,
    client_index: usize,
    counter: &str,
    before: u64,
    after: u64,
) -> u64 {
    after.checked_sub(before).unwrap_or_else(|| {
        panic!(
            "mTLS {window} diagnostic counter regressed: client_index={client_index}, counter={counter}, before={before}, after={after}"
        )
    })
}

fn select_v2_batch_scheduler_client(
    preferred_client_index: usize,
    in_flight_per_client: &[usize],
    lanes_per_client: usize,
) -> Option<usize> {
    (0..in_flight_per_client.len())
        .map(|offset| (preferred_client_index + offset) % in_flight_per_client.len())
        .find(|client_index| in_flight_per_client[*client_index] < lanes_per_client)
}

#[test]
fn no_fault_setup_delta_rejects_per_client_counter_regression() {
    assert_eq!(
        checked_no_fault_setup_delta("pure-regression", 3, "setup_attempts", 7, 7),
        0
    );
    assert!(std::panic::catch_unwind(|| {
        checked_no_fault_setup_delta("pure-regression", 3, "setup_attempts", 7, 6)
    })
    .is_err());
}

#[test]
fn v2_batch_scheduler_no_eligible_boundary_requires_a_completed_admission() {
    let mut in_flight = vec![V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT; V2_BATCH_RELEASE_GATE_CLIENTS];
    assert_eq!(
        select_v2_batch_scheduler_client(0, &in_flight, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,),
        None,
        "a full four-lane client set cannot accept another scheduler admission"
    );
    in_flight[7] -= 1;
    assert_eq!(
        select_v2_batch_scheduler_client(0, &in_flight, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,),
        Some(7),
        "draining one completed alternate admission restores a deterministic slot"
    );
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

/// Emits only fixed-dimension lifecycle counters, so expiry/replacement
/// intervals can be attributed without exposing peer, subscriber, or process
/// identities in qualification diagnostics.
fn emit_fixed_lifecycle_connection_snapshot(
    phase: &str,
    metrics: &[QualificationConnectionLifecycleMetrics],
) {
    let ledger = metrics.iter().fold(
        ConnectionAttemptSettlementLedger {
            attempts: 0,
            successes: 0,
            transport_failures: 0,
            authentication_failures: 0,
            timeout_failures: 0,
            superseded: 0,
            abandoned: 0,
            protocol_failures: 0,
            backend_failures: 0,
            reconnect_attempts: 0,
            reconnect_failures: 0,
        },
        |mut aggregate, metric| {
            let current = connection_attempt_settlement_ledger(metric);
            aggregate.attempts = aggregate.attempts.saturating_add(current.attempts);
            aggregate.successes = aggregate.successes.saturating_add(current.successes);
            aggregate.transport_failures = aggregate
                .transport_failures
                .saturating_add(current.transport_failures);
            aggregate.authentication_failures = aggregate
                .authentication_failures
                .saturating_add(current.authentication_failures);
            aggregate.timeout_failures = aggregate
                .timeout_failures
                .saturating_add(current.timeout_failures);
            aggregate.superseded = aggregate.superseded.saturating_add(current.superseded);
            aggregate.abandoned = aggregate.abandoned.saturating_add(current.abandoned);
            aggregate.protocol_failures = aggregate
                .protocol_failures
                .saturating_add(current.protocol_failures);
            aggregate.backend_failures = aggregate
                .backend_failures
                .saturating_add(current.backend_failures);
            aggregate.reconnect_attempts = aggregate
                .reconnect_attempts
                .saturating_add(current.reconnect_attempts);
            aggregate.reconnect_failures = aggregate
                .reconnect_failures
                .saturating_add(current.reconnect_failures);
            aggregate
        },
    );
    println!(
        "MTLS_FIXED_LIFECYCLE_SNAPSHOT phase={phase} members={} connection_attempts={} connection_successes={} connection_failure_transport={} connection_failure_authentication={} connection_failure_timeout={} connection_superseded={} connection_abandoned={} connection_failure_protocol={} connection_failure_backend={} reconnect_attempts={} reconnect_failures={}",
        metrics.len(),
        ledger.attempts,
        ledger.successes,
        ledger.transport_failures,
        ledger.authentication_failures,
        ledger.timeout_failures,
        ledger.superseded,
        ledger.abandoned,
        ledger.protocol_failures,
        ledger.backend_failures,
        ledger.reconnect_attempts,
        ledger.reconnect_failures,
    );
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
            "fault-outcome flush exceeded the fixed per-node connection bound plus exact baseline carry-in: node={node_index}, counter=connection_terminal_outcomes, observed={terminal}, bound={terminal_bound}, new_attempt_bound={bound}, baseline_outstanding={baseline_outstanding}, attempts={attempts}, reconnect_attempts={reconnect_attempts}, reconnect_failures={reconnect_failures}, before={before:?}, after={after:?}"
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

fn deadline_admits_complete_restart_readiness_round(now: Instant, deadline: Instant) -> bool {
    now.checked_add(Duration::from_millis(
        QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_FINAL_READINESS_PROBE_MILLIS,
    ))
    .is_some_and(|round_deadline| round_deadline <= deadline)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveRestartReadinessRound {
    Recovery { deadline: Instant },
    WaitForFinal { dispatch_at: Instant },
    Final { deadline: Instant },
    Exhausted,
}

fn active_restart_readiness_round(
    now: Instant,
    recovery_deadline: Instant,
    catchup_deadline: Instant,
    final_round_started: bool,
) -> ActiveRestartReadinessRound {
    if deadline_admits_complete_restart_readiness_round(now, recovery_deadline) {
        return ActiveRestartReadinessRound::Recovery {
            deadline: now
                + Duration::from_millis(
                    QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_FINAL_READINESS_PROBE_MILLIS,
                ),
        };
    }
    if now < recovery_deadline {
        return ActiveRestartReadinessRound::WaitForFinal {
            dispatch_at: recovery_deadline,
        };
    }
    if final_round_started {
        ActiveRestartReadinessRound::Exhausted
    } else {
        ActiveRestartReadinessRound::Final {
            deadline: catchup_deadline,
        }
    }
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
            high_water.vm_rss_kib <= high_water.vm_hwm_kib,
            "VmRSS high-water exceeds VmHWM: node={node_index}, rss_kib={}, hwm_kib={}",
            high_water.vm_rss_kib,
            high_water.vm_hwm_kib
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
        let certified =
            rcgen::CertifiedIssuer::self_signed(parameters, key).expect("sign qualification root");
        Self { certified }
    }

    fn intermediate(common_name: &str, root: &Self) -> Self {
        let key = KeyPair::generate().expect("generate qualification intermediate key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let certified = rcgen::CertifiedIssuer::signed_by(parameters, key, &root.certified)
            .expect("sign qualification intermediate");
        Self { certified }
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
            rcgen::string::Ia5String::try_from(spiffe_id).expect("valid qualification SPIFFE URI"),
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
            .signed_by(&key, &self.certified)
            .expect("sign qualification workload certificate");
        ProjectedCredential {
            certificate_chain_pem: certificate.pem() + &self.certified.pem(),
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
#[derive(Clone, Copy)]
enum ConsumerCredentialGeneration {
    OldRoot,
    NewRoot,
}

struct TestPki {
    old_root_pem: String,
    new_root_pem: String,
    old_intermediate: Issuer,
    new_intermediate: Issuer,
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
            old_root_pem: old_root.certified.pem(),
            new_root_pem: new_root.certified.pem(),
            old_intermediate,
            new_intermediate,
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

    fn consumer_identity_state(&self, identity: &str) -> IdentityState {
        self.consumer_identity_state_with_trust(identity, TrustGeneration::OldOnly)
    }

    fn consumer_identity_state_with_trust(
        &self,
        identity: &str,
        trust_generation: TrustGeneration,
    ) -> IdentityState {
        let credential_generation = match trust_generation {
            TrustGeneration::OldOnly | TrustGeneration::Overlap => {
                ConsumerCredentialGeneration::OldRoot
            }
            TrustGeneration::NewOnly => ConsumerCredentialGeneration::NewRoot,
        };
        self.consumer_identity_state_with_generations(
            identity,
            credential_generation,
            trust_generation,
        )
    }

    fn consumer_identity_state_with_generations(
        &self,
        identity: &str,
        credential_generation: ConsumerCredentialGeneration,
        trust_generation: TrustGeneration,
    ) -> IdentityState {
        let credential = match credential_generation {
            ConsumerCredentialGeneration::OldRoot => self.old_intermediate.issue_workload(identity),
            ConsumerCredentialGeneration::NewRoot => self.new_intermediate.issue_workload(identity),
        };
        let trust_domain =
            TrustDomain::new("qualification.invalid").expect("qualification trust domain is valid");
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&self.trust_bundle(trust_generation))
                .expect("parse qualification consumer trust bundle"),
        });
        build_identity_state(
            parse_certs_pem(&credential.certificate_chain_pem)
                .expect("parse qualification consumer certificate chain"),
            parse_key_pem(&credential.private_key_pem)
                .expect("parse qualification consumer private key"),
            trust_bundles,
        )
        .expect("build qualification consumer identity state")
    }
}

enum ReaderMessage {
    Reply(Box<QualificationNodeReply>),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCommandKind {
    AwaitBound,
    Command(QualificationNodeCommandKind),
}

impl PendingCommandKind {
    fn from_command(command: &QualificationNodeCommand) -> Self {
        Self::Command(command.kind())
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

/// Release-only source and command binding. This accepts only a wholly clean
/// exact-head worktree, including untracked files and submodules.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseGateProvenance {
    source_revision: String,
    source_tree: String,
    source_worktree_sha256: String,
    cargo_lock_sha256: String,
    cargo_target_directory: String,
    cargo_target_directory_sha256: String,
    evidence_root_directory: String,
    evidence_root_directory_sha256: String,
    fs_verity_snapshot_root_directory: String,
    fs_verity_snapshot_root_directory_sha256: String,
    fs_verity_snapshot_root_device: u64,
    fs_verity_snapshot_root_inode: u64,
    pair_directory: String,
    pair_directory_sha256: String,
    command_argv_sha256: String,
    cargo_executable_alias: String,
    cargo_executable: String,
    cargo_executable_sha256: String,
    cargo_executable_mode: u16,
    canonical_cargo_argv: Vec<String>,
    cargo_profile: String,
    opt_level: String,
}

const RELEASE_GATE_EXPECTED_CARGO_ARGV: &[&str] = &[
    "cargo",
    "test",
    "--locked",
    "--release",
    "-p",
    "opc-session-testkit",
    "--test",
    "qualification_mtls_multiprocess",
    "--no-default-features",
    "three_process_projected_mtls_persistent_v2_batch_release_gate",
    "--",
    "--ignored",
    "--exact",
    "--test-threads=1",
    "--nocapture",
];

impl ReleaseGateProvenance {
    fn capture() -> io::Result<Self> {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        release_gate_provenance_at(&repository)
    }

    fn verify_unchanged(&self) -> io::Result<()> {
        if Self::capture()? != *self {
            return Err(io::Error::other(
                "release-gate source or canonical command binding changed during the campaign",
            ));
        }
        Ok(())
    }
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
    // The immutable snapshot namespace has a distinct lifecycle from mutable
    // workspace files, but must survive until every child has stopped.
    _snapshot_namespace: Option<PinnedV9SnapshotNamespace>,
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
    readiness_probe_commands: usize,
}

/// Retain no-follow descriptors for both the configured fs-verity base and
/// the fresh campaign child. The child configs carry the child identity, so
/// the node cannot accept a substituted namespace merely because its path and
/// inherited environment still look plausible.
struct PinnedV9SnapshotNamespace {
    // Kept rather than recursively removed on Drop: after a failed identity
    // check, pathname cleanup could otherwise delete a same-UID replacement.
    namespace: PathBuf,
    base: PathBuf,
    base_descriptor: OwnedFd,
    base_device: u64,
    base_inode: u64,
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
}

impl PinnedV9SnapshotNamespace {
    fn path(&self) -> &Path {
        &self.namespace
    }

    fn device(&self) -> u64 {
        self.device
    }

    fn inode(&self) -> u64 {
        self.inode
    }

    fn verify(&self) -> io::Result<()> {
        let base = fstat(&self.base_descriptor)?;
        let namespace = fstat(&self.descriptor)?;
        let base_metadata = fs::symlink_metadata(&self.base)?;
        let namespace_metadata = fs::symlink_metadata(self.path())?;
        let private_directory = |metadata: &fs::Metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode() & 0o7777 == 0o700
        };
        if !private_directory(&base_metadata)
            || !private_directory(&namespace_metadata)
            || base.st_dev as u64 != self.base_device
            || base.st_ino as u64 != self.base_inode
            || base_metadata.dev() != self.base_device
            || base_metadata.ino() != self.base_inode
            || namespace.st_dev as u64 != self.device
            || namespace.st_ino as u64 != self.inode
            || namespace_metadata.dev() != self.device
            || namespace_metadata.ino() != self.inode
            || fs::canonicalize(&self.base)? != self.base
            || fs::canonicalize(self.path())? != self.path()
            || self.path().parent() != Some(self.base.as_path())
        {
            return Err(io::Error::other(
                "V9 fs-verity snapshot namespace identity changed",
            ));
        }
        Ok(())
    }
}

fn stateless_consumer_voter_topology_for_configuration(
    members: &[QualificationMember],
    configuration_generation: &str,
    configuration_epoch: u64,
) -> ValidatedQuorumTopology {
    let descriptors = members
        .iter()
        .map(|member| {
            QuorumReplicaDescriptor::new(
                ReplicaId::new(member.replica_id.clone())
                    .expect("qualification consumer replica ID"),
                ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                    .expect("qualification consumer endpoint"),
                ReplicaTlsIdentity::new(member.tls_identity.clone())
                    .expect("qualification consumer TLS identity"),
                ReplicaFailureDomain::new(member.failure_domain.clone())
                    .expect("qualification consumer failure domain"),
                ReplicaBackingIdentity::new(member.backing_identity.clone())
                    .expect("qualification consumer backing identity"),
            )
        })
        .collect::<Vec<_>>();
    let roster_attestation_root = qualification_roster_attestation_trust_root();
    let manifest = SessionReplicationManifest::try_new_with_epoch_and_roster_attestation_root(
        SessionClusterId::new(format!("qualification-mtls-{}-cluster", members.len()))
            .expect("qualification consumer cluster ID"),
        SessionConfigurationGeneration::new(configuration_generation)
            .expect("qualification consumer configuration generation"),
        SessionConfigurationEpoch::new(configuration_epoch)
            .expect("qualification consumer configuration epoch"),
        descriptors.clone(),
        Some(roster_attestation_root.clone()),
    )
    .expect("qualification consumer replication manifest");
    let local_replica = descriptors
        .first()
        .expect("qualification consumer local replica")
        .replica_id()
        .clone();
    ValidatedQuorumTopology::try_from_fixed_durable_quorum(
        QuorumTopologyConfig::new_consensus_with_roster_attestation_trust_root(
            local_replica,
            descriptors,
            manifest.fixed_durable_quorum_consensus_identity(),
            roster_attestation_root,
        ),
    )
    .expect("qualification consumer validated fixed topology")
}

#[test]
fn stateless_consumer_voter_topology_binds_fixed_root_and_epoch_scope() {
    let members = (0..3)
        .map(|node_index| QualificationMember {
            node_index,
            replica_id: format!("node-{node_index}"),
            endpoint_host: format!("node-{node_index}.qualification.invalid"),
            endpoint_port: 41_000 + u16::try_from(node_index).expect("qualification node index"),
            dial_addr: None,
            tls_identity: spiffe_id(node_index),
            failure_domain: format!("zone-{node_index}"),
            backing_identity: format!("disk-{node_index}"),
        })
        .collect::<Vec<_>>();
    let topology = stateless_consumer_voter_topology_for_configuration(&members, "v1", 1);
    let expected_root = qualification_roster_attestation_trust_root();
    assert_eq!(
        topology
            .roster_attestation_trust_root()
            .map(opc_session_store::RosterAttestationTrustRootV1::identity),
        Some(expected_root.identity())
    );
    let roster = topology
        .session_consumer_roster()
        .expect("fixed qualification consumer roster");
    assert_eq!(
        topology.consensus_identity(),
        Some(roster.scope().consensus_identity())
    );
    for member in &members {
        let replica_id =
            ReplicaId::new(member.replica_id.clone()).expect("qualification consumer replica ID");
        let node_id = topology
            .consensus_node_id(&replica_id)
            .expect("qualification consumer consensus node ID");
        let authority = roster
            .voter(node_id)
            .expect("qualification consumer voter authority");
        assert_eq!(authority.scope(), roster.scope());
        assert_eq!(authority.tls_identity(), member.tls_identity);
        assert_eq!(authority.voter_count(), members.len());
    }

    let epoch_two = stateless_consumer_voter_topology_for_configuration(&members, "v1-negative", 2)
        .session_consumer_roster()
        .expect("epoch-two qualification consumer roster");
    assert_ne!(roster.scope(), epoch_two.scope());
}

impl Fleet {
    fn fs_verity_snapshot_campaign_namespace(
        release_provenance: Option<&ReleaseGateProvenance>,
    ) -> Option<PinnedV9SnapshotNamespace> {
        let root = match env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV) {
            Some(root) => root,
            None => {
                assert_ne!(
                    env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref(),
                    Some(std::ffi::OsStr::new("required")),
                    "required fs-verity qualification needs {FS_VERITY_SNAPSHOT_ROOT_ENV}"
                );
                return None;
            }
        };
        assert_eq!(
            env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref(),
            Some(std::ffi::OsStr::new("required")),
            "{FS_VERITY_SNAPSHOT_ROOT_ENV} is accepted only for required fs-verity qualification"
        );
        let root = v9_canonical_fs_verity_snapshot_root_directory(Some(root))
            .expect("canonical private fs-verity snapshot root");
        if let Some(provenance) = release_provenance {
            assert!(
                root.directory.to_str()
                    == Some(provenance.fs_verity_snapshot_root_directory.as_str())
                    && root.device == provenance.fs_verity_snapshot_root_device
                    && root.inode == provenance.fs_verity_snapshot_root_inode,
                "V9 fs-verity snapshot root differs from captured release provenance"
            );
        }
        let base_descriptor = v9_open_private_external_root(&root.directory)
            .expect("open canonical private fs-verity snapshot root");
        let base_metadata = fstat(&base_descriptor).expect("fstat fs-verity snapshot root");
        assert_eq!(base_metadata.st_dev as u64, root.device);
        assert_eq!(base_metadata.st_ino as u64, root.inode);
        let namespace = tempfile::Builder::new()
            .prefix("opc-v9-snapshots-")
            .tempdir_in(&root.directory)
            .expect("create private V9 fs-verity snapshot namespace");
        let namespace_name = namespace
            .path()
            .file_name()
            .expect("fresh V9 fs-verity namespace direct name");
        let descriptor = openat(
            &base_descriptor,
            namespace_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open no-follow V9 fs-verity snapshot namespace");
        let descriptor_metadata =
            fstat(&descriptor).expect("fstat V9 fs-verity snapshot namespace");
        let namespace = namespace.keep();
        let metadata =
            fs::symlink_metadata(&namespace).expect("stat private V9 fs-verity snapshot namespace");
        assert!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode() & 0o7777 == 0o700
                && fs::canonicalize(&namespace)
                    .expect("canonical private V9 fs-verity snapshot namespace")
                    .starts_with(&root.directory),
            "V9 fs-verity snapshot namespace must remain private below its configured root"
        );
        let pinned = PinnedV9SnapshotNamespace {
            namespace,
            base: root.directory,
            base_descriptor,
            base_device: base_metadata.st_dev as u64,
            base_inode: base_metadata.st_ino as u64,
            descriptor,
            device: descriptor_metadata.st_dev as u64,
            inode: descriptor_metadata.st_ino as u64,
        };
        pinned
            .verify()
            .expect("pin V9 fs-verity snapshot namespace identity");
        Some(pinned)
    }

    fn start(member_count: usize) -> Self {
        let schedule = session_mtls_candidate_schedule_sha256(
            SessionMtlsCandidateCampaign::RotationCore,
            member_count,
        )
        .expect("supported rotation-core candidate topology");
        Self::start_with_schedule(member_count, schedule, None)
    }

    fn start_traffic(member_count: usize) -> Self {
        let schedule = qualification_traffic_schedule_sha256(member_count)
            .expect("supported traffic qualification topology");
        Self::start_with_schedule(member_count, schedule, None)
    }

    fn start_with_release_provenance(
        member_count: usize,
        release_provenance: &ReleaseGateProvenance,
    ) -> Self {
        let schedule = session_mtls_candidate_schedule_sha256(
            SessionMtlsCandidateCampaign::RotationCore,
            member_count,
        )
        .expect("supported rotation-core candidate topology");
        Self::start_with_schedule(member_count, schedule, Some(release_provenance))
    }

    fn start_with_schedule(
        member_count: usize,
        workload_schedule_sha256: String,
        release_provenance: Option<&ReleaseGateProvenance>,
    ) -> Self {
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
        let snapshot_namespace = Self::fs_verity_snapshot_campaign_namespace(release_provenance);
        if let Some(namespace) = &snapshot_namespace {
            assert_ne!(
                fs::metadata(workspace.path())
                    .expect("stat ordinary V9 qualification workspace")
                    .dev(),
                fs::metadata(namespace.path())
                    .expect("stat V9 fs-verity snapshot namespace")
                    .dev(),
                "V9 mutable workspace must not share the fs-verity snapshot filesystem"
            );
            namespace
                .verify()
                .expect("revalidate V9 fs-verity snapshot namespace before child configuration");
        }
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
            let snapshots = snapshot_namespace
                .as_ref()
                .map(|namespace| namespace.path().join(format!("node-{node_index}")))
                .unwrap_or_else(|| node_root.join("snapshots"));
            let database_path = node_root.join("session.sqlite");
            fs::create_dir(&projected_root).expect("create projected root");
            fs::create_dir(&snapshots).expect("create snapshots root");
            if snapshot_namespace.is_some() {
                fs::set_permissions(&snapshots, Permissions::from_mode(0o700))
                    .expect("make V9 fs-verity snapshot leaf owner private");
            }
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
                snapshot_root_directory: snapshot_namespace
                    .as_ref()
                    .map(|namespace| namespace.path().to_path_buf()),
                snapshot_root_device: snapshot_namespace
                    .as_ref()
                    .map(PinnedV9SnapshotNamespace::device),
                snapshot_root_inode: snapshot_namespace
                    .as_ref()
                    .map(PinnedV9SnapshotNamespace::inode),
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
        if let Some(namespace) = &snapshot_namespace {
            namespace
                .verify()
                .expect("revalidate V9 fs-verity snapshot namespace before child startup");
        }

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
            _snapshot_namespace: snapshot_namespace,
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
            readiness_probe_commands: 0,
        };
        fleet.wait_ready();
        fleet.assert_all_material_ready();
        fleet.verify_snapshot_namespace();
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

    fn verify_snapshot_namespace(&self) {
        if let Some(namespace) = &self._snapshot_namespace {
            namespace
                .verify()
                .expect("V9 fs-verity snapshot namespace changed during campaign");
        }
    }

    fn member_count(&self) -> usize {
        self.nodes.len()
    }

    fn required_quorum(&self) -> usize {
        self.member_count() / 2 + 1
    }

    fn start_stateless_consumer(
        &mut self,
        node_index: usize,
        consumer_identities: Vec<String>,
    ) -> (SocketAddr, SessionConsumerScope) {
        match self.nodes[node_index].invoke(&QualificationNodeCommand::StartStatelessConsumer {
            consumer_identities,
        }) {
            QualificationNodeReply::StatelessConsumerStarted { bind_addr, scope } => {
                (bind_addr, scope)
            }
            reply => panic!(
                "stateless consumer listener did not start: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn arm_stateless_consumer_delayed_response(&mut self, node_index: usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::ArmStatelessConsumerDelayedResponse)
        {
            QualificationNodeReply::StatelessConsumerDelayedResponseArmed => {}
            reply => panic!(
                "stateless consumer delayed-response simulation did not arm: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    /// Derive the exact server authority from the same validated immutable
    /// qualification topology used by every child. This preserves the node,
    /// SPIFFE identity, voter count, and roster commitment together rather
    /// than rebuilding client authority from identity text or consumer scope.
    fn stateless_consumer_voter_authorities(&self) -> Vec<SessionConsumerVoterAuthority> {
        self.stateless_consumer_voter_authorities_for_configuration("v1", 1)
    }

    /// Mint a separately validated authority for an intentionally distinct
    /// configuration scope.  This is used only as a negative Hello control:
    /// its TLS identities still name these real voters, but its committed
    /// cluster/configuration/epoch scope cannot authorize this listener.
    fn stateless_consumer_voter_authorities_for_configuration(
        &self,
        configuration_generation: &str,
        configuration_epoch: u64,
    ) -> Vec<SessionConsumerVoterAuthority> {
        let topology = stateless_consumer_voter_topology_for_configuration(
            &self.members,
            configuration_generation,
            configuration_epoch,
        );
        let roster = topology
            .session_consumer_roster()
            .expect("qualification consumer roster");

        self.members
            .iter()
            .map(|member| {
                let replica_id = ReplicaId::new(member.replica_id.clone())
                    .expect("qualification consumer replica ID");
                let node_id = topology
                    .consensus_node_id(&replica_id)
                    .expect("qualification consumer consensus node ID");
                let authority = roster
                    .voter(node_id)
                    .expect("qualification consumer voter authority");
                assert_eq!(authority.tls_identity(), member.tls_identity);
                assert_eq!(authority.voter_count(), self.member_count());
                authority
            })
            .collect()
    }

    fn arm_stateless_consumer_response_holds(&mut self, node_index: usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::ArmStatelessConsumerResponseHolds)
        {
            QualificationNodeReply::StatelessConsumerResponseHoldsArmed { responses: 4 } => {}
            reply => panic!(
                "stateless consumer four-response hold gate did not arm: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn stateless_consumer_response_hold_status(&mut self, node_index: usize) -> (usize, usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::StatelessConsumerResponseHoldStatus)
        {
            QualificationNodeReply::StatelessConsumerResponseHoldStatus {
                armed_responses,
                held_responses,
            } => (armed_responses, held_responses),
            reply => panic!(
                "stateless consumer four-response hold status unavailable: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn release_stateless_consumer_response_holds(&mut self, node_index: usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::ReleaseStatelessConsumerResponseHolds)
        {
            QualificationNodeReply::StatelessConsumerResponseHoldsReleased { responses: 4 } => {}
            reply => panic!(
                "stateless consumer four-response hold gate did not release: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn arm_stateless_consumer_ambiguity_witness_hold(&mut self, node_index: usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::ArmStatelessConsumerAmbiguityWitnessHold)
        {
            QualificationNodeReply::StatelessConsumerAmbiguityWitnessHoldArmed => {}
            reply => panic!(
                "stateless consumer causal witness hold gate did not arm: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn stateless_consumer_ambiguity_witness_hold_status(
        &mut self,
        node_index: usize,
    ) -> (usize, usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::StatelessConsumerAmbiguityWitnessHoldStatus)
        {
            QualificationNodeReply::StatelessConsumerAmbiguityWitnessHoldStatus {
                armed_responses,
                held_responses,
            } => (armed_responses, held_responses),
            reply => panic!(
                "stateless consumer causal witness hold status unavailable: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn release_stateless_consumer_ambiguity_witness_hold(&mut self, node_index: usize) {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::ReleaseStatelessConsumerAmbiguityWitnessHold)
        {
            QualificationNodeReply::StatelessConsumerAmbiguityWitnessHoldReleased => {}
            reply => panic!(
                "stateless consumer causal witness hold gate did not release: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn consumer_tls_peer_credential_rejections(&mut self, node_index: usize) -> u64 {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::ConsumerTlsPeerCredentialRejections)
        {
            QualificationNodeReply::ConsumerTlsPeerCredentialRejections { rejections } => {
                rejections
            }
            reply => panic!(
                "unexpected consumer TLS peer-credential rejection response: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn stateless_consumer_admission_status(
        &mut self,
        node_index: usize,
    ) -> opc_session_testkit::qualification::SessionMtlsBatchReleaseGateServerAdmissionV1 {
        match self.nodes[node_index]
            .invoke(&QualificationNodeCommand::StatelessConsumerAdmissionStatus)
        {
            QualificationNodeReply::StatelessConsumerAdmissionStatus {
                admission_limit,
                active_connections,
                high_water_connections,
                admission_waits,
                admission_rejections,
                samples,
                listener_available,
            } => opc_session_testkit::qualification::SessionMtlsBatchReleaseGateServerAdmissionV1 {
                logical_voter_index: node_index,
                admission_limit,
                expected_peak_connections: 16,
                active_connections,
                high_water_connections,
                normal_headroom_high_water_connections: 0,
                capacity_probe_high_water_connections: 0,
                capacity_probe_exercised: false,
                capacity_probe_admission_waits: 0,
                capacity_probe_admission_rejections: 0,
                capacity_probe_typed_rejection: false,
                admission_waits,
                admission_rejections,
                samples,
                listener_available,
            },
            reply => panic!(
                "process-local stateless consumer admission status unavailable: node={node_index}, reply={reply:?}, stderr={}",
                self.node_stderr(node_index)
            ),
        }
    }

    fn readiness_reports(&mut self, node_indices: &[usize]) -> Vec<FleetReadiness> {
        self.readiness_reports_by(node_indices, Instant::now() + CHILD_TIMEOUT)
    }

    fn readiness_reports_by(
        &mut self,
        node_indices: &[usize],
        deadline: Instant,
    ) -> Vec<FleetReadiness> {
        self.readiness_probe_commands = self
            .readiness_probe_commands
            .checked_add(node_indices.len())
            .expect("readiness probe command count overflow");
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
                        configured_voter_ids: _,
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
        self.verify_snapshot_namespace();
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
            "same-disk-exact-address-active-mutator/v3"
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
        let recovery_deadline = catchup_started_at
            + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RECOVERY_MILLIS);
        let catchup_deadline = recovery_deadline
            + Duration::from_millis(
                QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_FINAL_READINESS_PROBE_MILLIS,
            );
        assert_eq!(
            catchup_deadline.duration_since(catchup_started_at),
            Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_CATCHUP_MILLIS)
        );
        let mut last_complete_reports: Option<Vec<FleetReadiness>> = None;
        let mut final_readiness_round_started = false;
        loop {
            let now = Instant::now();
            let (probe_deadline, is_final_readiness_round) = match active_restart_readiness_round(
                now,
                recovery_deadline,
                catchup_deadline,
                final_readiness_round_started,
            ) {
                ActiveRestartReadinessRound::Recovery { deadline } => (deadline, false),
                ActiveRestartReadinessRound::WaitForFinal { dispatch_at } => {
                    thread::sleep(dispatch_at.duration_since(now));
                    continue;
                }
                ActiveRestartReadinessRound::Final { deadline } => {
                    final_readiness_round_started = true;
                    (deadline, true)
                }
                ActiveRestartReadinessRound::Exhausted => panic!(
                    "active-mutator restart exhausted its final readiness round: node={node_index}, total_elapsed_millis={}, catchup_elapsed_millis={}, readiness_before={readiness_before:?}, last_complete_reports={last_complete_reports:?}, stderr={:?}",
                    restart_started_at.elapsed().as_millis(),
                    catchup_started_at.elapsed().as_millis(),
                    self.stderr_diagnostics()
                ),
            };
            let reports = self.readiness_reports_by(&all_node_indices, probe_deadline);
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
                    deadline_allows_completion(Instant::now(), probe_deadline),
                    "active-mutator all-voter readiness round completed after its bound"
                );
                break;
            }
            last_complete_reports = Some(reports);
            if is_final_readiness_round {
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
                controller,
                controller_before,
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

    fn all_consensus_diagnostics(
        &mut self,
    ) -> Vec<opc_session_store::ConsensusStoreDiagnosticSnapshot> {
        let deadline = Instant::now() + CHILD_TIMEOUT;
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::ConsensusDiagnostics);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive_until(deadline) {
                QualificationNodeReply::ConsensusDiagnostics { metrics } => metrics,
                reply => panic!("unexpected consensus diagnostics response: {reply:?}"),
            })
            .collect()
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

        // The caller has just established all-voter readiness, and the next
        // recovered-member phase establishes it again after this clean
        // baseline. Do not issue readiness probes inside this interval: a
        // probe uses the same authenticated consensus lanes whose terminal
        // outcomes this loop is required to account for.
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
                    <= Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,),
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
                    <= Duration::from_millis(QUALIFICATION_TRAFFIC_MEMBER_RECOVERY_COVERAGE_MILLIS,),
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
                "fault-era connection outcomes did not settle before the recovery baseline: phase={phase}, server_tail_window={server_tail_window:?}, outbound_quiet_window={outbound_quiet_window:?}, elapsed={:?}, outbound_stable_for={outbound_stable_for:?}, traffic={traffic:?}, lifecycle={lifecycle:?}, stderr={:?}",
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
        let readiness_probe_commands_before_settlement = self.readiness_probe_commands;
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
        assert_eq!(
            self.readiness_probe_commands, readiness_probe_commands_before_settlement,
            "fault-outcome settlement must not issue readiness commands through the lanes whose outcomes it measures"
        );
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
                    Err(SessionConsensusPeerError::Authentication
                        | SessionConsensusPeerError::Unavailable)
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
        self.verify_snapshot_namespace();
        for node in &mut self.nodes {
            node.shutdown();
        }
        self.verify_snapshot_namespace();
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
    // Qualification provenance never resolves a caller-controlled `git` from
    // PATH or inherits Git configuration/environment overrides.
    let mut command = Command::new("/usr/bin/git");
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(repository);
    let output = bounded_candidate_git_command_output(&mut command, maximum_bytes)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(io::Error::other("candidate source state is unavailable"));
    }
    Ok(output.stdout)
}

const CANDIDATE_GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_GIT_TERMINATE_GRACE: Duration = Duration::from_millis(250);
const CANDIDATE_GIT_PIPE_POLL: Duration = Duration::from_millis(5);
const MAX_CANDIDATE_GIT_STDERR_BYTES: u64 = 8 * 1024;

struct BoundedCandidateGitOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct CandidateGitPipeReader {
    reader: Option<JoinHandle<io::Result<Vec<u8>>>>,
}

impl CandidateGitPipeReader {
    fn is_finished(&self) -> bool {
        self.reader.as_ref().is_some_and(JoinHandle::is_finished)
    }

    fn join_finished(&mut self) -> io::Result<Vec<u8>> {
        let reader = self
            .reader
            .take()
            .ok_or_else(|| io::Error::other("candidate Git pipe reader is unavailable"))?;
        reader
            .join()
            .map_err(|_| io::Error::other("candidate Git pipe reader panicked"))?
    }
}

fn bounded_candidate_git_command_output(
    command: &mut Command,
    maximum_stdout_bytes: u64,
) -> io::Result<BoundedCandidateGitOutput> {
    // This creates a fresh process group before exec whose PGID is exactly
    // the child PID; only that freshly-created group is ever signalled below.
    command.process_group(0);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let process_group = rustix::process::Pid::from_child(&child);
    let stop_readers = Arc::new(AtomicBool::new(false));
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_candidate_git_process_group(
                &mut child,
                process_group,
                &stop_readers,
                &mut [],
            )
            .map_err(|_| io::Error::other("candidate Git fail-closed cleanup failed"))?;
            return Err(io::Error::other("candidate Git stdout is unavailable"));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_candidate_git_process_group(
                &mut child,
                process_group,
                &stop_readers,
                &mut [],
            )
            .map_err(|_| io::Error::other("candidate Git fail-closed cleanup failed"))?;
            return Err(io::Error::other("candidate Git stderr is unavailable"));
        }
    };
    if let Err(error) = configure_candidate_git_pipe_nonblocking(&stdout)
        .and_then(|()| configure_candidate_git_pipe_nonblocking(&stderr))
    {
        terminate_candidate_git_process_group(&mut child, process_group, &stop_readers, &mut [])
            .map_err(|_| io::Error::other("candidate Git fail-closed cleanup failed"))?;
        return Err(error);
    }
    let mut readers = match (
        spawn_bounded_candidate_git_pipe_reader(
            "candidate-git-stdout",
            stdout,
            maximum_stdout_bytes,
            Arc::clone(&stop_readers),
        ),
        spawn_bounded_candidate_git_pipe_reader(
            "candidate-git-stderr",
            stderr,
            MAX_CANDIDATE_GIT_STDERR_BYTES,
            Arc::clone(&stop_readers),
        ),
    ) {
        (Ok(stdout), Ok(stderr)) => [stdout, stderr],
        (stdout, stderr) => {
            let mut started = [stdout.ok(), stderr.ok()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            terminate_candidate_git_process_group(
                &mut child,
                process_group,
                &stop_readers,
                &mut started,
            )
            .map_err(|_| io::Error::other("candidate Git fail-closed cleanup failed"))?;
            return Err(io::Error::other("start bounded candidate Git pipe reader"));
        }
    };
    let deadline = Instant::now() + CANDIDATE_GIT_COMMAND_TIMEOUT;
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    return candidate_git_fail_closed(
                        &mut child,
                        process_group,
                        &stop_readers,
                        &mut readers,
                        "poll candidate Git command",
                    );
                }
            };
        }
        if stdout.is_none() && readers[0].is_finished() {
            stdout = match readers[0].join_finished() {
                Ok(stdout) => Some(stdout),
                Err(_) => {
                    return candidate_git_fail_closed(
                        &mut child,
                        process_group,
                        &stop_readers,
                        &mut readers,
                        "read bounded candidate Git stdout",
                    );
                }
            };
        }
        if stderr.is_none() && readers[1].is_finished() {
            stderr = match readers[1].join_finished() {
                Ok(stderr) => Some(stderr),
                Err(_) => {
                    return candidate_git_fail_closed(
                        &mut child,
                        process_group,
                        &stop_readers,
                        &mut readers,
                        "read bounded candidate Git stderr",
                    );
                }
            };
        }
        // Do not take an early-completed pipe value while the other pipe or
        // the leader is still pending: doing so would discard valid output
        // and turn an ordinary asymmetric close into a deadline failure.
        if let (Some(status), Some(stdout), Some(stderr)) = (&status, &stdout, &stderr) {
            return Ok(BoundedCandidateGitOutput {
                status: *status,
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            });
        }
        if Instant::now() >= deadline {
            return candidate_git_fail_closed(
                &mut child,
                process_group,
                &stop_readers,
                &mut readers,
                "candidate Git command exceeded fixed runtime",
            );
        }
        thread::sleep(CANDIDATE_GIT_PIPE_POLL);
    }
}

fn candidate_git_fail_closed(
    child: &mut Child,
    process_group: rustix::process::Pid,
    stop_readers: &AtomicBool,
    readers: &mut [CandidateGitPipeReader],
    failure: &'static str,
) -> io::Result<BoundedCandidateGitOutput> {
    terminate_candidate_git_process_group(child, process_group, stop_readers, readers)
        .map_err(|_| io::Error::other("candidate Git fail-closed cleanup failed"))?;
    Err(io::Error::other(failure))
}

fn configure_candidate_git_pipe_nonblocking<R: AsFd>(pipe: &R) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(pipe)?;
    Ok(rustix::fs::fcntl_setfl(
        pipe,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}

fn spawn_bounded_candidate_git_pipe_reader<R>(
    name: &str,
    reader: R,
    maximum_bytes: u64,
    stop: Arc<AtomicBool>,
) -> io::Result<CandidateGitPipeReader>
where
    R: Read + Send + 'static,
{
    let reader = thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || read_bounded_candidate_git_pipe(reader, maximum_bytes, stop))?;
    Ok(CandidateGitPipeReader {
        reader: Some(reader),
    })
}

fn read_bounded_candidate_git_pipe<R: Read>(
    mut reader: R,
    maximum_bytes: u64,
    stop: Arc<AtomicBool>,
) -> io::Result<Vec<u8>> {
    let initial_capacity = usize::try_from(maximum_bytes.min(64 * 1024))
        .map_err(|_| io::Error::other("candidate Git pipe size overflow"))?;
    let mut encoded = Vec::with_capacity(initial_capacity);
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(encoded),
            Ok(read) => {
                total = total
                    .checked_add(
                        u64::try_from(read)
                            .map_err(|_| io::Error::other("candidate Git pipe size overflow"))?,
                    )
                    .ok_or_else(|| io::Error::other("candidate Git pipe size overflow"))?;
                if total > maximum_bytes {
                    return Err(io::Error::other("candidate Git pipe exceeds its bound"));
                }
                encoded.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::Acquire) {
                    return Err(io::Error::other(
                        "candidate Git pipe remained open after termination",
                    ));
                }
                thread::sleep(CANDIDATE_GIT_PIPE_POLL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn signal_owned_candidate_git_process_group(
    process_group: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> io::Result<()> {
    match rustix::process::kill_process_group(process_group, signal) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == 3 => Ok(()), // ESRCH: no owned survivor.
        Err(error) => Err(error.into()),
    }
}

fn terminate_candidate_git_process_group(
    child: &mut Child,
    process_group: rustix::process::Pid,
    stop_readers: &AtomicBool,
    readers: &mut [CandidateGitPipeReader],
) -> io::Result<()> {
    signal_owned_candidate_git_process_group(process_group, rustix::process::Signal::TERM)?;
    let terminate_deadline = Instant::now() + CANDIDATE_GIT_TERMINATE_GRACE;
    while Instant::now() < terminate_deadline {
        let _ = child.try_wait()?;
        thread::sleep(CANDIDATE_GIT_PIPE_POLL);
    }
    // Do not key the KILL decision on the leader: a leader may already have
    // exited while a descendant still owns either pipe.
    signal_owned_candidate_git_process_group(process_group, rustix::process::Signal::KILL)?;
    let reap_deadline = Instant::now() + CANDIDATE_GIT_TERMINATE_GRACE;
    while Instant::now() < reap_deadline {
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(CANDIDATE_GIT_PIPE_POLL);
    }
    if child.try_wait()?.is_none() {
        return Err(io::Error::other(
            "candidate Git leader did not reap after owned-group SIGKILL",
        ));
    }
    stop_readers.store(true, Ordering::Release);
    let readers_deadline = Instant::now() + CANDIDATE_GIT_TERMINATE_GRACE;
    for reader in readers {
        // A completed reader may already have been joined while reporting an
        // overflow/error to the caller; there is nothing left to wait for.
        if reader.reader.is_none() {
            continue;
        }
        while !reader.is_finished() && Instant::now() < readers_deadline {
            thread::sleep(CANDIDATE_GIT_PIPE_POLL);
        }
        if !reader.is_finished() {
            return Err(io::Error::other(
                "candidate Git pipe reader did not finish after owned-group termination",
            ));
        }
        let _ = reader.join_finished()?;
    }
    Ok(())
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

fn release_gate_provenance_at(repository: &Path) -> io::Result<ReleaseGateProvenance> {
    let source_revision = candidate_git_text(repository, &["rev-parse", "HEAD"])?;
    let source_tree = candidate_git_text(repository, &["rev-parse", "HEAD^{tree}"])?;
    if source_revision.len() != 40
        || source_tree.len() != 40
        || !source_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !source_tree.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::other(
            "release-gate source is not a committed Git head",
        ));
    }
    release_gate_require_clean_source_at(repository)?;
    let index_stages = candidate_git_output(
        repository,
        &["ls-files", "--cached", "--stage", "-z", "--"],
        MAX_CANDIDATE_SOURCE_BYTES,
    )?;
    let mut source_hasher = Sha256::new();
    source_hasher.update(b"opc-session-mtls-release-gate-source/v3\0");
    source_hasher.update(source_revision.as_bytes());
    source_hasher.update(b"\0");
    source_hasher.update(source_tree.as_bytes());
    source_hasher.update(b"\0");
    source_hasher.update(index_stages);
    let observed_cargo = release_gate_observed_cargo_argv()?;
    if !release_gate_argv_is_canonical(&observed_cargo.argv) {
        return Err(io::Error::other(
            "release-gate Cargo invocation does not exactly match the canonical command",
        ));
    }
    let mut command_hasher = Sha256::new();
    command_hasher.update(b"opc-session-mtls-release-gate-observed-argv/v2\0");
    hash_candidate_source_part(
        &mut command_hasher,
        b"cargo-executable",
        observed_cargo.backing.as_os_str().as_encoded_bytes(),
    )?;
    hash_candidate_source_part(
        &mut command_hasher,
        b"cargo-executable-alias",
        observed_cargo.alias.as_os_str().as_encoded_bytes(),
    )?;
    hash_candidate_source_part(
        &mut command_hasher,
        b"cargo-executable-sha256",
        observed_cargo.backing_sha256.as_bytes(),
    )?;
    hash_candidate_source_part(
        &mut command_hasher,
        b"cargo-executable-mode",
        &observed_cargo.backing_mode.to_be_bytes(),
    )?;
    for argument in &observed_cargo.argv {
        hash_candidate_source_part(&mut command_hasher, b"argv", argument.as_bytes())?;
    }
    let cargo_lock =
        read_bounded_candidate_file(&repository.join("Cargo.lock"), MAX_CANDIDATE_SOURCE_BYTES)?;
    let mut cargo_lock_hasher = Sha256::new();
    cargo_lock_hasher.update(b"opc-session-mtls-release-gate-cargo-lock/v1\0");
    cargo_lock_hasher.update(cargo_lock);
    let external_namespaces = v9_external_namespace_bindings()?;
    Ok(ReleaseGateProvenance {
        source_revision,
        source_tree,
        source_worktree_sha256: format!("sha256:{:x}", source_hasher.finalize()),
        cargo_lock_sha256: format!("sha256:{:x}", cargo_lock_hasher.finalize()),
        cargo_target_directory: external_namespaces.cargo_target_directory,
        cargo_target_directory_sha256: external_namespaces.cargo_target_directory_sha256,
        evidence_root_directory: external_namespaces.evidence_root_directory,
        evidence_root_directory_sha256: external_namespaces.evidence_root_directory_sha256,
        fs_verity_snapshot_root_directory: external_namespaces.fs_verity_snapshot_root_directory,
        fs_verity_snapshot_root_directory_sha256: external_namespaces
            .fs_verity_snapshot_root_directory_sha256,
        fs_verity_snapshot_root_device: external_namespaces.fs_verity_snapshot_root_device,
        fs_verity_snapshot_root_inode: external_namespaces.fs_verity_snapshot_root_inode,
        pair_directory: external_namespaces.pair_directory,
        pair_directory_sha256: external_namespaces.pair_directory_sha256,
        command_argv_sha256: format!("sha256:{:x}", command_hasher.finalize()),
        cargo_executable_alias: v9_canonical_path_string(
            &observed_cargo.alias,
            "release-gate Cargo executable alias",
        )?,
        cargo_executable: v9_canonical_path_string(
            &observed_cargo.backing,
            "release-gate Cargo executable backing",
        )?,
        cargo_executable_sha256: observed_cargo.backing_sha256,
        cargo_executable_mode: observed_cargo.backing_mode,
        canonical_cargo_argv: observed_cargo.argv,
        cargo_profile: env!("OPC_SESSION_TESTKIT_CARGO_PROFILE_FAMILY").to_owned(),
        opt_level: env!("OPC_SESSION_TESTKIT_CARGO_OPT_LEVEL").to_owned(),
    })
}

fn release_gate_argv_is_canonical(observed_argv: &[String]) -> bool {
    observed_argv
        .iter()
        .map(String::as_str)
        .eq(RELEASE_GATE_EXPECTED_CARGO_ARGV.iter().copied())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseGateObservedCargo {
    argv: Vec<String>,
    /// Normalized absolute alias used as Cargo's `argv[0]`, retained for replay.
    alias: PathBuf,
    /// Canonical `/proc/<pid>/exe`, proved equal to the alias backing file.
    backing: PathBuf,
    backing_sha256: String,
    backing_mode: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseGateCargoExecutableBinding {
    alias: PathBuf,
    backing: PathBuf,
    backing_sha256: String,
    backing_mode: u16,
    backing_identity: ReleaseGateCargoBackingIdentity,
}

/// Identity and bounded attributes observed through the one nofollow Cargo
/// backing descriptor.  These values are intentionally not evidence fields:
/// they make pathname replacement during capture a hard failure rather than
/// allowing a mode from one file to combine with bytes from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReleaseGateCargoBackingIdentity {
    device: u64,
    inode: u64,
    mode: u16,
    size: u64,
}

fn release_gate_cargo_executable_matches(observed: &Path, backing: &Path) -> bool {
    fs::canonicalize(observed).ok() == fs::canonicalize(backing).ok()
}

fn release_gate_cargo_backing_identity<Fd: AsFd>(
    descriptor: Fd,
) -> io::Result<ReleaseGateCargoBackingIdentity> {
    let metadata = fstat(descriptor)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file() {
        return Err(io::Error::other(
            "release-gate Cargo backing descriptor is not a regular file",
        ));
    }
    let size = u64::try_from(metadata.st_size)
        .map_err(|_| io::Error::other("release-gate Cargo backing size is invalid"))?;
    if size > MAX_CANDIDATE_ARTIFACT_BYTES {
        return Err(io::Error::other(
            "release-gate Cargo backing exceeds the artifact bound",
        ));
    }
    let mode = u16::try_from(Mode::from_raw_mode(metadata.st_mode).bits() & 0o7777)
        .map_err(|_| io::Error::other("release-gate Cargo backing mode is out of range"))?;
    if mode & 0o111 == 0 {
        return Err(io::Error::other(
            "release-gate Cargo backing is not executable",
        ));
    }
    Ok(ReleaseGateCargoBackingIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
        mode,
        size,
    })
}

fn release_gate_cargo_path_matches_backing_descriptor(
    path: &Path,
    identity: ReleaseGateCargoBackingIdentity,
    label: &str,
) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.dev() != identity.device
        || metadata.ino() != identity.inode
    {
        return Err(io::Error::other(format!(
            "release-gate Cargo {label} no longer identifies the opened backing descriptor"
        )));
    }
    Ok(())
}

fn release_gate_cargo_backing_sha256_from_descriptor(
    file: &mut File,
    identity: ReleaseGateCargoBackingIdentity,
) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
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
            .ok_or_else(|| io::Error::other("release-gate Cargo backing size overflow"))?;
        if total > identity.size || total > MAX_CANDIDATE_ARTIFACT_BYTES {
            return Err(io::Error::other(
                "release-gate Cargo backing changed or exceeds its artifact bound",
            ));
        }
        hasher.update(&encoded[..read]);
    }
    if total != identity.size {
        return Err(io::Error::other(
            "release-gate Cargo backing changed while its descriptor was hashed",
        ));
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn release_gate_cargo_executable_binding_at(
    alias: &Path,
) -> io::Result<ReleaseGateCargoExecutableBinding> {
    release_gate_cargo_executable_binding_at_with_before_hash(alias, |_| Ok(()))
}

/// The test-only seam proves that a pathname replacement after the descriptor
/// is opened cannot combine an executable backing's mode with a replacement
/// file's content digest. Production capture supplies a no-op hook.
fn release_gate_cargo_executable_binding_at_with_before_hash<BeforeHash>(
    alias: &Path,
    before_hash: BeforeHash,
) -> io::Result<ReleaseGateCargoExecutableBinding>
where
    BeforeHash: FnOnce(&Path) -> io::Result<()>,
{
    let alias = v9_canonical_path_string(alias, "release-gate Cargo executable alias")
        .map(PathBuf::from)?;
    let alias_metadata = fs::symlink_metadata(&alias)?;
    if !alias_metadata.file_type().is_file() && !alias_metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "release-gate Cargo executable alias is not a file or symlink",
        ));
    }
    let backing = fs::canonicalize(&alias)?;
    let backing = v9_canonical_path_string(&backing, "release-gate Cargo executable backing")
        .map(PathBuf::from)?;
    let descriptor = open(
        &backing,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let backing_identity = release_gate_cargo_backing_identity(&descriptor)?;
    release_gate_cargo_path_matches_backing_descriptor(&alias, backing_identity, "alias")?;
    release_gate_cargo_path_matches_backing_descriptor(&backing, backing_identity, "backing")?;
    before_hash(&backing)?;
    let mut file = File::from(descriptor);
    let backing_sha256 =
        release_gate_cargo_backing_sha256_from_descriptor(&mut file, backing_identity)?;
    if release_gate_cargo_backing_identity(&file)? != backing_identity {
        return Err(io::Error::other(
            "release-gate Cargo backing descriptor changed while it was hashed",
        ));
    }
    release_gate_cargo_path_matches_backing_descriptor(&alias, backing_identity, "alias")?;
    release_gate_cargo_path_matches_backing_descriptor(&backing, backing_identity, "backing")?;
    Ok(ReleaseGateCargoExecutableBinding {
        alias,
        backing,
        backing_sha256,
        backing_mode: backing_identity.mode,
        backing_identity,
    })
}

/// Resolve Cargo without erasing a symlink alias. The alias is the executable
/// spelling that must be replayed; its canonical backing file is separately
/// pinned so a rustup proxy cannot silently turn into a direct `rustup test`.
fn release_gate_resolved_cargo_executable() -> io::Result<ReleaseGateCargoExecutableBinding> {
    let configured = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let configured = PathBuf::from(configured);
    let candidate = if configured.is_absolute() || configured.components().count() > 1 {
        configured
    } else {
        env::var_os("PATH")
            .map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
            .into_iter()
            .flatten()
            .map(|directory| directory.join(&configured))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| io::Error::other("resolved Cargo executable is unavailable"))?
    };
    release_gate_cargo_executable_binding_at(&candidate)
}

#[test]
fn release_gate_argv_requires_the_exact_observed_cargo_tail() {
    let canonical = RELEASE_GATE_EXPECTED_CARGO_ARGV
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        RELEASE_GATE_EXPECTED_CARGO_ARGV,
        opc_session_testkit::qualification::
            SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_CARGO_ARGV,
        "the V9 disclosure and producer's observed Cargo argv must remain one exact command"
    );
    assert!(release_gate_argv_is_canonical(&canonical));
    let mut reordered = canonical.clone();
    reordered.swap(1, 2);
    assert!(!release_gate_argv_is_canonical(&reordered));
    let mut missing = canonical.clone();
    missing.pop();
    assert!(!release_gate_argv_is_canonical(&missing));
    let mut direct_binary = canonical;
    direct_binary[0] = "qualification_mtls_multiprocess".to_owned();
    assert!(!release_gate_argv_is_canonical(&direct_binary));
}

#[test]
fn v9_reproduction_recipe_is_env_prefixed_shell_safe_and_exact() {
    let recipe = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
            "/var/lib/opc testkit/target",
            "/var/lib/opc testkit/evidence",
            "/var/lib/opc testkit/fs-verity-snapshots",
            "/usr/local/bin/cargo",
        )
        .expect("render canonical V9 reproduction command");
    assert_eq!(
        recipe,
        "CARGO='/usr/local/bin/cargo' CARGO_TARGET_DIR='/var/lib/opc testkit/target' OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY='/var/lib/opc testkit/evidence' OPC_FS_VERITY_QUALIFICATION='required' OPC_FS_VERITY_SNAPSHOT_ROOT='/var/lib/opc testkit/fs-verity-snapshots' '/usr/local/bin/cargo' 'test' '--locked' '--release' '-p' 'opc-session-testkit' '--test' 'qualification_mtls_multiprocess' '--no-default-features' 'three_process_projected_mtls_persistent_v2_batch_release_gate' '--' '--ignored' '--exact' '--test-threads=1' '--nocapture'"
    );
    assert!(opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
            "/var/lib/opc/../target",
            "/var/lib/opc/evidence",
            "/var/lib/opc/fs-verity-snapshots",
            "/usr/local/bin/cargo",
        )
        .is_none());
    assert!(opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
            "/var/lib/opc\ntarget",
            "/var/lib/opc/evidence",
            "/var/lib/opc/fs-verity-snapshots",
            "/usr/local/bin/cargo",
        )
        .is_none());
}

#[test]
fn v9_reproduction_recipe_shell_round_trips_quoted_alias_and_namespaces() {
    let workspace = tempfile::tempdir().expect("create shell-recipe workspace");
    let marker = workspace.path().join("must-not-exist");
    let injection = "'$(touch $RECIPE_MARKER);semicolon";
    let target = workspace.path().join(format!("target{injection}"));
    let root = workspace.path().join(format!("evidence{injection}"));
    let snapshot_root = workspace.path().join(format!("snapshots{injection}"));
    let backing = workspace.path().join("rustup-backing");
    let alias = workspace.path().join(format!("cargo{injection}"));
    let recorded = workspace.path().join("recorded-arguments");
    fs::create_dir(&target).expect("create quoted target path");
    fs::create_dir(&root).expect("create quoted evidence root");
    fs::create_dir(&snapshot_root).expect("create quoted snapshot root");
    fs::write(
        &backing,
        "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$CARGO\" \"$CARGO_TARGET_DIR\" \"$OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY\" \"$OPC_FS_VERITY_QUALIFICATION\" \"$OPC_FS_VERITY_SNAPSHOT_ROOT\" \"$@\" > \"$RECIPE_RECORD\"\n",
    )
    .expect("write quoted Cargo backing script");
    fs::set_permissions(&backing, Permissions::from_mode(0o700))
        .expect("make quoted Cargo backing executable");
    symlink(&backing, &alias).expect("create quoted Cargo alias symlink");

    let alias = alias.to_str().expect("quoted alias UTF-8");
    let target = target.to_str().expect("quoted target UTF-8");
    let root = root.to_str().expect("quoted evidence root UTF-8");
    let snapshot_root = snapshot_root.to_str().expect("quoted snapshot root UTF-8");
    let recipe = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_reproduction_command(target, root, snapshot_root, alias)
            .expect("render quoted V9 reproduction command");
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(&recipe)
        .env("RECIPE_MARKER", &marker)
        .env("RECIPE_RECORD", &recorded)
        .status()
        .expect("execute V9 reproduction command through /bin/sh");
    assert!(
        status.success(),
        "quoted V9 recipe must execute the alias once"
    );
    assert!(
        !marker.exists(),
        "the apostrophe/semicolon/command-substitution-like alias and paths must not execute a side effect"
    );
    let observed = String::from_utf8(fs::read(&recorded).expect("read shell argument record"))
        .expect("shell record is UTF-8")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let expected = std::iter::once(alias.to_owned())
        .chain([
            alias.to_owned(),
            target.to_owned(),
            root.to_owned(),
            "required".to_owned(),
            snapshot_root.to_owned(),
        ])
        .chain(
            opc_session_testkit::qualification::
                SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_CARGO_ARGV
                .iter()
                .skip(1)
                .map(|argument| (*argument).to_owned()),
        )
        .collect::<Vec<_>>();
    assert_eq!(
        observed, expected,
        "the recipe must execute the alias (not its backing) and round-trip argv[0], CARGO, all external namespace variables, and every Cargo argument exactly once"
    );
}

#[test]
fn release_gate_cargo_executable_rejects_a_fake_cargo_basename() {
    let temporary = tempfile::tempdir().expect("temporary executable directory");
    let actual = temporary.path().join("actual-cargo");
    let fake_directory = temporary.path().join("fake");
    fs::create_dir(&fake_directory).expect("fake executable directory");
    let fake = fake_directory.join("cargo");
    fs::write(&actual, b"actual cargo").expect("write actual executable");
    fs::write(&fake, b"fake cargo").expect("write fake basename");
    assert!(release_gate_cargo_executable_matches(&actual, &actual));
    assert!(
        !release_gate_cargo_executable_matches(&fake, &actual),
        "a process merely named cargo cannot impersonate Cargo's resolved executable"
    );
}

#[test]
fn release_gate_cargo_alias_binds_spelling_backing_and_content() {
    let temporary = tempfile::tempdir().expect("temporary Cargo alias directory");
    let backing = temporary.path().join("rustup-backing");
    let alias = temporary.path().join("cargo");
    let fake_backing = temporary.path().join("fake-rustup-backing");
    let fake_alias = temporary.path().join("fake-cargo");
    fs::write(&backing, b"same Cargo proxy content").expect("write Cargo backing");
    fs::set_permissions(&backing, Permissions::from_mode(0o755))
        .expect("make Cargo backing executable");
    symlink(&backing, &alias).expect("create Cargo alias symlink");
    fs::write(&fake_backing, b"same Cargo proxy content").expect("write fake Cargo backing");
    fs::set_permissions(&fake_backing, Permissions::from_mode(0o755))
        .expect("make fake Cargo backing executable");
    symlink(&fake_backing, &fake_alias).expect("create fake Cargo alias symlink");

    let binding =
        release_gate_cargo_executable_binding_at(&alias).expect("capture real Cargo alias binding");
    let fake = release_gate_cargo_executable_binding_at(&fake_alias)
        .expect("capture fake Cargo alias binding");
    assert_eq!(
        binding.alias, alias,
        "the replay field retains the alias spelling instead of canonicalizing it away"
    );
    assert_eq!(
        binding.backing,
        fs::canonicalize(&backing).expect("canonical Cargo backing"),
        "the alias's backing path is separately pinned"
    );
    assert_eq!(
        binding.backing_sha256,
        candidate_sha256_file(&binding.backing, MAX_CANDIDATE_ARTIFACT_BYTES)
            .expect("hash canonical Cargo backing"),
        "the backing content commitment is exact"
    );
    assert_eq!(binding.backing_mode, 0o755);
    let backing_metadata = fs::metadata(&binding.backing).expect("read canonical Cargo backing");
    assert_eq!(binding.backing_identity.device, backing_metadata.dev());
    assert_eq!(binding.backing_identity.inode, backing_metadata.ino());
    assert_eq!(binding.backing_identity.mode, 0o755);
    assert_eq!(
        binding.backing_identity.size,
        u64::try_from(b"same Cargo proxy content".len()).expect("bounded Cargo fixture size")
    );
    assert_eq!(
        binding.backing_sha256, fake.backing_sha256,
        "the replacement regression also covers a same-content fake backing"
    );
    assert_ne!(binding.alias, fake.alias);
    assert_ne!(binding.backing, fake.backing);
    assert!(
        !release_gate_cargo_executable_matches(&fake.backing, &binding.backing),
        "a fake alias/backing pair cannot satisfy the captured Cargo identity"
    );
    fs::set_permissions(&backing, Permissions::from_mode(0o644))
        .expect("remove execute bit from canonical Cargo backing");
    assert!(
        release_gate_cargo_executable_binding_at(&alias).is_err(),
        "the canonical Cargo backing must retain an execute bit through evidence capture"
    );
}

#[test]
fn release_gate_cargo_binding_rejects_backing_replacement_between_mode_and_hash() {
    let temporary = tempfile::tempdir().expect("temporary Cargo race directory");
    let backing = temporary.path().join("rustup-backing");
    let alias = temporary.path().join("cargo");
    let non_executable_replacement = temporary.path().join("rustup-backing-replacement");
    fs::write(&backing, b"executable Cargo backing A").expect("write executable Cargo backing");
    fs::set_permissions(&backing, Permissions::from_mode(0o755))
        .expect("make backing A executable");
    fs::write(
        &non_executable_replacement,
        b"non-executable replacement backing B",
    )
    .expect("write non-executable replacement backing");
    fs::set_permissions(&non_executable_replacement, Permissions::from_mode(0o644))
        .expect("make backing B non-executable");
    symlink(&backing, &alias).expect("create Cargo alias symlink");

    let replacement_digest =
        candidate_sha256_file(&non_executable_replacement, MAX_CANDIDATE_ARTIFACT_BYTES)
            .expect("hash replacement backing B");
    assert!(
        release_gate_cargo_executable_binding_at_with_before_hash(&alias, |opened_backing| {
            assert_eq!(opened_backing, backing.as_path());
            fs::rename(&non_executable_replacement, opened_backing)
        })
        .is_err(),
        "the opened executable backing A must never be recorded with replacement B's content or mode"
    );
    assert_eq!(
        candidate_sha256_file(&backing, MAX_CANDIDATE_ARTIFACT_BYTES)
            .expect("hash installed replacement backing B"),
        replacement_digest,
        "the deterministic race did replace the backing pathname after descriptor capture"
    );
    assert!(
        release_gate_cargo_executable_binding_at(&alias).is_err(),
        "a subsequent capture rejects the installed non-executable backing B"
    );
}

/// Exact release-only cleanliness rule. This intentionally treats every
/// untracked path (even ignored paths) and every dirty submodule as evidence
/// poison; release runners must use a separately clean exact-HEAD worktree.
fn release_gate_require_clean_source_at(repository: &Path) -> io::Result<()> {
    let source_status = candidate_git_output(
        repository,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=none",
        ],
        MAX_CANDIDATE_SOURCE_BYTES,
    )?;
    if !source_status.is_empty() {
        return Err(io::Error::other(
            "release-gate source tree is dirty; refuse evidence emission",
        ));
    }
    let mut merge_head_command = Command::new("/usr/bin/git");
    merge_head_command
        .args(["rev-parse", "-q", "--verify", "MERGE_HEAD"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(repository);
    let merge_head = bounded_candidate_git_command_output(&mut merge_head_command, 64)?;
    if merge_head.status.code() != Some(1)
        || !merge_head.stdout.is_empty()
        || !merge_head.stderr.is_empty()
    {
        return Err(io::Error::other(
            "release-gate source has an active or unreadable merge state",
        ));
    }
    let submodules = candidate_git_output(
        repository,
        &["submodule", "status", "--recursive"],
        MAX_CANDIDATE_SOURCE_BYTES,
    )?;
    if submodules
        .split(|byte| *byte == b'\n')
        .any(|line| matches!(line.first(), Some(b'-' | b'+' | b'U')))
    {
        return Err(io::Error::other(
            "release-gate source has an absent, dirty, or conflicted submodule",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn release_gate_observed_cargo_argv() -> io::Result<ReleaseGateObservedCargo> {
    let resolved_cargo = release_gate_resolved_cargo_executable()?;
    let mut process_id = std::process::id();
    for _ in 0..8 {
        let proc_root = PathBuf::from(format!("/proc/{process_id}"));
        let command = read_bounded_candidate_file(&proc_root.join("cmdline"), 16 * 1024)?;
        let argv = command
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .map(|argument| {
                std::str::from_utf8(argument)
                    .map(str::to_owned)
                    .map_err(|_| io::Error::other("release-gate observed argv is not UTF-8"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        if argv.first().is_some_and(|program| {
            Path::new(program)
                .file_name()
                .is_some_and(|name| name == "cargo")
        }) {
            let backing = fs::canonicalize(proc_root.join("exe"))?;
            if !release_gate_cargo_executable_matches(&backing, &resolved_cargo.backing) {
                return Err(io::Error::other(
                    "release-gate Cargo parent executable does not match the resolved alias backing",
                ));
            }
            if fs::canonicalize(&resolved_cargo.alias)? != resolved_cargo.backing {
                return Err(io::Error::other(
                    "release-gate Cargo alias no longer resolves to its captured backing",
                ));
            }
            let mut normalized = argv;
            normalized[0] = "cargo".to_owned();
            return Ok(ReleaseGateObservedCargo {
                argv: normalized,
                alias: resolved_cargo.alias,
                backing,
                backing_sha256: resolved_cargo.backing_sha256,
                backing_mode: resolved_cargo.backing_mode,
            });
        }
        let status = read_bounded_candidate_file(&proc_root.join("status"), 16 * 1024)?;
        let status = std::str::from_utf8(&status)
            .map_err(|_| io::Error::other("release-gate proc status is not UTF-8"))?;
        let parent = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:\t"))
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|parent| *parent != 0)
            .ok_or_else(|| io::Error::other("release-gate Cargo parent is unavailable"))?;
        process_id = parent;
    }
    Err(io::Error::other(
        "release gate must be launched by the canonical Cargo command",
    ))
}

#[cfg(not(target_os = "linux"))]
fn release_gate_observed_cargo_argv() -> io::Result<ReleaseGateObservedCargo> {
    Err(io::Error::other(
        "release-gate Cargo argv observation is supported only on Linux",
    ))
}

fn candidate_git_text(repository: &Path, arguments: &[&str]) -> io::Result<String> {
    let output = candidate_git_output(repository, arguments, 128)?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| io::Error::other("release-gate Git output is not UTF-8"))?
        .trim_end();
    Ok(value.to_owned())
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

const V9_EXTERNAL_TEST_ID: &str = "three_process_projected_mtls_persistent_v2_batch_release_gate";

fn v9_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Recompute the opaque run identity from both canonical artifacts' shared
/// release provenance. Keeping the V1 digest in this input makes a valid V9
/// document non-transferable to another V1 release-gate result. The V4
/// domain additionally binds a canonical V9 claims preimage, with the
/// run-ID field replaced by a fixed digest placeholder to keep the contract
/// noncircular.
fn v9_pair_run_id(
    v1: &SessionMtlsBatchReleaseGateEvidenceV1,
    v1_canonical: &[u8],
    provenance: &ReleaseGateProvenance,
    v9: &SessionHaPersistentConsumerHeadEvidenceV9,
) -> io::Result<String> {
    let bindings = &v1.bindings;
    let v9_schema_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_schema_sha256();
    v9_pair_run_id_material(
        provenance,
        &[
            bindings.evidence_schema_sha256.as_str(),
            bindings.configuration_sha256.as_str(),
            bindings.public_material_manifest_sha256.as_str(),
            bindings.workload_schedule_sha256.as_str(),
            bindings.child_sha256.as_str(),
            bindings.harness_sha256.as_str(),
        ],
        &v9_schema_sha256,
        &v9.invocation.argv_sha256,
        v1_canonical,
        &v9_pair_claims_preimage(v9)?,
    )
}

/// Fixed valid digest used only in the run-ID preimage. Replacing the actual
/// run ID before canonical encoding makes the V9 campaign claims themselves
/// a strict input without hashing a value that is defined by the same hash.
const V9_PAIR_RUN_ID_PREIMAGE_PLACEHOLDER: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn v9_pair_claims_preimage(v9: &SessionHaPersistentConsumerHeadEvidenceV9) -> io::Result<Vec<u8>> {
    let mut preimage = v9.clone();
    preimage.invocation.run_id_sha256 = V9_PAIR_RUN_ID_PREIMAGE_PLACEHOLDER.to_owned();
    preimage
        .to_canonical_json()
        .map_err(|_| io::Error::other("V9 run identity claims preimage is invalid"))
}

/// Shared with focused regression tests so every run-ID input, including the
/// disclosed external namespaces and runnable command, is independently
/// exercised without manufacturing a long-running release-gate V1 artifact.
fn v9_pair_run_id_material(
    provenance: &ReleaseGateProvenance,
    v1_binding_values: &[&str],
    v9_schema_sha256: &str,
    argv_sha256: &str,
    v1_canonical: &[u8],
    v9_claims_preimage: &[u8],
) -> io::Result<String> {
    if v1_binding_values.len() != 6 {
        return Err(io::Error::other(
            "V9 run identity requires the complete six-field V1 binding set",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-ha-persistent-consumer-v9-pair-run/v4\0");
    let fs_verity_snapshot_root_device = provenance.fs_verity_snapshot_root_device.to_string();
    let fs_verity_snapshot_root_inode = provenance.fs_verity_snapshot_root_inode.to_string();
    for value in [
        provenance.source_revision.as_str(),
        provenance.source_tree.as_str(),
        provenance.source_worktree_sha256.as_str(),
        provenance.cargo_lock_sha256.as_str(),
        provenance.cargo_target_directory.as_str(),
        provenance.cargo_target_directory_sha256.as_str(),
        provenance.evidence_root_directory.as_str(),
        provenance.evidence_root_directory_sha256.as_str(),
        provenance.fs_verity_snapshot_root_directory.as_str(),
        provenance.fs_verity_snapshot_root_directory_sha256.as_str(),
        fs_verity_snapshot_root_device.as_str(),
        fs_verity_snapshot_root_inode.as_str(),
        provenance.pair_directory.as_str(),
        provenance.pair_directory_sha256.as_str(),
        provenance.command_argv_sha256.as_str(),
        provenance.cargo_executable_alias.as_str(),
        provenance.cargo_executable.as_str(),
        provenance.cargo_executable_sha256.as_str(),
        provenance.cargo_profile.as_str(),
        provenance.opt_level.as_str(),
    ] {
        hash_candidate_source_part(&mut hasher, b"binding", value.as_bytes())?;
    }
    hash_candidate_source_part(
        &mut hasher,
        b"cargo-executable-mode",
        &provenance.cargo_executable_mode.to_be_bytes(),
    )?;
    for value in v1_binding_values {
        hash_candidate_source_part(&mut hasher, b"binding", value.as_bytes())?;
    }
    for value in [v9_schema_sha256, V9_EXTERNAL_TEST_ID, argv_sha256] {
        hash_candidate_source_part(&mut hasher, b"binding", value.as_bytes())?;
    }
    for argument in &provenance.canonical_cargo_argv {
        hash_candidate_source_part(&mut hasher, b"canonical-cargo-argv", argument.as_bytes())?;
    }
    let reproduction_command = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
            &provenance.cargo_target_directory,
            &provenance.evidence_root_directory,
            &provenance.fs_verity_snapshot_root_directory,
            &provenance.cargo_executable_alias,
        )
        .ok_or_else(|| io::Error::other("V9 canonical reproduction command is invalid"))?;
    hash_candidate_source_part(
        &mut hasher,
        b"reproduction-command",
        reproduction_command.as_bytes(),
    )?;
    hash_candidate_source_part(&mut hasher, b"v1-canonical", v1_canonical)?;
    hash_candidate_source_part(&mut hasher, b"v9-claims-preimage", v9_claims_preimage)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn v1_v9_release_gate_process_generations_agree(
    v1_resource_generation_count: usize,
    v9_release_gate_process_generations: u8,
) -> io::Result<()> {
    let expected = u8::try_from(v1_resource_generation_count)
        .map_err(|_| io::Error::other("V1 resource-generation count overflows V9"))?;
    if v9_release_gate_process_generations != expected {
        return Err(io::Error::other(
            "V1/V9 release-gate process-generation count is inconsistent",
        ));
    }
    Ok(())
}

fn validate_v1_v9_pair(
    v1_canonical: &[u8],
    v9_canonical: &[u8],
    provenance: &ReleaseGateProvenance,
) -> io::Result<()> {
    let v1 = SessionMtlsBatchReleaseGateEvidenceV1::from_json(v1_canonical)
        .map_err(|_| io::Error::other("V9 pair V1 artifact is not canonical"))?;
    let v9 = SessionHaPersistentConsumerHeadEvidenceV9::from_json(v9_canonical)
        .map_err(|_| io::Error::other("V9 pair artifact is not canonical"))?;
    v1_v9_release_gate_process_generations_agree(
        v1.resource_generations.len(),
        v9.process_ledger.release_gate_process_generations,
    )?;
    let bindings = &v1.bindings;
    if bindings.source_revision != provenance.source_revision
        || bindings.source_tree != provenance.source_tree
        || bindings.source_worktree_sha256 != provenance.source_worktree_sha256
        || bindings.cargo_lock_sha256 != provenance.cargo_lock_sha256
        || bindings.command_argv_sha256 != provenance.command_argv_sha256
        || v1.cargo_profile != provenance.cargo_profile
        || v1.opt_level != provenance.opt_level
        || v9.provenance.source_revision != provenance.source_revision
        || v9.provenance.source_tree != provenance.source_tree
        || v9.provenance.source_worktree_sha256 != provenance.source_worktree_sha256
        || !v9.qualification_complete
        || v9.bindings.child_sha256 != bindings.child_sha256
        || v9.bindings.harness_sha256 != bindings.harness_sha256
        // This test executable is both the harness and the evidence-emitting
        // executable; reject a V9 that tries to bind a different file.
        || v9.bindings.executable_sha256 != bindings.harness_sha256
        || v9.bindings.v9_schema_sha256
            != opc_session_testkit::qualification::session_ha_persistent_consumer_head_evidence_v9_schema_sha256()
        || v9.bindings.v1_canonical_sha256 != v9_sha256(v1_canonical)
        || v9.bindings.cargo_target_directory != provenance.cargo_target_directory
        || v9.bindings.cargo_target_directory_sha256 != provenance.cargo_target_directory_sha256
        || v9.bindings.evidence_root_directory != provenance.evidence_root_directory
        || v9.bindings.evidence_root_directory_sha256 != provenance.evidence_root_directory_sha256
        || v9.bindings.fs_verity_snapshot_root_directory
            != provenance.fs_verity_snapshot_root_directory
        || v9.bindings.fs_verity_snapshot_root_directory_sha256
            != provenance.fs_verity_snapshot_root_directory_sha256
        || v9.bindings.fs_verity_snapshot_root_device
            != provenance.fs_verity_snapshot_root_device
        || v9.bindings.fs_verity_snapshot_root_inode
            != provenance.fs_verity_snapshot_root_inode
        || v9.bindings.pair_directory != provenance.pair_directory
        || v9.bindings.pair_directory_sha256 != provenance.pair_directory_sha256
        || v9.invocation.cargo_executable_alias != provenance.cargo_executable_alias
        || v9.invocation.cargo_executable != provenance.cargo_executable
        || v9.invocation.cargo_executable_sha256 != provenance.cargo_executable_sha256
        || v9.invocation.cargo_executable_mode != provenance.cargo_executable_mode
        || v9.invocation.canonical_cargo_argv != provenance.canonical_cargo_argv
        || v9.invocation.reproduction_command
            != opc_session_testkit::qualification::session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
                &provenance.cargo_target_directory,
                &provenance.evidence_root_directory,
                &provenance.fs_verity_snapshot_root_directory,
                &provenance.cargo_executable_alias,
            )
            .ok_or_else(|| io::Error::other("V9 canonical reproduction command is invalid"))?
    {
        return Err(io::Error::other("V1/V9 release pair binding is inconsistent"));
    }
    let expected_run_id = v9_pair_run_id(&v1, v1_canonical, provenance, &v9)?;
    if v9.invocation.run_id_sha256 != expected_run_id {
        return Err(io::Error::other(
            "V1/V9 release pair run identity is inconsistent",
        ));
    }
    Ok(())
}

fn v9_require_runtime_digest(label: &str, expected: &str, actual: &str) -> io::Result<()> {
    if expected != actual {
        return Err(io::Error::other(format!(
            "V9 {label} changed between campaign and publication"
        )));
    }
    Ok(())
}

/// Re-read every mutable process-local binding immediately before evidence is
/// made durable. This cannot eliminate a same-UID actor replacing a binary
/// after this check and before `renameat`; nofollow descriptors, create-new,
/// and the final source recheck reduce that residual to the caller's own UID.
fn v9_verify_prepublication_bindings(
    v1_canonical: &[u8],
    v9_canonical: &[u8],
    provenance: &ReleaseGateProvenance,
) -> io::Result<()> {
    let current_provenance = ReleaseGateProvenance::capture()?;
    if &current_provenance != provenance {
        return Err(io::Error::other(
            "V9 release provenance changed before publication",
        ));
    }
    validate_v1_v9_pair(v1_canonical, v9_canonical, &current_provenance)?;
    let v1 = SessionMtlsBatchReleaseGateEvidenceV1::from_json(v1_canonical)
        .map_err(|_| io::Error::other("V9 prepublication V1 artifact is not canonical"))?;
    let v9 = SessionHaPersistentConsumerHeadEvidenceV9::from_json(v9_canonical)
        .map_err(|_| io::Error::other("V9 prepublication artifact is not canonical"))?;
    let child_sha256 = candidate_sha256_file(
        Path::new(env!("CARGO_BIN_EXE_opc-session-quorum-node")),
        MAX_CANDIDATE_ARTIFACT_BYTES,
    )?;
    let executable = env::current_exe()?;
    let executable_sha256 = candidate_sha256_file(&executable, MAX_CANDIDATE_ARTIFACT_BYTES)?;
    let argv_sha256 = v9_sha256(&fs::read("/proc/self/cmdline")?);
    v9_require_runtime_digest("V1 child digest", &v1.bindings.child_sha256, &child_sha256)?;
    v9_require_runtime_digest(
        "V1 harness digest",
        &v1.bindings.harness_sha256,
        &executable_sha256,
    )?;
    v9_require_runtime_digest("V9 child digest", &v9.bindings.child_sha256, &child_sha256)?;
    v9_require_runtime_digest(
        "V9 harness digest",
        &v9.bindings.harness_sha256,
        &executable_sha256,
    )?;
    v9_require_runtime_digest(
        "V9 executable digest",
        &v9.bindings.executable_sha256,
        &executable_sha256,
    )?;
    v9_require_runtime_digest("V9 argv digest", &v9.invocation.argv_sha256, &argv_sha256)?;
    // `validate_v1_v9_pair` above recomputes both the canonical V1 digest and
    // the V9 run identity from these just-recaptured bindings.
    Ok(())
}

fn build_v9_external_evidence(
    measurements: &PersistentConsumerRunMeasurements,
    gate: &BatchReleaseGateRunFacts,
) -> io::Result<(Vec<u8>, SessionHaPersistentConsumerHeadEvidenceV9)> {
    let argv = fs::read("/proc/self/cmdline")?;
    if !argv
        .split(|byte| *byte == 0)
        .any(|argument| argument == V9_EXTERNAL_TEST_ID.as_bytes())
    {
        return Err(io::Error::other(
            "V9 requires the exact release-gate test invocation",
        ));
    }
    if measurements.release_provenance.as_ref() != Some(&gate.release_provenance) {
        return Err(io::Error::other(
            "V9 requires one identical release provenance across both campaigns",
        ));
    }
    gate.release_provenance.verify_unchanged()?;
    let v1 = SessionMtlsBatchReleaseGateEvidenceV1::from_json(&gate.canonical_v1)
        .map_err(|_| io::Error::other("V9 requires exact canonical V1 evidence"))?;
    let source_revision = gate.release_provenance.source_revision.clone();
    let source_tree = gate.release_provenance.source_tree.clone();
    let source_worktree_sha256 = gate.release_provenance.source_worktree_sha256.clone();
    let child = candidate_sha256_file(
        Path::new(env!("CARGO_BIN_EXE_opc-session-quorum-node")),
        MAX_CANDIDATE_ARTIFACT_BYTES,
    )?;
    let executable = env::current_exe()?;
    let executable_sha256 = candidate_sha256_file(&executable, MAX_CANDIDATE_ARTIFACT_BYTES)?;
    let harness_sha256 = executable_sha256.clone();
    let lane = |name: &str,
                transport_revision: u16,
                consumer_alpn: &str,
                observed: PersistentConsumerLaneMeasurements| {
        QualificationPersistentConsumerLaneV9 {
            lane: name.to_owned(),
            transport_revision,
            application_revision: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.application_revision,
            sdk_protocol_revision: 5,
            consumer_alpn: consumer_alpn.to_owned(),
            executed: observed.admission_operations > 0 && observed.status_operations > 0,
            admission_operations: observed.admission_operations,
            status_operations: observed.status_operations,
            before_leader_loss_operations: observed.before_leader_loss_operations,
            after_leader_loss_operations: observed.after_leader_loss_operations,
            after_restart_operations: observed.after_restart_operations,
            after_voter_loss_operations: observed.after_voter_loss_operations,
            tenant_authority: QualificationPersistentConsumerAuthorityV9 {
                positive_observations: observed.tenant_positive_observations,
                negative_boundary_rejections: observed.tenant_negative_boundary_rejections,
            },
            scope_authority: QualificationPersistentConsumerAuthorityV9 {
                positive_observations: observed.scope_positive_observations,
                negative_boundary_rejections: observed.scope_negative_boundary_rejections,
            },
            fence_authority: QualificationPersistentConsumerAuthorityV9 {
                positive_observations: observed.fence_positive_observations,
                negative_boundary_rejections: observed.fence_negative_boundary_rejections,
            },
        }
    };
    let argv_sha256 = v9_sha256(&argv);
    let mut evidence = SessionHaPersistentConsumerHeadEvidenceV9 {
        schema_version: "opc-session-ha-persistent-consumer-head-evidence/v9".to_owned(),
        evidence_kind: "persistent-consumer-executed-lanes".to_owned(),
        experimental: true,
        // Reached only after the combined ignored release gate has returned
        // every process, authority, rotation, capacity, and V1 causal fact.
        qualification_complete: true,
        provenance: QualificationPersistentConsumerProvenanceV9 {
            source_revision: source_revision.clone(),
            source_tree,
            source_tree_status: "clean".to_owned(),
            source_worktree_sha256: source_worktree_sha256.clone(),
        },
        invocation: QualificationPersistentConsumerInvocationV9 {
            test_id: V9_EXTERNAL_TEST_ID.to_owned(),
            argv_sha256: argv_sha256.clone(),
            run_id_sha256: V9_PAIR_RUN_ID_PREIMAGE_PLACEHOLDER.to_owned(),
            cargo_executable_alias: gate.release_provenance.cargo_executable_alias.clone(),
            cargo_executable: gate.release_provenance.cargo_executable.clone(),
            cargo_executable_sha256: gate.release_provenance.cargo_executable_sha256.clone(),
            cargo_executable_mode: gate.release_provenance.cargo_executable_mode,
            canonical_cargo_argv: gate.release_provenance.canonical_cargo_argv.clone(),
            reproduction_command: opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
                    &gate.release_provenance.cargo_target_directory,
                    &gate.release_provenance.evidence_root_directory,
                    &gate.release_provenance.fs_verity_snapshot_root_directory,
                    &gate.release_provenance.cargo_executable_alias,
                )
                .ok_or_else(|| io::Error::other("V9 canonical reproduction command is invalid"))?,
        },
        bindings: QualificationPersistentConsumerBindingsV9 {
            v9_schema_sha256: opc_session_testkit::qualification::session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            harness_sha256,
            child_sha256: child,
            executable_sha256,
            v1_canonical_sha256: v9_sha256(&gate.canonical_v1),
            cargo_target_directory: gate.release_provenance.cargo_target_directory.clone(),
            cargo_target_directory_sha256: gate
                .release_provenance
                .cargo_target_directory_sha256
                .clone(),
            evidence_root_directory: gate.release_provenance.evidence_root_directory.clone(),
            evidence_root_directory_sha256: gate
                .release_provenance
                .evidence_root_directory_sha256
                .clone(),
            fs_verity_snapshot_root_directory: gate
                .release_provenance
                .fs_verity_snapshot_root_directory
                .clone(),
            fs_verity_snapshot_root_directory_sha256: gate
                .release_provenance
                .fs_verity_snapshot_root_directory_sha256
                .clone(),
            fs_verity_snapshot_root_device: gate
                .release_provenance
                .fs_verity_snapshot_root_device,
            fs_verity_snapshot_root_inode: gate
                .release_provenance
                .fs_verity_snapshot_root_inode,
            pair_directory: gate.release_provenance.pair_directory.clone(),
            pair_directory_sha256: gate.release_provenance.pair_directory_sha256.clone(),
        },
        process_ledger: QualificationPersistentConsumerProcessLedgerV9 {
            initial_processes: measurements.initial_processes,
            unclean_process_losses: measurements.unclean_process_losses,
            restarted_processes: measurements.restarted_processes,
            observed_process_generations: measurements.observed_process_generations,
            release_gate_process_generations: u8::try_from(gate.process_generations)
                .map_err(|_| io::Error::other("V9 release process ledger overflow"))?,
        },
        release_gate: QualificationPersistentConsumerReleaseGateV9 {
            credential_rotation_executed: gate.old_credential_rejected && gate.new_credential_rejected,
            old_credential_rejected: gate.old_credential_rejected,
            new_credential_rejected: gate.new_credential_rejected,
            fixed_capacity_reclaimed: gate.capacity_reclaimed,
            durable_status_cardinality: u8::try_from(gate.durable_status_cardinality)
                .map_err(|_| io::Error::other("V9 durable-status cardinality overflow"))?,
            post_outcome_unknown_mutation_dispatches: u8::try_from(
                gate.post_outcome_unknown_mutation_dispatches,
            )
            .map_err(|_| io::Error::other("V9 mutation ledger overflow"))?,
        },
        lanes: [
            lane(
                "general",
                SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                "opc-session-consumer/1",
                measurements.general_lane,
            ),
            lane(
                "protected_roster",
                SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION,
                "opc-session-consumer/3",
                measurements.protected_roster_lane,
            ),
        ],
        members: 3,
        authenticated_setup_successes: measurements.authenticated_setup_successes,
        warm_reused_calls: measurements.warm_reused_calls,
        fixed_labels_only: true,
        identifying_values_recorded: false,
    };
    evidence.invocation.run_id_sha256 =
        v9_pair_run_id(&v1, &gate.canonical_v1, &gate.release_provenance, &evidence)?;
    let canonical = evidence
        .to_canonical_json()
        .map_err(|_| io::Error::other("V9 semantic validation failed"))?;
    v9_verify_prepublication_bindings(&gate.canonical_v1, &canonical, &gate.release_provenance)?;
    Ok((canonical, evidence))
}

fn v9_paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn v9_open_private_external_root(root: &Path) -> io::Result<std::os::fd::OwnedFd> {
    if !root.is_absolute() {
        return Err(io::Error::other(
            "V9 external evidence root is not absolute",
        ));
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for component in root.components() {
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(io::Error::other(
                "V9 external evidence root is not normalized",
            ));
        };
        directory = openat(
            &directory,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    let metadata = fstat(&directory)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || Mode::from_raw_mode(metadata.st_mode).bits() & 0o7777 != 0o700
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::other(
            "V9 external evidence root is not an owner-private directory",
        ));
    }
    Ok(directory)
}

fn v9_git_directory(repository: &Path, argument: &str) -> io::Result<PathBuf> {
    let value = candidate_git_text(repository, &["rev-parse", argument])?;
    let value = PathBuf::from(value);
    let value = if value.is_absolute() {
        value
    } else {
        repository.join(value)
    };
    fs::canonicalize(value)
}

/// Release evidence never infers Cargo's target directory from a repository
/// default or Cargo configuration. The caller must name an existing canonical
/// absolute target namespace so it can be fingerprinted and kept disjoint.
fn v9_canonical_cargo_target_directory(value: Option<OsString>) -> io::Result<PathBuf> {
    let target = value.ok_or_else(|| {
        io::Error::other("V9 evidence requires an explicit absolute CARGO_TARGET_DIR")
    })?;
    let target = PathBuf::from(target);
    if !target.is_absolute() {
        return Err(io::Error::other("CARGO_TARGET_DIR is not absolute"));
    }
    fs::canonicalize(target)
}

fn v9_canonical_path_string(path: &Path, label: &str) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::other(format!("{label} is not UTF-8")))?
        .to_owned();
    if value.len() > 4096
        || value.as_bytes().contains(&0)
        || value.as_bytes().iter().any(u8::is_ascii_control)
        || !Path::new(&value).is_absolute()
        || Path::new(&value).as_os_str().as_encoded_bytes() != value.as_bytes()
        || value.contains("//")
        || (value != "/" && value.ends_with('/'))
        || value
            .split('/')
            .skip(1)
            .any(|component| matches!(component, "." | ".."))
        || Path::new(&value)
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::Error::other(format!(
            "{label} is not a canonical absolute path"
        )));
    }
    Ok(value)
}

fn v9_canonical_evidence_root_directory(value: Option<OsString>) -> io::Result<PathBuf> {
    let root = value.ok_or_else(|| {
        io::Error::other("V9 evidence requires OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY")
    })?;
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(io::Error::other(
            "OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY is not absolute",
        ));
    }
    let root_fd = v9_open_private_external_root(&root)?;
    let canonical = fs::canonicalize(format!("/proc/self/fd/{}", root_fd.as_raw_fd()))?;
    if canonical != root {
        return Err(io::Error::other(
            "OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY is not canonical",
        ));
    }
    v9_canonical_path_string(&canonical, "V9 external evidence root")?;
    Ok(canonical)
}

struct V9FsVeritySnapshotRoot {
    directory: PathBuf,
    device: u64,
    inode: u64,
}

fn v9_require_distinct_snapshot_filesystem(
    target: &Path,
    snapshot_root: &V9FsVeritySnapshotRoot,
) -> io::Result<()> {
    if fs::metadata(target)?.dev() == snapshot_root.device {
        return Err(io::Error::other(
            "V9 Cargo target must not share the fs-verity snapshot filesystem",
        ));
    }
    Ok(())
}

fn v9_canonical_fs_verity_snapshot_root_directory(
    value: Option<OsString>,
) -> io::Result<V9FsVeritySnapshotRoot> {
    if env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref() != Some(std::ffi::OsStr::new("required"))
    {
        return Err(io::Error::other(
            "V9 fs-verity snapshots require the fixed qualification marker",
        ));
    }
    let root = value
        .ok_or_else(|| io::Error::other("V9 evidence requires OPC_FS_VERITY_SNAPSHOT_ROOT"))?;
    let root_bytes = root.as_encoded_bytes().to_vec();
    let root = PathBuf::from(root);
    if !root.is_absolute() {
        return Err(io::Error::other(
            "OPC_FS_VERITY_SNAPSHOT_ROOT is not absolute",
        ));
    }
    let root_fd = v9_open_private_external_root(&root)?;
    let identity = fstat(&root_fd)?;
    let canonical = fs::canonicalize(format!("/proc/self/fd/{}", root_fd.as_raw_fd()))?;
    if root_bytes != canonical.as_os_str().as_encoded_bytes() {
        return Err(io::Error::other(
            "OPC_FS_VERITY_SNAPSHOT_ROOT is not canonical",
        ));
    }
    v9_canonical_path_string(&canonical, "V9 fs-verity snapshot root")?;
    Ok(V9FsVeritySnapshotRoot {
        directory: canonical,
        device: identity.st_dev as u64,
        inode: identity.st_ino as u64,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct V9ExternalNamespaceBindings {
    cargo_target_directory: String,
    cargo_target_directory_sha256: String,
    evidence_root_directory: String,
    evidence_root_directory_sha256: String,
    fs_verity_snapshot_root_directory: String,
    fs_verity_snapshot_root_directory_sha256: String,
    fs_verity_snapshot_root_device: u64,
    fs_verity_snapshot_root_inode: u64,
    pair_directory: String,
    pair_directory_sha256: String,
}

/// Capture both operator-provisioned external namespaces before either
/// campaign starts. The V9 envelope and its run identity carry these exact
/// canonical strings, path commitments, and the snapshot-base device/inode,
/// so a separate store consumer can distinguish a same-path replacement.
fn v9_external_namespace_bindings() -> io::Result<V9ExternalNamespaceBindings> {
    let repository = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
    let gitdir = v9_git_directory(&repository, "--absolute-git-dir")?;
    let common_gitdir = v9_git_directory(&repository, "--git-common-dir")?;
    let target = v9_canonical_cargo_target_directory(env::var_os("CARGO_TARGET_DIR"))?;
    let root = v9_canonical_evidence_root_directory(env::var_os(
        "OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY",
    ))?;
    let snapshot_root =
        v9_canonical_fs_verity_snapshot_root_directory(env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV))?;
    v9_require_distinct_snapshot_filesystem(&target, &snapshot_root)?;
    v9_require_external_disjointness(
        &target,
        &[repository.clone(), gitdir.clone(), common_gitdir.clone()],
    )?;
    v9_require_external_disjointness(
        &root,
        &[
            repository.clone(),
            gitdir.clone(),
            common_gitdir.clone(),
            target.clone(),
        ],
    )?;
    v9_require_external_disjointness(
        &snapshot_root.directory,
        &[
            repository,
            gitdir,
            common_gitdir,
            target.clone(),
            root.clone(),
        ],
    )?;

    let cargo_target_directory = v9_canonical_path_string(&target, "CARGO_TARGET_DIR")?;
    let evidence_root_directory = v9_canonical_path_string(&root, "V9 external evidence root")?;
    let fs_verity_snapshot_root_directory =
        v9_canonical_path_string(&snapshot_root.directory, "V9 fs-verity snapshot root")?;
    let pair_directory = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory(&evidence_root_directory)
        .ok_or_else(|| io::Error::other("V9 pair directory cannot be derived from evidence root"))?;
    let cargo_target_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_cargo_target_directory_sha256(
            &cargo_target_directory,
        )
        .ok_or_else(|| io::Error::other("V9 Cargo target directory commitment is invalid"))?;
    let evidence_root_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_evidence_root_directory_sha256(
            &evidence_root_directory,
        )
        .ok_or_else(|| io::Error::other("V9 evidence root commitment is invalid"))?;
    let fs_verity_snapshot_root_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_fs_verity_snapshot_root_directory_sha256(
            &fs_verity_snapshot_root_directory,
        )
        .ok_or_else(|| io::Error::other("V9 fs-verity snapshot root commitment is invalid"))?;
    let pair_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory_sha256(&pair_directory)
        .ok_or_else(|| io::Error::other("V9 pair directory commitment is invalid"))?;
    Ok(V9ExternalNamespaceBindings {
        cargo_target_directory,
        cargo_target_directory_sha256,
        evidence_root_directory,
        evidence_root_directory_sha256,
        fs_verity_snapshot_root_directory,
        fs_verity_snapshot_root_directory_sha256,
        fs_verity_snapshot_root_device: snapshot_root.device,
        fs_verity_snapshot_root_inode: snapshot_root.inode,
        pair_directory,
        pair_directory_sha256,
    })
}

fn v9_require_external_disjointness(root: &Path, protected: &[PathBuf]) -> io::Result<()> {
    if protected
        .iter()
        .any(|protected| v9_paths_overlap(root, protected))
    {
        return Err(io::Error::other(
            "V9 external evidence root overlaps source, git metadata, or Cargo target",
        ));
    }
    Ok(())
}

/// Publish already-validated canonical pair bytes into one opened private
/// namespace.  This seam lets the no-clobber/durability mechanics be tested
/// without manufacturing a release-qualified source invocation.
fn publish_v9_pair_files_at<Fd: AsFd>(root_fd: Fd, v1: &[u8], v9: &[u8]) -> io::Result<()> {
    publish_v9_pair_files_at_with_directory_sync(root_fd, v1, v9, |directory| {
        fsync(directory).map_err(Into::into)
    })
}

fn publish_v9_pair_files_at_with_directory_sync<Fd: AsFd, SyncDirectory>(
    root_fd: Fd,
    v1: &[u8],
    v9: &[u8],
    sync_directory: SyncDirectory,
) -> io::Result<()>
where
    SyncDirectory: FnOnce(&Fd) -> io::Result<()>,
{
    publish_v9_pair_files_at_with_pre_rename(root_fd, v1, v9, sync_directory, || Ok(()))
}

fn publish_v9_pair_files_at_with_pre_rename<Fd: AsFd, SyncDirectory, BeforeRename>(
    root_fd: Fd,
    v1: &[u8],
    v9: &[u8],
    sync_directory: SyncDirectory,
    before_rename: BeforeRename,
) -> io::Result<()>
where
    SyncDirectory: FnOnce(&Fd) -> io::Result<()>,
    BeforeRename: FnOnce() -> io::Result<()>,
{
    let staging = create_candidate_staging_directory(&root_fd)?;
    let staging_fd = match openat(
        &root_fd,
        staging.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let _ = unlinkat(&root_fd, staging.as_str(), AtFlags::REMOVEDIR);
            return Err(error.into());
        }
    };
    let mut renamed = false;
    let result: io::Result<()> = (|| {
        // Persist the parent entry for the private staging directory before
        // any artifact bytes are written. A failure here is pre-rename and
        // therefore safely cleaned up below.
        fsync(&root_fd)?;
        write_private_candidate_file_at(&staging_fd, "batch-release-gate-v1.json", v1)?;
        write_private_candidate_file_at(&staging_fd, "persistent-consumer-v9.json", v9)?;
        fsync(&staging_fd)?;
        // This is the last point before the atomic visibility transition. A
        // same-UID writer can still race after this check; the immutable
        // no-replace rename and retained post-rename recovery artifact make
        // that residual explicit rather than claiming it is impossible.
        before_rename()?;
        renameat_with(
            &root_fd,
            staging.as_str(),
            &root_fd,
            "session-ha-persistent-consumer-v9",
            RenameFlags::NOREPLACE,
        )?;
        renamed = true;
        // If this fails the complete create-new artifact remains visible for
        // explicit operator recovery; deleting it would turn a durability
        // unknown into silent data loss.
        sync_directory(&root_fd).map_err(|_| {
            io::Error::other("V9 evidence published but directory durability is unknown")
        })?;
        Ok(())
    })();
    if result.is_err() && !renamed {
        let _ = unlinkat(&staging_fd, "batch-release-gate-v1.json", AtFlags::empty());
        let _ = unlinkat(&staging_fd, "persistent-consumer-v9.json", AtFlags::empty());
        let _ = unlinkat(&root_fd, staging.as_str(), AtFlags::REMOVEDIR);
    }
    result
}

fn publish_v9_external_evidence_at(root: &Path, v1: &[u8], v9: &[u8]) -> io::Result<()> {
    let provenance = ReleaseGateProvenance::capture()?;
    v9_verify_prepublication_bindings(v1, v9, &provenance)?;
    // The caller must provision this dedicated namespace. In particular, do
    // not recursively create or chmod an ancestor that might be shared.
    let root_fd = v9_open_private_external_root(root)?;
    let root = fs::canonicalize(format!("/proc/self/fd/{}", root_fd.as_raw_fd()))?;
    let canonical_root = v9_canonical_path_string(&root, "V9 publication root")?;
    if canonical_root != provenance.evidence_root_directory {
        return Err(io::Error::other(
            "V9 publication root differs from the root bound into the release provenance",
        ));
    }
    v9_verify_prepublication_bindings(v1, v9, &provenance)?;
    publish_v9_pair_files_at_with_pre_rename(
        &root_fd,
        v1,
        v9,
        |directory| fsync(directory).map_err(Into::into),
        || v9_verify_prepublication_bindings(v1, v9, &provenance),
    )?;
    let published_pair = fs::canonicalize(root.join(
        opc_session_testkit::qualification::SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_PAIR_DIRECTORY,
    ))?;
    if v9_canonical_path_string(&published_pair, "V9 published pair root")?
        != provenance.pair_directory
    {
        return Err(io::Error::other(
            "V9 published pair root differs from the root bound into the release provenance",
        ));
    }
    Ok(())
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

fn ensure_v2_batch_release_feature_profile() -> io::Result<()> {
    if cfg!(feature = "foundation-insecure") {
        return Err(io::Error::other(
            "V2 batch release evidence is disabled when foundation-insecure is compiled",
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
    let lifecycle_after_soft_retirement = fleet.wait_for_expiry_soft_retirement(
        expiring_node_index,
        &lifecycle_before_expiry,
        not_after,
    );
    emit_fixed_lifecycle_connection_snapshot(
        "soft_authenticated_retirement",
        &lifecycle_after_soft_retirement,
    );
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
    emit_fixed_lifecycle_connection_snapshot("hard_expiry", &fleet.all_lifecycle_metrics());
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
    emit_fixed_lifecycle_connection_snapshot(
        "replacement_publication",
        &fleet.all_lifecycle_metrics(),
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
    emit_fixed_lifecycle_connection_snapshot("settled_recovery", &fleet.all_lifecycle_metrics());
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
    let high_water_generations = sampler.finish();
    let high_water = merge_resource_generation_high_water(&high_water_generations);
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
fn batch_release_evidence_feature_gate_matches_the_compiled_transport_profile() {
    let result = ensure_v2_batch_release_feature_profile();
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

fn write_candidate_git_helper_script(path: &Path, body: &[u8]) {
    fs::write(path, body).expect("write candidate Git helper script");
    fs::set_permissions(path, Permissions::from_mode(0o700))
        .expect("make candidate Git helper script executable");
}

fn candidate_git_process_is_gone(process_id: u32) -> bool {
    let Some(process_id) = i32::try_from(process_id)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    match rustix::process::test_kill_process(process_id) {
        Ok(()) => false,
        Err(error) if error.raw_os_error() == 3 => true, // ESRCH
        Err(_) => false,
    }
}

#[test]
fn bounded_candidate_git_runner_returns_success_and_rejects_output_overflow() {
    let workspace = tempfile::tempdir().expect("create bounded Git helper workspace");
    let helper = workspace.path().join("fake-git");
    write_candidate_git_helper_script(&helper, b"#!/bin/sh\nprintf 'clean-output'\n");
    let output = bounded_candidate_git_command_output(&mut Command::new(&helper), 64)
        .expect("bounded Git helper succeeds");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"clean-output");
    assert!(output.stderr.is_empty());

    write_candidate_git_helper_script(&helper, b"#!/bin/sh\nprintf 'overflow-output'\n");
    assert!(
        bounded_candidate_git_command_output(&mut Command::new(&helper), 3).is_err(),
        "the bounded Git runner must fail closed when stdout exceeds its exact bound"
    );
}

#[test]
fn bounded_candidate_git_runner_retains_early_stdout_until_late_stderr_and_exit() {
    let workspace = tempfile::tempdir().expect("create asymmetric Git helper workspace");
    let helper = workspace.path().join("fake-git");
    write_candidate_git_helper_script(
        &helper,
        b"#!/bin/sh\nprintf 'early-output'\nexec 1>&-\nsleep 0.15\nprintf 'late-diagnostic' >&2\n",
    );

    let started = Instant::now();
    let output = bounded_candidate_git_command_output(&mut Command::new(&helper), 64)
        .expect("early stdout close with late stderr and exit remains successful");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "retaining early stdout is weakening-sensitive: discarding it waits for the five-second deadline"
    );
    assert!(output.status.success());
    assert_eq!(output.stdout, b"early-output");
    assert_eq!(output.stderr, b"late-diagnostic");
}

#[test]
fn bounded_candidate_git_runner_kills_pipe_holding_term_resistant_descendant() {
    let workspace = tempfile::tempdir().expect("create descendant helper workspace");
    let helper = workspace.path().join("fake-git");
    let descendant_pid = workspace.path().join("descendant.pid");
    let leader_pid = workspace.path().join("leader.pid");
    write_candidate_git_helper_script(
        &helper,
        b"#!/bin/sh\nprintf '%s' \"$$\" > \"$2\"\n(\n  trap '' TERM\n  while :; do sleep 1; done\n) &\ndescendant=$!\nprintf '%s' \"$descendant\" > \"$1\"\nexit 0\n",
    );

    let started = Instant::now();
    let result = bounded_candidate_git_command_output(
        Command::new(&helper).arg(&descendant_pid).arg(&leader_pid),
        64,
    );
    assert!(
        result.is_err(),
        "a descendant-held pipe must hit the deadline"
    );
    assert!(
        started.elapsed()
            < CANDIDATE_GIT_COMMAND_TIMEOUT
                + CANDIDATE_GIT_TERMINATE_GRACE
                + CANDIDATE_GIT_TERMINATE_GRACE
                + Duration::from_secs(1),
        "the leader-exit pipe attack cannot turn the trusted Git helper into an unbounded wait"
    );
    let observed_leader_pid = fs::read_to_string(&leader_pid)
        .expect("leader reported its pid")
        .trim()
        .parse::<u32>()
        .expect("leader pid is numeric");
    let observed_descendant_pid = fs::read_to_string(&descendant_pid)
        .expect("parent recorded background descendant pid")
        .trim()
        .parse::<u32>()
        .expect("background descendant pid is numeric");
    assert_ne!(
        observed_leader_pid, observed_descendant_pid,
        "the parent-recorded $! must name a distinct background descendant"
    );
    let gone_deadline = Instant::now() + CANDIDATE_GIT_TERMINATE_GRACE;
    while !candidate_git_process_is_gone(observed_descendant_pid) && Instant::now() < gone_deadline
    {
        thread::sleep(CANDIDATE_GIT_PIPE_POLL);
    }
    assert!(
        candidate_git_process_is_gone(observed_descendant_pid),
        "owned process-group SIGKILL leaves the exact parent-recorded descendant PID gone after its leader exits"
    );
}

#[test]
fn v9_external_namespace_is_owner_private_nofollow_and_no_clobber() {
    let workspace = tempfile::tempdir().expect("create V9 publication workspace");
    let root = workspace.path().join("evidence");
    fs::create_dir(&root).expect("create dedicated external evidence root");
    fs::set_permissions(&root, Permissions::from_mode(0o700))
        .expect("make external evidence root owner private");
    let root_fd = v9_open_private_external_root(&root).expect("open private root without links");
    publish_v9_pair_files_at(&root_fd, b"canonical-v1", b"canonical-v9")
        .expect("first pair publication is create-new");
    assert!(
        publish_v9_pair_files_at(&root_fd, b"other-v1", b"other-v9").is_err(),
        "a complete prior pair must not be replaced"
    );
    let published = root.join("session-ha-persistent-consumer-v9");
    assert_eq!(
        fs::read(published.join("batch-release-gate-v1.json")).expect("read retained V1"),
        b"canonical-v1"
    );
    assert_eq!(
        fs::read(published.join("persistent-consumer-v9.json")).expect("read retained V9"),
        b"canonical-v9"
    );
    assert_eq!(
        fs::read_dir(&root).expect("inspect private root").count(),
        1,
        "the pre-rename no-clobber failure removes its staging directory"
    );

    let link = workspace.path().join("linked-evidence");
    symlink(&root, &link).expect("create hostile evidence-root symlink");
    assert!(v9_open_private_external_root(&link).is_err());
}

#[test]
fn v9_external_path_overlap_is_symmetric() {
    assert!(v9_paths_overlap(
        Path::new("/external/evidence"),
        Path::new("/external")
    ));
    assert!(v9_paths_overlap(
        Path::new("/external"),
        Path::new("/external/evidence")
    ));
    assert!(!v9_paths_overlap(
        Path::new("/external/evidence"),
        Path::new("/other")
    ));
}

#[test]
fn v9_external_root_rejects_linked_git_common_git_and_target_descendants() {
    let repository = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("canonical SDK repository");
    let gitdir = v9_git_directory(&repository, "--absolute-git-dir")
        .expect("resolve linked-worktree git directory");
    let common_gitdir =
        v9_git_directory(&repository, "--git-common-dir").expect("resolve common git directory");
    let target = repository.join("target");
    let protected = vec![
        repository,
        gitdir.clone(),
        common_gitdir.clone(),
        target.clone(),
    ];

    assert!(v9_require_external_disjointness(&gitdir, &protected).is_err());
    assert!(v9_require_external_disjointness(&common_gitdir, &protected).is_err());
    assert!(v9_require_external_disjointness(&target.join("v9-evidence"), &protected).is_err());
}

#[test]
fn v9_requires_explicit_canonical_cargo_target_directory() {
    let workspace = tempfile::tempdir().expect("create target-directory workspace");
    let configured_target = workspace.path().join("configured-target");
    fs::create_dir(&configured_target).expect("create explicit target directory");
    assert!(v9_canonical_cargo_target_directory(None).is_err());
    assert!(v9_canonical_cargo_target_directory(Some(OsString::from("relative-target"))).is_err());
    assert_eq!(
        v9_canonical_cargo_target_directory(Some(configured_target.clone().into_os_string()))
            .expect("canonical explicit target directory"),
        fs::canonicalize(&configured_target).expect("canonical configured target"),
        "a caller-selected target directory must not be replaced by repository/target"
    );
}

#[test]
fn v9_canonical_path_parser_rejects_snapshot_root_aliases() {
    assert!(v9_canonical_path_string(
        Path::new("/external/fs-verity-snapshots/."),
        "V9 fs-verity snapshot root"
    )
    .is_err());
    assert!(v9_canonical_path_string(
        Path::new("/external//fs-verity-snapshots"),
        "V9 fs-verity snapshot root"
    )
    .is_err());
    assert!(v9_canonical_path_string(
        Path::new("/external/fs-verity-snapshots"),
        "V9 fs-verity snapshot root"
    )
    .is_ok());
}

#[test]
fn v9_target_rejects_snapshot_root_on_the_same_filesystem() {
    let workspace = tempfile::tempdir().expect("same-device V9 workspace");
    let target = workspace.path().join("target");
    let snapshot_root = workspace.path().join("fs-verity-snapshots");
    fs::create_dir(&target).expect("create same-device V9 target");
    fs::create_dir(&snapshot_root).expect("create same-device V9 snapshot root");
    let snapshot_metadata = fs::metadata(&snapshot_root).expect("stat V9 snapshot root");
    let binding = V9FsVeritySnapshotRoot {
        directory: snapshot_root,
        device: snapshot_metadata.dev(),
        inode: snapshot_metadata.ino(),
    };
    assert_eq!(
        fs::metadata(&target).expect("stat V9 target").dev(),
        binding.device
    );
    assert_eq!(
        v9_require_distinct_snapshot_filesystem(&target, &binding)
            .expect_err("same-device V9 target must fail closed")
            .to_string(),
        "V9 Cargo target must not share the fs-verity snapshot filesystem"
    );
}

fn v9_test_release_provenance() -> ReleaseGateProvenance {
    let cargo_target_directory = "/var/lib/opc-testkit/target".to_owned();
    let evidence_root_directory = "/var/lib/opc-testkit/evidence".to_owned();
    let fs_verity_snapshot_root_directory = "/var/lib/opc-testkit/fs-verity-snapshots".to_owned();
    let pair_directory = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory(&evidence_root_directory)
        .expect("derive fixed V9 pair root");
    ReleaseGateProvenance {
        source_revision: "a".repeat(40),
        source_tree: "b".repeat(40),
        source_worktree_sha256: format!("sha256:{}", "c".repeat(64)),
        cargo_lock_sha256: format!("sha256:{}", "d".repeat(64)),
        cargo_target_directory_sha256: opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_cargo_target_directory_sha256(
                &cargo_target_directory,
            )
            .expect("commit test target"),
        cargo_target_directory,
        evidence_root_directory_sha256: opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_evidence_root_directory_sha256(
                &evidence_root_directory,
            )
            .expect("commit test evidence root"),
        evidence_root_directory,
        fs_verity_snapshot_root_directory_sha256: opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_fs_verity_snapshot_root_directory_sha256(
                &fs_verity_snapshot_root_directory,
            )
            .expect("commit test fs-verity snapshot root"),
        fs_verity_snapshot_root_device: 17,
        fs_verity_snapshot_root_inode: 19,
        fs_verity_snapshot_root_directory,
        pair_directory_sha256: opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_pair_directory_sha256(&pair_directory)
                .expect("commit test pair root"),
        pair_directory,
        command_argv_sha256: format!("sha256:{}", "e".repeat(64)),
        cargo_executable_alias: "/var/lib/opc-testkit/cargo".to_owned(),
        cargo_executable: "/var/lib/opc-testkit/rustup".to_owned(),
        cargo_executable_sha256: format!("sha256:{}", "f".repeat(64)),
        cargo_executable_mode: 0o755,
        canonical_cargo_argv: opc_session_testkit::qualification::
            SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_CARGO_ARGV
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        cargo_profile: "release".to_owned(),
        opt_level: "3".to_owned(),
    }
}

fn v9_test_claims(provenance: &ReleaseGateProvenance) -> SessionHaPersistentConsumerHeadEvidenceV9 {
    let lane = |name: &str,
                transport_revision: u16,
                consumer_alpn: &str,
                tenant_negative_boundary_rejections: u8| {
        QualificationPersistentConsumerLaneV9 {
            lane: name.to_owned(),
            transport_revision,
            application_revision: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.application_revision,
            sdk_protocol_revision: 5,
            consumer_alpn: consumer_alpn.to_owned(),
            executed: true,
            admission_operations: 1,
            status_operations: 1,
            before_leader_loss_operations: 1,
            after_leader_loss_operations: 1,
            after_restart_operations: 1,
            after_voter_loss_operations: 1,
            tenant_authority: QualificationPersistentConsumerAuthorityV9 {
                positive_observations: 1,
                negative_boundary_rejections: tenant_negative_boundary_rejections,
            },
            scope_authority: QualificationPersistentConsumerAuthorityV9 {
                positive_observations: 1,
                negative_boundary_rejections: 1,
            },
            fence_authority: QualificationPersistentConsumerAuthorityV9 {
                positive_observations: 1,
                negative_boundary_rejections: 1,
            },
        }
    };
    SessionHaPersistentConsumerHeadEvidenceV9 {
        schema_version: "opc-session-ha-persistent-consumer-head-evidence/v9".to_owned(),
        evidence_kind: "persistent-consumer-executed-lanes".to_owned(),
        experimental: true,
        qualification_complete: true,
        provenance: QualificationPersistentConsumerProvenanceV9 {
            source_revision: provenance.source_revision.clone(),
            source_tree: provenance.source_tree.clone(),
            source_tree_status: "clean".to_owned(),
            source_worktree_sha256: provenance.source_worktree_sha256.clone(),
        },
        invocation: QualificationPersistentConsumerInvocationV9 {
            test_id: V9_EXTERNAL_TEST_ID.to_owned(),
            argv_sha256: format!("sha256:{}", "7".repeat(64)),
            run_id_sha256: V9_PAIR_RUN_ID_PREIMAGE_PLACEHOLDER.to_owned(),
            cargo_executable_alias: provenance.cargo_executable_alias.clone(),
            cargo_executable: provenance.cargo_executable.clone(),
            cargo_executable_sha256: provenance.cargo_executable_sha256.clone(),
            cargo_executable_mode: provenance.cargo_executable_mode,
            canonical_cargo_argv: provenance.canonical_cargo_argv.clone(),
            reproduction_command: opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_reproduction_command(
                    &provenance.cargo_target_directory,
                    &provenance.evidence_root_directory,
                    &provenance.fs_verity_snapshot_root_directory,
                    &provenance.cargo_executable_alias,
                )
                .expect("render V9 test recipe"),
        },
        bindings: QualificationPersistentConsumerBindingsV9 {
            v9_schema_sha256: opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            harness_sha256: format!("sha256:{}", "8".repeat(64)),
            child_sha256: format!("sha256:{}", "9".repeat(64)),
            executable_sha256: format!("sha256:{}", "8".repeat(64)),
            v1_canonical_sha256: v9_sha256(b"canonical-v1"),
            cargo_target_directory: provenance.cargo_target_directory.clone(),
            cargo_target_directory_sha256: provenance.cargo_target_directory_sha256.clone(),
            evidence_root_directory: provenance.evidence_root_directory.clone(),
            evidence_root_directory_sha256: provenance.evidence_root_directory_sha256.clone(),
            fs_verity_snapshot_root_directory: provenance.fs_verity_snapshot_root_directory.clone(),
            fs_verity_snapshot_root_directory_sha256: provenance
                .fs_verity_snapshot_root_directory_sha256
                .clone(),
            fs_verity_snapshot_root_device: provenance.fs_verity_snapshot_root_device,
            fs_verity_snapshot_root_inode: provenance.fs_verity_snapshot_root_inode,
            pair_directory: provenance.pair_directory.clone(),
            pair_directory_sha256: provenance.pair_directory_sha256.clone(),
        },
        process_ledger: QualificationPersistentConsumerProcessLedgerV9 {
            initial_processes: 3,
            unclean_process_losses: 2,
            restarted_processes: 1,
            observed_process_generations: 4,
            release_gate_process_generations: 4,
        },
        release_gate: QualificationPersistentConsumerReleaseGateV9 {
            credential_rotation_executed: true,
            old_credential_rejected: true,
            new_credential_rejected: true,
            fixed_capacity_reclaimed: true,
            durable_status_cardinality: 12,
            post_outcome_unknown_mutation_dispatches: 0,
        },
        lanes: [
            lane(
                "general",
                SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION,
                "opc-session-consumer/1",
                1,
            ),
            lane(
                "protected_roster",
                SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION,
                "opc-session-consumer/3",
                3,
            ),
        ],
        members: 3,
        authenticated_setup_successes: 48,
        warm_reused_calls: 1_000,
        fixed_labels_only: true,
        identifying_values_recorded: false,
    }
}

#[test]
fn v9_backslash_heavy_paths_fit_the_mirrored_closed_document_envelope() {
    let escaped_path = |label: &str| format!("/{label}{}", "\\".repeat(2_990));
    let mut provenance = v9_test_release_provenance();
    provenance.cargo_target_directory = escaped_path("target");
    provenance.cargo_target_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_cargo_target_directory_sha256(
            &provenance.cargo_target_directory,
        )
        .expect("commit escaped target path");
    provenance.evidence_root_directory = escaped_path("evidence");
    provenance.evidence_root_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_evidence_root_directory_sha256(
            &provenance.evidence_root_directory,
        )
        .expect("commit escaped evidence root");
    provenance.fs_verity_snapshot_root_directory = escaped_path("snapshots");
    provenance.fs_verity_snapshot_root_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_fs_verity_snapshot_root_directory_sha256(
            &provenance.fs_verity_snapshot_root_directory,
        )
        .expect("commit escaped fs-verity root");
    provenance.pair_directory = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory(
            &provenance.evidence_root_directory,
        )
        .expect("derive escaped pair directory");
    provenance.pair_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory_sha256(
            &provenance.pair_directory,
        )
        .expect("commit escaped pair directory");
    provenance.cargo_executable_alias = escaped_path("cargo");
    provenance.cargo_executable = escaped_path("rustup");

    let mut evidence = v9_test_claims(&provenance);
    evidence.invocation.run_id_sha256 = v9_test_run_id(&provenance, &evidence);
    assert!(
        evidence.invocation.reproduction_command.chars().count() <= 16 * 1024,
        "the exact regenerated recipe stays within its closed schema bound"
    );
    let canonical = evidence
        .to_canonical_json()
        .expect("escaped real-path evidence fits the producer bound");
    assert!(
        canonical.len() > 64 * 1024,
        "the fixture causally exceeds the retired late-failure boundary"
    );
    assert!(canonical.len() <= SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_MAX_BYTES);
    assert_eq!(
        SessionHaPersistentConsumerHeadEvidenceV9::from_json(&canonical),
        Ok(evidence),
        "the producer and consumer must share one exact escaped-path envelope"
    );
    assert_eq!(
        SessionHaPersistentConsumerHeadEvidenceV9::from_json(&vec![
            b' ';
            SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_MAX_BYTES
                + 1
        ]),
        Err(SessionHaPersistentConsumerHeadEvidenceV9Error::DocumentTooLarge)
    );
}

fn v9_test_run_id(
    provenance: &ReleaseGateProvenance,
    claims: &SessionHaPersistentConsumerHeadEvidenceV9,
) -> String {
    let v1_bindings = [
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        format!("sha256:{}", "3".repeat(64)),
        format!("sha256:{}", "4".repeat(64)),
        format!("sha256:{}", "5".repeat(64)),
        format!("sha256:{}", "6".repeat(64)),
    ];
    let v1_binding_refs = v1_bindings.iter().map(String::as_str).collect::<Vec<_>>();
    v9_pair_run_id_material(
        provenance,
        &v1_binding_refs,
        &opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
        &claims.invocation.argv_sha256,
        b"canonical-v1",
        &v9_pair_claims_preimage(claims).expect("canonical V9 claims preimage"),
    )
    .expect("construct V9 run identity from canonical claims")
}

#[test]
fn v9_run_identity_binds_reconstructible_external_namespaces_and_recipe() {
    let provenance = v9_test_release_provenance();
    let v1_bindings = [
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        format!("sha256:{}", "3".repeat(64)),
        format!("sha256:{}", "4".repeat(64)),
        format!("sha256:{}", "5".repeat(64)),
        format!("sha256:{}", "6".repeat(64)),
    ];
    let v1_binding_refs = v1_bindings.iter().map(String::as_str).collect::<Vec<_>>();
    let run_id = v9_pair_run_id_material(
        &provenance,
        &v1_binding_refs,
        &opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
        &format!("sha256:{}", "7".repeat(64)),
        b"canonical-v1",
        b"canonical-v9-claims",
    )
    .expect("construct baseline V9 run identity");

    let mut target_replacement = provenance.clone();
    target_replacement.cargo_target_directory = "/var/lib/opc-testkit/replaced-target".to_owned();
    target_replacement.cargo_target_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_cargo_target_directory_sha256(
            &target_replacement.cargo_target_directory,
        )
        .expect("commit replaced target");
    assert_ne!(
        v9_pair_run_id_material(
            &target_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replaced-target V9 run identity"),
        run_id,
        "a syntactically valid replacement target must not inherit the original V1/V9 run ID"
    );

    let mut cross_bound_root = provenance.clone();
    cross_bound_root.evidence_root_directory = "/var/lib/opc-testkit/other-evidence".to_owned();
    cross_bound_root.evidence_root_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_evidence_root_directory_sha256(
            &cross_bound_root.evidence_root_directory,
        )
        .expect("commit replacement evidence root");
    cross_bound_root.pair_directory = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory(
            &cross_bound_root.evidence_root_directory,
        )
        .expect("derive replacement pair root");
    cross_bound_root.pair_directory_sha256 = opc_session_testkit::qualification::
        session_ha_persistent_consumer_head_evidence_v9_pair_directory_sha256(
            &cross_bound_root.pair_directory,
        )
        .expect("commit replacement pair root");
    assert_ne!(
        v9_pair_run_id_material(
            &cross_bound_root,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct cross-root V9 run identity"),
        run_id,
        "a complete replacement root/pair cannot cross-bind to the original V1 artifact"
    );

    let mut snapshot_root_replacement = provenance.clone();
    snapshot_root_replacement.fs_verity_snapshot_root_directory =
        "/var/lib/opc-testkit/other-fs-verity-snapshots".to_owned();
    snapshot_root_replacement.fs_verity_snapshot_root_directory_sha256 =
        opc_session_testkit::qualification::
            session_ha_persistent_consumer_head_evidence_v9_fs_verity_snapshot_root_directory_sha256(
                &snapshot_root_replacement.fs_verity_snapshot_root_directory,
            )
            .expect("commit replacement fs-verity snapshot root");
    assert_ne!(
        v9_pair_run_id_material(
            &snapshot_root_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replacement-snapshot-root V9 run identity"),
        run_id,
        "a replacement fs-verity snapshot root cannot inherit the original V1/V9 run ID"
    );

    let mut snapshot_root_identity_replacement = provenance.clone();
    snapshot_root_identity_replacement.fs_verity_snapshot_root_inode += 1;
    assert_ne!(
        v9_pair_run_id_material(
            &snapshot_root_identity_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replaced-snapshot-identity V9 run identity"),
        run_id,
        "a same-path fs-verity snapshot-root inode replacement cannot inherit the original V1/V9 run ID"
    );

    let mut alias_replacement = provenance.clone();
    alias_replacement.cargo_executable_alias = "/var/lib/opc-testkit/replaced-cargo".to_owned();
    assert_ne!(
        v9_pair_run_id_material(
            &alias_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replacement-alias V9 run identity"),
        run_id,
        "a replacement Cargo alias cannot inherit the original V1/V9 run ID"
    );

    let mut backing_replacement = provenance.clone();
    backing_replacement.cargo_executable = "/var/lib/opc-testkit/replaced-rustup".to_owned();
    assert_ne!(
        v9_pair_run_id_material(
            &backing_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replacement-backing V9 run identity"),
        run_id,
        "a replacement Cargo backing cannot inherit the original V1/V9 run ID"
    );

    let mut content_replacement = provenance;
    content_replacement.cargo_executable_sha256 = format!("sha256:{}", "8".repeat(64));
    assert_ne!(
        v9_pair_run_id_material(
            &content_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replacement-Cargo-content V9 run identity"),
        run_id,
        "a replacement Cargo backing content digest cannot inherit the original V1/V9 run ID"
    );

    let mut mode_replacement = content_replacement;
    mode_replacement.cargo_executable_mode = 0o700;
    assert_ne!(
        v9_pair_run_id_material(
            &mode_replacement,
            &v1_binding_refs,
            &opc_session_testkit::qualification::
                session_ha_persistent_consumer_head_evidence_v9_schema_sha256(),
            &format!("sha256:{}", "7".repeat(64)),
            b"canonical-v1",
            b"canonical-v9-claims",
        )
        .expect("construct replacement-mode V9 run identity"),
        run_id,
        "a changed canonical Cargo execute mode cannot inherit the original V1/V9 run ID"
    );
}

#[test]
fn v9_run_identity_binds_every_mutable_campaign_claim() {
    let provenance = v9_test_release_provenance();
    let baseline = v9_test_claims(&provenance);
    let baseline_run_id = v9_test_run_id(&provenance, &baseline);

    let mut process_generation = baseline.clone();
    process_generation
        .process_ledger
        .release_gate_process_generations += 1;
    let mut lane = baseline.clone();
    lane.lanes[0].after_voter_loss_operations += 1;
    let mut authority = baseline.clone();
    authority.lanes[1].scope_authority.positive_observations += 1;
    let mut setup = baseline.clone();
    setup.authenticated_setup_successes += 1;
    let mut warm_call = baseline.clone();
    warm_call.warm_reused_calls += 1;
    let mut flexible_binding = baseline.clone();
    flexible_binding.bindings.child_sha256 = format!("sha256:{}", "a".repeat(64));
    let mut invocation = baseline.clone();
    invocation.invocation.argv_sha256 = format!("sha256:{}", "b".repeat(64));

    for (claim, changed) in [
        ("process-generation", process_generation),
        ("lane lifecycle", lane),
        ("authority observation", authority),
        ("authenticated setup", setup),
        ("warm call", warm_call),
        ("flexible binding", flexible_binding),
        ("invocation", invocation),
    ] {
        let changed_run_id = v9_test_run_id(&provenance, &changed);
        assert_ne!(
            changed_run_id, baseline_run_id,
            "mutating the V9 {claim} claim must change the noncircular pair run ID"
        );
        let mut forged = changed;
        forged.invocation.run_id_sha256 = baseline_run_id.clone();
        assert_ne!(
            v9_test_run_id(&provenance, &forged),
            forged.invocation.run_id_sha256,
            "a changed V9 {claim} claim cannot retain a previously issued run ID"
        );
    }
}

#[test]
fn v1_v9_generation_cross_equality_rejects_a_recomputed_v4_contradiction() {
    let provenance = v9_test_release_provenance();
    let mut v9 = v9_test_claims(&provenance);
    v9.invocation.run_id_sha256 = v9_test_run_id(&provenance, &v9);
    assert!(
        v9.to_canonical_json().is_ok(),
        "the baseline V9 process-generation claim is independently valid"
    );
    v1_v9_release_gate_process_generations_agree(
        4,
        v9.process_ledger.release_gate_process_generations,
    )
    .expect("the matching V1 resource-generation cardinality is accepted");

    let mut contradictory = v9.clone();
    contradictory
        .process_ledger
        .release_gate_process_generations = 5;
    contradictory.invocation.run_id_sha256 = v9_test_run_id(&provenance, &contradictory);
    assert!(
        contradictory.to_canonical_json().is_ok(),
        "the changed V9 generation count remains structurally and semantically valid"
    );
    assert_ne!(
        contradictory.invocation.run_id_sha256, v9.invocation.run_id_sha256,
        "the V4 claims preimage correctly changes the pair run ID"
    );
    assert!(
        v1_v9_release_gate_process_generations_agree(
            4,
            contradictory.process_ledger.release_gate_process_generations,
        )
        .is_err(),
        "the pair validator rejects a run-ID-recomputed V9 count that contradicts V1 resource_generations"
    );
}

#[test]
fn v9_runtime_digest_binding_rejects_sha_shaped_mirrors_and_replacements() {
    let expected = format!("sha256:{}", "a".repeat(64));
    let mirrored = format!("sha256:{}", "b".repeat(64));
    assert!(v9_require_runtime_digest("child", &expected, &mirrored).is_err());

    let workspace = tempfile::tempdir().expect("create artifact replacement workspace");
    let child = workspace.path().join("quorum-node");
    let harness = workspace.path().join("qualification-harness");
    fs::write(&child, b"child-before").expect("write child before replacement");
    fs::write(&harness, b"harness-before").expect("write harness before replacement");
    let child_before = candidate_sha256_file(&child, 1024).expect("hash child before replacement");
    let harness_before =
        candidate_sha256_file(&harness, 1024).expect("hash harness before replacement");
    fs::write(&child, b"child-after").expect("replace child before publication");
    fs::write(&harness, b"harness-after").expect("replace harness before publication");
    let child_after = candidate_sha256_file(&child, 1024).expect("hash child after replacement");
    let harness_after =
        candidate_sha256_file(&harness, 1024).expect("hash harness after replacement");
    assert!(v9_require_runtime_digest("child", &child_before, &child_after).is_err());
    assert!(v9_require_runtime_digest("harness", &harness_before, &harness_after).is_err());
}

#[test]
fn v9_postrename_directory_sync_failure_retains_the_complete_pair() {
    let workspace = tempfile::tempdir().expect("create V9 post-rename workspace");
    let root = workspace.path().join("evidence");
    fs::create_dir(&root).expect("create dedicated external evidence root");
    fs::set_permissions(&root, Permissions::from_mode(0o700))
        .expect("make external evidence root owner private");
    let root_fd = v9_open_private_external_root(&root).expect("open private root without links");
    let result = publish_v9_pair_files_at_with_directory_sync(
        &root_fd,
        b"canonical-v1",
        b"canonical-v9",
        |_| Err(io::Error::other("injected directory sync failure")),
    );
    assert!(result.is_err());
    let published = root.join("session-ha-persistent-consumer-v9");
    assert_eq!(
        fs::read(published.join("batch-release-gate-v1.json")).expect("retain V1 after rename"),
        b"canonical-v1"
    );
    assert_eq!(
        fs::read(published.join("persistent-consumer-v9.json")).expect("retain V9 after rename"),
        b"canonical-v9"
    );
}

#[test]
fn v9_prerename_revalidation_failure_removes_the_staged_pair() {
    let workspace = tempfile::tempdir().expect("create V9 pre-rename workspace");
    let root = workspace.path().join("evidence");
    fs::create_dir(&root).expect("create dedicated external evidence root");
    fs::set_permissions(&root, Permissions::from_mode(0o700))
        .expect("make external evidence root owner private");
    let root_fd = v9_open_private_external_root(&root).expect("open private root without links");
    let result = publish_v9_pair_files_at_with_pre_rename(
        &root_fd,
        b"canonical-v1",
        b"canonical-v9",
        |directory| fsync(directory).map_err(Into::into),
        || Err(io::Error::other("injected final binding replacement")),
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read_dir(&root).expect("inspect private root").count(),
        0,
        "a final pre-rename binding failure must not leave a partial artifact"
    );
}

#[test]
fn release_gate_porcelain_cleanliness_rejects_staged_untracked_ignored_and_submodule_dirt() {
    let repository = tempfile::tempdir().expect("create release provenance repository");
    let run_git = |directory: &Path, arguments: &[&str]| {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(directory)
            .status()
            .expect("run release provenance git command");
        assert!(status.success(), "release provenance git command failed");
    };
    run_git(repository.path(), &["init", "--quiet"]);
    fs::write(repository.path().join("tracked.txt"), b"tracked\n")
        .expect("write tracked release input");
    fs::write(repository.path().join(".gitignore"), b"ignored-artifact\n")
        .expect("write release ignore fixture");
    run_git(repository.path(), &["add", "."]);
    run_git(
        repository.path(),
        &[
            "-c",
            "user.name=Qualification Test",
            "-c",
            "user.email=qualification@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test fixture",
        ],
    );
    assert!(release_gate_require_clean_source_at(repository.path()).is_ok());

    fs::write(repository.path().join("tracked.txt"), b"staged\n")
        .expect("write staged release input");
    run_git(repository.path(), &["add", "tracked.txt"]);
    assert!(release_gate_require_clean_source_at(repository.path()).is_err());
    fs::write(repository.path().join("tracked.txt"), b"tracked\n")
        .expect("restore staged release input");
    run_git(repository.path(), &["add", "tracked.txt"]);

    fs::write(repository.path().join("tracked.txt"), b"unstaged\n")
        .expect("write unstaged release input");
    assert!(
        release_gate_require_clean_source_at(repository.path()).is_err(),
        "porcelain -z must reject unstaged tracked modifications too"
    );
    fs::write(repository.path().join("tracked.txt"), b"tracked\n")
        .expect("restore unstaged release input");

    fs::write(repository.path().join("untracked-artifact"), b"untracked\n")
        .expect("write untracked release artifact");
    assert!(release_gate_require_clean_source_at(repository.path()).is_err());
    fs::remove_file(repository.path().join("untracked-artifact"))
        .expect("remove test-only untracked release artifact");
    fs::write(repository.path().join("ignored-artifact"), b"ignored\n")
        .expect("write ignored release artifact");
    assert!(release_gate_require_clean_source_at(repository.path()).is_err());
    fs::remove_file(repository.path().join("ignored-artifact"))
        .expect("remove test-only ignored release artifact");

    let submodule = tempfile::tempdir().expect("create submodule repository");
    run_git(submodule.path(), &["init", "--quiet"]);
    fs::write(submodule.path().join("child.txt"), b"child\n").expect("write submodule input");
    run_git(submodule.path(), &["add", "child.txt"]);
    run_git(
        submodule.path(),
        &[
            "-c",
            "user.name=Qualification Test",
            "-c",
            "user.email=qualification@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "submodule fixture",
        ],
    );
    let submodule_path = submodule.path().to_str().expect("UTF-8 submodule path");
    run_git(
        repository.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            submodule_path,
            "nested",
        ],
    );
    run_git(repository.path(), &["add", ".gitmodules", "nested"]);
    run_git(
        repository.path(),
        &[
            "-c",
            "user.name=Qualification Test",
            "-c",
            "user.email=qualification@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "add submodule",
        ],
    );
    assert!(release_gate_require_clean_source_at(repository.path()).is_ok());
    fs::write(repository.path().join("nested/child.txt"), b"dirty child\n")
        .expect("dirty nested submodule");
    assert!(release_gate_require_clean_source_at(repository.path()).is_err());
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

fn stateless_consumer_identity(index: usize) -> String {
    format!(
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/session-consumer/nf/test/instance/{index}"
    )
}

/// A real projected-mTLS workload identity in a different tenant namespace.
/// It is intentionally absent from the listener's authorization grants.
fn protected_foreign_tenant_identity() -> String {
    "spiffe://qualification.invalid/tenant/foreign/ns/test/sa/session-consumer/nf/test/instance/0"
        .to_owned()
}

fn stateless_consumer_key(index: usize) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("qualification-consumer").expect("qualification consumer tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("opaque-consumer-session-{index}"))
            .try_into()
            .expect("bounded opaque consumer session key"),
    }
}

fn qualification_fenced_transition_key(index: usize) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("session-ha-qualification")
            .expect("qualification fenced-transition tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("opaque-fenced-transition-{index}"))
            .try_into()
            .expect("bounded opaque fenced-transition key"),
    }
}

async fn qualification_fenced_transition_record(
    member_count: usize,
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    payload: &'static [u8],
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("qualification-fenced-transition"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload),
    };
    seal_qualification_consensus_record(member_count, &mut record).await;
    record
}

async fn seal_qualification_consensus_record(
    member_count: usize,
    record: &mut StoredSessionRecord,
) {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("session-ha-qualification-key-v1").expect("qualification consensus key ID"),
            KeyPurpose::Session,
            record.key.tenant.clone(),
            Zeroizing::new([0x5a; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("install qualification consensus key");
    record.payload = EncryptedSessionPayload::encrypt(
        &provider,
        record,
        &format!("qualification-mtls-{member_count}-cluster"),
    )
    .await
    .expect("seal opaque qualification consensus payload");
}

async fn qualification_fenced_transition_v2_request(
    member_count: usize,
    index: usize,
) -> FencedTransitionV2Request {
    let key = qualification_fenced_transition_key(index);
    let owner = OwnerId::new(format!("qualification-v2-owner-{index}"))
        .expect("qualification V2 transition owner");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(30),
    )
    .expect("build qualification V2 acquire action");
    let record = qualification_fenced_transition_record(
        member_count,
        key,
        owner,
        lease
            .committed_fence()
            .expect("derive qualification V2 committed fence"),
        match index {
            0 => b"opaque-qualification-v2-transition-one",
            1 => b"opaque-qualification-v2-transition-two",
            _ => b"opaque-qualification-v2-transition-three",
        },
    )
    .await;
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("initial qualification V2 epoch"),
        FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes()),
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("build self-authenticating qualification V2 request")
}

const V2_BATCH_RELEASE_GATE_CLIENTS: usize = 12;
const V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT: usize = 4;
const V2_BATCH_RELEASE_GATE_PENDING_CALLS: usize = 64;
const V2_BATCH_RELEASE_GATE_OVER_CAPACITY_CALLS: usize =
    V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT + V2_BATCH_RELEASE_GATE_PENDING_CALLS + 1;
const V2_BATCH_RELEASE_GATE_PRELOAD_BATCH_SIZE: usize = 256;
const V2_BATCH_RELEASE_GATE_PRELOAD_CONCURRENCY: usize = 1;
const V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE: usize = 12;

/// Causal facts emitted by the full release-gate run.  The canonical V1 bytes
/// are retained verbatim so a later envelope binds the exact durable artifact,
/// rather than reconstructing claims from a lossy JSON value.
struct BatchReleaseGateRunFacts {
    canonical_v1: Vec<u8>,
    release_provenance: ReleaseGateProvenance,
    capacity_reclaimed: bool,
    old_credential_rejected: bool,
    new_credential_rejected: bool,
    process_generations: usize,
    durable_status_cardinality: usize,
    post_outcome_unknown_mutation_dispatches: usize,
}
const V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY: usize =
    V2_BATCH_RELEASE_GATE_CLIENTS * V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT;
const V2_BATCH_RELEASE_GATE_PRELOAD_CREATES: usize = 50_000;
const V2_BATCH_RELEASE_GATE_PACED_MUTATIONS: usize = 60_000;
const V2_BATCH_RELEASE_GATE_MUTATIONS_PER_SECOND: usize = 1_000;
const V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES: usize = 1_008;
const V2_BATCH_RELEASE_GATE_P99: Duration = Duration::from_millis(25);
const V2_BATCH_RELEASE_GATE_P999: Duration = Duration::from_millis(100);
const V2_BATCH_RELEASE_GATE_AMBIGUITY_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// All status-only reads for one ambiguous batch share this finite budget.
/// This prevents a fast NotFound/Unavailable peer from spinning until an
/// inner transport deadline happens to expire.
const V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_ATTEMPT_LIMIT: usize = 64;
const V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_RETRY_BACKOFF: Duration = Duration::from_millis(10);
const V2_BATCH_RELEASE_GATE_NOT_TRANSMITTED_RETRY_LIMIT: usize = 16;
const V2_BATCH_RELEASE_GATE_HOLD_ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// Deliberately shorter than the normal ten-second client operation bound.
/// It is used only to causally expire one response after server durability;
/// the immutable family deadline remains the existing 30-second bound.
const V2_BATCH_RELEASE_GATE_CAUSAL_AMBIGUITY_OPERATION_TIMEOUT: Duration =
    Duration::from_millis(250);

fn assert_v2_batch_release_profile() {
    let cargo_profile = env!("OPC_SESSION_TESTKIT_CARGO_PROFILE_FAMILY");
    let opt_level = env!("OPC_SESSION_TESTKIT_CARGO_OPT_LEVEL");
    ensure_v2_batch_release_feature_profile()
        .expect("the V2 batch release gate requires a production feature profile");
    println!(
        "V2_BATCH_RELEASE_GATE_PROFILE profile={cargo_profile:?} opt_level={opt_level:?} debug_assertions={} foundation_insecure={}",
        cfg!(debug_assertions),
        cfg!(feature = "foundation-insecure"),
    );
    assert_eq!(
        cargo_profile, "release",
        "the V2 batch release gate requires Cargo's release profile"
    );
    assert_eq!(
        opt_level, "3",
        "the V2 batch release gate requires Cargo release opt-level 3"
    );
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "the V2 batch release gate requires debug assertions disabled"
    );
}

fn qualification_v2_batch_percentile(
    samples: &mut [Duration],
    numerator: usize,
    denominator: usize,
) -> Duration {
    assert!(!samples.is_empty(), "latency sample set is nonempty");
    assert!(numerator > 0 && numerator <= denominator);
    samples.sort_unstable();
    let rank = samples
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1);
    samples[rank]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualificationV2BatchSampleFailure {
    InvalidSuccessResponse,
    TypedStoreError,
    TypedOutcomeUnknown,
    UnexpectedTypedError,
    MismatchedResponse,
    NotTransmittedRetryExhausted,
    UnexpectedTransportError,
}

fn qualification_checked_elapsed(
    completed_at: Instant,
    scheduled_at: Instant,
) -> Result<Duration, QualificationV2BatchSampleFailure> {
    completed_at
        .checked_duration_since(scheduled_at)
        .ok_or(QualificationV2BatchSampleFailure::UnexpectedTransportError)
}

#[test]
fn v2_batch_elapsed_rejects_causal_clock_inversion() {
    let completed = Instant::now();
    let scheduled = completed
        .checked_add(Duration::from_millis(1))
        .expect("fixed inversion offset is representable");
    assert_eq!(
        qualification_checked_elapsed(completed, scheduled),
        Err(QualificationV2BatchSampleFailure::UnexpectedTransportError)
    );
}

fn qualification_assert_v2_batch_response(
    requests: &[FencedTransitionV2Request],
    response: SessionConsumerV2Response,
) -> Result<(), QualificationV2BatchSampleFailure> {
    match response {
        SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results)) => {
            if results.len() != requests.len() {
                return Err(QualificationV2BatchSampleFailure::InvalidSuccessResponse);
            }
            let encoded =
                opc_consensus::encode_bounded(&results).map_err(|_| QualificationV2BatchSampleFailure::InvalidSuccessResponse)?;
            if encoded.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES {
                return Err(QualificationV2BatchSampleFailure::InvalidSuccessResponse);
            }
            for (request, result) in requests.iter().zip(results) {
                if result.request_id() != request.request_id()
                    || !result
                        .result()
                        .as_ref()
                        .is_ok_and(|outcome| outcome.matches_v2_request(request))
                {
                    return Err(QualificationV2BatchSampleFailure::InvalidSuccessResponse);
                }
            }
            Ok(())
        }
        SessionConsumerV2Response::FencedTransitionV2Batch(Err(error)) => match error {
            opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::Store(
                _,
            ) => Err(QualificationV2BatchSampleFailure::TypedStoreError),
            opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::OutcomeUnknown {
                ..
            } => Err(QualificationV2BatchSampleFailure::TypedOutcomeUnknown),
            _ => Err(QualificationV2BatchSampleFailure::UnexpectedTypedError),
        },
        _ => Err(QualificationV2BatchSampleFailure::MismatchedResponse),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2BatchMutationResolution {
    Recorded,
    NotTransmitted(SessionConsumerClientError),
    OutcomeUnknown,
}

/// A redispatch is permitted only when the exact pre-write cause is the
/// backend-unavailable classification.  All other typed failures remain
/// terminal evidence for this bounded qualification dispatcher.
const fn qualification_v2_batch_retryable_prewrite_cause(
    cause: SessionConsumerClientError,
) -> bool {
    matches!(cause, SessionConsumerClientError::Unavailable)
}

/// Full qualification batch policy with injected transport seams. Production
/// and the paused causal regression both use this exact dispatcher, so the
/// test proves the dispatch-to-status boundary rather than a disconnected
/// counter model.
async fn qualification_execute_v2_batch_sample_with<M, MF, S, SF>(
    request_count: usize,
    scheduled_at: Instant,
    deadline: tokio::time::Instant,
    mut mutation: M,
    status: S,
) -> Result<(Duration, bool, usize, V2BatchStatusRetryCounts), QualificationV2BatchSampleFailure>
where
    M: FnMut() -> MF,
    MF: std::future::Future<
        Output = Result<V2BatchMutationResolution, QualificationV2BatchSampleFailure>,
    >,
    S: FnMut(usize) -> SF,
    SF: std::future::Future<
        Output = Result<V2BatchStatusResolution, QualificationV2BatchSampleFailure>,
    >,
{
    assert!(
        (1..=MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS).contains(&request_count),
        "release-gate batch remains within the protocol operation bound"
    );
    let mut not_transmitted_retries = 0usize;
    let recovered_unknown = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted);
        }
        let outcome = tokio::time::timeout_at(deadline, mutation())
            .await
            .map_err(|_| QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted)?;
        match outcome {
            Ok(V2BatchMutationResolution::Recorded) => break false,
            Ok(V2BatchMutationResolution::NotTransmitted(cause))
                if qualification_v2_batch_retryable_prewrite_cause(cause) =>
            {
                if not_transmitted_retries >= V2_BATCH_RELEASE_GATE_NOT_TRANSMITTED_RETRY_LIMIT {
                    return Err(QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted);
                }
                not_transmitted_retries += 1;
                tokio::time::sleep_until(
                    tokio::time::Instant::now()
                        .checked_add(V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_RETRY_BACKOFF)
                        .expect("fixed mutation retry backoff is representable")
                        .min(deadline),
                )
                .await;
            }
            Ok(V2BatchMutationResolution::NotTransmitted(_)) => {
                return Err(QualificationV2BatchSampleFailure::UnexpectedTransportError);
            }
            Ok(V2BatchMutationResolution::OutcomeUnknown) => break true,
            Err(error) => return Err(error),
        }
    };
    let status_retries = if recovered_unknown {
        qualification_resolve_v2_batch_outcome_unknown_with(request_count, deadline, status, None)
            .await?
    } else {
        V2BatchStatusRetryCounts::default()
    };
    let completed_at = Instant::now();
    // A status sample whose completion precedes its scheduling point is a
    // causal inversion, not a zero-duration success.  Reuse the same
    // fail-closed conversion covered by the regression below.
    let elapsed = qualification_checked_elapsed(completed_at, scheduled_at)?;
    Ok((
        elapsed,
        recovered_unknown,
        not_transmitted_retries,
        status_retries,
    ))
}

async fn qualification_execute_v2_batch_sample(
    client: PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    requests: Vec<FencedTransitionV2Request>,
    scheduled_at: Instant,
) -> Result<(Duration, bool, usize, V2BatchStatusRetryCounts), QualificationV2BatchSampleFailure> {
    let encoded = opc_consensus::encode_bounded(&requests).expect("bounded V2 batch encodes");
    assert!(
        encoded.len() <= MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES,
        "V2 batch stays below its fixed consumer/consensus request cap"
    );
    let deadline = tokio::time::Instant::now() + V2_BATCH_RELEASE_GATE_AMBIGUITY_RECOVERY_TIMEOUT;
    let mutation_request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Batch {
            requests: requests.clone(),
        },
    );
    qualification_execute_v2_batch_sample_with(
        requests.len(),
        scheduled_at,
        deadline,
        {
            let client = client.clone();
            let requests = requests.clone();
            move || {
                let client = client.clone();
                let request = mutation_request.clone();
                let requests = requests.clone();
                async move {
                    match client.execute_v2(&request).await {
                        Ok(response) => {
                            qualification_assert_v2_batch_response(&requests, response)?;
                            Ok(V2BatchMutationResolution::Recorded)
                        }
                        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause }) => {
                            Ok(V2BatchMutationResolution::NotTransmitted(cause))
                        }
                        Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch {
                            request_ids,
                        }) if request_ids
                            == requests
                                .iter()
                                .map(FencedTransitionV2Request::request_id)
                                .collect::<Vec<_>>() =>
                        {
                            Ok(V2BatchMutationResolution::OutcomeUnknown)
                        }
                        Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch {
                            ..
                        }) => Err(QualificationV2BatchSampleFailure::UnexpectedTransportError),
                        Err(_) => Err(QualificationV2BatchSampleFailure::UnexpectedTransportError),
                    }
                }
            }
        },
        {
            let client = client.clone();
            let requests = requests.clone();
            move |index| {
                let client = client.clone();
                let transition = requests[index].clone();
                async move {
                    let status_request = SessionConsumerV2Request::new(
                        scope,
                        SessionConsumerV2Operation::FencedTransitionV2Status {
                            request: Box::new(transition.clone()),
                        },
                    );
                    match client.execute_v2(&status_request).await {
                        Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                            SessionConsumerV2FencedTransitionStatus::Recorded(result),
                        ))) if result
                            .as_ref()
                            .as_ref()
                            .is_ok_and(|outcome| outcome.matches_v2_request(&transition)) =>
                        {
                            Ok(V2BatchStatusResolution::Terminal)
                        }
                        Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                            SessionConsumerV2FencedTransitionStatus::NotFound,
                        ))) => Ok(V2BatchStatusResolution::Retry(
                            V2BatchStatusRetryCause::NotFound,
                        )),
                        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                            cause: SessionConsumerClientError::Unavailable,
                        }) => Ok(V2BatchStatusResolution::Retry(
                            V2BatchStatusRetryCause::NotTransmitted,
                        )),
                        Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
                            cause: SessionConsumerClientError::Unavailable,
                        }) => Ok(V2BatchStatusResolution::Retry(
                            V2BatchStatusRetryCause::ReadUnavailable,
                        )),
                        Ok(response)
                            if qualification_v2_batch_status_is_retryable_unavailable(
                                &response,
                            ) =>
                        {
                            Ok(V2BatchStatusResolution::Retry(
                                V2BatchStatusRetryCause::TypedUnavailable,
                            ))
                        }
                        _ => Err(QualificationV2BatchSampleFailure::UnexpectedTransportError),
                    }
                }
            }
        },
    )
    .await
}

/// Bounded, status-only ambiguity retry accounting.  The total is retained
/// alongside each independently observable retry cause so evidence cannot
/// relabel status recovery as a client transport queue measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct V2BatchStatusRetryCounts {
    attempts_total: usize,
    terminal_attempts: usize,
    total: usize,
    not_found: usize,
    not_transmitted: usize,
    read_unavailable: usize,
    typed_unavailable: usize,
}

impl V2BatchStatusRetryCounts {
    fn record_attempt(&mut self) {
        self.attempts_total = self
            .attempts_total
            .checked_add(1)
            .expect("bounded status attempt counter fits usize");
    }

    fn record_terminal(&mut self) {
        self.terminal_attempts = self
            .terminal_attempts
            .checked_add(1)
            .expect("bounded terminal status counter fits usize");
    }

    fn record(&mut self, cause: V2BatchStatusRetryCause) {
        self.total = self
            .total
            .checked_add(1)
            .expect("bounded status retry counter fits usize");
        match cause {
            V2BatchStatusRetryCause::NotFound => {
                self.not_found = self
                    .not_found
                    .checked_add(1)
                    .expect("bounded not-found status counter fits usize")
            }
            V2BatchStatusRetryCause::NotTransmitted => {
                self.not_transmitted = self
                    .not_transmitted
                    .checked_add(1)
                    .expect("bounded not-transmitted status counter fits usize")
            }
            V2BatchStatusRetryCause::ReadUnavailable => {
                self.read_unavailable = self
                    .read_unavailable
                    .checked_add(1)
                    .expect("bounded unavailable-read status counter fits usize")
            }
            V2BatchStatusRetryCause::TypedUnavailable => {
                self.typed_unavailable = self
                    .typed_unavailable
                    .checked_add(1)
                    .expect("bounded typed-unavailable status counter fits usize")
            }
        }
    }

    fn accumulate(&mut self, other: Self) {
        self.attempts_total = self
            .attempts_total
            .checked_add(other.attempts_total)
            .expect("bounded aggregate status attempts fit usize");
        self.terminal_attempts = self
            .terminal_attempts
            .checked_add(other.terminal_attempts)
            .expect("bounded aggregate terminal status attempts fit usize");
        self.total = self
            .total
            .checked_add(other.total)
            .expect("bounded aggregate status retries fit usize");
        self.not_found = self
            .not_found
            .checked_add(other.not_found)
            .expect("bounded aggregate not-found status retries fit usize");
        self.not_transmitted = self
            .not_transmitted
            .checked_add(other.not_transmitted)
            .expect("bounded aggregate not-transmitted status retries fit usize");
        self.read_unavailable = self
            .read_unavailable
            .checked_add(other.read_unavailable)
            .expect("bounded aggregate unavailable-read status retries fit usize");
        self.typed_unavailable = self
            .typed_unavailable
            .checked_add(other.typed_unavailable)
            .expect("bounded aggregate typed-unavailable status retries fit usize");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2BatchStatusRetryCause {
    NotFound,
    NotTransmitted,
    ReadUnavailable,
    TypedUnavailable,
}

/// The release gate retains its caller-owned IDs through every effect boundary.
/// This deliberately records per-ID attempts rather than inferring retries from
/// an aggregate pool counter: an OutcomeUnknown ID may only be read afterward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2BatchMutationTerminal {
    NotTransmitted(SessionConsumerClientError),
    OutcomeUnknown,
}

#[derive(Debug, Clone)]
struct V2BatchAttemptLedgerEntry {
    request_id: FencedTransitionV2RequestId,
    mutation_attempts: usize,
    effect_accepted: bool,
    mutation_terminal: Option<V2BatchMutationTerminal>,
    status_attempts: usize,
    status_terminal: bool,
}

/// Bounded exactly by the wire batch cardinality. A caller can neither add an
/// unobserved ID nor silently replay an ambiguous one.
#[derive(Debug, Clone)]
struct V2BatchAttemptLedger {
    entries: Vec<V2BatchAttemptLedgerEntry>,
}

impl V2BatchAttemptLedger {
    fn new(requests: &[FencedTransitionV2Request]) -> Self {
        assert!(
            (1..=MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS).contains(&requests.len()),
            "the per-ID ledger is bounded by one protocol batch"
        );
        let entries = requests
            .iter()
            .map(|request| V2BatchAttemptLedgerEntry {
                request_id: request.request_id(),
                mutation_attempts: 0,
                effect_accepted: false,
                mutation_terminal: None,
                status_attempts: 0,
                status_terminal: false,
            })
            .collect::<Vec<_>>();
        assert!(
            entries
                .iter()
                .enumerate()
                .all(|(index, entry)| entries[..index]
                    .iter()
                    .all(|previous| previous.request_id != entry.request_id)),
            "a batch ledger rejects duplicate caller-owned IDs"
        );
        Self { entries }
    }

    fn record_mutation_dispatch(&mut self) {
        for entry in &mut self.entries {
            assert!(
                !matches!(
                    entry.mutation_terminal,
                    Some(V2BatchMutationTerminal::OutcomeUnknown)
                ),
                "an OutcomeUnknown ID is status-only and can never redispatch"
            );
            entry.mutation_attempts = entry
                .mutation_attempts
                .checked_add(1)
                .expect("bounded per-ID mutation attempts fit usize");
        }
    }

    fn record_mutation_terminal(&mut self, terminal: V2BatchMutationTerminal) {
        for entry in &mut self.entries {
            assert!(
                entry.mutation_attempts > 0,
                "a terminal effect has a dispatch"
            );
            assert!(
                entry.mutation_terminal.is_none(),
                "one terminal classification per ID"
            );
            assert!(
                !matches!(terminal, V2BatchMutationTerminal::OutcomeUnknown)
                    || entry.effect_accepted,
                "OutcomeUnknown follows the observed durable effect boundary"
            );
            entry.mutation_terminal = Some(terminal);
        }
    }

    fn record_durable_acceptance(&mut self) {
        for entry in &mut self.entries {
            assert!(
                entry.mutation_attempts > 0,
                "a durable acceptance has a dispatch"
            );
            assert!(
                entry.mutation_terminal.is_none(),
                "acceptance precedes terminal classification"
            );
            entry.effect_accepted = true;
        }
    }

    fn record_status_attempt(&mut self, request_index: usize) {
        let entry = self
            .entries
            .get_mut(request_index)
            .expect("status index is retained");
        assert!(
            matches!(
                entry.mutation_terminal,
                Some(V2BatchMutationTerminal::OutcomeUnknown)
            ),
            "only OutcomeUnknown IDs enter the status-only recovery seam"
        );
        entry.status_attempts = entry
            .status_attempts
            .checked_add(1)
            .expect("bounded per-ID status attempts fit usize");
    }

    fn record_status_terminal(&mut self, request_index: usize) {
        let entry = self
            .entries
            .get_mut(request_index)
            .expect("status index is retained");
        assert!(
            entry.status_attempts > 0,
            "terminal status follows a retained-ID read"
        );
        entry.status_terminal = true;
    }

    fn outcome_unknown_cardinality(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.mutation_terminal,
                    Some(V2BatchMutationTerminal::OutcomeUnknown)
                )
            })
            .count()
    }

    fn post_outcome_unknown_mutation_dispatches(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.mutation_terminal,
                    Some(V2BatchMutationTerminal::OutcomeUnknown)
                ) && entry.mutation_attempts > 1
            })
            .count()
    }

    fn recovered_outcome_unknown_families(&self) -> usize {
        usize::from(
            self.outcome_unknown_cardinality() > 0
                && self
                    .entries
                    .iter()
                    .filter(|entry| {
                        matches!(
                            entry.mutation_terminal,
                            Some(V2BatchMutationTerminal::OutcomeUnknown)
                        )
                    })
                    .all(|entry| entry.status_terminal),
        )
    }

    fn actual_redispatches(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| {
                entry
                    .mutation_attempts
                    .checked_sub(1)
                    .expect("a ledger terminal always follows an initial dispatch")
            })
            .max()
            .unwrap_or(0)
    }
}

#[tokio::test]
async fn v2_batch_attempt_ledger_conserves_twelve_ambiguous_ids_and_rejects_replay() {
    let requests = futures_util::future::join_all(
        (0..V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE)
            .map(|index| qualification_fenced_transition_v2_request(3, index)),
    )
    .await;
    let mut ambiguous = V2BatchAttemptLedger::new(&requests);
    ambiguous.record_mutation_dispatch();
    ambiguous.record_durable_acceptance();
    ambiguous.record_mutation_terminal(V2BatchMutationTerminal::OutcomeUnknown);
    let deadline = tokio::time::Instant::now() + V2_BATCH_RELEASE_GATE_AMBIGUITY_RECOVERY_TIMEOUT;
    let status_counts = qualification_resolve_v2_batch_outcome_unknown_with(
        requests.len(),
        deadline,
        |_| async { Ok(V2BatchStatusResolution::Terminal) },
        Some(&mut ambiguous),
    )
    .await
    .expect("the retained IDs resolve through the real status-only seam");
    assert_eq!(status_counts.attempts_total, 12);
    assert_eq!(status_counts.terminal_attempts, 12);
    assert_eq!(ambiguous.outcome_unknown_cardinality(), 12);
    assert_eq!(ambiguous.post_outcome_unknown_mutation_dispatches(), 0);
    assert_eq!(ambiguous.recovered_outcome_unknown_families(), 1);
    assert_eq!(ambiguous.actual_redispatches(), 0);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ambiguous.record_mutation_dispatch();
        }))
        .is_err(),
        "an ambiguous retained ID must never re-enter the mutation dispatcher"
    );

    let mut overload = V2BatchAttemptLedger::new(&requests);
    overload.record_mutation_dispatch();
    overload.record_mutation_terminal(V2BatchMutationTerminal::NotTransmitted(
        SessionConsumerClientError::Overloaded,
    ));
    assert_eq!(overload.actual_redispatches(), 0);
    assert!(overload
        .entries
        .iter()
        .all(|entry| entry.mutation_attempts == 1));
}

/// One immutable recovery family shared by the initial mutation dispatch,
/// every proven-not-transmitted retry, and all status-only recovery work.
/// The status cap is deliberately aggregate rather than per retained ID.
#[derive(Debug, Clone, Copy)]
struct V2BatchAmbiguityBudget {
    deadline: tokio::time::Instant,
    status_attempts: usize,
}

impl V2BatchAmbiguityBudget {
    fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            status_attempts: 0,
        }
    }

    fn take_status_attempt(&mut self) -> bool {
        if self.status_attempts >= V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_ATTEMPT_LIMIT {
            return false;
        }
        self.status_attempts += 1;
        true
    }

    fn clipped_retry_at(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
            .checked_add(V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_RETRY_BACKOFF)
            .expect("fixed status retry backoff is representable")
            .min(self.deadline)
    }
}

#[tokio::test(start_paused = true)]
async fn v2_batch_ambiguity_recovery_uses_one_real_aggregate_budget_and_deadline() {
    use std::sync::atomic::AtomicUsize;

    let deadline = tokio::time::Instant::now() + V2_BATCH_RELEASE_GATE_AMBIGUITY_RECOVERY_TIMEOUT;
    // Model the one allowed proven-not-transmitted replay before the transport
    // reports OutcomeUnknownBatch. The injected status seam below is the same
    // helper production uses; it must never dispatch another mutation.
    let mutation_dispatches = Arc::new(AtomicUsize::new(1));
    tokio::time::sleep_until(
        tokio::time::Instant::now()
            .checked_add(V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_RETRY_BACKOFF)
            .expect("fixed retry backoff is representable")
            .min(deadline),
    )
    .await;
    mutation_dispatches.fetch_add(1, Ordering::SeqCst);
    let status_calls = Arc::new(AtomicUsize::new(0));
    let calls_per_id = Arc::new(Mutex::new(vec![0usize; 12]));
    let causes = [
        V2BatchStatusRetryCause::NotFound,
        V2BatchStatusRetryCause::NotTransmitted,
        V2BatchStatusRetryCause::ReadUnavailable,
        V2BatchStatusRetryCause::TypedUnavailable,
    ];
    let counts = qualification_resolve_v2_batch_outcome_unknown_with(
        12,
        deadline,
        {
            let status_calls = Arc::clone(&status_calls);
            let calls_per_id = Arc::clone(&calls_per_id);
            move |request_index| {
                let status_calls = Arc::clone(&status_calls);
                let calls_per_id = Arc::clone(&calls_per_id);
                async move {
                    status_calls.fetch_add(1, Ordering::SeqCst);
                    let attempt = {
                        let mut attempts = calls_per_id.lock().expect("script lock");
                        let attempt = attempts[request_index];
                        attempts[request_index] = attempt.saturating_add(1);
                        attempt
                    };
                    // Four IDs consume five retry causes and the other eight four;
                    // together with twelve terminal reads this is exactly 64.
                    let retries_before_terminal = if request_index < 4 { 5 } else { 4 };
                    Ok(if attempt < retries_before_terminal {
                        V2BatchStatusResolution::Retry(
                            causes[(request_index + attempt) % causes.len()],
                        )
                    } else {
                        V2BatchStatusResolution::Terminal
                    })
                }
            }
        },
        None,
    )
    .await
    .expect("scripted terminal receipt reads fit the one aggregate budget");
    assert_eq!(
        counts.attempts_total,
        V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_ATTEMPT_LIMIT
    );
    assert_eq!(
        counts.total + counts.terminal_attempts,
        counts.attempts_total
    );
    assert_eq!(counts.terminal_attempts, 12);
    assert_eq!(
        counts.not_found
            + counts.not_transmitted
            + counts.read_unavailable
            + counts.typed_unavailable,
        counts.total
    );
    assert!(counts.not_found > 0 && counts.not_transmitted > 0);
    assert!(counts.read_unavailable > 0 && counts.typed_unavailable > 0);
    assert_eq!(status_calls.load(Ordering::SeqCst), 64);
    assert_eq!(
        mutation_dispatches.load(Ordering::SeqCst),
        2,
        "after OutcomeUnknownBatch, recovery is status-only and cannot redispatch"
    );
    assert!(tokio::time::Instant::now() <= deadline);

    let expiry = tokio::time::Instant::now() + V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_RETRY_BACKOFF;
    let expiry_calls = Arc::new(AtomicUsize::new(0));
    let expired = qualification_resolve_v2_batch_outcome_unknown_with(
        12,
        expiry,
        {
            let expiry_calls = Arc::clone(&expiry_calls);
            move |_| {
                let expiry_calls = Arc::clone(&expiry_calls);
                async move {
                    expiry_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(V2BatchStatusResolution::Retry(
                        V2BatchStatusRetryCause::NotFound,
                    ))
                }
            }
        },
        None,
    )
    .await;
    assert_eq!(
        expired,
        Err(QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted)
    );
    assert_eq!(expiry_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tokio::time::Instant::now(), expiry);
}

#[tokio::test(start_paused = true)]
async fn v2_batch_sample_causally_recovers_one_expired_durable_response_without_redispatch() {
    use std::sync::atomic::AtomicUsize;

    let family_deadline =
        tokio::time::Instant::now() + V2_BATCH_RELEASE_GATE_AMBIGUITY_RECOVERY_TIMEOUT;
    let trace = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let mutation_dispatches = Arc::new(AtomicUsize::new(0));
    let status_calls = Arc::new(AtomicUsize::new(0));
    let outcome = qualification_execute_v2_batch_sample_with(
        12,
        Instant::now(),
        family_deadline,
        {
            let trace = Arc::clone(&trace);
            let mutation_dispatches = Arc::clone(&mutation_dispatches);
            move || {
                let trace = Arc::clone(&trace);
                let mutation_dispatches = Arc::clone(&mutation_dispatches);
                async move {
                    assert_eq!(mutation_dispatches.fetch_add(1, Ordering::SeqCst), 0);
                    trace.lock().expect("trace lock").push("dispatch");
                    // The server has durably accepted this exact batch, but
                    // its held response outlives the caller operation window.
                    trace.lock().expect("trace lock").push("durable-accept");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    trace.lock().expect("trace lock").push("response-deadline");
                    Ok(V2BatchMutationResolution::OutcomeUnknown)
                }
            }
        },
        {
            let trace = Arc::clone(&trace);
            let status_calls = Arc::clone(&status_calls);
            move |_| {
                let trace = Arc::clone(&trace);
                let status_calls = Arc::clone(&status_calls);
                async move {
                    status_calls.fetch_add(1, Ordering::SeqCst);
                    trace.lock().expect("trace lock").push("terminal-status");
                    Ok(V2BatchStatusResolution::Terminal)
                }
            }
        },
    )
    .await
    .expect("one durable ambiguous family is classified before its retained deadline");
    assert!(
        outcome.1,
        "the caller receives OutcomeUnknown after its deadline"
    );
    assert_eq!(outcome.2, 0, "no proven-not-transmitted replay was needed");
    assert_eq!(outcome.3.attempts_total, 12);
    assert_eq!(outcome.3.terminal_attempts, 12);
    assert_eq!(status_calls.load(Ordering::SeqCst), 12);
    assert_eq!(mutation_dispatches.load(Ordering::SeqCst), 1);
    assert!(tokio::time::Instant::now() < family_deadline);
    let trace = trace.lock().expect("trace lock");
    assert_eq!(
        &trace[..3],
        ["dispatch", "durable-accept", "response-deadline"]
    );
    assert!(trace[3..].iter().all(|event| *event == "terminal-status"));
}

/// A confirmed status response can still report a retryable service outage.
/// It is safe to retry because this operation only reads one caller-retained
/// V2 receipt; all other status outcomes remain exact terminal evidence.
fn qualification_v2_batch_status_is_retryable_unavailable(
    response: &SessionConsumerV2Response,
) -> bool {
    matches!(
        response,
        SessionConsumerV2Response::FencedTransitionV2Status(Err(
            SessionConsumerStoreError::Unavailable
        )) | SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
    )
}

#[test]
fn v2_batch_prewrite_retry_cause_matrix_is_exactly_backend_unavailable() {
    assert!(qualification_v2_batch_retryable_prewrite_cause(
        SessionConsumerClientError::Unavailable
    ));
    for cause in [
        SessionConsumerClientError::Authentication,
        SessionConsumerClientError::Scope,
        SessionConsumerClientError::Protocol,
        SessionConsumerClientError::Unsupported,
        SessionConsumerClientError::Deadline,
        SessionConsumerClientError::Overloaded,
        SessionConsumerClientError::ShuttingDown,
    ] {
        assert!(
            !qualification_v2_batch_retryable_prewrite_cause(cause),
            "only a causal backend unavailable may redispatch: {cause:?}"
        );
    }
}

#[test]
fn v2_batch_ambiguity_status_retries_only_confirmed_unavailable() {
    for transient in [
        SessionConsumerV2Response::FencedTransitionV2Status(Err(
            SessionConsumerStoreError::Unavailable,
        )),
        SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable),
    ] {
        assert!(
            qualification_v2_batch_status_is_retryable_unavailable(&transient),
            "a confirmed V2 status outage is safe to retry without replaying the batch"
        );
    }

    for terminal in [
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::RequestConflict,
        )),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Expired,
        )),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Retired,
        )),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::HistoryFull,
        )),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::EpochNotActive,
        )),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::RetentionExhausted,
        )),
        SessionConsumerV2Response::Rejected(SessionConsumerRejection::ScopeMismatch),
    ] {
        assert!(
            !qualification_v2_batch_status_is_retryable_unavailable(&terminal),
            "only confirmed service unavailability is retryable; exact terminal evidence remains fatal"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2BatchStatusResolution {
    Terminal,
    Retry(V2BatchStatusRetryCause),
}

/// Execute the production status-only recovery policy against an injected
/// status operation. The callback is deliberately the only seam: all timing,
/// aggregate accounting, and backoff remain shared with the real transport
/// recovery below.
async fn qualification_resolve_v2_batch_outcome_unknown_with<F, Fut>(
    request_count: usize,
    deadline: tokio::time::Instant,
    mut status: F,
    mut ledger: Option<&mut V2BatchAttemptLedger>,
) -> Result<V2BatchStatusRetryCounts, QualificationV2BatchSampleFailure>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<
        Output = Result<V2BatchStatusResolution, QualificationV2BatchSampleFailure>,
    >,
{
    let mut status_retries = V2BatchStatusRetryCounts::default();
    let mut budget = V2BatchAmbiguityBudget::new(deadline);
    for request_index in 0..request_count {
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted);
            }
            if !budget.take_status_attempt() {
                return Err(QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted);
            }
            if let Some(ledger) = ledger.as_deref_mut() {
                ledger.record_status_attempt(request_index);
            }
            let resolution = tokio::time::timeout_at(deadline, status(request_index))
                .await
                .map_err(|_| QualificationV2BatchSampleFailure::NotTransmittedRetryExhausted)??;
            status_retries.record_attempt();
            match resolution {
                V2BatchStatusResolution::Terminal => {
                    status_retries.record_terminal();
                    if let Some(ledger) = ledger.as_deref_mut() {
                        ledger.record_status_terminal(request_index);
                    }
                    break;
                }
                V2BatchStatusResolution::Retry(retry_cause) => {
                    status_retries.record(retry_cause);
                    tokio::time::sleep_until(budget.clipped_retry_at()).await;
                }
            }
        }
    }
    Ok(status_retries)
}

async fn qualification_resolve_v2_batch_outcome_unknown(
    client: &PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    requests: &[FencedTransitionV2Request],
    deadline: tokio::time::Instant,
    ledger: &mut V2BatchAttemptLedger,
) -> V2BatchStatusRetryCounts {
    let requests = requests.to_vec();
    let client = client.clone();
    qualification_resolve_v2_batch_outcome_unknown_with(
        requests.len(),
        deadline,
        move |index| {
            let client = client.clone();
            let transition = requests[index].clone();
            async move {
                let status_request = SessionConsumerV2Request::new(
                    scope,
                    SessionConsumerV2Operation::FencedTransitionV2Status {
                        request: Box::new(transition.clone()),
                    },
                );
                match client.execute_v2(&status_request).await {
                    Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                        SessionConsumerV2FencedTransitionStatus::Recorded(result),
                    ))) if result
                        .as_ref()
                        .as_ref()
                        .is_ok_and(|outcome| outcome.matches_v2_request(&transition)) =>
                    {
                        Ok(V2BatchStatusResolution::Terminal)
                    }
                    Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                        SessionConsumerV2FencedTransitionStatus::NotFound,
                    ))) => Ok(V2BatchStatusResolution::Retry(
                        V2BatchStatusRetryCause::NotFound,
                    )),
                    Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                        cause: SessionConsumerClientError::Unavailable,
                    }) => Ok(V2BatchStatusResolution::Retry(
                        V2BatchStatusRetryCause::NotTransmitted,
                    )),
                    Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
                        cause: SessionConsumerClientError::Unavailable,
                    }) => Ok(V2BatchStatusResolution::Retry(
                        V2BatchStatusRetryCause::ReadUnavailable,
                    )),
                    Ok(response)
                        if qualification_v2_batch_status_is_retryable_unavailable(&response) =>
                    {
                        Ok(V2BatchStatusResolution::Retry(
                            V2BatchStatusRetryCause::TypedUnavailable,
                        ))
                    }
                    Ok(_) | Err(_) => {
                        Err(QualificationV2BatchSampleFailure::UnexpectedTransportError)
                    }
                }
            }
        },
        Some(ledger),
    )
    .await
    .expect("ambiguous V2 batch status recovery stays within its immutable aggregate budget")
}

async fn qualification_execute_v2_status_sample(
    client: PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    transition: FencedTransitionV2Request,
    scheduled_at: Instant,
) -> Duration {
    let response = client
        .execute_v2(&SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: Box::new(transition.clone()),
            },
        ))
        .await
        .expect("warm V2 status read has a typed response");
    let completed_at = Instant::now();
    assert!(matches!(
        response,
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(result)
        )) if result.as_ref().as_ref().is_ok_and(|outcome| outcome.matches_v2_request(&transition))
    ));
    completed_at
        .checked_duration_since(scheduled_at)
        .expect("status sample completion cannot precede its scheduled boundary")
}

fn qualification_persistent_v2_client(
    endpoints: Arc<Mutex<Vec<SocketAddr>>>,
    node_index: usize,
    voter_authority: SessionConsumerVoterAuthority,
    identity: IdentityState,
    pool_config: PersistentSessionConsumerConfig,
    operation_timeout: Option<Duration>,
) -> (
    watch::Sender<Option<IdentityState>>,
    PersistentSessionConsumerClient,
) {
    let (identity_sender, identity_receiver) = watch::channel(Some(identity));
    let tls = TlsConfigBuilder::new(identity_receiver)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("bounded V2 seam client mTLS configuration");
    let initial_endpoint = endpoints
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index];
    let resolved_endpoints = Arc::clone(&endpoints);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let endpoint = resolved_endpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index];
        Box::pin(async move { Ok(endpoint) })
    });
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(initial_endpoint.ip().into()),
        voter_authority,
        tls,
    );
    let stateless = match operation_timeout {
        Some(timeout) => stateless.with_operation_timeout(timeout),
        None => stateless,
    };
    (
        identity_sender,
        PersistentSessionConsumerClient::try_from_stateless(stateless, pool_config)
            .expect("bounded persistent V2 seam client"),
    )
}

async fn qualification_assert_v2_active_history(
    client: PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    expected_entries: usize,
) {
    let response = client
        .execute_v2(&SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2HistoryState,
        ))
        .await
        .expect("V2 active history response");
    assert!(matches!(
        response,
        SessionConsumerV2Response::FencedTransitionV2HistoryState(Ok(state))
            if state.active_epoch() == Some(FencedTransitionV2HistoryEpoch::new(1).expect("epoch one"))
                && state.bound_entries() == expected_entries
    ));
}

async fn qualification_build_v2_batches(
    member_count: usize,
    first_index: usize,
    operation_count: usize,
    batch_size: usize,
) -> Vec<Vec<FencedTransitionV2Request>> {
    assert!((1..=MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS).contains(&batch_size));
    let mut batches = Vec::with_capacity(operation_count.div_ceil(batch_size));
    let mut batch = Vec::with_capacity(batch_size);
    for index in first_index..first_index.saturating_add(operation_count) {
        batch.push(qualification_fenced_transition_v2_request(member_count, index).await);
        if batch.len() == batch_size {
            batches.push(std::mem::take(&mut batch));
            batch = Vec::with_capacity(batch_size);
        }
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    batches
}

#[derive(Clone, Copy)]
enum ConsumerQualificationMode {
    Stateless,
    Persistent,
}

impl ConsumerQualificationMode {
    fn name(self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::Persistent => "persistent",
        }
    }
}

#[derive(Debug)]
enum QualificationConsumerClient {
    Stateless(Box<StatelessSessionConsumerClient>),
    Persistent(PersistentSessionConsumerClient),
}

#[derive(Debug)]
enum QualificationConsumerExecuteError {
    Stateless(SessionConsumerClientError),
    Persistent(PersistentSessionConsumerExecuteError),
}

impl QualificationConsumerClient {
    async fn execute(
        &self,
        request: SessionConsumerRequest,
    ) -> Result<SessionConsumerResponse, QualificationConsumerExecuteError> {
        match self {
            Self::Stateless(client) => client
                .execute(request)
                .await
                .map_err(QualificationConsumerExecuteError::Stateless),
            Self::Persistent(client) => client
                .execute(&request)
                .await
                .map_err(QualificationConsumerExecuteError::Persistent),
        }
    }

    async fn capabilities(&self) -> Result<BackendCapabilities, SessionConsumerClientError> {
        match self {
            Self::Stateless(client) => client.capabilities().await,
            Self::Persistent(client) => client.capabilities().await,
        }
    }

    async fn acquire_with_id(
        &self,
        request_id: SessionConsumerRequestId,
        key: SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, SessionConsumerLeaseMutationError> {
        match self {
            Self::Stateless(client) => client.acquire_with_id(request_id, key, owner, ttl).await,
            Self::Persistent(client) => client.acquire_with_id(request_id, &key, &owner, ttl).await,
        }
    }

    async fn lease_mutation_status(
        &self,
        request: &SessionConsumerLeaseMutationRequest,
    ) -> Result<SessionConsumerLeaseMutationStatus, StoreError> {
        match self {
            Self::Stateless(client) => client.lease_mutation_status(request).await,
            Self::Persistent(client) => client.lease_mutation_status(request).await,
        }
    }

    async fn prewarm(&self) -> Result<bool, SessionConsumerClientError> {
        match self {
            Self::Stateless(_) => Ok(true),
            Self::Persistent(client) => Ok(client.prewarm().await?.ready),
        }
    }

    async fn persistent_setup_and_reuse(&self) -> Option<(u64, u64)> {
        match self {
            Self::Stateless(_) => None,
            Self::Persistent(client) => {
                let diagnostics = client.diagnostics().await;
                Some((diagnostics.setup_successes, diagnostics.reused))
            }
        }
    }

    async fn shutdown(&self) {
        if let Self::Persistent(client) = self {
            let report = client.shutdown().await;
            assert_eq!(report.forced_calls, 0);
            assert_eq!(report.forced_watches, 0);
        }
    }
}

struct PersistentConsumerRunMeasurements {
    /// The one release-only source binding captured before the first `/1` and
    /// `/3` campaign. Lightweight runs deliberately carry no such binding.
    release_provenance: Option<ReleaseGateProvenance>,
    authenticated_setup_successes: u64,
    warm_reused_calls: u64,
    protected_roster_setup_successes: u64,
    tenant_positive_observations: u8,
    tenant_negative_boundary_rejections: u8,
    scope_positive_observations: u8,
    scope_negative_boundary_rejections: u8,
    fence_positive_observations: u8,
    fence_negative_boundary_rejections: u8,
    initial_processes: u8,
    unclean_process_losses: u8,
    restarted_processes: u8,
    observed_process_generations: u8,
    general_lane: PersistentConsumerLaneMeasurements,
    protected_roster_lane: PersistentConsumerLaneMeasurements,
}

#[derive(Clone, Copy, Default)]
struct PersistentConsumerLaneMeasurements {
    admission_operations: u8,
    status_operations: u8,
    before_leader_loss_operations: u8,
    after_leader_loss_operations: u8,
    after_restart_operations: u8,
    after_voter_loss_operations: u8,
    tenant_positive_observations: u8,
    tenant_negative_boundary_rejections: u8,
    scope_positive_observations: u8,
    scope_negative_boundary_rejections: u8,
    fence_positive_observations: u8,
    fence_negative_boundary_rejections: u8,
}

/// Count the protected foreign-tenant boundary only when the ingress returns
/// its deliberate non-oracular result. An ungranted projected-root identity
/// is closed before Hello as `Unavailable`, so callers cannot distinguish
/// tenant membership from any other denied role.
fn protected_tenant_boundary_observation(
    result: &Result<
        opc_session_net::PersistentSessionConsumerReadiness,
        SessionConsumerClientError,
    >,
) -> u8 {
    u8::from(matches!(
        result,
        Err(SessionConsumerClientError::Unavailable)
    ))
}

/// Only the two observations that can still be ambiguous after a confirmed
/// outcome-unknown mutation may consume the bounded receipt-recovery retry.
/// Every typed rejection, authorization/scope/protocol failure, or durable
/// negative receipt is terminal for this retained request body.
fn lease_receipt_recovery_is_retryable(
    result: &Result<SessionConsumerLeaseMutationStatus, StoreError>,
) -> bool {
    matches!(
        result,
        Ok(SessionConsumerLeaseMutationStatus::NotFound) | Err(StoreError::BackendUnavailable(_))
    )
}

/// The tenant negative is a deliberately non-oracular `Unavailable`, so its
/// surrounding same-voter controls must prove that the retained protected
/// capsule is still *admitted*. A terminal or compacted read is a successful
/// transport call, but cannot credit that availability/authority bracket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtectedRosterStatusClass {
    Admitted,
    Terminal,
    Compacted,
}

fn protected_roster_status_class(
    outcome: &opc_session_net::FencedMutationRosterRecoveryOutcome,
) -> ProtectedRosterStatusClass {
    match outcome {
        opc_session_net::FencedMutationRosterRecoveryOutcome::Admitted(_) => {
            ProtectedRosterStatusClass::Admitted
        }
        opc_session_net::FencedMutationRosterRecoveryOutcome::Terminal(_) => {
            ProtectedRosterStatusClass::Terminal
        }
        opc_session_net::FencedMutationRosterRecoveryOutcome::Compacted => {
            ProtectedRosterStatusClass::Compacted
        }
    }
}

fn protected_roster_admitted_status_observation(status: ProtectedRosterStatusClass) -> u8 {
    u8::from(matches!(status, ProtectedRosterStatusClass::Admitted))
}

fn require_protected_roster_admitted_status_class(phase: &str, status: ProtectedRosterStatusClass) {
    assert_eq!(
        protected_roster_admitted_status_observation(status),
        1,
        "{phase}: the same-voter protected `/3` status control must be \
         RecoveryOutcome::Admitted; terminal or compacted status cannot bracket \
         the non-oracular tenant boundary"
    );
}

fn require_protected_roster_admitted_status(
    outcome: opc_session_net::FencedMutationRosterRecoveryOutcome,
    phase: &str,
) {
    require_protected_roster_admitted_status_class(phase, protected_roster_status_class(&outcome));
}

fn protected_scope_boundary_observation(
    result: &Result<
        opc_session_net::PersistentSessionConsumerReadiness,
        SessionConsumerClientError,
    >,
) -> u8 {
    u8::from(matches!(result, Err(SessionConsumerClientError::Scope)))
}

fn protected_fence_boundary_observation(
    result: &Result<
        opc_session_net::FencedMutationRosterRecoveryOutcome,
        opc_session_net::FencedMutationRosterClientError,
    >,
) -> u8 {
    u8::from(matches!(
        result,
        Err(opc_session_net::FencedMutationRosterClientError::AuthorityRejected)
    ))
}

/// Select only a voter whose current readiness report proves that it is the
/// live quorum leader.  A `/3` pool is endpoint-pinned, so retaining a pool
/// whose voter was deliberately killed would turn the post-loss status proof
/// into a transport accident instead of an authenticated roster recovery.
fn protected_roster_proven_live_voter(reports: &[FleetReadiness]) -> usize {
    reports
        .iter()
        .find(|report| {
            report.ready
                && report.reason_code == QualificationReadinessCode::Ready
                && report.leader_id == Some(report.node_id)
                && report.configured_voters >= report.required_quorum
                && report.fresh_reachable_voters >= report.required_quorum
                && report.agreeing_voters >= report.required_quorum
        })
        .map(|report| report.node_index)
        .expect("protected /3 recovery requires a readiness-proven live voter")
}

/// The process facts in current-head evidence are derived from the exact PIDs
/// observed at the fault seam.  Keeping this local ledger prevents a test
/// narrative ("two losses and one restart") from becoming an unbound claim.
#[derive(Default)]
struct PersistentConsumerProcessLedger {
    generations: std::collections::BTreeMap<usize, Vec<u32>>,
    lost: std::collections::BTreeSet<u32>,
}

/// Testkit-local, deterministic provider/executor identity for the public
/// `/3` adapter.  The root key intentionally matches the projected ingress
/// trust root installed in the separately running quorum-node binary; this is
/// not a synthetic in-process transport path.
struct QualificationRosterIssuer {
    executor_key: SigningKey,
    executor_root: FencedMutationRosterAttestationTrustRootV1,
    executor_certificate: FencedMutationRosterExecutorCertificatePartsV1,
}

impl QualificationRosterIssuer {
    fn new(scope: SessionConsumerScope) -> Arc<Self> {
        let root_key = SigningKey::from_bytes((&[0x31; 32]).into()).expect("fixed roster root");
        let executor_key =
            SigningKey::from_bytes((&[0x33; 32]).into()).expect("fixed roster executor");
        let root = qualification_roster_attestation_trust_root();
        let root_public = root.compressed_public_key();
        let now = Timestamp::now_utc();
        let not_before = now.add_seconds(-60).expect("roster leaf lower bound");
        let not_after = now.add_seconds(3_600).expect("roster leaf upper bound");
        let scope_commitment =
            opc_session_store::consumer::session_consumer_roster_scope_commitment(scope);
        let certificate = |role, subject_identity_commitment, key_id, key: &SigningKey| {
            let public_key: [u8; 33] = key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("P-256 compressed leaf key");
            let mut certificate = RosterAttestationLeafCertificatePartsV1 {
                root_id: root.root_id(),
                role,
                configuration_identity: scope.consensus_identity(),
                scope: scope_commitment,
                subject_identity_commitment,
                leaf_epoch: 1,
                key_id,
                not_before,
                not_after,
                public_key,
                root_signature: [0; 64],
            };
            certificate.root_signature = Self::sign(
                &root_key,
                RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                    .expect("canonical roster certificate"),
            );
            certificate
        };
        let executor_leaf = certificate(
            RosterAttestationCertificateRoleV1::Executor,
            [0x42; 32],
            [0x52; 32],
            &executor_key,
        );
        let executor_root =
            FencedMutationRosterAttestationTrustRootV1::new(root.root_id(), root_public)
                .expect("public executor trust root");
        let executor_certificate = FencedMutationRosterExecutorCertificatePartsV1::new(
            executor_leaf.root_id,
            executor_leaf.configuration_identity,
            executor_leaf.subject_identity_commitment,
            executor_leaf.leaf_epoch,
            executor_leaf.key_id,
            executor_leaf.not_before,
            executor_leaf.not_after,
            executor_leaf.public_key,
            executor_leaf.root_signature,
        )
        .expect("public executor certificate");
        Arc::new(Self {
            executor_key,
            executor_root,
            executor_certificate,
        })
    }

    fn sign(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
        let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).expect("fixed signing");
        signature.normalize_s().to_bytes().into()
    }
}

#[async_trait::async_trait]
impl FencedMutationRosterExecutorAttestor for QualificationRosterIssuer {
    fn trust_root(&self) -> FencedMutationRosterAttestationTrustRootV1 {
        self.executor_root.clone()
    }

    fn executor_certificate(
        &self,
    ) -> Result<FencedMutationRosterExecutorCertificatePartsV1, FencedMutationRosterExecutorError>
    {
        Ok(self.executor_certificate.clone())
    }

    async fn sign_terminal(
        &self,
        input: &opc_session_net::FencedMutationRosterTerminalAttestationSigningInputV1<'_>,
    ) -> Result<[u8; 64], FencedMutationRosterExecutorError> {
        Ok(Self::sign(&self.executor_key, input.signing_digest()?))
    }

    async fn sign_compact_terminal(
        &self,
        input: &FencedMutationRosterCompactTerminalMemberSigningInputV2<'_>,
    ) -> Result<[u8; 64], FencedMutationRosterExecutorError> {
        Ok(Self::sign(&self.executor_key, input.signing_digest()?))
    }
}

struct QualificationRosterProvider;

#[async_trait::async_trait]
impl FencedMutationRosterMemberProvider for QualificationRosterProvider {
    type Error = ();

    async fn prepare(
        &self,
        _call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderCallOutcome::prepared_not_run())
    }

    async fn execute(
        &self,
        _call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderCallOutcome::outcome_unknown())
    }

    async fn status(
        &self,
        _call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderCallOutcome::not_found())
    }

    async fn adopt(
        &self,
        _call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderCallOutcome::outcome_unknown())
    }
}

/// One real public protected-roster admission retained for read-only recovery
/// across the process faults in the three-member qualifier.  The only mutable
/// capability is consumed by `admit`; every subsequent call is status/recover.
struct QualificationProtectedRosterRun {
    client: FencedMutationRosterClient,
    transport: PersistentSessionConsumerClient,
    voter_index: usize,
    admission: FencedMutationRosterAdmissionInput,
    lease: LeaseGuard,
    current_recovery: Option<FencedMutationRosterRecoveryInput>,
}

fn qualification_fenced_mutation_roster_client(
    protected: PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
) -> FencedMutationRosterClient {
    protected
        .into_fenced_mutation_roster_client(
            Arc::new(QualificationRosterProvider),
            QualificationRosterIssuer::new(scope) as Arc<dyn FencedMutationRosterExecutorAttestor>,
            NonZeroUsize::new(6).expect("fixed public roster concurrency"),
        )
        .expect("compose the real protected-roster client")
}

fn qualification_single_lane_persistent_config() -> PersistentSessionConsumerConfig {
    let defaults = PersistentSessionConsumerConfig::default();
    PersistentSessionConsumerConfig::try_new(
        1,
        defaults.pending_calls(),
        defaults.pool_wait_timeout(),
        defaults.watch_connections(),
        defaults.setup_timeout(),
        defaults.connect_attempts(),
        defaults.reconnect_jitter(),
        defaults.shutdown_drain(),
    )
    .expect("one-lane auxiliary qualification pool stays within public bounds")
}

impl QualificationProtectedRosterRun {
    async fn prepare(
        member_count: usize,
        general: &QualificationConsumerClient,
        protected: PersistentSessionConsumerClient,
        voter_index: usize,
        scope: SessionConsumerScope,
    ) -> Self {
        let key = SessionKey {
            tenant: TenantId::new("session-ha-qualification").expect("bounded roster tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"qualification-roster-session")
                .try_into()
                .expect("bounded roster stable ID"),
        };
        let owner = OwnerId::new("qualification-roster-owner").expect("bounded roster owner");
        let lease = general
            .acquire_with_id(
                SessionConsumerRequestId::from_bytes([0x71; 16]),
                key.clone(),
                owner.clone(),
                PROTECTED_ROSTER_LEASE_TTL,
            )
            .await
            .expect("general lane obtains the real protected-roster lease");
        let mut record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("qualification-roster-admission"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        seal_qualification_consensus_record(member_count, &mut record).await;
        let created = general
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([0x72; 16]),
                SessionConsumerOperation::CompareAndSet {
                    op: Box::new(CompareAndSet {
                        key,
                        lease: lease.clone(),
                        expected_generation: None,
                        new_record: record,
                    }),
                },
            ))
            .await
            .expect("general lane creates the admission record");
        assert!(matches!(
            created,
            SessionConsumerResponse::CompareAndSet(Ok(
                opc_session_store::CompareAndSetResult::Success
            ))
        ));

        let client = qualification_fenced_mutation_roster_client(protected.clone(), scope);
        let members = (0_u8..6)
            .map(|ordinal| {
                FencedMutationRosterMember::new(
                    ordinal,
                    FencedMutationRosterMemberOperationId::from_bytes([ordinal + 1; 16])
                        .expect("fixed roster operation identity"),
                    vec![0xd0, ordinal],
                    u64::from(ordinal) + 1,
                )
                .expect("fixed public roster member")
            })
            .collect();
        let proposal = FencedMutationRosterAdmissionProposal::new(
            FencedMutationRosterProfile::v1(),
            FencedMutationRosterId::from_bytes([0x73; 16]).expect("fixed roster ID"),
            members,
            FencedMutationRosterEstablishedMutation::no_op(),
            vec![0x74],
            vec![0x75],
            vec![0x76],
        )
        .expect("bounded no-op protected roster proposal");
        let admission = client
            .prepare(lease.clone(), Generation::new(1), proposal)
            .expect("real leased roster admission body");
        Self {
            client,
            transport: protected,
            voter_index,
            admission,
            lease,
            current_recovery: None,
        }
    }

    async fn admit_outcome_unknown(&mut self) {
        assert!(matches!(
            self.client
                .admit(&mut self.admission)
                .await
                .expect("real /3 PollAdmit"),
            FencedMutationRosterAdmissionOutcome::OutcomeUnknown(_)
        ));
    }

    async fn status(&self) -> opc_session_net::FencedMutationRosterRecoveryOutcome {
        match self.current_recovery.as_ref() {
            Some(recovery) => self
                .client
                .recover(recovery)
                .await
                .expect("real /3 successor recovery status"),
            None => self
                .client
                .admission_status(&self.admission)
                .await
                .expect("real /3 ambiguous-admission status"),
        }
    }

    fn voter_index(&self) -> usize {
        self.voter_index
    }

    /// Replace the deliberately short-deadline pool at the same voter without
    /// opening its normal-deadline successor first. The caller proves the
    /// effectful server task released its listener permit before prewarming.
    async fn retire_short_deadline_transport(
        &mut self,
        protected: PersistentSessionConsumerClient,
        voter_index: usize,
        scope: SessionConsumerScope,
    ) {
        assert_eq!(
            voter_index, self.voter_index,
            "the short-deadline transport profile changes at the same voter"
        );
        let next_client = qualification_fenced_mutation_roster_client(protected.clone(), scope);
        let old_client = std::mem::replace(&mut self.client, next_client);
        let old_transport = std::mem::replace(&mut self.transport, protected);
        drop(old_client);
        old_transport.shutdown().await;
    }

    /// Reconstruct the same authenticated roster admission on a different
    /// live `/3` transport. The replacement is proven warm before the old
    /// endpoint-local pool is retired. The admission, tenant/scope
    /// commitments, and retained fence remain byte-for-byte unchanged.
    async fn rebind_live_voter(
        &mut self,
        protected: PersistentSessionConsumerClient,
        voter_index: usize,
        scope: SessionConsumerScope,
    ) {
        assert_ne!(
            voter_index, self.voter_index,
            "a same-voter protected-roster status must reuse its bounded pool"
        );
        protected
            .prewarm()
            .await
            .expect("replacement-voter protected-roster mTLS prewarm");
        let next_client = qualification_fenced_mutation_roster_client(protected.clone(), scope);
        let old_client = std::mem::replace(&mut self.client, next_client);
        let old_transport = std::mem::replace(&mut self.transport, protected);
        self.voter_index = voter_index;
        drop(old_client);
        old_transport.shutdown().await;
    }

    async fn recover(
        &mut self,
        general: &QualificationConsumerClient,
        scope: SessionConsumerScope,
    ) -> u8 {
        let released = general
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([0x77; 16]),
                SessionConsumerOperation::ReleaseLease {
                    lease: self.lease.clone(),
                },
            ))
            .await
            .expect("general lane releases the original roster lease");
        assert!(matches!(
            released,
            SessionConsumerResponse::ReleaseLease(Ok(()))
        ));
        let successor = general
            .acquire_with_id(
                SessionConsumerRequestId::from_bytes([0x78; 16]),
                self.lease.key().clone(),
                self.lease.owner().clone(),
                PROTECTED_ROSTER_LEASE_TTL,
            )
            .await
            .expect("general lane obtains a higher-fence roster recovery lease");
        assert!(
            successor.fence() > self.lease.fence(),
            "protected recovery requires the actual higher-fence successor"
        );
        let retained_recovery = self
            .admission
            .recovery(successor.clone(), Generation::new(1))
            .expect("same real roster identity builds recovery input");
        let recovered = self
            .client
            .recover(&retained_recovery)
            .await
            .expect("real /3 admission recovery");
        require_protected_roster_admitted_status(
            recovered,
            "current-fence protected-roster recovery",
        );
        let released_successor = general
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([0x79; 16]),
                SessionConsumerOperation::ReleaseLease {
                    lease: successor.clone(),
                },
            ))
            .await
            .expect("general lane releases the recovered roster lease");
        assert!(matches!(
            released_successor,
            SessionConsumerResponse::ReleaseLease(Ok(()))
        ));
        let current = general
            .acquire_with_id(
                SessionConsumerRequestId::from_bytes([0x7a; 16]),
                successor.key().clone(),
                successor.owner().clone(),
                PROTECTED_ROSTER_LEASE_TTL,
            )
            .await
            .expect("general lane obtains the current recovery lease");
        assert!(
            current.fence() > successor.fence(),
            "fence negative requires a retained, now-stale recovery guard"
        );
        // `retained_recovery` was a valid current `/3` recovery capsule. Once
        // a later lease has been durably acquired it becomes stale, so submit
        // that exact retained capsule through the public adapter and require
        // the typed rejection. This remains read-only and cannot replay the
        // original admission mutation.
        let stale_result = self.client.recover(&retained_recovery).await;
        let stale_rejected = protected_fence_boundary_observation(&stale_result);
        assert_eq!(
            stale_rejected, 1,
            "the retained old-fence protected recovery must receive the typed authority rejection"
        );
        let recovery = self
            .admission
            .recovery(current.clone(), Generation::new(1))
            .expect("current roster lease builds recovery input");
        let recovered = self
            .client
            .recover(&recovery)
            .await
            .expect("real /3 recovery under the current lease");
        require_protected_roster_admitted_status(
            recovered,
            "successor-fence protected-roster recovery",
        );
        self.lease = current;
        self.current_recovery = Some(recovery);
        stale_rejected
    }
}

impl PersistentConsumerProcessLedger {
    fn record_initial(&mut self, node_index: usize, process_id: u32) {
        assert!(
            self.generations
                .insert(node_index, vec![process_id])
                .is_none(),
            "each quorum node has one initial process generation"
        );
    }

    fn record_unclean_loss(&mut self, node_index: usize, process_id: u32) {
        let generations = self
            .generations
            .get(&node_index)
            .expect("loss belongs to an observed quorum node");
        assert_eq!(
            generations.last().copied(),
            Some(process_id),
            "unclean loss must name the current node generation"
        );
        assert!(
            self.lost.insert(process_id),
            "one process generation can be lost only once"
        );
    }

    fn record_restart(&mut self, node_index: usize, previous: u32, replacement: u32) {
        assert_ne!(previous, replacement, "restart must mint a new process ID");
        let generations = self
            .generations
            .get_mut(&node_index)
            .expect("restart belongs to an observed quorum node");
        assert_eq!(
            generations.last().copied(),
            Some(previous),
            "restart must follow the recorded current generation"
        );
        assert!(
            self.lost.contains(&previous),
            "restart follows an unclean loss"
        );
        generations.push(replacement);
    }

    fn initial_processes(&self) -> u8 {
        u8::try_from(self.generations.len()).expect("bounded quorum size")
    }

    fn unclean_process_losses(&self) -> u8 {
        u8::try_from(self.lost.len()).expect("bounded process-loss ledger")
    }

    fn restarted_processes(&self) -> u8 {
        u8::try_from(
            self.generations
                .values()
                .map(|generations| generations.len().saturating_sub(1))
                .sum::<usize>(),
        )
        .expect("bounded process-restart ledger")
    }

    fn observed_process_generations(&self) -> u8 {
        u8::try_from(self.generations.values().map(Vec::len).sum::<usize>())
            .expect("bounded process-generation ledger")
    }
}

fn run_consumer_multiprocess_qualification(
    member_count: usize,
    mode: ConsumerQualificationMode,
    release_provenance: Option<ReleaseGateProvenance>,
) -> Option<PersistentConsumerRunMeasurements> {
    if release_provenance.is_some() {
        assert_eq!(
            member_count, 3,
            "the frozen V9 protected-roster authority bracket has exactly three endpoint/authority pairs"
        );
    }
    if let Some(provenance) = release_provenance.as_ref() {
        provenance
            .verify_unchanged()
            .expect("release provenance is clean before the first dual-lane campaign");
    }
    let mut fleet = match release_provenance.as_ref() {
        Some(provenance) => Fleet::start_with_release_provenance(member_count, provenance),
        None => Fleet::start(member_count),
    };
    let mut process_ledger = PersistentConsumerProcessLedger::default();
    for (node_index, node) in fleet.nodes.iter().enumerate() {
        process_ledger.record_initial(node_index, node.process_id());
    }
    let initial_processes = process_ledger.initial_processes();
    assert_eq!(usize::from(initial_processes), member_count);
    let consumer_identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let mut endpoints = Vec::with_capacity(member_count);
    let mut scope = None;
    for node_index in 0..member_count {
        let (address, node_scope) =
            fleet.start_stateless_consumer(node_index, consumer_identities.clone());
        if let Some(expected) = scope {
            assert!(
                node_scope == expected,
                "consumer scope differs between voters"
            );
        } else {
            scope = Some(node_scope);
        }
        endpoints.push(address);
    }
    let scope = scope.expect("one consumer scope per qualification fleet");
    let voter_authorities = fleet.stateless_consumer_voter_authorities();
    assert!(voter_authorities
        .iter()
        .all(|authority| authority.scope() == scope));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("stateless consumer qualification runtime");
    let mut identity_sources = Vec::with_capacity(consumer_identities.len());
    let clients = consumer_identities
        .iter()
        .enumerate()
        .map(|(consumer_index, identity)| {
            let node_index = consumer_index % member_count;
            let (identity_source, identity_receiver) =
                watch::channel(Some(fleet.pki.consumer_identity_state(identity)));
            identity_sources.push(identity_source);
            let tls = TlsConfigBuilder::new(identity_receiver)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("stateless consumer client mTLS configuration");
            let stateless = StatelessSessionConsumerClient::new(
                endpoints[node_index],
                rustls_pki_types::ServerName::IpAddress(endpoints[node_index].ip().into()),
                voter_authorities[node_index].clone(),
                tls,
            );
            match mode {
                ConsumerQualificationMode::Stateless => {
                    QualificationConsumerClient::Stateless(Box::new(stateless))
                }
                ConsumerQualificationMode::Persistent => QualificationConsumerClient::Persistent(
                    PersistentSessionConsumerClient::try_from_stateless(
                        stateless,
                        PersistentSessionConsumerConfig::default(),
                    )
                    .expect("fixed persistent consumer configuration"),
                ),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(clients.len(), 12);
    // `/3` is not a relabelled capability request: establish an independently
    // constructed revision-five roster pool against the same real projected
    // mTLS listener before recording this run as dual-lane evidence.
    let (roster_identity_source, _roster_identity_receiver) = watch::channel(Some(
        fleet.pki.consumer_identity_state(&consumer_identities[0]),
    ));
    let protected_roster_client_for_voter =
        |node_index: usize, operation_timeout: Option<Duration>| {
            let roster_tls = TlsConfigBuilder::new(roster_identity_source.subscribe())
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("protected-roster persistent mTLS configuration");
            let stateless = StatelessSessionConsumerClient::new(
                endpoints[node_index],
                rustls_pki_types::ServerName::IpAddress(endpoints[node_index].ip().into()),
                voter_authorities[node_index].clone(),
                roster_tls,
            );
            let stateless = match operation_timeout {
                Some(timeout) => stateless.with_operation_timeout(timeout),
                None => stateless,
            };
            PersistentSessionConsumerClient::try_from_fenced_mutation_roster_stateless(
                stateless,
                qualification_single_lane_persistent_config(),
            )
            .expect("fixed protected-roster persistent configuration")
        };
    // The pre-loss run establishes node 0 deliberately. Every post-loss `/3`
    // operation below replaces this endpoint-pinned pool with the same
    // authenticated identity on a readiness-proven live voter.
    let protected_roster_client =
        protected_roster_client_for_voter(0, Some(DELAYED_CONSUMER_CLIENT_DEADLINE));
    assert!(protected_roster_client.fenced_mutation_roster_transport_enabled());
    runtime
        .block_on(protected_roster_client.prewarm())
        .expect("real protected-roster mTLS prewarm");
    let protected_roster_setup_successes = runtime
        .block_on(protected_roster_client.diagnostics())
        .setup_successes;
    assert!(
        protected_roster_setup_successes > 0,
        "protected-roster lane must complete an authenticated setup"
    );
    // The scope control retains the admitted identity but presents a separately
    // validated configuration authority. It must fail during Hello before a
    // protected application operation is accepted.
    let protected_scope_negative = if matches!(mode, ConsumerQualificationMode::Persistent) {
        let foreign_authority = fleet
            .stateless_consumer_voter_authorities_for_configuration("v1-negative", 2)
            .into_iter()
            .next()
            .expect("separately validated scope-control authority");
        assert_ne!(
            foreign_authority.scope(),
            scope,
            "scope negative must not reuse the listener authority"
        );
        let (scope_source, scope_receiver) = watch::channel(Some(
            fleet.pki.consumer_identity_state(&consumer_identities[0]),
        ));
        let scope_tls = TlsConfigBuilder::new(scope_receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("scope-control protected mTLS configuration");
        let scope_pool =
            PersistentSessionConsumerClient::try_from_fenced_mutation_roster_stateless(
                StatelessSessionConsumerClient::new(
                    endpoints[0],
                    rustls_pki_types::ServerName::IpAddress(endpoints[0].ip().into()),
                    foreign_authority,
                    scope_tls,
                ),
                qualification_single_lane_persistent_config(),
            )
            .expect("scope-control protected persistent configuration");
        let scope_result = runtime.block_on(scope_pool.prewarm());
        let scope_observation = protected_scope_boundary_observation(&scope_result);
        assert_eq!(
            scope_observation, 1,
            "the wrong-scope `/3` pool must be rejected by Hello before admission"
        );
        runtime.block_on(scope_pool.shutdown());
        drop(scope_source);
        scope_observation
    } else {
        0
    };
    if matches!(mode, ConsumerQualificationMode::Persistent) {
        assert!(runtime.block_on(async {
            futures_util::future::join_all(clients.iter().map(QualificationConsumerClient::prewarm))
                .await
                .into_iter()
                .all(|result| result.is_ok_and(|ready| ready))
        }));
    }
    assert!(runtime.block_on(async {
        futures_util::future::join_all(
            clients
                .iter()
                .map(QualificationConsumerClient::capabilities),
        )
        .await
        .into_iter()
        .all(|result| result.is_ok())
    }));
    let mut persistent_measurements = if matches!(mode, ConsumerQualificationMode::Persistent) {
        let before = runtime.block_on(async {
            futures_util::future::join_all(
                clients
                    .iter()
                    .map(QualificationConsumerClient::persistent_setup_and_reuse),
            )
            .await
        });
        let setup_successes = before
            .iter()
            .flatten()
            .map(|(setup, _)| *setup)
            .sum::<u64>();
        let reused_before = before
            .iter()
            .flatten()
            .map(|(_, reused)| *reused)
            .sum::<u64>();
        assert!(
            setup_successes >= 48,
            "twelve persistent clients prewarm four authenticated lanes each"
        );

        for sample in 0..QUALIFICATION_PERSISTENT_CONSUMER_MIN_WARM_SAMPLES_V7 {
            runtime
                .block_on(clients[sample % clients.len()].capabilities())
                .expect("warm persistent capability call");
        }
        let after = runtime.block_on(async {
            futures_util::future::join_all(
                clients
                    .iter()
                    .map(QualificationConsumerClient::persistent_setup_and_reuse),
            )
            .await
        });
        let reused_after = after
            .iter()
            .flatten()
            .map(|(_, reused)| *reused)
            .sum::<u64>();
        let warm_reused_calls = reused_after
            .checked_sub(reused_before)
            .expect("persistent reuse counter is monotonic");
        assert_eq!(
            warm_reused_calls, QUALIFICATION_PERSISTENT_CONSUMER_MIN_WARM_SAMPLES_V7 as u64,
            "every measured warm call reuses authenticated capacity"
        );
        Some(PersistentConsumerRunMeasurements {
            release_provenance: release_provenance.clone(),
            authenticated_setup_successes: setup_successes,
            warm_reused_calls,
            protected_roster_setup_successes,
            tenant_positive_observations: 0,
            tenant_negative_boundary_rejections: 0,
            scope_positive_observations: 0,
            scope_negative_boundary_rejections: 0,
            fence_positive_observations: 0,
            fence_negative_boundary_rejections: 0,
            initial_processes,
            unclean_process_losses: 0,
            restarted_processes: 0,
            observed_process_generations: initial_processes,
            general_lane: PersistentConsumerLaneMeasurements::default(),
            protected_roster_lane: PersistentConsumerLaneMeasurements::default(),
        })
    } else {
        None
    };
    for client in &clients {
        let diagnostic = format!("{client:?}");
        for forbidden in [
            "snapshot",
            "replica",
            "voter",
            "learner",
            "session-consumer-",
        ] {
            assert!(
                !diagnostic.contains(forbidden),
                "consumer diagnostics must not expose member or replica authority"
            );
        }
    }

    let known_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes([0x41; 16]),
        SessionConsumerOperation::AcquireLease {
            key: stateless_consumer_key(0),
            owner: OwnerId::new("qualification-consumer-owner").expect("consumer owner"),
            ttl: Duration::from_secs(30),
        },
    );
    let known_response = runtime
        .block_on(clients[0].execute(known_request.clone()))
        .expect("known consumer mutation response");
    assert!(matches!(
        known_response,
        SessionConsumerResponse::AcquireLease(Ok(_))
    ));
    let recovered_known_response = runtime
        .block_on(clients[0].execute(known_request))
        .expect("exact known consumer mutation retry");
    assert!(
        recovered_known_response == known_response,
        "a known durable consumer success must be recoverable by its retained request ID"
    );
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.general_lane.admission_operations = 1;
        measurements.general_lane.before_leader_loss_operations = 1;
    }
    let mut protected_roster_run = if matches!(mode, ConsumerQualificationMode::Persistent) {
        let mut run = runtime.block_on(QualificationProtectedRosterRun::prepare(
            member_count,
            &clients[0],
            protected_roster_client,
            0,
            scope,
        ));
        // Preparation has completed every general-lane mutation. Arm the
        // one-response acknowledgement gate immediately before the already-
        // warm `/3` PollAdmit. The child enters it only after the admission is
        // durably Recorded, while this client's shorter deadline classifies
        // the lost reply as OutcomeUnknown without replaying the mutation.
        fleet.arm_stateless_consumer_ambiguity_witness_hold(0);
        runtime.block_on(run.admit_outcome_unknown());
        let roster_hold_ack_deadline = Instant::now() + V2_BATCH_RELEASE_GATE_HOLD_ACK_TIMEOUT;
        loop {
            let (armed_responses, held_responses) =
                fleet.stateless_consumer_ambiguity_witness_hold_status(0);
            if armed_responses == 0 && held_responses == 1 {
                break;
            }
            assert!(
                Instant::now() < roster_hold_ack_deadline,
                "protected-roster admission did not acknowledge its durable held response: armed={armed_responses}, held={held_responses}"
            );
            thread::sleep(Duration::from_millis(10));
        }
        fleet.release_stateless_consumer_ambiguity_witness_hold(0);
        let roster_hold_release_deadline = Instant::now() + V2_BATCH_RELEASE_GATE_HOLD_ACK_TIMEOUT;
        loop {
            let (armed_responses, held_responses) =
                fleet.stateless_consumer_ambiguity_witness_hold_status(0);
            if armed_responses == 0 && held_responses == 0 {
                break;
            }
            assert!(
                Instant::now() < roster_hold_release_deadline,
                "protected-roster durable response hold did not release: armed={armed_responses}, held={held_responses}"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let status_client = protected_roster_client_for_voter(0, None);
        runtime.block_on(run.retire_short_deadline_transport(status_client, 0, scope));
        runtime
            .block_on(run.transport.prewarm())
            .expect("normal-deadline protected-roster status mTLS prewarm");
        require_protected_roster_admitted_status(
            runtime.block_on(run.status()),
            "before protected-roster lane accounting",
        );
        if let Some(measurements) = persistent_measurements.as_mut() {
            measurements.protected_roster_lane.admission_operations = 1;
            measurements.protected_roster_lane.status_operations = 1;
            measurements
                .protected_roster_lane
                .before_leader_loss_operations = 1;
            // The accepted `/3` admission binds the current tenant/scope/fence
            // authority in the authenticated ingress capsule. Tenant and
            // scope negatives above came from separate rejected `/3` Hello
            // controls; fence is filled only from the later stale-capsule
            // response at the actual recovery seam.
            measurements
                .protected_roster_lane
                .tenant_positive_observations = 1;
            measurements
                .protected_roster_lane
                .tenant_negative_boundary_rejections = 0;
            measurements
                .protected_roster_lane
                .scope_positive_observations = 1;
            measurements
                .protected_roster_lane
                .scope_negative_boundary_rejections = protected_scope_negative;
            measurements
                .protected_roster_lane
                .fence_positive_observations = 1;
        }
        Some(run)
    } else {
        None
    };
    // The tenant negative is deliberately bracketed by the admitted `/3`
    // capsule's status control on this same voter. This distinguishes the
    // anti-oracle `Unavailable` boundary from a node outage without asking the
    // server to reveal a tenant or role decision.
    let protected_tenant_negative = if matches!(mode, ConsumerQualificationMode::Persistent) {
        let protected = protected_roster_run
            .as_ref()
            .expect("persistent qualification retains the admitted `/3` run");
        let initial_nodes = (0..member_count).collect::<Vec<_>>();
        require_protected_roster_admitted_status(
            runtime.block_on(protected.status()),
            "before the non-oracular tenant control",
        );
        assert!(
            fleet
                .readiness_reports(&initial_nodes)
                .iter()
                .all(|report| report.ready),
            "all same-fleet voters are healthy before the non-oracular tenant control"
        );
        let foreign_identity = protected_foreign_tenant_identity();
        let (foreign_source, _foreign_receiver) =
            watch::channel(Some(fleet.pki.consumer_identity_state(&foreign_identity)));
        let mut tenant_observation = 0_u8;
        for node_index in 0..member_count {
            let foreign_tls = TlsConfigBuilder::new(foreign_source.subscribe())
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("foreign-tenant protected mTLS configuration");
            let foreign_pool =
                PersistentSessionConsumerClient::try_from_fenced_mutation_roster_stateless(
                    StatelessSessionConsumerClient::new(
                        endpoints[node_index],
                        rustls_pki_types::ServerName::IpAddress(endpoints[node_index].ip().into()),
                        voter_authorities[node_index].clone(),
                        foreign_tls,
                    ),
                    qualification_single_lane_persistent_config(),
                )
                .expect("foreign-tenant protected persistent configuration");
            let admission_before = fleet.stateless_consumer_admission_status(node_index);
            let foreign_result = runtime.block_on(foreign_pool.prewarm());
            let admission_after = fleet.stateless_consumer_admission_status(node_index);
            assert_eq!(
                protected_tenant_boundary_observation(&foreign_result),
                1,
                "every endpoint/authority foreign-tenant `/3` pair must close as non-oracular Unavailable (voter {node_index})"
            );
            assert_eq!(
                admission_after.admission_rejections, admission_before.admission_rejections,
                "the foreign-tenant `/3` boundary must be admitted by listener capacity before its non-oracular credential rejection (voter {node_index})"
            );
            tenant_observation = tenant_observation
                .checked_add(1)
                .expect("bounded foreign-tenant probe count");
            runtime.block_on(foreign_pool.shutdown());
        }
        assert_eq!(
            tenant_observation,
            u8::try_from(member_count).expect("bounded foreign-tenant probe count"),
            "the tenant control records every endpoint/authority pair exactly once"
        );
        if release_provenance.is_some() {
            assert_eq!(
                tenant_observation, 3,
                "the frozen V9 foreign-tenant bracket requires exact Unavailable from all three voters"
            );
        }
        drop(foreign_source);
        require_protected_roster_admitted_status(
            runtime.block_on(protected.status()),
            "after the non-oracular tenant control",
        );
        assert!(
            fleet
                .readiness_reports(&initial_nodes)
                .iter()
                .all(|report| report.ready),
            "all same-fleet voters remain healthy after the non-oracular tenant control"
        );
        tenant_observation
    } else {
        0
    };
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements
            .protected_roster_lane
            .tenant_negative_boundary_rejections = protected_tenant_negative;
    }
    let foreign_tenant_key = SessionKey {
        tenant: TenantId::new("qualification-foreign-tenant")
            .expect("bounded foreign tenant fixture"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"opaque-foreign-tenant-session")
            .try_into()
            .expect("bounded foreign tenant stable ID"),
    };
    let tenant_negative_boundary_rejections = u8::from(matches!(
        runtime.block_on(clients[0].execute(SessionConsumerRequest::new(
            scope,
            SessionConsumerRequestId::from_bytes([0x42; 16]),
            SessionConsumerOperation::Get {
                key: foreign_tenant_key,
            },
        ))),
        Ok(SessionConsumerResponse::Rejected(
            SessionConsumerRejection::Unauthorized
        ))
    ));
    assert_eq!(tenant_negative_boundary_rejections, 1);
    let scope_identity = scope.consensus_identity();
    let foreign_scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
        scope_identity.cluster_id(),
        scope_identity.configuration_id(),
        SessionConfigurationEpoch::new(scope_identity.configuration_epoch().get() + 1)
            .expect("bounded foreign scope epoch"),
    ));
    // Both public clients enforce their topology scope before a Call frame can
    // cross the wire. Preserve and assert that exact typed pre-transmission
    // boundary instead of expecting the server's unreachable ScopeMismatch.
    let scope_negative_boundary_rejections = u8::from(matches!(
        runtime.block_on(clients[0].execute(SessionConsumerRequest::new(
            foreign_scope,
            SessionConsumerRequestId::from_bytes([0x43; 16]),
            SessionConsumerOperation::Capabilities,
        ))),
        Err(QualificationConsumerExecuteError::Stateless(
            SessionConsumerClientError::Scope
        )) | Err(QualificationConsumerExecuteError::Persistent(
            PersistentSessionConsumerExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Scope
            }
        ))
    ));
    assert_eq!(scope_negative_boundary_rejections, 1);
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.tenant_positive_observations = 1;
        measurements.tenant_negative_boundary_rejections = tenant_negative_boundary_rejections;
        measurements.scope_positive_observations = 1;
        measurements.scope_negative_boundary_rejections = scope_negative_boundary_rejections;
        measurements.general_lane.tenant_positive_observations = 1;
        measurements
            .general_lane
            .tenant_negative_boundary_rejections = tenant_negative_boundary_rejections;
        measurements.general_lane.scope_positive_observations = 1;
        measurements.general_lane.scope_negative_boundary_rejections =
            scope_negative_boundary_rejections;
    }

    let first_atomic_key = qualification_fenced_transition_key(0);
    let first_atomic_capability = runtime
        .block_on(clients[1].execute(SessionConsumerRequest::new(
            scope,
            SessionConsumerRequestId::from_bytes([0x60; 16]),
            SessionConsumerOperation::FencedTransitionCapability,
        )))
        .expect("atomic transition capability response");
    assert_eq!(
        first_atomic_capability,
        SessionConsumerResponse::FencedTransitionCapability(Ok(
            AtomicFencedTransitionCapability::V1
        )),
        "all admitted voters must prove the exact V1 transition capability"
    );
    let first_atomic_observation = runtime
        .block_on(clients[1].execute(SessionConsumerRequest::new(
            scope,
            SessionConsumerRequestId::from_bytes([0x61; 16]),
            SessionConsumerOperation::ObserveFencedTransition {
                key: first_atomic_key.clone(),
            },
        )))
        .expect("fresh atomic transition observation response");
    let first_atomic_fence = match first_atomic_observation {
        SessionConsumerResponse::ObserveFencedTransition(Ok(observation)) => {
            assert!(
                observation.record().is_none(),
                "a fresh atomic transition key must have no record"
            );
            assert_eq!(
                observation.current_fence(),
                FenceToken::new(0),
                "a fresh atomic transition key must expose its zero fence floor"
            );
            observation.current_fence()
        }
        _ => panic!("fresh atomic transition observation must be typed and successful"),
    };
    let first_atomic_id_bytes = [0x62; 16];
    let first_atomic_id = FencedTransitionRequestId::from_bytes(first_atomic_id_bytes);
    let first_atomic_owner =
        OwnerId::new("qualification-atomic-owner").expect("atomic transition owner");
    let first_atomic_lease = FencedTransitionLease::acquire(
        first_atomic_key.clone(),
        first_atomic_owner.clone(),
        first_atomic_fence,
        Duration::from_secs(30),
    )
    .expect("build first atomic acquire action");
    let first_atomic_record = runtime.block_on(qualification_fenced_transition_record(
        member_count,
        first_atomic_key.clone(),
        first_atomic_owner.clone(),
        first_atomic_lease
            .committed_fence()
            .expect("derive first committed fence"),
        b"opaque-qualification-fenced-transition-one",
    ));
    assert_eq!(first_atomic_record.generation, Generation::new(1));
    assert_eq!(
        first_atomic_record.fence,
        FenceToken::new(first_atomic_fence.get() + 1),
        "the first atomic record must bind the observed fence successor"
    );
    let first_atomic_transition = FencedTransitionRequest::new(
        first_atomic_id,
        first_atomic_lease,
        FencedTransitionMutation::create(first_atomic_record.clone()),
    )
    .expect("build first atomic create transition");
    assert_eq!(
        first_atomic_transition.request_id().as_bytes(),
        &first_atomic_id_bytes,
        "the nested atomic transition ID must retain the caller bytes"
    );
    let first_atomic_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes(first_atomic_id_bytes),
        SessionConsumerOperation::FencedTransition {
            request: Box::new(first_atomic_transition.clone()),
        },
    );
    assert_eq!(
        first_atomic_request.request_id().as_bytes(),
        first_atomic_transition.request_id().as_bytes(),
        "the public and nested atomic transition IDs must be byte-identical"
    );
    let first_atomic_outcome = match runtime
        .block_on(clients[1].execute(first_atomic_request.clone()))
        .expect("first atomic transition response")
    {
        SessionConsumerResponse::FencedTransition(Ok(outcome)) => {
            assert!(
                outcome.matches_request(&first_atomic_transition),
                "the atomic transition outcome must exactly match its request"
            );
            outcome
        }
        _ => panic!("first atomic transition must return a typed success"),
    };
    assert_eq!(
        runtime
            .block_on(clients[1].execute(first_atomic_request.clone()))
            .expect("first atomic transition replay response"),
        SessionConsumerResponse::FencedTransition(Ok(first_atomic_outcome.clone())),
        "the exact atomic transition replay must return its recorded outcome"
    );
    let conflicting_atomic_lease = FencedTransitionLease::acquire(
        first_atomic_key.clone(),
        first_atomic_owner.clone(),
        first_atomic_fence,
        Duration::from_secs(31),
    )
    .expect("build conflicting atomic acquire action");
    let conflicting_atomic_transition = FencedTransitionRequest::new(
        first_atomic_id,
        conflicting_atomic_lease,
        FencedTransitionMutation::create(first_atomic_record.clone()),
    )
    .expect("build conflicting atomic transition");
    let fence_negative_boundary_rejections = u8::from(matches!(
        runtime
            .block_on(clients[1].execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes(first_atomic_id_bytes),
                SessionConsumerOperation::FencedTransition {
                    request: Box::new(conflicting_atomic_transition),
                },
            )))
            .expect("conflicting atomic transition response"),
        SessionConsumerResponse::FencedTransition(Err(
            SessionConsumerFencedTransitionError::RequestConflict
        ))
    ));
    assert_eq!(
        fence_negative_boundary_rejections, 1,
        "a different atomic body under one retained ID must be a typed fence boundary conflict"
    );
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.fence_positive_observations = 1;
        measurements.fence_negative_boundary_rejections = fence_negative_boundary_rejections;
        measurements.general_lane.status_operations = 1;
        measurements.general_lane.fence_positive_observations = 1;
        measurements.general_lane.fence_negative_boundary_rejections =
            fence_negative_boundary_rejections;
    }
    let first_atomic_status_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes(first_atomic_id_bytes),
        SessionConsumerOperation::FencedTransitionStatus {
            request: Box::new(first_atomic_transition.clone()),
        },
    );
    assert_eq!(
        runtime
            .block_on(clients[1].execute(first_atomic_status_request.clone()))
            .expect("first atomic transition status response"),
        SessionConsumerResponse::FencedTransitionStatus(Ok(
            SessionConsumerFencedTransitionStatus::Recorded(Box::new(Ok(
                first_atomic_outcome.clone()
            )))
        )),
        "the first atomic transition status must retain the original success"
    );

    // Keep the consumer outcome proof and the leader-loss proof distinct. A
    // known quorum result does not imply that every follower has already
    // applied the same log head. Wait for two identical all-voter observations
    // before injecting the leader fault so this case measures stable-cluster
    // leader failover rather than stacking a lagging-log campaign onto it.
    let all_nodes = (0..member_count).collect::<Vec<_>>();
    let convergence_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    let mut previous_converged = None;
    let before_fault = loop {
        let reports = fleet.readiness_reports(&all_nodes);
        let first = reports.first().copied().expect("nonempty quorum fleet");
        let converged = first.ready
            && first.reason_code == QualificationReadinessCode::Ready
            && first.leader_id.is_some()
            && first.committed_index.is_some()
            && first.committed_index == first.applied_index
            && reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.term == first.term
                    && report.leader_id == first.leader_id
                    && report.committed_index == first.committed_index
                    && report.applied_index == first.applied_index
            });
        let signature = converged.then_some((
            first.term,
            first.leader_id,
            first.committed_index,
            first.applied_index,
        ));
        if signature.is_some() && signature == previous_converged {
            break reports;
        }
        let wait_for_heartbeat = signature.is_some();
        previous_converged = signature;
        assert!(
            Instant::now() < convergence_deadline,
            "{} consumer quorum did not reach a stable all-voter log head before leader loss",
            mode.name(),
        );
        let observation_interval = if wait_for_heartbeat {
            Duration::from_millis(
                DURABLE_CONSENSUS_TIMING_PROFILE
                    .append_entries_timeout_millis
                    .saturating_add(100),
            )
        } else {
            Duration::from_millis(100)
        };
        thread::sleep(observation_interval);
    };
    let old_leader_id = before_fault[0]
        .leader_id
        .expect("stable qualification leader identity");
    let old_term = before_fault[0].term;
    let leader_node_index = before_fault
        .iter()
        .find_map(|report| {
            report
                .leader_id
                .filter(|leader| *leader == report.node_id)
                .map(|_| report.node_index)
        })
        .expect("stable qualification leader");
    let (leader_address, leader_process_id) = fleet.kill_node_unclean(leader_node_index);
    process_ledger.record_unclean_loss(leader_node_index, leader_process_id);
    let leader_survivors = all_nodes
        .iter()
        .copied()
        .filter(|node_index| *node_index != leader_node_index)
        .collect::<Vec<_>>();
    let leader_loss_deadline = Instant::now() + STATELESS_CONSUMER_LEADER_RECOVERY_TIMEOUT;
    let mut previous_replacement = None;
    let replacement_reports = loop {
        let reports = fleet.readiness_reports(&leader_survivors);
        let replacement = reports.first().and_then(|report| report.leader_id);
        let coherent_replacement = replacement.is_some_and(|leader| leader != old_leader_id)
            && reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.term > old_term
                    && report.term == reports[0].term
                    && report.leader_id == replacement
                    && report.configured_voters == member_count
                    && report.required_quorum == fleet.required_quorum()
            });
        let replacement_signature = coherent_replacement.then_some((replacement, reports[0].term));
        if replacement_signature.is_some() && replacement_signature == previous_replacement {
            break reports;
        }
        previous_replacement = replacement_signature;
        assert!(
            Instant::now() < leader_loss_deadline,
            "{} consumer quorum exceeded its bounded functional leader-recovery path",
            mode.name(),
        );
        thread::sleep(Duration::from_millis(50));
    };
    let replacement_leader_node_index = replacement_reports
        .iter()
        .find_map(|report| {
            report
                .leader_id
                .filter(|leader| *leader == report.node_id)
                .map(|_| report.node_index)
        })
        .expect("coherent replacement leader");
    // Status identities are deliberately namespaced by the authenticated
    // consumer, independently of the server endpoint. Build a fresh transport
    // to the replacement leader with the same identity that submitted the
    // first transition; using an arbitrary endpoint-local client here would
    // correctly query a different receipt namespace and return NotFound.
    let (replacement_identity_source, replacement_identity_receiver) = watch::channel(Some(
        fleet.pki.consumer_identity_state(&consumer_identities[1]),
    ));
    let replacement_tls = TlsConfigBuilder::new(replacement_identity_receiver)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("replacement-leader consumer mTLS configuration");
    let replacement_stateless = StatelessSessionConsumerClient::new(
        endpoints[replacement_leader_node_index],
        rustls_pki_types::ServerName::IpAddress(
            endpoints[replacement_leader_node_index].ip().into(),
        ),
        voter_authorities[replacement_leader_node_index].clone(),
        replacement_tls,
    );
    let leader_survivor_client = match mode {
        ConsumerQualificationMode::Stateless => {
            QualificationConsumerClient::Stateless(Box::new(replacement_stateless))
        }
        ConsumerQualificationMode::Persistent => QualificationConsumerClient::Persistent(
            PersistentSessionConsumerClient::try_from_stateless(
                replacement_stateless,
                qualification_single_lane_persistent_config(),
            )
            .expect("replacement-leader persistent consumer configuration"),
        ),
    };
    assert!(
        runtime
            .block_on(leader_survivor_client.prewarm())
            .is_ok_and(|ready| ready),
        "the same authenticated consumer must establish replacement-leader transport"
    );
    assert_eq!(
        runtime
            .block_on(leader_survivor_client.execute(first_atomic_status_request))
            .expect("recovered atomic transition status response"),
        SessionConsumerResponse::FencedTransitionStatus(Ok(
            SessionConsumerFencedTransitionStatus::Recorded(Box::new(Ok(
                first_atomic_outcome.clone()
            )))
        )),
        "the replacement leader must recover the exact prior atomic outcome"
    );
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.general_lane.after_leader_loss_operations = 1;
    }
    if let Some(protected) = protected_roster_run.as_mut() {
        let protected_voter = protected_roster_proven_live_voter(&replacement_reports);
        assert_ne!(
            protected_voter, leader_node_index,
            "the protected `/3` client must not retain the deliberately lost leader endpoint"
        );
        if protected.voter_index() != protected_voter {
            let rebound = protected_roster_client_for_voter(protected_voter, None);
            runtime.block_on(protected.rebind_live_voter(rebound, protected_voter, scope));
        }
        require_protected_roster_admitted_status(
            runtime.block_on(protected.status()),
            "after protected-roster leader loss",
        );
        if let Some(measurements) = persistent_measurements.as_mut() {
            measurements.protected_roster_lane.status_operations += 1;
            measurements
                .protected_roster_lane
                .after_leader_loss_operations = 1;
        }
    }
    assert_eq!(
        runtime
            .block_on(leader_survivor_client.execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([0x63; 16]),
                SessionConsumerOperation::Get {
                    key: first_atomic_key.clone(),
                },
            )))
            .expect("recovered atomic record response"),
        SessionConsumerResponse::Get(Ok(Some(first_atomic_record.clone()))),
        "the replacement leader must read the created atomic record"
    );

    let second_atomic_key = qualification_fenced_transition_key(1);
    let second_atomic_fence = match runtime
        .block_on(leader_survivor_client.execute(SessionConsumerRequest::new(
            scope,
            SessionConsumerRequestId::from_bytes([0x64; 16]),
            SessionConsumerOperation::ObserveFencedTransition {
                key: second_atomic_key.clone(),
            },
        )))
        .expect("second fresh atomic observation response")
    {
        SessionConsumerResponse::ObserveFencedTransition(Ok(observation)) => {
            assert!(
                observation.record().is_none() && observation.current_fence() == FenceToken::new(0),
                "the replacement leader must observe a fresh atomic key"
            );
            observation.current_fence()
        }
        _ => panic!("second fresh atomic observation must be typed and successful"),
    };
    let second_atomic_id_bytes = [0x65; 16];
    let second_atomic_id = FencedTransitionRequestId::from_bytes(second_atomic_id_bytes);
    let second_atomic_owner =
        OwnerId::new("qualification-atomic-failover-owner").expect("failover atomic owner");
    let second_atomic_lease = FencedTransitionLease::acquire(
        second_atomic_key.clone(),
        second_atomic_owner.clone(),
        second_atomic_fence,
        Duration::from_secs(30),
    )
    .expect("build second atomic acquire action");
    let second_atomic_record = runtime.block_on(qualification_fenced_transition_record(
        member_count,
        second_atomic_key.clone(),
        second_atomic_owner,
        second_atomic_lease
            .committed_fence()
            .expect("derive second committed fence"),
        b"opaque-qualification-fenced-transition-two",
    ));
    assert_eq!(second_atomic_record.generation, Generation::new(1));
    assert_eq!(
        second_atomic_record.fence,
        FenceToken::new(second_atomic_fence.get() + 1),
        "the failover atomic record must bind the observed fence successor"
    );
    let second_atomic_transition = FencedTransitionRequest::new(
        second_atomic_id,
        second_atomic_lease,
        FencedTransitionMutation::create(second_atomic_record),
    )
    .expect("build second atomic create transition");
    let second_atomic_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes(second_atomic_id_bytes),
        SessionConsumerOperation::FencedTransition {
            request: Box::new(second_atomic_transition.clone()),
        },
    );
    assert_eq!(
        second_atomic_request.request_id().as_bytes(),
        second_atomic_transition.request_id().as_bytes(),
        "the failover public and nested transition IDs must be byte-identical"
    );
    let second_atomic_outcome = match runtime
        .block_on(leader_survivor_client.execute(second_atomic_request.clone()))
        .expect("second atomic transition response")
    {
        SessionConsumerResponse::FencedTransition(Ok(outcome)) => {
            assert!(
                outcome.matches_request(&second_atomic_transition),
                "the replacement-leader atomic outcome must exactly match its request"
            );
            outcome
        }
        _ => panic!("replacement leader must return a typed atomic success"),
    };
    assert_eq!(
        runtime
            .block_on(leader_survivor_client.execute(second_atomic_request))
            .expect("second atomic transition replay response"),
        SessionConsumerResponse::FencedTransition(Ok(second_atomic_outcome.clone())),
        "the replacement leader must replay the second atomic outcome"
    );
    assert_eq!(
        runtime
            .block_on(leader_survivor_client.execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes(second_atomic_id_bytes),
                SessionConsumerOperation::FencedTransitionStatus {
                    request: Box::new(second_atomic_transition),
                },
            )))
            .expect("second atomic transition status response"),
        SessionConsumerResponse::FencedTransitionStatus(Ok(
            SessionConsumerFencedTransitionStatus::Recorded(Box::new(Ok(second_atomic_outcome)))
        )),
        "the replacement leader must retain the second atomic success"
    );
    let leader_failover_request_id = SessionConsumerRequestId::from_bytes([0x51; 16]);
    let leader_failover_key = stateless_consumer_key(2);
    let leader_failover_owner = OwnerId::new("qualification-leader-failover-owner")
        .expect("leader-failover consumer owner");
    let leader_failover_lease = runtime
        .block_on(leader_survivor_client.acquire_with_id(
            leader_failover_request_id,
            leader_failover_key.clone(),
            leader_failover_owner.clone(),
            Duration::from_secs(30),
        ))
        .expect("consumer mutation must commit through the replacement leader");
    let recovered_leader_failover_lease = runtime
        .block_on(leader_survivor_client.acquire_with_id(
            leader_failover_request_id,
            leader_failover_key,
            leader_failover_owner,
            Duration::from_secs(30),
        ))
        .expect("replacement leader must recover the durable mutation outcome");
    assert!(
        recovered_leader_failover_lease == leader_failover_lease,
        "the replacement leader must return the exact committed consumer outcome"
    );

    fleet.spawn_node_at_manifest_address(leader_node_index, leader_address, leader_process_id);
    let restarted_process_id = fleet.nodes[leader_node_index].process_id();
    assert_ne!(restarted_process_id, leader_process_id);
    process_ledger.record_restart(leader_node_index, leader_process_id, restarted_process_id);
    let restart_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    loop {
        let reports = fleet.readiness_reports(&all_nodes);
        if reports.iter().all(|report| report.ready) {
            break;
        }
        assert!(
            Instant::now() < restart_deadline,
            "leader restart did not regain readiness"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let (_, restarted_scope) =
        fleet.start_stateless_consumer(leader_node_index, consumer_identities.clone());
    assert!(
        restarted_scope == scope,
        "restarted listener retains its scope"
    );
    assert!(
        runtime
            .block_on(leader_survivor_client.capabilities())
            .is_ok(),
        "the surviving general lane remains operational after the lost leader restarts"
    );
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.general_lane.after_restart_operations = 1;
    }
    let recovered_reports = fleet.readiness_reports(&all_nodes);
    if let Some(protected) = protected_roster_run.as_mut() {
        let protected_voter = protected_roster_proven_live_voter(&recovered_reports);
        if protected.voter_index() != protected_voter {
            let rebound = protected_roster_client_for_voter(protected_voter, None);
            runtime.block_on(protected.rebind_live_voter(rebound, protected_voter, scope));
        }
        let stale_fence_rejection =
            runtime.block_on(protected.recover(&leader_survivor_client, scope));
        require_protected_roster_admitted_status(
            runtime.block_on(protected.status()),
            "after protected-roster recovery",
        );
        if let Some(measurements) = persistent_measurements.as_mut() {
            measurements.protected_roster_lane.status_operations += 1;
            measurements.protected_roster_lane.after_restart_operations = 1;
            measurements
                .protected_roster_lane
                .fence_negative_boundary_rejections = stale_fence_rejection;
        }
    }

    let recovered_leader = recovered_reports
        .iter()
        .find_map(|report| {
            report
                .leader_id
                .filter(|leader| *leader == report.node_id)
                .map(|_| report.node_index)
        })
        .expect("leader after restart");
    let voter_loss_node = all_nodes
        .iter()
        .copied()
        .find(|node_index| *node_index != recovered_leader)
        .expect("nonleader voter for loss qualification");
    let (_voter_address, voter_process_id) = fleet.kill_node_unclean(voter_loss_node);
    assert_ne!(voter_process_id, leader_process_id);
    process_ledger.record_unclean_loss(voter_loss_node, voter_process_id);
    let voter_survivors = all_nodes
        .iter()
        .copied()
        .filter(|node_index| *node_index != voter_loss_node)
        .collect::<Vec<_>>();
    let voter_loss_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    loop {
        let reports = fleet.readiness_reports(&voter_survivors);
        if reports.iter().all(|report| {
            report.ready
                && report.reason_code == QualificationReadinessCode::Ready
                && report.configured_voters == member_count
                && report.required_quorum == fleet.required_quorum()
        }) {
            break;
        }
        assert!(
            Instant::now() < voter_loss_deadline,
            "{} consumer quorum did not recover one voter loss",
            mode.name(),
        );
        thread::sleep(Duration::from_millis(50));
    }
    let survivor_reports = fleet.readiness_reports(&voter_survivors);
    let current_leader = survivor_reports
        .iter()
        .find_map(|report| {
            report
                .leader_id
                .filter(|leader| *leader == report.node_id)
                .map(|_| report.node_index)
        })
        .expect("leader after voter loss");
    let follower_node_index = survivor_reports
        .iter()
        .find(|report| report.node_index != current_leader)
        .map(|report| {
            assert_eq!(
                report.leader_id,
                Some(
                    survivor_reports
                        .iter()
                        .find(|candidate| candidate.node_index == current_leader)
                        .expect("current leader report")
                        .node_id
                )
            );
            report.node_index
        })
        .expect("live follower after voter loss");
    let before_delayed_log_index = survivor_reports[0]
        .applied_index
        .expect("stable applied index before delayed acquire");
    assert!(survivor_reports.iter().all(|report| {
        report.committed_index == Some(before_delayed_log_index)
            && report.applied_index == Some(before_delayed_log_index)
    }));
    let healthy_client = &clients[follower_node_index];
    let (delayed_identity_source, delayed_identity_receiver) = watch::channel(Some(
        fleet
            .pki
            .consumer_identity_state(&consumer_identities[follower_node_index]),
    ));
    let delayed_tls = TlsConfigBuilder::new(delayed_identity_receiver)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("delayed-response consumer mTLS configuration");
    let delayed_stateless = StatelessSessionConsumerClient::new(
        endpoints[follower_node_index],
        rustls_pki_types::ServerName::IpAddress(endpoints[follower_node_index].ip().into()),
        voter_authorities[follower_node_index].clone(),
        delayed_tls,
    )
    .with_operation_timeout(DELAYED_CONSUMER_CLIENT_DEADLINE);
    let delayed_client = match mode {
        ConsumerQualificationMode::Stateless => {
            QualificationConsumerClient::Stateless(Box::new(delayed_stateless))
        }
        ConsumerQualificationMode::Persistent => QualificationConsumerClient::Persistent(
            PersistentSessionConsumerClient::try_from_stateless(
                delayed_stateless,
                PersistentSessionConsumerConfig::default(),
            )
            .expect("bounded delayed persistent consumer configuration"),
        ),
    };
    fleet.arm_stateless_consumer_delayed_response(follower_node_index);
    let ambiguous_request_id = SessionConsumerRequestId::from_bytes([0x52; 16]);
    let ambiguous_key = stateless_consumer_key(1);
    let ambiguous_owner =
        OwnerId::new("qualification-ambiguous-owner").expect("ambiguous consumer owner");
    let ambiguous_ttl = Duration::from_secs(30);
    assert!(matches!(
        runtime.block_on(delayed_client.acquire_with_id(
            ambiguous_request_id,
            ambiguous_key.clone(),
            ambiguous_owner.clone(),
            ambiguous_ttl,
        )),
        Err(SessionConsumerLeaseMutationError::OutcomeUnknown { request_id }) if request_id == ambiguous_request_id
    ));
    drop(delayed_client);
    let retained = SessionConsumerLeaseMutationRequest::new(
        ambiguous_request_id,
        SessionConsumerLeaseMutationOperation::Acquire {
            key: ambiguous_key.clone(),
            owner: ambiguous_owner.clone(),
            ttl: ambiguous_ttl,
        },
    );
    let status_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    let recovered = loop {
        let receipt_status = runtime.block_on(healthy_client.lease_mutation_status(&retained));
        match receipt_status {
            Ok(SessionConsumerLeaseMutationStatus::Recorded(result)) => match *result {
                Ok(SessionConsumerLeaseMutationResult::Acquire(guard)) => break guard,
                _ => panic!("lease receipt returned an unexpected recorded result"),
            },
            // Receipt absence and the explicitly classified transient
            // transport status are both deliberately ambiguous after an
            // outcome-unknown mutation. A bounded status-only retry can
            // reconcile them; it never submits a second mutation. Do not
            // widen this to every StoreError: authority/scope/protocol and
            // permanent errors must fail at their first observation.
            status if lease_receipt_recovery_is_retryable(&status) => {
                assert!(
                    Instant::now() < status_deadline,
                    "read-only receipt did not converge after the delayed acquire"
                );
                thread::sleep(Duration::from_millis(20));
            }
            Ok(status) => {
                panic!("lease receipt recovery returned a non-retryable status: {status:?}")
            }
            Err(error) => {
                panic!("lease receipt recovery returned a non-retryable error: {error:?}")
            }
        }
    };
    assert_eq!(recovered.key(), &ambiguous_key);
    assert_eq!(recovered.owner(), &ambiguous_owner);
    assert!(
        recovered.expires_at() > recovered.acquired_at(),
        "receipt recovery returns the persisted guard, not a fresh acquisition"
    );
    assert_eq!(
        runtime.block_on(healthy_client.lease_mutation_status(&retained)),
        Ok(SessionConsumerLeaseMutationStatus::Recorded(Box::new(Ok(
            SessionConsumerLeaseMutationResult::Acquire(recovered.clone())
        )))),
        "a second read-only status lookup must preserve the exact guard, TTL, fence, and credential"
    );
    // An ordinary retained consumer mutation has exactly two consensus
    // entries: its body-binding marker and the inner Acquire. The status
    // barrier/read never proposes an entry, so this exact delta proves one
    // Acquire and no replay or status-induced logical-time/fence/TTL change.
    const DELAYED_ACQUIRE_CONSENSUS_ENTRIES: u64 = 2;
    let delayed_settlement_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    loop {
        let reports = fleet.readiness_reports(&voter_survivors);
        if reports.iter().all(|report| {
            report.committed_index
                == Some(before_delayed_log_index + DELAYED_ACQUIRE_CONSENSUS_ENTRIES)
                && report.applied_index
                    == Some(before_delayed_log_index + DELAYED_ACQUIRE_CONSENSUS_ENTRIES)
        }) {
            break;
        }
        assert!(
            Instant::now() < delayed_settlement_deadline,
            "the delayed acquire must consume only its binding and one Acquire log position"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(runtime.block_on(healthy_client.capabilities()).is_ok());
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.general_lane.after_voter_loss_operations = 1;
    }
    if let Some(protected) = protected_roster_run.as_mut() {
        let protected_voter =
            protected_roster_proven_live_voter(&fleet.readiness_reports(&voter_survivors));
        assert_ne!(
            protected_voter, voter_loss_node,
            "the protected `/3` client must not retain the deliberately lost second voter endpoint"
        );
        if protected.voter_index() != protected_voter {
            let rebound = protected_roster_client_for_voter(protected_voter, None);
            runtime.block_on(protected.rebind_live_voter(rebound, protected_voter, scope));
        }
        require_protected_roster_admitted_status(
            runtime.block_on(protected.status()),
            "after protected-roster second-voter loss",
        );
        if let Some(measurements) = persistent_measurements.as_mut() {
            measurements.protected_roster_lane.status_operations += 1;
            measurements
                .protected_roster_lane
                .after_voter_loss_operations = 1;
        }
    }

    let voter_ids_before = before_fault
        .iter()
        .map(|report| report.configured_voters)
        .collect::<Vec<_>>();
    let voter_ids_after = fleet
        .readiness_reports(&voter_survivors)
        .iter()
        .map(|report| report.configured_voters)
        .collect::<Vec<_>>();
    assert_eq!(
        voter_ids_after,
        vec![member_count; voter_ids_before.len() - 1]
    );
    if matches!(mode, ConsumerQualificationMode::Persistent) {
        runtime.block_on(async {
            for client in &clients {
                client.shutdown().await;
            }
            leader_survivor_client.shutdown().await;
            if let Some(protected) = protected_roster_run.as_ref() {
                protected.transport.shutdown().await;
            }
        });
    }
    drop(replacement_identity_source);
    drop(delayed_identity_source);
    drop(identity_sources);
    drop(roster_identity_source);
    fleet.shutdown();
    if let Some(measurements) = persistent_measurements.as_mut() {
        measurements.initial_processes = process_ledger.initial_processes();
        measurements.unclean_process_losses = process_ledger.unclean_process_losses();
        measurements.restarted_processes = process_ledger.restarted_processes();
        measurements.observed_process_generations = process_ledger.observed_process_generations();
    }
    if let Some(provenance) = release_provenance.as_ref() {
        provenance
            .verify_unchanged()
            .expect("release provenance remains clean through the dual-lane campaign");
    }
    persistent_measurements
}

fn run_stateless_consumer_multiprocess_qualification(member_count: usize) {
    assert!(run_consumer_multiprocess_qualification(
        member_count,
        ConsumerQualificationMode::Stateless,
        None,
    )
    .is_none());
}

fn assert_current_persistent_consumer_head_evidence_binding() {
    let evidence_schema: serde_json::Value =
        serde_json::from_str(SESSION_HA_PERSISTENT_CONSUMER_HEAD_EVIDENCE_V9_SCHEMA_JSON)
            .expect("v9 current-head persistent-consumer evidence schema");
    assert_eq!(
        evidence_schema["$defs"]["general_lane"]["allOf"][1]["properties"]["transport_revision"]
            ["const"],
        serde_json::json!(SESSION_QUORUM_CONSUMER_TRANSPORT_REVISION),
        "the general lane schema must bind the compiled consumer wire revision"
    );
    assert_eq!(
        evidence_schema["$defs"]["protected_roster_lane"]["allOf"][1]["properties"]
            ["transport_revision"]["const"],
        serde_json::json!(SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION),
        "the protected-roster lane schema must bind its isolated transport revision"
    );
}

fn run_persistent_consumer_multiprocess_qualification(
    member_count: usize,
    release_provenance: Option<ReleaseGateProvenance>,
) -> PersistentConsumerRunMeasurements {
    assert_current_persistent_consumer_head_evidence_binding();
    run_consumer_multiprocess_qualification(
        member_count,
        ConsumerQualificationMode::Persistent,
        release_provenance,
    )
    .expect("persistent run emits bounded measurements")
}

// The revision-5 lane deliberately uses its own ALPN and request envelope.
// This is a compact real-network recovery qualification, not a synthetic
// backend exercise: every operation crosses projected-SVID mTLS into an
// independently running OpenRaft/SQLite voter.
fn run_persistent_consumer_v2_multiprocess_qualification() {
    const MEMBER_COUNT: usize = 3;
    let mut fleet = Fleet::start(MEMBER_COUNT);
    // The server-side authorization manifest deliberately admits the same
    // fixed pool used by the V1 qualification. Keep this bounded and shared
    // across voters; the V2 client itself uses only the first identity.
    let consumer_identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let consumer_identity = consumer_identities[0].clone();
    let mut endpoints = Vec::with_capacity(MEMBER_COUNT);
    let mut scope = None;
    for node_index in 0..MEMBER_COUNT {
        let (endpoint, node_scope) =
            fleet.start_stateless_consumer(node_index, consumer_identities.clone());
        if let Some(expected) = scope {
            assert_eq!(
                node_scope, expected,
                "V2 consumer scope differs between voters"
            );
        } else {
            scope = Some(node_scope);
        }
        endpoints.push(endpoint);
    }
    let scope = scope.expect("one V2 consumer scope per qualification fleet");
    let voter_authorities = fleet.stateless_consumer_voter_authorities();
    assert!(voter_authorities
        .iter()
        .all(|authority| authority.scope() == scope));
    let endpoints = Arc::new(Mutex::new(endpoints));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("V2 consumer qualification runtime");
    let consumer_identity_state = fleet.pki.consumer_identity_state(&consumer_identity);
    let client_for = |node_index: usize, operation_timeout: Option<Duration>| {
        let (_identity_source, identity_receiver) =
            watch::channel(Some(consumer_identity_state.clone()));
        let tls = TlsConfigBuilder::new(identity_receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("V2 consumer client mTLS configuration");
        let initial_endpoint = endpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index];
        let resolved_endpoints = Arc::clone(&endpoints);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let endpoint = resolved_endpoints
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index];
            Box::pin(async move { Ok(endpoint) })
        });
        let stateless = StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(initial_endpoint.ip().into()),
            voter_authorities[node_index].clone(),
            tls,
        );
        let stateless = match operation_timeout {
            Some(timeout) => stateless.with_operation_timeout(timeout),
            None => stateless,
        };
        PersistentSessionConsumerClient::try_from_stateless(
            stateless,
            PersistentSessionConsumerConfig::default(),
        )
        .expect("fixed persistent V2 consumer configuration")
    };
    let client = client_for(0, None);
    runtime
        .block_on(client.prewarm_v2())
        .expect("prewarm fixed V2 pool");
    let v2_before = client.v2_diagnostics();
    assert_eq!(
        v2_before.setup_successes, 4,
        "V2 prewarm opens four fixed lanes"
    );
    assert_eq!(
        v2_before.idle, 4,
        "V2 prewarm retains four fixed idle lanes"
    );
    assert_eq!(
        runtime
            .block_on(client.execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2Capability,
            )))
            .expect("V2 capability response"),
        SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2
        )),
        "the real V2 ALPN lane must admit precisely the generic V2 contract"
    );

    let first = runtime.block_on(qualification_fenced_transition_v2_request(MEMBER_COUNT, 0));
    let first_request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2 {
            request: Box::new(first.clone()),
        },
    );
    let first_outcome = match runtime
        .block_on(client.execute_v2(&first_request))
        .expect("first V2 transition response")
    {
        SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)) => {
            assert!(outcome.matches_v2_request(&first));
            outcome
        }
        response => panic!("first V2 transition must return its typed outcome: {response:?}"),
    };
    assert_eq!(
        runtime
            .block_on(client.execute_v2(&first_request))
            .expect("exact V2 replay response"),
        SessionConsumerV2Response::FencedTransitionV2(Ok(first_outcome.clone())),
        "the full self-authenticating V2 ID replays its exact durable outcome"
    );
    let first_status = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Status {
            request: Box::new(first.clone()),
        },
    );
    assert_eq!(
        runtime
            .block_on(client.execute_v2(&first_status))
            .expect("V2 status response"),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Ok(first_outcome.clone())))
        )),
        "status returns the same exact V2 receipt"
    );

    // A structural body substitution retains the original complete ID in
    // both envelope locations. It must be a typed conflict, not a second
    // transition or malformed transport frame.
    let altered = runtime.block_on(qualification_fenced_transition_v2_request(MEMBER_COUNT, 1));
    let altered_request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2 {
            request: Box::new(altered),
        },
    );
    let original_id = serde_json::to_value(first_request.request_id()).expect("V2 ID encodes");
    let mut conflicted_value = serde_json::to_value(altered_request).expect("V2 envelope encodes");
    let serde_json::Value::Object(fields) = &mut conflicted_value else {
        panic!("V2 envelope is an object");
    };
    fields.insert("request_id".to_owned(), original_id.clone());
    fields
        .get_mut("operation")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|operation| operation.get_mut("request"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 request body")
        .insert("request_id".to_owned(), original_id);
    let conflicted: SessionConsumerV2Request =
        serde_json::from_value(conflicted_value).expect("structural V2 conflict decodes");
    assert_eq!(
        runtime
            .block_on(client.execute_v2(&conflicted))
            .expect("V2 conflict response"),
        SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::RequestConflict
        ))
    );
    let v2_pre_fault = client.v2_diagnostics();
    assert_eq!(
        v2_pre_fault.reconnects, 0,
        "the steady pre-fault V2 pool does not discard an authenticated lane: {v2_pre_fault:?}"
    );

    let all_nodes = (0..MEMBER_COUNT).collect::<Vec<_>>();
    let before_fault = fleet.readiness_reports(&all_nodes);
    let old_leader_id = before_fault
        .iter()
        .find_map(|report| report.leader_id)
        .expect("V2 qualification leader");
    let old_term = before_fault[0].term;
    let leader_node_index = before_fault
        .iter()
        .find_map(|report| (report.node_id == old_leader_id).then_some(report.node_index))
        .expect("V2 qualification leader node");
    let (leader_address, leader_process_id) = fleet.kill_node_unclean(leader_node_index);
    let survivors = all_nodes
        .iter()
        .copied()
        .filter(|node_index| *node_index != leader_node_index)
        .collect::<Vec<_>>();
    let recovery_deadline = Instant::now() + STATELESS_CONSUMER_LEADER_RECOVERY_TIMEOUT;
    let replacement = loop {
        let reports = fleet.readiness_reports(&survivors);
        if let Some(report) = reports.iter().find(|report| {
            report.ready
                && report
                    .leader_id
                    .is_some_and(|leader| leader != old_leader_id)
                && report.term > old_term
                && report.node_id == report.leader_id.expect("leader is present")
        }) {
            break report.node_index;
        }
        assert!(
            Instant::now() < recovery_deadline,
            "V2 consumer quorum did not elect a replacement leader"
        );
        thread::sleep(Duration::from_millis(50));
    };
    let replacement_client = client_for(replacement, None);
    assert_eq!(
        runtime
            .block_on(replacement_client.execute_v2(&first_status))
            .expect("V2 status after leader loss"),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Ok(first_outcome.clone())))
        )),
        "a re-elected leader returns the original V2 receipt"
    );

    fleet.spawn_node_at_manifest_address(leader_node_index, leader_address, leader_process_id);
    let restart_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    while !fleet
        .readiness_reports(&all_nodes)
        .iter()
        .all(|report| report.ready)
    {
        assert!(
            Instant::now() < restart_deadline,
            "restarted V2 leader did not regain readiness"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let (restarted_leader_endpoint, _) =
        fleet.start_stateless_consumer(leader_node_index, consumer_identities.clone());
    endpoints
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[leader_node_index] =
        restarted_leader_endpoint;

    let voter_loss_node = all_nodes
        .iter()
        .copied()
        .find(|node_index| *node_index != replacement)
        .expect("V2 nonleader voter");
    let (voter_address, voter_process_id) = fleet.kill_node_unclean(voter_loss_node);
    let voter_survivors = all_nodes
        .iter()
        .copied()
        .filter(|node_index| *node_index != voter_loss_node)
        .collect::<Vec<_>>();
    let voter_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    while !fleet
        .readiness_reports(&voter_survivors)
        .iter()
        .all(|report| report.ready && report.required_quorum == fleet.required_quorum())
    {
        assert!(
            Instant::now() < voter_deadline,
            "V2 quorum did not survive voter loss"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let delayed_client = client_for(replacement, Some(DELAYED_CONSUMER_CLIENT_DEADLINE));
    runtime
        .block_on(delayed_client.prewarm_v2())
        .expect("prewarm the bounded delayed-response V2 client");
    fleet.arm_stateless_consumer_delayed_response(replacement);
    let ambiguous = runtime.block_on(qualification_fenced_transition_v2_request(MEMBER_COUNT, 2));
    let ambiguous_execute = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2 {
            request: Box::new(ambiguous.clone()),
        },
    );
    assert_eq!(
        runtime
            .block_on(delayed_client.execute_v2(&ambiguous_execute))
            .expect_err("post-commit V2 response-loss must be ambiguous"),
        PersistentSessionConsumerV2ExecuteError::OutcomeUnknown {
            request_id: ambiguous.request_id(),
        },
        "the post-commit response-loss seam returns the exact caller-retained V2 ID"
    );
    drop(delayed_client);
    let ambiguous_status = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Status {
            request: Box::new(ambiguous.clone()),
        },
    );
    assert!(matches!(
        runtime
            .block_on(replacement_client.execute_v2(&ambiguous_status))
            .expect("ambiguous V2 status readback"),
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(result)
        )) if result.as_ref().as_ref().is_ok_and(|outcome| outcome.matches_v2_request(&ambiguous))
    ));

    let successor = runtime.block_on(qualification_fenced_transition_v2_request(MEMBER_COUNT, 3));
    assert!(matches!(
        runtime
            .block_on(replacement_client.execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2 {
                    request: Box::new(successor.clone()),
                },
            )))
            .expect("fresh V2 successor response"),
        SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)) if outcome.matches_v2_request(&successor)
    ));

    fleet.spawn_node_at_manifest_address(voter_loss_node, voter_address, voter_process_id);
    let voter_restart_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    while !fleet
        .readiness_reports(&all_nodes)
        .iter()
        .all(|report| report.ready)
    {
        assert!(
            Instant::now() < voter_restart_deadline,
            "restarted V2 voter did not regain readiness"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let (restarted_voter_endpoint, _) =
        fleet.start_stateless_consumer(voter_loss_node, consumer_identities);
    endpoints
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[voter_loss_node] =
        restarted_voter_endpoint;
    let v2_after = client.v2_diagnostics();
    assert!(
        v2_after.reused >= 4,
        "steady V2 calls reuse fixed authenticated lanes without a reconnect storm: {v2_after:?}"
    );
    assert!(
        v2_after.reconnects <= 4,
        "endpoint loss or bounded lifecycle expiry discards at most the fixed four-lane pool once: {v2_after:?}"
    );
    runtime
        .block_on(client.prewarm_v2())
        .expect("re-establish the exact fixed V2 width after endpoint recovery");
    let v2_reestablished = client.v2_diagnostics();
    let v2_readiness = runtime.block_on(client.v2_readiness());
    assert!(v2_readiness.ready, "re-established V2 pool is ready");
    assert_eq!(v2_readiness.configured_request_connections, 4);
    assert_eq!(v2_readiness.ready_request_connections, 4);
    assert_eq!(v2_reestablished.active, 4);
    assert_eq!(v2_reestablished.idle, 4);
    assert!(
        v2_reestablished.setup_successes <= 8,
        "one recovered fixed pool cannot create an unbounded setup storm: {v2_reestablished:?}"
    );
    runtime.block_on(async {
        client.shutdown().await;
        replacement_client.shutdown().await;
    });
    fleet.shutdown();
}

// This ignored gate is intentionally a same-host, three-child-process
// qualification. It exercises the production persistent V2 pool over TCP,
// projected-SVID mTLS, exact SPIFFE peer verification, V2 ALPN, and Hello;
// it is not a cross-host production-capacity claim.
fn run_persistent_consumer_v2_batch_release_gate(
    release_provenance: ReleaseGateProvenance,
) -> BatchReleaseGateRunFacts {
    release_provenance
        .verify_unchanged()
        .expect("release gate source remains clean before its V1 campaign");
    const MEMBER_COUNT: usize = 3;
    assert_v2_batch_release_profile();
    let observed_profile = env!("OPC_SESSION_TESTKIT_CARGO_PROFILE_FAMILY");
    let observed_opt_level = env!("OPC_SESSION_TESTKIT_CARGO_OPT_LEVEL");
    assert_eq!(V2_BATCH_RELEASE_GATE_CLIENTS, 12);
    assert_eq!(V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT, 4);
    assert_eq!(V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY, 48);
    assert_eq!(
        V2_BATCH_RELEASE_GATE_CLIENTS / MEMBER_COUNT * V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,
        16,
        "each voter receives exactly its normal sixteen-connection workload envelope below the bounded listener admission limit"
    );
    assert_eq!(V2_BATCH_RELEASE_GATE_PRELOAD_CREATES, 50_000);
    assert_eq!(V2_BATCH_RELEASE_GATE_PACED_MUTATIONS, 60_000);
    assert_eq!(V2_BATCH_RELEASE_GATE_MUTATIONS_PER_SECOND, 1_000);
    assert_eq!(V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES, 1_008);
    let mut fleet = Fleet::start_with_schedule(
        MEMBER_COUNT,
        session_mtls_batch_release_gate_schedule_sha256(),
        Some(&release_provenance),
    );
    let consumer_identities = (0..V2_BATCH_RELEASE_GATE_CLIENTS)
        .map(stateless_consumer_identity)
        .collect::<Vec<_>>();
    let mut endpoints = Vec::with_capacity(MEMBER_COUNT);
    let mut scope = None;
    for node_index in 0..MEMBER_COUNT {
        let (endpoint, node_scope) =
            fleet.start_stateless_consumer(node_index, consumer_identities.clone());
        if let Some(expected) = scope {
            assert_eq!(
                node_scope, expected,
                "V2 batch scope differs between voters"
            );
        } else {
            scope = Some(node_scope);
        }
        endpoints.push(endpoint);
    }
    let scope = scope.expect("three V2 batch consumer scopes");
    let voter_authorities = fleet.stateless_consumer_voter_authorities();
    assert!(voter_authorities
        .iter()
        .all(|authority| authority.scope() == scope));
    let endpoints = Arc::new(Mutex::new(endpoints));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("V2 batch release-gate runtime");
    let pool_config = PersistentSessionConsumerConfig::try_new(
        V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,
        V2_BATCH_RELEASE_GATE_PENDING_CALLS,
        Duration::from_millis(250),
        2,
        Duration::from_millis(1_500),
        2,
        Duration::from_millis(25),
        Duration::from_secs(5),
    )
    .expect("fixed V2 batch pool and queue configuration");
    assert_eq!(
        pool_config.connect_attempts(),
        2,
        "mTLS setup accounting is derived from the fixed two-attempt connection policy"
    );
    let credential_negative_pool_config = PersistentSessionConsumerConfig::try_new(
        1,
        0,
        Duration::from_millis(250),
        1,
        Duration::from_millis(1_500),
        1,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("single-attempt credential-negative pool configuration");
    let mut identity_senders = Vec::with_capacity(V2_BATCH_RELEASE_GATE_CLIENTS);
    let mut clients = Vec::with_capacity(V2_BATCH_RELEASE_GATE_CLIENTS);
    for (consumer_index, consumer_identity) in consumer_identities.iter().enumerate() {
        let node_index = consumer_index % MEMBER_COUNT;
        let (identity_sender, identity_receiver) =
            watch::channel(Some(fleet.pki.consumer_identity_state(consumer_identity)));
        let tls = TlsConfigBuilder::new(identity_receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("V2 batch client mTLS configuration");
        let initial_endpoint = endpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index];
        let resolved_endpoints = Arc::clone(&endpoints);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let endpoint = resolved_endpoints
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[node_index];
            Box::pin(async move { Ok(endpoint) })
        });
        let stateless = StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(initial_endpoint.ip().into()),
            voter_authorities[node_index].clone(),
            tls,
        );
        identity_senders.push(identity_sender);
        clients.push(
            PersistentSessionConsumerClient::try_from_stateless(stateless, pool_config)
                .expect("fixed persistent V2 batch client"),
        );
    }
    assert_eq!(clients.len(), V2_BATCH_RELEASE_GATE_CLIENTS);
    runtime.block_on(async {
        let readiness = futures_util::future::join_all(clients.iter().map(|client| async {
            client.prewarm_v2().await.expect("prewarm fixed V2 lanes");
            client.v2_readiness().await
        }))
        .await;
        assert!(readiness.iter().all(|ready| {
            ready.ready
                && ready.configured_request_connections == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT
                && ready.ready_request_connections == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT
        }));
    });
    // Snapshot immediately after the exact 48-lane initial prewarm. Later
    // load-window accounting is relative to this stable physical baseline.
    let initial_prewarm_diagnostics = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    let prewarmed = initial_prewarm_diagnostics.clone();
    assert!(prewarmed.iter().all(|diagnostics| {
        diagnostics.setup_attempts == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
            && diagnostics.setup_failures == 0
            && diagnostics.setup_successes == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
            && diagnostics.active == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
            && diagnostics.idle == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
            && diagnostics.pool_wait_current == 0
            && diagnostics.pool_wait_max == 0
            && diagnostics.reconnects == 0
    }));

    // Establish the overlap generation on every server before the measured
    // workload. The later replacement is the only member that receives a
    // new-root leaf, which makes the client trust routing below observable.
    for node_index in 0..MEMBER_COUNT {
        fleet.transition_member(
            node_index,
            CredentialGeneration::Initial,
            TrustGeneration::Overlap,
            &format!("v2-batch-initial-overlap-node-{node_index}"),
        );
    }

    assert_eq!(
        runtime
            .block_on(clients[0].execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2Capability,
            )))
            .expect("V2 batch capability response"),
        SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2
        )),
        "the release gate uses the V2 ALPN/Hello contract, not the V1 listener"
    );

    let first = runtime.block_on(qualification_fenced_transition_v2_request(MEMBER_COUNT, 0));
    let first_response = runtime
        .block_on(clients[0].execute_v2(&SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(first.clone()),
            },
        )))
        .expect("singleton first V2 activation response");
    assert!(matches!(
        first_response,
        SessionConsumerV2Response::FencedTransitionV2(Ok(outcome))
            if outcome.matches_v2_request(&first)
    ));

    let process_ids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    // The sampler observes only the three child voters. The harness process
    // and any server queue high-water are downstream diagnostics, not
    // acceptance evidence for this client-pool qualification.
    let warmed_resources = process_ids
        .iter()
        .copied()
        .map(read_classified_process_resources)
        .collect::<Vec<_>>();
    let resource_sampler = ResourceSampler::start(process_ids.clone());

    let preload_batches = runtime.block_on(qualification_build_v2_batches(
        MEMBER_COUNT,
        1,
        V2_BATCH_RELEASE_GATE_PRELOAD_CREATES,
        V2_BATCH_RELEASE_GATE_PRELOAD_BATCH_SIZE,
    ));
    assert_eq!(
        preload_batches.iter().map(Vec::len).sum::<usize>(),
        V2_BATCH_RELEASE_GATE_PRELOAD_CREATES
    );
    let retained_preload_requests = preload_batches
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        retained_preload_requests.len(),
        V2_BATCH_RELEASE_GATE_PRELOAD_CREATES
    );
    let (
        preload_recovered_unknown,
        preload_not_transmitted_retries,
        preload_not_transmitted_retry_high_water,
        preload_status_retries,
    ) = runtime.block_on(async {
        let mut recovered_unknown = 0usize;
        let mut not_transmitted_retries = 0usize;
        let mut not_transmitted_retry_high_water = 0usize;
        let mut status_retries = V2BatchStatusRetryCounts::default();
        for batches in preload_batches.chunks(V2_BATCH_RELEASE_GATE_PRELOAD_CONCURRENCY) {
            let measurements = futures_util::future::join_all(batches.iter().map(|requests| {
                qualification_execute_v2_batch_sample(
                    clients[0].clone(),
                    scope,
                    requests.clone(),
                    Instant::now(),
                )
            }))
            .await;
            let measurements = measurements
                .into_iter()
                .map(|measurement| measurement.expect("preload V2 batch sample succeeds"))
                .collect::<Vec<_>>();
            assert_eq!(measurements.len(), batches.len());
            recovered_unknown = recovered_unknown
                .checked_add(
                    measurements
                        .iter()
                        .filter(|(_, recovered, _, _)| *recovered)
                        .count(),
                )
                .expect("bounded preload recovery count fits usize");
            not_transmitted_retries = not_transmitted_retries
                .checked_add(
                    measurements
                        .iter()
                        .map(|(_, _, retries, _)| retries)
                        .sum::<usize>(),
                )
                .expect("bounded preload retry count fits usize");
            not_transmitted_retry_high_water = not_transmitted_retry_high_water.max(
                measurements
                    .iter()
                    .map(|(_, _, retries, _)| *retries)
                    .max()
                    .unwrap_or(0),
            );
            for (_, _, _, retries) in measurements {
                status_retries.accumulate(retries);
            }
        }
        (
            recovered_unknown,
            not_transmitted_retries,
            not_transmitted_retry_high_water,
            status_retries,
        )
    });
    assert_eq!(
        preload_batches.len(),
        196,
        "50k preload has the exact 256-operation batch schedule"
    );
    assert_eq!(
        preload_recovered_unknown, 0,
        "a 256-operation preload family cannot truthfully claim recovery under the fixed 64-status-attempt cap"
    );
    assert_eq!(
        preload_status_retries.attempts_total,
        preload_status_retries
            .terminal_attempts
            .checked_add(preload_status_retries.total)
            .expect("preload status-attempt conservation fits usize"),
        "preload status attempts are conserved between terminal reads and retries"
    );
    assert_eq!(
        preload_status_retries.total,
        preload_status_retries
            .not_found
            .checked_add(preload_status_retries.not_transmitted)
            .and_then(|total| total.checked_add(preload_status_retries.read_unavailable))
            .and_then(|total| total.checked_add(preload_status_retries.typed_unavailable))
            .expect("preload status retry-cause conservation fits usize"),
        "preload status retries are conserved across their named causes"
    );
    assert_eq!(
        preload_status_retries,
        V2BatchStatusRetryCounts::default(),
        "preload status recovery is conserved as an explicit zero rather than discarded"
    );
    assert!(
        preload_not_transmitted_retry_high_water
            <= V2_BATCH_RELEASE_GATE_NOT_TRANSMITTED_RETRY_LIMIT,
        "every retained preload mutation replay obeys the fixed per-batch bound"
    );
    let mutation_batches = runtime.block_on(qualification_build_v2_batches(
        MEMBER_COUNT,
        1 + V2_BATCH_RELEASE_GATE_PRELOAD_CREATES,
        V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
        V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE,
    ));
    let mutation_batch_count = mutation_batches.len();
    assert_eq!(
        mutation_batches.iter().map(Vec::len).sum::<usize>(),
        V2_BATCH_RELEASE_GATE_PACED_MUTATIONS
    );

    // Long unpaced batches deliberately keep one client hot. Restore and
    // freeze the complete fixed-width pool immediately before latency
    // measurement so setup work is excluded and every measured call is warm.
    runtime.block_on(async {
        futures_util::future::join_all(clients.iter().map(|client| async {
            client
                .prewarm_v2()
                .await
                .expect("restore fixed V2 width before measured work");
            let ready = client.v2_readiness().await;
            assert!(ready.ready);
            assert_eq!(
                ready.ready_request_connections,
                V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT
            );
            let diagnostics = client.v2_diagnostics();
            assert_eq!(
                diagnostics.active, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
                "each measured V2 client retains its declared fixed lane width"
            );
            assert_eq!(
                diagnostics.idle, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
                "each measured V2 client is fully idle immediately before warm work"
            );
        }))
        .await;
    });
    // This is the required post-50k preload/restore snapshot. The preload
    // window must not have created a per-operation transport setup.
    let post_preload_restore_diagnostics = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    assert_no_fault_v2_setup_delta(
        "50k preload/restore",
        &initial_prewarm_diagnostics,
        &post_preload_restore_diagnostics,
    );
    let measurement_baseline = post_preload_restore_diagnostics.clone();
    let consensus_diagnostics_before_warm_reads = fleet.all_consensus_diagnostics();

    const WARM_STATUS_REQUEST_STRIDE: usize = 53;
    let (mut warm_read_samples, mut warm_status_request_indices) = runtime.block_on(async {
        let mut samples = Vec::with_capacity(V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES);
        let mut request_indices = Vec::with_capacity(V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES);
        let retained_request_count = V2_BATCH_RELEASE_GATE_PRELOAD_CREATES;
        let mut sample_index = 0usize;
        for _ in
            0..(V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES / V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY)
        {
            let scheduled_at = Instant::now();
            let mut reads = Vec::with_capacity(V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY);
            for client in &clients {
                for _ in 0..V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT {
                    let request_index = 1usize
                        .checked_add(
                            sample_index
                                .checked_mul(WARM_STATUS_REQUEST_STRIDE)
                                .expect("bounded warm status index multiplication fits usize")
                                % retained_request_count,
                        )
                        .expect("bounded warm status request index fits usize");
                    sample_index = sample_index
                        .checked_add(1)
                        .expect("bounded warm status sample count fits usize");
                    request_indices.push(request_index);
                    let retained_request = retained_preload_requests
                        .get(
                            request_index
                                .checked_sub(1)
                                .expect("one-based warm status request index is nonzero"),
                        )
                        .expect("warm status index selects retained preload request")
                        .clone();
                    reads.push(qualification_execute_v2_status_sample(
                        client.clone(),
                        scope,
                        retained_request,
                        scheduled_at,
                    ));
                }
            }
            let wave = futures_util::future::join_all(reads).await;
            samples.extend(wave);
        }
        (samples, request_indices)
    });
    assert_eq!(
        warm_read_samples.len(),
        V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES,
        "warm-read sample collection is exact and bounded"
    );
    warm_status_request_indices.sort_unstable();
    warm_status_request_indices.dedup();
    assert_eq!(
        warm_status_request_indices.len(),
        V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES,
        "warm status reads cover an exact deterministic non-hot retained-request spread"
    );
    let warm_status_request_min = *warm_status_request_indices
        .first()
        .expect("warm status request spread is nonempty");
    let warm_status_request_max = *warm_status_request_indices
        .last()
        .expect("warm status request spread is nonempty");
    let consensus_diagnostics_after_warm_reads = fleet.all_consensus_diagnostics();
    let status_local_delta = consensus_diagnostics_after_warm_reads
        .iter()
        .zip(&consensus_diagnostics_before_warm_reads)
        .map(|(after, before)| {
            after
                .status_local_requests
                .checked_sub(before.status_local_requests)
                .expect("status-local counter is monotonic")
        })
        .sum::<u64>();
    let status_ingress_delta = consensus_diagnostics_after_warm_reads
        .iter()
        .zip(&consensus_diagnostics_before_warm_reads)
        .map(|(after, before)| {
            after
                .status_ingress_requests
                .checked_sub(before.status_ingress_requests)
                .expect("status-ingress counter is monotonic")
        })
        .sum::<u64>();
    let status_leader_delta = consensus_diagnostics_after_warm_reads
        .iter()
        .zip(&consensus_diagnostics_before_warm_reads)
        .map(|(after, before)| {
            after
                .status_leader_cohort_requests
                .checked_sub(before.status_leader_cohort_requests)
                .expect("status-leader counter is monotonic")
        })
        .sum::<u64>();
    let status_representative_delta = consensus_diagnostics_after_warm_reads
        .iter()
        .zip(&consensus_diagnostics_before_warm_reads)
        .map(|(after, before)| {
            after
                .status_representatives
                .checked_sub(before.status_representatives)
                .expect("status-representative counter is monotonic")
        })
        .sum::<u64>();
    let status_proposal_delta = consensus_diagnostics_after_warm_reads
        .iter()
        .zip(&consensus_diagnostics_before_warm_reads)
        .map(|(after, before)| {
            after
                .status_proposals
                .checked_sub(before.status_proposals)
                .expect("status-proposal counter is monotonic")
        })
        .sum::<u64>();
    assert_eq!(
        status_local_delta, V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES as u64,
        "every recorded warm read enters exactly one bounded node-local batch",
    );
    let expected_voter_representatives = u64::try_from(
        MEMBER_COUNT
            * (V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES / V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY),
    )
    .expect("bounded voter representative count");
    assert_eq!(status_ingress_delta, expected_voter_representatives);
    assert_eq!(status_representative_delta, expected_voter_representatives);
    assert_eq!(status_leader_delta, expected_voter_representatives);
    assert_eq!(
        status_proposal_delta,
        u64::try_from(
            V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES / V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY,
        )
        .expect("bounded status proposal count"),
        "each 48-reader wave has exactly one consensus linearization point",
    );

    // Take a public capacity snapshot immediately before the paced phase.
    // The scheduler below supplies the complementary caller-side bound: no
    // client can have more than this many submitted V2 calls at once.
    runtime.block_on(async {
        let readiness = futures_util::future::join_all(
            clients
                .iter()
                .map(PersistentSessionConsumerClient::v2_readiness),
        )
        .await;
        for (client_index, ready) in readiness.iter().enumerate() {
            assert!(
                ready.ready
                    && ready.configured_request_connections
                        == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT
                    && ready.ready_request_connections == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,
                "V2 client {client_index} is fully ready immediately before paced work: {ready:?}"
            );
            let diagnostics = clients[client_index].v2_diagnostics();
            assert_eq!(
                diagnostics.active,
                V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
                "V2 client {client_index} has its declared active lane width immediately before paced work: {diagnostics:?}"
            );
            assert_eq!(
                diagnostics.idle,
                V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
                "V2 client {client_index} has no checked-out lanes immediately before paced work: {diagnostics:?}"
            );
        }
    });

    let (
        mut mutation_samples,
        mutation_recovered_unknown,
        mutation_not_transmitted_retries,
        mutation_status_retries,
        mutation_not_transmitted_retry_high_water,
        mutation_status_retries_high_water,
        mutation_status_attempts_high_water,
        mutation_phase_elapsed,
        mutation_scheduled_batches_per_client,
        mutation_completed_batches_per_client,
        mutation_slow_lane_other_completions,
        mutation_saturated_client_skips,
        mutation_max_in_flight_per_client,
        mutation_max_global_in_flight,
    ) = runtime.block_on(async {
        let phase_started = Instant::now();
        let interval_nanos = 1_000_000_000_u64
            .checked_mul(u64::try_from(V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE).expect("fixed batch size fits u64"))
            .expect("fixed pacing interval fits u64")
            / u64::try_from(V2_BATCH_RELEASE_GATE_MUTATIONS_PER_SECOND)
                .expect("fixed mutation rate fits u64");
        let mut pending = futures_util::stream::FuturesUnordered::<
            tokio::task::JoinHandle<(
                usize,
                usize,
                Result<(Duration, bool, usize, V2BatchStatusRetryCounts), QualificationV2BatchSampleFailure>,
            )>,
        >::new();
        let mut samples = Vec::with_capacity(mutation_batches.len());
        let mut recovered_unknown = 0usize;
        let mut not_transmitted_retries = 0usize;
        let mut status_retries = V2BatchStatusRetryCounts::default();
        let mut not_transmitted_retry_high_water = 0usize;
        let mut status_retries_high_water = 0usize;
        let mut status_attempts_high_water = 0usize;
        let mut scheduled_batches_per_client = vec![0usize; clients.len()];
        let mut completed_batches_per_client = vec![0usize; clients.len()];
        let mut saturated_client_skips = 0usize;
        // The first four paced admissions occupy the complete declared
        // scheduler width of one client. That client is skipped until another
        // fixed producer completes, proving that a slow producer cannot
        // create global HOL or leave a capacity-hole deadlock.
        let slow_lane_client_index = 0usize;
        let (mut slow_lane_release_senders, mut slow_lane_release_receivers): (Vec<_>, Vec<_>) =
            (0..V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT)
                .map(|_| oneshot::channel::<()>())
                .unzip();
        let mut slow_lane_other_completions = 0usize;
        let mut in_flight_per_client = vec![0usize; clients.len()];
        let mut max_in_flight_per_client = vec![0usize; clients.len()];
        let mut max_global_in_flight = 0usize;
        for (batch_index, requests) in mutation_batches.into_iter().enumerate() {
            let scheduled_at = phase_started
                + Duration::from_nanos(
                    interval_nanos
                        .checked_mul(u64::try_from(batch_index).expect("bounded batch index fits u64"))
                        .expect("bounded scheduled batch offset fits u64"),
                );
            tokio::time::sleep_until(tokio::time::Instant::from_std(scheduled_at)).await;
            // Drain global capacity only. A saturated preferred client is
            // skipped below, so one slow four-lane pool cannot induce global
            // head-of-line blocking for other ready producers.
            while pending.len() >= V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY {
                use futures_util::StreamExt;
                let (completed_batch_index, completed_client_index, result) = pending
                    .next()
                    .await
                    .expect("bounded batch driver has a task")
                    .expect("bounded batch sample task completes");
                let (sample, recovered, retries, status_retry_counts) = result.unwrap_or_else(|failure| {
                    let node_index = completed_client_index % MEMBER_COUNT;
                    let diagnostics = fleet.all_consensus_diagnostics();
                    panic!(
                        "V2 batch release gate paced failure: batch_index={completed_batch_index}, client_index={completed_client_index}, node_index={node_index}, failure={failure:?}, diagnostics_by_node={diagnostics:?}"
                    )
                });
                assert!(
                    in_flight_per_client[completed_client_index] > 0,
                    "completed V2 batch has a matching scheduler admission"
                );
                in_flight_per_client[completed_client_index] -= 1;
                completed_batches_per_client[completed_client_index] += 1;
                if completed_client_index != slow_lane_client_index
                    && !slow_lane_release_senders.is_empty()
                {
                    slow_lane_other_completions += 1;
                    for sender in slow_lane_release_senders.drain(..) {
                        sender
                            .send(())
                            .expect("the bounded slow lanes remain scheduled");
                    }
                }
                samples.push(sample);
                recovered_unknown += usize::from(recovered);
                not_transmitted_retries += retries;
                status_retries.accumulate(status_retry_counts);
                not_transmitted_retry_high_water = not_transmitted_retry_high_water.max(retries);
                status_retries_high_water = status_retries_high_water.max(status_retry_counts.total);
                status_attempts_high_water =
                    status_attempts_high_water.max(status_retry_counts.attempts_total);
            }
            let preferred_client_index = if batch_index < V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT {
                slow_lane_client_index
            } else {
                batch_index % clients.len()
            };
            let client_index = select_v2_batch_scheduler_client(
                preferred_client_index,
                &in_flight_per_client,
                V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,
            )
                .expect("global capacity implies one V2 producer has a free lane");
            saturated_client_skips += usize::from(client_index != preferred_client_index);
            scheduled_batches_per_client[client_index] += 1;
            assert!(
                pending.len() < V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY,
                "the global V2 scheduler bound leaves capacity for one admitted call"
            );
            assert!(
                in_flight_per_client[client_index] < V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,
                "the per-client V2 scheduler bound leaves capacity for one admitted call"
            );
            in_flight_per_client[client_index] += 1;
            max_in_flight_per_client[client_index] =
                max_in_flight_per_client[client_index].max(in_flight_per_client[client_index]);
            max_global_in_flight = max_global_in_flight.max(pending.len() + 1);
            let client = clients[client_index].clone();
            let slow_lane_wait = if batch_index < V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT {
                Some(
                    slow_lane_release_receivers.remove(0),
                )
            } else {
                None
            };
            pending.push(tokio::spawn(async move {
                if let Some(slow_lane_wait) = slow_lane_wait {
                    slow_lane_wait
                        .await
                        .expect("the bounded slow lane is released after alternate progress");
                }
                (
                    batch_index,
                    client_index,
                    qualification_execute_v2_batch_sample(client, scope, requests, scheduled_at)
                        .await,
                )
            }));
        }
        use futures_util::StreamExt;
        while let Some(result) = pending.next().await {
            let (completed_batch_index, completed_client_index, result) =
                result.expect("bounded batch sample task completes");
            let (sample, recovered, retries, status_retry_counts) = result.unwrap_or_else(|failure| {
                let node_index = completed_client_index % MEMBER_COUNT;
                let diagnostics = fleet.all_consensus_diagnostics();
                panic!(
                    "V2 batch release gate paced failure: batch_index={completed_batch_index}, client_index={completed_client_index}, node_index={node_index}, failure={failure:?}, diagnostics_by_node={diagnostics:?}"
                )
            });
            assert!(
                in_flight_per_client[completed_client_index] > 0,
                "completed V2 batch has a matching scheduler admission"
            );
            in_flight_per_client[completed_client_index] -= 1;
            completed_batches_per_client[completed_client_index] += 1;
            if completed_client_index != slow_lane_client_index
                && !slow_lane_release_senders.is_empty()
            {
                slow_lane_other_completions += 1;
                for sender in slow_lane_release_senders.drain(..) {
                    sender
                        .send(())
                        .expect("the bounded slow lanes remain scheduled");
                }
            }
            samples.push(sample);
            recovered_unknown += usize::from(recovered);
            not_transmitted_retries += retries;
            status_retries.accumulate(status_retry_counts);
            not_transmitted_retry_high_water = not_transmitted_retry_high_water.max(retries);
            status_retries_high_water = status_retries_high_water.max(status_retry_counts.total);
            status_attempts_high_water =
                status_attempts_high_water.max(status_retry_counts.attempts_total);
        }
        assert!(
            in_flight_per_client.iter().all(|in_flight| *in_flight == 0),
            "every caller-side V2 scheduler admission completes"
        );
        (
            samples,
            recovered_unknown,
            not_transmitted_retries,
            status_retries,
            not_transmitted_retry_high_water,
            status_retries_high_water,
            status_attempts_high_water,
            phase_started.elapsed(),
            scheduled_batches_per_client,
            completed_batches_per_client,
            slow_lane_other_completions,
            saturated_client_skips,
            max_in_flight_per_client,
            max_global_in_flight,
        )
    });
    let consensus_diagnostics_after_measured_work = fleet.all_consensus_diagnostics();
    for (node_index, (after, before)) in consensus_diagnostics_after_measured_work
        .iter()
        .zip(&consensus_diagnostics_before_warm_reads)
        .enumerate()
    {
        assert_eq!(
            after.sqlite_connection_lock_deadline, before.sqlite_connection_lock_deadline,
            "node {node_index} measured work cannot wait through a SQLite connection-lock deadline",
        );
        assert_eq!(
            after.sqlite_worker_permit_deadline, before.sqlite_worker_permit_deadline,
            "node {node_index} measured work cannot exhaust a fixed SQLite worker permit",
        );
        assert_eq!(
            after.sqlite_execution_deadline, before.sqlite_execution_deadline,
            "node {node_index} measured work cannot exceed the bounded SQLite execution deadline",
        );
    }
    assert_eq!(
        mutation_samples.len(),
        V2_BATCH_RELEASE_GATE_PACED_MUTATIONS / V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE,
        "all open-loop mutation batches returned exactly one typed response"
    );
    runtime.block_on(qualification_assert_v2_active_history(
        clients[0].clone(),
        scope,
        1 + V2_BATCH_RELEASE_GATE_PRELOAD_CREATES + V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
    ));
    let paced_elapsed_nanos = u64::try_from(mutation_phase_elapsed.as_nanos())
        .expect("paced elapsed time fits evidence nanoseconds");
    let achieved_logical_operations_per_second_milli =
        session_mtls_batch_release_gate_achieved_rate_milli(
            V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
            paced_elapsed_nanos,
        )
        .expect("paced elapsed time is nonzero and rate fits evidence");
    assert!(
        achieved_logical_operations_per_second_milli
            >= SESSION_MTLS_BATCH_RELEASE_GATE_MIN_ACHIEVED_RATE_MILLI,
        "V2 batch release gate achieved less than 99.9% of its offered operation rate: achieved_milli={achieved_logical_operations_per_second_milli}"
    );
    assert!(
        mutation_scheduled_batches_per_client
            .iter()
            .all(|scheduled| *scheduled > 0),
        "saturated-client skipping retains bounded slow-lane progress for every V2 client: {mutation_scheduled_batches_per_client:?}"
    );
    let min_completed_batches = mutation_completed_batches_per_client
        .iter()
        .copied()
        .min()
        .expect("fixed V2 client set is nonempty");
    assert!(
        min_completed_batches > 0,
        "every fixed V2 producer retains one bounded slow-lane completion: {mutation_completed_batches_per_client:?}"
    );
    assert!(
        mutation_saturated_client_skips > 0 && mutation_slow_lane_other_completions > 0,
        "one bounded slow client is skipped while another fixed client completes, avoiding global HOL: skips={mutation_saturated_client_skips}, other_completions={mutation_slow_lane_other_completions}"
    );
    assert!(
        mutation_max_in_flight_per_client
            .iter()
            .all(|max_in_flight| *max_in_flight <= V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT),
        "each V2 client remains at or below its four declared active calls: {mutation_max_in_flight_per_client:?}"
    );
    assert!(
        mutation_max_global_in_flight <= V2_BATCH_RELEASE_GATE_WAVE_CONCURRENCY,
        "the V2 scheduler remains at or below its 48-call global bound: max={mutation_max_global_in_flight}"
    );
    assert!(
        mutation_not_transmitted_retry_high_water
            <= V2_BATCH_RELEASE_GATE_NOT_TRANSMITTED_RETRY_LIMIT,
        "no V2 call exceeds its fixed not-transmitted retry bound"
    );
    // The raw samples include scheduled-submission delay and bounded pool
    // queue dwell through receipt validation; no percentile histogram drops
    // or compresses individual observations.
    let warm_p99 = qualification_v2_batch_percentile(&mut warm_read_samples, 99, 100);
    let warm_p999 = qualification_v2_batch_percentile(&mut warm_read_samples, 999, 1_000);
    let mutation_p99 = qualification_v2_batch_percentile(&mut mutation_samples, 99, 100);
    let mutation_p999 = qualification_v2_batch_percentile(&mut mutation_samples, 999, 1_000);
    assert!(warm_p99 <= V2_BATCH_RELEASE_GATE_P99);
    assert!(warm_p999 <= V2_BATCH_RELEASE_GATE_P999);
    assert!(mutation_p99 <= V2_BATCH_RELEASE_GATE_P99);
    assert!(mutation_p999 <= V2_BATCH_RELEASE_GATE_P999);
    let warm_read_p99_millis =
        u64::try_from(warm_p99.as_millis()).expect("warm p99 fits evidence milliseconds");
    let warm_read_p999_millis =
        u64::try_from(warm_p999.as_millis()).expect("warm p99.9 fits evidence milliseconds");
    let mutation_p99_millis =
        u64::try_from(mutation_p99.as_millis()).expect("mutation p99 fits evidence milliseconds");
    let mutation_p999_millis = u64::try_from(mutation_p999.as_millis())
        .expect("mutation p99.9 fits evidence milliseconds");
    assert!(warm_read_p99_millis <= SESSION_MTLS_BATCH_RELEASE_GATE_P99_CEILING_MILLIS);
    assert!(warm_read_p999_millis <= SESSION_MTLS_BATCH_RELEASE_GATE_P999_CEILING_MILLIS);
    assert!(mutation_p99_millis <= SESSION_MTLS_BATCH_RELEASE_GATE_P99_CEILING_MILLIS);
    assert!(mutation_p999_millis <= SESSION_MTLS_BATCH_RELEASE_GATE_P999_CEILING_MILLIS);

    // Snapshot after the exact 60k paced mutations plus 1,008 distributed
    // warm reads, before any fault or credential seam is introduced.
    let post_measured_load_diagnostics = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    assert_no_fault_v2_setup_delta(
        "60k paced mutations plus 1008 warm reads",
        &post_preload_restore_diagnostics,
        &post_measured_load_diagnostics,
    );
    let measured_diagnostics = post_measured_load_diagnostics;
    let configured_connections =
        (V2_BATCH_RELEASE_GATE_CLIENTS * V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT) as u64;
    assert_eq!(
        measured_diagnostics
            .iter()
            .map(|diagnostics| diagnostics.active)
            .sum::<u64>(),
        configured_connections,
        "authenticated V2 connection cardinality is fixed independently of operations or subscribers"
    );
    assert_eq!(
        measured_diagnostics
            .iter()
            .map(|diagnostics| diagnostics.idle)
            .sum::<u64>(),
        configured_connections,
        "every fixed V2 lane returns idle after measured work"
    );
    let recovered_lanes = u64::try_from(
        mutation_recovered_unknown
            .checked_add(mutation_not_transmitted_retries)
            .expect("bounded measured recovery count fits usize"),
    )
    .expect("bounded measured recovery count fits u64");
    let setup_delta = measured_diagnostics
        .iter()
        .zip(&measurement_baseline)
        .map(|(after, before)| {
            after
                .setup_successes
                .checked_sub(before.setup_successes)
                .expect("measured setup-success counter is monotonic")
        })
        .sum::<u64>();
    let reconnect_delta = measured_diagnostics
        .iter()
        .zip(&measurement_baseline)
        .map(|(after, before)| {
            after
                .reconnects
                .checked_sub(before.reconnects)
                .expect("measured reconnect counter is monotonic")
        })
        .sum::<u64>();
    let reused_delta = measured_diagnostics
        .iter()
        .zip(&measurement_baseline)
        .map(|(after, before)| {
            after
                .reused
                .checked_sub(before.reused)
                .expect("measured reuse counter is monotonic")
        })
        .sum::<u64>();
    assert!(
        setup_delta <= recovered_lanes,
        "only an exact typed safe/ambiguous boundary may re-establish a lane during measured work"
    );
    assert!(
        reconnect_delta <= recovered_lanes,
        "typed safe/ambiguous recovery cannot create a reconnect storm"
    );
    assert!(
        reused_delta
            >= u64::try_from(
                mutation_batch_count
                    .checked_add(V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES)
                    .expect("bounded measured call count fits usize"),
            )
            .expect("bounded call count fits u64"),
        "typed measured work reuses the prewarmed V2 pools"
    );
    assert!(measured_diagnostics.iter().all(|diagnostics| {
        diagnostics.setup_attempts == diagnostics.setup_successes + diagnostics.setup_failures
            && diagnostics.pool_wait_current == 0
            && diagnostics.pool_wait_max <= V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64
    }));

    let all_nodes = (0..MEMBER_COUNT).collect::<Vec<_>>();
    runtime.block_on(qualification_assert_v2_active_history(
        clients[0].clone(),
        scope,
        1 + V2_BATCH_RELEASE_GATE_PRELOAD_CREATES + V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
    ));
    let reports_before_loss = fleet.readiness_reports(&all_nodes);
    let old_leader_id = reports_before_loss
        .iter()
        .find_map(|report| report.leader_id)
        .expect("release-gate leader");
    let old_term = reports_before_loss[0].term;
    let leader_node_index = reports_before_loss
        .iter()
        .find_map(|report| (report.node_id == old_leader_id).then_some(report.node_index))
        .expect("leader endpoint index");
    let killed_endpoint_client_index = (0..clients.len())
        .find(|client_index| client_index % MEMBER_COUNT == leader_node_index)
        .expect("one original client is pinned to the killed endpoint");
    let killed_endpoint_before = clients[killed_endpoint_client_index].v2_diagnostics();
    resource_sampler.mark_offline(leader_node_index);
    let (leader_address, leader_process_id) = fleet.kill_node_unclean(leader_node_index);
    let survivors = all_nodes
        .iter()
        .copied()
        .filter(|node_index| *node_index != leader_node_index)
        .collect::<Vec<_>>();
    let recovery_deadline = Instant::now() + STATELESS_CONSUMER_LEADER_RECOVERY_TIMEOUT;
    let replacement = loop {
        let reports = fleet.readiness_reports(&survivors);
        if let Some(report) = reports.iter().find(|report| {
            report.ready
                && report
                    .leader_id
                    .is_some_and(|leader| leader != old_leader_id)
                && report.term > old_term
        }) {
            break report.node_index;
        }
        assert!(
            Instant::now() < recovery_deadline,
            "release-gate quorum did not elect a replacement leader"
        );
        thread::sleep(Duration::from_millis(50));
    };
    let status_after_loss = runtime.block_on(qualification_execute_v2_status_sample(
        clients
            .iter()
            .enumerate()
            .find_map(|(index, client)| (index % MEMBER_COUNT == replacement).then_some(client))
            .expect("client routed to replacement endpoint")
            .clone(),
        scope,
        first.clone(),
        Instant::now(),
    ));
    assert!(status_after_loss <= V2_BATCH_RELEASE_GATE_P999);
    fleet.spawn_node_at_manifest_address(leader_node_index, leader_address, leader_process_id);
    let restarted_process_id = fleet.nodes[leader_node_index].process_id();
    assert_ne!(
        restarted_process_id, leader_process_id,
        "restarted logical voter must install a distinct child PID"
    );
    resource_sampler.install_restarted_process(leader_node_index, restarted_process_id);
    let restart_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    while !fleet
        .readiness_reports(&all_nodes)
        .iter()
        .all(|report| report.ready)
    {
        assert!(
            Instant::now() < restart_deadline,
            "restarted release-gate leader did not regain readiness"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let (restarted_endpoint, _) =
        fleet.start_stateless_consumer(leader_node_index, consumer_identities.clone());
    endpoints
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)[leader_node_index] = restarted_endpoint;
    runtime.block_on(qualification_execute_v2_status_sample(
        clients[killed_endpoint_client_index].clone(),
        scope,
        first.clone(),
        Instant::now(),
    ));
    let killed_endpoint_after = clients[killed_endpoint_client_index].v2_diagnostics();
    assert_eq!(
        killed_endpoint_after.active, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
        "the client pinned to the killed endpoint restores all four active lanes"
    );
    assert_eq!(
        killed_endpoint_after.idle, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
        "the client pinned to the killed endpoint restores all four idle lanes"
    );
    let killed_endpoint_reconnect_delta = killed_endpoint_after
        .reconnects
        .checked_sub(killed_endpoint_before.reconnects)
        .expect("killed-endpoint reconnect counter is monotonic");
    assert!(
        (1..=V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64)
            .contains(&killed_endpoint_reconnect_delta),
        "the client pinned to the killed endpoint reconnects each lost lane at most once"
    );
    runtime.block_on(qualification_assert_v2_active_history(
        clients[0].clone(),
        scope,
        1 + V2_BATCH_RELEASE_GATE_PRELOAD_CREATES + V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
    ));

    // The replacement alone receives a new-root leaf while every member has
    // already published old+new trust. Exactly the four clients pinned to
    // that member move to new-root-only trust; the other eight stay
    // old-root-only and continue to use their old-root server leaves.
    fleet.transition_member(
        replacement,
        CredentialGeneration::NewRoot,
        TrustGeneration::Overlap,
        "v2-batch-replacement-new-root-overlap",
    );
    let new_only_client_indices = (0..clients.len())
        .filter(|client_index| client_index % MEMBER_COUNT == replacement)
        .collect::<Vec<_>>();
    assert_eq!(
        new_only_client_indices.len(),
        V2_BATCH_RELEASE_GATE_CLIENTS / MEMBER_COUNT,
        "exactly four fixed V2 clients are routed to the replacement member"
    );
    let rotation_before = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    for (client_index, ((sender, identity), client)) in identity_senders
        .iter()
        .zip(&consumer_identities)
        .zip(&clients)
        .enumerate()
    {
        let trust_generation = if client_index % MEMBER_COUNT == replacement {
            TrustGeneration::NewOnly
        } else {
            TrustGeneration::OldOnly
        };
        sender
            .send(Some(fleet.pki.consumer_identity_state_with_trust(
                identity,
                trust_generation,
            )))
            .expect("live V2 client identity source remains subscribed");
        client
            .request_reauthentication()
            .expect("request fixed V2 pool credential drain");
    }
    let refreshed_status_samples = runtime.block_on(async {
        futures_util::future::join_all(clients.iter().map(|client| async {
            client
                .prewarm_v2()
                .await
                .expect("re-establish fixed V2 pool after SVID rotation");
            qualification_execute_v2_status_sample(
                client.clone(),
                scope,
                first.clone(),
                Instant::now(),
            )
            .await
        }))
        .await
    });
    assert_eq!(
        refreshed_status_samples.len(),
        V2_BATCH_RELEASE_GATE_CLIENTS,
        "every original fixed V2 client completed an exact post-rotation status request"
    );
    assert_eq!(
        new_only_client_indices.len(),
        V2_BATCH_RELEASE_GATE_CLIENTS / MEMBER_COUNT,
        "the exact NewOnly status validation is server-observed for each replacement-routed client"
    );
    let rotation_refreshed = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    for client_index in &new_only_client_indices {
        let before = rotation_before[*client_index];
        let after = rotation_refreshed[*client_index];
        assert!(
            after.setup_successes
                >= before
                    .setup_successes
                    .checked_add(
                        u64::try_from(V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT)
                            .expect("fixed lane count fits u64"),
                    )
                    .expect("new-only setup-success lower bound fits u64"),
            "each replacement-routed new-only client must authenticate four fresh new-root credential lanes"
        );
        assert_eq!(after.active, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64);
        assert_eq!(after.idle, V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64);
    }

    // Release exactly one original replacement-routed four-lane pool. The
    // replacement listener therefore has 12 admitted original lanes and four
    // explicitly bounded seam slots; neither negative nor delayed work can
    // be mistaken for a capacity rejection or raise the fleet above 48.
    let seam_client_index = *new_only_client_indices
        .first()
        .expect("one replacement-routed original V2 client");
    let released_original_before_shutdown = clients[seam_client_index].v2_diagnostics();
    runtime.block_on(clients[seam_client_index].shutdown());
    let original_lanes_after_release = clients
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != seam_client_index)
        .filter(|(index, _)| index % MEMBER_COUNT == replacement)
        .map(|(_, client)| client.v2_diagnostics().active)
        .sum::<u64>();
    assert_eq!(
        original_lanes_after_release, 12,
        "releasing one original replacement-routed pool leaves exactly four normal lanes below the twenty-connection listener admission limit"
    );

    // All consensus-bearing work is complete.  Make this listener genuinely
    // new-root-only before exercising the old-credential seam: publishing it
    // directly preserves the already-established cluster peer channels while
    // changing the listener's independently selected trust generation.
    let replacement_source_before = fleet.projected_status(replacement);
    let replacement_controller_before = fleet.material_status(replacement);
    fleet.publish_known_projected_generation(
        replacement,
        CredentialGeneration::NewRoot,
        TrustGeneration::NewOnly,
        "v2-batch-replacement-new-only-credential-negative",
    );
    fleet.wait_for_member_publication(
        replacement,
        replacement_source_before.generation,
        replacement_controller_before.epoch,
    );
    let old_credential_new_only_server_rejections_before =
        fleet.consumer_tls_peer_credential_rejections(replacement);
    let (_old_leaf_identity_source, old_leaf_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        replacement,
        voter_authorities[replacement].clone(),
        fleet.pki.consumer_identity_state_with_generations(
            &consumer_identities[seam_client_index],
            ConsumerCredentialGeneration::OldRoot,
            // The client retains overlap trust so it verifies the new server
            // leaf; only its presented credential is intentionally old.
            TrustGeneration::Overlap,
        ),
        credential_negative_pool_config,
        None,
    );
    let old_credential_new_only_server_result = runtime.block_on(old_leaf_client.prewarm_v2());
    assert!(
        matches!(
            old_credential_new_only_server_result,
            Err(SessionConsumerClientError::Authentication
                | SessionConsumerClientError::Unavailable)
        ),
        "old credential/new-only server negative must expose only typed authentication or unavailable"
    );
    runtime.block_on(old_leaf_client.shutdown());
    let old_leaf_diagnostics = old_leaf_client.v2_diagnostics();
    assert_eq!(old_leaf_diagnostics.setup_attempts, 1);
    assert_eq!(old_leaf_diagnostics.setup_failures, 1);
    assert_eq!(old_leaf_diagnostics.setup_successes, 0);
    assert_eq!(old_leaf_diagnostics.active, 0);
    assert_eq!(old_leaf_diagnostics.idle, 0);
    assert_eq!(old_leaf_diagnostics.pool_wait_current, 0);
    let old_credential_new_only_server_tls_peer_credential_rejected = fleet
        .consumer_tls_peer_credential_rejections(replacement)
        == old_credential_new_only_server_rejections_before
            .checked_add(1)
            .expect("release-gate peer-credential rejection counter remains below u64 maximum");
    assert!(
        old_credential_new_only_server_tls_peer_credential_rejected,
        "old credential/new-only server negative produces exactly one local TLS peer-credential rejection"
    );

    let (_delayed_identity_source, delayed_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        replacement,
        voter_authorities[replacement].clone(),
        fleet.pki.consumer_identity_state_with_trust(
            &consumer_identities[seam_client_index],
            TrustGeneration::NewOnly,
        ),
        pool_config,
        None,
    );
    runtime
        .block_on(delayed_client.prewarm_v2())
        .expect("prewarm the released-slot delayed-response V2 client");
    let delayed_prewarmed_diagnostics = delayed_client.v2_diagnostics();
    assert_eq!(delayed_prewarmed_diagnostics.active, 4);
    assert_eq!(
        original_lanes_after_release + delayed_prewarmed_diagnostics.active,
        16,
        "the replacement listener returns to its fixed sixteen normal connections before the bounded headroom probe"
    );
    let ambiguous_requests = runtime.block_on(qualification_build_v2_batches(
        MEMBER_COUNT,
        1 + V2_BATCH_RELEASE_GATE_PRELOAD_CREATES + V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
        V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE,
        V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE,
    ));
    let ambiguous_requests = ambiguous_requests
        .into_iter()
        .next()
        .expect("one bounded ambiguity batch");
    let pressure_requests = runtime.block_on(qualification_build_v2_batches(
        MEMBER_COUNT,
        1 + V2_BATCH_RELEASE_GATE_PRELOAD_CREATES
            + V2_BATCH_RELEASE_GATE_PACED_MUTATIONS
            + ambiguous_requests.len(),
        V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE,
        V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE,
    ));
    let pressure_requests = pressure_requests
        .into_iter()
        .next()
        .expect("one fresh bounded pressure batch");
    let ambiguous_request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Batch {
            requests: ambiguous_requests.clone(),
        },
    );
    let pressure_request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Batch {
            requests: pressure_requests.clone(),
        },
    );
    let ambiguous_request_ids = ambiguous_requests
        .iter()
        .map(FencedTransitionV2Request::request_id)
        .collect::<Vec<_>>();
    let mut causal_attempt_ledger = V2BatchAttemptLedger::new(&ambiguous_requests);
    // This one-lane client is the causal ambiguity witness. Its caller
    // deadline is intentionally shorter than the normal default; it is not a
    // load knob and cannot increase any release timeout.
    let (causal_identity_source, causal_ambiguity_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        replacement,
        voter_authorities[replacement].clone(),
        fleet.pki.consumer_identity_state_with_generations(
            &consumer_identities[seam_client_index],
            ConsumerCredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
        ),
        credential_negative_pool_config,
        Some(V2_BATCH_RELEASE_GATE_CAUSAL_AMBIGUITY_OPERATION_TIMEOUT),
    );
    runtime
        .block_on(causal_ambiguity_client.prewarm_v2())
        .expect("prewarm the one-lane causal ambiguity witness");
    let pressure_family_deadline =
        tokio::time::Instant::now() + V2_BATCH_RELEASE_GATE_AMBIGUITY_RECOVERY_TIMEOUT;
    // The separately keyed causal witness is held only after its durable
    // mutation completes. It has its own one-lane pool and must not consume
    // any of the four fixed pressure lanes below.
    fleet.arm_stateless_consumer_ambiguity_witness_hold(replacement);
    let causal_ambiguous_request = ambiguous_request.clone();
    causal_attempt_ledger.record_mutation_dispatch();
    let causal_pressure_holder = runtime.spawn({
        let client = causal_ambiguity_client.clone();
        async move { client.execute_v2(&causal_ambiguous_request).await }
    });
    let causal_hold_ack_deadline = Instant::now() + V2_BATCH_RELEASE_GATE_HOLD_ACK_TIMEOUT;
    runtime.block_on(async {
        loop {
            let (armed_responses, held_responses) =
                fleet.stateless_consumer_ambiguity_witness_hold_status(replacement);
            if armed_responses == 0 && held_responses == 1 {
                break;
            }
            assert!(
                Instant::now() < causal_hold_ack_deadline,
                "causal witness did not acknowledge its one durable held response: armed={armed_responses}, held={held_responses}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let causal_pressure_outcome = runtime
        .block_on(causal_pressure_holder)
        .expect("causal ambiguity witness task joins");
    assert!(
        matches!(
            causal_pressure_outcome,
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch { ref request_ids })
                if *request_ids == ambiguous_request_ids
        ),
        "the acknowledged post-durability witness hold must expire the designated caller into OutcomeUnknown"
    );
    causal_attempt_ledger.record_durable_acceptance();
    causal_attempt_ledger.record_mutation_terminal(V2BatchMutationTerminal::OutcomeUnknown);
    assert!(
        tokio::time::Instant::now() < pressure_family_deadline,
        "status classification retains the deadline captured before designated mutation dispatch"
    );
    fleet.release_stateless_consumer_ambiguity_witness_hold(replacement);
    let non_slow_client_index = (seam_client_index + 1) % clients.len();
    // The designated twelve IDs are now durable and OutcomeUnknown. Resolve
    // them immediately, exactly once, through the read-only status surface;
    // every later pressure mutation uses the fresh family below.
    let ambiguity_status_retries =
        runtime.block_on(qualification_resolve_v2_batch_outcome_unknown(
            &clients[non_slow_client_index],
            scope,
            &ambiguous_requests,
            pressure_family_deadline,
            &mut causal_attempt_ledger,
        ));
    assert_eq!(
        ambiguity_status_retries.terminal_attempts,
        ambiguous_requests.len(),
        "one terminal read-only receipt is recorded for each designated ambiguous ID"
    );
    assert_eq!(
        causal_attempt_ledger.outcome_unknown_cardinality(),
        ambiguous_requests.len(),
        "every retained ambiguous ID is accounted for by the actual mutation seam"
    );
    assert!(
        causal_attempt_ledger
            .entries
            .iter()
            .all(|entry| entry.mutation_attempts == 1
                && entry.status_attempts >= 1
                && entry.status_terminal),
        "the exact ambiguous IDs are mutation-dispatched once and then status-only"
    );
    assert_eq!(
        causal_attempt_ledger.post_outcome_unknown_mutation_dispatches(),
        0,
        "no OutcomeUnknown ID is ever mutation-replayed"
    );

    // Four delayed in-flight calls occupy the exact fixed request-lane
    // width. The next 64 calls then occupy the fixed caller queue, and the
    // 69th admission must fail immediately with typed backpressure. These
    // are logical callers only: the prewarmed four-lane pool opens no extra
    // physical connections and server queue depth remains unmeasured.
    assert_eq!(
        V2_BATCH_RELEASE_GATE_OVER_CAPACITY_CALLS,
        V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT + V2_BATCH_RELEASE_GATE_PENDING_CALLS + 1
    );
    let delayed_setup_before_pressure = delayed_client.v2_diagnostics();
    fleet.arm_stateless_consumer_response_holds(replacement);
    let mut pressure_holders = Vec::with_capacity(V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT);
    for _ in 0..V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT {
        let client = delayed_client.clone();
        let request = pressure_request.clone();
        pressure_holders.push(runtime.spawn(async move { client.execute_v2(&request).await }));
    }
    // Enqueue every bounded pressure caller before yielding for any held
    // response acknowledgement. This prevents the pressure phase from
    // submitting copies after a server has accepted the shared request IDs:
    // only the first four lane admissions may reach the listener, while the
    // remaining callers are already bounded in the client queue.
    let mut queued_pressure_calls = Vec::with_capacity(V2_BATCH_RELEASE_GATE_PENDING_CALLS);
    for _ in 0..V2_BATCH_RELEASE_GATE_PENDING_CALLS {
        let client = delayed_client.clone();
        let request = pressure_request.clone();
        queued_pressure_calls.push(runtime.spawn(async move { client.execute_v2(&request).await }));
    }
    let queued_caller_count = queued_pressure_calls.len();
    let hold_ack_deadline = Instant::now() + V2_BATCH_RELEASE_GATE_HOLD_ACK_TIMEOUT;
    let held_response_count = runtime.block_on(async {
        loop {
            let (armed_responses, held_responses) =
                fleet.stateless_consumer_response_hold_status(replacement);
            if armed_responses == 0 && held_responses == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT {
                break held_responses;
            }
            assert!(
                Instant::now() < hold_ack_deadline,
                "cross-process response-hold acknowledgement did not observe all four durable V2 executions: armed={armed_responses}, held={held_responses}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    runtime.block_on(qualification_execute_v2_status_sample(
        clients[non_slow_client_index].clone(),
        scope,
        pressure_requests[0].clone(),
        Instant::now(),
    ));
    let cross_client_fair_progress = 1;
    let queue_pressure_deadline = Instant::now() + V2_BATCH_RELEASE_GATE_HOLD_ACK_TIMEOUT;
    let pressure_queued = runtime.block_on(async {
        loop {
            let diagnostics = delayed_client.v2_diagnostics();
            if diagnostics.pool_wait_current == V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64
                && diagnostics.pool_wait_max == V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64
            {
                break diagnostics;
            }
            assert!(
                Instant::now() < queue_pressure_deadline,
                "bounded four-lane hold did not fill the exact 64-caller queue: diagnostics={diagnostics:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    assert_eq!(
        pressure_queued.pool_wait_current, V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
        "the deliberate over-capacity probe fills exactly the fixed per-pool caller queue"
    );
    assert_eq!(
        pressure_queued.pool_wait_max, V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
        "the deliberate over-capacity probe records the exact fixed queue high-water"
    );
    assert_eq!(
        delayed_client.v2_diagnostics().pool_wait_current,
        V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
        "an independent client progresses while the slow pool's four real lanes remain saturated"
    );
    let mut overload_attempt_ledger = V2BatchAttemptLedger::new(&pressure_requests);
    overload_attempt_ledger.record_mutation_dispatch();
    let over_capacity_result = runtime.block_on(delayed_client.execute_v2(&pressure_request));
    assert!(
        matches!(
            over_capacity_result,
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Overloaded,
            })
        ),
        "the 69th fixed-pool caller is rejected as typed not-transmitted overload"
    );
    overload_attempt_ledger.record_mutation_terminal(V2BatchMutationTerminal::NotTransmitted(
        SessionConsumerClientError::Overloaded,
    ));
    assert_eq!(
        overload_attempt_ledger.actual_redispatches(),
        0,
        "typed overload remains its one existing backpressure event, never a retry"
    );
    assert_eq!(
        pressure_holders.len(),
        V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT
    );
    assert_eq!(queued_caller_count, V2_BATCH_RELEASE_GATE_PENDING_CALLS);
    assert_eq!(
        pressure_holders.len() + queued_caller_count + 1,
        V2_BATCH_RELEASE_GATE_OVER_CAPACITY_CALLS,
        "four held lanes plus 64 queued callers make the next call exactly the 69th admission"
    );
    fleet.release_stateless_consumer_response_holds(replacement);
    let released_response_count = held_response_count
        .checked_add(1)
        .expect("causal plus pressure held-response accounting fits usize");
    let recovered_queued_caller_count = queued_pressure_calls.len();
    let pressure_results = runtime.block_on(async {
        let holders = futures_util::future::join_all(pressure_holders).await;
        let queued = futures_util::future::join_all(queued_pressure_calls).await;
        holders.into_iter().chain(queued).collect::<Vec<_>>()
    });
    let mut admitted_pressure_responses = 0usize;
    for result in pressure_results {
        let outcome = result.expect("every held or queued V2 caller task joins without panic");
        match outcome {
            Ok(response) => {
                qualification_assert_v2_batch_response(&pressure_requests, response).expect(
                    "every admitted released pressure caller returns its exact durable response",
                );
                admitted_pressure_responses = admitted_pressure_responses
                    .checked_add(1)
                    .expect("bounded admitted pressure responses fit usize");
            }
            Err(error) => {
                panic!("admitted pressure caller returned a non-recorded outcome: {error:?}")
            }
        }
    }
    assert_eq!(
        admitted_pressure_responses,
        V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT + V2_BATCH_RELEASE_GATE_PENDING_CALLS,
        "every admitted pressure caller joins before it is counted and records the exact response"
    );
    let exact_active_history_entries = 1usize
        .checked_add(V2_BATCH_RELEASE_GATE_PRELOAD_CREATES)
        .and_then(|total| total.checked_add(V2_BATCH_RELEASE_GATE_PACED_MUTATIONS))
        .and_then(|total| total.checked_add(ambiguous_requests.len()))
        .and_then(|total| total.checked_add(pressure_requests.len()))
        .expect("fixed unique request history fits usize");
    assert_eq!(exact_active_history_entries, 110_025);
    runtime.block_on(qualification_assert_v2_active_history(
        clients[non_slow_client_index].clone(),
        scope,
        exact_active_history_entries,
    ));
    let durable_status_cardinality = causal_attempt_ledger.outcome_unknown_cardinality();
    let pressure_settled = delayed_client.v2_diagnostics();
    assert_eq!(pressure_settled.pool_wait_current, 0);
    assert_eq!(
        pressure_settled.pool_wait_max, V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
        "pressure recovery retains, rather than erases, the exact queue high-water"
    );
    assert_eq!(
        pressure_settled.setup_attempts, delayed_setup_before_pressure.setup_attempts,
        "typed caller backpressure does not create a resolve, TCP, TLS, or Hello attempt"
    );
    runtime
        .block_on(delayed_client.prewarm_v2())
        .expect("the fixed delayed pool recovers after typed overload");
    runtime.block_on(qualification_execute_v2_status_sample(
        delayed_client.clone(),
        scope,
        pressure_requests[0].clone(),
        Instant::now(),
    ));
    let pressure_recovered = delayed_client.v2_diagnostics();
    assert_eq!(
        pressure_recovered.setup_attempts, delayed_setup_before_pressure.setup_attempts,
        "the recovered fixed pool retains its four prewarmed physical lanes"
    );
    assert_eq!(
        pressure_recovered.active,
        V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
    );
    assert_eq!(
        pressure_recovered.idle,
        V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
    );
    runtime.block_on(delayed_client.shutdown());
    let delayed_after_ambiguity = delayed_client.v2_diagnostics();
    assert_eq!(
        delayed_after_ambiguity.setup_attempts,
        delayed_after_ambiguity.setup_successes + delayed_after_ambiguity.setup_failures,
        "the supplemental delayed probe accounts for every physical lane setup"
    );
    assert_eq!(delayed_after_ambiguity.active, 0);
    assert_eq!(delayed_after_ambiguity.idle, 0);
    assert_eq!(delayed_after_ambiguity.pool_wait_current, 0);
    assert_eq!(
        delayed_after_ambiguity.pool_wait_max, V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
        "the post-shutdown delayed-pool diagnostic serializes the exact fixed overload high-water"
    );
    runtime.block_on(causal_ambiguity_client.shutdown());
    drop(causal_identity_source);
    let causal_after_ambiguity = causal_ambiguity_client.v2_diagnostics();
    assert_eq!(causal_after_ambiguity.active, 0);
    assert_eq!(causal_after_ambiguity.idle, 0);
    assert_eq!(causal_after_ambiguity.pool_wait_current, 0);
    // The delayed-response supplemental ledger includes the designated
    // one-lane causal witness, so every listener-admission setup remains in
    // the closed release evidence rather than becoming an untracked probe.
    let mut delayed_after_ambiguity = delayed_after_ambiguity;
    delayed_after_ambiguity.setup_attempts = delayed_after_ambiguity
        .setup_attempts
        .checked_add(causal_after_ambiguity.setup_attempts)
        .expect("causal setup-attempt accounting fits u64");
    delayed_after_ambiguity.setup_failures = delayed_after_ambiguity
        .setup_failures
        .checked_add(causal_after_ambiguity.setup_failures)
        .expect("causal setup-failure accounting fits u64");
    delayed_after_ambiguity.setup_successes = delayed_after_ambiguity
        .setup_successes
        .checked_add(causal_after_ambiguity.setup_successes)
        .expect("causal setup-success accounting fits u64");
    delayed_after_ambiguity.reused = delayed_after_ambiguity
        .reused
        .checked_add(causal_after_ambiguity.reused)
        .expect("causal reuse accounting fits u64");
    delayed_after_ambiguity.reconnects = delayed_after_ambiguity
        .reconnects
        .checked_add(causal_after_ambiguity.reconnects)
        .expect("causal reconnect accounting fits u64");
    let (restored_identity_source, restored_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        replacement,
        voter_authorities[replacement].clone(),
        fleet.pki.consumer_identity_state_with_trust(
            &consumer_identities[seam_client_index],
            TrustGeneration::NewOnly,
        ),
        pool_config,
        None,
    );
    runtime
        .block_on(restored_client.prewarm_v2())
        .expect("restore the released original four-lane replacement pool");
    clients[seam_client_index] = restored_client;
    drop(restored_identity_source);
    let old_root_server = (replacement + 1) % MEMBER_COUNT;
    let old_root_seam_client_index = (0..clients.len())
        .find(|client_index| client_index % MEMBER_COUNT == old_root_server)
        .expect("old-root client pool");
    let released_old_root_before_shutdown = clients[old_root_seam_client_index].v2_diagnostics();
    runtime.block_on(clients[old_root_seam_client_index].shutdown());
    let old_root_lanes_after_release = clients
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != old_root_seam_client_index)
        .filter(|(index, _)| index % MEMBER_COUNT == old_root_server)
        .map(|(_, client)| client.v2_diagnostics().active)
        .sum::<u64>();
    assert_eq!(
        old_root_lanes_after_release, 12,
        "releasing one old-root pool leaves exactly four normal lanes below the twenty-connection listener admission limit for the credential negative"
    );
    // Likewise select OldOnly at the second listener only after all quorum
    // activity has ended.  Its retained old-root clients continue to trust its
    // old server leaf, while the supplemental client presents only new-root.
    let old_root_source_before = fleet.projected_status(old_root_server);
    let old_root_controller_before = fleet.material_status(old_root_server);
    fleet.publish_known_projected_generation(
        old_root_server,
        CredentialGeneration::Initial,
        TrustGeneration::OldOnly,
        "v2-batch-old-root-server-credential-negative",
    );
    fleet.wait_for_member_publication(
        old_root_server,
        old_root_source_before.generation,
        old_root_controller_before.epoch,
    );
    let new_credential_old_root_server_rejections_before =
        fleet.consumer_tls_peer_credential_rejections(old_root_server);
    let (_new_only_identity_source, new_only_old_root_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        old_root_server,
        voter_authorities[old_root_server].clone(),
        fleet.pki.consumer_identity_state_with_generations(
            &consumer_identities[old_root_seam_client_index],
            ConsumerCredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
        ),
        credential_negative_pool_config,
        None,
    );
    let new_credential_old_root_server_result =
        runtime.block_on(new_only_old_root_client.prewarm_v2());
    assert!(
        matches!(
            new_credential_old_root_server_result,
            Err(SessionConsumerClientError::Authentication
                | SessionConsumerClientError::Unavailable)
        ),
        "new credential/old-root server negative must expose only typed authentication or unavailable"
    );
    runtime.block_on(new_only_old_root_client.shutdown());
    let new_only_old_root_diagnostics = new_only_old_root_client.v2_diagnostics();
    assert_eq!(new_only_old_root_diagnostics.setup_attempts, 1);
    assert_eq!(new_only_old_root_diagnostics.setup_failures, 1);
    assert_eq!(new_only_old_root_diagnostics.setup_successes, 0);
    assert_eq!(new_only_old_root_diagnostics.active, 0);
    assert_eq!(new_only_old_root_diagnostics.idle, 0);
    assert_eq!(new_only_old_root_diagnostics.pool_wait_current, 0);
    let new_credential_old_root_server_tls_peer_credential_rejected = fleet
        .consumer_tls_peer_credential_rejections(old_root_server)
        == new_credential_old_root_server_rejections_before
            .checked_add(1)
            .expect("release-gate peer-credential rejection counter remains below u64 maximum");
    assert!(
        new_credential_old_root_server_tls_peer_credential_rejected,
        "new credential/old-root server negative produces exactly one local TLS peer-credential rejection"
    );
    let (restored_old_root_identity_source, restored_old_root_client) =
        qualification_persistent_v2_client(
            Arc::clone(&endpoints),
            old_root_server,
            voter_authorities[old_root_server].clone(),
            fleet.pki.consumer_identity_state_with_trust(
                &consumer_identities[old_root_seam_client_index],
                TrustGeneration::OldOnly,
            ),
            pool_config,
            None,
        );
    runtime
        .block_on(restored_old_root_client.prewarm_v2())
        .expect("restore old-root pool");
    clients[old_root_seam_client_index] = restored_old_root_client;
    drop(restored_old_root_identity_source);

    runtime.block_on(qualification_assert_v2_active_history(
        clients[0].clone(),
        scope,
        exact_active_history_entries,
    ));

    let restored_seam_current = clients[seam_client_index].v2_diagnostics();
    let restored_old_root_current = clients[old_root_seam_client_index].v2_diagnostics();
    // This post-recovery/seam snapshot folds retired generations into the two
    // restored original pools, so neither their reconnect/setup counters nor
    // their queue high-water marks disappear at replacement.
    let mut after_recovery = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    after_recovery[seam_client_index] = cumulative_replaced_v2_diagnostics(
        released_original_before_shutdown,
        restored_seam_current,
    );
    after_recovery[old_root_seam_client_index] = cumulative_replaced_v2_diagnostics(
        released_old_root_before_shutdown,
        restored_old_root_current,
    );
    assert_eq!(
        after_recovery
            .iter()
            .map(|diagnostics| diagnostics.active)
            .sum::<u64>(),
        configured_connections,
        "recovery retains the fixed authenticated V2 connection cardinality"
    );
    assert_eq!(
        after_recovery
            .iter()
            .map(|diagnostics| diagnostics.idle)
            .sum::<u64>(),
        configured_connections,
        "recovery drains back to the fixed idle V2 width"
    );
    for (client_index, (before, after)) in prewarmed.iter().zip(&after_recovery).enumerate() {
        assert!(
            after.setup_attempts >= before.setup_attempts
                && after.setup_failures >= before.setup_failures
                && after.setup_successes >= before.setup_successes
                && after.reused >= before.reused
                && after.reconnects >= before.reconnects,
            "settled V2 counters are monotonic: client_index={client_index}"
        );
        assert_eq!(
            after.setup_attempts,
            after.setup_successes + after.setup_failures,
            "settled V2 setup attempts are accounted exactly: client_index={client_index}"
        );
        assert_eq!(
            after.pool_wait_current, 0,
            "settled V2 pool has no queued callers: client_index={client_index}"
        );
        assert!(
            after.pool_wait_max <= V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
            "V2 pool queue high-water remains within its configured bound: client_index={client_index}"
        );
    }
    assert!(
        after_recovery
            .iter()
            .map(|diagnostics| diagnostics.setup_successes)
            .sum::<u64>()
            <= configured_connections
                .checked_mul(3)
                .expect("fixed setup-storm ceiling fits u64"),
        "one endpoint loss and one SVID rotation cannot create an unbounded setup storm"
    );
    assert!(
        after_recovery
            .iter()
            .map(|diagnostics| diagnostics.reconnects)
            .sum::<u64>()
            <= configured_connections,
        "one bounded recovery cannot discard more than the fixed V2 lanes"
    );
    // Evidence carries cumulative client lifecycle counters, including the
    // initial 48-lane prewarm; it does not subtract the baseline away.
    let original_setup_attempts = after_recovery
        .iter()
        .map(|diagnostics| diagnostics.setup_attempts)
        .sum::<u64>();
    let original_setup_failures = after_recovery
        .iter()
        .map(|diagnostics| diagnostics.setup_failures)
        .sum::<u64>();
    let original_setup_successes = after_recovery
        .iter()
        .map(|diagnostics| diagnostics.setup_successes)
        .sum::<u64>();
    let supplemental_setup_attempt_delta = delayed_after_ambiguity
        .setup_attempts
        .checked_add(old_leaf_diagnostics.setup_attempts)
        .and_then(|total| total.checked_add(new_only_old_root_diagnostics.setup_attempts))
        .expect("supplemental setup-attempt accounting fits u64");
    let supplemental_setup_failure_delta = delayed_after_ambiguity
        .setup_failures
        .checked_add(old_leaf_diagnostics.setup_failures)
        .and_then(|total| total.checked_add(new_only_old_root_diagnostics.setup_failures))
        .expect("supplemental setup-failure accounting fits u64");
    let supplemental_setup_success_delta = delayed_after_ambiguity
        .setup_successes
        .checked_add(old_leaf_diagnostics.setup_successes)
        .and_then(|total| total.checked_add(new_only_old_root_diagnostics.setup_successes))
        .expect("supplemental setup-success accounting fits u64");
    let setup_attempts = original_setup_attempts
        .checked_add(supplemental_setup_attempt_delta)
        .expect("total setup-attempt accounting fits u64");
    let setup_failures = original_setup_failures
        .checked_add(supplemental_setup_failure_delta)
        .expect("total setup-failure accounting fits u64");
    let setup_successes = original_setup_successes
        .checked_add(supplemental_setup_success_delta)
        .expect("total setup-success accounting fits u64");
    let observed_setup_accounting = MtlsSetupAccounting {
        original_and_restored: SetupAccounting {
            attempts: original_setup_attempts,
            failures: original_setup_failures,
        },
        supplemental: SetupAccounting {
            attempts: supplemental_setup_attempt_delta,
            failures: supplemental_setup_failure_delta,
        },
    };
    let setup_ceilings = v2_batch_release_gate_setup_ceilings();
    let total_setup_accounting = observed_setup_accounting.total();
    println!(
        "V2_BATCH_RELEASE_GATE_MTLS_SETUP_ACCOUNTING original_and_restored_attempts={} original_and_restored_attempt_bound={} original_and_restored_failures={} original_and_restored_failure_bound={} supplemental_attempts={} supplemental_attempt_bound={} supplemental_failures={} supplemental_failure_bound={} total_attempts={} total_attempt_bound={} total_failures={} total_failure_bound={}",
        observed_setup_accounting.original_and_restored.attempts,
        setup_ceilings.original_and_restored.attempts,
        observed_setup_accounting.original_and_restored.failures,
        setup_ceilings.original_and_restored.failures,
        observed_setup_accounting.supplemental.attempts,
        setup_ceilings.supplemental.attempts,
        observed_setup_accounting.supplemental.failures,
        setup_ceilings.supplemental.failures,
        total_setup_accounting.attempts,
        setup_ceilings.total.attempts,
        total_setup_accounting.failures,
        setup_ceilings.total.failures,
    );
    verify_mtls_setup_accounting(observed_setup_accounting, setup_ceilings)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        setup_attempts,
        setup_successes + setup_failures,
        "release-gate setup deltas conserve every physical V2 lane attempt"
    );
    // The normal fleet deliberately holds exactly sixteen persistent lanes at
    // each listener.  Open one independent projected-mTLS/Hello status lane
    // per node, while those normal lanes remain live, so the process-local
    // listener counter proves a positive (but still bounded) server margin.
    // This is admission evidence, not a client-pool inference.
    let headroom_pool_config = PersistentSessionConsumerConfig::try_new(
        1,
        0,
        Duration::from_millis(250),
        1,
        Duration::from_millis(1_500),
        1,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("one-lane server-headroom probe has fixed bounded setup");
    let mut headroom_probes = Vec::with_capacity(MEMBER_COUNT);
    let mut normal_headroom_high_water_connections = [0usize; MEMBER_COUNT];
    // Capacity is exercised at the logical voter that was actually killed
    // and restarted, not merely at the survivor elected as temporary leader.
    // This binds the 16→17→20→typed-unavailable21→16 sequence to the only
    // doubled process-generation record.
    let capacity_probe_node = leader_node_index;
    let normal_before_capacity = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    for node_index in 0..MEMBER_COUNT {
        let (credential_generation, trust_generation) = if node_index == replacement {
            (
                ConsumerCredentialGeneration::NewRoot,
                TrustGeneration::NewOnly,
            )
        } else if node_index == old_root_server {
            (
                ConsumerCredentialGeneration::OldRoot,
                TrustGeneration::OldOnly,
            )
        } else {
            (
                ConsumerCredentialGeneration::OldRoot,
                TrustGeneration::Overlap,
            )
        };
        let (identity_source, probe) = qualification_persistent_v2_client(
            Arc::clone(&endpoints),
            node_index,
            voter_authorities[node_index].clone(),
            fleet.pki.consumer_identity_state_with_generations(
                &consumer_identities[node_index],
                credential_generation,
                trust_generation,
            ),
            headroom_pool_config,
            None,
        );
        runtime
            .block_on(probe.prewarm_v2())
            .expect("the seventeenth listener connection is admitted");
        runtime.block_on(qualification_execute_v2_status_sample(
            probe.clone(),
            scope,
            first.clone(),
            Instant::now(),
        ));
        let admitted = fleet.stateless_consumer_admission_status(node_index);
        assert_eq!(admitted.active_connections, 17);
        assert_eq!(admitted.high_water_connections, 17);
        assert_eq!(admitted.admission_limit, 20);
        assert_eq!(admitted.admission_rejections, 0);
        normal_headroom_high_water_connections[node_index] = admitted.high_water_connections;
        headroom_probes.push((identity_source, probe));
    }
    // Keep the seventeenth connection at one chosen listener and fill only
    // its remaining three permits.  The next projected-mTLS/Hello setup must
    // be rejected by the listener without evicting any of the sixteen normal
    // lanes.  The monotonic process counter records this deliberate capacity
    // phase separately from the normal-headroom phase below.
    let capacity_before = fleet.stateless_consumer_admission_status(capacity_probe_node);
    let (capacity_credential_generation, capacity_trust_generation) =
        if capacity_probe_node == replacement {
            (
                ConsumerCredentialGeneration::NewRoot,
                TrustGeneration::NewOnly,
            )
        } else {
            (
                ConsumerCredentialGeneration::OldRoot,
                TrustGeneration::Overlap,
            )
        };
    let mut capacity_probes = Vec::with_capacity(3);
    for _ in 0..3 {
        let (identity_source, probe) = qualification_persistent_v2_client(
            Arc::clone(&endpoints),
            capacity_probe_node,
            voter_authorities[capacity_probe_node].clone(),
            fleet.pki.consumer_identity_state_with_generations(
                &consumer_identities[capacity_probe_node],
                capacity_credential_generation,
                capacity_trust_generation,
            ),
            headroom_pool_config,
            None,
        );
        runtime
            .block_on(probe.prewarm_v2())
            .expect("the bounded listener capacity probe admits connections 18 through 20");
        runtime.block_on(qualification_execute_v2_status_sample(
            probe.clone(),
            scope,
            first.clone(),
            Instant::now(),
        ));
        capacity_probes.push((identity_source, probe));
    }
    let capacity_full = fleet.stateless_consumer_admission_status(capacity_probe_node);
    assert_eq!(capacity_full.active_connections, 20);
    assert_eq!(capacity_full.high_water_connections, 20);
    let (_rejected_identity_source, rejected_probe) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        capacity_probe_node,
        voter_authorities[capacity_probe_node].clone(),
        fleet.pki.consumer_identity_state_with_generations(
            &consumer_identities[capacity_probe_node],
            capacity_credential_generation,
            capacity_trust_generation,
        ),
        headroom_pool_config,
        None,
    );
    let capacity_probe_typed_rejection = matches!(
        runtime.block_on(rejected_probe.prewarm_v2()),
        Err(SessionConsumerClientError::Unavailable)
    );
    assert!(
        capacity_probe_typed_rejection,
        "the twenty-first listener admission is rejected without retrying or evicting normal lanes"
    );
    runtime.block_on(rejected_probe.shutdown());
    let capacity_rejected = fleet.stateless_consumer_admission_status(capacity_probe_node);
    assert_eq!(capacity_rejected.active_connections, 20);
    assert_eq!(capacity_rejected.high_water_connections, 20);
    let capacity_probe_high_water_connections = capacity_rejected.high_water_connections;
    let capacity_probe_admission_waits = capacity_rejected
        .admission_waits
        .checked_sub(capacity_before.admission_waits)
        .expect("listener admission waits are monotonic across the capacity phase");
    let capacity_probe_admission_rejections = capacity_rejected
        .admission_rejections
        .checked_sub(capacity_before.admission_rejections)
        .expect("listener admission rejections are monotonic across the capacity phase");
    assert_eq!(capacity_probe_admission_waits, 0);
    assert_eq!(capacity_probe_admission_rejections, 1);
    for (_, probe) in &capacity_probes {
        runtime.block_on(probe.shutdown());
    }
    for (_, probe) in &headroom_probes {
        runtime.block_on(probe.shutdown());
    }
    for node_index in 0..MEMBER_COUNT {
        let settle_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let settled = fleet.stateless_consumer_admission_status(node_index);
            if settled.active_connections == 16 {
                assert_eq!(
                    settled.high_water_connections,
                    if node_index == capacity_probe_node {
                        20
                    } else {
                        17
                    }
                );
                break;
            }
            assert!(
                Instant::now() < settle_deadline,
                "headroom probe failed to reclaim its one listener admission: node={node_index}, status={settled:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    runtime.block_on(async {
        for client in &clients {
            let reads = (0..V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT).map(|_| {
                qualification_execute_v2_status_sample(
                    client.clone(),
                    scope,
                    first.clone(),
                    Instant::now(),
                )
            });
            futures_util::future::join_all(reads).await;
        }
    });
    let normal_after_capacity = clients
        .iter()
        .map(PersistentSessionConsumerClient::v2_diagnostics)
        .collect::<Vec<_>>();
    for (before, after) in normal_before_capacity.iter().zip(&normal_after_capacity) {
        assert_eq!(after.setup_attempts, before.setup_attempts);
        assert_eq!(after.reconnects, before.reconnects);
        assert_eq!(after.active, before.active);
        assert_eq!(after.idle, before.idle);
    }
    drop(capacity_probes);
    drop(headroom_probes);
    let current_process_ids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    let (settled_resources, _) =
        fleet.wait_for_resources_to_settle(&current_process_ids, &warmed_resources);
    let resource_high_water_generations = resource_sampler.finish();
    for (node_index, generations) in resource_high_water_generations.iter().enumerate() {
        let expected_generations = if node_index == leader_node_index {
            2
        } else {
            1
        };
        assert_eq!(
            generations.len(),
            expected_generations,
            "resource sampler retains a bounded logical-voter generation ledger"
        );
        assert!(
            generations.iter().all(|generation| generation.samples >= 1),
            "each sampled logical-voter generation has at least one resource observation"
        );
    }
    let resource_high_water =
        merge_resource_generation_high_water(&resource_high_water_generations);
    assert_process_resource_bounds(
        MEMBER_COUNT,
        &warmed_resources,
        &resource_high_water,
        &settled_resources,
    );
    let resource_observations = warmed_resources
        .iter()
        .zip(&resource_high_water)
        .zip(&settled_resources)
        .enumerate()
        .map(|(logical_voter_index, ((warmed, high_water), settled))| {
            opc_session_testkit::qualification::SessionMtlsBatchReleaseGateResourceObservationV1 {
                logical_voter_index,
                warmed_file_descriptors: warmed.file_descriptors,
                warmed_socket_file_descriptors: warmed.socket_file_descriptors,
                warmed_nontransport_file_descriptors: warmed.nontransport_file_descriptors,
                warmed_threads: warmed.threads,
                warmed_vm_rss_kib: warmed.vm_rss_kib,
                warmed_vm_hwm_kib: warmed.vm_hwm_kib,
                high_water_file_descriptors: high_water.file_descriptors,
                high_water_threads: high_water.threads,
                high_water_vm_rss_kib: high_water.vm_rss_kib,
                high_water_vm_hwm_kib: high_water.vm_hwm_kib,
                settled_file_descriptors: settled.file_descriptors,
                settled_socket_file_descriptors: settled.socket_file_descriptors,
                settled_threads: settled.threads,
                settled_vm_rss_kib: settled.vm_rss_kib,
                settled_vm_hwm_kib: settled.vm_hwm_kib,
                high_water_file_descriptor_ceiling: process_file_descriptor_high_water_bound(
                    MEMBER_COUNT,
                    warmed.nontransport_file_descriptors,
                ),
                settled_file_descriptor_ceiling: warmed
                    .file_descriptors
                    .checked_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE)
                    .expect("settled file-descriptor ceiling fits usize"),
                settled_socket_file_descriptor_ceiling: warmed
                    .socket_file_descriptors
                    .checked_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE)
                    .expect("settled socket-file-descriptor ceiling fits usize"),
                high_water_thread_ceiling: warmed
                    .threads
                    .checked_add(QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE)
                    .expect("high-water thread ceiling fits usize"),
                high_water_vm_hwm_ceiling_kib: warmed
                    .vm_hwm_kib
                    .checked_add(QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB)
                    .expect("high-water vm-hwm ceiling fits u64"),
                settled_vm_rss_ceiling_kib: warmed
                    .vm_rss_kib
                    .checked_add(QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB)
                    .expect("settled vm-rss ceiling fits u64"),
            }
        })
        .collect::<Vec<_>>();
    let server_admissions = (0..MEMBER_COUNT)
        .map(|node_index| {
            let mut admission = fleet.stateless_consumer_admission_status(node_index);
            admission.normal_headroom_high_water_connections =
                normal_headroom_high_water_connections[node_index];
            admission.capacity_probe_exercised = node_index == capacity_probe_node;
            if admission.capacity_probe_exercised {
                admission.capacity_probe_high_water_connections =
                    capacity_probe_high_water_connections;
                admission.capacity_probe_admission_waits = capacity_probe_admission_waits;
                admission.capacity_probe_admission_rejections = capacity_probe_admission_rejections;
                admission.capacity_probe_typed_rejection = capacity_probe_typed_rejection;
            }
            admission
        })
        .collect::<Vec<_>>();
    for admission in &server_admissions {
        assert_eq!(admission.admission_limit, 20);
        assert_eq!(admission.expected_peak_connections, 16);
        assert!(admission.listener_available && admission.samples > 0);
        assert!(
            admission.high_water_connections > admission.expected_peak_connections,
            "a real supplemental listener admission must prove positive server headroom"
        );
        assert_eq!(admission.active_connections, 16);
        if admission.logical_voter_index == capacity_probe_node {
            assert_eq!(admission.high_water_connections, 20);
            assert_eq!(admission.capacity_probe_high_water_connections, 20);
            assert_eq!(admission.capacity_probe_admission_waits, 0);
            assert_eq!(admission.capacity_probe_admission_rejections, 1);
            assert!(admission.capacity_probe_typed_rejection);
        } else {
            assert_eq!(admission.high_water_connections, 17);
            assert_eq!(admission.capacity_probe_high_water_connections, 0);
        }
    }
    let mut resource_generations = resource_high_water_generations
        .iter()
        .enumerate()
        .flat_map(|(logical_voter_index, generations)| {
            generations
                .iter()
                .enumerate()
                .map(move |(generation_ordinal, generation)| {
                    SessionMtlsBatchReleaseGateResourceGenerationV1 {
                        logical_voter_index,
                        generation_ordinal: u8::try_from(generation_ordinal)
                            .expect("bounded restarted voter has a portable generation ordinal"),
                        process_id: generation.process_id,
                        samples: generation.samples,
                    }
                })
        })
        .collect::<Vec<_>>();
    resource_generations.sort_by_key(|generation| {
        (
            generation.logical_voter_index,
            generation.generation_ordinal,
        )
    });
    let distinct_resource_processes = resource_generations
        .iter()
        .map(|generation| generation.process_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        distinct_resource_processes.len(),
        resource_generations.len(),
        "each logical-voter generation has a distinct nonzero process ID"
    );
    assert_eq!(
        resource_generations
            .iter()
            .filter(|generation| generation.logical_voter_index == leader_node_index)
            .map(|generation| generation.generation_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1],
        "the killed voter records old then replacement process generations"
    );
    let replacement_seam_pool_wait_max = released_original_before_shutdown
        .pool_wait_max
        .max(restored_seam_current.pool_wait_max);
    let old_root_seam_pool_wait_max = released_old_root_before_shutdown
        .pool_wait_max
        .max(restored_old_root_current.pool_wait_max);
    assert_eq!(
        after_recovery[seam_client_index].pool_wait_max, replacement_seam_pool_wait_max,
        "replacement seam preserves the retired and restored client-pool wait high-water"
    );
    assert_eq!(
        after_recovery[old_root_seam_client_index].pool_wait_max, old_root_seam_pool_wait_max,
        "old-root seam preserves the retired and restored client-pool wait high-water"
    );
    let pool_wait_max = after_recovery
        .iter()
        .map(|diagnostics| diagnostics.pool_wait_max)
        .max()
        .expect("fixed V2 client set is nonempty");
    fleet
        .candidate_evidence_inputs
        .verify_unchanged(&fleet.config_paths)
        .expect("candidate inputs remain unchanged before release-gate evidence output");
    release_provenance
        .verify_unchanged()
        .expect("release gate source remains clean and frozen before evidence output");
    let original_pool = SessionMtlsBatchReleaseGatePoolEvidenceV1 {
        role: SessionMtlsBatchReleaseGatePoolRoleV1::OriginalFixedPools,
        setup_attempts: original_setup_attempts,
        setup_failures: original_setup_failures,
        setup_successes: original_setup_successes,
        pool_wait_current: 0,
        pool_wait_max,
        configured_lanes: configured_connections,
        active_lanes: after_recovery
            .iter()
            .map(|diagnostics| diagnostics.active)
            .sum(),
        idle_lanes: after_recovery
            .iter()
            .map(|diagnostics| diagnostics.idle)
            .sum(),
    };
    let supplemental_pools = [
        (
            SessionMtlsBatchReleaseGatePoolRoleV1::OldCredentialNewOnlyServer,
            old_leaf_diagnostics,
            1,
        ),
        (
            SessionMtlsBatchReleaseGatePoolRoleV1::DelayedResponseAmbiguity,
            delayed_after_ambiguity,
            V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
        ),
        (
            SessionMtlsBatchReleaseGatePoolRoleV1::NewCredentialOldRootServer,
            new_only_old_root_diagnostics,
            1,
        ),
    ]
    .into_iter()
    .map(
        |(role, diagnostics, configured_lanes)| SessionMtlsBatchReleaseGatePoolEvidenceV1 {
            role,
            setup_attempts: diagnostics.setup_attempts,
            setup_failures: diagnostics.setup_failures,
            setup_successes: diagnostics.setup_successes,
            pool_wait_current: diagnostics.pool_wait_current,
            pool_wait_max: diagnostics.pool_wait_max,
            configured_lanes,
            active_lanes: diagnostics.active,
            idle_lanes: diagnostics.idle,
        },
    )
    .collect::<Vec<_>>();
    let all_pools = std::iter::once(&original_pool).chain(supplemental_pools.iter());
    let aggregate_setup_attempts = all_pools.clone().map(|pool| pool.setup_attempts).sum();
    let aggregate_setup_failures = all_pools.clone().map(|pool| pool.setup_failures).sum();
    let aggregate_setup_successes = all_pools.clone().map(|pool| pool.setup_successes).sum();
    let aggregate_pool_wait_max = all_pools
        .map(|pool| pool.pool_wait_max)
        .max()
        .expect("all pools accounted");
    assert_eq!(
        aggregate_pool_wait_max, V2_BATCH_RELEASE_GATE_PENDING_CALLS as u64,
        "the serialized aggregate wait high-water is the delayed fixed-pool overload evidence"
    );
    println!(
        "V2_BATCH_RELEASE_GATE_POOL_WAIT_SCOPES original_and_restored_max={} replacement_released_and_restored_max={} old_root_released_and_restored_max={} delayed_ambiguity_max={} old_credential_negative_max={} new_credential_old_root_negative_max={} aggregate_max={}",
        pool_wait_max,
        replacement_seam_pool_wait_max,
        old_root_seam_pool_wait_max,
        delayed_after_ambiguity.pool_wait_max,
        old_leaf_diagnostics.pool_wait_max,
        new_only_old_root_diagnostics.pool_wait_max,
        aggregate_pool_wait_max,
    );
    assert_eq!(mutation_recovered_unknown, 0);
    assert_eq!(mutation_status_retries, V2BatchStatusRetryCounts::default());
    assert_eq!(mutation_status_retries_high_water, 0);
    assert_eq!(mutation_status_attempts_high_water, 0);
    let evidence_status_retries = ambiguity_status_retries;
    let evidence_status_attempts_high_water = ambiguity_status_retries.attempts_total;
    let evidence_status_retries_high_water = ambiguity_status_retries.total;
    assert!(
        evidence_status_retries.attempts_total
            <= V2_BATCH_RELEASE_GATE_AMBIGUITY_STATUS_ATTEMPT_LIMIT,
        "all delayed-response status reads remain within the one 64-attempt evidence budget"
    );
    let gate_process_generations = resource_generations.len();
    let typed_evidence = SessionMtlsBatchReleaseGateEvidenceV1 {
        schema_version: "opc-session-mtls-batch-release-gate-evidence/v1".to_owned(),
        experimental: true,
        qualification_complete: false,
        cargo_profile: observed_profile.to_owned(),
        opt_level: observed_opt_level.to_owned(),
        debug_assertions: cfg!(debug_assertions),
        foundation_insecure: cfg!(feature = "foundation-insecure"),
        bindings: SessionMtlsBatchReleaseGateBindingsV1 {
            evidence_schema_sha256: opc_session_testkit::qualification::session_mtls_batch_release_gate_evidence_v1_schema_sha256(),
            configuration_sha256: fleet.candidate_evidence_inputs.configuration_sha256.clone(),
            public_material_manifest_sha256: fleet.candidate_public_material_manifest.sha256().expect("public material manifest"),
            workload_schedule_sha256: session_mtls_batch_release_gate_schedule_sha256(),
            source_revision: release_provenance.source_revision.clone(),
            source_tree: release_provenance.source_tree.clone(),
            source_tree_status: SessionMtlsCandidateSourceTreeStatus::Clean,
            source_worktree_sha256: release_provenance.source_worktree_sha256.clone(),
            cargo_lock_sha256: release_provenance.cargo_lock_sha256.clone(),
            command_argv_sha256: release_provenance.command_argv_sha256.clone(),
            child_sha256: fleet.candidate_evidence_inputs.child_sha256.clone(),
            harness_sha256: fleet.candidate_evidence_inputs.harness_sha256.clone(),
        },
        members: MEMBER_COUNT,
        clients: V2_BATCH_RELEASE_GATE_CLIENTS,
        lanes_per_client: V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT,
        // This is the offered logical mutation rate, not an actor-count or
        // attach-per-second capacity claim.
        logical_operations_per_second: V2_BATCH_RELEASE_GATE_MUTATIONS_PER_SECOND,
        warm_status_samples: V2_BATCH_RELEASE_GATE_WARM_READ_SAMPLES,
        warm_status_request_cardinality: warm_status_request_indices.len(),
        warm_status_request_index_min: warm_status_request_min,
        warm_status_request_index_max: warm_status_request_max,
        warm_status_request_stride: WARM_STATUS_REQUEST_STRIDE,
        active_history_entries: exact_active_history_entries,
        normal_configured_lanes: configured_connections,
        normal_active_lanes: after_recovery
            .iter()
            .map(|diagnostics| diagnostics.active)
            .sum(),
        normal_idle_lanes: after_recovery
            .iter()
            .map(|diagnostics| diagnostics.idle)
            .sum(),
        original_fixed_pools: original_pool,
        supplemental_pools,
        aggregate_setup_attempts,
        aggregate_setup_failures,
        aggregate_setup_successes,
        restarted_voter_index: leader_node_index,
        capacity_probe_voter_index: capacity_probe_node,
        capacity_probe_overall_admission_waits: capacity_probe_admission_waits,
        capacity_probe_overall_admission_rejections: capacity_probe_admission_rejections,
        preload_recovered_unknown,
        preload_not_transmitted_retries,
        preload_not_transmitted_retry_high_water,
        paced_not_transmitted_retries: mutation_not_transmitted_retries,
        paced_not_transmitted_retry_high_water: mutation_not_transmitted_retry_high_water,
        // The 69th pressure call is a typed overload observation, not a
        // proven-unavailable redispatch. The ledger therefore derives zero
        // retries and zero retry high-water from its single terminal attempt.
        pressure_not_transmitted_retries: overload_attempt_ledger.actual_redispatches(),
        pressure_not_transmitted_retry_high_water: overload_attempt_ledger.actual_redispatches(),
        preload_status_attempts_total: preload_status_retries.attempts_total,
        preload_status_terminal_attempts: preload_status_retries.terminal_attempts,
        preload_status_retries_total: preload_status_retries.total,
        preload_status_not_found_retries: preload_status_retries.not_found,
        preload_status_not_transmitted_retries: preload_status_retries.not_transmitted,
        preload_status_read_unavailable_retries: preload_status_retries.read_unavailable,
        preload_status_typed_unavailable_retries: preload_status_retries.typed_unavailable,
        status_retries_total: evidence_status_retries.total,
        status_attempts_total: evidence_status_retries.attempts_total,
        status_attempts_high_water: evidence_status_attempts_high_water,
        status_terminal_attempts: evidence_status_retries.terminal_attempts,
        status_retries_high_water: evidence_status_retries_high_water,
        status_not_found_retries: evidence_status_retries.not_found,
        status_not_transmitted_retries: evidence_status_retries.not_transmitted,
        status_read_unavailable_retries: evidence_status_retries.read_unavailable,
        status_typed_unavailable_retries: evidence_status_retries.typed_unavailable,
        aggregate_pool_wait_max,
        resource_generations,
        resource_observations,
        server_admissions,
        paced_operations: V2_BATCH_RELEASE_GATE_PACED_MUTATIONS,
        paced_elapsed_nanos,
        achieved_logical_operations_per_second_milli,
        mutation_batch_samples: mutation_samples.len(),
        warm_read_p99_millis,
        warm_read_p999_millis,
        mutation_p99_millis,
        mutation_p999_millis,
        saturated_client_skips: mutation_saturated_client_skips,
        slow_lane_completed_batches: min_completed_batches,
        over_capacity_typed_backpressure_events: 1,
        held_response_count: held_response_count
            .checked_add(1)
            .expect("causal plus pressure held-response accounting fits usize"),
        causal_held_response_count: 1,
        queued_caller_count,
        cross_client_fair_progress,
        released_response_count,
        recovered_queued_caller_count,
        durable_status_cardinality,
        post_outcome_unknown_mutation_dispatches: causal_attempt_ledger
            .post_outcome_unknown_mutation_dispatches(),
        not_transmitted_retries: preload_not_transmitted_retries
            .checked_add(mutation_not_transmitted_retries)
            .expect("bounded preload and paced retry accounting fits usize"),
        recovered_unknown: causal_attempt_ledger.recovered_outcome_unknown_families(),
        // No server queue depth is sampled by this client-side harness.
        server_queue_depth_measured: false,
        server_queue_depth_scope: SessionMtlsBatchReleaseGateServerQueueDepthScopeV1::Downstream,
        positive_new_credential_new_server_statuses: new_only_client_indices.len(),
        old_credential_new_only_server_tls_peer_credential_rejected,
        new_credential_old_root_server_tls_peer_credential_rejected,
    };
    typed_evidence
        .validate()
        .expect("typed batch evidence validates");
    let encoded_typed_evidence = typed_evidence
        .to_canonical_json()
        .expect("typed batch evidence encodes and schema-validates exact bytes");
    assert_eq!(
        SessionMtlsBatchReleaseGateEvidenceV1::from_json(&encoded_typed_evidence)
            .expect("typed batch evidence round-trips"),
        typed_evidence
    );
    println!(
        "V2_BATCH_RELEASE_GATE_EVIDENCE {}",
        String::from_utf8(encoded_typed_evidence.clone()).expect("typed evidence is UTF-8 JSON")
    );
    runtime.block_on(async {
        for client in &clients {
            client.shutdown().await;
        }
    });
    fleet.shutdown();
    BatchReleaseGateRunFacts {
        canonical_v1: encoded_typed_evidence,
        release_provenance,
        capacity_reclaimed: pressure_recovered.active
            == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64
            && pressure_recovered.idle == V2_BATCH_RELEASE_GATE_LANES_PER_CLIENT as u64,
        old_credential_rejected: old_credential_new_only_server_tls_peer_credential_rejected,
        new_credential_rejected: new_credential_old_root_server_tls_peer_credential_rejected,
        process_generations: gate_process_generations,
        durable_status_cardinality,
        post_outcome_unknown_mutation_dispatches: causal_attempt_ledger
            .post_outcome_unknown_mutation_dispatches(),
    }
}

fn assert_batch_credential_negative_handshake(
    server_credential: CredentialGeneration,
    server_trust: TrustGeneration,
    client_credential: ConsumerCredentialGeneration,
    client_trust: TrustGeneration,
    phase: &str,
) {
    const MEMBER_COUNT: usize = 3;
    const TARGET: usize = 0;
    let mut fleet = Fleet::start(MEMBER_COUNT);
    let consumer_identities = (0..V2_BATCH_RELEASE_GATE_CLIENTS)
        .map(stateless_consumer_identity)
        .collect::<Vec<_>>();
    let identity = consumer_identities[TARGET].clone();
    let (endpoint, scope) = fleet.start_stateless_consumer(TARGET, consumer_identities);
    let voter_authority = fleet
        .stateless_consumer_voter_authorities()
        .into_iter()
        .nth(TARGET)
        .expect("qualification target voter authority");
    assert_eq!(
        voter_authority.scope(),
        scope,
        "matching credential control must use the listener's exact fixed authority scope"
    );
    let source_before = fleet.projected_status(TARGET);
    let controller_before = fleet.material_status(TARGET);
    fleet.publish_known_projected_generation(TARGET, server_credential, server_trust, phase);
    fleet.wait_for_member_publication(TARGET, source_before.generation, controller_before.epoch);
    let endpoints = Arc::new(Mutex::new(vec![endpoint; MEMBER_COUNT]));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bounded credential-negative runtime");
    let pool_config = PersistentSessionConsumerConfig::try_new(
        1,
        0,
        Duration::from_millis(250),
        1,
        Duration::from_millis(1_500),
        1,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("single-lane credential-negative pool");

    let positive_credential = match server_trust {
        TrustGeneration::OldOnly => ConsumerCredentialGeneration::OldRoot,
        TrustGeneration::NewOnly => ConsumerCredentialGeneration::NewRoot,
        TrustGeneration::Overlap => panic!("credential-negative server trust must be exclusive"),
    };
    let (_positive_identity_source, positive_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        TARGET,
        voter_authority.clone(),
        fleet.pki.consumer_identity_state_with_generations(
            &identity,
            positive_credential,
            server_trust,
        ),
        pool_config,
        None,
    );
    runtime
        .block_on(positive_client.prewarm_v2())
        .expect("matching credential is a positive mTLS control");
    let positive_diagnostics = positive_client.v2_diagnostics();
    assert_eq!(positive_diagnostics.setup_attempts, 1);
    assert_eq!(positive_diagnostics.setup_successes, 1);
    runtime.block_on(positive_client.shutdown());
    assert_eq!(
        fleet.consumer_tls_peer_credential_rejections(TARGET),
        0,
        "matching credential control cannot increment the peer-credential rejection counter: phase={phase}"
    );
    let peer_credential_rejections_before = fleet.consumer_tls_peer_credential_rejections(TARGET);

    let (_negative_identity_source, negative_client) = qualification_persistent_v2_client(
        Arc::clone(&endpoints),
        TARGET,
        voter_authority,
        fleet.pki.consumer_identity_state_with_generations(
            &identity,
            client_credential,
            client_trust,
        ),
        pool_config,
        None,
    );
    let negative_result = runtime.block_on(negative_client.prewarm_v2());
    assert!(
        matches!(
            negative_result,
            Err(SessionConsumerClientError::Authentication
                | SessionConsumerClientError::Unavailable)
        ),
        "actual consumer listener mismatched credential result is typed authentication or unavailable: phase={phase}, result={negative_result:?}"
    );
    runtime.block_on(negative_client.shutdown());
    let negative_diagnostics = negative_client.v2_diagnostics();
    assert_eq!(negative_diagnostics.setup_attempts, 1);
    assert_eq!(negative_diagnostics.setup_successes, 0);
    assert_eq!(negative_diagnostics.setup_failures, 1);
    assert_eq!(negative_diagnostics.active, 0);
    assert_eq!(negative_diagnostics.idle, 0);
    assert_eq!(negative_diagnostics.pool_wait_current, 0);
    assert_eq!(
        fleet.consumer_tls_peer_credential_rejections(TARGET),
        peer_credential_rejections_before
            .checked_add(1)
            .expect("bounded peer-credential rejection counter remains below u64 maximum"),
        "the mismatched credential produces exactly one local TLS peer-credential rejection: phase={phase}"
    );
    fleet.shutdown();
}

#[test]
fn bounded_batch_credential_negatives_reach_consumer_listener_rejection() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_batch_credential_negative_handshake(
        CredentialGeneration::NewRoot,
        TrustGeneration::NewOnly,
        ConsumerCredentialGeneration::OldRoot,
        TrustGeneration::Overlap,
        "batch-negative-new-only-server",
    );
    assert_batch_credential_negative_handshake(
        CredentialGeneration::Initial,
        TrustGeneration::OldOnly,
        ConsumerCredentialGeneration::NewRoot,
        TrustGeneration::Overlap,
        "batch-negative-old-root-server",
    );
}

#[test]
fn three_process_projected_mtls_stateless_quorum_consumers() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_stateless_consumer_multiprocess_qualification(3);
}

#[test]
fn five_process_projected_mtls_stateless_quorum_consumers() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_stateless_consumer_multiprocess_qualification(5);
}

#[test]
fn three_process_projected_mtls_persistent_quorum_consumers() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_persistent_consumer_multiprocess_qualification(3, None);
}

#[test]
fn three_process_projected_mtls_persistent_v2_fenced_transition_consumers() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_persistent_consumer_v2_multiprocess_qualification();
}

#[test]
#[ignore = "release-profile attestation sentinel; executes only the profile guard"]
fn v2_batch_release_gate_profile_attestation_sentinel() {
    assert_v2_batch_release_profile();
}

#[test]
#[ignore = "manual same-host three-process V2 batch release gate (50k preload + 60k paced mutations)"]
fn three_process_projected_mtls_persistent_v2_batch_release_gate() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let release_provenance = ReleaseGateProvenance::capture()
        .expect("release gate requires one clean provenance before either dual-lane campaign");
    let persistent_measurements =
        run_persistent_consumer_multiprocess_qualification(3, Some(release_provenance.clone()));
    assert!(
        persistent_measurements.authenticated_setup_successes >= 48
            && persistent_measurements.warm_reused_calls
                >= QUALIFICATION_PERSISTENT_CONSUMER_MIN_WARM_SAMPLES_V7 as u64
            && persistent_measurements.protected_roster_setup_successes > 0,
        "the release-gate invocation must first execute both real persistent lanes"
    );
    let v1 = run_persistent_consumer_v2_batch_release_gate(release_provenance);
    assert!(
        SessionMtlsBatchReleaseGateEvidenceV1::from_json(&v1.canonical_v1).is_ok(),
        "the full gate returns its exact canonical V1 artifact for a V9 envelope publisher"
    );
    assert!(
        v1.capacity_reclaimed && v1.old_credential_rejected && v1.new_credential_rejected,
        "the returned gate facts retain the real capacity and credential boundaries"
    );
    assert!(
        v1.process_generations >= 4
            && v1.durable_status_cardinality == V2_BATCH_RELEASE_GATE_MUTATION_BATCH_SIZE
            && v1.post_outcome_unknown_mutation_dispatches == 0,
        "the returned gate facts retain the process and retained-ID causal ledger"
    );
    let (v9_canonical, v9) = build_v9_external_evidence(&persistent_measurements, &v1)
        .expect("the combined real run builds a closed V9 envelope");
    assert!(
        v9.qualification_complete,
        "only the complete combined ignored release gate may reach V9 publication"
    );
    assert_eq!(
        SessionHaPersistentConsumerHeadEvidenceV9::from_json(&v9_canonical)
            .expect("V9 canonical evidence round-trips"),
        v9
    );
    let output_root = env::var_os("OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY")
        .map(PathBuf::from)
        .expect("V9 requires an external caller-supplied evidence directory");
    publish_v9_external_evidence_at(&output_root, &v1.canonical_v1, &v9_canonical)
        .expect("V9 evidence publication is exclusive and durable");
}

#[test]
fn five_process_projected_mtls_persistent_quorum_consumers() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_persistent_consumer_multiprocess_qualification(5, None);
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
fn active_restart_reserves_one_final_readiness_round_after_recovery() {
    let started = Instant::now();
    let readiness_round =
        Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_FINAL_READINESS_PROBE_MILLIS);
    let recovery_deadline =
        started + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_RECOVERY_MILLIS);
    let catchup_deadline = recovery_deadline
        + Duration::from_millis(QUALIFICATION_TRAFFIC_UNCLEAN_RESTART_FINAL_READINESS_PROBE_MILLIS);

    assert_eq!(
        active_restart_readiness_round(started, recovery_deadline, catchup_deadline, false),
        ActiveRestartReadinessRound::Recovery {
            deadline: started + readiness_round,
        }
    );
    assert_eq!(
        active_restart_readiness_round(
            recovery_deadline - readiness_round,
            recovery_deadline,
            catchup_deadline,
            false,
        ),
        ActiveRestartReadinessRound::Recovery {
            deadline: recovery_deadline,
        }
    );
    assert_eq!(
        active_restart_readiness_round(
            recovery_deadline - readiness_round + Duration::from_nanos(1),
            recovery_deadline,
            catchup_deadline,
            false,
        ),
        ActiveRestartReadinessRound::WaitForFinal {
            dispatch_at: recovery_deadline,
        }
    );
    assert_eq!(
        active_restart_readiness_round(
            started + Duration::from_millis(20_200),
            recovery_deadline,
            catchup_deadline,
            false,
        ),
        ActiveRestartReadinessRound::WaitForFinal {
            dispatch_at: recovery_deadline,
        }
    );
    assert_eq!(
        active_restart_readiness_round(
            recovery_deadline,
            recovery_deadline,
            catchup_deadline,
            false,
        ),
        ActiveRestartReadinessRound::Final {
            deadline: catchup_deadline,
        }
    );
    assert_eq!(
        active_restart_readiness_round(
            recovery_deadline,
            recovery_deadline,
            catchup_deadline,
            true,
        ),
        ActiveRestartReadinessRound::Exhausted
    );
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
            kind: PendingCommandKind::Command(QualificationNodeCommandKind::CompareAndSet),
            sequence: 7,
            send_elapsed_millis: 42,
        }
    );
    assert_eq!(
        format!("{diagnostic:?}"),
        "PendingCommandDiagnostic { kind: Command(CompareAndSet), sequence: 7, send_elapsed_millis: 42 }"
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
fn replaced_v2_pool_diagnostics_preserve_released_and_restored_counters() {
    let prewarmed = PersistentSessionConsumerV2Diagnostics {
        setup_attempts: 4,
        setup_failures: 0,
        setup_successes: 4,
        reused: 9,
        reconnects: 0,
        active: 4,
        idle: 4,
        pool_wait_current: 0,
        pool_wait_max: 0,
    };
    let released_before_shutdown = PersistentSessionConsumerV2Diagnostics {
        setup_attempts: 8,
        setup_failures: 1,
        setup_successes: 7,
        reused: 15,
        reconnects: 3,
        active: 4,
        idle: 4,
        pool_wait_current: 0,
        pool_wait_max: 2,
    };
    let restored_current = PersistentSessionConsumerV2Diagnostics {
        setup_attempts: 4,
        setup_failures: 0,
        setup_successes: 4,
        reused: 2,
        reconnects: 0,
        active: 4,
        idle: 4,
        pool_wait_current: 0,
        pool_wait_max: 1,
    };
    let combined = cumulative_replaced_v2_diagnostics(released_before_shutdown, restored_current);
    assert_eq!(combined.setup_attempts - prewarmed.setup_attempts, 8);
    assert_eq!(combined.setup_failures - prewarmed.setup_failures, 1);
    assert_eq!(combined.setup_successes - prewarmed.setup_successes, 7);
    assert_eq!(combined.reused - prewarmed.reused, 8);
    assert_eq!(combined.reconnects - prewarmed.reconnects, 3);
    assert_eq!(combined.active, restored_current.active);
    assert_eq!(combined.idle, restored_current.idle);
    assert_eq!(
        combined.pool_wait_current,
        restored_current.pool_wait_current
    );
    assert_eq!(combined.pool_wait_max, 2);
}

#[test]
fn mtls_setup_accounting_rejects_each_attempt_and_failure_ceiling() {
    let ceilings = v2_batch_release_gate_setup_ceilings();
    assert_eq!(ceilings.original_and_restored.attempts, 168);
    assert_eq!(ceilings.original_and_restored.failures, 120);
    assert_eq!(ceilings.supplemental.attempts, 10);
    assert_eq!(ceilings.supplemental.failures, 10);
    assert_eq!(ceilings.total.attempts, 178);
    assert_eq!(ceilings.total.failures, 130);

    let mut original_attempts = MtlsSetupAccounting {
        original_and_restored: SetupAccounting {
            attempts: ceilings.original_and_restored.attempts + 1,
            failures: 0,
        },
        supplemental: SetupAccounting {
            attempts: 0,
            failures: 0,
        },
    };
    let error = verify_mtls_setup_accounting(original_attempts, ceilings)
        .expect_err("original attempt ceiling must reject overflow");
    assert!(error.contains("scope=original_and_restored"));
    assert!(error.contains("attempt ceiling"));

    original_attempts.original_and_restored = SetupAccounting {
        attempts: 0,
        failures: ceilings.original_and_restored.failures + 1,
    };
    let error = verify_mtls_setup_accounting(original_attempts, ceilings)
        .expect_err("original failure ceiling must reject overflow");
    assert!(error.contains("scope=original_and_restored"));
    assert!(error.contains("failure ceiling"));

    let mut supplemental_attempts = MtlsSetupAccounting {
        original_and_restored: SetupAccounting {
            attempts: 0,
            failures: 0,
        },
        supplemental: SetupAccounting {
            attempts: ceilings.supplemental.attempts + 1,
            failures: 0,
        },
    };
    let error = verify_mtls_setup_accounting(supplemental_attempts, ceilings)
        .expect_err("supplemental attempt ceiling must reject overflow");
    assert!(error.contains("scope=supplemental"));
    assert!(error.contains("attempt ceiling"));

    supplemental_attempts.supplemental = SetupAccounting {
        attempts: 0,
        failures: ceilings.supplemental.failures + 1,
    };
    let error = verify_mtls_setup_accounting(supplemental_attempts, ceilings)
        .expect_err("supplemental failure ceiling must reject overflow");
    assert!(error.contains("scope=supplemental"));
    assert!(error.contains("failure ceiling"));

    let total_observed = MtlsSetupAccounting {
        original_and_restored: SetupAccounting {
            attempts: 1,
            failures: 1,
        },
        supplemental: SetupAccounting {
            attempts: 1,
            failures: 1,
        },
    };
    let total_attempt_ceilings = MtlsSetupCeilings {
        total: SetupAccounting {
            attempts: 1,
            failures: ceilings.total.failures,
        },
        ..ceilings
    };
    let error = verify_mtls_setup_accounting(total_observed, total_attempt_ceilings)
        .expect_err("total attempt ceiling must reject overflow");
    assert!(error.contains("scope=total"));
    assert!(error.contains("attempt ceiling"));

    let total_failure_ceilings = MtlsSetupCeilings {
        total: SetupAccounting {
            attempts: ceilings.total.attempts,
            failures: 1,
        },
        ..ceilings
    };
    let error = verify_mtls_setup_accounting(total_observed, total_failure_ceilings)
        .expect_err("total failure ceiling must reject overflow");
    assert!(error.contains("scope=total"));
    assert!(error.contains("failure ceiling"));
}

#[test]
fn resource_sampler_generation_ledger_keeps_initial_offline_and_restarted_pid() {
    let initial = ProcessResourceHighWater {
        process_id: 41,
        samples: 0,
        file_descriptors: 0,
        threads: 0,
        vm_rss_kib: 0,
        vm_hwm_kib: 0,
    };
    let snapshot = ProcessResourceSnapshot {
        file_descriptors: 8,
        socket_file_descriptors: 2,
        nontransport_file_descriptors: 6,
        threads: 3,
        vm_rss_kib: 100,
        vm_hwm_kib: 120,
    };
    let mut generations = vec![vec![initial]];
    let mut observed_process_ids = vec![None];
    record_resource_generation_sample(&mut generations, &mut observed_process_ids, 0, 41, snapshot);
    // Offline is intentionally not sampled. Retaining the old observed PID
    // makes the next distinct authoritative PID a new logical generation.
    record_resource_generation_sample(&mut generations, &mut observed_process_ids, 0, 73, snapshot);
    assert_eq!(generations[0].len(), 2);
    assert_eq!(generations[0][0].process_id, 41);
    assert_eq!(generations[0][1].process_id, 73);
    assert!(generations[0]
        .iter()
        .all(|generation| generation.samples >= 1));
}

#[test]
fn persistent_consumer_process_ledger_derives_loss_restart_and_generation_counts() {
    let mut ledger = PersistentConsumerProcessLedger::default();
    ledger.record_initial(0, 101);
    ledger.record_initial(1, 102);
    ledger.record_initial(2, 103);
    ledger.record_unclean_loss(0, 101);
    ledger.record_restart(0, 101, 201);
    ledger.record_unclean_loss(2, 103);

    assert_eq!(ledger.initial_processes(), 3);
    assert_eq!(ledger.unclean_process_losses(), 2);
    assert_eq!(ledger.restarted_processes(), 1);
    assert_eq!(ledger.observed_process_generations(), 4);
}

#[test]
fn protected_authority_negative_counters_require_exact_typed_boundaries() {
    let tenant_rejection = Err(SessionConsumerClientError::Unavailable);
    let tenant_non_boundary = Err(SessionConsumerClientError::Authentication);
    assert_eq!(protected_tenant_boundary_observation(&tenant_rejection), 1);
    assert_eq!(
        protected_tenant_boundary_observation(&tenant_non_boundary),
        0,
        "the foreign-tenant boundary is intentionally non-oracular"
    );

    let scope_rejection = Err(SessionConsumerClientError::Scope);
    let scope_non_boundary = Err(SessionConsumerClientError::Protocol);
    assert_eq!(protected_scope_boundary_observation(&scope_rejection), 1);
    assert_eq!(protected_scope_boundary_observation(&scope_non_boundary), 0);

    let fence_rejection = Err(opc_session_net::FencedMutationRosterClientError::AuthorityRejected);
    let fence_non_boundary = Err(opc_session_net::FencedMutationRosterClientError::Unavailable);
    assert_eq!(protected_fence_boundary_observation(&fence_rejection), 1);
    assert_eq!(protected_fence_boundary_observation(&fence_non_boundary), 0);
}

#[test]
fn protected_roster_failover_resolver_excludes_node_zero_for_both_causal_losses() {
    let ready = |node_index| FleetReadiness {
        node_index,
        ready: true,
        reason_code: QualificationReadinessCode::Ready,
        node_id: u64::try_from(node_index + 1).expect("bounded node identifier"),
        term: 7,
        leader_id: Some(2),
        configured_voters: 3,
        fresh_reachable_voters: 2,
        agreeing_voters: 2,
        required_quorum: 2,
        committed_index: Some(11),
        applied_index: Some(11),
    };
    // First causal fault: the elected leader was node 0, so only nodes 1/2
    // are available to reconstruct the protected endpoint-pinned client.
    let after_leader_zero_loss = [ready(1), ready(2)];
    assert_eq!(
        protected_roster_proven_live_voter(&after_leader_zero_loss),
        1
    );

    // Second causal fault: node 0 had restarted, then was the deliberately
    // lost voter while node 1 remained leader. The resolver must again reject
    // the old endpoint rather than silently falling back to endpoints[0].
    let after_second_zero_loss = [ready(1), ready(2)];
    assert_eq!(
        protected_roster_proven_live_voter(&after_second_zero_loss),
        1
    );
}

#[test]
fn post_voter_loss_receipt_recovery_retries_only_explicit_ambiguities() {
    assert!(lease_receipt_recovery_is_retryable(&Ok(
        SessionConsumerLeaseMutationStatus::NotFound
    )));
    assert!(lease_receipt_recovery_is_retryable(&Err(
        StoreError::BackendUnavailable("transient authenticated transport loss".into())
    )));
    for result in [
        Ok(SessionConsumerLeaseMutationStatus::RequestConflict),
        Err(StoreError::StaleFence),
        Err(StoreError::TopologyAuthorityRevoked),
        Err(StoreError::InvalidKey("scope/protocol rejection".into())),
        Err(StoreError::CapabilityNotSupported(
            "authentication rejection".into(),
        )),
        Err(StoreError::LeaseExpired),
    ] {
        assert!(
            !lease_receipt_recovery_is_retryable(&result),
            "only NotFound and BackendUnavailable may consume a receipt-recovery retry"
        );
    }
}

#[test]
fn protected_tenant_bracket_credits_only_an_admitted_roster_status() {
    require_protected_roster_admitted_status_class(
        "admitted positive control",
        ProtectedRosterStatusClass::Admitted,
    );
    assert_eq!(
        protected_roster_admitted_status_observation(ProtectedRosterStatusClass::Admitted),
        1,
        "an admitted same-voter `/3` status is the required positive bracket"
    );
    assert_eq!(
        protected_roster_admitted_status_observation(ProtectedRosterStatusClass::Terminal),
        0,
        "a successful terminal status must not credit the tenant authority bracket"
    );
    assert_eq!(
        protected_roster_admitted_status_observation(ProtectedRosterStatusClass::Compacted),
        0,
        "a successful compacted status must not credit the tenant authority bracket"
    );
    assert!(
        std::panic::catch_unwind(|| {
            require_protected_roster_admitted_status_class(
                "terminal negative control",
                ProtectedRosterStatusClass::Terminal,
            );
        })
        .is_err(),
        "a successful terminal status must fail the tenant bracket"
    );
    assert!(
        std::panic::catch_unwind(|| {
            require_protected_roster_admitted_status_class(
                "compacted negative control",
                ProtectedRosterStatusClass::Compacted,
            );
        })
        .is_err(),
        "a successful compacted status must fail the tenant bracket"
    );
    assert!(
        std::panic::catch_unwind(|| {
            require_protected_roster_admitted_status(
                opc_session_net::FencedMutationRosterRecoveryOutcome::Compacted,
                "public compacted recovery outcome",
            );
        })
        .is_err(),
        "the public compacted recovery outcome must fail before it can bracket authority"
    );
    assert_eq!(
        protected_roster_status_class(
            &opc_session_net::FencedMutationRosterRecoveryOutcome::Compacted
        ),
        ProtectedRosterStatusClass::Compacted,
        "the public recovery outcome is classified before it can credit the bracket"
    );
}

#[test]
fn protected_roster_recovery_requires_exact_admitted_outcomes() {
    require_protected_roster_admitted_status_class(
        "current-fence protected-roster recovery",
        ProtectedRosterStatusClass::Admitted,
    );
    for outcome in [
        ProtectedRosterStatusClass::Terminal,
        ProtectedRosterStatusClass::Compacted,
    ] {
        assert!(
            std::panic::catch_unwind(|| {
                require_protected_roster_admitted_status_class(
                    "negative protected-roster recovery control",
                    outcome,
                );
            })
            .is_err(),
            "a successful-looking non-admitted protected-roster recovery cannot advance the restart ledger"
        );
    }
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
