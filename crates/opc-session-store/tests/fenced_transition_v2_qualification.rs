//! Long-running SDK-702 V2 history qualification.
//!
//! This is deliberately ignored in ordinary CI.  It uses three real fixed
//! durable-quorum voters and their public proposal/apply APIs; it never seeds
//! the receipt table or invokes a private state-machine helper.

#![recursion_limit = "256"]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_store::fenced_transition::FencedTransitionV2Effect;
use opc_session_store::test_support::consensus_local_durable_progress_for_test;
use opc_session_store::{
    derive_fixed_durable_quorum_consensus_identity, fenced_transition_v2_profile_digest, Clock,
    ConsensusSessionStore, EncryptedSessionPayload, FenceToken, FencedTransitionLease,
    FencedTransitionMutation, FencedTransitionMutationResult, FencedTransitionOutcome,
    FencedTransitionV2CallerNonce, FencedTransitionV2HistoryEpoch, FencedTransitionV2HistoryState,
    FencedTransitionV2Request, FencedTransitionV2RequestId, FencedTransitionV2Status, Generation,
    OwnerId, PlacementResiliencePolicy, QuorumReplicaDescriptor, QuorumTopologyConfig,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionBackend, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusStatus,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionKey, SessionKeyType,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord, Timestamp,
    ValidatedQuorumTopology, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES,
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES, FENCED_TRANSITION_V2_RECLAIM_BATCH,
    FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
};
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tokio::time::Instant;

const VOTERS: usize = 3;
const QUALIFICATION_SESSIONS: usize = 50_000;
const QUALIFICATION_SUSTAINED_RATE: usize = 500;
const QUALIFICATION_SUSTAINED_SECONDS: usize = 30 * 60;
const QUALIFICATION_BURST_RATE: usize = 1_000;
const QUALIFICATION_BURST_SECONDS: usize = 60;
const QUALIFICATION_SUSTAINED_TRANSITIONS: usize =
    QUALIFICATION_SUSTAINED_RATE * QUALIFICATION_SUSTAINED_SECONDS;
const QUALIFICATION_BURST_TRANSITIONS: usize =
    QUALIFICATION_BURST_RATE * QUALIFICATION_BURST_SECONDS;
const QUALIFICATION_RELEASE_TRANSITIONS: usize =
    QUALIFICATION_SESSIONS + QUALIFICATION_SUSTAINED_TRANSITIONS + QUALIFICATION_BURST_TRANSITIONS;
// 197 preload batches, 120,000 paced batches, 28 retained-replay batches at
// seven rotations, eight graceful-reopen replays, and one reclaim-time write.
const QUALIFICATION_EXPECTED_EFFECT_BATCHES: u64 = 120_234;
// This is the exact cardinality of the fixed proposal-batch plan, distinct
// from its 120,234 batch count: 50,000 preload + 960,000 paced + 28 retained
// replay + eight graceful-reopen replay + one reclaim request.
const QUALIFICATION_EXPECTED_EFFECT_REQUEST_SLOTS: u64 = 1_010_037;
const QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS: u64 = 10;
const QUALIFICATION_TRANSITIONS: usize = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + 1;
// This is the remaining capacity of the active epoch after the 100,000
// transition operational target. It is not the release workload's remaining
// capacity within the eight-epoch retained envelope.
const QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS: usize =
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET;
// This is the remaining capacity of the complete retained envelope after the
// 1,010,000-operation release workload.
const QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS: usize =
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES - QUALIFICATION_RELEASE_TRANSITIONS;
// Match the fixed durable quorum's bounded proposal-admission capacity. This
// represents a small, realistic client burst while leaving consensus itself to
// serialize and durably apply every proposal on the three voters.
const QUALIFICATION_IN_FLIGHT_CLIENTS: usize = DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS;
const QUALIFICATION_TRANSIENT_RETRY_LIMIT: usize = 16;
const QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF: Duration = Duration::from_millis(25);
// This qualification contract is deliberately stricter than the production
// default. A completed mutation is still classified after this instant so its
// effect is never discarded, but a qualified batch may not contribute a tail
// longer than this hard bound.
const QUALIFICATION_RELEASE_BATCH_DEADLINE: Duration = Duration::from_millis(800);
const QUALIFICATION_PRELOAD_BATCH_OPERATIONS: usize = 256;
const QUALIFICATION_MAX_PHYSICAL_EFFECT_BATCH_OPERATIONS: u64 =
    QUALIFICATION_PRELOAD_BATCH_OPERATIONS as u64;
// At 500 operations/second, an eight-item batch has a 16 ms formation window.
// That leaves real budget for quorum apply while measuring each item's full
// scheduled-arrival-to-completion latency against the 25 ms p99 contract.
const QUALIFICATION_PACED_BATCH_OPERATIONS: usize = 8;
// This fixed regression exercises the first two automatic production snapshot
// boundaries without replaying the 1.01M release workload. Every public batch
// becomes one accepted OpenRaft proposal. Three phases of 4,096-plus-eight
// batches ensure that the first publication can complete before the second
// `LogsSinceLast(4096)` boundary, while retaining the release workload's
// eight-item batch shape and at-most-eight client tasks.
const BOUNDED_SCALE_STALL_SESSION_SLOTS: usize =
    QUALIFICATION_IN_FLIGHT_CLIENTS * QUALIFICATION_PACED_BATCH_OPERATIONS + 1;
const BOUNDED_SCALE_STALL_BATCHES_PER_PHASE: usize = 4_096 + QUALIFICATION_IN_FLIGHT_CLIENTS;
const BOUNDED_SCALE_STALL_PHASES: [(&str, usize); 3] = [
    (
        "snapshot-threshold-one-500-per-second",
        QUALIFICATION_SUSTAINED_RATE,
    ),
    (
        "snapshot-threshold-two-1000-per-second",
        QUALIFICATION_BURST_RATE,
    ),
    (
        "post-publication-second-threshold-1000-per-second",
        QUALIFICATION_BURST_RATE,
    ),
];
// The isolated qualification voters contain only this feature's state. These
// fixed physical regression envelopes deliberately exceed the immutable
// semantic receipt maximum to allow SQLite pages/indexes and one bounded WAL,
// while still making accidental unbounded retention fail the release gate.
const QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES: u64 =
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES * 3;
const QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES: u64 =
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES * 2;
#[cfg(target_os = "linux")]
const QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB: u64 = 2 * 1024 * 1024;
const _: () = {
    assert!(QUALIFICATION_IN_FLIGHT_CLIENTS >= 1);
    assert!(BOUNDED_SCALE_STALL_SESSION_SLOTS >= QUALIFICATION_PACED_BATCH_OPERATIONS);
    assert!(FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES > 0);
    assert!(FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES >= QUALIFICATION_RELEASE_TRANSITIONS);
};
const FIXED_V2_PROFILE_DIGEST: [u8; 32] = [
    0x8a, 0x0b, 0x70, 0xb5, 0x46, 0x54, 0xc7, 0x25, 0x0c, 0xf5, 0x46, 0x9d, 0xb6, 0xe1, 0xe5, 0x45,
    0xf3, 0x5e, 0x38, 0xe9, 0x77, 0x8d, 0x5f, 0x50, 0x0f, 0xea, 0x67, 0x06, 0x96, 0xc4, 0xbd, 0xc3,
];

#[derive(Default)]
struct ReleaseLatencySamples {
    batch: Vec<Duration>,
    item_scheduled_to_completion: Vec<Duration>,
}

impl ReleaseLatencySamples {
    fn record_batch(
        &mut self,
        elapsed: Duration,
        completed_at: Instant,
        item_scheduled_at: &[Instant],
    ) {
        self.batch.push(elapsed);
        self.item_scheduled_to_completion
            .extend(item_scheduled_at.iter().map(|scheduled_at| {
                completed_at
                    .checked_duration_since(*scheduled_at)
                    .expect("a release batch cannot complete before an item is scheduled")
            }));
    }

    fn percentile(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
        assert!(!samples.is_empty(), "release latency samples must be real");
        samples.sort_unstable();
        let index = (samples.len() * numerator)
            .div_ceil(denominator)
            .saturating_sub(1);
        samples[index]
    }

    fn p99_and_p999(&mut self) -> (Duration, Duration, Duration, Duration) {
        (
            Self::percentile(&mut self.batch, 99, 100),
            Self::percentile(&mut self.batch, 999, 1_000),
            Self::percentile(&mut self.item_scheduled_to_completion, 99, 100),
            Self::percentile(&mut self.item_scheduled_to_completion, 999, 1_000),
        )
    }
}

#[derive(Default)]
struct ReleaseEffectCounters {
    mutation_batches: AtomicU64,
    batch_elapsed_max_us: AtomicU64,
    resolved_after_deadline: AtomicU64,
    mutation_attempts: AtomicU64,
    not_transmitted_retries: AtomicU64,
    outcome_unknown_batches: AtomicU64,
    effect_request_slots: AtomicU64,
    outcome_unknown_request_slots: AtomicU64,
    status_attempts: AtomicU64,
    status_initial_request_slots: AtomicU64,
    status_retry_request_slots: AtomicU64,
    status_retry_rounds: AtomicU64,
    mutation_deadline_before_dispatch: AtomicU64,
    not_transmitted_deadline: AtomicU64,
    deadline_after_backoff: AtomicU64,
    status_deadline_before_dispatch: AtomicU64,
    status_deadline_timeout: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseEffectCounterSnapshot {
    mutation_batches: u64,
    batch_elapsed_max_us: u64,
    resolved_after_deadline: u64,
    mutation_attempts: u64,
    not_transmitted_retries: u64,
    outcome_unknown_batches: u64,
    effect_request_slots: u64,
    outcome_unknown_request_slots: u64,
    status_attempts: u64,
    status_initial_request_slots: u64,
    status_retry_request_slots: u64,
    status_retry_rounds: u64,
    mutation_deadline_before_dispatch: u64,
    not_transmitted_deadline: u64,
    deadline_after_backoff: u64,
    status_deadline_before_dispatch: u64,
    status_deadline_timeout: u64,
}

/// Versioned, closed, redaction-safe evidence emitted only after the ignored
/// 1.01M-operation gate has satisfied every assertion. The schema alongside
/// this test is intentionally strict; this Rust type additionally performs a
/// bounded canonical round trip before any bytes reach test output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseQualificationEvidence {
    version: u8,
    /// This is completion of this exact SDK-702 qualification gate only.  It
    /// deliberately says nothing about production or ePDG maturity.
    qualification_complete: bool,
    elapsed_ms: u64,
    non_phase_overhead_ms: u64,
    source: ReleaseEvidenceSource,
    build_cargo_lock_sha256: String,
    runtime_cargo_lock_sha256: String,
    required_reproduction_recipe: String,
    libtest_argv: Vec<String>,
    artifact: ReleaseEvidenceArtifact,
    execution: ReleaseEvidenceExecution,
    quiet_host: ReleaseEvidenceQuietHost,
    process_loss: ReleaseEvidenceProcessLoss,
    profile: ReleaseEvidenceProfile,
    schedule: ReleaseEvidenceSchedule,
    resources: ReleaseEvidenceResources,
    lifecycle: ReleaseEvidenceLifecycle,
    outcomes: ReleaseEvidenceOutcomes,
    effects: ReleaseEffectCounterSnapshot,
    phases: Vec<ReleaseEvidencePhase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceSource {
    build_revision: String,
    build_tree: String,
    source_worktree_sha256: String,
    revision: String,
    tree: String,
    worktree: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceArtifact {
    mechanism: String,
    path_id: String,
    cooperative_same_uid_boundary: String,
}

/// The execution identity is deliberately limited to values that can be
/// observed by this test binary.  In particular, it does not claim to have
/// observed Cargo's parent-process argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceExecution {
    cargo_target_dir_id: String,
    fs_verity_snapshot_base_id: String,
    fs_verity_snapshot_root_id: String,
    fs_verity_snapshot_root_device: u64,
    fs_verity_snapshot_root_inode: u64,
    current_exe_relative_to_target_id: String,
    current_exe_sha256: String,
    current_exe_device: u64,
    current_exe_inode: u64,
    compiled_schema_sha256: String,
    build_attestation_path_id: String,
    build_attestation_sha256: String,
    build_attestation_wrapper_sha256: String,
    build_attestation_boundary: String,
    target_os: String,
    target_arch: String,
    target_env: String,
    enabled_features: Vec<String>,
    runner_quiet_host_boundary: String,
}

/// This records sampled coverage, not an impossible claim that an arbitrary
/// short-lived host process could not run between Linux `/proc` observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceQuietHost {
    boundary: String,
    cadence_ms: u64,
    maximum_sample_gap_us: u64,
    monitored_elapsed_ms: u64,
    samples: u64,
    start_sampled: bool,
    end_sampled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceProfile {
    cargo_profile_family: String,
    cargo_opt_level: String,
    debug_assertions: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceSchedule {
    preload_operations: u64,
    sustained_operations: u64,
    sustained_rate_per_second: u64,
    sustained_seconds: u64,
    burst_operations: u64,
    burst_rate_per_second: u64,
    burst_seconds: u64,
    total_operations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceResources {
    voters: u64,
    in_flight_clients: u64,
    batch_deadline_ms: u64,
    operational_headroom_transitions: u64,
    retained_envelope_headroom_transitions: u64,
    database_ceiling_bytes_per_voter: u64,
    snapshot_ceiling_bytes_per_voter: u64,
    process_peak_rss_ceiling_kib: u64,
    pre_reclaim_database_bytes_by_voter: Vec<u64>,
    pre_reclaim_snapshot_bytes_by_voter: Vec<u64>,
    post_reclaim_database_bytes_by_voter: Vec<u64>,
    post_reclaim_snapshot_bytes_by_voter: Vec<u64>,
    database_artifacts_by_voter: Vec<u64>,
    snapshot_artifacts_by_voter: Vec<u64>,
    peak_rss_kib: u64,
    peak_rss_measurement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceLifecycle {
    rotations: u64,
    graceful_same_process_engine_reopens: u64,
    logical_in_process_voters: u64,
    reclaim_batches: u64,
    reclaimed_entries: u64,
    reclaim_remaining: u64,
    maintenance_attempts: u64,
    maintenance_elapsed_max_us: u64,
    maintenance_resolved_after_800ms: u64,
    maintenance_deadline_exceeded: u64,
    maintenance_failures: u64,
    production_maintenance_invocations: u64,
    production_maintenance_ok: u64,
    production_maintenance_err: u64,
    post_commit_reply_loss_projections: u64,
    maintenance_readback_projections: u64,
}

/// A separately executed current-head testkit run. The store lane stays
/// explicitly limited to a graceful same-process reopen; it does not claim
/// process loss by virtue of this in-process test alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceProcessLoss {
    scope: String,
    companion_path_id: String,
    companion_sha256: String,
    companion_schema_sha256: String,
    companion_source_revision: String,
    companion_source_tree: String,
    companion_source_worktree_sha256: String,
    companion_v1_canonical_sha256: String,
    companion_invocation_argv_sha256: String,
    companion_harness_sha256: String,
    companion_child_sha256: String,
    companion_executable_sha256: String,
    strict_validation_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidenceOutcomes {
    release_operations_committed: u64,
    matched_workload_outcomes: u64,
    reclaim_operations_committed: u64,
    matched_reclaim_outcomes: u64,
    total_operations_committed: u64,
    transient_exact_retries: u64,
    read_only_observation_retries: u64,
    maintenance_reconciliation_retries: u64,
    effect_not_transmitted_retries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEvidencePhase {
    name: String,
    offered_ops_per_second: u64,
    operations: u64,
    elapsed_ms: u64,
    batch_samples: u64,
    item_samples: u64,
    peak_unjoined_batch_task_slots: u64,
    batch_p99_us: u64,
    batch_p999_us: u64,
    batch_max_us: u64,
    item_p99_us: u64,
    item_p999_us: u64,
    item_max_us: u64,
}

impl ReleaseEffectCounters {
    /// Record a batch only after its exact, unquantized completion duration
    /// has met the qualification deadline.  Evidence uses microseconds, so
    /// comparing after `as_micros` would incorrectly accept 800ms + 1ns.
    fn record_qualified_batch_elapsed(&self, elapsed: Duration) -> Result<(), ReleaseBatchFailure> {
        if elapsed > QUALIFICATION_RELEASE_BATCH_DEADLINE {
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::CompletionDeadlineExceeded,
            });
        }
        let elapsed_us = u64::try_from(elapsed.as_micros())
            .expect("release batch elapsed microseconds fit the evidence counter");
        checked_counter_increment(&self.mutation_batches, "release mutation batches");
        checked_counter_max(
            &self.batch_elapsed_max_us,
            elapsed_us,
            "release batch elapsed maximum",
        );
        Ok(())
    }

    fn record_batch_elapsed(&self, deadline: Instant) -> Result<(), ReleaseBatchFailure> {
        let started = deadline
            .checked_sub(QUALIFICATION_RELEASE_BATCH_DEADLINE)
            .expect("release batch deadline has its exact qualification duration");
        self.record_qualified_batch_elapsed(Instant::now().duration_since(started))
    }

    fn snapshot(&self) -> ReleaseEffectCounterSnapshot {
        ReleaseEffectCounterSnapshot {
            mutation_batches: self.mutation_batches.load(Ordering::Relaxed),
            batch_elapsed_max_us: self.batch_elapsed_max_us.load(Ordering::Relaxed),
            resolved_after_deadline: self.resolved_after_deadline.load(Ordering::Relaxed),
            mutation_attempts: self.mutation_attempts.load(Ordering::Relaxed),
            not_transmitted_retries: self.not_transmitted_retries.load(Ordering::Relaxed),
            outcome_unknown_batches: self.outcome_unknown_batches.load(Ordering::Relaxed),
            effect_request_slots: self.effect_request_slots.load(Ordering::Relaxed),
            outcome_unknown_request_slots: self
                .outcome_unknown_request_slots
                .load(Ordering::Relaxed),
            status_attempts: self.status_attempts.load(Ordering::Relaxed),
            status_initial_request_slots: self.status_initial_request_slots.load(Ordering::Relaxed),
            status_retry_request_slots: self.status_retry_request_slots.load(Ordering::Relaxed),
            status_retry_rounds: self.status_retry_rounds.load(Ordering::Relaxed),
            mutation_deadline_before_dispatch: self
                .mutation_deadline_before_dispatch
                .load(Ordering::Relaxed),
            not_transmitted_deadline: self.not_transmitted_deadline.load(Ordering::Relaxed),
            deadline_after_backoff: self.deadline_after_backoff.load(Ordering::Relaxed),
            status_deadline_before_dispatch: self
                .status_deadline_before_dispatch
                .load(Ordering::Relaxed),
            status_deadline_timeout: self.status_deadline_timeout.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct ReleaseLifecycleMutationCounters {
    attempts: AtomicU64,
    elapsed_max_us: AtomicU64,
    resolved_after_800ms: AtomicU64,
    deadline_exceeded: AtomicU64,
    failures: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ReleaseLifecycleMutationCounterSnapshot {
    attempts: u64,
    elapsed_max_us: u64,
    resolved_after_800ms: u64,
    deadline_exceeded: u64,
    failures: u64,
}

/// Physical local-leader invocations are deliberately distinct from the ten
/// logical lifecycle operations.  A readback-based reconciliation can turn an
/// unavailable reply into one logical success without pretending that the
/// original production invocation did not return an error to its caller.
#[derive(Default)]
struct ProductionMaintenanceCounters {
    invocations: AtomicU64,
    ok: AtomicU64,
    err: AtomicU64,
    post_commit_reply_loss_projections: AtomicU64,
    readback_projections: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ProductionMaintenanceCounterSnapshot {
    invocations: u64,
    ok: u64,
    err: u64,
    post_commit_reply_loss_projections: u64,
    readback_projections: u64,
}

impl ProductionMaintenanceCounters {
    fn record_invocation<T>(&self, result: &Result<T, StoreError>) {
        checked_counter_increment(&self.invocations, "production maintenance invocations");
        if result.is_ok() {
            checked_counter_increment(&self.ok, "production maintenance successes");
        } else {
            checked_counter_increment(&self.err, "production maintenance errors");
        }
    }

    fn snapshot(&self) -> ProductionMaintenanceCounterSnapshot {
        ProductionMaintenanceCounterSnapshot {
            invocations: self.invocations.load(Ordering::Relaxed),
            ok: self.ok.load(Ordering::Relaxed),
            err: self.err.load(Ordering::Relaxed),
            post_commit_reply_loss_projections: self
                .post_commit_reply_loss_projections
                .load(Ordering::Relaxed),
            readback_projections: self.readback_projections.load(Ordering::Relaxed),
        }
    }
}

fn checked_counter_increment(counter: &AtomicU64, label: &str) {
    checked_counter_increment_by(counter, 1, label);
}

fn checked_counter_increment_by(counter: &AtomicU64, increment: u64, label: &str) {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(increment)
        })
        .unwrap_or_else(|_| panic!("{label} counter overflow"));
}

fn checked_counter_max(counter: &AtomicU64, value: u64, label: &str) {
    let mut observed = counter.load(Ordering::Relaxed);
    while value > observed {
        match counter.compare_exchange_weak(observed, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(current) => observed = current,
        }
    }
    let _ = label;
}

impl ReleaseLifecycleMutationCounters {
    fn record<T>(&self, started: Instant, result: &Result<T, StoreError>, accepted: bool) {
        self.record_elapsed(started.elapsed(), result, accepted);
    }

    fn record_elapsed<T>(&self, elapsed: Duration, result: &Result<T, StoreError>, accepted: bool) {
        checked_counter_increment(&self.attempts, "maintenance attempts");
        // Compare the exact Duration before lossy microsecond quantization:
        // 800ms + 1ns is a late lifecycle result even though its serialized
        // integer-microsecond maximum is still 800,000.
        let elapsed_us = u64::try_from(elapsed.as_micros())
            .expect("maintenance elapsed microseconds fit the evidence counter");
        checked_counter_max(
            &self.elapsed_max_us,
            elapsed_us,
            "maintenance elapsed maximum",
        );
        if elapsed > QUALIFICATION_RELEASE_BATCH_DEADLINE {
            // There is intentionally no timeout here: a lifecycle CAS is
            // classified to completion and then recorded as late.  Counting
            // the completed-late and deadline facts separately keeps a
            // future change from hiding a late Err behind an early return.
            checked_counter_increment(&self.resolved_after_800ms, "maintenance late resolution");
            checked_counter_increment(&self.deadline_exceeded, "maintenance deadline exceeded");
        }
        if !accepted {
            let _ = result;
            checked_counter_increment(&self.failures, "maintenance failures");
        }
    }

    fn snapshot(&self) -> ReleaseLifecycleMutationCounterSnapshot {
        ReleaseLifecycleMutationCounterSnapshot {
            attempts: self.attempts.load(Ordering::Relaxed),
            elapsed_max_us: self.elapsed_max_us.load(Ordering::Relaxed),
            resolved_after_800ms: self.resolved_after_800ms.load(Ordering::Relaxed),
            deadline_exceeded: self.deadline_exceeded.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }
}

/// Classify a local-leader lifecycle mutation eventually.  It deliberately
/// never wraps the future in `timeout`, retries it, or replays an ambiguous
/// maintenance CAS: the operation itself owns its public reconciliation
/// semantics and this wrapper only measures its completed classification.
async fn measure_eventual_lifecycle_mutation<T, Operation, IsAccepted>(
    counters: &ReleaseLifecycleMutationCounters,
    operation: Operation,
    is_accepted: IsAccepted,
) -> Result<T, StoreError>
where
    Operation: Future<Output = Result<T, StoreError>>,
    IsAccepted: FnOnce(&Result<T, StoreError>) -> bool,
{
    let started = Instant::now();
    let result = operation.await;
    let accepted = is_accepted(&result);
    counters.record(started, &result, accepted);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseBatchFailureStage {
    TaskJoinFailed,
    BatchCardinalityInvalid,
    CompletionDeadlineExceeded,
    NotTransmittedExhausted,
    NotTransmittedRejected,
    EffectUnsupported,
    OutcomeIdentityMismatch,
    ResolvedBatchError,
    ResolvedItemError,
    RecordedItemError,
    ResolvedShapeMismatch,
    RecordedOutcomeMismatch,
    StatusReadRejected,
    StatusUnresolved,
    MutationDeadlineBeforeDispatch,
    NotTransmittedDeadline,
    DeadlineAfterBackoff,
    StatusDeadlineBeforeDispatch,
    StatusDeadlineTimeout,
}

fn release_batch_expected_no_effect_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::FencedTransitionHistoryFull
            | StoreError::FencedTransitionRequestConflict
            | StoreError::FencedTransitionRequestExpired
    )
}

impl ReleaseBatchFailureStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TaskJoinFailed => "task_join_failed",
            Self::BatchCardinalityInvalid => "batch_cardinality_invalid",
            Self::CompletionDeadlineExceeded => "completion_deadline_exceeded",
            Self::NotTransmittedExhausted => "not_transmitted_exhausted",
            Self::NotTransmittedRejected => "not_transmitted_rejected",
            Self::EffectUnsupported => "effect_unsupported",
            Self::OutcomeIdentityMismatch => "outcome_identity_mismatch",
            Self::ResolvedBatchError => "resolved_batch_error",
            Self::ResolvedItemError => "resolved_item_error",
            Self::RecordedItemError => "recorded_item_error",
            Self::ResolvedShapeMismatch => "resolved_shape_mismatch",
            Self::RecordedOutcomeMismatch => "recorded_outcome_mismatch",
            Self::StatusReadRejected => "status_read_rejected",
            Self::StatusUnresolved => "status_unresolved",
            Self::MutationDeadlineBeforeDispatch => "mutation_deadline_before_dispatch",
            Self::NotTransmittedDeadline => "not_transmitted_deadline",
            Self::DeadlineAfterBackoff => "deadline_after_backoff",
            Self::StatusDeadlineBeforeDispatch => "status_deadline_before_dispatch",
            Self::StatusDeadlineTimeout => "status_deadline_timeout",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReleaseBatchFailure {
    stage: ReleaseBatchFailureStage,
}

type ReleaseBatchOutcomes = Vec<Result<FencedTransitionOutcome, StoreError>>;
type ReleaseBatchEffect = FencedTransitionV2Effect<Result<ReleaseBatchOutcomes, StoreError>>;

struct ReleaseBatchCompletion {
    requests: Vec<FencedTransitionV2Request>,
    outcomes: Vec<Result<FencedTransitionOutcome, StoreError>>,
    session_slots: Vec<usize>,
    scheduled_at: Vec<Instant>,
    batch_elapsed: Duration,
    completed_at: Instant,
    successor_first_item: bool,
}

async fn collect_next_release_batch(
    in_flight: &mut JoinSet<Result<ReleaseBatchCompletion, ReleaseBatchFailure>>,
    in_flight_session_slots: &mut BTreeSet<usize>,
    latency: &mut ReleaseLatencySamples,
    sessions: &mut [(FencedTransitionV2Request, FencedTransitionOutcome)],
    representatives: &mut Vec<(FencedTransitionV2Request, FencedTransitionOutcome)>,
    matched_workload_outcomes: &AtomicU64,
) -> Result<usize, ReleaseBatchFailure> {
    let completion = in_flight
        .join_next()
        .await
        .expect("a release batch must remain in flight")
        .map_err(|_| ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::TaskJoinFailed,
        })??;
    let ReleaseBatchCompletion {
        requests,
        outcomes,
        session_slots,
        scheduled_at,
        batch_elapsed,
        completed_at,
        successor_first_item,
    } = completion;
    let batch_len = requests.len();
    if outcomes.len() != batch_len || session_slots.len() != batch_len {
        return Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::ResolvedShapeMismatch,
        });
    }
    latency.record_batch(batch_elapsed, completed_at, &scheduled_at);
    for (batch_offset, ((request, outcome), slot)) in requests
        .into_iter()
        .zip(outcomes)
        .zip(session_slots)
        .enumerate()
    {
        if !in_flight_session_slots.remove(&slot) {
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::ResolvedShapeMismatch,
            });
        }
        let outcome = outcome.map_err(|_| ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::ResolvedItemError,
        })?;
        if !is_exact_qualified_v2_success(&request, &outcome) {
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::ResolvedShapeMismatch,
            });
        }
        matched_workload_outcomes.fetch_add(1, Ordering::Relaxed);
        if successor_first_item && batch_offset == 0 {
            representatives.push((request.clone(), outcome.clone()));
        }
        sessions[slot] = (request, outcome);
    }
    Ok(batch_len)
}

struct BoundedScaleDiagnostics<'a> {
    stores: &'a [ConsensusSessionStore],
    effect_counters: &'a ReleaseEffectCounters,
    read_backend_unavailable_retries: &'a AtomicU64,
}

#[derive(Clone, Copy)]
struct BoundedScaleProgress {
    phase_name: &'static str,
    target_rate: usize,
    phase_started: Instant,
    workload_elapsed: Option<Duration>,
    submitted_batches: usize,
    completed_batches: usize,
    peak_unjoined_batch_task_slots: usize,
}

struct BoundedScaleObservation<'a> {
    progress: BoundedScaleProgress,
    latency: &'a mut ReleaseLatencySamples,
}

fn bounded_scale_observation<'a>(
    phase_name: &'static str,
    target_rate: usize,
    phase_started: Instant,
    submitted_batches: usize,
    completed_batches: usize,
    peak_unjoined_batch_task_slots: usize,
    latency: &'a mut ReleaseLatencySamples,
) -> BoundedScaleObservation<'a> {
    BoundedScaleObservation {
        progress: BoundedScaleProgress {
            phase_name,
            target_rate,
            phase_started,
            workload_elapsed: None,
            submitted_batches,
            completed_batches,
            peak_unjoined_batch_task_slots,
        },
        latency,
    }
}

impl BoundedScaleObservation<'_> {
    fn with_workload_elapsed(mut self, workload_elapsed: Duration) -> Self {
        self.progress.workload_elapsed = Some(workload_elapsed);
        self
    }
}

/// Emit only fixed-dimension evidence for the bounded snapshot-scale
/// regression. In particular, neither a request body nor a backend error is
/// rendered: the fixed test fixture's consensus status and diagnostic snapshot
/// types have redaction-safe `Debug` surfaces.
fn emit_bounded_scale_stall_observation(
    diagnostics: &BoundedScaleDiagnostics<'_>,
    stage: &str,
    observation: &mut BoundedScaleObservation<'_>,
) {
    let BoundedScaleProgress {
        phase_name,
        target_rate,
        phase_started,
        workload_elapsed,
        submitted_batches,
        completed_batches,
        peak_unjoined_batch_task_slots,
    } = observation.progress;
    let elapsed = workload_elapsed.unwrap_or_else(|| phase_started.elapsed());
    let completed_operations = completed_batches * QUALIFICATION_PACED_BATCH_OPERATIONS;
    let achieved_ops_per_second_milli = if elapsed.is_zero() {
        0_u128
    } else {
        (completed_operations as u128)
            .checked_mul(1_000)
            .expect("bounded diagnostic rate numerator")
            .checked_mul(1_000_000_000)
            .expect("bounded diagnostic rate nanosecond numerator")
            / elapsed.as_nanos()
    };
    let latency_summary =
        (!observation.latency.batch.is_empty()).then(|| observation.latency.p99_and_p999());
    let voter_status = diagnostics
        .stores
        .iter()
        .map(ConsensusSessionStore::status)
        .collect::<Vec<_>>();
    let completed_snapshot_count_by_voter = voter_status
        .iter()
        .map(|status| status.completed_snapshot_count)
        .collect::<Vec<_>>();
    let voter_diagnostics = diagnostics
        .stores
        .iter()
        .map(ConsensusSessionStore::diagnostic_snapshot)
        .collect::<Vec<_>>();
    let voter_engine_progress = diagnostics
        .stores
        .iter()
        .map(consensus_local_durable_progress_for_test)
        .collect::<Vec<_>>();
    let effect_snapshot = diagnostics.effect_counters.snapshot();
    let read_backend_unavailable_retries = diagnostics
        .read_backend_unavailable_retries
        .load(Ordering::Relaxed);
    let (batch_p99_us, batch_p999_us, item_p99_us, item_p999_us) = latency_summary
        .map(|(batch_p99, batch_p999, item_p99, item_p999)| {
            (
                Some(batch_p99.as_micros()),
                Some(batch_p999.as_micros()),
                Some(item_p99.as_micros()),
                Some(item_p999.as_micros()),
            )
        })
        .unwrap_or((None, None, None, None));
    eprintln!(
        "sdk-704 bounded snapshot scale: phase={phase_name} stage={stage} offered_ops_per_second={target_rate} submitted_batches={submitted_batches} completed_batches={completed_batches} completed_operations={completed_operations} achieved_ops_per_second_milli={achieved_ops_per_second_milli} peak_unjoined_batch_task_slots={peak_unjoined_batch_task_slots} batch_p99_us={batch_p99_us:?} batch_p999_us={batch_p999_us:?} item_p99_us={item_p99_us:?} item_p999_us={item_p999_us:?} elapsed_ms={} read_backend_unavailable_retries={read_backend_unavailable_retries} effect_counters={effect_snapshot:?} completed_snapshot_count_by_voter={completed_snapshot_count_by_voter:?} voter_status={voter_status:?} voter_engine_progress={voter_engine_progress:?} voter_diagnostics={voter_diagnostics:?}",
        elapsed.as_millis(),
    );
}

/// Preserve the isolated voter artifacts after a controlled scale failure.
/// The shutdown result is reduced to one safe boolean so a failed engine is
/// never formatted into qualification output.
async fn fail_bounded_scale_stall(
    directory: tempfile::TempDir,
    peer_slots: &[Arc<ScopedLoopbackPeer>],
    diagnostics: &BoundedScaleDiagnostics<'_>,
    stage: &str,
    observation: &mut BoundedScaleObservation<'_>,
) {
    emit_bounded_scale_stall_observation(diagnostics, stage, observation);
    futures_util::future::join_all(peer_slots.iter().map(|peer| peer.clear())).await;
    let shutdown_complete = futures_util::future::join_all(
        diagnostics
            .stores
            .iter()
            .map(ConsensusSessionStore::shutdown),
    )
    .await
    .iter()
    .all(Result::is_ok);
    let preserved_directory = directory.keep();
    let phase_name = observation.progress.phase_name;
    panic!(
        "SDK-704 bounded snapshot-scale regression failed closed at phase={phase_name} stage={stage} shutdown_complete={shutdown_complete} preserved_directory={}",
        preserved_directory.display(),
    );
}

#[derive(Debug, Clone)]
struct MutableClock(Arc<Mutex<Timestamp>>);

impl MutableClock {
    fn new(now: Timestamp) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    fn set(&self, now: Timestamp) {
        *self.0.lock().expect("qualification clock mutex") = now;
    }
}

impl Clock for MutableClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().expect("qualification clock mutex")
    }
}

async fn retry_exact_consensus_operation<T, Operation, OperationFuture>(
    transient_retries: &AtomicU64,
    mut operation: Operation,
) -> Result<T, StoreError>
where
    Operation: FnMut() -> OperationFuture,
    OperationFuture: Future<Output = Result<T, StoreError>>,
{
    for attempt in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        match operation().await {
            Ok(value) => return Ok(value),
            // This generic helper is deliberately read-only-only. Keep the
            // ambiguous mutation outcome explicit so a future broad retry
            // arm cannot silently retransmit a mutation-shaped operation.
            Err(StoreError::FencedTransitionOutcomeUnknown) => {
                return Err(StoreError::FencedTransitionOutcomeUnknown);
            }
            Err(StoreError::BackendUnavailable(_))
                if attempt < QUALIFICATION_TRANSIENT_RETRY_LIMIT =>
            {
                transient_retries.fetch_add(1, Ordering::Relaxed);
                // This helper is used only for immutable observations. An
                // ambiguous mutation must instead converge through its exact
                // request status without being transmitted again.
                tokio::time::sleep(QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the bounded retry loop returns on its final attempt")
}

/// Execute one exact V2 batch without ever redispatching a mutation whose
/// proposal effect is ambiguous. Only a backend-proved `NotTransmitted`
/// unavailability may retry the same complete body. Once any request may have
/// crossed the effect boundary, convergence is read-only and retains every
/// original request body in input order.
async fn execute_release_batch_effect<Execute, ExecuteFuture, Status, StatusFuture>(
    deadline: Instant,
    requests: Vec<FencedTransitionV2Request>,
    counters: &ReleaseEffectCounters,
    mut execute: Execute,
    status: Status,
) -> Result<ReleaseBatchOutcomes, ReleaseBatchFailure>
where
    Execute: FnMut(Vec<FencedTransitionV2Request>) -> ExecuteFuture + Send,
    ExecuteFuture: Future<Output = ReleaseBatchEffect> + Send,
    Status: Fn(FencedTransitionV2Request) -> StatusFuture + Sync,
    StatusFuture: Future<Output = Result<FencedTransitionV2Status, StoreError>> + Send,
{
    let request_slot_count = u64::try_from(requests.len())
        .expect("release batch request-slot count fits evidence counter");
    if request_slot_count == 0
        || request_slot_count > QUALIFICATION_MAX_PHYSICAL_EFFECT_BATCH_OPERATIONS
    {
        return Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::BatchCardinalityInvalid,
        });
    }
    checked_counter_increment_by(
        &counters.effect_request_slots,
        request_slot_count,
        "release effect request slots",
    );
    let request_ids = requests
        .iter()
        .map(FencedTransitionV2Request::request_id)
        .collect::<Vec<FencedTransitionV2RequestId>>();

    for attempt in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        if Instant::now() >= deadline {
            counters
                .mutation_deadline_before_dispatch
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::MutationDeadlineBeforeDispatch,
            });
        }
        counters.mutation_attempts.fetch_add(1, Ordering::Relaxed);
        // A dispatched mutation owns its complete effect classification. Do
        // not cancel it at this caller deadline and accidentally treat a
        // possible transmission as a retry-safe absence of transmission.
        let effect = execute(requests.clone()).await;
        match effect {
            FencedTransitionV2Effect::Resolved(Ok(outcomes)) => {
                if outcomes.len() != requests.len() {
                    return Err(ReleaseBatchFailure {
                        stage: ReleaseBatchFailureStage::ResolvedShapeMismatch,
                    });
                }
                for (outcome, request) in outcomes.iter().zip(&requests) {
                    match outcome {
                        Ok(outcome) if outcome.matches_v2_request(request) => {}
                        Ok(_) => {
                            return Err(ReleaseBatchFailure {
                                stage: ReleaseBatchFailureStage::ResolvedShapeMismatch,
                            });
                        }
                        // A completed effect may also be a deterministic
                        // no-effect rejection. It is still resolved and must
                        // not be retried or discarded for a deadline that
                        // elapsed after the mutation returned.
                        Err(error) if release_batch_expected_no_effect_error(error) => {}
                        Err(_) => {
                            return Err(ReleaseBatchFailure {
                                stage: ReleaseBatchFailureStage::ResolvedItemError,
                            });
                        }
                    }
                }
                if Instant::now() > deadline {
                    counters
                        .resolved_after_deadline
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Ok(outcomes);
            }
            FencedTransitionV2Effect::Resolved(Err(_)) => {
                // A resolved batch-level Err is still a completed mutation
                // classification.  It must contribute to the same late
                // accounting as a resolved Ok rather than disappearing from
                // the evidence merely because the caller rejects it.
                if Instant::now() > deadline {
                    counters
                        .resolved_after_deadline
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::ResolvedBatchError,
                });
            }
            FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(_))
                if attempt < QUALIFICATION_TRANSIENT_RETRY_LIMIT =>
            {
                if Instant::now() >= deadline {
                    counters
                        .not_transmitted_deadline
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(ReleaseBatchFailure {
                        stage: ReleaseBatchFailureStage::NotTransmittedDeadline,
                    });
                }
                let remaining = match deadline.checked_duration_since(Instant::now()) {
                    Some(remaining) => remaining,
                    None => {
                        counters
                            .not_transmitted_deadline
                            .fetch_add(1, Ordering::Relaxed);
                        return Err(ReleaseBatchFailure {
                            stage: ReleaseBatchFailureStage::NotTransmittedDeadline,
                        });
                    }
                };
                tokio::time::sleep(remaining.min(QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF)).await;
                if Instant::now() >= deadline {
                    counters
                        .deadline_after_backoff
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(ReleaseBatchFailure {
                        stage: ReleaseBatchFailureStage::DeadlineAfterBackoff,
                    });
                }
                counters
                    .not_transmitted_retries
                    .fetch_add(1, Ordering::Relaxed);
            }
            FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(_)) => {
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::NotTransmittedExhausted,
                });
            }
            FencedTransitionV2Effect::NotTransmitted(_) => {
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::NotTransmittedRejected,
                });
            }
            FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: received,
            } => {
                if received != request_ids {
                    return Err(ReleaseBatchFailure {
                        stage: ReleaseBatchFailureStage::OutcomeIdentityMismatch,
                    });
                }
                counters
                    .outcome_unknown_batches
                    .fetch_add(1, Ordering::Relaxed);
                checked_counter_increment_by(
                    &counters.outcome_unknown_request_slots,
                    request_slot_count,
                    "outcome-unknown request slots",
                );
                break;
            }
            _ => {
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::EffectUnsupported,
                });
            }
        }
    }

    let mut resolved = vec![None; requests.len()];
    for round in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        if Instant::now() >= deadline {
            counters
                .status_deadline_before_dispatch
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::StatusDeadlineBeforeDispatch,
            });
        }
        let pending = resolved
            .iter()
            .enumerate()
            .filter_map(|(index, result)| result.is_none().then_some(index))
            .collect::<Vec<_>>();
        let pending_slots = u64::try_from(pending.len())
            .expect("pending status request-slot count fits evidence counter");
        if round == 0 {
            checked_counter_increment_by(
                &counters.status_initial_request_slots,
                pending_slots,
                "initial status request slots",
            );
        } else {
            checked_counter_increment_by(
                &counters.status_retry_request_slots,
                pending_slots,
                "retry status request slots",
            );
        }
        let mut pending_observations = Vec::with_capacity(pending.len());
        for index in pending {
            // Status is immutable and can be cancelled by `timeout_at`, but
            // it still must not begin once the caller's convergence budget
            // has elapsed.
            if Instant::now() >= deadline {
                counters
                    .status_deadline_before_dispatch
                    .fetch_add(1, Ordering::Relaxed);
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::StatusDeadlineBeforeDispatch,
                });
            }
            let request = requests[index].clone();
            let observation = status(request.clone());
            counters.status_attempts.fetch_add(1, Ordering::Relaxed);
            pending_observations.push(async move { (index, request, observation.await) });
        }
        let observations = match tokio::time::timeout_at(
            deadline,
            futures_util::future::join_all(pending_observations),
        )
        .await
        {
            Ok(observations) => observations,
            Err(_) => {
                counters
                    .status_deadline_timeout
                    .fetch_add(1, Ordering::Relaxed);
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::StatusDeadlineTimeout,
                });
            }
        };

        for (index, request, observation) in observations {
            match observation {
                Ok(FencedTransitionV2Status::Recorded(recorded)) => {
                    let recorded = *recorded;
                    match &recorded {
                        Ok(outcome) if outcome.matches_v2_request(&request) => {}
                        Ok(_) => {
                            return Err(ReleaseBatchFailure {
                                stage: ReleaseBatchFailureStage::RecordedOutcomeMismatch,
                            });
                        }
                        Err(error) if release_batch_expected_no_effect_error(error) => {}
                        Err(_) => {
                            return Err(ReleaseBatchFailure {
                                stage: ReleaseBatchFailureStage::RecordedItemError,
                            });
                        }
                    }
                    resolved[index] = Some(recorded);
                }
                Ok(FencedTransitionV2Status::NotFound) | Err(StoreError::BackendUnavailable(_)) => {
                }
                Ok(FencedTransitionV2Status::RequestConflict) => {
                    resolved[index] = Some(Err(StoreError::FencedTransitionRequestConflict));
                }
                Ok(FencedTransitionV2Status::Expired) => {
                    resolved[index] = Some(Err(StoreError::FencedTransitionRequestExpired));
                }
                Ok(FencedTransitionV2Status::Retired) => {
                    resolved[index] = Some(Err(StoreError::FencedTransitionHistoryEpochRetired));
                }
                Ok(FencedTransitionV2Status::HistoryFull) => {
                    resolved[index] = Some(Err(StoreError::FencedTransitionHistoryFull));
                }
                Ok(FencedTransitionV2Status::EpochNotActive) => {
                    resolved[index] = Some(Err(StoreError::FencedTransitionHistoryEpochNotActive));
                }
                Ok(FencedTransitionV2Status::RetentionExhausted) => {
                    resolved[index] = Some(Err(StoreError::FencedTransitionRetentionExhausted));
                }
                Err(_) => {
                    return Err(ReleaseBatchFailure {
                        stage: ReleaseBatchFailureStage::StatusReadRejected,
                    });
                }
            }
        }

        if resolved.iter().all(Option::is_some) {
            return Ok(resolved
                .into_iter()
                .map(|result| result.expect("every exact V2 status is resolved"))
                .collect());
        }
        if round == QUALIFICATION_TRANSIENT_RETRY_LIMIT {
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::StatusUnresolved,
            });
        }
        counters.status_retry_rounds.fetch_add(1, Ordering::Relaxed);
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining,
            None => {
                counters
                    .status_deadline_before_dispatch
                    .fetch_add(1, Ordering::Relaxed);
                return Err(ReleaseBatchFailure {
                    stage: ReleaseBatchFailureStage::StatusDeadlineBeforeDispatch,
                });
            }
        };
        tokio::time::sleep(remaining.min(QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF)).await;
        if Instant::now() >= deadline {
            counters
                .deadline_after_backoff
                .fetch_add(1, Ordering::Relaxed);
            return Err(ReleaseBatchFailure {
                stage: ReleaseBatchFailureStage::DeadlineAfterBackoff,
            });
        }
    }
    unreachable!("the bounded status convergence loop returns on its final attempt")
}

async fn execute_release_store_batch(
    deadline: Instant,
    store: &ConsensusSessionStore,
    requests: Vec<FencedTransitionV2Request>,
    counters: &ReleaseEffectCounters,
) -> Result<ReleaseBatchOutcomes, ReleaseBatchFailure> {
    let result = execute_release_batch_effect(
        deadline,
        requests,
        counters,
        |requests| SessionBackend::fenced_transition_v2_batch_effect(store, requests),
        |request| async move { store.fenced_transition_v2_status(&request).await },
    )
    .await;
    // This is intentionally after eventual effect classification: no
    // mutation is cancelled to meet the bound.  The exact `Duration` check
    // then fails the qualification before its lossy microsecond value can be
    // serialized into successful evidence.
    counters.record_batch_elapsed(deadline)?;
    result
}

/// Execute one mutation-shaped request through the effect boundary. An
/// ambiguous dispatch converges through only its immutable exact status; it
/// is never handed to the generic read retry helper.
async fn execute_release_store_transition(
    deadline: Instant,
    store: &ConsensusSessionStore,
    request: FencedTransitionV2Request,
    counters: &ReleaseEffectCounters,
) -> Result<FencedTransitionOutcome, ReleaseBatchFailure> {
    let outcomes = execute_release_store_batch(deadline, store, vec![request], counters).await?;
    match outcomes.as_slice() {
        [Ok(outcome)] => Ok(outcome.clone()),
        [Err(_)] => Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::ResolvedItemError,
        }),
        _ => Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::ResolvedShapeMismatch,
        }),
    }
}

/// Select the store that can perform local-only maintenance from the newest
/// Openraft observations. A former leader can retain a self-report briefly,
/// so only a self-report in the highest observed admitted term is eligible.
fn current_local_maintenance_leader_from_statuses(
    statuses: &[SessionConsensusStatus],
) -> Option<usize> {
    let highest_term = statuses
        .iter()
        .filter(|status| status.admitted)
        .map(|status| status.term)
        .max()?;
    let mut leaders = statuses.iter().enumerate().filter(|(_, status)| {
        status.admitted && status.term == highest_term && status.leader_id == Some(status.node_id)
    });
    let (leader_index, _) = leaders.next()?;
    leaders.next().is_none().then_some(leader_index)
}

/// Wait only for an unambiguous, current-term local leader. The maintenance
/// call itself still enforces fixed-quorum admission and local leadership; this
/// selector merely avoids invoking that intentionally non-forwarding API on a
/// cached former leader.
async fn current_local_maintenance_leader(stores: &[ConsensusSessionStore]) -> usize {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let statuses = stores
                .iter()
                .map(ConsensusSessionStore::status)
                .collect::<Vec<_>>();
            if let Some(leader) = current_local_maintenance_leader_from_statuses(&statuses) {
                return leader;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixed quorum reports an unambiguous current-term local maintenance leader")
}

/// Retry an ambiguous lifecycle CAS only after a fresh linearized history read
/// proves whether that exact CAS changed durable state.  Maintenance has no
/// caller-supplied request ID, so replaying it blindly after a lost reply could
/// run the next ordered batch instead of the original one.
async fn maintain_exact_history_batch(
    stores: &[ConsensusSessionStore],
    expected: FencedTransitionV2HistoryState,
    transient_retries: &AtomicU64,
    production_counters: &ProductionMaintenanceCounters,
    post_commit_reply_loss: Option<&AtomicUsize>,
) -> Result<FencedTransitionV2HistoryState, StoreError> {
    for attempt in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        // Unlike ordinary application operations, operator maintenance is a
        // deliberately local-leader-only boundary and is never forwarded.
        // A release workload can span several election terms, so never cache
        // the leader selected before the 131k-transition phase.
        let store = &stores[current_local_maintenance_leader(stores).await];
        let production_result = store.maintain_fenced_transition_v2_history(expected).await;
        production_counters.record_invocation(&production_result);
        // This fault is deliberately after the public local-leader method
        // completed successfully: it models only the caller losing that
        // successful reply, never a pre-proposal or pre-commit failure. The
        // bounded one-shot counter keeps unrelated qualification calls on
        // their ordinary production path.
        let result = match production_result {
            Ok(_)
                if post_commit_reply_loss.is_some_and(|remaining| {
                    remaining
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                            count.checked_sub(1)
                        })
                        .is_ok()
                }) =>
            {
                checked_counter_increment(
                    &production_counters.post_commit_reply_loss_projections,
                    "post-commit reply-loss projections",
                );
                Err(StoreError::BackendUnavailable(
                    "test-only post-commit V2 maintenance reply loss".into(),
                ))
            }
            result => result,
        };
        match result {
            Ok(state) => return Ok(state),
            // `EpochNotActive` can be the post-commit observation of this
            // exact expected state after its reply was lost.  This helper is
            // used only for the eligible retirement sequence below; it never
            // treats that error itself as success.
            Err(
                StoreError::BackendUnavailable(_)
                | StoreError::FencedTransitionHistoryEpochNotActive,
            ) if attempt < QUALIFICATION_TRANSIENT_RETRY_LIMIT => {
                transient_retries.fetch_add(1, Ordering::Relaxed);
                let observation_store = &stores[current_local_maintenance_leader(stores).await];
                let observed = retry_exact_consensus_operation(transient_retries, || {
                    observation_store.fenced_transition_v2_history_state()
                })
                .await?;
                if observed != expected {
                    checked_counter_increment(
                        &production_counters.readback_projections,
                        "maintenance readback projections",
                    );
                    return Ok(observed);
                }
                // The linearized state is unchanged, so this is still the
                // same lifecycle CAS, not an inferred successful batch.
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the bounded maintenance retry loop returns on its final attempt")
}

#[derive(Clone)]
struct ScopedLoopbackPeer {
    source_index: usize,
    node_id: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    forward_mutation_reply_losses: Arc<AtomicUsize>,
}

impl ScopedLoopbackPeer {
    fn new(
        source_index: usize,
        node_id: SessionConsensusNodeId,
        identity: ConsensusIdentity,
    ) -> Self {
        Self {
            source_index,
            node_id,
            identity,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            forward_mutation_reply_losses: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    async fn clear(&self) {
        *self.handler.write().await = None;
    }

    fn drop_next_forward_mutation_reply(&self) {
        self.forward_mutation_reply_losses
            .fetch_add(1, Ordering::SeqCst);
    }
}

impl fmt::Debug for ScopedLoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedLoopbackPeer")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for ScopedLoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let drop_forward_mutation_reply = request.family
            == SessionConsensusRpcFamily::ForwardMutation
            && self
                .forward_mutation_reply_losses
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        let response = handler.handle(request.sender, request).await;
        if drop_forward_mutation_reply {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        Ok(response)
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("sdk-702-qualification-voter-{index}")).expect("replica ID")
}

fn members() -> Vec<QuorumReplicaDescriptor> {
    (0..VOTERS)
        .map(|index| {
            QuorumReplicaDescriptor::new(
                replica_id(index),
                ReplicaEndpoint::new(format!("sdk-702-qualification-voter-{index}.invalid"), 7443)
                    .expect("endpoint"),
                ReplicaTlsIdentity::new(format!(
                    "spiffe://test/session/sdk-702-qualification/{index}"
                ))
                .expect("TLS identity"),
                ReplicaFailureDomain::new(format!("sdk-702-qualification-zone-{index}"))
                    .expect("failure domain"),
                ReplicaBackingIdentity::new(format!("sdk-702-qualification-disk-{index}"))
                    .expect("backing identity"),
            )
        })
        .collect()
}

fn fixed_identity(
    members: &[QuorumReplicaDescriptor],
    placement_policy: PlacementResiliencePolicy,
) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new("sdk-702-v2-qualification").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    derive_fixed_durable_quorum_consensus_identity(
        cluster_id,
        epoch,
        &fingerprints,
        placement_policy,
    )
}

fn fixed_topology(
    local_index: usize,
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> ValidatedQuorumTopology {
    let identity = fixed_identity(&members, placement_policy);
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(replica_id(local_index), members, identity),
        placement_policy,
    )
    .expect("fixed durable quorum topology")
}

async fn fixed_cluster(
    directory: &Path,
    clock: Arc<dyn Clock>,
) -> (
    Vec<ConsensusSessionStore>,
    Vec<std::path::PathBuf>,
    Vec<std::path::PathBuf>,
    Vec<Arc<ScopedLoopbackPeer>>,
) {
    fixed_cluster_with_snapshot_root(directory, directory, clock).await
}

async fn fixed_cluster_with_snapshot_root(
    directory: &Path,
    snapshot_root: &Path,
    clock: Arc<dyn Clock>,
) -> (
    Vec<ConsensusSessionStore>,
    Vec<std::path::PathBuf>,
    Vec<std::path::PathBuf>,
    Vec<Arc<ScopedLoopbackPeer>>,
) {
    let placement_policy = PlacementResiliencePolicy::default();
    let members = members();
    let identity = fixed_identity(&members, placement_policy);
    let topologies = (0..VOTERS)
        .map(|index| fixed_topology(index, members.clone(), placement_policy))
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|topology| topology.local_consensus_node_id().expect("node ID"))
        .collect::<Vec<_>>();
    let database_paths = (0..VOTERS)
        .map(|index| directory.join(format!("voter-{index}.sqlite")))
        .collect::<Vec<_>>();
    let snapshot_paths = (0..VOTERS)
        .map(|index| snapshot_root.join(format!("snapshots-{index}")))
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..VOTERS {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(source, node_id, identity)),
                );
            }
        }
    }

    let mut stores = Vec::with_capacity(VOTERS);
    for source in 0..VOTERS {
        let peers = (0..VOTERS)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("exact fixed peer")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        stores.push(
            ConsensusSessionStore::open_fixed_durable_quorum_with_clock(
                topologies[source].clone(),
                SqliteSessionBackend::open(&database_paths[source]).expect("SQLite voter"),
                &snapshot_paths[source],
                peers,
                Arc::clone(&clock),
                DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            )
            .await
            .expect("open fixed voter"),
        );
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed durable quorum");
    }
    let peer_slots = paths.into_values().collect();
    (stores, database_paths, snapshot_paths, peer_slots)
}

const FS_VERITY_QUALIFICATION_ENV: &str = "OPC_FS_VERITY_QUALIFICATION";
const FS_VERITY_SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";

fn release_fs_verity_snapshot_root_from_environment(
    qualification: Option<&OsStr>,
    snapshot_root: Option<&OsStr>,
    expected_path_id: &str,
    expected_device: u64,
    expected_inode: u64,
) -> Result<PathBuf, &'static str> {
    if qualification != Some(OsStr::new("required")) {
        return Err("release qualification requires the fixed fs-verity marker");
    }
    let requested_snapshot_root = snapshot_root
        .map(|value| (value.as_encoded_bytes().to_vec(), PathBuf::from(value)))
        .ok_or("release qualification requires an fs-verity snapshot root")?;
    let requested_snapshot_root_bytes = requested_snapshot_root.0;
    let requested_snapshot_root = requested_snapshot_root.1;
    if !requested_snapshot_root.is_absolute() {
        return Err("release fs-verity snapshot root must be absolute");
    }
    let snapshot_metadata = std::fs::symlink_metadata(&requested_snapshot_root)
        .map_err(|_| "release fs-verity snapshot root is unavailable")?;
    if snapshot_metadata.file_type().is_symlink() || !snapshot_metadata.is_dir() {
        return Err("release fs-verity snapshot root is not a directory");
    }
    #[cfg(unix)]
    if snapshot_metadata.uid() != nix::unistd::Uid::current().as_raw()
        || snapshot_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("release fs-verity snapshot root is not owner-private");
    }
    #[cfg(not(unix))]
    return Err("release fs-verity qualification requires Unix private-directory checks");
    let snapshot_root = std::fs::canonicalize(&requested_snapshot_root)
        .map_err(|_| "release fs-verity snapshot root is not canonical")?;
    if snapshot_root != requested_snapshot_root
        || snapshot_root.as_os_str().as_encoded_bytes() != requested_snapshot_root_bytes
        || !is_sha256_path_id(expected_path_id)
        || expected_device == 0
        || expected_inode == 0
        || redacted_path_id(&snapshot_root) != expected_path_id
        || snapshot_metadata.dev() != expected_device
        || snapshot_metadata.ino() != expected_inode
    {
        return Err("release fs-verity snapshot root is not the attested wrapper-owned namespace");
    }
    Ok(snapshot_root)
}

fn required_release_fs_verity_snapshot_root(execution: &ReleaseEvidenceExecution) -> PathBuf {
    release_fs_verity_snapshot_root_from_environment(
        std::env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref(),
        std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV).as_deref(),
        &execution.fs_verity_snapshot_root_id,
        execution.fs_verity_snapshot_root_device,
        execution.fs_verity_snapshot_root_inode,
    )
    .expect("release qualification requires the attested wrapper-owned fs-verity snapshot root")
}

#[cfg(unix)]
#[test]
fn release_snapshot_root_requires_the_private_attested_identity() {
    let workspace = tempfile::tempdir().expect("snapshot-root workspace");
    let snapshot_root = workspace.path().join("snapshot-root");
    std::fs::create_dir(&snapshot_root).expect("create snapshot root");
    std::fs::set_permissions(&snapshot_root, std::fs::Permissions::from_mode(0o700))
        .expect("private snapshot root");
    let metadata = std::fs::metadata(&snapshot_root).expect("snapshot metadata");
    let expected_id = redacted_path_id(&snapshot_root);

    assert_eq!(
        release_fs_verity_snapshot_root_from_environment(
            Some(OsStr::new("required")),
            Some(snapshot_root.as_os_str()),
            &expected_id,
            metadata.dev(),
            metadata.ino(),
        )
        .expect("accept attested wrapper snapshot child"),
        std::fs::canonicalize(&snapshot_root).expect("canonical snapshot root")
    );
    assert!(release_fs_verity_snapshot_root_from_environment(
        Some(OsStr::new("required")),
        Some(workspace.path().as_os_str()),
        &expected_id,
        metadata.dev(),
        metadata.ino(),
    )
    .is_err());
    assert!(release_fs_verity_snapshot_root_from_environment(
        Some(OsStr::new("hostile")),
        Some(snapshot_root.as_os_str()),
        &expected_id,
        metadata.dev(),
        metadata.ino(),
    )
    .is_err());
    assert!(release_fs_verity_snapshot_root_from_environment(
        Some(OsStr::new("required")),
        Some(snapshot_root.as_os_str()),
        &expected_id,
        metadata.dev(),
        metadata.ino().saturating_add(1),
    )
    .is_err());
    let aliased = OsString::from(format!("{}/.", snapshot_root.display()));
    assert!(release_fs_verity_snapshot_root_from_environment(
        Some(OsStr::new("required")),
        Some(aliased.as_os_str()),
        &expected_id,
        metadata.dev(),
        metadata.ino(),
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn wrapper_snapshot_child_must_join_the_live_v9_shared_base() {
    let workspace = tempfile::tempdir().expect("shared fs-verity base workspace");
    let base = workspace.path().join("fs-verity-base");
    std::fs::create_dir(&base).expect("create shared fs-verity base");
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
        .expect("make shared fs-verity base private");
    let child = base.join("sdk702-release-snapshots-test");
    std::fs::create_dir(&child).expect("create wrapper snapshot child");
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))
        .expect("make wrapper snapshot child private");
    let canonical_base = base.canonicalize().expect("canonical shared base");
    let canonical_child = child.canonicalize().expect("canonical wrapper child");
    let base_metadata = std::fs::metadata(&canonical_base).expect("stat shared base");
    let child_metadata = std::fs::metadata(&canonical_child).expect("stat wrapper child");
    let mut execution = release_evidence_test_fixture().execution;
    execution.fs_verity_snapshot_base_id = redacted_path_id(&canonical_base);
    execution.fs_verity_snapshot_root_id = redacted_path_id(&canonical_child);
    execution.fs_verity_snapshot_root_device = child_metadata.dev();
    execution.fs_verity_snapshot_root_inode = child_metadata.ino();
    let source = release_evidence_test_fixture().source;
    let mut bindings = process_loss_v9_test_fixture(&source).bindings;
    let base_text = canonical_base
        .to_str()
        .expect("UTF-8 shared fs-verity base")
        .to_owned();
    bindings.fs_verity_snapshot_root_directory = base_text.clone();
    bindings.fs_verity_snapshot_root_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-fs-verity-snapshot-root/v1\0",
        b"canonical-fs-verity-snapshot-root",
        &base_text,
    )
    .expect("shared-base commitment");
    bindings.fs_verity_snapshot_root_device = base_metadata.dev();
    bindings.fs_verity_snapshot_root_inode = base_metadata.ino();
    assert!(validate_shared_fs_verity_snapshot_base_for_child(
        &canonical_child,
        &execution,
        &bindings,
    )
    .is_ok());

    let mut mismatched_base = execution.clone();
    mismatched_base.fs_verity_snapshot_base_id = redacted_path_id(&canonical_child);
    assert!(validate_shared_fs_verity_snapshot_base_for_child(
        &canonical_child,
        &mismatched_base,
        &bindings,
    )
    .is_err());

    std::fs::rename(&base, workspace.path().join("replaced-base-original"))
        .expect("replace shared base pathname");
    std::fs::create_dir(&base).expect("create replacement base");
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
        .expect("make replacement base private");
    let replacement_child = base.join("sdk702-release-snapshots-test");
    std::fs::create_dir(&replacement_child).expect("create replacement wrapper child");
    std::fs::set_permissions(&replacement_child, std::fs::Permissions::from_mode(0o700))
        .expect("make replacement wrapper child private");
    assert!(validate_shared_fs_verity_snapshot_base_for_child(
        &replacement_child
            .canonicalize()
            .expect("canonical replacement child"),
        &execution,
        &bindings,
    )
    .is_err());
}

async fn shutdown_fixed_cluster(
    stores: &[ConsensusSessionStore],
    peer_slots: &[Arc<ScopedLoopbackPeer>],
) {
    futures_util::future::join_all(peer_slots.iter().map(|peer| peer.clear())).await;
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::shutdown)).await
    {
        result.expect("shut down fixed durable quorum engine");
    }
}

async fn ready_leader(stores: &[ConsensusSessionStore]) -> usize {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let readiness = futures_util::future::join_all(
                stores
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await;
            let statuses = stores
                .iter()
                .map(ConsensusSessionStore::status)
                .collect::<Vec<_>>();
            if readiness.iter().all(|report| report.is_ready())
                && statuses.iter().all(|status| status.admitted)
                && statuses
                    .first()
                    .and_then(|status| status.leader_id)
                    .is_some_and(|leader| {
                        statuses
                            .iter()
                            .all(|status| status.leader_id == Some(leader))
                    })
            {
                let leader = statuses[0].leader_id.expect("known fixed-quorum leader");
                return statuses
                    .iter()
                    .position(|status| status.node_id == leader)
                    .expect("leader is an exact fixed voter");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixed quorum reaches durable readiness and elects a leader")
}

#[test]
fn maintenance_leader_selection_replaces_a_stale_self_reported_three_voter_leader() {
    let placement_policy = PlacementResiliencePolicy::default();
    let quorum_members = members();
    let node_ids = (0..VOTERS)
        .map(|index| {
            fixed_topology(index, quorum_members.clone(), placement_policy)
                .local_consensus_node_id()
                .expect("fixed voter node ID")
        })
        .collect::<Vec<_>>();
    let status = |node_id, term, leader_id| SessionConsensusStatus {
        node_id,
        term,
        leader_id: Some(leader_id),
        last_log_index: None,
        applied_index: None,
        admitted: true,
        completed_snapshot_count: 0,
    };

    let initial_term = [
        status(node_ids[0], 7, node_ids[0]),
        status(node_ids[1], 7, node_ids[0]),
        status(node_ids[2], 7, node_ids[0]),
    ];
    assert_eq!(
        current_local_maintenance_leader_from_statuses(&initial_term),
        Some(0)
    );

    // This is the deterministic status shape during a term change: voter 0
    // has a stale self-report, while the newly elected voter 1 and its peer
    // have observed the later term. The selector must not retain voter 0.
    let reselected_term = [
        status(node_ids[0], 7, node_ids[0]),
        status(node_ids[1], 8, node_ids[1]),
        status(node_ids[2], 8, node_ids[1]),
    ];
    assert_eq!(
        current_local_maintenance_leader_from_statuses(&reselected_term),
        Some(1)
    );
}

fn key(index: usize) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sdk-702-v2-qualification").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("unique-transition-{index}"))
            .try_into()
            .expect("stable ID"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("sdk-702-v2-qualification-owner").expect("owner")
}

fn sealing_provider() -> MemoryKeyProvider {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("sdk-702-v2-qualification-key").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("sdk-702-v2-qualification").expect("tenant"),
            Zeroizing::new([0x72; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("active session key");
    provider
}

async fn create_request(
    index: usize,
    history_epoch: FencedTransitionV2HistoryEpoch,
    key: SessionKey,
    fence: FenceToken,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let owner = owner();
    let lease =
        FencedTransitionLease::acquire(key.clone(), owner.clone(), fence, Duration::from_secs(60))
            .expect("acquire request");
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: FenceToken::new(fence.get() + 1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2-qualification"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"qualification")),
    };
    record.payload =
        EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-qualification")
            .await
            .expect("seal qualification transition payload");
    let nonce = FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes());
    FencedTransitionV2Request::new(
        history_epoch,
        nonce,
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("self-authenticating request")
}

async fn effect_deadline_test_request() -> FencedTransitionV2Request {
    let provider = sealing_provider();
    create_request(
        0,
        FencedTransitionV2HistoryEpoch::new(1).expect("deadline-test V2 epoch"),
        key(0),
        FenceToken::new(0),
        &provider,
    )
    .await
}

async fn renew_update_request(
    index: usize,
    history_epoch: FencedTransitionV2HistoryEpoch,
    previous: &FencedTransitionOutcome,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let key = previous.lease().key().clone();
    let owner = previous.lease().owner().clone();
    let fence = previous.lease().fence();
    let expected_generation = previous.committed_generation();
    let generation = expected_generation
        .next()
        .expect("qualification generation has headroom");
    let lease = FencedTransitionLease::renew(previous.lease().clone(), Duration::from_secs(60))
        .expect("renew request");
    let mut record = StoredSessionRecord {
        key,
        generation,
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2-qualification"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"qualification-update")),
    };
    record.payload =
        EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-qualification")
            .await
            .expect("seal qualification update payload");
    let nonce = FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes());
    FencedTransitionV2Request::new(
        history_epoch,
        nonce,
        lease,
        FencedTransitionMutation::update(expected_generation, record),
    )
    .expect("self-authenticating update request")
}

/// Validate the semantic result shape in addition to V2's self-authenticating
/// request/result correlation. The release workload has only create and
/// renewal-update operations, so accepting another mutation result here would
/// make the evidence claim false even if its generic response were valid.
fn is_exact_qualified_v2_success(
    request: &FencedTransitionV2Request,
    outcome: &FencedTransitionOutcome,
) -> bool {
    if !outcome.matches_v2_request(request) {
        return false;
    }
    match (request.lease(), request.mutation()) {
        (FencedTransitionLease::Acquire { .. }, FencedTransitionMutation::Create { record }) => {
            outcome.mutation() == FencedTransitionMutationResult::Created
                && outcome.committed_generation() == record.generation
        }
        (
            FencedTransitionLease::Renew { lease: prior, .. },
            FencedTransitionMutation::Update {
                expected_generation,
                record,
            },
        ) => {
            outcome.mutation() == FencedTransitionMutationResult::Updated
                && outcome.lease().key() == prior.key()
                && outcome.lease().owner() == prior.owner()
                && outcome.lease().fence() == prior.fence()
                && outcome.lease().acquired_at() == prior.acquired_at()
                && outcome.lease().credential_id() == prior.credential_id()
                && expected_generation.next() == Some(record.generation)
                && outcome.committed_generation() == record.generation
        }
        _ => false,
    }
}

fn assert_exact_qualified_v2_success(
    request: &FencedTransitionV2Request,
    outcome: &FencedTransitionOutcome,
) {
    assert!(
        is_exact_qualified_v2_success(request, outcome),
        "every qualified V2 outcome must exactly match its V2 request"
    );
}

fn assert_exact_qualified_update_request(
    previous: &FencedTransitionOutcome,
    request: &FencedTransitionV2Request,
) {
    match (request.lease(), request.mutation()) {
        (
            FencedTransitionLease::Renew { lease, .. },
            FencedTransitionMutation::Update {
                expected_generation,
                record,
            },
        ) => {
            assert_eq!(lease, previous.lease());
            assert_eq!(*expected_generation, previous.committed_generation());
            assert_eq!(record.key, *previous.lease().key());
            assert_eq!(record.owner, *previous.lease().owner());
            assert_eq!(record.fence, previous.lease().fence());
            assert_eq!(
                record.generation,
                previous
                    .committed_generation()
                    .next()
                    .expect("qualified prior generation has headroom")
            );
        }
        _ => panic!("qualified update request must renew the exact prior outcome"),
    }
}

fn request_with_changed_body(request: &FencedTransitionV2Request) -> FencedTransitionV2Request {
    let mut encoded = serde_json::to_value(request).expect("serialize retained V2 request");
    let mutation = encoded
        .get_mut("mutation")
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 request mutation");
    let mutation_body = if mutation.contains_key("create") {
        mutation.get_mut("create")
    } else {
        mutation.get_mut("update")
    };
    let record = mutation_body
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|mutation| mutation.get_mut("record"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 create or update request record");
    record.insert(
        "state_type".to_owned(),
        serde_json::Value::String("sdk-702-v2-qualification-altered".to_owned()),
    );
    serde_json::from_value(encoded).expect("deserialize altered V2 request")
}

const QUALIFICATION_FILESYSTEM_MAX_DEPTH: usize = 16;
const QUALIFICATION_FILESYSTEM_MAX_ENTRIES: u64 = 32_768;

fn bounded_directory_measure(path: &Path) -> (u64, u64) {
    use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};

    fn checked_identity(
        before: rustix::fs::Stat,
        descriptor: &File,
        label: &str,
    ) -> rustix::fs::Stat {
        let after = fstat(descriptor).expect("fstat bounded qualification filesystem descriptor");
        assert!(
            before.st_dev == after.st_dev && before.st_ino == after.st_ino,
            "qualification filesystem {label} changed while descriptor-pinned"
        );
        after
    }

    fn walk(directory: &File, depth: usize, entries: &mut u64) -> (u64, u64) {
        assert!(
            depth <= QUALIFICATION_FILESYSTEM_MAX_DEPTH,
            "qualification filesystem traversal depth is bounded"
        );
        let mut bytes = 0_u64;
        let mut artifacts = 0_u64;
        let directory_entries = Dir::read_from(directory)
            .expect("read descriptor-pinned qualification artifact directory");
        for entry in directory_entries {
            let entry = entry.expect("read qualification artifact directory entry");
            let name = entry.file_name();
            #[cfg(unix)]
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            *entries = entries
                .checked_add(1)
                .expect("qualification filesystem entry count overflow");
            assert!(
                *entries <= QUALIFICATION_FILESYSTEM_MAX_ENTRIES,
                "qualification filesystem traversal cardinality is bounded"
            );
            let metadata = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .expect("read qualification artifact metadata without following links");
            assert!(
                !FileType::from_raw_mode(metadata.st_mode).is_symlink(),
                "qualification filesystem evidence rejects symlink traversal"
            );
            if FileType::from_raw_mode(metadata.st_mode).is_dir() {
                let child = File::from(
                    openat(
                        directory,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .expect("open qualification child directory without following links"),
                );
                checked_identity(metadata, &child, "child directory");
                let (nested_bytes, nested_artifacts) = walk(&child, depth + 1, entries);
                bytes = bytes
                    .checked_add(nested_bytes)
                    .expect("qualification directory byte total overflow");
                artifacts = artifacts
                    .checked_add(nested_artifacts)
                    .expect("qualification directory artifact count overflow");
            } else {
                assert!(
                    FileType::from_raw_mode(metadata.st_mode).is_file(),
                    "qualification filesystem evidence accepts only regular files"
                );
                let file = File::from(
                    openat(
                        directory,
                        name,
                        qualification_nofollow_metadata_flags(),
                        Mode::empty(),
                    )
                    .expect("open qualification regular file without following links"),
                );
                let metadata = checked_identity(metadata, &file, "regular file");
                bytes = bytes
                    .checked_add(
                        u64::try_from(metadata.st_size)
                            .expect("qualification regular file size is nonnegative"),
                    )
                    .expect("qualification directory byte total overflow");
                artifacts = artifacts
                    .checked_add(1)
                    .expect("qualification directory artifact count overflow");
            }
        }
        (bytes, artifacts)
    }

    let root = File::from(
        openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open qualification root directory without following links"),
    );
    assert!(
        FileType::from_raw_mode(
            fstat(&root)
                .expect("fstat qualification root directory")
                .st_mode,
        )
        .is_dir(),
        "qualification directory root is a real descriptor-pinned directory"
    );
    let mut entries = 0;
    walk(&root, 0, &mut entries)
}

fn directory_bytes(path: &Path) -> u64 {
    bounded_directory_measure(path).0
}

fn qualification_nofollow_metadata_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;

    #[cfg(target_os = "linux")]
    {
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
}

fn sqlite_database_family_bytes(path: &Path) -> u64 {
    use rustix::fs::{fstat, openat, FileType, Mode, CWD};

    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            let candidate = std::path::PathBuf::from(candidate);
            match openat(
                CWD,
                &candidate,
                qualification_nofollow_metadata_flags(),
                Mode::empty(),
            ) {
                Ok(descriptor) => {
                    let metadata = fstat(&descriptor).expect("fstat SQLite qualification artifact");
                    assert!(
                        FileType::from_raw_mode(metadata.st_mode).is_file(),
                        "SQLite qualification artifact must be a regular no-follow file"
                    );
                    u64::try_from(metadata.st_size)
                        .expect("SQLite qualification artifact size is nonnegative")
                }
                Err(error)
                    if !suffix.is_empty()
                        && std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
                {
                    0
                }
                Err(error) => panic!(
                    "read required SQLite qualification artifact {}: {error}",
                    candidate.display()
                ),
            }
        })
        .fold(0_u64, |total, bytes| {
            total
                .checked_add(bytes)
                .expect("SQLite qualification artifact byte total overflow")
        })
}

fn sqlite_database_family_artifacts(path: &Path) -> u64 {
    use rustix::fs::{fstat, openat, FileType, Mode, CWD};

    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            let candidate = std::path::PathBuf::from(candidate);
            match openat(
                CWD,
                &candidate,
                qualification_nofollow_metadata_flags(),
                Mode::empty(),
            ) {
                Ok(descriptor) => {
                    let metadata = fstat(&descriptor).expect("fstat SQLite qualification artifact");
                    assert!(
                        FileType::from_raw_mode(metadata.st_mode).is_file(),
                        "SQLite qualification artifact must be a regular no-follow file"
                    );
                    1
                }
                Err(error)
                    if !suffix.is_empty()
                        && std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
                {
                    0
                }
                Err(error) => panic!(
                    "read required SQLite qualification artifact {}: {error}",
                    candidate.display()
                ),
            }
        })
        .fold(0_u64, |total, artifacts| {
            total
                .checked_add(artifacts)
                .expect("SQLite qualification artifact count overflow")
        })
}

fn directory_artifacts(path: &Path) -> u64 {
    bounded_directory_measure(path).1
}

fn assert_voter_resource_ceiling(label: &str, values: &[u64], ceiling: u64) {
    assert_eq!(values.len(), VOTERS, "{label} must cover every voter");
    assert!(
        values.iter().all(|value| *value > 0 && *value <= ceiling),
        "{label} must be nonzero and no greater than {ceiling} bytes per voter: {values:?}",
    );
}

#[cfg(target_os = "linux")]
fn process_peak_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("read Linux process status for release resource qualification");
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .expect("Linux process status contains VmHWM")
}

#[cfg(not(target_os = "linux"))]
fn process_peak_rss_kib() -> u64 {
    0
}

#[cfg(target_os = "linux")]
const fn qualification_process_peak_rss_ceiling_kib() -> u64 {
    QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB
}

#[cfg(not(target_os = "linux"))]
const fn qualification_process_peak_rss_ceiling_kib() -> u64 {
    0
}

#[tokio::test(flavor = "multi_thread")]
async fn release_effect_boundary_never_redispatches_an_ambiguous_batch() {
    let directory = tempfile::tempdir().expect("release effect-boundary directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("release effect-boundary start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, peer_slots) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    let mut requests = Vec::new();
    let mut expected = Vec::new();
    for index in 0..2 {
        let transition_key = key(index);
        let observation = store
            .observe_fenced_transition(&transition_key)
            .await
            .expect("effect-boundary fence observation");
        let request = create_request(
            index,
            epoch,
            transition_key,
            observation.current_fence(),
            &provider,
        )
        .await;
        let outcome = store
            .fenced_transition_v2(request.clone())
            .await
            .expect("establish exact effect-boundary fixture");
        requests.push(request);
        expected.push(Ok(outcome));
    }

    let counters = ReleaseEffectCounters::default();
    let steps = Arc::new(Mutex::new(VecDeque::from([
        FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
            "release_test_unavailable".into(),
        )),
        FencedTransitionV2Effect::Resolved(Ok(expected.clone())),
    ])));
    let execution_calls = Arc::new(AtomicUsize::new(0));
    let observed = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        requests.clone(),
        &counters,
        {
            let steps = Arc::clone(&steps);
            let execution_calls = Arc::clone(&execution_calls);
            let requests = requests.clone();
            move |received| {
                let steps = Arc::clone(&steps);
                let execution_calls = Arc::clone(&execution_calls);
                let requests = requests.clone();
                async move {
                    execution_calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(received, requests, "retry retains the exact request bodies");
                    steps
                        .lock()
                        .expect("effect steps lock")
                        .pop_front()
                        .expect("bounded effect step")
                }
            }
        },
        |_| async { Ok(FencedTransitionV2Status::NotFound) },
    )
    .await
    .expect("proved-not-transmitted batch may retry");
    assert_eq!(observed, expected);
    assert_eq!(execution_calls.load(Ordering::SeqCst), 2);
    assert_eq!(counters.snapshot().not_transmitted_retries, 1);
    assert_eq!(counters.snapshot().status_attempts, 0);

    let counters = ReleaseEffectCounters::default();
    let execution_calls = Arc::new(AtomicUsize::new(0));
    let status_calls = Arc::new(AtomicUsize::new(0));
    let request_ids = requests
        .iter()
        .map(FencedTransitionV2Request::request_id)
        .collect::<Vec<_>>();
    let observed = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        requests.clone(),
        &counters,
        {
            let execution_calls = Arc::clone(&execution_calls);
            let request_ids = request_ids.clone();
            move |_| {
                let execution_calls = Arc::clone(&execution_calls);
                let request_ids = request_ids.clone();
                async move {
                    execution_calls.fetch_add(1, Ordering::SeqCst);
                    FencedTransitionV2Effect::OutcomeUnknown { request_ids }
                }
            }
        },
        {
            let requests = requests.clone();
            let expected = expected.clone();
            let status_calls = Arc::clone(&status_calls);
            move |request| {
                let requests = requests.clone();
                let expected = expected.clone();
                let status_calls = Arc::clone(&status_calls);
                async move {
                    let call = status_calls.fetch_add(1, Ordering::SeqCst);
                    if call < requests.len() {
                        return Ok(FencedTransitionV2Status::NotFound);
                    }
                    let index = requests
                        .iter()
                        .position(|candidate| candidate == &request)
                        .expect("status request retains an original exact body");
                    Ok(FencedTransitionV2Status::Recorded(Box::new(
                        expected[index].clone(),
                    )))
                }
            }
        },
    )
    .await
    .expect("ambiguous batch converges only by exact status");
    assert_eq!(observed, expected);
    assert_eq!(execution_calls.load(Ordering::SeqCst), 1);
    assert_eq!(status_calls.load(Ordering::SeqCst), 4);
    assert_eq!(counters.snapshot().outcome_unknown_batches, 1);
    assert_eq!(counters.snapshot().status_retry_rounds, 1);

    let counters = ReleaseEffectCounters::default();
    let execution_calls = Arc::new(AtomicUsize::new(0));
    let expired = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF,
        vec![requests[0].clone()],
        &counters,
        {
            let execution_calls = Arc::clone(&execution_calls);
            move |_| {
                let execution_calls = Arc::clone(&execution_calls);
                async move {
                    execution_calls.fetch_add(1, Ordering::SeqCst);
                    FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                        "release_test_unavailable".into(),
                    ))
                }
            }
        },
        |_| async { Ok(FencedTransitionV2Status::NotFound) },
    )
    .await;
    assert_eq!(
        expired,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::DeadlineAfterBackoff,
        })
    );
    assert_eq!(
        execution_calls.load(Ordering::SeqCst),
        1,
        "deadline expiry must not dispatch another mutation"
    );
    assert_eq!(counters.snapshot().not_transmitted_retries, 0);

    let counters = ReleaseEffectCounters::default();
    let execution_calls = Arc::new(AtomicUsize::new(0));
    let unresolved = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        vec![requests[0].clone()],
        &counters,
        {
            let execution_calls = Arc::clone(&execution_calls);
            let request_id = requests[0].request_id();
            move |_| {
                let execution_calls = Arc::clone(&execution_calls);
                async move {
                    execution_calls.fetch_add(1, Ordering::SeqCst);
                    FencedTransitionV2Effect::OutcomeUnknown {
                        request_ids: vec![request_id],
                    }
                }
            }
        },
        |_| async { Ok(FencedTransitionV2Status::NotFound) },
    )
    .await;
    assert_eq!(
        unresolved,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::StatusUnresolved,
        })
    );
    assert_eq!(execution_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        counters.snapshot().status_attempts,
        (QUALIFICATION_TRANSIENT_RETRY_LIMIT + 1) as u64
    );

    let counters = ReleaseEffectCounters::default();
    let mismatched = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        requests.clone(),
        &counters,
        {
            let reversed_ids = request_ids.into_iter().rev().collect::<Vec<_>>();
            move |_| {
                let reversed_ids = reversed_ids.clone();
                async move {
                    FencedTransitionV2Effect::OutcomeUnknown {
                        request_ids: reversed_ids,
                    }
                }
            }
        },
        |_| async { Ok(FencedTransitionV2Status::NotFound) },
    )
    .await;
    assert_eq!(
        mismatched,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::OutcomeIdentityMismatch,
        })
    );
    assert_eq!(counters.snapshot().status_attempts, 0);

    let unexpected_resolved_error = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        vec![requests[0].clone()],
        &ReleaseEffectCounters::default(),
        |_| async {
            FencedTransitionV2Effect::Resolved(Ok(vec![Err(StoreError::BackendUnavailable(
                "release_test_unexpected_item_error".into(),
            ))]))
        },
        |_| async { Ok(FencedTransitionV2Status::NotFound) },
    )
    .await;
    assert_eq!(
        unexpected_resolved_error,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::ResolvedItemError,
        }),
        "a string-bearing resolved item error must collapse to a fixed diagnostic stage"
    );

    let request_id = requests[0].request_id();
    let unexpected_recorded_error = execute_release_batch_effect(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        vec![requests[0].clone()],
        &ReleaseEffectCounters::default(),
        move |_| async move {
            FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: vec![request_id],
            }
        },
        |_| async {
            Ok(FencedTransitionV2Status::Recorded(Box::new(Err(
                StoreError::BackendUnavailable("release_test_unexpected_status_error".into()),
            ))))
        },
    )
    .await;
    assert_eq!(
        unexpected_recorded_error,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::RecordedItemError,
        }),
        "a string-bearing recorded item error must collapse to a fixed diagnostic stage"
    );

    shutdown_fixed_cluster(&stores, &peer_slots).await;
}

#[tokio::test(start_paused = true)]
async fn release_effect_deadline_accepts_a_resolved_mutation_that_completes_late() {
    let request = effect_deadline_test_request().await;
    let counters = ReleaseEffectCounters::default();
    let mutation_calls = Arc::new(AtomicUsize::new(0));
    let status_calls = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + Duration::from_millis(1);
    let result = tokio::join!(
        execute_release_batch_effect(
            deadline,
            vec![request],
            &counters,
            {
                let mutation_calls = Arc::clone(&mutation_calls);
                move |_| {
                    let mutation_calls = Arc::clone(&mutation_calls);
                    async move {
                        mutation_calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        FencedTransitionV2Effect::Resolved(Err(
                            StoreError::FencedTransitionHistoryFull,
                        ))
                    }
                }
            },
            {
                let status_calls = Arc::clone(&status_calls);
                move |_| {
                    let status_calls = Arc::clone(&status_calls);
                    async move {
                        status_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(FencedTransitionV2Status::NotFound)
                    }
                }
            },
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(2)).await;
        },
    )
    .0;
    assert_eq!(
        result,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::ResolvedBatchError,
        }),
        "the post-deadline classification is accepted as resolved, never recast as a timeout"
    );
    assert_eq!(mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(counters.snapshot().mutation_deadline_before_dispatch, 0);
    assert_eq!(counters.snapshot().resolved_after_deadline, 1);
}

#[tokio::test(start_paused = true)]
async fn release_effect_deadline_accounts_for_a_resolved_ok_that_completes_late() {
    let request = effect_deadline_test_request().await;
    let counters = ReleaseEffectCounters::default();
    let deadline = Instant::now() + Duration::from_millis(1);
    let result = tokio::join!(
        execute_release_batch_effect(
            deadline,
            vec![request],
            &counters,
            |_| async {
                tokio::time::sleep(Duration::from_millis(2)).await;
                FencedTransitionV2Effect::Resolved(Ok(vec![Err(
                    StoreError::FencedTransitionHistoryFull,
                )]))
            },
            |_| async { Ok(FencedTransitionV2Status::NotFound) },
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(2)).await;
        },
    )
    .0;
    assert_eq!(
        result,
        Ok(vec![Err(StoreError::FencedTransitionHistoryFull)]),
        "a late resolved Ok remains a classified no-effect result"
    );
    assert_eq!(counters.snapshot().resolved_after_deadline, 1);
}

#[tokio::test(start_paused = true)]
async fn lifecycle_measurement_counts_late_ok_and_err_without_cancelling_either() {
    let counters = ReleaseLifecycleMutationCounters::default();
    let ok = tokio::join!(
        measure_eventual_lifecycle_mutation(
            &counters,
            async {
                tokio::time::sleep(Duration::from_millis(801)).await;
                Ok::<_, StoreError>(())
            },
            Result::is_ok,
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(801)).await;
        },
    )
    .0;
    assert_eq!(ok, Ok(()));
    let error = tokio::join!(
        measure_eventual_lifecycle_mutation(
            &counters,
            async {
                tokio::time::sleep(Duration::from_millis(801)).await;
                Err::<(), _>(StoreError::BackendUnavailable(
                    "late lifecycle classification".into(),
                ))
            },
            |_| false,
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(801)).await;
        },
    )
    .0;
    assert!(matches!(error, Err(StoreError::BackendUnavailable(_))));
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.attempts, 2);
    assert!(snapshot.elapsed_max_us >= 801_000);
    assert_eq!(snapshot.resolved_after_800ms, 2);
    assert_eq!(snapshot.deadline_exceeded, 2);
    assert_eq!(snapshot.failures, 1);
}

#[test]
fn lifecycle_measurement_compares_exact_duration_before_microsecond_quantization() {
    let counters = ReleaseLifecycleMutationCounters::default();
    counters.record_elapsed(
        QUALIFICATION_RELEASE_BATCH_DEADLINE,
        &Ok::<_, StoreError>(()),
        true,
    );
    assert_eq!(counters.snapshot().resolved_after_800ms, 0);
    counters.record_elapsed(
        QUALIFICATION_RELEASE_BATCH_DEADLINE + Duration::from_nanos(1),
        &Ok::<_, StoreError>(()),
        true,
    );
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.attempts, 2);
    assert_eq!(snapshot.elapsed_max_us, 800_000);
    assert_eq!(snapshot.resolved_after_800ms, 1);
    assert_eq!(snapshot.deadline_exceeded, 1);
}

#[test]
fn production_maintenance_ledger_preserves_retry_and_reply_loss_causality() {
    let counters = ProductionMaintenanceCounters::default();
    counters.record_invocation::<FencedTransitionV2HistoryState>(&Err(
        StoreError::BackendUnavailable("first local-leader reply unavailable".into()),
    ));
    // A fresh exact readback would decide whether a second invocation is safe;
    // this test records that it was unchanged before the second physical call.
    checked_counter_increment(
        &counters.readback_projections,
        "test maintenance readback projection",
    );
    counters.record_invocation(&Ok::<(), StoreError>(()));
    checked_counter_increment(
        &counters.post_commit_reply_loss_projections,
        "test post-commit reply-loss projection",
    );
    let snapshot = counters.snapshot();
    assert_eq!(snapshot.invocations, 2);
    assert_eq!(snapshot.ok, 1);
    assert_eq!(snapshot.err, 1);
    assert_eq!(snapshot.ok + snapshot.err, snapshot.invocations);
    assert_eq!(snapshot.readback_projections, 1);
    assert_eq!(snapshot.post_commit_reply_loss_projections, 1);
}

#[tokio::test(start_paused = true)]
async fn release_effect_deadline_does_not_redispatch_not_transmitted_after_expiry() {
    let request = effect_deadline_test_request().await;
    let counters = ReleaseEffectCounters::default();
    let mutation_calls = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + Duration::from_millis(1);
    let result = tokio::join!(
        execute_release_batch_effect(
            deadline,
            vec![request],
            &counters,
            {
                let mutation_calls = Arc::clone(&mutation_calls);
                move |_| {
                    let mutation_calls = Arc::clone(&mutation_calls);
                    async move {
                        mutation_calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(2)).await;
                        FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                            "deadline-test-unavailable".into(),
                        ))
                    }
                }
            },
            |_| async { Ok(FencedTransitionV2Status::NotFound) },
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(2)).await;
        },
    )
    .0;
    assert_eq!(
        result,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::NotTransmittedDeadline,
        })
    );
    assert_eq!(mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.snapshot().not_transmitted_deadline, 1);
}

#[tokio::test(start_paused = true)]
async fn release_effect_deadline_times_out_one_immutable_status_without_a_second_read() {
    let request = effect_deadline_test_request().await;
    let request_id = request.request_id();
    let counters = ReleaseEffectCounters::default();
    let status_calls = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + Duration::from_millis(1);
    let result = tokio::join!(
        execute_release_batch_effect(
            deadline,
            vec![request],
            &counters,
            move |_| {
                let request_id = request_id;
                async move {
                    FencedTransitionV2Effect::OutcomeUnknown {
                        request_ids: vec![request_id],
                    }
                }
            },
            {
                let status_calls = Arc::clone(&status_calls);
                move |_| {
                    let status_calls = Arc::clone(&status_calls);
                    async move {
                        status_calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        Ok(FencedTransitionV2Status::NotFound)
                    }
                }
            },
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(1)).await;
        },
    )
    .0;
    assert_eq!(
        result,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::StatusDeadlineTimeout,
        })
    );
    assert_eq!(status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.snapshot().status_deadline_timeout, 1);
}

#[tokio::test(start_paused = true)]
async fn release_effect_deadline_clipped_backoff_cannot_start_post_deadline_mutation() {
    let request = effect_deadline_test_request().await;
    let counters = ReleaseEffectCounters::default();
    let mutation_calls = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF;
    let result = tokio::join!(
        execute_release_batch_effect(
            deadline,
            vec![request],
            &counters,
            {
                let mutation_calls = Arc::clone(&mutation_calls);
                move |_| {
                    let mutation_calls = Arc::clone(&mutation_calls);
                    async move {
                        mutation_calls.fetch_add(1, Ordering::SeqCst);
                        FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                            "deadline-test-unavailable".into(),
                        ))
                    }
                }
            },
            |_| async { Ok(FencedTransitionV2Status::NotFound) },
        ),
        async {
            tokio::task::yield_now().await;
            tokio::time::advance(QUALIFICATION_RELEASE_BATCH_RETRY_BACKOFF).await;
        },
    )
    .0;
    assert_eq!(
        result,
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::DeadlineAfterBackoff,
        })
    );
    assert_eq!(mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.snapshot().deadline_after_backoff, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_restart_stops_old_engines_before_same_path_reopen() {
    let directory = tempfile::tempdir().expect("fixed-quorum restart directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum restart start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, database_paths, snapshot_paths, peer_slots) =
        fixed_cluster(directory.path(), clock.clone()).await;
    let first_leader = ready_leader(&stores).await;
    assert!(stores[first_leader].status().admitted);

    shutdown_fixed_cluster(&stores, &peer_slots).await;
    drop(stores);
    drop(peer_slots);

    let (reopened, reopened_database_paths, reopened_snapshot_paths, reopened_peer_slots) =
        fixed_cluster(directory.path(), clock).await;
    assert_eq!(reopened_database_paths, database_paths);
    assert_eq!(reopened_snapshot_paths, snapshot_paths);
    let reopened_leader = ready_leader(&reopened).await;
    assert!(reopened[reopened_leader].status().admitted);
    shutdown_fixed_cluster(&reopened, &reopened_peer_slots).await;
}

#[tokio::test]
async fn fixed_quorum_first_v2_transition_activates_and_applies_on_every_voter() {
    let directory = tempfile::tempdir().expect("fixed-quorum V2 directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed-quorum V2 start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let provider = sealing_provider();
    let key = key(0);
    let observation = stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("fixed-quorum fence observation");
    let transition = create_request(
        0,
        FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"),
        key,
        observation.current_fence(),
        &provider,
    )
    .await;
    let outcome = stores[leader]
        .fenced_transition_v2(transition.clone())
        .await
        .expect("first fixed-quorum V2 transition");
    assert!(matches!(
        outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));
    assert_exact_qualified_v2_success(&transition, &outcome);

    for voter in &stores {
        let history = voter
            .fenced_transition_v2_history_state()
            .await
            .expect("V2 history on every voter");
        assert_eq!(history.bound_entries(), 1);
        assert!(matches!(
            voter
                .fenced_transition_v2_status(&transition)
                .await
                .expect("V2 receipt on every voter"),
            FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_v2_batch_preserves_input_order_and_independent_statuses() {
    let directory = tempfile::tempdir().expect("fixed-quorum V2 batch directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum V2 batch start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    // Activation remains the existing singleton transition. The following
    // independent create and renewal exercise the public bounded coalescing
    // API and prove that each item retains its own exact status identity.
    let first_key = key(0);
    let first_observation = store
        .observe_fenced_transition(&first_key)
        .await
        .expect("singleton activation observation");
    let first_request = create_request(
        0,
        epoch,
        first_key,
        first_observation.current_fence(),
        &provider,
    )
    .await;
    let first_outcome = store
        .fenced_transition_v2(first_request.clone())
        .await
        .expect("singleton V2 activation");

    let second_key = key(1);
    let second_observation = store
        .observe_fenced_transition(&second_key)
        .await
        .expect("batch create observation");
    let second_request = create_request(
        1,
        epoch,
        second_key,
        second_observation.current_fence(),
        &provider,
    )
    .await;
    let renewal_request = renew_update_request(2, epoch, &first_outcome, &provider).await;
    let requests = vec![second_request.clone(), renewal_request.clone()];
    let outcomes = store
        .fenced_transition_v2_batch(requests.clone())
        .await
        .expect("public bounded V2 batch");
    assert_eq!(outcomes.len(), requests.len());
    let second_outcome = outcomes[0].clone().expect("first batch item result");
    let renewal_outcome = outcomes[1].clone().expect("second batch item result");
    assert!(matches!(
        second_outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));
    assert!(matches!(
        renewal_outcome.mutation(),
        FencedTransitionMutationResult::Updated
    ));
    assert_exact_qualified_v2_success(&first_request, &first_outcome);
    assert_exact_qualified_v2_success(&second_request, &second_outcome);
    assert_exact_qualified_v2_success(&renewal_request, &renewal_outcome);

    for voter in &stores {
        let history = voter
            .fenced_transition_v2_history_state()
            .await
            .expect("V2 batch history on every voter");
        assert_eq!(history.bound_entries(), 3);
        for (request, outcome) in [
            (&first_request, &first_outcome),
            (&second_request, &second_outcome),
            (&renewal_request, &renewal_outcome),
        ] {
            assert!(matches!(
                voter
                    .fenced_transition_v2_status(request)
                    .await
                    .expect("V2 batch item status on every voter"),
                FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_public_v2_batches_use_the_store_local_warm_route() {
    const BATCHES: usize = 4;
    const ITEMS_PER_BATCH: usize = 2;

    let directory = tempfile::tempdir().expect("fixed-quorum public warm-route directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum public warm-route start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    // The public singleton deliberately remains cold. Its definitive success
    // is the only local proof which may seed the later public batch route.
    let activation_key = key(0);
    let activation_observation = store
        .observe_fenced_transition(&activation_key)
        .await
        .expect("public singleton activation observation");
    let activation = create_request(
        0,
        epoch,
        activation_key,
        activation_observation.current_fence(),
        &provider,
    )
    .await;
    store
        .fenced_transition_v2(activation)
        .await
        .expect("public singleton activation seeds the batch route");

    let before = store.diagnostic_snapshot();
    for batch in 0..BATCHES {
        let mut requests = Vec::with_capacity(ITEMS_PER_BATCH);
        for item in 0..ITEMS_PER_BATCH {
            let request_index = 1 + batch * ITEMS_PER_BATCH + item;
            let transition_key = key(request_index);
            let observation = store
                .observe_fenced_transition(&transition_key)
                .await
                .expect("warm batch observation");
            requests.push(
                create_request(
                    request_index,
                    epoch,
                    transition_key,
                    observation.current_fence(),
                    &provider,
                )
                .await,
            );
        }
        let outcomes = store
            .fenced_transition_v2_batch(requests)
            .await
            .expect("public warm V2 batch");
        assert_eq!(outcomes.len(), ITEMS_PER_BATCH);
        assert!(outcomes.into_iter().all(|outcome| matches!(
            outcome,
            Ok(outcome) if matches!(outcome.mutation(), FencedTransitionMutationResult::Created)
        )));
    }
    let after = store.diagnostic_snapshot();

    assert_eq!(
        after.public_raw_v2_cold_admissions - before.public_raw_v2_cold_admissions,
        0,
        "warm public batches must not repeat generic V2 admission"
    );
    assert_eq!(
        after.public_raw_v2_history_reads - before.public_raw_v2_history_reads,
        0,
        "warm public batches must not reread V2 history"
    );
    assert_eq!(
        after.fixed_raw_v2_acceptance_snapshots - before.fixed_raw_v2_acceptance_snapshots,
        BATCHES as u64,
        "each warm batch consumes exactly one atomic acceptance snapshot"
    );
    assert_eq!(
        after.fixed_raw_v2_proposals - before.fixed_raw_v2_proposals,
        BATCHES as u64,
        "each warm batch issues exactly one proposal"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_public_v2_batch_effect_activates_once_then_uses_store_local_warm_route() {
    const ITEMS_PER_BATCH: usize = 2;

    let directory = tempfile::tempdir().expect("fixed-quorum effect warm-route directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum effect warm-route start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    let mut first_requests = Vec::with_capacity(ITEMS_PER_BATCH);
    for index in 0..ITEMS_PER_BATCH {
        let transition_key = key(index);
        let observation = store
            .observe_fenced_transition(&transition_key)
            .await
            .expect("first effect-batch observation");
        first_requests.push(
            create_request(
                index,
                epoch,
                transition_key,
                observation.current_fence(),
                &provider,
            )
            .await,
        );
    }

    let before_first = store.diagnostic_snapshot();
    let first_outcomes = match SessionBackend::fenced_transition_v2_batch_effect(
        store,
        first_requests.clone(),
    )
    .await
    {
        FencedTransitionV2Effect::Resolved(Ok(outcomes)) => outcomes,
        effect => panic!("first fixed V2 batch effect must resolve definitively: {effect:?}"),
    };
    assert_eq!(first_outcomes.len(), ITEMS_PER_BATCH);
    for (request, outcome) in first_requests.iter().zip(first_outcomes) {
        assert_exact_qualified_v2_success(request, &outcome.expect("first effect item result"));
    }
    let after_first = store.diagnostic_snapshot();
    assert_eq!(
        after_first.public_raw_v2_cold_admissions - before_first.public_raw_v2_cold_admissions,
        1,
        "the pristine typed effect uses the existing cold activation admission"
    );
    assert_eq!(
        after_first.public_raw_v2_history_reads - before_first.public_raw_v2_history_reads,
        1,
        "the pristine typed effect checks the existing activation history once"
    );
    assert_eq!(
        after_first.fixed_raw_v2_acceptance_snapshots
            - before_first.fixed_raw_v2_acceptance_snapshots,
        2,
        "activation and its coalesced suffix each consume their exact snapshot"
    );
    assert_eq!(
        after_first.fixed_raw_v2_proposals - before_first.fixed_raw_v2_proposals,
        1,
        "only the activated suffix uses the raw fixed-V2 proposal boundary"
    );

    let mut warm_requests = Vec::with_capacity(ITEMS_PER_BATCH);
    for index in ITEMS_PER_BATCH..(ITEMS_PER_BATCH * 2) {
        let transition_key = key(index);
        let observation = store
            .observe_fenced_transition(&transition_key)
            .await
            .expect("warm effect-batch observation");
        warm_requests.push(
            create_request(
                index,
                epoch,
                transition_key,
                observation.current_fence(),
                &provider,
            )
            .await,
        );
    }

    let before_warm = store.diagnostic_snapshot();
    let warm_outcomes =
        match SessionBackend::fenced_transition_v2_batch_effect(store, warm_requests.clone()).await
        {
            FencedTransitionV2Effect::Resolved(Ok(outcomes)) => outcomes,
            effect => panic!("warmed fixed V2 batch effect must resolve definitively: {effect:?}"),
        };
    assert_eq!(warm_outcomes.len(), ITEMS_PER_BATCH);
    for (request, outcome) in warm_requests.iter().zip(warm_outcomes) {
        assert_exact_qualified_v2_success(request, &outcome.expect("warm effect item result"));
    }
    let after_warm = store.diagnostic_snapshot();
    assert_eq!(
        after_warm.public_raw_v2_cold_admissions - before_warm.public_raw_v2_cold_admissions,
        0,
        "a definitively resolved typed effect seeds the later store-local warm route"
    );
    assert_eq!(
        after_warm.public_raw_v2_history_reads - before_warm.public_raw_v2_history_reads,
        0,
        "a warmed typed effect does not reread generic V2 history"
    );
    assert_eq!(
        after_warm.fixed_raw_v2_acceptance_snapshots
            - before_warm.fixed_raw_v2_acceptance_snapshots,
        1,
        "a warmed typed batch consumes exactly one uncached acceptance snapshot"
    );
    assert_eq!(
        after_warm.fixed_raw_v2_proposals - before_warm.fixed_raw_v2_proposals,
        1,
        "a warmed typed batch issues exactly one raw fixed-V2 proposal"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_public_v2_batch_effect_not_transmitted_does_not_seed_warm_route() {
    let directory = tempfile::tempdir().expect("fixed-quorum rejected effect warm-route directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum rejected effect warm-route start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let initial_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");
    let inactive_epoch = FencedTransitionV2HistoryEpoch::new(2).expect("inactive V2 epoch");

    let rejected_key = key(0);
    let rejected_observation = store
        .observe_fenced_transition(&rejected_key)
        .await
        .expect("rejected effect observation");
    let rejected_request = create_request(
        0,
        inactive_epoch,
        rejected_key,
        rejected_observation.current_fence(),
        &provider,
    )
    .await;
    assert!(matches!(
        SessionBackend::fenced_transition_v2_batch_effect(store, vec![rejected_request]).await,
        FencedTransitionV2Effect::NotTransmitted(StoreError::FencedTransitionHistoryEpochNotActive)
    ));

    let mut first_requests = Vec::with_capacity(2);
    for index in 1..3 {
        let transition_key = key(index);
        let observation = store
            .observe_fenced_transition(&transition_key)
            .await
            .expect("cold effect after rejection observation");
        first_requests.push(
            create_request(
                index,
                initial_epoch,
                transition_key,
                observation.current_fence(),
                &provider,
            )
            .await,
        );
    }
    let before_first = store.diagnostic_snapshot();
    assert!(matches!(
        SessionBackend::fenced_transition_v2_batch_effect(store, first_requests).await,
        FencedTransitionV2Effect::Resolved(Ok(_))
    ));
    let after_first = store.diagnostic_snapshot();
    assert_eq!(
        after_first.public_raw_v2_cold_admissions - before_first.public_raw_v2_cold_admissions,
        1,
        "a rejected typed effect must not select the later warm route"
    );
    assert_eq!(
        after_first.public_raw_v2_history_reads - before_first.public_raw_v2_history_reads,
        1,
        "a rejected typed effect must not skip fresh history admission"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_public_v2_batch_effect_outcome_unknown_does_not_seed_warm_route() {
    let directory =
        tempfile::tempdir().expect("fixed-quorum ambiguous effect warm-route directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum ambiguous effect warm-route start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, peer_slots) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let ingress = (leader + 1) % VOTERS;
    let store = &stores[ingress];
    let leader_node_id = stores[leader].status().node_id;
    let ingress_to_leader = peer_slots
        .iter()
        .find(|peer| peer.source_index == ingress && peer.node_id == leader_node_id)
        .expect("exact ingress-to-leader peer");
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    let ambiguous_key = key(0);
    let ambiguous_observation = store
        .observe_fenced_transition(&ambiguous_key)
        .await
        .expect("ambiguous effect observation");
    let ambiguous_request = create_request(
        0,
        epoch,
        ambiguous_key,
        ambiguous_observation.current_fence(),
        &provider,
    )
    .await;
    ingress_to_leader.drop_next_forward_mutation_reply();
    assert!(matches!(
        SessionBackend::fenced_transition_v2_batch_effect(store, vec![ambiguous_request.clone()])
            .await,
        FencedTransitionV2Effect::OutcomeUnknown { request_ids }
            if request_ids == vec![ambiguous_request.request_id()]
    ));

    let next_key = key(1);
    let next_observation = store
        .observe_fenced_transition(&next_key)
        .await
        .expect("cold effect after ambiguity observation");
    let next_request = create_request(
        1,
        epoch,
        next_key,
        next_observation.current_fence(),
        &provider,
    )
    .await;
    let before_next = store.diagnostic_snapshot();
    assert!(matches!(
        SessionBackend::fenced_transition_v2_batch_effect(store, vec![next_request]).await,
        FencedTransitionV2Effect::Resolved(Ok(_))
    ));
    let after_next = store.diagnostic_snapshot();
    assert_eq!(
        after_next.public_raw_v2_cold_admissions - before_next.public_raw_v2_cold_admissions,
        1,
        "an ambiguous typed effect must not select the later warm route"
    );
    assert_eq!(
        after_next.public_raw_v2_history_reads - before_next.public_raw_v2_history_reads,
        1,
        "an ambiguous typed effect must not skip fresh history admission"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_public_v2_batch_effect_stale_warm_hint_fails_closed_before_proposal() {
    let directory = tempfile::tempdir().expect("fixed-quorum stale effect warm-route directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum stale effect warm-route start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, database_paths, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    let activation_key = key(0);
    let activation_observation = store
        .observe_fenced_transition(&activation_key)
        .await
        .expect("effect activation observation");
    let activation_request = create_request(
        0,
        epoch,
        activation_key,
        activation_observation.current_fence(),
        &provider,
    )
    .await;
    assert!(matches!(
        SessionBackend::fenced_transition_v2_batch_effect(store, vec![activation_request]).await,
        FencedTransitionV2Effect::Resolved(Ok(_))
    ));

    let batch_key = key(1);
    let batch_observation = store
        .observe_fenced_transition(&batch_key)
        .await
        .expect("stale effect warm-route batch observation");
    let batch = vec![
        create_request(
            1,
            epoch,
            batch_key,
            batch_observation.current_fence(),
            &provider,
        )
        .await,
    ];
    for database_path in &database_paths {
        let connection = rusqlite::Connection::open(database_path)
            .expect("open fixed voter database for stale effect route");
        connection
            .execute(
                "DELETE FROM consensus_fenced_transition_v2_activation WHERE singleton = 1",
                [],
            )
            .expect("remove fixed V2 activation certificate");
    }

    let before_logs = stores
        .iter()
        .map(|voter| voter.status().last_log_index)
        .collect::<Vec<_>>();
    let before = store.diagnostic_snapshot();
    assert!(matches!(
        SessionBackend::fenced_transition_v2_batch_effect(store, batch).await,
        FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(_))
    ));
    let after = store.diagnostic_snapshot();
    assert_eq!(
        after.public_raw_v2_cold_admissions - before.public_raw_v2_cold_admissions,
        0,
        "a stale typed-effect warm hint must not fall back to generic V2 admission"
    );
    assert_eq!(
        after.public_raw_v2_history_reads - before.public_raw_v2_history_reads,
        0,
        "a stale typed-effect warm hint must not reread generic V2 history"
    );
    let after_logs = stores
        .iter()
        .map(|voter| voter.status().last_log_index)
        .collect::<Vec<_>>();
    assert_eq!(
        after_logs, before_logs,
        "a stale typed-effect warm hint must fail at the atomic acceptance boundary before proposal"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_public_v2_stale_warm_hint_fails_closed_before_proposal() {
    for fault in 0..3 {
        let fault_name = match fault {
            0 => "activation removal",
            1 => "operator recovery pending state",
            2 => "membership application-authority scope drift",
            _ => unreachable!("the bounded fault matrix has exactly three entries"),
        };
        let directory = tempfile::tempdir().expect("fixed-quorum stale warm-route directory");
        let start = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
                .expect("fixed-quorum stale warm-route start"),
        );
        let clock = Arc::new(MutableClock::new(start));
        let (stores, database_paths, _, _) = fixed_cluster(directory.path(), clock).await;
        let leader = ready_leader(&stores).await;
        let store = &stores[leader];
        let provider = sealing_provider();
        let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

        // A definitive public singleton success is the only way to seed this
        // store's later public-batch routing hint.
        let activation_key = key(0);
        let activation_observation = store
            .observe_fenced_transition(&activation_key)
            .await
            .expect("public singleton activation observation");
        store
            .fenced_transition_v2(
                create_request(
                    0,
                    epoch,
                    activation_key,
                    activation_observation.current_fence(),
                    &provider,
                )
                .await,
            )
            .await
            .expect("public singleton activation seeds the batch route");

        // Even with that local hint set, a public singleton must retain the
        // cold admission path rather than using the later batch route.
        let singleton_key = key(1);
        let singleton_observation = store
            .observe_fenced_transition(&singleton_key)
            .await
            .expect("public singleton after warming observation");
        let before_singleton = store.diagnostic_snapshot();
        store
            .fenced_transition_v2(
                create_request(
                    1,
                    epoch,
                    singleton_key,
                    singleton_observation.current_fence(),
                    &provider,
                )
                .await,
            )
            .await
            .expect("public singleton after warming remains cold");
        let after_singleton = store.diagnostic_snapshot();
        assert_eq!(
            after_singleton.public_raw_v2_cold_admissions
                - before_singleton.public_raw_v2_cold_admissions,
            1,
            "a public singleton after warming must retain cold admission: {fault_name}"
        );

        let batch_key = key(2);
        let batch_observation = store
            .observe_fenced_transition(&batch_key)
            .await
            .expect("stale warm-route batch observation");
        let batch = vec![
            create_request(
                2,
                epoch,
                batch_key,
                batch_observation.current_fence(),
                &provider,
            )
            .await,
        ];

        // Every exact voter must independently lose the same durable proof.
        // The local hint remains set, so the public batch must reach its
        // uncached fixed-quorum acceptance boundary and fail before proposal.
        for database_path in &database_paths {
            let connection =
                rusqlite::Connection::open(database_path).expect("open fixed voter database");
            match fault {
                0 => {
                    connection
                        .execute(
                            "DELETE FROM consensus_fenced_transition_v2_activation WHERE singleton = 1",
                            [],
                        )
                        .expect("remove fixed V2 activation certificate");
                }
                1 => {
                    connection
                        .execute(
                            "UPDATE consensus_operator_recovery \
                             SET pending_epoch = recovery_epoch + 1, pending_plan_digest = zeroblob(32) \
                             WHERE singleton = 1",
                            [],
                        )
                        .expect("activate fixed operator recovery latch");
                }
                2 => {
                    connection
                        .execute(
                            "UPDATE consensus_membership_scope \
                             SET application_authority_epoch = application_authority_epoch + 1 \
                             WHERE singleton = 1",
                            [],
                        )
                        .expect("persist fixed application-authority scope drift");
                }
                _ => unreachable!("the bounded fault matrix has exactly three entries"),
            }
        }

        let before_batch_logs = stores
            .iter()
            .map(|voter| voter.status().last_log_index)
            .collect::<Vec<_>>();
        let before_batch = store.diagnostic_snapshot();
        assert!(
            store.fenced_transition_v2_batch(batch).await.is_err(),
            "a stale public warm hint must fail closed after {fault_name}"
        );
        let after_batch = store.diagnostic_snapshot();
        assert_eq!(
            after_batch.public_raw_v2_cold_admissions - before_batch.public_raw_v2_cold_admissions,
            0,
            "a stale warm route must not fall back to generic V2 admission: {fault_name}"
        );
        let after_batch_logs = stores
            .iter()
            .map(|voter| voter.status().last_log_index)
            .collect::<Vec<_>>();
        assert_eq!(
            after_batch_logs, before_batch_logs,
            "a stale public warm hint must fail before any Openraft proposal: {fault_name}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_history_maintenance_reselects_the_local_leader() {
    let directory = tempfile::tempdir().expect("fixed-quorum V2 maintenance directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum V2 maintenance start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _, _) = fixed_cluster(directory.path(), clock.clone()).await;
    let leader = ready_leader(&stores).await;
    let provider = sealing_provider();
    let key = key(0);
    let observation = stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("fixed-quorum maintenance fence observation");
    let transition = create_request(
        0,
        FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"),
        key,
        observation.current_fence(),
        &provider,
    )
    .await;
    stores[leader]
        .fenced_transition_v2(transition)
        .await
        .expect("fixed-quorum maintenance transition");

    clock.set(
        start
            .add_seconds(24 * 60 * 60 + 1)
            .expect("maintenance retention boundary"),
    );
    let leader = ready_leader(&stores).await;
    let expected = stores[leader]
        .fenced_transition_v2_history_state()
        .await
        .expect("linearized maintenance history");
    let follower = (leader + 1) % stores.len();
    assert!(matches!(
        stores[follower]
            .maintain_fenced_transition_v2_history(expected)
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));

    let transient_retries = AtomicU64::new(0);
    let production_maintenance_counters = ProductionMaintenanceCounters::default();
    let maintained = maintain_exact_history_batch(
        &stores,
        expected,
        &transient_retries,
        &production_maintenance_counters,
        None,
    )
    .await
    .expect("maintenance reselects the current local leader");
    // Maintenance is a no-op until the active epoch is full. A one-entry
    // epoch cannot be retired merely because the result window elapsed: the
    // first full epoch opens its successor while retaining the old replay
    // epoch above the still-empty retirement floor.
    assert_eq!(maintained.retired_through(), None);
    assert_eq!(
        maintained.active_epoch(),
        Some(FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"))
    );
    assert_eq!(maintained.reclaim_epoch(), None);
    assert_eq!(maintained.reclaim_remaining(), 0);
    assert_eq!(maintained.bound_entries(), 1);
    assert_eq!(maintained.reclaimed_entries(), 0);
}

/// Release qualification for V2 capacity and retired-history reclamation.
/// Its shared injected clock advances through a consensus read barrier, never
/// by SQLite mutation or a wall-clock sleep.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "131,074 attempted / 131,073 committed real fixed-quorum consensus transitions are release qualification"]
async fn sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity() {
    let started = Instant::now();
    let directory = tempfile::tempdir().expect("qualification directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("qualification start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, database_paths, snapshot_paths, _) =
        fixed_cluster(directory.path(), clock.clone()).await;
    let store = &stores[ready_leader(&stores).await];
    let provider = sealing_provider();
    let transient_retries = Arc::new(AtomicU64::new(0));
    let effect_counters = Arc::new(ReleaseEffectCounters::default());
    let production_maintenance_counters = ProductionMaintenanceCounters::default();
    assert_eq!(
        fenced_transition_v2_profile_digest(),
        FIXED_V2_PROFILE_DIGEST
    );
    assert_eq!(
        FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
        QUALIFICATION_SESSIONS * 2,
        "the downstream contract is two unique transitions for each of 50,000 sessions"
    );
    assert_eq!(
        QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS, 31_072,
        "qualification must exercise every declared active-epoch operational transition of headroom"
    );
    let first_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("first epoch");

    // Activate the versioned capability with one ordinary session before the
    // bounded client burst. This keeps the first activation's unanimous proof
    // and durable certificate single-valued while still sending every request
    // through the same public three-voter consensus/apply path.
    let first_key = key(0);
    let first_observation = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&first_key)
    })
    .await
    .expect("initial real consensus fence observation");
    let first_request = create_request(
        0,
        first_epoch,
        first_key,
        first_observation.current_fence(),
        &provider,
    )
    .await;
    let first_outcome = execute_release_store_transition(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        store,
        first_request.clone(),
        &effect_counters,
    )
    .await
    .expect("initial capability-activating transition must commit through quorum apply");
    assert!(matches!(
        first_outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));
    let first_update = renew_update_request(1, first_epoch, &first_outcome, &provider).await;
    let first_updated = execute_release_store_transition(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        store,
        first_update.clone(),
        &effect_counters,
    )
    .await
    .expect("initial session update must commit through quorum apply");
    assert!(matches!(
        first_updated.mutation(),
        FencedTransitionMutationResult::Updated
    ));

    // Exercise the production contract: exactly two distinct committed
    // transitions for each of 50,000 durable sessions. The second operation is
    // a real lease renewal plus record update, not a disposable-key shortcut
    // around the state machine. Remaining independent sessions are admitted as
    // a bounded client burst; each task still performs its observation,
    // proposal, and three-voter durable apply through the public API. Sorting
    // the completed tasks restores deterministic session indexing for the
    // delayed-retry exemplar and the subsequent headroom updates.
    let mut remaining_session_states = futures_util::stream::iter(1..QUALIFICATION_SESSIONS)
        .map(|session_index| {
            let provider = &provider;
            let transient_retries = Arc::clone(&transient_retries);
            let effect_counters = Arc::clone(&effect_counters);
            async move {
                let key = key(session_index);
                let observation = retry_exact_consensus_operation(&transient_retries, || {
                    store.observe_fenced_transition(&key)
                })
                .await
                .expect("real consensus fence observation");
                let create_index = session_index * 2;
                let create = create_request(
                    create_index,
                    first_epoch,
                    key,
                    observation.current_fence(),
                    provider,
                )
                .await;
                let created = execute_release_store_transition(
                    Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
                    store,
                    create.clone(),
                    &effect_counters,
                )
                .await
                .expect("session create must commit through quorum apply");
                assert!(matches!(
                    created.mutation(),
                    FencedTransitionMutationResult::Created
                ));

                let update =
                    renew_update_request(create_index + 1, first_epoch, &created, provider).await;
                let updated = execute_release_store_transition(
                    Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
                    store,
                    update.clone(),
                    &effect_counters,
                )
                .await
                .expect("session update must commit through quorum apply");
                assert!(matches!(
                    updated.mutation(),
                    FencedTransitionMutationResult::Updated
                ));
                (session_index, create, created, updated)
            }
        })
        .buffer_unordered(QUALIFICATION_IN_FLIGHT_CLIENTS)
        .collect::<Vec<_>>()
        .await;
    let mut session_states = vec![(0, first_request, first_outcome, first_updated)];
    session_states.append(&mut remaining_session_states);
    session_states.sort_unstable_by_key(|(session_index, _, _, _)| *session_index);
    assert_eq!(
        session_states.len(),
        QUALIFICATION_SESSIONS,
        "every session must complete its create and update through fixed quorum"
    );
    let (first_session_index, first_request, first_outcome, _) = &session_states[0];
    assert_eq!(
        *first_session_index, 0,
        "the delayed-retry exemplar must remain the deterministic first session"
    );
    let (first_request, first_outcome) = (first_request.clone(), first_outcome.clone());
    let headroom_states = session_states
        .iter()
        .take(QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS)
        .map(|(_, _, _, updated)| updated.clone())
        .collect::<Vec<_>>();
    let target_history = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("read history at the downstream operational target");
    assert_eq!(
        target_history.bound_entries(),
        FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
        "100,000 transitions for 50,000 sessions must commit before using headroom"
    );
    assert_eq!(target_history.active_epoch(), Some(first_epoch));

    // Consume all 31,072 declared transitions of operational headroom with a
    // third real update on retained sessions.
    let mut completed_headroom_states =
        futures_util::stream::iter(headroom_states.into_iter().enumerate())
            .map(|(headroom_index, state)| {
                let provider = &provider;
                let effect_counters = Arc::clone(&effect_counters);
                async move {
                    let request_index =
                        FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET + headroom_index;
                    let update =
                        renew_update_request(request_index, first_epoch, &state, provider).await;
                    let updated = execute_release_store_transition(
                        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
                        store,
                        update.clone(),
                        &effect_counters,
                    )
                    .await
                    .expect("headroom update must commit through quorum apply");
                    assert!(matches!(
                        updated.mutation(),
                        FencedTransitionMutationResult::Updated
                    ));
                    (headroom_index, updated)
                }
            })
            .buffer_unordered(QUALIFICATION_IN_FLIGHT_CLIENTS)
            .collect::<Vec<_>>()
            .await;
    completed_headroom_states.sort_unstable_by_key(|(headroom_index, _)| *headroom_index);
    assert_eq!(
        completed_headroom_states.len(),
        QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS,
        "every declared active-epoch operational transition of headroom must commit through fixed quorum"
    );
    let headroom_states = completed_headroom_states
        .into_iter()
        .map(|(_, state)| state)
        .collect::<Vec<_>>();

    // The exact one-over request is another valid update for a live session.
    // Capacity admission must precede every lease, record, and watch-visible
    // effect.
    let one_over_state = &headroom_states[0];
    let one_over_key = one_over_state.lease().key().clone();
    let observation_before_rejection = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&one_over_key)
    })
    .await
    .expect("read one-over record and fence before rejection");
    let record_before_rejection = observation_before_rejection
        .record()
        .cloned()
        .expect("one-over session remains live");
    let fence_before_rejection = observation_before_rejection.current_fence();
    let one_over_request = renew_update_request(
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        first_epoch,
        one_over_state,
        &provider,
    )
    .await;
    let replication_before_rejection =
        retry_exact_consensus_operation(&transient_retries, || store.max_replication_sequence())
            .await
            .expect("read application sequence before one-over rejection");
    let mut one_over_watch = retry_exact_consensus_operation(&transient_retries, || {
        store.watch(replication_before_rejection + 1)
    })
    .await
    .expect("open live watch before one-over rejection");
    assert_eq!(
        execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            vec![one_over_request.clone()],
            &effect_counters,
        )
        .await
        .expect("one-over exact effect must resolve"),
        vec![Err(StoreError::FencedTransitionHistoryFull)],
        "one-over request must not execute"
    );
    assert_eq!(
        execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            vec![one_over_request.clone()],
            &effect_counters,
        )
        .await
        .expect("one-over exact replay effect must resolve"),
        vec![Err(StoreError::FencedTransitionHistoryFull)],
        "exact one-over retry must remain a deterministic no-effect rejection"
    );
    let changed_one_over_request = request_with_changed_body(&one_over_request);
    assert_eq!(
        execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            vec![changed_one_over_request.clone()],
            &effect_counters,
        )
        .await
        .expect("one-over changed-body effect must resolve"),
        vec![Err(StoreError::FencedTransitionRequestConflict)],
        "same full ID with a changed update body must not acquire capacity or a lease"
    );
    let observation_after_rejection = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&one_over_key)
    })
    .await
    .expect("read one-over record and fence after all rejected retries");
    assert_eq!(
        observation_after_rejection, observation_before_rejection,
        "one-over rejection must preserve the complete public record and durable fence observation"
    );
    assert_eq!(
        observation_after_rejection.record(),
        Some(&record_before_rejection),
        "one-over history rejection must not mutate the business record"
    );
    assert_eq!(
        observation_after_rejection.current_fence(),
        fence_before_rejection,
        "one-over history rejection must not renew a lease or advance the fence"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.max_replication_sequence()
        })
        .await
        .expect("read application sequence after one-over rejections"),
        replication_before_rejection,
        "one-over rejection and both retries must not apply an application entry"
    );
    assert!(
        one_over_watch.next().now_or_never().is_none(),
        "one-over rejection and both retries must not emit a watch event"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&one_over_request)
        })
        .await
        .expect("read one-over request status"),
        FencedTransitionV2Status::HistoryFull,
        "one-over request must have no retained result"
    );

    let history = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("read durable history counter");
    assert_eq!(
        history.bound_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
    );
    assert_eq!(history.active_epoch(), Some(first_epoch));

    let (old_request, old_outcome) = (first_request, first_outcome);
    let old_record_before_retries = retry_exact_consensus_operation(&transient_retries, || {
        store.get(old_request.lease().key())
    })
    .await
    .expect("read old request record before delayed retries")
    .expect("old request session remains live");
    assert!(matches!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&old_request)
        })
        .await
        .expect("old request remains recorded before retirement"),
        FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(old_outcome.clone())
    ));
    assert_eq!(
        execute_release_store_transition(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            old_request.clone(),
            &effect_counters,
        )
        .await
        .expect("delayed exact retry before retirement"),
        old_outcome,
        "an old exact retry must replay its original outcome after later session updates"
    );

    let changed_old_request = request_with_changed_body(&old_request);
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&changed_old_request)
        })
        .await
        .expect("altered old request status before retirement"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(
        execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            vec![changed_old_request.clone()],
            &effect_counters,
        )
        .await
        .expect("altered old-body effect must resolve before retirement"),
        vec![Err(StoreError::FencedTransitionRequestConflict)],
        "an altered old body must conflict before retirement"
    );
    clock.set(
        start
            .add_seconds(24 * 60 * 60 + 1)
            .expect("retention-boundary qualification time"),
    );
    let history_before_successor = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("commit advanced logical time through a public read barrier");
    let history = maintain_exact_history_batch(
        &stores,
        history_before_successor,
        &transient_retries,
        &production_maintenance_counters,
        None,
    )
    .await
    .expect("full first epoch opens its fixed-quorum successor");

    let next_epoch = FencedTransitionV2HistoryEpoch::new(2).expect("next epoch");
    assert_eq!(history.active_epoch(), Some(next_epoch));
    assert_eq!(history.retired_through(), None);
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(history.reclaim_remaining(), 0);
    assert_eq!(history.bound_entries(), 0);
    assert_eq!(history.reclaimed_entries(), 0);
    assert_eq!(
        history.generation(),
        history_before_successor.generation() + 1,
        "opening the immediate successor is exactly one replicated lifecycle transition"
    );

    let next_key = key(QUALIFICATION_TRANSITIONS + 1);
    let next_observation = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&next_key)
    })
    .await
    .expect("next-epoch fence observation");
    let next_request = create_request(
        QUALIFICATION_TRANSITIONS + 1,
        next_epoch,
        next_key.clone(),
        next_observation.current_fence(),
        &provider,
    )
    .await;
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&old_request)
        })
        .await
        .expect("old request remains bound in the first replay epoch"),
        FencedTransitionV2Status::Expired
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&changed_old_request)
        })
        .await
        .expect("altered old retry status after successor rotation"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(
        execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            vec![old_request.clone()],
            &effect_counters,
        )
        .await
        .expect("expired old request effect must resolve"),
        vec![Err(StoreError::FencedTransitionRequestExpired)],
        "an expired retained binding must never execute again"
    );
    assert_eq!(
        execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            store,
            vec![changed_old_request.clone()],
            &effect_counters,
        )
        .await
        .expect("expired changed-body effect must resolve"),
        vec![Err(StoreError::FencedTransitionRequestConflict)],
        "body conflict must remain deterministic after successor rotation"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&next_request)
        })
        .await
        .expect("next epoch status after successor rotation"),
        FencedTransitionV2Status::NotFound
    );
    assert!(
        retry_exact_consensus_operation(&transient_retries, || store.get(&next_key))
            .await
            .expect("read next epoch key before execution")
            .is_none(),
        "a status read must not install a business record"
    );
    let next_outcome = execute_release_store_transition(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        store,
        next_request.clone(),
        &effect_counters,
    )
    .await
    .expect("active successor epoch must execute without retiring its predecessor");
    assert!(matches!(
        next_outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.get(old_request.lease().key())
        })
        .await
        .expect("read old request record after retained replay"),
        Some(old_record_before_retries),
        "expiry, body conflict, and successor execution must not duplicate or roll back old business state"
    );
    let history = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("read history after successor execution");
    assert_eq!(history.active_epoch(), Some(next_epoch));
    assert_eq!(history.retired_through(), None);
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(history.reclaim_remaining(), 0);
    assert_eq!(history.bound_entries(), 1);
    assert_eq!(history.reclaimed_entries(), 0);

    let database_bytes_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    let database_bytes = database_bytes_by_voter.iter().sum::<u64>();
    let snapshot_bytes = snapshot_bytes_by_voter.iter().sum::<u64>();
    let peak_rss_kib = process_peak_rss_kib();
    eprintln!(
        "sdk-702 v2 qualification: elapsed={:?} committed={} reclaimed={} transient_exact_retries={} db_bytes_by_voter={database_bytes_by_voter:?} db_bytes={} snapshot_bytes_by_voter={snapshot_bytes_by_voter:?} snapshot_bytes={} peak_rss_kib={peak_rss_kib}",
        started.elapsed(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + 1,
        history.reclaimed_entries(),
        transient_retries.load(Ordering::Relaxed),
        database_bytes,
        snapshot_bytes,
    );
    assert_voter_resource_ceiling(
        "post-reclaim SQLite database family",
        &database_bytes_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "post-reclaim snapshot directory",
        &snapshot_bytes_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    #[cfg(target_os = "linux")]
    assert!(
        peak_rss_kib <= QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "three-voter peak RSS {peak_rss_kib} KiB exceeds the fixed {} KiB ceiling",
        QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
    );
}

/// Pace a real request stream without hiding a quorum that cannot keep up.
///
/// The sleep only applies while the fixed quorum is ahead of the requested
/// rate. A slower quorum therefore makes the measured rate truthful rather
/// than dropping requests, seeding state, or hiding client backlog.
fn qualification_schedule_offset(submitted: usize, per_second: usize) -> Duration {
    let nanoseconds = (submitted as u128)
        .checked_mul(1_000_000_000)
        .expect("qualification schedule numerator fits u128")
        / u128::try_from(per_second).expect("positive qualification rate");
    Duration::from_nanos(
        u64::try_from(nanoseconds).expect("qualification schedule duration fits u64 nanoseconds"),
    )
}

fn duration_evidence_microseconds(duration: Duration, label: &str) -> u64 {
    u64::try_from(duration.as_micros())
        .unwrap_or_else(|_| panic!("{label} duration does not fit evidence microseconds"))
}

fn duration_evidence_milliseconds(duration: Duration, label: &str) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or_else(|_| panic!("{label} duration does not fit evidence milliseconds"))
}

async fn pace_release_phase(phase_started: Instant, submitted: usize, per_second: usize) {
    let due = phase_started + qualification_schedule_offset(submitted, per_second);
    let now = Instant::now();
    if due > now {
        tokio::time::sleep(due - now).await;
    }
}

fn qualification_phase_max_elapsed_ms(operations: u64, offered_ops_per_second: u64) -> u64 {
    // Completion rate must be at least 99.9% of the offered rate.  The
    // quotient is intentionally floored: adding one millisecond would weaken
    // the predicate (900,000 / 500 -> exactly 1,801,801 ms; 60,000 / 1,000
    // -> exactly 60,060 ms).
    let numerator = (operations as u128)
        .checked_mul(1_000_000)
        .expect("qualification pacing numerator fits u128");
    let denominator = (offered_ops_per_second as u128)
        .checked_mul(999)
        .expect("qualification pacing denominator fits u128");
    u64::try_from(numerator / denominator).expect("qualification pacing milliseconds fit u64")
}

fn assert_qualification_phase_pacing(
    elapsed: Duration,
    operations: u64,
    offered_ops_per_second: u64,
) {
    let maximum = Duration::from_millis(qualification_phase_max_elapsed_ms(
        operations,
        offered_ops_per_second,
    ));
    assert!(
        elapsed <= maximum,
        "the finite-window completion rate must be at least 99.9% of the offered release target"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QualificationBuildProfile {
    cargo_profile_family: &'static str,
    cargo_opt_level: &'static str,
    debug_assertions: bool,
}

impl QualificationBuildProfile {
    const fn observed() -> Self {
        Self {
            cargo_profile_family: env!("OPC_SESSION_STORE_CARGO_PROFILE_FAMILY"),
            cargo_opt_level: env!("OPC_SESSION_STORE_CARGO_OPT_LEVEL"),
            debug_assertions: cfg!(debug_assertions),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualificationBuildProfileError {
    NotReleaseQualified,
}

fn validate_release_qualification_profile(
    profile: QualificationBuildProfile,
) -> Result<(), QualificationBuildProfileError> {
    if profile.cargo_profile_family == "release"
        && profile.cargo_opt_level == "3"
        && !profile.debug_assertions
    {
        Ok(())
    } else {
        Err(QualificationBuildProfileError::NotReleaseQualified)
    }
}

fn require_release_qualification_profile() -> QualificationBuildProfile {
    let profile = QualificationBuildProfile::observed();
    if validate_release_qualification_profile(profile).is_err() {
        panic!("SDK-702 release qualification requires the release profile contract");
    }
    profile
}

const RELEASE_EVIDENCE_MAX_BYTES: usize = 128 * 1024;
const RELEASE_BUILD_ATTESTATION_MAX_BYTES: usize = 16 * 1024;
const RELEASE_EVIDENCE_RECIPE_MAX_BYTES: usize = 1_024;
const RELEASE_GIT_STDOUT_MAX_BYTES: usize = 4 * 1024 * 1024;
const RELEASE_GIT_STDERR_MAX_BYTES: usize = 64 * 1024;
const RELEASE_GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const RELEASE_GIT_COMMAND_TERMINATE_GRACE: Duration = Duration::from_millis(250);
const RELEASE_EXECUTABLE_MAX_BYTES: u64 = 512 * 1024 * 1024;
static RELEASE_EVIDENCE_TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE: &str = "OPC_FS_VERITY_QUALIFICATION=required OPC_FS_VERITY_SNAPSHOT_ROOT=<existing-absolute-external-fs-verity-root> /usr/bin/python3 ci/sdk702-release-attest.py --cargo <absolute-trusted-cargo> --target-dir <absent-absolute-external-target> --snapshot-root <existing-absolute-external-fs-verity-root> --attestation-namespace <absent-absolute-external-namespace> --evidence <absent-absolute-external-namespace> --process-loss-evidence <absolute-external-testkit-v9-json> --lease <absolute-external-lock-file>";
const RELEASE_EVIDENCE_LIBTEST_ARGS: [&str; 4] = [
    "--ignored",
    "--exact",
    "release_1010000_operation_successor_scale_is_bounded_and_recoverable",
    "--nocapture",
];
const RELEASE_EVIDENCE_EXISTING_ARTIFACT_VALIDATION_RECIPE: &str = "OPC_QUAL_EVIDENCE_VALIDATE=<absolute-external-evidence-namespace> CARGO_TARGET_DIR=<absolute-external-target> cargo test --locked -p opc-session-store --release --test fenced_transition_v2_qualification -- --ignored --exact validate_existing_release_evidence_artifact --nocapture";
const PROCESS_LOSS_V9_SCHEMA_SHA256: &str =
    "sha256:65d456edc15359e9cbac25a6771822219797c53f03aa6ca5d8837e43a6dbc018";
const PROCESS_LOSS_V9_PAIR_DIRECTORY: &str = "session-ha-persistent-consumer-v9";
const PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS: usize = 16 * 1024;
const PROCESS_LOSS_CANONICAL_CARGO_ARGV: [&str; 15] = [
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
const RELEASE_EVIDENCE_SCHEMA: &str =
    include_str!("../qualification/v1/fenced-transition-v2-release-evidence.schema.json");
const PROCESS_LOSS_EVIDENCE_SCHEMA: &str = include_str!(
    "../../opc-session-testkit/qualification/v9/session-ha-persistent-consumer-head-evidence.schema.json"
);
const PROCESS_LOSS_V1_EVIDENCE_SCHEMA: &str = include_str!(
    "../../opc-session-testkit/qualification/v1/session-mtls-batch-release-gate-evidence.schema.json"
);
const PROCESS_LOSS_V9_PRODUCER_SOURCE: &str =
    include_str!("../../opc-session-testkit/tests/qualification_mtls_multiprocess.rs");
const PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES: usize = 128 * 1024;
const PROCESS_LOSS_V1_EVIDENCE_MAX_BYTES: usize = 64 * 1024;
const PROCESS_LOSS_V1_LEAF: &str = "batch-release-gate-v1.json";
const PROCESS_LOSS_V9_LEAF: &str = "persistent-consumer-v9.json";
const RELEASE_BUILD_ATTESTATION_KIND: &str = "sdk702_trusted_release_attestation_wrapper/v2";
const RELEASE_BUILD_ATTESTATION_LEAF: &str = "sdk702-release-build-attestation.json";
const QUALIFICATION_WRAPPER_LEASE_PIN_DOMAIN: &str =
    "sdk702_trusted_release_attestation_wrapper/lease-procfd/v1";
const QUALIFICATION_TRUSTED_GIT_EXECUTABLE: &str = "/usr/bin/git";
const QUALIFICATION_QUIET_HOST_BOUNDARY: &str =
    "linux_proc_nonancestor_cargo_rustc_sampled_interval_no_observation";
const QUALIFICATION_QUIET_HOST_CADENCE: Duration = Duration::from_millis(250);
const QUALIFICATION_QUIET_HOST_MAXIMUM_GAP: Duration = Duration::from_secs(2);

fn qualification_repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical qualification repository root")
}

/// Every provenance command starts from this one environment-scrubbing
/// context.  Once discovery succeeds, all later commands carry both the
/// canonical worktree and the canonical gitdir explicitly rather than relying
/// on an inherited `GIT_*` value.
struct QualificationGitContext {
    worktree: PathBuf,
    gitdir: Option<PathBuf>,
    git_executable: PathBuf,
}

#[derive(Debug)]
struct BoundedCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy)]
enum CommandPipe {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct BoundedCommandFailure {
    reason: &'static str,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

fn read_bounded_command_pipe<R>(
    mut reader: R,
    maximum: usize,
    overflow_error: &'static str,
    pipe: CommandPipe,
    completed: mpsc::Sender<(CommandPipe, Result<Vec<u8>, &'static str>)>,
) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8 * 1024];
        let mut overflowed = false;
        let result = loop {
            let read = match reader.read(&mut buffer) {
                Ok(read) => read,
                Err(_) => break Err("read bounded provenance command pipe"),
            };
            if read == 0 {
                break if overflowed {
                    Err(overflow_error)
                } else {
                    Ok(bytes)
                };
            }
            if !overflowed {
                match bytes.len().checked_add(read) {
                    Some(length) if length <= maximum => bytes.extend_from_slice(&buffer[..read]),
                    _ => overflowed = true,
                }
            }
        };
        let _ = completed.send((pipe, result));
    })
}

fn bounded_command_output(command: &mut Command) -> Result<BoundedCommandOutput, &'static str> {
    bounded_command_output_with_timeout(command, RELEASE_GIT_COMMAND_TIMEOUT)
}

fn bounded_command_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<BoundedCommandOutput, &'static str> {
    bounded_command_output_with_timeout_diagnostic(command, timeout)
        .map_err(|failure| failure.reason)
}

fn bounded_command_output_with_timeout_diagnostic(
    command: &mut Command,
    timeout: Duration,
) -> Result<BoundedCommandOutput, BoundedCommandFailure> {
    // Every trusted Git invocation gets a fresh process group, so the PID
    // returned by `spawn` is also its group leader. This lets a timeout stop
    // Git plus any helper it started, rather than merely reaping its parent.
    command.process_group(0);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| BoundedCommandFailure {
        reason: "spawn trusted provenance command",
        stdout: None,
        stderr: None,
    })?;
    let process_group = child.id();
    let stdout = child.stdout.take().ok_or(BoundedCommandFailure {
        reason: "trusted provenance command stdout unavailable",
        stdout: None,
        stderr: None,
    })?;
    let stderr = child.stderr.take().ok_or(BoundedCommandFailure {
        reason: "trusted provenance command stderr unavailable",
        stdout: None,
        stderr: None,
    })?;
    let (pipe_sender, pipe_receiver) = mpsc::channel();
    let stdout = read_bounded_command_pipe(
        stdout,
        RELEASE_GIT_STDOUT_MAX_BYTES,
        "trusted provenance command stdout exceeds bound",
        CommandPipe::Stdout,
        pipe_sender.clone(),
    );
    let stderr = read_bounded_command_pipe(
        stderr,
        RELEASE_GIT_STDERR_MAX_BYTES,
        "trusted provenance command diagnostics exceed bound",
        CommandPipe::Stderr,
        pipe_sender,
    );
    let (joined_sender, joined_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let joined = stdout.join().is_ok() && stderr.join().is_ok();
        let _ = joined_sender.send(joined);
    });
    let deadline = std::time::Instant::now() + timeout;
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut failure = None;
    while std::time::Instant::now() < deadline {
        while let Ok((pipe, result)) = pipe_receiver.try_recv() {
            match (pipe, result) {
                (CommandPipe::Stdout, Ok(value)) => stdout = Some(value),
                (CommandPipe::Stderr, Ok(value)) => stderr = Some(value),
                (_, Err(reason)) => failure = Some(reason),
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(_) => failure = Some("poll trusted provenance command"),
            }
        }
        if failure.is_some() || (status.is_some() && stdout.is_some() && stderr.is_some()) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if failure.is_none() {
        if let (Some(completed_status), Some(completed_stdout), Some(completed_stderr)) =
            (status.take(), stdout.take(), stderr.take())
        {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if matches!(joined_receiver.recv_timeout(remaining), Ok(true)) {
                return Ok(BoundedCommandOutput {
                    status: completed_status,
                    stdout: completed_stdout,
                    stderr: completed_stderr,
                });
            }
            status = Some(completed_status);
            stdout = Some(completed_stdout);
            stderr = Some(completed_stderr);
            failure = Some("trusted provenance command readers did not join by deadline");
        }
    }
    let reason = failure.unwrap_or("trusted provenance command exceeded fixed runtime");
    let cleanup_deadline = std::time::Instant::now()
        + RELEASE_GIT_COMMAND_TERMINATE_GRACE
        + RELEASE_GIT_COMMAND_TERMINATE_GRACE;
    if let Err(cleanup_failure) = terminate_command_process_group(
        &mut child,
        process_group,
        &pipe_receiver,
        &mut stdout,
        &mut stderr,
        &mut status,
        &joined_receiver,
        cleanup_deadline,
    ) {
        // A command failure must still be followed by the complete TERM/KILL
        // cleanup sequence. Preserve the original cause when there was one,
        // but fail closed if cleanup could not prove that its group and both
        // bounded readers were gone.
        failure.get_or_insert(cleanup_failure);
    }
    Err(BoundedCommandFailure {
        reason: failure.unwrap_or(reason),
        stdout,
        stderr,
    })
}

fn signal_command_process_group(process_group: u32, signal: &str) -> Result<(), &'static str> {
    // `nix` signal/process support is deliberately not enabled in this
    // production crate. Invoke the fixed system helper only to signal this
    // owned, numeric process group; a raced `ESRCH` is harmless because the
    // subsequent `try_wait` still reaps the direct Git child.
    let status = Command::new("/bin/kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{process_group}"))
        .status()
        .map_err(|_| "spawn trusted provenance process-group signal helper")?;
    if status.success() {
        Ok(())
    } else {
        Err("signal trusted provenance process group")
    }
}

fn command_process_group_exists(process_group: u32) -> bool {
    Command::new("/bin/kill")
        .arg("-0")
        .arg("--")
        .arg(format!("-{process_group}"))
        .status()
        .is_ok_and(|status| status.success())
}

#[allow(clippy::too_many_arguments)] // All cleanup handles are independently required to reap the process group.
fn terminate_command_process_group(
    child: &mut std::process::Child,
    process_group: u32,
    pipe_receiver: &mpsc::Receiver<(CommandPipe, Result<Vec<u8>, &'static str>)>,
    stdout: &mut Option<Vec<u8>>,
    stderr: &mut Option<Vec<u8>>,
    status: &mut Option<std::process::ExitStatus>,
    joined_receiver: &mpsc::Receiver<bool>,
    deadline: std::time::Instant,
) -> Result<(), &'static str> {
    let _ = signal_command_process_group(process_group, "TERM");
    let terminate_deadline = std::time::Instant::now() + RELEASE_GIT_COMMAND_TERMINATE_GRACE;
    let mut cleanup_failure = None;
    while std::time::Instant::now() < terminate_deadline {
        if let Err(error) = drain_command_pipes(pipe_receiver, stdout, stderr) {
            cleanup_failure.get_or_insert(error);
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => *status = value,
                Err(_) => {
                    cleanup_failure.get_or_insert("poll terminated trusted provenance command");
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    // Always KILL the owned group after the fixed TERM grace. The leader may
    // already have exited while a descendant still owns a pipe descriptor.
    let _ = signal_command_process_group(process_group, "KILL");
    while std::time::Instant::now() < deadline {
        if let Err(error) = drain_command_pipes(pipe_receiver, stdout, stderr) {
            cleanup_failure.get_or_insert(error);
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => *status = value,
                Err(_) => {
                    cleanup_failure.get_or_insert("poll killed trusted provenance command");
                }
            }
        }
        if status.is_some() && !command_process_group_exists(process_group) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if !matches!(joined_receiver.recv_timeout(remaining), Ok(true)) {
                return Err("trusted provenance command readers did not join after SIGKILL");
            }
            if let Err(error) = drain_command_pipes(pipe_receiver, stdout, stderr) {
                cleanup_failure.get_or_insert(error);
            }
            if let Some(error) = cleanup_failure {
                return Err(error);
            }
            return (stdout.is_some() && stderr.is_some())
                .then_some(())
                .ok_or("trusted provenance command pipe completion missing after SIGKILL");
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(cleanup_failure.unwrap_or("trusted provenance process group did not reap after SIGKILL"))
}

fn drain_command_pipes(
    pipe_receiver: &mpsc::Receiver<(CommandPipe, Result<Vec<u8>, &'static str>)>,
    stdout: &mut Option<Vec<u8>>,
    stderr: &mut Option<Vec<u8>>,
) -> Result<(), &'static str> {
    let mut failure = None;
    while let Ok((pipe, result)) = pipe_receiver.try_recv() {
        match (pipe, result) {
            (CommandPipe::Stdout, Ok(value)) => *stdout = Some(value),
            (CommandPipe::Stderr, Ok(value)) => *stderr = Some(value),
            (_, Err(reason)) => {
                failure.get_or_insert(reason);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn trusted_git_executable() -> Result<PathBuf, &'static str> {
    let executable = Path::new(QUALIFICATION_TRUSTED_GIT_EXECUTABLE)
        .canonicalize()
        .map_err(|_| "canonical trusted git executable unavailable")?;
    if !executable.is_absolute()
        || !std::fs::metadata(&executable)
            .map_err(|_| "stat trusted git executable")?
            .is_file()
    {
        return Err("trusted git executable is not an absolute regular file");
    }
    Ok(executable)
}

impl QualificationGitContext {
    fn discovered(worktree: PathBuf) -> Self {
        Self::with_candidate_executable(
            worktree,
            None,
            Path::new(QUALIFICATION_TRUSTED_GIT_EXECUTABLE),
        )
        .expect("bind absolute trusted git for release qualification")
    }

    fn bound(worktree: PathBuf, gitdir: PathBuf) -> Self {
        Self::with_candidate_executable(
            worktree,
            Some(gitdir),
            Path::new(QUALIFICATION_TRUSTED_GIT_EXECUTABLE),
        )
        .expect("bind absolute trusted git for release qualification")
    }

    fn with_candidate_executable(
        worktree: PathBuf,
        gitdir: Option<PathBuf>,
        candidate: &Path,
    ) -> Result<Self, &'static str> {
        let trusted = trusted_git_executable()?;
        let candidate = candidate
            .canonicalize()
            .map_err(|_| "canonical candidate git executable unavailable")?;
        if candidate != trusted {
            return Err("release qualification refuses an untrusted git executable");
        }
        if !worktree.is_absolute() {
            return Err("release qualification git worktree is not absolute");
        }
        Ok(Self {
            worktree,
            gitdir,
            git_executable: trusted,
        })
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.git_executable);
        // Do not inherit either path resolution or dynamic-loader/configuration
        // controls from a caller.  The absolute executable remains the sole
        // trusted process image; failures carry no Git diagnostics or paths.
        command.env_clear();
        command.env("PATH", "/usr/bin:/bin");
        command.env("HOME", "/nonexistent");
        command.env("XDG_CONFIG_HOME", "/nonexistent");
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.env("LC_ALL", "C");
        command.env("LANG", "C");
        command.current_dir(&self.worktree);
        command.arg("--no-pager");
        command.arg("-c").arg("core.fsmonitor=false");
        if let Some(gitdir) = &self.gitdir {
            command.arg("--work-tree").arg(&self.worktree);
            command.arg("--git-dir").arg(gitdir);
        }
        command.args(arguments);
        command
    }

    fn output(&self, arguments: &[&str]) -> Result<BoundedCommandOutput, &'static str> {
        bounded_command_output(&mut self.command(arguments))
    }

    fn checked_output(&self, arguments: &[&str]) -> String {
        let output = self
            .output(arguments)
            .expect("trusted git provenance command must run");
        assert!(
            output.status.success(),
            "git provenance command must succeed for release qualification evidence"
        );
        assert!(
            output.stderr.is_empty(),
            "successful git provenance command must not emit diagnostics"
        );
        let value = String::from_utf8(output.stdout).expect("git provenance is UTF-8");
        assert!(
            !value.contains('\0') && value.len() <= RELEASE_GIT_STDOUT_MAX_BYTES,
            "git provenance is bounded and contains no NUL"
        );
        if value.is_empty() {
            return value;
        }
        let line = value
            .strip_suffix('\n')
            .expect("git provenance line is newline terminated");
        assert!(
            !line.is_empty() && !line.contains(['\n', '\r']),
            "git provenance must be one bounded canonical line"
        );
        line.to_owned()
    }

    fn checked_bytes(&self, arguments: &[&str]) -> Vec<u8> {
        let output = self
            .output(arguments)
            .expect("trusted git provenance command must run");
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "trusted git byte provenance command must succeed without diagnostics"
        );
        output.stdout
    }

    fn require_merge_head_absent(&self) {
        let output = self
            .output(&["rev-parse", "-q", "--verify", "MERGE_HEAD"])
            .expect("trusted git MERGE_HEAD probe must run");
        match output.status.code() {
            Some(1) if output.stdout.is_empty() && output.stderr.is_empty() => {}
            Some(0) => panic!("release qualification must not have MERGE_HEAD"),
            _ => panic!("git MERGE_HEAD probe failed instead of proving it absent"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseEvidenceProvenance {
    source: ReleaseEvidenceSource,
    build_cargo_lock_sha256: String,
    runtime_cargo_lock_sha256: String,
    compiled_schema_sha256: String,
    canonical_gitdir: PathBuf,
    canonical_common_gitdir: PathBuf,
}

fn clean_worktree_sha256(revision: &str, tree: &str, index_stage_manifest: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"sdk702-clean-worktree-index-stage-v1\0");
    digest.update(revision.as_bytes());
    digest.update([0]);
    digest.update(tree.as_bytes());
    digest.update([0]);
    digest.update(index_stage_manifest);
    format!("{:x}", digest.finalize())
}

#[allow(clippy::option_env_unwrap)] // Release recipe requires these compile-time attestations.
fn release_evidence_provenance_snapshot() -> ReleaseEvidenceProvenance {
    let repository_root = qualification_repository_root();
    let discovered = QualificationGitContext::discovered(repository_root.clone());
    let discovered_root =
        PathBuf::from(discovered.checked_output(&["rev-parse", "--show-toplevel"]))
            .canonicalize()
            .expect("canonical git worktree root");
    assert_eq!(
        discovered_root, repository_root,
        "git worktree must bind Cargo manifest root"
    );
    let gitdir = PathBuf::from(discovered.checked_output(&["rev-parse", "--absolute-git-dir"]))
        .canonicalize()
        .expect("canonical gitdir");
    let common_gitdir =
        PathBuf::from(discovered.checked_output(&["rev-parse", "--git-common-dir"]))
            .canonicalize()
            .expect("canonical common gitdir");
    let git = QualificationGitContext::bound(repository_root.clone(), gitdir.clone());
    assert_eq!(
        git.checked_output(&["rev-parse", "--show-toplevel"]),
        repository_root.display().to_string(),
        "bound git worktree must remain canonical"
    );
    assert_eq!(
        PathBuf::from(git.checked_output(&["rev-parse", "--absolute-git-dir"]))
            .canonicalize()
            .expect("canonical bound gitdir"),
        gitdir,
        "bound gitdir must remain canonical"
    );
    assert_eq!(
        PathBuf::from(git.checked_output(&["rev-parse", "--git-common-dir"]))
            .canonicalize()
            .expect("canonical bound common gitdir"),
        common_gitdir,
        "bound common gitdir must remain canonical"
    );
    assert_eq!(
        git.checked_output(&["rev-parse", "--is-inside-work-tree"]),
        "true",
        "qualification provenance requires a git worktree"
    );

    // A and B bracket every mutable input used by this snapshot.  The tree is
    // derived from A, never from a later HEAD.
    let revision = git.checked_output(&["rev-parse", "HEAD"]);
    assert!(
        is_lower_hex_exact(&revision, 40),
        "trusted git HEAD must be an exact lower-hex object identity"
    );
    let revision_tree = format!("{revision}^{{tree}}");
    let tree = git.checked_output(&["rev-parse", &revision_tree]);
    assert!(
        is_lower_hex_exact(&tree, 40),
        "trusted git HEAD tree must be an exact lower-hex object identity"
    );
    let status = git.checked_output(&[
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored",
        "--ignore-submodules=none",
    ]);
    assert!(
        status.is_empty(),
        "release qualification requires a fully clean worktree including ignored files"
    );
    git.require_merge_head_absent();
    let source_worktree_sha256 = clean_worktree_sha256(
        &revision,
        &tree,
        &git.checked_bytes(&["ls-files", "--cached", "--stage", "-z"]),
    );
    let repository_metadata =
        std::fs::metadata(&repository_root).expect("stat canonical repository root for Cargo.lock");
    let repository_parent = pinned_parent_file(
        &repository_root,
        repository_metadata.dev(),
        repository_metadata.ino(),
    )
    .expect("open descriptor-pinned repository root for Cargo.lock");
    let runtime_cargo_lock_sha256 = format!(
        "{:x}",
        Sha256::digest(
            read_bounded_nofollow_regular_file(
                &repository_parent,
                OsStr::new("Cargo.lock"),
                RELEASE_GIT_STDOUT_MAX_BYTES,
                "runtime Cargo.lock",
            )
            .expect("read bounded no-follow Cargo.lock for release qualification evidence")
        )
    );
    let build_cargo_lock_sha256 = format!(
        "{:x}",
        Sha256::digest(include_bytes!("../../../Cargo.lock"))
    );
    assert_eq!(
        runtime_cargo_lock_sha256, build_cargo_lock_sha256,
        "runtime Cargo.lock must equal the build-tracked Cargo.lock"
    );
    assert_eq!(
        git.checked_output(&["rev-parse", "HEAD"]),
        revision,
        "HEAD changed during qualification provenance capture"
    );
    let build_revision = option_env!("OPC_QUAL_SOURCE_REVISION")
        .expect("OPC_QUAL_SOURCE_REVISION must be set at compile time for the release recipe");
    let build_tree = option_env!("OPC_QUAL_SOURCE_TREE")
        .expect("OPC_QUAL_SOURCE_TREE must be set at compile time for the release recipe");
    let build_worktree_sha256 = option_env!("OPC_QUAL_SOURCE_WORKTREE_SHA256").expect(
        "OPC_QUAL_SOURCE_WORKTREE_SHA256 must be set at compile time for the release recipe",
    );
    let build_schema_sha256 = option_env!("OPC_QUAL_RELEASE_SCHEMA_SHA256").expect(
        "OPC_QUAL_RELEASE_SCHEMA_SHA256 must be set at compile time for the release recipe",
    );
    let compiled_schema_sha256 = format!("{:x}", Sha256::digest(RELEASE_EVIDENCE_SCHEMA));
    assert_eq!(
        build_revision, revision,
        "the runtime clean HEAD must equal the build-time source revision"
    );
    assert_eq!(
        build_tree, tree,
        "the runtime clean HEAD tree must equal the build-time source tree"
    );
    assert_eq!(
        build_worktree_sha256, source_worktree_sha256,
        "the runtime clean index-stage manifest must equal the build-time source worktree digest"
    );
    assert_eq!(
        build_schema_sha256, compiled_schema_sha256,
        "the compiled release schema digest must equal the runtime included schema"
    );
    assert!(
        is_lower_hex_exact(build_revision, 40)
            && is_lower_hex_exact(build_tree, 40)
            && is_lower_hex_exact(build_worktree_sha256, 64)
            && is_lower_hex_exact(build_schema_sha256, 64),
        "compile-time source inputs must be exact lower-hex Git identities"
    );
    ReleaseEvidenceProvenance {
        source: ReleaseEvidenceSource {
            build_revision: build_revision.to_owned(),
            build_tree: build_tree.to_owned(),
            source_worktree_sha256,
            revision,
            tree,
            worktree: "clean".to_owned(),
        },
        build_cargo_lock_sha256,
        runtime_cargo_lock_sha256,
        compiled_schema_sha256,
        canonical_gitdir: gitdir,
        canonical_common_gitdir: common_gitdir,
    }
}

fn qualification_target_environment() -> &'static str {
    #[cfg(target_env = "gnu")]
    {
        "gnu"
    }
    #[cfg(target_env = "musl")]
    {
        "musl"
    }
    #[cfg(target_env = "msvc")]
    {
        "msvc"
    }
    #[cfg(not(any(target_env = "gnu", target_env = "musl", target_env = "msvc")))]
    {
        "unknown"
    }
}

fn qualification_enabled_features() -> Vec<String> {
    let mut enabled = Vec::new();
    if cfg!(feature = "test-control") {
        enabled.push("test-control".to_owned());
    }
    if cfg!(feature = "test-vfs") {
        enabled.push("test-vfs".to_owned());
    }
    enabled
}

fn redacted_path_id(path: &Path) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(path.as_os_str().as_encoded_bytes())
    )
}

fn is_lower_hex_exact(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256_path_id(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex_exact(digest, 64))
}

/// This byte inclusion is intentional: a release test compiled without the
/// exact checked-in wrapper bytes cannot accept an attestation emitted by a
/// different wrapper. Cargo tracks `include_bytes!` as a build dependency.
fn compiled_release_attestation_wrapper_sha256() -> String {
    format!(
        "{:x}",
        Sha256::digest(include_bytes!("../../../ci/sdk702-release-attest.py"))
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBuildAttestation {
    kind: String,
    source_revision: String,
    source_tree: String,
    source_worktree_sha256: String,
    cargo_lock_sha256: String,
    release_schema_sha256: String,
    cargo_target_dir_id: String,
    fs_verity_snapshot_base_id: String,
    fs_verity_snapshot_root_id: String,
    fs_verity_snapshot_root_device: u64,
    fs_verity_snapshot_root_inode: u64,
    executable_sha256: String,
    executable_device: u64,
    executable_inode: u64,
    wrapper_sha256: String,
    observed_libtest_argv: Vec<String>,
    required_reproduction_recipe: String,
}

fn observed_release_libtest_argv() -> Vec<String> {
    let observed = std::env::args_os()
        .skip(1)
        .map(|argument| {
            argument
                .into_string()
                .expect("release qualification libtest arguments must be UTF-8")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        RELEASE_EVIDENCE_LIBTEST_ARGS
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>(),
        "release evidence observes only this exact libtest argv tail; Cargo parent argv is not observable"
    );
    observed
}

fn strict_decode_release_build_attestation(
    encoded: &[u8],
) -> Result<ReleaseBuildAttestation, &'static str> {
    if encoded.len() > RELEASE_BUILD_ATTESTATION_MAX_BYTES {
        return Err("release build attestation exceeds bounded decoder limit");
    }
    let attestation: ReleaseBuildAttestation =
        serde_json::from_slice(encoded).map_err(|_| "release build attestation is not closed")?;
    let canonical = serde_json::to_vec(&attestation)
        .map_err(|_| "release build attestation cannot canonicalize")?;
    if canonical != encoded {
        return Err("release build attestation is not canonical");
    }
    Ok(attestation)
}

fn validate_release_build_attestation(
    attestation: &ReleaseBuildAttestation,
    provenance: &ReleaseEvidenceProvenance,
    target_dir: &Path,
    executable_sha256: &str,
    executable_identity: EvidenceArtifactIdentity,
    observed_libtest_argv: &[String],
) -> Result<(), &'static str> {
    if attestation.kind != RELEASE_BUILD_ATTESTATION_KIND
        || attestation.source_revision != provenance.source.revision
        || attestation.source_tree != provenance.source.tree
        || attestation.source_worktree_sha256 != provenance.source.source_worktree_sha256
        || attestation.cargo_lock_sha256 != provenance.runtime_cargo_lock_sha256
        || attestation.release_schema_sha256 != provenance.compiled_schema_sha256
        || attestation.cargo_target_dir_id != redacted_path_id(target_dir)
        || !is_sha256_path_id(&attestation.fs_verity_snapshot_base_id)
        || !is_sha256_path_id(&attestation.fs_verity_snapshot_root_id)
        || attestation.fs_verity_snapshot_root_device == 0
        || attestation.fs_verity_snapshot_root_inode == 0
        || attestation.executable_sha256 != executable_sha256
        || attestation.executable_device != executable_identity.device
        || attestation.executable_inode != executable_identity.inode
        || attestation.wrapper_sha256 != compiled_release_attestation_wrapper_sha256()
        || attestation.observed_libtest_argv != observed_libtest_argv
        || attestation.required_reproduction_recipe != RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE
        || !is_lower_hex_exact(&attestation.source_worktree_sha256, 64)
        || !is_lower_hex_exact(&attestation.cargo_lock_sha256, 64)
        || !is_lower_hex_exact(&attestation.release_schema_sha256, 64)
        || !is_lower_hex_exact(&attestation.executable_sha256, 64)
        || !is_lower_hex_exact(&attestation.wrapper_sha256, 64)
        || !is_sha256_path_id(&attestation.cargo_target_dir_id)
    {
        return Err("trusted release build attestation does not bind this executable and source");
    }
    Ok(())
}

fn hash_pinned_regular_file_streaming(
    file: &mut File,
    maximum: u64,
) -> Result<(String, EvidenceArtifactIdentity), &'static str> {
    use rustix::fs::{fstat, FileType};

    let initial = fstat(&*file).map_err(|_| "fstat pinned executable descriptor")?;
    if !FileType::from_raw_mode(initial.st_mode).is_file() {
        return Err("pinned executable descriptor is not a regular file");
    }
    let size = u64::try_from(initial.st_size).map_err(|_| "pinned executable size invalid")?;
    if size > maximum {
        return Err("pinned executable exceeds streaming size limit");
    }
    let mut digest = Sha256::new();
    let mut read_total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "stream pinned executable descriptor")?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(u64::try_from(read).map_err(|_| "pinned executable read length invalid")?)
            .ok_or("pinned executable streaming length overflow")?;
        if read_total > maximum {
            return Err("pinned executable grew past streaming size limit");
        }
        digest.update(&buffer[..read]);
    }
    let after = fstat(&*file).map_err(|_| "re-fstat pinned executable descriptor")?;
    if after.st_dev != initial.st_dev
        || after.st_ino != initial.st_ino
        || after.st_size != initial.st_size
        || read_total != size
    {
        return Err("pinned executable changed while streaming hash");
    }
    Ok((format!("{:x}", digest.finalize()), rustix_identity(initial)))
}

fn require_exact_release_build_attestation_namespace(parent: &File) -> Result<(), &'static str> {
    use rustix::fs::Dir;

    let mut entries = 0_u8;
    for entry in Dir::read_from(parent).map_err(|_| "read trusted build attestation namespace")? {
        let entry = entry.map_err(|_| "read trusted build attestation namespace entry")?;
        let name = entry.file_name();
        #[cfg(unix)]
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        entries = entries
            .checked_add(1)
            .ok_or("trusted build attestation namespace entry count overflow")?;
        if entries != 1 || name.to_bytes() != RELEASE_BUILD_ATTESTATION_LEAF.as_bytes() {
            return Err("trusted build attestation namespace has extra residue");
        }
    }
    if entries != 1 {
        return Err("trusted build attestation namespace is missing its fixed leaf");
    }
    Ok(())
}

fn required_release_build_attestation(
    provenance: &ReleaseEvidenceProvenance,
    target_dir: &Path,
    evidence_namespace: &Path,
    executable_sha256: &str,
    executable_identity: EvidenceArtifactIdentity,
    observed_libtest_argv: &[String],
) -> Result<(PathBuf, String, ReleaseBuildAttestation), &'static str> {
    let supplied = PathBuf::from(
        std::env::var_os("OPC_QUAL_BUILD_ATTESTATION")
            .ok_or("OPC_QUAL_BUILD_ATTESTATION must name trusted wrapper output")?,
    );
    let (canonical_parent, leaf, canonical_path) =
        canonical_direct_leaf_path(&supplied, "OPC_QUAL_BUILD_ATTESTATION")?;
    if leaf != OsStr::new(RELEASE_BUILD_ATTESTATION_LEAF) {
        return Err("release build attestation must use the fixed trusted-wrapper leaf");
    }
    let repository_root = qualification_repository_root();
    if paths_overlap(&canonical_path, &repository_root)
        || paths_overlap(&canonical_path, &provenance.canonical_gitdir)
        || paths_overlap(&canonical_path, &provenance.canonical_common_gitdir)
        || paths_overlap(&canonical_path, target_dir)
        || paths_overlap(&canonical_path, evidence_namespace)
    {
        return Err("release build attestation is not externally disjoint");
    }
    let parent_metadata = std::fs::metadata(&canonical_parent)
        .map_err(|_| "stat release build attestation parent")?;
    if !parent_metadata.is_dir() || parent_metadata.mode() & 0o077 != 0 {
        return Err("release build attestation parent is not a private namespace");
    }
    let parent = pinned_parent_file(
        &canonical_parent,
        parent_metadata.dev(),
        parent_metadata.ino(),
    )?;
    require_exact_release_build_attestation_namespace(&parent)?;
    let encoded = read_bounded_nofollow_regular_file(
        &parent,
        &leaf,
        RELEASE_BUILD_ATTESTATION_MAX_BYTES,
        "release build attestation",
    )?;
    let attestation = strict_decode_release_build_attestation(&encoded)?;
    validate_release_build_attestation(
        &attestation,
        provenance,
        target_dir,
        executable_sha256,
        executable_identity,
        observed_libtest_argv,
    )?;
    Ok((
        canonical_path,
        format!("{:x}", Sha256::digest(encoded)),
        attestation,
    ))
}

fn release_evidence_execution_identity(
    provenance: &ReleaseEvidenceProvenance,
    evidence_namespace: &Path,
    observed_libtest_argv: &[String],
) -> Result<(ReleaseEvidenceExecution, PathBuf), &'static str> {
    use rustix::fs::{openat, Mode, OFlags, CWD};

    let repository_root = qualification_repository_root();
    let target_dir = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .ok_or("CARGO_TARGET_DIR must bind the release evidence executable")?,
    )
    .canonicalize()
    .map_err(|_| "canonical CARGO_TARGET_DIR")?;
    if !target_dir.is_absolute()
        || paths_overlap(&target_dir, &repository_root)
        || paths_overlap(&target_dir, &provenance.canonical_gitdir)
        || paths_overlap(&target_dir, &provenance.canonical_common_gitdir)
    {
        return Err("CARGO_TARGET_DIR is not an external canonical target");
    }
    // `/proc/self/exe` is the kernel-pinned identity of this process.  The
    // descriptive link below is used only to derive a redacted target-relative
    // identifier; its pathname is never reopened or trusted for file identity.
    let executable_descriptor = openat(
        CWD,
        "/proc/self/exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "open pinned Linux running executable descriptor")?;
    let mut executable = File::from(executable_descriptor);
    let current_exe_link =
        std::fs::read_link("/proc/self/exe").map_err(|_| "read pinned Linux executable link")?;
    if !current_exe_link.is_absolute() {
        return Err("pinned Linux executable link is not absolute");
    }
    let relative = current_exe_link
        .strip_prefix(&target_dir)
        .map_err(|_| "pinned executable link is not target-relative")?;
    if relative.as_os_str().is_empty()
        || !relative.is_relative()
        || !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err("pinned executable relative identifier is not normal");
    }
    let (executable_sha256, executable_identity) =
        hash_pinned_regular_file_streaming(&mut executable, RELEASE_EXECUTABLE_MAX_BYTES)?;
    let (attestation_path, attestation_sha256, attestation) = required_release_build_attestation(
        provenance,
        &target_dir,
        evidence_namespace,
        &executable_sha256,
        executable_identity,
        observed_libtest_argv,
    )?;
    let enabled_features = qualification_enabled_features();
    if !enabled_features.is_empty() {
        return Err("exact release reproduction recipe enables no store features");
    }
    release_fs_verity_snapshot_root_from_environment(
        std::env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref(),
        std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV).as_deref(),
        &attestation.fs_verity_snapshot_root_id,
        attestation.fs_verity_snapshot_root_device,
        attestation.fs_verity_snapshot_root_inode,
    )?;
    Ok((
        ReleaseEvidenceExecution {
            cargo_target_dir_id: redacted_path_id(&target_dir),
            fs_verity_snapshot_base_id: attestation.fs_verity_snapshot_base_id,
            fs_verity_snapshot_root_id: attestation.fs_verity_snapshot_root_id,
            fs_verity_snapshot_root_device: attestation.fs_verity_snapshot_root_device,
            fs_verity_snapshot_root_inode: attestation.fs_verity_snapshot_root_inode,
            current_exe_relative_to_target_id: redacted_path_id(relative),
            current_exe_sha256: executable_sha256,
            current_exe_device: executable_identity.device,
            current_exe_inode: executable_identity.inode,
            compiled_schema_sha256: provenance.compiled_schema_sha256.clone(),
            build_attestation_path_id: redacted_path_id(&attestation_path),
            build_attestation_sha256: attestation_sha256,
            build_attestation_wrapper_sha256: compiled_release_attestation_wrapper_sha256(),
            build_attestation_boundary: RELEASE_BUILD_ATTESTATION_KIND.to_owned(),
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            target_env: qualification_target_environment().to_owned(),
            enabled_features,
            runner_quiet_host_boundary: QUALIFICATION_QUIET_HOST_BOUNDARY.to_owned(),
        },
        attestation_path,
    ))
}

const RELEASE_EVIDENCE_NAMESPACE_LEAF: &str = "fenced-transition-v2-release-evidence.json";
const RELEASE_EVIDENCE_ACCEPTED_LEAF: &str = ".accepted";

struct PinnedReleaseEvidenceArtifact {
    evidence: ReleaseEvidenceArtifact,
    canonical_external_parent: PathBuf,
    canonical_namespace: PathBuf,
    external_parent: File,
    namespace: OsString,
    namespace_parent: File,
    leaf: OsString,
    external_parent_device: u64,
    external_parent_inode: u64,
    namespace_device: u64,
    namespace_inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceArtifactIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

impl EvidenceArtifactIdentity {
    const fn same_inode(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn rustix_identity(stat: rustix::fs::Stat) -> EvidenceArtifactIdentity {
    EvidenceArtifactIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: u64::try_from(stat.st_size).expect("evidence artifact size is nonnegative"),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn rustix_identity(stat: rustix::fs::Stat) -> EvidenceArtifactIdentity {
    EvidenceArtifactIdentity {
        device: u64::try_from(stat.st_dev).expect("evidence artifact device is nonnegative"),
        inode: stat.st_ino,
        size: u64::try_from(stat.st_size).expect("evidence artifact size is nonnegative"),
    }
}

#[cfg(target_os = "linux")]
const fn rustix_private_mode(stat: rustix::fs::Stat) -> u32 {
    stat.st_mode & 0o777
}

#[cfg(not(target_os = "linux"))]
const fn rustix_private_mode(stat: rustix::fs::Stat) -> u32 {
    (stat.st_mode & 0o777) as u32
}

fn pinned_parent_file(
    canonical_parent: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<File, &'static str> {
    use rustix::fs::{fstat, openat, Mode, OFlags, CWD};

    let descriptor = openat(
        CWD,
        canonical_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "open canonical external evidence parent without following links")?;
    let identity =
        rustix_identity(fstat(&descriptor).map_err(|_| "fstat evidence parent descriptor")?);
    if identity.device != expected_device || identity.inode != expected_inode {
        return Err("canonical evidence parent pathname identity changed");
    }
    Ok(File::from(descriptor))
}

fn require_current_user_private_directory(
    stat: rustix::fs::Stat,
    label: &'static str,
) -> Result<(), &'static str> {
    use rustix::fs::FileType;

    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != nix::unistd::Uid::current().as_raw()
        || stat.st_mode & 0o777 != 0o700
    {
        let _ = label;
        return Err("qualification namespace parent is not current-user private mode 0700");
    }
    Ok(())
}

fn require_current_user_private_regular_file(
    stat: rustix::fs::Stat,
    label: &'static str,
) -> Result<(), &'static str> {
    use rustix::fs::FileType;

    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != nix::unistd::Uid::current().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        let _ = label;
        return Err("qualification leaf is not a current-user private regular file");
    }
    Ok(())
}

fn pinned_current_user_private_directory(
    canonical_parent: &Path,
    expected_device: u64,
    expected_inode: u64,
    label: &'static str,
) -> Result<File, &'static str> {
    use rustix::fs::fstat;

    let before = std::fs::metadata(canonical_parent)
        .map_err(|_| "stat private qualification namespace parent")?;
    if before.dev() != expected_device || before.ino() != expected_inode {
        return Err("private qualification namespace parent pathname identity changed");
    }
    let parent = pinned_parent_file(canonical_parent, expected_device, expected_inode)?;
    require_current_user_private_directory(
        fstat(&parent).map_err(|_| "fstat private qualification namespace parent")?,
        label,
    )?;
    let after = std::fs::metadata(canonical_parent)
        .map_err(|_| "re-stat private qualification namespace parent")?;
    if after.dev() != expected_device || after.ino() != expected_inode {
        return Err("private qualification namespace parent pathname changed");
    }
    Ok(parent)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn assert_external_disjoint(path: &Path, repository_root: &Path, gitdir: &Path, label: &str) {
    assert!(path.is_absolute(), "{label} must be absolute");
    assert!(
        !paths_overlap(path, repository_root) && !paths_overlap(path, gitdir),
        "{label} must be outside the canonical worktree and gitdir"
    );
}

/// The protected Git topology is deliberately not included in the pairwise
/// set: a linked worktree's gitdir is normally nested under its common gitdir,
/// and a main worktree's `.git` is normally nested under the worktree. Every
/// external input, however, must be pairwise disjoint and outside every one of
/// those protected boundaries before the publisher creates its namespace.
fn validate_release_evidence_external_topology_before_mkdir(
    external_paths: &[(&Path, &str)],
    repository_root: &Path,
    gitdir: &Path,
    common_gitdir: &Path,
) -> Result<(), &'static str> {
    for (index, (path, label)) in external_paths.iter().enumerate() {
        if !path.is_absolute() {
            let _ = label;
            return Err("release evidence external path is not absolute");
        }
        for (other, other_label) in external_paths.iter().skip(index + 1) {
            if paths_overlap(path, other) {
                let _ = (label, other_label);
                return Err("release evidence external paths are not pairwise disjoint");
            }
        }
        for protected in [repository_root, gitdir, common_gitdir] {
            if paths_overlap(path, protected) {
                return Err("release evidence external path overlaps a protected Git boundary");
            }
        }
    }
    Ok(())
}

fn canonical_direct_leaf_path(
    supplied: &Path,
    label: &'static str,
) -> Result<(PathBuf, OsString, PathBuf), &'static str> {
    if !supplied.is_absolute() {
        return Err("external evidence input path must be absolute");
    }
    let parent = supplied
        .parent()
        .ok_or("external evidence input path has no parent")?
        .canonicalize()
        .map_err(|_| "canonicalize external evidence input parent")?;
    let leaf = supplied
        .file_name()
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or("external evidence input path is not a direct leaf")?
        .to_os_string();
    let canonical = parent.join(&leaf);
    if !canonical.is_absolute() {
        let _ = label;
        return Err("canonical external evidence input path is not absolute");
    }
    Ok((parent, leaf, canonical))
}

/// An advisory, descriptor-held single-run lease.  It deliberately protects
/// only this qualification's external lease file and has no authority over
/// unrelated processes or their files.
struct QualificationHostLease {
    lock: nix::fcntl::Flock<File>,
    canonical_parent: PathBuf,
    canonical_path: PathBuf,
    lease_name: OsString,
    procfd: PathBuf,
    wrapper_pid: u32,
    wrapper_fd: u32,
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    parent: File,
}

struct WrapperLeasePin {
    lease_path: PathBuf,
    canonical_parent: PathBuf,
    lease_name: OsString,
    procfd: PathBuf,
    wrapper_pid: u32,
    wrapper_fd: u32,
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
}

fn required_wrapper_lease_pin_value(name: &'static str) -> Result<String, &'static str> {
    std::env::var(name).map_err(|_| "required trusted wrapper lease pin is absent or non-UTF-8")
}

fn parse_wrapper_lease_pin_u32(name: &'static str) -> Result<u32, &'static str> {
    required_wrapper_lease_pin_value(name).and_then(|value| {
        value
            .parse()
            .map_err(|_| "trusted wrapper lease pin is invalid")
    })
}

fn parse_wrapper_lease_pin_u64(name: &'static str) -> Result<u64, &'static str> {
    required_wrapper_lease_pin_value(name).and_then(|value| {
        value
            .parse()
            .map_err(|_| "trusted wrapper lease pin is invalid")
    })
}

impl WrapperLeasePin {
    fn from_environment() -> Result<Self, &'static str> {
        if required_wrapper_lease_pin_value("OPC_QUAL_LEASE_PIN_DOMAIN")?
            != QUALIFICATION_WRAPPER_LEASE_PIN_DOMAIN
        {
            return Err("trusted wrapper lease pin domain is not exact");
        }
        let wrapper_pid = parse_wrapper_lease_pin_u32("OPC_QUAL_LEASE_PIN_WRAPPER_PID")?;
        // `nix`/`rustix` process APIs are not enabled for this production
        // crate. This is the Linux `/proc/self/stat` representation of the
        // same getppid result, parsed by the bounded helper below.
        let observed_parent = process_parent_id(std::process::id())?
            .ok_or("trusted wrapper lease direct parent disappeared")?;
        if wrapper_pid == 0 || observed_parent != wrapper_pid {
            return Err("trusted wrapper lease pin does not name this direct parent");
        }
        let wrapper_fd = parse_wrapper_lease_pin_u32("OPC_QUAL_LEASE_PIN_WRAPPER_FD")?;
        if wrapper_fd > i32::MAX as u32 {
            return Err("trusted wrapper lease pin descriptor is invalid");
        }
        let procfd = PathBuf::from(required_wrapper_lease_pin_value(
            "OPC_QUAL_LEASE_PIN_PROCFD",
        )?);
        let expected_procfd = PathBuf::from("/proc")
            .join(wrapper_pid.to_string())
            .join("fd")
            .join(wrapper_fd.to_string());
        if procfd != expected_procfd {
            return Err("trusted wrapper lease procfd path is not exact");
        }
        let lease_path = PathBuf::from(
            std::env::var_os("OPC_QUAL_LEASE")
                .ok_or("OPC_QUAL_LEASE must name an external qualification lease file")?,
        );
        let (canonical_parent, lease_name, canonical_path) =
            canonical_direct_leaf_path(&lease_path, "OPC_QUAL_LEASE")?;
        if lease_path != canonical_path {
            return Err("trusted wrapper lease path is not canonical");
        }
        let exported_parent = PathBuf::from(required_wrapper_lease_pin_value(
            "OPC_QUAL_LEASE_PIN_PARENT",
        )?);
        if exported_parent != canonical_parent {
            return Err("trusted wrapper lease parent is not its canonical parent");
        }
        let exported_name =
            OsString::from(required_wrapper_lease_pin_value("OPC_QUAL_LEASE_PIN_NAME")?);
        if exported_name != lease_name {
            return Err("trusted wrapper lease name is not its canonical direct leaf");
        }
        let mode_text = required_wrapper_lease_pin_value("OPC_QUAL_LEASE_PIN_MODE")?;
        let mode = u32::from_str_radix(&mode_text, 8)
            .map_err(|_| "trusted wrapper lease mode is invalid")?;
        if mode_text != format!("{mode:04o}") || mode != 0o600 {
            return Err("trusted wrapper lease mode is not exact private 0600");
        }
        let uid = parse_wrapper_lease_pin_u32("OPC_QUAL_LEASE_PIN_UID")?;
        if uid != nix::unistd::Uid::current().as_raw() {
            return Err("trusted wrapper lease owner is not the current user");
        }
        Ok(Self {
            lease_path: canonical_path,
            canonical_parent,
            lease_name,
            procfd,
            wrapper_pid,
            wrapper_fd,
            parent_device: parse_wrapper_lease_pin_u64("OPC_QUAL_LEASE_PIN_PARENT_DEVICE")?,
            parent_inode: parse_wrapper_lease_pin_u64("OPC_QUAL_LEASE_PIN_PARENT_INODE")?,
            device: parse_wrapper_lease_pin_u64("OPC_QUAL_LEASE_PIN_DEVICE")?,
            inode: parse_wrapper_lease_pin_u64("OPC_QUAL_LEASE_PIN_INODE")?,
            mode,
            uid,
        })
    }
}

fn validate_wrapper_lease_file(
    parent: &File,
    lease_name: &OsStr,
    lease_file: &File,
    pin: &WrapperLeasePin,
) -> Result<(), &'static str> {
    use rustix::fs::{fstat, statat, AtFlags};

    let descriptor = fstat(lease_file).map_err(|_| "fstat trusted wrapper lease procfd")?;
    let pathname = statat(parent, lease_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "stat trusted wrapper lease pathname without following links")?;
    for stat in [descriptor, pathname] {
        require_current_user_private_regular_file(stat, "trusted wrapper qualification lease")?;
        let identity = rustix_identity(stat);
        if identity.device != pin.device
            || identity.inode != pin.inode
            || rustix_private_mode(stat) != pin.mode
            || stat.st_uid != pin.uid
        {
            return Err("trusted wrapper lease descriptor or pathname identity changed");
        }
    }
    Ok(())
}

fn open_trusted_wrapper_lease_procfd(pin: &WrapperLeasePin) -> Result<File, &'static str> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pin.procfd)
        .map_err(|_| "open trusted wrapper lease procfd")?;
    let flags = rustix::io::fcntl_getfd(&file)
        .map_err(|_| "inspect trusted wrapper lease procfd close-on-exec")?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err("trusted wrapper lease procfd is not close-on-exec");
    }
    use rustix::fs::fstat;
    let stat = fstat(&file).map_err(|_| "fstat trusted wrapper lease procfd")?;
    require_current_user_private_regular_file(stat, "trusted wrapper lease procfd")?;
    let identity = rustix_identity(stat);
    if identity.device != pin.device
        || identity.inode != pin.inode
        || rustix_private_mode(stat) != pin.mode
        || stat.st_uid != pin.uid
    {
        return Err("trusted wrapper lease procfd identity changed");
    }
    Ok(file)
}

impl QualificationHostLease {
    fn revalidate(&self) -> Result<(), &'static str> {
        if self.procfd
            != PathBuf::from("/proc")
                .join(self.wrapper_pid.to_string())
                .join("fd")
                .join(self.wrapper_fd.to_string())
        {
            return Err("trusted wrapper lease procfd path changed");
        }
        let pin = WrapperLeasePin {
            lease_path: self.canonical_path.clone(),
            canonical_parent: self.canonical_parent.clone(),
            lease_name: self.lease_name.clone(),
            procfd: self.procfd.clone(),
            wrapper_pid: self.wrapper_pid,
            wrapper_fd: self.wrapper_fd,
            parent_device: self.parent_device,
            parent_inode: self.parent_inode,
            device: self.device,
            inode: self.inode,
            mode: self.mode,
            uid: self.uid,
        };
        let reopened = open_trusted_wrapper_lease_procfd(&pin)?;
        let parent = pinned_current_user_private_directory(
            &self.canonical_parent,
            self.parent_device,
            self.parent_inode,
            "trusted wrapper qualification lease parent",
        )?;
        let parent_stat = rustix::fs::fstat(&self.parent)
            .map_err(|_| "fstat retained trusted wrapper lease parent")?;
        require_current_user_private_directory(
            parent_stat,
            "trusted wrapper qualification lease parent",
        )?;
        let parent_identity = rustix_identity(parent_stat);
        if parent_identity.device != self.parent_device
            || parent_identity.inode != self.parent_inode
        {
            return Err("trusted wrapper lease parent descriptor identity changed");
        }
        validate_wrapper_lease_file(&self.parent, &self.lease_name, &self.lock, &pin)?;
        validate_wrapper_lease_file(&parent, &self.lease_name, &reopened, &pin)?;
        if self.canonical_parent.join(&self.lease_name) != self.canonical_path {
            return Err("trusted wrapper lease canonical path changed");
        }
        Ok(())
    }
}

fn read_bounded_proc_file(
    process_id: u32,
    leaf: &str,
    maximum: u64,
) -> Result<Option<Vec<u8>>, &'static str> {
    let path = PathBuf::from("/proc")
        .join(process_id.to_string())
        .join(leaf);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("open bounded Linux proc observation"),
    };
    let mut bytes = Vec::new();
    file.take(
        maximum
            .checked_add(1)
            .ok_or("Linux proc observation limit overflow")?,
    )
    .read_to_end(&mut bytes)
    .map_err(|_| "read bounded Linux proc observation")?;
    if bytes.len() > usize::try_from(maximum).map_err(|_| "Linux proc observation limit invalid")? {
        return Err("Linux proc observation exceeds bound");
    }
    Ok(Some(bytes))
}

fn process_parent_id(process_id: u32) -> Result<Option<u32>, &'static str> {
    let Some(stat) = read_bounded_proc_file(process_id, "stat", 4 * 1024)? else {
        return Ok(None);
    };
    let stat = std::str::from_utf8(&stat).map_err(|_| "Linux proc stat is not UTF-8")?;
    // `comm` is parenthesized and can contain spaces, so split only after its
    // final closing parenthesis. The following fields are state then PPID.
    let (_, tail) = stat
        .rsplit_once(") ")
        .ok_or("Linux proc stat has invalid shape")?;
    Ok(Some(
        tail.split_whitespace()
            .nth(1)
            .ok_or("Linux proc stat lacks parent identifier")?
            .parse()
            .map_err(|_| "Linux proc parent identifier invalid")?,
    ))
}

fn invoking_process_ancestry() -> Result<BTreeSet<u32>, &'static str> {
    let mut ancestry = BTreeSet::new();
    let mut current = std::process::id();
    for _ in 0..128 {
        if !ancestry.insert(current) {
            break;
        }
        let Some(parent) = process_parent_id(current)? else {
            return Err("Linux proc ancestry disappeared during qualification");
        };
        if parent == 0 || parent == current {
            break;
        }
        current = parent;
    }
    Ok(ancestry)
}

fn qualification_build_job_name(name: &str) -> bool {
    matches!(name.trim(), "cargo" | "rustc")
}

fn observed_nonancestor_qualification_build_job(
    ancestry: &BTreeSet<u32>,
) -> Result<bool, &'static str> {
    let processes =
        std::fs::read_dir("/proc").map_err(|_| "read Linux proc for qualification host")?;
    for entry in processes {
        let entry = entry.map_err(|_| "read Linux proc entry for qualification host")?;
        let name = entry.file_name();
        let Some(process_id) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        if ancestry.contains(&process_id) {
            continue;
        }
        let Some(comm) = read_bounded_proc_file(process_id, "comm", 256)? else {
            continue;
        };
        let comm = std::str::from_utf8(&comm).map_err(|_| "Linux proc comm is not UTF-8")?;
        if qualification_build_job_name(comm) {
            return Ok(true);
        }
    }
    Ok(false)
}

struct QuietHostMonitorLedger {
    started: Instant,
    last_sample: Instant,
    samples: u64,
    maximum_gap: Duration,
    start_sampled: bool,
    end_sampled: bool,
    observed_competing_build: bool,
    sampling_error: bool,
    maximum_gap_exceeded: bool,
}

impl QuietHostMonitorLedger {
    fn new(started: Instant) -> Self {
        Self {
            started,
            last_sample: started,
            samples: 0,
            maximum_gap: Duration::ZERO,
            start_sampled: false,
            end_sampled: false,
            observed_competing_build: false,
            sampling_error: false,
            maximum_gap_exceeded: false,
        }
    }

    fn record_at(
        &mut self,
        now: Instant,
        observed_competing_build: Result<bool, &'static str>,
        end: bool,
    ) {
        let gap = now
            .checked_duration_since(self.last_sample)
            .expect("quiet-host monotonic sample time");
        self.maximum_gap = self.maximum_gap.max(gap);
        if self.samples > 0 && gap > QUALIFICATION_QUIET_HOST_MAXIMUM_GAP {
            self.maximum_gap_exceeded = true;
        }
        self.last_sample = now;
        self.samples = self
            .samples
            .checked_add(1)
            .expect("quiet-host sample count fits evidence");
        self.start_sampled = true;
        self.end_sampled |= end;
        match observed_competing_build {
            Ok(observed) => self.observed_competing_build |= observed,
            Err(_) => self.sampling_error = true,
        }
    }

    fn evidence(&self, finished: Instant) -> Result<ReleaseEvidenceQuietHost, &'static str> {
        if !self.start_sampled
            || !self.end_sampled
            || self.samples < 2
            || self.observed_competing_build
            || self.sampling_error
            || self.maximum_gap_exceeded
        {
            return Err("quiet-host sampled interval did not satisfy the qualification boundary");
        }
        Ok(ReleaseEvidenceQuietHost {
            boundary: QUALIFICATION_QUIET_HOST_BOUNDARY.to_owned(),
            cadence_ms: duration_evidence_milliseconds(
                QUALIFICATION_QUIET_HOST_CADENCE,
                "quiet-host cadence",
            ),
            maximum_sample_gap_us: duration_evidence_microseconds(
                self.maximum_gap,
                "quiet-host maximum sample gap",
            ),
            monitored_elapsed_ms: duration_evidence_milliseconds(
                finished
                    .checked_duration_since(self.started)
                    .expect("quiet-host monitor lifetime is monotonic"),
                "quiet-host monitored elapsed",
            ),
            samples: self.samples,
            start_sampled: self.start_sampled,
            end_sampled: self.end_sampled,
        })
    }
}

struct QualificationQuietHostMonitor {
    stop: Arc<AtomicBool>,
    ledger: Arc<Mutex<QuietHostMonitorLedger>>,
    worker: Option<thread::JoinHandle<()>>,
    ancestry: BTreeSet<u32>,
}

impl QualificationQuietHostMonitor {
    fn start() -> Result<Self, &'static str> {
        if !cfg!(target_os = "linux") {
            return Err("release qualification quiet-host proof requires Linux proc");
        }
        let ancestry = invoking_process_ancestry()?;
        let started = Instant::now();
        let ledger = Arc::new(Mutex::new(QuietHostMonitorLedger::new(started)));
        {
            let mut ledger_guard = ledger
                .lock()
                .map_err(|_| "quiet-host monitor ledger poisoned")?;
            ledger_guard.record_at(
                started,
                observed_nonancestor_qualification_build_job(&ancestry),
                false,
            );
            if ledger_guard.observed_competing_build || ledger_guard.sampling_error {
                return Err("quiet-host preflight observed a non-ancestor Cargo or rustc job");
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_ledger = Arc::clone(&ledger);
        let worker_ancestry = ancestry.clone();
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                thread::sleep(QUALIFICATION_QUIET_HOST_CADENCE);
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                if let Ok(mut ledger) = worker_ledger.lock() {
                    ledger.record_at(
                        Instant::now(),
                        observed_nonancestor_qualification_build_job(&worker_ancestry),
                        false,
                    );
                }
            }
        });
        Ok(Self {
            stop,
            ledger,
            worker: Some(worker),
            ancestry,
        })
    }

    fn finish(mut self) -> Result<ReleaseEvidenceQuietHost, &'static str> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .expect("quiet-host monitor has worker")
            .join()
            .map_err(|_| "quiet-host monitor worker panicked")?;
        let finished = Instant::now();
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| "quiet-host monitor ledger poisoned")?;
        ledger.record_at(
            finished,
            observed_nonancestor_qualification_build_job(&self.ancestry),
            true,
        );
        ledger.evidence(finished)
    }
}

fn acquire_qualification_host_lease(
    provenance: &ReleaseEvidenceProvenance,
    target_dir: &Path,
    evidence_namespace: &Path,
    process_loss_companion: &Path,
    build_attestation: &Path,
) -> QualificationHostLease {
    let pin = WrapperLeasePin::from_environment()
        .expect("require the exact trusted wrapper procfd lease contract");
    let lease_path = &pin.lease_path;
    let repository_root = qualification_repository_root();
    assert_external_disjoint(
        lease_path,
        &repository_root,
        &provenance.canonical_gitdir,
        "OPC_QUAL_LEASE",
    );
    assert!(
        !paths_overlap(lease_path, &provenance.canonical_common_gitdir),
        "qualification lease must be outside the canonical common gitdir"
    );
    assert!(
        !paths_overlap(lease_path, target_dir)
            && !paths_overlap(lease_path, evidence_namespace)
            && !paths_overlap(lease_path, process_loss_companion)
            && !paths_overlap(lease_path, build_attestation),
        "qualification lease must be disjoint from target and evidence inputs"
    );
    acquire_qualification_host_lease_from_pin(&pin, None)
        .expect("open, lock, and revalidate the exact trusted wrapper lease procfd")
}

fn acquire_qualification_host_lease_from_pin(
    pin: &WrapperLeasePin,
    between_procfd_identity_and_lock: Option<&dyn Fn()>,
) -> Result<QualificationHostLease, &'static str> {
    // The procfd opener is deliberately normal owned-File acquisition. The
    // wrapper holds its descriptor across this child, so the exact inode is
    // first proven from the parent's trusted proc entry, then exclusively
    // flocked here without RawFd adoption or inherited-descriptor ambiguity.
    let lease_file = open_trusted_wrapper_lease_procfd(pin)?;
    if let Some(seam) = between_procfd_identity_and_lock {
        seam();
    }
    let lock = nix::fcntl::Flock::lock(lease_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| "acquire exclusive trusted wrapper qualification lease")?;
    let parent = pinned_current_user_private_directory(
        &pin.canonical_parent,
        pin.parent_device,
        pin.parent_inode,
        "trusted wrapper qualification lease parent",
    )?;
    let lease = QualificationHostLease {
        lock,
        canonical_parent: pin.canonical_parent.clone(),
        canonical_path: pin.lease_path.clone(),
        lease_name: pin.lease_name.clone(),
        procfd: pin.procfd.clone(),
        wrapper_pid: pin.wrapper_pid,
        wrapper_fd: pin.wrapper_fd,
        parent_device: pin.parent_device,
        parent_inode: pin.parent_inode,
        device: pin.device,
        inode: pin.inode,
        mode: pin.mode,
        uid: pin.uid,
        parent,
    };
    lease.revalidate()?;
    Ok(lease)
}

fn validate_private_qualification_lease_descriptor(
    parent: &File,
    lease_name: &OsStr,
    lease_file: &File,
) -> Result<EvidenceArtifactIdentity, &'static str> {
    use rustix::fs::{fstat, statat, AtFlags};

    let lease_stat =
        fstat(lease_file).map_err(|_| "fstat no-follow external qualification lease")?;
    require_current_user_private_regular_file(lease_stat, "qualification lease")?;
    let lease_identity = rustix_identity(lease_stat);
    let lease_path_stat = statat(parent, lease_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "stat no-follow external qualification lease pathname")?;
    require_current_user_private_regular_file(lease_path_stat, "qualification lease")?;
    if rustix_identity(lease_path_stat) != lease_identity {
        return Err("qualification lease pathname changed after no-follow open");
    }
    Ok(lease_identity)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionProvenance {
    source_revision: String,
    source_tree: String,
    source_tree_status: String,
    source_worktree_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionLane {
    lane: String,
    transport_revision: u16,
    application_revision: u16,
    sdk_protocol_revision: u16,
    consumer_alpn: String,
    executed: bool,
    admission_operations: u8,
    status_operations: u8,
    before_leader_loss_operations: u8,
    after_leader_loss_operations: u8,
    after_restart_operations: u8,
    after_voter_loss_operations: u8,
    tenant_authority: ProcessLossCompanionAuthority,
    scope_authority: ProcessLossCompanionAuthority,
    fence_authority: ProcessLossCompanionAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionAuthority {
    positive_observations: u8,
    negative_boundary_rejections: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionInvocation {
    test_id: String,
    argv_sha256: String,
    run_id_sha256: String,
    cargo_executable_alias: String,
    cargo_executable: String,
    cargo_executable_sha256: String,
    cargo_executable_mode: u16,
    canonical_cargo_argv: Vec<String>,
    reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionBindings {
    v9_schema_sha256: String,
    harness_sha256: String,
    child_sha256: String,
    executable_sha256: String,
    v1_canonical_sha256: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionProcessLedger {
    initial_processes: u8,
    unclean_process_losses: u8,
    restarted_processes: u8,
    observed_process_generations: u8,
    release_gate_process_generations: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionReleaseGate {
    credential_rotation_executed: bool,
    old_credential_rejected: bool,
    new_credential_rejected: bool,
    fixed_capacity_reclaimed: bool,
    durable_status_cardinality: u8,
    post_outcome_unknown_mutation_dispatches: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessLossCompanionEvidence {
    schema_version: String,
    evidence_kind: String,
    experimental: bool,
    qualification_complete: bool,
    provenance: ProcessLossCompanionProvenance,
    invocation: ProcessLossCompanionInvocation,
    bindings: ProcessLossCompanionBindings,
    process_ledger: ProcessLossCompanionProcessLedger,
    release_gate: ProcessLossCompanionReleaseGate,
    lanes: [ProcessLossCompanionLane; 2],
    members: u8,
    authenticated_setup_successes: u64,
    warm_reused_calls: u64,
    fixed_labels_only: bool,
    identifying_values_recorded: bool,
}

fn process_loss_canonical_absolute_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.as_bytes().contains(&0)
        || value.as_bytes().iter().any(u8::is_ascii_control)
        || !value.starts_with('/')
        || value.contains("//")
        || (value.len() > 1 && value.ends_with('/'))
    {
        return false;
    }
    value
        .split('/')
        .skip(1)
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn process_loss_canonical_path_at(path: &Path) -> Result<String, &'static str> {
    let canonical = path
        .canonicalize()
        .map_err(|_| "canonicalize V9 external path")?;
    let value = canonical
        .to_str()
        .ok_or("V9 external path is not UTF-8")?
        .to_owned();
    if !process_loss_canonical_absolute_path(&value) {
        return Err("V9 external path is not canonical absolute UTF-8");
    }
    Ok(value)
}

fn process_loss_path_commitment(
    domain: &[u8],
    label: &[u8],
    path: &str,
) -> Result<String, &'static str> {
    if !process_loss_canonical_absolute_path(path) {
        return Err("V9 path commitment input is not canonical");
    }
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_v1_v9_pair_part(&mut hasher, label, path.as_bytes())?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn process_loss_v9_pair_directory(root: &str) -> Result<String, &'static str> {
    if !process_loss_canonical_absolute_path(root) {
        return Err("V9 evidence root is not canonical");
    }
    Ok(format!("{root}/{PROCESS_LOSS_V9_PAIR_DIRECTORY}"))
}

fn process_loss_shell_quote(value: &str) -> String {
    // POSIX: close the quoted word, emit one literal apostrophe in a
    // double-quoted word, and reopen it: '"'"'. This never invokes a shell
    // expansion for apostrophes, semicolons, or command-substitution syntax.
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn process_loss_v9_reproduction_command(
    target: &str,
    root: &str,
    snapshot_root: &str,
    cargo_alias: &str,
) -> Result<String, &'static str> {
    if !process_loss_canonical_absolute_path(target)
        || !process_loss_canonical_absolute_path(root)
        || !process_loss_canonical_absolute_path(snapshot_root)
        || !process_loss_canonical_absolute_path(cargo_alias)
    {
        return Err("V9 reproduction command path is not canonical");
    }
    let mut command = format!(
        "CARGO={} CARGO_TARGET_DIR={} OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY={} OPC_FS_VERITY_QUALIFICATION='required' OPC_FS_VERITY_SNAPSHOT_ROOT={} {}",
        process_loss_shell_quote(cargo_alias),
        process_loss_shell_quote(target),
        process_loss_shell_quote(root),
        process_loss_shell_quote(snapshot_root),
        process_loss_shell_quote(cargo_alias),
    );
    for argument in PROCESS_LOSS_CANONICAL_CARGO_ARGV.iter().skip(1) {
        command.push(' ');
        command.push_str(&process_loss_shell_quote(argument));
    }
    Ok(command)
}

fn process_loss_reproduction_command_has_canonical_argv(command: &str) -> bool {
    let expected_tail = PROCESS_LOSS_CANONICAL_CARGO_ARGV
        .iter()
        .skip(1)
        .map(|argument| process_loss_shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    command.starts_with("CARGO='")
        && command.contains("' CARGO_TARGET_DIR='")
        && command.contains("' OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY='")
        && command
            .contains("' OPC_FS_VERITY_QUALIFICATION='required' OPC_FS_VERITY_SNAPSHOT_ROOT='")
        && command.ends_with(&format!(" {expected_tail}"))
}

/// The producer records both the replay alias (normally rustup's `cargo`
/// symlink) and its canonical backing executable.  Consumption is deliberately
/// fail-closed while that producer filesystem is still required for this
/// release qualification: a moved alias or changed backing cannot replay the
/// recorded command under a different program.
fn verify_live_process_loss_cargo_alias(
    invocation: &ProcessLossCompanionInvocation,
) -> Result<(), &'static str> {
    verify_live_process_loss_cargo_alias_with_seam(invocation, None)
}

/// Hash the recorded Cargo backing through one no-follow descriptor.  The
/// alias and backing pathnames are checked on both sides of the read so a
/// caller cannot swap either name between the producer's recorded identity
/// checks and this consumer's digest.
fn verify_live_process_loss_cargo_alias_with_seam(
    invocation: &ProcessLossCompanionInvocation,
    after_open: Option<&dyn Fn()>,
) -> Result<(), &'static str> {
    use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, CWD};

    let alias = Path::new(&invocation.cargo_executable_alias);
    let alias_metadata =
        std::fs::symlink_metadata(alias).map_err(|_| "V9 Cargo executable alias is absent")?;
    if !alias_metadata.file_type().is_file() && !alias_metadata.file_type().is_symlink() {
        return Err("V9 Cargo executable alias is neither a file nor a symlink");
    }
    let backing = alias
        .canonicalize()
        .map_err(|_| "canonicalize V9 Cargo executable alias")?;
    let backing_text = backing
        .to_str()
        .ok_or("V9 Cargo executable backing is not UTF-8")?;
    let descriptor = openat(
        CWD,
        &backing,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "open V9 Cargo executable backing without following links")?;
    let backing_stat = fstat(&descriptor).map_err(|_| "fstat V9 Cargo executable backing")?;
    let backing_identity = rustix_identity(backing_stat);
    let backing_mode = u16::try_from(u64::from(backing_stat.st_mode) & 0o7777)
        .map_err(|_| "V9 Cargo executable backing mode is out of range")?;
    if backing_text != invocation.cargo_executable
        || !FileType::from_raw_mode(backing_stat.st_mode).is_file()
        || backing_mode != invocation.cargo_executable_mode
        || backing_mode & 0o111 == 0
    {
        return Err("V9 Cargo executable alias does not resolve to its recorded regular backing");
    }
    if rustix_identity(
        statat(CWD, &backing, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "stat V9 Cargo executable backing pathname")?,
    ) != backing_identity
    {
        return Err("V9 Cargo executable backing pathname identity changed before digest");
    }
    let alias_identity = (alias_metadata.dev(), alias_metadata.ino());
    let size = backing_identity.size;
    if size > RELEASE_EXECUTABLE_MAX_BYTES {
        return Err("V9 Cargo executable backing exceeds its bounded digest limit");
    }
    let mut file = File::from(descriptor);
    if let Some(seam) = after_open {
        seam();
    }
    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let to_read = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "V9 Cargo executable digest length overflows")?;
        let read = file
            .read(&mut buffer[..to_read])
            .map_err(|_| "read V9 Cargo executable backing")?;
        if read == 0 {
            return Err("V9 Cargo executable backing changed during digest");
        }
        hasher.update(&buffer[..read]);
        remaining -= u64::try_from(read).map_err(|_| "V9 Cargo executable digest read overflow")?;
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|_| "recheck V9 Cargo executable backing")?
        != 0
    {
        return Err("V9 Cargo executable backing grew during digest");
    }
    let backing_after = fstat(&file).map_err(|_| "re-fstat V9 Cargo executable backing")?;
    if rustix_identity(backing_after) != backing_identity
        || backing_after.st_mode & 0o7777 != backing_stat.st_mode & 0o7777
    {
        return Err("V9 Cargo executable backing changed during digest");
    }
    if rustix_identity(
        statat(CWD, &backing, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "re-stat V9 Cargo executable backing pathname")?,
    ) != backing_identity
    {
        return Err("V9 Cargo executable backing pathname identity changed during digest");
    }
    let alias_after =
        std::fs::symlink_metadata(alias).map_err(|_| "re-stat V9 Cargo executable alias")?;
    if (alias_after.dev(), alias_after.ino()) != alias_identity
        || alias
            .canonicalize()
            .map_err(|_| "re-canonicalize V9 Cargo executable alias")?
            != backing
    {
        return Err("V9 Cargo executable alias changed during digest");
    }
    if format!("sha256:{:x}", hasher.finalize()) != invocation.cargo_executable_sha256 {
        return Err("V9 Cargo executable backing digest changed");
    }
    Ok(())
}

fn strict_decode_process_loss_companion(
    encoded: &[u8],
    expected_source: &ReleaseEvidenceSource,
) -> Result<ProcessLossCompanionEvidence, &'static str> {
    if encoded.len() > PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES {
        return Err("testkit process-loss companion exceeds its bounded decoder limit");
    }
    let evidence: ProcessLossCompanionEvidence =
        serde_json::from_slice(encoded).map_err(|_| "testkit process-loss companion is invalid")?;
    let instance: serde_json::Value = serde_json::from_slice(encoded)
        .map_err(|_| "testkit process-loss companion JSON invalid")?;
    let schema: serde_json::Value = serde_json::from_str(PROCESS_LOSS_EVIDENCE_SCHEMA)
        .map_err(|_| "testkit process-loss schema invalid")?;
    opc_schema_validate::validate(&schema, &instance)
        .map_err(|_| "testkit process-loss companion violates its V9 schema")?;
    let expected_lanes = [
        ("general", 6, "opc-session-consumer/1"),
        ("protected_roster", 5, "opc-session-consumer/3"),
    ];
    let expected_schema_sha256 = PROCESS_LOSS_V9_SCHEMA_SHA256;
    if evidence.schema_version != "opc-session-ha-persistent-consumer-head-evidence/v9"
        || evidence.evidence_kind != "persistent-consumer-executed-lanes"
        || !evidence.experimental
        || !evidence.qualification_complete
        || evidence.members != 3
        || evidence.authenticated_setup_successes < 48
        || evidence.warm_reused_calls < 1_000
        || !evidence.fixed_labels_only
        || evidence.identifying_values_recorded
        || evidence.provenance.source_revision != expected_source.revision
        || evidence.provenance.source_tree != expected_source.tree
        || evidence.provenance.source_tree_status != "clean"
        || evidence.provenance.source_worktree_sha256
            != format!("sha256:{}", expected_source.source_worktree_sha256)
        || evidence.invocation.test_id
            != "three_process_projected_mtls_persistent_v2_batch_release_gate"
        || !is_sha256_path_id(&evidence.invocation.argv_sha256)
        || !is_sha256_path_id(&evidence.invocation.run_id_sha256)
        || !is_sha256_path_id(&evidence.invocation.cargo_executable_sha256)
        || evidence.invocation.cargo_executable_mode == 0
        || evidence.invocation.cargo_executable_mode > 0o7777
        || evidence.invocation.cargo_executable_mode & 0o111 == 0
        || !process_loss_canonical_absolute_path(&evidence.invocation.cargo_executable_alias)
        || !process_loss_canonical_absolute_path(&evidence.invocation.cargo_executable)
        || evidence.invocation.canonical_cargo_argv
            != PROCESS_LOSS_CANONICAL_CARGO_ARGV
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect::<Vec<_>>()
        || evidence.invocation.reproduction_command.is_empty()
        || evidence.invocation.reproduction_command.chars().count()
            > PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS
        || evidence.bindings.v9_schema_sha256 != expected_schema_sha256
        || [
            &evidence.bindings.harness_sha256,
            &evidence.bindings.child_sha256,
            &evidence.bindings.executable_sha256,
            &evidence.bindings.v1_canonical_sha256,
            &evidence.bindings.cargo_target_directory_sha256,
            &evidence.bindings.evidence_root_directory_sha256,
            &evidence.bindings.fs_verity_snapshot_root_directory_sha256,
            &evidence.bindings.pair_directory_sha256,
        ]
        .into_iter()
        .any(|digest| !is_sha256_path_id(digest))
        || !process_loss_canonical_absolute_path(&evidence.bindings.cargo_target_directory)
        || !process_loss_canonical_absolute_path(&evidence.bindings.evidence_root_directory)
        || !process_loss_canonical_absolute_path(
            &evidence.bindings.fs_verity_snapshot_root_directory,
        )
        || evidence.bindings.fs_verity_snapshot_root_device == 0
        || evidence.bindings.fs_verity_snapshot_root_inode == 0
        || !process_loss_canonical_absolute_path(&evidence.bindings.pair_directory)
        || evidence.process_ledger.initial_processes != 3
        || evidence.process_ledger.unclean_process_losses != 2
        || evidence.process_ledger.restarted_processes != 1
        || evidence.process_ledger.observed_process_generations != 4
        || evidence.process_ledger.release_gate_process_generations < 4
        || !evidence.release_gate.credential_rotation_executed
        || !evidence.release_gate.old_credential_rejected
        || !evidence.release_gate.new_credential_rejected
        || !evidence.release_gate.fixed_capacity_reclaimed
        || evidence.release_gate.durable_status_cardinality != 12
        || evidence
            .release_gate
            .post_outcome_unknown_mutation_dispatches
            != 0
        || evidence
            .lanes
            .iter()
            .zip(expected_lanes)
            .any(|(lane, expected)| {
                lane.lane != expected.0
                    || lane.transport_revision != expected.1
                    || lane.application_revision != 4
                    || lane.sdk_protocol_revision != 5
                    || lane.consumer_alpn != expected.2
                    || !lane.executed
                    || lane.admission_operations == 0
                    || lane.status_operations == 0
                    || lane.before_leader_loss_operations == 0
                    || lane.after_leader_loss_operations == 0
                    || lane.after_restart_operations == 0
                    || lane.after_voter_loss_operations == 0
            })
        || evidence
            .lanes
            .iter()
            .flat_map(|lane| {
                [
                    &lane.tenant_authority,
                    &lane.scope_authority,
                    &lane.fence_authority,
                ]
            })
            .any(|authority| {
                authority.positive_observations == 0 || authority.negative_boundary_rejections == 0
            })
        || evidence.lanes[1]
            .tenant_authority
            .negative_boundary_rejections
            != 3
    {
        return Err("testkit process-loss companion violates its typed V9 contract");
    }
    if serde_json::to_vec(&evidence).map_err(|_| "canonicalize testkit companion")? != encoded {
        return Err("testkit process-loss companion is not canonical");
    }
    if evidence.bindings.cargo_target_directory_sha256
        != process_loss_path_commitment(
            b"opc-session-mtls-release-gate-cargo-target/v1\0",
            b"canonical-target-directory",
            &evidence.bindings.cargo_target_directory,
        )?
        || evidence.bindings.evidence_root_directory_sha256
            != process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-evidence-root/v1\0",
                b"canonical-evidence-root",
                &evidence.bindings.evidence_root_directory,
            )?
        || evidence.bindings.fs_verity_snapshot_root_directory_sha256
            != process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-fs-verity-snapshot-root/v1\0",
                b"canonical-fs-verity-snapshot-root",
                &evidence.bindings.fs_verity_snapshot_root_directory,
            )?
        || evidence.bindings.pair_directory
            != process_loss_v9_pair_directory(&evidence.bindings.evidence_root_directory)?
        || evidence.bindings.pair_directory_sha256
            != process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-pair-directory/v1\0",
                b"canonical-pair-directory",
                &evidence.bindings.pair_directory,
            )?
        || evidence.invocation.reproduction_command
            != process_loss_v9_reproduction_command(
                &evidence.bindings.cargo_target_directory,
                &evidence.bindings.evidence_root_directory,
                &evidence.bindings.fs_verity_snapshot_root_directory,
                &evidence.invocation.cargo_executable_alias,
            )?
    {
        return Err("testkit process-loss companion V9 namespace binding is inconsistent");
    }
    Ok(evidence)
}

fn v1_pair_binding<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, &'static str> {
    value
        .get("bindings")
        .and_then(serde_json::Value::as_object)
        .and_then(|bindings| bindings.get(key))
        .and_then(serde_json::Value::as_str)
        .ok_or("testkit V1/V9 pair binding is absent")
}

fn hash_v1_v9_pair_part(
    hasher: &mut Sha256,
    label: &[u8],
    value: &[u8],
) -> Result<(), &'static str> {
    let label_length = u64::try_from(label.len()).map_err(|_| "V1/V9 pair label overflow")?;
    let value_length = u64::try_from(value.len()).map_err(|_| "V1/V9 pair value overflow")?;
    hasher.update(label_length.to_be_bytes());
    hasher.update(label);
    hasher.update(value_length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn process_loss_command_argv_sha256(
    companion: &ProcessLossCompanionEvidence,
) -> Result<String, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-mtls-release-gate-observed-argv/v2\0");
    hash_v1_v9_pair_part(
        &mut hasher,
        b"cargo-executable",
        companion.invocation.cargo_executable.as_bytes(),
    )?;
    hash_v1_v9_pair_part(
        &mut hasher,
        b"cargo-executable-alias",
        companion.invocation.cargo_executable_alias.as_bytes(),
    )?;
    hash_v1_v9_pair_part(
        &mut hasher,
        b"cargo-executable-sha256",
        companion.invocation.cargo_executable_sha256.as_bytes(),
    )?;
    hash_v1_v9_pair_part(
        &mut hasher,
        b"cargo-executable-mode",
        &companion.invocation.cargo_executable_mode.to_be_bytes(),
    )?;
    for argument in &companion.invocation.canonical_cargo_argv {
        hash_v1_v9_pair_part(&mut hasher, b"argv", argument.as_bytes())?;
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn v1_v9_pair_run_id(
    v1: &serde_json::Value,
    v1_encoded: &[u8],
    v9: &ProcessLossCompanionEvidence,
) -> Result<String, &'static str> {
    let cargo_profile = v1
        .get("cargo_profile")
        .and_then(serde_json::Value::as_str)
        .ok_or("testkit V1/V9 cargo profile is absent")?;
    let opt_level = v1
        .get("opt_level")
        .and_then(serde_json::Value::as_str)
        .ok_or("testkit V1/V9 opt level is absent")?;
    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-ha-persistent-consumer-v9-pair-run/v4\0");
    let fs_verity_snapshot_root_device = v9.bindings.fs_verity_snapshot_root_device.to_string();
    let fs_verity_snapshot_root_inode = v9.bindings.fs_verity_snapshot_root_inode.to_string();
    for value in [
        v1_pair_binding(v1, "source_revision")?,
        v1_pair_binding(v1, "source_tree")?,
        v1_pair_binding(v1, "source_worktree_sha256")?,
        v1_pair_binding(v1, "cargo_lock_sha256")?,
        &v9.bindings.cargo_target_directory,
        &v9.bindings.cargo_target_directory_sha256,
        &v9.bindings.evidence_root_directory,
        &v9.bindings.evidence_root_directory_sha256,
        &v9.bindings.fs_verity_snapshot_root_directory,
        &v9.bindings.fs_verity_snapshot_root_directory_sha256,
        fs_verity_snapshot_root_device.as_str(),
        fs_verity_snapshot_root_inode.as_str(),
        &v9.bindings.pair_directory,
        &v9.bindings.pair_directory_sha256,
        v1_pair_binding(v1, "command_argv_sha256")?,
        &v9.invocation.cargo_executable_alias,
        &v9.invocation.cargo_executable,
        &v9.invocation.cargo_executable_sha256,
        cargo_profile,
        opt_level,
    ] {
        hash_v1_v9_pair_part(&mut hasher, b"binding", value.as_bytes())?;
    }
    hash_v1_v9_pair_part(
        &mut hasher,
        b"cargo-executable-mode",
        &v9.invocation.cargo_executable_mode.to_be_bytes(),
    )?;
    for value in [
        v1_pair_binding(v1, "evidence_schema_sha256")?,
        v1_pair_binding(v1, "configuration_sha256")?,
        v1_pair_binding(v1, "public_material_manifest_sha256")?,
        v1_pair_binding(v1, "workload_schedule_sha256")?,
        v1_pair_binding(v1, "child_sha256")?,
        v1_pair_binding(v1, "harness_sha256")?,
        &v9.bindings.v9_schema_sha256,
        "three_process_projected_mtls_persistent_v2_batch_release_gate",
        &v9.invocation.argv_sha256,
    ] {
        hash_v1_v9_pair_part(&mut hasher, b"binding", value.as_bytes())?;
    }
    for argument in &v9.invocation.canonical_cargo_argv {
        hash_v1_v9_pair_part(&mut hasher, b"canonical-cargo-argv", argument.as_bytes())?;
    }
    hash_v1_v9_pair_part(
        &mut hasher,
        b"reproduction-command",
        v9.invocation.reproduction_command.as_bytes(),
    )?;
    hash_v1_v9_pair_part(&mut hasher, b"v1-canonical", v1_encoded)?;
    hash_v1_v9_pair_part(
        &mut hasher,
        b"v9-claims-preimage",
        &process_loss_v9_claims_preimage(v9)?,
    )?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

const PROCESS_LOSS_V9_RUN_ID_PREIMAGE_PLACEHOLDER: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn process_loss_v9_claims_preimage(
    v9: &ProcessLossCompanionEvidence,
) -> Result<Vec<u8>, &'static str> {
    let mut preimage = v9.clone();
    preimage.invocation.run_id_sha256 = PROCESS_LOSS_V9_RUN_ID_PREIMAGE_PLACEHOLDER.to_owned();
    serde_json::to_vec(&preimage).map_err(|_| "V9 run identity claims preimage is invalid")
}

/// V1 is consumed through its frozen closed schema without importing the
/// testkit's public typed decoder: `opc-session-testkit` already depends on
/// this store crate, so a store-test dependency would reverse that direction.
/// This decoder therefore preserves the producer's material property locally:
/// one EOF-terminated JSON value, closed-schema validation, and exact compact
/// canonical bytes before any digest or run identity is computed.
fn strict_decode_canonical_json_value(
    encoded: &[u8],
    maximum: usize,
    label: &'static str,
) -> Result<serde_json::Value, &'static str> {
    if encoded.len() > maximum {
        return Err("canonical JSON input exceeds bounded decoder limit");
    }
    let mut decoder = serde_json::Deserializer::from_slice(encoded);
    let value = serde_json::Value::deserialize(&mut decoder)
        .map_err(|_| "canonical JSON input is invalid")?;
    decoder
        .end()
        .map_err(|_| "canonical JSON input has trailing JSON")?;
    if serde_json::to_vec(&value).map_err(|_| "canonical JSON input cannot canonicalize")?
        != encoded
    {
        let _ = label;
        return Err("canonical JSON input is not canonical");
    }
    Ok(value)
}

fn strict_decode_process_loss_v1(encoded: &[u8]) -> Result<serde_json::Value, &'static str> {
    let value = strict_decode_canonical_json_value(
        encoded,
        PROCESS_LOSS_V1_EVIDENCE_MAX_BYTES,
        "testkit V1 process-loss companion",
    )?;
    let v1_schema: serde_json::Value = serde_json::from_str(PROCESS_LOSS_V1_EVIDENCE_SCHEMA)
        .map_err(|_| "testkit V1 process-loss schema is invalid")?;
    opc_schema_validate::validate(&v1_schema, &value)
        .map_err(|_| "testkit V1 process-loss companion violates its schema")?;
    Ok(value)
}

/// Validate the producer target as a real, canonical namespace of its own.
/// The store wrapper's target is deliberately a separate build namespace: it
/// must never stand in for the target recorded by the testkit producer.
fn strict_process_loss_pair_target_topology(
    v9: &ProcessLossCompanionEvidence,
    expected: &ReleaseEvidenceProvenance,
    wrapper_target_directory: &Path,
    pair_directory: &Path,
    evidence_root_directory: &Path,
) -> Result<(String, String), &'static str> {
    let wrapper_target_directory = process_loss_canonical_path_at(wrapper_target_directory)?;
    let producer_target_directory =
        process_loss_canonical_path_at(Path::new(&v9.bindings.cargo_target_directory))?;
    if producer_target_directory != v9.bindings.cargo_target_directory
        || v9.bindings.cargo_target_directory_sha256
            != process_loss_path_commitment(
                b"opc-session-mtls-release-gate-cargo-target/v1\0",
                b"canonical-target-directory",
                &producer_target_directory,
            )?
    {
        return Err("V9 producer Cargo target is not its recorded canonical commitment");
    }
    if paths_overlap(
        Path::new(&producer_target_directory),
        Path::new(&wrapper_target_directory),
    ) {
        return Err("V9 producer Cargo target overlaps the wrapper Cargo target");
    }
    let producer_snapshot_root_directory =
        process_loss_canonical_path_at(Path::new(&v9.bindings.fs_verity_snapshot_root_directory))?;
    let producer_snapshot_root_metadata = std::fs::metadata(&producer_snapshot_root_directory)
        .map_err(|_| "stat V9 producer fs-verity snapshot root")?;
    if producer_snapshot_root_directory != v9.bindings.fs_verity_snapshot_root_directory
        || producer_snapshot_root_metadata.uid() != nix::unistd::Uid::current().as_raw()
        || producer_snapshot_root_metadata.mode() & 0o7777 != 0o700
        || producer_snapshot_root_metadata.dev() != v9.bindings.fs_verity_snapshot_root_device
        || producer_snapshot_root_metadata.ino() != v9.bindings.fs_verity_snapshot_root_inode
    {
        return Err("V9 producer fs-verity snapshot root is not its recorded private identity");
    }
    if [
        Path::new(&wrapper_target_directory),
        Path::new(&producer_target_directory),
        evidence_root_directory,
        pair_directory,
    ]
    .into_iter()
    .any(|path| paths_overlap(path, Path::new(&producer_snapshot_root_directory)))
    {
        return Err("V9 producer fs-verity snapshot root overlaps an unrelated namespace");
    }

    let pair_metadata =
        std::fs::metadata(pair_directory).map_err(|_| "stat V9 process-loss pair directory")?;
    if !pair_metadata.is_dir()
        || pair_metadata.uid() != nix::unistd::Uid::current().as_raw()
        || pair_metadata.mode() & 0o777 != 0o700
    {
        return Err("V9 process-loss pair directory is not current-user private mode 0700");
    }

    let repository_root = qualification_repository_root();
    for path in [
        Path::new(&wrapper_target_directory),
        Path::new(&producer_target_directory),
        Path::new(&producer_snapshot_root_directory),
        pair_directory,
        evidence_root_directory,
    ] {
        if !path.is_absolute()
            || paths_overlap(path, &repository_root)
            || paths_overlap(path, &expected.canonical_gitdir)
            || paths_overlap(path, &expected.canonical_common_gitdir)
        {
            return Err("V9 process-loss pair path overlaps a protected Git boundary");
        }
    }
    Ok((wrapper_target_directory, producer_target_directory))
}

/// The V9 producer's strict validator computes its run ID from these exact
/// canonical V1 bytes; this binds the pair, not just V9's JSON shape.
fn strict_decode_process_loss_pair(
    v1_encoded: &[u8],
    v9_encoded: &[u8],
    expected: &ReleaseEvidenceProvenance,
    actual_target_directory: &Path,
    actual_pair_directory: &Path,
) -> Result<ProcessLossCompanionEvidence, &'static str> {
    let v1 = strict_decode_process_loss_v1(v1_encoded)?;
    let v1_release_gate_process_generations = u8::try_from(
        v1.get("resource_generations")
            .and_then(serde_json::Value::as_array)
            .ok_or("testkit V1 resource generations are absent")?
            .len(),
    )
    .map_err(|_| "testkit V1 resource generations exceed the V9 count range")?;
    let expected_source = &expected.source;
    let v9 = strict_decode_process_loss_companion(v9_encoded, expected_source)?;
    verify_live_process_loss_cargo_alias(&v9.invocation)?;
    let pair_directory = process_loss_canonical_path_at(actual_pair_directory)?;
    let evidence_root_directory = process_loss_canonical_path_at(
        actual_pair_directory
            .parent()
            .ok_or("V9 pair directory has no evidence root")?,
    )?;
    let (_, producer_target_directory) = strict_process_loss_pair_target_topology(
        &v9,
        expected,
        actual_target_directory,
        Path::new(&pair_directory),
        Path::new(&evidence_root_directory),
    )?;
    if process_loss_v9_pair_directory(&evidence_root_directory)? != pair_directory
        || v9.bindings.evidence_root_directory != evidence_root_directory
        || v9.bindings.evidence_root_directory_sha256
            != process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-evidence-root/v1\0",
                b"canonical-evidence-root",
                &evidence_root_directory,
            )?
        || v9.bindings.pair_directory != pair_directory
        || v9.bindings.pair_directory_sha256
            != process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-pair-directory/v1\0",
                b"canonical-pair-directory",
                &pair_directory,
            )?
        || v9.invocation.reproduction_command
            != process_loss_v9_reproduction_command(
                &producer_target_directory,
                &evidence_root_directory,
                &v9.bindings.fs_verity_snapshot_root_directory,
                &v9.invocation.cargo_executable_alias,
            )?
        || v9.bindings.v1_canonical_sha256 != format!("sha256:{:x}", Sha256::digest(v1_encoded))
        || v1_pair_binding(&v1, "source_revision")? != expected_source.revision
        || v1_pair_binding(&v1, "source_tree")? != expected_source.tree
        || v1_pair_binding(&v1, "source_worktree_sha256")?
            != format!("sha256:{}", expected_source.source_worktree_sha256)
        || v1_pair_binding(&v1, "cargo_lock_sha256")?
            != format!("sha256:{}", expected.runtime_cargo_lock_sha256)
        || v1_pair_binding(&v1, "command_argv_sha256")? != process_loss_command_argv_sha256(&v9)?
        || v1_pair_binding(&v1, "child_sha256")? != v9.bindings.child_sha256
        || v1_pair_binding(&v1, "harness_sha256")? != v9.bindings.harness_sha256
        || v9.bindings.executable_sha256 != v9.bindings.harness_sha256
        || v9.process_ledger.release_gate_process_generations != v1_release_gate_process_generations
        || v9.invocation.run_id_sha256 != v1_v9_pair_run_id(&v1, v1_encoded, &v9)?
    {
        return Err("testkit V1/V9 process-loss pair provenance is inconsistent");
    }
    Ok(v9)
}

struct PinnedProcessLossCompanion {
    evidence: ReleaseEvidenceProcessLoss,
    companion: ProcessLossCompanionEvidence,
    producer_target_directory: PathBuf,
    producer_evidence_root_directory: PathBuf,
    canonical_parent: PathBuf,
    canonical_path: PathBuf,
    parent: File,
    leaf: OsString,
    v1_leaf: OsString,
    parent_device: u64,
    parent_inode: u64,
    identity: EvidenceArtifactIdentity,
    v1_identity: EvidenceArtifactIdentity,
    sha256: String,
    v1_sha256: String,
}

fn required_wrapper_process_loss_identity(
    prefix: &str,
    maximum: usize,
) -> Result<(String, EvidenceArtifactIdentity), &'static str> {
    let variable = |suffix: &str| format!("OPC_QUAL_PROCESS_LOSS_{}_{}", prefix, suffix);
    let digest = std::env::var(variable("SHA256"))
        .map_err(|_| "trusted wrapper must provide process-loss descriptor digest")?;
    let device = std::env::var(variable("DEVICE"))
        .map_err(|_| "trusted wrapper must provide process-loss descriptor device")?
        .parse::<u64>()
        .map_err(|_| "trusted wrapper process-loss device is invalid")?;
    let inode = std::env::var(variable("INODE"))
        .map_err(|_| "trusted wrapper must provide process-loss descriptor inode")?
        .parse::<u64>()
        .map_err(|_| "trusted wrapper process-loss inode is invalid")?;
    let size = std::env::var(variable("SIZE"))
        .map_err(|_| "trusted wrapper must provide process-loss descriptor size")?
        .parse::<u64>()
        .map_err(|_| "trusted wrapper process-loss size is invalid")?;
    if !is_lower_hex_exact(&digest, 64) || device == 0 || inode == 0 || size > maximum as u64 {
        return Err("trusted wrapper process-loss descriptor identity is invalid");
    }
    Ok((
        digest,
        EvidenceArtifactIdentity {
            device,
            inode,
            size,
        },
    ))
}

fn release_process_loss_binding(
    path: &Path,
    bytes: &[u8],
    companion: &ProcessLossCompanionEvidence,
) -> ReleaseEvidenceProcessLoss {
    ReleaseEvidenceProcessLoss {
        // The V9 companion is only accepted after the exact separately-run
        // multiprocess command below. Its scope is external: the store lane
        // continues to say only graceful same-process reopen.
        scope: "external_session_testkit_multiprocess_mtls_only".to_owned(),
        companion_path_id: redacted_path_id(path),
        companion_sha256: format!("{:x}", Sha256::digest(bytes)),
        companion_schema_sha256: companion.bindings.v9_schema_sha256.clone(),
        companion_source_revision: companion.provenance.source_revision.clone(),
        companion_source_tree: companion.provenance.source_tree.clone(),
        companion_source_worktree_sha256: companion.provenance.source_worktree_sha256.clone(),
        companion_v1_canonical_sha256: companion.bindings.v1_canonical_sha256.clone(),
        companion_invocation_argv_sha256: companion.invocation.argv_sha256.clone(),
        companion_harness_sha256: companion.bindings.harness_sha256.clone(),
        companion_child_sha256: companion.bindings.child_sha256.clone(),
        companion_executable_sha256: companion.bindings.executable_sha256.clone(),
        strict_validation_command: companion.invocation.reproduction_command.clone(),
    }
}

fn require_exact_process_loss_pair_leaves(parent: &File) -> Result<(), &'static str> {
    use rustix::fs::Dir;

    let mut v1 = false;
    let mut v9 = false;
    let mut entries = 0_u8;
    for entry in Dir::read_from(parent).map_err(|_| "read process-loss pair namespace")? {
        let entry = entry.map_err(|_| "read process-loss pair namespace entry")?;
        let name = entry.file_name();
        #[cfg(unix)]
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        entries = entries
            .checked_add(1)
            .ok_or("process-loss pair namespace entry count overflow")?;
        match name.to_bytes() {
            value if value == PROCESS_LOSS_V1_LEAF.as_bytes() && !v1 => v1 = true,
            value if value == PROCESS_LOSS_V9_LEAF.as_bytes() && !v9 => v9 = true,
            _ => return Err("process-loss pair namespace has unaccepted residue"),
        }
    }
    if entries != 2 || !v1 || !v9 {
        return Err("process-loss pair namespace is not exactly the V1/V9 pair");
    }
    Ok(())
}

fn required_process_loss_companion(
    provenance: &ReleaseEvidenceProvenance,
    target_dir: &Path,
    evidence_namespace: &Path,
) -> PinnedProcessLossCompanion {
    let supplied_path = PathBuf::from(
        std::env::var_os("OPC_QUAL_PROCESS_LOSS_EVIDENCE")
            .expect("OPC_QUAL_PROCESS_LOSS_EVIDENCE must name a testkit V9 companion"),
    );
    let (canonical_parent, leaf, path) =
        canonical_direct_leaf_path(&supplied_path, "OPC_QUAL_PROCESS_LOSS_EVIDENCE")
            .expect("canonical direct process-loss companion path");
    assert_eq!(
        leaf,
        OsStr::new(PROCESS_LOSS_V9_LEAF),
        "process-loss input must be the fixed V9 leaf of its published pair"
    );
    assert_external_disjoint(
        &path,
        &qualification_repository_root(),
        &provenance.canonical_gitdir,
        "OPC_QUAL_PROCESS_LOSS_EVIDENCE",
    );
    assert!(
        !paths_overlap(&path, &provenance.canonical_common_gitdir),
        "process-loss companion must be outside the canonical common gitdir"
    );
    assert!(
        !paths_overlap(&path, target_dir) && !paths_overlap(&path, evidence_namespace),
        "process-loss companion must be disjoint from target and store-evidence namespaces"
    );
    let parent_metadata =
        std::fs::metadata(&canonical_parent).expect("stat canonical process-loss companion parent");
    let parent = pinned_current_user_private_directory(
        &canonical_parent,
        parent_metadata.dev(),
        parent_metadata.ino(),
        "process-loss companion parent",
    )
    .expect("open descriptor-pinned process-loss companion parent");
    require_exact_process_loss_pair_leaves(&parent)
        .expect("process-loss namespace contains exactly the strict V1/V9 pair");
    let (bytes, identity) = read_bounded_current_user_private_regular_file_with_identity(
        &parent,
        &leaf,
        PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES,
        "process-loss companion",
    )
    .expect("read bounded no-follow process-loss companion");
    let v1_leaf = OsString::from(PROCESS_LOSS_V1_LEAF);
    let (v1_bytes, v1_identity) = read_bounded_current_user_private_regular_file_with_identity(
        &parent,
        &v1_leaf,
        PROCESS_LOSS_V1_EVIDENCE_MAX_BYTES,
        "process-loss V1 pair companion",
    )
    .expect("read bounded no-follow process-loss V1 pair companion");
    let (wrapper_sha256, wrapper_identity) =
        required_wrapper_process_loss_identity("EVIDENCE", PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES)
            .expect("trusted wrapper process-loss descriptor identity");
    let (wrapper_v1_sha256, wrapper_v1_identity) =
        required_wrapper_process_loss_identity("V1", PROCESS_LOSS_V1_EVIDENCE_MAX_BYTES)
            .expect("trusted wrapper process-loss V1 descriptor identity");
    assert_eq!(
        identity, wrapper_identity,
        "process-loss leaf changed after wrapper pinning"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        wrapper_sha256,
        "process-loss bytes changed after wrapper pinning"
    );
    assert_eq!(
        v1_identity, wrapper_v1_identity,
        "process-loss V1 leaf changed after wrapper pinning"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&v1_bytes)),
        wrapper_v1_sha256,
        "process-loss V1 bytes changed after wrapper pinning"
    );
    let companion = strict_decode_process_loss_pair(
        &v1_bytes,
        &bytes,
        provenance,
        target_dir,
        &canonical_parent,
    )
    .expect("strictly validate separately executed testkit process-loss companion");
    let producer_target_directory = PathBuf::from(&companion.bindings.cargo_target_directory);
    let producer_evidence_root_directory = canonical_parent
        .parent()
        .expect("process-loss pair must have an evidence root")
        .canonicalize()
        .expect("canonicalize process-loss evidence root");
    let bound = release_process_loss_binding(&path, &bytes, &companion);
    PinnedProcessLossCompanion {
        evidence: bound,
        companion,
        producer_target_directory,
        producer_evidence_root_directory,
        canonical_parent,
        canonical_path: path,
        parent,
        leaf,
        v1_leaf,
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        identity,
        v1_identity,
        sha256: wrapper_sha256,
        v1_sha256: wrapper_v1_sha256,
    }
}

/// Bind the wrapper-created snapshot child back to the one stable fs-verity
/// base captured by the independently validated V9 producer. The child has a
/// distinct inode; its direct parent is the intentionally shared authority.
fn validate_shared_fs_verity_snapshot_base(
    execution: &ReleaseEvidenceExecution,
    process_loss: &PinnedProcessLossCompanion,
) -> Result<(), &'static str> {
    let snapshot_child = release_fs_verity_snapshot_root_from_environment(
        std::env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref(),
        std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV).as_deref(),
        &execution.fs_verity_snapshot_root_id,
        execution.fs_verity_snapshot_root_device,
        execution.fs_verity_snapshot_root_inode,
    )?;
    validate_shared_fs_verity_snapshot_base_for_child(
        &snapshot_child,
        execution,
        &process_loss.companion.bindings,
    )
}

fn validate_shared_fs_verity_snapshot_base_for_child(
    snapshot_child: &Path,
    execution: &ReleaseEvidenceExecution,
    bindings: &ProcessLossCompanionBindings,
) -> Result<(), &'static str> {
    let snapshot_base = snapshot_child
        .parent()
        .ok_or("wrapper fs-verity snapshot child has no stable base")?
        .canonicalize()
        .map_err(|_| "wrapper fs-verity snapshot base is not canonical")?;
    let base_metadata = std::fs::symlink_metadata(&snapshot_base)
        .map_err(|_| "stat wrapper fs-verity snapshot base")?;
    let snapshot_base_text = snapshot_base
        .to_str()
        .ok_or("wrapper fs-verity snapshot base is not UTF-8")?;
    let snapshot_base_commitment = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-fs-verity-snapshot-root/v1\0",
        b"canonical-fs-verity-snapshot-root",
        snapshot_base_text,
    )?;
    if snapshot_base == snapshot_child
        || base_metadata.file_type().is_symlink()
        || !base_metadata.is_dir()
        || base_metadata.uid() != nix::unistd::Uid::current().as_raw()
        || base_metadata.mode() & 0o7777 != 0o700
        || redacted_path_id(&snapshot_base) != execution.fs_verity_snapshot_base_id
        || snapshot_base_text != bindings.fs_verity_snapshot_root_directory
        || snapshot_base_commitment != bindings.fs_verity_snapshot_root_directory_sha256
        || base_metadata.dev() != bindings.fs_verity_snapshot_root_device
        || base_metadata.ino() != bindings.fs_verity_snapshot_root_inode
    {
        return Err("wrapper fs-verity snapshot base does not bind the V9 shared root");
    }
    Ok(())
}

/// The testkit producer publishes one intentionally nested root/pair/leaves
/// hierarchy. Check that root against every actual *unrelated* wrapper
/// namespace without comparing it to its own pair/leaves. Canonical parents
/// are authority boundaries checked against the protected roots, but they are
/// not occupied wrapper namespaces: disjoint leaves may share one external
/// parent with the producer.
fn validate_process_loss_root_external_topology_before_mkdir(
    producer_root: &Path,
    unrelated_namespaces: &[(&Path, &str)],
    unrelated_parents: &[(&Path, &str)],
    repository_root: &Path,
    gitdir: &Path,
    common_gitdir: &Path,
) -> Result<(), &'static str> {
    if !producer_root.is_absolute() {
        return Err("V9 producer evidence root is not absolute");
    }
    for protected in [repository_root, gitdir, common_gitdir] {
        if paths_overlap(producer_root, protected) {
            return Err("V9 producer evidence root overlaps a protected Git boundary");
        }
    }
    for (path, label) in unrelated_namespaces.iter().chain(unrelated_parents) {
        if !path.is_absolute() {
            let _ = label;
            return Err("V9 producer evidence external path is not absolute");
        }
        for protected in [repository_root, gitdir, common_gitdir] {
            if paths_overlap(path, protected) {
                let _ = label;
                return Err("V9 producer evidence external path overlaps a protected Git boundary");
            }
        }
    }
    for (path, label) in unrelated_namespaces {
        if paths_overlap(producer_root, path) {
            let _ = label;
            return Err("V9 producer evidence root overlaps an unrelated external namespace");
        }
    }
    Ok(())
}

fn revalidate_pinned_process_loss_companion(
    pinned: &PinnedProcessLossCompanion,
    provenance: &ReleaseEvidenceProvenance,
) -> Result<ReleaseEvidenceProcessLoss, &'static str> {
    use rustix::fs::fstat;

    let descriptor_stat = fstat(&pinned.parent).map_err(|_| "fstat process-loss parent")?;
    require_current_user_private_directory(descriptor_stat, "process-loss companion parent")?;
    let descriptor_identity = rustix_identity(descriptor_stat);
    if descriptor_identity.device != pinned.parent_device
        || descriptor_identity.inode != pinned.parent_inode
    {
        return Err("pinned process-loss parent descriptor identity changed");
    }
    let rebound = pinned_current_user_private_directory(
        &pinned.canonical_parent,
        pinned.parent_device,
        pinned.parent_inode,
        "process-loss companion parent",
    )?;
    drop(rebound);
    require_exact_process_loss_pair_leaves(&pinned.parent)?;
    let (bytes, identity) = read_bounded_current_user_private_regular_file_with_identity(
        &pinned.parent,
        &pinned.leaf,
        PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES,
        "process-loss companion revalidation",
    )?;
    let (v1_bytes, v1_identity) = read_bounded_current_user_private_regular_file_with_identity(
        &pinned.parent,
        &pinned.v1_leaf,
        PROCESS_LOSS_V1_EVIDENCE_MAX_BYTES,
        "process-loss V1 pair revalidation",
    )?;
    if identity != pinned.identity || format!("{:x}", Sha256::digest(&bytes)) != pinned.sha256 {
        return Err("process-loss companion leaf changed before publication");
    }
    if v1_identity != pinned.v1_identity
        || format!("{:x}", Sha256::digest(&v1_bytes)) != pinned.v1_sha256
    {
        return Err("process-loss V1 companion leaf changed before publication");
    }
    let target_dir = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .ok_or("CARGO_TARGET_DIR is absent during process-loss revalidation")?,
    );
    let companion = strict_decode_process_loss_pair(
        &v1_bytes,
        &bytes,
        provenance,
        &target_dir,
        &pinned.canonical_parent,
    )?;
    let bound = release_process_loss_binding(&pinned.canonical_path, &bytes, &companion);
    if bound != pinned.evidence {
        return Err("process-loss companion provenance changed before publication");
    }
    Ok(bound)
}

fn required_release_evidence_artifact(
    provenance: &ReleaseEvidenceProvenance,
    observed_libtest_argv: &[String],
) -> (
    PinnedReleaseEvidenceArtifact,
    ReleaseEvidenceExecution,
    PinnedProcessLossCompanion,
    QualificationHostLease,
) {
    use rustix::fs::{fstat, mkdirat, openat, Mode, OFlags};

    let repository_root = qualification_repository_root();
    let namespace_path = PathBuf::from(
        std::env::var_os("OPC_QUAL_EVIDENCE")
            .expect("OPC_QUAL_EVIDENCE must name an absent external evidence namespace"),
    );
    let (canonical_parent, namespace, canonical_namespace) =
        canonical_direct_leaf_path(&namespace_path, "OPC_QUAL_EVIDENCE")
            .expect("canonical direct external evidence namespace path");
    let target_dir = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .expect("CARGO_TARGET_DIR must bind the release evidence executable"),
    )
    .canonicalize()
    .expect("canonical CARGO_TARGET_DIR for disjointness");
    let process_loss_path = canonical_direct_leaf_path(
        &PathBuf::from(
            std::env::var_os("OPC_QUAL_PROCESS_LOSS_EVIDENCE")
                .expect("OPC_QUAL_PROCESS_LOSS_EVIDENCE must name a testkit V9 companion"),
        ),
        "OPC_QUAL_PROCESS_LOSS_EVIDENCE",
    )
    .expect("canonical direct process-loss companion path before evidence namespace creation")
    .2;
    let build_attestation_path = canonical_direct_leaf_path(
        &PathBuf::from(
            std::env::var_os("OPC_QUAL_BUILD_ATTESTATION")
                .expect("OPC_QUAL_BUILD_ATTESTATION must name trusted wrapper output"),
        ),
        "OPC_QUAL_BUILD_ATTESTATION",
    )
    .expect("canonical direct build attestation path before evidence namespace creation")
    .2;
    let lease_path = canonical_direct_leaf_path(
        &PathBuf::from(
            std::env::var_os("OPC_QUAL_LEASE")
                .expect("OPC_QUAL_LEASE must name an external qualification lease file"),
        ),
        "OPC_QUAL_LEASE",
    )
    .expect("canonical direct qualification lease path before evidence namespace creation")
    .2;
    // Read and descriptor-pin the complete producer pair before creating any
    // store evidence directory. This exposes the producer target for the
    // final topology check while preserving a no-residue rejection path.
    let process_loss =
        required_process_loss_companion(provenance, &target_dir, &canonical_namespace);
    validate_process_loss_root_external_topology_before_mkdir(
        &process_loss.producer_evidence_root_directory,
        &[
            (&target_dir, "CARGO_TARGET_DIR"),
            (&canonical_namespace, "OPC_QUAL_EVIDENCE"),
            (&build_attestation_path, "OPC_QUAL_BUILD_ATTESTATION"),
            (&lease_path, "OPC_QUAL_LEASE"),
        ],
        &[
            (
                target_dir.parent().expect("CARGO_TARGET_DIR has a parent"),
                "CARGO_TARGET_DIR parent",
            ),
            (&canonical_parent, "OPC_QUAL_EVIDENCE parent"),
            (
                build_attestation_path
                    .parent()
                    .expect("build attestation has a parent"),
                "OPC_QUAL_BUILD_ATTESTATION parent",
            ),
            (
                lease_path.parent().expect("lease has a parent"),
                "OPC_QUAL_LEASE parent",
            ),
        ],
        &repository_root,
        &provenance.canonical_gitdir,
        &provenance.canonical_common_gitdir,
    )
    .expect("V9 producer root must be disjoint before lease acquisition or mkdir");
    validate_release_evidence_external_topology_before_mkdir(
        &[
            (&canonical_namespace, "OPC_QUAL_EVIDENCE"),
            (&target_dir, "CARGO_TARGET_DIR"),
            (
                &process_loss.producer_target_directory,
                "V9_PRODUCER_CARGO_TARGET_DIR",
            ),
            (&process_loss_path, "OPC_QUAL_PROCESS_LOSS_EVIDENCE"),
            (&build_attestation_path, "OPC_QUAL_BUILD_ATTESTATION"),
            (&lease_path, "OPC_QUAL_LEASE"),
        ],
        &repository_root,
        &provenance.canonical_gitdir,
        &provenance.canonical_common_gitdir,
    )
    .expect("all external release evidence paths must validate before namespace creation");
    let (execution, bound_build_attestation_path) = release_evidence_execution_identity(
        provenance,
        &canonical_namespace,
        observed_libtest_argv,
    )
    .expect(
        "bind trusted release build attestation to pinned executable before namespace creation",
    );
    validate_shared_fs_verity_snapshot_base(&execution, &process_loss).expect(
        "wrapper snapshot child must bind the V9 shared fs-verity base before namespace creation",
    );
    assert!(
        !paths_overlap(&bound_build_attestation_path, &process_loss.canonical_path),
        "release build attestation and process-loss companion must be distinct external leaves"
    );
    let qualification_host_lease = acquire_qualification_host_lease(
        provenance,
        &target_dir,
        &canonical_namespace,
        &process_loss_path,
        &build_attestation_path,
    );
    assert!(
        std::fs::symlink_metadata(&namespace_path).is_err(),
        "OPC_QUAL_EVIDENCE must be an absent exclusively-created namespace"
    );
    let parent_stat = nix::sys::stat::stat(&canonical_parent)
        .expect("stat canonical external evidence parent before descriptor open");
    let external_parent = pinned_parent_file(
        &canonical_parent,
        parent_stat.st_dev as u64,
        parent_stat.st_ino as u64,
    )
    .expect("open descriptor-pinned external evidence parent");
    qualification_host_lease
        .revalidate()
        .expect("trusted wrapper lease must remain pinned immediately before namespace creation");
    // The exclusively-created mode-0700 namespace is the publication
    // boundary. All later temp/final names are descriptor-relative below it;
    // we never repair a raced pathname with stat-then-unlink authority.
    mkdirat(
        &external_parent,
        namespace.as_os_str(),
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .expect("create private no-replace external evidence namespace");
    external_parent
        .sync_all()
        .expect("fsync external evidence parent after private namespace creation");
    let namespace_parent = File::from(
        openat(
            &external_parent,
            namespace.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open private no-follow evidence namespace"),
    );
    let namespace_identity =
        rustix_identity(fstat(&namespace_parent).expect("fstat private evidence namespace"));
    let artifact = PinnedReleaseEvidenceArtifact {
        evidence: ReleaseEvidenceArtifact {
            mechanism: "rustix_private_namespace_dirfd_noreplace_fsync".to_owned(),
            path_id: redacted_path_id(&canonical_namespace.join(RELEASE_EVIDENCE_NAMESPACE_LEAF)),
            cooperative_same_uid_boundary: "private_mode_0700_namespace_no_shared_path_authority"
                .to_owned(),
        },
        canonical_external_parent: canonical_parent,
        canonical_namespace,
        external_parent,
        namespace,
        namespace_parent,
        leaf: OsString::from(RELEASE_EVIDENCE_NAMESPACE_LEAF),
        external_parent_device: parent_stat.st_dev as u64,
        external_parent_inode: parent_stat.st_ino as u64,
        namespace_device: namespace_identity.device,
        namespace_inode: namespace_identity.inode,
    };
    (artifact, execution, process_loss, qualification_host_lease)
}

fn verify_pinned_release_evidence_parent(
    artifact: &PinnedReleaseEvidenceArtifact,
) -> Result<(), &'static str> {
    use rustix::fs::fstat;

    let external = rustix_identity(
        fstat(&artifact.external_parent).map_err(|_| "fstat external evidence parent")?,
    );
    if external.device != artifact.external_parent_device
        || external.inode != artifact.external_parent_inode
    {
        return Err("pinned external evidence parent descriptor identity changed");
    }
    let rebound_external = pinned_parent_file(
        &artifact.canonical_external_parent,
        artifact.external_parent_device,
        artifact.external_parent_inode,
    )?;
    drop(rebound_external);
    let namespace = rustix_identity(
        fstat(&artifact.namespace_parent).map_err(|_| "fstat private evidence namespace")?,
    );
    if namespace.device != artifact.namespace_device || namespace.inode != artifact.namespace_inode
    {
        return Err("pinned private evidence namespace descriptor identity changed");
    }
    if artifact.evidence.path_id
        != redacted_path_id(&artifact.canonical_namespace.join(&artifact.leaf))
    {
        return Err("release evidence path identifier is not its canonical namespace leaf");
    }
    use rustix::fs::{openat, Mode, OFlags};
    let rebound_namespace = File::from(
        openat(
            &artifact.external_parent,
            artifact.namespace.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "open private evidence namespace from external parent")?,
    );
    if rustix_identity(fstat(&rebound_namespace).map_err(|_| "fstat rebound evidence namespace")?)
        != namespace
    {
        return Err("private evidence namespace pathname identity changed");
    }
    Ok(())
}

#[derive(Default)]
struct ReleaseEvidenceWriterSeams<'a> {
    before_rename: Option<&'a dyn Fn()>,
    after_rename: Option<&'a dyn Fn()>,
    after_parent_fsync: Option<&'a dyn Fn()>,
    fail_post_rename_verification: bool,
    fail_post_rename_fsync: bool,
    fail_external_parent_fsync: bool,
    fail_failure_marker: bool,
}

fn fsync_pinned_external_evidence_parent(
    artifact: &PinnedReleaseEvidenceArtifact,
    seams: &ReleaseEvidenceWriterSeams<'_>,
) -> Result<(), &'static str> {
    verify_pinned_release_evidence_parent(artifact)?;
    if seams.fail_external_parent_fsync {
        return Err("deterministic external evidence parent fsync failure");
    }
    artifact
        .external_parent
        .sync_all()
        .map_err(|_| "fsync descriptor-pinned external evidence parent")
}

fn mark_private_evidence_namespace_failed(
    artifact: &PinnedReleaseEvidenceArtifact,
    seams: &ReleaseEvidenceWriterSeams<'_>,
) -> Result<(), &'static str> {
    use rustix::fs::{openat, Mode, OFlags};

    if seams.fail_failure_marker {
        return Err("deterministic private evidence failure-marker error");
    }
    let name = OsString::from(format!(
        ".failed-{}",
        RELEASE_EVIDENCE_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut marker = File::from(
        openat(
            &artifact.namespace_parent,
            name.as_os_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "create private evidence failure marker")?,
    );
    marker
        .write_all(b"failed")
        .and_then(|_| marker.sync_all())
        .map_err(|_| "fsync private evidence failure marker")?;
    artifact
        .namespace_parent
        .sync_all()
        .map_err(|_| "fsync private evidence namespace failure marker")
}

fn fail_post_rename_evidence_publication(
    artifact: &PinnedReleaseEvidenceArtifact,
    _identity: EvidenceArtifactIdentity,
    seams: &ReleaseEvidenceWriterSeams<'_>,
    failure: &'static str,
) -> Result<(), &'static str> {
    // Linux has no rename-by-inode operation.  A preceding `statat` cannot
    // make a later pathname `renameat` safe: another same-UID writer could
    // replace the leaf between those operations.  Preserve every final leaf
    // instead of relocating an unverified replacement.  With no `.accepted`
    // marker this namespace is fail-closed and the strict reader rejects the
    // residue rather than accepting or clobbering it.
    mark_private_evidence_namespace_failed(artifact, seams)?;
    Err(failure)
}

fn verify_private_evidence_final(
    artifact: &PinnedReleaseEvidenceArtifact,
    bytes: &[u8],
    identity: EvidenceArtifactIdentity,
) -> Result<(), &'static str> {
    use rustix::fs::{statat, AtFlags};

    verify_pinned_release_evidence_parent(artifact)?;
    let final_stat = rustix_identity(
        statat(
            &artifact.namespace_parent,
            artifact.leaf.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| "stat private final evidence leaf without following links")?,
    );
    if !final_stat.same_inode(identity)
        || final_stat.size != u64::try_from(bytes.len()).expect("evidence byte length fits u64")
    {
        return Err("private final evidence leaf is not the owned temporary inode");
    }
    let observed = read_bounded_nofollow_regular_file(
        &artifact.namespace_parent,
        artifact.leaf.as_os_str(),
        bytes.len(),
        "private final release evidence",
    )?;
    if observed != bytes {
        return Err("private final evidence bytes differ from canonical evidence");
    }
    let final_after_read = rustix_identity(
        statat(
            &artifact.namespace_parent,
            artifact.leaf.as_os_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| "re-stat private final evidence leaf without following links")?,
    );
    if final_after_read != final_stat {
        return Err("private final evidence leaf identity changed while read");
    }
    Ok(())
}

fn write_release_evidence_artifact_with_seams(
    artifact: &PinnedReleaseEvidenceArtifact,
    bytes: &[u8],
    seams: &ReleaseEvidenceWriterSeams<'_>,
) -> Result<(), &'static str> {
    write_release_evidence_artifact_with_seams_and_lease(artifact, bytes, seams, None)
}

fn publish_release_evidence_noreplace(
    directory: &File,
    temporary: &OsStr,
    final_leaf: &OsStr,
) -> rustix::io::Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    {
        rustix::fs::renameat_with(
            directory,
            temporary,
            directory,
            final_leaf,
            rustix::fs::RenameFlags::NOREPLACE,
        )
    }
    #[cfg(target_os = "freebsd")]
    {
        use rustix::fs::{linkat, unlinkat, AtFlags};

        // FreeBSD has no rustix `renameat_with` export. A hard-link publish is
        // still atomic and no-clobber for this same-filesystem private
        // namespace. If unlinking the temporary name fails, the caller adds a
        // durable failure marker and never creates `.accepted`.
        linkat(
            directory,
            temporary,
            directory,
            final_leaf,
            AtFlags::empty(),
        )?;
        unlinkat(directory, temporary, AtFlags::empty())
    }
}

fn write_release_evidence_artifact_with_seams_and_lease(
    artifact: &PinnedReleaseEvidenceArtifact,
    bytes: &[u8],
    seams: &ReleaseEvidenceWriterSeams<'_>,
    qualification_host_lease: Option<&QualificationHostLease>,
) -> Result<(), &'static str> {
    use rustix::fs::{fstat, openat, Mode, OFlags};

    if let Some(lease) = qualification_host_lease {
        lease.revalidate()?;
    }
    verify_pinned_release_evidence_parent(artifact)?;
    let temporary = OsString::from(format!(
        ".opc-qualification-evidence-{}-{}",
        std::process::id(),
        RELEASE_EVIDENCE_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let descriptor = openat(
        &artifact.namespace_parent,
        temporary.as_os_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "open pinned external evidence temporary file")?;
    let mut file = File::from(descriptor);
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        mark_private_evidence_namespace_failed(artifact, seams)
            .map_err(|_| "evidence write failure could not seal private namespace")?;
        return Err("write or fsync canonical private evidence");
    }
    let published_identity = rustix_identity(
        fstat(&file).map_err(|_| "fstat canonical external evidence temporary after fsync")?,
    );
    if let Some(before_rename) = seams.before_rename {
        before_rename();
    }
    if let Some(lease) = qualification_host_lease {
        if lease.revalidate().is_err() {
            drop(file);
            mark_private_evidence_namespace_failed(artifact, seams)
                .map_err(|_| "trusted wrapper lease failure could not seal private namespace")?;
            return Err("trusted wrapper lease changed immediately before publication");
        }
    }
    if verify_pinned_release_evidence_parent(artifact).is_err() {
        drop(file);
        mark_private_evidence_namespace_failed(artifact, seams)
            .map_err(|_| "evidence parent failure could not seal private namespace")?;
        return Err("evidence parent changed immediately before rename");
    }
    if publish_release_evidence_noreplace(
        &artifact.namespace_parent,
        temporary.as_os_str(),
        artifact.leaf.as_os_str(),
    )
    .is_err()
    {
        drop(file);
        mark_private_evidence_namespace_failed(artifact, seams)
            .map_err(|_| "publication failure could not seal private namespace")?;
        return Err("atomically publish absent external evidence artifact");
    }
    // The retained temporary fd pins the exact inode through rename.  A
    // post-rename error leaves the namespace fail-closed below; Linux cannot
    // safely relocate a pathname after a separate identity check.
    if let Some(after_rename) = seams.after_rename {
        after_rename();
    }
    let post_rename = (|| -> Result<(), &'static str> {
        verify_private_evidence_final(artifact, bytes, published_identity)?;
        if seams.fail_post_rename_verification {
            return Err("deterministic post-rename verification failure");
        }
        if seams.fail_post_rename_fsync {
            return Err("deterministic post-rename fsync failure");
        }
        artifact
            .namespace_parent
            .sync_all()
            .map_err(|_| "fsync pinned private evidence namespace")?;
        // The namespace entry itself lives in this distinct parent.  Sync it
        // after the final leaf has been durably published and before any
        // acceptance marker can make evidence consumable after a crash.
        fsync_pinned_external_evidence_parent(artifact, seams)?;
        if let Some(after_parent_fsync) = seams.after_parent_fsync {
            after_parent_fsync();
        }
        verify_private_evidence_final(artifact, bytes, published_identity)?;
        let marker_bytes = format!("sha256:{:x}", Sha256::digest(bytes));
        let mut accepted = File::from(
            openat(
                &artifact.namespace_parent,
                RELEASE_EVIDENCE_ACCEPTED_LEAF,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| "create private evidence acceptance marker")?,
        );
        accepted
            .write_all(marker_bytes.as_bytes())
            .and_then(|_| accepted.sync_all())
            .map_err(|_| "fsync private evidence acceptance marker")?;
        artifact
            .namespace_parent
            .sync_all()
            .map_err(|_| "fsync accepted private evidence namespace")?;
        verify_private_evidence_final(artifact, bytes, published_identity)?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = post_rename {
        return fail_post_rename_evidence_publication(artifact, published_identity, seams, error);
    }
    Ok(())
}

fn write_release_evidence_artifact(artifact: &PinnedReleaseEvidenceArtifact, bytes: &[u8]) {
    write_release_evidence_artifact_with_seams(
        artifact,
        bytes,
        &ReleaseEvidenceWriterSeams::default(),
    )
    .expect("publish descriptor-pinned external evidence artifact");
}

fn publish_release_evidence_artifact(
    artifact: &PinnedReleaseEvidenceArtifact,
    bytes: &[u8],
    initial_provenance: &ReleaseEvidenceProvenance,
    observed_libtest_argv: &[String],
    process_loss_companion: &PinnedProcessLossCompanion,
    qualification_host_lease: &QualificationHostLease,
) {
    let immediately_before_publication = release_evidence_provenance_snapshot();
    assert_eq!(
        immediately_before_publication, *initial_provenance,
        "qualification provenance changed before evidence publication"
    );
    let (immediately_before_execution, _) = release_evidence_execution_identity(
        &immediately_before_publication,
        &artifact.canonical_namespace,
        observed_libtest_argv,
    )
    .expect("revalidate pinned executable and trusted wrapper attestation before publication");
    let decoded = strict_decode_release_evidence(bytes)
        .expect("publication bytes remain strict canonical release evidence");
    assert_eq!(
        immediately_before_execution, decoded.execution,
        "release executable or trusted wrapper attestation changed before evidence publication"
    );
    let immediately_before_process_loss = revalidate_pinned_process_loss_companion(
        process_loss_companion,
        &immediately_before_publication,
    )
    .expect("process-loss companion descriptor and provenance remain pinned before publication");
    assert_eq!(
        immediately_before_process_loss, decoded.process_loss,
        "release evidence must bind the exact process-loss companion revalidated before publication"
    );
    write_release_evidence_artifact_with_seams_and_lease(
        artifact,
        bytes,
        &ReleaseEvidenceWriterSeams::default(),
        Some(qualification_host_lease),
    )
    .expect("publish evidence while the trusted wrapper lease remains pinned");
    qualification_host_lease
        .revalidate()
        .expect("trusted wrapper lease must remain pinned at qualification completion");
}

fn pinned_release_evidence_test_artifact(
    parent: &Path,
    leaf: &str,
) -> PinnedReleaseEvidenceArtifact {
    let canonical_external_parent = parent
        .canonicalize()
        .expect("canonical test evidence parent");
    let external_stat =
        nix::sys::stat::stat(&canonical_external_parent).expect("stat test evidence parent");
    let external_parent = pinned_parent_file(
        &canonical_external_parent,
        external_stat.st_dev as u64,
        external_stat.st_ino as u64,
    )
    .expect("open descriptor-pinned test evidence parent");
    let namespace = OsString::from(format!(
        "namespace-{}",
        RELEASE_EVIDENCE_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let namespace_path = canonical_external_parent.join(&namespace);
    std::fs::create_dir(&namespace_path).expect("create test private evidence namespace");
    std::fs::set_permissions(&namespace_path, std::fs::Permissions::from_mode(0o700))
        .expect("set test private evidence namespace mode");
    let namespace_stat =
        nix::sys::stat::stat(&namespace_path).expect("stat test evidence namespace");
    let namespace_parent = pinned_parent_file(
        &namespace_path,
        namespace_stat.st_dev as u64,
        namespace_stat.st_ino as u64,
    )
    .expect("open descriptor-pinned test evidence namespace");
    PinnedReleaseEvidenceArtifact {
        evidence: ReleaseEvidenceArtifact {
            mechanism: "rustix_private_namespace_dirfd_noreplace_fsync".to_owned(),
            path_id: redacted_path_id(&namespace_path.join(leaf)),
            cooperative_same_uid_boundary: "private_mode_0700_namespace_no_shared_path_authority"
                .to_owned(),
        },
        canonical_external_parent,
        canonical_namespace: namespace_path,
        external_parent,
        namespace,
        namespace_parent,
        leaf: OsString::from(leaf),
        external_parent_device: external_stat.st_dev as u64,
        external_parent_inode: external_stat.st_ino as u64,
        namespace_device: namespace_stat.st_dev as u64,
        namespace_inode: namespace_stat.st_ino as u64,
    }
}

fn pinned_release_evidence_test_leaf_path(
    external_parent: &Path,
    artifact: &PinnedReleaseEvidenceArtifact,
) -> PathBuf {
    external_parent
        .join(&artifact.namespace)
        .join(&artifact.leaf)
}

#[test]
fn release_evidence_writer_never_clobbers_or_follows_parent_rebind() {
    let directory = tempfile::tempdir().expect("writer test root");
    let parent = directory.path().join("evidence-parent");
    std::fs::create_dir(&parent).expect("writer test parent");
    let artifact = pinned_release_evidence_test_artifact(&parent, "evidence.json");
    let final_leaf = pinned_release_evidence_test_leaf_path(&parent, &artifact);
    write_release_evidence_artifact(&artifact, b"first");
    assert_eq!(std::fs::read(&final_leaf).unwrap(), b"first");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_release_evidence_artifact(&artifact, b"second");
    }))
    .is_err());
    assert_eq!(std::fs::read(&final_leaf).unwrap(), b"first");

    let rebound = directory.path().join("rebound-parent");
    std::fs::rename(&parent, &rebound).expect("rebind test parent");
    std::fs::create_dir(&parent).expect("replace test parent");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_release_evidence_artifact(&artifact, b"rebound");
    }))
    .is_err());
    assert!(
        !parent.join(&artifact.namespace).exists(),
        "a rebound external parent cannot acquire the pinned private namespace"
    );
}

#[test]
fn release_evidence_writer_descriptor_seams_preserve_foreign_leaves_and_cleanup_owned_ones() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("writer seam test root");
    let real_parent = directory.path().join("real-parent");
    let symlink_parent = directory.path().join("symlink-parent");
    std::fs::create_dir(&real_parent).expect("writer seam real parent");
    symlink(&real_parent, &symlink_parent).expect("writer seam parent symlink");
    let artifact = pinned_release_evidence_test_artifact(&symlink_parent, "evidence.json");
    assert_eq!(
        artifact.evidence.path_id,
        redacted_path_id(&pinned_release_evidence_test_leaf_path(
            &real_parent,
            &artifact
        )),
        "the recorded artifact path is a stable redacted canonical-parent identifier"
    );
    let real_leaf = pinned_release_evidence_test_leaf_path(&real_parent, &artifact);

    symlink("/dev/null", &real_leaf).expect("existing target symlink");
    assert!(write_release_evidence_artifact_with_seams(
        &artifact,
        b"candidate",
        &ReleaseEvidenceWriterSeams::default(),
    )
    .is_err());
    assert!(
        std::fs::symlink_metadata(&real_leaf)
            .expect("existing target symlink metadata")
            .file_type()
            .is_symlink(),
        "NOREPLACE must neither clobber nor follow an existing target symlink"
    );
    std::fs::remove_file(&real_leaf).expect("remove test symlink");

    let original_parent = real_parent.clone();
    let rebound_parent = directory.path().join("rebound-parent");
    let before_rename = || {
        std::fs::rename(&original_parent, &rebound_parent).expect("rebind parent before rename");
        std::fs::create_dir(&original_parent).expect("replacement parent after rebind");
    };
    assert!(write_release_evidence_artifact_with_seams(
        &artifact,
        b"rebound",
        &ReleaseEvidenceWriterSeams {
            before_rename: Some(&before_rename),
            ..ReleaseEvidenceWriterSeams::default()
        },
    )
    .is_err());
    assert!(!original_parent.join(&artifact.namespace).exists());
    assert!(
        !pinned_release_evidence_test_leaf_path(&rebound_parent, &artifact).exists(),
        "the pre-rename failure leaves no accepted final leaf"
    );

    let replaced_artifact = pinned_release_evidence_test_artifact(&rebound_parent, "evidence.json");
    let replaced_leaf = pinned_release_evidence_test_leaf_path(&rebound_parent, &replaced_artifact);
    let replace_final_leaf = || {
        std::fs::remove_file(&replaced_leaf).expect("remove owned leaf in final replacement seam");
        std::fs::write(&replaced_leaf, b"foreign replacement")
            .expect("install foreign final replacement");
    };
    assert!(write_release_evidence_artifact_with_seams(
        &replaced_artifact,
        b"owned candidate",
        &ReleaseEvidenceWriterSeams {
            after_rename: Some(&replace_final_leaf),
            ..ReleaseEvidenceWriterSeams::default()
        },
    )
    .is_err());
    assert_eq!(
        std::fs::read(&replaced_leaf).expect("foreign replacement remains"),
        b"foreign replacement",
        "the private namespace writer never unlinks a foreign replacement after a stat check"
    );
    std::fs::remove_file(&replaced_leaf).expect("remove foreign replacement");

    let same_inode_leaf = replaced_leaf.clone();
    let overwrite_same_inode = || {
        std::fs::write(&same_inode_leaf, b"same-inode overwrite")
            .expect("overwrite the owned final inode without replacing its directory entry");
    };
    assert!(write_release_evidence_artifact_with_seams(
        &replaced_artifact,
        b"owned candidate",
        &ReleaseEvidenceWriterSeams {
            after_rename: Some(&overwrite_same_inode),
            ..ReleaseEvidenceWriterSeams::default()
        },
    )
    .is_err());
    assert!(
        replaced_leaf.exists(),
        "a post-rename same-inode overwrite is left unaccepted rather than pathname-renamed after a raced stat"
    );
    assert!(
        !replaced_leaf
            .parent()
            .unwrap()
            .join(RELEASE_EVIDENCE_ACCEPTED_LEAF)
            .exists(),
        "same-inode overwrite cannot leave an accepted-looking artifact"
    );
    std::fs::remove_file(&replaced_leaf).expect("remove test-owned same-inode overwrite");
    let post_fsync_leaf = replaced_leaf.clone();
    let replace_after_fsync = || {
        std::fs::remove_file(&post_fsync_leaf).expect("remove final leaf after parent fsync");
        std::fs::write(&post_fsync_leaf, b"post-fsync foreign replacement")
            .expect("replace final leaf after parent fsync");
    };
    assert!(write_release_evidence_artifact_with_seams(
        &replaced_artifact,
        b"owned candidate",
        &ReleaseEvidenceWriterSeams {
            after_parent_fsync: Some(&replace_after_fsync),
            ..ReleaseEvidenceWriterSeams::default()
        },
    )
    .is_err());
    assert_eq!(
        std::fs::read(&replaced_leaf).unwrap(),
        b"post-fsync foreign replacement"
    );
    std::fs::remove_file(&replaced_leaf).expect("remove post-fsync replacement");

    for seams in [
        ReleaseEvidenceWriterSeams {
            fail_post_rename_verification: true,
            ..ReleaseEvidenceWriterSeams::default()
        },
        ReleaseEvidenceWriterSeams {
            fail_post_rename_fsync: true,
            ..ReleaseEvidenceWriterSeams::default()
        },
    ] {
        assert!(write_release_evidence_artifact_with_seams(
            &replaced_artifact,
            b"owned candidate",
            &seams,
        )
        .is_err());
        assert!(
            !replaced_leaf
                .parent()
                .unwrap()
                .join(RELEASE_EVIDENCE_ACCEPTED_LEAF)
                .exists(),
            "a post-rename failure cannot leave an accepted private artifact"
        );
        assert!(replaced_leaf.exists());
        std::fs::remove_file(&replaced_leaf)
            .expect("remove test-owned post-rename failure leaf before next seam");
    }

    let external_fsync_artifact =
        pinned_release_evidence_test_artifact(&rebound_parent, "evidence.json");
    let external_fsync_leaf =
        pinned_release_evidence_test_leaf_path(&rebound_parent, &external_fsync_artifact);
    assert!(write_release_evidence_artifact_with_seams(
        &external_fsync_artifact,
        b"owned candidate",
        &ReleaseEvidenceWriterSeams {
            fail_external_parent_fsync: true,
            ..ReleaseEvidenceWriterSeams::default()
        },
    )
    .is_err());
    assert!(external_fsync_leaf.exists());
    assert!(
        !external_fsync_leaf
            .parent()
            .unwrap()
            .join(RELEASE_EVIDENCE_ACCEPTED_LEAF)
            .exists(),
        "external-parent fsync failure is fail-closed before acceptance"
    );

    assert!(write_release_evidence_artifact_with_seams(
        &replaced_artifact,
        b"owned candidate",
        &ReleaseEvidenceWriterSeams {
            fail_post_rename_verification: true,
            fail_failure_marker: true,
            ..ReleaseEvidenceWriterSeams::default()
        },
    )
    .is_err());
    assert!(
        !replaced_leaf
            .parent()
            .unwrap()
            .join(RELEASE_EVIDENCE_ACCEPTED_LEAF)
            .exists(),
        "failure-marker errors never report an accepted private artifact"
    );
}

fn validate_release_evidence(evidence: &ReleaseQualificationEvidence) -> Result<(), &'static str> {
    let phase_elapsed_ms = evidence
        .phases
        .iter()
        .try_fold(0_u64, |total, phase| total.checked_add(phase.elapsed_ms))
        .ok_or("release qualification phase elapsed total overflow")?;
    let status_request_slots = evidence
        .effects
        .status_initial_request_slots
        .checked_add(evidence.effects.status_retry_request_slots)
        .ok_or("release status request-slot equation overflow")?;
    let schedule_total = evidence
        .schedule
        .preload_operations
        .checked_add(evidence.schedule.sustained_operations)
        .and_then(|total| total.checked_add(evidence.schedule.burst_operations))
        .ok_or("release schedule total equation overflow")?;
    let committed_total = evidence
        .outcomes
        .release_operations_committed
        .checked_add(evidence.outcomes.reclaim_operations_committed)
        .ok_or("release committed-operation equation overflow")?;
    let expected_mutation_attempts = evidence
        .effects
        .mutation_batches
        .checked_add(evidence.effects.not_transmitted_retries)
        .ok_or("release mutation-attempt equation overflow")?;
    let maximum_not_transmitted_retries = evidence
        .effects
        .mutation_batches
        .checked_mul(QUALIFICATION_TRANSIENT_RETRY_LIMIT as u64)
        .ok_or("release not-transmitted retry bound overflow")?;
    let maximum_unknown_request_slots = evidence
        .effects
        .outcome_unknown_batches
        .checked_mul(QUALIFICATION_MAX_PHYSICAL_EFFECT_BATCH_OPERATIONS)
        .ok_or("release outcome-unknown request-slot bound overflow")?;
    let maximum_status_retry_slots = evidence
        .effects
        .outcome_unknown_request_slots
        .checked_mul(QUALIFICATION_TRANSIENT_RETRY_LIMIT as u64)
        .ok_or("release status retry request-slot bound overflow")?;
    let maximum_status_retry_slots_per_round = evidence
        .effects
        .status_retry_rounds
        .checked_mul(QUALIFICATION_MAX_PHYSICAL_EFFECT_BATCH_OPERATIONS)
        .ok_or("release status retry round cardinality overflow")?;
    let maximum_status_retry_rounds = evidence
        .effects
        .outcome_unknown_batches
        .checked_mul(QUALIFICATION_TRANSIENT_RETRY_LIMIT as u64)
        .ok_or("release status retry-round bound overflow")?;
    let maximum_read_only_retries = evidence
        .outcomes
        .total_operations_committed
        .checked_mul(QUALIFICATION_TRANSIENT_RETRY_LIMIT as u64)
        .ok_or("release read-only retry bound overflow")?;
    let maximum_maintenance_retries = QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS
        .checked_mul(QUALIFICATION_TRANSIENT_RETRY_LIMIT as u64)
        .ok_or("release maintenance retry bound overflow")?;
    let exact_transient_retries = evidence
        .outcomes
        .read_only_observation_retries
        .checked_add(evidence.outcomes.maintenance_reconciliation_retries)
        .and_then(|total| total.checked_add(evidence.outcomes.effect_not_transmitted_retries))
        .ok_or("release transient retry attribution equation overflow")?;
    let release_deadline_us = duration_evidence_microseconds(
        QUALIFICATION_RELEASE_BATCH_DEADLINE,
        "release batch deadline",
    );
    let release_deadline_ms = duration_evidence_milliseconds(
        QUALIFICATION_RELEASE_BATCH_DEADLINE,
        "release batch deadline",
    );
    let expected_reclaimed_entries = 2_u64
        .checked_mul(FENCED_TRANSITION_V2_RECLAIM_BATCH as u64)
        .ok_or("release reclaimed-entry equation overflow")?;
    let expected_reclaim_remaining = (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64)
        .checked_sub(expected_reclaimed_entries)
        .ok_or("release reclaim remaining equation underflow")?;
    if evidence.version != 1
        || !evidence.qualification_complete
        || evidence.elapsed_ms == 0
        || evidence.elapsed_ms
            != phase_elapsed_ms
                .checked_add(evidence.non_phase_overhead_ms)
                .ok_or("release qualification elapsed total overflow")?
        || evidence.source.build_revision != evidence.source.revision
        || evidence.source.build_tree != evidence.source.tree
        || evidence.source.revision.len() != 40
        || evidence.source.tree.len() != 40
        || !is_lower_hex_exact(&evidence.source.source_worktree_sha256, 64)
        || evidence.source.worktree != "clean"
        || evidence.build_cargo_lock_sha256.len() != 64
        || evidence.runtime_cargo_lock_sha256.len() != 64
        || evidence.build_cargo_lock_sha256 != evidence.runtime_cargo_lock_sha256
        || evidence.required_reproduction_recipe != RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE
        || evidence.required_reproduction_recipe.len() > RELEASE_EVIDENCE_RECIPE_MAX_BYTES
        || evidence.libtest_argv
            != RELEASE_EVIDENCE_LIBTEST_ARGS
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect::<Vec<_>>()
        || evidence.artifact.mechanism != "rustix_private_namespace_dirfd_noreplace_fsync"
        || !is_sha256_path_id(&evidence.artifact.path_id)
        || evidence.artifact.cooperative_same_uid_boundary
            != "private_mode_0700_namespace_no_shared_path_authority"
        || !is_sha256_path_id(&evidence.execution.cargo_target_dir_id)
        || !is_sha256_path_id(&evidence.execution.fs_verity_snapshot_base_id)
        || !is_sha256_path_id(&evidence.execution.fs_verity_snapshot_root_id)
        || evidence.execution.fs_verity_snapshot_root_device == 0
        || evidence.execution.fs_verity_snapshot_root_inode == 0
        || !is_sha256_path_id(&evidence.execution.current_exe_relative_to_target_id)
        || evidence.execution.current_exe_sha256.len() != 64
        || evidence.execution.current_exe_device == 0
        || evidence.execution.current_exe_inode == 0
        || evidence.execution.compiled_schema_sha256
            != format!("{:x}", Sha256::digest(RELEASE_EVIDENCE_SCHEMA))
        || !is_sha256_path_id(&evidence.execution.build_attestation_path_id)
        || !is_lower_hex_exact(&evidence.execution.build_attestation_sha256, 64)
        || evidence.execution.build_attestation_wrapper_sha256
            != compiled_release_attestation_wrapper_sha256()
        || evidence.execution.build_attestation_boundary != RELEASE_BUILD_ATTESTATION_KIND
        || evidence.execution.target_os != "linux"
        || evidence.execution.target_arch != std::env::consts::ARCH
        || evidence.execution.target_env != qualification_target_environment()
        || !evidence.execution.enabled_features.is_empty()
        || evidence.execution.runner_quiet_host_boundary != QUALIFICATION_QUIET_HOST_BOUNDARY
        || evidence.quiet_host.boundary != QUALIFICATION_QUIET_HOST_BOUNDARY
        || evidence.quiet_host.cadence_ms
            != duration_evidence_milliseconds(
                QUALIFICATION_QUIET_HOST_CADENCE,
                "quiet-host cadence",
            )
        || evidence.quiet_host.maximum_sample_gap_us
            > duration_evidence_microseconds(
                QUALIFICATION_QUIET_HOST_MAXIMUM_GAP,
                "quiet-host maximum gap",
            )
        || evidence.quiet_host.monitored_elapsed_ms < evidence.elapsed_ms
        || evidence.quiet_host.samples < 2
        || !evidence.quiet_host.start_sampled
        || !evidence.quiet_host.end_sampled
        || evidence.process_loss.scope != "external_session_testkit_multiprocess_mtls_only"
        || !is_sha256_path_id(&evidence.process_loss.companion_path_id)
        || evidence.process_loss.companion_sha256.len() != 64
        || evidence.process_loss.companion_schema_sha256
            != format!("sha256:{:x}", Sha256::digest(PROCESS_LOSS_EVIDENCE_SCHEMA))
        || evidence.process_loss.companion_source_revision != evidence.source.revision
        || evidence.process_loss.companion_source_tree != evidence.source.tree
        || evidence.process_loss.companion_source_worktree_sha256
            != format!("sha256:{}", evidence.source.source_worktree_sha256)
        || !is_sha256_path_id(&evidence.process_loss.companion_v1_canonical_sha256)
        || !is_sha256_path_id(&evidence.process_loss.companion_invocation_argv_sha256)
        || !is_sha256_path_id(&evidence.process_loss.companion_harness_sha256)
        || !is_sha256_path_id(&evidence.process_loss.companion_child_sha256)
        || !is_sha256_path_id(&evidence.process_loss.companion_executable_sha256)
        || evidence
            .process_loss
            .strict_validation_command
            .chars()
            .count()
            > PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS
        || !process_loss_reproduction_command_has_canonical_argv(
            &evidence.process_loss.strict_validation_command,
        )
        || evidence.profile.cargo_profile_family != "release"
        || evidence.profile.cargo_opt_level != "3"
        || evidence.profile.debug_assertions
        || evidence.schedule.preload_operations != QUALIFICATION_SESSIONS as u64
        || evidence.schedule.sustained_operations != QUALIFICATION_SUSTAINED_TRANSITIONS as u64
        || evidence.schedule.sustained_rate_per_second != QUALIFICATION_SUSTAINED_RATE as u64
        || evidence.schedule.sustained_seconds != QUALIFICATION_SUSTAINED_SECONDS as u64
        || evidence.schedule.burst_operations != QUALIFICATION_BURST_TRANSITIONS as u64
        || evidence.schedule.burst_rate_per_second != QUALIFICATION_BURST_RATE as u64
        || evidence.schedule.burst_seconds != QUALIFICATION_BURST_SECONDS as u64
        || evidence.schedule.total_operations != QUALIFICATION_RELEASE_TRANSITIONS as u64
        || schedule_total != evidence.schedule.total_operations
        || evidence.resources.voters != VOTERS as u64
        || evidence.resources.in_flight_clients != QUALIFICATION_IN_FLIGHT_CLIENTS as u64
        || evidence.resources.batch_deadline_ms != release_deadline_ms
        || evidence.resources.batch_deadline_ms > 800
        || evidence.resources.operational_headroom_transitions
            != QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS as u64
        || evidence.resources.retained_envelope_headroom_transitions
            != QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS as u64
        || evidence.resources.database_ceiling_bytes_per_voter
            != QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES
        || evidence.resources.snapshot_ceiling_bytes_per_voter
            != QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES
        || evidence.resources.process_peak_rss_ceiling_kib
            != qualification_process_peak_rss_ceiling_kib()
        || evidence.resources.peak_rss_measurement != "linux_proc_self_status_vmhwm_kib"
        || !cfg!(target_os = "linux")
        || evidence.resources.pre_reclaim_database_bytes_by_voter.len() != VOTERS
        || evidence.resources.pre_reclaim_snapshot_bytes_by_voter.len() != VOTERS
        || evidence
            .resources
            .post_reclaim_database_bytes_by_voter
            .len()
            != VOTERS
        || evidence
            .resources
            .post_reclaim_snapshot_bytes_by_voter
            .len()
            != VOTERS
        || evidence.resources.database_artifacts_by_voter.len() != VOTERS
        || evidence.resources.snapshot_artifacts_by_voter.len() != VOTERS
        || evidence
            .resources
            .database_artifacts_by_voter
            .iter()
            .chain(evidence.resources.snapshot_artifacts_by_voter.iter())
            .any(|value| *value == 0)
        || evidence
            .resources
            .pre_reclaim_database_bytes_by_voter
            .iter()
            .chain(
                evidence
                    .resources
                    .post_reclaim_database_bytes_by_voter
                    .iter(),
            )
            .any(|value| {
                *value == 0 || *value > evidence.resources.database_ceiling_bytes_per_voter
            })
        || evidence
            .resources
            .pre_reclaim_snapshot_bytes_by_voter
            .iter()
            .chain(
                evidence
                    .resources
                    .post_reclaim_snapshot_bytes_by_voter
                    .iter(),
            )
            .any(|value| {
                *value == 0 || *value > evidence.resources.snapshot_ceiling_bytes_per_voter
            })
        || evidence.resources.peak_rss_kib == 0
        || evidence.resources.peak_rss_kib > evidence.resources.process_peak_rss_ceiling_kib
        || evidence.outcomes.release_operations_committed != evidence.schedule.total_operations
        || evidence.outcomes.matched_workload_outcomes != evidence.schedule.total_operations
        || evidence.outcomes.reclaim_operations_committed != 1
        || evidence.outcomes.matched_reclaim_outcomes != 1
        || evidence.outcomes.total_operations_committed != committed_total
        || evidence.outcomes.effect_not_transmitted_retries
            != evidence.effects.not_transmitted_retries
        || evidence.outcomes.read_only_observation_retries > maximum_read_only_retries
        || evidence.outcomes.maintenance_reconciliation_retries > maximum_maintenance_retries
        || evidence.outcomes.maintenance_reconciliation_retries
            < evidence.lifecycle.maintenance_readback_projections
        || evidence.outcomes.transient_exact_retries != exact_transient_retries
        || evidence.lifecycle.rotations != 7
        || evidence.lifecycle.graceful_same_process_engine_reopens != 1
        || evidence.lifecycle.logical_in_process_voters != VOTERS as u64
        || evidence.lifecycle.reclaim_batches != 2
        || evidence.lifecycle.reclaimed_entries != expected_reclaimed_entries
        || evidence.lifecycle.reclaim_remaining != expected_reclaim_remaining
        || evidence.lifecycle.maintenance_attempts != QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS
        || evidence.lifecycle.maintenance_elapsed_max_us > release_deadline_us
        || evidence.lifecycle.maintenance_resolved_after_800ms != 0
        || evidence.lifecycle.maintenance_deadline_exceeded != 0
        || evidence.lifecycle.maintenance_failures != 0
        || evidence.lifecycle.production_maintenance_invocations
            != evidence
                .lifecycle
                .production_maintenance_ok
                .checked_add(evidence.lifecycle.production_maintenance_err)
                .ok_or("production maintenance result equation overflow")?
        || evidence.lifecycle.production_maintenance_invocations
            < QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS
        || evidence.lifecycle.production_maintenance_invocations
            > QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS
                .checked_mul(QUALIFICATION_TRANSIENT_RETRY_LIMIT as u64 + 1)
                .ok_or("production maintenance invocation bound overflow")?
        || evidence.lifecycle.post_commit_reply_loss_projections != 1
        || evidence.lifecycle.maintenance_readback_projections != 2
        || evidence.effects.mutation_batches != QUALIFICATION_EXPECTED_EFFECT_BATCHES
        || evidence.effects.effect_request_slots != QUALIFICATION_EXPECTED_EFFECT_REQUEST_SLOTS
        || evidence.effects.mutation_attempts != expected_mutation_attempts
        || evidence.effects.not_transmitted_retries > maximum_not_transmitted_retries
        || evidence.effects.batch_elapsed_max_us > release_deadline_us
        || evidence.effects.resolved_after_deadline != 0
        || evidence.effects.mutation_deadline_before_dispatch != 0
        || evidence.effects.not_transmitted_deadline != 0
        || evidence.effects.deadline_after_backoff != 0
        || evidence.effects.status_deadline_before_dispatch != 0
        || evidence.effects.status_deadline_timeout != 0
        || (evidence.effects.outcome_unknown_batches == 0
            && (evidence.effects.outcome_unknown_request_slots != 0
                || evidence.effects.status_attempts != 0
                || evidence.effects.status_initial_request_slots != 0
                || evidence.effects.status_retry_request_slots != 0
                || evidence.effects.status_retry_rounds != 0))
        || (evidence.effects.outcome_unknown_batches > 0
            && (evidence.effects.outcome_unknown_request_slots == 0
                || evidence.effects.outcome_unknown_request_slots
                    < evidence.effects.outcome_unknown_batches
                || evidence.effects.outcome_unknown_request_slots > maximum_unknown_request_slots
                || evidence.effects.outcome_unknown_request_slots
                    > evidence.effects.effect_request_slots
                || evidence.effects.status_initial_request_slots
                    != evidence.effects.outcome_unknown_request_slots
                || evidence.effects.status_attempts != status_request_slots
                || evidence.effects.status_retry_request_slots > maximum_status_retry_slots
                || evidence.effects.status_retry_request_slots
                    > maximum_status_retry_slots_per_round
                || (evidence.effects.status_retry_request_slots == 0
                    && evidence.effects.status_retry_rounds != 0)
                || (evidence.effects.status_retry_request_slots > 0
                    && evidence.effects.status_retry_rounds == 0)
                || evidence.effects.status_retry_rounds
                    > evidence.effects.status_retry_request_slots
                || (evidence.effects.outcome_unknown_batches == evidence.effects.mutation_batches
                    && evidence.effects.outcome_unknown_request_slots
                        != evidence.effects.effect_request_slots)))
        || evidence.effects.status_retry_rounds > maximum_status_retry_rounds
        || evidence.phases.len() != 2
        || evidence.phases.iter().enumerate().any(|(index, phase)| {
            let (name, rate, operations) = if index == 0 {
                (
                    "sustained-500-per-second",
                    QUALIFICATION_SUSTAINED_RATE as u64,
                    QUALIFICATION_SUSTAINED_TRANSITIONS as u64,
                )
            } else {
                (
                    "burst-1000-per-second",
                    QUALIFICATION_BURST_RATE as u64,
                    QUALIFICATION_BURST_TRANSITIONS as u64,
                )
            };
            phase.name != name
                || phase.offered_ops_per_second != rate
                || phase.operations != operations
                || phase.elapsed_ms == 0
                || { phase.elapsed_ms > qualification_phase_max_elapsed_ms(operations, rate) }
                || phase.batch_samples != operations / QUALIFICATION_PACED_BATCH_OPERATIONS as u64
                || phase.item_samples != phase.operations
                || phase.peak_unjoined_batch_task_slots == 0
                || phase.peak_unjoined_batch_task_slots > QUALIFICATION_IN_FLIGHT_CLIENTS as u64
                || phase.batch_p99_us > phase.batch_p999_us
                || phase.batch_p999_us > phase.batch_max_us
                || phase.item_p99_us > phase.item_p999_us
                || phase.item_p999_us > phase.item_max_us
                || phase.item_p99_us > 25_000
                || phase.item_p999_us > 100_000
                || phase.batch_max_us > release_deadline_us
                || phase.item_max_us > release_deadline_us
        })
    {
        return Err("release qualification evidence violates its fixed contract");
    }
    for value in [
        &evidence.source.build_revision,
        &evidence.source.build_tree,
        &evidence.source.source_worktree_sha256,
        &evidence.source.revision,
        &evidence.source.tree,
        &evidence.build_cargo_lock_sha256,
        &evidence.runtime_cargo_lock_sha256,
        &evidence.execution.current_exe_sha256,
        &evidence.execution.compiled_schema_sha256,
        &evidence.execution.build_attestation_sha256,
        &evidence.execution.build_attestation_wrapper_sha256,
        &evidence.process_loss.companion_sha256,
        &evidence.process_loss.companion_source_revision,
    ] {
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("release qualification evidence digest is non-hex");
        }
    }
    Ok(())
}

fn strict_decode_release_evidence(
    encoded: &[u8],
) -> Result<ReleaseQualificationEvidence, &'static str> {
    if encoded.len() > RELEASE_EVIDENCE_MAX_BYTES {
        return Err("release qualification evidence exceeds its bounded decoder limit");
    }
    let decoded: ReleaseQualificationEvidence =
        serde_json::from_slice(encoded).map_err(|_| "release evidence JSON is not closed")?;
    let schema: serde_json::Value = serde_json::from_str(RELEASE_EVIDENCE_SCHEMA)
        .map_err(|_| "release evidence schema is invalid")?;
    let instance: serde_json::Value =
        serde_json::from_slice(encoded).map_err(|_| "release evidence JSON is invalid")?;
    opc_schema_validate::validate(&schema, &instance)
        .map_err(|_| "release evidence violates its adjacent schema")?;
    validate_release_evidence(&decoded)?;
    let canonical =
        serde_json::to_vec(&decoded).map_err(|_| "release evidence cannot canonicalize")?;
    if encoded != canonical {
        return Err("release evidence is not canonical");
    }
    Ok(decoded)
}

fn read_bounded_nofollow_regular_file(
    parent: &File,
    leaf: &OsStr,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, &'static str> {
    read_bounded_nofollow_regular_file_with_identity(parent, leaf, maximum, label)
        .map(|(bytes, _)| bytes)
}

fn read_bounded_nofollow_regular_file_with_identity(
    parent: &File,
    leaf: &OsStr,
    maximum: usize,
    label: &'static str,
) -> Result<(Vec<u8>, EvidenceArtifactIdentity), &'static str> {
    read_bounded_nofollow_regular_file_with_identity_and_seam(parent, leaf, maximum, label, None)
}

fn read_bounded_nofollow_regular_file_with_seam(
    parent: &File,
    leaf: &OsStr,
    maximum: usize,
    label: &'static str,
    after_initial_stat: Option<&dyn Fn()>,
) -> Result<Vec<u8>, &'static str> {
    read_bounded_nofollow_regular_file_with_identity_and_seam(
        parent,
        leaf,
        maximum,
        label,
        after_initial_stat,
    )
    .map(|(bytes, _)| bytes)
}

fn read_bounded_nofollow_regular_file_with_identity_and_seam(
    parent: &File,
    leaf: &OsStr,
    maximum: usize,
    label: &'static str,
    after_initial_stat: Option<&dyn Fn()>,
) -> Result<(Vec<u8>, EvidenceArtifactIdentity), &'static str> {
    use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags};

    let mut file = File::from(
        openat(
            parent,
            leaf,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "open bounded evidence input without following links")?,
    );
    let initial = fstat(&file).map_err(|_| "fstat bounded evidence input")?;
    if !FileType::from_raw_mode(initial.st_mode).is_file() {
        let _ = label;
        return Err("bounded evidence input is not a regular file");
    }
    let size =
        usize::try_from(initial.st_size).map_err(|_| "bounded evidence input has invalid size")?;
    if size > maximum {
        return Err("bounded evidence input exceeds size limit");
    }
    if let Some(after_initial_stat) = after_initial_stat {
        after_initial_stat();
    }
    let mut bytes = Vec::with_capacity(size);
    let read_limit = maximum
        .checked_add(1)
        .ok_or("bounded evidence read limit overflow")?;
    (&mut file)
        .take(u64::try_from(read_limit).map_err(|_| "bounded evidence read limit invalid")?)
        .read_to_end(&mut bytes)
        .map_err(|_| "read bounded evidence input")?;
    let after = fstat(&file).map_err(|_| "re-fstat bounded evidence input")?;
    if after.st_dev != initial.st_dev
        || after.st_ino != initial.st_ino
        || after.st_size != initial.st_size
        || bytes.len() != size
        || bytes.len() > maximum
    {
        return Err("bounded evidence input changed while read");
    }
    let pathname_after = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "re-stat bounded evidence pathname without following links")?;
    if pathname_after.st_dev != initial.st_dev
        || pathname_after.st_ino != initial.st_ino
        || pathname_after.st_size != initial.st_size
    {
        return Err("bounded evidence pathname changed while read");
    }
    Ok((bytes, rustix_identity(initial)))
}

fn read_bounded_current_user_private_regular_file_with_identity(
    parent: &File,
    leaf: &OsStr,
    maximum: usize,
    label: &'static str,
) -> Result<(Vec<u8>, EvidenceArtifactIdentity), &'static str> {
    use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags};

    let mut file = File::from(
        openat(
            parent,
            leaf,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "open private qualification leaf without following links")?,
    );
    let initial = fstat(&file).map_err(|_| "fstat private qualification leaf")?;
    require_current_user_private_regular_file(initial, label)?;
    let initial_identity = rustix_identity(initial);
    let size = usize::try_from(initial.st_size)
        .map_err(|_| "private qualification leaf has invalid size")?;
    if size > maximum {
        return Err("private qualification leaf exceeds size limit");
    }
    let mut bytes = Vec::with_capacity(size);
    (&mut file)
        .take(
            u64::try_from(
                maximum
                    .checked_add(1)
                    .ok_or("private qualification read limit overflow")?,
            )
            .map_err(|_| "private qualification read limit invalid")?,
        )
        .read_to_end(&mut bytes)
        .map_err(|_| "read private qualification leaf")?;
    let after = fstat(&file).map_err(|_| "re-fstat private qualification leaf")?;
    require_current_user_private_regular_file(after, label)?;
    let pathname_after = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "re-stat private qualification leaf without following links")?;
    require_current_user_private_regular_file(pathname_after, label)?;
    if rustix_identity(after) != initial_identity
        || rustix_identity(pathname_after) != initial_identity
        || bytes.len() != size
        || bytes.len() > maximum
    {
        return Err("private qualification leaf changed while read");
    }
    Ok((bytes, initial_identity))
}

fn require_exact_release_evidence_namespace_leaves(namespace: &File) -> Result<(), &'static str> {
    use rustix::fs::Dir;

    let mut final_leaf = false;
    let mut accepted_leaf = false;
    let mut entries = 0_u8;
    for entry in Dir::read_from(namespace).map_err(|_| "read private evidence namespace")? {
        let entry = entry.map_err(|_| "read private evidence namespace entry")?;
        let name = entry.file_name();
        #[cfg(unix)]
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        entries = entries
            .checked_add(1)
            .ok_or("private evidence namespace entry count overflow")?;
        if entries > 2 {
            return Err("private evidence namespace has extra residue");
        }
        match name.to_bytes() {
            value if value == RELEASE_EVIDENCE_NAMESPACE_LEAF.as_bytes() => {
                if final_leaf {
                    return Err("private evidence namespace duplicates final leaf");
                }
                final_leaf = true;
            }
            value if value == RELEASE_EVIDENCE_ACCEPTED_LEAF.as_bytes() => {
                if accepted_leaf {
                    return Err("private evidence namespace duplicates acceptance marker");
                }
                accepted_leaf = true;
            }
            _ => return Err("private evidence namespace has an unaccepted leaf"),
        }
    }
    if !final_leaf || !accepted_leaf {
        return Err("private evidence namespace is not exactly final plus acceptance marker");
    }
    Ok(())
}

/// Validate a finished namespace without creating, overwriting, unlinking, or
/// otherwise mutating it. The accepted marker is part of the publication
/// protocol, so canonical JSON bytes alone are deliberately insufficient.
fn validate_existing_release_evidence_namespace_with_context(
    namespace_path: &Path,
    repository_root: &Path,
    canonical_gitdir: &Path,
    canonical_common_gitdir: &Path,
    target_dir: &Path,
) -> Result<(), &'static str> {
    use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags};

    let (canonical_parent, namespace_leaf, canonical_namespace) =
        canonical_direct_leaf_path(namespace_path, "existing release evidence namespace")?;
    let canonical_repository_root = repository_root
        .canonicalize()
        .map_err(|_| "canonicalize existing evidence worktree")?;
    let canonical_gitdir = canonical_gitdir
        .canonicalize()
        .map_err(|_| "canonicalize existing evidence gitdir")?;
    let canonical_common_gitdir = canonical_common_gitdir
        .canonicalize()
        .map_err(|_| "canonicalize existing evidence common gitdir")?;
    let canonical_target_dir = target_dir
        .canonicalize()
        .map_err(|_| "canonicalize existing evidence target directory")?;
    if paths_overlap(&canonical_namespace, &canonical_target_dir)
        || [
            &canonical_repository_root,
            &canonical_gitdir,
            &canonical_common_gitdir,
        ]
        .into_iter()
        .any(|protected| {
            paths_overlap(&canonical_namespace, protected)
                || paths_overlap(&canonical_target_dir, protected)
        })
    {
        return Err("existing evidence namespace paths are not mutually disjoint");
    }
    let parent_metadata = std::fs::metadata(&canonical_parent)
        .map_err(|_| "stat existing external evidence namespace parent")?;
    let external_parent = pinned_parent_file(
        &canonical_parent,
        parent_metadata.dev(),
        parent_metadata.ino(),
    )?;
    let namespace = File::from(
        openat(
            &external_parent,
            namespace_leaf.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "open existing external evidence namespace without following links")?,
    );
    let namespace_identity = fstat(&namespace)
        .map(rustix_identity)
        .map_err(|_| "fstat existing external evidence namespace")?;
    require_current_user_private_directory(
        fstat(&namespace).map_err(|_| "re-fstat existing external evidence namespace")?,
        "existing release evidence namespace",
    )?;
    let namespace_path_stat = statat(
        &external_parent,
        namespace_leaf.as_os_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| "stat existing external evidence namespace pathname")?;
    require_current_user_private_directory(
        namespace_path_stat,
        "existing release evidence namespace",
    )?;
    if rustix_identity(namespace_path_stat) != namespace_identity {
        return Err("existing external evidence namespace pathname identity changed");
    }
    if namespace_identity.size != 0 {
        // POSIX directory sizes are filesystem-defined. This branch exists
        // only to consume the descriptor identity and avoid a path reopen.
    }
    require_exact_release_evidence_namespace_leaves(&namespace)?;
    let encoded = read_bounded_current_user_private_regular_file_with_identity(
        &namespace,
        OsStr::new(RELEASE_EVIDENCE_NAMESPACE_LEAF),
        RELEASE_EVIDENCE_MAX_BYTES,
        "existing release evidence",
    )?
    .0;
    let evidence = strict_decode_release_evidence(&encoded)?;
    if evidence.artifact.path_id
        != redacted_path_id(&canonical_namespace.join(RELEASE_EVIDENCE_NAMESPACE_LEAF))
    {
        return Err("existing evidence artifact path identifier does not bind canonical namespace");
    }
    let accepted = read_bounded_current_user_private_regular_file_with_identity(
        &namespace,
        OsStr::new(RELEASE_EVIDENCE_ACCEPTED_LEAF),
        80,
        "existing release evidence acceptance marker",
    )?
    .0;
    let expected = format!("sha256:{:x}", Sha256::digest(&encoded));
    if accepted != expected.as_bytes() {
        return Err("existing evidence namespace acceptance marker does not bind canonical bytes");
    }
    require_exact_release_evidence_namespace_leaves(&namespace)?;
    let namespace_after = statat(
        &external_parent,
        namespace_leaf.as_os_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| "re-stat existing external evidence namespace pathname")?;
    if rustix_identity(namespace_after) != namespace_identity {
        return Err("existing external evidence namespace changed while validating");
    }
    // Keep the decoded value live through the marker check so this interface
    // cannot accidentally devolve into a marker-only consumer.
    let _ = evidence;
    Ok(())
}

fn validate_existing_release_evidence_namespace(namespace_path: &Path) -> Result<(), &'static str> {
    let repository_root = qualification_repository_root();
    let git = QualificationGitContext::discovered(repository_root.clone());
    let canonical_gitdir = PathBuf::from(git.checked_output(&["rev-parse", "--absolute-git-dir"]))
        .canonicalize()
        .map_err(|_| "canonicalize existing evidence gitdir")?;
    let canonical_common_gitdir =
        PathBuf::from(git.checked_output(&["rev-parse", "--git-common-dir"]))
            .canonicalize()
            .map_err(|_| "canonicalize existing evidence common gitdir")?;
    let target_dir = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .ok_or("CARGO_TARGET_DIR must bind existing evidence validation")?,
    )
    .canonicalize()
    .map_err(|_| "canonicalize existing evidence target directory")?;
    validate_existing_release_evidence_namespace_with_context(
        namespace_path,
        &repository_root,
        &canonical_gitdir,
        &canonical_common_gitdir,
        &target_dir,
    )
}

#[test]
#[ignore = "operator-invoked validation of an already-existing external release evidence namespace"]
fn validate_existing_release_evidence_artifact() {
    let namespace = PathBuf::from(
        std::env::var_os("OPC_QUAL_EVIDENCE_VALIDATE")
            .expect("OPC_QUAL_EVIDENCE_VALIDATE must name an existing namespace"),
    );
    validate_existing_release_evidence_namespace(&namespace)
        .expect("strictly validate existing release evidence without publishing");
    println!(
        "SDK702_RELEASE_EVIDENCE_VALIDATED namespace_path_id={}",
        redacted_path_id(
            &namespace
                .canonicalize()
                .expect("canonical validated namespace")
        )
    );
}

fn canonical_release_evidence_bytes(evidence: &ReleaseQualificationEvidence) -> Vec<u8> {
    validate_release_evidence(evidence).expect("typed release qualification evidence");
    let encoded = serde_json::to_vec(evidence).expect("serialize release qualification evidence");
    let decoded = strict_decode_release_evidence(&encoded)
        .expect("strictly decode canonical release qualification evidence");
    assert_eq!(
        decoded, *evidence,
        "typed evidence must survive exact byte round trip"
    );
    encoded
}

fn release_evidence_test_fixture() -> ReleaseQualificationEvidence {
    let phase = |name: &str, offered_ops_per_second: u64, operations: u64| ReleaseEvidencePhase {
        name: name.to_owned(),
        offered_ops_per_second,
        operations,
        elapsed_ms: operations.checked_mul(1_000).unwrap() / offered_ops_per_second,
        batch_samples: operations / QUALIFICATION_PACED_BATCH_OPERATIONS as u64,
        item_samples: operations,
        peak_unjoined_batch_task_slots: QUALIFICATION_IN_FLIGHT_CLIENTS as u64,
        batch_p99_us: 1,
        batch_p999_us: 1,
        batch_max_us: 1,
        item_p99_us: 1,
        item_p999_us: 1,
        item_max_us: 1,
    };
    ReleaseQualificationEvidence {
        version: 1,
        qualification_complete: true,
        elapsed_ms: (QUALIFICATION_SUSTAINED_TRANSITIONS as u64 * 1_000
            / QUALIFICATION_SUSTAINED_RATE as u64)
            + (QUALIFICATION_BURST_TRANSITIONS as u64 * 1_000 / QUALIFICATION_BURST_RATE as u64)
            + 1,
        non_phase_overhead_ms: 1,
        source: ReleaseEvidenceSource {
            build_revision: "a".repeat(40),
            build_tree: "b".repeat(40),
            source_worktree_sha256: "3".repeat(64),
            revision: "a".repeat(40),
            tree: "b".repeat(40),
            worktree: "clean".to_owned(),
        },
        build_cargo_lock_sha256: "c".repeat(64),
        runtime_cargo_lock_sha256: "c".repeat(64),
        required_reproduction_recipe: RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE.to_owned(),
        libtest_argv: RELEASE_EVIDENCE_LIBTEST_ARGS
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        artifact: ReleaseEvidenceArtifact {
            mechanism: "rustix_private_namespace_dirfd_noreplace_fsync".to_owned(),
            path_id: format!("sha256:{}", "e".repeat(64)),
            cooperative_same_uid_boundary: "private_mode_0700_namespace_no_shared_path_authority"
                .to_owned(),
        },
        execution: ReleaseEvidenceExecution {
            cargo_target_dir_id: format!("sha256:{}", "f".repeat(64)),
            fs_verity_snapshot_base_id: format!("sha256:{}", "6".repeat(64)),
            fs_verity_snapshot_root_id: format!("sha256:{}", "7".repeat(64)),
            fs_verity_snapshot_root_device: 1,
            fs_verity_snapshot_root_inode: 1,
            current_exe_relative_to_target_id: format!("sha256:{}", "0".repeat(64)),
            current_exe_sha256: "d".repeat(64),
            current_exe_device: 1,
            current_exe_inode: 1,
            compiled_schema_sha256: format!("{:x}", Sha256::digest(RELEASE_EVIDENCE_SCHEMA)),
            build_attestation_path_id: format!("sha256:{}", "4".repeat(64)),
            build_attestation_sha256: "5".repeat(64),
            build_attestation_wrapper_sha256: compiled_release_attestation_wrapper_sha256(),
            build_attestation_boundary: RELEASE_BUILD_ATTESTATION_KIND.to_owned(),
            target_os: "linux".to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
            target_env: qualification_target_environment().to_owned(),
            enabled_features: Vec::new(),
            runner_quiet_host_boundary: QUALIFICATION_QUIET_HOST_BOUNDARY.to_owned(),
        },
        quiet_host: ReleaseEvidenceQuietHost {
            boundary: QUALIFICATION_QUIET_HOST_BOUNDARY.to_owned(),
            cadence_ms: 250,
            maximum_sample_gap_us: 1,
            monitored_elapsed_ms: (QUALIFICATION_SUSTAINED_TRANSITIONS as u64 * 1_000
                / QUALIFICATION_SUSTAINED_RATE as u64)
                + (QUALIFICATION_BURST_TRANSITIONS as u64 * 1_000
                    / QUALIFICATION_BURST_RATE as u64)
                + 1,
            samples: 2,
            start_sampled: true,
            end_sampled: true,
        },
        process_loss: ReleaseEvidenceProcessLoss {
            scope: "external_session_testkit_multiprocess_mtls_only".to_owned(),
            companion_path_id: format!("sha256:{}", "1".repeat(64)),
            companion_sha256: "2".repeat(64),
            companion_schema_sha256: format!(
                "sha256:{:x}",
                Sha256::digest(PROCESS_LOSS_EVIDENCE_SCHEMA)
            ),
            companion_source_revision: "a".repeat(40),
            companion_source_tree: "b".repeat(40),
            companion_source_worktree_sha256: format!("sha256:{}", "3".repeat(64)),
            companion_v1_canonical_sha256: format!("sha256:{}", "6".repeat(64)),
            companion_invocation_argv_sha256: format!("sha256:{}", "7".repeat(64)),
            companion_harness_sha256: format!("sha256:{}", "8".repeat(64)),
            companion_child_sha256: format!("sha256:{}", "9".repeat(64)),
            companion_executable_sha256: format!("sha256:{}", "a".repeat(64)),
            strict_validation_command: process_loss_v9_reproduction_command(
                "/var/lib/opc-testkit/target",
                "/var/lib/opc-testkit/evidence",
                "/var/lib/opc-testkit/fs-verity-snapshots",
                "/usr/bin/cargo",
            )
            .expect("fixture V9 reproduction command"),
        },
        profile: ReleaseEvidenceProfile {
            cargo_profile_family: "release".to_owned(),
            cargo_opt_level: "3".to_owned(),
            debug_assertions: false,
        },
        schedule: ReleaseEvidenceSchedule {
            preload_operations: QUALIFICATION_SESSIONS as u64,
            sustained_operations: QUALIFICATION_SUSTAINED_TRANSITIONS as u64,
            sustained_rate_per_second: QUALIFICATION_SUSTAINED_RATE as u64,
            sustained_seconds: QUALIFICATION_SUSTAINED_SECONDS as u64,
            burst_operations: QUALIFICATION_BURST_TRANSITIONS as u64,
            burst_rate_per_second: QUALIFICATION_BURST_RATE as u64,
            burst_seconds: QUALIFICATION_BURST_SECONDS as u64,
            total_operations: QUALIFICATION_RELEASE_TRANSITIONS as u64,
        },
        resources: ReleaseEvidenceResources {
            voters: VOTERS as u64,
            in_flight_clients: QUALIFICATION_IN_FLIGHT_CLIENTS as u64,
            batch_deadline_ms: QUALIFICATION_RELEASE_BATCH_DEADLINE.as_millis() as u64,
            operational_headroom_transitions: QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS as u64,
            retained_envelope_headroom_transitions:
                QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS as u64,
            database_ceiling_bytes_per_voter: QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
            snapshot_ceiling_bytes_per_voter: QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
            process_peak_rss_ceiling_kib: qualification_process_peak_rss_ceiling_kib(),
            pre_reclaim_database_bytes_by_voter: vec![1; VOTERS],
            pre_reclaim_snapshot_bytes_by_voter: vec![1; VOTERS],
            post_reclaim_database_bytes_by_voter: vec![1; VOTERS],
            post_reclaim_snapshot_bytes_by_voter: vec![1; VOTERS],
            database_artifacts_by_voter: vec![1; VOTERS],
            snapshot_artifacts_by_voter: vec![1; VOTERS],
            peak_rss_kib: 1,
            peak_rss_measurement: "linux_proc_self_status_vmhwm_kib".to_owned(),
        },
        lifecycle: ReleaseEvidenceLifecycle {
            rotations: 7,
            graceful_same_process_engine_reopens: 1,
            logical_in_process_voters: VOTERS as u64,
            reclaim_batches: 2,
            reclaimed_entries: (2 * FENCED_TRANSITION_V2_RECLAIM_BATCH) as u64,
            reclaim_remaining: (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                - 2 * FENCED_TRANSITION_V2_RECLAIM_BATCH) as u64,
            maintenance_attempts: QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS,
            maintenance_elapsed_max_us: 1,
            maintenance_resolved_after_800ms: 0,
            maintenance_deadline_exceeded: 0,
            maintenance_failures: 0,
            production_maintenance_invocations: QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS,
            production_maintenance_ok: 9,
            production_maintenance_err: 1,
            post_commit_reply_loss_projections: 1,
            maintenance_readback_projections: 2,
        },
        outcomes: ReleaseEvidenceOutcomes {
            release_operations_committed: QUALIFICATION_RELEASE_TRANSITIONS as u64,
            matched_workload_outcomes: QUALIFICATION_RELEASE_TRANSITIONS as u64,
            reclaim_operations_committed: 1,
            matched_reclaim_outcomes: 1,
            total_operations_committed: (QUALIFICATION_RELEASE_TRANSITIONS + 1) as u64,
            // One post-commit reply-loss and one stale no-effect CAS each
            // require a linearized maintenance reconciliation readback.
            transient_exact_retries: 2,
            read_only_observation_retries: 0,
            maintenance_reconciliation_retries: 2,
            effect_not_transmitted_retries: 0,
        },
        effects: ReleaseEffectCounterSnapshot {
            mutation_batches: QUALIFICATION_EXPECTED_EFFECT_BATCHES,
            batch_elapsed_max_us: 1,
            resolved_after_deadline: 0,
            mutation_attempts: QUALIFICATION_EXPECTED_EFFECT_BATCHES,
            not_transmitted_retries: 0,
            outcome_unknown_batches: 0,
            effect_request_slots: QUALIFICATION_EXPECTED_EFFECT_REQUEST_SLOTS,
            outcome_unknown_request_slots: 0,
            status_attempts: 0,
            status_initial_request_slots: 0,
            status_retry_request_slots: 0,
            status_retry_rounds: 0,
            mutation_deadline_before_dispatch: 0,
            not_transmitted_deadline: 0,
            deadline_after_backoff: 0,
            status_deadline_before_dispatch: 0,
            status_deadline_timeout: 0,
        },
        phases: vec![
            phase(
                "sustained-500-per-second",
                QUALIFICATION_SUSTAINED_RATE as u64,
                QUALIFICATION_SUSTAINED_TRANSITIONS as u64,
            ),
            phase(
                "burst-1000-per-second",
                QUALIFICATION_BURST_RATE as u64,
                QUALIFICATION_BURST_TRANSITIONS as u64,
            ),
        ],
    }
}

fn process_loss_v9_test_fixture(source: &ReleaseEvidenceSource) -> ProcessLossCompanionEvidence {
    let authority = || ProcessLossCompanionAuthority {
        positive_observations: 1,
        negative_boundary_rejections: 1,
    };
    let lane =
        |lane: &str, transport_revision: u16, consumer_alpn: &str| ProcessLossCompanionLane {
            lane: lane.to_owned(),
            transport_revision,
            application_revision: 4,
            sdk_protocol_revision: 5,
            consumer_alpn: consumer_alpn.to_owned(),
            executed: true,
            admission_operations: 1,
            status_operations: 1,
            before_leader_loss_operations: 1,
            after_leader_loss_operations: 1,
            after_restart_operations: 1,
            after_voter_loss_operations: 1,
            tenant_authority: authority(),
            scope_authority: authority(),
            fence_authority: authority(),
        };
    ProcessLossCompanionEvidence {
        schema_version: "opc-session-ha-persistent-consumer-head-evidence/v9".to_owned(),
        evidence_kind: "persistent-consumer-executed-lanes".to_owned(),
        experimental: true,
        qualification_complete: true,
        provenance: ProcessLossCompanionProvenance {
            source_revision: source.revision.clone(),
            source_tree: source.tree.clone(),
            source_tree_status: "clean".to_owned(),
            source_worktree_sha256: format!("sha256:{}", source.source_worktree_sha256),
        },
        invocation: ProcessLossCompanionInvocation {
            test_id: "three_process_projected_mtls_persistent_v2_batch_release_gate".to_owned(),
            argv_sha256: format!("sha256:{}", "1".repeat(64)),
            run_id_sha256: format!("sha256:{}", "2".repeat(64)),
            cargo_executable_alias: "/usr/bin/cargo".to_owned(),
            cargo_executable: "/usr/bin/cargo".to_owned(),
            cargo_executable_sha256: format!("sha256:{}", "0".repeat(64)),
            cargo_executable_mode: 0o755,
            canonical_cargo_argv: PROCESS_LOSS_CANONICAL_CARGO_ARGV
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            reproduction_command: process_loss_v9_reproduction_command(
                "/var/lib/opc-testkit/target",
                "/var/lib/opc-testkit/evidence",
                "/var/lib/opc-testkit/fs-verity-snapshots",
                "/usr/bin/cargo",
            )
            .expect("fixture V9 reproduction command"),
        },
        bindings: ProcessLossCompanionBindings {
            v9_schema_sha256: PROCESS_LOSS_V9_SCHEMA_SHA256.to_owned(),
            harness_sha256: format!("sha256:{}", "3".repeat(64)),
            child_sha256: format!("sha256:{}", "4".repeat(64)),
            executable_sha256: format!("sha256:{}", "3".repeat(64)),
            v1_canonical_sha256: format!("sha256:{}", "5".repeat(64)),
            cargo_target_directory: "/var/lib/opc-testkit/target".to_owned(),
            cargo_target_directory_sha256: process_loss_path_commitment(
                b"opc-session-mtls-release-gate-cargo-target/v1\0",
                b"canonical-target-directory",
                "/var/lib/opc-testkit/target",
            )
            .expect("fixture target commitment"),
            evidence_root_directory: "/var/lib/opc-testkit/evidence".to_owned(),
            evidence_root_directory_sha256: process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-evidence-root/v1\0",
                b"canonical-evidence-root",
                "/var/lib/opc-testkit/evidence",
            )
            .expect("fixture root commitment"),
            fs_verity_snapshot_root_directory: "/var/lib/opc-testkit/fs-verity-snapshots"
                .to_owned(),
            fs_verity_snapshot_root_directory_sha256: process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-fs-verity-snapshot-root/v1\0",
                b"canonical-fs-verity-snapshot-root",
                "/var/lib/opc-testkit/fs-verity-snapshots",
            )
            .expect("fixture fs-verity snapshot-root commitment"),
            fs_verity_snapshot_root_device: 17,
            fs_verity_snapshot_root_inode: 19,
            pair_directory: "/var/lib/opc-testkit/evidence/session-ha-persistent-consumer-v9"
                .to_owned(),
            pair_directory_sha256: process_loss_path_commitment(
                b"opc-session-ha-persistent-consumer-v9-pair-directory/v1\0",
                b"canonical-pair-directory",
                "/var/lib/opc-testkit/evidence/session-ha-persistent-consumer-v9",
            )
            .expect("fixture pair commitment"),
        },
        process_ledger: ProcessLossCompanionProcessLedger {
            initial_processes: 3,
            unclean_process_losses: 2,
            restarted_processes: 1,
            observed_process_generations: 4,
            release_gate_process_generations: 4,
        },
        release_gate: ProcessLossCompanionReleaseGate {
            credential_rotation_executed: true,
            old_credential_rejected: true,
            new_credential_rejected: true,
            fixed_capacity_reclaimed: true,
            durable_status_cardinality: 12,
            post_outcome_unknown_mutation_dispatches: 0,
        },
        lanes: [
            lane("general", 6, "opc-session-consumer/1"),
            ProcessLossCompanionLane {
                tenant_authority: ProcessLossCompanionAuthority {
                    positive_observations: 1,
                    negative_boundary_rejections: 3,
                },
                ..lane("protected_roster", 5, "opc-session-consumer/3")
            },
        ],
        members: 3,
        authenticated_setup_successes: 48,
        warm_reused_calls: 1_000,
        fixed_labels_only: true,
        identifying_values_recorded: false,
    }
}

fn process_loss_v1_test_fixture(
    source: &ReleaseEvidenceSource,
    cargo_lock_sha256: String,
    command_argv_sha256: String,
    child_sha256: String,
    harness_sha256: String,
) -> serde_json::Value {
    let digest = |fill: char| format!("sha256:{}", fill.to_string().repeat(64));
    let pool = |role,
                setup_attempts,
                setup_failures,
                setup_successes,
                pool_wait_max,
                configured_lanes,
                active_lanes,
                idle_lanes| {
        serde_json::json!({
            "role": role,
            "setup_attempts": setup_attempts,
            "setup_failures": setup_failures,
            "setup_successes": setup_successes,
            "pool_wait_current": 0,
            "pool_wait_max": pool_wait_max,
            "configured_lanes": configured_lanes,
            "active_lanes": active_lanes,
            "idle_lanes": idle_lanes,
        })
    };
    let observation = |logical_voter_index| {
        serde_json::json!({
            "logical_voter_index": logical_voter_index,
            "warmed_file_descriptors": 20,
            "warmed_socket_file_descriptors": 8,
            "warmed_nontransport_file_descriptors": 12,
            "warmed_threads": 10,
            "warmed_vm_rss_kib": 1000,
            "warmed_vm_hwm_kib": 1200,
            "high_water_file_descriptors": 20,
            "high_water_threads": 10,
            "high_water_vm_rss_kib": 1000,
            "high_water_vm_hwm_kib": 1200,
            "settled_file_descriptors": 20,
            "settled_socket_file_descriptors": 8,
            "settled_threads": 10,
            "settled_vm_rss_kib": 1000,
            "settled_vm_hwm_kib": 1200,
            "high_water_file_descriptor_ceiling": 64,
            "settled_file_descriptor_ceiling": 24,
            "settled_socket_file_descriptor_ceiling": 12,
            "high_water_thread_ceiling": 18,
            "high_water_vm_hwm_ceiling_kib": 2048,
            "settled_vm_rss_ceiling_kib": 2048,
        })
    };
    let admission = |logical_voter_index| {
        let capacity_probe = logical_voter_index == 0;
        serde_json::json!({
            "logical_voter_index": logical_voter_index,
            "admission_limit": 20,
            "expected_peak_connections": 16,
            "active_connections": 16,
            "high_water_connections": if capacity_probe { 20 } else { 17 },
            "normal_headroom_high_water_connections": 17,
            "capacity_probe_high_water_connections": if capacity_probe { 20 } else { 0 },
            "capacity_probe_exercised": capacity_probe,
            "capacity_probe_admission_waits": 0,
            "capacity_probe_admission_rejections": if capacity_probe { 1 } else { 0 },
            "capacity_probe_typed_rejection": capacity_probe,
            "admission_waits": 0,
            "admission_rejections": if capacity_probe { 1 } else { 0 },
            "samples": 1,
            "listener_available": true,
        })
    };
    serde_json::json!({
        "schema_version": "opc-session-mtls-batch-release-gate-evidence/v1",
        "experimental": true,
        "qualification_complete": false,
        "cargo_profile": "release",
        "opt_level": "3",
        "debug_assertions": false,
        "foundation_insecure": false,
        "bindings": {
            "evidence_schema_sha256": digest('1'),
            "configuration_sha256": digest('2'),
            "public_material_manifest_sha256": digest('3'),
            "workload_schedule_sha256": digest('4'),
            "source_revision": source.revision,
            "source_tree": source.tree,
            "source_tree_status": "clean",
            "source_worktree_sha256": format!("sha256:{}", source.source_worktree_sha256),
            "cargo_lock_sha256": cargo_lock_sha256,
            "command_argv_sha256": command_argv_sha256,
            "child_sha256": child_sha256,
            "harness_sha256": harness_sha256,
        },
        "members": 3,
        "clients": 12,
        "lanes_per_client": 4,
        "logical_operations_per_second": 1000,
        "warm_status_samples": 1008,
        "warm_status_request_cardinality": 1008,
        "warm_status_request_index_min": 1,
        "warm_status_request_index_max": 49980,
        "warm_status_request_stride": 53,
        "active_history_entries": 110025,
        "normal_configured_lanes": 48,
        "normal_active_lanes": 48,
        "normal_idle_lanes": 48,
        "original_fixed_pools": pool("original_fixed_pools", 48, 0, 48, 2, 48, 48, 48),
        "supplemental_pools": [
            pool("old_credential_new_only_server", 1, 1, 0, 0, 1, 0, 0),
            pool("delayed_response_ambiguity", 4, 0, 4, 64, 4, 0, 0),
            pool("new_credential_old_root_server", 1, 1, 0, 0, 1, 0, 0),
        ],
        "aggregate_setup_attempts": 54,
        "aggregate_setup_failures": 2,
        "aggregate_setup_successes": 52,
        "restarted_voter_index": 0,
        "capacity_probe_voter_index": 0,
        "capacity_probe_overall_admission_waits": 0,
        "capacity_probe_overall_admission_rejections": 1,
        "preload_recovered_unknown": 0,
        "preload_not_transmitted_retries": 0,
        "preload_not_transmitted_retry_high_water": 0,
        "paced_not_transmitted_retries": 0,
        "paced_not_transmitted_retry_high_water": 0,
        "pressure_not_transmitted_retries": 0,
        "pressure_not_transmitted_retry_high_water": 0,
        "preload_status_attempts_total": 0,
        "preload_status_terminal_attempts": 0,
        "preload_status_retries_total": 0,
        "preload_status_not_found_retries": 0,
        "preload_status_not_transmitted_retries": 0,
        "preload_status_read_unavailable_retries": 0,
        "preload_status_typed_unavailable_retries": 0,
        "status_retries_total": 1,
        "status_attempts_total": 13,
        "status_attempts_high_water": 13,
        "status_terminal_attempts": 12,
        "status_retries_high_water": 1,
        "status_not_found_retries": 1,
        "status_not_transmitted_retries": 0,
        "status_read_unavailable_retries": 0,
        "status_typed_unavailable_retries": 0,
        "aggregate_pool_wait_max": 64,
        "resource_generations": [
            {"logical_voter_index": 0, "generation_ordinal": 0, "process_id": 11, "samples": 1},
            {"logical_voter_index": 0, "generation_ordinal": 1, "process_id": 12, "samples": 1},
            {"logical_voter_index": 1, "generation_ordinal": 0, "process_id": 13, "samples": 1},
            {"logical_voter_index": 2, "generation_ordinal": 0, "process_id": 14, "samples": 1},
        ],
        "resource_observations": [observation(0), observation(1), observation(2)],
        "server_admissions": [admission(0), admission(1), admission(2)],
        "paced_operations": 60000,
        "paced_elapsed_nanos": 60000000000_u64,
        "achieved_logical_operations_per_second_milli": 1000000,
        "mutation_batch_samples": 5000,
        "warm_read_p99_millis": 25,
        "warm_read_p999_millis": 100,
        "mutation_p99_millis": 25,
        "mutation_p999_millis": 100,
        "saturated_client_skips": 1,
        "slow_lane_completed_batches": 1,
        "over_capacity_typed_backpressure_events": 1,
        "held_response_count": 5,
        "causal_held_response_count": 1,
        "queued_caller_count": 64,
        "cross_client_fair_progress": 1,
        "released_response_count": 5,
        "recovered_queued_caller_count": 64,
        "durable_status_cardinality": 12,
        "post_outcome_unknown_mutation_dispatches": 0,
        "not_transmitted_retries": 0,
        "recovered_unknown": 1,
        "server_queue_depth_measured": false,
        "server_queue_depth_scope": "downstream",
        "positive_new_credential_new_server_statuses": 4,
        "old_credential_new_only_server_tls_peer_credential_rejected": true,
        "new_credential_old_root_server_tls_peer_credential_rejected": true,
    })
}

fn process_loss_exact_pair_test_fixture(
    workspace: &Path,
) -> (
    ReleaseEvidenceProvenance,
    PathBuf,
    PathBuf,
    Vec<u8>,
    ProcessLossCompanionEvidence,
) {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let wrapper_target = workspace.join("store-wrapper-target");
    let producer_target = workspace.join("testkit-producer-target");
    let evidence_root = workspace.join("testkit-evidence-root");
    let snapshot_root = workspace.join("testkit-fs-verity-snapshots");
    let pair_directory = evidence_root.join(PROCESS_LOSS_V9_PAIR_DIRECTORY);
    let backing = workspace.join("rustup-cargo-backing");
    let alias = workspace.join("cargo");
    std::fs::create_dir(&wrapper_target).expect("create wrapper target");
    std::fs::create_dir(&producer_target).expect("create producer target");
    std::fs::create_dir(&evidence_root).expect("create producer evidence root");
    std::fs::create_dir(&snapshot_root).expect("create producer fs-verity snapshot root");
    std::fs::set_permissions(&snapshot_root, std::fs::Permissions::from_mode(0o700))
        .expect("make producer fs-verity snapshot root private");
    std::fs::create_dir(&pair_directory).expect("create producer pair directory");
    std::fs::set_permissions(&pair_directory, std::fs::Permissions::from_mode(0o700))
        .expect("make producer pair directory private");
    std::fs::write(&backing, b"test rustup cargo backing").expect("write Cargo backing");
    std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o700))
        .expect("make Cargo backing executable");
    symlink(&backing, &alias).expect("create rustup-style Cargo alias");

    let expected = release_build_attestation_test_provenance();
    let mut v9 = process_loss_v9_test_fixture(&expected.source);
    let canonical = |path: &Path| {
        path.canonicalize()
            .expect("canonical test path")
            .to_string_lossy()
            .into_owned()
    };
    let producer_target_text = canonical(&producer_target);
    let evidence_root_text = canonical(&evidence_root);
    let snapshot_root_text = canonical(&snapshot_root);
    let pair_directory_text = canonical(&pair_directory);
    v9.bindings.cargo_target_directory = producer_target_text.clone();
    v9.bindings.cargo_target_directory_sha256 = process_loss_path_commitment(
        b"opc-session-mtls-release-gate-cargo-target/v1\0",
        b"canonical-target-directory",
        &producer_target_text,
    )
    .expect("producer target commitment");
    v9.bindings.evidence_root_directory = evidence_root_text.clone();
    v9.bindings.evidence_root_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-evidence-root/v1\0",
        b"canonical-evidence-root",
        &evidence_root_text,
    )
    .expect("producer root commitment");
    v9.bindings.fs_verity_snapshot_root_directory = snapshot_root_text.clone();
    v9.bindings.fs_verity_snapshot_root_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-fs-verity-snapshot-root/v1\0",
        b"canonical-fs-verity-snapshot-root",
        &snapshot_root_text,
    )
    .expect("producer fs-verity snapshot-root commitment");
    let snapshot_metadata = std::fs::metadata(&snapshot_root).expect("stat producer snapshot root");
    v9.bindings.fs_verity_snapshot_root_device = snapshot_metadata.dev();
    v9.bindings.fs_verity_snapshot_root_inode = snapshot_metadata.ino();
    v9.bindings.pair_directory = pair_directory_text.clone();
    v9.bindings.pair_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-pair-directory/v1\0",
        b"canonical-pair-directory",
        &pair_directory_text,
    )
    .expect("producer pair commitment");
    v9.invocation.cargo_executable_alias = alias
        .to_str()
        .expect("absolute rustup-style alias path is UTF-8")
        .to_owned();
    v9.invocation.cargo_executable = canonical(&backing);
    v9.invocation.cargo_executable_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(&backing).expect("read Cargo backing"))
    );
    v9.invocation.cargo_executable_mode = 0o700;
    v9.invocation.reproduction_command = process_loss_v9_reproduction_command(
        &producer_target_text,
        &evidence_root_text,
        &snapshot_root_text,
        &v9.invocation.cargo_executable_alias,
    )
    .expect("producer-rendered alias recipe");

    let v1 = process_loss_v1_test_fixture(
        &expected.source,
        format!("sha256:{}", expected.runtime_cargo_lock_sha256),
        process_loss_command_argv_sha256(&v9).expect("V1 command binding"),
        v9.bindings.child_sha256.clone(),
        v9.bindings.harness_sha256.clone(),
    );
    let v1_encoded = serde_json::to_vec(&v1).expect("canonical V1 pair fixture");
    v9.bindings.v1_canonical_sha256 = format!("sha256:{:x}", Sha256::digest(&v1_encoded));
    v9.invocation.run_id_sha256 =
        v1_v9_pair_run_id(&v1, &v1_encoded, &v9).expect("producer-compatible pair run ID");
    (expected, wrapper_target, pair_directory, v1_encoded, v9)
}

#[test]
fn strict_decode_process_loss_pair_uses_the_rustup_alias_and_distinct_producer_target() {
    let workspace = tempfile::tempdir().expect("strict pair alias workspace");
    let (expected, wrapper_target, pair_directory, v1_encoded, v9) =
        process_loss_exact_pair_test_fixture(workspace.path());
    let v9_encoded = serde_json::to_vec(&v9).expect("canonical V9 pair fixture");
    assert_eq!(
        strict_decode_process_loss_pair(
            &v1_encoded,
            &v9_encoded,
            &expected,
            &wrapper_target,
            &pair_directory,
        ),
        Ok(v9.clone()),
        "the exact pair accepts the producer-rendered recipe through its rustup-style alias"
    );

    let mut backing_recipe = v9;
    backing_recipe.invocation.reproduction_command = process_loss_v9_reproduction_command(
        &backing_recipe.bindings.cargo_target_directory,
        &backing_recipe.bindings.evidence_root_directory,
        &backing_recipe.bindings.fs_verity_snapshot_root_directory,
        &backing_recipe.invocation.cargo_executable,
    )
    .expect("backing-rendered recipe");
    backing_recipe.invocation.run_id_sha256 = v1_v9_pair_run_id(
        &serde_json::from_slice(&v1_encoded).unwrap(),
        &v1_encoded,
        &backing_recipe,
    )
    .expect("run ID for rejected backing recipe");
    assert!(
        strict_decode_process_loss_pair(
            &v1_encoded,
            &serde_json::to_vec(&backing_recipe).unwrap(),
            &expected,
            &wrapper_target,
            &pair_directory,
        )
        .is_err(),
        "the canonical backing spelling cannot replace the producer alias in a full strict pair"
    );
}

#[test]
fn strict_decode_process_loss_pair_rejects_a_self_consistent_v9_generation_contradiction() {
    let workspace = tempfile::tempdir().expect("strict pair generation contradiction workspace");
    let (expected, wrapper_target, pair_directory, v1_encoded, mut v9) =
        process_loss_exact_pair_test_fixture(workspace.path());
    let v1 = strict_decode_process_loss_v1(&v1_encoded).expect("canonical V1 pair fixture");
    let v1_generation_count = u8::try_from(
        v1.get("resource_generations")
            .and_then(serde_json::Value::as_array)
            .expect("V1 resource generations")
            .len(),
    )
    .expect("V1 resource generation count fits V9 field");
    v9.process_ledger.release_gate_process_generations = v1_generation_count + 1;
    v9.invocation.run_id_sha256 =
        v1_v9_pair_run_id(&v1, &v1_encoded, &v9).expect("self-consistent mutated V9 run ID");
    let v9_encoded = serde_json::to_vec(&v9).expect("canonical self-consistent V9 contradiction");
    assert_eq!(
        strict_decode_process_loss_companion(&v9_encoded, &expected.source),
        Ok(v9.clone()),
        "the altered V9 claims and recomputed run ID remain internally valid"
    );
    assert_eq!(
        v9.invocation.run_id_sha256,
        v1_v9_pair_run_id(&v1, &v1_encoded, &v9).expect("recheck mutated V9 run ID"),
        "the pair digest binds the recomputed canonical V9 claims preimage"
    );
    assert!(
        strict_decode_process_loss_pair(
            &v1_encoded,
            &v9_encoded,
            &expected,
            &wrapper_target,
            &pair_directory,
        )
        .is_err(),
        "the consumer rejects a V9 generation count that contradicts canonical V1"
    );
}

#[test]
fn strict_process_loss_pair_target_topology_rejects_wrapper_target_overlap_before_mkdir() {
    let workspace = tempfile::tempdir().expect("strict pair target topology workspace");
    let (expected, wrapper_target, pair_directory, _, v9) =
        process_loss_exact_pair_test_fixture(workspace.path());
    let evidence_root = pair_directory.parent().expect("pair root");
    assert!(strict_process_loss_pair_target_topology(
        &v9,
        &expected,
        &wrapper_target,
        &pair_directory,
        evidence_root,
    )
    .is_ok());
    std::fs::create_dir(PathBuf::from(&v9.bindings.cargo_target_directory).join("nested-wrapper"))
        .expect("create nested wrapper target");
    for overlapping_wrapper_target in [
        PathBuf::from(&v9.bindings.cargo_target_directory),
        PathBuf::from(&v9.bindings.cargo_target_directory).join("nested-wrapper"),
        PathBuf::from(&v9.bindings.cargo_target_directory)
            .parent()
            .expect("producer target parent")
            .to_path_buf(),
    ] {
        assert_eq!(
            strict_process_loss_pair_target_topology(
                &v9,
                &expected,
                &overlapping_wrapper_target,
                &pair_directory,
                evidence_root,
            ),
            Err("V9 producer Cargo target overlaps the wrapper Cargo target"),
        );
    }
    let absent_namespace = workspace.path().join("must-remain-absent");
    assert!(
        !absent_namespace.exists(),
        "target topology validation creates no publisher residue before mkdir"
    );
}

#[test]
fn process_loss_companion_rejects_incomplete_schema_source_and_shape_only_pairs() {
    let source = release_evidence_test_fixture().source;
    let evidence = process_loss_v9_test_fixture(&source);
    let encoded = serde_json::to_vec(&evidence).expect("canonical V9 fixture");
    assert_eq!(
        strict_decode_process_loss_companion(&encoded, &source),
        Ok(evidence.clone())
    );

    let mut incomplete = evidence.clone();
    incomplete.qualification_complete = false;
    assert!(strict_decode_process_loss_companion(
        &serde_json::to_vec(&incomplete).unwrap(),
        &source,
    )
    .is_err());
    let mut wrong_schema = evidence.clone();
    wrong_schema.bindings.v9_schema_sha256 = format!("sha256:{}", "f".repeat(64));
    assert!(strict_decode_process_loss_companion(
        &serde_json::to_vec(&wrong_schema).unwrap(),
        &source,
    )
    .is_err());
    let mut wrong_tree = evidence.clone();
    wrong_tree.provenance.source_tree = "f".repeat(40);
    assert!(strict_decode_process_loss_companion(
        &serde_json::to_vec(&wrong_tree).unwrap(),
        &source,
    )
    .is_err());
    let mut wrong_worktree = evidence.clone();
    wrong_worktree.provenance.source_worktree_sha256 = format!("sha256:{}", "f".repeat(64));
    assert!(strict_decode_process_loss_companion(
        &serde_json::to_vec(&wrong_worktree).unwrap(),
        &source,
    )
    .is_err());
    assert!(
        strict_decode_process_loss_pair(
            b"{}",
            &encoded,
            &release_build_attestation_test_provenance(),
            Path::new("/"),
            Path::new("/"),
        )
        .is_err(),
        "a canonical-looking V9 alone cannot replace its strict V1 pair"
    );
}

#[test]
fn process_loss_companion_accepts_the_mirrored_128_kib_v9_envelope() {
    let escaped_path = |label: &str| format!("/{label}{}", "\\".repeat(2_990));
    let source = release_evidence_test_fixture().source;
    let mut evidence = process_loss_v9_test_fixture(&source);
    evidence.bindings.cargo_target_directory = escaped_path("target");
    evidence.bindings.cargo_target_directory_sha256 = process_loss_path_commitment(
        b"opc-session-mtls-release-gate-cargo-target/v1\0",
        b"canonical-target-directory",
        &evidence.bindings.cargo_target_directory,
    )
    .expect("commit escaped target path");
    evidence.bindings.evidence_root_directory = escaped_path("evidence");
    evidence.bindings.evidence_root_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-evidence-root/v1\0",
        b"canonical-evidence-root",
        &evidence.bindings.evidence_root_directory,
    )
    .expect("commit escaped evidence root");
    evidence.bindings.fs_verity_snapshot_root_directory = escaped_path("snapshots");
    evidence.bindings.fs_verity_snapshot_root_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-fs-verity-snapshot-root/v1\0",
        b"canonical-fs-verity-snapshot-root",
        &evidence.bindings.fs_verity_snapshot_root_directory,
    )
    .expect("commit escaped snapshot root");
    evidence.bindings.pair_directory = format!(
        "{}/{}",
        evidence.bindings.evidence_root_directory, PROCESS_LOSS_V9_PAIR_DIRECTORY
    );
    evidence.bindings.pair_directory_sha256 = process_loss_path_commitment(
        b"opc-session-ha-persistent-consumer-v9-pair-directory/v1\0",
        b"canonical-pair-directory",
        &evidence.bindings.pair_directory,
    )
    .expect("commit escaped pair directory");
    evidence.invocation.cargo_executable_alias = escaped_path("cargo");
    evidence.invocation.cargo_executable = escaped_path("rustup");
    evidence.invocation.reproduction_command = process_loss_v9_reproduction_command(
        &evidence.bindings.cargo_target_directory,
        &evidence.bindings.evidence_root_directory,
        &evidence.bindings.fs_verity_snapshot_root_directory,
        &evidence.invocation.cargo_executable_alias,
    )
    .expect("regenerate escaped V9 command");

    let encoded = serde_json::to_vec(&evidence).expect("encode escaped V9 evidence");
    assert!(
        encoded.len() > 64 * 1024,
        "the fixture causally exceeds the retired store-consumer boundary"
    );
    assert!(encoded.len() <= PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES);
    assert_eq!(
        strict_decode_process_loss_companion(&encoded, &source),
        Ok(evidence)
    );
    assert!(strict_decode_process_loss_companion(
        &vec![b' '; PROCESS_LOSS_V9_EVIDENCE_MAX_BYTES + 1],
        &source,
    )
    .is_err());
    assert!(
        strict_decode_process_loss_v1(&vec![b' '; PROCESS_LOSS_V1_EVIDENCE_MAX_BYTES + 1]).is_err()
    );
}

#[test]
fn process_loss_v9_rejects_target_root_pair_recipe_and_argv_mutations() {
    let source = release_evidence_test_fixture().source;
    let evidence = process_loss_v9_test_fixture(&source);
    assert!(strict_decode_process_loss_companion(
        &serde_json::to_vec(&evidence).expect("canonical V9 baseline"),
        &source,
    )
    .is_ok());

    let mut target = evidence.clone();
    target.bindings.cargo_target_directory = "/var/lib/opc-testkit/replaced-target".to_owned();
    assert!(
        strict_decode_process_loss_companion(&serde_json::to_vec(&target).unwrap(), &source)
            .is_err()
    );

    let mut root = evidence.clone();
    root.bindings.evidence_root_directory = "/var/lib/opc-testkit/replaced-evidence".to_owned();
    assert!(
        strict_decode_process_loss_companion(&serde_json::to_vec(&root).unwrap(), &source).is_err()
    );

    let mut pair = evidence.clone();
    pair.bindings.pair_directory = "/var/lib/opc-testkit/replaced-pair".to_owned();
    assert!(
        strict_decode_process_loss_companion(&serde_json::to_vec(&pair).unwrap(), &source).is_err()
    );

    let mut recipe = evidence.clone();
    recipe.invocation.reproduction_command.push(' ');
    assert!(
        strict_decode_process_loss_companion(&serde_json::to_vec(&recipe).unwrap(), &source)
            .is_err()
    );

    let mut alias = evidence.clone();
    alias.invocation.cargo_executable_alias = "/usr/bin/replaced-cargo".to_owned();
    assert!(
        strict_decode_process_loss_companion(&serde_json::to_vec(&alias).unwrap(), &source)
            .is_err()
    );

    let mut backing_digest = evidence.clone();
    backing_digest.invocation.cargo_executable_sha256 = format!("sha256:{}", "f".repeat(64));
    assert!(strict_decode_process_loss_companion(
        &serde_json::to_vec(&backing_digest).unwrap(),
        &source,
    )
    .is_ok(), "the digest shape is structurally valid; its live and V1 command binding are checked when consuming the pair");

    let mut non_executable_mode = evidence.clone();
    non_executable_mode.invocation.cargo_executable_mode = 0o600;
    assert!(
        strict_decode_process_loss_companion(
            &serde_json::to_vec(&non_executable_mode).unwrap(),
            &source,
        )
        .is_err(),
        "the typed V9 contract rejects a backing mode without execute permission"
    );

    let mut argv = evidence;
    argv.invocation.canonical_cargo_argv.swap(0, 1);
    assert!(
        strict_decode_process_loss_companion(&serde_json::to_vec(&argv).unwrap(), &source).is_err()
    );
}

#[test]
fn process_loss_v9_recipe_quotes_apostrophe_semicolon_and_substitution_paths() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let workspace = tempfile::tempdir().expect("store V9 shell-recipe workspace");
    let marker = workspace.path().join("must-not-exist");
    let injection = "'$(touch $RECIPE_MARKER);semicolon";
    let target = workspace.path().join(format!("target{injection}"));
    let root = workspace.path().join(format!("evidence{injection}"));
    let snapshot_root = workspace.path().join(format!("snapshots{injection}"));
    let backing = workspace.path().join("rustup-backing");
    let alias = workspace.path().join(format!("cargo{injection}"));
    let recorded = workspace.path().join("recorded-arguments");
    std::fs::create_dir(&target).expect("create quoted target path");
    std::fs::create_dir(&root).expect("create quoted evidence root");
    std::fs::create_dir(&snapshot_root).expect("create quoted snapshot root");
    std::fs::write(
        &backing,
        "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$CARGO\" \"$CARGO_TARGET_DIR\" \"$OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY\" \"$OPC_FS_VERITY_QUALIFICATION\" \"$OPC_FS_VERITY_SNAPSHOT_ROOT\" \"$@\" > \"$RECIPE_RECORD\"\n",
    )
    .expect("write quoted Cargo backing script");
    std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o700))
        .expect("make quoted Cargo backing executable");
    symlink(&backing, &alias).expect("create quoted Cargo alias symlink");

    let alias_text = alias.to_str().expect("quoted alias UTF-8");
    let target_text = target.to_str().expect("quoted target UTF-8");
    let root_text = root.to_str().expect("quoted root UTF-8");
    let snapshot_root_text = snapshot_root.to_str().expect("quoted snapshot root UTF-8");
    let recipe = process_loss_v9_reproduction_command(
        target_text,
        root_text,
        snapshot_root_text,
        alias_text,
    )
    .expect("render shell-safe V9 recipe");
    assert!(Command::new("/bin/sh")
        .arg("-c")
        .arg(&recipe)
        .env("RECIPE_MARKER", &marker)
        .env("RECIPE_RECORD", &recorded)
        .status()
        .expect("execute V9 recipe through POSIX shell")
        .success());
    assert!(
        !marker.exists(),
        "the apostrophe/semicolon/substitution-like paths cannot execute a side effect"
    );
    let observed = String::from_utf8(std::fs::read(&recorded).expect("read argument record"))
        .expect("argument record UTF-8")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let expected = std::iter::once(alias_text.to_owned())
        .chain([
            alias_text.to_owned(),
            target_text.to_owned(),
            root_text.to_owned(),
            "required".to_owned(),
            snapshot_root_text.to_owned(),
        ])
        .chain(
            PROCESS_LOSS_CANONICAL_CARGO_ARGV
                .iter()
                .skip(1)
                .map(|argument| (*argument).to_owned()),
        )
        .collect::<Vec<_>>();
    assert_eq!(
        observed, expected,
        "the replay executes the alias exactly once"
    );
    assert!(process_loss_v9_reproduction_command(
        "/tmp/cargo\n",
        "/tmp/root",
        "/tmp/snapshots",
        "/tmp/cargo"
    )
    .is_err());
}

#[test]
fn process_loss_v9_alias_binds_rustup_style_spelling_backing_and_digest() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let workspace = tempfile::tempdir().expect("store V9 Cargo alias workspace");
    let backing = workspace.path().join("rustup-backing");
    let replacement = workspace.path().join("fake-rustup-backing");
    let alias = workspace.path().join("cargo");
    std::fs::write(&backing, b"real rustup backing").expect("write backing");
    std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o700))
        .expect("make backing executable");
    std::fs::write(&replacement, b"replacement rustup backing").expect("write replacement");
    symlink(&backing, &alias).expect("create rustup-style Cargo alias");
    let source = release_evidence_test_fixture().source;
    let mut invocation = process_loss_v9_test_fixture(&source).invocation;
    invocation.cargo_executable_alias = alias.to_string_lossy().into_owned();
    invocation.cargo_executable = backing
        .canonicalize()
        .expect("canonical backing")
        .to_string_lossy()
        .into_owned();
    invocation.cargo_executable_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(&backing).expect("read backing"))
    );
    invocation.cargo_executable_mode = 0o700;
    assert!(verify_live_process_loss_cargo_alias(&invocation).is_ok());
    std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o600))
        .expect("remove backing execute bits");
    assert!(
        verify_live_process_loss_cargo_alias(&invocation).is_err(),
        "a non-executable backing cannot retain a recorded executable mode"
    );
    std::fs::set_permissions(&backing, std::fs::Permissions::from_mode(0o700))
        .expect("restore backing execute bits");
    std::fs::remove_file(&alias).expect("remove alias before replacement");
    symlink(&replacement, &alias).expect("replace alias backing");
    assert!(
        verify_live_process_loss_cargo_alias(&invocation).is_err(),
        "a backing executable cannot be replayed as the recorded rustup-style alias"
    );
    std::fs::remove_file(&alias).expect("remove replaced alias before race fixture");
    symlink(&backing, &alias).expect("restore rustup-style Cargo alias");
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755))
        .expect("make replacement executable with a distinct mode");
    assert!(
        verify_live_process_loss_cargo_alias_with_seam(
            &invocation,
            Some(&|| {
                std::fs::rename(&replacement, &backing)
                    .expect("atomically replace backing after descriptor open");
            }),
        )
        .is_err(),
        "an A-to-B Cargo backing mode/content replacement is rejected after descriptor pinning"
    );
}

#[test]
fn process_loss_v9_run_id_binds_namespace_recipe_and_argv_material() {
    let source = release_evidence_test_fixture().source;
    let v1 = serde_json::json!({
        "cargo_profile": "release",
        "opt_level": "3",
        "bindings": {
            "source_revision": source.revision,
            "source_tree": source.tree,
            "source_worktree_sha256": format!("sha256:{}", source.source_worktree_sha256),
            "cargo_lock_sha256": format!("sha256:{}", "c".repeat(64)),
            "command_argv_sha256": format!("sha256:{}", "d".repeat(64)),
            "evidence_schema_sha256": format!("sha256:{}", "1".repeat(64)),
            "configuration_sha256": format!("sha256:{}", "2".repeat(64)),
            "public_material_manifest_sha256": format!("sha256:{}", "3".repeat(64)),
            "workload_schedule_sha256": format!("sha256:{}", "4".repeat(64)),
            "child_sha256": format!("sha256:{}", "5".repeat(64)),
            "harness_sha256": format!("sha256:{}", "6".repeat(64)),
        },
    });
    let v1_canonical = serde_json::to_vec(&v1).expect("synthetic V1 run-id material");
    let baseline = process_loss_v9_test_fixture(&source);
    let run_id = v1_v9_pair_run_id(&v1, &v1_canonical, &baseline)
        .expect("construct producer-compatible V2 run ID");
    for mutate in [
        |v9: &mut ProcessLossCompanionEvidence| {
            v9.bindings.cargo_target_directory.push_str("-replacement")
        },
        |v9: &mut ProcessLossCompanionEvidence| {
            v9.bindings.evidence_root_directory.push_str("-replacement")
        },
        |v9: &mut ProcessLossCompanionEvidence| v9.bindings.pair_directory.push_str("-replacement"),
        |v9: &mut ProcessLossCompanionEvidence| v9.invocation.reproduction_command.push(' '),
        |v9: &mut ProcessLossCompanionEvidence| {
            v9.invocation
                .cargo_executable_alias
                .push_str("-replacement")
        },
        |v9: &mut ProcessLossCompanionEvidence| {
            v9.invocation.cargo_executable_sha256 = format!("sha256:{}", "f".repeat(64))
        },
        |v9: &mut ProcessLossCompanionEvidence| v9.invocation.cargo_executable_mode = 0o700,
        |v9: &mut ProcessLossCompanionEvidence| v9.warm_reused_calls += 1,
        |v9: &mut ProcessLossCompanionEvidence| {
            v9.lanes[0].tenant_authority.positive_observations += 1
        },
        |v9: &mut ProcessLossCompanionEvidence| v9.invocation.canonical_cargo_argv.swap(0, 1),
    ] {
        let mut replaced = baseline.clone();
        mutate(&mut replaced);
        assert_ne!(
            v1_v9_pair_run_id(&v1, &v1_canonical, &replaced).expect("mutated V2 run ID material"),
            run_id,
            "the V4 run ID binds executable mode and every canonical V9 claims-preimage mutation"
        );
    }
}

#[test]
fn process_loss_v1_canonical_bytes_are_required_before_pair_digesting() {
    assert_eq!(
        strict_decode_canonical_json_value(b"{\"v1\":true}", 64, "V1 canonical seam"),
        Ok(serde_json::json!({"v1": true}))
    );
    assert!(
        strict_decode_canonical_json_value(b" {\"v1\":true}", 64, "V1 whitespace seam").is_err(),
        "V1 whitespace is rejected before any pair digest can use the raw bytes"
    );
    assert!(
        strict_decode_canonical_json_value(
            b"{\"v1\":true,\"v1\":true}",
            64,
            "V1 duplicate-key seam",
        )
        .is_err(),
        "a duplicate V1 key cannot survive canonical re-encoding, even though Value is last-wins"
    );
    assert!(
        strict_decode_process_loss_v1(b"{}").is_err(),
        "the frozen V1 closed schema rejects an incomplete or unknown-field-only document"
    );
}

fn release_build_attestation_test_provenance() -> ReleaseEvidenceProvenance {
    ReleaseEvidenceProvenance {
        source: ReleaseEvidenceSource {
            build_revision: "a".repeat(40),
            build_tree: "b".repeat(40),
            source_worktree_sha256: "c".repeat(64),
            revision: "a".repeat(40),
            tree: "b".repeat(40),
            worktree: "clean".to_owned(),
        },
        build_cargo_lock_sha256: "d".repeat(64),
        runtime_cargo_lock_sha256: "d".repeat(64),
        compiled_schema_sha256: format!("{:x}", Sha256::digest(RELEASE_EVIDENCE_SCHEMA)),
        canonical_gitdir: PathBuf::from("/test-only-gitdir"),
        canonical_common_gitdir: PathBuf::from("/test-only-common-gitdir"),
    }
}

fn release_build_attestation_test_fixture(target_dir: &Path) -> ReleaseBuildAttestation {
    let provenance = release_build_attestation_test_provenance();
    ReleaseBuildAttestation {
        kind: RELEASE_BUILD_ATTESTATION_KIND.to_owned(),
        source_revision: provenance.source.revision,
        source_tree: provenance.source.tree,
        source_worktree_sha256: provenance.source.source_worktree_sha256,
        cargo_lock_sha256: provenance.runtime_cargo_lock_sha256,
        release_schema_sha256: provenance.compiled_schema_sha256,
        cargo_target_dir_id: redacted_path_id(target_dir),
        fs_verity_snapshot_base_id: format!("sha256:{}", "a".repeat(64)),
        fs_verity_snapshot_root_id: format!("sha256:{}", "b".repeat(64)),
        fs_verity_snapshot_root_device: 13,
        fs_verity_snapshot_root_inode: 14,
        executable_sha256: "e".repeat(64),
        executable_device: 11,
        executable_inode: 12,
        wrapper_sha256: compiled_release_attestation_wrapper_sha256(),
        observed_libtest_argv: RELEASE_EVIDENCE_LIBTEST_ARGS
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
        required_reproduction_recipe: RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE.to_owned(),
    }
}

#[test]
fn release_build_attestation_rejects_stale_schema_and_executable_tampering() {
    let target = tempfile::tempdir().expect("test target directory");
    let provenance = release_build_attestation_test_provenance();
    let argv = RELEASE_EVIDENCE_LIBTEST_ARGS
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let attestation = release_build_attestation_test_fixture(target.path());
    assert!(validate_release_build_attestation(
        &attestation,
        &provenance,
        target.path(),
        &"e".repeat(64),
        EvidenceArtifactIdentity {
            device: 11,
            inode: 12,
            size: 1,
        },
        &argv,
    )
    .is_ok());
    let mut stale_schema = attestation.clone();
    stale_schema.release_schema_sha256 = "f".repeat(64);
    assert!(validate_release_build_attestation(
        &stale_schema,
        &provenance,
        target.path(),
        &"e".repeat(64),
        EvidenceArtifactIdentity {
            device: 11,
            inode: 12,
            size: 1,
        },
        &argv,
    )
    .is_err());
    let mut stale_manifest = attestation.clone();
    stale_manifest.source_worktree_sha256 = "f".repeat(64);
    assert!(validate_release_build_attestation(
        &stale_manifest,
        &provenance,
        target.path(),
        &"e".repeat(64),
        EvidenceArtifactIdentity {
            device: 11,
            inode: 12,
            size: 1,
        },
        &argv,
    )
    .is_err());
    let mut stale_executable = attestation;
    stale_executable.executable_sha256 = "f".repeat(64);
    assert!(validate_release_build_attestation(
        &stale_executable,
        &provenance,
        target.path(),
        &"e".repeat(64),
        EvidenceArtifactIdentity {
            device: 11,
            inode: 12,
            size: 1,
        },
        &argv,
    )
    .is_err());
}

#[test]
fn release_build_attestation_decoder_rejects_noncanonical_tampering() {
    let attestation = release_build_attestation_test_fixture(Path::new("/target"));
    let encoded = serde_json::to_vec(&attestation).expect("canonical attestation test JSON");
    assert_eq!(
        strict_decode_release_build_attestation(&encoded),
        Ok(attestation.clone())
    );
    assert!(strict_decode_release_build_attestation(
        format!(" { }", String::from_utf8(encoded).unwrap()).as_bytes()
    )
    .is_err());
    assert!(strict_decode_release_build_attestation(&vec![
        b' ';
        RELEASE_BUILD_ATTESTATION_MAX_BYTES + 1
    ])
    .is_err());
}

#[test]
fn qualification_git_refuses_a_path_selected_fake_executable() {
    let temporary = tempfile::tempdir().expect("fake git directory");
    let fake = temporary.path().join("git");
    std::fs::write(&fake, b"not a trusted executable").expect("write fake git");
    assert!(QualificationGitContext::with_candidate_executable(
        qualification_repository_root(),
        None,
        &fake,
    )
    .is_err());
}

#[test]
fn bounded_git_runner_kills_a_sigterm_resistant_descendant_and_reaps_its_group() {
    let mut hung = Command::new("/bin/sh");
    hung.arg("-c").arg(
        "(trap '' TERM; while :; do :; done) & descendant=$!; printf '%s %s\\n' \"$$\" \"$descendant\"; exit 0",
    );
    let started = std::time::Instant::now();
    let failure =
        bounded_command_output_with_timeout_diagnostic(&mut hung, Duration::from_millis(50))
            .expect_err("leader exit cannot make a pipe-holding descendant complete");
    assert_eq!(
        failure.reason,
        "trusted provenance command exceeded fixed runtime"
    );
    assert!(failure.stderr.as_deref().unwrap_or_default().is_empty());
    let records = String::from_utf8(failure.stdout.expect("early parent PID record retained"))
        .expect("parent PID record is UTF-8");
    let mut ids = records.split_whitespace();
    let leader = ids
        .next()
        .expect("parent records its leader PID")
        .parse::<u32>()
        .expect("leader PID is numeric");
    let descendant = ids
        .next()
        .expect("parent records its descendant via $!")
        .parse::<u32>()
        .expect("descendant PID is numeric");
    assert_ne!(
        leader, descendant,
        "the $! descendant must not be the exited leader"
    );
    let probe = Command::new("/bin/kill")
        .env("LC_ALL", "C")
        .arg("-0")
        .arg("--")
        .arg(descendant.to_string())
        .output()
        .expect("probe killed descendant");
    assert!(
        !probe.status.success()
            && String::from_utf8_lossy(&probe.stderr).contains("No such process"),
        "the exact descendant must be gone with ESRCH after whole-group KILL"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "TERM-resistant descendants must be killed as one bounded process group"
    );
}

#[test]
fn bounded_git_runner_retains_an_early_pipe_while_waiting_for_the_other_pipe() {
    let mut asymmetric = Command::new("/bin/sh");
    asymmetric
        .arg("-c")
        .arg("printf early; exec 1>&-; sleep 0.05; printf late >&2");
    let output = bounded_command_output_with_timeout(&mut asymmetric, Duration::from_secs(1))
        .expect("both asymmetric pipes complete before the fixed deadline");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"early");
    assert_eq!(output.stderr, b"late");
}

#[test]
fn quiet_host_monitor_ledger_rejects_a_gap_over_the_declared_bound() {
    let started = Instant::now();
    let mut ledger = QuietHostMonitorLedger::new(started);
    ledger.record_at(started, Ok(false), false);
    ledger.record_at(
        started + QUALIFICATION_QUIET_HOST_MAXIMUM_GAP + Duration::from_nanos(1),
        Ok(false),
        true,
    );
    assert!(ledger.evidence(Instant::now()).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn quiet_host_observer_detects_a_short_lived_nonancestor_cargo_process() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("competing Cargo test directory");
    let competing = temporary.path().join("cargo");
    symlink("/bin/sleep", &competing).expect("create short-lived cargo process alias");
    let mut child = Command::new(&competing)
        .arg("2")
        .spawn()
        .expect("spawn short-lived competing Cargo process");
    thread::sleep(Duration::from_millis(25));
    let observed = observed_nonancestor_qualification_build_job(&BTreeSet::new())
        .expect("scan bounded Linux proc for competing Cargo process");
    let _ = child.kill();
    let _ = child.wait();
    assert!(observed);
}

#[test]
fn release_evidence_is_closed_canonical_and_has_exact_totals() {
    let evidence = release_evidence_test_fixture();
    assert!(
        evidence
            .process_loss
            .strict_validation_command
            .chars()
            .count()
            > 512,
        "the real V9 replay command exercises the retired 512-character release-schema ceiling"
    );
    let encoded = canonical_release_evidence_bytes(&evidence);
    assert_eq!(strict_decode_release_evidence(&encoded), Ok(evidence));
}

#[test]
fn release_process_loss_command_bound_matches_the_v9_companion_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(RELEASE_EVIDENCE_SCHEMA).expect("release evidence schema");
    assert_eq!(
        schema.pointer("/$defs/process_loss/properties/strict_validation_command/maxLength"),
        Some(&serde_json::Value::from(
            PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS as u64
        )),
        "the final release schema must retain the full V9 replay-command contract"
    );

    let mut maximum = release_evidence_test_fixture();
    let fixture_chars = maximum
        .process_loss
        .strict_validation_command
        .chars()
        .count();
    assert!(fixture_chars > 512 && fixture_chars < PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS);
    maximum.process_loss.strict_validation_command.insert_str(
        "CARGO='".len(),
        &"é".repeat(PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS - fixture_chars),
    );
    assert_eq!(
        maximum
            .process_loss
            .strict_validation_command
            .chars()
            .count(),
        PROCESS_LOSS_REPRODUCTION_COMMAND_MAX_CHARS,
        "the typed bound counts Unicode scalar values exactly like JSON Schema"
    );
    let maximum_value = serde_json::to_value(&maximum).expect("maximum command evidence");
    assert!(opc_schema_validate::validate(&schema, &maximum_value).is_ok());
    assert!(validate_release_evidence(&maximum).is_ok());
    assert!(strict_decode_release_evidence(
        &serde_json::to_vec(&maximum).expect("maximum command JSON")
    )
    .is_ok());

    let mut oversized = maximum;
    oversized
        .process_loss
        .strict_validation_command
        .insert("CARGO='".len(), 'é');
    let oversized_value = serde_json::to_value(&oversized).expect("oversized command evidence");
    assert!(opc_schema_validate::validate(&schema, &oversized_value).is_err());
    assert!(validate_release_evidence(&oversized).is_err());
}

#[test]
fn release_evidence_rejects_unknown_trailing_duplicate_and_invalid_totals() {
    let evidence = release_evidence_test_fixture();
    let encoded = canonical_release_evidence_bytes(&evidence);
    let text = String::from_utf8(encoded).expect("test evidence UTF-8");
    let mut incomplete = evidence.clone();
    incomplete.qualification_complete = false;
    assert!(
        validate_release_evidence(&incomplete).is_err(),
        "an incomplete store gate cannot be serialized as accepted evidence"
    );
    assert!(strict_decode_release_evidence(format!("{text} trailing").as_bytes()).is_err());
    assert!(strict_decode_release_evidence(format!(" {text}").as_bytes()).is_err());
    assert!(
        strict_decode_release_evidence(text.replacen(',', ", ", 1).as_bytes()).is_err(),
        "schema-valid whitespace is rejected because emitted evidence is canonical"
    );
    assert!(
        strict_decode_release_evidence(&vec![b' '; RELEASE_EVIDENCE_MAX_BYTES + 1]).is_err(),
        "the strict decoder rejects a real payload beyond 128 KiB before parsing"
    );
    assert!(strict_decode_release_evidence(
        text.replacen("{\"version\":1", "{\"version\":1,\"unknown\":0", 1)
            .as_bytes()
    )
    .is_err());
    assert!(strict_decode_release_evidence(
        text.replacen("{\"version\":1", "{\"version\":1,\"version\":1", 1)
            .as_bytes()
    )
    .is_err());
    let mut invalid = release_evidence_test_fixture();
    invalid.outcomes.total_operations_committed -= 1;
    assert!(validate_release_evidence(&invalid).is_err());
    let mut schema_only = serde_json::to_value(release_evidence_test_fixture()).unwrap();
    schema_only["effects"]["mutation_batches"] = serde_json::Value::from(1_u64);
    assert!(strict_decode_release_evidence(&serde_json::to_vec(&schema_only).unwrap()).is_err());
    let mut schema_valid_typed_invalid =
        serde_json::to_value(release_evidence_test_fixture()).unwrap();
    schema_valid_typed_invalid["effects"]["mutation_attempts"] =
        serde_json::Value::from(QUALIFICATION_EXPECTED_EFFECT_BATCHES + 1);
    let schema: serde_json::Value = serde_json::from_str(RELEASE_EVIDENCE_SCHEMA).unwrap();
    assert!(opc_schema_validate::validate(&schema, &schema_valid_typed_invalid).is_ok());
    assert!(
        strict_decode_release_evidence(&serde_json::to_vec(&schema_valid_typed_invalid).unwrap())
            .is_err(),
        "checked cross-field arithmetic is enforced by the shared typed validator after schema validation"
    );
    let mut impossible_first_status_round =
        serde_json::to_value(release_evidence_test_fixture()).unwrap();
    impossible_first_status_round["effects"]["outcome_unknown_batches"] =
        serde_json::Value::from(QUALIFICATION_EXPECTED_EFFECT_BATCHES);
    impossible_first_status_round["effects"]["outcome_unknown_request_slots"] =
        serde_json::Value::from(QUALIFICATION_EXPECTED_EFFECT_BATCHES);
    impossible_first_status_round["effects"]["status_initial_request_slots"] =
        serde_json::Value::from(QUALIFICATION_EXPECTED_EFFECT_BATCHES);
    impossible_first_status_round["effects"]["status_attempts"] =
        serde_json::Value::from(QUALIFICATION_EXPECTED_EFFECT_BATCHES);
    assert!(
        opc_schema_validate::validate(&schema, &impossible_first_status_round).is_ok(),
        "the closed schema intentionally delegates exact cross-batch slot arithmetic to the shared typed validator"
    );
    assert!(
        strict_decode_release_evidence(
            &serde_json::to_vec(&impossible_first_status_round).unwrap()
        )
        .is_err(),
        "every unknown batch requires its exact first-round pending request cardinality"
    );
    let mut impossible_physical_retry_round =
        serde_json::to_value(release_evidence_test_fixture()).unwrap();
    impossible_physical_retry_round["effects"]["outcome_unknown_batches"] =
        serde_json::Value::from(2_u64);
    impossible_physical_retry_round["effects"]["outcome_unknown_request_slots"] =
        serde_json::Value::from(512_u64);
    impossible_physical_retry_round["effects"]["status_initial_request_slots"] =
        serde_json::Value::from(512_u64);
    impossible_physical_retry_round["effects"]["status_retry_request_slots"] =
        serde_json::Value::from(257_u64);
    impossible_physical_retry_round["effects"]["status_retry_rounds"] =
        serde_json::Value::from(1_u64);
    impossible_physical_retry_round["effects"]["status_attempts"] =
        serde_json::Value::from(769_u64);
    assert!(
        opc_schema_validate::validate(&schema, &impossible_physical_retry_round).is_ok(),
        "the schema cannot express a retry-round's exact 256-slot physical cardinality"
    );
    assert!(
        strict_decode_release_evidence(
            &serde_json::to_vec(&impossible_physical_retry_round).unwrap()
        )
        .is_err(),
        "one status retry round cannot claim more than one physical 256-request batch"
    );
    let mut impossible_unknown_batch_size =
        serde_json::to_value(release_evidence_test_fixture()).unwrap();
    impossible_unknown_batch_size["effects"]["outcome_unknown_batches"] =
        serde_json::Value::from(1_u64);
    impossible_unknown_batch_size["effects"]["outcome_unknown_request_slots"] =
        serde_json::Value::from(257_u64);
    impossible_unknown_batch_size["effects"]["status_initial_request_slots"] =
        serde_json::Value::from(257_u64);
    impossible_unknown_batch_size["effects"]["status_attempts"] = serde_json::Value::from(257_u64);
    assert!(
        opc_schema_validate::validate(&schema, &impossible_unknown_batch_size).is_ok(),
        "aggregate schema ranges cannot express the one-batch 256-slot limit"
    );
    assert!(
        strict_decode_release_evidence(
            &serde_json::to_vec(&impossible_unknown_batch_size).unwrap()
        )
        .is_err(),
        "every outcome-unknown batch has at most 256 physical request slots"
    );
    let mut missing_maintenance_reconciliation = release_evidence_test_fixture();
    missing_maintenance_reconciliation
        .outcomes
        .maintenance_reconciliation_retries = 1;
    missing_maintenance_reconciliation
        .outcomes
        .transient_exact_retries = 1;
    assert!(
        validate_release_evidence(&missing_maintenance_reconciliation).is_err(),
        "each maintenance readback projection is causally backed by a reconciliation retry"
    );
    let mut impossible_retry_attribution = release_evidence_test_fixture();
    impossible_retry_attribution
        .outcomes
        .effect_not_transmitted_retries = 1;
    assert!(
        validate_release_evidence(&impossible_retry_attribution).is_err(),
        "every permitted retry must be represented in the exact three-ledger aggregate"
    );
}

#[test]
fn release_effect_completion_deadline_uses_exact_duration_before_evidence_quantization() {
    let counters = ReleaseEffectCounters::default();
    assert_eq!(
        counters.record_qualified_batch_elapsed(QUALIFICATION_RELEASE_BATCH_DEADLINE),
        Ok(())
    );
    assert_eq!(
        counters.snapshot().batch_elapsed_max_us,
        800_000,
        "the accepted exact boundary is subsequently serialized in microseconds"
    );
    assert_eq!(
        counters.record_qualified_batch_elapsed(
            QUALIFICATION_RELEASE_BATCH_DEADLINE + Duration::from_nanos(1),
        ),
        Err(ReleaseBatchFailure {
            stage: ReleaseBatchFailureStage::CompletionDeadlineExceeded,
        }),
        "800ms + 1ns must fail before its floor-quantized 800,000us value can be serialized"
    );
    assert_eq!(
        counters.snapshot().mutation_batches,
        1,
        "a rejected late completion is never admitted into successful effect evidence"
    );
}

#[test]
fn release_evidence_topology_accepts_linked_worktree_gitdir_nested_in_common_gitdir() {
    let root = tempfile::tempdir().expect("release evidence topology root");
    let worktree = root.path().join("linked-worktree-checkout");
    let common_gitdir = root.path().join("common-gitdir");
    let linked_gitdir = common_gitdir.join("worktrees").join("linked-worktree");
    let external = root.path().join("external");
    std::fs::create_dir(&worktree).expect("create linked worktree checkout");
    std::fs::create_dir(&common_gitdir).expect("create linked-worktree common gitdir");
    std::fs::create_dir_all(&linked_gitdir)
        .expect("create linked-worktree gitdir in common gitdir");
    std::fs::create_dir(&external).expect("create external release evidence root");

    let namespace = external.join("evidence-namespace");
    let target = external.join("target");
    let process_loss = external.join("process-loss.json");
    let build_attestation = external.join("build-attestation.json");
    let lease = external.join("lease");
    assert_eq!(
        validate_release_evidence_external_topology_before_mkdir(
            &[
                (&namespace, "OPC_QUAL_EVIDENCE"),
                (&target, "CARGO_TARGET_DIR"),
                (&process_loss, "OPC_QUAL_PROCESS_LOSS_EVIDENCE"),
                (&build_attestation, "OPC_QUAL_BUILD_ATTESTATION"),
                (&lease, "OPC_QUAL_LEASE"),
            ],
            &worktree,
            &linked_gitdir,
            &common_gitdir,
        ),
        Ok(()),
        "the protected gitdir/common-gitdir nesting of a real linked-worktree topology is allowed"
    );
}

#[test]
fn release_evidence_topology_rejects_an_external_path_inside_common_gitdir_before_mkdir() {
    let root = tempfile::tempdir().expect("release evidence common-gitdir rejection root");
    let worktree = root.path().join("worktree");
    let common_gitdir = root.path().join("common-gitdir");
    let linked_gitdir = common_gitdir.join("worktrees").join("linked-worktree");
    let external = root.path().join("external");
    std::fs::create_dir(&worktree).expect("create worktree boundary");
    std::fs::create_dir(&common_gitdir).expect("create common gitdir boundary");
    std::fs::create_dir_all(&linked_gitdir).expect("create linked gitdir boundary");
    std::fs::create_dir(&external).expect("create external evidence root");

    let rejected_namespace = common_gitdir.join("forbidden-evidence-namespace");
    assert_eq!(
        validate_release_evidence_external_topology_before_mkdir(
            &[
                (&rejected_namespace, "OPC_QUAL_EVIDENCE"),
                (&external.join("target"), "CARGO_TARGET_DIR"),
                (
                    &external.join("process-loss.json"),
                    "OPC_QUAL_PROCESS_LOSS_EVIDENCE"
                ),
                (
                    &external.join("build-attestation.json"),
                    "OPC_QUAL_BUILD_ATTESTATION"
                ),
                (&external.join("lease"), "OPC_QUAL_LEASE"),
            ],
            &worktree,
            &linked_gitdir,
            &common_gitdir,
        ),
        Err("release evidence external path overlaps a protected Git boundary")
    );
    assert!(
        !rejected_namespace.exists(),
        "topology validation runs before the publisher can create an evidence namespace"
    );
}

#[test]
fn release_evidence_topology_rejects_overlapping_external_paths_before_mkdir() {
    let root = tempfile::tempdir().expect("release evidence external overlap root");
    let worktree = root.path().join("worktree");
    let gitdir = root.path().join("gitdir");
    let common_gitdir = root.path().join("common-gitdir");
    let external = root.path().join("external");
    std::fs::create_dir(&worktree).expect("create worktree boundary");
    std::fs::create_dir(&gitdir).expect("create gitdir boundary");
    std::fs::create_dir(&common_gitdir).expect("create common gitdir boundary");
    std::fs::create_dir(&external).expect("create external evidence root");

    let namespace = external.join("evidence-namespace");
    let overlapping_target = namespace.join("target");
    assert_eq!(
        validate_release_evidence_external_topology_before_mkdir(
            &[
                (&namespace, "OPC_QUAL_EVIDENCE"),
                (&overlapping_target, "CARGO_TARGET_DIR"),
            ],
            &worktree,
            &gitdir,
            &common_gitdir,
        ),
        Err("release evidence external paths are not pairwise disjoint")
    );
    assert!(
        !namespace.exists(),
        "overlap validation fails before the publisher can create its namespace"
    );
}

#[test]
fn process_loss_root_topology_rejects_unrelated_wrapper_namespaces_before_mkdir() {
    let root = tempfile::tempdir().expect("producer-root topology workspace");
    let protected_worktree = root.path().join("worktree");
    let protected_gitdir = root.path().join("gitdir");
    let protected_common = root.path().join("common-gitdir");
    let external = root.path().join("external");
    let producer_root = external.join("producer-evidence");
    std::fs::create_dir(&protected_worktree).expect("create worktree boundary");
    std::fs::create_dir(&protected_gitdir).expect("create gitdir boundary");
    std::fs::create_dir(&protected_common).expect("create common boundary");
    std::fs::create_dir(&external).expect("create external parent");
    std::fs::create_dir(&producer_root).expect("create producer root");

    for (unrelated, label) in [
        (producer_root.join("wrapper-target"), "wrapper target"),
        (
            producer_root.join("store-evidence"),
            "store evidence namespace",
        ),
    ] {
        assert_eq!(
            validate_process_loss_root_external_topology_before_mkdir(
                &producer_root,
                &[(unrelated.as_path(), label)],
                &[(
                    unrelated.parent().expect("unrelated parent"),
                    "unrelated parent"
                )],
                &protected_worktree,
                &protected_gitdir,
                &protected_common,
            ),
            Err("V9 producer evidence root overlaps an unrelated external namespace"),
        );
        assert!(
            !unrelated.exists(),
            "{label} topology rejection runs before any publisher mkdir residue"
        );
    }
    for (unrelated, label) in [
        (producer_root.as_path(), "producer root itself"),
        (
            producer_root.parent().expect("producer root parent"),
            "producer root ancestor",
        ),
    ] {
        assert_eq!(
            validate_process_loss_root_external_topology_before_mkdir(
                &producer_root,
                &[(unrelated, label)],
                &[],
                &protected_worktree,
                &protected_gitdir,
                &protected_common,
            ),
            Err("V9 producer evidence root overlaps an unrelated external namespace"),
        );
    }
}

#[test]
fn process_loss_root_topology_allows_disjoint_siblings_under_one_external_parent() {
    let root = tempfile::tempdir().expect("producer-root sibling topology workspace");
    let protected_worktree = root.path().join("worktree");
    let protected_gitdir = root.path().join("gitdir");
    let protected_common = root.path().join("common-gitdir");
    let external = root.path().join("external");
    let producer_root = external.join("testkit-v9-root");
    std::fs::create_dir(&protected_worktree).expect("create worktree boundary");
    std::fs::create_dir(&protected_gitdir).expect("create gitdir boundary");
    std::fs::create_dir(&protected_common).expect("create common boundary");
    std::fs::create_dir(&external).expect("create shared external parent");
    std::fs::create_dir(&producer_root).expect("create producer root");

    let target = external.join("wrapper-target");
    let evidence = external.join("store-evidence");
    let attestation = external
        .join("attestation")
        .join("sdk702-release-build-attestation.json");
    let lease = external.join("lease").join("sdk702.lock");
    assert_eq!(
        validate_process_loss_root_external_topology_before_mkdir(
            &producer_root,
            &[
                (&target, "CARGO_TARGET_DIR"),
                (&evidence, "OPC_QUAL_EVIDENCE"),
                (&attestation, "OPC_QUAL_BUILD_ATTESTATION"),
                (&lease, "OPC_QUAL_LEASE"),
            ],
            &[
                (
                    target.parent().expect("target parent"),
                    "CARGO_TARGET_DIR parent"
                ),
                (
                    evidence.parent().expect("evidence parent"),
                    "OPC_QUAL_EVIDENCE parent"
                ),
                (
                    attestation.parent().expect("attestation parent"),
                    "OPC_QUAL_BUILD_ATTESTATION parent",
                ),
                (
                    lease.parent().expect("lease parent"),
                    "OPC_QUAL_LEASE parent"
                ),
            ],
            &protected_worktree,
            &protected_gitdir,
            &protected_common,
        ),
        Ok(())
    );
}

#[test]
fn existing_release_evidence_namespace_validation_is_read_only_and_strict() {
    let root = tempfile::tempdir().expect("existing evidence validation root");
    let parent = root.path().join("external-parent");
    let worktree = root.path().join("worktree");
    let gitdir = root.path().join("gitdir");
    let target = root.path().join("target");
    std::fs::create_dir(&parent).expect("existing evidence external parent");
    std::fs::create_dir(&worktree).expect("existing evidence worktree boundary");
    std::fs::create_dir(&gitdir).expect("existing evidence gitdir boundary");
    std::fs::create_dir(&target).expect("existing evidence target boundary");
    let artifact = pinned_release_evidence_test_artifact(&parent, RELEASE_EVIDENCE_NAMESPACE_LEAF);
    let namespace = parent.join(&artifact.namespace);
    let mut fixture = release_evidence_test_fixture();
    fixture.artifact.path_id = redacted_path_id(&namespace.join(RELEASE_EVIDENCE_NAMESPACE_LEAF));
    let encoded = canonical_release_evidence_bytes(&fixture);
    write_release_evidence_artifact(&artifact, &encoded);
    assert_eq!(
        validate_existing_release_evidence_namespace_with_context(
            &namespace, &worktree, &gitdir, &gitdir, &target,
        ),
        Ok(())
    );

    let alias_parent = root.path().join("external-parent-alias");
    std::os::unix::fs::symlink(&parent, &alias_parent)
        .expect("existing evidence namespace parent alias");
    assert_eq!(
        validate_existing_release_evidence_namespace_with_context(
            &alias_parent.join(&artifact.namespace),
            &worktree,
            &gitdir,
            &gitdir,
            &target,
        ),
        Ok(()),
        "parent symlink aliases bind the actual canonical namespace path identifier"
    );

    std::fs::write(namespace.join(".failed-test"), b"failed").expect("install failed residue");
    assert!(validate_existing_release_evidence_namespace_with_context(
        &namespace, &worktree, &gitdir, &gitdir, &target,
    )
    .is_err());
    std::fs::remove_file(namespace.join(".failed-test")).expect("remove failed residue");
    std::fs::write(namespace.join(".opc-qualification-evidence-temp"), b"temp")
        .expect("install temporary residue");
    assert!(validate_existing_release_evidence_namespace_with_context(
        &namespace, &worktree, &gitdir, &gitdir, &target,
    )
    .is_err());
    std::fs::remove_file(namespace.join(".opc-qualification-evidence-temp"))
        .expect("remove temporary residue");
    std::fs::write(namespace.join("unknown"), b"unknown").expect("install unknown residue");
    assert!(validate_existing_release_evidence_namespace_with_context(
        &namespace, &worktree, &gitdir, &gitdir, &target,
    )
    .is_err());
    std::fs::remove_file(namespace.join("unknown")).expect("remove unknown residue");

    let copied_parent = root.path().join("copied-external-parent");
    std::fs::create_dir(&copied_parent).expect("copy evidence parent");
    let copied_namespace = copied_parent.join("copied-namespace");
    std::fs::create_dir(&copied_namespace).expect("copy evidence namespace");
    for leaf in [
        RELEASE_EVIDENCE_NAMESPACE_LEAF,
        RELEASE_EVIDENCE_ACCEPTED_LEAF,
    ] {
        std::fs::copy(namespace.join(leaf), copied_namespace.join(leaf))
            .expect("copy canonical evidence namespace leaf");
    }
    assert!(validate_existing_release_evidence_namespace_with_context(
        &copied_namespace,
        &worktree,
        &gitdir,
        &gitdir,
        &target,
    )
    .is_err());
    assert!(validate_existing_release_evidence_namespace_with_context(
        Path::new("relative-evidence-namespace"),
        &worktree,
        &gitdir,
        &gitdir,
        &target,
    )
    .is_err());
    assert!(validate_existing_release_evidence_namespace_with_context(
        &namespace, &worktree, &gitdir, &gitdir, &parent,
    )
    .is_err());
    let nested_target = namespace.join("nested-target");
    std::fs::create_dir(&nested_target).expect("nested target overlap fixture");
    assert!(validate_existing_release_evidence_namespace_with_context(
        &namespace,
        &worktree,
        &gitdir,
        &gitdir,
        &nested_target,
    )
    .is_err());
    std::fs::remove_dir(&nested_target).expect("remove nested target overlap fixture");

    let in_worktree_parent = worktree.join("in-worktree-parent");
    std::fs::create_dir(&in_worktree_parent).expect("in-worktree evidence parent");
    let in_worktree_artifact =
        pinned_release_evidence_test_artifact(&in_worktree_parent, RELEASE_EVIDENCE_NAMESPACE_LEAF);
    write_release_evidence_artifact(&in_worktree_artifact, &encoded);
    assert!(validate_existing_release_evidence_namespace_with_context(
        &in_worktree_parent.join(&in_worktree_artifact.namespace),
        &worktree,
        &gitdir,
        &gitdir,
        &target,
    )
    .is_err());

    let main_worktree_gitdir = worktree.join(".git");
    std::fs::create_dir(&main_worktree_gitdir).expect("main-worktree .git boundary");
    assert_eq!(
        validate_existing_release_evidence_namespace_with_context(
            &namespace,
            &worktree,
            &main_worktree_gitdir,
            &main_worktree_gitdir,
            &target,
        ),
        Ok(()),
        "a main worktree and its nested .git boundary remain valid protected topology"
    );

    let common_gitdir = root.path().join("common-gitdir");
    let linked_worktree = root.path().join("linked-worktree");
    let linked_gitdir = common_gitdir.join("worktrees").join("linked-worktree");
    std::fs::create_dir(&common_gitdir).expect("linked-worktree common gitdir boundary");
    std::fs::create_dir(&linked_worktree).expect("linked-worktree boundary");
    std::fs::create_dir_all(&linked_gitdir).expect("linked-worktree gitdir boundary");
    assert_eq!(
        validate_existing_release_evidence_namespace_with_context(
            &namespace,
            &linked_worktree,
            &linked_gitdir,
            &common_gitdir,
            &target,
        ),
        Ok(()),
        "a linked worktree gitdir nested below its common gitdir remains valid protected topology"
    );
}

#[test]
fn bounded_nofollow_evidence_reads_reject_fifo_device_growth_and_oversize() {
    use nix::sys::stat::Mode;

    let root = tempfile::tempdir().expect("bounded evidence read root");
    let parent_path = root.path().join("parent");
    std::fs::create_dir(&parent_path).expect("bounded evidence read parent");
    let parent_metadata = std::fs::metadata(&parent_path).expect("stat bounded evidence parent");
    let parent = pinned_parent_file(&parent_path, parent_metadata.dev(), parent_metadata.ino())
        .expect("open bounded evidence parent");

    // Linux preserves the descriptor-relative setup. Apple lacks `mkfifoat`,
    // but this private, test-owned temporary parent has no concurrent writer,
    // so path-based FIFO setup is equivalent for the pinned-parent reader.
    #[cfg(not(target_vendor = "apple"))]
    nix::unistd::mkfifoat(&parent, "candidate.fifo", Mode::S_IRUSR | Mode::S_IWUSR)
        .expect("create bounded-read FIFO");
    #[cfg(target_vendor = "apple")]
    nix::unistd::mkfifo(
        &parent_path.join("candidate.fifo"),
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .expect("create bounded-read FIFO");
    assert!(
        read_bounded_nofollow_regular_file(&parent, OsStr::new("candidate.fifo"), 16, "FIFO")
            .is_err(),
        "O_NONBLOCK plus no-follow fstat rejects a FIFO without waiting for a writer"
    );
    let device_metadata = std::fs::metadata("/dev").expect("stat /dev for device rejection");
    let device_parent = pinned_parent_file(
        Path::new("/dev"),
        device_metadata.dev(),
        device_metadata.ino(),
    )
    .expect("open /dev for device rejection");
    assert!(
        read_bounded_nofollow_regular_file(&device_parent, OsStr::new("null"), 16, "device")
            .is_err(),
        "descriptor-relative reader rejects non-regular devices"
    );

    std::fs::write(parent_path.join("oversize"), vec![0_u8; 17])
        .expect("write oversized bounded-read input");
    assert!(
        read_bounded_nofollow_regular_file(&parent, OsStr::new("oversize"), 16, "oversize")
            .is_err(),
        "initial metadata size cap rejects an oversized input before allocation"
    );
    let growing = parent_path.join("growing");
    std::fs::write(&growing, b"x").expect("write growing bounded-read input");
    let append = || {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&growing)
            .expect("open growing bounded-read input for append seam");
        file.write_all(b"y")
            .expect("append growing bounded-read input");
    };
    assert!(read_bounded_nofollow_regular_file_with_seam(
        &parent,
        OsStr::new("growing"),
        16,
        "append growth",
        Some(&append),
    )
    .is_err());
    let replaced = parent_path.join("replaced");
    std::fs::write(&replaced, b"owned").expect("write replaceable bounded input");
    let replacement = || {
        std::fs::remove_file(&replaced).expect("remove bounded input for replacement seam");
        std::fs::write(&replaced, b"foreign").expect("install replacement bounded input");
    };
    assert!(
        read_bounded_nofollow_regular_file_with_identity_and_seam(
            &parent,
            OsStr::new("replaced"),
            16,
            "descriptor replacement",
            Some(&replacement),
        )
        .is_err(),
        "descriptor-relative companion reads reject a replaced leaf"
    );
}

#[test]
fn private_lease_descriptor_rejects_a_fifo_and_a_shared_parent() {
    use nix::sys::stat::Mode as NixMode;
    use rustix::fs::{openat, Mode, OFlags};

    let root = tempfile::tempdir().expect("private lease root");
    let parent_path = root.path().join("lease-parent");
    std::fs::create_dir(&parent_path).expect("create private lease parent");
    let metadata = std::fs::metadata(&parent_path).expect("stat private lease parent");
    assert!(
        pinned_current_user_private_directory(
            &parent_path,
            metadata.dev(),
            metadata.ino(),
            "shared lease parent",
        )
        .is_err(),
        "a mode-0755 lease parent cannot acquire qualification authority"
    );

    std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
        .expect("set private lease parent mode");
    let parent = pinned_current_user_private_directory(
        &parent_path,
        metadata.dev(),
        metadata.ino(),
        "private lease parent",
    )
    .expect("open private lease parent");

    // Linux preserves the descriptor-relative setup. Apple lacks `mkfifoat`,
    // but this private, test-owned temporary parent has no concurrent writer,
    // so path-based FIFO setup is equivalent for the pinned-parent validator.
    #[cfg(not(target_vendor = "apple"))]
    nix::unistd::mkfifoat(&parent, "lease", NixMode::S_IRUSR | NixMode::S_IWUSR)
        .expect("create lease FIFO");
    #[cfg(target_vendor = "apple")]
    nix::unistd::mkfifo(
        &parent_path.join("lease"),
        NixMode::S_IRUSR | NixMode::S_IWUSR,
    )
    .expect("create lease FIFO");
    let fifo = File::from(
        openat(
            &parent,
            "lease",
            OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open lease FIFO without blocking"),
    );
    assert!(
        validate_private_qualification_lease_descriptor(&parent, OsStr::new("lease"), &fifo)
            .is_err(),
        "a FIFO replacement cannot pass the post-open qualification lease validation"
    );
}

#[test]
fn wrapper_lease_procfd_contract_child() {
    let Some(case) = std::env::var_os("OPC_QUAL_LEASE_TEST_CHILD_CASE") else {
        return;
    };
    let pin = WrapperLeasePin::from_environment()
        .expect("child must receive its direct wrapper's exact lease procfd contract");
    let namespace = PathBuf::from(
        std::env::var_os("OPC_QUAL_LEASE_TEST_NAMESPACE")
            .expect("child test evidence namespace path"),
    );
    match case.to_string_lossy().as_ref() {
        "positive" => {
            let lease = acquire_qualification_host_lease_from_pin(&pin, None)
                .expect("exact wrapper-parent procfd lease is accepted and locked");
            lease
                .revalidate()
                .expect("retained wrapper-parent procfd lease remains exact");
            assert!(
                !namespace.exists(),
                "the positive pin test does not publish evidence"
            );
        }
        "replace-before-lock" => {
            let replacement = pin.lease_path.clone();
            let result = acquire_qualification_host_lease_from_pin(
                &pin,
                Some(&|| {
                    std::fs::remove_file(&replacement)
                        .expect("remove A pathname after procfd identity observation");
                    std::fs::write(&replacement, b"B")
                        .expect("install B pathname before lock revalidation");
                    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
                        .expect("make B a private leaf");
                }),
            );
            assert!(
                result.is_err(),
                "A-to-B replacement between procfd identity and lock revalidation must fail"
            );
            assert!(
                !namespace.exists(),
                "a failed lease acquisition cannot create an evidence namespace"
            );
        }
        "replace-before-publication" => {
            let lease = acquire_qualification_host_lease_from_pin(&pin, None)
                .expect("acquire A before deterministic publication seam");
            let artifact = pinned_release_evidence_test_artifact(
                &pin.canonical_parent,
                RELEASE_EVIDENCE_NAMESPACE_LEAF,
            );
            let final_leaf = artifact.canonical_namespace.join(&artifact.leaf);
            let replacement = pin.lease_path.clone();
            let before_rename = || {
                std::fs::remove_file(&replacement)
                    .expect("remove A pathname immediately before publication");
                std::fs::write(&replacement, b"B")
                    .expect("install B pathname immediately before publication");
                std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
                    .expect("make replacement B private");
            };
            let seams = ReleaseEvidenceWriterSeams {
                before_rename: Some(&before_rename),
                ..ReleaseEvidenceWriterSeams::default()
            };
            assert!(
                write_release_evidence_artifact_with_seams_and_lease(
                    &artifact,
                    b"canonical",
                    &seams,
                    Some(&lease),
                )
                .is_err(),
                "a changed lease pathname immediately before publication must fail closed"
            );
            assert!(
                !final_leaf.exists(),
                "prepublication lease replacement cannot publish an evidence leaf"
            );
        }
        _ => panic!("unknown wrapper lease child test case"),
    }
}

fn run_wrapper_lease_procfd_contract_child(case: &str) {
    let root = tempfile::tempdir().expect("wrapper lease procfd test root");
    let parent = root.path().join("private-lease-parent");
    let lease = parent.join("lease");
    let namespace = parent.join("absent-evidence-namespace");
    std::fs::create_dir(&parent).expect("create wrapper private lease parent");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("make wrapper lease parent private");
    std::fs::write(&lease, b"A").expect("create wrapper-held lease A");
    std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600))
        .expect("make wrapper-held lease A private");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lease)
        .expect("retain wrapper lease descriptor across child");
    let parent_metadata = std::fs::metadata(&parent).expect("stat wrapper lease parent");
    let lease_metadata = held.metadata().expect("fstat wrapper-held lease A");
    let wrapper_pid = std::process::id();
    let wrapper_fd = held.as_raw_fd();
    assert!(
        wrapper_fd >= 0,
        "wrapper-held lease descriptor is nonnegative"
    );
    let mut child =
        Command::new(std::env::current_exe().expect("current qualification test binary"));
    child
        .arg("--exact")
        .arg("wrapper_lease_procfd_contract_child")
        .arg("--nocapture")
        .env("OPC_QUAL_LEASE_TEST_CHILD_CASE", case)
        .env("OPC_QUAL_LEASE_TEST_NAMESPACE", &namespace)
        .env("OPC_QUAL_LEASE", &lease)
        .env(
            "OPC_QUAL_LEASE_PIN_DOMAIN",
            QUALIFICATION_WRAPPER_LEASE_PIN_DOMAIN,
        )
        .env("OPC_QUAL_LEASE_PIN_WRAPPER_PID", wrapper_pid.to_string())
        .env("OPC_QUAL_LEASE_PIN_WRAPPER_FD", wrapper_fd.to_string())
        .env(
            "OPC_QUAL_LEASE_PIN_PROCFD",
            format!("/proc/{wrapper_pid}/fd/{wrapper_fd}"),
        )
        .env("OPC_QUAL_LEASE_PIN_PARENT", &parent)
        .env("OPC_QUAL_LEASE_PIN_NAME", "lease")
        .env(
            "OPC_QUAL_LEASE_PIN_PARENT_DEVICE",
            parent_metadata.dev().to_string(),
        )
        .env(
            "OPC_QUAL_LEASE_PIN_PARENT_INODE",
            parent_metadata.ino().to_string(),
        )
        .env(
            "OPC_QUAL_LEASE_PIN_DEVICE",
            lease_metadata.dev().to_string(),
        )
        .env("OPC_QUAL_LEASE_PIN_INODE", lease_metadata.ino().to_string())
        .env(
            "OPC_QUAL_LEASE_PIN_MODE",
            format!("{:04o}", lease_metadata.mode() & 0o777),
        )
        .env("OPC_QUAL_LEASE_PIN_UID", lease_metadata.uid().to_string());
    assert!(
        child
            .status()
            .expect("run direct child under wrapper procfd contract")
            .success(),
        "wrapper procfd contract child case {case} must pass"
    );
}

#[test]
fn wrapper_lease_procfd_contract_accepts_the_exact_direct_parent_pin() {
    run_wrapper_lease_procfd_contract_child("positive");
}

#[test]
fn wrapper_lease_procfd_contract_rejects_a_to_b_replacements_before_lock_and_publication() {
    run_wrapper_lease_procfd_contract_child("replace-before-lock");
    run_wrapper_lease_procfd_contract_child("replace-before-publication");
}

#[test]
#[ignore = "release-profile sentinel for the ignored 1.01M qualification"]
fn release_qualification_profile_guard() {
    let profile = require_release_qualification_profile();
    assert_eq!(validate_release_qualification_profile(profile), Ok(()));
}

#[test]
fn release_qualification_build_profile_validation_matrix() {
    let rejected = QualificationBuildProfileError::NotReleaseQualified;
    assert_eq!(
        validate_release_qualification_profile(QualificationBuildProfile {
            cargo_profile_family: "release",
            cargo_opt_level: "0",
            debug_assertions: false,
        }),
        Err(rejected)
    );
    assert_eq!(
        validate_release_qualification_profile(QualificationBuildProfile {
            cargo_profile_family: "debug",
            cargo_opt_level: "3",
            debug_assertions: false,
        }),
        Err(rejected)
    );
    assert_eq!(
        validate_release_qualification_profile(QualificationBuildProfile {
            cargo_profile_family: "release",
            cargo_opt_level: "3",
            debug_assertions: true,
        }),
        Err(rejected)
    );
    assert_eq!(
        validate_release_qualification_profile(QualificationBuildProfile {
            cargo_profile_family: "release",
            cargo_opt_level: "3",
            debug_assertions: false,
        }),
        Ok(())
    );
}

#[test]
fn qualification_quiet_host_classifier_is_exact_and_redaction_safe() {
    assert!(qualification_build_job_name("cargo\n"));
    assert!(qualification_build_job_name("rustc\n"));
    assert!(!qualification_build_job_name("cargo-watch\n"));
    assert!(!qualification_build_job_name(
        "fenced_transition_v2_qualification\n"
    ));
    assert_eq!(
        QUALIFICATION_QUIET_HOST_BOUNDARY,
        "linux_proc_nonancestor_cargo_rustc_sampled_interval_no_observation"
    );
}

#[test]
fn process_loss_v9_recipe_matches_the_producer_canonical_argv() {
    assert_eq!(PROCESS_LOSS_CANONICAL_CARGO_ARGV.len(), 15);
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(PROCESS_LOSS_EVIDENCE_SCHEMA)),
        PROCESS_LOSS_V9_SCHEMA_SHA256,
        "the local V9 schema digest literal binds the current producer schema"
    );
    let recipe = process_loss_v9_reproduction_command(
        "/var/lib/opc testkit/target",
        "/var/lib/opc testkit/evidence",
        "/var/lib/opc testkit/fs-verity-snapshots",
        "/usr/local/bin/cargo",
    )
    .expect("canonical producer recipe");
    assert_eq!(
        recipe,
        "CARGO='/usr/local/bin/cargo' CARGO_TARGET_DIR='/var/lib/opc testkit/target' OPC_SESSION_TESTKIT_V9_EVIDENCE_DIRECTORY='/var/lib/opc testkit/evidence' OPC_FS_VERITY_QUALIFICATION='required' OPC_FS_VERITY_SNAPSHOT_ROOT='/var/lib/opc testkit/fs-verity-snapshots' '/usr/local/bin/cargo' 'test' '--locked' '--release' '-p' 'opc-session-testkit' '--test' 'qualification_mtls_multiprocess' '--no-default-features' 'three_process_projected_mtls_persistent_v2_batch_release_gate' '--' '--ignored' '--exact' '--test-threads=1' '--nocapture'"
    );
    assert!(
        PROCESS_LOSS_V9_PRODUCER_SOURCE.contains(
            "const RELEASE_GATE_EXPECTED_CARGO_ARGV: &[&str] = &[\n    \"cargo\",\n    \"test\",\n    \"--locked\",\n    \"--release\",\n    \"-p\",\n    \"opc-session-testkit\",\n    \"--test\",\n    \"qualification_mtls_multiprocess\",\n    \"--no-default-features\",\n    \"three_process_projected_mtls_persistent_v2_batch_release_gate\",\n    \"--\",\n    \"--ignored\",\n    \"--exact\",\n    \"--test-threads=1\",\n    \"--nocapture\",\n];"
        ),
        "the local strict recipe is cross-checked against the testkit producer's canonical argv metadata"
    );
    assert!(PROCESS_LOSS_V9_PRODUCER_SOURCE
        .contains("b\"opc-session-ha-persistent-consumer-v9-pair-run/v4\\0\""));
    assert!(PROCESS_LOSS_V9_PRODUCER_SOURCE.contains("b\"cargo-executable-alias\""));
    assert!(PROCESS_LOSS_V9_PRODUCER_SOURCE.contains("b\"cargo-executable-sha256\""));
    assert!(PROCESS_LOSS_V9_PRODUCER_SOURCE.contains("b\"cargo-executable-mode\""));
    assert!(PROCESS_LOSS_V9_PRODUCER_SOURCE.contains("b\"canonical-cargo-argv\""));
    assert!(PROCESS_LOSS_V9_PRODUCER_SOURCE.contains("b\"v9-claims-preimage\""));
    assert!(RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE
        .contains("--target-dir <absent-absolute-external-target>"));
    assert!(RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE
        .starts_with("OPC_FS_VERITY_QUALIFICATION=required OPC_FS_VERITY_SNAPSHOT_ROOT=<existing-absolute-external-fs-verity-root> "));
    assert!(RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE
        .contains("--snapshot-root <existing-absolute-external-fs-verity-root>"));
    assert!(RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE
        .contains("--process-loss-evidence <absolute-external-testkit-v9-json>"));
}

#[test]
fn release_qualification_dimensions_are_fixed() {
    assert_eq!(QUALIFICATION_SESSIONS, 50_000);
    assert_eq!(QUALIFICATION_SUSTAINED_TRANSITIONS, 900_000);
    assert_eq!(QUALIFICATION_BURST_TRANSITIONS, 60_000);
    assert_eq!(QUALIFICATION_RELEASE_TRANSITIONS, 1_010_000);
    assert_eq!(QUALIFICATION_EXPECTED_EFFECT_BATCHES, 120_234);
    assert_eq!(
        QUALIFICATION_EXPECTED_EFFECT_REQUEST_SLOTS,
        50_000 + 960_000 + 28 + 8 + 1,
        "singleton replay effects are counted by their real request slots, not their batch maxima"
    );
    assert_eq!(
        QUALIFICATION_RELEASE_BATCH_DEADLINE,
        Duration::from_millis(800)
    );
    assert_eq!(
        QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS, 31_072,
        "operational headroom is per active epoch after the 100,000-operation target"
    );
    assert_eq!(
        QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS, 38_576,
        "retained-envelope headroom is after the 1,010,000-operation release workload"
    );
    assert_eq!(
        QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET
    );
    assert_eq!(
        QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS,
        FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES - QUALIFICATION_RELEASE_TRANSITIONS
    );
    assert_ne!(
        QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS,
        QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS,
        "active-epoch operational headroom and retained-envelope release headroom are distinct dimensions"
    );
    assert_eq!(QUALIFICATION_IN_FLIGHT_CLIENTS, 8);
    assert_eq!(
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
        55_408_852_992
    );
    assert_eq!(
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
        36_939_235_328
    );
    assert_eq!(
        qualification_phase_max_elapsed_ms(
            QUALIFICATION_SUSTAINED_TRANSITIONS as u64,
            QUALIFICATION_SUSTAINED_RATE as u64,
        ),
        1_801_801
    );
    assert_eq!(
        qualification_phase_max_elapsed_ms(
            QUALIFICATION_BURST_TRANSITIONS as u64,
            QUALIFICATION_BURST_RATE as u64,
        ),
        60_060
    );
    assert_qualification_phase_pacing(
        Duration::from_millis(60_060),
        QUALIFICATION_BURST_TRANSITIONS as u64,
        QUALIFICATION_BURST_RATE as u64,
    );
    assert!(std::panic::catch_unwind(|| {
        assert_qualification_phase_pacing(
            Duration::from_millis(60_061),
            QUALIFICATION_BURST_TRANSITIONS as u64,
            QUALIFICATION_BURST_RATE as u64,
        );
    })
    .is_err());
}

/// Bounded release-profile diagnosis for the first remaining automatic
/// snapshot scale seam. It keeps the production public V2 effect boundary,
/// a real fixed three-voter quorum, and the release workload's exact client
/// burst shape while stopping after two completed snapshot publications.
///
/// This is intentionally ignored in ordinary CI: the value is its release
/// profile evidence and its diagnostic output if a snapshot-era quorum fails.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "SDK-704 bounded two-snapshot fixed-quorum scale diagnosis"]
async fn bounded_two_snapshot_thresholds_keep_public_v2_batches_live() {
    let build_profile = require_release_qualification_profile();
    assert_eq!(QUALIFICATION_PACED_BATCH_OPERATIONS, 8);
    assert_eq!(QUALIFICATION_IN_FLIGHT_CLIENTS, 8);
    assert_eq!(BOUNDED_SCALE_STALL_BATCHES_PER_PHASE, 4_104);

    let directory = tempfile::tempdir().expect("SDK-704 bounded scale directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("SDK-704 bounded scale start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let snapshot_root = std::fs::canonicalize(
        std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV)
            .expect("bounded scale requires the explicit fs-verity snapshot root"),
    )
    .expect("canonical bounded-scale fs-verity snapshot root");
    let (stores, _, _, peer_slots) =
        fixed_cluster_with_snapshot_root(directory.path(), &snapshot_root, clock).await;
    let ingress_store = &stores[ready_leader(&stores).await];
    let provider = sealing_provider();
    let transient_retries = AtomicU64::new(0);
    let effect_counters = Arc::new(ReleaseEffectCounters::default());
    let diagnostics = BoundedScaleDiagnostics {
        stores: &stores,
        effect_counters: effect_counters.as_ref(),
        read_backend_unavailable_retries: &transient_retries,
    };
    let history_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");
    let setup_started = Instant::now();
    let mut setup_latency = ReleaseLatencySamples::default();

    // The first singleton is the sole capability activation. The remaining
    // 64 creates warm the exact same public batch effect path used by every
    // scale-phase update, without using a state-machine or receipt shortcut.
    let mut create_requests = Vec::with_capacity(BOUNDED_SCALE_STALL_SESSION_SLOTS);
    for session_index in 0..BOUNDED_SCALE_STALL_SESSION_SLOTS {
        let transition_key = key(session_index);
        let observation = match retry_exact_consensus_operation(&transient_retries, || {
            ingress_store.observe_fenced_transition(&transition_key)
        })
        .await
        {
            Ok(observation) => observation,
            Err(_) => {
                fail_bounded_scale_stall(
                    directory,
                    &peer_slots,
                    &diagnostics,
                    "fence_observation",
                    &mut bounded_scale_observation(
                        "setup",
                        0,
                        setup_started,
                        0,
                        0,
                        0,
                        &mut setup_latency,
                    ),
                )
                .await;
                unreachable!("bounded scale failure always panics")
            }
        };
        create_requests.push(
            create_request(
                session_index,
                history_epoch,
                transition_key,
                observation.current_fence(),
                &provider,
            )
            .await,
        );
    }
    if transient_retries.load(Ordering::Relaxed) != 0 {
        fail_bounded_scale_stall(
            directory,
            &peer_slots,
            &diagnostics,
            "setup_backend_unavailable",
            &mut bounded_scale_observation("setup", 0, setup_started, 0, 0, 0, &mut setup_latency),
        )
        .await;
        unreachable!("bounded scale failure always panics")
    }

    let first_request = create_requests.remove(0);
    let first_outcomes = match execute_release_store_batch(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        ingress_store,
        vec![first_request.clone()],
        &effect_counters,
    )
    .await
    {
        Ok(outcomes) => outcomes,
        Err(failure) => {
            fail_bounded_scale_stall(
                directory,
                &peer_slots,
                &diagnostics,
                failure.stage.as_str(),
                &mut bounded_scale_observation(
                    "setup",
                    0,
                    setup_started,
                    0,
                    0,
                    0,
                    &mut setup_latency,
                ),
            )
            .await;
            unreachable!("bounded scale failure always panics")
        }
    };
    let first_outcome = match first_outcomes.as_slice() {
        [Ok(outcome)] => outcome.clone(),
        _ => {
            fail_bounded_scale_stall(
                directory,
                &peer_slots,
                &diagnostics,
                "singleton_outcome_shape",
                &mut bounded_scale_observation(
                    "setup",
                    0,
                    setup_started,
                    0,
                    0,
                    0,
                    &mut setup_latency,
                ),
            )
            .await;
            unreachable!("bounded scale failure always panics")
        }
    };
    assert_exact_qualified_v2_success(&first_request, &first_outcome);
    let mut sessions = vec![(first_request, first_outcome)];
    for requests in create_requests.chunks(QUALIFICATION_PACED_BATCH_OPERATIONS) {
        let requests = requests.to_vec();
        let outcomes = match execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            ingress_store,
            requests.clone(),
            &effect_counters,
        )
        .await
        {
            Ok(outcomes) => outcomes,
            Err(failure) => {
                fail_bounded_scale_stall(
                    directory,
                    &peer_slots,
                    &diagnostics,
                    failure.stage.as_str(),
                    &mut bounded_scale_observation(
                        "setup",
                        0,
                        setup_started,
                        0,
                        0,
                        0,
                        &mut setup_latency,
                    ),
                )
                .await;
                unreachable!("bounded scale failure always panics")
            }
        };
        if outcomes.len() != requests.len() {
            fail_bounded_scale_stall(
                directory,
                &peer_slots,
                &diagnostics,
                "warm_batch_outcome_shape",
                &mut bounded_scale_observation(
                    "setup",
                    0,
                    setup_started,
                    0,
                    0,
                    0,
                    &mut setup_latency,
                ),
            )
            .await;
            unreachable!("bounded scale failure always panics")
        }
        for (request, outcome) in requests.into_iter().zip(outcomes) {
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(_) => {
                    fail_bounded_scale_stall(
                        directory,
                        &peer_slots,
                        &diagnostics,
                        "warm_batch_item_result",
                        &mut bounded_scale_observation(
                            "setup",
                            0,
                            setup_started,
                            0,
                            0,
                            0,
                            &mut setup_latency,
                        ),
                    )
                    .await;
                    unreachable!("bounded scale failure always panics")
                }
            };
            assert_exact_qualified_v2_success(&request, &outcome);
            sessions.push((request, outcome));
        }
    }
    assert_eq!(sessions.len(), BOUNDED_SCALE_STALL_SESSION_SLOTS);

    let mut representatives = Vec::new();
    let matched_workload_outcomes = AtomicU64::new(0);
    let mut nonce = BOUNDED_SCALE_STALL_SESSION_SLOTS;
    let mut cumulative_completed_batches = 0usize;
    for (phase_name, target_rate) in BOUNDED_SCALE_STALL_PHASES {
        let phase_started = Instant::now();
        let mut latency = ReleaseLatencySamples::default();
        let mut submitted_batches = 0usize;
        let mut completed_batches = 0usize;
        let mut in_flight: JoinSet<Result<ReleaseBatchCompletion, ReleaseBatchFailure>> =
            JoinSet::new();
        let mut in_flight_session_slots = BTreeSet::new();
        let mut peak_unjoined_batch_task_slots = 0usize;

        while completed_batches < BOUNDED_SCALE_STALL_BATCHES_PER_PHASE {
            if submitted_batches < BOUNDED_SCALE_STALL_BATCHES_PER_PHASE
                && in_flight.len() < QUALIFICATION_IN_FLIGHT_CLIENTS
            {
                let mut requests = Vec::with_capacity(QUALIFICATION_PACED_BATCH_OPERATIONS);
                let mut session_slots = Vec::with_capacity(QUALIFICATION_PACED_BATCH_OPERATIONS);
                let mut scheduled_at = Vec::with_capacity(QUALIFICATION_PACED_BATCH_OPERATIONS);
                for batch_offset in 0..QUALIFICATION_PACED_BATCH_OPERATIONS {
                    let scheduled_operations =
                        submitted_batches * QUALIFICATION_PACED_BATCH_OPERATIONS + batch_offset;
                    pace_release_phase(phase_started, scheduled_operations, target_rate).await;
                    scheduled_at.push(
                        phase_started
                            + qualification_schedule_offset(scheduled_operations, target_rate),
                    );
                    let slot = (0..sessions.len())
                        .find(|slot| !in_flight_session_slots.contains(slot))
                        .expect("bounded-scale session slots cover every in-flight batch item");
                    assert!(
                        in_flight_session_slots.insert(slot),
                        "one bounded-scale session cannot have two V2 mutations in flight"
                    );
                    let update =
                        renew_update_request(nonce, history_epoch, &sessions[slot].1, &provider)
                            .await;
                    assert_exact_qualified_update_request(&sessions[slot].1, &update);
                    requests.push(update);
                    session_slots.push(slot);
                    nonce += 1;
                }
                let task_ingress_store = (*ingress_store).clone();
                let task_effect_counters = Arc::clone(&effect_counters);
                let batch_started = Instant::now();
                let batch_deadline = batch_started
                    .checked_add(QUALIFICATION_RELEASE_BATCH_DEADLINE)
                    .expect("release batch deadline is representable");
                in_flight.spawn(async move {
                    let outcomes = execute_release_store_batch(
                        batch_deadline,
                        &task_ingress_store,
                        requests.clone(),
                        &task_effect_counters,
                    )
                    .await?;
                    let completed_at = Instant::now();
                    Ok(ReleaseBatchCompletion {
                        requests,
                        outcomes,
                        session_slots,
                        scheduled_at,
                        batch_elapsed: completed_at.duration_since(batch_started),
                        completed_at,
                        successor_first_item: false,
                    })
                });
                submitted_batches += 1;
                peak_unjoined_batch_task_slots =
                    peak_unjoined_batch_task_slots.max(in_flight.len());
                continue;
            }

            let batch_len = match collect_next_release_batch(
                &mut in_flight,
                &mut in_flight_session_slots,
                &mut latency,
                &mut sessions,
                &mut representatives,
                &matched_workload_outcomes,
            )
            .await
            {
                Ok(batch_len) => batch_len,
                Err(failure) => {
                    fail_bounded_scale_stall(
                        directory,
                        &peer_slots,
                        &diagnostics,
                        failure.stage.as_str(),
                        &mut bounded_scale_observation(
                            phase_name,
                            target_rate,
                            phase_started,
                            submitted_batches,
                            completed_batches,
                            peak_unjoined_batch_task_slots,
                            &mut latency,
                        ),
                    )
                    .await;
                    unreachable!("bounded scale failure always panics")
                }
            };
            if batch_len != QUALIFICATION_PACED_BATCH_OPERATIONS {
                fail_bounded_scale_stall(
                    directory,
                    &peer_slots,
                    &diagnostics,
                    "paced_batch_shape",
                    &mut bounded_scale_observation(
                        phase_name,
                        target_rate,
                        phase_started,
                        submitted_batches,
                        completed_batches,
                        peak_unjoined_batch_task_slots,
                        &mut latency,
                    ),
                )
                .await;
                unreachable!("bounded scale failure always panics")
            }
            completed_batches += 1;
        }

        // The workload ends when the final submitted batch completes. Freeze
        // its elapsed time before the read-only status/history evidence below
        // so their convergence work cannot reduce the measured throughput.
        let workload_elapsed = phase_started.elapsed();

        assert_eq!(submitted_batches, BOUNDED_SCALE_STALL_BATCHES_PER_PHASE);
        assert!(in_flight.is_empty());
        assert!(in_flight_session_slots.is_empty());
        assert!(peak_unjoined_batch_task_slots <= QUALIFICATION_IN_FLIGHT_CLIENTS);
        cumulative_completed_batches += completed_batches;

        // The final request from a fixed slot must retain an exact recorded
        // receipt after every phase. This is deliberately a read-only status
        // convergence check; it does not issue another mutation or inspect a
        // private receipt table.
        let exact_status = match retry_exact_consensus_operation(&transient_retries, || {
            ingress_store.fenced_transition_v2_status(&sessions[0].0)
        })
        .await
        {
            Ok(status) => status,
            Err(_) => {
                fail_bounded_scale_stall(
                    directory,
                    &peer_slots,
                    &diagnostics,
                    "exact_status_read",
                    &mut bounded_scale_observation(
                        phase_name,
                        target_rate,
                        phase_started,
                        submitted_batches,
                        completed_batches,
                        peak_unjoined_batch_task_slots,
                        &mut latency,
                    )
                    .with_workload_elapsed(workload_elapsed),
                )
                .await;
                unreachable!("bounded scale failure always panics")
            }
        };
        if !matches!(
            exact_status,
            FencedTransitionV2Status::Recorded(result)
                if result
                    .as_ref()
                    .as_ref()
                    .is_ok_and(|outcome| outcome.matches_v2_request(&sessions[0].0))
        ) {
            fail_bounded_scale_stall(
                directory,
                &peer_slots,
                &diagnostics,
                "exact_status_mismatch",
                &mut bounded_scale_observation(
                    phase_name,
                    target_rate,
                    phase_started,
                    submitted_batches,
                    completed_batches,
                    peak_unjoined_batch_task_slots,
                    &mut latency,
                )
                .with_workload_elapsed(workload_elapsed),
            )
            .await;
            unreachable!("bounded scale failure always panics")
        }

        let history = match retry_exact_consensus_operation(&transient_retries, || {
            ingress_store.fenced_transition_v2_history_state()
        })
        .await
        {
            Ok(history) => history,
            Err(_) => {
                fail_bounded_scale_stall(
                    directory,
                    &peer_slots,
                    &diagnostics,
                    "history_read",
                    &mut bounded_scale_observation(
                        phase_name,
                        target_rate,
                        phase_started,
                        submitted_batches,
                        completed_batches,
                        peak_unjoined_batch_task_slots,
                        &mut latency,
                    )
                    .with_workload_elapsed(workload_elapsed),
                )
                .await;
                unreachable!("bounded scale failure always panics")
            }
        };
        let expected_bound_entries = BOUNDED_SCALE_STALL_SESSION_SLOTS
            + cumulative_completed_batches * QUALIFICATION_PACED_BATCH_OPERATIONS;
        if history.bound_entries() != expected_bound_entries {
            fail_bounded_scale_stall(
                directory,
                &peer_slots,
                &diagnostics,
                "history_bound_entries",
                &mut bounded_scale_observation(
                    phase_name,
                    target_rate,
                    phase_started,
                    submitted_batches,
                    completed_batches,
                    peak_unjoined_batch_task_slots,
                    &mut latency,
                )
                .with_workload_elapsed(workload_elapsed),
            )
            .await;
            unreachable!("bounded scale failure always panics")
        }

        emit_bounded_scale_stall_observation(
            &diagnostics,
            "completed",
            &mut bounded_scale_observation(
                phase_name,
                target_rate,
                phase_started,
                submitted_batches,
                completed_batches,
                peak_unjoined_batch_task_slots,
                &mut latency,
            )
            .with_workload_elapsed(workload_elapsed),
        );
    }

    assert_eq!(
        matched_workload_outcomes.load(Ordering::Relaxed),
        (BOUNDED_SCALE_STALL_BATCHES_PER_PHASE
            * BOUNDED_SCALE_STALL_PHASES.len()
            * QUALIFICATION_PACED_BATCH_OPERATIONS) as u64,
        "every bounded-scale outcome must match its exact V2 request"
    );
    // Snapshot publication briefly moves followers through a non-admitted
    // status while the durable state is installed. Read-only readiness
    // convergence distinguishes that expected publication transition from a
    // persistent quorum loss without submitting another mutation.
    let _ = ready_leader(&stores).await;
    let final_statuses = stores
        .iter()
        .map(ConsensusSessionStore::status)
        .collect::<Vec<_>>();
    if !final_statuses.iter().all(|status| status.admitted) {
        fail_bounded_scale_stall(
            directory,
            &peer_slots,
            &diagnostics,
            "quorum_not_admitted",
            &mut bounded_scale_observation(
                "snapshot-threshold-summary",
                0,
                Instant::now(),
                0,
                0,
                0,
                &mut ReleaseLatencySamples::default(),
            ),
        )
        .await;
        unreachable!("bounded scale failure always panics")
    }
    if final_statuses
        .iter()
        .any(|status| status.completed_snapshot_count < 2)
    {
        fail_bounded_scale_stall(
            directory,
            &peer_slots,
            &diagnostics,
            "fewer_than_two_completed_snapshots_per_voter",
            &mut bounded_scale_observation(
                "snapshot-threshold-summary",
                0,
                Instant::now(),
                0,
                0,
                0,
                &mut ReleaseLatencySamples::default(),
            ),
        )
        .await;
        unreachable!("bounded scale failure always panics")
    }
    let completed_snapshot_count = final_statuses
        .iter()
        .map(|status| status.completed_snapshot_count)
        .sum::<u64>();
    if transient_retries.load(Ordering::Relaxed) != 0 {
        fail_bounded_scale_stall(
            directory,
            &peer_slots,
            &diagnostics,
            "read_backend_unavailable",
            &mut bounded_scale_observation(
                "snapshot-threshold-summary",
                0,
                Instant::now(),
                0,
                0,
                0,
                &mut ReleaseLatencySamples::default(),
            ),
        )
        .await;
        unreachable!("bounded scale failure always panics")
    }
    eprintln!(
        "sdk-704 bounded snapshot scale summary: cargo_profile_family={} cargo_opt_level={} debug_assertions={} topology_voters={} session_slots={} batches_per_phase={} total_batches={} total_exact_outcomes={} required_completed_snapshots_per_voter=2 read_backend_unavailable_retries={} completed_snapshot_count_by_voter={:?} total_completed_snapshots={completed_snapshot_count}",
        build_profile.cargo_profile_family,
        build_profile.cargo_opt_level,
        build_profile.debug_assertions,
        stores.len(),
        BOUNDED_SCALE_STALL_SESSION_SLOTS,
        BOUNDED_SCALE_STALL_BATCHES_PER_PHASE,
        cumulative_completed_batches,
        matched_workload_outcomes.load(Ordering::Relaxed),
        transient_retries.load(Ordering::Relaxed),
        final_statuses
            .iter()
            .map(|status| status.completed_snapshot_count)
            .collect::<Vec<_>>(),
    );
    shutdown_fixed_cluster(&stores, &peer_slots).await;
}

/// Full SDK-702 release workload through a real three-voter OpenRaft quorum.
///
/// This is intentionally ignored: it submits the real 1,010,000 operations
/// (50,000 preload, 500/s for 30 minutes, then 1,000/s for 60 seconds) using
/// the public V2 API.  It does not substitute generic batches, seed receipts,
/// or call SQLite/state-machine internals. The pacing assertions cover both
/// requested finite-window rates and emit only fixed-dimension, redaction-safe
/// release evidence.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "SDK-702 real 1,010,000-operation three-voter release qualification"]
#[allow(clippy::assertions_on_constants)] // Keep the runtime assertion for the ignored release recipe.
async fn release_1010000_operation_successor_scale_is_bounded_and_recoverable() {
    assert!(
        cfg!(target_os = "linux"),
        "release qualification requires Linux VmHWM"
    );
    let provenance_at_start = release_evidence_provenance_snapshot();
    let observed_libtest_argv = observed_release_libtest_argv();
    let (artifact, execution, process_loss, _qualification_host_lease) =
        required_release_evidence_artifact(&provenance_at_start, &observed_libtest_argv);
    let build_profile = require_release_qualification_profile();
    let quiet_host_monitor = QualificationQuietHostMonitor::start()
        .expect("quiet host must be observed before qualification work begins");
    let started = Instant::now();
    // Keep mutable SQLite files, WALs, and general test scratch on the normal
    // tempfile filesystem. Only immutable fixed-quorum snapshots use the
    // wrapper-created fs-verity namespace.
    let directory = tempfile::tempdir().expect("SDK-702 release qualification directory");
    let snapshot_root = required_release_fs_verity_snapshot_root(&execution);
    #[cfg(unix)]
    assert_ne!(
        std::fs::metadata(directory.path())
            .expect("stat SDK-702 ordinary workspace")
            .dev(),
        std::fs::metadata(&snapshot_root)
            .expect("stat attested fs-verity snapshot root")
            .dev(),
        "mutable SQLite/WAL workspace must not share the fs-verity snapshot filesystem"
    );
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("SDK-702 release qualification start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (mut stores, database_paths, snapshot_paths, mut peer_slots) =
        fixed_cluster_with_snapshot_root(directory.path(), &snapshot_root, clock.clone()).await;
    let provider = sealing_provider();
    let transient_retries = Arc::new(AtomicU64::new(0));
    // Keep every permitted retry in a causally distinct ledger: immutable
    // application observations, maintenance readback reconciliation, and
    // backend-proved non-transmitted effects. The serialized aggregate is
    // checked against these three exact components before publication.
    let maintenance_reconciliation_retries = AtomicU64::new(0);
    let effect_counters = Arc::new(ReleaseEffectCounters::default());
    let lifecycle_counters = Arc::new(ReleaseLifecycleMutationCounters::default());
    let production_maintenance_counters = ProductionMaintenanceCounters::default();
    let matched_workload_outcomes = Arc::new(AtomicU64::new(0));
    let matched_reclaim_outcomes = AtomicU64::new(0);
    let first_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    assert_eq!(
        QUALIFICATION_RELEASE_TRANSITIONS, 1_010_000,
        "the release envelope is 50k + (500/s * 30m) + (1k/s * 60s)"
    );
    assert_eq!(FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS, 1);
    assert_eq!(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, 7);
    assert_eq!(
        FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            * (FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS + FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS),
        "the public fixed resource contract must remain exactly eight epochs"
    );

    // The first V2 effect is deliberately singleton activation.  Every later
    // preload create is submitted through the public bounded coalescing API;
    // no receipt, database, or private-apply shortcut exists in this path.
    // Keep the original request/outcome as an attestation exemplar for each
    // epoch; later updates exercise independent lease renewal paths.
    // Readiness and leader discovery are phase setup, not application traffic.
    // Keep one public ingress: its normal forwarding path follows any later
    // leader change without adding three fresh read barriers to every batch.
    let leader = ready_leader(&stores).await;
    let ingress_store = &stores[leader];
    let first_key = key(0);
    let first_observation = retry_exact_consensus_operation(&transient_retries, || {
        ingress_store.observe_fenced_transition(&first_key)
    })
    .await
    .expect("singleton activation fence observation");
    let first_request = create_request(
        0,
        first_epoch,
        first_key,
        first_observation.current_fence(),
        &provider,
    )
    .await;
    let first_outcome = execute_release_store_batch(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        ingress_store,
        vec![first_request.clone()],
        &effect_counters,
    )
    .await
    .expect("singleton V2 activation effect must converge")
    .into_iter()
    .next()
    .expect("singleton V2 activation has one result")
    .expect("singleton V2 activation");
    assert_exact_qualified_v2_success(&first_request, &first_outcome);
    matched_workload_outcomes.fetch_add(1, Ordering::Relaxed);
    let mut sessions = vec![(first_request, first_outcome)];
    for chunk_start in (1..QUALIFICATION_SESSIONS).step_by(QUALIFICATION_PRELOAD_BATCH_OPERATIONS) {
        let chunk_end =
            (chunk_start + QUALIFICATION_PRELOAD_BATCH_OPERATIONS).min(QUALIFICATION_SESSIONS);
        let mut requests = Vec::with_capacity(chunk_end - chunk_start);
        for session_index in chunk_start..chunk_end {
            let session_key = key(session_index);
            let observation = retry_exact_consensus_operation(&transient_retries, || {
                ingress_store.observe_fenced_transition(&session_key)
            })
            .await
            .expect("preload batch fence observation");
            requests.push(
                create_request(
                    session_index,
                    first_epoch,
                    session_key,
                    observation.current_fence(),
                    &provider,
                )
                .await,
            );
        }
        let outcomes = execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            ingress_store,
            requests.clone(),
            &effect_counters,
        )
        .await
        .expect("preload bounded V2 batch effect must converge");
        assert_eq!(outcomes.len(), requests.len());
        for (request, outcome) in requests.into_iter().zip(outcomes) {
            let outcome = outcome.expect("preload item result");
            assert_exact_qualified_v2_success(&request, &outcome);
            matched_workload_outcomes.fetch_add(1, Ordering::Relaxed);
            sessions.push((request, outcome));
        }
    }
    assert_eq!(sessions.len(), QUALIFICATION_SESSIONS);
    let mut representatives = vec![sessions[0].clone()];
    let mut active_epoch = first_epoch;
    let mut active_entries = QUALIFICATION_SESSIONS;
    let mut nonce = QUALIFICATION_SESSIONS;
    let mut rotations = 0usize;
    let mut phase_evidence = Vec::with_capacity(2);

    // Keep exactly 50,000 representative sessions in memory. The retained
    // receipt resource itself is bounded by the public eight-epoch contract
    // asserted above, not by this test-side cache.
    for (phase_name, target_rate, operations) in [
        (
            "sustained-500-per-second",
            QUALIFICATION_SUSTAINED_RATE,
            QUALIFICATION_SUSTAINED_TRANSITIONS,
        ),
        (
            "burst-1000-per-second",
            QUALIFICATION_BURST_RATE,
            QUALIFICATION_BURST_TRANSITIONS,
        ),
    ] {
        let phase_started = Instant::now();
        let mut latency = ReleaseLatencySamples::default();
        let mut submitted = 0usize;
        let mut completed = 0usize;
        let mut in_flight: JoinSet<Result<ReleaseBatchCompletion, ReleaseBatchFailure>> =
            JoinSet::new();
        let mut in_flight_session_slots = BTreeSet::new();
        // `JoinSet::len()` counts submitted batch tasks until they are
        // joined, including a task that has already completed. It bounds
        // outstanding/unjoined client task slots; it is not a measurement of
        // simultaneously executing consensus calls.
        let mut peak_unjoined_batch_task_slots = 0usize;
        while completed < operations {
            if active_entries == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
                assert!(
                    in_flight.is_empty() && in_flight_session_slots.is_empty(),
                    "successor rotation must wait for every exact submitted batch"
                );
                let leader = current_local_maintenance_leader(&stores).await;
                let before = retry_exact_consensus_operation(&transient_retries, || {
                    stores[leader].fenced_transition_v2_history_state()
                })
                .await
                .expect("linearized full active epoch before successor rotation");
                assert_eq!(before.active_epoch(), Some(active_epoch));
                assert_eq!(
                    before.bound_entries(),
                    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                );
                assert!(
                    rotations < FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS,
                    "the 1.01m envelope must require exactly seven successors, never a ninth epoch"
                );
                let after = measure_eventual_lifecycle_mutation(
                    &lifecycle_counters,
                    maintain_exact_history_batch(
                        &stores,
                        before,
                        &maintenance_reconciliation_retries,
                        &production_maintenance_counters,
                        None,
                    ),
                    Result::is_ok,
                )
                .await
                .expect("open bounded successor through local-leader maintenance");
                rotations += 1;
                active_epoch = FencedTransitionV2HistoryEpoch::new(active_epoch.get() + 1)
                    .expect("representable successor epoch");
                assert_eq!(after.active_epoch(), Some(active_epoch));
                assert_eq!(after.retired_through(), None);
                assert_eq!(after.reclaim_epoch(), None);
                assert_eq!(after.bound_entries(), 0);
                active_entries = 0;

                // Every earlier epoch remains publicly attestable and exactly
                // replayable before the 24-hour floor/reclaim boundary.
                for (request, outcome) in &representatives {
                    assert!(matches!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2_status(request)
                        })
                        .await
                        .expect("pre-floor representative status"),
                        FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
                    ));
                    let replay = execute_release_store_batch(
                        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
                        &stores[leader],
                        vec![request.clone()],
                        &effect_counters,
                    )
                    .await
                    .expect("pre-floor exact replay effect must converge")
                    .into_iter()
                    .next()
                    .expect("pre-floor exact replay has one result")
                    .expect("pre-floor exact replay");
                    assert_exact_qualified_v2_success(request, &replay);
                    assert_eq!(replay, *outcome);
                    let changed = request_with_changed_body(request);
                    assert_eq!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2_status(&changed)
                        })
                        .await
                        .expect("pre-floor changed-body status"),
                        FencedTransitionV2Status::RequestConflict
                    );
                }
            }

            let outstanding_entries = in_flight_session_slots.len();
            let remaining_epoch_capacity = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                .checked_sub(active_entries + outstanding_entries)
                .expect("in-flight release batches remain within the active epoch");
            if submitted < operations
                && in_flight.len() < QUALIFICATION_IN_FLIGHT_CLIENTS
                && remaining_epoch_capacity > 0
            {
                let batch_len = QUALIFICATION_PACED_BATCH_OPERATIONS
                    .min(operations - submitted)
                    .min(remaining_epoch_capacity);
                let mut requests = Vec::with_capacity(batch_len);
                let mut session_slots = Vec::with_capacity(batch_len);
                let mut scheduled_at = Vec::with_capacity(batch_len);
                let successor_first_item = active_entries == 0 && outstanding_entries == 0;
                for batch_offset in 0..batch_len {
                    pace_release_phase(phase_started, submitted + batch_offset, target_rate).await;
                    scheduled_at.push(
                        phase_started
                            + qualification_schedule_offset(submitted + batch_offset, target_rate),
                    );
                    // Every outstanding batch updates disjoint independently
                    // fenced sessions. Its first item after a rotation is
                    // retained as that epoch's exact replay representative.
                    // Physical coalescing never creates an all-or-nothing
                    // multi-key contract or permits two concurrent effects
                    // for one session.
                    let slot = nonce % sessions.len();
                    assert!(
                        in_flight_session_slots.insert(slot),
                        "one session cannot have two release mutations in flight"
                    );
                    let update =
                        renew_update_request(nonce, active_epoch, &sessions[slot].1, &provider)
                            .await;
                    assert_exact_qualified_update_request(&sessions[slot].1, &update);
                    requests.push(update);
                    session_slots.push(slot);
                    nonce += 1;
                }
                let task_ingress_store = (*ingress_store).clone();
                let task_effect_counters = Arc::clone(&effect_counters);
                let batch_started = Instant::now();
                let batch_deadline = batch_started
                    .checked_add(QUALIFICATION_RELEASE_BATCH_DEADLINE)
                    .expect("release batch deadline is representable");
                in_flight.spawn(async move {
                    let outcomes = execute_release_store_batch(
                        batch_deadline,
                        &task_ingress_store,
                        requests.clone(),
                        &task_effect_counters,
                    )
                    .await?;
                    let completed_at = Instant::now();
                    Ok(ReleaseBatchCompletion {
                        requests,
                        outcomes,
                        session_slots,
                        scheduled_at,
                        batch_elapsed: completed_at.duration_since(batch_started),
                        completed_at,
                        successor_first_item,
                    })
                });
                submitted += batch_len;
                peak_unjoined_batch_task_slots =
                    peak_unjoined_batch_task_slots.max(in_flight.len());
                continue;
            }
            let batch_len = match collect_next_release_batch(
                &mut in_flight,
                &mut in_flight_session_slots,
                &mut latency,
                &mut sessions,
                &mut representatives,
                &matched_workload_outcomes,
            )
            .await
            {
                Ok(batch_len) => batch_len,
                Err(failure) => {
                    let voter_status = stores
                        .iter()
                        .map(ConsensusSessionStore::status)
                        .collect::<Vec<_>>();
                    let voter_diagnostics = stores
                        .iter()
                        .map(ConsensusSessionStore::diagnostic_snapshot)
                        .collect::<Vec<_>>();
                    let effect_snapshot = effect_counters.snapshot();
                    eprintln!(
                        "sdk-702 successor failure: phase={phase_name} stage={} submitted={submitted} completed={completed} active_entries={active_entries} in_flight_batches={} in_flight_sessions={} effect_counters={effect_snapshot:?} voter_status={voter_status:?} voter_diagnostics={voter_diagnostics:?}",
                        failure.stage.as_str(),
                        in_flight.len(),
                        in_flight_session_slots.len(),
                    );
                    panic!(
                        "paced bounded V2 batch failed closed at stage {}",
                        failure.stage.as_str()
                    );
                }
            };
            active_entries += batch_len;
            completed += batch_len;
        }
        assert_eq!(submitted, operations);
        assert!(in_flight.is_empty());
        assert!(in_flight_session_slots.is_empty());
        assert!(peak_unjoined_batch_task_slots <= QUALIFICATION_IN_FLIGHT_CLIENTS);
        let elapsed = phase_started.elapsed();
        let batch_samples = latency.batch.len();
        let item_samples = latency.item_scheduled_to_completion.len();
        let (batch_p99, batch_p999, item_p99, item_p999) = latency.p99_and_p999();
        let batch_max = *latency
            .batch
            .last()
            .expect("qualified phase has a batch maximum after percentile sort");
        let item_max = *latency
            .item_scheduled_to_completion
            .last()
            .expect("qualified phase has an item maximum after percentile sort");
        assert_qualification_phase_pacing(elapsed, operations as u64, target_rate as u64);
        assert!(item_p99 <= Duration::from_millis(25));
        assert!(item_p999 <= Duration::from_millis(100));
        assert!(
            batch_max <= QUALIFICATION_RELEASE_BATCH_DEADLINE,
            "a qualified batch must not hide a multi-second tail behind percentiles"
        );
        assert!(
            item_max <= QUALIFICATION_RELEASE_BATCH_DEADLINE,
            "a qualified item must not hide a multi-second tail behind percentiles"
        );
        phase_evidence.push(ReleaseEvidencePhase {
            name: phase_name.to_owned(),
            offered_ops_per_second: target_rate as u64,
            operations: operations as u64,
            // Every relevant `Duration` above was compared against its exact
            // bound before this intentionally coarser evidence conversion.
            elapsed_ms: duration_evidence_milliseconds(elapsed, "qualified phase elapsed"),
            batch_samples: batch_samples as u64,
            item_samples: item_samples as u64,
            peak_unjoined_batch_task_slots: peak_unjoined_batch_task_slots as u64,
            batch_p99_us: duration_evidence_microseconds(batch_p99, "qualified batch p99"),
            batch_p999_us: duration_evidence_microseconds(batch_p999, "qualified batch p999"),
            batch_max_us: duration_evidence_microseconds(batch_max, "qualified batch maximum"),
            item_p99_us: duration_evidence_microseconds(item_p99, "qualified item p99"),
            item_p999_us: duration_evidence_microseconds(item_p999, "qualified item p999"),
            item_max_us: duration_evidence_microseconds(item_max, "qualified item maximum"),
        });
    }

    assert_eq!(
        nonce, QUALIFICATION_RELEASE_TRANSITIONS,
        "the paced workload must use exactly its declared 1,010,000 unique V2 IDs"
    );
    assert_eq!(sessions.len(), QUALIFICATION_SESSIONS);
    assert_eq!(
        matched_workload_outcomes.load(Ordering::Relaxed),
        QUALIFICATION_RELEASE_TRANSITIONS as u64,
        "every declared workload result must match its exact request and expected mutation"
    );
    assert_eq!(rotations, 7, "the 1.01m envelope crosses seven successors");
    let leader = ready_leader(&stores).await;
    let history = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("history after 1.01m real operations");
    assert_eq!(
        history.active_epoch(),
        Some(FencedTransitionV2HistoryEpoch::new(8).expect("epoch 8"))
    );
    assert_eq!(history.retired_through(), None);
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(
        history.bound_entries(),
        QUALIFICATION_RELEASE_TRANSITIONS % FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
    );
    assert_eq!(representatives.len(), 8);

    // A restart after seven rotations uses only the public shutdown and
    // constructor boundaries plus the same durable voter files. Removing all
    // authenticated handlers before waiting for every engine-owned task makes
    // this a graceful same-process engine reopen: no old handler or engine
    // can serve the reopened paths.
    let logical_in_process_voters =
        u64::try_from(stores.len()).expect("logical voter count fits release evidence");
    shutdown_fixed_cluster(&stores, &peer_slots).await;
    drop(stores);
    drop(peer_slots);
    // These samples are deliberately taken with all first-generation stores,
    // engines, peer handlers, and backends dropped.  No object can checkpoint
    // or append while the pre-reclaim filesystem evidence is observed.
    let database_bytes_before_reclaim_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_before_reclaim_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    assert_voter_resource_ceiling(
        "pre-reclaim SQLite database family",
        &database_bytes_before_reclaim_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "pre-reclaim snapshot directory",
        &snapshot_bytes_before_reclaim_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    let (stores_after_restart, _, _, peer_slots_after_restart) =
        fixed_cluster_with_snapshot_root(directory.path(), &snapshot_root, clock.clone()).await;
    stores = stores_after_restart;
    peer_slots = peer_slots_after_restart;
    let leader = ready_leader(&stores).await;
    for (request, outcome) in &representatives {
        assert!(matches!(
            retry_exact_consensus_operation(&transient_retries, || {
                stores[leader].fenced_transition_v2_status(request)
            })
            .await
            .expect("restart exact status"),
            FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
        ));
        let replay = execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            &stores[leader],
            vec![request.clone()],
            &effect_counters,
        )
        .await
        .expect("restart exact replay effect must converge")
        .into_iter()
        .next()
        .expect("restart exact replay has one result")
        .expect("restart exact replay");
        assert_exact_qualified_v2_success(request, &replay);
        assert_eq!(replay, *outcome);
        let changed = request_with_changed_body(request);
        assert_eq!(
            retry_exact_consensus_operation(&transient_retries, || {
                stores[leader].fenced_transition_v2_status(&changed)
            })
            .await
            .expect("restart changed-body status"),
            FencedTransitionV2Status::RequestConflict
        );
    }

    // The eight epoch representatives above prove retained replay and
    // conflict classification. Independently sweep the newest request and
    // result for every active session through only public read surfaces. This
    // binds the final 50,000 receipts to their exact request bodies and proves
    // that the corresponding live record/fence survived the durable restart.
    // These reads occur after the timed 1.01m mutation workload and are not
    // counted as release operations.
    let active_integrity_pairs = futures_util::stream::iter(&sessions)
        .map(|(request, outcome)| {
            let transient_retries = Arc::clone(&transient_retries);
            let store = &stores[leader];
            async move {
                assert!(matches!(
                    retry_exact_consensus_operation(&transient_retries, || {
                        store.fenced_transition_v2_status(request)
                    })
                    .await
                    .expect("restart latest-session exact status"),
                    FencedTransitionV2Status::Recorded(result)
                        if result.as_ref() == &Ok(outcome.clone())
                ));
                let observation = retry_exact_consensus_operation(&transient_retries, || {
                    store.observe_fenced_transition(request.lease().key())
                })
                .await
                .expect("restart latest-session public record observation");
                let expected_record = request
                    .mutation()
                    .record()
                    .expect("latest active request carries its committed record");
                assert_eq!(observation.record(), Some(expected_record));
                assert_eq!(observation.current_fence(), expected_record.fence);
                assert_eq!(observation.current_fence(), outcome.lease().fence());
            }
        })
        .buffer_unordered(QUALIFICATION_IN_FLIGHT_CLIENTS)
        .count()
        .await;
    assert_eq!(active_integrity_pairs, QUALIFICATION_SESSIONS);

    // Logical-time acceleration crosses the 24-hour boundary without a
    // wall-clock day. The first reclaim must advance only the oldest floor,
    // delete at most one ordered batch, and leave epoch 8 writable.
    clock.set(
        start
            .add_seconds(24 * 60 * 60 + 1)
            .expect("retention boundary"),
    );
    let before_floor = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized history before floor advancement");
    // Discard exactly one already-successful public maintenance reply. This
    // is post-commit reply loss only: the helper must reconcile by a fresh
    // linearized state read, never retry the stale expected-state CAS.
    let post_commit_reply_loss = AtomicUsize::new(1);
    let after_floor = measure_eventual_lifecycle_mutation(
        &lifecycle_counters,
        maintain_exact_history_batch(
            &stores,
            before_floor,
            &maintenance_reconciliation_retries,
            &production_maintenance_counters,
            Some(&post_commit_reply_loss),
        ),
        Result::is_ok,
    )
    .await
    .expect("reconcile an accepted oldest-floor advancement after reply loss");
    assert_eq!(
        post_commit_reply_loss.load(Ordering::SeqCst),
        0,
        "the test must discard exactly one successful maintenance reply"
    );
    let epoch_one = FencedTransitionV2HistoryEpoch::new(1).expect("epoch one");
    let epoch_eight = FencedTransitionV2HistoryEpoch::new(8).expect("epoch eight");
    assert_eq!(after_floor.generation(), before_floor.generation() + 1);
    assert_eq!(after_floor.active_epoch(), Some(epoch_eight));
    assert_eq!(after_floor.active_epoch(), before_floor.active_epoch());
    assert_eq!(before_floor.retired_through(), None);
    assert_eq!(after_floor.retired_through(), Some(epoch_one));
    assert_eq!(after_floor.reclaim_epoch(), Some(epoch_one));
    assert_eq!(
        after_floor.reclaim_remaining(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - FENCED_TRANSITION_V2_RECLAIM_BATCH
    );
    assert_eq!(
        after_floor.reclaimed_entries(),
        before_floor.reclaimed_entries() + FENCED_TRANSITION_V2_RECLAIM_BATCH as u64,
        "the ordered reclaim cursor advances by exactly one bounded batch"
    );
    let observed_after_reply_loss = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized history reconstructed after maintenance reply loss");
    assert_eq!(observed_after_reply_loss, after_floor);
    assert_eq!(
        measure_eventual_lifecycle_mutation(
            &lifecycle_counters,
            maintain_exact_history_batch(
                &stores,
                before_floor,
                &maintenance_reconciliation_retries,
                &production_maintenance_counters,
                None,
            ),
            Result::is_ok,
        )
        .await,
        Ok(after_floor),
        "the exact stale expected state must reconcile by readback without a second batch"
    );
    let observed_after_stale_retry = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized history after stale maintenance retry");
    assert_eq!(
        observed_after_stale_retry, after_floor,
        "the stale expected-state retry has no second lifecycle, floor, or cursor effect"
    );
    // The public restart above proves durable replay recovery; the exact
    // SQLite snapshot companion is
    // `fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression`.
    let (oldest, _) = &representatives[0];
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            stores[leader].fenced_transition_v2_status(oldest)
        })
        .await
        .expect("oldest status at floor"),
        FencedTransitionV2Status::Retired
    );
    let changed_oldest = request_with_changed_body(oldest);
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            stores[leader].fenced_transition_v2_status(&changed_oldest)
        })
        .await
        .expect("oldest changed-body status at floor"),
        FencedTransitionV2Status::RequestConflict
    );

    let active_slot = nonce % sessions.len();
    let active_update =
        renew_update_request(nonce, epoch_eight, &sessions[active_slot].1, &provider).await;
    assert_exact_qualified_update_request(&sessions[active_slot].1, &active_update);
    let active_outcome = execute_release_store_batch(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        &stores[leader],
        vec![active_update.clone()],
        &effect_counters,
    )
    .await
    .expect("active successor effect converges during reclaim")
    .into_iter()
    .next()
    .expect("one active batch outcome")
    .expect("active batch item result");
    assert_exact_qualified_v2_success(&active_update, &active_outcome);
    matched_reclaim_outcomes.fetch_add(1, Ordering::Relaxed);
    sessions[active_slot] = (active_update.clone(), active_outcome.clone());
    let active_status = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_status(&active_update)
    })
    .await
    .expect("active reclaim-time exact receipt status");
    assert!(matches!(
        active_status,
        FencedTransitionV2Status::Recorded(result)
            if result
                .as_ref()
                .as_ref()
                .is_ok_and(|outcome| outcome.matches_v2_request(&active_update))
    ));
    let active_observation = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].observe_fenced_transition(active_update.lease().key())
    })
    .await
    .expect("active reclaim-time public record observation");
    let active_record = active_observation
        .record()
        .expect("active reclaim-time record remains present");
    assert_eq!(
        active_record,
        active_update
            .mutation()
            .record()
            .expect("active reclaim-time update carries its replacement record")
    );
    assert_eq!(
        matched_reclaim_outcomes.load(Ordering::Relaxed),
        1,
        "the reclaim-time write is separately counted from the 1.01m workload"
    );
    let during_reclaim = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized state after active mutation during reclaim");
    let after_second_reclaim = measure_eventual_lifecycle_mutation(
        &lifecycle_counters,
        maintain_exact_history_batch(
            &stores,
            during_reclaim,
            &maintenance_reconciliation_retries,
            &production_maintenance_counters,
            None,
        ),
        Result::is_ok,
    )
    .await
    .expect("continue bounded reclaim without allocating epoch nine");
    assert_eq!(after_second_reclaim.active_epoch(), Some(epoch_eight));
    assert_eq!(after_second_reclaim.retired_through(), Some(epoch_one));
    assert_eq!(after_second_reclaim.reclaim_epoch(), Some(epoch_one));
    assert_eq!(
        after_second_reclaim.reclaim_remaining(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 2 * FENCED_TRANSITION_V2_RECLAIM_BATCH,
        "the physical residual occupies the eighth slot; maintenance cannot allocate epoch nine"
    );

    let effect_snapshot = effect_counters.snapshot();
    let read_only_observation_retries = transient_retries.load(Ordering::Relaxed);
    let maintenance_reconciliation_retry_count =
        maintenance_reconciliation_retries.load(Ordering::Relaxed);
    let transient_exact_retries = read_only_observation_retries
        .checked_add(maintenance_reconciliation_retry_count)
        .and_then(|total| total.checked_add(effect_snapshot.not_transmitted_retries))
        .expect("release retry-attribution aggregate fits evidence");
    shutdown_fixed_cluster(&stores, &peer_slots).await;
    drop(stores);
    drop(peer_slots);
    // Final serialized resource evidence is sampled only after every store,
    // engine, peer, and backend handle has been joined and dropped.
    let database_bytes_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    let database_artifacts_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_artifacts(path))
        .collect::<Vec<_>>();
    let snapshot_artifacts_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_artifacts(path))
        .collect::<Vec<_>>();
    let peak_rss_kib = process_peak_rss_kib();
    assert_voter_resource_ceiling(
        "post-shutdown SQLite database family",
        &database_bytes_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "post-shutdown snapshot directory",
        &snapshot_bytes_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    #[cfg(target_os = "linux")]
    assert!(
        peak_rss_kib <= QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "three-voter peak RSS {peak_rss_kib} KiB exceeds the fixed {} KiB ceiling",
        QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
    );
    assert_eq!(effect_snapshot.resolved_after_deadline, 0);
    assert_eq!(
        effect_snapshot.mutation_batches,
        QUALIFICATION_EXPECTED_EFFECT_BATCHES
    );
    assert_eq!(
        effect_snapshot.effect_request_slots, QUALIFICATION_EXPECTED_EFFECT_REQUEST_SLOTS,
        "the fixed proposal batch plan has an exact request-slot cardinality"
    );
    assert!(
        effect_snapshot.batch_elapsed_max_us
            <= QUALIFICATION_RELEASE_BATCH_DEADLINE.as_micros() as u64,
        "all release mutation batches must meet the 800ms qualification bound after classification"
    );
    let lifecycle_snapshot = lifecycle_counters.snapshot();
    assert_eq!(
        lifecycle_snapshot.attempts, QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS,
        "seven rotations, two reclaim calls, and one stale no-effect CAS are measured exactly once"
    );
    assert!(
        lifecycle_snapshot.elapsed_max_us
            <= QUALIFICATION_RELEASE_BATCH_DEADLINE.as_micros() as u64,
        "all lifecycle mutations must complete their eventual classification within 800ms"
    );
    assert_eq!(lifecycle_snapshot.resolved_after_800ms, 0);
    assert_eq!(lifecycle_snapshot.deadline_exceeded, 0);
    assert_eq!(lifecycle_snapshot.failures, 0);
    let production_maintenance_snapshot = production_maintenance_counters.snapshot();
    assert_eq!(
        production_maintenance_snapshot.invocations,
        production_maintenance_snapshot
            .ok
            .checked_add(production_maintenance_snapshot.err)
            .expect("production maintenance result equation")
    );
    assert_eq!(
        production_maintenance_snapshot.invocations,
        QUALIFICATION_EXPECTED_LIFECYCLE_MUTATIONS
    );
    assert_eq!(production_maintenance_snapshot.ok, 9);
    assert_eq!(production_maintenance_snapshot.err, 1);
    assert_eq!(
        production_maintenance_snapshot.post_commit_reply_loss_projections,
        1
    );
    assert_eq!(production_maintenance_snapshot.readback_projections, 2);
    let elapsed_ms = u64::try_from(started.elapsed().as_millis())
        .expect("release qualification elapsed milliseconds fit evidence");
    let quiet_host = quiet_host_monitor
        .finish()
        .expect("quiet host must remain sampled throughout qualification work");
    let phase_elapsed_ms = phase_evidence
        .iter()
        .try_fold(0_u64, |total, phase| total.checked_add(phase.elapsed_ms))
        .expect("release phase elapsed milliseconds fit evidence");
    let non_phase_overhead_ms = elapsed_ms
        .checked_sub(phase_elapsed_ms)
        .expect("release total elapsed includes both timed phases");
    let evidence = ReleaseQualificationEvidence {
        version: 1,
        qualification_complete: true,
        elapsed_ms,
        non_phase_overhead_ms,
        source: provenance_at_start.source.clone(),
        build_cargo_lock_sha256: provenance_at_start.build_cargo_lock_sha256.clone(),
        runtime_cargo_lock_sha256: provenance_at_start.runtime_cargo_lock_sha256.clone(),
        required_reproduction_recipe: RELEASE_EVIDENCE_REQUIRED_REPRODUCTION_RECIPE.to_owned(),
        libtest_argv: observed_libtest_argv.clone(),
        artifact: artifact.evidence.clone(),
        execution,
        quiet_host,
        process_loss: process_loss.evidence.clone(),
        profile: ReleaseEvidenceProfile {
            cargo_profile_family: build_profile.cargo_profile_family.to_owned(),
            cargo_opt_level: build_profile.cargo_opt_level.to_owned(),
            debug_assertions: build_profile.debug_assertions,
        },
        schedule: ReleaseEvidenceSchedule {
            preload_operations: QUALIFICATION_SESSIONS as u64,
            sustained_operations: QUALIFICATION_SUSTAINED_TRANSITIONS as u64,
            sustained_rate_per_second: QUALIFICATION_SUSTAINED_RATE as u64,
            sustained_seconds: QUALIFICATION_SUSTAINED_SECONDS as u64,
            burst_operations: QUALIFICATION_BURST_TRANSITIONS as u64,
            burst_rate_per_second: QUALIFICATION_BURST_RATE as u64,
            burst_seconds: QUALIFICATION_BURST_SECONDS as u64,
            total_operations: QUALIFICATION_RELEASE_TRANSITIONS as u64,
        },
        resources: ReleaseEvidenceResources {
            voters: logical_in_process_voters,
            in_flight_clients: QUALIFICATION_IN_FLIGHT_CLIENTS as u64,
            batch_deadline_ms: QUALIFICATION_RELEASE_BATCH_DEADLINE.as_millis() as u64,
            operational_headroom_transitions: QUALIFICATION_OPERATIONAL_HEADROOM_TRANSITIONS as u64,
            retained_envelope_headroom_transitions:
                QUALIFICATION_RETAINED_ENVELOPE_HEADROOM_TRANSITIONS as u64,
            database_ceiling_bytes_per_voter: QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
            snapshot_ceiling_bytes_per_voter: QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
            process_peak_rss_ceiling_kib: qualification_process_peak_rss_ceiling_kib(),
            pre_reclaim_database_bytes_by_voter: database_bytes_before_reclaim_by_voter,
            pre_reclaim_snapshot_bytes_by_voter: snapshot_bytes_before_reclaim_by_voter,
            post_reclaim_database_bytes_by_voter: database_bytes_by_voter,
            post_reclaim_snapshot_bytes_by_voter: snapshot_bytes_by_voter,
            database_artifacts_by_voter,
            snapshot_artifacts_by_voter,
            peak_rss_kib,
            peak_rss_measurement: "linux_proc_self_status_vmhwm_kib".to_owned(),
        },
        lifecycle: ReleaseEvidenceLifecycle {
            rotations: rotations as u64,
            graceful_same_process_engine_reopens: 1,
            logical_in_process_voters: VOTERS as u64,
            reclaim_batches: 2,
            reclaimed_entries: after_second_reclaim.reclaimed_entries(),
            reclaim_remaining: after_second_reclaim.reclaim_remaining() as u64,
            maintenance_attempts: lifecycle_snapshot.attempts,
            maintenance_elapsed_max_us: lifecycle_snapshot.elapsed_max_us,
            maintenance_resolved_after_800ms: lifecycle_snapshot.resolved_after_800ms,
            maintenance_deadline_exceeded: lifecycle_snapshot.deadline_exceeded,
            maintenance_failures: lifecycle_snapshot.failures,
            production_maintenance_invocations: production_maintenance_snapshot.invocations,
            production_maintenance_ok: production_maintenance_snapshot.ok,
            production_maintenance_err: production_maintenance_snapshot.err,
            post_commit_reply_loss_projections: production_maintenance_snapshot
                .post_commit_reply_loss_projections,
            maintenance_readback_projections: production_maintenance_snapshot.readback_projections,
        },
        outcomes: ReleaseEvidenceOutcomes {
            release_operations_committed: QUALIFICATION_RELEASE_TRANSITIONS as u64,
            matched_workload_outcomes: matched_workload_outcomes.load(Ordering::Relaxed),
            reclaim_operations_committed: 1,
            matched_reclaim_outcomes: matched_reclaim_outcomes.load(Ordering::Relaxed),
            total_operations_committed: (QUALIFICATION_RELEASE_TRANSITIONS + 1) as u64,
            transient_exact_retries,
            read_only_observation_retries,
            maintenance_reconciliation_retries: maintenance_reconciliation_retry_count,
            effect_not_transmitted_retries: effect_snapshot.not_transmitted_retries,
        },
        effects: effect_snapshot,
        phases: phase_evidence,
    };
    let evidence = canonical_release_evidence_bytes(&evidence);
    publish_release_evidence_artifact(
        &artifact,
        &evidence,
        &provenance_at_start,
        &observed_libtest_argv,
        &process_loss,
        &_qualification_host_lease,
    );
    println!(
        "SDK702_RELEASE_EVIDENCE artifact_path_id={} artifact_sha256={} existing_validation_recipe={}",
        artifact.evidence.path_id,
        format_args!("{:x}", Sha256::digest(&evidence)),
        RELEASE_EVIDENCE_EXISTING_ARTIFACT_VALIDATION_RECIPE,
    );
}
