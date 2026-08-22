use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::{
    decode_bounded, derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch,
    ConsensusIdentity, DURABLE_CONSENSUS_TIMING_PROFILE, DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider,
    KeyPurpose, MemoryKeyProvider, SessionAad, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_session_store::fenced_mutation_roster::{
    FencedMutationRosterAdoption, FencedMutationRosterDescriptor, FencedMutationRosterDisposition,
    FencedMutationRosterOrdinal,
};
use opc_session_store::{
    derive_fenced_mutation_roster_scope, AtomicFencedTransitionCapability, Clock, CompareAndSet,
    CompareAndSetResult, ConsensusSessionStore, DurableReadinessReport, DurableReadinessScope,
    DurableReadinessState, DurableRecoveryState, EncryptedSessionPayload, EncryptingSessionBackend,
    FenceToken, FencedMutationRosterAdmission, FencedMutationRosterFenceIntent,
    FencedMutationRosterMember, FencedMutationRosterMemberAttestation,
    FencedMutationRosterMemberAttestationError, FencedMutationRosterMemberAttestationVerifier,
    FencedMutationRosterMemberExecutionContext, FencedMutationRosterMembers,
    FencedMutationRosterOperationId, FencedMutationRosterProtectedPlan,
    FencedMutationRosterProtectedResult, FencedMutationRosterProviderOutcome,
    FencedMutationRosterScope, FencedTransitionLease, FencedTransitionMutation,
    FencedTransitionMutationResult, FencedTransitionRequest, FencedTransitionRequestId,
    FencedTransitionStatus, Generation, LeaseError, ManagedProviderJobError,
    ManagedProviderJobMemberPhase, ManagedProviderJobMode, ManagedProviderJobRemoteProvider,
    ManagedProviderMemberStatusEvidence, ObservedPhysicalNodeIdentity, OwnerId,
    QuorumReplicaDescriptor, QuorumTopologyAttestor, QuorumTopologyConfig, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ReplicationOp,
    RestoreScanRequest, SessionBackend, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcFamily, SessionConsensusRpcHandler,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionConsumerIdentity,
    SessionConsumerScope, SessionConsumerV3Operation, SessionConsumerV3Request,
    SessionConsumerV3Response, SessionConsumerV4Operation, SessionConsumerV4Request,
    SessionConsumerV4Response, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp,
    SessionPayloadEncoding, SessionQuorumConsumer, SessionStorePlatformProfile,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord, SystemClock,
    TopologyAttestationClaims, TopologyAttestationEvidence, TopologyAttestationPolicy,
    TopologyAttestationProvenance, TopologyAttestationResult, TopologyAttestationTime,
    TopologyAttestationVerificationError, TopologyAttestationVerificationInput,
    TopologyCollectorId, ValidatedQuorumTopology, VerifiedQuorumTopologyAttestation,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_types::{NetworkFunctionKind, TenantId};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use tempfile::TempDir;
use tokio::sync::Notify;

const MEMBER_COUNT: usize = 3;
const OPERATION_TIMEOUT: Duration = Duration::from_millis(750);
// Allow one complete resampled election after a split vote, followed by one
// complete profiled operation. These test-evidence ceilings follow the shared
// timing authority instead of assuming the former short election window.
const RECOVERY_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);
const CLUSTER_START_TIMEOUT: Duration = RECOVERY_TIMEOUT;
const SNAPSHOT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_COMMAND_BATCH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SNAPSHOT_CATCH_UP_COMMANDS: usize = 4_300;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
// `timeout_at` bounds which protocol event wins, but a host runtime can only
// observe its timer once it is scheduled. Keep this below half the deliberate
// fault-gap so a delayed peer response can never satisfy this assertion.
const ATTESTATION_PROBE_TIMER_DISPATCH_TOLERANCE: Duration = Duration::from_millis(250);
const MAX_CAPTURED_CONSENSUS_PAYLOADS: usize = 4_096;
// Keep the bounded election qualification from competing with the deliberately
// expensive snapshot-compaction qualification under the parallel test harness.
static ELECTION_AND_SNAPSHOT_TEST_PERMIT: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(1);
// Each fixture runs three in-process Raft voters with bounded election and
// operation deadlines. Cap only these heavyweight fixtures so the default
// parallel libtest scheduler cannot make unrelated clusters consume one
// another's protocol budgets; non-cluster tests remain fully parallel.
static CLUSTER_TEST_PERMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
const ENCRYPTION_NAMESPACE: &str = "consensus-boundary-qualification";
const PLAINTEXT_CANARY_BEFORE_ROTATION: &[u8] =
    b"opc-session-consensus-plaintext-canary-before-key-rotation";
const PLAINTEXT_CANARY_AFTER_ROTATION: &[u8] =
    b"opc-session-consensus-plaintext-canary-after-key-rotation";
const RAW_KEY_MATERIAL_CANARY: &[u8; AES_256_GCM_SIV_KEY_LEN] = &[0x5a; AES_256_GCM_SIV_KEY_LEN];

/// A deterministic boundary double for the public durable-store adapter
/// tests below.  This deliberately does not model a remote mTLS provider;
/// the session-net qualification owns that transport proof.
#[derive(Clone)]
struct ManagedProviderAdapterDouble {
    execute_outcome: Option<FencedMutationRosterProviderOutcome>,
    status_outcome: AdapterStatusOutcome,
    execute_calls: Arc<AtomicUsize>,
    status_calls: Arc<AtomicUsize>,
    adopt_calls: Arc<AtomicUsize>,
    execute_gate: Option<Arc<AppendEntriesApplyGate>>,
}

#[derive(Clone, Copy)]
enum AdapterStatusOutcome {
    Inconclusive,
    NotApplied,
}

impl ManagedProviderAdapterDouble {
    fn applied() -> Self {
        Self {
            execute_outcome: Some(FencedMutationRosterProviderOutcome::AppliedExecuted),
            status_outcome: AdapterStatusOutcome::Inconclusive,
            execute_calls: Arc::new(AtomicUsize::new(0)),
            status_calls: Arc::new(AtomicUsize::new(0)),
            adopt_calls: Arc::new(AtomicUsize::new(0)),
            execute_gate: None,
        }
    }

    fn inconclusive() -> Self {
        Self {
            execute_outcome: None,
            status_outcome: AdapterStatusOutcome::Inconclusive,
            execute_calls: Arc::new(AtomicUsize::new(0)),
            status_calls: Arc::new(AtomicUsize::new(0)),
            adopt_calls: Arc::new(AtomicUsize::new(0)),
            execute_gate: None,
        }
    }

    fn not_applied() -> Self {
        Self {
            execute_outcome: None,
            status_outcome: AdapterStatusOutcome::NotApplied,
            execute_calls: Arc::new(AtomicUsize::new(0)),
            status_calls: Arc::new(AtomicUsize::new(0)),
            adopt_calls: Arc::new(AtomicUsize::new(0)),
            execute_gate: None,
        }
    }

    fn compensated() -> Self {
        Self {
            execute_outcome: Some(FencedMutationRosterProviderOutcome::CompensatedReconciled),
            status_outcome: AdapterStatusOutcome::Inconclusive,
            execute_calls: Arc::new(AtomicUsize::new(0)),
            status_calls: Arc::new(AtomicUsize::new(0)),
            adopt_calls: Arc::new(AtomicUsize::new(0)),
            execute_gate: None,
        }
    }

    fn applied_arming(gate: Arc<AppendEntriesApplyGate>) -> Self {
        let mut provider = Self::applied();
        provider.execute_gate = Some(gate);
        provider
    }

    fn attestation(
        context: &FencedMutationRosterMemberExecutionContext<'_>,
        outcome: FencedMutationRosterProviderOutcome,
    ) -> Result<FencedMutationRosterMemberAttestation, ()> {
        FencedMutationRosterMemberAttestation::new(context, outcome, Box::new([0x5a]))
            .map_err(|_| ())
    }
}

#[async_trait]
impl ManagedProviderJobRemoteProvider for ManagedProviderAdapterDouble {
    type Error = ();

    async fn execute_member(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterMemberAttestation, Self::Error> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.execute_gate {
            gate.arm();
        }
        self.execute_outcome
            .ok_or(())
            .and_then(|outcome| Self::attestation(context, outcome))
    }

    async fn member_status(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<ManagedProviderMemberStatusEvidence, Self::Error> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        match self.status_outcome {
            AdapterStatusOutcome::Inconclusive => {
                Ok(ManagedProviderMemberStatusEvidence::Inconclusive)
            }
            AdapterStatusOutcome::NotApplied => Ok(ManagedProviderMemberStatusEvidence::attested(
                Self::attestation(
                    context,
                    FencedMutationRosterProviderOutcome::NotAppliedReconciled,
                )?,
            )),
        }
    }

    async fn adopt_member(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
        _status: opc_session_store::ManagedProviderMemberStatus,
    ) -> Result<FencedMutationRosterMemberAttestation, Self::Error> {
        self.adopt_calls.fetch_add(1, Ordering::SeqCst);
        Self::attestation(context, FencedMutationRosterProviderOutcome::AppliedAdopted)
    }
}

struct ManagedProviderAdapterVerifier;

#[async_trait]
impl FencedMutationRosterMemberAttestationVerifier for ManagedProviderAdapterVerifier {
    async fn verify_member_attestation(
        &self,
        _identity: &SessionConsumerIdentity,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
        attestation: &FencedMutationRosterMemberAttestation,
    ) -> Result<FencedMutationRosterProviderOutcome, FencedMutationRosterMemberAttestationError>
    {
        attestation
            .validate_for(context)
            .map_err(|_| FencedMutationRosterMemberAttestationError::Rejected)?;
        Ok(attestation.outcome())
    }
}

fn managed_provider_adapter_admission(
    operation_byte: u8,
    member_count: usize,
) -> FencedMutationRosterAdmission {
    let members = (0..member_count)
        .map(|index| {
            FencedMutationRosterMember::new(
                FencedMutationRosterOrdinal::new(
                    u8::try_from(index).expect("bounded test ordinal"),
                )
                .expect("valid test ordinal"),
                [operation_byte.wrapping_add(u8::try_from(index).expect("member byte")); 16],
                FencedMutationRosterDescriptor::new(Vec::new()).expect("empty descriptor"),
                1,
                1,
                FencedMutationRosterDisposition::Pending,
                FencedMutationRosterAdoption::Unreconciled,
            )
            .expect("valid adapter member")
        })
        .collect::<Vec<_>>();
    let members = match members.as_slice() {
        [first] => FencedMutationRosterMembers::new([first.clone()]),
        [first, second] => FencedMutationRosterMembers::new([first.clone(), second.clone()]),
        _ => unreachable!("adapter coverage uses one or two members"),
    }
    .expect("valid adapter manifest");
    FencedMutationRosterAdmission::new(
        1,
        FencedMutationRosterOperationId::new([operation_byte; 16]).expect("test operation ID"),
        FencedMutationRosterScope::from_digest([operation_byte; 32]),
        FencedMutationRosterFenceIntent::new(
            OwnerId::new(format!("managed-adapter-owner-{operation_byte:02x}"))
                .expect("test owner"),
            FenceToken::new(1),
        ),
        Generation::new(1),
        members,
        FencedMutationRosterProtectedPlan::new(Box::new([operation_byte]))
            .expect("test protected plan"),
    )
    .expect("valid adapter admission")
    .with_terminal_result(
        FencedMutationRosterProtectedResult::new(Box::new([operation_byte.wrapping_add(1)]))
            .expect("test protected result"),
    )
    .expect("valid terminal result")
}

async fn admit_managed_provider_adapter_roster(
    store: &ConsensusSessionStore,
    scope: SessionConsumerScope,
    identity: &SessionConsumerIdentity,
    admission: FencedMutationRosterAdmission,
) -> FencedMutationRosterAdmission {
    let admission = admission.with_scope(derive_fenced_mutation_roster_scope(
        identity.spiffe_identity_commitment(),
        scope,
    ));
    let response = store
        .consumer_service()
        .execute_v3(
            identity,
            SessionConsumerV3Request::new(
                scope,
                SessionConsumerV3Operation::FencedMutationRosterAdmit {
                    admission: Box::new(admission.clone()),
                },
            ),
        )
        .await;
    assert!(
        matches!(
            response,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ),
        "public V3 roster admission must commit before the managed facade runs: {response:?}"
    );
    admission
}

async fn activate_managed_provider_adapter_roster(
    store: &ConsensusSessionStore,
    scope: SessionConsumerScope,
    marker: u8,
) {
    let (transition, _) = fenced_acquire_create_request(
        session_key([marker, 0x51]),
        owner(format!("managed-provider-gate-activation-{marker:02x}")),
        FenceToken::new(0),
        [marker; 16],
        Duration::from_secs(30),
        b"managed-provider-gate-activation",
    );
    store
        .fenced_transition(transition)
        .await
        .expect("activate fenced-transition receipt ledger");
    let identity = SessionConsumerIdentity::new(format!(
        "spiffe://managed-adapter/gate-activation-{marker:02x}"
    ))
    .expect("activation identity");
    let admission = managed_provider_adapter_admission(marker, 1).with_scope(
        derive_fenced_mutation_roster_scope(identity.spiffe_identity_commitment(), scope),
    );
    let response = store
        .consumer_service()
        .execute_v3(
            &identity,
            SessionConsumerV3Request::new(
                scope,
                SessionConsumerV3Operation::FencedMutationRosterAdmit {
                    admission: Box::new(admission),
                },
            ),
        )
        .await;
    assert!(
        matches!(
            response,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ),
        "public roster activation must commit: {response:?}"
    );
}

async fn terminalize_predecessor_adapter_roster(
    store: &ConsensusSessionStore,
    scope: SessionConsumerScope,
    identity: &SessionConsumerIdentity,
    admission: &FencedMutationRosterAdmission,
) {
    let attestations = admission
        .members()
        .as_slice()
        .iter()
        .map(|member| {
            let context = FencedMutationRosterMemberExecutionContext::for_admission_member(
                admission,
                member.ordinal(),
            )
            .expect("admitted predecessor member context");
            ManagedProviderAdapterDouble::attestation(
                &context,
                FencedMutationRosterProviderOutcome::AppliedExecuted,
            )
            .expect("predecessor attestation")
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let response = store
        .consumer_service_with_attestation_verifier(Arc::new(ManagedProviderAdapterVerifier))
        .execute_v4(
            identity,
            SessionConsumerV4Request::new(
                scope,
                SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                    admission: Box::new(admission.clone()),
                    attestations,
                    protected_checkpoint: admission
                        .protected_plan()
                        .as_bytes()
                        .to_vec()
                        .into_boxed_slice(),
                },
            ),
        )
        .await;
    assert!(
        matches!(
            response,
            SessionConsumerV4Response::FencedMutationRosterTerminalize(Ok(_))
        ),
        "public V4 predecessor terminal must commit before managed facade runs: {response:?}"
    );
}

/// Stage the exact published format-seven layout only after every production
/// SQLite/OpenRaft handle has closed. The next access is the public production
/// open path, which validates and upgrades this on-disk image transactionally.
fn stage_closed_published_format_seven_voters(cluster: &TestCluster) {
    assert!(
        cluster.stores.is_empty() && cluster._backends.is_empty(),
        "format-seven staging is permitted only after every voter handle closes"
    );
    for index in 0..MEMBER_COUNT {
        let connection = rusqlite::Connection::open(
            cluster
                ._directory
                .path()
                .join(format!("node-{index}.sqlite")),
        )
        .expect("open closed path-backed voter for exact format-seven staging");
        connection
            .execute_batch(
                "DROP INDEX consensus_fenced_mutation_roster_managed_provider_jobs_recovery; \
                 DROP TABLE consensus_fenced_mutation_roster_managed_provider_jobs; \
                 DROP TABLE consensus_fenced_mutation_roster_managed_provider_authorities; \
                 DROP TABLE consensus_fenced_mutation_roster_protocol_claims;",
            )
            .expect("remove only format-eight managed tables from closed voter");
        connection
            .execute(
                "UPDATE consensus_identity SET schema_version = 7 WHERE singleton = 1",
                [],
            )
            .expect("restore exact published format-seven marker");
        let format: i64 = connection
            .query_row(
                "SELECT schema_version FROM consensus_identity WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("inspect closed format-seven marker");
        assert_eq!(
            format, 7,
            "closed voter has the published format-seven marker"
        );
        let managed_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ( \
                    'consensus_fenced_mutation_roster_protocol_claims', \
                    'consensus_fenced_mutation_roster_managed_provider_authorities', \
                    'consensus_fenced_mutation_roster_managed_provider_jobs' \
                 )",
                [],
                |row| row.get(0),
            )
            .expect("verify no format-eight managed table remains on closed voter");
        assert_eq!(
            managed_tables, 0,
            "format-seven source keeps no format-eight managed-provider table"
        );
    }
}

fn assert_no_provider_io(provider: &ManagedProviderAdapterDouble) {
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 0);
}

fn assert_no_managed_provider_rows(
    cluster: &TestCluster,
    leader: usize,
    admission: &FencedMutationRosterAdmission,
) {
    let connection = rusqlite::Connection::open(
        cluster
            ._directory
            .path()
            .join(format!("node-{leader}.sqlite")),
    )
    .expect("open file-backed leader SQLite for read-only assertion");
    let request_id = admission.request_id().to_bytes();
    for table in [
        "consensus_fenced_mutation_roster_operations",
        "consensus_fenced_mutation_roster_protocol_claims",
        "consensus_fenced_mutation_roster_managed_provider_jobs",
        "consensus_fenced_mutation_roster_managed_provider_authorities",
    ] {
        let count: u64 = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE request_id = ?1"),
                params![request_id.as_slice()],
                |row| row.get(0),
            )
            .expect("query exact managed-provider durable rows");
        assert_eq!(count, 0, "unadmitted roster created {table} state");
    }
}

#[derive(Clone, Copy)]
struct AppendEntriesRequestDelay {
    request_id: [u8; 16],
    delay_millis: u64,
}

/// A one-shot test gate placed before the receiving voter handles the chosen
/// replicated entry.  Unlike a duration-based delay, its caller can prove
/// that a quorum committed while this particular replica is still unable to
/// advance its SQLite state machine.
struct AppendEntriesApplyGate {
    request_id: Box<[u8]>,
    receipt_marker: Box<[u8]>,
    armed: AtomicBool,
    receipt_seen: AtomicBool,
    was_reached: AtomicBool,
    was_released: AtomicBool,
    reached: Notify,
    release: Notify,
}

impl AppendEntriesApplyGate {
    fn after_record(request_id: Box<[u8]>, receipt_marker: Box<[u8]>) -> Arc<Self> {
        Arc::new(Self {
            request_id,
            receipt_marker,
            armed: AtomicBool::new(false),
            receipt_seen: AtomicBool::new(false),
            was_reached: AtomicBool::new(false),
            was_released: AtomicBool::new(false),
            reached: Notify::new(),
            release: Notify::new(),
        })
    }

    async fn wait_if_selected(&self, payload: &[u8]) {
        if !self.armed.load(Ordering::SeqCst) || !contains_bytes(payload, &self.request_id) {
            return;
        }
        // Record carries the verifier commitment while Finalize does not.
        // Ignore repeated Record replication and block only the first later
        // roster append, which is the exact Finalize application.
        if !self.receipt_seen.load(Ordering::SeqCst) {
            if contains_bytes(payload, &self.receipt_marker) {
                self.receipt_seen.store(true, Ordering::SeqCst);
            }
            return;
        }
        if contains_bytes(payload, &self.receipt_marker) {
            return;
        }
        self.was_reached.store(true, Ordering::SeqCst);
        self.reached.notify_waiters();
        loop {
            let released = self.release.notified();
            if self.was_released.load(Ordering::SeqCst) {
                break;
            }
            released.await;
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn reached(&self) {
        loop {
            let reached = self.reached.notified();
            if self.was_reached.load(Ordering::SeqCst) {
                break;
            }
            reached.await;
        }
    }

    fn release(&self) {
        self.was_released.store(true, Ordering::SeqCst);
        self.release.notify_waiters();
    }
}

#[derive(Clone)]
struct LoopbackPeer {
    target: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    handler: Arc<StdRwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
    forward_mutation_calls: Arc<AtomicUsize>,
    forward_responses_to_drop: Arc<AtomicUsize>,
    dropped_forward_responses: Arc<AtomicUsize>,
    forward_response_delay_millis: Arc<AtomicU64>,
    delayed_forward_responses: Arc<AtomicUsize>,
    append_entries_request_delay: Arc<StdMutex<Option<AppendEntriesRequestDelay>>>,
    append_entries_apply_gate: Arc<StdMutex<Option<Arc<AppendEntriesApplyGate>>>>,
    delayed_append_entries: Arc<AtomicUsize>,
    rpc_delay_millis: Arc<AtomicU64>,
    delayed_calls: Arc<AtomicUsize>,
    captured_payloads: Arc<StdMutex<Vec<Bytes>>>,
}

impl LoopbackPeer {
    fn new(target: SessionConsensusNodeId, identity: ConsensusIdentity) -> Self {
        Self {
            target,
            identity,
            handler: Arc::new(StdRwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
            forward_mutation_calls: Arc::new(AtomicUsize::new(0)),
            forward_responses_to_drop: Arc::new(AtomicUsize::new(0)),
            dropped_forward_responses: Arc::new(AtomicUsize::new(0)),
            forward_response_delay_millis: Arc::new(AtomicU64::new(0)),
            delayed_forward_responses: Arc::new(AtomicUsize::new(0)),
            append_entries_request_delay: Arc::new(StdMutex::new(None)),
            append_entries_apply_gate: Arc::new(StdMutex::new(None)),
            delayed_append_entries: Arc::new(AtomicUsize::new(0)),
            rpc_delay_millis: Arc::new(AtomicU64::new(0)),
            delayed_calls: Arc::new(AtomicUsize::new(0)),
            captured_payloads: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().expect("consensus handler lock") = Some(handler);
    }

    fn clear_handler(&self) {
        self.handler
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    fn forward_mutation_calls(&self) -> usize {
        self.forward_mutation_calls.load(Ordering::SeqCst)
    }

    fn drop_forward_responses(&self, count: usize) {
        self.forward_responses_to_drop
            .store(count, Ordering::SeqCst);
    }

    fn stop_dropping_forward_responses(&self) {
        self.forward_responses_to_drop.store(0, Ordering::SeqCst);
    }

    fn dropped_forward_responses(&self) -> usize {
        self.dropped_forward_responses.load(Ordering::SeqCst)
    }

    fn delay_forward_responses(&self, delay: Duration) {
        self.forward_response_delay_millis.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    fn stop_delaying_forward_responses(&self) {
        self.forward_response_delay_millis
            .store(0, Ordering::SeqCst);
    }

    fn delayed_forward_responses(&self) -> usize {
        self.delayed_forward_responses.load(Ordering::SeqCst)
    }

    fn delay_append_entries_for_request(&self, request_id: [u8; 16], delay: Duration) {
        *self
            .append_entries_request_delay
            .lock()
            .expect("append-entries request delay mutex") = Some(AppendEntriesRequestDelay {
            request_id,
            delay_millis: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
        });
    }

    fn stop_delaying_append_entries_for_request(&self) {
        *self
            .append_entries_request_delay
            .lock()
            .expect("append-entries request delay mutex") = None;
    }

    fn install_append_entries_apply_gate(&self, gate: Arc<AppendEntriesApplyGate>) {
        *self
            .append_entries_apply_gate
            .lock()
            .expect("append-entries apply gate mutex") = Some(gate);
    }

    fn clear_append_entries_apply_gate(&self) {
        self.append_entries_apply_gate
            .lock()
            .expect("append-entries apply gate mutex")
            .take();
    }

    fn delayed_append_entries(&self) -> usize {
        self.delayed_append_entries.load(Ordering::SeqCst)
    }

    fn delay_calls(&self, delay: Duration) {
        self.rpc_delay_millis.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    fn stop_delaying_calls(&self) {
        self.rpc_delay_millis.store(0, Ordering::SeqCst);
    }

    fn delayed_calls(&self) -> usize {
        self.delayed_calls.load(Ordering::SeqCst)
    }

    fn clear_captured_payloads(&self) {
        self.captured_payloads
            .lock()
            .expect("consensus capture mutex")
            .clear();
    }

    fn captured_payloads(&self) -> Vec<Bytes> {
        let captured = self
            .captured_payloads
            .lock()
            .expect("consensus capture mutex")
            .clone();
        assert!(
            captured.len() < MAX_CAPTURED_CONSENSUS_PAYLOADS,
            "consensus payload qualification capture was saturated"
        );
        captured
    }
}

impl fmt::Debug for LoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackPeer")
            .field("target", &self.target)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Test-only probe shape matching the V1 capability request. It lets the
/// shim below reject precisely that new request while preserving ordinary
/// linearizable read barriers and all current Raft traffic.
#[derive(Deserialize)]
struct FencedTransitionCapabilityProbeV1 {
    schema_version: u16,
}

struct RejectFencedTransitionCapabilityProbeHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
}

impl fmt::Debug for RejectFencedTransitionCapabilityProbeHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RejectFencedTransitionCapabilityProbeHandler(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for RejectFencedTransitionCapabilityProbeHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::ReadBarrier
            && matches!(
                decode_bounded::<FencedTransitionCapabilityProbeV1>(&request.payload),
                Ok(FencedTransitionCapabilityProbeV1 { schema_version: 1 })
            )
        {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Protocol),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

#[async_trait]
impl SessionConsensusPeer for LoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.target
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        if request.family == SessionConsensusRpcFamily::ForwardMutation {
            self.forward_mutation_calls.fetch_add(1, Ordering::SeqCst);
        }
        let rpc_delay = self.rpc_delay_millis.load(Ordering::SeqCst);
        if rpc_delay != 0 {
            self.delayed_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(rpc_delay)).await;
        }

        let append_entries_delay = if request.family == SessionConsensusRpcFamily::AppendEntries {
            self.append_entries_request_delay
                .lock()
                .expect("append-entries request delay mutex")
                .as_ref()
                .and_then(|delay| {
                    contains_bytes(&request.payload, &delay.request_id)
                        .then_some(Duration::from_millis(delay.delay_millis))
                })
        } else {
            None
        };
        if let Some(delay) = append_entries_delay {
            self.delayed_append_entries.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
        }

        let append_entries_apply_gate =
            if request.family == SessionConsensusRpcFamily::AppendEntries {
                self.append_entries_apply_gate
                    .lock()
                    .expect("append-entries apply gate mutex")
                    .clone()
            } else {
                None
            };
        if let Some(gate) = append_entries_apply_gate {
            gate.wait_if_selected(&request.payload).await;
        }

        {
            let mut captured = self
                .captured_payloads
                .lock()
                .expect("consensus capture mutex");
            if captured.len() < MAX_CAPTURED_CONSENSUS_PAYLOADS {
                captured.push(request.payload.clone().into());
            }
        }

        let handler = self
            .handler
            .read()
            .expect("consensus handler lock")
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        let sender = request.sender;
        let family = request.family;
        let response = handler.handle(sender, request).await;

        if family == SessionConsensusRpcFamily::ForwardMutation {
            let delay = self.forward_response_delay_millis.load(Ordering::SeqCst);
            if delay != 0 {
                self.delayed_forward_responses
                    .fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }

        if family == SessionConsensusRpcFamily::ForwardMutation
            && self
                .forward_responses_to_drop
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.dropped_forward_responses
                .fetch_add(1, Ordering::SeqCst);
            return Err(SessionConsensusPeerError::Unavailable);
        }

        Ok(response)
    }
}

struct TestCluster {
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
    stores: Vec<ConsensusSessionStore>,
    _backends: Vec<SqliteSessionBackend>,
    _directory: TempDir,
    _test_permit: tokio::sync::SemaphorePermit<'static>,
}

impl Drop for TestCluster {
    fn drop(&mut self) {
        // Break the test-only peer-handler/store cycles before the cluster
        // resources and final concurrency permit are released.
        for path in self.paths.values() {
            path.clear_handler();
        }
    }
}

#[derive(Debug)]
struct MutableTestClock(StdMutex<opc_types::Timestamp>);

impl MutableTestClock {
    fn new(now: opc_types::Timestamp) -> Self {
        Self(StdMutex::new(now))
    }

    fn set(&self, now: opc_types::Timestamp) {
        *self.0.lock().expect("test clock mutex") = now;
    }
}

impl Clock for MutableTestClock {
    fn now_utc(&self) -> opc_types::Timestamp {
        *self.0.lock().expect("test clock mutex")
    }
}

async fn commit_snapshot_triggering_commands(store: &ConsensusSessionStore) {
    use futures_util::StreamExt;

    // Retain the production 4,096-log snapshot threshold and commit every
    // qualification command. Exercise only the SDK's fixed, bounded proposal
    // admission capacity so per-call forwarding/readback latency does not turn
    // this real-profile proof into a serial wall-clock race.
    futures_util::stream::iter(0..SNAPSHOT_CATCH_UP_COMMANDS)
        .map(|_| store.max_replication_sequence())
        .buffer_unordered(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
        .for_each(|result| async {
            result.expect("advance committed logical time toward snapshot compaction");
        })
        .await;
}

impl TestCluster {
    async fn start() -> Self {
        Self::start_with_operation_timeout(OPERATION_TIMEOUT).await
    }

    async fn start_with_operation_timeout(operation_timeout: Duration) -> Self {
        let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let identity = consensus_identity(&members);
        let topologies = (0..MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
                    members.clone(),
                    identity,
                ))
                .expect("validate consensus topology")
            })
            .collect::<Vec<_>>();
        Self::start_with_topologies(operation_timeout, topologies).await
    }

    async fn start_with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::start_with_clock_and_operation_timeout(clock, OPERATION_TIMEOUT).await
    }

    async fn start_with_clock_and_operation_timeout(
        clock: Arc<dyn Clock>,
        operation_timeout: Duration,
    ) -> Self {
        let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let identity = consensus_identity(&members);
        let topologies = (0..MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
                    members.clone(),
                    identity,
                ))
                .expect("validate consensus topology")
            })
            .collect::<Vec<_>>();
        Self::start_with_topologies_and_clock(operation_timeout, topologies, clock).await
    }

    async fn start_with_topologies(
        operation_timeout: Duration,
        topologies: Vec<ValidatedQuorumTopology>,
    ) -> Self {
        Self::start_with_topologies_and_clock(operation_timeout, topologies, Arc::new(SystemClock))
            .await
    }

    async fn start_with_topologies_and_clock(
        operation_timeout: Duration,
        topologies: Vec<ValidatedQuorumTopology>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let test_permit = Self::acquire_test_permit().await;
        Self::start_with_topologies_and_clock_with_permit(
            operation_timeout,
            topologies,
            clock,
            test_permit,
        )
        .await
    }

    async fn acquire_test_permit() -> tokio::sync::SemaphorePermit<'static> {
        CLUSTER_TEST_PERMIT
            .acquire()
            .await
            .expect("cluster-test permit remains available")
    }

    async fn start_with_topologies_and_clock_with_permit(
        operation_timeout: Duration,
        topologies: Vec<ValidatedQuorumTopology>,
        clock: Arc<dyn Clock>,
        test_permit: tokio::sync::SemaphorePermit<'static>,
    ) -> Self {
        assert_eq!(topologies.len(), MEMBER_COUNT);
        let directory = tempfile::tempdir().expect("create fleet directory");
        let backends = (0..MEMBER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open file-backed SQLite node")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| {
                topology
                    .local_consensus_node_id()
                    .expect("consensus node ID")
            })
            .collect::<Vec<_>>();
        let identity = topologies
            .first()
            .and_then(ValidatedQuorumTopology::consensus_identity)
            .expect("consensus identity");

        let mut paths = BTreeMap::new();
        for source in 0..MEMBER_COUNT {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(LoopbackPeer::new(node_id, identity)),
                    );
                }
            }
        }

        let mut stores = Vec::with_capacity(MEMBER_COUNT);
        for index in 0..MEMBER_COUNT {
            let peers = (0..MEMBER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> =
                        paths.get(&(index, target)).expect("loopback path").clone();
                    (node_ids[target], peer)
                })
                .collect::<BTreeMap<_, _>>();
            let store = ConsensusSessionStore::open_with_clock(
                topologies[index].clone(),
                backends[index].clone(),
                directory.path().join(format!("snapshots-{index}")),
                peers,
                clock.clone(),
                operation_timeout,
            )
            .await
            .expect("open consensus node");
            stores.push(store);
        }

        let cluster = Self {
            paths,
            stores,
            _backends: backends,
            _directory: directory,
            _test_permit: test_permit,
        };

        for ((_, target), path) in &cluster.paths {
            path.install(cluster.stores[*target].rpc_handler());
        }

        let initialize = cluster
            .stores
            .iter()
            .map(ConsensusSessionStore::initialize_cluster)
            .collect::<Vec<_>>();
        let results = futures_util::future::join_all(initialize).await;
        for result in results {
            result.expect("initialize identical membership concurrently");
        }

        cluster
            .wait_all_ready(CLUSTER_START_TIMEOUT)
            .await
            .expect("fresh cluster reaches durable readiness");
        cluster
    }

    /// Reopen every voter from the same closed file-backed fleet. This stays
    /// on the production OpenRaft/store construction path; it only rebuilds
    /// the in-process authenticated loopback transport used by this test
    /// harness.
    async fn reopen(
        directory: TempDir,
        operation_timeout: Duration,
    ) -> Result<Self, opc_session_store::ConsensusSessionStoreOpenError> {
        let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let identity = consensus_identity(&members);
        let topologies = (0..MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
                    members.clone(),
                    identity,
                ))
                .expect("validate reopened consensus topology")
            })
            .collect::<Vec<_>>();
        let test_permit = Self::acquire_test_permit().await;
        let backends = (0..MEMBER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("reopen file-backed SQLite node")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| {
                topology
                    .local_consensus_node_id()
                    .expect("reopened consensus node ID")
            })
            .collect::<Vec<_>>();
        let mut paths = BTreeMap::new();
        for source in 0..MEMBER_COUNT {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(LoopbackPeer::new(node_id, identity)),
                    );
                }
            }
        }
        let mut stores = Vec::with_capacity(MEMBER_COUNT);
        for index in 0..MEMBER_COUNT {
            let peers = (0..MEMBER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> = paths
                        .get(&(index, target))
                        .expect("reopened loopback path")
                        .clone();
                    (node_ids[target], peer)
                })
                .collect::<BTreeMap<_, _>>();
            stores.push(
                ConsensusSessionStore::open_with_clock(
                    topologies[index].clone(),
                    backends[index].clone(),
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                    Arc::new(SystemClock),
                    operation_timeout,
                )
                .await?,
            );
        }
        let cluster = Self {
            paths,
            stores,
            _backends: backends,
            _directory: directory,
            _test_permit: test_permit,
        };
        for ((_, target), path) in &cluster.paths {
            path.install(cluster.stores[*target].rpc_handler());
        }
        let initialize = cluster
            .stores
            .iter()
            .map(ConsensusSessionStore::initialize_cluster)
            .collect::<Vec<_>>();
        for result in futures_util::future::join_all(initialize).await {
            result?;
        }
        cluster
            .wait_all_ready(CLUSTER_START_TIMEOUT)
            .await
            .map_err(|_| opc_session_store::ConsensusSessionStoreOpenError::RecoveryRequired)?;
        Ok(cluster)
    }

    /// Drop all stores, backends, and loopback handler references before a
    /// raw SQLite corruption fixture opens the persistent files.
    fn close_into_directory(mut self) -> TempDir {
        for path in self.paths.values() {
            path.clear_handler();
        }
        self.stores.clear();
        self._backends.clear();
        std::mem::replace(
            &mut self._directory,
            tempfile::tempdir().expect("replacement fleet directory"),
        )
    }

    async fn wait_all_ready(&self, deadline: Duration) -> Result<(), ()> {
        tokio::time::timeout(deadline, async {
            loop {
                let reports = futures_util::future::join_all(
                    self.stores
                        .iter()
                        .map(ConsensusSessionStore::probe_durable_readiness),
                )
                .await;
                if reports.iter().all(|report| report.is_ready()) {
                    return;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| ())
    }

    /// Close every SQLite/OpenRaft handle while retaining only the exact
    /// path-backed voter files and their authenticated in-process peers.
    fn close_path_backed_voters(&mut self) {
        for path in self.paths.values() {
            path.clear_handler();
        }
        self.stores.clear();
        self._backends.clear();
    }

    /// Reopen the retained voter files through the public production `open`
    /// constructor, rather than the deterministic-clock test constructor.
    async fn reopen_path_backed_voters_through_production_open(&mut self) {
        self.try_reopen_path_backed_voters_through_production_open()
            .await
            .expect("production-open closed consensus voter");
    }

    /// Attempt the public production reopen while preserving the exact
    /// file-backed fleet for a caller that needs to observe fail-closed open
    /// validation.
    async fn try_reopen_path_backed_voters_through_production_open(
        &mut self,
    ) -> Result<(), opc_session_store::ConsensusSessionStoreOpenError> {
        assert!(
            self.stores.is_empty() && self._backends.is_empty(),
            "production reopen requires all prior consensus and SQLite handles to be closed"
        );
        let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let identity = consensus_identity(&members);
        let topologies = (0..MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
                    members.clone(),
                    identity,
                ))
                .expect("validate reopened consensus topology")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| {
                topology
                    .local_consensus_node_id()
                    .expect("reopened consensus node ID")
            })
            .collect::<Vec<_>>();
        let backends = (0..MEMBER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(
                    self._directory.path().join(format!("node-{index}.sqlite")),
                )
                .expect("reopen closed file-backed SQLite node")
            })
            .collect::<Vec<_>>();
        let mut stores = Vec::with_capacity(MEMBER_COUNT);
        for index in 0..MEMBER_COUNT {
            let peers = (0..MEMBER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> = self
                        .paths
                        .get(&(index, target))
                        .expect("reopened loopback path")
                        .clone();
                    (node_ids[target], peer)
                })
                .collect::<BTreeMap<_, _>>();
            stores.push(
                ConsensusSessionStore::open(
                    topologies[index].clone(),
                    backends[index].clone(),
                    self._directory.path().join(format!("snapshots-{index}")),
                    peers,
                )
                .await?,
            );
        }
        for ((_, target), path) in &self.paths {
            path.install(stores[*target].rpc_handler());
        }
        self._backends = backends;
        self.stores = stores;
        let initialized = self
            .stores
            .iter()
            .map(ConsensusSessionStore::initialize_cluster)
            .collect::<Vec<_>>();
        for result in futures_util::future::join_all(initialized).await {
            result?;
        }
        self.wait_all_ready(CLUSTER_START_TIMEOUT)
            .await
            .map_err(|_| opc_session_store::ConsensusSessionStoreOpenError::RecoveryRequired)?;
        Ok(())
    }

    fn observed_leader(&self) -> (usize, SessionConsensusNodeId, u64) {
        let statuses = self
            .stores
            .iter()
            .map(ConsensusSessionStore::status)
            .collect::<Vec<_>>();
        let leader_id = statuses
            .first()
            .and_then(|status| status.leader_id)
            .expect("known leader");
        let term = statuses.first().expect("cluster status").term;
        assert!(
            statuses
                .iter()
                .all(|status| status.leader_id == Some(leader_id) && status.term == term),
            "all ready members must agree on the observed leader and term"
        );
        let leader_index = statuses
            .iter()
            .position(|status| status.node_id == leader_id)
            .expect("leader is a configured member");
        (leader_index, leader_id, term)
    }

    fn isolate(&self, node: usize) {
        for peer in 0..MEMBER_COUNT {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound path")
                    .set_enabled(false);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound path")
                    .set_enabled(false);
            }
        }
    }

    fn heal(&self, node: usize) {
        for peer in 0..MEMBER_COUNT {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound path")
                    .set_enabled(true);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound path")
                    .set_enabled(true);
            }
        }
    }

    fn arm_forward_response_loss(&self, source: usize, count: usize) -> usize {
        let before = self.dropped_forward_responses(source);
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .drop_forward_responses(count);
            }
        }
        before
    }

    fn stop_forward_response_loss(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_dropping_forward_responses();
            }
        }
    }

    fn arm_forward_response_delay(&self, source: usize, delay: Duration) -> usize {
        let before = self.delayed_forward_responses(source);
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delay_forward_responses(delay);
            }
        }
        before
    }

    fn stop_forward_response_delay(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_delaying_forward_responses();
            }
        }
    }

    fn delay_calls(&self, source: usize, delay: Duration) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delay_calls(delay);
            }
        }
    }

    fn stop_delaying_calls(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_delaying_calls();
            }
        }
    }

    fn delayed_calls(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delayed_calls()
            })
            .sum()
    }

    fn delay_append_entries_for_request(
        &self,
        source: usize,
        request_id: [u8; 16],
        delay: Duration,
    ) -> usize {
        let before = self.delayed_append_entries(source);
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delay_append_entries_for_request(request_id, delay);
            }
        }
        before
    }

    fn stop_delaying_append_entries_for_request(&self, source: usize) {
        for target in 0..MEMBER_COUNT {
            if source != target {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .stop_delaying_append_entries_for_request();
            }
        }
    }

    fn gate_append_entries_to(
        &self,
        source: usize,
        target: usize,
        gate: Arc<AppendEntriesApplyGate>,
    ) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .install_append_entries_apply_gate(gate);
    }

    fn clear_append_entries_gate_to(&self, source: usize, target: usize) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .clear_append_entries_apply_gate();
    }

    fn delayed_forward_responses(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delayed_forward_responses()
            })
            .sum()
    }

    fn delayed_append_entries(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .delayed_append_entries()
            })
            .sum()
    }

    fn dropped_forward_responses(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .dropped_forward_responses()
            })
            .sum()
    }

    fn forward_mutation_calls(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .forward_mutation_calls()
            })
            .sum()
    }

    fn reject_fenced_transition_capability_probe(&self, source: usize, target: usize) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .install(Arc::new(RejectFencedTransitionCapabilityProbeHandler {
                inner: self.stores[target].rpc_handler(),
            }));
    }

    fn restore_current_rpc_handler(&self, source: usize, target: usize) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .install(self.stores[target].rpc_handler());
    }

    fn clear_captured_payloads(&self) {
        for path in self.paths.values() {
            path.clear_captured_payloads();
        }
    }

    fn captured_payloads(&self) -> Vec<Bytes> {
        self.paths
            .values()
            .flat_map(|path| path.captured_payloads())
            .collect()
    }
}

struct CountingKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    active_key_calls: AtomicUsize,
    key_by_id_calls: AtomicUsize,
    rotation_calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn new(inner: Arc<MemoryKeyProvider>) -> Self {
        Self {
            inner,
            active_key_calls: AtomicUsize::new(0),
            key_by_id_calls: AtomicUsize::new(0),
            rotation_calls: AtomicUsize::new(0),
        }
    }

    fn call_counts(&self) -> (usize, usize, usize) {
        (
            self.active_key_calls.load(Ordering::SeqCst),
            self.key_by_id_calls.load(Ordering::SeqCst),
            self.rotation_calls.load(Ordering::SeqCst),
        )
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.active_key_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.key_by_id_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.rotation_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("consensus-test-{index}")).expect("replica ID")
}

fn member(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(index),
        ReplicaEndpoint::new(format!("consensus-test-{index}.invalid"), 7443)
            .expect("replica endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/session/consensus/{index}"))
            .expect("TLS identity"),
        ReplicaFailureDomain::new(format!("consensus-test-zone-{index}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("consensus-test-disk-{index}"))
            .expect("backing identity"),
    )
}

fn consensus_identity(members: &[QuorumReplicaDescriptor]) -> ConsensusIdentity {
    consensus_identity_for_cluster(members, "session-openraft-integration-tests", 1)
}

fn consensus_identity_for_cluster(
    members: &[QuorumReplicaDescriptor],
    cluster_name: &str,
    epoch: u64,
) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new(cluster_name).expect("consensus cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(epoch).expect("consensus epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

#[derive(Debug)]
struct DigestTopologyAttestor;

impl QuorumTopologyAttestor for DigestTopologyAttestor {
    fn verify(
        &self,
        input: TopologyAttestationVerificationInput<'_>,
    ) -> Result<(), TopologyAttestationVerificationError> {
        (input.proof() == input.canonical_digest())
            .then_some(())
            .ok_or(TopologyAttestationVerificationError::InvalidProof)
    }
}

fn attestation_collector() -> TopologyCollectorId {
    TopologyCollectorId::new("consensus-integration-attestor").expect("collector identity")
}

fn attestation_policy(
    collector: TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
) -> TopologyAttestationPolicy {
    TopologyAttestationPolicy::try_new(provenance, vec![collector], Duration::from_secs(300))
        .expect("attestation policy")
}

fn topology_evidence(
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
) -> Vec<TopologyAttestationEvidence> {
    members
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let claims = TopologyAttestationClaims::new(
                descriptor.replica_id().clone(),
                descriptor.tls_identity().clone(),
                ObservedPhysicalNodeIdentity::new(format!(
                    "consensus-integration-physical-node-{index}"
                ))
                .expect("physical node identity"),
                descriptor.failure_domain().clone(),
                descriptor.backing_identity().clone(),
                descriptor.configuration_fingerprint(),
                identity,
                collector.clone(),
                provenance,
                observed_at,
                expires_at,
            );
            let proof = claims.canonical_digest().to_vec();
            TopologyAttestationEvidence::try_new(claims, proof).expect("bounded evidence")
        })
        .collect()
}

fn attested_topologies(
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
    admitted_at: TopologyAttestationTime,
) -> Vec<ValidatedQuorumTopology> {
    let policy = attestation_policy(collector.clone(), provenance);
    let evidence = topology_evidence(
        members,
        identity,
        collector,
        provenance,
        observed_at,
        expires_at,
    );
    (0..MEMBER_COUNT)
        .map(|index| {
            ValidatedQuorumTopology::try_from_attested(
                QuorumTopologyConfig::new_consensus(replica_id(index), members.to_vec(), identity),
                evidence.clone(),
                &policy,
                &DigestTopologyAttestor,
                admitted_at,
            )
            .expect("attested topology")
        })
        .collect()
}

fn refreshed_attestation(
    topology: &ValidatedQuorumTopology,
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
    verified_at: TopologyAttestationTime,
) -> VerifiedQuorumTopologyAttestation {
    refreshed_attestation_with_provenance(
        topology,
        members,
        identity,
        collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        observed_at,
        expires_at,
        verified_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn refreshed_attestation_with_provenance(
    topology: &ValidatedQuorumTopology,
    members: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
    verified_at: TopologyAttestationTime,
) -> VerifiedQuorumTopologyAttestation {
    let policy = attestation_policy(collector.clone(), provenance);
    topology
        .verify_attestation_evidence(
            topology_evidence(
                members,
                identity,
                collector,
                provenance,
                observed_at,
                expires_at,
            ),
            &policy,
            &DigestTopologyAttestor,
            verified_at,
        )
        .expect("refreshed attestation")
}

fn session_key(label: impl AsRef<[u8]>) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("consensus-test-tenant").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(label.as_ref())
            .try_into()
            .expect("valid stable ID"),
    }
}

fn owner(label: impl Into<String>) -> OwnerId {
    OwnerId::new(label).expect("owner")
}

fn plaintext_record(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
    plaintext: &[u8],
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("consensus-encryption-boundary"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(plaintext),
    }
}

fn encryption_provider() -> Arc<CountingKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("consensus-boundary-key-2026-07").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("consensus-test-tenant").expect("tenant"),
            Zeroizing::new([0x5a; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("install qualification key");
    Arc::new(CountingKeyProvider::new(provider))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn json_contains_bytes(value: &serde_json::Value, needle: &[u8]) -> bool {
    match value {
        serde_json::Value::Array(values) => {
            let encoded_bytes = values
                .iter()
                .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Option<Vec<_>>>();
            encoded_bytes
                .as_deref()
                .is_some_and(|bytes| contains_bytes(bytes, needle))
                || values
                    .iter()
                    .any(|value| json_contains_bytes(value, needle))
        }
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| json_contains_bytes(value, needle)),
        serde_json::Value::String(value) => contains_bytes(value.as_bytes(), needle),
        _ => false,
    }
}

fn assert_artifact_bytes_are_sealed(label: &str, bytes: &[u8]) {
    for canary in [
        PLAINTEXT_CANARY_BEFORE_ROTATION,
        PLAINTEXT_CANARY_AFTER_ROTATION,
        RAW_KEY_MATERIAL_CANARY.as_slice(),
    ] {
        assert!(
            !contains_bytes(bytes, canary),
            "plaintext session payload crossed the encryption boundary into {label}"
        );
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
            assert!(
                !json_contains_bytes(&value, canary),
                "JSON-encoded plaintext session payload crossed the encryption boundary into {label}"
            );
        }
    }
}

fn assert_file_tree_is_sealed(root: &Path) {
    let entries = std::fs::read_dir(root).expect("read durable artifact directory");
    for entry in entries {
        let path = entry.expect("durable artifact entry").path();
        if path.is_dir() {
            assert_file_tree_is_sealed(&path);
        } else if path.is_file() {
            let bytes = std::fs::read(&path).expect("read durable artifact");
            assert_artifact_bytes_are_sealed("durable file", &bytes);
        }
    }
}

fn assert_sqlite_authority_is_sealed(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open consensus database for qualification");
    for (table, column, is_json) in [
        ("session_records", "payload", false),
        ("session_replication_log", "entry_json", true),
        ("consensus_log", "entry_json", true),
        ("consensus_request_outcomes", "response_json", true),
    ] {
        let query = format!("SELECT CAST({column} AS BLOB) FROM {table}");
        let mut statement = connection.prepare(&query).expect("prepare authority scan");
        let values = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query authority bytes");
        for value in values {
            let bytes = value.expect("read authority bytes");
            assert_artifact_bytes_are_sealed("SQLite consensus authority", &bytes);
            if is_json {
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("authority JSON");
                for canary in [
                    PLAINTEXT_CANARY_BEFORE_ROTATION,
                    PLAINTEXT_CANARY_AFTER_ROTATION,
                    RAW_KEY_MATERIAL_CANARY.as_slice(),
                ] {
                    assert!(
                        !json_contains_bytes(&value, canary),
                        "plaintext session payload was encoded into SQLite consensus authority"
                    );
                }
            }
        }
    }
}

fn consensus_sqlite_progress(database: &Path) -> (Option<u64>, Option<u64>, Option<u64>, u64, u64) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open consensus database progress");
    let optional_index = |sql: &str| {
        connection
            .query_row(sql, [], |row| row.get::<_, i64>(0))
            .optional()
            .expect("read optional consensus index")
            .and_then(|value| u64::try_from(value).ok())
    };
    (
        optional_index("SELECT log_index FROM consensus_committed WHERE singleton = 1"),
        optional_index("SELECT log_index FROM consensus_applied WHERE singleton = 1"),
        optional_index("SELECT log_index FROM consensus_purged WHERE singleton = 1"),
        connection
            .query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("read consensus log row count"),
        connection
            .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                row.get::<_, u64>(0)
            })
            .expect("read consensus snapshot row count"),
    )
}

fn sealed_record(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
    payload: &'static [u8],
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("consensus-test-session"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("synthetic-consensus-test-key").expect("key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "synthetic-keyed-session-digest",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "synthetic-consensus-test-backend",
        )
        .expect("session AAD"),
    );
    let mut ciphertext_and_tag = payload.to_vec();
    ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
    let envelope = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
        ciphertext_and_tag,
    }
    .encode()
    .expect("test envelope");
    record.payload = EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope");
    record
}

fn sealed_transition_record(
    key: SessionKey,
    generation: u64,
    owner: &OwnerId,
    fence: FenceToken,
    payload: &'static [u8],
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: owner.clone(),
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("consensus-test-session"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("synthetic-consensus-test-key").expect("key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "synthetic-keyed-session-digest",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "synthetic-consensus-test-backend",
        )
        .expect("session AAD"),
    );
    let mut ciphertext_and_tag = payload.to_vec();
    ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
    let envelope = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
        ciphertext_and_tag,
    }
    .encode()
    .expect("test envelope");
    record.payload = EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope");
    record
}

fn fenced_acquire_create_request(
    key: SessionKey,
    owner: OwnerId,
    expected_fence: FenceToken,
    request_id: [u8; 16],
    ttl: Duration,
    payload: &'static [u8],
) -> (FencedTransitionRequest, StoredSessionRecord) {
    let lease = FencedTransitionLease::acquire(key.clone(), owner.clone(), expected_fence, ttl)
        .expect("build acquire action");
    let record = sealed_transition_record(
        key,
        1,
        &owner,
        lease.committed_fence().expect("derive committed fence"),
        payload,
    );
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes(request_id),
        lease,
        FencedTransitionMutation::create(record.clone()),
    )
    .expect("build create transition");
    (request, record)
}

async fn assert_fenced_renewal_cas_conflict_has_no_effect(
    store: &ConsensusSessionStore,
    key: &SessionKey,
    request: FencedTransitionRequest,
) {
    let before = store
        .max_replication_sequence()
        .await
        .expect("read replication head before rejected renewal");
    let observation = store
        .observe_fenced_transition(key)
        .await
        .expect("observe state before rejected renewal");

    assert!(
        matches!(
            store.fenced_transition(request.clone()).await,
            Err(StoreError::CasConflict)
        ),
        "a renew transition without a live expected record is a typed CAS conflict"
    );
    assert!(
        matches!(
            store.fenced_transition_status(&request).await,
            Ok(FencedTransitionStatus::Recorded(result))
                if matches!(result.as_ref(), Err(StoreError::CasConflict))
        ),
        "the durable request status retains the exact deterministic rejection"
    );
    assert_eq!(
        store
            .observe_fenced_transition(key)
            .await
            .expect("observe state after rejected renewal"),
        observation,
        "a rejected renewal leaves the record view and fence floor unchanged"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("read replication head after rejected renewal"),
        before,
        "a rejected renewal has no application or watch position"
    );
    assert!(
        store
            .get_replication_log(before + 1, 1)
            .await
            .expect("read watch journal after rejected renewal")
            .is_empty(),
        "a rejected renewal writes no watch entry"
    );
}

async fn replication_logs(cluster: &TestCluster) -> Vec<Vec<opc_session_store::ReplicationEntry>> {
    futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.get_replication_log(1, 128)),
    )
    .await
    .into_iter()
    .map(|result| result.expect("read committed replication log"))
    .collect()
}

async fn assert_differing_replica_compaction_floors_never_union(cluster: &TestCluster) {
    let logs = replication_logs(cluster).await;
    assert!(logs.iter().all(|log| log == &logs[0]));
    assert!(logs[0].len() >= MEMBER_COUNT);

    // Test-only post-commit fault injection: no authoritative mutation follows
    // these deliberately different local floors. The read contract must expose
    // each typed outcome rather than constructing a cross-replica union page.
    for (index, floor) in (1_i64..=3).enumerate() {
        let connection = rusqlite::Connection::open(
            cluster
                ._directory
                .path()
                .join(format!("node-{index}.sqlite")),
        )
        .expect("open replica for deliberate compaction disagreement");
        connection
            .execute(
                "UPDATE consensus_operator_recovery SET watch_cursor_invalidation_floor = ?1 WHERE singleton = 1",
                [floor],
            )
            .expect("install deliberate local compaction floor");
    }

    let outcomes = futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.get_replication_log(1, MEMBER_COUNT)),
    )
    .await;
    for (index, outcome) in outcomes.into_iter().enumerate() {
        assert_eq!(
            outcome.expect_err("a stale cursor must not be filled from another replica"),
            StoreError::ReplicationLogCursorCompacted {
                resume_from: u64::try_from(index + 2).expect("small resume point"),
            }
        );
    }

    let watch_outcomes =
        futures_util::future::join_all(cluster.stores.iter().map(|store| store.watch(1))).await;
    for (index, outcome) in watch_outcomes.into_iter().enumerate() {
        let error = match outcome {
            Ok(_) => panic!("a compacted production watch must not skip history"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            StoreError::ReplicationLogCursorCompacted {
                resume_from: u64::try_from(index + 2).expect("small resume point"),
            }
        );
    }
}

fn assert_raw_consensus_guard<T>(result: Result<T, StoreError>) {
    assert!(matches!(
        result,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "consensus_authority_required"
    ));
}

fn assert_raw_consensus_lease_guard<T>(result: Result<T, LeaseError>) {
    assert!(matches!(
        result,
        Err(LeaseError::Backend(message))
            if message.contains("consensus_authority_required")
    ));
}

#[tokio::test]
async fn production_readiness_requires_fresh_authenticated_topology_and_accepts_refresh() {
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let collector = attestation_collector();
    // The proof has a real monotonic expiry. Hold the fixture permit before
    // minting it, otherwise another cluster can make valid evidence expire in
    // the test queue before this fixture gets a chance to open it.
    let test_permit = TestCluster::acquire_test_permit().await;
    let topologies = attested_topologies(
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(1_000),
        TopologyAttestationTime::from_unix_seconds(1_010),
        TopologyAttestationTime::from_unix_seconds(1_000),
    );
    let attestation_context = topologies[0].clone();
    let cluster = TestCluster::start_with_topologies_and_clock_with_permit(
        Duration::from_secs(5),
        topologies,
        Arc::new(SystemClock),
        test_permit,
    )
    .await;
    let store = &cluster.stores[0];

    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_001)),
        SessionStorePlatformProfile::Quorum
    );
    let admitted =
        store.topology_attestation_summary_at(TopologyAttestationTime::from_unix_seconds(1_001));
    assert_eq!(
        admitted.provenance(),
        TopologyAttestationProvenance::AuthenticatedPlatform
    );
    assert_eq!(admitted.configuration_epoch(), 1);
    assert_eq!(admitted.result(), TopologyAttestationResult::Verified);
    let production_ready = store
        .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(1_001))
        .await;
    assert_eq!(
        production_ready.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(production_ready.is_production_traffic_ready());
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_001)),
        SessionStorePlatformProfile::Quorum
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_000)),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_000,
            ))
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_001)),
        SessionStorePlatformProfile::Quorum
    );

    let (initial_leader, _, _) = cluster.observed_leader();
    let initial_delayed_before = cluster.delayed_calls(initial_leader);
    // The injected peer delay is much longer than the attestation deadline.
    // This leaves a 1.75 s gap after the timer-dispatch tolerance, so a
    // completed peer call cannot be mistaken for deadline enforcement.
    cluster.delay_calls(initial_leader, Duration::from_secs(3));
    let initial_attestation_budget = Duration::from_secs(1);
    let initial_probe_started = Instant::now();
    let initial_crossed_expiry = cluster.stores[initial_leader]
        .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(1_009))
        .await;
    let initial_elapsed = initial_probe_started.elapsed();
    cluster.stop_delaying_calls(initial_leader);
    assert!(
        cluster.delayed_calls(initial_leader) > initial_delayed_before,
        "the attestation-bound probe must enter the delayed peer path"
    );
    assert_eq!(
        initial_crossed_expiry.state(),
        DurableReadinessState::TopologyInvalid
    );
    assert!(
        initial_elapsed >= Duration::from_millis(500)
            && initial_elapsed
                < initial_attestation_budget + ATTESTATION_PROBE_TIMER_DISPATCH_TOLERANCE,
        "initial attestation deadline must bound the barrier; elapsed {initial_elapsed:?}"
    );
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("cluster recovers after the bounded initial probe");

    let expired =
        store.topology_attestation_summary_at(TopologyAttestationTime::from_unix_seconds(1_010));
    assert_eq!(expired.result(), TopologyAttestationResult::Expired);
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_010)),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_010,
            ))
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    assert_eq!(
        store.production_platform_profile_at(TopologyAttestationTime::from_unix_seconds(1_009)),
        SessionStorePlatformProfile::Unknown,
        "an expired forward evaluation must prevent wall-clock rollback revival"
    );

    let refreshed = refreshed_attestation(
        &attestation_context,
        &members,
        identity,
        &collector,
        TopologyAttestationTime::from_unix_seconds(1_020),
        TopologyAttestationTime::from_unix_seconds(1_100),
        TopologyAttestationTime::from_unix_seconds(1_020),
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_019),
        ),
        SessionStorePlatformProfile::Unknown,
        "a refreshed token cannot authorize a time before its verification"
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_021),
        ),
        SessionStorePlatformProfile::Quorum
    );
    let refreshed_ready = store
        .probe_production_durable_readiness_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_021),
        )
        .await;
    assert_eq!(
        refreshed_ready.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(refreshed_ready.is_production_traffic_ready());
    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );

    cluster.delay_calls(0, Duration::from_millis(750));
    let older_probe = store.probe_production_durable_readiness_with_attestation_at(
        &refreshed,
        TopologyAttestationTime::from_unix_seconds(1_022),
    );
    let newer_evaluation = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_023),
        )
    };
    let (older_report, newer_profile) = tokio::join!(older_probe, newer_evaluation);
    cluster.stop_delaying_calls(0);
    assert_eq!(newer_profile, SessionStorePlatformProfile::Quorum);
    assert_eq!(
        older_report.state(),
        DurableReadinessState::TopologyInvalid,
        "a delayed older evaluation must fail after a newer time is observed"
    );
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("cluster recovers after the delayed rollback race");

    let foreign_identity =
        consensus_identity_for_cluster(&members, "foreign-session-openraft-cluster", 1);
    let foreign_topologies = attested_topologies(
        &members,
        foreign_identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(9_000),
        TopologyAttestationTime::from_unix_seconds(9_100),
        TopologyAttestationTime::from_unix_seconds(9_000),
    );
    let foreign = refreshed_attestation(
        &foreign_topologies[0],
        &members,
        foreign_identity,
        &collector,
        TopologyAttestationTime::from_unix_seconds(9_000),
        TopologyAttestationTime::from_unix_seconds(9_100),
        TopologyAttestationTime::from_unix_seconds(9_000),
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &foreign,
            TopologyAttestationTime::from_unix_seconds(9_001),
        ),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_with_attestation_at(
                &foreign,
                TopologyAttestationTime::from_unix_seconds(9_001),
            )
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    let conformance_only = refreshed_attestation_with_provenance(
        &attestation_context,
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::DeterministicConformance,
        TopologyAttestationTime::from_unix_seconds(9_500),
        TopologyAttestationTime::from_unix_seconds(9_600),
        TopologyAttestationTime::from_unix_seconds(9_500),
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &conformance_only,
            TopologyAttestationTime::from_unix_seconds(9_501),
        ),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_023),
        ),
        SessionStorePlatformProfile::Quorum,
        "foreign and non-production future tokens must not poison the time authority"
    );

    let wall_start = TopologyAttestationTime::now().expect("current attestation time");
    let short_lived_attestation_budget = Duration::from_secs(2);
    let wall_expiry = TopologyAttestationTime::from_unix_seconds(
        wall_start
            .unix_seconds()
            .checked_add(short_lived_attestation_budget.as_secs())
            .expect("test wall-clock expiry"),
    );
    let short_lived = refreshed_attestation(
        &attestation_context,
        &members,
        identity,
        &collector,
        wall_start,
        wall_expiry,
        wall_start,
    );
    let short_lived_delayed_before = cluster.delayed_calls(0);
    // As above, leave a gap substantially larger than scheduler dispatch so
    // this verifies the attestation deadline rather than a peer response.
    cluster.delay_calls(0, Duration::from_secs(4));
    let probe_started = Instant::now();
    let crossed_expiry = store
        .probe_production_durable_readiness_with_attestation_at(&short_lived, wall_start)
        .await;
    let elapsed = probe_started.elapsed();
    cluster.stop_delaying_calls(0);
    assert!(
        cluster.delayed_calls(0) > short_lived_delayed_before,
        "the refreshed-attestation probe must enter the delayed peer path"
    );
    assert_eq!(
        crossed_expiry.state(),
        DurableReadinessState::TopologyInvalid
    );
    assert!(
        elapsed >= Duration::from_millis(500)
            && elapsed
                < short_lived_attestation_budget + ATTESTATION_PROBE_TIMER_DISPATCH_TOLERANCE,
        "attestation deadline must bound the barrier; elapsed {elapsed:?}"
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(&short_lived, wall_start),
        SessionStorePlatformProfile::Unknown,
        "monotonic expiry must prevent a retry with the old pre-expiry wall time"
    );
    assert_eq!(
        store
            .probe_production_durable_readiness_with_attestation_at(&short_lived, wall_start)
            .await
            .state(),
        DurableReadinessState::TopologyInvalid
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(
            &short_lived,
            TopologyAttestationTime::from_unix_seconds(u64::MAX),
        ),
        SessionStorePlatformProfile::Unknown,
        "the bounded time authority must fail closed at the representable maximum"
    );
}

#[tokio::test]
async fn descriptor_only_three_node_store_cannot_be_upgraded_by_attested_token() {
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let collector = attestation_collector();
    let attested = attested_topologies(
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(1_500),
        TopologyAttestationTime::from_unix_seconds(1_600),
        TopologyAttestationTime::from_unix_seconds(1_500),
    );
    let token = refreshed_attestation(
        &attested[0],
        &members,
        identity,
        &collector,
        TopologyAttestationTime::from_unix_seconds(1_500),
        TopologyAttestationTime::from_unix_seconds(1_600),
        TopologyAttestationTime::from_unix_seconds(1_500),
    );

    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let now = TopologyAttestationTime::from_unix_seconds(1_501);
    assert_eq!(store.topology().mode().as_str(), "descriptor-only-lab-ha");
    assert_eq!(
        store.production_platform_profile_at(now),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_with_attestation_at(&token, now),
        SessionStorePlatformProfile::Unknown,
        "a valid same-identity token must not upgrade a descriptor-only store"
    );

    let initial = store.probe_production_durable_readiness_at(now).await;
    assert_eq!(initial.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(
        initial.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(!initial.is_production_traffic_ready());
    let refreshed = store
        .probe_production_durable_readiness_with_attestation_at(&token, now)
        .await;
    assert_eq!(refreshed.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(
        refreshed.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(!refreshed.is_production_traffic_ready());

    let engine = store.probe_durable_readiness().await;
    assert!(engine.is_ready());
    assert_eq!(engine.scope(), DurableReadinessScope::EngineOnly);
    assert!(!engine.is_production_traffic_ready());
}

#[tokio::test]
async fn deterministic_topology_is_visible_but_never_production_ready() {
    let members = (0..MEMBER_COUNT).map(member).collect::<Vec<_>>();
    let identity = consensus_identity(&members);
    let collector = attestation_collector();
    let test_permit = TestCluster::acquire_test_permit().await;
    let topologies = attested_topologies(
        &members,
        identity,
        &collector,
        TopologyAttestationProvenance::DeterministicConformance,
        TopologyAttestationTime::from_unix_seconds(2_000),
        TopologyAttestationTime::from_unix_seconds(2_100),
        TopologyAttestationTime::from_unix_seconds(2_000),
    );
    let cluster = TestCluster::start_with_topologies_and_clock_with_permit(
        OPERATION_TIMEOUT,
        topologies,
        Arc::new(SystemClock),
        test_permit,
    )
    .await;
    let store = &cluster.stores[0];
    let now = TopologyAttestationTime::from_unix_seconds(2_001);

    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(
        store.production_platform_profile_at(now),
        SessionStorePlatformProfile::Unknown
    );
    let summary = store.topology_attestation_summary_at(now);
    assert_eq!(
        summary.provenance(),
        TopologyAttestationProvenance::DeterministicConformance
    );
    assert_eq!(summary.result(), TopologyAttestationResult::Verified);
    assert!(!summary.is_production_verified());
    let production = store.probe_production_durable_readiness_at(now).await;
    assert_eq!(production.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(
        production.scope(),
        DurableReadinessScope::ProductionTopologyAttested
    );
    assert!(!production.is_production_traffic_ready());
    let engine = store.probe_durable_readiness().await;
    assert!(engine.is_ready());
    assert_eq!(engine.scope(), DurableReadinessScope::EngineOnly);
    assert!(!engine.is_production_traffic_ready());
}

#[tokio::test]
async fn consensus_claim_fences_retained_and_reopened_raw_sqlite_handles() {
    let cluster = TestCluster::start().await;
    let raw = &cluster._backends[0];
    let store = &cluster.stores[0];
    let key = session_key(b"raw-authority-bypass");

    let raw_capabilities = raw.capabilities().await;
    assert_eq!(
        raw_capabilities,
        opc_session_store::BackendCapabilities::minimal()
    );
    let consensus_capabilities = store.capabilities().await;
    assert!(consensus_capabilities.atomic_compare_and_set);
    assert!(consensus_capabilities.monotonic_fencing_token);
    assert!(consensus_capabilities.ordered_replication_log);
    assert!(consensus_capabilities.restore_scan);

    assert_raw_consensus_guard(raw.get(&key).await);
    assert_raw_consensus_guard(
        raw.scan_restore_records(RestoreScanRequest::default())
            .await,
    );
    assert_raw_consensus_guard(raw.max_replication_sequence().await);
    assert_raw_consensus_guard(raw.get_replication_log(1, 16).await);
    assert_raw_consensus_guard(raw.rebuild_replication_state(Vec::new()).await);
    assert_raw_consensus_guard(raw.next_lease_info().await);
    assert_raw_consensus_guard(raw.watch(1).await);
    assert_raw_consensus_lease_guard(
        raw.acquire(&key, owner("raw-owner"), Duration::from_secs(30))
            .await,
    );

    let lease = store
        .acquire(&key, owner("consensus-owner"), Duration::from_secs(30))
        .await
        .expect("consensus lease");
    let record = sealed_record(key.clone(), 1, &lease, b"opaque-authoritative-value");
    assert_raw_consensus_guard(
        raw.compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await,
    );
    assert_raw_consensus_guard(raw.delete_fenced(&lease).await);
    assert_raw_consensus_guard(raw.refresh_ttl(&lease, Duration::from_secs(30)).await);
    assert_raw_consensus_lease_guard(raw.renew(&lease, Duration::from_secs(30)).await);
    assert_raw_consensus_lease_guard(raw.release(lease.clone()).await);

    let batch = raw
        .batch(vec![SessionOp::Get { key: key.clone() }])
        .await
        .expect("batch retains per-slot result contract");
    assert!(matches!(
        batch.as_slice(),
        [opc_session_store::SessionOpResult::Get(Err(
            StoreError::CapabilityNotSupported(capability)
        ))] if capability == "consensus_authority_required"
    ));

    store
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: record,
        })
        .await
        .expect("consensus mutation remains available");
    let entry = store
        .get_replication_log(1, 128)
        .await
        .expect("committed application journal")
        .into_iter()
        .next()
        .expect("journal entry");
    assert_raw_consensus_guard(raw.replicate_entry(entry).await);

    let reopened = SqliteSessionBackend::open(cluster._directory.path().join("node-0.sqlite"))
        .expect("reopen consensus-owned SQLite file");
    assert_raw_consensus_guard(reopened.get(&key).await);
    assert_raw_consensus_lease_guard(
        reopened
            .acquire(&key, owner("reopened-owner"), Duration::from_secs(30))
            .await,
    );

    let committed = store
        .get(&key)
        .await
        .expect("linearizable read")
        .expect("committed record");
    assert_eq!(committed.generation, Generation::new(1));
}

#[tokio::test]
async fn batch_preflight_rejects_unsealed_payload_before_any_slot_commits() {
    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let first_key = session_key(b"batch-sealed-first");
    let second_key = session_key(b"batch-unsealed-second");
    let first_lease = store
        .acquire(
            &first_key,
            owner("batch-owner-first"),
            Duration::from_secs(30),
        )
        .await
        .expect("first lease");
    let second_lease = store
        .acquire(
            &second_key,
            owner("batch-owner-second"),
            Duration::from_secs(30),
        )
        .await
        .expect("second lease");
    let before = store
        .max_replication_sequence()
        .await
        .expect("journal head before rejected batch");

    let error = store
        .batch(vec![
            SessionOp::CompareAndSet(CompareAndSet {
                key: first_key.clone(),
                lease: first_lease.clone(),
                expected_generation: None,
                new_record: sealed_record(first_key.clone(), 1, &first_lease, b"sealed-first-slot"),
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: second_key.clone(),
                lease: second_lease.clone(),
                expected_generation: None,
                new_record: plaintext_record(second_key, 1, &second_lease, b"unsealed-second-slot"),
            }),
        ])
        .await
        .expect_err("an unsealed later slot rejects the complete raw batch");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert_eq!(
        store.get(&first_key).await.expect("read first key"),
        None,
        "preflight must run before the first slot reaches Openraft"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("journal head after rejected batch"),
        before
    );
}

#[tokio::test]
async fn batch_commits_independent_slots_and_preserves_partial_results() {
    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let first_key = session_key(b"batch-partial-first");
    let second_key = session_key(b"batch-partial-second");
    let first_lease = store
        .acquire(
            &first_key,
            owner("batch-partial-owner-first"),
            Duration::from_secs(30),
        )
        .await
        .expect("first lease");
    let second_lease = store
        .acquire(
            &second_key,
            owner("batch-partial-owner-second"),
            Duration::from_secs(30),
        )
        .await
        .expect("second lease");
    let first_record = sealed_record(
        first_key.clone(),
        1,
        &first_lease,
        b"sealed-batch-partial-first",
    );
    let second_record = sealed_record(
        second_key.clone(),
        1,
        &second_lease,
        b"sealed-batch-partial-second",
    );
    let conflict_record = sealed_record(
        first_key.clone(),
        2,
        &first_lease,
        b"sealed-batch-partial-conflict",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("journal head before partial batch");

    let results = store
        .batch(vec![
            SessionOp::CompareAndSet(CompareAndSet {
                key: first_key.clone(),
                lease: first_lease.clone(),
                expected_generation: None,
                new_record: first_record.clone(),
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: first_key.clone(),
                lease: first_lease,
                expected_generation: None,
                new_record: conflict_record,
            }),
            SessionOp::CompareAndSet(CompareAndSet {
                key: second_key.clone(),
                lease: second_lease,
                expected_generation: None,
                new_record: second_record.clone(),
            }),
        ])
        .await
        .expect("partial batch invocation");

    assert_eq!(results.len(), 3);
    assert!(matches!(
        &results[0],
        opc_session_store::SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    assert!(matches!(
        &results[1],
        opc_session_store::SessionOpResult::CompareAndSet(Ok(
            CompareAndSetResult::Conflict { current: Some(record) }
        )) if record == &first_record
    ));
    assert!(matches!(
        &results[2],
        opc_session_store::SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));

    let after = store
        .max_replication_sequence()
        .await
        .expect("journal head after partial batch");
    assert_eq!(after, before.checked_add(2).expect("small journal advance"));
    let entries = store
        .get_replication_log(before + 1, 2)
        .await
        .expect("partial batch journal entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, before + 1);
    assert_eq!(entries[1].sequence, before + 2);
    assert!(matches!(
        &entries[0].op,
        ReplicationOp::CompareAndSet { key, .. } if key == &first_key
    ));
    assert!(matches!(
        &entries[1].op,
        ReplicationOp::CompareAndSet { key, .. } if key == &second_key
    ));
    assert_eq!(
        store.get(&first_key).await.expect("first record read"),
        Some(first_record)
    );
    assert_eq!(
        store.get(&second_key).await.expect("second record read"),
        Some(second_record)
    );
}

#[tokio::test]
async fn encryption_wrapper_keeps_plaintext_above_consensus_and_durable_authority() {
    let cluster = TestCluster::start().await;
    let provider = encryption_provider();
    let writer = EncryptingSessionBackend::new(
        Arc::new(cluster.stores[0].clone()),
        Arc::clone(&provider),
        ENCRYPTION_NAMESPACE,
    );

    let before_key = session_key(b"encryption-boundary-before-rotation");
    let before_lease = writer
        .acquire(
            &before_key,
            owner("encryption-boundary-owner-before"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire pre-rotation lease");
    cluster.clear_captured_payloads();
    assert_eq!(
        writer
            .compare_and_set(CompareAndSet {
                key: before_key.clone(),
                lease: before_lease.clone(),
                expected_generation: None,
                new_record: plaintext_record(
                    before_key.clone(),
                    1,
                    &before_lease,
                    PLAINTEXT_CANARY_BEFORE_ROTATION,
                ),
            })
            .await
            .expect("write plaintext through encryption adapter"),
        CompareAndSetResult::Success
    );

    provider
        .rotate_key(
            KeyPurpose::Session,
            &TenantId::new("consensus-test-tenant").expect("tenant"),
        )
        .await
        .expect("rotate active data key");

    let after_key = session_key(b"encryption-boundary-after-rotation");
    let after_lease = writer
        .acquire(
            &after_key,
            owner("encryption-boundary-owner-after"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire post-rotation lease");
    assert_eq!(
        writer
            .compare_and_set(CompareAndSet {
                key: after_key.clone(),
                lease: after_lease.clone(),
                expected_generation: None,
                new_record: plaintext_record(
                    after_key.clone(),
                    1,
                    &after_lease,
                    PLAINTEXT_CANARY_AFTER_ROTATION,
                ),
            })
            .await
            .expect("write with rotated data key"),
        CompareAndSetResult::Success
    );
    assert_eq!(provider.call_counts(), (2, 0, 1));

    for store in &cluster.stores {
        for (key, plaintext) in [
            (&before_key, PLAINTEXT_CANARY_BEFORE_ROTATION),
            (&after_key, PLAINTEXT_CANARY_AFTER_ROTATION),
        ] {
            let record = store
                .get(key)
                .await
                .expect("linearizable raw read")
                .expect("raw record");
            assert_eq!(
                record.payload.encoding(),
                SessionPayloadEncoding::EnvelopeV1
            );
            assert!(!contains_bytes(record.payload.as_bytes(), plaintext));
        }
    }
    assert_eq!(
        provider.call_counts(),
        (2, 0, 1),
        "consensus and raw durable reads must not call the key provider"
    );

    for store in &cluster.stores {
        let reader = EncryptingSessionBackend::new(
            Arc::new(store.clone()),
            Arc::clone(&provider),
            ENCRYPTION_NAMESPACE,
        );
        for (key, expected) in [
            (&before_key, PLAINTEXT_CANARY_BEFORE_ROTATION),
            (&after_key, PLAINTEXT_CANARY_AFTER_ROTATION),
        ] {
            let record = reader
                .get(key)
                .await
                .expect("decrypt through outer adapter")
                .expect("decrypted record");
            assert_eq!(record.payload.encoding(), SessionPayloadEncoding::Plaintext);
            assert_eq!(record.payload.as_bytes(), expected);
        }
    }
    assert_eq!(provider.call_counts(), (2, MEMBER_COUNT * 2, 1));

    let captured_payloads = cluster.captured_payloads();
    assert!(
        !captured_payloads.is_empty(),
        "qualification must observe replicated consensus traffic"
    );
    for payload in captured_payloads {
        assert_artifact_bytes_are_sealed("consensus RPC payload", &payload);
    }
    for index in 0..MEMBER_COUNT {
        assert_sqlite_authority_is_sealed(
            &cluster
                ._directory
                .path()
                .join(format!("node-{index}.sqlite")),
        );
    }
    assert_file_tree_is_sealed(cluster._directory.path());
}

#[tokio::test]
async fn writes_leases_and_cas_converge_with_linearizable_reads() {
    // This proof qualifies cross-node convergence, not a sub-second operation
    // deadline. Use the production budget so the concurrent snapshot workload
    // cannot exhaust a healthy linearizable read barrier under the workspace
    // test harness.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let key = session_key(b"cross-node-cas");
    let lease = cluster.stores[1]
        .acquire(&key, owner("owner-a"), Duration::from_secs(30))
        .await
        .expect("acquire through node 1");
    let initial = sealed_record(key.clone(), 1, &lease, b"sealed-v1");

    assert_eq!(
        cluster.stores[2]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: initial,
            })
            .await
            .expect("CAS through node 2"),
        CompareAndSetResult::Success
    );

    let renewed = cluster.stores[0]
        .renew(&lease, Duration::from_secs(30))
        .await
        .expect("renew through node 0");
    let updated = sealed_record(key.clone(), 2, &renewed, b"sealed-v2");
    assert_eq!(
        cluster.stores[1]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: renewed,
                expected_generation: Some(Generation::new(1)),
                new_record: updated.clone(),
            })
            .await
            .expect("update through node 1"),
        CompareAndSetResult::Success
    );

    let reads =
        futures_util::future::join_all(cluster.stores.iter().map(|store| store.get(&key))).await;
    for read in reads {
        assert_eq!(
            read.expect("linearizable read from every node"),
            Some(updated.clone())
        );
    }

    let logs = replication_logs(&cluster).await;
    assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
    let authoritative_entry = logs[0][0].clone();
    assert!(matches!(
        cluster.stores[0]
            .replicate_entry(authoritative_entry)
            .await,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "direct_replication_authority"
    ));
    assert!(matches!(
        cluster.stores[0]
            .rebuild_replication_state(logs[0].clone())
            .await,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "direct_rebuild_authority"
    ));
    assert_differing_replica_compaction_floors_never_union(&cluster).await;
}

#[tokio::test]
async fn red_696_split_acquire_then_cas_leaves_a_committed_intermediate_boundary() {
    // Retained RED evidence for #696: this passing test describes why composing
    // acquire and CAS is insufficient for callers that require one atomic
    // fenced transition. It is deliberately not an expected-failure test.
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let store = &cluster.stores[leader];
    let key = session_key(b"red-696-split-boundary");
    let persisted_record_count = || {
        let connection = rusqlite::Connection::open(
            cluster
                ._directory
                .path()
                .join(format!("node-{leader}.sqlite")),
        )
        .expect("open temporary leader replica");
        connection
            .query_row(
                "SELECT COUNT(*) FROM session_records WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4",
                rusqlite::params![
                    key.tenant.as_str(),
                    key.nf_kind.as_str(),
                    key.key_type.to_string(),
                    key.stable_id.as_ref(),
                ],
                |row| row.get::<_, i64>(0),
            )
            .expect("count persisted transition record")
    };
    let before = store
        .max_replication_sequence()
        .await
        .expect("read journal head before split transition");
    let mut watch = store
        .watch(before + 1)
        .await
        .expect("subscribe before split transition");
    let before_log = store
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    let lease = store
        .acquire(&key, owner("red-696-owner"), Duration::from_secs(30))
        .await
        .expect("commit split lease acquisition");
    let lease_fence = lease.fence();
    let after_lease_log = store
        .status()
        .last_log_index
        .expect("lease acquisition has a durable log head");
    assert_eq!(
        after_lease_log,
        before_log + 1,
        "split lease acquisition must consume its own consensus entry",
    );

    // A crash or competing actor at this point observes a durable new fence
    // but no record. The first committed application/watch entry is therefore
    // externally distinct from the later record mutation.
    assert_eq!(
        persisted_record_count(),
        0,
        "the record must remain absent after only the lease commit"
    );

    let record = sealed_record(key.clone(), 1, &lease, b"sealed-red-696-record");
    assert!(
        store
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .expect("commit split record mutation")
            == CompareAndSetResult::Success,
        "the second operation must apply the record mutation"
    );
    let after_record_log = store
        .status()
        .last_log_index
        .expect("record mutation has a durable log head");
    assert_eq!(
        after_record_log,
        after_lease_log + 1,
        "split CAS must consume a second, distinct consensus entry",
    );
    assert_eq!(
        persisted_record_count(),
        1,
        "only the second operation may make the record visible"
    );
    let after_record = store
        .max_replication_sequence()
        .await
        .expect("read journal head after split record mutation");
    assert!(
        after_record == before + 2,
        "the record mutation must occupy a second application position"
    );
    let lease_entry = store
        .get_replication_log(before + 1, 1)
        .await
        .expect("read committed lease entry");
    assert!(
        matches!(lease_entry.as_slice(), [entry]
            if matches!(&entry.op, ReplicationOp::AcquireLease { fence, .. } if *fence == lease_fence)),
        "the first application entry must contain only the lease acquisition"
    );
    let record_entry = store
        .get_replication_log(before + 2, 1)
        .await
        .expect("read committed record entry");
    assert!(
        matches!(record_entry.as_slice(), [entry] if matches!(&entry.op, ReplicationOp::CompareAndSet { .. })),
        "the second application entry must contain only the record mutation"
    );

    use futures_util::StreamExt;
    let first_watch = watch
        .next()
        .await
        .expect("first split watch entry")
        .expect("first split watch result");
    let second_watch = watch
        .next()
        .await
        .expect("second split watch entry")
        .expect("second split watch result");
    assert!(
        matches!(first_watch.op, ReplicationOp::AcquireLease { .. }),
        "the first watch entry must expose only the lease acquisition"
    );
    assert!(
        matches!(second_watch.op, ReplicationOp::CompareAndSet { .. }),
        "the second watch entry must expose only the record mutation"
    );
    assert!(
        first_watch.sequence + 1 == second_watch.sequence,
        "the split operations must produce distinct ordered watch entries"
    );
}

#[tokio::test]
async fn red_696_split_renew_then_cas_leaves_a_committed_intermediate_boundary() {
    // Retained RED evidence for #696: legacy renewal and CAS are distinct
    // consensus operations. A crash between them durably extends the lease
    // while leaving the record at its old generation and payload.
    use futures_util::StreamExt;

    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let store = &cluster.stores[leader];
    let key = session_key(b"red-696-split-renew-boundary");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe absent renewal key");
    let (create, original) = fenced_acquire_create_request(
        key.clone(),
        owner("red-696-renew-owner"),
        observation.current_fence(),
        [0x91; 16],
        Duration::from_secs(30),
        b"sealed-red-696-renew-original",
    );
    let created = store
        .fenced_transition(create)
        .await
        .expect("establish record before split renewal");

    let before = store
        .max_replication_sequence()
        .await
        .expect("read journal head before split renewal");
    let before_log = store
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");
    let mut watch = store
        .watch(before + 1)
        .await
        .expect("subscribe before split renewal");

    let renewed = store
        .renew(created.lease(), Duration::from_secs(60))
        .await
        .expect("commit split lease renewal");
    assert_eq!(renewed.fence(), created.lease().fence());
    assert!(renewed.expires_at() > created.lease().expires_at());
    let after_renewal_log = store
        .status()
        .last_log_index
        .expect("renewal has a durable log head");
    assert!(
        after_renewal_log > before_log,
        "split renewal consumes at least one independent consensus entry"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == original),
        "the intermediate boundary retains the old record generation and payload"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("read journal head after split renewal"),
        before + 1,
        "the renewal is independently visible before CAS"
    );

    let successor = sealed_record(key.clone(), 2, &renewed, b"sealed-red-696-renew-successor");
    assert_eq!(
        store
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: renewed,
                expected_generation: Some(Generation::new(1)),
                new_record: successor.clone(),
            })
            .await
            .expect("commit CAS after split renewal"),
        CompareAndSetResult::Success
    );
    assert!(
        store
            .status()
            .last_log_index
            .expect("CAS has a durable log head")
            > after_renewal_log,
        "split CAS consumes a later, distinct consensus entry"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == successor),
        "only the second entry installs the successor record"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("read journal head after split CAS"),
        before + 2,
        "renewal and CAS occupy distinct application positions"
    );

    let renewal_entry = watch
        .next()
        .await
        .expect("split renewal watch entry")
        .expect("split renewal watch result");
    let cas_entry = watch
        .next()
        .await
        .expect("split CAS watch entry")
        .expect("split CAS watch result");
    assert!(matches!(renewal_entry.op, ReplicationOp::RenewLease { .. }));
    assert!(matches!(cas_entry.op, ReplicationOp::CompareAndSet { .. }));
    assert_eq!(renewal_entry.sequence + 1, cas_entry.sequence);
}

#[tokio::test]
async fn fenced_transition_acquire_create_is_one_committed_application_and_watch_entry() {
    use futures_util::StreamExt;

    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let key = session_key(b"fenced-transition-atomic-create");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe absent transition key");
    assert!(observation.record().is_none(), "fresh key has no record");

    let (request, record) = fenced_acquire_create_request(
        key.clone(),
        owner("fenced-transition-owner"),
        observation.current_fence(),
        [0x11; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-create",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("read application head before transition");
    let mut watch = store
        .watch(before + 1)
        .await
        .expect("subscribe before transition");

    let outcome = store
        .fenced_transition(request.clone())
        .await
        .expect("commit atomic fenced transition");
    assert!(
        matches!(outcome.mutation(), FencedTransitionMutationResult::Created),
        "transition reports record creation"
    );
    assert!(
        outcome.committed_generation() == Generation::new(1),
        "transition reports the created generation"
    );
    assert!(
        outcome.lease().fence() == request.lease().committed_fence().expect("committed fence"),
        "transition returns the acquired fence"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(committed)) if committed == record),
        "record becomes visible with the lease at the same application boundary"
    );
    let after = store
        .max_replication_sequence()
        .await
        .expect("read application head after transition");
    assert!(
        after == before + 1,
        "transition occupies one application position"
    );
    let entries = store
        .get_replication_log(before + 1, 1)
        .await
        .expect("read atomic transition entry");
    assert!(
        matches!(entries.as_slice(), [entry]
            if matches!(&entry.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }]))),
        "one application entry contains both the lease and record effects"
    );
    let watched = watch
        .next()
        .await
        .expect("atomic transition watch entry")
        .expect("atomic transition watch result");
    assert!(
        watched.sequence == before + 1
            && matches!(&watched.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "one watch entry exposes the complete atomic transition"
    );
}

#[tokio::test]
async fn fenced_transition_with_finite_record_expiry_uses_one_consensus_entry() {
    let cluster = TestCluster::start().await;
    let (leader_index, _, _) = cluster.observed_leader();
    let store = &cluster.stores[leader_index];
    let key = session_key(b"fenced-transition-one-proposal");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe absent transition key");
    let owner = owner("fenced-transition-one-proposal-owner");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        observation.current_fence(),
        Duration::from_secs(30),
    )
    .expect("build acquire action");
    let mut record = sealed_transition_record(
        key,
        1,
        &owner,
        lease.committed_fence().expect("derive committed fence"),
        b"sealed-fenced-transition-one-proposal",
    );
    record.expires_at = Some(opc_types::Timestamp::from_offset_datetime(
        time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
    ));
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x12; 16]),
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("build finite-expiry transition");
    let before = store
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    store
        .fenced_transition(request)
        .await
        .expect("commit finite-expiry transition");

    let after = store
        .status()
        .last_log_index
        .expect("committed transition has a durable log head");
    assert_eq!(
        after,
        before + 1,
        "finite record expiry must be admitted in the transition entry, not a separate logical-time preflight",
    );
}

#[tokio::test]
async fn fenced_transition_replay_and_status_bind_one_exact_request_body() {
    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let key = session_key(b"fenced-transition-replay");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition key");
    let request_owner = owner("fenced-transition-owner");
    let (request, _) = fenced_acquire_create_request(
        key.clone(),
        request_owner.clone(),
        observation.current_fence(),
        [0x12; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-replay",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("read application head before replay");
    let first = store
        .fenced_transition(request.clone())
        .await
        .expect("commit transition before replay");
    let after_first = store
        .max_replication_sequence()
        .await
        .expect("read application head after first submission");
    let replay = store
        .fenced_transition(request.clone())
        .await
        .expect("replay exact transition");
    let after_replay = store
        .max_replication_sequence()
        .await
        .expect("read application head after replay");
    assert!(first == replay, "exact replay returns the recorded outcome");
    assert!(
        after_first == before + 1 && after_replay == after_first,
        "exact replay has one application effect"
    );
    assert!(
        matches!(store.fenced_transition_status(&request).await,
            Ok(FencedTransitionStatus::Recorded(result))
                if matches!(result.as_ref(), Ok(recorded) if recorded == &first)),
        "status returns the exact recorded success"
    );

    let (conflicting, _) = fenced_acquire_create_request(
        key.clone(),
        request_owner,
        observation.current_fence(),
        [0x12; 16],
        Duration::from_secs(29),
        b"sealed-fenced-transition-replay",
    );
    assert!(
        matches!(
            store.fenced_transition_status(&conflicting).await,
            Ok(FencedTransitionStatus::RequestConflict)
        ),
        "same identity with another canonical body reports a conflict"
    );
    assert!(
        matches!(
            store.fenced_transition(conflicting).await,
            Err(StoreError::FencedTransitionRequestConflict)
        ),
        "same identity with another canonical body has no effect"
    );

    let (unseen, _) = fenced_acquire_create_request(
        key,
        owner("fenced-transition-owner"),
        observation.current_fence(),
        [0x13; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-replay",
    );
    assert!(
        matches!(
            store.fenced_transition_status(&unseen).await,
            Ok(FencedTransitionStatus::NotFound)
        ),
        "status distinguishes an unrecorded identity"
    );
}

#[tokio::test]
async fn fenced_transition_stale_fence_and_generation_rejections_leave_state_unchanged() {
    let cluster = TestCluster::start().await;
    let store = &cluster.stores[0];
    let key = session_key(b"fenced-transition-rejections");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition key");
    let request_owner = owner("fenced-transition-owner");
    let (create, original) = fenced_acquire_create_request(
        key.clone(),
        request_owner.clone(),
        observation.current_fence(),
        [0x21; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-original",
    );
    let created = store
        .fenced_transition(create)
        .await
        .expect("commit initial transition");
    let after_create = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe committed transition");

    let (stale, _) = fenced_acquire_create_request(
        key.clone(),
        request_owner.clone(),
        observation.current_fence(),
        [0x22; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-stale",
    );
    assert!(
        matches!(
            store.fenced_transition(stale.clone()).await,
            Err(StoreError::StaleFence)
        ),
        "a stale observation is rejected before either effect"
    );
    assert!(
        matches!(
            store.fenced_transition_status(&stale).await,
            Ok(FencedTransitionStatus::Recorded(result))
                if matches!(result.as_ref(), Err(StoreError::StaleFence))
        ),
        "status preserves the deterministic stale-fence result"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == original),
        "stale admission preserves the record"
    );
    let after_stale = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe after stale rejection");
    assert!(
        after_stale.current_fence() == after_create.current_fence(),
        "stale admission preserves the durable fence floor"
    );

    let unexpected = sealed_transition_record(
        key.clone(),
        8,
        &request_owner,
        created.lease().fence(),
        b"sealed-fenced-transition-unexpected-generation",
    );
    let generation_request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x23; 16]),
        FencedTransitionLease::renew(created.lease().clone(), Duration::from_secs(30))
            .expect("build renewal action"),
        FencedTransitionMutation::update(Generation::new(7), unexpected),
    )
    .expect("build unexpected-generation transition");
    assert!(
        matches!(
            store.fenced_transition(generation_request).await,
            Err(StoreError::CasConflict)
        ),
        "unexpected generation is rejected before renewal or replacement"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == original),
        "generation rejection preserves the record"
    );
    let after_generation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe after generation rejection");
    assert!(
        after_generation.current_fence() == after_create.current_fence(),
        "generation rejection preserves the durable fence floor"
    );
}

#[tokio::test]
async fn fenced_transition_renew_rejects_record_owner_or_fence_mismatch() {
    use futures_util::StreamExt;

    // This proof qualifies deterministic stale-fence rejection after durable
    // record drift, not the compressed fixture deadline. Use the production
    // budget so concurrent workspace work cannot turn the expected typed
    // rejection into an unrelated quorum failure.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let store = &cluster.stores[0];
    let key = session_key(b"fenced-transition-renew-owner-fence-mismatch");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition key");
    let request_owner = owner("fenced-transition-current-owner");
    let (create, original) = fenced_acquire_create_request(
        key.clone(),
        request_owner.clone(),
        observation.current_fence(),
        [0x24; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-owner-fence-original",
    );
    let created = store
        .fenced_transition(create)
        .await
        .expect("commit initial transition");

    // Mutate only the persisted record in every temporary replica. The lease
    // rows remain intact, so each renewal request below is otherwise currently
    // valid and may reach the record-ownership admission check.
    for (request_id, mismatched_owner, mismatched_fence) in [
        (
            [0x25; 16],
            owner("fenced-transition-unexpected-owner"),
            created.lease().fence(),
        ),
        (
            [0x26; 16],
            request_owner.clone(),
            FenceToken::new(created.lease().fence().get() + 1),
        ),
    ] {
        let mismatched = sealed_transition_record(
            key.clone(),
            original.generation.get(),
            &mismatched_owner,
            mismatched_fence,
            b"sealed-fenced-transition-owner-fence-original",
        );
        for index in 0..MEMBER_COUNT {
            let connection = rusqlite::Connection::open(
                cluster
                    ._directory
                    .path()
                    .join(format!("node-{index}.sqlite")),
            )
            .expect("open temporary replica for owner/fence drift");
            assert_eq!(
                connection
                    .execute(
                        r#"
                        UPDATE session_records
                        SET owner = ?1, fence = ?2, payload = ?3, encoding = ?4
                        WHERE tenant = ?5 AND nf_kind = ?6 AND key_type = ?7 AND stable_id = ?8
                        "#,
                        rusqlite::params![
                            mismatched_owner.as_str(),
                            mismatched_fence.get(),
                            mismatched.payload.as_bytes(),
                            2_i64,
                            key.tenant.as_str(),
                            key.nf_kind.as_str(),
                            key.key_type.to_string(),
                            key.stable_id.as_ref(),
                        ],
                    )
                    .expect("inject record owner/fence drift"),
                1,
                "temporary fixture changes exactly the transition record"
            );
        }

        let successor = sealed_transition_record(
            key.clone(),
            2,
            &request_owner,
            created.lease().fence(),
            b"sealed-fenced-transition-owner-fence-successor",
        );
        let renewal = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes(request_id),
            FencedTransitionLease::renew(created.lease().clone(), Duration::from_secs(30))
                .expect("build still-valid renewal"),
            FencedTransitionMutation::update(Generation::new(1), successor),
        )
        .expect("build renewal transition");
        let before = store
            .max_replication_sequence()
            .await
            .expect("read application head before owner/fence rejection");
        let mut watch = store
            .watch(before + 1)
            .await
            .expect("subscribe before owner/fence rejection");

        assert!(
            matches!(
                store.fenced_transition(renewal.clone()).await,
                Err(StoreError::StaleFence)
            ),
            "a valid renewal cannot mutate a record with a different owner or fence"
        );
        assert!(
            matches!(
                store.fenced_transition_status(&renewal).await,
                Ok(FencedTransitionStatus::Recorded(result))
                    if matches!(result.as_ref(), Err(StoreError::StaleFence))
            ),
            "the deterministic rejection retains its typed stale-fence outcome"
        );
        assert!(
            matches!(store.get(&key).await, Ok(Some(record))
                if record == mismatched
                    && record.generation == original.generation
                    && record.payload == mismatched.payload),
            "rejection preserves the mismatched stored record, generation, and payload"
        );
        assert_eq!(
            store
                .max_replication_sequence()
                .await
                .expect("read application head after owner/fence rejection"),
            before,
            "the rejected renewal has no second application effect"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), watch.next())
                .await
                .is_err(),
            "the rejected renewal emits no watch effect"
        );
    }
}

#[tokio::test]
async fn fenced_transition_expired_old_owner_races_new_owner_with_one_effect() {
    use futures_util::StreamExt;

    let admission_time = opc_types::Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("test timestamp"),
    );
    let clock = Arc::new(MutableTestClock::new(admission_time));
    let cluster = TestCluster::start_with_clock(clock.clone()).await;
    let key = session_key(b"fenced-transition-owner-takeover-race");
    let old_owner = owner("fenced-transition-race-old-owner");
    let new_owner = owner("fenced-transition-race-new-owner");
    let observation = cluster.stores[0]
        .observe_fenced_transition(&key)
        .await
        .expect("observe absent takeover key");
    let (create, _) = fenced_acquire_create_request(
        key.clone(),
        old_owner.clone(),
        observation.current_fence(),
        [0x92; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-race-original",
    );
    let created = cluster.stores[0]
        .fenced_transition(create)
        .await
        .expect("establish old-owner record");

    let old_successor = sealed_transition_record(
        key.clone(),
        2,
        &old_owner,
        created.lease().fence(),
        b"sealed-fenced-transition-race-old-successor",
    );
    let old_request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x93; 16]),
        FencedTransitionLease::renew(created.lease().clone(), Duration::from_secs(60))
            .expect("build old-owner renewal"),
        FencedTransitionMutation::update(Generation::new(1), old_successor),
    )
    .expect("build old-owner transition");

    let new_lease = FencedTransitionLease::acquire(
        key.clone(),
        new_owner.clone(),
        created.lease().fence(),
        Duration::from_secs(60),
    )
    .expect("build new-owner acquisition");
    let new_record = sealed_transition_record(
        key.clone(),
        2,
        &new_owner,
        new_lease.committed_fence().expect("derive takeover fence"),
        b"sealed-fenced-transition-race-new-successor",
    );
    let new_request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x94; 16]),
        new_lease,
        FencedTransitionMutation::update(Generation::new(1), new_record.clone()),
    )
    .expect("build new-owner transition");

    clock.set(created.lease().expires_at());
    let before = cluster.stores[0]
        .max_replication_sequence()
        .await
        .expect("read head before owner race");
    let mut watch = cluster.stores[0]
        .watch(before + 1)
        .await
        .expect("subscribe before owner race");
    let (old_result, new_result) = tokio::join!(
        cluster.stores[0].fenced_transition(old_request.clone()),
        cluster.stores[1].fenced_transition(new_request.clone()),
    );

    assert!(
        matches!(
            old_result,
            Err(StoreError::LeaseExpired | StoreError::StaleFence)
        ),
        "the expired old owner loses regardless of proposal ordering"
    );
    let takeover = new_result.expect("the new owner wins the expired-lease race");
    assert!(matches!(
        takeover.mutation(),
        FencedTransitionMutationResult::Updated
    ));
    assert_eq!(takeover.committed_generation(), Generation::new(2));
    assert_eq!(takeover.lease().owner(), &new_owner);
    assert!(
        matches!(cluster.stores[2].get(&key).await, Ok(Some(record)) if record == new_record),
        "every voter exposes only the new-owner record"
    );
    assert_eq!(
        cluster.stores[0]
            .max_replication_sequence()
            .await
            .expect("read head after owner race"),
        before + 1,
        "the concurrent race has exactly one application effect"
    );
    let watched = watch
        .next()
        .await
        .expect("takeover watch entry")
        .expect("takeover watch result");
    assert!(
        matches!(&watched.op, ReplicationOp::Batch { ops }
            if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "only the atomic new-owner acquisition and update is observable"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), watch.next())
            .await
            .is_err(),
        "the rejected old-owner transition emits no watch effect"
    );
    assert!(matches!(
        cluster.stores[0]
            .fenced_transition_status(&old_request)
            .await,
        Ok(FencedTransitionStatus::Recorded(result))
            if matches!(result.as_ref(), Err(StoreError::LeaseExpired | StoreError::StaleFence))
    ));
    assert!(matches!(
        cluster.stores[1]
            .fenced_transition_status(&new_request)
            .await,
        Ok(FencedTransitionStatus::Recorded(result)) if result.as_ref().is_ok()
    ));
}

#[tokio::test]
async fn fenced_transition_renew_update_refresh_ttl_and_delete_preserve_fence_rules() {
    use futures_util::StreamExt;

    // This proof qualifies atomic renewal/mutation effects, not a sub-second
    // operation deadline. Use the production budget so scheduler contention
    // cannot turn a healthy committed transition into an ambiguous outcome.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader_index, _, _) = cluster.observed_leader();
    let store = &cluster.stores[leader_index];
    let key = session_key(b"fenced-transition-mutation-variants");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition key");
    let request_owner = owner("fenced-transition-owner");
    let (create, _) = fenced_acquire_create_request(
        key.clone(),
        request_owner.clone(),
        observation.current_fence(),
        [0x31; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-v1",
    );
    let created = store
        .fenced_transition(create)
        .await
        .expect("commit initial transition");
    let updated_record = sealed_transition_record(
        key.clone(),
        2,
        &request_owner,
        created.lease().fence(),
        b"sealed-fenced-transition-v2",
    );
    let update = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x32; 16]),
        FencedTransitionLease::renew(created.lease().clone(), Duration::from_secs(30))
            .expect("build update renewal"),
        FencedTransitionMutation::update(Generation::new(1), updated_record.clone()),
    )
    .expect("build update transition");
    let before_update = store
        .max_replication_sequence()
        .await
        .expect("read application head before renewal update");
    let mut update_watch = store
        .watch(before_update + 1)
        .await
        .expect("subscribe before renewal update");
    let before_update_log = store
        .status()
        .last_log_index
        .expect("read consensus head after subscribing before renewal update");
    let updated = store
        .fenced_transition(update)
        .await
        .expect("commit renewal and update");
    let after_update_log = store
        .status()
        .last_log_index
        .expect("read consensus head immediately after renewal update");
    assert!(
        matches!(updated.mutation(), FencedTransitionMutationResult::Updated)
            && updated.committed_generation() == Generation::new(2)
            && updated.lease().fence() == created.lease().fence(),
        "renewal update retains the fence and advances the generation"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == updated_record),
        "renewal update replaces the record"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("read application head after renewal update"),
        before_update + 1,
        "renewal update consumes exactly one application and replication position"
    );
    assert_eq!(
        after_update_log,
        before_update_log + 1,
        "renewal update consumes exactly one committed consensus position"
    );
    let update_entries = store
        .get_replication_log(before_update + 1, 1)
        .await
        .expect("read renewal-update application entry");
    assert!(
        matches!(update_entries.as_slice(), [entry]
            if matches!(&entry.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::RenewLease { .. }, ReplicationOp::CompareAndSet { .. }]))),
        "renewal update is one batch with exactly its lease renewal and record update"
    );
    let watched_update = update_watch
        .next()
        .await
        .expect("renewal-update watch entry")
        .expect("renewal-update watch result");
    assert!(
        watched_update.sequence == before_update + 1
            && matches!(&watched_update.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::RenewLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "watch exposes renewal update as one complete batch with no intermediate effect"
    );

    let refresh = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x33; 16]),
        FencedTransitionLease::renew(updated.lease().clone(), Duration::from_secs(30))
            .expect("build refresh renewal"),
        FencedTransitionMutation::refresh_ttl(Generation::new(2), Duration::from_secs(30))
            .expect("build refresh mutation"),
    )
    .expect("build refresh transition");
    let before_refresh = store
        .max_replication_sequence()
        .await
        .expect("read application head before renewal TTL refresh");
    let mut refresh_watch = store
        .watch(before_refresh + 1)
        .await
        .expect("subscribe before renewal TTL refresh");
    let before_refresh_log = store
        .status()
        .last_log_index
        .expect("read consensus head after subscribing before renewal TTL refresh");
    let refreshed = store
        .fenced_transition(refresh)
        .await
        .expect("commit renewal and TTL refresh");
    let after_refresh_log = store
        .status()
        .last_log_index
        .expect("read consensus head immediately after renewal TTL refresh");
    let expires_at = match refreshed.mutation() {
        FencedTransitionMutationResult::TtlRefreshed { expires_at } => expires_at,
        _ => panic!("transition must report TTL refresh"),
    };
    assert!(
        refreshed.lease().fence() == created.lease().fence(),
        "TTL refresh preserves the fence"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record.expires_at == Some(expires_at)),
        "TTL refresh installs the recorded absolute expiry"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("read application head after renewal TTL refresh"),
        before_refresh + 1,
        "renewal TTL refresh consumes exactly one application and replication position"
    );
    assert_eq!(
        after_refresh_log,
        before_refresh_log + 1,
        "renewal TTL refresh consumes exactly one committed consensus position"
    );
    let refresh_entries = store
        .get_replication_log(before_refresh + 1, 1)
        .await
        .expect("read renewal-TTL-refresh application entry");
    assert!(
        matches!(refresh_entries.as_slice(), [entry]
            if matches!(&entry.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::RenewLease { .. }, ReplicationOp::RefreshTtl { .. }]))),
        "renewal TTL refresh is one batch with exactly its lease renewal and TTL mutation"
    );
    let watched_refresh = refresh_watch
        .next()
        .await
        .expect("renewal-TTL-refresh watch entry")
        .expect("renewal-TTL-refresh watch result");
    assert!(
        watched_refresh.sequence == before_refresh + 1
            && matches!(&watched_refresh.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::RenewLease { .. }, ReplicationOp::RefreshTtl { .. }])),
        "watch exposes renewal TTL refresh as one complete batch with no intermediate effect"
    );

    let delete = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x34; 16]),
        FencedTransitionLease::renew(refreshed.lease().clone(), Duration::from_secs(30))
            .expect("build delete renewal"),
        FencedTransitionMutation::delete(Generation::new(2)),
    )
    .expect("build delete transition");
    let before_delete = store
        .max_replication_sequence()
        .await
        .expect("read application head before renewal delete");
    let mut delete_watch = store
        .watch(before_delete + 1)
        .await
        .expect("subscribe before renewal delete");
    let before_delete_log = store
        .status()
        .last_log_index
        .expect("read consensus head after subscribing before renewal delete");
    let deleted = store
        .fenced_transition(delete)
        .await
        .expect("commit renewal and delete");
    let after_delete_log = store
        .status()
        .last_log_index
        .expect("read consensus head immediately after renewal delete");
    assert!(
        matches!(deleted.mutation(), FencedTransitionMutationResult::Deleted)
            && deleted.committed_generation() == Generation::new(2)
            && deleted.lease().fence() == created.lease().fence(),
        "renewal delete preserves the fence and reports the removed generation"
    );
    assert!(
        matches!(store.get(&key).await, Ok(None)),
        "delete removes the live record"
    );
    let after_delete = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe deleted transition key");
    assert!(
        after_delete.record().is_none() && after_delete.current_fence() == created.lease().fence(),
        "delete retains the fence floor after removing the record"
    );
    assert_eq!(
        store
            .max_replication_sequence()
            .await
            .expect("read application head after renewal delete"),
        before_delete + 1,
        "renewal delete consumes exactly one application and replication position"
    );
    assert_eq!(
        after_delete_log,
        before_delete_log + 1,
        "renewal delete consumes exactly one committed consensus position"
    );
    let delete_entries = store
        .get_replication_log(before_delete + 1, 1)
        .await
        .expect("read renewal-delete application entry");
    assert!(
        matches!(delete_entries.as_slice(), [entry]
            if matches!(&entry.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::RenewLease { .. }, ReplicationOp::DeleteFenced { .. }]))),
        "renewal delete is one batch with exactly its lease renewal and record deletion"
    );
    let watched_delete = delete_watch
        .next()
        .await
        .expect("renewal-delete watch entry")
        .expect("renewal-delete watch result");
    assert!(
        watched_delete.sequence == before_delete + 1
            && matches!(&watched_delete.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::RenewLease { .. }, ReplicationOp::DeleteFenced { .. }])),
        "watch exposes renewal delete as one complete batch with no intermediate effect"
    );
}

#[tokio::test]
async fn fenced_transition_renew_rejects_absent_or_expired_records_without_effects() {
    let admission_time = opc_types::Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("test timestamp"),
    );
    let clock = Arc::new(MutableTestClock::new(admission_time));
    // This proof uses a controlled logical clock to distinguish no-effect CAS
    // rejections from silent renewals. It does not qualify a compressed
    // transport deadline, so retain the production operation budget.
    let cluster = TestCluster::start_with_clock_and_operation_timeout(
        clock.clone(),
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    )
    .await;
    let store = &cluster.stores[0];
    let request_owner = owner("fenced-transition-rejection-owner");

    for (index, variant) in ["update", "refresh", "delete"].into_iter().enumerate() {
        let key = session_key(format!("fenced-transition-absent-{variant}").as_bytes());
        let lease = store
            .acquire(&key, request_owner.clone(), Duration::from_secs(60))
            .await
            .expect("acquire lease for an absent-record renewal");
        let successor = sealed_transition_record(
            key.clone(),
            2,
            &request_owner,
            lease.fence(),
            b"sealed-fenced-transition-absent-successor",
        );
        let request = match variant {
            "update" => FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x70 + index as u8; 16]),
                FencedTransitionLease::renew(lease.clone(), Duration::from_secs(120))
                    .expect("build absent-record update renewal"),
                FencedTransitionMutation::update(Generation::new(1), successor),
            ),
            "refresh" => FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x70 + index as u8; 16]),
                FencedTransitionLease::renew(lease.clone(), Duration::from_secs(120))
                    .expect("build absent-record refresh renewal"),
                FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                    .expect("build absent-record refresh mutation"),
            ),
            "delete" => FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x70 + index as u8; 16]),
                FencedTransitionLease::renew(lease.clone(), Duration::from_secs(120))
                    .expect("build absent-record delete renewal"),
                FencedTransitionMutation::delete(Generation::new(1)),
            ),
            _ => unreachable!("fixed mutation variant"),
        }
        .expect("build absent-record transition");
        assert_fenced_renewal_cas_conflict_has_no_effect(store, &key, request).await;

        // An incorrectly applied renewal would extend this guard to 120s.
        // Advancing exactly to its original deadline proves no rejected
        // transition renewed the lease, without a wall-clock delay.
        clock.set(lease.expires_at());
        let expiry_probe = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x73 + index as u8; 16]),
            FencedTransitionLease::renew(lease, Duration::from_secs(30))
                .expect("build expired absent-record renewal probe"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("build expired absent-record probe");
        assert!(
            matches!(
                store.fenced_transition(expiry_probe).await,
                Err(StoreError::LeaseExpired)
            ),
            "the rejected absent-record renewal did not extend its original lease"
        );
    }

    for (index, variant) in ["update", "refresh", "delete"].into_iter().enumerate() {
        let key = session_key(format!("fenced-transition-expired-{variant}").as_bytes());
        let observation = store
            .observe_fenced_transition(&key)
            .await
            .expect("observe expired-record test key");
        let (create, _) = fenced_acquire_create_request(
            key.clone(),
            request_owner.clone(),
            observation.current_fence(),
            [0x80 + index as u8; 16],
            Duration::from_secs(600),
            b"sealed-fenced-transition-expired-original",
        );
        let created = store
            .fenced_transition(create)
            .await
            .expect("commit record before deterministic expiry");
        let establish_expiry = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x83 + index as u8; 16]),
            FencedTransitionLease::renew(created.lease().clone(), Duration::from_secs(600))
                .expect("build finite-expiry renewal"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(1))
                .expect("build finite-expiry mutation"),
        )
        .expect("build finite-expiry transition");
        let refreshed = store
            .fenced_transition(establish_expiry)
            .await
            .expect("commit finite record expiry");
        let record_expiry = match refreshed.mutation() {
            FencedTransitionMutationResult::TtlRefreshed { expires_at } => expires_at,
            _ => panic!("finite-expiry transition must report its deadline"),
        };
        clock.set(record_expiry);
        assert!(
            matches!(store.get(&key).await, Ok(None)),
            "a finite record expiry equal to committed admission time is not live"
        );

        let successor = sealed_transition_record(
            key.clone(),
            2,
            &request_owner,
            refreshed.lease().fence(),
            b"sealed-fenced-transition-expired-successor",
        );
        let request = match variant {
            "update" => FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x86 + index as u8; 16]),
                FencedTransitionLease::renew(refreshed.lease().clone(), Duration::from_secs(120))
                    .expect("build expired-record update renewal"),
                FencedTransitionMutation::update(Generation::new(1), successor),
            ),
            "refresh" => FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x86 + index as u8; 16]),
                FencedTransitionLease::renew(refreshed.lease().clone(), Duration::from_secs(120))
                    .expect("build expired-record refresh renewal"),
                FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                    .expect("build expired-record refresh mutation"),
            ),
            "delete" => FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x86 + index as u8; 16]),
                FencedTransitionLease::renew(refreshed.lease().clone(), Duration::from_secs(120))
                    .expect("build expired-record delete renewal"),
                FencedTransitionMutation::delete(Generation::new(1)),
            ),
            _ => unreachable!("fixed mutation variant"),
        }
        .expect("build expired-record transition");
        assert_fenced_renewal_cas_conflict_has_no_effect(store, &key, request).await;

        // The finite record deadline is exactly the committed admission time.
        // The lease remains live until this later original deadline, so this
        // probe distinguishes a no-effect CAS conflict from a silent renewal.
        clock.set(refreshed.lease().expires_at());
        let expiry_probe = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x89 + index as u8; 16]),
            FencedTransitionLease::renew(refreshed.lease().clone(), Duration::from_secs(30))
                .expect("build expired-record renewal probe"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("build expired-record probe");
        assert!(
            matches!(
                store.fenced_transition(expiry_probe).await,
                Err(StoreError::LeaseExpired)
            ),
            "the rejected expired-record renewal did not extend its original lease"
        );
    }
}

#[tokio::test]
async fn fenced_transition_expired_lease_is_rejected_at_committed_admission() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let source = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[source];
    let key = session_key(b"fenced-transition-expired-admission");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition key");
    let request_owner = owner("fenced-transition-owner");
    let (create, original) = fenced_acquire_create_request(
        key.clone(),
        request_owner.clone(),
        observation.current_fence(),
        [0x41; 16],
        Duration::from_millis(50),
        b"sealed-fenced-transition-expiry",
    );
    let created = store
        .fenced_transition(create)
        .await
        .expect("commit short-lived transition");
    let expiry_request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x42; 16]),
        FencedTransitionLease::renew(created.lease().clone(), Duration::from_secs(30))
            .expect("build expired renewal"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("build expiry transition");
    cluster.delay_calls(source, Duration::from_millis(200));
    let result = store.fenced_transition(expiry_request).await;
    cluster.stop_delaying_calls(source);
    assert!(
        matches!(result, Err(StoreError::LeaseExpired)),
        "a lease expired before committed admission cannot mutate the record"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == original),
        "expired admission leaves the stored record unchanged"
    );
    let after_expiry = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe after expired admission");
    assert!(
        after_expiry.current_fence() == created.lease().fence(),
        "expired admission does not mint another fence"
    );
}

#[tokio::test]
async fn fenced_transition_ambiguous_forward_retry_recovers_exactly_one_effect() {
    let cluster = TestCluster::start().await;

    for source in 0..MEMBER_COUNT {
        let store = &cluster.stores[source];
        let key = session_key(format!("fenced-transition-ambiguous-{source}").as_bytes());
        let observation = store
            .observe_fenced_transition(&key)
            .await
            .expect("observe transition key");
        let (request, record) = fenced_acquire_create_request(
            key.clone(),
            owner(format!("fenced-transition-owner-{source}")),
            observation.current_fence(),
            [0x50 + source as u8; 16],
            Duration::from_secs(30),
            b"sealed-fenced-transition-ambiguous",
        );
        let before = store
            .max_replication_sequence()
            .await
            .expect("read application head before delayed response");
        let delayed_before = cluster
            .arm_forward_response_delay(source, OPERATION_TIMEOUT + Duration::from_millis(250));
        let result = store.fenced_transition(request.clone()).await;
        cluster.stop_forward_response_delay(source);
        let response_was_delayed = cluster.delayed_forward_responses(source) > delayed_before;

        if response_was_delayed {
            assert!(
                matches!(result, Err(StoreError::FencedTransitionOutcomeUnknown)),
                "a delayed forwarded result is explicitly ambiguous"
            );
            assert!(
                matches!(
                    store.fenced_transition_status(&request).await,
                    Ok(FencedTransitionStatus::Recorded(result)) if result.as_ref().is_ok()
                ),
                "exact status resolves the ambiguous request"
            );
            let replay = store
                .fenced_transition(request)
                .await
                .expect("replay exact ambiguous transition");
            assert!(
                matches!(replay.mutation(), FencedTransitionMutationResult::Created),
                "exact replay returns the committed effect"
            );
            assert!(
                matches!(store.get(&key).await, Ok(Some(committed)) if committed == record),
                "ambiguous retry leaves the committed record intact"
            );
            let after = store
                .max_replication_sequence()
                .await
                .expect("read application head after ambiguity recovery");
            assert!(
                after == before + 1,
                "ambiguous retry has one application effect"
            );
            return;
        }

        assert!(
            result.is_ok(),
            "local leader transition completes without forwarding"
        );
    }

    panic!("no forwarded transition path was exercised while delay was armed");
}

#[tokio::test]
async fn fenced_transition_does_not_auto_replay_after_forward_write_boundary() {
    let cluster = TestCluster::start().await;

    for source in 0..MEMBER_COUNT {
        let store = &cluster.stores[source];
        let key = session_key(format!("fenced-transition-no-auto-replay-{source}").as_bytes());
        let observation = store
            .observe_fenced_transition(&key)
            .await
            .expect("observe transition key");
        let (request, record) = fenced_acquire_create_request(
            key.clone(),
            owner(format!("fenced-transition-no-auto-replay-owner-{source}")),
            observation.current_fence(),
            [0x58 + source as u8; 16],
            Duration::from_secs(30),
            b"sealed-fenced-transition-no-auto-replay",
        );
        let before = store
            .max_replication_sequence()
            .await
            .expect("read application head before response loss");
        let forwards_before = cluster.forward_mutation_calls(source);
        let dropped_before = cluster.arm_forward_response_loss(source, 1);

        let result = store.fenced_transition(request.clone()).await;
        cluster.stop_forward_response_loss(source);
        let response_was_lost = cluster.dropped_forward_responses(source) > dropped_before;

        if response_was_lost {
            assert!(
                matches!(result, Err(StoreError::FencedTransitionOutcomeUnknown)),
                "a possibly delivered transition returns typed ambiguity"
            );
            assert_eq!(
                cluster.forward_mutation_calls(source),
                forwards_before + 1,
                "the request must not be forwarded again after a possibly delivered write",
            );
            assert!(
                matches!(
                    store.fenced_transition_status(&request).await,
                    Ok(FencedTransitionStatus::Recorded(result)) if result.as_ref().is_ok()
                ),
                "exact status resolves the retained request without replay"
            );
            assert!(
                matches!(store.get(&key).await, Ok(Some(committed)) if committed == record),
                "the possibly delivered transition has one committed record effect"
            );
            assert_eq!(
                store
                    .max_replication_sequence()
                    .await
                    .expect("read application head after exact status"),
                before + 1,
                "status recovery must not create a second application effect",
            );
            return;
        }

        assert!(result.is_ok(), "local leader transition completes directly");
    }

    panic!("no forwarded transition path was exercised while response loss was armed");
}

#[tokio::test]
async fn fenced_transition_preproposal_partition_leaves_no_receipt_or_fence() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let source = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[source];
    let key = session_key(b"fenced-transition-preproposal-partition");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition before partition");
    let (request, _) = fenced_acquire_create_request(
        key.clone(),
        owner("fenced-transition-preproposal-owner"),
        observation.current_fence(),
        [0x61; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-preproposal",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("read application head before preproposal fault");
    let forwards_before = cluster.forward_mutation_calls(source);

    // Observation established only a fresh live-voter proof, not a durable
    // activation. Once this follower is isolated it cannot re-establish the
    // required linearizable admission, so it must fail before ForwardMutation.
    cluster.isolate(source);
    let rejected = store.fenced_transition(request.clone()).await;
    assert!(
        matches!(rejected.as_ref(), Err(StoreError::BackendUnavailable(_))),
        "an unactivated isolated source is definitely rejected before transmission"
    );
    assert!(
        !matches!(
            rejected.as_ref(),
            Err(StoreError::FencedTransitionOutcomeUnknown)
        ),
        "a pre-transmission activation failure is never an ambiguous outcome"
    );
    assert_eq!(
        cluster.forward_mutation_calls(source),
        forwards_before,
        "an unactivated isolated source never sends ForwardMutation"
    );

    cluster.heal(source);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed follower regains consensus authority");
    assert!(
        matches!(
            store.fenced_transition_status(&request).await,
            Ok(FencedTransitionStatus::NotFound)
        ),
        "a preproposal failure leaves no retained request result"
    );
    let after = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe key after preproposal failure");
    assert!(
        after.record().is_none() && after.current_fence() == observation.current_fence(),
        "a preproposal failure leaves neither record nor fence effect"
    );
    assert!(
        store
            .max_replication_sequence()
            .await
            .expect("read application head after preproposal recovery")
            == before,
        "a preproposal failure has no application effect"
    );
}

#[tokio::test]
async fn fenced_transition_durable_activation_avoids_reprobe_on_rejecting_peer_path() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let source = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[source];

    let activation_key = session_key(b"fenced-transition-activation-before-rejected-probe");
    let activation_observation = store
        .observe_fenced_transition(&activation_key)
        .await
        .expect("observe the activating transition key");
    let (activation_request, _) = fenced_acquire_create_request(
        activation_key,
        owner("fenced-transition-activation-owner"),
        activation_observation.current_fence(),
        [0x60; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-activation-before-rejected-probe",
    );
    store
        .fenced_transition(activation_request)
        .await
        .expect("commit the first transition and durable activation");
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("all live voters apply durable activation");

    // This precise shim is not an old binary: it rejects only a new V1 probe,
    // while ordinary barriers, forwarding, and Raft append traffic stay live.
    // A later operation must use the durable activation rather than probing it.
    cluster.reject_fenced_transition_capability_probe(source, leader);
    assert!(
        matches!(
            store
                .fenced_transition_capability()
                .await
                .expect("durable activation avoids the rejected capability-probe path"),
            Some(AtomicFencedTransitionCapability::V1)
        ),
        "a durably activated scope advertises V1 without a fresh peer probe"
    );

    let second_key = session_key(b"fenced-transition-after-rejected-probe");
    let second_observation = store
        .observe_fenced_transition(&second_key)
        .await
        .expect("observe a post-activation transition key");
    let (second_request, second_expected) = fenced_acquire_create_request(
        second_key.clone(),
        owner("fenced-transition-activation-owner"),
        second_observation.current_fence(),
        [0x5f; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-after-rejected-probe",
    );
    let forwards_before = cluster.forward_mutation_calls(source);
    let second = store
        .fenced_transition(second_request.clone())
        .await
        .expect("post-activation transition succeeds through the rejecting probe path");
    assert!(
        matches!(second.mutation(), FencedTransitionMutationResult::Created),
        "the activated path commits one fresh record"
    );
    assert!(
        cluster.forward_mutation_calls(source) > forwards_before,
        "the activated follower forwards normally through the current implementation"
    );
    assert!(
        matches!(store.get(&second_key).await, Ok(Some(record)) if record == second_expected),
        "the post-activation transition leaves its expected record"
    );
    assert!(
        matches!(
            store.fenced_transition_status(&second_request).await,
            Ok(FencedTransitionStatus::Recorded(result))
                if matches!(result.as_ref(), Ok(recorded) if recorded == &second)
        ),
        "the post-activation transition retains its exact result"
    );
    cluster.restore_current_rpc_handler(source, leader);
}

#[tokio::test]
async fn fenced_transition_new_follower_rejects_old_leader_before_forwarding() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let source = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[source];
    let key = session_key(b"fenced-transition-new-follower-old-leader");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("new follower observes transition key before leader downgrade");
    let (request, _) = fenced_acquire_create_request(
        key,
        owner("fenced-transition-new-follower-owner"),
        observation.current_fence(),
        [0x5e; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-new-follower-old-leader",
    );
    let forwards_before = cluster.forward_mutation_calls(source);

    // The source has not activated this scope. Its leader rejects only the
    // V1 capability probe while still serving ordinary read barriers, so a
    // fresh all-voter proof must fail before the forwarding boundary.
    cluster.reject_fenced_transition_capability_probe(source, leader);
    let rejected = store.fenced_transition(request).await;
    assert!(
        matches!(
            rejected.as_ref(),
            Err(StoreError::CapabilityNotSupported(capability))
                if capability == "atomic_fenced_transition_v1"
        ),
        "an unsupported leader is a definite preflight failure"
    );
    assert!(
        !matches!(
            rejected.as_ref(),
            Err(StoreError::FencedTransitionOutcomeUnknown)
        ),
        "a preflight failure must never be reported as an ambiguous outcome"
    );
    assert_eq!(
        cluster.forward_mutation_calls(source),
        forwards_before,
        "the new follower never sends ForwardMutation to the old leader"
    );
}

#[tokio::test]
async fn fenced_transition_enqueued_without_quorum_recovers_one_effect_by_exact_id() {
    use futures_util::StreamExt;

    // The fault below deliberately exceeds the selected operation budget to
    // prove OutcomeUnknown recovery. Healthy setup and recovery use the
    // production budget so unrelated scheduler contention does not become the
    // quorum loss under test.
    let operation_timeout = DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT;
    let cluster = TestCluster::start_with_operation_timeout(operation_timeout).await;
    let (leader, _, _) = cluster.observed_leader();
    let store = &cluster.stores[leader];
    let key = session_key(b"fenced-transition-enqueued-without-quorum");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition before proposal fault");
    let (request, expected) = fenced_acquire_create_request(
        key.clone(),
        owner("fenced-transition-enqueued-owner"),
        observation.current_fence(),
        [0x62; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-enqueued",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("read application head before proposal fault");
    let mut watch = store
        .watch(before + 1)
        .await
        .expect("subscribe before proposal fault");
    let delayed_before = cluster.delay_append_entries_for_request(
        leader,
        *request.request_id().as_bytes(),
        operation_timeout + Duration::from_millis(250),
    );

    let ambiguous = store.fenced_transition(request.clone()).await;
    cluster.stop_delaying_append_entries_for_request(leader);
    assert!(
        cluster.delayed_append_entries(leader) > delayed_before,
        "the accepted proposal reached the follower replication phase"
    );
    assert!(
        matches!(ambiguous, Err(StoreError::FencedTransitionOutcomeUnknown)),
        "an enqueued proposal without a quorum acknowledgement has an unknown outcome"
    );

    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("cluster recovers after delayed proposal replication");
    let resolved = match store
        .fenced_transition_status(&request)
        .await
        .expect("resolve exact transition after recovery")
    {
        FencedTransitionStatus::Recorded(result) => match *result {
            Ok(recorded) => {
                let replay = store
                    .fenced_transition(request.clone())
                    .await
                    .expect("replay recorded transition after recovery");
                assert!(
                    replay == recorded,
                    "exact replay returns the retained outcome"
                );
                recorded
            }
            Err(_) => panic!("recovery must retain or safely complete the exact transition"),
        },
        FencedTransitionStatus::NotFound => store
            .fenced_transition(request.clone())
            .await
            .expect("safely complete an unrecorded transition after recovery"),
        FencedTransitionStatus::RequestConflict
        | FencedTransitionStatus::Expired
        | FencedTransitionStatus::HistoryFull
        | FencedTransitionStatus::RetentionExhausted => {
            panic!("recovery must retain or safely complete the exact transition")
        }
    };
    assert!(
        matches!(resolved.mutation(), FencedTransitionMutationResult::Created),
        "recovered transition reports its one create effect"
    );
    assert!(
        matches!(store.get(&key).await, Ok(Some(record)) if record == expected),
        "recovery leaves the expected record visible"
    );
    assert!(
        store
            .max_replication_sequence()
            .await
            .expect("read application head after ambiguity recovery")
            == before + 1,
        "the exact-ID recovery has one application effect"
    );
    let watched = tokio::time::timeout(RECOVERY_TIMEOUT, watch.next())
        .await
        .expect("one recovered watch entry arrives within the recovery bound")
        .expect("recovered watch remains open")
        .expect("recovered watch entry succeeds");
    assert!(
        watched.sequence == before + 1
            && matches!(&watched.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "the recovered request has one atomic watch effect"
    );
}

#[tokio::test]
async fn fenced_transition_leader_transfer_preserves_exact_replay_on_surviving_voter() {
    use futures_util::StreamExt;

    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster = TestCluster::start().await;
    let (old_leader, old_leader_id, old_term) = cluster.observed_leader();
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != old_leader)
        .collect::<Vec<_>>();
    let store = &cluster.stores[old_leader];
    let key = session_key(b"fenced-transition-leader-transfer");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition before leader transfer");
    let (request, expected) = fenced_acquire_create_request(
        key.clone(),
        owner("fenced-transition-transfer-owner"),
        observation.current_fence(),
        [0x63; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-transfer",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("read application head before committed transition");
    let mut watch = cluster.stores[survivors[0]]
        .watch(before + 1)
        .await
        .expect("subscribe surviving voter before transition");
    let committed = store
        .fenced_transition(request.clone())
        .await
        .expect("commit transition before leader transfer");
    let watched = tokio::time::timeout(RECOVERY_TIMEOUT, watch.next())
        .await
        .expect("committed watch entry arrives within the recovery bound")
        .expect("committed watch remains open")
        .expect("committed watch entry succeeds");
    assert!(
        watched.sequence == before + 1
            && matches!(&watched.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "the committed transition has one atomic watch effect before failover"
    );
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("all live voters apply the durable activation before failover");

    cluster.isolate(old_leader);
    let recovery_deadline = tokio::time::Instant::now() + RECOVERY_TIMEOUT;
    let (new_leader_id, new_term) = tokio::time::timeout_at(recovery_deadline, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if let Some(candidate) = statuses.first().and_then(|status| status.leader_id) {
                let term = statuses.first().expect("survivor status").term;
                if candidate != old_leader_id
                    && term > old_term
                    && statuses
                        .iter()
                        .all(|status| status.leader_id == Some(candidate) && status.term == term)
                {
                    break (candidate, term);
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving voters elect a new leader");
    assert!(new_leader_id != old_leader_id && new_term > old_term);

    let survivor = &cluster.stores[survivors[0]];
    assert!(
        matches!(
            survivor
                .fenced_transition_capability()
                .await
                .expect("surviving quorum advertises the durably activated capability"),
            Some(AtomicFencedTransitionCapability::V1)
        ),
        "one unavailable minority does not prevent a durably activated scope from advertising V1"
    );
    let status = survivor
        .fenced_transition_status(&request)
        .await
        .expect("surviving voter resolves the exact committed result");
    assert!(
        matches!(status, FencedTransitionStatus::Recorded(result)
            if matches!(result.as_ref(), Ok(recorded) if recorded == &committed)),
        "leader transfer preserves the exact recorded result"
    );
    let replay = survivor
        .fenced_transition(request.clone())
        .await
        .expect("surviving quorum replays the exact committed result after durable activation");
    assert!(
        replay == committed,
        "exact replay returns the original outcome while the old leader remains unavailable"
    );
    assert!(
        survivor
            .max_replication_sequence()
            .await
            .expect("read surviving application head after exact replay")
            == before + 1,
        "exact replay through a surviving activated quorum does not add an application effect"
    );
    assert!(
        tokio::time::timeout(OPERATION_TIMEOUT, watch.next())
            .await
            .is_err(),
        "exact replay through a surviving activated quorum emits no second watch effect"
    );

    let fresh_key = session_key(b"fenced-transition-leader-transfer-after-activation");
    let fresh_observation = survivor
        .observe_fenced_transition(&fresh_key)
        .await
        .expect("surviving quorum observes a fresh transition after failover");
    let (fresh_request, fresh_expected) = fenced_acquire_create_request(
        fresh_key.clone(),
        owner("fenced-transition-transfer-survivor-owner"),
        fresh_observation.current_fence(),
        [0x64; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-transfer-after-activation",
    );
    let fresh = survivor
        .fenced_transition(fresh_request)
        .await
        .expect("surviving activated quorum commits a fresh transition");
    assert!(
        matches!(fresh.mutation(), FencedTransitionMutationResult::Created),
        "the surviving activated quorum remains available for a fresh transition"
    );
    let fresh_watched = tokio::time::timeout(RECOVERY_TIMEOUT, watch.next())
        .await
        .expect("fresh watch entry arrives within the recovery bound")
        .expect("fresh watch remains open")
        .expect("fresh watch entry succeeds");
    assert!(
        fresh_watched.sequence == before + 2
            && matches!(&fresh_watched.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "the fresh surviving-quorum transition has exactly one atomic watch effect"
    );

    cluster.heal(old_leader);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed voter rejoins the exact compatible scope");
    let replay = survivor
        .fenced_transition(request)
        .await
        .expect("surviving voter replays after compatibility is re-established");
    assert!(
        replay == committed,
        "exact replay survives leader transfer and voter recovery"
    );
    assert!(
        matches!(survivor.get(&key).await, Ok(Some(record)) if record == expected),
        "the surviving voter retains the committed record"
    );
    assert!(
        matches!(survivor.get(&fresh_key).await, Ok(Some(record)) if record == fresh_expected),
        "the healed cluster retains the fresh surviving-quorum record"
    );
    assert!(
        survivor
            .max_replication_sequence()
            .await
            .expect("read surviving application head after replay")
            == before + 2,
        "leader transfer, exact replay, and recovery retain exactly the two committed applications"
    );
}

#[tokio::test]
async fn cold_start_concurrent_mutations_share_one_gap_free_committed_sequence() {
    // This proof qualifies concurrent mutation ordering, not a sub-second
    // formation deadline. Use the production operation budget so unrelated
    // heavyweight tests cannot exhaust cluster formation under the parallel
    // workspace harness before the ordering proof begins.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let keys = [
        session_key(b"cold-start-a"),
        session_key(b"cold-start-b"),
        session_key(b"cold-start-c"),
    ];
    let acquisitions = futures_util::future::join_all((0..MEMBER_COUNT).map(|index| {
        cluster.stores[index].acquire(
            &keys[index],
            owner(format!("cold-owner-{index}")),
            Duration::from_secs(30),
        )
    }))
    .await;
    let leases = acquisitions
        .into_iter()
        .map(|result| result.expect("concurrent cold-start lease"))
        .collect::<Vec<_>>();

    let writes = futures_util::future::join_all((0..MEMBER_COUNT).map(|index| {
        cluster.stores[(index + 1) % MEMBER_COUNT].compare_and_set(CompareAndSet {
            key: keys[index].clone(),
            lease: leases[index].clone(),
            expected_generation: None,
            new_record: sealed_record(keys[index].clone(), 1, &leases[index], b"sealed-cold-start"),
        })
    }))
    .await;
    for result in writes {
        assert_eq!(
            result.expect("concurrent cold-start CAS"),
            CompareAndSetResult::Success
        );
    }

    let logs = replication_logs(&cluster).await;
    assert_eq!(logs[0].len(), MEMBER_COUNT * 2);
    assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
    for (offset, entry) in logs[0].iter().enumerate() {
        assert_eq!(
            entry.sequence,
            u64::try_from(offset + 1).expect("test index")
        );
        assert!(entry.tx_id.is_canonical());
        assert_eq!(
            entry.tx_id.len(),
            opc_session_store::REPLICATION_TX_ID_CANONICAL_BYTES
        );
    }
    let transaction_ids = logs[0]
        .iter()
        .map(|entry| entry.tx_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(transaction_ids.len(), logs[0].len());
}

#[tokio::test]
async fn restore_pages_use_only_linearizable_applied_state_and_fail_closed_when_stale() {
    // This test proves healthy linearizable paging and cursor invalidation
    // across isolate/heal. Use the production operation budget so concurrent
    // snapshot and SQLite qualification work cannot turn the stale-cursor
    // assertion into a scheduler-induced, correctly typed work-budget error.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;

    for label in [b"restore-a".as_slice(), b"restore-b", b"restore-c"] {
        let key = session_key(label);
        let lease = cluster.stores[0]
            .acquire(
                &key,
                owner(format!(
                    "restore-owner-{}",
                    char::from(label[label.len() - 1])
                )),
                Duration::from_secs(30),
            )
            .await
            .expect("acquire restore-test lease through the fleet");
        assert_eq!(
            cluster.stores[1]
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: sealed_record(key, 1, &lease, b"sealed-restore-state"),
                })
                .await
                .expect("commit restore-test record through the fleet"),
            CompareAndSetResult::Success
        );
    }

    let first_pages = futures_util::future::join_all(
        cluster
            .stores
            .iter()
            .map(|store| store.scan_restore_records(RestoreScanRequest::all(2))),
    )
    .await
    .into_iter()
    .map(|page| page.expect("linearizable first restore page"))
    .collect::<Vec<_>>();
    assert_eq!(first_pages[0].records.len(), 2);
    assert!(!first_pages[0].complete);
    assert!(first_pages
        .iter()
        .all(|page| page.records == first_pages[0].records));

    let stale_cursor = first_pages[0]
        .next_cursor
        .clone()
        .expect("bounded first page has a continuation");
    for (store, first_page) in cluster.stores.iter().zip(&first_pages) {
        let second = store
            .scan_restore_records(RestoreScanRequest {
                cursor: first_page.next_cursor.clone(),
                ..RestoreScanRequest::all(2)
            })
            .await
            .expect("linearizable second restore page");
        assert_eq!(second.records.len(), 1);
        assert!(second.complete);
        assert_eq!(second.records[0].key.stable_id.as_ref(), b"restore-c");
    }

    cluster.isolate(0);
    let isolated = tokio::time::timeout(
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT + RECOVERY_TIMEOUT,
        cluster.stores[0].scan_restore_records(RestoreScanRequest::all(1)),
    )
    .await
    .expect("isolated restore attempt is bounded");
    assert!(matches!(isolated, Err(StoreError::BackendUnavailable(_))));

    cluster.heal(0);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed node regains linearizable restore authority");

    let new_key = session_key(b"restore-d");
    let new_lease = cluster.stores[2]
        .acquire(&new_key, owner("restore-owner-d"), Duration::from_secs(30))
        .await
        .expect("acquire lease after restore cursor publication");
    assert_eq!(
        cluster.stores[1]
            .compare_and_set(CompareAndSet {
                key: new_key.clone(),
                lease: new_lease.clone(),
                expected_generation: None,
                new_record: sealed_record(new_key, 1, &new_lease, b"sealed-restore-state"),
            })
            .await
            .expect("commit record after restore cursor publication"),
        CompareAndSetResult::Success
    );

    let stale = cluster.stores[0]
        .scan_restore_records(RestoreScanRequest {
            cursor: Some(stale_cursor),
            ..RestoreScanRequest::all(2)
        })
        .await
        .expect_err("record mutation must invalidate an older restore snapshot");
    assert_eq!(stale, StoreError::RestoreScanCursorStale);

    let restarted = cluster.stores[0]
        .scan_restore_records(RestoreScanRequest::all(4))
        .await
        .expect("restart from the first page after a stale cursor");
    assert_eq!(restarted.records.len(), 4);
    assert!(restarted.complete);
}

#[tokio::test]
async fn isolated_node_fails_closed_and_recovers_after_both_peer_paths_heal() {
    let cluster = TestCluster::start().await;
    cluster.isolate(0);

    let probe_started = Instant::now();
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        cluster.stores[0].probe_durable_readiness(),
    )
    .await
    .expect("readiness probe is bounded");
    assert_eq!(report.state(), DurableReadinessState::NoQuorum);
    assert_eq!(
        report.recovery_progress().state(),
        DurableRecoveryState::AwaitingQuorum
    );
    assert_eq!(report.recovery_progress().reason_code(), "awaiting_quorum");
    assert!(
        report.recovery_progress().local_applied_index()
            <= report.recovery_progress().local_log_index()
    );
    assert!(probe_started.elapsed() < Duration::from_secs(2));

    let key = session_key(b"partitioned-write");
    let mutation_started = Instant::now();
    let mutation = tokio::time::timeout(
        Duration::from_secs(2),
        cluster.stores[0].acquire(&key, owner("isolated-owner"), Duration::from_secs(30)),
    )
    .await
    .expect("partitioned mutation is bounded");
    assert!(
        mutation.is_err(),
        "isolated node must not acknowledge a write"
    );
    assert!(mutation_started.elapsed() < Duration::from_secs(2));

    cluster.heal(0);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed node rejoins fresh readiness");
    let healed_report = cluster.stores[0].probe_durable_readiness().await;
    assert_eq!(healed_report.state(), DurableReadinessState::Ready);
    assert_eq!(
        healed_report.recovery_progress().state(),
        DurableRecoveryState::Synchronized
    );
    assert!(
        healed_report.recovery_progress().local_applied_index()
            >= healed_report.committed_barrier_index()
    );
    cluster.stores[0]
        .acquire(&key, owner("healed-owner"), Duration::from_secs(30))
        .await
        .expect("mutation succeeds after healing");
}

#[tokio::test]
async fn observed_leader_loss_elects_a_different_higher_term_leader_and_recovers() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster = TestCluster::start().await;
    let (old_leader_index, old_leader_id, old_term) = cluster.observed_leader();
    cluster.isolate(old_leader_index);
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != old_leader_index)
        .collect::<Vec<_>>();
    let recovery_deadline = tokio::time::Instant::now() + RECOVERY_TIMEOUT;

    let (new_leader_id, new_term) = tokio::time::timeout_at(recovery_deadline, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if let Some(new_leader_id) = statuses.first().and_then(|status| status.leader_id) {
                let new_term = statuses.first().expect("survivor status").term;
                if new_leader_id != old_leader_id
                    && new_term > old_term
                    && statuses.iter().all(|status| {
                        status.leader_id == Some(new_leader_id) && status.term == new_term
                    })
                {
                    break (new_leader_id, new_term);
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority elects a different higher-term leader");
    assert_ne!(new_leader_id, old_leader_id);
    assert!(new_term > old_term);

    tokio::time::timeout_at(recovery_deadline, async {
        loop {
            let reports = futures_util::future::join_all(
                survivors
                    .iter()
                    .map(|index| cluster.stores[*index].probe_durable_readiness()),
            )
            .await;
            if reports.iter().all(DurableReadinessReport::is_ready) {
                let statuses = survivors
                    .iter()
                    .map(|index| cluster.stores[*index].status())
                    .collect::<Vec<_>>();
                if statuses.iter().all(|status| {
                    status.leader_id == Some(new_leader_id) && status.term == new_term
                }) {
                    break;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority reaches durable readiness after leader election");

    let key = session_key(b"observed-leader-loss");
    let lease = cluster.stores[survivors[0]]
        .acquire(&key, owner("post-failover-owner"), Duration::from_secs(30))
        .await
        .expect("survivor quorum accepts a lease after leader loss");
    let committed = sealed_record(key.clone(), 1, &lease, b"sealed-post-failover");
    assert_eq!(
        CompareAndSetResult::Success,
        cluster.stores[survivors[1]]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: committed.clone(),
            })
            .await
            .expect("survivor quorum commits after leader loss")
    );

    cluster.heal(old_leader_index);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("old leader catches up after rejoining");
    for store in &cluster.stores {
        assert_eq!(
            Some(committed.clone()),
            store.get(&key).await.expect("rejoined fleet converges")
        );
    }
}

#[tokio::test]
async fn lagging_replica_installs_compacted_snapshot_without_losing_committed_state() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    // Snapshot qualification intentionally commits thousands of operations.
    // Keep each operation on the production budget while parallel workspace
    // tests contend for the runner. The aggregate command and recovery bounds
    // keep the complete qualification finite.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let lagging_before = cluster.stores[0]
        .probe_durable_readiness()
        .await
        .recovery_progress()
        .local_applied_index()
        .expect("lagging node initial applied index");
    cluster.isolate(0);
    tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            let reports = futures_util::future::join_all(
                cluster.stores[1..]
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await;
            if reports.iter().all(DurableReadinessReport::is_ready) {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority elects a current leader");

    let key = session_key(b"snapshot-catch-up-committed-record");
    let lease = cluster.stores[1]
        .acquire(
            &key,
            owner("snapshot-catch-up-owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("majority commits lease while follower is isolated");
    let committed_record = sealed_record(key.clone(), 1, &lease, b"sealed-snapshot-catch-up");
    assert_eq!(
        CompareAndSetResult::Success,
        cluster.stores[2]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: committed_record.clone(),
            })
            .await
            .expect("majority commits record while follower is isolated")
    );

    tokio::time::timeout(SNAPSHOT_COMMAND_BATCH_TIMEOUT, async {
        commit_snapshot_triggering_commands(&cluster.stores[1]).await;
    })
    .await
    .expect("snapshot command batch completes within its aggregate bound");

    let compacted = tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            let progress = cluster.stores[1]
                .probe_durable_readiness()
                .await
                .recovery_progress();
            if progress
                .purged_index()
                .is_some_and(|index| index > lagging_before)
                && progress.snapshot_index().is_some()
            {
                break progress;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("majority compacts beyond the isolated follower");

    cluster.heal(0);
    if cluster
        .wait_all_ready(SNAPSHOT_RECOVERY_TIMEOUT)
        .await
        .is_err()
    {
        let reports = futures_util::future::join_all(
            cluster
                .stores
                .iter()
                .map(ConsensusSessionStore::probe_durable_readiness),
        )
        .await;
        let sqlite = consensus_sqlite_progress(&cluster._directory.path().join("node-0.sqlite"));
        panic!(
            "lagging follower did not rejoin after snapshot install: {reports:?}; sqlite={sqlite:?}"
        );
    }
    let recovered = cluster.stores[0]
        .get(&key)
        .await
        .expect("linearizable read after snapshot catch-up");
    assert_eq!(Some(committed_record), recovered);
    let recovered_progress = cluster.stores[0]
        .probe_durable_readiness()
        .await
        .recovery_progress();
    assert_eq!(
        DurableRecoveryState::Synchronized,
        recovered_progress.state()
    );
    assert!(recovered_progress.local_applied_index() >= compacted.snapshot_index());
}

#[tokio::test]
async fn fenced_transition_snapshot_install_preserves_exact_replay_without_second_effect() {
    use futures_util::StreamExt;

    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (lagging_leader, old_leader_id, old_term) = cluster.observed_leader();
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != lagging_leader)
        .collect::<Vec<_>>();
    let store = &cluster.stores[lagging_leader];
    let key = session_key(b"fenced-transition-snapshot-install");
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("observe transition before snapshot fault");
    let (request, expected) = fenced_acquire_create_request(
        key.clone(),
        owner("fenced-transition-snapshot-owner"),
        observation.current_fence(),
        [0x64; 16],
        Duration::from_secs(30),
        b"sealed-fenced-transition-snapshot",
    );
    let before = store
        .max_replication_sequence()
        .await
        .expect("read application head before transition");
    let mut transition_watch = cluster.stores[survivors[0]]
        .watch(before + 1)
        .await
        .expect("subscribe surviving voter before transition");
    let committed = store
        .fenced_transition(request.clone())
        .await
        .expect("commit transition before snapshot fault");
    let transition_log_index = store
        .status()
        .last_log_index
        .expect("committed transition has a durable log index");
    let watched = tokio::time::timeout(RECOVERY_TIMEOUT, transition_watch.next())
        .await
        .expect("committed transition watch entry arrives")
        .expect("committed transition watch remains open")
        .expect("committed transition watch entry succeeds");
    assert!(
        watched.sequence == before + 1
            && matches!(&watched.op, ReplicationOp::Batch { ops }
                if matches!(ops.as_slice(), [ReplicationOp::AcquireLease { .. }, ReplicationOp::CompareAndSet { .. }])),
        "the pre-fault transition has one atomic watch effect"
    );

    let lagging_before = cluster.stores[lagging_leader]
        .probe_durable_readiness()
        .await
        .recovery_progress()
        .local_applied_index()
        .expect("lagging leader initial applied index");
    cluster.isolate(lagging_leader);
    tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            let reports = futures_util::future::join_all(
                survivors
                    .iter()
                    .map(|index| cluster.stores[*index].probe_durable_readiness()),
            )
            .await;
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if reports.iter().all(DurableReadinessReport::is_ready) {
                if let Some(new_leader_id) = statuses.first().and_then(|status| status.leader_id) {
                    let new_term = statuses.first().expect("survivor status").term;
                    if new_leader_id != old_leader_id
                        && new_term > old_term
                        && statuses.iter().all(|status| {
                            status.leader_id == Some(new_leader_id) && status.term == new_term
                        })
                    {
                        break;
                    }
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving voters elect after the committed leader is lost");

    tokio::time::timeout(SNAPSHOT_COMMAND_BATCH_TIMEOUT, async {
        commit_snapshot_triggering_commands(&cluster.stores[survivors[0]]).await;
    })
    .await
    .expect("snapshot command batch completes within its aggregate bound");

    let compacted = tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            let progress = cluster.stores[survivors[0]]
                .probe_durable_readiness()
                .await
                .recovery_progress();
            if progress
                .purged_index()
                .is_some_and(|index| index > lagging_before)
                && progress
                    .snapshot_index()
                    .is_some_and(|index| index >= transition_log_index)
            {
                break progress;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("surviving majority compacts the committed transition into a snapshot");

    cluster.heal(lagging_leader);
    cluster
        .wait_all_ready(SNAPSHOT_RECOVERY_TIMEOUT)
        .await
        .expect("lagging former leader installs the compacted snapshot and rejoins");

    let restored = &cluster.stores[lagging_leader];
    assert!(
        matches!(restored.get(&key).await, Ok(Some(record)) if record == expected),
        "snapshot installation restores the committed fenced record"
    );
    assert!(
        matches!(restored.fenced_transition_status(&request).await,
            Ok(FencedTransitionStatus::Recorded(result))
                if matches!(result.as_ref(), Ok(recorded) if recorded == &committed)),
        "snapshot installation restores the exact request receipt"
    );
    let after_restore = restored
        .max_replication_sequence()
        .await
        .expect("read restored application head");
    assert_eq!(
        before + 1,
        after_restore,
        "snapshot restoration retains exactly one application effect"
    );
    let mut no_second_watch = restored
        .watch(after_restore + 1)
        .await
        .expect("subscribe after restored transition");
    let replay = restored
        .fenced_transition(request)
        .await
        .expect("replay exact transition after snapshot installation");
    assert_eq!(
        committed, replay,
        "same-ID replay after snapshot installation returns the exact recorded outcome"
    );
    assert_eq!(
        after_restore,
        restored
            .max_replication_sequence()
            .await
            .expect("read application head after restored replay"),
        "same-ID replay after snapshot installation adds no application effect"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), no_second_watch.next())
            .await
            .is_err(),
        "same-ID replay after snapshot installation emits no second watch effect"
    );
    let recovered_progress = restored.probe_durable_readiness().await.recovery_progress();
    assert_eq!(
        DurableRecoveryState::Synchronized,
        recovered_progress.state(),
        "restored voter reports synchronized recovery"
    );
    assert!(
        recovered_progress.local_applied_index() >= compacted.snapshot_index(),
        "restored voter applies at least the compacted snapshot index"
    );
}

#[tokio::test]
async fn repeated_lost_forward_responses_retry_one_request_without_duplicate_event() {
    // This test deliberately consumes more retry backoffs than the member
    // count. Use the production operation budget so concurrent snapshot and
    // SQLite qualification work cannot turn the success-path assertion into
    // a scheduler-induced, correctly typed deadline ambiguity.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;

    for source in 0..MEMBER_COUNT {
        let key = session_key(format!("lost-response-{source}").as_bytes());
        let lease = cluster.stores[source]
            .acquire(
                &key,
                owner(format!("lost-response-owner-{source}")),
                Duration::from_secs(30),
            )
            .await
            .expect("prepare lease before response loss");
        let before = cluster.stores[source]
            .max_replication_sequence()
            .await
            .expect("replication head before response loss");
        // More losses than the admitted member count proves retries are
        // deadline/backoff bounded rather than prematurely attempt bounded.
        let dropped_before = cluster.arm_forward_response_loss(source, MEMBER_COUNT + 1);

        let result = cluster.stores[source]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: sealed_record(key.clone(), 1, &lease, b"sealed-after-loss"),
            })
            .await;
        cluster.stop_forward_response_loss(source);
        let response_was_lost = cluster.dropped_forward_responses(source) > dropped_before;

        if response_was_lost {
            assert_eq!(
                result.expect("retry after delivered response loss"),
                CompareAndSetResult::Success
            );
            let after = cluster.stores[source]
                .max_replication_sequence()
                .await
                .expect("replication head after response loss");
            assert_eq!(after, before + 1);

            let logs = replication_logs(&cluster).await;
            assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
            let matching_events = logs[0]
                .iter()
                .filter(|entry| {
                    matches!(
                        &entry.op,
                        ReplicationOp::CompareAndSet { key: event_key, .. }
                            if event_key == &key
                    )
                })
                .count();
            assert_eq!(matching_events, 1);
            return;
        }

        assert_eq!(
            result.expect("local leader CAS"),
            CompareAndSetResult::Success
        );
    }

    panic!("no follower path was exercised while response loss was armed");
}

#[tokio::test]
async fn committed_write_with_a_late_forward_result_is_typed_ambiguous_and_applied_once() {
    let cluster = TestCluster::start().await;

    for source in 0..MEMBER_COUNT {
        let key = session_key(format!("late-result-{source}").as_bytes());
        let lease = cluster.stores[source]
            .acquire(
                &key,
                owner(format!("late-result-owner-{source}")),
                Duration::from_secs(30),
            )
            .await
            .expect("prepare lease before late result");
        let before = cluster.stores[source]
            .max_replication_sequence()
            .await
            .expect("replication head before late result");
        let delayed_before = cluster
            .arm_forward_response_delay(source, OPERATION_TIMEOUT + Duration::from_millis(250));
        let expected = sealed_record(key.clone(), 1, &lease, b"sealed-late-result");

        let result = cluster.stores[source]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: expected.clone(),
            })
            .await;
        cluster.stop_forward_response_delay(source);
        let response_was_delayed = cluster.delayed_forward_responses(source) > delayed_before;

        if response_was_delayed {
            assert_eq!(result, Err(StoreError::CasIdempotencyOutcomeUnavailable));
            let committed = cluster.stores[source]
                .get(&key)
                .await
                .expect("linearizable read after late result");
            assert_eq!(committed, Some(expected));
            let after = cluster.stores[source]
                .max_replication_sequence()
                .await
                .expect("replication head after late result");
            assert_eq!(after, before + 1);

            let logs = replication_logs(&cluster).await;
            assert!(logs.windows(2).all(|pair| pair[0] == pair[1]));
            let matching_events = logs[0]
                .iter()
                .filter(|entry| {
                    matches!(
                        &entry.op,
                        ReplicationOp::CompareAndSet { key: event_key, .. }
                            if event_key == &key
                    )
                })
                .count();
            assert_eq!(matching_events, 1);
            return;
        }

        assert_eq!(
            result.expect("local leader CAS"),
            CompareAndSetResult::Success
        );
    }

    panic!("no follower path was exercised while forward results were delayed");
}

#[tokio::test]
async fn managed_provider_facade_uses_exact_postcommit_results_on_file_backed_three_voter_store() {
    // This is intentionally non-qualifying store-adapter evidence. It uses
    // file-backed SQLite and public OpenRaft APIs, but deterministic local
    // provider/verifier doubles rather than the authenticated mTLS network
    // transport qualified in the dedicated session-net lane.
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let scope = cluster.stores[leader]
        .consumer_scope()
        .expect("current consumer scope");
    let worker = SessionConsumerIdentity::new("spiffe://managed-adapter/worker")
        .expect("test worker identity");
    // The roster ledger is independently rooted in a current fenced-
    // transition receipt. Seed that exact public prerequisite before the V3
    // roster activation; no private backend or test-only admission path is
    // used here.
    let (fenced_transition_activation, _) = fenced_acquire_create_request(
        session_key(b"managed-provider-facade-roster-activation"),
        owner("managed-provider-facade-roster-activation"),
        FenceToken::new(0),
        [0x6f; 16],
        Duration::from_secs(30),
        b"managed-provider-facade-roster-activation",
    );
    cluster.stores[leader]
        .fenced_transition(fenced_transition_activation)
        .await
        .expect("activate exact current fenced-transition receipt ledger");
    let capability = cluster.stores[leader]
        .fenced_mutation_roster_history_state()
        .await;
    assert!(
        capability.is_ok(),
        "public roster capability before activation: {capability:?}"
    );

    // Seed the exact current V2 roster activation through the public
    // consumer adapter. Managed V5 subsequently performs its own fresh V5
    // all-voter probe before every proposal; neither certificate can stand in
    // for the other.
    let activation_identity = SessionConsumerIdentity::new("spiffe://managed-adapter/activation")
        .expect("activation identity");
    let activation_admission = managed_provider_adapter_admission(0x70, 1).with_scope(
        derive_fenced_mutation_roster_scope(
            activation_identity.spiffe_identity_commitment(),
            scope,
        ),
    );
    let activation = cluster.stores[leader]
        .consumer_service()
        .execute_v3(
            &activation_identity,
            SessionConsumerV3Request::new(
                scope,
                SessionConsumerV3Operation::FencedMutationRosterAdmit {
                    admission: Box::new(activation_admission.clone()),
                },
            ),
        )
        .await;
    match activation {
        SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_)) => {}
        SessionConsumerV3Response::Rejected(rejection) => {
            panic!("exact public roster activation rejected: {rejection:?}")
        }
        other => panic!("exact public roster activation failed: {other:?}"),
    }

    // The facade is not an admission API. An invalid member and a valid
    // member of an unadmitted roster both fail before a claim/job mutation or
    // provider call.
    let unadmitted_provider = ManagedProviderAdapterDouble::applied();
    let unadmitted = cluster.stores[leader]
        .managed_provider_job_facade(
            scope,
            worker.clone(),
            [0x75; 32],
            [0x76; 32],
            unadmitted_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct unadmitted facade");
    let unadmitted_admission = managed_provider_adapter_admission(0x74, 1);
    assert_eq!(
        unadmitted
            .run_member(
                unadmitted_admission.clone(),
                Box::new([0x77]),
                FencedMutationRosterOrdinal::new(1).expect("out-of-manifest ordinal"),
            )
            .await,
        Err(ManagedProviderJobError::InvalidMember)
    );
    assert_no_provider_io(&unadmitted_provider);
    assert_no_managed_provider_rows(&cluster, leader, &unadmitted_admission);
    assert_eq!(
        unadmitted
            .run_member(
                unadmitted_admission.clone(),
                Box::new([0x77]),
                FencedMutationRosterOrdinal::new(0).expect("manifest ordinal"),
            )
            .await,
        Err(ManagedProviderJobError::Unavailable)
    );
    assert_no_provider_io(&unadmitted_provider);
    assert_no_managed_provider_rows(&cluster, leader, &unadmitted_admission);

    // All matching members: Ensure, Start, Record, and Finalize report the
    // committed status through the public facade, including a partial
    // verification before the second member establishes the roster.
    let applied = ManagedProviderAdapterDouble::applied();
    let all_match = cluster.stores[leader]
        .managed_provider_job_facade(
            scope,
            worker.clone(),
            [0x81; 32],
            [0x82; 32],
            applied.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct fixed facade");
    let all_match_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &worker,
        managed_provider_adapter_admission(0x80, 2),
    )
    .await;
    let checkpoint: Box<[u8]> = Box::new([0x83]);
    let first_result = all_match
        .run_member(
            all_match_admission.clone(),
            checkpoint.clone(),
            FencedMutationRosterOrdinal::new(0).expect("first ordinal"),
        )
        .await;
    assert_eq!(
        first_result,
        Err(ManagedProviderJobError::Unavailable),
        "incomplete finalization is not a committed Finalize result"
    );
    assert_eq!(
        applied.execute_calls.load(Ordering::SeqCst),
        1,
        "first member receives the sole effect-start permit"
    );
    assert_eq!(
        all_match
            .job_status(
                all_match_admission.clone(),
                FencedMutationRosterOrdinal::new(0).expect("first ordinal"),
            )
            .await
            .expect("public partial verification status")
            .phase(),
        ManagedProviderJobMemberPhase::Verified,
        "one verified member remains an exact nonterminal partial result"
    );
    let established_result = all_match
        .run_member(
            all_match_admission.clone(),
            checkpoint.clone(),
            FencedMutationRosterOrdinal::new(1).expect("second ordinal"),
        )
        .await;
    assert_eq!(
        applied.execute_calls.load(Ordering::SeqCst),
        2,
        "second member receives its independent effect-start permit"
    );
    let established = established_result.expect("second member finalizes matching roster");
    assert_eq!(established.mode(), ManagedProviderJobMode::ManagedV5);
    assert_eq!(
        established.phase(),
        ManagedProviderJobMemberPhase::Established
    );
    assert_eq!(applied.execute_calls.load(Ordering::SeqCst), 2);
    let _ = all_match_admission;

    // An indeterminate recovered effect is the exact committed
    // RequireReconciliation outcome, not an additional provider execution.
    let inconclusive = ManagedProviderAdapterDouble::inconclusive();
    let reconciliation = cluster.stores[leader]
        .managed_provider_job_facade(
            scope,
            worker.clone(),
            [0x91; 32],
            [0x92; 32],
            inconclusive.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct reconciliation facade");
    let reconciliation_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &worker,
        managed_provider_adapter_admission(0x90, 1),
    )
    .await;
    let ordinal = FencedMutationRosterOrdinal::new(0).expect("only ordinal");
    assert_eq!(
        reconciliation
            .run_member(reconciliation_admission.clone(), Box::new([0x93]), ordinal)
            .await,
        Err(ManagedProviderJobError::ReconciliationRequired),
        "an unavailable initial effect leaves a durable recovery row"
    );
    let executions_before_recovery = inconclusive.execute_calls.load(Ordering::SeqCst);
    assert_eq!(
        reconciliation
            .run_member(reconciliation_admission.clone(), Box::new([0x93]), ordinal)
            .await,
        Err(ManagedProviderJobError::ReconciliationRequired),
        "the recovered inconclusive status commits RequireReconciliation"
    );
    assert_eq!(
        inconclusive.execute_calls.load(Ordering::SeqCst),
        executions_before_recovery,
        "recovery never repeats the durable effect start"
    );
    assert_eq!(
        reconciliation
            .job_status(reconciliation_admission.clone(), ordinal)
            .await
            .expect("public reconciliation status")
            .phase(),
        ManagedProviderJobMemberPhase::ReconciliationRequired
    );

    // The immutable checkpoint is checked before provider I/O.
    let executes_before_mismatch = inconclusive.execute_calls.load(Ordering::SeqCst);
    assert_eq!(
        reconciliation
            .run_member(reconciliation_admission.clone(), Box::new([0x94]), ordinal)
            .await,
        Err(ManagedProviderJobError::Unavailable)
    );
    assert_eq!(
        inconclusive.execute_calls.load(Ordering::SeqCst),
        executes_before_mismatch,
        "checkpoint mismatch reaches no provider I/O"
    );

    // The authenticated scope is checked before a provider call as well.
    let current = scope.consensus_identity();
    let stale_scope = SessionConsumerScope::new(ConsensusIdentity::new(
        current.cluster_id(),
        current.configuration_id(),
        ConsensusConfigurationEpoch::new(current.configuration_epoch().get() + 1)
            .expect("successor epoch"),
    ));
    let stale_provider = ManagedProviderAdapterDouble::applied();
    let unauthorized = cluster.stores[leader]
        .managed_provider_job_facade(
            stale_scope,
            worker.clone(),
            [0xb1; 32],
            [0xb2; 32],
            stale_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("factory seals stale scope for pre-I/O rejection");
    assert_eq!(
        unauthorized
            .run_member(reconciliation_admission, Box::new([0x93]), ordinal)
            .await,
        Err(ManagedProviderJobError::Unavailable)
    );
    assert_no_provider_io(&stale_provider);

    // Conclusive NotApplied after EffectStarted records the verifier-bound
    // receipt and invokes the Abort command.  Its replicated abort latch is
    // roster-wide: sibling start attempts return FreshAdmissionRequired with
    // no provider execution, including through public status replay.
    let not_applied = ManagedProviderAdapterDouble::not_applied();
    let abort_worker = SessionConsumerIdentity::new("spiffe://managed-adapter/abort-worker")
        .expect("abort worker");
    let aborting = cluster.stores[leader]
        .managed_provider_job_facade(
            scope,
            abort_worker.clone(),
            [0xc1; 32],
            [0xc2; 32],
            not_applied.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct abort facade");
    let abort_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &abort_worker,
        managed_provider_adapter_admission(0xc0, 2),
    )
    .await;
    assert_eq!(
        aborting
            .run_member(abort_admission.clone(), Box::new([0xc3]), ordinal)
            .await,
        Err(ManagedProviderJobError::ReconciliationRequired),
        "first unavailable effect durably starts only the first member"
    );
    assert_eq!(
        aborting
            .run_member(abort_admission.clone(), Box::new([0xc3]), ordinal)
            .await,
        Err(ManagedProviderJobError::FreshAdmissionRequired),
        "verified NotApplied commits the absorbing abort outcome"
    );
    let calls_before_sibling = not_applied.execute_calls.load(Ordering::SeqCst);
    let sibling = aborting
        .run_member(
            abort_admission.clone(),
            Box::new([0xc3]),
            FencedMutationRosterOrdinal::new(1).expect("sibling ordinal"),
        )
        .await
        .expect("the replicated latch reports its committed aborted outcome");
    assert_eq!(sibling.phase(), ManagedProviderJobMemberPhase::Aborted);
    assert_eq!(
        not_applied.execute_calls.load(Ordering::SeqCst),
        calls_before_sibling,
        "abort latch reaches no sibling provider I/O"
    );
    assert_eq!(
        aborting
            .job_status(abort_admission, ordinal)
            .await
            .expect("public aborted status")
            .phase(),
        ManagedProviderJobMemberPhase::Aborted
    );

    // A conclusive compensated effect commits an aborted managed terminal.
    // Its retry reaches the persisted terminal replay rather than returning a
    // postcommit unavailable result or re-running provider I/O.
    let compensated_provider = ManagedProviderAdapterDouble::compensated();
    let compensated_worker =
        SessionConsumerIdentity::new("spiffe://managed-adapter/compensated-worker")
            .expect("compensated worker");
    let compensated = cluster.stores[leader]
        .managed_provider_job_facade(
            scope,
            compensated_worker.clone(),
            [0xd1; 32],
            [0xd2; 32],
            compensated_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct compensated facade");
    let compensated_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &compensated_worker,
        managed_provider_adapter_admission(0xd0, 1),
    )
    .await;
    let compensated_checkpoint = Box::new([0xd3]);
    let compensated_status = compensated
        .run_member(
            compensated_admission.clone(),
            compensated_checkpoint.clone(),
            ordinal,
        )
        .await
        .expect("compensated terminal is the exact committed managed result");
    assert_eq!(compensated_status.mode(), ManagedProviderJobMode::ManagedV5);
    assert_eq!(
        compensated_status.phase(),
        ManagedProviderJobMemberPhase::Aborted
    );
    assert_eq!(compensated_provider.execute_calls.load(Ordering::SeqCst), 1);
    let replay = compensated
        .run_member(compensated_admission, compensated_checkpoint, ordinal)
        .await
        .expect("post-terminal replay returns durable managed status");
    assert_eq!(replay.mode(), ManagedProviderJobMode::ManagedV5);
    assert_eq!(replay.phase(), ManagedProviderJobMemberPhase::Aborted);
    assert_eq!(compensated_provider.execute_calls.load(Ordering::SeqCst), 1);

    // A predecessor terminal also uses mode 3, but it has no matching
    // managed authority/job commitment. The facade must not reinterpret that
    // durable predecessor terminal as V5 or touch any provider path.
    let predecessor_provider = ManagedProviderAdapterDouble::applied();
    let predecessor = cluster.stores[leader]
        .managed_provider_job_facade(
            scope,
            worker.clone(),
            [0xe1; 32],
            [0xe2; 32],
            predecessor_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct predecessor facade");
    let predecessor_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &worker,
        managed_provider_adapter_admission(0xe0, 1),
    )
    .await;
    terminalize_predecessor_adapter_roster(
        &cluster.stores[leader],
        scope,
        &worker,
        &predecessor_admission,
    )
    .await;
    let predecessor_status = predecessor
        .job_status(predecessor_admission.clone(), ordinal)
        .await
        .expect("ordinary predecessor terminal is publicly classifiable");
    assert_eq!(
        predecessor_status.mode(),
        ManagedProviderJobMode::FrozenV4Terminal,
        "ordinary mode-three terminals classify before absent V5 job ownership is rejected"
    );
    assert_no_provider_io(&predecessor_provider);
    assert_eq!(
        predecessor
            .run_member(predecessor_admission.clone(), Box::new([0xe3]), ordinal,)
            .await,
        Err(ManagedProviderJobError::FrozenV4Terminal)
    );
    assert_no_provider_io(&predecessor_provider);
    // A fresh facade on a different file-backed voter has no process-local
    // memory of the terminal; it must derive the same frozen result from the
    // replicated predecessor state after reopening the public surface.
    let reopened_provider = ManagedProviderAdapterDouble::applied();
    let reopened = cluster.stores[(leader + 1) % MEMBER_COUNT]
        .managed_provider_job_facade(
            scope,
            worker,
            [0xe1; 32],
            [0xe2; 32],
            reopened_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct reopened predecessor facade");
    let reopened_status = reopened
        .job_status(predecessor_admission.clone(), ordinal)
        .await
        .expect("reopened ordinary predecessor terminal is publicly classifiable");
    assert_eq!(
        reopened_status.mode(),
        ManagedProviderJobMode::FrozenV4Terminal,
        "a follower classifies the replicated ordinary terminal without a local V5 authority row"
    );
    assert_no_provider_io(&reopened_provider);
    assert_eq!(
        reopened
            .run_member(predecessor_admission, Box::new([0xe3]), ordinal)
            .await,
        Err(ManagedProviderJobError::FrozenV4Terminal),
        "a reopened predecessor terminal remains frozen"
    );
    assert_no_provider_io(&reopened_provider);
}

#[tokio::test]
async fn managed_provider_facade_reopens_closed_format_seven_voters_through_production_open() {
    let mut cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let scope = cluster.stores[leader]
        .consumer_scope()
        .expect("current consumer scope");

    // Commit a predecessor terminal through the public V3/V4 APIs before
    // closing the voters. The closed format-seven image must preserve this
    // result as a frozen predecessor, never reinterpret it as managed V5.
    activate_managed_provider_adapter_roster(&cluster.stores[leader], scope, 0xa4).await;
    let predecessor_worker =
        SessionConsumerIdentity::new("spiffe://managed-adapter/format-seven-predecessor")
            .expect("predecessor worker identity");
    let predecessor_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &predecessor_worker,
        managed_provider_adapter_admission(0xa5, 1),
    )
    .await;
    terminalize_predecessor_adapter_roster(
        &cluster.stores[leader],
        scope,
        &predecessor_worker,
        &predecessor_admission,
    )
    .await;

    cluster.close_path_backed_voters();
    stage_closed_published_format_seven_voters(&cluster);
    cluster
        .reopen_path_backed_voters_through_production_open()
        .await;

    let (leader, _, _) = cluster.observed_leader();
    let reopened_scope = cluster.stores[leader]
        .consumer_scope()
        .expect("reopened consumer scope");
    assert_eq!(
        scope, reopened_scope,
        "reopen preserves the exact tenant scope"
    );
    let predecessor_provider = ManagedProviderAdapterDouble::applied();
    let predecessor_facade = cluster.stores[leader]
        .managed_provider_job_facade(
            reopened_scope,
            predecessor_worker,
            [0xa6; 32],
            [0xa7; 32],
            predecessor_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct public facade after format-seven production open");
    let predecessor_status = predecessor_facade
        .job_status(
            predecessor_admission,
            FencedMutationRosterOrdinal::new(0).expect("predecessor ordinal"),
        )
        .await
        .expect("public facade reads persisted predecessor terminal after production open");
    assert_eq!(
        predecessor_status.mode(),
        ManagedProviderJobMode::FrozenV4Terminal,
        "the migrated format-seven terminal remains a frozen predecessor"
    );
    assert_eq!(
        predecessor_status.phase(),
        ManagedProviderJobMemberPhase::Established,
        "the public facade returns the exact committed predecessor phase"
    );
    assert_no_provider_io(&predecessor_provider);

    // Commit a managed V5 terminal after the production open. A second full
    // close/reopen must make a fresh public facade return the same persisted
    // result and must not perform another provider effect.
    let managed_worker =
        SessionConsumerIdentity::new("spiffe://managed-adapter/format-seven-managed")
            .expect("managed worker identity");
    let managed_admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        reopened_scope,
        &managed_worker,
        managed_provider_adapter_admission(0xa8, 1),
    )
    .await;
    let executing_provider = ManagedProviderAdapterDouble::applied();
    let executing_facade = cluster.stores[leader]
        .managed_provider_job_facade(
            reopened_scope,
            managed_worker.clone(),
            [0xa9; 32],
            [0xaa; 32],
            executing_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct public managed facade after format-seven production open");
    let ordinal = FencedMutationRosterOrdinal::new(0).expect("managed ordinal");
    let checkpoint = Box::new([0xab]);
    let committed = executing_facade
        .run_member(managed_admission.clone(), checkpoint.clone(), ordinal)
        .await
        .expect("public facade returns committed managed terminal");
    assert_eq!(committed.mode(), ManagedProviderJobMode::ManagedV5);
    assert_eq!(
        committed.phase(),
        ManagedProviderJobMemberPhase::Established
    );
    assert_eq!(executing_provider.execute_calls.load(Ordering::SeqCst), 1);

    cluster.close_path_backed_voters();
    cluster
        .reopen_path_backed_voters_through_production_open()
        .await;

    let (leader, _, _) = cluster.observed_leader();
    let persisted_provider = ManagedProviderAdapterDouble::applied();
    let persisted_facade = cluster.stores[leader]
        .managed_provider_job_facade(
            cluster.stores[leader]
                .consumer_scope()
                .expect("twice-reopened consumer scope"),
            managed_worker,
            [0xa9; 32],
            [0xaa; 32],
            persisted_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct fresh public facade after second production open");
    let persisted = persisted_facade
        .job_status(managed_admission.clone(), ordinal)
        .await
        .expect("fresh public facade reads exact persisted managed terminal");
    assert_eq!(
        persisted, committed,
        "the fresh public facade returns the exact persisted committed status"
    );
    assert_no_provider_io(&persisted_provider);
    let replay = persisted_facade
        .run_member(managed_admission, checkpoint, ordinal)
        .await
        .expect("public facade replays the exact persisted managed terminal");
    assert_eq!(
        replay, committed,
        "the facade replay returns the exact persisted committed status"
    );
    assert_no_provider_io(&persisted_provider);
}

#[tokio::test]
async fn reopened_format_eight_managed_terminal_phase_bindings_fail_closed() {
    #[derive(Clone, Copy)]
    enum Corruption {
        EstablishedOperationWithAbortedJobs,
        AbortedOperationWithEstablishedJobs,
    }

    for corruption in [
        Corruption::EstablishedOperationWithAbortedJobs,
        Corruption::AbortedOperationWithEstablishedJobs,
    ] {
        let mut cluster = TestCluster::start().await;
        let (leader, _, _) = cluster.observed_leader();
        let scope = cluster.stores[leader]
            .consumer_scope()
            .expect("current consumer scope");
        activate_managed_provider_adapter_roster(&cluster.stores[leader], scope, 0xb4).await;

        // Begin from the exact published format-seven file layout, then use
        // only the public production open path to upgrade to the V5 tables.
        cluster.close_path_backed_voters();
        stage_closed_published_format_seven_voters(&cluster);
        cluster
            .reopen_path_backed_voters_through_production_open()
            .await;
        let (leader, _, _) = cluster.observed_leader();
        let scope = cluster.stores[leader]
            .consumer_scope()
            .expect("upgraded consumer scope");

        let marker = match corruption {
            Corruption::EstablishedOperationWithAbortedJobs => 0xb5,
            Corruption::AbortedOperationWithEstablishedJobs => 0xc5,
        };
        let worker = SessionConsumerIdentity::new(format!(
            "spiffe://managed-adapter/phase-binding-corruption-{marker:02x}"
        ))
        .expect("worker identity");
        let admission = admit_managed_provider_adapter_roster(
            &cluster.stores[leader],
            scope,
            &worker,
            managed_provider_adapter_admission(marker, 1),
        )
        .await;
        let provider = match corruption {
            Corruption::EstablishedOperationWithAbortedJobs => {
                ManagedProviderAdapterDouble::applied()
            }
            Corruption::AbortedOperationWithEstablishedJobs => {
                ManagedProviderAdapterDouble::compensated()
            }
        };
        let ordinal = FencedMutationRosterOrdinal::new(0).expect("only ordinal");
        let terminal = cluster.stores[leader]
            .managed_provider_job_facade(
                scope,
                worker.clone(),
                [marker.wrapping_add(1); 32],
                [marker.wrapping_add(2); 32],
                provider.clone(),
                ManagedProviderAdapterVerifier,
            )
            .expect("construct committed V5 facade")
            .run_member(
                admission.clone(),
                Box::new([marker.wrapping_add(3)]),
                ordinal,
            )
            .await
            .expect("commit managed V5 terminal before corruption");
        let expected_phase = match corruption {
            Corruption::EstablishedOperationWithAbortedJobs => {
                ManagedProviderJobMemberPhase::Established
            }
            Corruption::AbortedOperationWithEstablishedJobs => {
                ManagedProviderJobMemberPhase::Aborted
            }
        };
        assert_eq!(terminal.mode(), ManagedProviderJobMode::ManagedV5);
        assert_eq!(terminal.phase(), expected_phase);
        assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 1);

        let request_id = admission.request_id().to_bytes();
        cluster.close_path_backed_voters();
        for index in 0..MEMBER_COUNT {
            let connection = rusqlite::Connection::open(
                cluster
                    ._directory
                    .path()
                    .join(format!("node-{index}.sqlite")),
            )
            .expect("open closed format-eight voter");
            let (operation_phase, job_phase, outcome): (i64, i64, i64) = connection
                .query_row(
                    "SELECT operation.phase, job.phase, job.outcome \
                     FROM consensus_fenced_mutation_roster_operations AS operation \
                     JOIN consensus_fenced_mutation_roster_managed_provider_jobs AS job \
                       ON job.request_id = operation.request_id \
                     WHERE operation.request_id = ?1 AND job.ordinal = 0",
                    params![request_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read exact terminal V5 binding");
            match corruption {
                Corruption::EstablishedOperationWithAbortedJobs => {
                    assert_eq!((operation_phase, job_phase, outcome), (2, 4, 0));
                    connection
                        .execute(
                            "UPDATE consensus_fenced_mutation_roster_managed_provider_jobs \
                             SET phase = 5, outcome = 3 \
                             WHERE request_id = ?1",
                            params![request_id.as_slice()],
                        )
                        .expect("corrupt only established terminal job binding");
                }
                Corruption::AbortedOperationWithEstablishedJobs => {
                    assert_eq!((operation_phase, job_phase, outcome), (3, 5, 3));
                    connection
                        .execute(
                            "UPDATE consensus_fenced_mutation_roster_managed_provider_jobs \
                             SET phase = 4, outcome = 0 \
                             WHERE request_id = ?1",
                            params![request_id.as_slice()],
                        )
                        .expect("corrupt only aborted terminal job binding");
                }
            }
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .expect("checkpoint corrupt closed voter");
        }

        let reopened = cluster
            .try_reopen_path_backed_voters_through_production_open()
            .await;
        assert!(
            matches!(
                reopened,
                Err(opc_session_store::ConsensusSessionStoreOpenError::RecoveryRequired)
            ),
            "public production open must reject cross-bound terminal corruption: {reopened:?}"
        );

        for index in 0..MEMBER_COUNT {
            let connection = rusqlite::Connection::open(
                cluster
                    ._directory
                    .path()
                    .join(format!("node-{index}.sqlite")),
            )
            .expect("inspect rejected format-eight voter");
            let (operation_phase, job_phase, outcome): (i64, i64, i64) = connection
                .query_row(
                    "SELECT operation.phase, job.phase, job.outcome \
                     FROM consensus_fenced_mutation_roster_operations AS operation \
                     JOIN consensus_fenced_mutation_roster_managed_provider_jobs AS job \
                       ON job.request_id = operation.request_id \
                     WHERE operation.request_id = ?1 AND job.ordinal = 0",
                    params![request_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("read rejected terminal binding");
            match corruption {
                Corruption::EstablishedOperationWithAbortedJobs => {
                    assert_eq!((operation_phase, job_phase, outcome), (2, 5, 3));
                }
                Corruption::AbortedOperationWithEstablishedJobs => {
                    assert_eq!((operation_phase, job_phase, outcome), (3, 4, 0));
                }
            }
        }
        assert_eq!(
            provider.execute_calls.load(Ordering::SeqCst),
            1,
            "rejected reopen performs no additional provider execution"
        );
        assert_eq!(
            provider.status_calls.load(Ordering::SeqCst),
            0,
            "rejected reopen performs no provider status I/O"
        );
        assert_eq!(
            provider.adopt_calls.load(Ordering::SeqCst),
            0,
            "rejected reopen performs no provider adoption I/O"
        );
    }
}

#[tokio::test]
async fn managed_provider_finalize_forwarded_by_a_stale_follower_waits_for_its_exact_applied_index()
{
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    let (leader, _, _) = cluster.observed_leader();
    let caller = (leader + 1) % MEMBER_COUNT;
    let scope = cluster.stores[leader]
        .consumer_scope()
        .expect("current consumer scope");
    activate_managed_provider_adapter_roster(&cluster.stores[leader], scope, 0xf4).await;
    let worker = SessionConsumerIdentity::new("spiffe://managed-adapter/exact-local-apply")
        .expect("worker identity");
    let admission = admit_managed_provider_adapter_roster(
        &cluster.stores[leader],
        scope,
        &worker,
        managed_provider_adapter_admission(0xf5, 1),
    )
    .await;
    // Arm only after Start has committed and provider execution begins. The
    // next matching append is Record and the one after it is Finalize.
    let gate = AppendEntriesApplyGate::after_record(Box::new([0xf5; 16]), Box::new([0xf7; 32]));
    let provider = ManagedProviderAdapterDouble::applied_arming(gate.clone());
    let caller_facade = cluster.stores[caller]
        .managed_provider_job_facade(
            scope,
            worker.clone(),
            [0xf6; 32],
            [0xf7; 32],
            provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct follower facade");
    // Gate Finalize before the caller's handler, leaving the leader and the
    // third voter as the committing majority.
    cluster.gate_append_entries_to(leader, caller, gate.clone());
    let forwards_before = cluster.forward_mutation_calls(caller);
    let replay_admission = admission.clone();
    let mut task = tokio::spawn(async move {
        caller_facade
            .run_member(
                admission,
                Box::new([0xf8]),
                FencedMutationRosterOrdinal::new(0).expect("test ordinal"),
            )
            .await
    });

    tokio::select! {
        () = gate.reached() => {}
        result = &mut task => panic!("forwarded managed operation finished before Finalize gate: {result:?}"),
    }
    assert!(
        cluster.forward_mutation_calls(caller) > forwards_before,
        "the managed mutation was forwarded through the non-leader caller"
    );
    tokio::task::yield_now().await;
    assert!(
        !task.is_finished(),
        "the forwarding caller must not classify stale SQLite state before Finalize applies locally"
    );

    gate.release();
    let result = task
        .await
        .expect("forwarded managed operation task joins")
        .expect("exact local applied-index wait returns terminal status");
    cluster.clear_append_entries_gate_to(leader, caller);
    assert_eq!(result.mode(), ManagedProviderJobMode::ManagedV5);
    assert_eq!(result.phase(), ManagedProviderJobMemberPhase::Established);
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 1);

    // An accepted replay shares the public coordinator path and must read the
    // terminal instead of executing the provider again.
    let replay_provider = ManagedProviderAdapterDouble::applied();
    let replay = cluster.stores[caller]
        .managed_provider_job_facade(
            scope,
            SessionConsumerIdentity::new("spiffe://managed-adapter/exact-local-apply")
                .expect("worker identity"),
            [0xf6; 32],
            [0xf7; 32],
            replay_provider.clone(),
            ManagedProviderAdapterVerifier,
        )
        .expect("construct replay facade")
        .run_member(
            replay_admission,
            Box::new([0xf8]),
            FencedMutationRosterOrdinal::new(0).expect("test ordinal"),
        )
        .await
        .expect("accepted terminal replay");
    assert_eq!(replay.phase(), ManagedProviderJobMemberPhase::Established);
    assert_no_provider_io(&replay_provider);
}

#[tokio::test]
async fn reopened_persisted_managed_v5_corruption_fails_closed_without_fabricating_authority() {
    #[derive(Clone, Copy)]
    enum Corruption {
        MissingAuthority,
        MissingOwnedJob,
    }

    for corruption in [Corruption::MissingAuthority, Corruption::MissingOwnedJob] {
        let cluster =
            TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
                .await;
        let (leader, _, _) = cluster.observed_leader();
        let scope = cluster.stores[leader]
            .consumer_scope()
            .expect("current consumer scope");
        let marker = match corruption {
            Corruption::MissingAuthority => 0xa1,
            Corruption::MissingOwnedJob => 0xa2,
        };
        activate_managed_provider_adapter_roster(&cluster.stores[leader], scope, marker).await;
        let worker = SessionConsumerIdentity::new(format!(
            "spiffe://managed-adapter/reopen-corruption-{marker:02x}"
        ))
        .expect("worker identity");
        let admission = admit_managed_provider_adapter_roster(
            &cluster.stores[leader],
            scope,
            &worker,
            managed_provider_adapter_admission(marker.wrapping_add(1), 1),
        )
        .await;
        let ordinal = FencedMutationRosterOrdinal::new(0).expect("test ordinal");
        let provider = ManagedProviderAdapterDouble::applied();
        let terminal = cluster.stores[leader]
            .managed_provider_job_facade(
                scope,
                worker.clone(),
                [marker.wrapping_add(2); 32],
                [marker.wrapping_add(3); 32],
                provider.clone(),
                ManagedProviderAdapterVerifier,
            )
            .expect("construct committed V5 facade")
            .run_member(
                admission.clone(),
                Box::new([marker.wrapping_add(4)]),
                ordinal,
            )
            .await
            .expect("commit managed V5 terminal before corruption");
        assert_eq!(terminal.mode(), ManagedProviderJobMode::ManagedV5);
        assert_eq!(terminal.phase(), ManagedProviderJobMemberPhase::Established);
        assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 1);

        // Every Raft/store/backend handle is dropped before the raw persistent
        // fixture opens an image. The terminal operation is copied verbatim;
        // only one V5 proof component is removed from every voter.
        let request_id = admission.request_id().to_bytes();
        let directory = cluster.close_into_directory();
        let mut terminal_evidence = None;
        for index in 0..MEMBER_COUNT {
            let connection =
                rusqlite::Connection::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open closed voter SQLite image");
            let evidence = connection
                .query_row(
                    "SELECT phase, terminal_digest, terminal_result_digest \
                     FROM consensus_fenced_mutation_roster_operations WHERE request_id = ?1",
                    params![request_id.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .expect("read exact committed terminal evidence");
            assert_eq!(evidence.0, 2, "fixture starts from a terminal roster");
            if let Some(previous) = &terminal_evidence {
                assert_eq!(previous, &evidence, "all voters persist the same terminal");
            } else {
                terminal_evidence = Some(evidence);
            }
            let (phase, attempt, receipt, outcome): (i64, i64, Option<Vec<u8>>, Option<i64>) =
                connection
                    .query_row(
                        "SELECT phase, attempt_fence, receipt_digest, outcome \
                         FROM consensus_fenced_mutation_roster_managed_provider_jobs \
                         WHERE request_id = ?1 AND ordinal = 0",
                        params![request_id.as_slice()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .expect("fixture has an owned terminal V5 job");
            assert_eq!(phase, 4);
            assert!(attempt > 0 && receipt.is_some() && outcome.is_some());
            match corruption {
                Corruption::MissingAuthority => {
                    connection
                        .execute(
                            "DELETE FROM consensus_fenced_mutation_roster_managed_provider_authorities \
                             WHERE request_id = ?1",
                            params![request_id.as_slice()],
                        )
                        .expect("remove only persisted V5 authority");
                }
                Corruption::MissingOwnedJob => {
                    connection
                        .execute(
                            "DELETE FROM consensus_fenced_mutation_roster_managed_provider_jobs \
                             WHERE request_id = ?1 AND ordinal = 0",
                            params![request_id.as_slice()],
                        )
                        .expect("remove only one required V5 job");
                }
            }
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .expect("checkpoint corrupt closed fixture");
        }

        let reopened = match corruption {
            Corruption::MissingAuthority => {
                TestCluster::reopen(directory, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
                    .await
                    .expect("authority-only damage remains observable through the facade")
            }
            Corruption::MissingOwnedJob => {
                assert!(
                    matches!(
                        TestCluster::reopen(directory, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
                            .await,
                        Err(opc_session_store::ConsensusSessionStoreOpenError::RecoveryRequired)
                    ),
                    "missing required V5 job cardinality rejects the public store open"
                );
                continue;
            }
        };
        let (reopened_leader, _, _) = reopened.observed_leader();
        let reopened_provider = ManagedProviderAdapterDouble::applied();
        let facade = reopened.stores[reopened_leader]
            .managed_provider_job_facade(
                scope,
                worker,
                [marker.wrapping_add(2); 32],
                [marker.wrapping_add(3); 32],
                reopened_provider.clone(),
                ManagedProviderAdapterVerifier,
            )
            .expect("construct public reopened facade");
        assert_eq!(
            facade.job_status(admission.clone(), ordinal).await,
            Err(ManagedProviderJobError::Unavailable),
            "partial V5 evidence must fail closed through the public facade"
        );
        assert_eq!(
            facade
                .run_member(
                    admission.clone(),
                    Box::new([marker.wrapping_add(4)]),
                    ordinal
                )
                .await,
            Err(ManagedProviderJobError::Unavailable),
            "a damaged V5 terminal must not be reconstructed or executed"
        );
        assert_no_provider_io(&reopened_provider);

        let directory = reopened.close_into_directory();
        for index in 0..MEMBER_COUNT {
            let connection =
                rusqlite::Connection::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("inspect reopened voter SQLite image");
            let evidence: (i64, Vec<u8>, Vec<u8>) = connection
                .query_row(
                    "SELECT phase, terminal_digest, terminal_result_digest \
                     FROM consensus_fenced_mutation_roster_operations WHERE request_id = ?1",
                    params![request_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("preserve committed predecessor evidence");
            assert_eq!(Some(evidence), terminal_evidence);
            let authority_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM consensus_fenced_mutation_roster_managed_provider_authorities \
                     WHERE request_id = ?1",
                    params![request_id.as_slice()],
                    |row| row.get(0),
                )
                .expect("count V5 authorities after public rejection");
            let job_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM consensus_fenced_mutation_roster_managed_provider_jobs \
                     WHERE request_id = ?1",
                    params![request_id.as_slice()],
                    |row| row.get(0),
                )
                .expect("count V5 jobs after public rejection");
            match corruption {
                Corruption::MissingAuthority => {
                    assert_eq!(
                        authority_count, 0,
                        "public status cannot fabricate authority"
                    );
                    assert_eq!(job_count, 1, "owned receipt evidence remains intact");
                }
                Corruption::MissingOwnedJob => {
                    assert_eq!(authority_count, 1, "authority remains exact and unmodified");
                    assert_eq!(job_count, 0, "public status cannot fabricate a missing job");
                }
            }
        }
    }
}
