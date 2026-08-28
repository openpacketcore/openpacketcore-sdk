use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::engine::error::{InstallSnapshotError, RaftError};
use opc_consensus::engine::raft::InstallSnapshotResponse;
use opc_consensus::{
    decode_bounded, derive_configuration_id, encode_bounded, ConsensusClusterId,
    ConsensusConfigurationEpoch, ConsensusIdentity, DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider,
    KeyPurpose, MemoryKeyProvider, SessionAad, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_session_store::{
    AtomicFencedTransitionCapability, Clock, CompareAndSet, CompareAndSetResult,
    ConsensusSessionStore, DurableReadinessReport, DurableReadinessScope, DurableReadinessState,
    DurableRecoveryState, EncryptedSessionPayload, EncryptingSessionBackend, FenceToken,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionRequest, FencedTransitionRequestId, FencedTransitionStatus,
    FencedTransitionV2CallerNonce, FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2Request, FencedTransitionV2Status, Generation, LeaseError,
    ObservedPhysicalNodeIdentity, OwnerId, QuorumReplicaDescriptor, QuorumTopologyAttestor,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, ReplicationOp, RestoreScanRequest, SessionBackend, SessionConsensusNodeId,
    SessionConsensusPeer, SessionConsensusPeerError, SessionConsensusRpcFamily,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionOp, SessionPayloadEncoding,
    SessionStorePlatformProfile, SqliteSessionBackend, StateClass, StateType, StoreError,
    StoredSessionRecord, SystemClock, TopologyAttestationClaims, TopologyAttestationEvidence,
    TopologyAttestationPolicy, TopologyAttestationProvenance, TopologyAttestationResult,
    TopologyAttestationTime, TopologyAttestationVerificationError,
    TopologyAttestationVerificationInput, TopologyCollectorId, ValidatedQuorumTopology,
    VerifiedQuorumTopologyAttestation, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};
use opc_types::{NetworkFunctionKind, TenantId};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

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
const MAX_CAPTURED_INSTALL_SNAPSHOT_OBSERVATIONS: usize = 64;
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
const FS_VERITY_QUALIFICATION_ENV: &str = "OPC_FS_VERITY_QUALIFICATION";
const FS_VERITY_SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";

/// Create a snapshot-only fixture root on CI's prepared fs-verity mount.
///
/// SQLite databases intentionally continue to use the normal tempfile root,
/// so their mutable database, WAL, and journal I/O never share the loop mount.
fn fs_verity_snapshot_tempdir(prefix: &str) -> TempDir {
    let qualification_required = std::env::var_os(FS_VERITY_QUALIFICATION_ENV).as_deref()
        == Some(std::ffi::OsStr::new("required"));
    match std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV) {
        Some(root) => {
            let root = PathBuf::from(root);
            assert!(
                root.is_absolute(),
                "{FS_VERITY_SNAPSHOT_ROOT_ENV} must be an absolute fs-verity snapshot root"
            );
            tempfile::Builder::new()
                .prefix(prefix)
                .tempdir_in(&root)
                .expect("create fs-verity snapshot fixture directory")
        }
        None if qualification_required => {
            panic!("required fs-verity qualification requires {FS_VERITY_SNAPSHOT_ROOT_ENV}")
        }
        None => tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .expect("create local snapshot fixture directory"),
    }
}

#[derive(Clone, Copy)]
struct AppendEntriesRequestDelay {
    request_id: [u8; 16],
    delay_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InstallSnapshotObservation {
    snapshot_id: String,
    offset: u64,
    len: usize,
    data_sha256: [u8; 32],
    done: bool,
}

// This mirrors only the wire shape needed by the transport qualification. It
// keeps snapshot bytes transient while the observation retains their digest.
#[derive(Deserialize)]
struct InstallSnapshotRequestObservation {
    _vote: opc_consensus::engine::Vote<SessionConsensusNodeId>,
    meta: opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    offset: u64,
    data: Vec<u8>,
    done: bool,
}

fn install_snapshot_observation(
    request: &SessionConsensusWireRequest,
) -> Option<InstallSnapshotObservation> {
    let request = decode_bounded::<InstallSnapshotRequestObservation>(&request.payload).ok()?;
    Some(InstallSnapshotObservation {
        snapshot_id: request.meta.snapshot_id,
        offset: request.offset,
        len: request.data.len(),
        data_sha256: Sha256::digest(&request.data).into(),
        done: request.done,
    })
}

fn install_snapshot_engine_accepted(response: &SessionConsensusWireResponse) -> bool {
    let Ok(payload) = &response.result else {
        return false;
    };
    decode_bounded::<
        Result<
            InstallSnapshotResponse<SessionConsensusNodeId>,
            RaftError<SessionConsensusNodeId, InstallSnapshotError>,
        >,
    >(payload)
    .is_ok_and(|result| result.is_ok())
}

#[derive(Clone)]
struct LoopbackPeer {
    target: SessionConsensusNodeId,
    handler: Arc<StdRwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
    forward_mutation_calls: Arc<AtomicUsize>,
    forward_responses_to_drop: Arc<AtomicUsize>,
    dropped_forward_responses: Arc<AtomicUsize>,
    forward_response_delay_millis: Arc<AtomicU64>,
    delayed_forward_responses: Arc<AtomicUsize>,
    append_entries_request_delay: Arc<StdMutex<Option<AppendEntriesRequestDelay>>>,
    delayed_append_entries: Arc<AtomicUsize>,
    rpc_delay_millis: Arc<AtomicU64>,
    delayed_calls: Arc<AtomicUsize>,
    fenced_transition_v2_capability_probe_calls: Arc<AtomicUsize>,
    capture_payloads: Arc<AtomicBool>,
    captured_payloads: Arc<StdMutex<Vec<Bytes>>>,
    forward_mutation_max_payload_bytes: Arc<AtomicUsize>,
    append_entries_max_payload_bytes: Arc<AtomicUsize>,
    install_snapshot_responses_to_drop: Arc<AtomicUsize>,
    dropped_install_snapshot_responses: Arc<AtomicUsize>,
    install_snapshot_observations: Arc<StdMutex<Vec<InstallSnapshotObservation>>>,
    dropped_install_snapshot_observation: Arc<StdMutex<Option<InstallSnapshotObservation>>>,
    install_snapshot_observation_notify: Arc<tokio::sync::Notify>,
    install_snapshot_response_drop_notify: Arc<tokio::sync::Notify>,
}

impl LoopbackPeer {
    fn new(target: SessionConsensusNodeId) -> Self {
        Self {
            target,
            handler: Arc::new(StdRwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
            forward_mutation_calls: Arc::new(AtomicUsize::new(0)),
            forward_responses_to_drop: Arc::new(AtomicUsize::new(0)),
            dropped_forward_responses: Arc::new(AtomicUsize::new(0)),
            forward_response_delay_millis: Arc::new(AtomicU64::new(0)),
            delayed_forward_responses: Arc::new(AtomicUsize::new(0)),
            append_entries_request_delay: Arc::new(StdMutex::new(None)),
            delayed_append_entries: Arc::new(AtomicUsize::new(0)),
            rpc_delay_millis: Arc::new(AtomicU64::new(0)),
            delayed_calls: Arc::new(AtomicUsize::new(0)),
            fenced_transition_v2_capability_probe_calls: Arc::new(AtomicUsize::new(0)),
            capture_payloads: Arc::new(AtomicBool::new(true)),
            captured_payloads: Arc::new(StdMutex::new(Vec::new())),
            forward_mutation_max_payload_bytes: Arc::new(AtomicUsize::new(0)),
            append_entries_max_payload_bytes: Arc::new(AtomicUsize::new(0)),
            install_snapshot_responses_to_drop: Arc::new(AtomicUsize::new(0)),
            dropped_install_snapshot_responses: Arc::new(AtomicUsize::new(0)),
            install_snapshot_observations: Arc::new(StdMutex::new(Vec::new())),
            dropped_install_snapshot_observation: Arc::new(StdMutex::new(None)),
            install_snapshot_observation_notify: Arc::new(tokio::sync::Notify::new()),
            install_snapshot_response_drop_notify: Arc::new(tokio::sync::Notify::new()),
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

    fn fenced_transition_v2_capability_probe_calls(&self) -> usize {
        self.fenced_transition_v2_capability_probe_calls
            .load(Ordering::SeqCst)
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

    fn set_capture_payloads(&self, capture: bool) {
        self.capture_payloads.store(capture, Ordering::SeqCst);
    }

    fn forward_mutation_max_payload_bytes(&self) -> usize {
        self.forward_mutation_max_payload_bytes
            .load(Ordering::SeqCst)
    }

    fn append_entries_max_payload_bytes(&self) -> usize {
        self.append_entries_max_payload_bytes.load(Ordering::SeqCst)
    }

    fn arm_one_install_snapshot_response_loss(&self) {
        self.install_snapshot_responses_to_drop
            .store(1, Ordering::SeqCst);
        self.dropped_install_snapshot_responses
            .store(0, Ordering::SeqCst);
        self.install_snapshot_observations
            .lock()
            .expect("snapshot observation mutex")
            .clear();
        self.dropped_install_snapshot_observation
            .lock()
            .expect("dropped snapshot observation mutex")
            .take();
    }

    fn dropped_install_snapshot_responses(&self) -> usize {
        self.dropped_install_snapshot_responses
            .load(Ordering::SeqCst)
    }

    fn dropped_install_snapshot_observation(&self) -> Option<InstallSnapshotObservation> {
        self.dropped_install_snapshot_observation
            .lock()
            .expect("dropped snapshot observation mutex")
            .clone()
    }

    fn observed_install_snapshot_retry(&self, dropped: &InstallSnapshotObservation) -> bool {
        let observations = self
            .install_snapshot_observations
            .lock()
            .expect("snapshot observation mutex");
        assert!(
            observations.len() < MAX_CAPTURED_INSTALL_SNAPSHOT_OBSERVATIONS,
            "snapshot response-loss observation capture was saturated"
        );
        observations
            .iter()
            .position(|observation| observation == dropped)
            .is_some_and(|position| {
                observations
                    .iter()
                    .skip(position + 1)
                    .any(|observation| observation == dropped)
            })
    }

    fn install_snapshot_observation_notification(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.install_snapshot_observation_notify)
    }

    fn install_snapshot_response_drop_notification(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.install_snapshot_response_drop_notify)
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

/// Wire-identical test shape for the private V1 capability reply. This lets
/// the handler below distinguish a peer's explicit protocol `Unsupported`
/// result from a transport/protocol call failure.
#[derive(Serialize)]
#[allow(dead_code)]
enum FencedTransitionCapabilityReplyV1 {
    V1,
    Unsupported,
}

/// The activation certificate was added after the signed 36720e58 baseline.
/// Its probe has two required postcard fields; that baseline's one-field V1
/// decoder rejects the trailing field. This local handler emulates exactly
/// that peer behavior while retaining real authenticated Raft and ordinary
/// read-barrier traffic for the surrounding three-voter cluster.
#[derive(Deserialize)]
struct FencedTransitionActivationCapabilityProbeV2 {
    activation_probe_schema_version: u16,
    activation_command_schema_version: u16,
}

struct RejectFencedTransitionCapabilityProbeHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
}

/// Test-only shape of the V2 current-voter capability probe.
#[derive(Deserialize)]
struct FencedTransitionV2CapabilityProbe {
    schema_version: u16,
    profile_digest: [u8; 32],
}

struct RejectFencedTransitionV2CapabilityProbeHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
}

/// Test-only shape of the immutable protected-roster profile probe.
#[derive(Deserialize)]
struct ProtectedRosterProfileCapabilityProbe {
    domain: [u8; 8],
    schema_version: u16,
    profile_digest: [u8; 32],
}

/// Wire-identical test shape for the private profile-capability reply.
#[derive(Serialize)]
#[allow(dead_code)]
struct ProtectedRosterProfileCapabilityReply {
    domain: [u8; 8],
    schema_version: u16,
    outcome: ProtectedRosterProfileCapabilityOutcome,
}

#[derive(Serialize)]
#[allow(dead_code)]
enum ProtectedRosterProfileCapabilityOutcome {
    Supported { profile_digest: [u8; 32] },
    Unsupported,
}

struct MismatchedProtectedRosterProfileCapabilityProbeHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
}

impl fmt::Debug for MismatchedProtectedRosterProfileCapabilityProbeHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MismatchedProtectedRosterProfileCapabilityProbeHandler(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for MismatchedProtectedRosterProfileCapabilityProbeHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::ReadBarrier
            && matches!(
                decode_bounded::<ProtectedRosterProfileCapabilityProbe>(&request.payload),
                Ok(ProtectedRosterProfileCapabilityProbe {
                    domain: _domain,
                    schema_version: _schema_version,
                    profile_digest: _profile_digest,
                })
            )
        {
            return SessionConsensusWireResponse {
                result: Ok(encode_bounded(&ProtectedRosterProfileCapabilityReply {
                    domain: *b"opc-rr-1",
                    schema_version: 1,
                    outcome: ProtectedRosterProfileCapabilityOutcome::Supported {
                        profile_digest: [0xa7; 32],
                    },
                })
                .expect("bounded mismatched protected-roster profile reply")),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

impl fmt::Debug for RejectFencedTransitionV2CapabilityProbeHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RejectFencedTransitionV2CapabilityProbeHandler(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for RejectFencedTransitionV2CapabilityProbeHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::ReadBarrier
            && matches!(
                decode_bounded::<FencedTransitionV2CapabilityProbe>(&request.payload),
                Ok(FencedTransitionV2CapabilityProbe {
                    schema_version: 2,
                    profile_digest: _profile_digest,
                })
            )
        {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Protocol),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
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
                result: Ok(
                    encode_bounded(&FencedTransitionCapabilityReplyV1::Unsupported)
                        .expect("bounded explicit unsupported capability reply"),
                ),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

struct Baseline36720ActivationProbeHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
}

impl fmt::Debug for Baseline36720ActivationProbeHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Baseline36720ActivationProbeHandler(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for Baseline36720ActivationProbeHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::ReadBarrier
            && matches!(
                decode_bounded::<FencedTransitionActivationCapabilityProbeV2>(&request.payload),
                Ok(FencedTransitionActivationCapabilityProbeV2 {
                    activation_probe_schema_version: 2,
                    activation_command_schema_version: 1,
                })
            )
        {
            // The signed baseline accepts the established unit barrier and
            // one-field V1 capability probe, but rejects this new complete
            // activation probe before it can ever see a new log intent.
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

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        if request.family == SessionConsensusRpcFamily::ForwardMutation {
            self.forward_mutation_calls.fetch_add(1, Ordering::SeqCst);
            self.forward_mutation_max_payload_bytes
                .fetch_max(request.payload.len(), Ordering::SeqCst);
        }
        if request.family == SessionConsensusRpcFamily::AppendEntries {
            self.append_entries_max_payload_bytes
                .fetch_max(request.payload.len(), Ordering::SeqCst);
        }
        if request.family == SessionConsensusRpcFamily::ReadBarrier
            && matches!(
                decode_bounded::<FencedTransitionV2CapabilityProbe>(&request.payload),
                Ok(FencedTransitionV2CapabilityProbe {
                    schema_version: 2,
                    profile_digest: _profile_digest,
                })
            )
        {
            self.fenced_transition_v2_capability_probe_calls
                .fetch_add(1, Ordering::SeqCst);
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

        if self.capture_payloads.load(Ordering::SeqCst) {
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
        let snapshot_observation = (family == SessionConsensusRpcFamily::InstallSnapshot)
            .then(|| install_snapshot_observation(&request))
            .flatten();
        let response = handler.handle(sender, request).await;

        if family == SessionConsensusRpcFamily::InstallSnapshot
            && install_snapshot_engine_accepted(&response)
        {
            if let Some(observation) = snapshot_observation {
                let mut observations = self
                    .install_snapshot_observations
                    .lock()
                    .expect("snapshot observation mutex");
                if observations.len() < MAX_CAPTURED_INSTALL_SNAPSHOT_OBSERVATIONS {
                    observations.push(observation.clone());
                }
                drop(observations);
                self.install_snapshot_observation_notify.notify_one();

                if self
                    .install_snapshot_responses_to_drop
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok()
                {
                    *self
                        .dropped_install_snapshot_observation
                        .lock()
                        .expect("dropped snapshot observation mutex") = Some(observation);
                    self.dropped_install_snapshot_responses
                        .fetch_add(1, Ordering::SeqCst);
                    self.install_snapshot_response_drop_notify.notify_one();
                    return Err(SessionConsensusPeerError::Unavailable);
                }
            }
        }

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
    _snapshot_directory: TempDir,
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
    // Retain the production 4,096-log snapshot threshold and commit every
    // qualification command. Each request must finish before the next begins:
    // concurrent logical-time reads intentionally share one bounded consensus
    // proposal, whereas this helper must commit the full production snapshot
    // threshold without adding an application-visible effect.
    for _ in 0..SNAPSHOT_CATCH_UP_COMMANDS {
        store
            .max_replication_sequence()
            .await
            .expect("advance committed logical time toward snapshot compaction");
    }
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
        let directory = tempfile::tempdir().expect("create fleet database directory");
        let snapshot_directory = fs_verity_snapshot_tempdir("consensus-openraft-snapshots-");
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

        let mut paths = BTreeMap::new();
        for source in 0..MEMBER_COUNT {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(LoopbackPeer::new(node_id)));
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
                snapshot_directory.path().join(format!("snapshots-{index}")),
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
            _snapshot_directory: snapshot_directory,
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

    fn fenced_transition_v2_capability_probe_calls(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .fenced_transition_v2_capability_probe_calls()
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

    fn emulate_baseline_36720_activation_probe_rejection(&self, source: usize, target: usize) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .install(Arc::new(Baseline36720ActivationProbeHandler {
                inner: self.stores[target].rpc_handler(),
            }));
    }

    fn reject_fenced_transition_v2_capability_probe(&self, source: usize, target: usize) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .install(Arc::new(RejectFencedTransitionV2CapabilityProbeHandler {
                inner: self.stores[target].rpc_handler(),
            }));
    }

    fn mismatch_protected_roster_profile_capability_probe(&self, source: usize, target: usize) {
        self.paths
            .get(&(source, target))
            .expect("outbound path")
            .install(Arc::new(
                MismatchedProtectedRosterProfileCapabilityProbeHandler {
                    inner: self.stores[target].rpc_handler(),
                },
            ));
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

    /// The maximum-CAS evidence deliberately disables optional test capture:
    /// capturing an RPC by cloning it would manufacture a second full
    /// ciphertext allocation that production forwarding does not make.
    fn set_capture_payloads(&self, capture: bool) {
        for path in self.paths.values() {
            path.set_capture_payloads(capture);
        }
    }

    fn forward_mutation_max_payload_bytes(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .forward_mutation_max_payload_bytes()
            })
            .max()
            .unwrap_or(0)
    }

    fn append_entries_max_payload_bytes(&self, source: usize) -> usize {
        (0..MEMBER_COUNT)
            .filter(|target| *target != source)
            .map(|target| {
                self.paths
                    .get(&(source, target))
                    .expect("outbound path")
                    .append_entries_max_payload_bytes()
            })
            .max()
            .unwrap_or(0)
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

/// Count the two durable artifacts whose one-for-one growth proves an applied
/// CAS produced exactly one receipt and exactly one visible replication effect
/// on this SQLite voter.  The query intentionally reads scalar counts only:
/// the maximum-payload evidence must not hydrate or clone a ciphertext row.
fn durable_cas_artifact_counts(database: &Path) -> (u64, u64) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open consensus durable-artifact database");
    let receipts = connection
        .query_row(
            "SELECT COUNT(*) FROM consensus_request_outcomes",
            [],
            |row| row.get::<_, u64>(0),
        )
        .expect("count durable consensus receipts");
    let replication = connection
        .query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
            row.get::<_, u64>(0)
        })
        .expect("count durable replication effects");
    (receipts, replication)
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

/// Build a structurally valid synthetic AEAD envelope whose complete retained
/// ciphertext is exactly `payload_bytes`.  Calculating the per-record envelope
/// overhead first keeps the boundary test tied to the admitted capability,
/// rather than assuming that a one-mebibyte opaque plaintext has the same
/// stored width after key ID, nonce, AAD, and tag framing.
fn sealed_record_with_exact_payload_len(
    key: SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
    payload_bytes: usize,
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
    let encode = |ciphertext_and_tag| {
        CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
            aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
            ciphertext_and_tag,
        }
        .encode()
        .expect("test envelope")
    };
    let envelope_overhead = encode(vec![0xA5; AEAD_TAG_LEN]).len();
    let opaque_bytes = payload_bytes
        .checked_sub(envelope_overhead)
        .expect("admitted payload exceeds exact envelope framing");
    let mut ciphertext_and_tag = vec![0xA5; opaque_bytes];
    ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
    let envelope = encode(ciphertext_and_tag);
    assert_eq!(
        envelope.len(),
        payload_bytes,
        "synthetic ciphertext includes exactly the same envelope framing as a stored record"
    );
    record.payload = EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope");
    record
}

fn payload_sha256(record: &StoredSessionRecord) -> [u8; 32] {
    Sha256::digest(record.payload.as_bytes()).into()
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

fn fenced_v2_acquire_create_request(
    key: SessionKey,
    owner: OwnerId,
    expected_fence: FenceToken,
    nonce: [u8; 16],
    payload: &'static [u8],
) -> (FencedTransitionV2Request, StoredSessionRecord) {
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        expected_fence,
        Duration::from_secs(30),
    )
    .expect("build V2 acquire action");
    let record = sealed_transition_record(
        key,
        1,
        &owner,
        lease.committed_fence().expect("derive committed V2 fence"),
        payload,
    );
    let request = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 history epoch"),
        FencedTransitionV2CallerNonce::from_bytes(nonce),
        lease,
        FencedTransitionMutation::create(record.clone()),
    )
    .expect("build V2 create transition");
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
    // Exercise the actual leader so a cached ownership/read lease can never
    // masquerade as the fresh point-in-time quorum evidence required by
    // production readiness.
    let remote_probe_source = initial_leader;
    let initial_delayed_before = cluster.delayed_calls(remote_probe_source);
    // The injected peer delay is much longer than the attestation deadline.
    // This leaves a 1.75 s gap after the timer-dispatch tolerance, so a
    // completed peer call cannot be mistaken for deadline enforcement.
    cluster.delay_calls(remote_probe_source, Duration::from_secs(3));
    let initial_attestation_budget = Duration::from_secs(1);
    let initial_probe_started = Instant::now();
    let initial_crossed_expiry = cluster.stores[remote_probe_source]
        .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(1_009))
        .await;
    let initial_elapsed = initial_probe_started.elapsed();
    cluster.stop_delaying_calls(remote_probe_source);
    assert!(
        cluster.delayed_calls(remote_probe_source) > initial_delayed_before,
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

    let (leader_index, _, _) = cluster.observed_leader();
    let readiness_time = TopologyAttestationTime::from_unix_seconds(1_022);
    let primed = cluster.stores[leader_index]
        .probe_production_durable_readiness_with_attestation_at(&refreshed, readiness_time)
        .await;
    assert_eq!(
        primed.state(),
        DurableReadinessState::Ready,
        "the elected leader must first obtain fresh production quorum evidence"
    );

    // Disable the actual leader's inbound and outbound paths immediately
    // after its proof. The next production readiness probe must obtain a
    // point-in-time quorum proof; it must not reuse the raw-V2 admission
    // lease while the leader remains in the same term.
    cluster.isolate(leader_index);
    let isolated = tokio::time::timeout(
        DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT + RECOVERY_TIMEOUT,
        cluster.stores[leader_index]
            .probe_production_durable_readiness_with_attestation_at(&refreshed, readiness_time),
    )
    .await
    .expect(
        "post-isolation production readiness probe remains within its declared operation budget",
    );
    assert_eq!(
        isolated.state(),
        DurableReadinessState::NoQuorum,
        "a cached leader lease must not satisfy production readiness after immediate isolation"
    );
    cluster.heal(leader_index);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("cluster recovers after the production-readiness isolation proof");

    cluster.delay_calls(remote_probe_source, Duration::from_millis(750));
    let older_probe = cluster.stores[remote_probe_source]
        .probe_production_durable_readiness_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_022),
        );
    let newer_evaluation = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cluster.stores[remote_probe_source].production_platform_profile_with_attestation_at(
            &refreshed,
            TopologyAttestationTime::from_unix_seconds(1_023),
        )
    };
    let (older_report, newer_profile) = tokio::join!(older_probe, newer_evaluation);
    cluster.stop_delaying_calls(remote_probe_source);
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
    let short_lived_delayed_before = cluster.delayed_calls(remote_probe_source);
    // As above, leave a gap substantially larger than scheduler dispatch so
    // this verifies the attestation deadline rather than a peer response.
    cluster.delay_calls(remote_probe_source, Duration::from_secs(4));
    let probe_started = Instant::now();
    let crossed_expiry = cluster.stores[remote_probe_source]
        .probe_production_durable_readiness_with_attestation_at(&short_lived, wall_start)
        .await;
    let elapsed = probe_started.elapsed();
    cluster.stop_delaying_calls(remote_probe_source);
    assert!(
        cluster.delayed_calls(remote_probe_source) > short_lived_delayed_before,
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
        cluster.stores[remote_probe_source]
            .production_platform_profile_with_attestation_at(&short_lived, wall_start),
        SessionStorePlatformProfile::Unknown,
        "monotonic expiry must prevent a retry with the old pre-expiry wall time"
    );
    assert_eq!(
        cluster.stores[remote_probe_source]
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
    assert_file_tree_is_sealed(cluster._snapshot_directory.path());
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
async fn state_voter_activation_avoids_reprobe_on_rejecting_peer_path() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let source = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[source];
    let before = cluster.stores[leader]
        .status()
        .last_log_index
        .expect("formed cluster log head");
    store
        .activate_fenced_transition_capability()
        .await
        .expect("commit the state-voter V1 activation before consumer readiness");
    assert_eq!(
        store.status().applied_index,
        Some(before + 1),
        "a forwarding voter returns from activation only after its local state machine applies the certificate"
    );
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("all live voters apply durable activation");
    assert_eq!(
        cluster.stores[leader].status().last_log_index,
        Some(before + 1),
        "cold state-voter activation appends exactly one cluster-scope certificate"
    );
    store
        .activate_fenced_transition_capability()
        .await
        .expect("repeated startup activation is idempotent");
    assert_eq!(
        cluster.stores[leader].status().last_log_index,
        Some(before + 1),
        "a durable exact certificate avoids a second activation proposal"
    );

    // This precise shim is not an old binary: it rejects only a new V1 probe,
    // while ordinary barriers, forwarding, and Raft append traffic stay live.
    // A later operation must use the durable activation rather than probing it.
    cluster.reject_fenced_transition_capability_probe(source, leader);
    cluster.reject_fenced_transition_capability_probe(leader, source);
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
        "the activated path commits one fresh record without any capability-probe RPC"
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
    cluster.restore_current_rpc_handler(leader, source);
}

#[tokio::test]
async fn state_voter_activation_rejects_baseline_36720_peer_before_proposal() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let rejected_peer = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[leader];
    let before = store
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    // This preserves ordinary authenticated Raft and read-barrier traffic but
    // emulates a signed 36720e58 peer that can answer the old V1 probe yet
    // cannot decode the new activation-command probe or its log intent.
    cluster.emulate_baseline_36720_activation_probe_rejection(leader, rejected_peer);
    let result = store.activate_fenced_transition_capability().await;
    assert!(
        matches!(
            result,
            Err(StoreError::BackendUnavailable(_))
        ),
        "a baseline peer's activation-probe decode failure is transiently unavailable and fails closed"
    );
    assert_eq!(
        store.status().last_log_index,
        Some(before),
        "a failed unanimous V1 proof cannot append a certificate proposal"
    );
    cluster.restore_current_rpc_handler(leader, rejected_peer);
}

#[tokio::test]
async fn state_voter_activation_treats_an_unavailable_exact_probe_as_transient() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let unavailable_peer = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[leader];
    let before = store
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    // The leader still has the other voter for its typed B1, but activation
    // requires every exact voter to answer the new command probe. A missing
    // peer is a retryable inability to establish unanimity, not an explicit
    // capability declaration.
    cluster
        .paths
        .get(&(leader, unavailable_peer))
        .expect("leader outbound peer path")
        .set_enabled(false);
    let result = store.activate_fenced_transition_capability().await;
    assert!(matches!(result, Err(StoreError::BackendUnavailable(_))));
    assert_eq!(
        store.status().last_log_index,
        Some(before),
        "a transient probe failure cannot append an activation proposal"
    );
    cluster
        .paths
        .get(&(leader, unavailable_peer))
        .expect("leader outbound peer path")
        .set_enabled(true);
}

#[tokio::test]
async fn protected_roster_profile_activation_requires_three_exact_voters_and_reuses_certificate() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let before = cluster.stores[leader]
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    cluster.stores[leader]
        .activate_protected_roster_profile()
        .await
        .expect("all three exact current voters activate the immutable protected-roster profile");
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("all current voters apply the protected-roster profile certificate");
    for voter in &cluster.stores {
        assert_eq!(
            voter.status().last_log_index,
            Some(before + 1),
            "the unanimous exact profile appends one reusable cluster-scope certificate"
        );
        assert_eq!(
            voter.status().applied_index,
            Some(before + 1),
            "every current voter applies the exact protected-roster profile certificate"
        );
    }

    cluster.stores[leader]
        .activate_protected_roster_profile()
        .await
        .expect("the durable exact profile certificate is reusable");
    assert!(
        cluster
            .stores
            .iter()
            .all(|voter| voter.status().last_log_index == Some(before + 1)),
        "reusing the durable exact profile certificate does not append another activation"
    );
}

#[tokio::test]
async fn protected_roster_profile_activation_rejects_mismatched_current_voter_without_certificate()
{
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let mismatched_voter = (leader + 1) % MEMBER_COUNT;
    let before = cluster.stores[leader]
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    // This remains a live authenticated current voter and preserves ordinary
    // Raft traffic. It only advertises a different immutable roster profile,
    // which must not count toward the exact all-voter activation proof.
    cluster.mismatch_protected_roster_profile_capability_probe(leader, mismatched_voter);
    assert!(
        matches!(
            cluster.stores[leader]
                .activate_protected_roster_profile()
                .await,
            Err(StoreError::CapabilityNotSupported(capability))
                if capability == "atomic_fenced_transition_v1"
        ),
        "one mismatched current voter fails protected-roster profile activation closed"
    );
    assert!(
        cluster
            .stores
            .iter()
            .all(|voter| voter.status().last_log_index == Some(before)),
        "a failed exact profile proof creates no protected-roster profile certificate"
    );
    cluster.restore_current_rpc_handler(leader, mismatched_voter);
}

#[tokio::test]
async fn protected_roster_profile_activation_requires_every_voter_to_be_available() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let unavailable_voter = (leader + 1) % MEMBER_COUNT;
    let store = &cluster.stores[leader];
    let before = store
        .status()
        .last_log_index
        .expect("formed cluster has a durable log head");

    cluster
        .paths
        .get(&(leader, unavailable_voter))
        .expect("leader outbound peer path")
        .set_enabled(false);
    assert!(matches!(
        store.activate_protected_roster_profile().await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(
        store.status().last_log_index,
        Some(before),
        "an unavailable exact voter cannot be omitted from the immutable profile proof",
    );
    cluster
        .paths
        .get(&(leader, unavailable_voter))
        .expect("leader outbound peer path")
        .set_enabled(true);
}

#[tokio::test]
async fn fenced_transition_v2_current_voter_probe_fails_closed_then_activates_on_exact_replies() {
    let cluster = TestCluster::start().await;
    let (leader, _, _) = cluster.observed_leader();
    let rejecting_voter = (leader + 1) % MEMBER_COUNT;
    let rejected_key = session_key(b"fenced-transition-v2-current-voter-rejected");
    let rejected_observation = cluster.stores[leader]
        .observe_fenced_transition(&rejected_key)
        .await
        .expect("observe V2 key before unsupported current-voter probe");
    let (rejected_request, _) = fenced_v2_acquire_create_request(
        rejected_key.clone(),
        owner("fenced-transition-v2-current-voter-owner"),
        rejected_observation.current_fence(),
        [0x72; 16],
        b"sealed-fenced-transition-v2-current-voter-rejected",
    );
    let applications_before = replication_logs(&cluster).await;
    let probes_before = cluster.fenced_transition_v2_capability_probe_calls(leader);

    // This is a live current voter on the real leader's authenticated
    // loopback path. It rejects only the exact V2 probe, modeling an
    // unsupported/mismatched V2 profile while every ordinary Raft path stays
    // healthy. One non-exact voter must block the first V2 activation.
    cluster.reject_fenced_transition_v2_capability_probe(leader, rejecting_voter);
    assert!(
        matches!(
            cluster.stores[leader]
                .fenced_transition_v2(rejected_request.clone())
                .await,
            Err(StoreError::CapabilityNotSupported(capability))
                if capability == "atomic_fenced_transition_epoch_history_v2"
        ),
        "one unsupported current voter fails V2 admission before any proposal"
    );
    assert_eq!(
        cluster.fenced_transition_v2_capability_probe_calls(leader) - probes_before,
        MEMBER_COUNT - 1,
        "the leader requires a real exact-profile reply from every remote current voter"
    );
    assert_eq!(
        replication_logs(&cluster).await,
        applications_before,
        "the failed current-voter proof creates neither a V2 receipt nor an activation application"
    );

    cluster.restore_current_rpc_handler(leader, rejecting_voter);
    assert!(
        matches!(
            cluster.stores[leader]
                .fenced_transition_v2_status(&rejected_request)
                .await,
            Ok(FencedTransitionV2Status::NotFound)
        ),
        "a failed proof retains no V2 receipt history"
    );

    let accepted_key = session_key(b"fenced-transition-v2-current-voter-accepted");
    let accepted_observation = cluster.stores[leader]
        .observe_fenced_transition(&accepted_key)
        .await
        .expect("observe V2 key before exact current-voter proof");
    let (accepted_request, expected_record) = fenced_v2_acquire_create_request(
        accepted_key.clone(),
        owner("fenced-transition-v2-current-voter-owner"),
        accepted_observation.current_fence(),
        [0x73; 16],
        b"sealed-fenced-transition-v2-current-voter-accepted",
    );
    let probes_before = cluster.fenced_transition_v2_capability_probe_calls(leader);
    let outcome = cluster.stores[leader]
        .fenced_transition_v2(accepted_request.clone())
        .await
        .expect("all three exact V2 voters activate epoch one and apply one transition");
    assert!(
        matches!(outcome.mutation(), FencedTransitionMutationResult::Created),
        "the exact-profile activation applies the requested V2 mutation"
    );
    assert_eq!(
        cluster.fenced_transition_v2_capability_probe_calls(leader) - probes_before,
        2 * (MEMBER_COUNT - 1),
        "the first successful V2 activation rechecks both remote voters at each exact admission boundary"
    );

    for voter in &cluster.stores {
        assert!(
            matches!(
                voter
                    .fenced_transition_v2_capability()
                    .await
                    .expect("activated voter advertises exact V2 capability"),
                Some(FencedTransitionV2Capability::V2)
            ),
            "the activation is durable on every voter"
        );
        let history = voter
            .fenced_transition_v2_history_state()
            .await
            .expect("read V2 history from every voter");
        assert_eq!(
            history.active_epoch(),
            Some(FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch")),
            "each voter applies epoch-one activation"
        );
        assert_eq!(
            history.bound_entries(),
            1,
            "each voter retains one V2 receipt"
        );
        assert!(
            matches!(
                voter
                    .fenced_transition_v2_status(&accepted_request)
                    .await
                    .expect("read exact V2 receipt from every voter"),
                FencedTransitionV2Status::Recorded(result)
                    if result.as_ref() == &Ok(outcome.clone())
            ),
            "each voter retains the expected exact V2 receipt"
        );
        assert!(
            matches!(voter.get(&accepted_key).await, Ok(Some(record)) if record == expected_record),
            "each voter applies the V2 record mutation"
        );
    }
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
    let (isolated_index, _, _) = cluster.observed_leader();
    cluster.isolate(isolated_index);

    let probe_started = Instant::now();
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        cluster.stores[isolated_index].probe_durable_readiness(),
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
        cluster.stores[isolated_index].acquire(
            &key,
            owner("isolated-owner"),
            Duration::from_secs(30),
        ),
    )
    .await
    .expect("partitioned mutation is bounded");
    assert!(
        mutation.is_err(),
        "isolated node must not acknowledge a write"
    );
    assert!(mutation_started.elapsed() < Duration::from_secs(2));

    cluster.heal(isolated_index);
    cluster
        .wait_all_ready(RECOVERY_TIMEOUT)
        .await
        .expect("healed node rejoins fresh readiness");
    let healed_report = cluster.stores[isolated_index]
        .probe_durable_readiness()
        .await;
    assert_eq!(healed_report.state(), DurableReadinessState::Ready);
    assert_eq!(
        healed_report.recovery_progress().state(),
        DurableRecoveryState::Synchronized
    );
    assert!(
        healed_report.recovery_progress().local_applied_index()
            >= healed_report.committed_barrier_index()
    );
    cluster.stores[isolated_index]
        .acquire(&key, owner("healed-owner"), Duration::from_secs(30))
        .await
        .expect("mutation succeeds after healing");
}

#[tokio::test]
async fn isolated_leader_readiness_does_not_reuse_cached_quorum_proof() {
    let cluster = TestCluster::start().await;
    let (leader_index, _, _) = cluster.observed_leader();

    let primed = cluster.stores[leader_index].probe_durable_readiness().await;
    assert_eq!(
        primed.state(),
        DurableReadinessState::Ready,
        "the elected leader must first obtain a quorum proof"
    );

    // Isolate both inbound and outbound routes immediately after the proof.
    // The very next readiness probe must obtain fresh quorum evidence rather
    // than reuse the leader's still-valid raw-V2 admission lease.
    cluster.isolate(leader_index);
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        cluster.stores[leader_index].probe_durable_readiness(),
    )
    .await
    .expect("post-isolation leader readiness probe remains bounded");
    assert_eq!(
        report.state(),
        DurableReadinessState::NoQuorum,
        "a cached leader lease must not satisfy readiness after immediate isolation"
    );
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

    let snapshot_leader = [1, 2]
        .into_iter()
        .find(|index| {
            let status = cluster.stores[*index].status();
            status.leader_id == Some(status.node_id)
        })
        .expect("surviving majority has a snapshot leader");
    let lagging_snapshot_path = Arc::clone(
        cluster
            .paths
            .get(&(snapshot_leader, 0))
            .expect("leader-to-lagging snapshot path"),
    );
    lagging_snapshot_path.arm_one_install_snapshot_response_loss();
    let response_dropped = lagging_snapshot_path.install_snapshot_response_drop_notification();
    let observation_recorded = lagging_snapshot_path.install_snapshot_observation_notification();

    cluster.heal(0);
    tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, response_dropped.notified())
        .await
        .expect("lagging follower accepts one snapshot request before its response is lost");
    assert_eq!(
        1,
        lagging_snapshot_path.dropped_install_snapshot_responses(),
        "exactly one accepted snapshot response is lost"
    );
    let dropped_observation = lagging_snapshot_path
        .dropped_install_snapshot_observation()
        .expect("dropped snapshot response retains a bounded digest observation");
    assert!(
        !dropped_observation.done,
        "the deliberately lost response belongs to a non-final snapshot chunk"
    );
    tokio::time::timeout(SNAPSHOT_RECOVERY_TIMEOUT, async {
        loop {
            if lagging_snapshot_path.observed_install_snapshot_retry(&dropped_observation) {
                return;
            }
            observation_recorded.notified().await;
        }
    })
    .await
    .expect("leader retries the identical accepted snapshot request after response loss");
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
    let (recovered_leader, _, _) = cluster.observed_leader();
    let leader_progress = cluster.stores[recovered_leader]
        .probe_durable_readiness()
        .await
        .recovery_progress();
    assert_eq!(
        leader_progress.local_applied_index(),
        recovered_progress.local_applied_index(),
        "follower applied index converges after the lost snapshot response retry"
    );
    assert_eq!(
        leader_progress.snapshot_index(),
        recovered_progress.snapshot_index(),
        "follower snapshot index converges after the lost snapshot response retry"
    );
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
async fn maximum_admitted_cas_from_follower_forwards_applies_and_replicates_once() {
    // This boundary exercises the complete production 10-second operation
    // budget (forwarding, quorum commit, and every voter apply). The fixture's
    // 750ms default is intentional for ordinary negative tests, but is not an
    // additional compatibility limit on an admitted 1MiB consensus value.
    let cluster =
        TestCluster::start_with_operation_timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT)
            .await;
    // The fixture's ordinary captured-payload evidence clones its payloads for
    // later inspection. Disable only that optional test probe here so this
    // maximum-CAS qualification observes the production ownership path rather
    // than introducing a hidden full-ciphertext clone of its own.
    cluster.set_capture_payloads(false);

    let (leader, leader_id, _) = cluster.observed_leader();
    let source = (0..MEMBER_COUNT)
        .find(|index| *index != leader)
        .expect("three-voter fixture has a nonleader");
    assert_ne!(
        cluster.stores[source].status().node_id,
        leader_id,
        "the maximum CAS must enter through a current follower"
    );

    let max_payload_bytes = cluster.stores[source].capabilities().await.max_value_bytes;
    let key = session_key(b"maximum-follower-forwarded-cas");
    let lease = cluster.stores[leader]
        .acquire(
            &key,
            owner("maximum-follower-forwarded-owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("leader prepares lease for maximum follower CAS");
    let exact_record =
        sealed_record_with_exact_payload_len(key.clone(), 1, &lease, max_payload_bytes);
    assert_eq!(
        exact_record.payload.len(),
        max_payload_bytes,
        "the CAS carries the exact ciphertext capability after envelope framing"
    );
    let expected_payload_digest = payload_sha256(&exact_record);

    // Synchronize every durable voter before sampling its scalar receipt and
    // replication counts. `max_replication_sequence` owns the SDK's required
    // logical-time barrier, so its log position is the no-race baseline.
    let before_sequence = cluster.stores[leader]
        .max_replication_sequence()
        .await
        .expect("read pre-CAS replication sequence");
    let baseline_index = cluster.stores[leader]
        .status()
        .last_log_index
        .expect("logical-time baseline is committed");
    tokio::time::timeout(RECOVERY_TIMEOUT, async {
        loop {
            if cluster.stores.iter().all(|store| {
                store
                    .status()
                    .applied_index
                    .is_some_and(|index| index >= baseline_index)
            }) {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("all voters apply the pre-CAS baseline");
    let before_artifacts = (0..MEMBER_COUNT)
        .map(|index| {
            durable_cas_artifact_counts(
                &cluster
                    ._directory
                    .path()
                    .join(format!("node-{index}.sqlite")),
            )
        })
        .collect::<Vec<_>>();
    let forwards_before = cluster.forward_mutation_calls(source);
    let forwarded_bytes_before = cluster.forward_mutation_max_payload_bytes(source);
    let replicated_bytes_before = cluster.append_entries_max_payload_bytes(leader);

    assert_eq!(
        cluster.stores[source]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: exact_record,
            })
            .await
            .expect("maximum follower CAS returns the committed leader outcome"),
        CompareAndSetResult::Success,
    );
    let committed_index = cluster.stores[leader]
        .status()
        .last_log_index
        .expect("maximum CAS has a durable leader log index");
    assert!(
        committed_index > baseline_index,
        "the maximum CAS is a new committed application command"
    );
    tokio::time::timeout(RECOVERY_TIMEOUT, async {
        loop {
            if cluster.stores.iter().all(|store| {
                store
                    .status()
                    .applied_index
                    .is_some_and(|index| index >= committed_index)
            }) {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("all three voters apply the maximum follower CAS");

    assert_eq!(
        cluster.forward_mutation_calls(source),
        forwards_before + 1,
        "the selected nonleader sends the maximum CAS exactly once to the observed leader"
    );
    let forwarded_bytes = cluster.forward_mutation_max_payload_bytes(source);
    assert!(
        forwarded_bytes > max_payload_bytes
            && forwarded_bytes > forwarded_bytes_before
            && forwarded_bytes <= SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
        "the borrowed ForwardMutation envelope carried the complete maximum ciphertext over RPC"
    );
    let replicated_bytes = cluster.append_entries_max_payload_bytes(leader);
    assert!(
        replicated_bytes > max_payload_bytes
            && replicated_bytes > replicated_bytes_before
            && replicated_bytes <= SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
        "the leader replicated the complete maximum CAS through real AppendEntries RPCs"
    );

    let after_artifacts = (0..MEMBER_COUNT)
        .map(|index| {
            durable_cas_artifact_counts(
                &cluster
                    ._directory
                    .path()
                    .join(format!("node-{index}.sqlite")),
            )
        })
        .collect::<Vec<_>>();
    for (before, after) in before_artifacts.iter().zip(&after_artifacts) {
        assert_eq!(
            after.0,
            before.0 + 1,
            "each applied voter durably retains exactly one CAS outcome receipt"
        );
        assert_eq!(
            after.1,
            before.1 + 1,
            "each applied voter durably retains exactly one CAS replication effect"
        );
    }
    assert_eq!(
        cluster.stores[leader]
            .max_replication_sequence()
            .await
            .expect("read post-CAS replication sequence"),
        before_sequence + 1,
        "the maximum CAS has exactly one visible mutation effect"
    );

    // The one-byte-over case is rejected by follower-side admission before a
    // ForwardMutation can be transmitted or a durable receipt/effect can be
    // created.  Build a complete valid envelope first so this tests the actual
    // capability boundary rather than malformed-ciphertext rejection.
    let oversized_record =
        sealed_record_with_exact_payload_len(key.clone(), 2, &lease, max_payload_bytes + 1);
    let forwards_before_rejection = cluster.forward_mutation_calls(source);
    let artifacts_before_rejection = (0..MEMBER_COUNT)
        .map(|index| {
            durable_cas_artifact_counts(
                &cluster
                    ._directory
                    .path()
                    .join(format!("node-{index}.sqlite")),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        cluster.stores[source]
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: Some(Generation::new(1)),
                new_record: oversized_record,
            })
            .await
            .expect_err("one byte beyond the ciphertext capability must fail closed"),
        StoreError::PayloadTooLarge {
            actual: max_payload_bytes + 1,
            max: max_payload_bytes,
        }
    );
    assert_eq!(
        cluster.forward_mutation_calls(source),
        forwards_before_rejection,
        "the oversized CAS cannot cross follower-to-leader forwarding"
    );
    assert_eq!(
        (0..MEMBER_COUNT)
            .map(|index| {
                durable_cas_artifact_counts(
                    &cluster
                        ._directory
                        .path()
                        .join(format!("node-{index}.sqlite")),
                )
            })
            .collect::<Vec<_>>(),
        artifacts_before_rejection,
        "the oversized CAS creates neither a receipt nor a replication effect"
    );

    for store in &cluster.stores {
        let stored = store
            .get(&key)
            .await
            .expect("linearizable read of maximum replicated record")
            .expect("maximum CAS record is present on every voter");
        assert_eq!(stored.payload.len(), max_payload_bytes);
        assert_eq!(payload_sha256(&stored), expected_payload_digest);
    }
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
