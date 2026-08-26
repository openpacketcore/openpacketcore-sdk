//! Contract tests for the production stateless quorum-consumer boundary.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
#[cfg(feature = "test-control")]
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
#[cfg(feature = "test-control")]
use std::sync::{Condvar, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use opc_consensus::engine::raft::AppendEntriesRequest;
#[cfg(feature = "test-control")]
use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{
    KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
#[cfg(feature = "test-control")]
use opc_session_net::DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT;
use opc_session_net::{
    session_consumer_payload_budget, PersistentSessionConsumerClient,
    PersistentSessionConsumerConfig, PersistentSessionConsumerV2ExecuteError, RemoteAddrResolver,
    RemoteSessionConsensusPeer, RosterIngressSigner, RosterIngressSignerError, SessionClusterId,
    SessionConfigurationGeneration, SessionConsensusServer, SessionConsensusServerHandle,
    SessionConsumerAuthorizer, SessionConsumerClientError, SessionConsumerFencedTransitionBackend,
    SessionConsumerLeaseMutationError, SessionConsumerMutationError,
    SessionConsumerPreparedCheckpointBackend, SessionQuorumConsumerServer,
    SessionQuorumConsumerServerHandle, SessionReauthenticationControl, SessionReplicationManifest,
    StatelessSessionConsumerClient, MAX_NEGOTIATED_FRAME_SIZE, SESSION_QUORUM_CONSUMER_ALPN,
    SESSION_QUORUM_CONSUMER_ROSTER_ALPN, SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION,
    SESSION_QUORUM_CONSUMER_V2_ALPN,
};
use opc_session_net::{
    FencedMutationRosterActive as ActiveRoster,
    FencedMutationRosterAdmissionOutcome as AdmissionOutcome,
    FencedMutationRosterAdmissionProposal as AdmissionProposal,
    FencedMutationRosterAttestationTrustRootV1,
    FencedMutationRosterClientError as RosterClientError,
    FencedMutationRosterCompactTerminalMemberSigningInputV2,
    FencedMutationRosterCompleteProofSet as CompleteProofSet,
    FencedMutationRosterEstablishedMutation as EstablishedMutation,
    FencedMutationRosterEstablishedPublicationCall as EstablishedPublicationCall,
    FencedMutationRosterEstablishedPublicationProvider as EstablishedPublicationProvider,
    FencedMutationRosterExecuteOutcome as ExecuteOutcome, FencedMutationRosterExecutorAttestor,
    FencedMutationRosterExecutorCertificatePartsV1, FencedMutationRosterExecutorError,
    FencedMutationRosterId as RosterId, FencedMutationRosterMember as Member,
    FencedMutationRosterMemberAdoption as MemberAdoption,
    FencedMutationRosterMemberCall as MemberCall,
    FencedMutationRosterMemberOperationId as MemberOperationId,
    FencedMutationRosterMemberOrdinal as MemberOrdinal,
    FencedMutationRosterMemberPrepareOutcome as MemberPrepareOutcome,
    FencedMutationRosterMemberProvider as MemberProvider,
    FencedMutationRosterMemberRecoveryOutcome as MemberRecoveryOutcome,
    FencedMutationRosterMemberRecoveryStatus as MemberRecoveryStatus, FencedMutationRosterProfile,
    FencedMutationRosterProviderCallOutcome as ProviderCallOutcome,
    FencedMutationRosterProviderReceiptCapsule as ProviderReceiptCapsule,
    FencedMutationRosterPublicationEvidence as PublicationEvidence,
    FencedMutationRosterPublicationProviderOutcome as PublicationProviderOutcome,
    FencedMutationRosterRecovered as RecoveredRoster,
    FencedMutationRosterRecoveryInput as RecoveryInput,
    FencedMutationRosterRecoveryOutcome as RecoveryOutcome,
    FencedMutationRosterTerminal as TerminalRoster,
    FencedMutationRosterTerminalAttestationSigningInputV1,
    FencedMutationRosterTerminalReceipt as TerminalReceipt,
    FencedMutationRosterTerminalStatus as TerminalStatus,
    FencedMutationRosterTerminalizationOutcome as TerminalizationOutcome,
};
use opc_session_store::fenced_mutation_roster::{
    RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
    RosterAttestationLeafCertificateV1, RosterCompactAdmissionProvenanceSigningInputV2,
    RosterIngressAttestationSigningInputV1,
};
#[cfg(feature = "test-control")]
use opc_session_store::sqlite::test_support::{
    protected_roster_terminal_apply_timings_for_test,
    reset_protected_roster_terminal_apply_timings_for_test,
};
use opc_session_store::{
    AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet, ConsensusSessionStore,
    EncryptedSessionPayload, EncryptingSessionBackend, FenceToken, FencedTransitionExecuteError,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, FencedTransitionV2CallerNonce,
    FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch, FencedTransitionV2Request,
    Generation, LeaseGuard, OwnerId, PreparedCheckpointBudget, PreparedCompareAndSetExecuteError,
    PreparedCompareAndSetOutcome, PreparedCompareAndSetPrepareError, PreparedCompareAndSetStatus,
    PreparedFencedTransitionJournal, PreparedFencedTransitionJournalKey,
    PreparedFencedTransitionLookup, ProtectedRosterConsensusDiagnosticSnapshot,
    QuorumReplicaDescriptor, QuorumTopologyConfig, QuorumTopologyMode, RecordExpiryPreflight,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    RestoreScanRequest, RosterAttestationTrustRootIdentityV1, RosterAttestationTrustRootV1,
    RosterIngressAttestationV1, SessionBackend, SessionConsensusCommand, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusResponse, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionConsumerAuthorization, SessionConsumerAuthorizationGrant, SessionConsumerChange,
    SessionConsumerLeaseError, SessionConsumerOperation, SessionConsumerOutcomeUnknown,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerRosterAuthorization, SessionConsumerRosterRejection,
    SessionConsumerScope, SessionConsumerStoreError, SessionConsumerTenantNfScope,
    SessionConsumerV2FencedTransitionError, SessionConsumerV2FencedTransitionStatus,
    SessionConsumerV2Operation, SessionConsumerV2Request, SessionConsumerV2Response,
    SessionConsumerVoterAuthority, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp,
    SessionPayloadEncoding, SessionQuorumConsumer, SessionQuorumRosterIngress,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
    ValidatedQuorumTopology, FENCED_MUTATION_ROSTER_MAX_CHECKPOINT_BYTES,
    FENCED_MUTATION_ROSTER_MAX_PLAN_BYTES, FENCED_MUTATION_ROSTER_MAX_RESULT_BYTES,
};

use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId, Timestamp};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[cfg(feature = "test-control")]
static PROTECTED_ROSTER_TERMINAL_APPLY_TIMING_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

opc_consensus::engine::declare_raft_types!(
    TestSessionRaftTypeConfig:
        D = SessionConsensusCommand,
        R = SessionConsensusResponse,
        NodeId = SessionConsensusNodeId,
        Node = opc_consensus::engine::EmptyNode,
        SnapshotData = io::Cursor<Vec<u8>>,
        AsyncRuntime = opc_consensus::DurableOpenraftRuntime,
);

fn transported_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        max_value_bytes: session_consumer_payload_budget(
            MAX_NEGOTIATED_FRAME_SIZE,
            MAX_NEGOTIATED_FRAME_SIZE,
        ),
        ..BackendCapabilities::all_enabled()
    }
}

#[cfg(feature = "test-control")]
fn protected_roster_terminal_apply_timing_diagnostic() -> String {
    let timings = protected_roster_terminal_apply_timings_for_test();
    format!(
        "decode_and_proof_count={}; decode_and_proof_nanos={}; terminalization_preparation_count={}; terminalization_preparation_nanos={}; production_apply_count={}; production_apply_nanos={}; committed_outcome_count={}; committed_outcome_nanos={}; replication_notification_count={}; replication_notification_nanos={}; transaction_remainder_commit_count={}; transaction_remainder_commit_nanos={}",
        timings.decode_and_proof_count,
        timings.decode_and_proof_nanos,
        timings.terminalization_preparation_count,
        timings.terminalization_preparation_nanos,
        timings.production_apply_count,
        timings.production_apply_nanos,
        timings.committed_outcome_count,
        timings.committed_outcome_nanos,
        timings.replication_notification_count,
        timings.replication_notification_nanos,
        timings.transaction_remainder_commit_count,
        timings.transaction_remainder_commit_nanos,
    )
}

#[cfg(not(feature = "test-control"))]
fn protected_roster_terminal_apply_timing_diagnostic() -> &'static str {
    "test-control-disabled"
}

/// Fixed-cardinality, redaction-safe evidence of the server response produced
/// by an exact terminal-status read. This records response classes only; it
/// never records terminal body bytes or underlying error values.
#[cfg(feature = "test-control")]
fn protected_roster_terminal_status_response_diagnostic(
    transport: &CommitThenLoseConsumerResponse,
) -> String {
    format!(
        "calls={}; recorded_responses={}; recovery_required_responses={}; unavailable_responses={}; authority_responses={}; other_rejected_responses={}; response_elapsed_millis={}",
        transport
            .roster_terminal_status_calls
            .load(Ordering::SeqCst),
        transport
            .roster_terminal_status_recorded_responses
            .load(Ordering::SeqCst),
        transport
            .roster_terminal_status_recovery_required_responses
            .load(Ordering::SeqCst),
        transport
            .roster_terminal_status_unavailable_responses
            .load(Ordering::SeqCst),
        transport
            .roster_terminal_status_authority_responses
            .load(Ordering::SeqCst),
        transport
            .roster_terminal_status_other_rejected_responses
            .load(Ordering::SeqCst),
        transport
            .roster_terminal_status_response_elapsed_millis
            .load(Ordering::SeqCst),
    )
}

#[cfg(not(feature = "test-control"))]
fn protected_roster_terminal_status_response_diagnostic(
    _transport: &CommitThenLoseConsumerResponse,
) -> &'static str {
    "test-control-disabled"
}

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "stateless consumer test CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, ca_key)
                .expect("test CA certificate"),
        }
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client mTLS config")
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server mTLS config")
    }

    fn identity_state(&self, spiffe_id: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "stateless consumer test leaf");
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("test leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("test leaf certificate");
        let certificates =
            parse_certs_pem(&(certificate.pem() + &self.ca.pem())).expect("test certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("test private key");
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test.example")
                .expect("test trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles).expect("test identity state")
    }
}

const THREE_VOTER_COUNT: usize = 3;
const THREE_VOTER_READY_TIMEOUT: Duration = Duration::from_secs(20);
const PROTECTED_ROSTER_STATUS_READBACK_ATTEMPTS: usize = 8;
// Retain the durable recovery qualification bound for the one explicitly
// triggered OpenRaft campaign and its bounded authenticated peer calls without
// changing any production deadline.
#[cfg(feature = "test-control")]
const THREE_VOTER_ELECTION_RECOVERY_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);
// After the survivor listeners prove every admitted handler has terminated,
// the selected successor campaigns only after every possible old-leader lease
// has expired. Automatic campaigns are disabled during this interval, so the
// two survivors cannot drift into a scheduler-dependent split vote.
#[cfg(feature = "test-control")]
const THREE_VOTER_LEASE_DRAIN: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_add(100),
);

// A request that passed the path gate immediately before isolation may still
// be inside the persistent transport's bounded AppendEntries attempt. Let that
// client-side attempt become terminal before restarting the survivor listeners;
// the subsequent handler barrier then supplies the last possible old-vote
// touch from which the complete leader-lease interval is measured.
#[cfg(feature = "test-control")]
const THREE_VOTER_APPEND_ATTEMPT_DRAIN: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .append_entries_timeout_millis
        .saturating_add(100),
);

/// Keep the consensus transport real while making each authenticated
/// read-barrier RPC consume a deterministic bounded interval.  A fresh V1
/// capability proof sends two such probes from the leader.  The test below
/// therefore distinguishes the one leader-side proof from the former
/// follower-plus-leader duplicate under the normal operation deadline.
#[derive(Debug)]
struct GatedReadBarrierPeer {
    inner: RemoteSessionConsensusPeer,
    enabled: Arc<AtomicBool>,
    delay: Duration,
    calls: Arc<AtomicUsize>,
    delay_prewrite_empty_append_entries: Arc<AtomicBool>,
    nonempty_append_entries_seen: Arc<AtomicBool>,
    prewrite_empty_append_entries_calls: Arc<AtomicUsize>,
    append_entries_decoded: Arc<AtomicUsize>,
    append_entries_decode_failures: Arc<AtomicUsize>,
}

#[async_trait]
impl SessionConsensusPeer for GatedReadBarrierPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.inner.node_id()
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        self.inner.scope_identity()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        self.record_request(&request).await;
        self.inner.call(request).await
    }

    async fn call_with_timeout(
        &self,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        self.record_request(&request).await;
        self.inner.call_with_timeout(request, timeout).await
    }
}

impl GatedReadBarrierPeer {
    async fn record_request(&self, request: &SessionConsensusWireRequest) {
        if matches!(
            request.family,
            opc_session_store::SessionConsensusRpcFamily::ReadBarrier
        ) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
        }
        if matches!(
            request.family,
            opc_session_store::SessionConsensusRpcFamily::AppendEntries
        ) {
            match opc_consensus::decode_bounded::<AppendEntriesRequest<TestSessionRaftTypeConfig>>(
                &request.payload,
            ) {
                Ok(append) => {
                    self.append_entries_decoded.fetch_add(1, Ordering::SeqCst);
                    if self
                        .delay_prewrite_empty_append_entries
                        .load(Ordering::Acquire)
                        && append.entries.is_empty()
                        && !self.nonempty_append_entries_seen.load(Ordering::Acquire)
                    {
                        self.prewrite_empty_append_entries_calls
                            .fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(self.delay).await;
                    } else if !append.entries.is_empty() {
                        self.nonempty_append_entries_seen
                            .store(true, Ordering::Release);
                    }
                }
                Err(_) => {
                    self.append_entries_decode_failures
                        .fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }
}

#[allow(dead_code)]
static THREE_VOTER_FLEET_TEST_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Test-only listener ownership that aborts a live consumer server if an
/// assertion unwinds before the test can await its normal shutdown.
struct AbortConsumerServerOnDrop(Option<SessionQuorumConsumerServerHandle>);

impl AbortConsumerServerOnDrop {
    fn new(server: SessionQuorumConsumerServerHandle) -> Self {
        Self(Some(server))
    }

    /// Consume the live handle and await all listener and connection tasks.
    async fn abort_and_wait(mut self) {
        if let Some(server) = self.0.take() {
            server.abort_and_wait().await;
        }
    }
}

impl Drop for AbortConsumerServerOnDrop {
    fn drop(&mut self) {
        if let Some(server) = self.0.take() {
            // Drop must never start or block on a runtime. The server's
            // cancellation and accept-task abort are synchronous.
            server.abort();
        }
    }
}

/// The normal integration fixture owns its temporary directory. The
/// process-loss qualification retains that exact directory under a parent-owned
/// temporary root after phase one, then gives later child phases a non-owning reopen
/// handle. This is deliberately a fixture-lifetime distinction only: both
/// forms use the same SQLite files and OpenRaft snapshot directories.
enum ThreeVoterFleetDirectory {
    Owned(tempfile::TempDir),
    Reopened(PathBuf),
}

impl ThreeVoterFleetDirectory {
    fn path(&self) -> &Path {
        match self {
            Self::Owned(directory) => directory.path(),
            Self::Reopened(path) => path,
        }
    }

    fn retain_after_process_loss(self) -> PathBuf {
        match self {
            Self::Owned(directory) => directory.keep(),
            Self::Reopened(path) => path,
        }
    }
}

#[allow(dead_code)]
struct ThreeVoterConsumerFleet {
    manifest: Arc<SessionReplicationManifest>,
    fixed_durable: bool,
    topologies: Vec<ValidatedQuorumTopology>,
    pki: Arc<TestPki>,
    path_enabled: BTreeMap<(usize, usize), Arc<AtomicBool>>,
    read_barrier_calls: Arc<AtomicUsize>,
    delay_prewrite_empty_append_entries: Arc<AtomicBool>,
    nonempty_append_entries_seen: Arc<AtomicBool>,
    prewrite_empty_append_entries_calls: Arc<AtomicUsize>,
    append_entries_decoded: Arc<AtomicUsize>,
    append_entries_decode_failures: Arc<AtomicUsize>,
    reauthentication: Vec<SessionReauthenticationControl>,
    address_slots: Vec<Arc<RwLock<Option<SocketAddr>>>>,
    servers: Vec<Option<SessionConsensusServerHandle>>,
    stores: Vec<ConsensusSessionStore>,
    backends: Vec<SqliteSessionBackend>,
    directory: Option<ThreeVoterFleetDirectory>,
    read_barrier_delay: Option<Duration>,
    roster_attestation_root: Option<RosterAttestationTrustRootV1>,
    test_gate: Option<tokio::sync::SemaphorePermit<'static>>,
}

impl Drop for ThreeVoterConsumerFleet {
    fn drop(&mut self) {
        for server in &mut self.servers {
            if let Some(server) = server.take() {
                server.abort();
            }
        }
    }
}

#[allow(dead_code)]
impl ThreeVoterConsumerFleet {
    async fn start(pki: Arc<TestPki>, read_barrier_delay: Option<Duration>) -> Self {
        Self::start_with_topology(pki, read_barrier_delay, false, None).await
    }

    async fn start_fixed_durable(pki: Arc<TestPki>) -> Self {
        Self::start_with_topology(pki, None, true, None).await
    }

    async fn start_fixed_durable_with_roster_attestation(
        pki: Arc<TestPki>,
        root: RosterAttestationTrustRootV1,
    ) -> Self {
        let fleet = Self::start_with_topology(pki, None, true, Some(root)).await;
        let (leader, _, _) = fleet.wait_for_observed_leader().await;
        fleet.stores[leader]
            .activate_protected_roster_profile()
            .await
            .expect("activate protected-roster profile before advertising deployment readiness");
        fleet.wait_all_ready().await;
        fleet
    }

    async fn start_with_topology(
        pki: Arc<TestPki>,
        read_barrier_delay: Option<Duration>,
        fixed_durable: bool,
        roster_attestation_root: Option<RosterAttestationTrustRootV1>,
    ) -> Self {
        Self::start_with_topology_in_directory(
            pki,
            read_barrier_delay,
            fixed_durable,
            roster_attestation_root,
            ThreeVoterFleetDirectory::Owned(
                tempfile::tempdir().expect("three-voter fleet directory"),
            ),
            None,
        )
        .await
    }

    async fn start_with_topology_in_directory(
        pki: Arc<TestPki>,
        read_barrier_delay: Option<Duration>,
        fixed_durable: bool,
        roster_attestation_root: Option<RosterAttestationTrustRootV1>,
        directory: ThreeVoterFleetDirectory,
        inherited_test_gate: Option<tokio::sync::SemaphorePermit<'static>>,
    ) -> Self {
        let test_gate = match inherited_test_gate {
            Some(test_gate) => test_gate,
            None => THREE_VOTER_FLEET_TEST_GATE
                .acquire()
                .await
                .expect("three-voter test gate remains open"),
        };
        let members = (0..THREE_VOTER_COUNT)
            .map(three_voter_member)
            .collect::<Vec<_>>();
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch_and_roster_attestation_root(
                SessionClusterId::new("consumer-three-voter-transition")
                    .expect("three-voter cluster ID"),
                SessionConfigurationGeneration::new("consumer-three-voter-v1")
                    .expect("three-voter configuration generation"),
                ConsensusConfigurationEpoch::new(1).expect("three-voter epoch"),
                members.clone(),
                roster_attestation_root.clone(),
            )
            .expect("three-voter replication manifest"),
        );
        let topologies = (0..THREE_VOTER_COUNT)
            .map(|index| {
                let consensus_identity = if fixed_durable {
                    manifest.fixed_durable_quorum_consensus_identity()
                } else {
                    manifest.consensus_identity()
                };
                let config = QuorumTopologyConfig::new_consensus(
                    three_voter_replica_id(index),
                    members.clone(),
                    consensus_identity,
                );
                let config = match &roster_attestation_root {
                    Some(root) => config.with_roster_attestation_trust_root(root.clone()),
                    None => config,
                };
                if fixed_durable {
                    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
                        config,
                        manifest.placement_policy(),
                    )
                    .expect("validate fixed-durable three-voter topology")
                } else {
                    ValidatedQuorumTopology::try_from(config)
                        .expect("validate three-voter topology")
                }
            })
            .collect::<Vec<_>>();
        assert!(topologies.iter().all(|topology| {
            (topology.summary().mode() == QuorumTopologyMode::FixedDurableQuorum) == fixed_durable
        }));
        let backends = (0..THREE_VOTER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open three-voter SQLite backend")
            })
            .collect::<Vec<_>>();
        let address_slots = (0..THREE_VOTER_COUNT)
            .map(|_| Arc::new(RwLock::new(None)))
            .collect::<Vec<_>>();
        let mut path_enabled = BTreeMap::new();
        let read_barrier_calls = Arc::new(AtomicUsize::new(0));
        let delay_prewrite_empty_append_entries = Arc::new(AtomicBool::new(false));
        let nonempty_append_entries_seen = Arc::new(AtomicBool::new(false));
        let prewrite_empty_append_entries_calls = Arc::new(AtomicUsize::new(0));
        let append_entries_decoded = Arc::new(AtomicUsize::new(0));
        let append_entries_decode_failures = Arc::new(AtomicUsize::new(0));
        let reauthentication = (0..THREE_VOTER_COUNT)
            .map(|_| SessionReauthenticationControl::new())
            .collect::<Vec<_>>();
        let mut stores = Vec::with_capacity(THREE_VOTER_COUNT);
        for index in 0..THREE_VOTER_COUNT {
            let local = if fixed_durable {
                manifest.bind_fixed_durable_quorum_local(three_voter_replica_id(index))
            } else {
                manifest.bind_local(three_voter_replica_id(index))
            }
            .expect("three-voter local consensus binding");
            let peers = (0..THREE_VOTER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let binding = local
                        .bind_remote(three_voter_replica_id(target))
                        .expect("three-voter remote consensus binding");
                    let enabled = Arc::new(AtomicBool::new(true));
                    let resolver_slot = Arc::clone(&address_slots[target]);
                    let resolver_enabled = Arc::clone(&enabled);
                    let resolver: RemoteAddrResolver = Arc::new(move || {
                        let resolver_slot = Arc::clone(&resolver_slot);
                        let resolver_enabled = Arc::clone(&resolver_enabled);
                        Box::pin(async move {
                            if !resolver_enabled.load(Ordering::Acquire) {
                                return Err(io::Error::new(
                                    io::ErrorKind::ConnectionRefused,
                                    "three-voter consensus path is isolated",
                                ));
                            }
                            resolver_slot
                                .read()
                                .map_err(|_| io::Error::other("three-voter address lock poisoned"))?
                                .as_ref()
                                .copied()
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::ConnectionRefused,
                                        "three-voter consensus listener is unavailable",
                                    )
                                })
                        })
                    });
                    let node_id = binding.remote_consensus_node_id();
                    let remote = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                        binding,
                        resolver,
                        pki.client_config(&three_voter_spiffe(index)),
                    )
                    .with_reauthentication_control(reauthentication[index].clone());
                    let peer = Arc::new(GatedReadBarrierPeer {
                        inner: remote,
                        enabled: Arc::clone(&enabled),
                        delay: read_barrier_delay.unwrap_or(Duration::ZERO),
                        calls: Arc::clone(&read_barrier_calls),
                        delay_prewrite_empty_append_entries: Arc::clone(
                            &delay_prewrite_empty_append_entries,
                        ),
                        nonempty_append_entries_seen: Arc::clone(&nonempty_append_entries_seen),
                        prewrite_empty_append_entries_calls: Arc::clone(
                            &prewrite_empty_append_entries_calls,
                        ),
                        append_entries_decoded: Arc::clone(&append_entries_decoded),
                        append_entries_decode_failures: Arc::clone(&append_entries_decode_failures),
                    });
                    path_enabled.insert((index, target), enabled);
                    let peer: Arc<dyn SessionConsensusPeer> = peer;
                    (node_id, peer)
                })
                .collect::<BTreeMap<_, _>>();
            let store = if fixed_durable {
                ConsensusSessionStore::open_fixed_durable_quorum(
                    topologies[index].clone(),
                    backends[index].clone(),
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                )
                .await
            } else {
                ConsensusSessionStore::open_with_operation_timeout(
                    topologies[index].clone(),
                    backends[index].clone(),
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                    opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
            };
            stores.push(store.expect("open three-voter consensus store"));
        }
        let mut servers = Vec::with_capacity(THREE_VOTER_COUNT);
        for index in 0..THREE_VOTER_COUNT {
            let binding = if fixed_durable {
                manifest.bind_fixed_durable_quorum_local(three_voter_replica_id(index))
            } else {
                manifest.bind_local(three_voter_replica_id(index))
            }
            .expect("three-voter consensus server binding");
            let (server, address) = SessionConsensusServer::new(
                stores[index].rpc_handler(),
                pki.server_config(&three_voter_spiffe(index)),
                binding,
            )
            .with_reauthentication_control(reauthentication[index].clone())
            .listen(
                "127.0.0.1:0"
                    .parse()
                    .expect("three-voter consensus listener"),
            )
            .await
            .expect("start three-voter consensus listener");
            *address_slots[index]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(address);
            servers.push(Some(server));
        }
        let fleet = Self {
            manifest,
            fixed_durable,
            topologies,
            pki,
            path_enabled,
            read_barrier_calls,
            delay_prewrite_empty_append_entries,
            nonempty_append_entries_seen,
            prewrite_empty_append_entries_calls,
            append_entries_decoded,
            append_entries_decode_failures,
            reauthentication,
            address_slots,
            servers,
            stores,
            backends,
            directory: Some(directory),
            read_barrier_delay,
            roster_attestation_root,
            test_gate: Some(test_gate),
        };
        for result in futures_util::future::join_all(
            fleet
                .stores
                .iter()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await
        {
            result.expect("initialize three-voter cluster");
        }
        fleet.wait_all_ready().await;
        fleet
    }

    async fn wait_all_ready(&self) {
        tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
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
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("three-voter cluster reaches durable readiness");
    }

    fn voter_authority(&self, index: usize) -> SessionConsumerVoterAuthority {
        let topology = &self.topologies[index];
        topology
            .session_consumer_roster()
            .expect("three-voter consumer roster")
            .voter(topology.local_consensus_node_id().expect("local node ID"))
            .expect("local three-voter authority")
    }

    fn consensus_identity(&self, index: usize) -> SessionConsensusIdentity {
        self.topologies[index]
            .consensus_identity()
            .expect("three-voter consensus identity")
    }

    fn reset_read_barrier_calls(&self) {
        self.read_barrier_calls.store(0, Ordering::SeqCst);
    }

    fn read_barrier_calls(&self) -> usize {
        self.read_barrier_calls.load(Ordering::SeqCst)
    }

    fn set_prewrite_empty_append_entries_delay(&self, enabled: bool) {
        if enabled {
            self.prewrite_empty_append_entries_calls
                .store(0, Ordering::SeqCst);
            self.nonempty_append_entries_seen
                .store(false, Ordering::Release);
            self.append_entries_decoded.store(0, Ordering::SeqCst);
            self.append_entries_decode_failures
                .store(0, Ordering::SeqCst);
        }
        self.delay_prewrite_empty_append_entries
            .store(enabled, Ordering::Release);
    }

    fn prewrite_empty_append_entries_calls(&self) -> usize {
        self.prewrite_empty_append_entries_calls
            .load(Ordering::SeqCst)
    }

    fn append_entries_observation(&self) -> (usize, usize, bool) {
        (
            self.append_entries_decoded.load(Ordering::SeqCst),
            self.append_entries_decode_failures.load(Ordering::SeqCst),
            self.nonempty_append_entries_seen.load(Ordering::Acquire),
        )
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
            .expect("three-voter leader");
        let term = statuses.first().expect("three-voter status").term;
        assert!(statuses.iter().all(|status| {
            status.leader_id == Some(leader_id) && status.term == term && status.admitted
        }));
        let leader = statuses
            .iter()
            .position(|status| status.node_id == leader_id)
            .expect("leader belongs to fleet");
        (leader, leader_id, term)
    }

    async fn wait_for_observed_leader(&self) -> (usize, SessionConsensusNodeId, u64) {
        let observed = tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
            loop {
                let statuses = self
                    .stores
                    .iter()
                    .map(ConsensusSessionStore::status)
                    .collect::<Vec<_>>();
                if let (Some(leader_id), Some(term)) = (
                    statuses.first().and_then(|status| status.leader_id),
                    statuses.first().map(|status| status.term),
                ) {
                    if statuses.iter().all(|status| {
                        status.leader_id == Some(leader_id)
                            && status.term == term
                            && status.admitted
                    }) {
                        let leader = statuses
                            .iter()
                            .position(|status| status.node_id == leader_id)
                            .expect("elected leader belongs to fleet");
                        return (leader, leader_id, term);
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if let Ok(observed) = observed {
            return observed;
        }
        let statuses = self
            .stores
            .iter()
            .map(ConsensusSessionStore::status)
            .collect::<Vec<_>>();
        let leaders_agree = statuses
            .first()
            .and_then(|status| status.leader_id)
            .is_some_and(|leader| {
                statuses
                    .iter()
                    .all(|status| status.leader_id == Some(leader))
            });
        let redacted = std::array::from_fn::<_, THREE_VOTER_COUNT, _>(|index| {
            let status = &statuses[index];
            (
                status.term,
                status.leader_id.is_some(),
                status.admitted,
                status.applied_index,
                status.last_log_index,
            )
        });
        panic!(
            "three-voter leader converges; leaders_agree={leaders_agree}; redacted_status={redacted:?}"
        )
    }

    /// Wait only for the admitted quorum needed to make snapshot-maintenance
    /// progress. A recovering third voter may legitimately lag the leader
    /// election across compaction, so this intentionally does not require
    /// all three status observations to converge.
    async fn wait_for_admitted_quorum_leader(
        &self,
        eligible_voters: &[usize],
        minimum_term: u64,
    ) -> (usize, SessionConsensusNodeId, u64) {
        assert!(
            eligible_voters.len() >= 2,
            "an admitted three-voter quorum needs at least two eligible voters"
        );
        assert!(
            eligible_voters
                .iter()
                .all(|index| *index < THREE_VOTER_COUNT),
            "eligible voters belong to the three-voter fleet"
        );
        assert!(
            eligible_voters
                .iter()
                .enumerate()
                .all(|(position, index)| !eligible_voters[..position].contains(index)),
            "eligible voters are unique"
        );

        let observed = tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
            loop {
                let statuses = eligible_voters
                    .iter()
                    .map(|index| (*index, self.stores[*index].status()))
                    .collect::<Vec<_>>();
                for (candidate, status) in &statuses {
                    let Some(leader_id) = status.leader_id else {
                        continue;
                    };
                    if !status.admitted || status.node_id != leader_id || status.term < minimum_term
                    {
                        continue;
                    }
                    let admitted_reports = statuses
                        .iter()
                        .filter(|(_, observer)| {
                            observer.admitted
                                && observer.leader_id == Some(leader_id)
                                && observer.term == status.term
                        })
                        .count();
                    if admitted_reports >= 2 {
                        return (*candidate, leader_id, status.term);
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if let Ok(observed) = observed {
            return observed;
        }
        let redacted = eligible_voters
            .iter()
            .map(|index| {
                let status = self.stores[*index].status();
                (
                    *index,
                    status.term,
                    status.leader_id.is_some(),
                    status.admitted,
                    status.applied_index,
                    status.last_log_index,
                )
            })
            .collect::<Vec<_>>();
        panic!(
            "an admitted quorum elects a self-reporting leader at or above term {minimum_term}; redacted_status={redacted:?}"
        )
    }

    async fn application_sequences(&self) -> [u64; THREE_VOTER_COUNT] {
        std::array::from_fn(|index| {
            self.stores[index]
                .status()
                .applied_index
                .expect("read three-voter application sequence")
        })
    }

    async fn application_sequence_observation(&self) -> [Option<u64>; THREE_VOTER_COUNT] {
        std::array::from_fn(|index| self.stores[index].status().applied_index)
    }

    async fn wait_all_application_sequences(&self, expected: u64) {
        let converged = tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
            loop {
                if self
                    .application_sequence_observation()
                    .await
                    .iter()
                    .all(|sequence| sequence.is_some_and(|sequence| sequence >= expected))
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if converged.is_err() {
            let sequences = self.application_sequence_observation().await;
            let redacted_status = std::array::from_fn::<_, THREE_VOTER_COUNT, _>(|index| {
                let status = self.stores[index].status();
                (
                    status.term,
                    status.leader_id.is_some(),
                    status.admitted,
                    status.applied_index,
                    status.last_log_index,
                )
            });
            let (decoded, decode_failures, nonempty) = self.append_entries_observation();
            panic!(
                "three-voter application sequences converge: expected={expected}; sequences={sequences:?}; redacted_status={redacted_status:?}; append_entries_decoded={decoded}; append_entries_decode_failures={decode_failures}; nonempty_append_entries_seen={nonempty}"
            );
        }
    }

    async fn isolate(&mut self, node: usize) {
        for peer in 0..THREE_VOTER_COUNT {
            if peer != node {
                self.path_enabled
                    .get(&(node, peer))
                    .expect("outbound three-voter consensus path")
                    .store(false, Ordering::Release);
                self.path_enabled
                    .get(&(peer, node))
                    .expect("inbound three-voter consensus path")
                    .store(false, Ordering::Release);
            }
        }
        if let Some(server) = self.servers[node].take() {
            server.abort_and_wait().await;
        }
        *self.address_slots[node]
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.reauthentication[node]
            .request_reauthentication()
            .expect("retire isolated node consensus lanes");
    }

    async fn restore(&mut self, node: usize) {
        self.start_listener(node).await;
        for peer in 0..THREE_VOTER_COUNT {
            if peer != node {
                self.path_enabled
                    .get(&(node, peer))
                    .expect("restored outbound three-voter consensus path")
                    .store(true, Ordering::Release);
                self.path_enabled
                    .get(&(peer, node))
                    .expect("restored inbound three-voter consensus path")
                    .store(true, Ordering::Release);
            }
        }
    }

    async fn start_listener(&mut self, node: usize) {
        assert!(
            self.servers[node].is_none(),
            "three-voter consensus listener starts only from a stopped state"
        );
        let binding = if self.fixed_durable {
            self.manifest
                .bind_fixed_durable_quorum_local(three_voter_replica_id(node))
        } else {
            self.manifest.bind_local(three_voter_replica_id(node))
        }
        .expect("three-voter restored consensus server binding");
        let (server, address) = SessionConsensusServer::new(
            self.stores[node].rpc_handler(),
            self.pki.server_config(&three_voter_spiffe(node)),
            binding,
        )
        .with_reauthentication_control(self.reauthentication[node].clone())
        .listen(
            "127.0.0.1:0"
                .parse()
                .expect("three-voter restored consensus listener"),
        )
        .await
        .expect("restore three-voter consensus listener");
        *self.address_slots[node]
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(address);
        self.servers[node] = Some(server);
    }

    async fn quiesce(&mut self) {
        for enabled in self.path_enabled.values() {
            enabled.store(false, Ordering::Release);
        }
        for slot in &self.address_slots {
            *slot
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        for control in &self.reauthentication {
            control
                .request_reauthentication()
                .expect("retire every three-voter consensus lane");
        }
        let servers = self
            .servers
            .iter_mut()
            .filter_map(Option::take)
            .collect::<Vec<_>>();
        futures_util::future::join_all(
            servers
                .into_iter()
                .map(SessionConsensusServerHandle::abort_and_wait),
        )
        .await;
        for result in
            futures_util::future::join_all(self.stores.iter().map(ConsensusSessionStore::shutdown))
                .await
        {
            result.expect("stop three-voter Openraft engine");
        }
        self.stores.clear();
        self.backends.clear();
    }

    async fn shutdown(mut self) {
        self.quiesce().await;
    }

    /// Stop every listener, consensus engine, and backing handle, retaining
    /// only the three SQLite files and their snapshots. The replacement fleet
    /// therefore proves a full-fleet durable reopen rather than a client
    /// reconnect or a single-voter listener bounce.
    async fn restart_all(mut self) -> Self {
        self.quiesce().await;
        let pki = Arc::clone(&self.pki);
        let read_barrier_delay = self.read_barrier_delay;
        let fixed_durable = self.fixed_durable;
        let roster_attestation_root = self.roster_attestation_root.clone();
        let directory = self
            .directory
            .take()
            .expect("full restart retains durable test directory");
        let test_gate = self
            .test_gate
            .take()
            .expect("full restart retains three-voter test gate");
        drop(self);
        Self::start_with_topology_in_directory(
            pki,
            read_barrier_delay,
            fixed_durable,
            roster_attestation_root,
            directory,
            Some(test_gate),
        )
        .await
    }

    #[cfg(feature = "test-control")]
    async fn quiesce_and_restart_survivors(&mut self, excluded: usize) {
        let survivors = (0..THREE_VOTER_COUNT)
            .filter(|index| *index != excluded)
            .collect::<Vec<_>>();
        for survivor in &survivors {
            *self.address_slots[*survivor]
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            self.servers[*survivor]
                .take()
                .expect("surviving consensus listener is running")
                .abort_and_drain_handlers_for_test()
                .await;
        }
        for survivor in &survivors {
            self.start_listener(*survivor).await;
        }
        for survivor in survivors {
            self.reauthentication[survivor]
                .request_reauthentication()
                .expect("retire the survivor's pre-barrier outbound consensus lanes");
        }
    }

    async fn wait_for_new_leader(
        &self,
        excluded: usize,
        previous: SessionConsensusNodeId,
        previous_term: u64,
        deadline: tokio::time::Instant,
    ) -> usize {
        tokio::time::timeout_at(deadline, async {
            loop {
                let survivors = (0..THREE_VOTER_COUNT)
                    .filter(|index| *index != excluded)
                    .collect::<Vec<_>>();
                let statuses = survivors
                    .iter()
                    .map(|index| self.stores[*index].status())
                    .collect::<Vec<_>>();
                if let Some(leader) = statuses.first().and_then(|status| status.leader_id) {
                    let term = statuses.first().expect("survivor status").term;
                    if leader != previous
                        && term > previous_term
                        && statuses.iter().all(|status| {
                            status.leader_id == Some(leader)
                                && status.term == term
                                && status.admitted
                        })
                    {
                        return survivors
                            .into_iter()
                            .find(|index| self.stores[*index].status().node_id == leader)
                            .expect("new leader is a survivor");
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            let statuses = (0..THREE_VOTER_COUNT)
                .map(|index| self.stores[index].status())
                .collect::<Vec<_>>();
            panic!("survivors elect a new leader; final statuses: {statuses:?}")
        })
    }
}

fn three_voter_replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("consumer-three-voter-{index}")).expect("three-voter replica ID")
}

fn three_voter_member(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        three_voter_replica_id(index),
        ReplicaEndpoint::new(format!("consumer-three-voter-{index}.test.invalid"), 7443)
            .expect("three-voter replica endpoint"),
        ReplicaTlsIdentity::new(three_voter_spiffe(index))
            .expect("three-voter replica TLS identity"),
        ReplicaFailureDomain::new(format!("consumer-three-voter-zone-{index}"))
            .expect("three-voter failure domain"),
        ReplicaBackingIdentity::new(format!("consumer-three-voter-disk-{index}"))
            .expect("three-voter backing identity"),
    )
}

fn three_voter_spiffe(index: usize) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consensus/instance/{index}")
}

/// Script exactly one real CAS commit whose consumer response is lost. The
/// inner service remains the real SQLite/OpenRaft consumer implementation;
/// this wrapper changes only the response delivery after a confirmed commit.
struct CommitThenLosePreparedCasResponse {
    inner: Arc<dyn SessionQuorumConsumer>,
    armed: AtomicBool,
    committed: tokio::sync::Notify,
    mutation_calls: AtomicUsize,
}

impl CommitThenLosePreparedCasResponse {
    fn new(inner: Arc<dyn SessionQuorumConsumer>) -> Self {
        Self {
            inner,
            armed: AtomicBool::new(true),
            committed: tokio::sync::Notify::new(),
            mutation_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for CommitThenLosePreparedCasResponse {
    async fn execute(
        &self,
        identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let cas = matches!(
            request.operation(),
            SessionConsumerOperation::CompareAndSet { .. }
        );
        let response = self.inner.execute(identity, request).await;
        if cas {
            self.mutation_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(response, SessionConsumerResponse::CompareAndSet(Ok(_)))
                && self
                    .armed
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                self.committed.notify_waiters();
                std::future::pending().await
            }
        }
        response
    }

    async fn watch(
        &self,
        identity: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(identity, scope, start_sequence).await
    }
}

struct CountingPreparedCasStatusConsumer {
    inner: Arc<dyn SessionQuorumConsumer>,
    status_calls: AtomicUsize,
}

#[async_trait]
impl SessionQuorumConsumer for CountingPreparedCasStatusConsumer {
    async fn execute(
        &self,
        identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        if matches!(
            request.operation(),
            SessionConsumerOperation::CompareAndSetStatus { .. }
        ) {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.execute(identity, request).await
    }

    async fn watch(
        &self,
        identity: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(identity, scope, start_sequence).await
    }
}

/// A real consumer listener wrapper that commits the inner operation then
/// withholds exactly one response until the test tears down its connection.
/// It never manufactures an outcome response or invokes a mutation twice.
#[allow(dead_code)]
struct CommitThenLoseConsumerResponse {
    inner: Arc<dyn SessionQuorumConsumer>,
    roster_ingress: Option<Arc<dyn SessionQuorumRosterIngress>>,
    lose_transition: AtomicBool,
    lose_status: AtomicBool,
    lose_roster_admission: AtomicBool,
    lose_roster_terminal: AtomicBool,
    transition_committed: tokio::sync::Notify,
    status_resolved: tokio::sync::Notify,
    roster_admission_committed: tokio::sync::Notify,
    roster_terminal_committed: tokio::sync::Notify,
    transition_calls: AtomicUsize,
    status_calls: AtomicUsize,
    roster_admission_calls: AtomicUsize,
    roster_terminal_calls: AtomicUsize,
    roster_admission_recorded_responses: AtomicUsize,
    roster_terminal_recorded_responses: AtomicUsize,
    roster_terminal_response_completions: AtomicUsize,
    roster_terminal_outcome_unknown_responses: AtomicUsize,
    roster_terminal_not_transmitted_responses: AtomicUsize,
    roster_terminal_rejected_responses: AtomicUsize,
    roster_terminal_response_elapsed_millis: AtomicU64,
    #[cfg(feature = "test-control")]
    roster_terminal_status_calls: AtomicUsize,
    #[cfg(feature = "test-control")]
    roster_terminal_status_recorded_responses: AtomicUsize,
    #[cfg(feature = "test-control")]
    roster_terminal_status_recovery_required_responses: AtomicUsize,
    #[cfg(feature = "test-control")]
    roster_terminal_status_unavailable_responses: AtomicUsize,
    #[cfg(feature = "test-control")]
    roster_terminal_status_authority_responses: AtomicUsize,
    #[cfg(feature = "test-control")]
    roster_terminal_status_other_rejected_responses: AtomicUsize,
    #[cfg(feature = "test-control")]
    roster_terminal_status_response_elapsed_millis: AtomicU64,
}

#[allow(dead_code)]
impl CommitThenLoseConsumerResponse {
    fn transition(inner: Arc<dyn SessionQuorumConsumer>) -> Self {
        Self {
            inner,
            roster_ingress: None,
            lose_transition: AtomicBool::new(true),
            lose_status: AtomicBool::new(false),
            lose_roster_admission: AtomicBool::new(false),
            lose_roster_terminal: AtomicBool::new(false),
            transition_committed: tokio::sync::Notify::new(),
            status_resolved: tokio::sync::Notify::new(),
            roster_admission_committed: tokio::sync::Notify::new(),
            roster_terminal_committed: tokio::sync::Notify::new(),
            transition_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            roster_admission_calls: AtomicUsize::new(0),
            roster_terminal_calls: AtomicUsize::new(0),
            roster_admission_recorded_responses: AtomicUsize::new(0),
            roster_terminal_recorded_responses: AtomicUsize::new(0),
            roster_terminal_response_completions: AtomicUsize::new(0),
            roster_terminal_outcome_unknown_responses: AtomicUsize::new(0),
            roster_terminal_not_transmitted_responses: AtomicUsize::new(0),
            roster_terminal_rejected_responses: AtomicUsize::new(0),
            roster_terminal_response_elapsed_millis: AtomicU64::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_calls: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_recorded_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_recovery_required_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_unavailable_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_authority_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_other_rejected_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_response_elapsed_millis: AtomicU64::new(0),
        }
    }

    fn status(inner: Arc<dyn SessionQuorumConsumer>) -> Self {
        Self {
            inner,
            roster_ingress: None,
            lose_transition: AtomicBool::new(false),
            lose_status: AtomicBool::new(true),
            lose_roster_admission: AtomicBool::new(false),
            lose_roster_terminal: AtomicBool::new(false),
            transition_committed: tokio::sync::Notify::new(),
            status_resolved: tokio::sync::Notify::new(),
            roster_admission_committed: tokio::sync::Notify::new(),
            roster_terminal_committed: tokio::sync::Notify::new(),
            transition_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            roster_admission_calls: AtomicUsize::new(0),
            roster_terminal_calls: AtomicUsize::new(0),
            roster_admission_recorded_responses: AtomicUsize::new(0),
            roster_terminal_recorded_responses: AtomicUsize::new(0),
            roster_terminal_response_completions: AtomicUsize::new(0),
            roster_terminal_outcome_unknown_responses: AtomicUsize::new(0),
            roster_terminal_not_transmitted_responses: AtomicUsize::new(0),
            roster_terminal_rejected_responses: AtomicUsize::new(0),
            roster_terminal_response_elapsed_millis: AtomicU64::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_calls: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_recorded_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_recovery_required_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_unavailable_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_authority_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_other_rejected_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_response_elapsed_millis: AtomicU64::new(0),
        }
    }

    fn roster_terminal(
        inner: Arc<dyn SessionQuorumConsumer>,
        roster_ingress: Arc<dyn SessionQuorumRosterIngress>,
    ) -> Self {
        Self::roster_loss(inner, roster_ingress, false, true)
    }

    fn roster_admission(
        inner: Arc<dyn SessionQuorumConsumer>,
        roster_ingress: Arc<dyn SessionQuorumRosterIngress>,
    ) -> Self {
        Self::roster_loss(inner, roster_ingress, true, false)
    }

    fn roster_passthrough(
        inner: Arc<dyn SessionQuorumConsumer>,
        roster_ingress: Arc<dyn SessionQuorumRosterIngress>,
    ) -> Self {
        Self::roster_loss(inner, roster_ingress, false, false)
    }

    fn roster_loss(
        inner: Arc<dyn SessionQuorumConsumer>,
        roster_ingress: Arc<dyn SessionQuorumRosterIngress>,
        lose_roster_admission: bool,
        lose_roster_terminal: bool,
    ) -> Self {
        Self {
            inner,
            roster_ingress: Some(roster_ingress),
            lose_transition: AtomicBool::new(false),
            lose_status: AtomicBool::new(false),
            lose_roster_admission: AtomicBool::new(lose_roster_admission),
            lose_roster_terminal: AtomicBool::new(lose_roster_terminal),
            transition_committed: tokio::sync::Notify::new(),
            status_resolved: tokio::sync::Notify::new(),
            roster_admission_committed: tokio::sync::Notify::new(),
            roster_terminal_committed: tokio::sync::Notify::new(),
            transition_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            roster_admission_calls: AtomicUsize::new(0),
            roster_terminal_calls: AtomicUsize::new(0),
            roster_admission_recorded_responses: AtomicUsize::new(0),
            roster_terminal_recorded_responses: AtomicUsize::new(0),
            roster_terminal_response_completions: AtomicUsize::new(0),
            roster_terminal_outcome_unknown_responses: AtomicUsize::new(0),
            roster_terminal_not_transmitted_responses: AtomicUsize::new(0),
            roster_terminal_rejected_responses: AtomicUsize::new(0),
            roster_terminal_response_elapsed_millis: AtomicU64::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_calls: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_recorded_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_recovery_required_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_unavailable_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_authority_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_other_rejected_responses: AtomicUsize::new(0),
            #[cfg(feature = "test-control")]
            roster_terminal_status_response_elapsed_millis: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for CommitThenLoseConsumerResponse {
    async fn execute(
        &self,
        identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let transition = matches!(
            request.operation(),
            SessionConsumerOperation::FencedTransition { .. }
        );
        let status = matches!(
            request.operation(),
            SessionConsumerOperation::FencedTransitionStatus { .. }
        );
        let response = self.inner.execute(identity, request).await;
        if transition {
            self.transition_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(response, SessionConsumerResponse::FencedTransition(Ok(_)))
                && self
                    .lose_transition
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                self.transition_committed.notify_waiters();
                std::future::pending().await
            }
        }
        if status {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(
                response,
                SessionConsumerResponse::FencedTransitionStatus(Ok(_))
            ) && self
                .lose_status
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.status_resolved.notify_waiters();
                std::future::pending().await
            }
        }
        response
    }

    async fn watch(
        &self,
        identity: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(identity, scope, start_sequence).await
    }
}

#[async_trait]
impl SessionQuorumRosterIngress for CommitThenLoseConsumerResponse {
    fn expected_roster_attestation_trust_root_identity(
        &self,
    ) -> Option<RosterAttestationTrustRootIdentityV1> {
        self.roster_ingress
            .as_ref()
            .and_then(|ingress| ingress.expected_roster_attestation_trust_root_identity())
    }

    fn prepare_compact_admission_provenance_input(
        &self,
        authorization: &SessionConsumerRosterAuthorization,
        request: &SessionConsumerRequest,
        attestation: &RosterIngressAttestationV1,
        certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<RosterCompactAdmissionProvenanceSigningInputV2, SessionConsumerRosterRejection>
    {
        self.roster_ingress
            .as_ref()
            .ok_or(SessionConsumerRosterRejection::Capability)?
            .prepare_compact_admission_provenance_input(
                authorization,
                request,
                attestation,
                certificate_subject_identity_commitment,
            )
    }

    async fn execute_roster_ingress(
        &self,
        authorization: &SessionConsumerRosterAuthorization,
        request: SessionConsumerRequest,
        attestation: RosterIngressAttestationV1,
        admission_provenance: Option<
            opc_session_store::fenced_mutation_roster::RosterCompactAdmissionProvenanceV2,
        >,
    ) -> SessionConsumerResponse {
        let admission = matches!(
            request.operation(),
            SessionConsumerOperation::FencedMutationRosterPollAdmit { .. }
        );
        let terminal = matches!(
            request.operation(),
            SessionConsumerOperation::FencedMutationRosterTerminalize { .. }
        );
        #[cfg(feature = "test-control")]
        let terminal_status = matches!(
            request.operation(),
            SessionConsumerOperation::FencedMutationRosterTerminalStatus { .. }
        );
        if admission {
            self.roster_admission_calls.fetch_add(1, Ordering::SeqCst);
        }
        if terminal {
            self.roster_terminal_calls.fetch_add(1, Ordering::SeqCst);
        }
        #[cfg(feature = "test-control")]
        if terminal_status {
            self.roster_terminal_status_calls
                .fetch_add(1, Ordering::SeqCst);
        }
        let roster_ingress_started = Instant::now();
        let response = self
            .roster_ingress
            .as_ref()
            .expect("only roster wrappers expose the protected ingress")
            .execute_roster_ingress(authorization, request, attestation, admission_provenance)
            .await;
        let admission_recorded = matches!(
            &response,
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                opc_session_store::consumer::SessionConsumerRosterAdmissionMutationResponse::Recorded(_)
            )
        );
        let terminal_recorded = matches!(
            &response,
            SessionConsumerResponse::FencedMutationRosterTerminalize(
                opc_session_store::consumer::SessionConsumerRosterTerminalMutationResponse::Recorded(_)
            )
        );
        if admission_recorded {
            self.roster_admission_recorded_responses
                .fetch_add(1, Ordering::SeqCst);
        }
        if terminal_recorded {
            self.roster_terminal_recorded_responses
                .fetch_add(1, Ordering::SeqCst);
        }
        if terminal {
            self.roster_terminal_response_completions
                .fetch_add(1, Ordering::SeqCst);
            self.roster_terminal_response_elapsed_millis.store(
                u64::try_from(roster_ingress_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            match &response {
                SessionConsumerResponse::FencedMutationRosterTerminalize(
                    opc_session_store::consumer::SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown,
                ) => {
                    self.roster_terminal_outcome_unknown_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                SessionConsumerResponse::FencedMutationRosterTerminalize(
                    opc_session_store::consumer::SessionConsumerRosterTerminalMutationResponse::NotTransmitted,
                ) => {
                    self.roster_terminal_not_transmitted_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                SessionConsumerResponse::FencedMutationRosterTerminalize(
                    opc_session_store::consumer::SessionConsumerRosterTerminalMutationResponse::Rejected(_),
                ) => {
                    self.roster_terminal_rejected_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        #[cfg(feature = "test-control")]
        if terminal_status {
            self.roster_terminal_status_response_elapsed_millis.store(
                u64::try_from(roster_ingress_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            match &response {
                SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                    opc_session_store::consumer::SessionConsumerRosterTerminalReadResponse::Recorded(_),
                ) => {
                    self.roster_terminal_status_recorded_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                    opc_session_store::consumer::SessionConsumerRosterTerminalReadResponse::Rejected(
                        SessionConsumerRosterRejection::RecoveryRequired,
                    ),
                ) => {
                    self.roster_terminal_status_recovery_required_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                    opc_session_store::consumer::SessionConsumerRosterTerminalReadResponse::Rejected(
                        SessionConsumerRosterRejection::Unavailable,
                    ),
                ) => {
                    self.roster_terminal_status_unavailable_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                    opc_session_store::consumer::SessionConsumerRosterTerminalReadResponse::Rejected(
                        SessionConsumerRosterRejection::Authority,
                    ),
                ) => {
                    self.roster_terminal_status_authority_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                    opc_session_store::consumer::SessionConsumerRosterTerminalReadResponse::Rejected(_),
                ) => {
                    self.roster_terminal_status_other_rejected_responses
                        .fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        if admission
            && admission_recorded
            && self
                .lose_roster_admission
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.roster_admission_committed.notify_waiters();
            std::future::pending::<SessionConsumerResponse>().await;
        }
        if terminal
            && terminal_recorded
            && self
                .lose_roster_terminal
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.roster_terminal_committed.notify_waiters();
            std::future::pending::<SessionConsumerResponse>().await;
        }
        response
    }
}

/// Records only wire operations while delegating every authority and physical
/// transition decision to the concrete consensus consumer service.
struct CountingFencedConsumerOperations {
    inner: Arc<dyn SessionQuorumConsumer>,
    capability_calls: AtomicUsize,
    transition_calls: AtomicUsize,
    status_calls: AtomicUsize,
}

impl CountingFencedConsumerOperations {
    fn new(inner: Arc<dyn SessionQuorumConsumer>) -> Self {
        Self {
            inner,
            capability_calls: AtomicUsize::new(0),
            transition_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for CountingFencedConsumerOperations {
    async fn execute(
        &self,
        identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        match request.operation() {
            SessionConsumerOperation::FencedTransitionCapability => {
                self.capability_calls.fetch_add(1, Ordering::SeqCst);
            }
            SessionConsumerOperation::FencedTransition { .. } => {
                self.transition_calls.fetch_add(1, Ordering::SeqCst);
            }
            SessionConsumerOperation::FencedTransitionStatus { .. } => {
                self.status_calls.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        self.inner.execute(identity, request).await
    }

    async fn watch(
        &self,
        identity: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(identity, scope, start_sequence).await
    }
}

#[derive(Default)]
struct CountingConsumer {
    calls: AtomicUsize,
    v2_calls: AtomicUsize,
}

struct HandshakeOnlySessionQuorumRosterIngress {
    expected_root_identity: RosterAttestationTrustRootIdentityV1,
    calls: AtomicUsize,
}

impl HandshakeOnlySessionQuorumRosterIngress {
    fn new(expected_root_identity: RosterAttestationTrustRootIdentityV1) -> Self {
        Self {
            expected_root_identity,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SessionQuorumRosterIngress for HandshakeOnlySessionQuorumRosterIngress {
    fn expected_roster_attestation_trust_root_identity(
        &self,
    ) -> Option<RosterAttestationTrustRootIdentityV1> {
        Some(self.expected_root_identity)
    }

    async fn execute_roster_ingress(
        &self,
        _authorization: &SessionConsumerRosterAuthorization,
        _request: SessionConsumerRequest,
        _attestation: RosterIngressAttestationV1,
        _admission_provenance: Option<
            opc_session_store::fenced_mutation_roster::RosterCompactAdmissionProvenanceV2,
        >,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
    }
}

#[derive(Default)]
struct HangingConsumer {
    calls: AtomicUsize,
}

#[async_trait]
impl SessionQuorumConsumer for HangingConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            SessionConsumerResponse::WatchOpened
        } else {
            std::future::pending().await
        }
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerAuthorization,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Ok(Box::pin(futures_util::stream::pending()))
    }
}

struct HangingV2Consumer {
    v2_calls: AtomicUsize,
    v2_call_started: tokio::sync::Notify,
}

impl HangingV2Consumer {
    fn new() -> Self {
        Self {
            v2_calls: AtomicUsize::new(0),
            v2_call_started: tokio::sync::Notify::new(),
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for HangingV2Consumer {
    async fn execute(
        &self,
        _authorization: &SessionConsumerAuthorization,
        _request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled())
    }

    async fn execute_v2(
        &self,
        _authorization: &SessionConsumerAuthorization,
        _request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        self.v2_calls.fetch_add(1, Ordering::SeqCst);
        self.v2_call_started.notify_waiters();
        std::future::pending().await
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerAuthorization,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

#[async_trait]
impl SessionQuorumConsumer for CountingConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerAuthorization,
        _request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled())
    }

    async fn execute_v2(
        &self,
        _identity: &SessionConsumerAuthorization,
        request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        self.v2_calls.fetch_add(1, Ordering::SeqCst);
        match request.operation() {
            SessionConsumerV2Operation::FencedTransitionV2Capability => {
                SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                    FencedTransitionV2Capability::V2,
                ))
            }
            _ => SessionConsumerV2Response::Rejected(SessionConsumerRejection::MalformedRequest),
        }
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerAuthorization,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

async fn authorizer_from_admitted_store(
    client_spiffe: &str,
    server_spiffe: &str,
) -> (
    SessionConsumerAuthorizer,
    SessionConsumerScope,
    SessionConsumerVoterAuthority,
) {
    let (_snapshots, store, scope, voter_authority, authorizer) =
        admitted_store_and_authorizer([client_spiffe.to_owned()], server_spiffe).await;
    // The authorizer contains the store-issued scope and member exclusion set;
    // it remains valid after this short-lived fixture store is dropped.
    drop(store);
    (authorizer, scope, voter_authority)
}

async fn three_voter_authorizer(
    store: &ConsensusSessionStore,
    client_spiffe: &str,
) -> SessionConsumerAuthorizer {
    let manifest = store
        .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(client_spiffe).expect("three-voter client SPIFFE"),
            [SessionConsumerTenantNfScope::new(
                TenantId::new("consumer-test").expect("tenant"),
                NetworkFunctionKind::smf(),
            )],
        )
        .expect("three-voter explicit consumer grant")])
        .await
        .expect("three-voter consumer manifest");
    SessionConsumerAuthorizer::try_new(manifest).expect("three-voter consumer authorizer")
}

async fn admitted_store_and_authorizer(
    client_spiffes: impl IntoIterator<Item = String>,
    server_spiffe: &str,
) -> (
    tempfile::TempDir,
    ConsensusSessionStore,
    SessionConsumerScope,
    SessionConsumerVoterAuthority,
    SessionConsumerAuthorizer,
) {
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let replica_id = ReplicaId::new("stateless-consumer-authorizer-test").expect("replica ID");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("consumer-authorizer.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(server_spiffe).expect("member TLS identity"),
        ReplicaFailureDomain::new("consumer-authorizer-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("consumer-authorizer-disk").expect("backing identity"),
    );
    let cluster =
        ConsensusClusterId::new("stateless-consumer-authorizer-test").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let configuration =
        derive_configuration_id(cluster, epoch, &[descriptor.configuration_fingerprint()]);
    let topology = ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        replica_id,
        vec![descriptor],
        SessionConsensusIdentity::new(cluster, configuration, epoch),
    )
    .expect("singleton topology");
    let voter_authority = topology
        .session_consumer_roster()
        .expect("consumer roster")
        .voter(topology.local_consensus_node_id().expect("local node ID"))
        .expect("local voter authority");
    let store = ConsensusSessionStore::open(
        topology,
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
        snapshots.path(),
        Default::default(),
    )
    .await
    .expect("open store");
    store.initialize_cluster().await.expect("initialize store");
    let grants = client_spiffes
        .into_iter()
        .map(|identity| {
            SessionConsumerAuthorizationGrant::try_new(
                SpiffeId::new(identity).expect("client SPIFFE"),
                [SessionConsumerTenantNfScope::new(
                    TenantId::new("consumer-test").expect("tenant"),
                    NetworkFunctionKind::smf(),
                )],
            )
            .expect("explicit consumer grant")
        })
        .collect::<Vec<_>>();
    let manifest = store
        .consumer_authorization_manifest(grants)
        .await
        .expect("admitted consumer manifest");
    let scope = manifest.scope();
    let authorizer = SessionConsumerAuthorizer::try_new(manifest).expect("consumer authorizer");
    (snapshots, store, scope, voter_authority, authorizer)
}

fn spiffe(suffix: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{suffix}")
}

fn tenant_spiffe(tenant: &str, suffix: &str) -> String {
    format!(
        "spiffe://test.example/tenant/{tenant}/ns/default/sa/session/nf/consumer/instance/{suffix}"
    )
}

fn consumer_client(
    pki: &TestPki,
    address: SocketAddr,
    _server_spiffe: &str,
    client_spiffe: &str,
    voter_authority: SessionConsumerVoterAuthority,
) -> StatelessSessionConsumerClient {
    StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        voter_authority,
        pki.client_config(client_spiffe),
    )
}

async fn read_json_frame<R>(reader: &mut R) -> serde_json::Value
where
    R: AsyncRead + Unpin,
{
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .await
        .expect("read JSON frame length");
    let mut payload = vec![
        0_u8;
        usize::try_from(u32::from_be_bytes(length))
            .expect("JSON frame length fits usize")
    ];
    reader
        .read_exact(&mut payload)
        .await
        .expect("read JSON frame payload");
    serde_json::from_slice(&payload).expect("decode JSON frame")
}

async fn accept_v2_tls(
    listener: &TcpListener,
    authenticated: &AuthenticatedServerConfig,
) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
    let (tcp, _) = listener.accept().await.expect("accept V2 TLS socket");
    let mut config = authenticated.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_QUORUM_CONSUMER_V2_ALPN.to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(tcp)
        .await
        .expect("complete V2 mTLS")
}

async fn v2_mutation_request(
    scope: SessionConsumerScope,
    nonce: u8,
    owner: &str,
) -> (
    SessionConsumerV2Request,
    opc_session_store::FencedTransitionV2RequestId,
) {
    let timestamp = time::OffsetDateTime::now_utc();
    let lease: LeaseGuard = serde_json::from_value(serde_json::json!({
        "key": test_key(),
        "owner": OwnerId::new(owner).expect("owner"),
        "fence": FenceToken::new(1),
        "acquired_at": Timestamp::from_offset_datetime(timestamp),
        "expires_at": Timestamp::from_offset_datetime(timestamp + time::Duration::minutes(1)),
        "credential_id": 1,
    }))
    .expect("public lease wire shape");
    let transition = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("nonzero history epoch"),
        FencedTransitionV2CallerNonce::from_bytes([nonce; 16]),
        FencedTransitionLease::renew(lease, Duration::from_secs(30)).expect("renew request"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("self-authenticating V2 transition");
    let request_id = transition.request_id();
    (
        SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(transition),
            },
        ),
        request_id,
    )
}

fn protected_roster_persistent_client(
    pki: &TestPki,
    address: SocketAddr,
    server_spiffe: &str,
    client_spiffe: &str,
    voter_authority: SessionConsumerVoterAuthority,
) -> PersistentSessionConsumerClient {
    PersistentSessionConsumerClient::try_from_fenced_mutation_roster_stateless(
        consumer_client(pki, address, server_spiffe, client_spiffe, voter_authority),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("protected-roster persistent consumer")
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("consumer-test").expect("tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"opaque-session-reference")
            .try_into()
            .expect("stable ID"),
    }
}

struct CountingKeyProvider {
    inner: MemoryKeyProvider,
    calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn with_active_session_key() -> Arc<Self> {
        let provider = Arc::new(Self {
            inner: MemoryKeyProvider::new(),
            calls: AtomicUsize::new(0),
        });
        provider
            .inner
            .insert_active_key(
                KeyId::new("consumer-v2-test-key").expect("test key ID"),
                KeyPurpose::Session,
                TenantId::new("consumer-test").expect("test tenant"),
                Zeroizing::new([0x61; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install test key");
        provider
    }

    fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryKeyProvider::new(),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, opc_key::KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, opc_key::KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyId, opc_key::KeyError> {
        self.inner.rotate_key(purpose, tenant).await
    }
}

/// For one successful physical transition, retain only the protected request
/// shape and deliberately replace the confirmed response with ambiguity.
struct OneShotOutcomeUnknownConsumer {
    inner: Arc<dyn SessionQuorumConsumer>,
    armed: AtomicBool,
    physical_payload_encoding: Mutex<Option<SessionPayloadEncoding>>,
    physical_payload_is_logical: AtomicBool,
}

impl OneShotOutcomeUnknownConsumer {
    fn new(inner: Arc<dyn SessionQuorumConsumer>) -> Self {
        Self {
            inner,
            armed: AtomicBool::new(true),
            physical_payload_encoding: Mutex::new(None),
            physical_payload_is_logical: AtomicBool::new(false),
        }
    }

    fn physical_payload_encoding(&self) -> Option<SessionPayloadEncoding> {
        *self
            .physical_payload_encoding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn physical_payload_is_logical(&self) -> bool {
        self.physical_payload_is_logical.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SessionQuorumConsumer for OneShotOutcomeUnknownConsumer {
    async fn execute(
        &self,
        identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let physical_evidence = match request.operation() {
            SessionConsumerOperation::FencedTransition { request } => {
                request.mutation().record().map(|record| {
                    (
                        record.payload.encoding(),
                        record.payload.as_bytes() == [0xa1],
                    )
                })
            }
            _ => None,
        };
        let request_id = request.request_id();
        let response = self.inner.execute(identity, request).await;
        if let Some((encoding, is_logical)) = physical_evidence {
            *self
                .physical_payload_encoding
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(encoding);
            self.physical_payload_is_logical
                .store(is_logical, Ordering::SeqCst);
            if matches!(response, SessionConsumerResponse::FencedTransition(Ok(_)))
                && self
                    .armed
                    .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                return SessionConsumerResponse::OutcomeUnknown(
                    SessionConsumerOutcomeUnknown::Mutation { request_id },
                );
            }
        }
        response
    }

    async fn watch(
        &self,
        identity: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(identity, scope, start_sequence).await
    }
}

#[derive(Clone, Copy)]
enum FencedConsumerClientKind {
    Stateless,
    Persistent,
}

struct FencedConsumerClientHandle {
    backend: Arc<dyn SessionBackend>,
    persistent: Option<PersistentSessionConsumerClient>,
}

impl FencedConsumerClientHandle {
    async fn shutdown(self) {
        if let Some(client) = self.persistent {
            let _ = client.shutdown().await;
        }
    }
}

fn fenced_consumer_backend(
    kind: FencedConsumerClientKind,
    pki: &TestPki,
    address: SocketAddr,
    server_spiffe: &str,
    client_spiffe: &str,
    voter_authority: SessionConsumerVoterAuthority,
) -> FencedConsumerClientHandle {
    let stateless = consumer_client(pki, address, server_spiffe, client_spiffe, voter_authority);
    match kind {
        FencedConsumerClientKind::Stateless => FencedConsumerClientHandle {
            backend: Arc::new(
                SessionConsumerFencedTransitionBackend::stateless(stateless)
                    .expect("stateless fenced-transition adapter"),
            ),
            persistent: None,
        },
        FencedConsumerClientKind::Persistent => {
            let persistent = PersistentSessionConsumerClient::try_from_stateless(
                stateless,
                PersistentSessionConsumerConfig::default(),
            )
            .expect("persistent fenced-transition client");
            FencedConsumerClientHandle {
                backend: Arc::new(
                    SessionConsumerFencedTransitionBackend::persistent(persistent.clone())
                        .expect("persistent fenced-transition adapter"),
                ),
                persistent: Some(persistent),
            }
        }
    }
}

fn fenced_create_request(payload: u8) -> FencedTransitionRequest {
    fenced_create_request_with_identity(payload, [0x71; 16], b"opaque-session-reference")
}

fn fenced_create_request_with_identity(
    payload: u8,
    request_id: [u8; 16],
    stable_id: &'static [u8],
) -> FencedTransitionRequest {
    let mut key = test_key();
    key.stable_id = Bytes::from_static(stable_id)
        .try_into()
        .expect("test stable ID");
    let owner = OwnerId::new("x").expect("test owner");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(30),
    )
    .expect("test acquire lease");
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes(request_id),
        lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner,
            fence: lease.committed_fence().expect("committed fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("x"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([payload]),
        }),
    )
    .expect("test create request")
}

async fn test_lease() -> opc_session_store::LeaseGuard {
    let backend = SqliteSessionBackend::in_memory().expect("test lease backend");
    backend
        .acquire(
            &test_key(),
            OwnerId::new("consumer-test-owner").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("test lease")
}

async fn raw_authenticated_consumer_connection(
    pki: &TestPki,
    address: SocketAddr,
    client_spiffe: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let handshake = pki
        .client_config(client_spiffe)
        .begin_handshake()
        .expect("raw test TLS handshake material");
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_QUORUM_CONSUMER_ALPN.to_vec()];
    let tcp = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect raw consumer TLS socket");
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            tcp,
        )
        .await
        .expect("complete raw consumer mTLS")
}

async fn counting_tcp_proxy(
    upstream: SocketAddr,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let address = listener.local_addr().expect("counting proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let task = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept consumer TCP");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    else {
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                });
            }
        })
    };
    (address, accepted, task)
}

async fn wait_for_dispatches(service: &HangingConsumer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while service.calls.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded fixture observes authenticated dispatches");
}

#[test]
fn production_default_features_expose_a_dedicated_stateless_consumer_boundary() {
    let _ = std::any::TypeId::of::<StatelessSessionConsumerClient>();
    let _ = std::any::TypeId::of::<SessionQuorumConsumerServer>();
    let _ = std::any::TypeId::of::<SessionConsumerAuthorizer>();
    assert_ne!(SESSION_QUORUM_CONSUMER_ALPN, b"opc-session-consensus/2");
    assert_ne!(SESSION_QUORUM_CONSUMER_ALPN, b"opc-session-net/5");
}

#[test]
fn stateless_lease_response_payloads_remain_source_compatible_lease_guards() {
    fn assert_lease_payload(
        payload: Result<opc_session_store::LeaseGuard, SessionConsumerLeaseError>,
    ) {
        assert!(payload.is_err());
    }

    match SessionConsumerResponse::AcquireLease(Err(SessionConsumerLeaseError::Unavailable)) {
        SessionConsumerResponse::AcquireLease(payload) => assert_lease_payload(payload),
        _ => unreachable!("constructed acquire response"),
    }
    match SessionConsumerResponse::RenewLease(Err(SessionConsumerLeaseError::Unavailable)) {
        SessionConsumerResponse::RenewLease(payload) => assert_lease_payload(payload),
        _ => unreachable!("constructed renew response"),
    }
}

#[tokio::test]
async fn one_authenticated_consumer_call_uses_the_dedicated_alpn_without_replay() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffe = spiffe("client");
    let service = Arc::new(CountingConsumer::default());
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");
    let client = StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    );

    assert_eq!(
        client
            .capabilities()
            .await
            .expect("authenticated capability call"),
        transported_capabilities()
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        1,
        "the client must send exactly one request and never replay it automatically"
    );

    let (_wrong_authorizer, _wrong_scope, wrong_voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &spiffe("wrong-scope-server")).await;
    let wrong_scope_client = StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        wrong_voter_authority,
        pki.client_config(&client_spiffe),
    );
    assert_eq!(
        wrong_scope_client.capabilities().await,
        Err(SessionConsumerClientError::Authentication),
        "a topology-derived authority for another server must not reach the service"
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn authenticated_v2_consumer_call_reaches_the_listener_on_its_dedicated_alpn() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("v2-server");
    let client_spiffe = spiffe("v2-client");
    let service = Arc::new(CountingConsumer::default());
    let (authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless V2 consumer listener");
    let client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );

    let request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Capability,
    );
    assert_eq!(
        client.execute_v2(&request).await,
        Ok(SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2,
        ))),
        "the V2 client Hello and request reach the V2 listener lane"
    );
    assert_eq!(
        service.v2_calls.load(Ordering::SeqCst),
        1,
        "the V2 service method receives exactly one listener-dispatched request"
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        0,
        "the V2 request never enters the V1 DTO service method"
    );
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn revision_five_v2_status_transports_a_retained_stale_fence_receipt() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("v2-status-error-server");
    let client_spiffe = spiffe("v2-status-error-client");
    let (_snapshots, store, scope, voter_authority, authorizer) =
        admitted_store_and_authorizer([client_spiffe.clone()], &server_spiffe).await;
    let (handle, address) = SessionQuorumConsumerServer::new(
        Arc::new(store.consumer_service()),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start revision-five consumer listener");
    let client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );
    let timestamp = time::OffsetDateTime::now_utc();
    let absent_lease: LeaseGuard = serde_json::from_value(serde_json::json!({
        "key": test_key(),
        "owner": OwnerId::new("v2-status-error-owner").expect("owner"),
        "fence": FenceToken::new(1),
        "acquired_at": Timestamp::from_offset_datetime(timestamp),
        "expires_at": Timestamp::from_offset_datetime(timestamp + time::Duration::minutes(1)),
        "credential_id": 1,
    }))
    .expect("public lease wire shape");
    let transition = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("nonzero history epoch"),
        FencedTransitionV2CallerNonce::from_bytes([0x78; 16]),
        FencedTransitionLease::renew(absent_lease, Duration::from_secs(30)).expect("renew request"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("self-authenticating V2 transition");

    let request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2 {
            request: Box::new(transition),
        },
    );
    let request_id = request.request_id().expect("V2 mutation has full ID");
    let execute = client.execute_v2(&request).await;
    assert_eq!(
        execute,
        Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }),
        "the unbound execution error is recovered only through exact V2 status"
    );

    let SessionConsumerV2Operation::FencedTransitionV2 {
        request: original_transition,
    } = request.operation()
    else {
        panic!("retain the exact V2 mutation request")
    };
    let status = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Status {
            request: Box::new((**original_transition).clone()),
        },
    );
    assert_eq!(
        client.execute_v2(&status).await,
        Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Err(
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::StaleFence,
                ),
            ))),
        )))
    );

    let mut malformed = serde_json::to_value(status).expect("status request encodes");
    let serde_json::Value::Object(fields) = &mut malformed else {
        panic!("V2 status envelope is an object");
    };
    fields.insert("request_id".into(), serde_json::Value::Null);
    let malformed: SessionConsumerV2Request =
        serde_json::from_value(malformed).expect("outer-ID mismatch decodes");
    assert_eq!(
        client.execute_v2(&malformed).await,
        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Protocol,
        }),
        "an outer full-ID mismatch remains rejected before dispatch"
    );
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_v2_setup_closes_retry_without_mutation_dispatch() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("v2-setup-close-server");
    let client_spiffe = spiffe("v2-setup-close-client");
    let (_authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind V2 setup-close listener");
    let address = listener.local_addr().expect("V2 setup-close address");
    let setups = Arc::new(AtomicUsize::new(0));
    let call_frames = Arc::new(AtomicUsize::new(0));
    let authenticated = pki.server_config(&server_spiffe);
    let peer = {
        let setups = Arc::clone(&setups);
        let call_frames = Arc::clone(&call_frames);
        tokio::spawn(async move {
            for _ in 0..2 {
                let mut tls = accept_v2_tls(&listener, &authenticated).await;
                let frame = read_json_frame(&mut tls).await;
                if frame["kind"] == "call" {
                    call_frames.fetch_add(1, Ordering::SeqCst);
                }
                assert_eq!(frame["kind"], "hello");
                setups.fetch_add(1, Ordering::SeqCst);
                // Drop before HelloAck: the client cannot establish a lane
                // or enqueue a mutation Call on this attempt.
            }
        })
    };
    let persistent = PersistentSessionConsumerClient::try_from_stateless(
        consumer_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            voter_authority,
        )
        .with_operation_timeout(Duration::from_secs(2)),
        PersistentSessionConsumerConfig::try_new(
            1,
            0,
            Duration::from_millis(250),
            1,
            Duration::from_millis(500),
            2,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("two-attempt V2 config"),
    )
    .expect("persistent V2 client");
    let (request, _) = v2_mutation_request(scope, 0x79, "v2-setup-close-owner").await;

    assert_eq!(
        persistent.execute_v2(&request).await,
        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        }),
        "TLS and Hello writes are setup only and remain retryable"
    );
    peer.await.expect("join setup-close peer");
    assert_eq!(
        setups.load(Ordering::SeqCst),
        2,
        "only the configured bounded setup retries are attempted"
    );
    assert_eq!(
        call_frames.load(Ordering::SeqCst),
        0,
        "no setup attempt dispatches a mutation Call"
    );
    persistent.shutdown().await;
}

#[tokio::test]
async fn persistent_v2_call_acceptance_then_close_is_exactly_outcome_unknown() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("v2-call-close-server");
    let client_spiffe = spiffe("v2-call-close-client");
    let (authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let service = Arc::new(HangingV2Consumer::new());
    let call_seen = service.v2_call_started.notified();
    tokio::pin!(call_seen);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start V2 close-after-Call listener");
    let persistent = PersistentSessionConsumerClient::from_stateless(
        consumer_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            voter_authority,
        )
        .with_operation_timeout(Duration::from_secs(2)),
    )
    .expect("persistent V2 client");
    let (request, request_id) = v2_mutation_request(scope, 0x7a, "v2-call-close-owner").await;
    let execute = persistent.execute_v2(&request);
    tokio::pin!(execute);
    tokio::select! {
        result = &mut execute => panic!("Call completed before peer receipt: {result:?}"),
        _ = &mut call_seen => {},
    }
    handle.abort_and_wait().await;

    assert_eq!(
        execute.await,
        Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }),
        "a lower transport acceptance after Call retains the exact V2 ID"
    );
    assert_eq!(
        service.v2_calls.load(Ordering::SeqCst),
        1,
        "the complete mutation Call is dispatched exactly once"
    );
    persistent.shutdown().await;
}

#[tokio::test]
async fn stateless_serial_calls_authenticate_fresh_and_accumulate_setup_delay() {
    const CALLS: usize = 4;
    const SETUP_DELAY: Duration = Duration::from_millis(40);

    let pki = TestPki::new();
    let server_spiffe = spiffe("red-server");
    let client_spiffe = spiffe("red-client");
    let service = Arc::new(CountingConsumer::default());
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let (handle, upstream_address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");

    // Delay every end-to-end TLS connection before forwarding any handshake
    // byte. A completed capability response therefore proves that the counted
    // proxy connection completed the authenticated consumer setup.
    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind deterministic setup-delay proxy");
    let proxy_address = proxy_listener.local_addr().expect("proxy address");
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted_connections = Arc::clone(&accepted_connections);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = proxy_listener.accept().await.expect("accept client");
                accepted_connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    tokio::time::sleep(SETUP_DELAY).await;
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(upstream_address).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                });
            }
        })
    };

    let client = consumer_client(
        &pki,
        proxy_address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );
    let started_at = tokio::time::Instant::now();
    for _ in 0..CALLS {
        assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
    }
    let elapsed = started_at.elapsed();

    assert!(
        elapsed >= SETUP_DELAY * u32::try_from(CALLS).expect("small call count"),
        "serial cold calls must accumulate the deterministic setup delay"
    );
    assert_eq!(
        accepted_connections.load(Ordering::SeqCst),
        CALLS,
        "the stateless client deliberately authenticates a fresh transport per call"
    );

    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn cloned_stateless_request_connections_fail_fast_at_the_shared_physical_cap() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("physical-request-server");
    let client_spiffe = spiffe("physical-request-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let service = Arc::new(HangingConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start physical-cap listener");
    let (proxy, accepted, proxy_task) = counting_tcp_proxy(upstream).await;
    let client = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, voter_authority);

    let mut held = (0..PHYSICAL_CAP)
        .map(|_| {
            let clone = client.clone();
            tokio::spawn(async move { clone.capabilities().await })
        })
        .collect::<Vec<_>>();
    wait_for_dispatches(&service, PHYSICAL_CAP).await;
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Overloaded),
        "the seventeenth clone is rejected before resolve, TCP, or dispatch"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);

    let released = held.pop().expect("one held caller");
    released.abort();
    assert!(
        released.await.is_err(),
        "cancelling a held connection completes"
    );
    let replacement = {
        let clone = client.clone();
        tokio::spawn(async move { clone.capabilities().await })
    };
    wait_for_dispatches(&service, PHYSICAL_CAP + 1).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        PHYSICAL_CAP + 1,
        "releasing one cap slot admits one fresh authenticated TCP connection"
    );
    replacement.abort();
    let _ = replacement.await;
    for caller in held {
        caller.abort();
        let _ = caller.await;
    }
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
#[allow(deprecated)]
async fn production_stateless_watch_is_denied_before_service_dispatch() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("physical-watch-server");
    let client_spiffe = spiffe("physical-watch-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let service = Arc::new(HangingConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start physical-watch listener");
    let (proxy, accepted, proxy_task) = counting_tcp_proxy(upstream).await;
    let client = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, voter_authority);

    // The public consumer Watch cursor is global and therefore carries no
    // exact tenant authority. Reject it locally before opening a connection
    // until the protocol has an identity-and-scope-bound cursor. The physical
    // Watch-pool machinery is deliberately dormant.
    assert!(matches!(
        client.watch(0).await,
        Err(StoreError::CapabilityNotSupported(capability))
            if capability == "tenant_scoped_consumer_watch"
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn independent_stateless_constructors_do_not_share_physical_request_budgets() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("independent-physical-server");
    let client_spiffe = spiffe("independent-physical-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let service = Arc::new(HangingConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start independent-budget listener");
    let (proxy, accepted, proxy_task) = counting_tcp_proxy(upstream).await;
    let first = consumer_client(
        &pki,
        proxy,
        &server_spiffe,
        &client_spiffe,
        voter_authority.clone(),
    );
    let second = consumer_client(&pki, proxy, &server_spiffe, &client_spiffe, voter_authority);

    let mut held = Vec::with_capacity(PHYSICAL_CAP * 2);
    for _ in 0..PHYSICAL_CAP {
        for client in [&first, &second] {
            let clone = client.clone();
            held.push(tokio::spawn(async move { clone.capabilities().await }));
            wait_for_dispatches(&service, held.len()).await;
        }
    }
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP * 2);
    assert_eq!(
        first.capabilities().await,
        Err(SessionConsumerClientError::Overloaded)
    );
    assert_eq!(
        second.capabilities().await,
        Err(SessionConsumerClientError::Overloaded)
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP * 2);

    for caller in held.drain(..) {
        caller.abort();
        let _ = caller.await;
    }
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn consumer_resolver_reconnects_the_same_client_after_endpoint_replacement() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("resolver-server");
    let client_spiffe = spiffe("resolver-client");
    let first_service = Arc::new(CountingConsumer::default());
    let (first_authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let (first_handle, first_address) = SessionQuorumConsumerServer::new(
        first_service.clone(),
        pki.server_config(&server_spiffe),
        first_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start first consumer listener");

    let resolved_address = Arc::new(RwLock::new(first_address));
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolved_address = Arc::clone(&resolved_address);
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolved_address = Arc::clone(&resolved_address);
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(*resolved_address.read().expect("resolver address lock"))
            })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    );

    assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
    assert_eq!(first_service.calls.load(Ordering::SeqCst), 1);
    first_handle.abort_and_wait().await;

    let second_service = Arc::new(CountingConsumer::default());
    let (second_authorizer, second_scope, _second_voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    assert_eq!(scope, second_scope, "replacement listener keeps its scope");
    let (second_handle, second_address) = SessionQuorumConsumerServer::new(
        second_service.clone(),
        pki.server_config(&server_spiffe),
        second_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start replacement consumer listener");
    *resolved_address.write().expect("resolver address lock") = second_address;

    assert_eq!(
        client.capabilities().await,
        Ok(transported_capabilities()),
        "the same client must reconnect through the replacement address"
    );
    assert_eq!(second_service.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "each new consumer connection must invoke the resolver"
    );
    second_handle.abort_and_wait().await;
}

#[tokio::test]
async fn pre_request_connection_budget_expires_during_a_stalled_tls_handshake() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("pre-request-stalled-server");
    let client_spiffe = spiffe("pre-request-stalled-client");
    let (_authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled TLS listener");
    let address = listener.local_addr().expect("stalled listener address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let stalled_tls = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept TLS client");
            accepted.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(address) })),
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(100))
    .with_operation_timeout(Duration::from_secs(1));

    let started_at = tokio::time::Instant::now();
    let outcome = client
        .delete_fenced_with_id(SessionConsumerRequestId::new(), test_lease().await)
        .await;
    let elapsed = started_at.elapsed();
    assert!(matches!(
        outcome,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert!(
        elapsed < Duration::from_millis(500),
        "the pre-request budget must expire before the complete operation deadline"
    );
    stalled_tls.abort();
}

#[tokio::test]
async fn v2_pre_request_connection_budget_expires_after_hello_before_hello_ack() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("v2-pre-request-stalled-server");
    let client_spiffe = spiffe("v2-pre-request-stalled-client");
    let (_authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled V2 TLS listener");
    let address = listener.local_addr().expect("stalled V2 listener address");
    let hello_seen = Arc::new(AtomicUsize::new(0));
    let authenticated = pki.server_config(&server_spiffe);
    let stalled_hello_ack = {
        let hello_seen = Arc::clone(&hello_seen);
        tokio::spawn(async move {
            let mut tls = accept_v2_tls(&listener, &authenticated).await;
            let hello = read_json_frame(&mut tls).await;
            assert_eq!(hello["kind"], "hello");
            hello_seen.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        })
    };
    let client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    )
    .with_pre_request_connection_timeout(Duration::from_millis(100))
    .with_operation_timeout(Duration::from_secs(1));
    let request = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Capability,
    );

    let started_at = tokio::time::Instant::now();
    assert_eq!(
        client.execute_v2(&request).await,
        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        }),
        "setup expiry through HelloAck remains proven not transmitted"
    );
    assert_eq!(hello_seen.load(Ordering::SeqCst), 1);
    assert!(
        started_at.elapsed() < Duration::from_millis(500),
        "the V2 setup deadline does not consume the operation response budget"
    );
    stalled_hello_ack.abort();
}

#[tokio::test]
async fn pre_request_connection_budget_leaves_time_for_a_healthy_later_roster_endpoint() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("pre-request-roster-server");
    let client_spiffe = spiffe("pre-request-roster-client");
    let (_first_authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let stalled_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled TLS listener");
    let stalled_address = stalled_listener
        .local_addr()
        .expect("stalled listener address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let stalled_tls = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            let (_stream, _) = stalled_listener
                .accept()
                .await
                .expect("accept stalled TLS client");
            accepted.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        })
    };
    let healthy_service = Arc::new(CountingConsumer::default());
    let (healthy_authorizer, healthy_scope, _healthy_voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    assert_eq!(scope, healthy_scope, "fixed roster retains one scope");
    let (healthy_handle, healthy_address) = SessionQuorumConsumerServer::new(
        healthy_service.clone(),
        pki.server_config(&server_spiffe),
        healthy_authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start healthy consumer listener");

    let resolver_attempts = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolver_attempts = Arc::clone(&resolver_attempts);
        Arc::new(move || {
            let address = if resolver_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                stalled_address
            } else {
                healthy_address
            };
            Box::pin(async move { Ok(address) })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(stalled_address.ip().into()),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(500))
    .with_operation_timeout(Duration::from_secs(2));

    let lease = test_lease().await;
    let started_at = tokio::time::Instant::now();
    let stalled = client
        .delete_fenced_with_id(SessionConsumerRequestId::new(), lease)
        .await;
    assert!(matches!(
        stalled,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.capabilities().await,
        Ok(transported_capabilities()),
        "a later admitted endpoint must remain reachable within the caller window"
    );
    assert_eq!(healthy_service.calls.load(Ordering::SeqCst), 1);
    assert!(
        started_at.elapsed() < Duration::from_millis(1_500),
        "the stalled endpoint must not consume the fixed-roster renewal window"
    );
    stalled_tls.abort();
    healthy_handle.abort_and_wait().await;
}

#[tokio::test]
async fn pre_request_connection_budget_does_not_shorten_post_call_outcome_deadline() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("pre-request-post-call-server");
    let client_spiffe = spiffe("pre-request-post-call-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let hanging = Arc::new(HangingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        hanging.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start hanging consumer listener");
    let request_id = SessionConsumerRequestId::new();
    let client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(address) })),
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(500))
    .with_operation_timeout(Duration::from_secs(1));

    let lease = test_lease().await;
    let started_at = tokio::time::Instant::now();
    let outcome = client.delete_fenced_with_id(request_id, lease).await;
    assert!(matches!(
        outcome,
        Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
            if retry_id == request_id
    ));
    assert_eq!(hanging.calls.load(Ordering::SeqCst), 1);
    assert!(
        started_at.elapsed() >= Duration::from_millis(800),
        "the post-call response wait must retain the full operation deadline"
    );
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn resolver_failure_is_unavailable_and_not_transmitted_for_mutations_and_leases() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("resolver-failure-server");
    let client_spiffe = spiffe("resolver-failure-client");
    let (_authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("resolver failure is redacted"))
            })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
        ),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    );

    let mutation = client
        .delete_fenced_with_id(SessionConsumerRequestId::new(), test_lease().await)
        .await;
    assert!(matches!(
        mutation,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    let lease = client
        .release_with_id(SessionConsumerRequestId::new(), test_lease().await)
        .await;
    assert!(matches!(
        lease,
        Err(SessionConsumerLeaseMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable
        })
    ));
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "each failed request resolves before its application frame is written"
    );
}

#[tokio::test]
async fn deserialized_structurally_invalid_lease_guards_fail_before_resolve_or_effect() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("invalid-guard-server");
    let client_spiffe = spiffe("invalid-guard-client");
    let (_authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("invalid guard must never resolve"))
            })
        })
    };
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
        ),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    );
    let mut encoded = serde_json::to_value(test_lease().await).expect("encode valid lease guard");
    encoded["credential_id"] = serde_json::json!(0);
    let forged: opc_session_store::LeaseGuard =
        serde_json::from_value(encoded).expect("public DTO accepts a structurally forged guard");

    assert!(matches!(
        client
            .delete_fenced_with_id(
                SessionConsumerRequestId::from_bytes([0x91; 16]),
                forged.clone()
            )
            .await,
        Err(SessionConsumerMutationError::NotTransmitted {
            cause: SessionConsumerClientError::Protocol
        })
    ));
    assert_eq!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([0x92; 16]),
                SessionConsumerOperation::Batch {
                    ops: vec![opc_session_store::SessionOp::DeleteFenced { lease: forged }]
                },
            ))
            .await,
        Err(SessionConsumerClientError::Protocol)
    );
    let descriptor = RecordExpiryPreflight::from_record(&StoredSessionRecord {
        key: test_key(),
        generation: Generation::new(1),
        owner: OwnerId::new("invalid-preflight-owner").expect("preflight owner"),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("invalid-preflight"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"opaque-invalid-preflight"),
    });
    for (request_byte, operation) in [
        (
            0x93,
            SessionConsumerOperation::AcquireLease {
                key: test_key(),
                owner: OwnerId::new("invalid-ttl-owner").expect("invalid TTL owner"),
                ttl: opc_session_store::MAX_SESSION_TTL + Duration::from_nanos(1),
            },
        ),
        (
            0x94,
            SessionConsumerOperation::Batch {
                ops: vec![SessionOp::Get { key: test_key() }; 257],
            },
        ),
        (
            0x95,
            SessionConsumerOperation::PreflightRecordExpiry {
                preflights: vec![descriptor; opc_session_store::MAX_RECORD_EXPIRY_PREFLIGHTS + 1],
            },
        ),
        (
            0x96,
            SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest::all(0),
            },
        ),
    ] {
        assert_eq!(
            client
                .execute(SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([request_byte; 16]),
                    operation,
                ))
                .await,
            Err(SessionConsumerClientError::Protocol)
        );
    }
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn outcome_unknown_is_not_replayed_and_consumer_debug_is_redacted() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("debug-server");
    let client_spiffe = spiffe("debug-client");
    let (authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let hanging = Arc::new(HangingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        hanging.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start hanging consumer listener");
    let request_id = SessionConsumerRequestId::from_bytes([0x5a; 16]);
    let client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(address) })),
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));

    let outcome = client
        .delete_fenced_with_id(request_id, test_lease().await)
        .await;
    assert!(matches!(
        &outcome,
        Err(SessionConsumerMutationError::OutcomeUnknown { request_id: retry_id })
            if *retry_id == request_id
    ));
    assert_eq!(
        hanging.calls.load(Ordering::SeqCst),
        1,
        "the client must never replay an application mutation after its outcome is unknown"
    );

    let diagnostic_address = "203.0.113.77:7443"
        .parse::<SocketAddr>()
        .expect("diagnostic address");
    let diagnostic_dns = "voter.state.example";
    let diagnostic_client = StatelessSessionConsumerClient::new_with_resolver(
        Arc::new(move || Box::pin(async move { Ok(diagnostic_address) })),
        rustls_pki_types::ServerName::try_from(diagnostic_dns.to_owned())
            .expect("diagnostic DNS server name"),
        voter_authority.clone(),
        pki.client_config(&client_spiffe),
    );
    let client_debug = format!("{diagnostic_client:?}");
    let outcome_debug = format!("{outcome:?}");
    assert!(!client_debug.contains(&diagnostic_address.to_string()));
    assert!(!client_debug.contains(diagnostic_dns));
    assert!(!client_debug.contains(&server_spiffe));
    assert!(!client_debug.contains(&format!("{scope:?}")));
    assert!(!client_debug.contains("address"));
    assert!(!client_debug.contains("scope"));
    assert!(!outcome_debug.contains(&format!("{request_id:?}")));
    assert!(!outcome_debug.contains("request_id"));
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn lease_call_boundary_classifies_before_and_after_transmission() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let admitted_spiffe = spiffe("admitted");
    let rejected_spiffe = spiffe("rejected");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&admitted_spiffe, &server_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");

    let request_id = SessionConsumerRequestId::new();
    let rejected = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &rejected_spiffe,
        voter_authority,
    )
    .release_with_id(request_id, test_lease().await)
    .await;
    assert!(
        matches!(
            &rejected,
            Err(SessionConsumerLeaseMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Authentication
                    | SessionConsumerClientError::Unavailable
            })
        ),
        "unexpected pre-call result: {rejected:?}"
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;

    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&admitted_spiffe, &server_spiffe).await;
    let hanging = Arc::new(HangingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        hanging.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start hanging consumer listener");
    let uncertain = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &admitted_spiffe,
        voter_authority,
    )
    .with_operation_timeout(Duration::from_secs(1))
    .release_with_id(request_id, test_lease().await)
    .await;
    assert!(matches!(
        uncertain,
        Err(SessionConsumerLeaseMutationError::OutcomeUnknown {
            request_id: retry_id
        }) if retry_id == request_id
    ));
    assert_eq!(hanging.calls.load(Ordering::SeqCst), 1);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn twelve_concurrent_stateless_consumers_remain_outside_member_authority() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffes = (0..12)
        .map(|index| spiffe(&format!("concurrent-{index}")))
        .collect::<Vec<_>>();
    let (_snapshots, _store, _scope, voter_authority, authorizer) =
        admitted_store_and_authorizer(client_spiffes.clone(), &server_spiffe).await;
    assert!(format!("{authorizer:?}").contains("consensus_member_count: 1"));

    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");
    let clients = client_spiffes
        .iter()
        .map(|client_spiffe| {
            consumer_client(
                &pki,
                address,
                &server_spiffe,
                client_spiffe,
                voter_authority.clone(),
            )
        })
        .collect::<Vec<_>>();

    let results =
        futures_util::future::join_all(clients.iter().map(|client| client.capabilities())).await;
    assert!(results
        .iter()
        .all(|result| result == &Ok(transported_capabilities())));
    assert_eq!(service.calls.load(Ordering::SeqCst), 12);
    for client in clients {
        let diagnostic = format!("{client:?}");
        assert!(!diagnostic.contains("127.0.0.1"));
        assert!(!diagnostic.contains("concurrent-"));
        assert!(!diagnostic.contains("snapshot"));
        assert!(!diagnostic.contains("replica"));
    }
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn consumer_mtls_role_identity_and_server_identity_mismatches_fail_closed() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let admitted_spiffe = spiffe("admitted");
    let member_spiffe = spiffe("member");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&admitted_spiffe, &server_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");

    let unknown_consumer = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &spiffe("not-admitted"),
        voter_authority.clone(),
    );
    assert_eq!(
        unknown_consumer.capabilities().await,
        Err(SessionConsumerClientError::Unavailable),
        "the listener must close an unauthorized authenticated connection without a role oracle"
    );

    let consensus_member_as_consumer = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &member_spiffe,
        voter_authority.clone(),
    );
    assert_eq!(
        consensus_member_as_consumer.capabilities().await,
        Err(SessionConsumerClientError::Unavailable),
        "a consensus-member certificate must not receive a consumer-role oracle"
    );

    let (_wrong_authorizer, _wrong_scope, wrong_voter_authority) =
        authorizer_from_admitted_store(&admitted_spiffe, &spiffe("different-server")).await;
    let wrong_server_identity = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &admitted_spiffe,
        wrong_voter_authority,
    );
    assert_eq!(
        wrong_server_identity.capabilities().await,
        Err(SessionConsumerClientError::Authentication)
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn protected_roster_client_rejects_general_capabilities_before_transport() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("protected-roster-local-gate-server");
    let client_spiffe = spiffe("protected-roster-local-gate-client");
    let (_authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other(
                    "protected-roster Capabilities must never resolve",
                ))
            })
        })
    };
    let client = PersistentSessionConsumerClient::try_from_fenced_mutation_roster_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
            ),
            voter_authority,
            pki.client_config(&client_spiffe),
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("protected-roster local-gate client");

    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Protocol),
        "the protected lane must reject general Capabilities before transport"
    );
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_attempts, 0);
    assert_eq!(diagnostics.resolve_attempts, 0);
    assert_eq!(diagnostics.tcp_attempts, 0);
    assert_eq!(diagnostics.tls_attempts, 0);
    client.shutdown().await;
}

#[tokio::test]
async fn protected_roster_mtls_identity_and_server_identity_mismatches_fail_closed() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("protected-roster-server");
    let admitted_spiffe = spiffe("protected-roster-admitted");
    let member_spiffe = server_spiffe.clone();
    let (authorizer, scope, voter_authority) =
        authorizer_from_admitted_store(&admitted_spiffe, &server_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let cluster = ConsensusClusterId::new("protected-roster-handshake-only")
        .expect("protected-roster handshake cluster");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("protected-roster handshake epoch");
    let issuer = ProductionRosterAttestationIssuer::new(
        SessionConsensusIdentity::new(cluster, derive_configuration_id(cluster, epoch, &[]), epoch),
        scope,
    );
    let roster_ingress = Arc::new(HandshakeOnlySessionQuorumRosterIngress::new(
        RosterIngressSigner::trust_root(issuer.as_ref()).identity(),
    ));
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_roster_ingress(roster_ingress.clone(), issuer.clone())
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start protected-roster consumer listener");

    for (label, client_spiffe) in [
        (
            "foreign tenant A",
            tenant_spiffe("protected-roster-foreign-a", "consumer"),
        ),
        (
            "foreign tenant B",
            tenant_spiffe("protected-roster-foreign-b", "consumer"),
        ),
        ("consensus member", member_spiffe),
    ] {
        let client = protected_roster_persistent_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            voter_authority.clone(),
        );
        assert_eq!(
            client.prewarm().await,
            Err(SessionConsumerClientError::Unavailable),
            "{label} must not receive a protected-roster role oracle"
        );
        assert!(
            client.diagnostics().await.tls_attempts > 0,
            "{label} protected-roster prewarm must attempt mTLS"
        );
        client.shutdown().await;
    }

    let (_wrong_authorizer, _wrong_scope, wrong_voter_authority) =
        authorizer_from_admitted_store(&admitted_spiffe, &spiffe("different-protected-server"))
            .await;
    let wrong_server_identity = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &admitted_spiffe,
        wrong_voter_authority,
    );
    assert_eq!(
        wrong_server_identity.prewarm().await,
        Err(SessionConsumerClientError::Authentication),
        "a wrong protected-roster expected server identity must fail authentication"
    );
    assert!(
        wrong_server_identity.diagnostics().await.tls_attempts > 0,
        "wrong protected-roster expected server identity must attempt mTLS"
    );
    wrong_server_identity.shutdown().await;
    handle.abort_and_wait().await;
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    assert_eq!(roster_ingress.calls(), 0);
}

#[tokio::test]
async fn protected_roster_prewarm_rejects_a_listener_without_roster_ingress() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("protected-roster-missing-ingress-server");
    let client_spiffe = spiffe("protected-roster-missing-ingress-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start /1-only consumer listener");
    let client = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );

    assert_eq!(
        client.prewarm().await,
        Err(SessionConsumerClientError::Protocol),
        "a protected-roster prewarm must reject a /1-only listener"
    );
    assert!(
        client.diagnostics().await.tls_attempts > 0,
        "a protected-roster prewarm must attempt mTLS before rejecting /1-only"
    );
    client.shutdown().await;
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn malformed_and_oversized_consumer_frames_are_rejected_before_dispatch() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffe = spiffe("client");
    let (authorizer, scope, _voter_authority) =
        authorizer_from_admitted_store(&client_spiffe, &server_spiffe).await;
    let service = Arc::new(CountingConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start stateless consumer listener");

    // A frozen revision-4 peer completes the same mTLS and ALPN handshake as a
    // real caller, but must be closed before application dispatch. There is no
    // downgrade or upgrade oracle at this boundary.
    let mut wrong_revision =
        raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    let wrong_hello = serde_json::to_vec(&serde_json::json!({
        "kind": "hello",
        "body": {
            "transport_revision": 4_u16,
            "scope": scope,
            "response_frame_size": opc_session_net::MAX_NEGOTIATED_FRAME_SIZE,
        },
    }))
    .expect("wrong revision hello encodes");
    wrong_revision
        .write_all(
            &u32::try_from(wrong_hello.len())
                .expect("wrong revision hello fits frame")
                .to_be_bytes(),
        )
        .await
        .expect("write wrong revision prefix");
    wrong_revision
        .write_all(&wrong_hello)
        .await
        .expect("write wrong revision hello");
    wrong_revision
        .flush()
        .await
        .expect("flush wrong revision hello");
    let mut response = [0_u8; 1];
    let wrong_revision_result =
        tokio::time::timeout(Duration::from_secs(1), wrong_revision.read(&mut response))
            .await
            .expect("wrong revision connection closes promptly");
    assert!(matches!(wrong_revision_result, Err(_) | Ok(0)));

    let mut malformed = raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    malformed
        .write_all(&[0, 0, 0, 1, b'{'])
        .await
        .expect("write malformed consumer frame");
    let malformed_result =
        tokio::time::timeout(Duration::from_secs(1), malformed.read(&mut response))
            .await
            .expect("malformed frame connection closes promptly");
    assert!(matches!(malformed_result, Err(_) | Ok(0)));

    let mut oversized = raw_authenticated_consumer_connection(&pki, address, &client_spiffe).await;
    oversized
        .write_all(&((16 * 1024 * 1024 + 1) as u32).to_be_bytes())
        .await
        .expect("write oversized consumer frame prefix");
    let oversized_result =
        tokio::time::timeout(Duration::from_secs(1), oversized.read(&mut response))
            .await
            .expect("oversized frame connection closes promptly");
    assert!(matches!(oversized_result, Err(_) | Ok(0)));
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn durable_consumer_request_ids_deduplicate_lease_races_and_fence_stale_owners() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("server");
    let client_spiffe = spiffe("lease-client");
    let (_snapshots, store, scope, voter_authority, authorizer) =
        admitted_store_and_authorizer([client_spiffe.clone()], &server_spiffe).await;
    let service = Arc::new(store.consumer_service());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start durable consumer listener");
    let client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );
    let first_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes([1; 16]),
        SessionConsumerOperation::AcquireLease {
            key: test_key(),
            owner: OwnerId::new("first-owner").expect("first owner"),
            ttl: Duration::from_secs(30),
        },
    );
    let second_request = SessionConsumerRequest::new(
        scope,
        SessionConsumerRequestId::from_bytes([2; 16]),
        SessionConsumerOperation::AcquireLease {
            key: test_key(),
            owner: OwnerId::new("second-owner").expect("second owner"),
            ttl: Duration::from_secs(30),
        },
    );
    let (first, second) = tokio::join!(
        client.execute(first_request.clone()),
        client.execute(second_request.clone())
    );
    let first = first.expect("first lease response");
    let second = second.expect("second lease response");
    assert_eq!(
        [first.clone(), second.clone()]
            .iter()
            .filter(|response| matches!(response, SessionConsumerResponse::AcquireLease(Ok(_))))
            .count(),
        1,
        "only one concurrent stateless consumer request may acquire the lease"
    );
    assert_eq!(
        [first.clone(), second.clone()]
            .iter()
            .filter(|response| {
                matches!(
                    response,
                    SessionConsumerResponse::AcquireLease(Err(
                        SessionConsumerLeaseError::AlreadyHeld
                    ))
                )
            })
            .count(),
        1
    );

    let (winner_request, winner_response) =
        if matches!(first, SessionConsumerResponse::AcquireLease(Ok(_))) {
            (first_request, first)
        } else {
            (second_request, second)
        };
    assert_eq!(
        client
            .execute(winner_request.clone())
            .await
            .expect("exact durable request retry"),
        winner_response,
        "a retained consumer request ID must replay only its prior durable result"
    );
    let lease = match winner_response {
        SessionConsumerResponse::AcquireLease(Ok(guard)) => guard,
        _ => unreachable!("winner response is an acquired lease"),
    };
    let conflicting_reuse = SessionConsumerRequest::new(
        scope,
        winner_request.request_id(),
        SessionConsumerOperation::AcquireLease {
            key: test_key(),
            owner: OwnerId::new("conflicting-owner").expect("conflicting owner"),
            ttl: Duration::from_secs(30),
        },
    );
    assert!(matches!(
        client.execute(conflicting_reuse).await,
        Ok(SessionConsumerResponse::AcquireLease(Err(
            SessionConsumerLeaseError::RequestConflict
        )))
    ));

    assert!(matches!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([3; 16]),
                SessionConsumerOperation::ReleaseLease {
                    lease: lease.clone()
                },
            ))
            .await,
        Ok(SessionConsumerResponse::ReleaseLease(Ok(())))
    ));
    assert!(matches!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([4; 16]),
                SessionConsumerOperation::AcquireLease {
                    key: test_key(),
                    owner: OwnerId::new("successor-owner").expect("successor owner"),
                    ttl: Duration::from_secs(30),
                },
            ))
            .await,
        Ok(SessionConsumerResponse::AcquireLease(Ok(_)))
    ));
    assert!(matches!(
        client
            .execute(SessionConsumerRequest::new(
                scope,
                SessionConsumerRequestId::from_bytes([5; 16]),
                SessionConsumerOperation::RenewLease {
                    lease,
                    ttl: Duration::from_secs(30),
                },
            ))
            .await,
        Ok(SessionConsumerResponse::RenewLease(Err(
            SessionConsumerLeaseError::StaleFence
        )))
    ));
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn stateless_and_persistent_consumers_accept_shorter_and_zero_ttl_renewals() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("renewal-server");
    let client_spiffe = spiffe("renewal-client");
    let (_snapshots, store, _scope, voter_authority, authorizer) =
        admitted_store_and_authorizer([client_spiffe.clone()], &server_spiffe).await;
    let service = Arc::new(store.consumer_service());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start renewal consumer listener");
    let stateless = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );

    let original = stateless
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0x81; 16]),
            test_key(),
            OwnerId::new("renewal-owner").expect("renewal owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire thirty-second lease");
    let shortened = stateless
        .renew_with_id(
            SessionConsumerRequestId::from_bytes([0x82; 16]),
            original.clone(),
            Duration::from_secs(7),
        )
        .await
        .expect("stateless renewal may shorten a live lease");
    assert!(shortened.expires_at() < original.expires_at());

    let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
        .expect("valid persistent configuration");
    let zero = persistent
        .renew_with_id(
            SessionConsumerRequestId::from_bytes([0x83; 16]),
            &shortened,
            Duration::ZERO,
        )
        .await
        .expect("persistent renewal accepts the valid zero TTL boundary");
    assert!(zero.expires_at() <= shortened.expires_at());
    assert_eq!(zero.key(), shortened.key());
    assert_eq!(zero.owner(), shortened.owner());
    assert_eq!(zero.fence(), shortened.fence());

    persistent.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_three_voter_first_transition_has_one_leader_activation_proof() {
    // Two leader probes are delayed together for four seconds.  That leaves
    // the normal ten-second operation deadline ample room for the one
    // authoritative leader proof.  Before the regression fix, the follower
    // spent eight seconds on a discarded local barrier+unanimity proof and
    // the same operation then timed out before the leader's activation proof.
    let pki = Arc::new(TestPki::new());
    let fleet =
        ThreeVoterConsumerFleet::start(Arc::clone(&pki), Some(Duration::from_secs(4))).await;
    let (leader, _, _) = fleet.observed_leader();
    let follower = (leader + 1) % THREE_VOTER_COUNT;
    let server_spiffe = three_voter_spiffe(follower);
    let client_spiffe = spiffe("three-voter-first-proof-client");
    let manifest = fleet.stores[follower]
        .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(&client_spiffe).expect("first-proof client SPIFFE"),
            [SessionConsumerTenantNfScope::new(
                TenantId::new("consumer-test").expect("tenant"),
                NetworkFunctionKind::smf(),
            )],
        )
        .expect("first-proof explicit consumer grant")])
        .await
        .expect("first-proof consumer manifest");
    let _scope = manifest.scope();
    let authorizer =
        SessionConsumerAuthorizer::try_new(manifest).expect("first-proof consumer authorizer");
    let voter_authority = fleet.voter_authority(follower);
    let (server, address) = SessionQuorumConsumerServer::new(
        Arc::new(fleet.stores[follower].consumer_service()),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("first-proof listener"),
    )
    .await
    .expect("start first-proof listener");
    let server = AbortConsumerServerOnDrop::new(server);
    let persistent = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            Arc::new(move || Box::pin(async move { Ok(address) })),
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            voter_authority,
            pki.client_config(&client_spiffe),
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("persistent first-proof client");
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xa4; 16]),
        FencedTransitionLease::acquire(
            test_key(),
            OwnerId::new("x").expect("first-proof owner"),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .expect("first-proof lease"),
        // A physical delete is valid without a payload envelope.  Its absent
        // generation records a deterministic no-effect receipt, which keeps
        // this focused proof regression independent from the protected-token
        // path covered by the response-loss test below.
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("first-proof physical transition");
    let before = fleet.stores[follower]
        .max_replication_sequence()
        .await
        .expect("application sequence before first transition");
    fleet.reset_read_barrier_calls();

    let outcome = persistent
        .fenced_transition(&request)
        .await
        .expect_err("absent delete returns its committed deterministic result");
    assert!(matches!(
        outcome,
        opc_session_net::SessionConsumerFencedTransitionMutationError::Store(_)
    ));
    assert_eq!(
        2,
        fleet.read_barrier_calls(),
        "only the elected leader sends the two fresh unanimous activation probes"
    );
    let status = persistent
        .fenced_transition_status(&request)
        .await
        .expect("first transition has one durable receipt");
    assert!(matches!(
        status,
        opc_session_store::SessionConsumerFencedTransitionStatus::Recorded(ref result)
            if result.as_ref().is_err()
    ));
    assert_eq!(
        before,
        fleet.stores[leader]
            .max_replication_sequence()
            .await
            .expect("application sequence after first transition"),
        "the committed no-effect receipt, its activation proof, and its lookup do not fabricate a user mutation"
    );
    persistent.shutdown().await;
    server.abort_and_wait().await;
    fleet.shutdown().await;
}

#[tokio::test]
async fn persistent_three_voter_consumer_write_does_not_spend_budget_on_a_read_quorum() {
    // An authenticated consumer mutation is linearized by its Raft write. A
    // separate read quorum before that write can consume the entire cellular
    // hot-path budget even though the write quorum itself is healthy.
    let operation_budget = Duration::from_millis(250);
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start(
        Arc::clone(&pki),
        Some(operation_budget + Duration::from_millis(50)),
    )
    .await;
    let (leader, _, _) = fleet.observed_leader();
    let follower = (leader + 1) % THREE_VOTER_COUNT;
    let server_spiffe = three_voter_spiffe(follower);
    let client_spiffe = spiffe("ordinary-write-hot-path-client");
    let (server, address) = SessionQuorumConsumerServer::new(
        Arc::new(fleet.stores[follower].consumer_service()),
        pki.server_config(&server_spiffe),
        three_voter_authorizer(&fleet.stores[follower], &client_spiffe).await,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("ordinary-write listener"),
    )
    .await
    .expect("start ordinary-write listener");
    let persistent = PersistentSessionConsumerClient::try_from_stateless(
        consumer_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            fleet.voter_authority(follower),
        )
        .with_operation_timeout(operation_budget),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("persistent ordinary-write client");

    assert!(
        persistent.capabilities().await.is_ok(),
        "warm and authenticate the persistent connection before measuring the mutation"
    );
    fleet.reset_read_barrier_calls();
    fleet.set_prewrite_empty_append_entries_delay(true);
    let started = Instant::now();
    let key = test_key();
    let owner = OwnerId::new("ordinary-write-hot-path-owner").expect("ordinary-write owner");
    let lease = persistent
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0xa5; 16]),
            &key,
            &owner,
            Duration::from_secs(30),
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "one healthy write quorum must fit inside the operation budget: {error:?}; delayed empty AppendEntries={}",
                fleet.prewrite_empty_append_entries_calls()
            )
        });
    let mutation_elapsed = started.elapsed();
    fleet.set_prewrite_empty_append_entries_delay(false);
    let observation_deadline = Instant::now() + Duration::from_secs(1);
    while !fleet.append_entries_observation().2 && Instant::now() < observation_deadline {
        tokio::task::yield_now().await;
    }
    assert!(
        mutation_elapsed < operation_budget,
        "ordinary consumer write exceeded its complete operation budget"
    );
    assert_eq!(
        fleet.prewrite_empty_append_entries_calls(),
        0,
        "the mutation must not issue a separate pre-write empty-AppendEntries quorum round"
    );
    let (decoded, decode_failures, nonempty_seen) = fleet.append_entries_observation();
    assert!(
        decoded > 0,
        "the fixture must observe real AppendEntries traffic"
    );
    assert_eq!(
        decode_failures, 0,
        "the fixture must fail rather than silently ignore an undecodable AppendEntries payload"
    );
    assert!(
        nonempty_seen,
        "the fixture must observe the actual Raft write, not pass without replication"
    );
    assert_eq!(lease.key(), &key);

    persistent.shutdown().await;
    server.abort_and_wait().await;
}

#[tokio::test]
async fn protected_consumer_chain_after_activation_elides_outer_capability_wire_calls() {
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start(Arc::clone(&pki), None).await;
    let (leader, _, _) = fleet.observed_leader();
    let follower = (leader + 1) % THREE_VOTER_COUNT;

    // This is the state-voter startup action ePDG performs before the
    // consumer listener becomes Ready. It commits the exact-scope certificate
    // once and the selected forwarding voter has locally observed it before
    // this test exposes the protected SWm chain.
    fleet.stores[follower]
        .activate_fenced_transition_capability()
        .await
        .expect("activate V1 before protected consumer readiness");
    fleet.wait_all_ready().await;
    let client_spiffe = spiffe("protected-warmed-transition-client");

    // A worker is a separate process from all state voters. Give it one
    // authenticated persistent client per public state-voter listener, then
    // require the concrete physical adapter to prewarm all three exact
    // bindings before it may be constructed.
    let mut servers = Vec::with_capacity(THREE_VOTER_COUNT);
    let mut addresses = Vec::with_capacity(THREE_VOTER_COUNT);
    let mut counted_services = Vec::with_capacity(THREE_VOTER_COUNT);
    for index in 0..THREE_VOTER_COUNT {
        let counted = Arc::new(CountingFencedConsumerOperations::new(Arc::new(
            fleet.stores[index].consumer_service(),
        )));
        let (server, address) = SessionQuorumConsumerServer::new(
            Arc::clone(&counted) as Arc<dyn SessionQuorumConsumer>,
            pki.server_config(&three_voter_spiffe(index)),
            three_voter_authorizer(&fleet.stores[index], &client_spiffe).await,
        )
        .listen(
            "127.0.0.1:0"
                .parse::<SocketAddr>()
                .expect("protected warmed listener"),
        )
        .await
        .expect("start protected warmed listener");
        servers.push(server);
        addresses.push(address);
        counted_services.push(counted);
    }
    let persistent_voters = addresses
        .iter()
        .copied()
        .enumerate()
        .map(|(index, address)| {
            PersistentSessionConsumerClient::try_from_stateless(
                StatelessSessionConsumerClient::new_with_resolver(
                    Arc::new(move || Box::pin(async move { Ok(address) })),
                    rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                    fleet.voter_authority(index),
                    pki.client_config(&client_spiffe),
                ),
                PersistentSessionConsumerConfig::default(),
            )
            .expect("persistent protected voter consumer")
        })
        .collect::<Vec<_>>();

    let foreign_client_spiffe = spiffe("protected-warmed-foreign-client");
    let follower_address = addresses[follower];
    let foreign_identity = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            Arc::new(move || Box::pin(async move { Ok(follower_address) })),
            rustls_pki_types::ServerName::IpAddress(follower_address.ip().into()),
            fleet.voter_authority(follower),
            pki.client_config(&foreign_client_spiffe),
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("foreign-identity persistent consumer");
    assert!(
        SessionConsumerFencedTransitionBackend::persistent_exact_voter_prewarm_backends(
            persistent_voters[..THREE_VOTER_COUNT - 1].iter().cloned(),
        )
        .await
        .is_err(),
        "a missing exact voter cannot make a worker Ready"
    );
    let mut duplicate_voters = persistent_voters.clone();
    duplicate_voters[follower] = duplicate_voters[leader].clone();
    assert!(
        SessionConsumerFencedTransitionBackend::persistent_exact_voter_prewarm_backends(
            duplicate_voters,
        )
        .await
        .is_err(),
        "a duplicate voter cannot be substituted for the exact roster"
    );
    let mut changed_identity_voters = persistent_voters.clone();
    changed_identity_voters[follower] = foreign_identity;
    assert!(
        SessionConsumerFencedTransitionBackend::persistent_exact_voter_prewarm_backends(
            changed_identity_voters,
        )
        .await
        .is_err(),
        "a changed local SPIFFE identity cannot be substituted into the exact worker roster"
    );
    assert_eq!(
        0,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "semantic roster validation fails before any capability RPC"
    );
    let journal_directory = tempfile::tempdir().expect("protected warmed journal directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            journal_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make protected warmed journal directory private");
    }
    let journal = Arc::new(
        PreparedFencedTransitionJournal::create_new(
            journal_directory.path().join("prepared.sqlite"),
            PreparedFencedTransitionJournalKey::from_bytes([0x44; 32]),
        )
        .expect("create protected warmed journal"),
    );
    let mut physical_backends =
        SessionConsumerFencedTransitionBackend::persistent_exact_voter_prewarm_backends(
            persistent_voters.clone(),
        )
        .await
        .expect("prewarmed authenticated physical consumer backends");
    assert_eq!(
        THREE_VOTER_COUNT,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "worker prewarm makes exactly one authenticated capability query per exact voter"
    );
    for backend in &physical_backends {
        assert_eq!(
            Some(AtomicFencedTransitionCapability::V1),
            backend
                .fenced_transition_capability()
                .await
                .expect("each prewarmed adapter has a local V1 readiness result")
        );
    }
    assert_eq!(
        THREE_VOTER_COUNT,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "every returned adapter shares the one exact roster prewarm"
    );
    let physical = Arc::new(physical_backends.remove(follower));
    let outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            physical,
            CountingKeyProvider::with_active_session_key(),
            "protected-warmed-consumer-chain",
        )
        .with_fenced_transition_journal(journal),
    );

    let before_proposal = fleet.stores[leader]
        .status()
        .last_log_index
        .expect("activation log index");
    fleet.reset_read_barrier_calls();
    let prepared = outer
        .prepare_fenced_transition(fenced_create_request(0xC2))
        .await
        .expect("prepare exact protected physical token without a capability RPC");
    assert_eq!(
        THREE_VOTER_COUNT,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "prepare relies on exact token construction, journal health, and pre-Ready readiness"
    );

    tokio::time::timeout(
        Duration::from_millis(100),
        outer.fenced_transition(&prepared),
    )
    .await
    .expect("prewarmed follower route reaches the elected voter inside the caller budget")
    .expect("one real protected physical transition");
    assert_eq!(
        1,
        counted_services[follower]
            .transition_calls
            .load(Ordering::SeqCst),
        "the exact protected token reaches the concrete consumer boundary once"
    );
    assert_eq!(
        THREE_VOTER_COUNT,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "activated V1 execute must not add a standalone capability wire call before its P1 write quorum"
    );
    assert_eq!(
        0,
        fleet.read_barrier_calls(),
        "activated V1 adds no B1/read-index; its one P1 Raft write quorum is the linearization point"
    );
    assert_eq!(
        Some(before_proposal + 1),
        fleet.stores[leader].status().last_log_index,
        "the warmed physical transition appends exactly one proposal"
    );

    let before_status_log = fleet.stores[leader].status().last_log_index;
    let before_status_barriers = fleet.read_barrier_calls();
    assert!(matches!(
        outer
            .fenced_transition_status(&prepared)
            .await
            .expect("read exact retained protected receipt"),
        FencedTransitionStatus::Recorded(ref outcome) if outcome.is_ok()
    ));
    assert_eq!(
        1,
        counted_services[follower]
            .status_calls
            .load(Ordering::SeqCst),
        "status reaches its separate bounded receipt lookup once"
    );
    assert_eq!(
        THREE_VOTER_COUNT,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "status remains a read-only receipt lookup without a capability wire call"
    );
    assert_eq!(
        before_status_barriers + 1,
        fleet.read_barrier_calls(),
        "status retains one bounded forwarded leader-linearized read"
    );
    assert_eq!(
        before_status_log,
        fleet.stores[leader].status().last_log_index,
        "status remains read-only and never appends a proposal"
    );
    let warm_prepared = outer
        .prepare_fenced_transition(fenced_create_request_with_identity(
            0xC3,
            [0x72; 16],
            b"opaque-session-reference-warm",
        ))
        .await
        .expect("prepare a distinct already-warm protected transition");
    outer
        .fenced_transition(&warm_prepared)
        .await
        .expect("second protected physical transition");
    assert_eq!(
        Some(before_proposal + 2),
        fleet.stores[leader].status().last_log_index,
        "each protected transition has exactly one durable proposal"
    );
    assert_eq!(
        2,
        counted_services[follower]
            .transition_calls
            .load(Ordering::SeqCst),
        "both first and already-warm transitions cross the concrete follower boundary once"
    );
    persistent_voters[follower]
        .request_reauthentication()
        .expect("rotate same semantic client identity");
    assert!(
        outer
            .fenced_transition_capability()
            .await
            .expect("same-SPIFFE reauthentication preserves local readiness")
            .is_some(),
        "the outer protected wrapper preserves its own capability refinement"
    );
    assert_eq!(
        THREE_VOTER_COUNT,
        counted_services
            .iter()
            .map(|service| service.capability_calls.load(Ordering::SeqCst))
            .sum::<usize>(),
        "same-SPIFFE reauthentication does not turn into a hot-path capability call"
    );
    assert_eq!(
        2,
        counted_services[follower]
            .transition_calls
            .load(Ordering::SeqCst),
        "the reauthentication proof remains prepare-only"
    );
    for client in persistent_voters {
        client.shutdown().await;
    }
    for server in servers {
        server.abort_and_wait().await;
    }
}

#[cfg(feature = "test-control")]
#[tokio::test]
async fn prepared_cas_three_voter_receipt_converges_after_real_commit_and_lost_response() {
    prepared_cas_three_voter_receipt_converges_with_payload(
        EncryptedSessionPayload::new([0xc5]),
        Duration::from_millis(100),
    )
    .await;
}

async fn prepared_cas_three_voter_receipt_converges_with_payload(
    payload: EncryptedSessionPayload,
    physical_attempt_timeout: Duration,
) {
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start(Arc::clone(&pki), None).await;
    let client_spiffe = spiffe("prepared-cas-three-voter-client");
    let a_spiffe = three_voter_spiffe(0);
    let c_spiffe = three_voter_spiffe(2);
    let status_a = Arc::new(CountingPreparedCasStatusConsumer {
        inner: Arc::new(fleet.stores[0].consumer_service()),
        status_calls: AtomicUsize::new(0),
    });
    let (a_server, a_address) = SessionQuorumConsumerServer::new(
        Arc::clone(&status_a) as Arc<dyn SessionQuorumConsumer>,
        pki.server_config(&a_spiffe),
        three_voter_authorizer(&fleet.stores[0], &client_spiffe).await,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("A listener"))
    .await
    .expect("start A listener");
    let c_loss = Arc::new(CommitThenLosePreparedCasResponse::new(Arc::new(
        fleet.stores[2].consumer_service(),
    )));
    let (c_server, c_address) = SessionQuorumConsumerServer::new(
        Arc::clone(&c_loss) as Arc<dyn SessionQuorumConsumer>,
        pki.server_config(&c_spiffe),
        three_voter_authorizer(&fleet.stores[2], &client_spiffe).await,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("C listener"))
    .await
    .expect("start C listener");

    let a_calls = Arc::new(AtomicUsize::new(0));
    let a_resolver: RemoteAddrResolver = {
        let calls = Arc::clone(&a_calls);
        Arc::new(move || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if call == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "A pre-write",
                    ))
                } else {
                    Ok(a_address)
                }
            })
        })
    };
    let b_calls = Arc::new(AtomicUsize::new(0));
    let b_resolver: RemoteAddrResolver = {
        let calls = Arc::clone(&b_calls);
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "B pre-write",
                ))
            })
        })
    };
    let c_calls = Arc::new(AtomicUsize::new(0));
    let c_resolver: RemoteAddrResolver = {
        let calls = Arc::clone(&c_calls);
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(c_address) })
        })
    };
    let server_name = rustls_pki_types::ServerName::IpAddress(a_address.ip().into());
    let client_a = PersistentSessionConsumerClient::from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            a_resolver,
            server_name.clone(),
            fleet.voter_authority(0),
            pki.client_config(&client_spiffe),
        ),
    )
    .expect("A persistent client");
    let client_b = PersistentSessionConsumerClient::from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            b_resolver,
            server_name.clone(),
            fleet.voter_authority(1),
            pki.client_config(&client_spiffe),
        ),
    )
    .expect("B persistent client");
    let client_c = PersistentSessionConsumerClient::from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            c_resolver,
            server_name,
            fleet.voter_authority(2),
            pki.client_config(&client_spiffe),
        ),
    )
    .expect("C persistent client");
    let key = test_key();
    let owner = OwnerId::new("prepared-cas-three-voter-owner").expect("owner");
    let lease = fleet.stores[2]
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .expect("real quorum lease");
    let before = fleet.stores[2]
        .max_replication_sequence()
        .await
        .expect("sequence before CAS");
    let expired_provider = CountingKeyProvider::with_active_session_key();
    let expired_wrapper = Arc::new(EncryptingSessionBackend::new(
        Arc::new(fleet.stores[2].clone()),
        Arc::clone(&expired_provider),
        "prepared-cas-three-voter",
    ));
    let expired = SessionConsumerPreparedCheckpointBackend::persistent(
        expired_wrapper,
        [client_a.clone(), client_b.clone(), client_c.clone()],
    )
    .expect("distinct same-scope protected composite");
    assert!(
        matches!(
            expired
                .prepare_compare_and_set(
                    SessionConsumerRequestId::from_bytes([0xc4; 16]),
                    CompareAndSet {
                        key: key.clone(),
                        lease: lease.clone(),
                        expected_generation: None,
                        new_record: StoredSessionRecord {
                            key: key.clone(),
                            generation: Generation::new(1),
                            owner: owner.clone(),
                            fence: lease.fence(),
                            state_class: StateClass::AuthoritativeSession,
                            state_type: StateType::from_static("prepared-cas-three-voter"),
                            expires_at: None,
                            payload: EncryptedSessionPayload::new([0xc4]),
                        },
                    },
                    PreparedCheckpointBudget::new(
                        tokio::time::Instant::now() - Duration::from_millis(1),
                        Duration::from_millis(25),
                    )
                    .expect("explicit expired physical budget"),
                )
                .await,
            Err(PreparedCompareAndSetPrepareError::NotTransmitted)
        ),
        "an expired original deadline reaches neither preflight nor seal"
    );
    assert_eq!(
        expired_provider.calls(),
        0,
        "expired prepare performs no KMS call"
    );
    let provider = CountingKeyProvider::with_active_session_key();
    let protected_wrapper = Arc::new(EncryptingSessionBackend::new(
        Arc::new(fleet.stores[2].clone()),
        Arc::clone(&provider),
        "prepared-cas-three-voter",
    ));
    let protected = SessionConsumerPreparedCheckpointBackend::persistent(
        protected_wrapper,
        [client_a.clone(), client_b.clone(), client_c.clone()],
    )
    .expect("distinct same-scope protected composite");
    let original_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut prepared = protected
        .prepare_compare_and_set(
            SessionConsumerRequestId::from_bytes([0xc5; 16]),
            CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    key,
                    generation: Generation::new(1),
                    owner,
                    fence: lease.fence(),
                    state_class: StateClass::AuthoritativeSession,
                    state_type: StateType::from_static("prepared-cas-three-voter"),
                    expires_at: None,
                    payload,
                },
            },
            PreparedCheckpointBudget::new(original_deadline, physical_attempt_timeout)
                .expect("explicit 100ms physical budget"),
        )
        .await
        .expect("one protected prepared CAS");
    assert_eq!(
        provider.calls(),
        1,
        "preparation seals the canonical CAS exactly once"
    );

    let committed = c_loss.committed.notified();
    tokio::pin!(committed);
    committed.as_mut().enable();
    let execute_result = prepared.execute_once().await;
    assert_eq!(
        execute_result,
        Err(PreparedCompareAndSetExecuteError::OutcomeUnknown),
        "C commits once but withholds its consumer response; route calls: A={}, B={}, C={}, mutations={}",
        a_calls.load(Ordering::SeqCst),
        b_calls.load(Ordering::SeqCst),
        c_calls.load(Ordering::SeqCst),
        c_loss.mutation_calls.load(Ordering::SeqCst),
    );
    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, &mut committed)
        .await
        .expect("C reaches one real durable CAS commit after the response deadline");
    assert_eq!(a_calls.load(Ordering::SeqCst), 1);
    assert_eq!(b_calls.load(Ordering::SeqCst), 1);
    assert_eq!(c_calls.load(Ordering::SeqCst), 1);
    assert_eq!(c_loss.mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        before + 1,
        fleet.stores[2]
            .max_replication_sequence()
            .await
            .expect("one real CAS effect"),
        "only the C route proposed the bound CAS intent"
    );

    fleet.reset_read_barrier_calls();
    assert_eq!(
        prepared.status_once(original_deadline).await,
        Ok(PreparedCompareAndSetStatus::Recorded(
            PreparedCompareAndSetOutcome::Applied,
        )),
        "first receipt rotates to A and reads the real durable ledger"
    );
    assert_eq!(a_calls.load(Ordering::SeqCst), 2, "first receipt uses A");
    assert_eq!(status_a.status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(c_loss.mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        before + 1,
        fleet.stores[2]
            .max_replication_sequence()
            .await
            .expect("receipt does not propose"),
        "status is a read-only ledger barrier"
    );
    assert_eq!(1, fleet.read_barrier_calls(), "one quorum receipt barrier");
    assert_eq!(
        provider.calls(),
        1,
        "receipt recovery neither reseals nor unseals the protected CAS"
    );
    assert!(client_c.diagnostics().await.reconnects >= 1);
    assert_eq!(
        prepared.execute_once().await,
        Err(PreparedCompareAndSetExecuteError::AlreadyExecuted)
    );
    client_c.shutdown().await;
    a_server.abort_and_wait().await;
    c_server.abort_and_wait().await;
}

#[derive(Debug)]
struct WarmPreparedCasLatencySample {
    payload_bytes: usize,
    attempt_budget: Duration,
    warm_get: Duration,
    execute_to_ambiguity: Duration,
    dispatch_outcome: WarmPreparedCasDispatchOutcome,
    receipt: Duration,
    receipt_outcome: WarmPreparedCasReceiptOutcome,
    a_resolves: usize,
    c_resolves: usize,
    a_setup_successes: u64,
    c_setup_successes: u64,
    c_reconnects: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarmPreparedCasDispatchOutcome {
    OutcomeUnknown,
    NotTransmitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarmPreparedCasReceiptOutcome {
    NotAttempted,
    RecordedApplied,
    NotFound,
    Deadline,
    TopologyAuthorityRevoked,
    Unavailable,
    RequestConflict,
    RecordedOther,
    OtherError,
}

fn warm_latency_percentile(samples: &mut [Duration], percentile: usize) -> Duration {
    assert!(!samples.is_empty(), "latency summary needs one sample");
    samples.sort_unstable();
    let index = ((samples.len() - 1) * percentile).div_ceil(100);
    samples[index]
}

async fn warm_prepared_cas_response_loss_sample(
    payload_bytes: usize,
    attempt_budget: Duration,
    warm_connections: bool,
) -> WarmPreparedCasLatencySample {
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start(Arc::clone(&pki), None).await;
    let client_spiffe = spiffe("prepared-cas-warm-matrix-client");
    let manifest = fleet.stores[0]
        .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(&client_spiffe).expect("warm matrix client SPIFFE"),
            [SessionConsumerTenantNfScope::new(
                TenantId::new("consumer-test").expect("tenant"),
                NetworkFunctionKind::smf(),
            )],
        )
        .expect("warm matrix explicit consumer grant")])
        .await
        .expect("warm matrix consumer manifest");
    let _scope = manifest.scope();
    let authorizer = SessionConsumerAuthorizer::try_new(manifest).expect("warm matrix authorizer");
    let a_spiffe = three_voter_spiffe(0);
    let c_spiffe = three_voter_spiffe(2);
    let status_a = Arc::new(CountingPreparedCasStatusConsumer {
        inner: Arc::new(fleet.stores[0].consumer_service()),
        status_calls: AtomicUsize::new(0),
    });
    let (a_server, a_address) = SessionQuorumConsumerServer::new(
        Arc::clone(&status_a) as Arc<dyn SessionQuorumConsumer>,
        pki.server_config(&a_spiffe),
        authorizer.clone(),
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("warm A listener"),
    )
    .await
    .expect("start warm A listener");
    let c_loss = Arc::new(CommitThenLosePreparedCasResponse::new(Arc::new(
        fleet.stores[2].consumer_service(),
    )));
    let (c_server, c_address) = SessionQuorumConsumerServer::new(
        Arc::clone(&c_loss) as Arc<dyn SessionQuorumConsumer>,
        pki.server_config(&c_spiffe),
        authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("warm C listener"),
    )
    .await
    .expect("start warm C listener");

    let a_resolves = Arc::new(AtomicUsize::new(0));
    let a_resolver: RemoteAddrResolver = {
        let resolves = Arc::clone(&a_resolves);
        Arc::new(move || {
            resolves.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(a_address) })
        })
    };
    let c_resolves = Arc::new(AtomicUsize::new(0));
    let c_resolver: RemoteAddrResolver = {
        let resolves = Arc::clone(&c_resolves);
        Arc::new(move || {
            resolves.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(c_address) })
        })
    };
    let server_name = rustls_pki_types::ServerName::IpAddress(a_address.ip().into());
    let client_a = PersistentSessionConsumerClient::from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            a_resolver,
            server_name.clone(),
            fleet.voter_authority(0),
            pki.client_config(&client_spiffe),
        ),
    )
    .expect("warm A persistent client");
    let client_c = PersistentSessionConsumerClient::from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            c_resolver,
            server_name,
            fleet.voter_authority(2),
            pki.client_config(&client_spiffe),
        ),
    )
    .expect("warm C persistent client");
    let key = test_key();
    let warm_get = if warm_connections {
        let warm_started = Instant::now();
        assert!(client_c
            .get(key.clone())
            .await
            .expect("warm C Get")
            .is_none());
        assert!(client_a
            .get(key.clone())
            .await
            .expect("warm A Get")
            .is_none());
        warm_started.elapsed()
    } else {
        Duration::ZERO
    };
    let a_warm = client_a.diagnostics().await;
    let c_warm = client_c.diagnostics().await;
    if warm_connections {
        assert!(
            a_warm.setup_successes >= 1,
            "A authenticated during warm Get"
        );
        assert!(
            c_warm.setup_successes >= 1,
            "C authenticated during warm Get"
        );
        assert_eq!(a_resolves.load(Ordering::SeqCst), 1);
        assert_eq!(c_resolves.load(Ordering::SeqCst), 1);
    } else {
        assert_eq!(a_warm.setup_successes, 0);
        assert_eq!(c_warm.setup_successes, 0);
    }

    // C is the first mutation voter; after C's possibly-sent response loss,
    // the canonical router must make its first read-only receipt attempt at A.
    let owner = OwnerId::new("prepared-cas-warm-matrix-owner").expect("owner");
    let lease = fleet.stores[2]
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .expect("warm matrix lease");
    let before = fleet.stores[2]
        .max_replication_sequence()
        .await
        .expect("warm matrix sequence before CAS");
    let provider = CountingKeyProvider::with_active_session_key();
    let protected_wrapper = Arc::new(EncryptingSessionBackend::new(
        Arc::new(fleet.stores[2].clone()),
        Arc::clone(&provider),
        "prepared-cas-warm-matrix",
    ));
    let protected = SessionConsumerPreparedCheckpointBackend::persistent(
        protected_wrapper,
        [client_c.clone(), client_a.clone()],
    )
    .expect("same-scope warm protected composite");
    let mut prepared = protected
        .prepare_compare_and_set(
            SessionConsumerRequestId::from_bytes([0xd1; 16]),
            CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    key,
                    generation: Generation::new(1),
                    owner,
                    fence: lease.fence(),
                    state_class: StateClass::AuthoritativeSession,
                    state_type: StateType::from_static("prepared-cas-warm-matrix"),
                    expires_at: None,
                    payload: EncryptedSessionPayload::new(vec![0xd1; payload_bytes]),
                },
            },
            PreparedCheckpointBudget::new(
                tokio::time::Instant::now() + Duration::from_secs(3),
                attempt_budget,
            )
            .expect("explicit warm matrix budget"),
        )
        .await
        .expect("warm matrix prepare");
    assert_eq!(provider.calls(), 1, "one canonical seal");

    let committed = c_loss.committed.notified();
    tokio::pin!(committed);
    committed.as_mut().enable();
    let execute_started = Instant::now();
    let dispatch_outcome = match prepared.execute_once().await {
        Err(PreparedCompareAndSetExecuteError::OutcomeUnknown) => {
            WarmPreparedCasDispatchOutcome::OutcomeUnknown
        }
        Err(PreparedCompareAndSetExecuteError::NotTransmitted) => {
            WarmPreparedCasDispatchOutcome::NotTransmitted
        }
        other => panic!("unexpected warm prepared CAS dispatch result: {other:?}"),
    };
    let execute_to_ambiguity = execute_started.elapsed();
    if dispatch_outcome == WarmPreparedCasDispatchOutcome::NotTransmitted {
        assert_eq!(c_loss.mutation_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fleet.stores[2]
                .max_replication_sequence()
                .await
                .expect("warm matrix unchanged sequence"),
            before,
            "a proven pre-dispatch deadline has no mutation effect"
        );
        let a_after = client_a.diagnostics().await;
        let c_after = client_c.diagnostics().await;
        client_a.shutdown().await;
        client_c.shutdown().await;
        a_server.abort_and_wait().await;
        c_server.abort_and_wait().await;
        return WarmPreparedCasLatencySample {
            payload_bytes,
            attempt_budget,
            warm_get,
            execute_to_ambiguity,
            dispatch_outcome,
            receipt: Duration::ZERO,
            receipt_outcome: WarmPreparedCasReceiptOutcome::NotAttempted,
            a_resolves: a_resolves.load(Ordering::SeqCst),
            c_resolves: c_resolves.load(Ordering::SeqCst),
            a_setup_successes: a_after.setup_successes,
            c_setup_successes: c_after.setup_successes,
            c_reconnects: c_after.reconnects,
        };
    }
    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, &mut committed)
        .await
        .expect("C commits one durable CAS");
    assert_eq!(c_loss.mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fleet.stores[2]
            .max_replication_sequence()
            .await
            .expect("warm matrix sequence after CAS"),
        before + 1,
        "exactly one mutation effect is durable"
    );

    fleet.reset_read_barrier_calls();
    let receipt_started = Instant::now();
    let receipt_result = prepared
        .status_once(tokio::time::Instant::now() + attempt_budget)
        .await;
    let receipt = receipt_started.elapsed();
    let receipt_outcome = match receipt_result {
        Ok(PreparedCompareAndSetStatus::Recorded(PreparedCompareAndSetOutcome::Applied)) => {
            WarmPreparedCasReceiptOutcome::RecordedApplied
        }
        Ok(PreparedCompareAndSetStatus::Recorded(_)) => {
            WarmPreparedCasReceiptOutcome::RecordedOther
        }
        Ok(PreparedCompareAndSetStatus::NotFound) => WarmPreparedCasReceiptOutcome::NotFound,
        Ok(PreparedCompareAndSetStatus::RequestConflict) => {
            WarmPreparedCasReceiptOutcome::RequestConflict
        }
        Err(opc_session_store::PreparedCompareAndSetStatusError::Deadline) => {
            WarmPreparedCasReceiptOutcome::Deadline
        }
        Err(opc_session_store::PreparedCompareAndSetStatusError::TopologyAuthorityRevoked) => {
            WarmPreparedCasReceiptOutcome::TopologyAuthorityRevoked
        }
        Err(opc_session_store::PreparedCompareAndSetStatusError::Unavailable) => {
            WarmPreparedCasReceiptOutcome::Unavailable
        }
        Err(opc_session_store::PreparedCompareAndSetStatusError::NotExecuted) => {
            panic!("possible-send token must remain receipt-only")
        }
        Err(_) => WarmPreparedCasReceiptOutcome::OtherError,
    };
    if receipt_outcome == WarmPreparedCasReceiptOutcome::RecordedApplied {
        assert_eq!(
            status_a.status_calls.load(Ordering::SeqCst),
            1,
            "the first durable receipt is the warmed A voter"
        );
        assert_eq!(
            fleet.read_barrier_calls(),
            1,
            "the recorded receipt performs exactly one linearized barrier"
        );
    }
    assert_eq!(c_loss.mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.calls(), 1, "receipt does not reseal or unseal");
    assert_eq!(
        prepared.execute_once().await,
        Err(PreparedCompareAndSetExecuteError::AlreadyExecuted),
        "possible-send permanently prohibits another mutation"
    );
    let a_after = client_a.diagnostics().await;
    let c_after = client_c.diagnostics().await;
    assert_eq!(a_resolves.load(Ordering::SeqCst), 1);
    assert_eq!(c_resolves.load(Ordering::SeqCst), 1);

    client_a.shutdown().await;
    client_c.shutdown().await;
    a_server.abort_and_wait().await;
    c_server.abort_and_wait().await;
    WarmPreparedCasLatencySample {
        payload_bytes,
        attempt_budget,
        warm_get,
        execute_to_ambiguity,
        dispatch_outcome,
        receipt,
        receipt_outcome,
        a_resolves: a_resolves.load(Ordering::SeqCst),
        c_resolves: c_resolves.load(Ordering::SeqCst),
        a_setup_successes: a_after.setup_successes,
        c_setup_successes: c_after.setup_successes,
        c_reconnects: c_after.reconnects,
    }
}

#[tokio::test]
#[ignore = "release-only warm latency evidence matrix; run explicitly"]
async fn prepared_cas_warm_response_loss_latency_matrix() {
    // This is intentionally a bounded evidence lane, not a throughput
    // benchmark or a product retry policy. Its explicit budgets remain the
    // physical-attempt ceilings: it does not normalize a 250ms product budget.
    let payload_kib = std::env::var("OPC_WARM_MATRIX_PAYLOAD_KIB")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("OPC_WARM_MATRIX_PAYLOAD_KIB must be an integer")
        });
    let budget_millis = std::env::var("OPC_WARM_MATRIX_BUDGET_MILLIS")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .expect("OPC_WARM_MATRIX_BUDGET_MILLIS must be an integer")
        });
    let payloads = payload_kib
        .map(|kib| vec![kib])
        .unwrap_or_else(|| vec![16, 32, 41, 64, 128]);
    let budgets = budget_millis
        .map(|millis| vec![millis])
        .unwrap_or_else(|| vec![25, 50, 100]);
    let repetitions = std::env::var("OPC_WARM_MATRIX_REPETITIONS")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("OPC_WARM_MATRIX_REPETITIONS must be an integer")
        })
        .unwrap_or(1);
    assert!(repetitions > 0, "warm matrix needs at least one repetition");
    for payload_bytes in payloads.into_iter().map(|kib| kib * 1024) {
        for attempt_budget in budgets.iter().copied().map(Duration::from_millis) {
            let mut samples = Vec::with_capacity(repetitions);
            for _ in 0..repetitions {
                samples.push(
                    warm_prepared_cas_response_loss_sample(payload_bytes, attempt_budget, true)
                        .await,
                );
            }
            let recorded = samples
                .iter()
                .filter(|sample| {
                    sample.receipt_outcome == WarmPreparedCasReceiptOutcome::RecordedApplied
                })
                .count();
            let ambiguous = samples
                .iter()
                .filter(|sample| {
                    sample.dispatch_outcome == WarmPreparedCasDispatchOutcome::OutcomeUnknown
                })
                .count();
            assert!(samples.iter().all(|sample| {
                sample.payload_bytes == payload_bytes
                    && sample.attempt_budget == attempt_budget
                    && sample.a_resolves == 1
                    && sample.c_resolves == 1
                    && sample.a_setup_successes >= 1
                    && sample.c_setup_successes >= 1
                    && sample.c_reconnects == 1
            }));
            let mut warm_get = samples
                .iter()
                .map(|sample| sample.warm_get)
                .collect::<Vec<_>>();
            let mut execute = samples
                .iter()
                .map(|sample| sample.execute_to_ambiguity)
                .collect::<Vec<_>>();
            let mut receipt = samples
                .iter()
                .map(|sample| sample.receipt)
                .collect::<Vec<_>>();
            eprintln!(
                "warm prepared CAS n={} ambiguous={}/{} recorded={}/{} payload={}KiB budget={}ms: warm-get(p50/max)={:?}/{:?} execute(p50/p95/p99/max)={:?}/{:?}/{:?}/{:?} receipt(p50/p95/p99/max)={:?}/{:?}/{:?}/{:?}",
                repetitions,
                ambiguous,
                repetitions,
                recorded,
                repetitions,
                payload_bytes / 1024,
                attempt_budget.as_millis(),
                warm_latency_percentile(&mut warm_get, 50),
                *warm_get.last().expect("nonempty warm samples"),
                warm_latency_percentile(&mut execute, 50),
                warm_latency_percentile(&mut execute, 95),
                warm_latency_percentile(&mut execute, 99),
                *execute.last().expect("nonempty execute samples"),
                warm_latency_percentile(&mut receipt, 50),
                warm_latency_percentile(&mut receipt, 95),
                warm_latency_percentile(&mut receipt, 99),
                *receipt.last().expect("nonempty receipt samples"),
            );
        }
    }
}

#[tokio::test]
#[ignore = "release-only cold comparison for the warm ambiguity matrix"]
async fn prepared_cas_cold_response_loss_latency_comparison() {
    let sample =
        warm_prepared_cas_response_loss_sample(16 * 1024, Duration::from_millis(100), false).await;
    eprintln!("cold prepared CAS n=1 (single observation; p50/p95/p99 not estimated): {sample:?}");
}

#[cfg(feature = "test-control")]
#[tokio::test]
async fn persistent_three_voter_fenced_status_converges_after_response_loss_and_compaction() {
    const SNAPSHOT_COMMANDS: usize = 4_300;
    let pki = Arc::new(TestPki::new());
    let mut fleet = ThreeVoterConsumerFleet::start(Arc::clone(&pki), None).await;
    let (old_leader, old_leader_id, old_term) = fleet.observed_leader();
    let initial_follower = (old_leader + 1) % THREE_VOTER_COUNT;
    let other_survivor = (0..THREE_VOTER_COUNT)
        .find(|index| *index != old_leader && *index != initial_follower)
        .expect("three-voter second survivor");
    assert_ne!(initial_follower, old_leader, "execute starts on a follower");

    let server_spiffe = three_voter_spiffe(initial_follower);
    let client_spiffe = spiffe("three-voter-client");
    let voter_authority = fleet.voter_authority(initial_follower);
    let transition_loss = Arc::new(CommitThenLoseConsumerResponse::transition(Arc::new(
        fleet.stores[initial_follower].consumer_service(),
    )));
    let (transition_server, transition_address) = SessionQuorumConsumerServer::new(
        transition_loss.clone(),
        pki.server_config(&server_spiffe),
        three_voter_authorizer(&fleet.stores[initial_follower], &client_spiffe).await,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("transition listener"),
    )
    .await
    .expect("start transition response-loss listener");
    let transition_server = AbortConsumerServerOnDrop::new(transition_server);
    let mut recovery_servers = Vec::with_capacity(THREE_VOTER_COUNT);
    let mut recovery_addresses = Vec::with_capacity(THREE_VOTER_COUNT);
    for index in 0..THREE_VOTER_COUNT {
        let recovery_spiffe = three_voter_spiffe(index);
        let (server, address) = SessionQuorumConsumerServer::new(
            Arc::new(fleet.stores[index].consumer_service()),
            pki.server_config(&recovery_spiffe),
            three_voter_authorizer(&fleet.stores[index], &client_spiffe).await,
        )
        .listen(
            "127.0.0.1:0"
                .parse::<SocketAddr>()
                .expect("recovery listener"),
        )
        .await
        .expect("start recovery listener");
        recovery_servers.push(AbortConsumerServerOnDrop::new(server));
        recovery_addresses.push(address);
    }

    let resolved_address = Arc::new(RwLock::new(transition_address));
    let resolver_address = Arc::clone(&resolved_address);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let address = *resolver_address
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Box::pin(async move { Ok(address) })
    });
    let persistent = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(transition_address.ip().into()),
            voter_authority,
            pki.client_config(&client_spiffe),
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("persistent three-voter consumer");
    let journal_directory = tempfile::tempdir().expect("three-voter prepared journal directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            journal_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make three-voter prepared journal directory private");
    }
    let journal = Arc::new(
        PreparedFencedTransitionJournal::create_new(
            journal_directory.path().join("prepared.sqlite"),
            PreparedFencedTransitionJournalKey::from_bytes([0x3a; 32]),
        )
        .expect("create three-voter prepared journal"),
    );
    let provider = CountingKeyProvider::with_active_session_key();
    let physical = Arc::new(
        SessionConsumerFencedTransitionBackend::persistent(persistent.clone())
            .expect("persistent physical fenced-transition backend"),
    );
    let outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            Arc::clone(&physical),
            Arc::clone(&provider),
            "consumer-three-voter-protected",
        )
        .with_fenced_transition_journal(Arc::clone(&journal)),
    );
    let logical_request = fenced_create_request(0xa1);
    let prepared = outer
        .prepare_fenced_transition(logical_request.clone())
        .await
        .expect("prepare one retained protected token");
    let request_id = prepared.request_id();
    let expected_token = Zeroizing::new(prepared.as_bytes().to_vec());
    assert_eq!(
        1,
        provider.calls(),
        "the caller prepares one exact protected token before dispatch"
    );
    let before = fleet.stores[initial_follower]
        .max_replication_sequence()
        .await
        .expect("application sequence before transition");

    let transition_committed = transition_loss.transition_committed.notified();
    tokio::pin!(transition_committed);
    transition_committed.as_mut().enable();
    let execute_outer = Arc::clone(&outer);
    let execute_token = prepared.clone();
    let execute =
        tokio::spawn(async move { execute_outer.fenced_transition(&execute_token).await });
    if tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, &mut transition_committed)
        .await
        .is_err()
    {
        transition_server.abort_and_wait().await;
        match execute.await.expect("execute task joins") {
            Err(error) => panic!("follower did not reach durable transition commit: {error}"),
            Ok(_) => panic!("follower returned before response loss"),
        }
    }
    assert_eq!(
        1,
        transition_loss.transition_calls.load(Ordering::SeqCst),
        "one physical consumer mutation reached the follower route"
    );
    fleet.wait_all_ready().await;
    for survivor in [initial_follower, other_survivor] {
        fleet.stores[survivor].set_automatic_election_for_test(false);
    }
    assert_eq!(
        (old_leader, old_leader_id, old_term),
        fleet.observed_leader(),
        "every voter still reports the original leader and term immediately before isolation"
    );
    fleet.isolate(old_leader).await;
    tokio::time::sleep(THREE_VOTER_APPEND_ATTEMPT_DRAIN).await;
    tokio::time::timeout(
        THREE_VOTER_READY_TIMEOUT,
        fleet.quiesce_and_restart_survivors(old_leader),
    )
    .await
    .expect("survivor transports and admitted consensus handlers quiesce");
    let election_deadline = tokio::time::Instant::now() + THREE_VOTER_ELECTION_RECOVERY_TIMEOUT;
    tokio::time::timeout_at(election_deadline, async {
        tokio::time::sleep(THREE_VOTER_LEASE_DRAIN).await;
        fleet.stores[initial_follower]
            .trigger_election_for_test()
            .await
            .expect("selected survivor starts a normal Openraft campaign");
    })
    .await
    .expect("old committed-leader lease drains within the recovery deadline");
    let new_leader = fleet
        .wait_for_new_leader(old_leader, old_leader_id, old_term, election_deadline)
        .await;
    assert_ne!(new_leader, old_leader, "leader changes after commit");
    for survivor in [initial_follower, other_survivor] {
        fleet.stores[survivor].set_automatic_election_for_test(true);
    }
    assert_eq!(
        initial_follower, new_leader,
        "the selected survivor wins its engine-generated campaign"
    );
    assert_eq!(
        old_term + 1,
        fleet.stores[new_leader].status().term,
        "exactly one normal Openraft campaign establishes the successor"
    );
    let status_target = (0..THREE_VOTER_COUNT)
        .find(|index| *index != old_leader && *index != new_leader)
        .expect("live follower status target after leader change");
    assert_ne!(
        status_target, new_leader,
        "status response loss targets a live follower"
    );
    let status_loss = Arc::new(CommitThenLoseConsumerResponse::status(Arc::new(
        fleet.stores[status_target].consumer_service(),
    )));
    let (status_server, status_address) = SessionQuorumConsumerServer::new(
        status_loss.clone(),
        pki.server_config(&three_voter_spiffe(status_target)),
        three_voter_authorizer(&fleet.stores[status_target], &client_spiffe).await,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("status listener"),
    )
    .await
    .expect("start follower status response-loss listener");
    let status_server = AbortConsumerServerOnDrop::new(status_server);
    let status_resolved_address = Arc::new(RwLock::new(status_address));
    let status_resolver_address = Arc::clone(&status_resolved_address);
    let status_resolver: RemoteAddrResolver = Arc::new(move || {
        let address = *status_resolver_address
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Box::pin(async move { Ok(address) })
    });
    let persistent_status = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            status_resolver,
            rustls_pki_types::ServerName::IpAddress(status_address.ip().into()),
            fleet.voter_authority(status_target),
            pki.client_config(&client_spiffe),
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("persistent follower-status consumer");
    let status_physical = Arc::new(
        SessionConsumerFencedTransitionBackend::persistent(persistent_status.clone())
            .expect("persistent follower-status fenced-transition backend"),
    );
    let status_outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            Arc::clone(&status_physical),
            Arc::clone(&provider),
            "consumer-three-voter-protected",
        )
        .with_fenced_transition_journal(Arc::clone(&journal)),
    );
    *resolved_address
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = recovery_addresses[initial_follower];
    transition_server.abort_and_wait().await;
    assert!(matches!(
        execute.await.expect("execute task joins"),
        Err(FencedTransitionExecuteError::OutcomeUnknown {
            request_id: returned_request_id
        }) if returned_request_id == request_id
    ));

    let status_resolved = status_loss.status_resolved.notified();
    tokio::pin!(status_resolved);
    status_resolved.as_mut().enable();
    let status_outer_for_recovery = Arc::clone(&status_outer);
    let status_token = prepared.clone();
    let recover = tokio::spawn(async move {
        status_outer_for_recovery
            .fenced_transition_status(&status_token)
            .await
    });
    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, &mut status_resolved)
        .await
        .expect("status target resolves durable receipt before response loss");
    assert_eq!(
        1,
        status_loss.status_calls.load(Ordering::SeqCst),
        "the first status request performed a real durable lookup"
    );
    tokio::time::sleep(
        DEFAULT_PERSISTENT_SESSION_CONSUMER_POOL_WAIT_TIMEOUT + Duration::from_millis(50),
    )
    .await;
    *status_resolved_address
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = recovery_addresses[status_target];
    status_server.abort_and_wait().await;
    let recorded = recover
        .await
        .expect("status task joins")
        .expect("persistent retry resolves exact durable receipt");
    assert!(matches!(
        recorded,
        FencedTransitionStatus::Recorded(ref result) if result.as_ref().is_ok()
    ));
    assert!(
        persistent.diagnostics().await.reconnects >= 1
            && persistent_status.diagnostics().await.reconnects >= 1,
        "both response losses retire their exact voter-specific persistent lanes before status recovery"
    );

    let transition_log_index = fleet.stores[new_leader]
        .status()
        .last_log_index
        .expect("committed transition log index");
    let target_log_index = transition_log_index + SNAPSHOT_COMMANDS as u64;
    const MAX_SNAPSHOT_MAINTENANCE_REJECTIONS: usize = 8;
    let mut workload_leader = new_leader;
    let mut workload_term = fleet.stores[workload_leader].status().term;
    tokio::time::timeout(Duration::from_secs(5 * 60), async {
        // Each command must finish before the next begins. Concurrent
        // logical-time reads intentionally share one bounded consensus
        // proposal, while this proof must cross the production snapshot-log
        // threshold with distinct committed entries.
        let mut maintenance_rejections = 0_usize;
        while fleet.stores[workload_leader]
            .status()
            .last_log_index
            .is_none_or(|index| index < target_log_index)
        {
            match fleet.stores[workload_leader]
                .max_replication_sequence()
                .await
            {
                Ok(_) => {}
                Err(StoreError::BackendUnavailable(_))
                    if maintenance_rejections < MAX_SNAPSHOT_MAINTENANCE_REJECTIONS =>
                {
                    maintenance_rejections += 1;
                    (workload_leader, _, workload_term) = fleet
                        .wait_for_admitted_quorum_leader(&[0, 1, 2], workload_term)
                        .await;
                    tokio::task::yield_now().await;
                }
                Err(_) => panic!("snapshot qualification command was rejected"),
            }
        }
    })
    .await
    .expect("snapshot qualification command batch completes");
    assert!(
        fleet.stores[workload_leader]
            .status()
            .last_log_index
            .is_some_and(|index| index >= target_log_index),
        "the qualification workload crosses the production snapshot-log threshold"
    );
    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
        loop {
            let progress = fleet.stores[workload_leader]
                .probe_durable_readiness()
                .await
                .recovery_progress();
            if progress
                .snapshot_index()
                .is_some_and(|index| index >= transition_log_index)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("committed transition is compacted into a snapshot");
    let after_compaction = status_outer
        .fenced_transition_status(&prepared)
        .await
        .expect("receipt lookup after snapshot compaction");
    assert_eq!(
        recorded, after_compaction,
        "response loss, reconnect, follower route, leader change, and compaction return one exact receipt"
    );

    let wrong_token_request = FencedTransitionRequest::new(
        request_id,
        FencedTransitionLease::acquire(
            test_key(),
            OwnerId::new("x").expect("test owner"),
            FenceToken::new(1),
            Duration::from_secs(30),
        )
        .expect("wrong-token lease"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("wrong-token request remains structurally valid");
    let wrong_token = physical
        .prepare_fenced_transition(wrong_token_request)
        .await
        .expect("prepare conflicting physical token");
    assert!(matches!(
        physical.fenced_transition_status(&wrong_token).await,
        Ok(FencedTransitionStatus::RequestConflict)
    ));
    let wrong_id = outer
        .prepare_fenced_transition(
            FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([0x72; 16]),
                logical_request.lease().clone(),
                logical_request.mutation().clone(),
            )
            .expect("wrong-ID request remains structurally valid"),
        )
        .await
        .expect("prepare wrong-ID protected token");
    assert!(matches!(
        outer.fenced_transition_status(&wrong_id).await,
        Ok(FencedTransitionStatus::NotFound)
    ));
    assert_eq!(
        expected_token.as_slice(),
        prepared.as_bytes(),
        "execute and every status lookup retain the caller's one exact token"
    );
    assert_eq!(
        2,
        provider.calls(),
        "status-only recovery never invokes the provider or reseals the committed token"
    );
    assert_eq!(
        before + 1,
        fleet.stores[new_leader]
            .max_replication_sequence()
            .await
            .expect("application sequence after all status reads"),
        "receipt recovery and all negative lookups add no application mutation or replay"
    );
    fleet.restore(old_leader).await;
    fleet.wait_all_ready().await;
    for (index, recovery_address) in recovery_addresses.iter().copied().enumerate() {
        let recovery_client = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new(
                recovery_address,
                rustls_pki_types::ServerName::IpAddress(recovery_address.ip().into()),
                fleet.voter_authority(index),
                pki.client_config(&client_spiffe),
            ),
            PersistentSessionConsumerConfig::default(),
        )
        .expect("persistent restored-voter consumer");
        let recovery_physical = Arc::new(
            SessionConsumerFencedTransitionBackend::persistent(recovery_client.clone())
                .expect("persistent restored-voter fenced-transition backend"),
        );
        let recovery_outer: Arc<dyn SessionBackend> = Arc::new(
            EncryptingSessionBackend::new(
                recovery_physical,
                Arc::clone(&provider),
                "consumer-three-voter-protected",
            )
            .with_fenced_transition_journal(Arc::clone(&journal)),
        );
        assert_eq!(
            recorded,
            recovery_outer
                .fenced_transition_status(&prepared)
                .await
                .expect("each restored voter returns the exact protected receipt"),
            "voter {index} returns the globally durable receipt without resubmit"
        );
        recovery_client.shutdown().await;
    }
    persistent.shutdown().await;
    persistent_status.shutdown().await;
    for server in recovery_servers {
        server.abort_and_wait().await;
    }
    fleet.shutdown().await;
}

#[tokio::test]
async fn authenticated_consumer_v2_recovers_journaled_protected_transition_after_tls_ambiguity() {
    for client_kind in [
        FencedConsumerClientKind::Stateless,
        FencedConsumerClientKind::Persistent,
    ] {
        let pki = TestPki::new();
        let server_spiffe = spiffe("v2-server");
        let client_spiffe = spiffe("v2-client");
        let (snapshots, store, _scope, voter_authority, authorizer) =
            admitted_store_and_authorizer([client_spiffe.clone()], &server_spiffe).await;
        let initial_service = Arc::new(OneShotOutcomeUnknownConsumer::new(Arc::new(
            store.consumer_service(),
        )));
        let initial_service_for_server: Arc<dyn SessionQuorumConsumer> = initial_service.clone();
        let (initial_handle, initial_address) = SessionQuorumConsumerServer::new(
            initial_service_for_server,
            pki.server_config(&server_spiffe),
            authorizer.clone(),
        )
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
        .await
        .expect("start initial consumer listener");

        let journal_directory = tempfile::tempdir().expect("journal directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(
                journal_directory.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("private journal directory");
        }
        let journal_path = journal_directory.path().join("prepared.sqlite");
        let journal_key = [0x91; 32];
        let initial_journal = Arc::new(
            PreparedFencedTransitionJournal::create_new(
                &journal_path,
                PreparedFencedTransitionJournalKey::from_bytes(journal_key),
            )
            .expect("open prepared journal"),
        );
        let initial_client = fenced_consumer_backend(
            client_kind,
            &pki,
            initial_address,
            &server_spiffe,
            &client_spiffe,
            voter_authority.clone(),
        );
        let initial_physical = Arc::clone(&initial_client.backend);
        let initial_provider = CountingKeyProvider::with_active_session_key();
        let initial_outer: Arc<dyn SessionBackend> = Arc::new(
            EncryptingSessionBackend::new(
                Arc::clone(&initial_physical),
                Arc::clone(&initial_provider),
                "consumer-v2-protected",
            )
            .with_fenced_transition_journal(Arc::clone(&initial_journal)),
        );

        assert!(matches!(
            initial_outer
                .fenced_transition_capability()
                .await
                .expect("capability"),
            Some(AtomicFencedTransitionCapability::V2)
        ));
        let prepared = initial_outer
            .prepare_fenced_transition(fenced_create_request(0xa1))
            .await
            .expect("prepare protected transition");
        assert_eq!(
            initial_provider.calls(),
            1,
            "preparation uses exactly one provider operation"
        );
        let request_id = prepared.request_id();
        let expected_token = Zeroizing::new(prepared.as_bytes().to_vec());
        assert!(matches!(
            initial_outer.fenced_transition(&prepared).await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id: recovered_id })
                if recovered_id == request_id
        ));
        assert_eq!(
            initial_service
                .physical_payload_encoding()
                .expect("initial service observed physical transition"),
            SessionPayloadEncoding::EnvelopeV1
        );
        assert!(
            !initial_service.physical_payload_is_logical(),
            "the physical consumer request remains sealed"
        );

        drop(initial_outer);
        drop(initial_physical);
        drop(initial_journal);
        initial_client.shutdown().await;
        drop(initial_provider);
        drop(prepared);
        initial_handle.abort_and_wait().await;

        let replacement_service = Arc::new(store.consumer_service());
        let (replacement_handle, replacement_address) = SessionQuorumConsumerServer::new(
            replacement_service,
            pki.server_config(&server_spiffe),
            authorizer,
        )
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
        .await
        .expect("start replacement consumer listener");
        let replacement_journal = Arc::new(
            PreparedFencedTransitionJournal::open_existing(
                &journal_path,
                PreparedFencedTransitionJournalKey::from_bytes(journal_key),
            )
            .expect("reopen prepared journal"),
        );
        let replacement_client = fenced_consumer_backend(
            client_kind,
            &pki,
            replacement_address,
            &server_spiffe,
            &client_spiffe,
            voter_authority,
        );
        let replacement_physical = Arc::clone(&replacement_client.backend);
        let replacement_provider = CountingKeyProvider::empty();
        let replacement_outer: Arc<dyn SessionBackend> = Arc::new(
            EncryptingSessionBackend::new(
                Arc::clone(&replacement_physical),
                Arc::clone(&replacement_provider),
                "consumer-v2-protected",
            )
            .with_fenced_transition_journal(replacement_journal),
        );
        let recovered = match replacement_outer
            .recover_prepared_fenced_transition(request_id)
            .await
            .expect("recover prepared transition")
        {
            PreparedFencedTransitionLookup::Found(prepared) => prepared,
            PreparedFencedTransitionLookup::Absent => panic!("prepared transition was lost"),
            _ => panic!("prepared transition lookup was unsupported"),
        };
        let recovered_is_exact = recovered.as_bytes() == expected_token.as_slice();
        assert!(recovered_is_exact, "recovered token is exact");

        let _outcome = replacement_outer
            .fenced_transition(&recovered)
            .await
            .expect("recover exact transition");
        assert!(matches!(
            replacement_outer
                .fenced_transition_status(&recovered)
                .await
                .expect("recover transition status"),
            FencedTransitionStatus::Recorded(_)
        ));
        assert_eq!(
            replacement_provider.calls(),
            0,
            "recovery never invokes the fresh provider"
        );
        assert!(matches!(
            replacement_outer
                .prepare_fenced_transition(fenced_create_request(0xa2))
                .await,
            Err(StoreError::FencedTransitionRequestConflict)
        ));
        assert_eq!(
            replacement_provider.calls(),
            0,
            "same-ID replacement is rejected before provider work"
        );

        drop(replacement_outer);
        drop(replacement_physical);
        replacement_client.shutdown().await;
        replacement_handle.abort_and_wait().await;
        drop(store);
        drop(snapshots);
    }
}

// The real consensus service runs all three authenticated voter transports at
// once. The maximum protected envelope is intentionally exercised on a
// multithreaded runtime so this remains the production topology rather than a
// serial in-process approximation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_commits_maximum_plan_and_result_then_established_terminal(
) {
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_roster_attestation(
        Arc::clone(&pki),
        ProductionRosterAttestationIssuer::trust_root(),
    )
    .await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    let ingress = leader;
    let server_spiffe = three_voter_spiffe(ingress);
    let client_spiffe = spiffe("three-voter-roster-maximum-client");
    let authorizer = three_voter_authorizer(&fleet.stores[ingress], &client_spiffe).await;
    let voter_authority = fleet.voter_authority(ingress);
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(ingress),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let service = Arc::new(fleet.stores[ingress].consumer_service());
    let consumer: Arc<dyn SessionQuorumConsumer> = service.clone();
    let roster_ingress: Arc<dyn SessionQuorumRosterIngress> = service;
    assert_eq!(
        roster_ingress.expected_roster_attestation_trust_root_identity(),
        Some(RosterIngressSigner::trust_root(attestor.as_ref()).identity()),
        "the fixed quorum must expose the same root that certifies /3 ingress"
    );
    let transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        consumer,
        roster_ingress,
    ));
    let (server, address) = SessionQuorumConsumerServer::new(
        transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_roster_ingress(transport.clone(), ingress_signer)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("maximum protected-roster listener"),
    )
    .await
    .expect("start maximum protected-roster listener");

    // Establish the incumbent record through the public SessionBackend
    // boundary. The protected roster is therefore a real checked successor,
    // never a direct test insertion into SQLite or consensus state.
    let setup_directory = tempfile::tempdir().expect("protected-roster journal directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            setup_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("private protected-roster journal directory");
    }
    let setup_provider = CountingKeyProvider::with_active_session_key();
    let setup_client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority.clone(),
    );
    let setup_physical: Arc<dyn SessionBackend> = Arc::new(
        SessionConsumerFencedTransitionBackend::stateless(setup_client)
            .expect("public stateless SessionBackend"),
    );
    let setup_outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            setup_physical,
            Arc::clone(&setup_provider),
            "three-voter-protected-roster",
        )
        .with_fenced_transition_journal(Arc::new(
            PreparedFencedTransitionJournal::create_new(
                setup_directory.path().join("prepared.sqlite"),
                PreparedFencedTransitionJournalKey::from_bytes([0x7a; 32]),
            )
            .expect("create protected-roster SessionBackend journal"),
        )),
    );
    let key = test_key();
    let owner = OwnerId::new("three-voter-roster-owner").expect("roster owner");
    let setup_lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(60),
    )
    .expect("incumbent roster lease");
    let setup = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xb1; 16]),
        setup_lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: setup_lease
                .committed_fence()
                .expect("incumbent roster fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("three-voter-roster-current"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0x51]),
        }),
    )
    .expect("incumbent protected roster record");
    let setup = setup_outer
        .prepare_fenced_transition(setup)
        .await
        .expect("prepare incumbent through SessionBackend");
    let setup = setup_outer
        .fenced_transition(&setup)
        .await
        .expect("commit incumbent through SessionBackend");
    let roster_lease = setup.lease().clone();
    let roster_generation = setup.committed_generation();
    let sequence_before = fleet.application_sequences().await[leader];
    let log_before = fleet.stores[leader]
        .status()
        .last_log_index
        .expect("protected-roster proposal baseline");
    fleet.wait_all_application_sequences(sequence_before).await;

    let persistent = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );
    assert!(persistent.fenced_mutation_roster_transport_enabled());
    assert_eq!(
        SESSION_QUORUM_CONSUMER_ROSTER_ALPN,
        b"opc-session-consumer/3"
    );
    assert_eq!(SESSION_QUORUM_CONSUMER_ROSTER_TRANSPORT_REVISION, 5);
    let shutdown_client = persistent.clone();
    let provider = Arc::new(SixMemberRosterEvidenceProvider::new(attestor.clone()));
    let publication_provider = Arc::new(EstablishedPublicationEvidenceProvider::default());
    let adapter = persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&provider),
            Arc::clone(&publication_provider),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("positive roster concurrency"),
        )
        .expect("compose public protected-roster provider adapter");
    let roster_client = adapter.client().clone();

    let protected_plan = vec![0x70; FENCED_MUTATION_ROSTER_MAX_PLAN_BYTES];
    let protected_result = vec![0x72; FENCED_MUTATION_ROSTER_MAX_RESULT_BYTES];
    let terminal_state_type = StateType::from_static("three-voter-roster-established");
    let mut expected_terminal = StoredSessionRecord {
        key: key.clone(),
        generation: roster_generation.next().expect("terminal generation"),
        owner: owner.clone(),
        fence: roster_lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: terminal_state_type.clone(),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let envelope_overhead = EncryptedSessionPayload::encrypt(
        setup_provider.as_ref(),
        &expected_terminal,
        "three-voter-protected-roster",
    )
    .await
    .expect("derive SDK checkpoint envelope overhead")
    .as_bytes()
    .len();
    let terminal_plaintext =
        vec![0x73; FENCED_MUTATION_ROSTER_MAX_CHECKPOINT_BYTES - envelope_overhead];
    expected_terminal.payload = EncryptedSessionPayload::new(&terminal_plaintext);
    let protected_checkpoint = EncryptedSessionPayload::encrypt(
        setup_provider.as_ref(),
        &expected_terminal,
        "three-voter-protected-roster",
    )
    .await
    .expect("seal exact maximum checkpoint through SessionBackend provider")
    .as_bytes()
    .to_vec();
    assert_eq!(protected_plan.len(), FENCED_MUTATION_ROSTER_MAX_PLAN_BYTES);
    assert_eq!(
        protected_checkpoint.len(),
        FENCED_MUTATION_ROSTER_MAX_CHECKPOINT_BYTES
    );
    assert_eq!(
        protected_result.len(),
        FENCED_MUTATION_ROSTER_MAX_RESULT_BYTES
    );
    expected_terminal.payload = EncryptedSessionPayload::try_envelope(&protected_checkpoint)
        .expect("canonical maximum checkpoint envelope");
    let members = (0_u8..6)
        .map(|ordinal| {
            Member::new(
                ordinal,
                MemberOperationId::from_bytes([ordinal + 1; 16]).expect("stable opaque member ID"),
                vec![0xd0, ordinal],
                u64::from(ordinal) + 41,
            )
            .expect("ordered opaque roster member")
        })
        .collect::<Vec<_>>();
    let proposal = AdmissionProposal::new(
        FencedMutationRosterProfile::v1(),
        RosterId::from_bytes([0xb2; 16]).expect("stable roster ID"),
        members.clone(),
        EstablishedMutation::put_checkpoint(terminal_state_type),
        protected_plan.clone(),
        protected_checkpoint.clone(),
        protected_result.clone(),
    )
    .expect("maximum protected roster proposal");
    let mut admission = roster_client
        .prepare(roster_lease, roster_generation, proposal)
        .expect("prepare exact protected roster body");
    let mut roster = match roster_client
        .admit(&mut admission)
        .await
        .expect("one real PollAdmit")
    {
        AdmissionOutcome::Admitted(active) => DurableCrashRecoveredRoster::Active(active),
        AdmissionOutcome::NotTransmitted => {
            panic!(
                "fresh maximum PollAdmit must reach the authenticated roster ingress; ingress calls={}",
                transport.roster_admission_calls.load(Ordering::SeqCst)
            )
        }
        AdmissionOutcome::OutcomeUnknown(_) => {
            let mut recovered = None;
            for attempt in 0..PROTECTED_ROSTER_STATUS_READBACK_ATTEMPTS {
                match roster_client.admission_status(&admission).await {
                    Ok(RecoveryOutcome::Admitted(value)) => {
                        recovered = Some(value);
                        break;
                    }
                    Ok(RecoveryOutcome::Terminal(_)) | Ok(RecoveryOutcome::Compacted) => {
                        panic!("lost maximum PollAdmit reply cannot already be terminal")
                    }
                    Err(RosterClientError::Unavailable)
                    | Err(RosterClientError::AdmissionRecordMissing) => {
                        if attempt + 1 < PROTECTED_ROSTER_STATUS_READBACK_ATTEMPTS {
                            tokio::task::yield_now().await;
                        }
                    }
                    Err(_) => {
                        panic!("exact maximum PollAdmit status readback rejected its bound request")
                    }
                }
            }
            let Some(recovered) = recovered else {
                let applied = fleet.application_sequence_observation().await;
                let (decoded, decode_failures, nonempty) = fleet.append_entries_observation();
                panic!(
                    "maximum PollAdmit remained ambiguous after bounded same-request readback; applied={applied:?}; append_entries_decoded={decoded}; append_entries_decode_failures={decode_failures}; nonempty_append_entries_seen={nonempty}"
                )
            };
            DurableCrashRecoveredRoster::Recovered(recovered)
        }
    };
    fleet
        .wait_all_application_sequences(sequence_before + 1)
        .await;
    assert_eq!(
        fleet.stores[leader].status().last_log_index,
        Some(log_before + 1),
        "PollAdmitted appends exactly one real quorum proposal",
    );
    assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(roster.members(), members.as_slice());
    assert_eq!(roster.protected_plan(), protected_plan);

    let mut proofs = Vec::with_capacity(6);
    match &mut roster {
        DurableCrashRecoveredRoster::Active(active) => {
            for ordinal in 0_u8..6 {
                let mut member = active
                    .member(MemberOrdinal::new(ordinal).expect("member ordinal"))
                    .expect("issue exactly one ordered member");
                assert!(matches!(
                    roster_client
                        .prepare_member(&mut member)
                        .await
                        .expect("provider-local prepare"),
                    MemberPrepareOutcome::Prepared
                ));
                match roster_client
                    .execute(&mut member)
                    .await
                    .expect("provider-local execute")
                {
                    ExecuteOutcome::Conclusive(proof) => proofs.push(*proof),
                    _ => panic!("fresh member effect must be conclusive"),
                }
            }
        }
        DurableCrashRecoveredRoster::Recovered(recovered) => {
            for ordinal in 0_u8..6 {
                let mut member = recovered
                    .member(MemberOrdinal::new(ordinal).expect("recovered member ordinal"))
                    .expect("issue exactly one recovered member");
                assert!(matches!(
                    roster_client
                        .status(&mut member)
                        .await
                        .expect("provider-local recovery status"),
                    MemberRecoveryOutcome::Ambiguous(MemberRecoveryStatus::NotFound)
                ));
                match roster_client
                    .adopt(&mut member)
                    .await
                    .expect("provider-local exact adoption")
                {
                    MemberRecoveryOutcome::Conclusive(proof) => proofs.push(*proof),
                    _ => panic!("NotFound cannot bypass exact member adoption"),
                }
            }
        }
    }
    let recovered_after_ambiguous_admission =
        matches!(&roster, DurableCrashRecoveredRoster::Recovered(_));
    assert_eq!(
        provider.prepare_calls.load(Ordering::SeqCst),
        if recovered_after_ambiguous_admission {
            0
        } else {
            6
        }
    );
    assert_eq!(
        provider.execute_calls.load(Ordering::SeqCst),
        if recovered_after_ambiguous_admission {
            0
        } else {
            6
        }
    );
    assert_eq!(
        provider.status_calls.load(Ordering::SeqCst),
        if recovered_after_ambiguous_admission {
            6
        } else {
            0
        }
    );
    assert_eq!(
        provider.adopt_calls.load(Ordering::SeqCst),
        if recovered_after_ambiguous_admission {
            6
        } else {
            0
        }
    );
    assert_eq!(
        provider.executions(),
        members
            .iter()
            .enumerate()
            .map(|(ordinal, member)| (
                u8::try_from(ordinal).expect("six member ordinal"),
                *member.operation_id().as_bytes(),
                member.descriptor().to_vec(),
                member.expected_version(),
            ))
            .collect::<Vec<_>>()
    );
    fleet
        .wait_all_application_sequences(sequence_before + 1)
        .await;
    assert_eq!(
        fleet.stores[leader].status().last_log_index,
        Some(log_before + 1),
        "six provider effects and their local journal transitions append no quorum proposal",
    );
    assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 0);

    let proofs = CompleteProofSet::new(proofs).expect("six SDK-issued conclusive proofs");
    assert_eq!(proofs.len(), 6);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 0);
    let mut terminal = roster_client
        .prepare_terminal(roster.for_terminal(), &proofs)
        .await
        .expect("bind the six proofs to one exact terminal body");
    #[cfg(feature = "test-control")]
    let _terminal_apply_timing_guard = PROTECTED_ROSTER_TERMINAL_APPLY_TIMING_TEST_LOCK
        .lock()
        .await;
    #[cfg(feature = "test-control")]
    reset_protected_roster_terminal_apply_timings_for_test();
    let terminalize_started = Instant::now();
    let terminalize_outcome = roster_client
        .terminalize(&mut terminal)
        .await
        .expect("one real Terminalize");
    let mut publication = match terminalize_outcome {
        TerminalizationOutcome::Committed(TerminalReceipt::Established(established)) => {
            assert_eq!(established.protected_checkpoint(), protected_checkpoint);
            assert_eq!(established.protected_result(), protected_result);
            established.into_publication()
        }
        TerminalizationOutcome::Committed(TerminalReceipt::Aborted(_)) => {
            panic!("six applied proofs must not commit an Aborted protected terminal")
        }
        TerminalizationOutcome::NotTransmitted => {
            panic!("fresh protected terminal must return its committed Established receipt")
        }
        TerminalizationOutcome::OutcomeUnknown => {
            let terminalize_elapsed_millis = terminalize_started.elapsed().as_millis();
            let terminal_status_started = Instant::now();
            let mut committed = None;
            for attempt in 0..PROTECTED_ROSTER_STATUS_READBACK_ATTEMPTS {
                match roster_client.terminal_status(&mut terminal).await {
                    Ok(TerminalStatus::Committed(TerminalReceipt::Established(established))) => {
                        assert_eq!(established.protected_checkpoint(), protected_checkpoint);
                        assert_eq!(established.protected_result(), protected_result);
                        committed = Some(established);
                        break;
                    }
                    Ok(TerminalStatus::Committed(TerminalReceipt::Aborted(_)))
                    | Ok(TerminalStatus::Compacted) => {
                        panic!("six conclusive Applied proofs cannot recover as non-Established")
                    }
                    Ok(TerminalStatus::Admitted)
                    | Err(RosterClientError::Unavailable)
                    | Err(RosterClientError::AdmissionRecordMissing) => {
                        if attempt + 1 < PROTECTED_ROSTER_STATUS_READBACK_ATTEMPTS {
                            tokio::task::yield_now().await;
                        }
                    }
                    Err(_) => {
                        panic!("exact maximum terminal status readback rejected its bound body")
                    }
                }
            }
            let terminal_status_elapsed_millis = terminal_status_started.elapsed().as_millis();
            if let Some(established) = committed {
                established.into_publication()
            } else {
                let applied = fleet.application_sequence_observation().await;
                let applied_deltas = applied.map(|sequence| {
                    sequence.map(|sequence| sequence.saturating_sub(sequence_before))
                });
                let terminal_record_materialized = futures_util::future::join_all(
                    fleet.stores.iter().map(|store| store.get(&key)),
                )
                .await
                .iter()
                .all(|record| matches!(record, Ok(Some(record)) if record == &expected_terminal));
                let (decoded, decode_failures, nonempty) = fleet.append_entries_observation();
                panic!(
                "protected terminal remained ambiguous after bounded exact-body readback; terminalize_elapsed_millis={terminalize_elapsed_millis}; terminal_status_elapsed_millis={terminal_status_elapsed_millis}; sequence_before={sequence_before}; applied={applied:?}; applied_deltas={applied_deltas:?}; terminal_record_materialized={terminal_record_materialized}; ingress_admission_calls={}; ingress_admission_recorded_responses={}; ingress_terminal_calls={}; ingress_terminal_recorded_responses={}; ingress_terminal_response_completions={}; ingress_terminal_outcome_unknown_responses={}; ingress_terminal_not_transmitted_responses={}; ingress_terminal_rejected_responses={}; ingress_terminal_response_elapsed_millis={}; terminal_status_server={}; terminal_apply_timings={}; append_entries_decoded={decoded}; append_entries_decode_failures={decode_failures}; nonempty_append_entries_seen={nonempty}",
                transport.roster_admission_calls.load(Ordering::SeqCst),
                transport
                    .roster_admission_recorded_responses
                    .load(Ordering::SeqCst),
                transport.roster_terminal_calls.load(Ordering::SeqCst),
                transport
                    .roster_terminal_recorded_responses
                    .load(Ordering::SeqCst),
                transport
                    .roster_terminal_response_completions
                    .load(Ordering::SeqCst),
                transport
                    .roster_terminal_outcome_unknown_responses
                    .load(Ordering::SeqCst),
                transport
                    .roster_terminal_not_transmitted_responses
                    .load(Ordering::SeqCst),
                transport
                    .roster_terminal_rejected_responses
                    .load(Ordering::SeqCst),
                transport
                    .roster_terminal_response_elapsed_millis
                    .load(Ordering::SeqCst),
                protected_roster_terminal_status_response_diagnostic(transport.as_ref()),
                protected_roster_terminal_apply_timing_diagnostic(),
            )
            }
        }
    };
    #[cfg(feature = "test-control")]
    {
        let timings = protected_roster_terminal_apply_timings_for_test();
        assert_eq!(
            [
                timings.decode_and_proof_count,
                timings.terminalization_preparation_count,
                timings.production_apply_count,
                timings.committed_outcome_count,
                timings.replication_notification_count,
                timings.transaction_remainder_commit_count,
            ],
            [THREE_VOTER_COUNT as u64; 6],
            "the terminal applies each fixed storage phase exactly once on every voter"
        );
    }
    fleet
        .wait_all_application_sequences(sequence_before + 2)
        .await;
    assert_eq!(
        fleet.stores[leader].status().last_log_index,
        Some(log_before + 2),
        "terminalization is the second and final fresh-success quorum proposal",
    );
    assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 1);
    adapter
        .publish(&mut publication)
        .await
        .expect("publication needs the exact Established receipt");
    assert_eq!(publication_provider.status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(publication_provider.publish_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fleet.application_sequences().await,
        [sequence_before + 2; THREE_VOTER_COUNT],
        "the Established-only authority read and provider-local publication cannot append a roster proposal"
    );
    assert_eq!(
        fleet.stores[leader].status().last_log_index,
        Some(log_before + 2),
        "publication cannot append a third fresh-success quorum proposal",
    );
    for store in &fleet.stores {
        assert_eq!(
            store
                .get(&key)
                .await
                .expect("replicated terminal row")
                .as_ref(),
            Some(&expected_terminal)
        );
    }
    let plaintext = expected_terminal
        .payload
        .decrypt(
            setup_provider.as_ref(),
            &expected_terminal.key,
            &expected_terminal.state_type,
            expected_terminal.generation,
            expected_terminal.fence,
            "three-voter-protected-roster",
        )
        .await
        .expect("decrypt exact established checkpoint");
    assert_eq!(plaintext.as_slice(), terminal_plaintext.as_slice());

    shutdown_client.shutdown().await;
    server.abort_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_not_found_after_outcome_unknown_requires_adoption()
{
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_roster_attestation(
        Arc::clone(&pki),
        ProductionRosterAttestationIssuer::trust_root(),
    )
    .await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    let server_spiffe = three_voter_spiffe(leader);
    let client_spiffe = spiffe("three-voter-roster-not-found-client");
    let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
    let voter_authority = fleet.voter_authority(leader);
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(leader),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let service = Arc::new(fleet.stores[leader].consumer_service());
    let transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        service.clone(),
        service,
    ));
    let (server, address) = SessionQuorumConsumerServer::new(
        transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_roster_ingress(transport.clone(), ingress_signer)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("NotFound protected-roster listener"),
    )
    .await
    .expect("start NotFound protected-roster listener");

    let physical: Arc<dyn SessionBackend> = Arc::new(
        SessionConsumerFencedTransitionBackend::stateless(consumer_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            voter_authority.clone(),
        ))
        .expect("public NotFound SessionBackend"),
    );
    let setup_directory = tempfile::tempdir().expect("NotFound SessionBackend journal directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            setup_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("private NotFound SessionBackend journal directory");
    }
    let setup_provider = CountingKeyProvider::with_active_session_key();
    let outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            physical,
            Arc::clone(&setup_provider),
            "three-voter-protected-roster-not-found",
        )
        .with_fenced_transition_journal(Arc::new(
            PreparedFencedTransitionJournal::create_new(
                setup_directory.path().join("prepared.sqlite"),
                PreparedFencedTransitionJournalKey::from_bytes([0x8a; 32]),
            )
            .expect("create NotFound SessionBackend journal"),
        )),
    );
    let key = test_key();
    let owner = OwnerId::new("three-voter-roster-not-found-owner").expect("NotFound owner");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(60),
    )
    .expect("NotFound incumbent lease");
    let incumbent = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xc1; 16]),
        lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.committed_fence().expect("NotFound incumbent fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("three-voter-roster-not-found-current"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0x81]),
        }),
    )
    .expect("NotFound incumbent request");
    let incumbent = outer
        .prepare_fenced_transition(incumbent)
        .await
        .expect("prepare NotFound incumbent through SessionBackend");
    let incumbent = outer
        .fenced_transition(&incumbent)
        .await
        .expect("commit NotFound incumbent through SessionBackend");
    let sequence_before = fleet.application_sequences().await[leader];
    fleet.wait_all_application_sequences(sequence_before).await;

    let persistent = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        voter_authority,
    );
    let shutdown_client = persistent.clone();
    let provider = Arc::new(
        SixMemberRosterEvidenceProvider::sixth_execute_outcome_unknown_then_adopted(
            attestor.clone(),
        ),
    );
    let publication_provider = Arc::new(EstablishedPublicationEvidenceProvider::default());
    let adapter = persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&provider),
            Arc::clone(&publication_provider),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("positive NotFound concurrency"),
        )
        .expect("compose NotFound protected-roster adapter");
    let client = adapter.client().clone();
    let members = (0_u8..6)
        .map(|ordinal| {
            Member::new(
                ordinal,
                MemberOperationId::from_bytes([ordinal + 21; 16])
                    .expect("NotFound stable member ID"),
                vec![0xe0, ordinal],
                u64::from(ordinal) + 71,
            )
            .expect("NotFound ordered member")
        })
        .collect::<Vec<_>>();
    let proposal = AdmissionProposal::new(
        FencedMutationRosterProfile::v1(),
        RosterId::from_bytes([0xc2; 16]).expect("NotFound roster ID"),
        members,
        EstablishedMutation::no_op(),
        vec![0x91],
        Vec::new(),
        Vec::new(),
    )
    .expect("NotFound roster proposal");
    let mut admission = client
        .prepare(
            incumbent.lease().clone(),
            incumbent.committed_generation(),
            proposal,
        )
        .expect("prepare NotFound roster");
    let mut active = match client
        .admit(&mut admission)
        .await
        .expect("admit NotFound roster")
    {
        AdmissionOutcome::Admitted(active) => active,
        _ => panic!("NotFound fixture needs a returned admission body"),
    };
    fleet
        .wait_all_application_sequences(sequence_before + 1)
        .await;
    let mut proofs = Vec::with_capacity(5);
    for ordinal in 0_u8..5 {
        let mut member = active
            .member(MemberOrdinal::new(ordinal).expect("NotFound member ordinal"))
            .expect("issue conclusive NotFound member");
        assert!(matches!(
            client
                .prepare_member(&mut member)
                .await
                .expect("prepare member"),
            MemberPrepareOutcome::Prepared
        ));
        match client.execute(&mut member).await.expect("execute member") {
            ExecuteOutcome::Conclusive(proof) => proofs.push(*proof),
            _ => panic!("first five effects are conclusive"),
        }
    }
    let mut sixth = active
        .member(MemberOrdinal::new(5).expect("sixth ordinal"))
        .expect("issue sixth ambiguous member");
    assert!(matches!(
        client
            .prepare_member(&mut sixth)
            .await
            .expect("prepare sixth"),
        MemberPrepareOutcome::Prepared
    ));
    assert!(matches!(
        client.execute(&mut sixth).await.expect("execute sixth"),
        ExecuteOutcome::Ambiguous(MemberRecoveryStatus::OutcomeUnknown)
    ));
    let mut sixth = sixth
        .into_recoverable()
        .expect("ambiguous sixth is recovery-only");
    assert!(matches!(
        client.status(&mut sixth).await.expect("exact sixth status"),
        MemberRecoveryOutcome::Ambiguous(MemberRecoveryStatus::NotFound)
    ));
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 6);
    assert_eq!(provider.status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication_provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication_provider.publish_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        proofs.len(),
        5,
        "NotFound after OutcomeUnknown cannot manufacture the missing sixth proof"
    );
    match client
        .adopt(&mut sixth)
        .await
        .expect("NotFound remains non-exclusionary for exact sixth adoption")
    {
        MemberRecoveryOutcome::Conclusive(proof) => proofs.push(*proof),
        _ => panic!("the exact sixth member must become conclusive only through adoption"),
    }
    let all = CompleteProofSet::new(proofs).expect("six SDK-issued proofs after exact adoption");
    let mut terminal = client
        .prepare_terminal(active.for_terminal(), &all)
        .await
        .expect("adopted sixth proof completes the exact terminal body");
    assert!(matches!(
        client
            .terminalize(&mut terminal)
            .await
            .expect("terminalize exactly once after adoption"),
        TerminalizationOutcome::Committed(TerminalReceipt::Established(_))
    ));
    assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 1);
    fleet
        .wait_all_application_sequences(sequence_before + 2)
        .await;
    assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 1);

    shutdown_client.shutdown().await;
    server.abort_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_durable_crash_cut_matrix() {
    assert_eq!(DURABLE_ROSTER_CRASH_CUT_MATRIX.len(), 13);
    for cut in DURABLE_ROSTER_CRASH_CUT_MATRIX {
        match cut {
            DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown => {
                persistent_three_voter_protected_roster_terminal_reply_outcome_unknown().await;
            }
            DurableRosterCrashCut::EstablishedBeforePublication => {
                persistent_three_voter_protected_roster_established_before_publication().await;
            }
            DurableRosterCrashCut::PublicationFirstSendNotTransmitted => {
                persistent_three_voter_protected_roster_publication_first_send_not_transmitted()
                    .await;
            }
            DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement => {
                persistent_three_voter_protected_roster_publication_before_acknowledgement().await;
            }
            _ => {
                persistent_three_voter_protected_roster_recovers_provider_crash_cut(cut, false)
                    .await
            }
        }
    }
}

/// Drive each provider-local cut through the real revision-five ingress, then
/// discard every client/provider handle and recover through the newly observed
/// leader under a higher current fence. The provider journal is the only state
/// deliberately retained across that durable-reopen boundary.
async fn persistent_three_voter_protected_roster_recovers_provider_crash_cut(
    cut: DurableRosterCrashCut,
    force_snapshot_before_full_restart: bool,
) {
    assert!(
        !force_snapshot_before_full_restart
            || matches!(cut, DurableRosterCrashCut::PreparedBeforeRun),
        "the snapshot/restart evidence compacts the retained PollAdmitted body before any member effect"
    );
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_roster_attestation(
        Arc::clone(&pki),
        ProductionRosterAttestationIssuer::trust_root(),
    )
    .await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    let server_spiffe = three_voter_spiffe(leader);
    let client_spiffe = spiffe("three-voter-durable-roster-crash-cut-client");
    let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(leader),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let initial_service = Arc::new(fleet.stores[leader].consumer_service());
    let initial_transport = Arc::new(match cut {
        DurableRosterCrashCut::PollAdmittedBeforeProviderWork => {
            CommitThenLoseConsumerResponse::roster_admission(
                initial_service.clone(),
                initial_service,
            )
        }
        DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown => {
            CommitThenLoseConsumerResponse::roster_terminal(
                initial_service.clone(),
                initial_service,
            )
        }
        _ => CommitThenLoseConsumerResponse::roster_passthrough(
            initial_service.clone(),
            initial_service,
        ),
    });
    let (initial_server, initial_address) = SessionQuorumConsumerServer::new(
        initial_transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_roster_ingress(initial_transport.clone(), ingress_signer.clone())
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("durable crash-cut initial listener"),
    )
    .await
    .expect("start durable crash-cut initial listener");
    let initial_server = AbortConsumerServerOnDrop::new(initial_server);

    let setup_directory = tempfile::tempdir().expect("durable crash-cut setup directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            setup_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("private durable crash-cut setup directory");
    }
    let setup_provider = CountingKeyProvider::with_active_session_key();
    let setup_physical: Arc<dyn SessionBackend> = Arc::new(
        SessionConsumerFencedTransitionBackend::stateless(consumer_client(
            &pki,
            initial_address,
            &server_spiffe,
            &client_spiffe,
            fleet.voter_authority(leader),
        ))
        .expect("durable crash-cut public SessionBackend"),
    );
    let setup_outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            setup_physical,
            Arc::clone(&setup_provider),
            "three-voter-durable-roster-crash-cut",
        )
        .with_fenced_transition_journal(Arc::new(
            PreparedFencedTransitionJournal::create_new(
                setup_directory.path().join("prepared.sqlite"),
                PreparedFencedTransitionJournalKey::from_bytes([0x9a; 32]),
            )
            .expect("create durable crash-cut prepared journal"),
        )),
    );
    let key = test_key();
    let owner = OwnerId::new("three-voter-durable-roster-crash-cut-owner")
        .expect("durable crash-cut owner");
    let initial_lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        // Crossing the production 4,096-entry snapshot threshold is
        // intentionally much longer than an ordinary crash cut. Keep the
        // authenticated authority live for that qualification workload; this
        // does not alter any transport/consensus operation deadline.
        Duration::from_secs(if force_snapshot_before_full_restart {
            10 * 60
        } else {
            60
        }),
    )
    .expect("durable crash-cut incumbent lease");
    let incumbent = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0x91; 16]),
        initial_lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: initial_lease
                .committed_fence()
                .expect("durable crash-cut incumbent fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("three-voter-durable-roster-crash-cut-current"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0x91]),
        }),
    )
    .expect("durable crash-cut incumbent request");
    let incumbent = setup_outer
        .prepare_fenced_transition(incumbent)
        .await
        .expect("prepare durable crash-cut incumbent");
    let incumbent = setup_outer
        .fenced_transition(&incumbent)
        .await
        .expect("commit durable crash-cut incumbent");
    let original_guard = incumbent.lease().clone();
    let expected_generation = incumbent.committed_generation();
    let admission_baseline = fleet.application_sequences().await[leader];
    fleet
        .wait_all_application_sequences(admission_baseline)
        .await;

    let members = (0_u8..6)
        .map(|ordinal| {
            Member::new(
                ordinal,
                MemberOperationId::from_bytes([ordinal.saturating_add(81); 16])
                    .expect("durable crash-cut stable member ID"),
                vec![0xc6, ordinal],
                u64::from(ordinal) + 501,
            )
            .expect("durable crash-cut member")
        })
        .collect::<Vec<_>>();
    let protected_plan = format!("durable-crash-cut-plan-{}", cut.name()).into_bytes();
    let protected_checkpoint = vec![0xc7, 0x01];
    let protected_result = vec![0xc8, 0x02];
    let proposal = AdmissionProposal::new(
        FencedMutationRosterProfile::v1(),
        RosterId::from_bytes([0x92; 16]).expect("durable crash-cut roster ID"),
        members.clone(),
        EstablishedMutation::no_op(),
        protected_plan.clone(),
        protected_checkpoint.clone(),
        protected_result.clone(),
    )
    .expect("durable crash-cut exact admission body");
    let provider_directory = tempfile::tempdir().expect("durable crash-cut provider directory");
    let provider_journal_path = provider_directory.path().join("provider.journal");
    let initial_journal = Arc::new(
        DurableRosterProviderJournal::create(&provider_journal_path)
            .expect("create durable crash-cut provider journal"),
    );
    initial_journal
        .append_admission(
            proposal.roster_id(),
            &protected_plan,
            &protected_checkpoint,
            &protected_result,
        )
        .expect("persist exact durable crash-cut admission body");
    let initial_persistent = protected_roster_persistent_client(
        &pki,
        initial_address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    let initial_shutdown = initial_persistent.clone();
    let initial_provider = Arc::new(DurableCrashCutProvider::initial(
        Arc::clone(&initial_journal),
        cut,
        attestor.clone(),
    ));
    let publication_directory =
        tempfile::tempdir().expect("durable crash-cut publication directory");
    let publication_journal_path = publication_directory.path().join("publication.journal");
    let initial_publication = Arc::new(DurableEstablishedPublicationProvider::initial(
        DurableEstablishedPublicationJournal::create(&publication_journal_path)
            .expect("create durable crash-cut publication journal"),
        matches!(
            cut,
            DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement
        ),
        matches!(
            cut,
            DurableRosterCrashCut::PublicationFirstSendNotTransmitted
        ),
    ));
    let initial_adapter = initial_persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&initial_provider),
            Arc::clone(&initial_publication),
            executor_attestor.clone(),
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("positive durable crash-cut concurrency"),
        )
        .expect("compose durable crash-cut initial adapter");
    let initial_client = initial_adapter.client().clone();
    let mut admission = initial_client
        .prepare(
            original_guard.clone(),
            expected_generation,
            proposal.clone(),
        )
        .expect("prepare durable crash-cut admission");
    let roster_id = admission.roster_id();
    let mut active = if matches!(cut, DurableRosterCrashCut::BeforeAdmission) {
        None
    } else {
        let active = match initial_client
            .admit(&mut admission)
            .await
            .expect("durable crash-cut PollAdmit")
        {
            AdmissionOutcome::Admitted(active) => {
                assert!(
                    !matches!(cut, DurableRosterCrashCut::PollAdmittedBeforeProviderWork),
                    "the admission-reply-loss cut must enter same-request status recovery"
                );
                Some(active)
            }
            AdmissionOutcome::NotTransmitted => {
                panic!("durable crash-cut PollAdmit must cross the real ingress")
            }
            AdmissionOutcome::OutcomeUnknown(_) => {
                assert!(matches!(
                    cut,
                    DurableRosterCrashCut::PollAdmittedBeforeProviderWork
                ));
                match initial_client
                    .admission_status(&admission)
                    .await
                    .expect("same-request PollAdmitted status readback")
                {
                    RecoveryOutcome::Admitted(recovered) => {
                        assert_eq!(recovered.roster_id(), roster_id);
                        assert_eq!(recovered.members(), members.as_slice());
                        assert_eq!(recovered.protected_plan(), protected_plan.as_slice());
                    }
                    RecoveryOutcome::Terminal(_) | RecoveryOutcome::Compacted => {
                        panic!("lost admission reply must read back exact PollAdmitted")
                    }
                }
                None
            }
        };
        fleet
            .wait_all_application_sequences(admission_baseline + 1)
            .await;
        assert_eq!(
            initial_transport
                .roster_admission_calls
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            initial_transport
                .roster_terminal_calls
                .load(Ordering::SeqCst),
            0
        );
        active
    };
    assert_eq!(initial_provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(initial_provider.execute_calls.load(Ordering::SeqCst), 0);

    let mut initial_proofs = Vec::with_capacity(6);
    for ordinal in 0..cut.initial_member_count() {
        let mut member = active
            .as_mut()
            .expect("only admitted cuts run provider work")
            .member(MemberOrdinal::new(ordinal).expect("durable crash-cut ordinal"))
            .expect("issue durable crash-cut member");
        let prepared = initial_client
            .prepare_member(&mut member)
            .await
            .expect("provider-local durable crash-cut prepare");
        if cut.pending_prepare() {
            assert!(matches!(
                prepared,
                MemberPrepareOutcome::Ambiguous(MemberRecoveryStatus::Pending)
            ));
            break;
        }
        assert!(matches!(prepared, MemberPrepareOutcome::Prepared));
        if matches!(cut, DurableRosterCrashCut::PreparedBeforeRun) {
            break;
        }
        let outcome = initial_client
            .execute(&mut member)
            .await
            .expect("provider-local durable crash-cut execute");
        if cut.outcome_unknown_ordinal() == Some(ordinal) {
            assert!(matches!(
                outcome,
                ExecuteOutcome::Ambiguous(MemberRecoveryStatus::OutcomeUnknown)
            ));
            break;
        }
        match outcome {
            ExecuteOutcome::Conclusive(proof) => initial_proofs.push(*proof),
            _ => panic!("non-ambiguous durable crash-cut execute must be conclusive"),
        }
    }
    assert_eq!(
        initial_transport
            .roster_terminal_calls
            .load(Ordering::SeqCst),
        0
    );
    if matches!(
        cut,
        DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown
            | DurableRosterCrashCut::EstablishedBeforePublication
            | DurableRosterCrashCut::PublicationFirstSendNotTransmitted
            | DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement
    ) {
        let proofs = CompleteProofSet::new(initial_proofs)
            .expect("terminal crash cuts persist all six exact proofs first");
        let mut terminal = initial_client
            .prepare_terminal(
                active
                    .as_ref()
                    .expect("terminal crash cuts retain an active roster")
                    .for_terminal(),
                &proofs,
            )
            .await
            .expect("prepare terminal crash-cut body");
        match cut {
            DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown => {
                assert!(matches!(
                    initial_client
                        .terminalize(&mut terminal)
                        .await
                        .expect("terminal reply-loss client result"),
                    TerminalizationOutcome::OutcomeUnknown
                ));
                match initial_client
                    .terminal_status(&mut terminal)
                    .await
                    .expect("same-request terminal status readback")
                {
                    TerminalStatus::Committed(TerminalReceipt::Established(established)) => {
                        assert_eq!(established.protected_checkpoint(), protected_checkpoint);
                        assert_eq!(established.protected_result(), protected_result);
                    }
                    TerminalStatus::Committed(TerminalReceipt::Aborted(_))
                    | TerminalStatus::Admitted
                    | TerminalStatus::Compacted => {
                        panic!("lost terminal reply must read back exact Established")
                    }
                }
            }
            DurableRosterCrashCut::EstablishedBeforePublication => {
                match initial_client
                    .terminalize(&mut terminal)
                    .await
                    .expect("commit Established before publication")
                {
                    TerminalizationOutcome::Committed(TerminalReceipt::Established(
                        established,
                    )) => {
                        assert_eq!(established.protected_checkpoint(), protected_checkpoint);
                        assert_eq!(established.protected_result(), protected_result);
                    }
                    _ => panic!("Established-before-publication cut requires Established"),
                }
            }
            DurableRosterCrashCut::PublicationFirstSendNotTransmitted => {
                let mut publication = match initial_client
                    .terminalize(&mut terminal)
                    .await
                    .expect("commit Established before transport-conclusive publication loss")
                {
                    TerminalizationOutcome::Committed(TerminalReceipt::Established(
                        established,
                    )) => {
                        assert_eq!(established.protected_checkpoint(), protected_checkpoint);
                        assert_eq!(established.protected_result(), protected_result);
                        established.into_publication()
                    }
                    _ => panic!("publication replay cut requires an Established receipt"),
                };
                assert!(
                    initial_adapter.publish(&mut publication).await.is_err(),
                    "the reply loss follows a retained transport-conclusive NotTransmitted marker"
                );
                assert_eq!(
                    initial_publication
                        .journal
                        .state_count(DurableEstablishedPublicationState::NotTransmitted),
                    1,
                    "the first send's exact no-transmission evidence is durable before the crash"
                );
                assert_eq!(
                    initial_publication
                        .journal
                        .state_results(DurableEstablishedPublicationState::NotTransmitted),
                    vec![durable_roster_hex(&protected_result)],
                    "the retained no-transmission marker is bound to the admitted protected result"
                );
                assert_eq!(
                    initial_publication
                        .journal
                        .state_count(DurableEstablishedPublicationState::Published),
                    0,
                    "a transport-conclusive no-transmission cannot manufacture an external effect"
                );
            }
            DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement => {
                let mut publication = match initial_client
                    .terminalize(&mut terminal)
                    .await
                    .expect("commit Established before publication acknowledgement")
                {
                    TerminalizationOutcome::Committed(TerminalReceipt::Established(
                        established,
                    )) => {
                        assert_eq!(established.protected_checkpoint(), protected_checkpoint);
                        assert_eq!(established.protected_result(), protected_result);
                        established.into_publication()
                    }
                    _ => panic!("publication crash cut requires an Established receipt"),
                };
                assert!(
                    initial_adapter.publish(&mut publication).await.is_err(),
                    "the durable published marker must survive the lost acknowledgement"
                );
                assert_eq!(
                    initial_publication
                        .journal
                        .state_count(DurableEstablishedPublicationState::Published),
                    1
                );
            }
            _ => unreachable!("only terminal crash cuts enter this branch"),
        }
        fleet
            .wait_all_application_sequences(admission_baseline + 2)
            .await;
        assert_eq!(
            initial_transport
                .roster_terminal_calls
                .load(Ordering::SeqCst),
            1
        );
    }
    let initial_admissions = initial_transport
        .roster_admission_calls
        .load(Ordering::SeqCst);
    let initial_terminals = initial_transport
        .roster_terminal_calls
        .load(Ordering::SeqCst);
    let protected_payload_key_calls_before_restart = setup_provider.calls();
    #[cfg(feature = "test-control")]
    if force_snapshot_before_full_restart {
        const SNAPSHOT_COMMANDS: usize = 4_300;
        let mut workload_leader = leader;
        let mut workload_term = fleet.stores[workload_leader].status().term;
        let admitted_log_index = fleet.stores[workload_leader]
            .status()
            .last_log_index
            .expect("retained PollAdmitted log index before snapshot");
        let target_log_index = admitted_log_index + SNAPSHOT_COMMANDS as u64;
        tokio::time::timeout(Duration::from_secs(5 * 60), async {
            const MAX_SNAPSHOT_MAINTENANCE_REJECTIONS: usize = 8;
            let mut maintenance_rejections = 0_usize;
            while fleet.stores[workload_leader]
                .status()
                .last_log_index
                .is_none_or(|index| index < target_log_index)
            {
                match fleet.stores[workload_leader]
                    .max_replication_sequence()
                    .await
                {
                    Ok(_) => {}
                    Err(StoreError::BackendUnavailable(_))
                        if maintenance_rejections < MAX_SNAPSHOT_MAINTENANCE_REJECTIONS =>
                    {
                        // Snapshot installation can briefly close ordinary
                        // proposal admission. Count the committed index—not
                        // replies—and continue through any self-reporting
                        // admitted-quorum successor at a monotonic term.
                        maintenance_rejections += 1;
                        (workload_leader, _, workload_term) = fleet
                            .wait_for_admitted_quorum_leader(&[0, 1, 2], workload_term)
                            .await;
                        tokio::task::yield_now().await;
                    }
                    Err(_) => panic!("snapshot qualification command was rejected"),
                }
            }
        })
        .await
        .expect("snapshot qualification command batch completes");
        assert!(
            fleet.stores[workload_leader]
                .status()
                .last_log_index
                .is_some_and(|index| index >= target_log_index),
            "the retained PollAdmitted body crosses the production snapshot-log threshold"
        );
        tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
            loop {
                let progress = fleet.stores[workload_leader]
                    .probe_durable_readiness()
                    .await
                    .recovery_progress();
                if progress
                    .snapshot_index()
                    .is_some_and(|index| index >= admitted_log_index)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("retained PollAdmitted body is compacted into a snapshot before restart");
        fleet.wait_all_application_sequences(target_log_index).await;
    }
    #[cfg(not(feature = "test-control"))]
    assert!(
        !force_snapshot_before_full_restart,
        "snapshot/restart evidence requires the explicit test-control feature"
    );
    drop(active);
    drop(admission);
    drop(initial_client);
    drop(initial_adapter);
    initial_shutdown.shutdown().await;
    initial_server.abort_and_wait().await;
    let fleet = if matches!(
        cut,
        DurableRosterCrashCut::EstablishedBeforePublication
            | DurableRosterCrashCut::PublicationFirstSendNotTransmitted
            | DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement
    ) || force_snapshot_before_full_restart
    {
        drop(initial_transport);
        fleet.restart_all().await
    } else {
        fleet
    };

    let (recovery_leader, _, _) = if force_snapshot_before_full_restart {
        // A snapshot/full-fleet reopen can expose one lagging voter while an
        // admitted quorum has already converged on the durable successor.
        // Recovery needs that quorum authority, not unanimous propagation of
        // the observation; the exact all-voter application equality below
        // remains the convergence proof before roster accounting resumes.
        fleet.wait_for_admitted_quorum_leader(&[0, 1, 2], 0).await
    } else {
        fleet.wait_for_observed_leader().await
    };
    // Exercise recovery through the currently observed leader while all three
    // voters independently validate and apply the retained state. Endpoint
    // routing is intentionally outside this roster qualification boundary.
    let recovery_voter = recovery_leader;
    let recovery_server_spiffe = three_voter_spiffe(recovery_voter);
    let recovery_service = Arc::new(fleet.stores[recovery_voter].consumer_service());
    let recovery_transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        recovery_service.clone(),
        recovery_service,
    ));
    let (recovery_server, recovery_address) = SessionQuorumConsumerServer::new(
        recovery_transport.clone(),
        pki.server_config(&recovery_server_spiffe),
        authorizer,
    )
    .with_roster_ingress(recovery_transport.clone(), ingress_signer.clone())
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("durable crash-cut recovery listener"),
    )
    .await
    .expect("start durable crash-cut recovery listener");
    let recovery_server = AbortConsumerServerOnDrop::new(recovery_server);
    // Mutating lease acquisition and the read-only recovery boundary both use
    // the current leader; durable-reopen evidence comes from the discarded
    // clients/providers and the full-fleet restart cuts.
    let lease_server_spiffe = three_voter_spiffe(recovery_leader);
    let lease_service = Arc::new(fleet.stores[recovery_leader].consumer_service());
    let lease_transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        lease_service.clone(),
        lease_service,
    ));
    let (lease_server, lease_address) = SessionQuorumConsumerServer::new(
        lease_transport.clone(),
        pki.server_config(&lease_server_spiffe),
        three_voter_authorizer(&fleet.stores[recovery_leader], &client_spiffe).await,
    )
    .with_roster_ingress(lease_transport.clone(), ingress_signer.clone())
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("durable crash-cut leader lease listener"),
    )
    .await
    .expect("start durable crash-cut leader lease listener");
    let lease_server = AbortConsumerServerOnDrop::new(lease_server);
    let lease_client = consumer_client(
        &pki,
        lease_address,
        &lease_server_spiffe,
        &client_spiffe,
        fleet.voter_authority(recovery_leader),
    );
    let original_owner = original_guard.owner().clone();
    let original_admission_fence = original_guard.fence();
    let (expired_guard, current_guard) = if matches!(cut, DurableRosterCrashCut::BeforeAdmission) {
        (None, original_guard.clone())
    } else {
        lease_client
            .release_with_id(
                SessionConsumerRequestId::from_bytes([0x93; 16]),
                original_guard.clone(),
            )
            .await
            .expect("release original durable crash-cut guard");
        let expired = lease_client
            .acquire_with_id(
                SessionConsumerRequestId::from_bytes([0x94; 16]),
                key.clone(),
                OwnerId::new("three-voter-durable-roster-crash-cut-expired")
                    .expect("durable crash-cut expired owner"),
                Duration::from_millis(20),
            )
            .await
            .expect("acquire expired durable crash-cut guard");
        while Timestamp::now_utc() <= expired.expires_at() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let current = lease_client
            .acquire_with_id(
                SessionConsumerRequestId::from_bytes([0x95; 16]),
                key.clone(),
                OwnerId::new("three-voter-durable-roster-crash-cut-current")
                    .expect("durable crash-cut current owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("acquire current higher durable crash-cut guard");
        assert!(current.fence() > expired.fence());
        (Some(expired), current)
    };
    let mut foreign_key = key.clone();
    foreign_key.stable_id = Bytes::from_static(b"foreign-opaque-session-reference")
        .try_into()
        .expect("foreign stable session ID");
    let foreign_guard = lease_client
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0x96; 16]),
            foreign_key,
            OwnerId::new("three-voter-durable-roster-crash-cut-foreign")
                .expect("foreign durable crash-cut owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire foreign durable crash-cut guard");
    // The deliberately distinct recovery voter can trail the leader by one
    // already-committed lease command at this instant.  Freeze the largest
    // applied index, then require every voter to converge to that exact
    // pre-roster baseline before counting provider-local work.
    let recovery_baseline = fleet
        .application_sequences()
        .await
        .into_iter()
        .max()
        .expect("three-voter recovery baseline");
    fleet
        .wait_all_application_sequences(recovery_baseline)
        .await;
    assert_eq!(
        fleet.application_sequences().await,
        [recovery_baseline; THREE_VOTER_COUNT],
        "all lease/takeover commands converge before roster mutation accounting",
    );
    let recovered_journal = Arc::new(
        DurableRosterProviderJournal::reopen(&provider_journal_path)
            .expect("reopen durable crash-cut provider journal"),
    );
    let recovery_provider = Arc::new(DurableCrashCutProvider::recovery(
        Arc::clone(&recovered_journal),
        attestor.clone(),
    ));
    let recovery_publication = Arc::new(DurableEstablishedPublicationProvider::recovery(
        DurableEstablishedPublicationJournal::reopen(&publication_journal_path)
            .expect("reopen durable crash-cut publication journal"),
        false,
    ));
    let (recovery_roster_address, recovery_roster_voter) =
        if matches!(cut, DurableRosterCrashCut::BeforeAdmission) {
            (lease_address, recovery_leader)
        } else {
            (recovery_address, recovery_voter)
        };
    let recovery_roster_server_spiffe = if matches!(cut, DurableRosterCrashCut::BeforeAdmission) {
        &lease_server_spiffe
    } else {
        &recovery_server_spiffe
    };
    let recovery_persistent = protected_roster_persistent_client(
        &pki,
        recovery_roster_address,
        recovery_roster_server_spiffe,
        &client_spiffe,
        fleet.voter_authority(recovery_roster_voter),
    );
    let recovery_shutdown = recovery_persistent.clone();
    let recovery_adapter = recovery_persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&recovery_provider),
            Arc::clone(&recovery_publication),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("positive recovery concurrency"),
        )
        .expect("compose durable crash-cut recovery adapter");
    let recovery_client = recovery_adapter.client().clone();
    if !matches!(cut, DurableRosterCrashCut::BeforeAdmission) {
        assert!(matches!(
            RecoveryInput::new(
                roster_id,
                original_owner.clone(),
                original_admission_fence,
                original_guard.clone(),
                expected_generation,
            ),
            Err(RosterClientError::AuthorityRejected)
        ));
        for (authority_case, expected_error, rejected) in [
            (
                "expired",
                RosterClientError::AuthorityRejected,
                RecoveryInput::new(
                    roster_id,
                    original_owner.clone(),
                    original_admission_fence,
                    expired_guard
                        .clone()
                        .expect("expired durable crash-cut guard"),
                    expected_generation,
                )
                .expect("expired durable crash-cut recovery input"),
            ),
            (
                "foreign",
                RosterClientError::RecoveryRequired,
                RecoveryInput::new(
                    roster_id,
                    original_owner.clone(),
                    original_admission_fence,
                    foreign_guard,
                    expected_generation,
                )
                .expect("foreign durable crash-cut recovery input"),
            ),
        ] {
            let result = recovery_client.recover(&rejected).await;
            assert!(
                matches!(result, Err(error) if error == expected_error),
                "{} rejects its {} recovery authority with the fixed classification, got {result:?}",
                cut.name(),
                authority_case,
            );
        }
    }
    if matches!(
        cut,
        DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown
            | DurableRosterCrashCut::EstablishedBeforePublication
            | DurableRosterCrashCut::PublicationFirstSendNotTransmitted
            | DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement
    ) {
        let input = RecoveryInput::new(
            roster_id,
            original_owner,
            original_admission_fence,
            current_guard.clone(),
            expected_generation,
        )
        .expect("current terminal crash-cut recovery input");
        let mut publication = match recovery_client
            .recover(&input)
            .await
            .expect("recover committed terminal from another voter")
        {
            RecoveryOutcome::Terminal(TerminalReceipt::Established(established)) => {
                assert_eq!(established.protected_checkpoint(), protected_checkpoint);
                assert_eq!(established.protected_result(), protected_result);
                established.into_publication()
            }
            RecoveryOutcome::Terminal(TerminalReceipt::Aborted(_)) => {
                panic!("terminal crash cuts must retain Established")
            }
            RecoveryOutcome::Admitted(_) | RecoveryOutcome::Compacted => {
                panic!("terminal crash cuts must not reopen execution authority")
            }
        };
        recovery_adapter
            .publish(&mut publication)
            .await
            .expect("only recovered Established receipt can publish");
        assert_eq!(
            initial_admissions
                + recovery_transport
                    .roster_admission_calls
                    .load(Ordering::SeqCst)
                + lease_transport
                    .roster_admission_calls
                    .load(Ordering::SeqCst),
            1,
            "terminal crash cut accepts one PollAdmit proposal"
        );
        assert_eq!(initial_terminals, 1);
        assert_eq!(
            recovery_transport
                .roster_terminal_calls
                .load(Ordering::SeqCst)
                + lease_transport.roster_terminal_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            fleet.application_sequences().await,
            [recovery_baseline; THREE_VOTER_COUNT],
            "recovery and publication cannot append after the retained terminal",
        );
        assert_eq!(
            recovery_publication
                .journal
                .state_count(DurableEstablishedPublicationState::Published),
            1,
            "the exact publication cannot be duplicated after restart recovery",
        );
        if matches!(
            cut,
            DurableRosterCrashCut::PublicationFirstSendNotTransmitted
        ) {
            assert!(
                current_guard.fence() > original_admission_fence,
                "the replay must recover under higher current authority"
            );
            assert_eq!(
                recovery_publication.begin_calls.load(Ordering::SeqCst),
                0,
                "a retained transport-conclusive marker permits status/adopt only, never a rebuilt intent"
            );
            assert_eq!(
                recovery_publication.status_calls.load(Ordering::SeqCst),
                1,
                "the successor first reads the retained exact publication identity"
            );
            assert_eq!(
                recovery_publication.adopt_calls.load(Ordering::SeqCst),
                1,
                "the successor performs one exact-byte resend through adoption"
            );
            assert_eq!(
                recovery_publication
                    .journal
                    .state_count(DurableEstablishedPublicationState::NotTransmitted),
                1,
                "the original no-transmission evidence remains durable"
            );
            assert_eq!(
                recovery_publication
                    .journal
                    .state_results(DurableEstablishedPublicationState::NotTransmitted),
                vec![durable_roster_hex(&protected_result)],
                "the retained marker remains bound to the admitted protected result"
            );
            assert_eq!(
                recovery_publication
                    .journal
                    .state_results(DurableEstablishedPublicationState::Published),
                vec![durable_roster_hex(&protected_result)],
                "the one external send uses exactly the retained protected-result bytes"
            );
            assert_eq!(
                setup_provider.calls(),
                protected_payload_key_calls_before_restart,
                "successor publication reuses retained opaque bytes without rebuilding, resealing, or drawing an IV"
            );
        }
        recovery_shutdown.shutdown().await;
        recovery_server.abort_and_wait().await;
        lease_server.abort_and_wait().await;
        fleet.shutdown().await;
        return;
    }
    let mut recovered = if matches!(cut, DurableRosterCrashCut::BeforeAdmission) {
        let mut retry = recovery_client
            .prepare(current_guard, expected_generation, proposal)
            .expect("prepare retained pre-admission roster after restart");
        match recovery_client
            .admit(&mut retry)
            .await
            .expect("admit retained pre-admission roster after restart")
        {
            AdmissionOutcome::Admitted(active) => DurableCrashRecoveredRoster::Active(active),
            AdmissionOutcome::NotTransmitted | AdmissionOutcome::OutcomeUnknown(_) => {
                panic!("pre-admission restart retry must return its exact admitted body")
            }
        }
    } else {
        let input = RecoveryInput::new(
            roster_id,
            original_owner,
            original_admission_fence,
            current_guard,
            expected_generation,
        )
        .expect("current durable crash-cut recovery input");
        match recovery_client
            .recover(&input)
            .await
            .expect("cross-voter durable crash-cut recovery")
        {
            RecoveryOutcome::Admitted(recovered) => {
                DurableCrashRecoveredRoster::Recovered(recovered)
            }
            RecoveryOutcome::Terminal(_) | RecoveryOutcome::Compacted => {
                panic!("provider-only crash cut must retain its PollAdmitted roster")
            }
        }
    };
    assert_eq!(recovered.roster_id(), roster_id);
    assert_eq!(recovered.members(), members.as_slice());
    assert_eq!(recovered.protected_plan(), protected_plan.as_slice());
    let terminal_baseline =
        recovery_baseline + u64::from(matches!(cut, DurableRosterCrashCut::BeforeAdmission));
    fleet
        .wait_all_application_sequences(terminal_baseline)
        .await;
    let mut proofs = Vec::with_capacity(6);
    match &mut recovered {
        DurableCrashRecoveredRoster::Active(active) => {
            for ordinal in 0_u8..6 {
                let mut member = active
                    .member(MemberOrdinal::new(ordinal).expect("fresh durable crash-cut ordinal"))
                    .expect("issue fresh durable crash-cut member");
                assert!(matches!(
                    recovery_client
                        .prepare_member(&mut member)
                        .await
                        .expect("fresh durable crash-cut prepare"),
                    MemberPrepareOutcome::Prepared
                ));
                match recovery_client
                    .execute(&mut member)
                    .await
                    .expect("fresh durable crash-cut execute")
                {
                    ExecuteOutcome::Conclusive(proof) => proofs.push(*proof),
                    _ => panic!("fresh durable crash-cut member must execute conclusively"),
                }
            }
        }
        DurableCrashRecoveredRoster::Recovered(recovered) => {
            for ordinal in 0_u8..6 {
                let mut member = recovered
                    .member(
                        MemberOrdinal::new(ordinal).expect("recovered durable crash-cut ordinal"),
                    )
                    .expect("issue recovered durable crash-cut member");
                assert!(matches!(
                    recovery_client
                        .status(&mut member)
                        .await
                        .expect("recovery status"),
                    MemberRecoveryOutcome::Ambiguous(MemberRecoveryStatus::NotFound)
                ));
                match recovery_client
                    .adopt(&mut member)
                    .await
                    .expect("recovery exact adoption")
                {
                    MemberRecoveryOutcome::Conclusive(proof) => proofs.push(*proof),
                    _ => panic!("NotFound remains non-exclusionary for exact adoption"),
                }
            }
        }
    }
    assert_eq!(recovered_journal.phase_calls("apply", 0), 1);
    for ordinal in 0_u8..6 {
        assert_eq!(
            recovered_journal.phase_calls("apply", ordinal),
            1,
            "{} must never duplicate the stable member effect",
            cut.name(),
        );
    }
    assert_eq!(
        fleet.application_sequences().await,
        [terminal_baseline; THREE_VOTER_COUNT],
        "{} provider prepare/execute/status/adopt are local and cannot append roster proposals",
        cut.name(),
    );
    let proofs = CompleteProofSet::new(proofs).expect("six exact durable crash-cut proofs");
    let mut terminal = recovery_client
        .prepare_terminal(recovered.for_terminal(), &proofs)
        .await
        .expect("prepare terminal from all six exact proofs");
    let mut publication = match recovery_client
        .terminalize(&mut terminal)
        .await
        .expect("terminalize durable crash-cut roster")
    {
        TerminalizationOutcome::Committed(TerminalReceipt::Established(established)) => {
            assert_eq!(established.protected_checkpoint(), protected_checkpoint);
            assert_eq!(established.protected_result(), protected_result);
            established.into_publication()
        }
        TerminalizationOutcome::Committed(TerminalReceipt::Aborted(_)) => {
            panic!("six exact durable crash-cut proofs must establish")
        }
        TerminalizationOutcome::NotTransmitted | TerminalizationOutcome::OutcomeUnknown => {
            panic!("fresh durable crash-cut terminal must return Established")
        }
    };
    fleet
        .wait_all_application_sequences(terminal_baseline + 1)
        .await;
    assert_eq!(
        initial_admissions
            + recovery_transport
                .roster_admission_calls
                .load(Ordering::SeqCst)
            + lease_transport
                .roster_admission_calls
                .load(Ordering::SeqCst),
        1,
        "{} accepts exactly one PollAdmit proposal",
        cut.name(),
    );
    assert_eq!(
        recovery_transport
            .roster_terminal_calls
            .load(Ordering::SeqCst)
            + lease_transport.roster_terminal_calls.load(Ordering::SeqCst),
        1
    );
    recovery_adapter
        .publish(&mut publication)
        .await
        .expect("publication requires its exact Established receipt");
    assert!(recovery_publication.status_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        fleet.application_sequences().await,
        [terminal_baseline + 1; THREE_VOTER_COUNT],
        "publication is provider-local and cannot add a third roster proposal",
    );

    recovery_shutdown.shutdown().await;
    recovery_server.abort_and_wait().await;
    lease_server.abort_and_wait().await;
    fleet.shutdown().await;
}

async fn persistent_three_voter_protected_roster_terminal_reply_outcome_unknown() {
    persistent_three_voter_protected_roster_recovers_provider_crash_cut(
        DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown,
        false,
    )
    .await;
}

async fn persistent_three_voter_protected_roster_established_before_publication() {
    persistent_three_voter_protected_roster_recovers_provider_crash_cut(
        DurableRosterCrashCut::EstablishedBeforePublication,
        false,
    )
    .await;
}

async fn persistent_three_voter_protected_roster_publication_first_send_not_transmitted() {
    persistent_three_voter_protected_roster_recovers_provider_crash_cut(
        DurableRosterCrashCut::PublicationFirstSendNotTransmitted,
        false,
    )
    .await;
}

async fn persistent_three_voter_protected_roster_publication_before_acknowledgement() {
    persistent_three_voter_protected_roster_recovers_provider_crash_cut(
        DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_established_before_publication_survives_full_restart(
) {
    persistent_three_voter_protected_roster_established_before_publication().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_publication_published_before_acknowledgement_survives_full_restart(
) {
    persistent_three_voter_protected_roster_publication_before_acknowledgement().await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_exact_bytes_survive_snapshot_and_full_restart() {
    // The retained admission is compacted only after its first provider
    // prepare is durable. Recovery runs on a distinct voter under a higher
    // guard, proves the exact plan and ordered members, then establishes and
    // re-reads the exact checkpoint/result after the full-fleet restart.
    persistent_three_voter_protected_roster_recovers_provider_crash_cut(
        DurableRosterCrashCut::PreparedBeforeRun,
        true,
    )
    .await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_aborted_exact_bytes_survive_snapshot_and_full_restart(
) {
    // Unlike the Established snapshot case, this commits the terminal before
    // compaction. Every member first becomes recovery-only, then receives an
    // SDK-issued NotApplied + Reconciled proof; therefore the durable terminal
    // is conclusively Aborted and cannot produce publication authority.
    const SNAPSHOT_COMMANDS: usize = 4_300;
    const MAX_SNAPSHOT_MAINTENANCE_REJECTIONS: usize = 8;

    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_roster_attestation(
        Arc::clone(&pki),
        ProductionRosterAttestationIssuer::trust_root(),
    )
    .await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    let recovery_voter = (leader + 1) % THREE_VOTER_COUNT;
    let server_spiffe = three_voter_spiffe(leader);
    let client_spiffe = spiffe("three-voter-roster-aborted-snapshot-client");
    let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(leader),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let initial_service = Arc::new(fleet.stores[leader].consumer_service());
    let initial_transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        initial_service.clone(),
        initial_service,
    ));
    let (initial_server, initial_address) = SessionQuorumConsumerServer::new(
        initial_transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_roster_ingress(initial_transport.clone(), ingress_signer.clone())
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("Aborted snapshot initial listener"),
    )
    .await
    .expect("start Aborted snapshot initial listener");
    let initial_server = AbortConsumerServerOnDrop::new(initial_server);

    let setup_directory = tempfile::tempdir().expect("Aborted snapshot setup directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(
            setup_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("private Aborted snapshot setup directory");
    }
    let setup_provider = CountingKeyProvider::with_active_session_key();
    let setup_physical: Arc<dyn SessionBackend> = Arc::new(
        SessionConsumerFencedTransitionBackend::stateless(consumer_client(
            &pki,
            initial_address,
            &server_spiffe,
            &client_spiffe,
            fleet.voter_authority(leader),
        ))
        .expect("Aborted snapshot public SessionBackend"),
    );
    let setup_outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            setup_physical,
            Arc::clone(&setup_provider),
            "three-voter-roster-aborted-snapshot",
        )
        .with_fenced_transition_journal(Arc::new(
            PreparedFencedTransitionJournal::create_new(
                setup_directory.path().join("prepared.sqlite"),
                PreparedFencedTransitionJournalKey::from_bytes([0xab; 32]),
            )
            .expect("create Aborted snapshot prepared journal"),
        )),
    );
    let key = test_key();
    let owner =
        OwnerId::new("three-voter-roster-aborted-snapshot-owner").expect("Aborted snapshot owner");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        // The established physical-snapshot qualification already uses this
        // fixed lifetime; it covers the bounded 4,300-command workload only.
        Duration::from_secs(10 * 60),
    )
    .expect("Aborted snapshot incumbent lease");
    let incumbent = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xac; 16]),
        lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: lease
                .committed_fence()
                .expect("Aborted snapshot incumbent fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("three-voter-roster-aborted-snapshot-current"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0xad]),
        }),
    )
    .expect("Aborted snapshot incumbent request");
    let incumbent = setup_outer
        .prepare_fenced_transition(incumbent)
        .await
        .expect("prepare Aborted snapshot incumbent");
    let incumbent = setup_outer
        .fenced_transition(&incumbent)
        .await
        .expect("commit Aborted snapshot incumbent");
    let original_guard = incumbent.lease().clone();
    let expected_generation = incumbent.committed_generation();
    let admission_baseline = fleet.application_sequences().await[leader];
    fleet
        .wait_all_application_sequences(admission_baseline)
        .await;

    let members = (0_u8..6)
        .map(|ordinal| {
            Member::new(
                ordinal,
                MemberOperationId::from_bytes([ordinal.saturating_add(101); 16])
                    .expect("Aborted snapshot member ID"),
                vec![0xae, ordinal],
                u64::from(ordinal) + 701,
            )
            .expect("Aborted snapshot member")
        })
        .collect::<Vec<_>>();
    let protected_plan = b"aborted-snapshot-plan".to_vec();
    let protected_checkpoint = vec![0xaf, 0x01, 0x00, 0xff];
    let protected_result = vec![0xb0, 0x02, 0x00, 0xfe];
    let proposal = AdmissionProposal::new(
        FencedMutationRosterProfile::v1(),
        RosterId::from_bytes([0xb1; 16]).expect("Aborted snapshot roster ID"),
        members.clone(),
        EstablishedMutation::no_op(),
        protected_plan.clone(),
        protected_checkpoint.clone(),
        protected_result.clone(),
    )
    .expect("Aborted snapshot exact admission body");
    let initial_persistent = protected_roster_persistent_client(
        &pki,
        initial_address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    let initial_shutdown = initial_persistent.clone();
    let initial_provider = Arc::new(
        SixMemberRosterEvidenceProvider::execute_outcome_unknown_then_reconciled(attestor.clone()),
    );
    let initial_publication = Arc::new(EstablishedPublicationEvidenceProvider::default());
    let initial_adapter = initial_persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&initial_provider),
            Arc::clone(&initial_publication),
            executor_attestor.clone(),
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("positive Aborted snapshot concurrency"),
        )
        .expect("compose Aborted snapshot initial adapter");
    let initial_client = initial_adapter.client().clone();
    let mut admission = initial_client
        .prepare(original_guard.clone(), expected_generation, proposal)
        .expect("prepare Aborted snapshot admission");
    let roster_id = admission.roster_id();
    let mut active = match initial_client
        .admit(&mut admission)
        .await
        .expect("admit Aborted snapshot roster")
    {
        AdmissionOutcome::Admitted(active) => active,
        AdmissionOutcome::NotTransmitted | AdmissionOutcome::OutcomeUnknown(_) => {
            panic!("fresh Aborted snapshot admission must return its exact active roster")
        }
    };
    fleet
        .wait_all_application_sequences(admission_baseline + 1)
        .await;
    assert_eq!(active.members(), members.as_slice());
    assert_eq!(active.protected_plan(), protected_plan.as_slice());

    let mut proofs = Vec::with_capacity(6);
    for ordinal in 0_u8..6 {
        let mut member = active
            .member(MemberOrdinal::new(ordinal).expect("Aborted snapshot member ordinal"))
            .expect("issue Aborted snapshot member");
        assert!(matches!(
            initial_client
                .prepare_member(&mut member)
                .await
                .expect("prepare Aborted snapshot member"),
            MemberPrepareOutcome::Prepared
        ));
        assert!(matches!(
            initial_client
                .execute(&mut member)
                .await
                .expect("execute Aborted snapshot member"),
            ExecuteOutcome::Ambiguous(MemberRecoveryStatus::OutcomeUnknown)
        ));
        let mut member = member
            .into_recoverable()
            .expect("ambiguous Aborted snapshot member is recovery-only");
        match initial_client
            .reconcile(&mut member)
            .await
            .expect("reconcile Aborted snapshot member")
        {
            MemberRecoveryOutcome::Conclusive(proof) => proofs.push(*proof),
            _ => {
                panic!("each Aborted snapshot member needs conclusive reconciliation")
            }
        }
    }
    assert_eq!(initial_provider.prepare_calls.load(Ordering::SeqCst), 6);
    assert_eq!(initial_provider.execute_calls.load(Ordering::SeqCst), 6);
    assert_eq!(initial_provider.reconcile_calls.load(Ordering::SeqCst), 6);
    assert_eq!(initial_provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(initial_provider.adopt_calls.load(Ordering::SeqCst), 0);
    let proofs =
        CompleteProofSet::new(proofs).expect("six SDK-issued NotApplied + Reconciled proofs");
    let mut terminal = initial_client
        .prepare_terminal(active.for_terminal(), &proofs)
        .await
        .expect("prepare exact Aborted terminal body");
    match initial_client
        .terminalize(&mut terminal)
        .await
        .expect("commit exact Aborted terminal")
    {
        TerminalizationOutcome::Committed(TerminalReceipt::Aborted(aborted)) => {
            assert_eq!(aborted.protected_checkpoint(), protected_checkpoint);
            assert_eq!(aborted.protected_result(), protected_result);
            // AbortedTerminal deliberately has no into_publication conversion.
        }
        TerminalizationOutcome::Committed(TerminalReceipt::Established(_)) => {
            panic!("reconciled non-applied proofs must commit Aborted")
        }
        TerminalizationOutcome::NotTransmitted | TerminalizationOutcome::OutcomeUnknown => {
            panic!("fresh conclusive Aborted terminal must return its committed receipt")
        }
    }
    fleet
        .wait_all_application_sequences(admission_baseline + 2)
        .await;
    let terminal_log_index = fleet.stores[leader]
        .status()
        .last_log_index
        .expect("conclusive Aborted terminal log index");
    assert_eq!(
        initial_transport
            .roster_admission_calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        initial_transport
            .roster_terminal_calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(initial_publication.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(initial_publication.publish_calls.load(Ordering::SeqCst), 0);

    let original_owner = original_guard.owner().clone();
    let original_admission_fence = original_guard.fence();
    drop(active);
    drop(admission);
    drop(initial_client);
    drop(initial_adapter);
    initial_shutdown.shutdown().await;
    initial_server.abort_and_wait().await;

    // Read the committed terminal through a voter other than the one that
    // accepted it, before the terminal is compacted into physical snapshots.
    let recovery_server_spiffe = three_voter_spiffe(recovery_voter);
    let recovery_service = Arc::new(fleet.stores[recovery_voter].consumer_service());
    let recovery_transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        recovery_service.clone(),
        recovery_service,
    ));
    let (recovery_server, recovery_address) = SessionQuorumConsumerServer::new(
        recovery_transport.clone(),
        pki.server_config(&recovery_server_spiffe),
        three_voter_authorizer(&fleet.stores[recovery_voter], &client_spiffe).await,
    )
    .with_roster_ingress(recovery_transport.clone(), ingress_signer.clone())
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("Aborted snapshot cross-voter recovery listener"),
    )
    .await
    .expect("start Aborted snapshot cross-voter recovery listener");
    let recovery_server = AbortConsumerServerOnDrop::new(recovery_server);
    let lease_server_spiffe = three_voter_spiffe(leader);
    let lease_service = Arc::new(fleet.stores[leader].consumer_service());
    let lease_transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        lease_service.clone(),
        lease_service,
    ));
    let (lease_server, lease_address) = SessionQuorumConsumerServer::new(
        lease_transport.clone(),
        pki.server_config(&lease_server_spiffe),
        three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await,
    )
    .with_roster_ingress(lease_transport.clone(), ingress_signer.clone())
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("Aborted snapshot lease listener"),
    )
    .await
    .expect("start Aborted snapshot lease listener");
    let lease_server = AbortConsumerServerOnDrop::new(lease_server);
    let lease_client = consumer_client(
        &pki,
        lease_address,
        &lease_server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    lease_client
        .release_with_id(
            SessionConsumerRequestId::from_bytes([0xb2; 16]),
            original_guard.clone(),
        )
        .await
        .expect("release original Aborted snapshot guard");
    let expired = lease_client
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0xb3; 16]),
            key.clone(),
            OwnerId::new("three-voter-roster-aborted-snapshot-expired")
                .expect("Aborted snapshot expired owner"),
            Duration::from_millis(20),
        )
        .await
        .expect("acquire expired Aborted snapshot guard");
    while Timestamp::now_utc() <= expired.expires_at() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let current_guard = lease_client
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0xb4; 16]),
            key.clone(),
            OwnerId::new("three-voter-roster-aborted-snapshot-current")
                .expect("Aborted snapshot current owner"),
            Duration::from_secs(10 * 60),
        )
        .await
        .expect("acquire current Aborted snapshot guard");
    assert!(current_guard.fence() > original_admission_fence);

    let recovery_persistent = protected_roster_persistent_client(
        &pki,
        recovery_address,
        &recovery_server_spiffe,
        &client_spiffe,
        fleet.voter_authority(recovery_voter),
    );
    let recovery_shutdown = recovery_persistent.clone();
    let recovery_provider = Arc::new(SixMemberRosterEvidenceProvider::new(attestor.clone()));
    let recovery_publication = Arc::new(EstablishedPublicationEvidenceProvider::default());
    let recovery_adapter = recovery_persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&recovery_provider),
            Arc::clone(&recovery_publication),
            executor_attestor.clone(),
            NonZeroUsize::new(THREE_VOTER_COUNT)
                .expect("positive cross-voter recovery concurrency"),
        )
        .expect("compose Aborted snapshot cross-voter recovery adapter");
    let recovery_client = recovery_adapter.client().clone();
    let recovery_input = RecoveryInput::new(
        roster_id,
        original_owner.clone(),
        original_admission_fence,
        current_guard.clone(),
        expected_generation,
    )
    .expect("current Aborted snapshot recovery input");
    match recovery_client
        .recover(&recovery_input)
        .await
        .expect("recover conclusive Aborted terminal from a different voter")
    {
        RecoveryOutcome::Terminal(TerminalReceipt::Aborted(aborted)) => {
            assert_eq!(aborted.protected_checkpoint(), protected_checkpoint);
            assert_eq!(aborted.protected_result(), protected_result);
        }
        RecoveryOutcome::Terminal(TerminalReceipt::Established(_)) => {
            panic!("cross-voter recovery must retain conclusive Aborted")
        }
        RecoveryOutcome::Admitted(_) | RecoveryOutcome::Compacted => {
            panic!("committed Aborted terminal must not reopen execution authority")
        }
    }
    assert_eq!(recovery_provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovery_provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovery_provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovery_provider.adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovery_provider.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovery_publication.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(recovery_publication.publish_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        recovery_transport
            .roster_admission_calls
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        recovery_transport
            .roster_terminal_calls
            .load(Ordering::SeqCst),
        0
    );

    let (mut workload_leader, _, mut workload_term) = fleet.wait_for_observed_leader().await;
    let workload_baseline = fleet.stores[workload_leader]
        .status()
        .last_log_index
        .expect("Aborted snapshot workload baseline");
    let target_log_index = workload_baseline + SNAPSHOT_COMMANDS as u64;
    tokio::time::timeout(Duration::from_secs(5 * 60), async {
        let mut maintenance_rejections = 0_usize;
        while fleet.stores[workload_leader]
            .status()
            .last_log_index
            .is_none_or(|index| index < target_log_index)
        {
            match fleet.stores[workload_leader]
                .max_replication_sequence()
                .await
            {
                Ok(_) => {}
                Err(StoreError::BackendUnavailable(_))
                    if maintenance_rejections < MAX_SNAPSHOT_MAINTENANCE_REJECTIONS =>
                {
                    maintenance_rejections += 1;
                    (workload_leader, _, workload_term) = fleet
                        .wait_for_admitted_quorum_leader(&[0, 1, 2], workload_term)
                        .await;
                    tokio::task::yield_now().await;
                }
                Err(_) => panic!("Aborted snapshot qualification command was rejected"),
            }
        }
    })
    .await
    .expect("Aborted snapshot qualification command batch completes");
    assert!(
        fleet.stores[workload_leader]
            .status()
            .last_log_index
            .is_some_and(|index| index >= target_log_index),
        "conclusive Aborted terminal crosses the production snapshot-log threshold"
    );
    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
        loop {
            let progress = fleet.stores[workload_leader]
                .probe_durable_readiness()
                .await
                .recovery_progress();
            if progress
                .snapshot_index()
                .is_some_and(|index| index >= terminal_log_index)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("conclusive Aborted terminal is compacted into a physical snapshot");
    fleet.wait_all_application_sequences(target_log_index).await;

    drop(recovery_client);
    drop(recovery_adapter);
    recovery_shutdown.shutdown().await;
    recovery_server.abort_and_wait().await;
    lease_server.abort_and_wait().await;
    drop(initial_transport);
    drop(recovery_transport);
    drop(lease_transport);
    let fleet = fleet.restart_all().await;

    let (restart_leader, _, _) = fleet.wait_for_observed_leader().await;
    let restart_voter = (restart_leader + 1) % THREE_VOTER_COUNT;
    let restart_server_spiffe = three_voter_spiffe(restart_voter);
    let restart_service = Arc::new(fleet.stores[restart_voter].consumer_service());
    let restart_transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        restart_service.clone(),
        restart_service,
    ));
    let (restart_server, restart_address) = SessionQuorumConsumerServer::new(
        restart_transport.clone(),
        pki.server_config(&restart_server_spiffe),
        three_voter_authorizer(&fleet.stores[restart_voter], &client_spiffe).await,
    )
    .with_roster_ingress(restart_transport.clone(), ingress_signer)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("Aborted snapshot restart listener"),
    )
    .await
    .expect("start Aborted snapshot restart listener");
    let restart_server = AbortConsumerServerOnDrop::new(restart_server);
    let restart_persistent = protected_roster_persistent_client(
        &pki,
        restart_address,
        &restart_server_spiffe,
        &client_spiffe,
        fleet.voter_authority(restart_voter),
    );
    let restart_shutdown = restart_persistent.clone();
    let restart_provider = Arc::new(SixMemberRosterEvidenceProvider::new(attestor));
    let restart_publication = Arc::new(EstablishedPublicationEvidenceProvider::default());
    let restart_adapter = restart_persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&restart_provider),
            Arc::clone(&restart_publication),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("positive restart recovery concurrency"),
        )
        .expect("compose Aborted snapshot restart adapter");
    match restart_adapter
        .client()
        .recover(&recovery_input)
        .await
        .expect("recover conclusive Aborted terminal from physical snapshot after full restart")
    {
        RecoveryOutcome::Terminal(TerminalReceipt::Aborted(aborted)) => {
            assert_eq!(aborted.protected_checkpoint(), protected_checkpoint);
            assert_eq!(aborted.protected_result(), protected_result);
        }
        RecoveryOutcome::Terminal(TerminalReceipt::Established(_)) => {
            panic!("full-restart snapshot recovery must retain conclusive Aborted")
        }
        RecoveryOutcome::Admitted(_) | RecoveryOutcome::Compacted => {
            panic!("full-restart Aborted recovery must not reopen execution authority")
        }
    }
    assert_eq!(restart_provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(restart_provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(restart_provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(restart_provider.adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(restart_provider.reconcile_calls.load(Ordering::SeqCst), 0);
    assert_eq!(restart_publication.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(restart_publication.publish_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        restart_transport
            .roster_admission_calls
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        restart_transport
            .roster_terminal_calls
            .load(Ordering::SeqCst),
        0
    );

    restart_shutdown.shutdown().await;
    restart_server.abort_and_wait().await;
    fleet.shutdown().await;
}

// Durable provider-only evidence shared by the protected-roster integration matrix.
enum SixMemberRosterEvidenceMode {
    ExecuteApplied,
    SixthExecuteOutcomeUnknownThenAdopted,
    ExecuteOutcomeUnknownThenReconciled,
}

enum DurableCrashRecoveredRoster {
    Active(ActiveRoster),
    Recovered(RecoveredRoster),
}

impl DurableCrashRecoveredRoster {
    fn roster_id(&self) -> RosterId {
        match self {
            Self::Active(roster) => roster.roster_id(),
            Self::Recovered(roster) => roster.roster_id(),
        }
    }

    fn members(&self) -> &[Member] {
        match self {
            Self::Active(roster) => roster.members(),
            Self::Recovered(roster) => roster.members(),
        }
    }

    fn protected_plan(&self) -> &[u8] {
        match self {
            Self::Active(roster) => roster.protected_plan(),
            Self::Recovered(roster) => roster.protected_plan(),
        }
    }

    fn for_terminal(&self) -> TerminalRoster<'_> {
        match self {
            Self::Active(roster) => roster.for_terminal(),
            Self::Recovered(roster) => roster.for_terminal(),
        }
    }
}

type ExecutionRecord = (u8, [u8; 16], Vec<u8>, u64);

struct SixMemberRosterEvidenceProvider {
    issuer: Arc<ProductionRosterAttestationIssuer>,
    mode: SixMemberRosterEvidenceMode,
    prepare_calls: AtomicUsize,
    execute_calls: AtomicUsize,
    status_calls: AtomicUsize,
    adopt_calls: AtomicUsize,
    reconcile_calls: AtomicUsize,
    executions: Mutex<Vec<ExecutionRecord>>,
}

impl SixMemberRosterEvidenceProvider {
    fn new(issuer: Arc<ProductionRosterAttestationIssuer>) -> Self {
        Self {
            issuer,
            mode: SixMemberRosterEvidenceMode::ExecuteApplied,
            prepare_calls: AtomicUsize::new(0),
            execute_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
            reconcile_calls: AtomicUsize::new(0),
            executions: Mutex::new(Vec::new()),
        }
    }

    fn sixth_execute_outcome_unknown_then_adopted(
        issuer: Arc<ProductionRosterAttestationIssuer>,
    ) -> Self {
        Self {
            issuer,
            mode: SixMemberRosterEvidenceMode::SixthExecuteOutcomeUnknownThenAdopted,
            prepare_calls: AtomicUsize::new(0),
            execute_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
            reconcile_calls: AtomicUsize::new(0),
            executions: Mutex::new(Vec::new()),
        }
    }

    fn execute_outcome_unknown_then_reconciled(
        issuer: Arc<ProductionRosterAttestationIssuer>,
    ) -> Self {
        Self {
            issuer,
            mode: SixMemberRosterEvidenceMode::ExecuteOutcomeUnknownThenReconciled,
            prepare_calls: AtomicUsize::new(0),
            execute_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
            reconcile_calls: AtomicUsize::new(0),
            executions: Mutex::new(Vec::new()),
        }
    }

    fn executions(&self) -> Vec<ExecutionRecord> {
        self.executions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn receipt(
        &self,
        call: &MemberCall<'_>,
        operation: opc_session_store::fenced_mutation_roster::RosterProviderOperationV1,
        outcome: opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1,
        evidence: Vec<u8>,
    ) -> Result<ProviderCallOutcome, ()> {
        self.issuer
            .provider_receipt(call, operation, outcome, evidence)
    }
}

#[async_trait]
impl MemberProvider for SixMemberRosterEvidenceProvider {
    type Error = ();

    async fn prepare(&self, _call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderCallOutcome::prepared_not_run())
    }

    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        self.executions.lock().map_err(|_| ())?.push((
            call.ordinal(),
            *call.operation_id().as_bytes(),
            call.descriptor().to_vec(),
            call.expected_version(),
        ));
        if (matches!(
            self.mode,
            SixMemberRosterEvidenceMode::SixthExecuteOutcomeUnknownThenAdopted
        ) && call.ordinal() == 5)
            || matches!(
                self.mode,
                SixMemberRosterEvidenceMode::ExecuteOutcomeUnknownThenReconciled
            )
        {
            Ok(ProviderCallOutcome::outcome_unknown())
        } else {
            self.receipt(
                call,
                opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Execute,
                opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::AppliedExecuted,
                vec![call.ordinal().saturating_add(1)],
            )
        }
    }

    async fn status(&self, _call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            SixMemberRosterEvidenceMode::ExecuteApplied
            | SixMemberRosterEvidenceMode::SixthExecuteOutcomeUnknownThenAdopted
            | SixMemberRosterEvidenceMode::ExecuteOutcomeUnknownThenReconciled => {
                Ok(ProviderCallOutcome::not_found())
            }
        }
    }

    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.adopt_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            SixMemberRosterEvidenceMode::ExecuteApplied => {
                self.executions.lock().map_err(|_| ())?.push((
                    call.ordinal(),
                    *call.operation_id().as_bytes(),
                    call.descriptor().to_vec(),
                    call.expected_version(),
                ));
                self.receipt(
                    call,
                    opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Adopt,
                    opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::AppliedAdopted,
                    vec![0xa5, call.ordinal()],
                )
            }
            SixMemberRosterEvidenceMode::SixthExecuteOutcomeUnknownThenAdopted => self.receipt(
                call,
                opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Adopt,
                opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::AppliedAdopted,
                vec![0xa6],
            ),
            SixMemberRosterEvidenceMode::ExecuteOutcomeUnknownThenReconciled => {
                Ok(ProviderCallOutcome::outcome_unknown())
            }
        }
    }

    async fn reconcile_member(
        &self,
        call: &MemberCall<'_>,
    ) -> Result<ProviderCallOutcome, Self::Error> {
        self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
        self.receipt(
            call,
            opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Reconcile,
            opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::NotAppliedReconciled,
            vec![0xb6, call.ordinal()],
        )
    }
}

/// A deliberately small, test-only durable provider journal.  It is not a
/// roster journal and has no consumer or consensus capability: each newline
/// is fsync'd provider-local evidence which the replacement provider reads
/// only to prove that it did not execute an operation again after a crash.
#[derive(Clone)]
struct DurableRosterProviderJournal {
    path: PathBuf,
}

impl DurableRosterProviderJournal {
    fn create(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        std::fs::File::create(&path)?.sync_all()?;
        Ok(Self { path })
    }

    fn reopen(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let _ = std::fs::OpenOptions::new().read(true).open(&path)?;
        Ok(Self { path })
    }

    fn append(&self, phase: &str, ordinal: u8, call: &MemberCall<'_>) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        writeln!(
            file,
            "{phase}:{ordinal}:{}:{}:{}",
            durable_roster_hex(call.operation_id().as_bytes()),
            durable_roster_hex(call.descriptor()),
            call.expected_version(),
        )?;
        file.sync_data()
    }

    fn append_admission(
        &self,
        roster_id: RosterId,
        protected_plan: &[u8],
        protected_checkpoint: &[u8],
        protected_result: &[u8],
    ) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        writeln!(
            file,
            "admission:{}:{}:{}:{}",
            durable_roster_hex(roster_id.as_bytes()),
            durable_roster_hex(protected_plan),
            durable_roster_hex(protected_checkpoint),
            durable_roster_hex(protected_result),
        )?;
        file.sync_data()
    }

    fn contents(&self) -> String {
        std::fs::read_to_string(&self.path).expect("read durable provider journal")
    }

    fn phase_calls(&self, phase: &str, ordinal: u8) -> usize {
        let prefix = format!("{phase}:{ordinal}:");
        self.contents()
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .count()
    }
}

fn durable_roster_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy, Debug)]
enum DurableRosterCrashCut {
    BeforeAdmission,
    PollAdmittedBeforeProviderWork,
    PreparePending,
    PreparedBeforeRun,
    RunOutcomeUnknown,
    AppliedBeforeFinalize,
    AdmittedBeforeSixth,
    SixthDurableApplyLostReply,
    AllSixBeforeTerminalRequest,
    TerminalCommittedReplyOutcomeUnknown,
    EstablishedBeforePublication,
    PublicationPublishedBeforeAcknowledgement,
    PublicationFirstSendNotTransmitted,
}

const DURABLE_ROSTER_CRASH_CUT_MATRIX: [DurableRosterCrashCut; 13] = [
    DurableRosterCrashCut::BeforeAdmission,
    DurableRosterCrashCut::PollAdmittedBeforeProviderWork,
    DurableRosterCrashCut::PreparePending,
    DurableRosterCrashCut::PreparedBeforeRun,
    DurableRosterCrashCut::RunOutcomeUnknown,
    DurableRosterCrashCut::AppliedBeforeFinalize,
    DurableRosterCrashCut::AdmittedBeforeSixth,
    DurableRosterCrashCut::SixthDurableApplyLostReply,
    DurableRosterCrashCut::AllSixBeforeTerminalRequest,
    DurableRosterCrashCut::TerminalCommittedReplyOutcomeUnknown,
    DurableRosterCrashCut::EstablishedBeforePublication,
    DurableRosterCrashCut::PublicationPublishedBeforeAcknowledgement,
    DurableRosterCrashCut::PublicationFirstSendNotTransmitted,
];

impl DurableRosterCrashCut {
    const fn name(self) -> &'static str {
        match self {
            Self::BeforeAdmission => "BeforeAdmission",
            Self::PollAdmittedBeforeProviderWork => "PollAdmittedBeforeProviderWork",
            Self::PreparePending => "PreparePending",
            Self::PreparedBeforeRun => "PreparedBeforeRun",
            Self::RunOutcomeUnknown => "RunOutcomeUnknown",
            Self::AppliedBeforeFinalize => "AppliedBeforeFinalize",
            Self::AdmittedBeforeSixth => "RosterAdmittedBeforeSixth",
            Self::SixthDurableApplyLostReply => "SixthDurableApplyLostReply",
            Self::AllSixBeforeTerminalRequest => "AllSixConvergedBeforeTerminalRequest",
            Self::TerminalCommittedReplyOutcomeUnknown => "TerminalCommittedReplyOutcomeUnknown",
            Self::EstablishedBeforePublication => "EstablishedBeforePublication",
            Self::PublicationFirstSendNotTransmitted => "PublicationFirstSendNotTransmitted",
            Self::PublicationPublishedBeforeAcknowledgement => {
                "PublicationPublishedBeforeAcknowledgement"
            }
        }
    }

    const fn initial_member_count(self) -> u8 {
        match self {
            Self::BeforeAdmission | Self::PollAdmittedBeforeProviderWork => 0,
            Self::PreparePending
            | Self::PreparedBeforeRun
            | Self::RunOutcomeUnknown
            | Self::AppliedBeforeFinalize => 1,
            Self::AdmittedBeforeSixth => 5,
            Self::SixthDurableApplyLostReply
            | Self::AllSixBeforeTerminalRequest
            | Self::TerminalCommittedReplyOutcomeUnknown
            | Self::EstablishedBeforePublication
            | Self::PublicationFirstSendNotTransmitted
            | Self::PublicationPublishedBeforeAcknowledgement => 6,
        }
    }

    const fn outcome_unknown_ordinal(self) -> Option<u8> {
        match self {
            Self::RunOutcomeUnknown => Some(0),
            Self::SixthDurableApplyLostReply => Some(5),
            _ => None,
        }
    }

    const fn pending_prepare(self) -> bool {
        matches!(self, Self::PreparePending)
    }
}

/// Provider implementation backed exclusively by [`DurableRosterProviderJournal`].
/// `adopt` records a durable apply only when the exact operation ID has not
/// already applied, allowing the test to catch a post-crash re-execution.
struct DurableCrashCutProvider {
    journal: Arc<DurableRosterProviderJournal>,
    issuer: Arc<ProductionRosterAttestationIssuer>,
    pending_prepare: bool,
    outcome_unknown_ordinal: Option<u8>,
    prepare_calls: AtomicUsize,
    execute_calls: AtomicUsize,
    status_calls: AtomicUsize,
    adopt_calls: AtomicUsize,
}

impl DurableCrashCutProvider {
    fn initial(
        journal: Arc<DurableRosterProviderJournal>,
        cut: DurableRosterCrashCut,
        issuer: Arc<ProductionRosterAttestationIssuer>,
    ) -> Self {
        Self {
            journal,
            issuer,
            pending_prepare: cut.pending_prepare(),
            outcome_unknown_ordinal: cut.outcome_unknown_ordinal(),
            prepare_calls: AtomicUsize::new(0),
            execute_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
        }
    }

    fn recovery(
        journal: Arc<DurableRosterProviderJournal>,
        issuer: Arc<ProductionRosterAttestationIssuer>,
    ) -> Self {
        Self {
            journal,
            issuer,
            pending_prepare: false,
            outcome_unknown_ordinal: None,
            prepare_calls: AtomicUsize::new(0),
            execute_calls: AtomicUsize::new(0),
            status_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
        }
    }

    fn record_apply_once(&self, call: &MemberCall<'_>) -> Result<(), ()> {
        if self.journal.phase_calls("apply", call.ordinal()) == 0 {
            self.journal
                .append("apply", call.ordinal(), call)
                .map_err(|_| ())?;
        }
        Ok(())
    }

    fn applied_proof(
        &self,
        call: &MemberCall<'_>,
        adoption: MemberAdoption,
    ) -> Result<ProviderCallOutcome, ()> {
        let outcome = match adoption {
            MemberAdoption::Executed => {
                opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::AppliedExecuted
            }
            MemberAdoption::Adopted => {
                opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::AppliedAdopted
            }
            MemberAdoption::Unreconciled | MemberAdoption::Reconciled => return Err(()),
        };
        let operation = match adoption {
            MemberAdoption::Executed => {
                opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Execute
            }
            MemberAdoption::Adopted => {
                opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Adopt
            }
            MemberAdoption::Unreconciled | MemberAdoption::Reconciled => return Err(()),
        };
        self.issuer.provider_receipt(
            call,
            operation,
            outcome,
            vec![call.ordinal().saturating_add(1)],
        )
    }
}

#[async_trait]
impl MemberProvider for DurableCrashCutProvider {
    type Error = ();

    async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        self.journal
            .append("prepare", call.ordinal(), call)
            .map_err(|_| ())?;
        if self.pending_prepare {
            ProviderCallOutcome::pending(vec![0x50, call.ordinal()]).map_err(|_| ())
        } else {
            Ok(ProviderCallOutcome::prepared_not_run())
        }
    }

    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        self.journal
            .append("execute", call.ordinal(), call)
            .map_err(|_| ())?;
        self.record_apply_once(call)?;
        if self.outcome_unknown_ordinal == Some(call.ordinal()) {
            Ok(ProviderCallOutcome::outcome_unknown())
        } else {
            self.applied_proof(call, MemberAdoption::Executed)
        }
    }

    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        self.journal
            .append("status", call.ordinal(), call)
            .map_err(|_| ())?;
        // NotFound is deliberately non-exclusionary: recovery must still be
        // able to adopt the exact persisted operation identity.
        Ok(ProviderCallOutcome::not_found())
    }

    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error> {
        self.adopt_calls.fetch_add(1, Ordering::SeqCst);
        self.journal
            .append("adopt", call.ordinal(), call)
            .map_err(|_| ())?;
        self.record_apply_once(call)?;
        self.applied_proof(call, MemberAdoption::Adopted)
    }

    async fn reconcile_member(
        &self,
        call: &MemberCall<'_>,
    ) -> Result<ProviderCallOutcome, Self::Error> {
        self.journal
            .append("reconcile", call.ordinal(), call)
            .map_err(|_| ())?;
        self.issuer.provider_receipt(
            call,
            opc_session_store::fenced_mutation_roster::RosterProviderOperationV1::Reconcile,
            opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1::NotAppliedReconciled,
            vec![0xb7, call.ordinal()],
        )
    }
}

/// Startup-owned publication provider for the Established-only integration
/// seam. It records provider-local work only; it has no consumer or backend
/// reference and therefore cannot add a roster consensus mutation.
#[derive(Default)]
struct EstablishedPublicationEvidenceProvider {
    status_calls: AtomicUsize,
    publish_calls: AtomicUsize,
}

/// Provider-local publication evidence used by the full-fleet reopen cuts.
///
/// The append-only file deliberately retains the stable ID, exact payload
/// commitment and payload bytes, state, and greatest accepted fence. It is
/// opened afresh after the prior journal handle is dropped; no `Arc`, lock, or
/// in-memory counter crosses the durable-reopen boundary.
#[derive(Clone)]
struct DurableEstablishedPublicationJournal {
    path: PathBuf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DurableEstablishedPublicationState {
    Reserved,
    Attempted,
    NotTransmitted,
    Published,
}

struct DurableEstablishedPublicationEntry {
    state: DurableEstablishedPublicationState,
    fence: u64,
    publication_id: String,
    payload_commitment: String,
    checkpoint: String,
    result: String,
}

impl DurableEstablishedPublicationJournal {
    fn create(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        std::fs::File::create(&path)?.sync_all()?;
        Ok(Self { path })
    }

    fn reopen(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let _ = std::fs::OpenOptions::new().read(true).open(&path)?;
        Ok(Self { path })
    }

    fn append(
        &self,
        state: DurableEstablishedPublicationState,
        call: &EstablishedPublicationCall<'_>,
    ) -> io::Result<()> {
        let state = match state {
            DurableEstablishedPublicationState::Reserved => "reserved",
            DurableEstablishedPublicationState::Attempted => "attempted",
            DurableEstablishedPublicationState::NotTransmitted => "not_transmitted",
            DurableEstablishedPublicationState::Published => "published",
        };
        let mut file = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        writeln!(
            file,
            "state:{state}:{}:{}:{}:{}:{}",
            call.current_fence().get(),
            durable_roster_hex(call.publication_id().as_bytes()),
            durable_roster_hex(&call.payload_commitment()),
            durable_roster_hex(call.protected_checkpoint()),
            durable_roster_hex(call.protected_result()),
        )?;
        file.sync_data()
    }

    fn append_floor(&self, call: &EstablishedPublicationCall<'_>) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        writeln!(
            file,
            "floor:{}:{}",
            call.current_fence().get(),
            durable_roster_hex(call.publication_id().as_bytes()),
        )?;
        file.sync_data()
    }

    fn entries(&self) -> io::Result<Vec<DurableEstablishedPublicationEntry>> {
        let entries = std::fs::read_to_string(&self.path)?
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(':');
                let (
                    Some("state"),
                    Some(state),
                    Some(fence),
                    Some(publication_id),
                    Some(payload_commitment),
                    Some(checkpoint),
                    Some(result),
                    None,
                ) = (
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                )
                else {
                    return None;
                };
                let state = match state {
                    "reserved" => DurableEstablishedPublicationState::Reserved,
                    "attempted" => DurableEstablishedPublicationState::Attempted,
                    "not_transmitted" => DurableEstablishedPublicationState::NotTransmitted,
                    "published" => DurableEstablishedPublicationState::Published,
                    _ => return None,
                };
                let fence = fence.parse().ok()?;
                Some(DurableEstablishedPublicationEntry {
                    state,
                    fence,
                    publication_id: publication_id.to_owned(),
                    payload_commitment: payload_commitment.to_owned(),
                    checkpoint: checkpoint.to_owned(),
                    result: result.to_owned(),
                })
            })
            .collect::<Vec<_>>();
        Ok(entries)
    }

    fn entry_for(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> io::Result<Option<DurableEstablishedPublicationEntry>> {
        let publication_id = durable_roster_hex(call.publication_id().as_bytes());
        let mut entry = self
            .entries()?
            .into_iter()
            .rfind(|entry| entry.publication_id == publication_id);
        if let Some(entry) = &mut entry {
            let floor = std::fs::read_to_string(&self.path)?
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split(':');
                    match (fields.next(), fields.next(), fields.next(), fields.next()) {
                        (Some("floor"), Some(fence), Some(id), None) if id == publication_id => {
                            fence.parse().ok()
                        }
                        _ => None,
                    }
                })
                .max()
                .unwrap_or(entry.fence);
            entry.fence = entry.fence.max(floor);
        }
        Ok(entry)
    }

    fn state_count(&self, state: DurableEstablishedPublicationState) -> usize {
        self.entries()
            .expect("read durable publication journal")
            .into_iter()
            .filter(|entry| entry.state == state)
            .count()
    }

    fn state_results(&self, state: DurableEstablishedPublicationState) -> Vec<String> {
        self.entries()
            .expect("read durable publication journal")
            .into_iter()
            .filter(|entry| entry.state == state)
            .map(|entry| entry.result)
            .collect()
    }
}

/// Reopen-only provider: `begin_publication` records only Reserved, while
/// `adopt` fsyncs Attempted before the one simulated external publication.
struct DurableEstablishedPublicationProvider {
    journal: DurableEstablishedPublicationJournal,
    lose_published_reply: AtomicBool,
    lose_not_transmitted_reply: AtomicBool,
    force_absent_once: AtomicBool,
    lock: Mutex<()>,
    status_calls: AtomicUsize,
    begin_calls: AtomicUsize,
    adopt_calls: AtomicUsize,
}

impl DurableEstablishedPublicationProvider {
    fn initial(
        journal: DurableEstablishedPublicationJournal,
        lose_published_reply: bool,
        lose_not_transmitted_reply: bool,
    ) -> Self {
        Self {
            journal,
            lose_published_reply: AtomicBool::new(lose_published_reply),
            lose_not_transmitted_reply: AtomicBool::new(lose_not_transmitted_reply),
            force_absent_once: AtomicBool::new(false),
            lock: Mutex::new(()),
            status_calls: AtomicUsize::new(0),
            begin_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
        }
    }

    fn recovery(journal: DurableEstablishedPublicationJournal, force_absent_once: bool) -> Self {
        Self {
            journal,
            lose_published_reply: AtomicBool::new(false),
            lose_not_transmitted_reply: AtomicBool::new(false),
            force_absent_once: AtomicBool::new(force_absent_once),
            lock: Mutex::new(()),
            status_calls: AtomicUsize::new(0),
            begin_calls: AtomicUsize::new(0),
            adopt_calls: AtomicUsize::new(0),
        }
    }

    fn evidence(call: &EstablishedPublicationCall<'_>) -> Result<PublicationEvidence, ()> {
        PublicationEvidence::new(call, vec![0xa7]).map_err(|_| ())
    }

    fn check_and_entry(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<Option<DurableEstablishedPublicationEntry>, ()> {
        call.validate_current_lease_at(Timestamp::now_utc())
            .map_err(|_| ())?;
        let mut entry = self.journal.entry_for(call).map_err(|_| ())?;
        if let Some(entry) = &mut entry {
            if entry.fence > call.current_fence().get() {
                return Err(());
            }
            if entry.payload_commitment != durable_roster_hex(&call.payload_commitment())
                || entry.checkpoint != durable_roster_hex(call.protected_checkpoint())
                || entry.result != durable_roster_hex(call.protected_result())
            {
                return Err(());
            }
            if entry.fence < call.current_fence().get() {
                self.journal.append_floor(call).map_err(|_| ())?;
                entry.fence = call.current_fence().get();
            }
        }
        Ok(entry)
    }
}

#[async_trait]
impl EstablishedPublicationProvider for DurableEstablishedPublicationProvider {
    type Error = ();

    async fn status(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        let _guard = self.lock.lock().map_err(|_| ())?;
        let entry = self.check_and_entry(call)?;
        if self.force_absent_once.swap(false, Ordering::SeqCst) {
            return Ok(PublicationProviderOutcome::Absent);
        }
        match entry.map(|entry| entry.state) {
            Some(DurableEstablishedPublicationState::Published) => {
                Ok(PublicationProviderOutcome::Published(Self::evidence(call)?))
            }
            Some(DurableEstablishedPublicationState::Reserved)
            | Some(DurableEstablishedPublicationState::Attempted)
            | Some(DurableEstablishedPublicationState::NotTransmitted) => {
                Ok(PublicationProviderOutcome::Pending(Self::evidence(call)?))
            }
            None => Ok(PublicationProviderOutcome::Absent),
        }
    }

    async fn begin_publication(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.begin_calls.fetch_add(1, Ordering::SeqCst);
        let _guard = self.lock.lock().map_err(|_| ())?;
        match self.check_and_entry(call)? {
            Some(entry) if entry.state == DurableEstablishedPublicationState::Published => {
                Ok(PublicationProviderOutcome::Published(Self::evidence(call)?))
            }
            Some(_) => Ok(PublicationProviderOutcome::Pending(Self::evidence(call)?)),
            None => {
                self.journal
                    .append(DurableEstablishedPublicationState::Reserved, call)
                    .map_err(|_| ())?;
                Ok(PublicationProviderOutcome::Pending(Self::evidence(call)?))
            }
        }
    }

    async fn adopt(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.adopt_calls.fetch_add(1, Ordering::SeqCst);
        let _guard = self.lock.lock().map_err(|_| ())?;
        match self.check_and_entry(call)? {
            Some(DurableEstablishedPublicationEntry {
                state: DurableEstablishedPublicationState::Published,
                ..
            }) => Ok(PublicationProviderOutcome::Published(Self::evidence(call)?)),
            Some(DurableEstablishedPublicationEntry {
                state: DurableEstablishedPublicationState::Reserved,
                ..
            }) => {
                self.journal
                    .append(DurableEstablishedPublicationState::Attempted, call)
                    .map_err(|_| ())?;
                if self
                    .lose_not_transmitted_reply
                    .swap(false, Ordering::SeqCst)
                {
                    // The transport provider conclusively proves this exact
                    // attempted send never crossed transport, then its reply
                    // is discarded at the recovery boundary. The durable
                    // marker lets only successor status/adopt resend the
                    // retained bytes.
                    self.journal
                        .append(DurableEstablishedPublicationState::NotTransmitted, call)
                        .map_err(|_| ())?;
                    return Err(());
                }
                // This record is the test's external-send boundary. It is
                // fsync'd before the final Published tombstone is written.
                self.journal
                    .append(DurableEstablishedPublicationState::Published, call)
                    .map_err(|_| ())?;
                if self.lose_published_reply.swap(false, Ordering::SeqCst) {
                    Err(())
                } else {
                    Ok(PublicationProviderOutcome::Published(Self::evidence(call)?))
                }
            }
            // A retained attempted marker is an ambiguous external-send
            // boundary.  A replacement provider may reconcile that exact
            // identity, but it must not record a second send attempt.
            Some(DurableEstablishedPublicationEntry {
                state: DurableEstablishedPublicationState::Attempted,
                ..
            }) => {
                self.journal
                    .append(DurableEstablishedPublicationState::Published, call)
                    .map_err(|_| ())?;
                Ok(PublicationProviderOutcome::Published(Self::evidence(call)?))
            }
            // Only provider-local, transport-conclusive no-transmission for
            // this exact identity restores one resend. The retained body is
            // revalidated by `check_and_entry` before this external boundary.
            Some(DurableEstablishedPublicationEntry {
                state: DurableEstablishedPublicationState::NotTransmitted,
                ..
            }) => {
                // This is the one simulated external-send boundary after the
                // retained exact-byte no-transmission proof.
                self.journal
                    .append(DurableEstablishedPublicationState::Published, call)
                    .map_err(|_| ())?;
                Ok(PublicationProviderOutcome::Published(Self::evidence(call)?))
            }
            None => Ok(PublicationProviderOutcome::Absent),
        }
    }
}

#[async_trait]
impl EstablishedPublicationProvider for EstablishedPublicationEvidenceProvider {
    type Error = ();

    async fn status(
        &self,
        _call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PublicationProviderOutcome::Absent)
    }

    async fn begin_publication(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        Ok(PublicationProviderOutcome::Pending(
            PublicationEvidence::new(call, vec![0x91])
                .expect("bind exact Established publication evidence"),
        ))
    }

    async fn adopt(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.publish_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PublicationProviderOutcome::Published(
            PublicationEvidence::new(call, vec![0x91])
                .expect("bind exact Established publication evidence"),
        ))
    }
}

// Fixed-key authority for the real revision-five protected-roster fixtures.
struct ProductionRosterAttestationIssuer {
    root: RosterAttestationTrustRootV1,
    ingress_key: SigningKey,
    executor_key: SigningKey,
    provider_key: SigningKey,
    ingress_certificate: RosterAttestationLeafCertificatePartsV1,
    executor_trust_root: FencedMutationRosterAttestationTrustRootV1,
    executor_attestation_certificate: FencedMutationRosterExecutorCertificatePartsV1,
    provider_certificate: RosterAttestationLeafCertificatePartsV1,
}

/// The test-only canonical capsule shape accepted at the public provider
/// boundary. Production callers see only the bounded opaque capsule; this
/// fixture keeps the matching codec private to the integration test so it can
/// exercise a separately protected Provider leaf without exposing a product
/// receipt constructor.
#[derive(Serialize)]
struct TestProviderReceiptWire {
    operation: opc_session_store::fenced_mutation_roster::RosterProviderOperationV1,
    outcome: opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1,
    proof_epoch: u64,
    evidence: Vec<u8>,
    certificate: TestProviderCertificateWire,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct TestProviderCertificateWire {
    root_id: [u8; 32],
    role: RosterAttestationCertificateRoleV1,
    configuration_identity: SessionConsensusIdentity,
    scope: [u8; 32],
    subject_identity_commitment: [u8; 32],
    leaf_epoch: u64,
    key_id: [u8; 32],
    not_before: Timestamp,
    not_after: Timestamp,
    public_key: Vec<u8>,
    root_signature: Vec<u8>,
}

struct ProductionRosterCertificateInput<'a> {
    role: RosterAttestationCertificateRoleV1,
    configuration_identity: SessionConsensusIdentity,
    scope: [u8; 32],
    subject_identity_commitment: [u8; 32],
    key_id: [u8; 32],
    public_key: &'a p256::ecdsa::VerifyingKey,
    not_before: Timestamp,
    not_after: Timestamp,
}

impl ProductionRosterAttestationIssuer {
    fn root_signing_key() -> SigningKey {
        SigningKey::from_bytes((&[0x31; 32]).into()).expect("fixed P-256 roster root scalar")
    }

    fn trust_root() -> RosterAttestationTrustRootV1 {
        let public_key = Self::compressed_public_key(Self::root_signing_key().verifying_key());
        RosterAttestationTrustRootV1::new([0xa1; 32], public_key)
            .expect("fixed P-256 roster trust root")
    }

    fn new(
        configuration_identity: SessionConsensusIdentity,
        scope: SessionConsumerScope,
    ) -> Arc<Self> {
        let root_key = Self::root_signing_key();
        let ingress_key = SigningKey::from_bytes((&[0x32; 32]).into())
            .expect("fixed P-256 transport-ingress scalar");
        let executor_key =
            SigningKey::from_bytes((&[0x33; 32]).into()).expect("fixed P-256 executor scalar");
        let provider_key =
            SigningKey::from_bytes((&[0x34; 32]).into()).expect("fixed P-256 provider scalar");
        let root = Self::trust_root();
        let now = Timestamp::now_utc();
        let not_before = now
            .add_seconds(-60)
            .expect("test roster leaf not-before timestamp");
        let not_after = now
            .add_seconds(3_600)
            .expect("test roster leaf not-after timestamp");
        let scope = opc_session_store::consumer::session_consumer_roster_scope_commitment(scope);
        let ingress_certificate = Self::certificate(
            &root_key,
            &root,
            ProductionRosterCertificateInput {
                role: RosterAttestationCertificateRoleV1::TransportIngress,
                configuration_identity,
                scope,
                subject_identity_commitment: [0x41; 32],
                key_id: [0x51; 32],
                public_key: ingress_key.verifying_key(),
                not_before,
                not_after,
            },
        );
        let executor_certificate = Self::certificate(
            &root_key,
            &root,
            ProductionRosterCertificateInput {
                role: RosterAttestationCertificateRoleV1::Executor,
                configuration_identity,
                scope,
                subject_identity_commitment: [0x42; 32],
                key_id: [0x52; 32],
                public_key: executor_key.verifying_key(),
                not_before,
                not_after,
            },
        );
        let executor_trust_root = FencedMutationRosterAttestationTrustRootV1::new(
            root.root_id(),
            Self::compressed_public_key(root_key.verifying_key()),
        )
        .expect("net-owned executor trust root");
        let executor_attestation_certificate = FencedMutationRosterExecutorCertificatePartsV1::new(
            executor_certificate.root_id,
            executor_certificate.configuration_identity,
            executor_certificate.subject_identity_commitment,
            executor_certificate.leaf_epoch,
            executor_certificate.key_id,
            executor_certificate.not_before,
            executor_certificate.not_after,
            executor_certificate.public_key,
            executor_certificate.root_signature,
        )
        .expect("net-owned Executor certificate");
        let provider_certificate = Self::certificate(
            &root_key,
            &root,
            ProductionRosterCertificateInput {
                role: RosterAttestationCertificateRoleV1::Provider,
                configuration_identity,
                scope,
                subject_identity_commitment: [0x43; 32],
                key_id: [0x53; 32],
                public_key: provider_key.verifying_key(),
                not_before,
                not_after,
            },
        );
        Arc::new(Self {
            root,
            ingress_key,
            executor_key,
            provider_key,
            ingress_certificate,
            executor_trust_root,
            executor_attestation_certificate,
            provider_certificate,
        })
    }

    fn provider_receipt(
        &self,
        call: &MemberCall<'_>,
        operation: opc_session_store::fenced_mutation_roster::RosterProviderOperationV1,
        outcome: opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1,
        evidence: Vec<u8>,
    ) -> Result<ProviderCallOutcome, ()> {
        let digest = call
            .provider_receipt_challenge()
            .protected_provider_leaf_receipt_digest(
                self.provider_certificate.subject_identity_commitment,
                outcome,
                &evidence,
            )
            .map_err(|_| ())?;
        let certificate = &self.provider_certificate;
        let canonical = postcard::to_allocvec(&TestProviderReceiptWire {
            operation,
            outcome,
            proof_epoch: call.provider_proof_epoch(),
            evidence,
            certificate: TestProviderCertificateWire {
                root_id: certificate.root_id,
                role: certificate.role,
                configuration_identity: certificate.configuration_identity,
                scope: certificate.scope,
                subject_identity_commitment: certificate.subject_identity_commitment,
                leaf_epoch: certificate.leaf_epoch,
                key_id: certificate.key_id,
                not_before: certificate.not_before,
                not_after: certificate.not_after,
                public_key: certificate.public_key.to_vec(),
                root_signature: certificate.root_signature.to_vec(),
            },
            signature: Self::low_s_p1363(&self.provider_key, digest).to_vec(),
        })
        .map_err(|_| ())?;
        Ok(ProviderCallOutcome::conclusive_receipt(
            ProviderReceiptCapsule::from_canonical_bytes(canonical).map_err(|_| ())?,
        ))
    }

    fn certificate(
        root_key: &SigningKey,
        root: &RosterAttestationTrustRootV1,
        input: ProductionRosterCertificateInput<'_>,
    ) -> RosterAttestationLeafCertificatePartsV1 {
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: input.role,
            configuration_identity: input.configuration_identity,
            scope: input.scope,
            subject_identity_commitment: input.subject_identity_commitment,
            leaf_epoch: 1,
            key_id: input.key_id,
            not_before: input.not_before,
            not_after: input.not_after,
            public_key: Self::compressed_public_key(input.public_key),
            root_signature: [0; 64],
        };
        certificate.root_signature = Self::low_s_p1363(
            root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                .expect("canonical roster leaf certificate digest"),
        );
        certificate
    }

    fn compressed_public_key(key: &p256::ecdsa::VerifyingKey) -> [u8; 33] {
        key.to_sec1_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed P-256 public key width")
    }

    fn low_s_p1363(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
        let signature: p256::ecdsa::Signature = key
            .sign_prehash(&digest)
            .expect("fixed P-256 prehash signature");
        signature.normalize_s().to_bytes().into()
    }
}

#[async_trait]
impl RosterIngressSigner for ProductionRosterAttestationIssuer {
    fn trust_root(&self) -> RosterAttestationTrustRootV1 {
        self.root.clone()
    }

    async fn attest(
        &self,
        input: &RosterIngressAttestationSigningInputV1,
    ) -> Result<RosterIngressAttestationV1, RosterIngressSignerError> {
        RosterIngressAttestationV1::issue_from_signed_parts(
            &self.root,
            self.ingress_certificate.clone(),
            input,
            Self::low_s_p1363(
                &self.ingress_key,
                input.digest().map_err(|_| RosterIngressSignerError)?,
            ),
        )
        .map_err(|_| RosterIngressSignerError)
    }

    fn compact_admission_certificate(
        &self,
    ) -> Result<RosterAttestationLeafCertificatePartsV1, RosterIngressSignerError> {
        Ok(self.ingress_certificate.clone())
    }

    async fn sign_compact_admission(
        &self,
        input: &RosterCompactAdmissionProvenanceSigningInputV2,
    ) -> Result<[u8; 64], RosterIngressSignerError> {
        Ok(Self::low_s_p1363(
            &self.ingress_key,
            input.digest().map_err(|_| RosterIngressSignerError)?,
        ))
    }
}

#[async_trait]
impl FencedMutationRosterExecutorAttestor for ProductionRosterAttestationIssuer {
    fn trust_root(&self) -> FencedMutationRosterAttestationTrustRootV1 {
        self.executor_trust_root.clone()
    }

    fn executor_certificate(
        &self,
    ) -> Result<FencedMutationRosterExecutorCertificatePartsV1, FencedMutationRosterExecutorError>
    {
        Ok(self.executor_attestation_certificate.clone())
    }

    async fn sign_terminal(
        &self,
        input: &FencedMutationRosterTerminalAttestationSigningInputV1<'_>,
    ) -> Result<[u8; 64], FencedMutationRosterExecutorError> {
        Ok(Self::low_s_p1363(
            &self.executor_key,
            input.signing_digest()?,
        ))
    }

    async fn sign_compact_terminal(
        &self,
        input: &FencedMutationRosterCompactTerminalMemberSigningInputV2<'_>,
    ) -> Result<[u8; 64], FencedMutationRosterExecutorError> {
        Ok(Self::low_s_p1363(
            &self.executor_key,
            input.signing_digest()?,
        ))
    }
}

// The test executable is deliberately its own child binary. Each phase gets a
// fresh process image, fresh TLS material, and newly constructed client and
// provider objects; only parent-owned durable voter files and fsync'd journals
// cross an exit.
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_PHASE_ENV: &str = "OPC_PROTECTED_ROSTER_PROCESS_LOSS_PHASE";
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_STATE_ENV: &str = "OPC_PROTECTED_ROSTER_PROCESS_LOSS_STATE";
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_TEST: &str =
    "persistent_three_voter_protected_roster_survives_real_os_process_loss";
#[cfg(feature = "test-control")]
fn install_protected_roster_process_loss_child_panic_hook() {
    std::panic::set_hook(Box::new(|panic| match panic.location() {
        Some(location) => eprintln!(
            "process-loss child panic; test_source={}; line={}; column={}",
            location.file().ends_with("stateless_quorum_consumer.rs"),
            location.line(),
            location.column(),
        ),
        None => eprintln!("process-loss child panic; location=unknown"),
    }));
}
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_SNAPSHOT_BOUND: Duration = Duration::from_secs(5 * 60);
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_LEASE_TTL: Duration = Duration::from_secs(60);
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_LEASE_EXPIRY_SCHEDULING_SLACK: Duration =
    Duration::from_secs(10);
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_LEASE_EXPIRY_POLL_BOUND: Duration = Duration::from_secs(
    PROTECTED_ROSTER_PROCESS_LOSS_LEASE_TTL.as_secs()
        + PROTECTED_ROSTER_PROCESS_LOSS_LEASE_EXPIRY_SCHEDULING_SLACK.as_secs(),
);
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_MAX_SEQUENTIAL_READY_WAITS: u64 = 6;
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_SEQUENTIAL_READY_BOUND: Duration = Duration::from_secs(
    THREE_VOTER_READY_TIMEOUT.as_secs() * PROTECTED_ROSTER_PROCESS_LOSS_MAX_SEQUENTIAL_READY_WAITS,
);
#[cfg(feature = "test-control")]
// The fixed margin covers synchronous setup and bounded consumer operations
// between the explicitly accounted readiness, expiry, and snapshot waits.
const PROTECTED_ROSTER_PROCESS_LOSS_CHILD_OPERATION_MARGIN: Duration = Duration::from_secs(2 * 60);
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_CHILD_EXIT_BOUND: Duration = Duration::from_secs(
    PROTECTED_ROSTER_PROCESS_LOSS_SNAPSHOT_BOUND.as_secs()
        + PROTECTED_ROSTER_PROCESS_LOSS_SEQUENTIAL_READY_BOUND.as_secs()
        + PROTECTED_ROSTER_PROCESS_LOSS_LEASE_EXPIRY_POLL_BOUND.as_secs()
        + PROTECTED_ROSTER_PROCESS_LOSS_CHILD_OPERATION_MARGIN.as_secs(),
);
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_CHILD_REAP_BOUND: Duration =
    PROTECTED_ROSTER_PROCESS_LOSS_LEASE_EXPIRY_SCHEDULING_SLACK;
#[cfg(feature = "test-control")]
const PROTECTED_ROSTER_PROCESS_LOSS_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[cfg(feature = "test-control")]
fn protected_roster_process_loss_state_dir() -> PathBuf {
    std::env::var_os(PROTECTED_ROSTER_PROCESS_LOSS_STATE_ENV)
        .map(PathBuf::from)
        .expect("process-loss child receives a private state directory")
}

#[cfg(feature = "test-control")]
fn write_protected_roster_process_loss_state(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .expect("create process-loss state file");
    file.write_all(bytes)
        .expect("write process-loss state file");
    file.sync_all().expect("sync process-loss state file");
    std::fs::File::open(
        path.parent()
            .expect("process-loss state file has a parent directory"),
    )
    .expect("open process-loss state directory")
    .sync_all()
    .expect("sync process-loss state directory");
}

#[cfg(feature = "test-control")]
fn read_protected_roster_process_loss_state(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read process-loss state file")
}

#[cfg(feature = "test-control")]
fn protected_roster_process_loss_mutation_counts(admission: usize, terminal: usize) -> Vec<u8> {
    format!("{admission}:{terminal}").into_bytes()
}

#[cfg(feature = "test-control")]
fn read_protected_roster_process_loss_mutation_counts(path: &Path) -> (usize, usize) {
    let encoded = String::from_utf8(read_protected_roster_process_loss_state(path))
        .expect("process-loss roster mutation counts are UTF-8");
    let (admission, terminal) = encoded
        .split_once(':')
        .expect("process-loss roster mutation counts are delimited");
    (
        admission
            .parse()
            .expect("process-loss admission mutation count is numeric"),
        terminal
            .parse()
            .expect("process-loss terminal mutation count is numeric"),
    )
}

#[cfg(feature = "test-control")]
fn protected_roster_process_loss_voter_positions(
    fleet: &ThreeVoterConsumerFleet,
) -> ([u64; THREE_VOTER_COUNT], [u64; THREE_VOTER_COUNT]) {
    let statuses = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::status)
        .collect::<Vec<_>>();
    (
        std::array::from_fn(|index| {
            statuses[index]
                .applied_index
                .expect("process-loss voter has an applied position")
        }),
        std::array::from_fn(|index| {
            statuses[index]
                .last_log_index
                .expect("process-loss voter has a durable log position")
        }),
    )
}

#[cfg(feature = "test-control")]
fn protected_roster_process_loss_counter_total<const N: usize>(counters: &[u64; N]) -> u64 {
    counters.iter().copied().sum()
}

#[cfg(feature = "test-control")]
fn assert_protected_roster_process_loss_state_unchanged(
    before: &[ProtectedRosterConsensusDiagnosticSnapshot],
    after: &[ProtectedRosterConsensusDiagnosticSnapshot],
    context: &str,
) {
    assert_eq!(before.len(), THREE_VOTER_COUNT);
    assert_eq!(after.len(), THREE_VOTER_COUNT);
    for voter in 0..THREE_VOTER_COUNT {
        assert_eq!(before[voter].occupancy_valid, 1, "{context}");
        assert_eq!(after[voter].occupancy_valid, 1, "{context}");
        assert_eq!(
            after[voter].live_reservations, before[voter].live_reservations,
            "{context}: live reservations remain unchanged on voter {voter}",
        );
        assert_eq!(
            after[voter].retained_reservations, before[voter].retained_reservations,
            "{context}: retained reservations remain unchanged on voter {voter}",
        );
        assert_eq!(
            after[voter].tombstone_reservations, before[voter].tombstone_reservations,
            "{context}: tombstone reservations remain unchanged on voter {voter}",
        );
        assert_eq!(
            protected_roster_process_loss_counter_total(
                &after[voter].state_machine_sqlite_commit_latency_millis,
            ),
            protected_roster_process_loss_counter_total(
                &before[voter].state_machine_sqlite_commit_latency_millis,
            ),
            "{context}: no roster-bearing state-machine transaction commits on voter {voter}",
        );
    }
}

#[cfg(feature = "test-control")]
async fn wait_for_protected_roster_process_loss_lease_expiry(guard: &LeaseGuard, phase: &str) {
    tokio::time::timeout(
        PROTECTED_ROSTER_PROCESS_LOSS_LEASE_EXPIRY_POLL_BOUND,
        async {
            while Timestamp::now_utc() <= guard.expires_at() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        },
    )
    .await
    .unwrap_or_else(|_| panic!("{phase} waits only for its prior held lease to expire"));
}

#[cfg(feature = "test-control")]
struct ProtectedRosterProcessLossChild {
    phase: &'static str,
    child: Option<Child>,
}

#[cfg(feature = "test-control")]
enum ProtectedRosterProcessLossChildCleanup {
    Reaped,
    HandedToProcessWideReaper,
}

#[cfg(feature = "test-control")]
struct ProtectedRosterProcessLossReaper {
    pending: Mutex<Vec<Child>>,
    available: Condvar,
}

#[cfg(feature = "test-control")]
fn protected_roster_process_loss_reaper(
    phase: &'static str,
) -> &'static Arc<ProtectedRosterProcessLossReaper> {
    static REAPER: OnceLock<Arc<ProtectedRosterProcessLossReaper>> = OnceLock::new();
    REAPER.get_or_init(|| {
        let reaper = Arc::new(ProtectedRosterProcessLossReaper {
            pending: Mutex::new(Vec::new()),
            available: Condvar::new(),
        });
        let worker = Arc::clone(&reaper);
        std::thread::Builder::new()
            .name("protected-roster-process-loss-reaper".to_owned())
            .spawn(move || loop {
                let mut child = {
                    let mut pending = worker
                        .pending
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    while pending.is_empty() {
                        pending = worker
                            .available
                            .wait(pending)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    pending
                        .pop()
                        .expect("process-loss reaper owns a pending child")
                };
                loop {
                    let _ = child.kill();
                    if child.wait().is_ok() {
                        break;
                    }
                    std::thread::sleep(PROTECTED_ROSTER_PROCESS_LOSS_CHILD_POLL_INTERVAL);
                }
            })
            .unwrap_or_else(|_| panic!("process-loss process-wide reaper starts; phase={phase}"));
        reaper
    })
}

#[cfg(feature = "test-control")]
impl ProtectedRosterProcessLossChild {
    fn spawn(state: &Path, phase: &'static str) -> Self {
        // Start the sole process-wide reaper before the child exists. A bounded
        // foreground cleanup can therefore always transfer ownership instead
        // of dropping an unreaped Child.
        let _ = protected_roster_process_loss_reaper(phase);
        let child = Command::new(std::env::current_exe().expect("current integration-test binary"))
            .arg("--exact")
            .arg(PROTECTED_ROSTER_PROCESS_LOSS_TEST)
            .arg("--nocapture")
            .env(PROTECTED_ROSTER_PROCESS_LOSS_PHASE_ENV, phase)
            .env(PROTECTED_ROSTER_PROCESS_LOSS_STATE_ENV, state)
            .env("RUST_TEST_THREADS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|_| panic!("process-loss child spawn fails; phase={phase}"));
        Self {
            phase,
            child: Some(child),
        }
    }

    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        let status = self
            .child
            .as_mut()
            .expect("process-loss child remains owned until it is reaped")
            .try_wait()?;
        if status.is_some() {
            drop(self.child.take());
        }
        Ok(status)
    }

    fn terminate_and_reap(&mut self) -> ProtectedRosterProcessLossChildCleanup {
        let reaped = {
            let Some(child) = self.child.as_mut() else {
                return ProtectedRosterProcessLossChildCleanup::Reaped;
            };
            let _ = child.kill();
            let deadline = Instant::now() + PROTECTED_ROSTER_PROCESS_LOSS_CHILD_REAP_BOUND;
            loop {
                if let Ok(Some(_)) = child.try_wait() {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(PROTECTED_ROSTER_PROCESS_LOSS_CHILD_POLL_INTERVAL);
            }
        };
        if reaped {
            drop(self.child.take());
            ProtectedRosterProcessLossChildCleanup::Reaped
        } else {
            let child = self
                .child
                .take()
                .expect("process-loss unreaped child remains owned for reaper handoff");
            let reaper = protected_roster_process_loss_reaper(self.phase);
            {
                let mut pending = reaper
                    .pending
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.push(child);
            }
            reaper.available.notify_one();
            ProtectedRosterProcessLossChildCleanup::HandedToProcessWideReaper
        }
    }
}

#[cfg(feature = "test-control")]
impl Drop for ProtectedRosterProcessLossChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

#[cfg(feature = "test-control")]
fn run_protected_roster_process_loss_child(state: &Path, phase: &str) {
    let phase = match phase {
        "phase-one" => "phase-one",
        "phase-two" => "phase-two",
        "phase-three" => "phase-three",
        _ => panic!("process-loss child requires a closed phase label"),
    };
    let mut child = ProtectedRosterProcessLossChild::spawn(state, phase);
    let deadline = Instant::now() + PROTECTED_ROSTER_PROCESS_LOSS_CHILD_EXIT_BOUND;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "process-loss child exits successfully; phase={phase}; status={status}"
                );
                return;
            }
            Ok(None) => {}
            Err(_) => match child.terminate_and_reap() {
                ProtectedRosterProcessLossChildCleanup::Reaped => {
                    panic!("process-loss child observation fails; phase={phase}")
                }
                ProtectedRosterProcessLossChildCleanup::HandedToProcessWideReaper => {
                    panic!("process-loss child reaper handoff follows observation failure; phase={phase}")
                }
            },
        }
        if Instant::now() >= deadline {
            match child.terminate_and_reap() {
                ProtectedRosterProcessLossChildCleanup::Reaped => {
                    panic!("process-loss child exceeds its fixed exit bound; phase={phase}")
                }
                ProtectedRosterProcessLossChildCleanup::HandedToProcessWideReaper => {
                    panic!("process-loss child reaper handoff follows exit-bound failure; phase={phase}")
                }
            }
        }
        std::thread::sleep(PROTECTED_ROSTER_PROCESS_LOSS_CHILD_POLL_INTERVAL);
    }
}

#[cfg(feature = "test-control")]
async fn compact_protected_roster_process_loss_admission(
    fleet: &ThreeVoterConsumerFleet,
    leader: usize,
    admitted_log_index: u64,
) {
    const SNAPSHOT_COMMANDS: usize = 4_300;
    const MAX_SNAPSHOT_MAINTENANCE_REJECTIONS: usize = 8;

    let target_log_index = admitted_log_index + SNAPSHOT_COMMANDS as u64;
    let mut workload_leader = leader;
    let mut workload_term = fleet.stores[workload_leader].status().term;
    tokio::time::timeout(PROTECTED_ROSTER_PROCESS_LOSS_SNAPSHOT_BOUND, async {
        let mut maintenance_rejections = 0_usize;
        while fleet.stores[workload_leader]
            .status()
            .last_log_index
            .is_none_or(|index| index < target_log_index)
        {
            match fleet.stores[workload_leader]
                .max_replication_sequence()
                .await
            {
                Ok(_) => {}
                Err(StoreError::BackendUnavailable(_))
                    if maintenance_rejections < MAX_SNAPSHOT_MAINTENANCE_REJECTIONS =>
                {
                    maintenance_rejections += 1;
                    (workload_leader, _, workload_term) = fleet
                        .wait_for_admitted_quorum_leader(&[0, 1, 2], workload_term)
                        .await;
                    tokio::task::yield_now().await;
                }
                Err(_) => panic!("process-loss snapshot command was rejected"),
            }
        }
    })
    .await
    .expect("process-loss snapshot command batch completes");
    tokio::time::timeout(THREE_VOTER_READY_TIMEOUT, async {
        loop {
            let progress = fleet.stores[workload_leader]
                .probe_durable_readiness()
                .await
                .recovery_progress();
            if progress
                .snapshot_index()
                .is_some_and(|index| index >= admitted_log_index)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("process-loss admission is compacted into a snapshot");
    fleet.wait_all_application_sequences(target_log_index).await;
}

#[cfg(feature = "test-control")]
async fn protected_roster_process_loss_phase_one(state: &Path) {
    let durable_root = tempfile::Builder::new()
        .prefix("protected-roster-three-voter-")
        .tempdir_in(state)
        .expect("create parent-owned durable process-loss directory");
    let pki = Arc::new(TestPki::new());
    let mut fleet = ThreeVoterConsumerFleet::start_with_topology_in_directory(
        Arc::clone(&pki),
        None,
        true,
        Some(ProductionRosterAttestationIssuer::trust_root()),
        ThreeVoterFleetDirectory::Owned(durable_root),
        None,
    )
    .await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    fleet.stores[leader]
        .activate_protected_roster_profile()
        .await
        .expect("phase one activates the persisted protected-roster profile");
    fleet.wait_all_ready().await;

    let server_spiffe = three_voter_spiffe(leader);
    let client_spiffe = spiffe("three-voter-process-loss-client");
    let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(leader),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let service = Arc::new(fleet.stores[leader].consumer_service());
    let transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        service.clone(),
        service,
    ));
    let (server, address) = SessionQuorumConsumerServer::new(
        transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_roster_ingress(transport.clone(), ingress_signer)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("phase-one protected-roster listener"),
    )
    .await
    .expect("start phase-one protected-roster listener");
    let _server = AbortConsumerServerOnDrop::new(server);

    let setup_provider = CountingKeyProvider::with_active_session_key();
    let setup_client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    let setup_physical: Arc<dyn SessionBackend> = Arc::new(
        SessionConsumerFencedTransitionBackend::stateless(setup_client)
            .expect("phase-one public SessionBackend"),
    );
    let setup_outer: Arc<dyn SessionBackend> = Arc::new(
        EncryptingSessionBackend::new(
            setup_physical,
            Arc::clone(&setup_provider),
            "three-voter-process-loss-protected-roster",
        )
        .with_fenced_transition_journal(Arc::new(
            PreparedFencedTransitionJournal::create_new(
                state.join("prepared.sqlite"),
                PreparedFencedTransitionJournalKey::from_bytes([0xd4; 32]),
            )
            .expect("create phase-one prepared-transition journal"),
        )),
    );
    let key = test_key();
    let owner = OwnerId::new("three-voter-process-loss-owner").expect("process-loss owner");
    let setup_lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        PROTECTED_ROSTER_PROCESS_LOSS_LEASE_TTL,
    )
    .expect("phase-one incumbent lease");
    let incumbent = FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([0xd5; 16]),
        setup_lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: setup_lease
                .committed_fence()
                .expect("phase-one incumbent fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("three-voter-process-loss-current"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([0xd6]),
        }),
    )
    .expect("phase-one incumbent request");
    let incumbent = setup_outer
        .prepare_fenced_transition(incumbent)
        .await
        .expect("prepare phase-one incumbent");
    let incumbent = setup_outer
        .fenced_transition(&incumbent)
        .await
        .expect("commit phase-one incumbent");
    let original_guard = incumbent.lease().clone();
    let expected_generation = incumbent.committed_generation();
    write_protected_roster_process_loss_state(
        &state.join("original-guard.json"),
        &serde_json::to_vec(&original_guard).expect("encode original process-loss guard"),
    );

    let admission_baseline = fleet
        .application_sequences()
        .await
        .into_iter()
        .max()
        .expect("phase-one three-voter admission baseline");
    fleet
        .wait_all_application_sequences(admission_baseline)
        .await;
    let members = (0_u8..6)
        .map(|ordinal| {
            Member::new(
                ordinal,
                MemberOperationId::from_bytes([ordinal.saturating_add(111); 16])
                    .expect("process-loss member ID"),
                vec![0xe1, ordinal],
                u64::from(ordinal) + 701,
            )
            .expect("process-loss member")
        })
        .collect::<Vec<_>>();
    let protected_plan = vec![0xe2; 97];
    let protected_checkpoint = vec![0xe3; 83];
    let protected_result = vec![0xe4; 79];
    let proposal = AdmissionProposal::new(
        FencedMutationRosterProfile::v1(),
        RosterId::from_bytes([0xe5; 16]).expect("process-loss roster ID"),
        members.clone(),
        EstablishedMutation::no_op(),
        protected_plan.clone(),
        protected_checkpoint.clone(),
        protected_result.clone(),
    )
    .expect("phase-one exact protected admission");
    let provider_journal_path = state.join("provider.journal");
    let provider_journal = Arc::new(
        DurableRosterProviderJournal::create(&provider_journal_path)
            .expect("create phase-one provider journal"),
    );
    provider_journal
        .append_admission(
            proposal.roster_id(),
            &protected_plan,
            &protected_checkpoint,
            &protected_result,
        )
        .expect("persist exact process-loss admission body");
    let publication_journal_path = state.join("publication.journal");
    let publication_journal =
        DurableEstablishedPublicationJournal::create(&publication_journal_path)
            .expect("create phase-one publication journal");
    let persistent = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    assert!(persistent.fenced_mutation_roster_transport_enabled());
    assert_eq!(
        SESSION_QUORUM_CONSUMER_ROSTER_ALPN,
        b"opc-session-consumer/3"
    );
    let provider = Arc::new(DurableCrashCutProvider::initial(
        Arc::clone(&provider_journal),
        DurableRosterCrashCut::PreparedBeforeRun,
        attestor,
    ));
    let publication = Arc::new(DurableEstablishedPublicationProvider::initial(
        publication_journal,
        false,
        false,
    ));
    let adapter = persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&provider),
            Arc::clone(&publication),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("process-loss concurrency"),
        )
        .expect("compose phase-one protected-roster adapter");
    let client = adapter.client().clone();
    let mut admission = client
        .prepare(original_guard.clone(), expected_generation, proposal)
        .expect("prepare phase-one protected-roster admission");
    let roster_id = admission.roster_id();
    let admission_diagnostics_before = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    let (admission_applied_before, admission_log_before) =
        protected_roster_process_loss_voter_positions(&fleet);
    let active = match client
        .admit(&mut admission)
        .await
        .expect("commit phase-one protected-roster admission")
    {
        AdmissionOutcome::Admitted(active) => active,
        AdmissionOutcome::NotTransmitted | AdmissionOutcome::OutcomeUnknown(_) => {
            panic!("phase one must durably admit exactly once")
        }
    };
    assert_eq!(active.roster_id(), roster_id);
    assert_eq!(active.protected_plan(), protected_plan.as_slice());
    let admission_applied_floor = fleet.stores[leader]
        .status()
        .applied_index
        .expect("serving voter applied the admitted PollAdmit");
    fleet
        .wait_all_application_sequences(admission_applied_floor)
        .await;
    let (admission_applied_after, admission_log_after) =
        protected_roster_process_loss_voter_positions(&fleet);
    let admission_diagnostics_after = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    for voter in 0..THREE_VOTER_COUNT {
        assert!(
            admission_applied_after[voter] >= admission_applied_floor
                && admission_applied_after[voter] > admission_applied_before[voter],
            "the admitted PollAdmit is applied at the observed operation floor on every voter",
        );
        assert!(
            admission_log_after[voter] >= admission_applied_floor
                && admission_log_after[voter] > admission_log_before[voter],
            "the admitted PollAdmit is durably present at the observed operation floor in every voter log",
        );
        assert_eq!(admission_diagnostics_after[voter].occupancy_valid, 1);
        assert_eq!(
            admission_diagnostics_after[voter].live_reservations,
            admission_diagnostics_before[voter].live_reservations + 1,
            "the admitted PollAdmit creates exactly one durable live reservation on every voter",
        );
        assert_eq!(
            admission_diagnostics_after[voter].retained_reservations,
            admission_diagnostics_before[voter].retained_reservations,
        );
        assert_eq!(
            protected_roster_process_loss_counter_total(
                &admission_diagnostics_after[voter].state_machine_sqlite_commit_latency_millis,
            ),
            protected_roster_process_loss_counter_total(
                &admission_diagnostics_before[voter].state_machine_sqlite_commit_latency_millis,
            ) + 1,
            "exactly one roster-bearing state-machine transaction commits PollAdmit on every voter",
        );
    }
    let admitted_log_index = admission_log_after[leader];
    assert_eq!(
        transport.roster_admission_calls.load(Ordering::SeqCst),
        1,
        "phase one admits exactly one protected roster"
    );
    let phase_one_admission_mutations = transport
        .roster_admission_recorded_responses
        .load(Ordering::SeqCst);
    assert_eq!(
        phase_one_admission_mutations, 1,
        "the exact per-voter admission delta pairs with one recorded success response",
    );
    assert_eq!(
        transport.roster_terminal_calls.load(Ordering::SeqCst),
        0,
        "phase one leaves the admitted cut for the replacement process"
    );
    assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
    compact_protected_roster_process_loss_admission(&fleet, leader, admitted_log_index).await;
    let phase_one_terminal_mutations = transport
        .roster_terminal_recorded_responses
        .load(Ordering::SeqCst);
    assert_eq!(
        phase_one_terminal_mutations, 0,
        "phase one exits only after the admitted durable cut",
    );

    let durable_directory = fleet
        .directory
        .take()
        .expect("phase one retains the three voter durable directory")
        .retain_after_process_loss();
    write_protected_roster_process_loss_state(
        &state.join("durable-directory"),
        durable_directory
            .to_str()
            .expect("durable directory is UTF-8")
            .as_bytes(),
    );
    write_protected_roster_process_loss_state(
        &state.join("roster-mutations"),
        &protected_roster_process_loss_mutation_counts(
            phase_one_admission_mutations,
            phase_one_terminal_mutations,
        ),
    );
    write_protected_roster_process_loss_state(&state.join("phase-one-complete"), b"complete");
    // Bypass every Rust destructor while the original lease remains held.
    // Phase two must cross actual expiry before it can acquire successor
    // authority and learn this exact cut from durable voter state/journals.
    std::process::exit(0);
}

#[cfg(feature = "test-control")]
async fn protected_roster_process_loss_phase_two(state: &Path) {
    assert_eq!(
        read_protected_roster_process_loss_state(&state.join("phase-one-complete")),
        b"complete",
        "phase two requires a fully exited phase-one durable cut"
    );
    let (phase_one_admission_mutations, phase_one_terminal_mutations) =
        read_protected_roster_process_loss_mutation_counts(&state.join("roster-mutations"));
    let durable_directory = PathBuf::from(
        String::from_utf8(read_protected_roster_process_loss_state(
            &state.join("durable-directory"),
        ))
        .expect("durable directory state is UTF-8"),
    );
    assert!(durable_directory.starts_with(state));
    assert!(durable_directory.is_dir());
    let original_guard: LeaseGuard = serde_json::from_slice(
        &read_protected_roster_process_loss_state(&state.join("original-guard.json")),
    )
    .expect("decode original process-loss guard");
    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start_with_topology_in_directory(
        Arc::clone(&pki),
        None,
        true,
        Some(ProductionRosterAttestationIssuer::trust_root()),
        ThreeVoterFleetDirectory::Reopened(durable_directory),
        None,
    )
    .await;
    // The reopen intentionally does not call activate_protected_roster_profile:
    // the only post-open writes below are one current-fence acquisition and
    // the one retained roster terminalization.
    fleet.wait_all_ready().await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    let server_spiffe = three_voter_spiffe(leader);
    let client_spiffe = spiffe("three-voter-process-loss-client");
    let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(leader),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let service = Arc::new(fleet.stores[leader].consumer_service());
    let transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        service.clone(),
        service,
    ));
    let (server, address) = SessionQuorumConsumerServer::new(
        transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_roster_ingress(transport.clone(), ingress_signer)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("phase-two protected-roster listener"),
    )
    .await
    .expect("start phase-two protected-roster listener");
    let _server = AbortConsumerServerOnDrop::new(server);
    let before_current_fence = fleet
        .application_sequences()
        .await
        .into_iter()
        .max()
        .expect("three process-loss voters have an applied sequence");
    fleet
        .wait_all_application_sequences(before_current_fence)
        .await;
    let lease_client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    wait_for_protected_roster_process_loss_lease_expiry(&original_guard, "phase two").await;
    let (current_fence_applied_before, current_fence_log_before) =
        protected_roster_process_loss_voter_positions(&fleet);
    let current_fence_diagnostics_before = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    let current_guard = lease_client
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0xe7; 16]),
            test_key(),
            OwnerId::new("three-voter-process-loss-successor").expect("successor owner"),
            PROTECTED_ROSTER_PROCESS_LOSS_LEASE_TTL,
        )
        .await
        .expect("acquire higher current process-loss fence");
    assert!(
        current_guard.fence() > original_guard.fence(),
        "replacement process receives a higher current fence"
    );
    let phase_two_guard = current_guard.clone();
    write_protected_roster_process_loss_state(
        &state.join("phase-two-guard.json"),
        &serde_json::to_vec(&phase_two_guard).expect("encode phase-two process-loss guard"),
    );
    let current_fence_applied_floor = fleet.stores[leader]
        .status()
        .applied_index
        .expect("serving voter applied the successor fence");
    fleet
        .wait_all_application_sequences(current_fence_applied_floor)
        .await;
    let (current_fence_applied_after, current_fence_log_after) =
        protected_roster_process_loss_voter_positions(&fleet);
    let current_fence_diagnostics_after = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    for voter in 0..THREE_VOTER_COUNT {
        assert!(
            current_fence_applied_after[voter] >= current_fence_applied_floor
                && current_fence_applied_after[voter] > current_fence_applied_before[voter],
            "the successor fence is applied at the observed operation floor on every reopened voter",
        );
        assert!(
            current_fence_log_after[voter] >= current_fence_applied_floor
                && current_fence_log_after[voter] > current_fence_log_before[voter],
            "the successor fence is durably present at the observed operation floor in every reopened voter log",
        );
        assert_eq!(
            current_fence_diagnostics_after[voter].live_reservations,
            current_fence_diagnostics_before[voter].live_reservations,
            "the generic successor-fence acquisition is not a roster mutation",
        );
        assert_eq!(
            protected_roster_process_loss_counter_total(
                &current_fence_diagnostics_after[voter].state_machine_sqlite_commit_latency_millis,
            ),
            protected_roster_process_loss_counter_total(
                &current_fence_diagnostics_before[voter].state_machine_sqlite_commit_latency_millis,
            ),
            "the generic successor-fence acquisition commits no roster state-machine transaction",
        );
    }

    let members = (0_u8..6)
        .map(|ordinal| {
            Member::new(
                ordinal,
                MemberOperationId::from_bytes([ordinal.saturating_add(111); 16])
                    .expect("process-loss member ID"),
                vec![0xe1, ordinal],
                u64::from(ordinal) + 701,
            )
            .expect("process-loss member")
        })
        .collect::<Vec<_>>();
    let protected_plan = vec![0xe2; 97];
    let protected_checkpoint = vec![0xe3; 83];
    let protected_result = vec![0xe4; 79];
    let roster_id = RosterId::from_bytes([0xe5; 16]).expect("process-loss roster ID");
    let expected_generation = Generation::new(1);
    let provider_journal = Arc::new(
        DurableRosterProviderJournal::reopen(state.join("provider.journal"))
            .expect("reopen phase-one provider journal"),
    );
    let exact_admission = format!(
        "admission:{}:{}:{}:{}",
        durable_roster_hex(roster_id.as_bytes()),
        durable_roster_hex(&protected_plan),
        durable_roster_hex(&protected_checkpoint),
        durable_roster_hex(&protected_result),
    );
    assert!(
        provider_journal
            .contents()
            .lines()
            .any(|line| line == exact_admission),
        "reopened provider journal binds the exact protected plan, checkpoint, and result"
    );
    let provider = Arc::new(DurableCrashCutProvider::recovery(
        Arc::clone(&provider_journal),
        attestor,
    ));
    let publication_journal =
        DurableEstablishedPublicationJournal::reopen(state.join("publication.journal"))
            .expect("reopen phase-one publication journal");
    let publication = Arc::new(DurableEstablishedPublicationProvider::recovery(
        publication_journal,
        false,
    ));
    let persistent = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    assert!(persistent.fenced_mutation_roster_transport_enabled());
    assert_eq!(
        SESSION_QUORUM_CONSUMER_ROSTER_ALPN,
        b"opc-session-consumer/3"
    );
    let adapter = persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&provider),
            Arc::clone(&publication),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("process-loss concurrency"),
        )
        .expect("compose phase-two protected-roster adapter");
    let client = adapter.client().clone();
    let input = RecoveryInput::new(
        roster_id,
        OwnerId::new("three-voter-process-loss-owner").expect("process-loss owner"),
        original_guard.fence(),
        current_guard,
        expected_generation,
    )
    .expect("construct current higher-fence process-loss recovery input");
    let mut recovered = match client
        .recover(&input)
        .await
        .expect("recover phase-one admitted roster from snapshots")
    {
        RecoveryOutcome::Admitted(recovered) => recovered,
        RecoveryOutcome::Terminal(_) | RecoveryOutcome::Compacted => {
            panic!("phase-two recovery retains the exact admitted roster")
        }
    };
    assert_eq!(recovered.roster_id(), roster_id);
    assert_eq!(recovered.members(), members.as_slice());
    assert_eq!(recovered.protected_plan(), protected_plan.as_slice());
    assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication.begin_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication.adopt_calls.load(Ordering::SeqCst), 0);
    let recovery_diagnostics_after = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    assert_protected_roster_process_loss_state_unchanged(
        &current_fence_diagnostics_after,
        &recovery_diagnostics_after,
        "reopen and read-only recovery do not reactivate the profile or append a roster command",
    );

    let mut proofs = Vec::with_capacity(6);
    for ordinal in 0_u8..6 {
        let mut member = recovered
            .member(MemberOrdinal::new(ordinal).expect("process-loss recovered ordinal"))
            .expect("issue process-loss recovered member");
        assert!(matches!(
            client
                .status(&mut member)
                .await
                .expect("read process-loss provider status"),
            MemberRecoveryOutcome::Ambiguous(MemberRecoveryStatus::NotFound)
        ));
        match client
            .adopt(&mut member)
            .await
            .expect("adopt exact process-loss provider operation")
        {
            MemberRecoveryOutcome::Conclusive(proof) => proofs.push(*proof),
            _ => panic!("recovered member remains recovery-only and adopts exactly once"),
        }
        assert_eq!(provider_journal.phase_calls("execute", ordinal), 0);
        assert_eq!(provider_journal.phase_calls("apply", ordinal), 1);
    }
    assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.status_calls.load(Ordering::SeqCst), 6);
    assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 6);
    let proofs = CompleteProofSet::new(proofs).expect("six exact process-loss proofs");
    let terminal_diagnostics_before = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    assert_protected_roster_process_loss_state_unchanged(
        &recovery_diagnostics_after,
        &terminal_diagnostics_before,
        "provider status and adoption have no per-member consensus write",
    );
    let (terminal_applied_before, terminal_log_before) =
        protected_roster_process_loss_voter_positions(&fleet);
    let mut terminal = client
        .prepare_terminal(recovered.for_terminal(), &proofs)
        .await
        .expect("prepare exact process-loss terminal");
    match client
        .terminalize(&mut terminal)
        .await
        .expect("terminalize exact process-loss roster")
    {
        TerminalizationOutcome::Committed(TerminalReceipt::Established(established)) => {
            assert_eq!(established.protected_checkpoint(), protected_checkpoint);
            assert_eq!(established.protected_result(), protected_result);
        }
        TerminalizationOutcome::Committed(TerminalReceipt::Aborted(_))
        | TerminalizationOutcome::NotTransmitted
        | TerminalizationOutcome::OutcomeUnknown => {
            panic!("phase two returns one exact Established terminal receipt")
        }
    }
    let terminal_applied_floor = fleet.stores[leader]
        .status()
        .applied_index
        .expect("serving voter applied the exact Established terminal");
    fleet
        .wait_all_application_sequences(terminal_applied_floor)
        .await;
    let (terminal_applied_after, terminal_log_after) =
        protected_roster_process_loss_voter_positions(&fleet);
    let terminal_diagnostics_after = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    for voter in 0..THREE_VOTER_COUNT {
        assert!(
            terminal_applied_after[voter] >= terminal_applied_floor
                && terminal_applied_after[voter] > terminal_applied_before[voter],
            "the exact Established terminal is applied at the observed operation floor on every voter",
        );
        assert!(
            terminal_log_after[voter] >= terminal_applied_floor
                && terminal_log_after[voter] > terminal_log_before[voter],
            "the exact Established terminal is durably present at the observed operation floor in every voter log",
        );
        assert_eq!(terminal_diagnostics_after[voter].occupancy_valid, 1);
        assert_eq!(
            terminal_diagnostics_after[voter].live_reservations + 1,
            terminal_diagnostics_before[voter].live_reservations,
            "terminalization consumes exactly the admission's live reservation on every voter",
        );
        assert_eq!(
            terminal_diagnostics_after[voter].retained_reservations,
            terminal_diagnostics_before[voter].retained_reservations + 1,
            "terminalization converts the same reservation into one retained terminal on every voter",
        );
        assert_eq!(
            protected_roster_process_loss_counter_total(
                &terminal_diagnostics_after[voter]
                    .state_machine_sqlite_commit_latency_millis,
            ),
            protected_roster_process_loss_counter_total(
                &terminal_diagnostics_before[voter]
                    .state_machine_sqlite_commit_latency_millis,
            ) + 1,
            "exactly one roster-bearing state-machine transaction commits Established on every voter",
        );
    }
    let phase_two_admission_mutations = transport
        .roster_admission_recorded_responses
        .load(Ordering::SeqCst);
    let phase_two_terminal_mutations = transport
        .roster_terminal_recorded_responses
        .load(Ordering::SeqCst);
    assert_eq!(
        phase_two_admission_mutations, 0,
        "the rejected stale-owner admission cannot become a successful roster mutation",
    );
    assert_eq!(
        phase_two_terminal_mutations, 1,
        "the exact Established receipt records one terminal roster mutation",
    );
    let retained_admission_mutations =
        phase_one_admission_mutations + phase_two_admission_mutations;
    let retained_terminal_mutations = phase_one_terminal_mutations + phase_two_terminal_mutations;
    assert_eq!(
        retained_admission_mutations, 1,
        "the persisted observed counts retain one admission mutation",
    );
    assert_eq!(
        retained_terminal_mutations, 1,
        "the persisted observed counts retain one terminal mutation",
    );
    assert_eq!(
        transport.roster_admission_calls.load(Ordering::SeqCst),
        0,
        "phase-two recovery sends no admission mutation after the durable cut",
    );
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(publication.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication.begin_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication.adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        publication
            .journal
            .state_count(DurableEstablishedPublicationState::Reserved),
        0
    );
    assert_eq!(
        publication
            .journal
            .state_count(DurableEstablishedPublicationState::Attempted),
        0
    );
    assert_eq!(
        publication
            .journal
            .state_count(DurableEstablishedPublicationState::NotTransmitted),
        0
    );
    assert_eq!(
        publication
            .journal
            .state_count(DurableEstablishedPublicationState::Published),
        0,
        "recovery returns Established but never replays an external publication",
    );

    write_protected_roster_process_loss_state(
        &state.join("phase-two-roster-mutations"),
        &protected_roster_process_loss_mutation_counts(
            retained_admission_mutations,
            retained_terminal_mutations,
        ),
    );
    write_protected_roster_process_loss_state(&state.join("phase-two-complete"), b"complete");
    // Bypass every Rust destructor after the terminal quorum commit while the
    // phase-two authority remains held. Phase three must cross actual expiry,
    // then reconstruct Established from durable voters before publication.
    std::process::exit(0);
}

#[cfg(feature = "test-control")]
async fn protected_roster_process_loss_phase_three(state: &Path) {
    assert_eq!(
        read_protected_roster_process_loss_state(&state.join("phase-two-complete")),
        b"complete",
        "phase three requires the fully exited terminal-committed cut"
    );
    let (retained_admission_mutations, retained_terminal_mutations) =
        read_protected_roster_process_loss_mutation_counts(
            &state.join("phase-two-roster-mutations"),
        );
    assert_eq!(
        retained_admission_mutations + retained_terminal_mutations,
        2,
        "the first two exited processes persist exactly two observed roster mutations",
    );
    let durable_directory = PathBuf::from(
        String::from_utf8(read_protected_roster_process_loss_state(
            &state.join("durable-directory"),
        ))
        .expect("durable directory state is UTF-8"),
    );
    assert!(durable_directory.starts_with(state));
    assert!(durable_directory.is_dir());
    let original_guard: LeaseGuard = serde_json::from_slice(
        &read_protected_roster_process_loss_state(&state.join("original-guard.json")),
    )
    .expect("decode original process-loss guard");
    let phase_two_guard: LeaseGuard = serde_json::from_slice(
        &read_protected_roster_process_loss_state(&state.join("phase-two-guard.json")),
    )
    .expect("decode phase-two process-loss guard");

    let pki = Arc::new(TestPki::new());
    let fleet = ThreeVoterConsumerFleet::start_with_topology_in_directory(
        Arc::clone(&pki),
        None,
        true,
        Some(ProductionRosterAttestationIssuer::trust_root()),
        ThreeVoterFleetDirectory::Reopened(durable_directory),
        None,
    )
    .await;
    // This third process deliberately performs no profile activation. Its
    // only durable consumer write is the higher current-fence acquisition;
    // recovery and publication remain read-only/provider-local respectively.
    fleet.wait_all_ready().await;
    let (leader, _, _) = fleet.wait_for_observed_leader().await;
    let server_spiffe = three_voter_spiffe(leader);
    let client_spiffe = spiffe("three-voter-process-loss-client");
    let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
    let attestor = ProductionRosterAttestationIssuer::new(
        fleet.consensus_identity(leader),
        authorizer.scope(),
    );
    let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
    let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
    let service = Arc::new(fleet.stores[leader].consumer_service());
    let transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
        service.clone(),
        service,
    ));
    let (server, address) = SessionQuorumConsumerServer::new(
        transport.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_roster_ingress(transport.clone(), ingress_signer)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("phase-three protected-roster listener"),
    )
    .await
    .expect("start phase-three protected-roster listener");
    let server = AbortConsumerServerOnDrop::new(server);
    let before_current_fence = fleet
        .application_sequences()
        .await
        .into_iter()
        .max()
        .expect("three process-loss voters retain an applied sequence");
    fleet
        .wait_all_application_sequences(before_current_fence)
        .await;
    let lease_client = consumer_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    wait_for_protected_roster_process_loss_lease_expiry(&phase_two_guard, "phase three").await;
    let phase_three_diagnostics_before_fence = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    let current_guard = lease_client
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0xe9; 16]),
            test_key(),
            OwnerId::new("three-voter-process-loss-terminal-successor")
                .expect("terminal successor owner"),
            PROTECTED_ROSTER_PROCESS_LOSS_LEASE_TTL,
        )
        .await
        .expect("acquire phase-three current process-loss fence");
    assert!(
        phase_two_guard.fence() > original_guard.fence(),
        "phase two itself used a higher successor fence"
    );
    assert!(
        current_guard.fence() > phase_two_guard.fence(),
        "phase three receives a higher current fence after phase-two expiry"
    );
    let phase_three_fence_applied_floor = fleet.stores[leader]
        .status()
        .applied_index
        .expect("serving voter applied the phase-three successor fence");
    fleet
        .wait_all_application_sequences(phase_three_fence_applied_floor)
        .await;
    let phase_three_applied_after_fence = fleet.application_sequences().await;
    assert!(
        phase_three_applied_after_fence
            .iter()
            .all(|sequence| *sequence >= phase_three_fence_applied_floor),
        "the phase-three successor fence is present at its observed operation floor on every voter",
    );
    let phase_three_diagnostics_after_fence = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    assert_protected_roster_process_loss_state_unchanged(
        &phase_three_diagnostics_before_fence,
        &phase_three_diagnostics_after_fence,
        "the generic phase-three successor fence commits no roster mutation",
    );

    let protected_plan = vec![0xe2; 97];
    let protected_checkpoint = vec![0xe3; 83];
    let protected_result = vec![0xe4; 79];
    let roster_id = RosterId::from_bytes([0xe5; 16]).expect("process-loss roster ID");
    let original_owner =
        OwnerId::new("three-voter-process-loss-owner").expect("process-loss owner");
    let expected_generation = Generation::new(1);
    let stale_phase_two_input = RecoveryInput::new(
        roster_id,
        original_owner.clone(),
        original_guard.fence(),
        phase_two_guard,
        expected_generation,
    )
    .expect("phase-two guard was syntactically a higher recovery authority");

    let provider_journal = Arc::new(
        DurableRosterProviderJournal::reopen(state.join("provider.journal"))
            .expect("reopen process-loss provider journal in phase three"),
    );
    let exact_admission = format!(
        "admission:{}:{}:{}:{}",
        durable_roster_hex(roster_id.as_bytes()),
        durable_roster_hex(&protected_plan),
        durable_roster_hex(&protected_checkpoint),
        durable_roster_hex(&protected_result),
    );
    assert!(
        provider_journal
            .contents()
            .lines()
            .any(|line| line == exact_admission),
        "the third process reads the byte-exact protected plan/checkpoint/result journal body"
    );
    let provider = Arc::new(DurableCrashCutProvider::recovery(
        Arc::clone(&provider_journal),
        attestor,
    ));
    let publication_provider = Arc::new(DurableEstablishedPublicationProvider::recovery(
        DurableEstablishedPublicationJournal::reopen(state.join("publication.journal"))
            .expect("reopen process-loss publication journal in phase three"),
        false,
    ));
    let persistent = protected_roster_persistent_client(
        &pki,
        address,
        &server_spiffe,
        &client_spiffe,
        fleet.voter_authority(leader),
    );
    assert!(persistent.fenced_mutation_roster_transport_enabled());
    assert_eq!(
        SESSION_QUORUM_CONSUMER_ROSTER_ALPN,
        b"opc-session-consumer/3"
    );
    let shutdown_client = persistent.clone();
    let adapter = persistent
        .into_fenced_mutation_roster_provider_adapter(
            Arc::clone(&provider),
            Arc::clone(&publication_provider),
            executor_attestor,
            NonZeroUsize::new(THREE_VOTER_COUNT).expect("process-loss concurrency"),
        )
        .expect("compose phase-three protected-roster adapter");
    let client = adapter.client().clone();
    let stale_phase_two_result = client.recover(&stale_phase_two_input).await;
    assert!(
        matches!(
            stale_phase_two_result,
            Err(RosterClientError::AuthorityRejected)
        ),
        "the expired phase-two guard is rejected remotely under the newer fence"
    );
    let input = RecoveryInput::new(
        roster_id,
        original_owner,
        original_guard.fence(),
        current_guard,
        expected_generation,
    )
    .expect("construct phase-three current higher-fence recovery input");
    let mut publication = match client
        .recover(&input)
        .await
        .expect("recover phase-two committed terminal from durable voters")
    {
        RecoveryOutcome::Terminal(TerminalReceipt::Established(established)) => {
            assert_eq!(established.protected_checkpoint(), protected_checkpoint);
            assert_eq!(established.protected_result(), protected_result);
            // This is the only public constructor for the opaque publication
            // capability: an admitted roster or an Aborted receipt cannot
            // produce it, so no provider-local effect precedes Established.
            established.into_publication()
        }
        RecoveryOutcome::Terminal(TerminalReceipt::Aborted(_)) => {
            panic!("phase three must retain the exact Established receipt")
        }
        RecoveryOutcome::Admitted(_) | RecoveryOutcome::Compacted => {
            panic!("terminal-committed process loss must not reopen execution authority")
        }
    };
    assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 0);
    for ordinal in 0_u8..6 {
        assert_eq!(provider_journal.phase_calls("execute", ordinal), 0);
        assert_eq!(provider_journal.phase_calls("apply", ordinal), 1);
    }
    assert_eq!(publication_provider.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication_provider.begin_calls.load(Ordering::SeqCst), 0);
    assert_eq!(publication_provider.adopt_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        publication_provider
            .journal
            .state_count(DurableEstablishedPublicationState::Published),
        0,
        "recovery alone cannot replay an external publication",
    );
    assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 0);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 0);
    let phase_three_diagnostics_after_recovery = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    assert_protected_roster_process_loss_state_unchanged(
        &phase_three_diagnostics_after_fence,
        &phase_three_diagnostics_after_recovery,
        "stale rejection and terminal recovery append neither a roster mutation nor a member write",
    );

    adapter
        .publish(&mut publication)
        .await
        .expect("only the recovered exact Established receipt can publish once");
    assert_eq!(publication_provider.status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(publication_provider.begin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(publication_provider.adopt_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        publication_provider
            .journal
            .state_count(DurableEstablishedPublicationState::Reserved),
        1
    );
    assert_eq!(
        publication_provider
            .journal
            .state_count(DurableEstablishedPublicationState::Attempted),
        1
    );
    assert_eq!(
        publication_provider
            .journal
            .state_count(DurableEstablishedPublicationState::NotTransmitted),
        0
    );
    assert_eq!(
        publication_provider
            .journal
            .state_count(DurableEstablishedPublicationState::Published),
        1,
        "the terminal-recovery process performs at most one provider-local external publication",
    );
    assert_eq!(
        publication_provider
            .journal
            .state_results(DurableEstablishedPublicationState::Published),
        vec![durable_roster_hex(&protected_result)],
        "the one provider-local publication retains the exact Established protected result",
    );
    assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 0);
    assert_eq!(transport.roster_terminal_calls.load(Ordering::SeqCst), 0);
    let phase_three_diagnostics_after_publication = fleet
        .stores
        .iter()
        .map(ConsensusSessionStore::protected_roster_diagnostic_snapshot)
        .collect::<Vec<_>>();
    assert_protected_roster_process_loss_state_unchanged(
        &phase_three_diagnostics_after_recovery,
        &phase_three_diagnostics_after_publication,
        "publication is provider-local and cannot append a third roster mutation",
    );

    drop(client);
    drop(adapter);
    shutdown_client.shutdown().await;
    server.abort_and_wait().await;
    fleet.shutdown().await;
    write_protected_roster_process_loss_state(&state.join("phase-three-complete"), b"complete");
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_three_voter_protected_roster_survives_real_os_process_loss() {
    let phase = std::env::var(PROTECTED_ROSTER_PROCESS_LOSS_PHASE_ENV).ok();
    if phase.is_some() {
        install_protected_roster_process_loss_child_panic_hook();
    }
    match phase.as_deref() {
        Some("phase-one") => {
            protected_roster_process_loss_phase_one(&protected_roster_process_loss_state_dir())
                .await;
        }
        Some("phase-two") => {
            protected_roster_process_loss_phase_two(&protected_roster_process_loss_state_dir())
                .await;
        }
        Some("phase-three") => {
            protected_roster_process_loss_phase_three(&protected_roster_process_loss_state_dir())
                .await;
        }
        Some(_) => panic!("invalid protected-roster process-loss phase"),
        None => {
            // Child processes have their own process-local gate. Hold this
            // process's permit while orchestrating them so their real
            // three-voter snapshot workload cannot overlap another heavy
            // fleet in the parent test binary.
            let _test_gate = THREE_VOTER_FLEET_TEST_GATE
                .acquire()
                .await
                .expect("three-voter process-loss parent gate remains open");
            let state = tempfile::tempdir().expect("parent process-loss state directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))
                    .expect("make parent process-loss state directory private");
            }
            run_protected_roster_process_loss_child(state.path(), "phase-one");
            run_protected_roster_process_loss_child(state.path(), "phase-two");
            run_protected_roster_process_loss_child(state.path(), "phase-three");
            assert_eq!(
                read_protected_roster_process_loss_state(
                    &state.path().join("phase-three-complete")
                ),
                b"complete",
                "three fresh child processes complete the durable process-loss qualification",
            );
        }
    }
}
