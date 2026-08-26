#![deny(missing_docs)]
//! High-performance session store substrate for OpenPacketCore (RFC 004).
//!
//! This crate provides the core abstractions for storing, leasing, and mutating
//! per-session network-function state with strict fencing correctness. Its
//! stale-owner protections are intended for 5G CNF session-state boundaries;
//! production suitability remains specific to the selected backend profile.
//!
//! # Protected checkpoint consumption
//!
//! Prepared checkpoint requests are obtained only from an SDK-owned
//! [`ProtectedSessionBackend`] wrapper. The returned affine request captures
//! its exact scope, caller request ID, sealed mutation, and deadline budget;
//! only the net-owned consumer composite can turn it into an execution handle.
//! Prepared is local type-state, never a wire or server authorization marker.
//!
//! ```compile_fail
//! use opc_session_store::{
//!     PreparedCheckpointAuthorityContext, PreparedCheckpointCompletion,
//!     PreparedCheckpointPort, PreparedCompareAndSetToken, PreparedLeaseAcquireToken,
//! };
//! ```
//!
//! ```compile_fail
//! use opc_session_store::{EncryptingSessionBackend, PreparedCompareAndSetRequest};
//!
//! let _ = PreparedCompareAndSetRequest::from_consumer_port;
//!
//! fn removed_attachment<B: ?Sized, P: ?Sized>(wrapper: EncryptingSessionBackend<B, P>) {
//!     let _ = wrapper.with_prepared_checkpoint_port(());
//! }
//! ```
//!
//! # Module map
//!
//! | Module | Responsibility |
//! | :--- | :--- |
//! | [`model`] | Keys, record headers, generations, state classes |
//! | [`capability`] | Backend capability declarations |
//! | [`backend`] | Storage API trait, CAS, batch operations |
//! | [`lease`] | Lease manager and fencing rules |
//! | [`membership`] | Typed topology-epoch transition requests and evidence |
//! | [`ownership`] | Generic CAS-backed ownership leases and bounded local cache |
//! | [`record`] | Stored record format and encrypted payloads |
//! | [`topology`] | Validated quorum membership and replica identity |
//! | [`topology_attestation`] | Epoch-bound observed platform-fact verification |
//! | [`readiness`] | Shared engine and topology-attested production readiness reports |
//! | [`recovery`] | Authorized offline legacy-fork inspection and recovery |
//! | [`fake`] | In-memory backend and lease manager for tests |
//! | [`error`] | `StoreError` and `LeaseError` |

#![forbid(unsafe_code)]

#[cfg(test)]
static CONSENSUS_TIMING_TEST_PERMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Serialize unit tests whose bounded Raft deadlines are themselves the
/// assertion while the default-parallel library suite performs heavy SQLite
/// snapshot and recovery work in the same process.
#[cfg(test)]
pub(crate) async fn acquire_consensus_timing_test_permit() -> tokio::sync::SemaphorePermit<'static>
{
    CONSENSUS_TIMING_TEST_PERMIT
        .acquire()
        .await
        .expect("consensus timing test permit remains open")
}

pub use opc_types::Timestamp;

pub mod backend;
pub mod capability;
pub mod clock;
pub mod consensus;
pub mod consumer;
pub mod error;
pub mod fake;
pub mod fenced_mutation_roster;
mod fenced_mutation_roster_executor;
mod fenced_mutation_roster_storage;
pub(crate) mod fenced_mutation_roster_transport;
pub mod fenced_transition;
pub mod fenced_transition_journal;
pub mod handover;
mod hex;
pub mod lease;
pub mod membership;
pub mod model;
pub mod owned_session;
pub mod ownership;
pub mod payload_codec;
pub mod quorum;
pub mod readiness;
pub mod record;
pub mod recovery;
mod replication_watch;
pub mod restore;
pub mod sqlite;
pub mod store;
pub mod topology;
pub mod topology_attestation;
pub mod ttl;

#[cfg(test)]
mod protected_fenced_transition_tests;

pub use backend::{
    BackendInstanceIdentity, BackendPeerBinding, BackendPeerScopeIdentity, CompareAndSet,
    CompareAndSetResult, EncryptingSessionBackend, MAX_RECORD_EXPIRY_PREFLIGHTS,
    MAX_REPLICATION_LOG_PAGE_ENTRIES, MAX_REPLICATION_OPERATION_DEPTH,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_WATCH_BACKLOG_ENTRIES,
    PREPARED_CHECKPOINT_MAX_PHYSICAL_ATTEMPT, PreparedCheckpointBudget,
    PreparedCheckpointBudgetError, PreparedCompareAndSetExecuteError, PreparedCompareAndSetOutcome,
    PreparedCompareAndSetPrepareError, PreparedCompareAndSetRequest, PreparedCompareAndSetStatus,
    PreparedCompareAndSetStatusError, PreparedLeaseAcquireExecuteError,
    PreparedLeaseAcquirePrepareError, PreparedLeaseAcquireRequest, PreparedLeaseAcquireStatusError,
    ProtectedRosterEstablishedSuccessor, ProtectedSelectorLedgerBase, ProtectedSessionBackend,
    REPLICATION_TX_ID_CANONICAL_BYTES, REPLICATION_TX_ID_MAX_BYTES,
    REPLICATION_TX_ID_MIN_BYTES, RecordExpiryPreflight, RemoteSealingSessionBackend,
    ReplicationEntry, ReplicationLogRange, ReplicationOp, ReplicationTxId, ReplicationTxIdError,
    ReplicationWatchCursor, SelectorLedgerStorageScope, SessionBackend, SessionOp, SessionOpResult,
    next_replication_sequence,
    record_expiry_preflights, validate_record_expiry_preflights_at,
    validate_record_expiry_preflights_profile, validate_replication_log_page,
    validate_replication_log_page_owned, validate_replication_page,
    validate_replication_page_owned, validate_replication_prefix,
    validate_replication_prefix_owned, validate_session_ops_at, validate_session_ops_profile,
    validate_session_ops_ttls,
};
pub use capability::{
    AppHaDurabilityRequirement, BackendCapabilities, SessionStateProfile,
    SessionStoreHaCompatibility, SessionStorePlatformProfile, assert_backend_suitable_for_profile,
    assert_suitable_for, evaluate_session_store_ha_compatibility, validate_backend_for_profile,
};
pub use clock::{Clock, MonotonicClock, SystemClock, TokioVirtualClock};
pub use consensus::types::{
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES,
    MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES,
    SESSION_CONSENSUS_V2_APPLIED_DIGEST_ENCODING_VERSION,
    SESSION_CONSENSUS_V2_APPLIED_DIGEST_SCHEMA_DESCRIPTOR,
    SESSION_CONSENSUS_V2_COMMAND_WIRE_SCHEMA_DESCRIPTOR,
};
pub use consensus::{
    ConsensusSessionConsumerService, ConsensusSessionStore, ConsensusSessionStoreOpenError,
    ConsensusStoreDiagnosticSnapshot, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    SESSION_CONSENSUS_SCHEMA_VERSION, SessionConsensusClusterId, SessionConsensusCommand,
    SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusEntryDigest, SessionConsensusIdentity, SessionConsensusIdentityError,
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRequestId, SessionConsensusResponse, SessionConsensusRpc,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusStatus,
    SessionConsensusStorageAnchor, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionMutationIntent, SessionMutationOutcome, SessionTopologyCandidateBootstrap,
    SessionTopologyTransitionPeers, SessionTopologyTransportAdmission,
    SessionTopologyTransportAdmissionError, validate_consensus_physical_fenced_transition_request,
};
pub use consumer::{
    MAX_SESSION_CONSUMER_AUTHORIZATION_GRANT_TUPLES, MAX_SESSION_CONSUMER_AUTHORIZATION_IDENTITIES,
    MAX_SESSION_CONSUMER_AUTHORIZATION_SCOPES_PER_IDENTITY, MAX_SESSION_CONSUMER_BATCH_OPERATIONS,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES, MAX_SESSION_CONSUMER_ROSTER_ADMISSION_CAPSULE_BYTES,
    MAX_SESSION_CONSUMER_ROSTER_ADMISSION_FRAME_BYTES,
    MAX_SESSION_CONSUMER_ROSTER_TERMINAL_CAPSULE_BYTES,
    MAX_SESSION_CONSUMER_ROSTER_TERMINAL_FRAME_BYTES, MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES,
    SESSION_CONSUMER_IDENTITY_MAX_BYTES, SESSION_CONSUMER_REQUEST_ID_BYTES,
    SESSION_CONSUMER_ROSTER_ALPN, SESSION_CONSUMER_ROSTER_TRANSPORT_REVISION,
    SessionConsumerAuthorization, SessionConsumerAuthorizationGrant,
    SessionConsumerAuthorizationGrantError, SessionConsumerAuthorizationManifest,
    SessionConsumerAuthorizationManifestError, SessionConsumerBatchResult, SessionConsumerChange,
    SessionConsumerChangeItem, SessionConsumerChangeKind,
    SessionConsumerCompareAndSetReceiptOutcome, SessionConsumerCompareAndSetRequest,
    SessionConsumerCompareAndSetStatus, SessionConsumerFencedTransitionError,
    SessionConsumerFencedTransitionStatus, SessionConsumerIdentity, SessionConsumerIdentityError,
    SessionConsumerLeaseError, SessionConsumerLeaseMutationOperation,
    SessionConsumerLeaseMutationRequest, SessionConsumerLeaseMutationResult,
    SessionConsumerLeaseMutationStatus, SessionConsumerOperation, SessionConsumerOutcomeUnknown,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerRoster, SessionConsumerRosterAdmissionCapsule,
    SessionConsumerRosterAdmissionMutationResponse, SessionConsumerRosterAdmissionReadResponse,
    SessionConsumerRosterAuthorization, SessionConsumerRosterCapsuleError,
    SessionConsumerRosterCommitment, SessionConsumerRosterCurrentPublicationAuthorityCapsule,
    SessionConsumerRosterCurrentPublicationAuthorityReadResponse, SessionConsumerRosterError,
    SessionConsumerRosterMember, SessionConsumerRosterRejection,
    SessionConsumerRosterTerminalCapsule, SessionConsumerRosterTerminalMutationResponse,
    SessionConsumerRosterTerminalReadResponse, SessionConsumerRosterTransportProfile,
    SessionConsumerScope, SessionConsumerStoreError, SessionConsumerTenantNfScope,
    SessionConsumerV2FencedTransitionError, SessionConsumerV2FencedTransitionStatus,
    SessionConsumerV2Operation, SessionConsumerV2Request, SessionConsumerV2Response,
    SessionConsumerVoterAuthority, SessionQuorumConsumer, SessionQuorumRosterIngress,
    StatelessSessionConsumer, derive_consumer_consensus_request_id, session_consumer_batch_result,
    session_consumer_batch_result_into_store,
};
pub use error::{CapabilityError, LeaseError, StoreError};
pub use fake::FakeSessionBackend;
pub use fenced_mutation_roster::{
    AdmissionProposal as FencedMutationRosterAdmissionProposal,
    CONSUMER_ALPN as FENCED_MUTATION_ROSTER_CONSUMER_ALPN,
    CONSUMER_REVISION as FENCED_MUTATION_ROSTER_CONSUMER_REVISION,
    Error as FencedMutationRosterError,
    EstablishedMutation as FencedMutationRosterEstablishedMutation,
    FRESH_ROSTER_MEMBERS as FENCED_MUTATION_ROSTER_FRESH_MEMBERS,
    MAX_CHECKPOINT_BYTES as FENCED_MUTATION_ROSTER_MAX_CHECKPOINT_BYTES,
    MAX_DESCRIPTOR_BYTES as FENCED_MUTATION_ROSTER_MAX_DESCRIPTOR_BYTES,
    MAX_HISTORY_EPOCH as FENCED_MUTATION_ROSTER_MAX_HISTORY_EPOCH,
    MAX_LIVE_ROSTERS as FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS,
    MAX_MEMBERS as FENCED_MUTATION_ROSTER_MAX_MEMBERS,
    MAX_PLAN_BYTES as FENCED_MUTATION_ROSTER_MAX_PLAN_BYTES,
    MAX_RESERVED_AND_RETAINED as FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
    MAX_RESULT_BYTES as FENCED_MUTATION_ROSTER_MAX_RESULT_BYTES,
    MAX_STATUS_BYTES as FENCED_MUTATION_ROSTER_MAX_STATUS_BYTES,
    MEMBER_OPERATION_ID_BYTES as FENCED_MUTATION_ROSTER_MEMBER_OPERATION_ID_BYTES,
    Member as FencedMutationRosterMember,
    MemberOperationId as FencedMutationRosterMemberOperationId, Phase as FencedMutationRosterPhase,
    Profile as FencedMutationRosterProfile, RECLAIM_BATCH as FENCED_MUTATION_ROSTER_RECLAIM_BATCH,
    ROSTER_ID_BYTES as FENCED_MUTATION_ROSTER_ID_BYTES, RosterAttestationCertificateRoleV1,
    RosterAttestationLeafCertificatePartsV1, RosterAttestationTrustRootIdentityV1,
    RosterAttestationTrustRootV1, RosterId as FencedMutationRosterId,
    RosterIngressAttestationSigningInputV1, RosterIngressAttestationV1,
    SCHEMA_V1 as FENCED_MUTATION_ROSTER_SCHEMA_V1,
    TERMINAL_RETENTION as FENCED_MUTATION_ROSTER_TERMINAL_RETENTION,
    profile_digest as fenced_mutation_roster_profile_digest, roster_executor_evidence_commitment,
    roster_ingress_capsule_commitment,
};
pub use fenced_transition::{
    AtomicFencedTransitionCapability, FENCED_TRANSITION_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_MAX_OUTCOME_BYTES, FENCED_TRANSITION_MAX_PREPARED_BYTES,
    FENCED_TRANSITION_MAX_PREPARED_LAYERS, FENCED_TRANSITION_OUTCOME_RETENTION,
    FENCED_TRANSITION_PREPARED_SCHEMA_V1, FENCED_TRANSITION_REQUEST_ID_BYTES,
    FENCED_TRANSITION_SCHEMA_V1, FENCED_TRANSITION_SCHEMA_V2,
    FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES, FENCED_TRANSITION_V2_CALLER_NONCE_BYTES,
    FENCED_TRANSITION_V2_COMMAND_TRANSPORT_PROFILE_INPUTS,
    FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_DESCRIPTOR,
    FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_REVISION,
    FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION, FENCED_TRANSITION_V2_ERROR_STATUS_REVISION,
    FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH, FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS,
    FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH,
    FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES,
    FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES, FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS,
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES,
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS,
    FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES,
    FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES,
    FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS,
    FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR,
    FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_REVISION,
    FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR,
    FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_MAGIC,
    FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_REVISION,
    FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_SCHEMA_DESCRIPTOR,
    FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES, FENCED_TRANSITION_V2_RECLAIM_BATCH,
    FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_DESCRIPTOR,
    FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_REVISION, FENCED_TRANSITION_V2_REQUEST_ID_BYTES,
    FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
    FENCED_TRANSITION_V2_RETENTION_PROFILE_INPUTS, FENCED_TRANSITION_V2_VALIDATION_PROFILE_INPUTS,
    FENCED_TRANSITION_V2_VALIDATION_SCHEMA_DESCRIPTOR,
    FENCED_TRANSITION_V2_VALIDATION_SCHEMA_REVISION, FencedTransitionExecuteError,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, FencedTransitionV2CallerNonce,
    FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch, FencedTransitionV2HistoryState,
    FencedTransitionV2Request, FencedTransitionV2RequestId, FencedTransitionV2Status,
    PreparedFencedTransition, PreparedFencedTransitionError, PreparedFencedTransitionLookup,
    fenced_transition_v2_profile_digest,
};
pub use fenced_transition_journal::{
    FENCED_TRANSITION_V2_PREPARED_JOURNAL_KEY_BYTES, FencedTransitionV2JournalScope,
    FencedTransitionV2PreparedJournal, FencedTransitionV2PreparedJournalKey,
    PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES, PreparedFencedTransitionJournal,
    PreparedFencedTransitionJournalKey,
};
pub use handover::{
    HANDOVER_ENVELOPE_MAGIC, HANDOVER_ENVELOPE_VERSION, HANDOVER_PHASE_HEADER_MAX_BYTES,
    HandoverEnvelope, HandoverEnvelopeDecodeError, HandoverEnvelopeFormat, HandoverError,
    HandoverManager, HandoverSessionRecord,
};
pub use lease::{LeaseGuard, SessionLeaseManager};
pub use membership::{
    SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT, SessionTopologyAbortAdmissionProof,
    SessionTopologyCandidateRetirementProof, SessionTopologyJointCommitAdmissionProof,
    SessionTopologyLearnersReadyAdmissionProof, SessionTopologyPrePrepareUnstageProof,
    SessionTopologyTransitionDigest, SessionTopologyTransitionError,
    SessionTopologyTransitionEvidence, SessionTopologyTransitionId,
    SessionTopologyTransitionLogIndexes, SessionTopologyTransitionOutcome,
    SessionTopologyTransitionPhase, SessionTopologyTransitionReason,
    SessionTopologyTransitionRequest, SessionTopologyTransitionStatus,
    SessionTopologyUniformCommitAdmissionProof,
};
pub use model::{
    CustomSessionKeyType, FenceToken, Generation, HandoverPhase, HandoverTxId, OWNER_ID_MAX_BYTES,
    OwnerId, SESSION_KEY_TYPE_MAX_BYTES, STABLE_ID_CANONICAL_SUBJECT_MAX_BYTES,
    STABLE_ID_HMAC_SHA256_BYTES, STABLE_ID_MAX_BYTES, STABLE_ID_MIN_BYTES,
    STABLE_ID_PRIVACY_KEY_MAX_BYTES, STABLE_ID_PRIVACY_KEY_MIN_BYTES, STATE_TYPE_MAX_BYTES,
    SessionKey, SessionKeyType, StableId, StableIdError, StateClass, StateType,
};
pub use owned_session::{OwnedSession, OwnedSessionMutationContext, OwnedSessionMutationError};
pub use ownership::{
    FencedOwnershipCache, FencedOwnershipCacheConfig, FencedOwnershipCacheLookup,
    FencedOwnershipCacheMetricsSnapshot, FencedOwnershipCacheReplayHead, FencedOwnershipCacheSeed,
    FencedOwnershipCapabilities, FencedOwnershipError, FencedOwnershipGeneration,
    FencedOwnershipKey, FencedOwnershipMetadata, FencedOwnershipMutation,
    FencedOwnershipMutationId, FencedOwnershipNamespace, FencedOwnershipRecord,
    FencedOwnershipStore, FencedOwnershipToken, FencedOwnershipWatchExit,
    OWNERSHIP_CACHE_MAX_ENTRIES, OWNERSHIP_CACHE_MAX_RETAINED_BYTES, OWNERSHIP_KEY_MAX_BYTES,
    OWNERSHIP_METADATA_MAX_BYTES,
};
pub use payload_codec::{
    SESSION_PAYLOAD_JSON_CONTENT_TYPE, SessionPayloadCodecError, SessionPayloadEnvelope,
    SessionPayloadFormat, SessionPayloadVersion, decode_json_payload,
    decode_session_payload_envelope, encode_json_payload, encode_session_payload_envelope,
    validate_session_payload_size, validate_session_payload_size_for_backend,
};
pub use quorum::{QuorumSessionStore, SessionStoreBackend};
pub use readiness::{
    DurableReadinessReport, DurableReadinessScope, DurableReadinessState, DurableRecoveryProgress,
    DurableRecoveryState, FixedQuorumReadinessReport, FixedQuorumTrafficAuthority,
    PlacementResilienceDisposition, PlacementResiliencePolicy, PlacementResilienceReport,
    ReplicaReadinessFailure, ReplicaReadinessObservation, ReplicaReadinessOutcome,
};
pub use record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord};
pub use recovery::{
    LegacyForkRecovery, RecoveryAction, RecoveryAlarm, RecoveryAuthorizationDenied,
    RecoveryAuthorizationScope, RecoveryAuthorizer, RecoveryConfirmation, RecoveryContext,
    RecoveryDecisionBasis, RecoveryDigest, RecoveryError, RecoveryExecutionReport,
    RecoveryExecutionState, RecoveryIntegrityKey, RecoveryLimits, RecoveryObserver, RecoveryPlan,
    RecoveryReplica, RecoveryReplicaEvidence, RecoveryReplicaFormat, RecoverySignal,
};
pub use restore::{
    OwnerFenceMetadata, RESTORE_SCAN_DEFAULT_PAGE_SIZE, RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES,
    RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE, RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
    RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES, RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
    RESTORE_SCAN_MAX_PAGE_SIZE, RESTORE_SCAN_MAX_SQLITE_VM_STEPS,
    RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS, RestoreBlockReason, RestoreBlockReasonCode,
    RestoreRecordSummary, RestoreScanCursor, RestoreScanCursorProfile, RestoreScanPage,
    RestoreScanRequest, RestoreScanScope, RestoreStage, StoredRecordHeaderSummary,
    summarize_restore_records,
};
pub use sqlite::SqliteSessionBackend;
#[cfg(feature = "test-vfs")]
#[doc(hidden)]
pub use sqlite::{
    ProactiveCheckpointIdleWaitForTest, ProactiveCheckpointShutdownJoinForTest,
    ProactiveCheckpointWorkerObservationForTest,
};
pub use store::SessionStore;
pub use topology::{
    QUORUM_TOPOLOGY_MAX_MEMBERS, QuorumReplicaDescriptor, QuorumTopologyConfig,
    QuorumTopologyError, QuorumTopologyMode, QuorumTopologySummary, REPLICA_ID_MAX_BYTES,
    REPLICA_IDENTITY_MAX_BYTES, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, ReplicaTopologyField, ReplicaTopologyFieldError,
    ValidatedQuorumTopology, derive_fixed_durable_quorum_consensus_identity,
};
pub use topology_attestation::{
    ObservedPhysicalNodeIdentity, QuorumTopologyAttestor, TOPOLOGY_ATTESTATION_MAX_PROOF_BYTES,
    TOPOLOGY_ATTESTATION_MAX_TRUSTED_COLLECTORS, TOPOLOGY_ATTESTATION_MAX_VALIDITY,
    TopologyAttestationBuildError, TopologyAttestationClaims, TopologyAttestationEvidence,
    TopologyAttestationFreshness, TopologyAttestationPolicy, TopologyAttestationProvenance,
    TopologyAttestationResult, TopologyAttestationSummary, TopologyAttestationTime,
    TopologyAttestationVerificationError, TopologyAttestationVerificationInput,
    TopologyCollectorId, VerifiedQuorumTopologyAttestation,
};
pub use ttl::{
    MAX_RECORD_EXPIRY_CLOCK_SKEW, MAX_SESSION_TTL, checked_session_deadline,
    validate_record_expiry_at, validate_record_expiry_profile, validate_session_ttl,
    validate_stored_record_expiry_at, validate_stored_record_expiry_profile,
};
