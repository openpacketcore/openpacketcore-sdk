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
    next_replication_sequence, record_expiry_preflights, validate_record_expiry_preflights_at,
    validate_record_expiry_preflights_profile, validate_replication_log_page,
    validate_replication_log_page_owned, validate_replication_page,
    validate_replication_page_owned, validate_replication_prefix,
    validate_replication_prefix_owned, validate_session_ops_at, validate_session_ops_profile,
    validate_session_ops_ttls, BackendInstanceIdentity, BackendPeerBinding,
    BackendPeerScopeIdentity, CompareAndSet, CompareAndSetResult, EncryptingSessionBackend,
    PreparedCheckpointBudget, PreparedCheckpointBudgetError, PreparedCompareAndSetExecuteError,
    PreparedCompareAndSetOutcome, PreparedCompareAndSetPrepareError, PreparedCompareAndSetRequest,
    PreparedCompareAndSetStatus, PreparedCompareAndSetStatusError,
    PreparedLeaseAcquireExecuteError, PreparedLeaseAcquirePrepareError,
    PreparedLeaseAcquireRequest, PreparedLeaseAcquireStatusError, ProtectedSelectorLedgerBase,
    ProtectedSessionBackend, RecordExpiryPreflight, RemoteSealingSessionBackend, ReplicationEntry,
    ReplicationLogRange, ReplicationOp, ReplicationTxId, ReplicationTxIdError,
    ReplicationWatchCursor, SelectorLedgerStorageScope, SessionBackend, SessionOp, SessionOpResult,
    MAX_RECORD_EXPIRY_PREFLIGHTS, MAX_REPLICATION_LOG_PAGE_ENTRIES,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
    MAX_REPLICATION_WATCH_BACKLOG_ENTRIES, PREPARED_CHECKPOINT_MAX_PHYSICAL_ATTEMPT,
    REPLICATION_TX_ID_CANONICAL_BYTES, REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
};
pub use capability::{
    assert_backend_suitable_for_profile, assert_suitable_for,
    evaluate_session_store_ha_compatibility, validate_backend_for_profile,
    AppHaDurabilityRequirement, BackendCapabilities, SessionStateProfile,
    SessionStoreHaCompatibility, SessionStorePlatformProfile,
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
    validate_consensus_physical_fenced_transition_request, ConsensusSessionConsumerService,
    ConsensusSessionStore, ConsensusSessionStoreOpenError, ConsensusStoreDiagnosticSnapshot,
    SessionConsensusClusterId, SessionConsensusCommand, SessionConsensusConfigurationEpoch,
    SessionConsensusConfigurationId, SessionConsensusEntryDigest, SessionConsensusIdentity,
    SessionConsensusIdentityError, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRequestId, SessionConsensusResponse,
    SessionConsensusRpc, SessionConsensusRpcFamily, SessionConsensusRpcHandler,
    SessionConsensusStatus, SessionConsensusStorageAnchor, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SessionMutationIntent, SessionMutationOutcome,
    SessionTopologyCandidateBootstrap, SessionTopologyTransitionPeers,
    SessionTopologyTransportAdmission, SessionTopologyTransportAdmissionError,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES,
    SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES, SESSION_CONSENSUS_SCHEMA_VERSION,
};
pub use consumer::{
    derive_consumer_consensus_request_id, session_consumer_batch_result,
    session_consumer_batch_result_into_store, SessionConsumerAuthorization,
    SessionConsumerAuthorizationGrant, SessionConsumerAuthorizationGrantError,
    SessionConsumerAuthorizationManifest, SessionConsumerAuthorizationManifestError,
    SessionConsumerBatchResult, SessionConsumerChange, SessionConsumerChangeItem,
    SessionConsumerChangeKind, SessionConsumerCompareAndSetReceiptOutcome,
    SessionConsumerCompareAndSetRequest, SessionConsumerCompareAndSetStatus,
    SessionConsumerFencedTransitionError, SessionConsumerFencedTransitionStatus,
    SessionConsumerIdentity, SessionConsumerIdentityError, SessionConsumerLeaseError,
    SessionConsumerLeaseMutationOperation, SessionConsumerLeaseMutationRequest,
    SessionConsumerLeaseMutationResult, SessionConsumerLeaseMutationStatus,
    SessionConsumerOperation, SessionConsumerOutcomeUnknown, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerRoster, SessionConsumerRosterCommitment, SessionConsumerRosterError,
    SessionConsumerRosterMember, SessionConsumerScope, SessionConsumerStoreError,
    SessionConsumerTenantNfScope, SessionConsumerV2FencedTransitionError,
    SessionConsumerV2FencedTransitionStatus, SessionConsumerV2Operation, SessionConsumerV2Request,
    SessionConsumerV2Response, SessionConsumerVoterAuthority, SessionQuorumConsumer,
    StatelessSessionConsumer, MAX_SESSION_CONSUMER_AUTHORIZATION_GRANT_TUPLES,
    MAX_SESSION_CONSUMER_AUTHORIZATION_IDENTITIES,
    MAX_SESSION_CONSUMER_AUTHORIZATION_SCOPES_PER_IDENTITY, MAX_SESSION_CONSUMER_BATCH_OPERATIONS,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES, MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES,
    SESSION_CONSUMER_IDENTITY_MAX_BYTES, SESSION_CONSUMER_REQUEST_ID_BYTES,
};
pub use error::{CapabilityError, LeaseError, StoreError};
pub use fake::FakeSessionBackend;
pub use fenced_transition::{
    fenced_transition_v2_profile_digest, AtomicFencedTransitionCapability,
    FencedTransitionExecuteError, FencedTransitionLease, FencedTransitionMutation,
    FencedTransitionMutationResult, FencedTransitionObservation, FencedTransitionOutcome,
    FencedTransitionRequest, FencedTransitionRequestId, FencedTransitionStatus,
    FencedTransitionV2CallerNonce, FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2HistoryState, FencedTransitionV2Request, FencedTransitionV2RequestId,
    FencedTransitionV2Status, PreparedFencedTransition, PreparedFencedTransitionError,
    PreparedFencedTransitionLookup, FENCED_TRANSITION_MAX_HISTORY_ENTRIES,
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
    FENCED_TRANSITION_V2_VALIDATION_SCHEMA_REVISION,
};
pub use fenced_transition_journal::{
    FencedTransitionV2JournalScope, FencedTransitionV2PreparedJournal,
    FencedTransitionV2PreparedJournalKey, PreparedFencedTransitionJournal,
    PreparedFencedTransitionJournalKey, FENCED_TRANSITION_V2_PREPARED_JOURNAL_KEY_BYTES,
    PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES,
};
pub use handover::{
    HandoverEnvelope, HandoverEnvelopeDecodeError, HandoverEnvelopeFormat, HandoverError,
    HandoverManager, HandoverSessionRecord, HANDOVER_ENVELOPE_MAGIC, HANDOVER_ENVELOPE_VERSION,
    HANDOVER_PHASE_HEADER_MAX_BYTES,
};
pub use lease::{LeaseGuard, SessionLeaseManager};
pub use membership::{
    SessionTopologyAbortAdmissionProof, SessionTopologyCandidateRetirementProof,
    SessionTopologyJointCommitAdmissionProof, SessionTopologyLearnersReadyAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionDigest,
    SessionTopologyTransitionError, SessionTopologyTransitionEvidence, SessionTopologyTransitionId,
    SessionTopologyTransitionLogIndexes, SessionTopologyTransitionOutcome,
    SessionTopologyTransitionPhase, SessionTopologyTransitionReason,
    SessionTopologyTransitionRequest, SessionTopologyTransitionStatus,
    SessionTopologyUniformCommitAdmissionProof, SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT,
};
pub use model::{
    CustomSessionKeyType, FenceToken, Generation, HandoverPhase, HandoverTxId, OwnerId, SessionKey,
    SessionKeyType, StableId, StableIdError, StateClass, StateType, OWNER_ID_MAX_BYTES,
    SESSION_KEY_TYPE_MAX_BYTES, STABLE_ID_CANONICAL_SUBJECT_MAX_BYTES, STABLE_ID_HMAC_SHA256_BYTES,
    STABLE_ID_MAX_BYTES, STABLE_ID_MIN_BYTES, STABLE_ID_PRIVACY_KEY_MAX_BYTES,
    STABLE_ID_PRIVACY_KEY_MIN_BYTES, STATE_TYPE_MAX_BYTES,
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
    decode_json_payload, decode_session_payload_envelope, encode_json_payload,
    encode_session_payload_envelope, validate_session_payload_size,
    validate_session_payload_size_for_backend, SessionPayloadCodecError, SessionPayloadEnvelope,
    SessionPayloadFormat, SessionPayloadVersion, SESSION_PAYLOAD_JSON_CONTENT_TYPE,
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
    summarize_restore_records, OwnerFenceMetadata, RestoreBlockReason, RestoreBlockReasonCode,
    RestoreRecordSummary, RestoreScanCursor, RestoreScanCursorProfile, RestoreScanPage,
    RestoreScanRequest, RestoreScanScope, RestoreStage, StoredRecordHeaderSummary,
    RESTORE_SCAN_DEFAULT_PAGE_SIZE, RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES,
    RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE, RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
    RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES, RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
    RESTORE_SCAN_MAX_PAGE_SIZE, RESTORE_SCAN_MAX_SQLITE_VM_STEPS,
    RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS,
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
    derive_fixed_durable_quorum_consensus_identity, QuorumReplicaDescriptor, QuorumTopologyConfig,
    QuorumTopologyError, QuorumTopologyMode, QuorumTopologySummary, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ReplicaTopologyField,
    ReplicaTopologyFieldError, ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
    REPLICA_IDENTITY_MAX_BYTES, REPLICA_ID_MAX_BYTES,
};
pub use topology_attestation::{
    ObservedPhysicalNodeIdentity, QuorumTopologyAttestor, TopologyAttestationBuildError,
    TopologyAttestationClaims, TopologyAttestationEvidence, TopologyAttestationFreshness,
    TopologyAttestationPolicy, TopologyAttestationProvenance, TopologyAttestationResult,
    TopologyAttestationSummary, TopologyAttestationTime, TopologyAttestationVerificationError,
    TopologyAttestationVerificationInput, TopologyCollectorId, VerifiedQuorumTopologyAttestation,
    TOPOLOGY_ATTESTATION_MAX_PROOF_BYTES, TOPOLOGY_ATTESTATION_MAX_TRUSTED_COLLECTORS,
    TOPOLOGY_ATTESTATION_MAX_VALIDITY,
};
pub use ttl::{
    checked_session_deadline, validate_record_expiry_at, validate_record_expiry_profile,
    validate_session_ttl, validate_stored_record_expiry_at, validate_stored_record_expiry_profile,
    MAX_RECORD_EXPIRY_CLOCK_SKEW, MAX_SESSION_TTL,
};
