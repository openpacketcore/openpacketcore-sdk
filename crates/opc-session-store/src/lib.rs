#![deny(missing_docs)]
//! High-performance session store substrate for OpenPacketCore (RFC 004).
//!
//! This crate provides the core abstractions for storing, leasing, and mutating
//! per-session network-function state with strict fencing correctness. Its
//! stale-owner protections are intended for 5G CNF session-state boundaries;
//! production suitability remains specific to the selected backend profile.
//!
//! # Module map
//!
//! | Module | Responsibility |
//! | :--- | :--- |
//! | [`model`] | Keys, record headers, generations, state classes |
//! | [`capability`] | Backend capability declarations |
//! | [`backend`] | Storage API trait, CAS, batch operations |
//! | [`lease`] | Lease manager and fencing rules |
//! | [`record`] | Stored record format and encrypted payloads |
//! | [`topology`] | Validated quorum membership and replica identity |
//! | [`readiness`] | Fresh, bounded durable-quorum readiness evidence |
//! | [`recovery`] | Authorized offline legacy-fork inspection and recovery |
//! | [`fake`] | In-memory backend and lease manager for tests |
//! | [`error`] | `StoreError` and `LeaseError` |

#![forbid(unsafe_code)]

pub use opc_types::Timestamp;

pub mod backend;
pub mod capability;
pub mod clock;
pub mod consensus;
pub mod error;
pub mod fake;
pub mod handover;
mod hex;
pub mod lease;
pub mod model;
pub mod owned_session;
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
pub mod ttl;

pub use backend::{
    next_replication_sequence, record_expiry_preflights, validate_record_expiry_preflights_at,
    validate_record_expiry_preflights_profile, validate_replication_log_page,
    validate_replication_log_page_owned, validate_replication_page,
    validate_replication_page_owned, validate_replication_prefix,
    validate_replication_prefix_owned, validate_session_ops_at, validate_session_ops_profile,
    validate_session_ops_ttls, BackendInstanceIdentity, BackendPeerBinding,
    BackendPeerScopeIdentity, CompareAndSet, CompareAndSetResult, EncryptingSessionBackend,
    RecordExpiryPreflight, RemoteSealingSessionBackend, ReplicationEntry, ReplicationLogRange,
    ReplicationOp, ReplicationTxId, ReplicationTxIdError, ReplicationWatchCursor, SessionBackend,
    SessionOp, SessionOpResult, MAX_RECORD_EXPIRY_PREFLIGHTS, MAX_REPLICATION_LOG_PAGE_ENTRIES,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
    MAX_REPLICATION_WATCH_BACKLOG_ENTRIES, REPLICATION_TX_ID_CANONICAL_BYTES,
    REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
};
pub use capability::{
    assert_backend_suitable_for_profile, assert_suitable_for,
    evaluate_session_store_ha_compatibility, validate_backend_for_profile,
    AppHaDurabilityRequirement, BackendCapabilities, SessionStateProfile,
    SessionStoreHaCompatibility, SessionStorePlatformProfile,
};
pub use clock::{Clock, MonotonicClock, SystemClock, TokioVirtualClock};
pub use consensus::{
    ConsensusSessionStore, ConsensusSessionStoreOpenError, SessionConsensusClusterId,
    SessionConsensusCommand, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusEntryDigest, SessionConsensusIdentity, SessionConsensusIdentityError,
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRequestId, SessionConsensusResponse, SessionConsensusRpc,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusStatus,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionMutationIntent,
    SessionMutationOutcome, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    SESSION_CONSENSUS_SCHEMA_VERSION,
};
pub use error::{CapabilityError, LeaseError, StoreError};
pub use fake::FakeSessionBackend;
pub use handover::{
    HandoverEnvelope, HandoverEnvelopeDecodeError, HandoverEnvelopeFormat, HandoverError,
    HandoverManager, HandoverSessionRecord, HANDOVER_ENVELOPE_MAGIC, HANDOVER_ENVELOPE_VERSION,
    HANDOVER_PHASE_HEADER_MAX_BYTES,
};
pub use lease::{LeaseGuard, SessionLeaseManager};
pub use model::{
    CustomSessionKeyType, FenceToken, Generation, HandoverPhase, HandoverTxId, OwnerId, SessionKey,
    SessionKeyType, StableId, StableIdError, StateClass, StateType, OWNER_ID_MAX_BYTES,
    SESSION_KEY_TYPE_MAX_BYTES, STABLE_ID_CANONICAL_SUBJECT_MAX_BYTES, STABLE_ID_HMAC_SHA256_BYTES,
    STABLE_ID_MAX_BYTES, STABLE_ID_MIN_BYTES, STABLE_ID_PRIVACY_KEY_MAX_BYTES,
    STABLE_ID_PRIVACY_KEY_MIN_BYTES, STATE_TYPE_MAX_BYTES,
};
pub use owned_session::{OwnedSession, OwnedSessionMutationContext, OwnedSessionMutationError};
pub use payload_codec::{
    decode_json_payload, decode_session_payload_envelope, encode_json_payload,
    encode_session_payload_envelope, validate_session_payload_size,
    validate_session_payload_size_for_backend, SessionPayloadCodecError, SessionPayloadEnvelope,
    SessionPayloadFormat, SessionPayloadVersion, SESSION_PAYLOAD_JSON_CONTENT_TYPE,
};
pub use quorum::{QuorumSessionStore, SessionStoreBackend};
pub use readiness::{
    DurableReadinessReport, DurableReadinessState, DurableRecoveryProgress, DurableRecoveryState,
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
    RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE, RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES,
    RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES, RESTORE_SCAN_MAX_PAGE_SIZE,
    RESTORE_SCAN_MAX_SQLITE_VM_STEPS, RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS,
};
pub use sqlite::SqliteSessionBackend;
pub use store::SessionStore;
pub use topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, QuorumTopologyError, QuorumTopologyMode,
    QuorumTopologySummary, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, ReplicaTopologyField, ReplicaTopologyFieldError,
    ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS, REPLICA_IDENTITY_MAX_BYTES,
    REPLICA_ID_MAX_BYTES,
};
pub use ttl::{
    checked_session_deadline, validate_record_expiry_at, validate_record_expiry_profile,
    validate_session_ttl, validate_stored_record_expiry_at, validate_stored_record_expiry_profile,
    MAX_RECORD_EXPIRY_CLOCK_SKEW, MAX_SESSION_TTL,
};
