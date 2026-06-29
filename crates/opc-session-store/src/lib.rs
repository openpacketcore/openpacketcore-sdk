#![deny(missing_docs)]
//! High-performance session store substrate for OpenPacketCore (RFC 004).
//!
//! This crate provides the core abstractions for storing, leasing, and mutating
//! per-session network-function state with strict fencing correctness. It is
//! designed for carrier-grade 5G CNFs where stale owners must not overwrite
//! newer session state.
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
//! | [`fake`] | In-memory backend and lease manager for tests |
//! | [`error`] | `StoreError` and `LeaseError` |

#![forbid(unsafe_code)]

pub mod backend;
pub mod capability;
pub mod clock;
pub mod error;
pub mod fake;
pub mod handover;
mod hex;
pub mod lease;
pub mod model;
pub mod owned_session;
pub mod payload_codec;
pub mod quorum;
pub mod record;
pub mod restore;
pub mod sqlite;
pub mod store;

pub use backend::{
    CompareAndSet, CompareAndSetResult, EncryptingSessionBackend, ReplicationEntry, ReplicationOp,
    SessionBackend, SessionOp, SessionOpResult,
};
pub use capability::{
    assert_backend_suitable_for_profile, assert_suitable_for,
    evaluate_session_store_ha_compatibility, validate_backend_for_profile,
    AppHaDurabilityRequirement, BackendCapabilities, SessionStateProfile,
    SessionStoreHaCompatibility, SessionStorePlatformProfile,
};
pub use clock::{Clock, SystemClock, TokioVirtualClock};
pub use error::{CapabilityError, LeaseError, StoreError};
pub use fake::FakeSessionBackend;
pub use handover::{HandoverEnvelope, HandoverError, HandoverManager, HandoverSessionRecord};
pub use lease::{LeaseGuard, SessionLeaseManager};
pub use model::{
    FenceToken, Generation, HandoverPhase, HandoverTxId, OwnerId, SessionKey, SessionKeyType,
    StateClass, StateType,
};
pub use owned_session::{OwnedSession, OwnedSessionMutationContext, OwnedSessionMutationError};
pub use payload_codec::{
    decode_json_payload, decode_session_payload_envelope, encode_json_payload,
    encode_session_payload_envelope, validate_session_payload_size,
    validate_session_payload_size_for_backend, SessionPayloadCodecError, SessionPayloadEnvelope,
    SessionPayloadFormat, SessionPayloadVersion, SESSION_PAYLOAD_JSON_CONTENT_TYPE,
};
pub use quorum::{FencedSessionReplica, QuorumSessionStore, SessionStoreBackend};
pub use record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord};
pub use restore::{
    summarize_restore_records, OwnerFenceMetadata, RestoreBlockReason, RestoreBlockReasonCode,
    RestoreRecordSummary, RestoreScanCursor, RestoreScanPage, RestoreScanRequest, RestoreScanScope,
    RestoreStage, StoredRecordHeaderSummary, RESTORE_SCAN_DEFAULT_PAGE_SIZE,
    RESTORE_SCAN_MAX_PAGE_SIZE,
};
pub use sqlite::SqliteSessionBackend;
pub use store::SessionStore;
