#![deny(missing_docs)]
//! Atomic snapshot publication and bounded config-change fanout.
//!
//! `ConfigBus` owns a single logical commit worker, publishes immutable running
//! snapshots, and isolates slow subscribers with bounded queues.
//! It also exposes bounded follower-local committed history and an atomic
//! snapshot-plus-tail recovery surface. The committed watch repages durable
//! state after every wake and rejects cursor gaps before config reaches a
//! consumer.
//!
//! Candidate-bearing commit and validate-only requests produce an
//! `opc_config_model::ApplyPlan` after validation and before durable side
//! effects. Existing constructors install the hot default classifier; explicit
//! classifier constructors let products add domain-specific drain, restart, and
//! forbidden-live rules without weakening commit ordering.

#![forbid(unsafe_code)]

pub mod alarms;
pub mod authority;
pub mod authorizer;
pub mod commit;
pub mod committed;
pub mod datastore;
pub mod metrics;
pub mod restore;
pub mod rollback;
pub mod subscribers;
pub mod types;

// Public Re-exports
pub use authority::{
    ConfigAuthorityOperation, ConfigAuthorityOutcome, ConfigAuthorityPort, ConfigLeaderHint,
    ConfigLeaderHintError, ConfigProjectionHead, MAX_CONFIG_LEADER_HINT_BYTES,
};
pub use authorizer::{
    AllowAllAuthorizer, AuthorizationContext, AuthorizationError, ConfigAuthorizer,
};
pub use commit::ConfigBus;
pub use committed::{
    CommittedConfigHistoryEntry, ConfigHistoryPage, ConfigRecovery, ConfigRevisionCursor,
    ConfigRevisionStream, MAX_CONFIG_HISTORY_PAGE_ENTRIES,
};
pub use datastore::{
    CommittedRevisionSource, EncryptingManagedDatastore, InMemoryManagedDatastore,
    ManagedDatastore, MockManagedDatastore,
};
pub use subscribers::{ConfigReceiver, SubscriberDisconnectReason, SubscriberLagPolicy};
pub use types::{
    AtomicConfigSnapshot, AuthorityMode, CommitWrite, CommitWriteReceipt, ConfigChange,
    ConfigEvent, ConfigEventRetainedSizeError, ConfigSnapshot, ConfirmedCommitResolution,
    DriftState, PublishedSnapshot, SealedConfig, StoreError, StoreErrorCode, StoredConfig,
    StoredRequestFingerprint, StoredRequestMode,
};
