#![deny(missing_docs)]
//! Atomic snapshot publication and bounded config-change fanout.
//!
//! `ConfigBus` owns a single logical commit worker, publishes immutable running
//! snapshots, and isolates slow subscribers with bounded queues.

#![forbid(unsafe_code)]

pub mod alarms;
pub mod authorizer;
pub mod commit;
pub mod datastore;
pub mod metrics;
pub mod restore;
pub mod rollback;
pub mod subscribers;
pub mod types;

// Public Re-exports
pub use authorizer::{
    AllowAllAuthorizer, AuthorizationContext, AuthorizationError, ConfigAuthorizer,
};
pub use commit::ConfigBus;
pub use datastore::{EncryptingManagedDatastore, ManagedDatastore, MockManagedDatastore};
pub use subscribers::{ConfigReceiver, SubscriberLagPolicy};
pub use types::{
    AtomicConfigSnapshot, AuthorityMode, ConfigChange, ConfigEvent, ConfigSnapshot, DriftState,
    PublishedSnapshot, SealedConfig, StoreError, StoreErrorCode, StoredConfig,
    StoredRequestFingerprint, StoredRequestMode,
};
