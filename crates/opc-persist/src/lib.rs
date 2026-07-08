//! ConfigStore trait and SQLite backend for OpenPacketCore management persistence.
//!
//! ## Core Design
//!
//! This crate provides the persistence layer defined in RFC 001. It implements a
//! narrow [`ConfigStore`] trait that backs configuration commits and audit trails
//! with a reference SQLite WAL backend. The backend is suitable for single-replica
//! management-plane state; it is NOT a distributed consensus store.
//!
//! The crate also exposes [`ConsensusConfigStore`], a durable consensus prototype
//! layered over local SQLite replicas. It is a hardening surface for HA work, not
//! yet a carrier-production consensus backend.
//!
//! ## SQLite Backend Profile
//!
//! The reference backend uses:
//! - `PRAGMA journal_mode = WAL` with `PRAGMA synchronous = EXTRA` for durability
//! - `PRAGMA foreign_keys = ON` for referential integrity
//! - Bounded WAL autocheckpoint to prevent unbounded WAL growth
//! - Mandatory preflight checks before accepting writes (storage path safety,
//!   fsync availability, POSIX locking compatibility)
//!
//! ## Preflight
//!
//! Before opening a database for writes, [`SqliteBackend::preflight`] verifies:
//! - The database path is on a persistent volume when durability is required
//! - WAL, SHM, and database files are on the same filesystem (device-id check)
//! - The volume is not a known-unsafe network filesystem
//! - `fsync` is available and not disabled by mount options
//! - Free space exceeds the configured threshold
//!
//! POSIX byte-range locking compatibility is inferred from the filesystem-safety
//! check rather than probed directly: the network filesystems that break SQLite
//! locking are exactly those the safety check rejects.
//!
//! If preflight fails, the backend fails closed — it will not accept writes
//! unless explicitly placed in ephemeral development mode.
//!
//! ## Audit Hash Chain
//!
//! Each audit entry carries an `entry_hmac` that chains to the previous entry:
//!
//! ```text
//! entry_hmac = HMAC(audit_key, tenant || audit_count || sequence || canonical_entry || previous_hash)
//! ```
//!
//! `config_history` stores the expected audit count and terminal entry hash so
//! truncated tails fail closed when stored configuration is loaded. Durable
//! backends require caller-supplied audit key material.
//!
//! ## Usage
//!
//! ```ignore
//! use opc_persist::{AuditKey, ConfigStore, SqliteBackend};
//! use std::path::PathBuf;
//!
//! async {
//!     // Open a backend (production profile):
//!     // let key_bytes = load_32_byte_audit_key_from_kms_or_secret_store();
//!     // let audit_key = AuditKey::new(key_bytes)?;
//!     // let backend = SqliteBackend::open_with_audit_key(
//!     //     "/var/lib/opc/config.db",
//!     //     false,
//!     //     100_000_000,
//!     //     audit_key,
//!     // ).await?;
//!
//!     // Open a backend in ephemeral mode (testing):
//!     let backend = SqliteBackend::open(PathBuf::from("/tmp/test.db"), true, 0).await?;
//!
//!     let caps = backend.preflight().await?;
//!     assert!(caps.is_safe_for_writes());
//!
//!     let stored = backend.load_latest().await?;
//!     // stored is None for a fresh database
//! };
//! ```
//!
//! ## Test Doubles
//!
//! The [`mock::MockConfigStore`] implementation is available in tests to verify
//! preflight rejection of unsafe paths and other trait-bound behavior without
//! touching the filesystem. The storage fault-injection decorator is compiled
//! only with the `dangerous-test-hooks` feature and must not be enabled in
//! production profiles.

#![deny(unsafe_code)]
// The crate is fully safe Rust. Filesystem checks use safe shell-out commands
// (stat, df, python3) rather than libc FFI.

mod backend;
pub mod break_glass;
mod consensus;
mod error;
mod mock;
mod preflight;
mod quorum;
mod schema;
mod security_policy;
mod types;

pub use crate::types::ConfigStore;
pub use backend::SqliteBackend;
pub use break_glass::{
    BreakGlassAlarmNotifier, BreakGlassApprovalTrait, BreakGlassRequest, BreakGlassService,
    BreakGlassSession, BreakGlassStatus, DefaultBreakGlassApproval, NoopBreakGlassAlarmNotifier,
};
pub use consensus::{
    AppendEntriesRequest, AppendEntriesResponse, ClusterMembership, ConsensusClock,
    ConsensusConfigStore, ConsensusMetricsDump, ConsensusOp, ConsensusPeer, InstallSnapshotRequest,
    InstallSnapshotResponse, LogEntry, NodeIdentity, PeerStatusDump, RequestVoteRequest,
    RequestVoteResponse, Role, TcpPeer, TcpRpcServer,
};
pub use error::{PersistError, PersistErrorKind};
#[cfg(feature = "dangerous-test-hooks")]
pub use mock::{FaultInjectingStore, FaultType};
pub use mock::{MockConfigStore, UnsafePathMock};
pub use preflight::PersistCapabilities;
pub use quorum::{FencedReplica, QuorumConfigStore};
#[cfg(any(test, feature = "dangerous-test-hooks"))]
pub use security_policy::TEST_COMMIT_FAIL;
pub use security_policy::{
    ActivePolicyMetadata, PolicyHistoryEntry, SecurityPolicyError, SecurityPolicyService,
    SerializablePolicy, SerializableRule, SerializableRuleList, SqliteSecurityPolicyService,
};
pub use types::{
    extract_tenant, redact_entry, AuditKey, AuditOpType, AuditRecord, CommitRecord, CommitSource,
    RollbackTarget, StoredConfig,
};
