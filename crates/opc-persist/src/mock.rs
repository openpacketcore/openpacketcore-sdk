//! Mock [`ConfigStore`] implementations for testing.
//!
//! ## MockConfigStore
//!
//! A thread-safe, in-memory mock suitable for unit tests that verify trait
//! behavior without touching the filesystem. It tracks all calls and allows
//! injecting errors and configuring preflight outcomes.
//!
//! ## UnsafePathMock
//!
//! A specialized mock that always reports preflight as failing because the
//! storage path is unsafe (e.g., NFS). Use this to verify that the management
//! substrate correctly rejects preflight failures via test doubles.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::preflight::PersistCapabilities;
use super::types::{AuditRecord, CommitRecord, RollbackTarget, StoredConfig};
use super::{ConfigStore, PersistError};

/// An in-memory mock ConfigStore for unit tests.
///
/// All state is held in memory and is not durable. The mock is fully
/// thread-safe and supports injecting errors on specific operations.
#[derive(Debug, Clone, Default)]
pub struct MockConfigStore {
    /// Commits stored in memory, keyed by tx_id.
    commits: Arc<RwLock<HashMap<Vec<u8>, StoredConfig>>>,
    /// The tx_id of the latest commit.
    latest_tx_id: Arc<RwLock<Option<Vec<u8>>>>,
    /// Transaction IDs that have been explicitly confirmed.
    confirmed_tx_ids: Arc<RwLock<std::collections::HashSet<Vec<u8>>>>,
    /// Error to inject on the next preflight call (consumed after use).
    preflight_error: Arc<RwLock<Option<PersistError>>>,
    /// PersistCapabilities to return from preflight (defaults to safe).
    preflight_caps: Arc<RwLock<PersistCapabilities>>,
    /// Whether preflight has been called yet.
    preflight_called: Arc<RwLock<bool>>,
}

impl MockConfigStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the preflight result for the next preflight call.
    pub fn set_preflight_result(&self, caps: PersistCapabilities) {
        *self.preflight_caps.write().unwrap() = caps;
    }

    /// Inject a preflight error for the next call.
    pub fn inject_preflight_error(&self, err: PersistError) {
        *self.preflight_error.write().unwrap() = Some(err);
    }

    /// Check whether preflight has been called.
    pub fn preflight_was_called(&self) -> bool {
        *self.preflight_called.read().unwrap()
    }
}

#[async_trait]
impl ConfigStore for MockConfigStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        let guard = self.latest_tx_id.read().unwrap();
        let Some(tx_id_bytes) = &*guard else {
            return Ok(None);
        };
        let commits = self.commits.read().unwrap();
        Ok(commits.get(tx_id_bytes).cloned())
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        let key = match target {
            RollbackTarget::ByTxId(tx_id) => tx_id.as_uuid().as_bytes().to_vec(),
            _ => {
                // For non-txid targets, the mock does not track state — fail gracefully
                return Err(PersistError::rollback_not_found());
            }
        };
        let commits = self.commits.read().unwrap();
        let config = commits
            .get(&key)
            .cloned()
            .ok_or_else(PersistError::rollback_not_found)?;

        // Reject if target is a pending commit
        if config.record.confirmed_deadline.is_some() {
            let confirmed = self.confirmed_tx_ids.read().unwrap();
            if !confirmed.contains(&key) {
                return Err(PersistError::rollback_not_found());
            }
        }

        Ok(config)
    }

    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        let tx_id_bytes = record.tx_id.as_uuid().as_bytes().to_vec();
        let stored = StoredConfig { record, audit };
        {
            let mut commits = self.commits.write().unwrap();
            commits.insert(tx_id_bytes.clone(), stored);
        }
        {
            let mut latest = self.latest_tx_id.write().unwrap();
            *latest = Some(tx_id_bytes);
        }
        Ok(())
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        let key = tx_id.as_uuid().as_bytes().to_vec();
        {
            let mut commits = self.commits.write().unwrap();
            let stored = commits
                .get_mut(&key)
                .ok_or_else(PersistError::rollback_not_found)?;
            stored.record.confirmed_deadline = None;
        }
        let mut confirmed = self.confirmed_tx_ids.write().unwrap();
        confirmed.insert(key);
        Ok(())
    }

    async fn create_rollback_point(
        &self,
        _tx_id: opc_types::TxId,
        _label: Option<String>,
    ) -> Result<(), PersistError> {
        // In the mock, rollback labels are not tracked
        Ok(())
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        *self.preflight_called.write().unwrap() = true;

        if let Some(err) = self.preflight_error.write().unwrap().take() {
            return Err(err);
        }

        Ok(self.preflight_caps.read().unwrap().clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnsafePathMock — preflight always fails
// ─────────────────────────────────────────────────────────────────────────────

/// A mock that always reports preflight failure due to an unsafe storage path.
///
/// Use this to verify that the management substrate correctly rejects preflight
/// failures for unsafe paths (e.g. NFS, insufficient free space, missing fsync).
#[derive(Debug, Clone, Default)]
pub struct UnsafePathMock {
    reason: String,
}

impl UnsafePathMock {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl ConfigStore for UnsafePathMock {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        Err(PersistError::preflight_failed(&self.reason))
    }

    async fn load_rollback(&self, _target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        Err(PersistError::preflight_failed(&self.reason))
    }

    async fn append_commit(
        &self,
        _record: CommitRecord,
        _audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        Err(PersistError::preflight_failed(&self.reason))
    }

    async fn mark_confirmed(&self, _tx_id: opc_types::TxId) -> Result<(), PersistError> {
        Err(PersistError::preflight_failed(&self.reason))
    }

    async fn create_rollback_point(
        &self,
        _tx_id: opc_types::TxId,
        _label: Option<String>,
    ) -> Result<(), PersistError> {
        Err(PersistError::preflight_failed(&self.reason))
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        Err(PersistError::preflight_failed(&self.reason))
    }
}

/// Fault types that can be injected into persistence operations.
///
/// This is only compiled behind the `dangerous-test-hooks` feature. It must not
/// be enabled by production profiles.
#[cfg(feature = "dangerous-test-hooks")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FaultType {
    /// Disk-full or quota-exceeded write failure.
    DiskFull,
    /// Fsync/sync failure or durable flush failure.
    FsyncFailure,
    /// Corrupt SQLite database file.
    CorruptDatabase,
    /// Corrupt WAL or inconsistent WAL-like restart state.
    CorruptWal,
    /// Audit-chain corruption.
    AuditChainCorruption,
    /// Partial audit write.
    PartialAuditWrite,
    /// Failed rollback target load.
    FailedRollbackLoad,
    /// Failure while marking transaction as confirmed.
    MarkConfirmedFailure,
    /// Failure while creating rollback point.
    CreateRollbackPointFailure,
}

/// A wrapper/decorator around any `ConfigStore` that can inject failures.
///
/// This is only compiled behind the `dangerous-test-hooks` feature. It must not
/// be enabled by production profiles.
#[cfg(feature = "dangerous-test-hooks")]
#[derive(Debug, Clone)]
pub struct FaultInjectingStore<S> {
    inner: S,
    active_faults: Arc<std::sync::Mutex<std::collections::HashSet<FaultType>>>,
}

#[cfg(feature = "dangerous-test-hooks")]
impl<S> FaultInjectingStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            active_faults: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    pub fn enable_fault(&self, fault: FaultType) {
        self.active_faults.lock().unwrap().insert(fault);
    }

    pub fn disable_fault(&self, fault: FaultType) {
        self.active_faults.lock().unwrap().remove(&fault);
    }

    pub fn clear_faults(&self) {
        self.active_faults.lock().unwrap().clear();
    }

    pub fn is_fault_enabled(&self, fault: FaultType) -> bool {
        self.active_faults.lock().unwrap().contains(&fault)
    }
}

#[cfg(feature = "dangerous-test-hooks")]
#[async_trait]
impl<S: ConfigStore> ConfigStore for FaultInjectingStore<S> {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        if self.is_fault_enabled(FaultType::CorruptDatabase) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: database disk image is malformed: path=/var/lib/opc/tenant-a/secret-key.db sql=SELECT * FROM config_history WHERE tenant_id='tenant-a-secret'"
            ));
        }
        if self.is_fault_enabled(FaultType::CorruptWal) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::wal_recovery_failed());
        }
        if self.is_fault_enabled(FaultType::AuditChainCorruption) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .persist_audit_chain_verification_failure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::audit_chain_broken());
        }

        let res = self.inner.load_latest().await?;
        if let Some(mut stored) = res {
            if self.is_fault_enabled(FaultType::AuditChainCorruption) {
                opc_redaction::metrics::METRICS
                    .persist_error
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .persist_audit_chain_verification_failure
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if !stored.audit.is_empty() {
                    stored.audit[0].entry_hmac = [0u8; 32];
                }
            }
            Ok(Some(stored))
        } else {
            Ok(None)
        }
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        if self.is_fault_enabled(FaultType::FailedRollbackLoad) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: failed to load rollback record: path=/var/lib/opc/tenant-a/secret-key.db key=config-key-2026-secret"
            ));
        }
        if self.is_fault_enabled(FaultType::CorruptDatabase) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: database disk image is malformed: path=/var/lib/opc/tenant-a/secret-key.db sql=SELECT * FROM config_history WHERE tenant_id='tenant-a-secret'"
            ));
        }
        if self.is_fault_enabled(FaultType::AuditChainCorruption) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .persist_audit_chain_verification_failure
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::audit_chain_broken());
        }

        self.inner.load_rollback(target).await
    }

    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        if self.is_fault_enabled(FaultType::DiskFull) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::out_of_space(0, 1024));
        }
        if self.is_fault_enabled(FaultType::FsyncFailure) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::io(
                "fsync failed: path=/var/lib/opc/tenant-a/secret-key.db, error=broken pipe key=config-key-2026-secret"
            ));
        }
        if self.is_fault_enabled(FaultType::PartialAuditWrite) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: partial write occurred on audit table: path=/var/lib/opc/tenant-a/secret-key.db key=config-key-2026-secret"
            ));
        }

        self.inner.append_commit(record, audit).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        if self.is_fault_enabled(FaultType::MarkConfirmedFailure) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: failed to update confirmed_at: path=/var/lib/opc/tenant-a/secret-key.db key=config-key-2026-secret"
            ));
        }

        self.inner.mark_confirmed(tx_id).await
    }

    async fn create_rollback_point(
        &self,
        tx_id: opc_types::TxId,
        label: Option<String>,
    ) -> Result<(), PersistError> {
        if self.is_fault_enabled(FaultType::CreateRollbackPointFailure) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: failed to insert rollback point: path=/var/lib/opc/tenant-a/secret-key.db key=config-key-2026-secret"
            ));
        }

        self.inner.create_rollback_point(tx_id, label).await
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        self.inner.preflight().await
    }
}
