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
use super::types::{
    AuditRecord, CommitRecord, ConfirmedCommitResolution, RollbackTarget, StoredConfig,
};
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

    fn append_write(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        resolution: Option<ConfirmedCommitResolution>,
    ) -> Result<(), PersistError> {
        if !super::types::config_principal_metadata_is_valid(&record.principal) {
            return Err(PersistError::constraint_violation(
                "config principal metadata is invalid",
            ));
        }
        let tx_id_bytes = record.tx_id.as_uuid().as_bytes().to_vec();
        let mut latest = self
            .latest_tx_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut commits = self
            .commits
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut confirmed = self
            .confirmed_tx_ids
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if commits.contains_key(&tx_id_bytes)
            || commits
                .values()
                .any(|stored| stored.record.version == record.version)
        {
            return Err(PersistError::constraint_violation(
                "duplicate config transaction or version",
            ));
        }
        if let Some(digest) = super::types::config_replay_lookup_digest(&record.principal)? {
            for stored in commits.values() {
                if super::types::config_replay_lookup_digest(&stored.record.principal)?.as_deref()
                    == Some(digest.as_str())
                {
                    return Err(PersistError::constraint_violation(
                        "config replay lookup digest is not unique",
                    ));
                }
            }
        }
        if let Some(label) = super::types::config_rollback_label(&record.principal)? {
            if !record.rollback_point {
                return Err(PersistError::constraint_violation(
                    "named rollback commit is not marked as a rollback point",
                ));
            }
            for stored in commits.values() {
                if super::types::config_rollback_label(&stored.record.principal)?.as_deref()
                    == Some(label.as_str())
                {
                    return Err(PersistError::constraint_violation(
                        "rollback label is not unique",
                    ));
                }
            }
        }
        let current = latest.as_ref().and_then(|key| commits.get(key));
        match (current, record.parent_tx_id) {
            (None, None) => {}
            (Some(current), Some(parent_tx_id))
                if current.record.tx_id == parent_tx_id
                    && current
                        .record
                        .version
                        .get()
                        .checked_add(1)
                        .is_some_and(|next| next == record.version.get()) => {}
            _ => {
                return Err(PersistError::constraint_violation(
                    "config commit parent is not the applied head",
                ));
            }
        }
        if let Some(current) = current {
            if super::types::config_recovery_required(&current.record.principal)? {
                return Err(PersistError::constraint_violation(
                    "config publication fence must clear before another append",
                ));
            }
        }
        let current_key = latest.clone();
        let current_is_pending = current_key.as_ref().is_some_and(|key| {
            commits
                .get(key)
                .is_some_and(|stored| stored.record.confirmed_deadline.is_some())
                && !confirmed.contains(key)
        });
        match (current_is_pending, resolution) {
            (false, None) => {}
            (true, Some(resolution))
                if record.parent_tx_id == Some(resolution.pending_tx_id())
                    && record.confirmed_deadline.is_none() =>
            {
                if matches!(resolution, ConfirmedCommitResolution::Confirm { .. }) {
                    let current_key = current_key.ok_or_else(|| {
                        PersistError::constraint_violation("pending config head is missing")
                    })?;
                    let current = commits.get_mut(&current_key).ok_or_else(|| {
                        PersistError::constraint_violation("pending config head is missing")
                    })?;
                    current.record.confirmed_deadline = None;
                    confirmed.insert(current_key);
                }
            }
            _ => {
                return Err(PersistError::constraint_violation(
                    "pending commit requires one atomic current-parent decision",
                ));
            }
        }
        commits.insert(tx_id_bytes.clone(), StoredConfig { record, audit });
        *latest = Some(tx_id_bytes);
        Ok(())
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

    async fn load_committed_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        let commits = self
            .commits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut records = commits.values().collect::<Vec<_>>();
        records.sort_by_key(|stored| stored.record.version);
        let mut visible = None;
        for stored in records {
            if super::types::config_recovery_required(&stored.record.principal)? {
                break;
            }
            visible = Some(stored.clone());
        }
        Ok(visible)
    }

    async fn load_since(
        &self,
        version: opc_types::ConfigVersion,
        limit: usize,
    ) -> Result<Vec<StoredConfig>, PersistError> {
        if limit > crate::CONFIG_HISTORY_PAGE_MAX_ENTRIES {
            return Err(PersistError::constraint_violation(
                "config history page exceeds the contract bound",
            ));
        }
        let commits = self
            .commits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut records = commits.values().collect::<Vec<_>>();
        records.sort_by_key(|stored| stored.record.version);
        let mut visible = Vec::with_capacity(limit);
        for stored in records {
            if super::types::config_recovery_required(&stored.record.principal)? {
                break;
            }
            if stored.record.version > version && visible.len() < limit {
                visible.push(stored.clone());
            }
        }
        Ok(visible)
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        let latest = self.latest_tx_id.read().unwrap();
        let commits = self.commits.read().unwrap();
        let confirmed = self.confirmed_tx_ids.read().unwrap();
        let config = match target {
            RollbackTarget::ByTxId(tx_id) => {
                commits.get(tx_id.as_uuid().as_bytes().as_slice()).cloned()
            }
            RollbackTarget::ByVersion(version) => commits
                .values()
                .find(|stored| stored.record.version == version)
                .cloned(),
            RollbackTarget::ByLabel(label) => {
                let mut matched = None;
                for stored in commits.values() {
                    if super::types::config_rollback_label(&stored.record.principal)?.as_deref()
                        == Some(label.as_str())
                    {
                        if matched.is_some() {
                            return Err(PersistError::inconsistent_state(
                                "rollback label is not unique",
                            ));
                        }
                        matched = Some(stored.clone());
                    }
                }
                matched
            }
            RollbackTarget::Previous => {
                let latest_version = latest
                    .as_ref()
                    .and_then(|key| commits.get(key))
                    .map(|stored| stored.record.version);
                commits
                    .values()
                    .filter(|stored| Some(stored.record.version) < latest_version)
                    .filter(|stored| {
                        stored.record.confirmed_deadline.is_none()
                            || confirmed
                                .contains(stored.record.tx_id.as_uuid().as_bytes().as_slice())
                    })
                    .max_by_key(|stored| stored.record.version)
                    .cloned()
            }
        }
        .ok_or_else(PersistError::rollback_not_found)?;

        // Reject if target is a pending commit
        if config.record.confirmed_deadline.is_some()
            && !confirmed.contains(config.record.tx_id.as_uuid().as_bytes().as_slice())
        {
            return Err(PersistError::rollback_not_found());
        }

        Ok(config)
    }

    async fn load_by_replay_lookup_digest(
        &self,
        digest: &str,
    ) -> Result<Option<StoredConfig>, PersistError> {
        super::types::validate_replay_lookup_digest(digest)?;
        let commits = self
            .commits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut found = None;
        for stored in commits.values() {
            if super::types::config_replay_lookup_digest(&stored.record.principal)?.as_deref()
                == Some(digest)
            {
                if found.is_some() {
                    return Err(PersistError::inconsistent_state(
                        "config replay lookup digest is not unique",
                    ));
                }
                found = Some(stored.clone());
            }
        }
        Ok(found)
    }

    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        self.append_write(record, audit, None)
    }

    async fn append_commit_resolving(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        resolution: ConfirmedCommitResolution,
    ) -> Result<(), PersistError> {
        self.append_write(record, audit, Some(resolution))
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        let key = tx_id.as_uuid().as_bytes().to_vec();
        let latest = self
            .latest_tx_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if latest.as_ref() != Some(&key) {
            return Err(PersistError::rollback_not_found());
        }
        let mut commits = self
            .commits
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stored = commits
            .get_mut(&key)
            .ok_or_else(PersistError::rollback_not_found)?;
        if let Some(encoded) =
            super::types::clear_config_recovery_required(&stored.record.principal)?
        {
            stored.record.principal = encoded;
        }
        Ok(())
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        let key = tx_id.as_uuid().as_bytes().to_vec();
        let latest = self
            .latest_tx_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if latest.as_ref() != Some(&key) {
            return Err(PersistError::rollback_not_found());
        }
        {
            let mut commits = self
                .commits
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stored = commits
                .get_mut(&key)
                .ok_or_else(PersistError::rollback_not_found)?;
            if stored.record.confirmed_deadline.is_none() {
                return Err(PersistError::rollback_not_found());
            }
            stored.record.confirmed_deadline = None;
        }
        let mut confirmed = self
            .confirmed_tx_ids
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    async fn load_since(
        &self,
        _version: opc_types::ConfigVersion,
        _limit: usize,
    ) -> Result<Vec<StoredConfig>, PersistError> {
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
    /// Failure while durably clearing a committed record's recovery marker.
    ClearRecoveryRequiredFailure,
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

    async fn load_committed_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        self.inner.load_committed_latest().await
    }

    async fn load_since(
        &self,
        version: opc_types::ConfigVersion,
        limit: usize,
    ) -> Result<Vec<StoredConfig>, PersistError> {
        self.inner.load_since(version, limit).await
    }

    async fn wait_for_committed_change(
        &self,
        version: opc_types::ConfigVersion,
    ) -> Result<(), PersistError> {
        self.inner.wait_for_committed_change(version).await
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

    async fn load_by_replay_lookup_digest(
        &self,
        digest: &str,
    ) -> Result<Option<StoredConfig>, PersistError> {
        self.inner.load_by_replay_lookup_digest(digest).await
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

    async fn append_commit_resolving(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        resolution: ConfirmedCommitResolution,
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
                "fsync failed: path=/var/lib/opc/tenant-a/secret-key.db, error=broken pipe key=config-key-2026-secret",
            ));
        }
        if self.is_fault_enabled(FaultType::PartialAuditWrite) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: partial write occurred on audit table: path=/var/lib/opc/tenant-a/secret-key.db key=config-key-2026-secret",
            ));
        }
        if self.is_fault_enabled(FaultType::MarkConfirmedFailure)
            && matches!(resolution, ConfirmedCommitResolution::Confirm { .. })
        {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: failed to atomically confirm the pending commit",
            ));
        }

        self.inner
            .append_commit_resolving(record, audit, resolution)
            .await
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        if self.is_fault_enabled(FaultType::ClearRecoveryRequiredFailure) {
            opc_redaction::metrics::METRICS
                .persist_error
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(PersistError::sqlite(
                "SQLite error: failed to clear the config recovery marker",
            ));
        }
        self.inner.clear_recovery_required(tx_id).await
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
