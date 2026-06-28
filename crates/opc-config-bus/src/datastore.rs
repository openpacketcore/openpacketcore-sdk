//! Durable datastore contract for the commit worker, an AEAD-encrypting
//! wrapper that binds records to RFC 001 §9.2 envelope AAD (transaction
//! lineage, principal, tenant, schema digest, store kind), and a non-durable
//! in-memory backend for development, CI, and bootstrap-only runtimes.

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use opc_config_model::{IdempotencyKey, OpcConfig, RollbackTarget};
use opc_crypto::{decrypt_envelope, encrypt_envelope};
use opc_key::{ConfigAad, EnvelopeAad, KeyProvider, Zeroizing};
use opc_types::TxId;

use crate::types::{SealedConfig, StoreError, StoredConfig};

const CONFIG_STORE_KIND: &str = "running";
const CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE: &str = "config envelope serialization failed";
const CONFIG_ENVELOPE_ENCRYPT_FAILED_MESSAGE: &str = "config envelope encryption failed";
const CONFIG_ENVELOPE_DECRYPT_FAILED_MESSAGE: &str = "config envelope decryption failed";
const CONFIG_ENVELOPE_MISSING_BLOB_MESSAGE: &str = "config envelope ciphertext is missing";
const CONFIG_ENVELOPE_AAD_FAILED_MESSAGE: &str = "config envelope AAD construction failed";
const RESTORE_SCHEMA_MISMATCH_MESSAGE: &str = "stored running config schema digest mismatch";

/// Durable backend contract consumed by the commit worker.
///
/// The bus is the single logical writer: implementations may assume calls are
/// not raced by other writers, but every mutation must be atomic and durable
/// before returning `Ok` — a commit the worker reports as persisted must be
/// visible after a crash, and a failed append must leave no partial record.
#[async_trait]
pub trait ManagedDatastore<C: OpcConfig>: Send + Sync {
    /// Loads the highest-version record, or `None` for an empty store (which
    /// makes restore fall back to the caller-supplied bootstrap config).
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError>;
    /// Resolves a rollback selector (previous/version/tx-id/label) to its
    /// stored record. Must return a `NotFound` error for unknown targets and
    /// must refuse records still pending commit-confirmed resolution.
    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig<C>, StoreError>;
    /// Looks up the most recent record bound to a caller retry key so the
    /// worker can replay the original result instead of committing twice;
    /// `Ok(None)` means the key was never used and the commit proceeds.
    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError>;
    /// Durably appends a commit record. Must be all-or-nothing and must
    /// reject duplicate transaction ids and duplicate versions so history
    /// stays a strict sequence. Records arrive with `recovery_required` set;
    /// the worker clears it only after snapshot publication.
    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError>;
    /// Durably clears the commit-fencing marker on `tx_id` after the snapshot
    /// swap. If this fails the bus fences itself, because a restart would
    /// otherwise refuse to republish the record.
    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError>;
    /// Durably clears the commit-confirmed deadline on `tx_id`, making the
    /// tentative commit permanent so it no longer auto-rolls back on expiry
    /// or restart.
    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError>;
}

#[async_trait]
impl<C, T> ManagedDatastore<C> for Arc<T>
where
    C: OpcConfig,
    T: ManagedDatastore<C> + ?Sized,
{
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        (**self).load_latest().await
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig<C>, StoreError> {
        (**self).load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        (**self).load_by_idempotency_key(idempotency_key).await
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        (**self).append_commit(commit).await
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        (**self).clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        (**self).mark_confirmed(tx_id).await
    }
}

/// Managed-datastore wrapper that binds persisted config records to RFC 001
/// AEAD envelopes using `opc-crypto` / `opc-key`.
#[derive(Clone)]
pub struct EncryptingManagedDatastore<C, P: ?Sized, S: ?Sized> {
    inner: Arc<S>,
    provider: Arc<P>,
    store_kind: Arc<str>,
    marker: PhantomData<fn() -> C>,
}

impl<C, P: ?Sized, S: ?Sized> EncryptingManagedDatastore<C, P, S> {
    /// Wraps `inner` so payloads are sealed/opened with keys from `provider`,
    /// using the default `"running"` store kind in the envelope AAD. Records
    /// encrypted under one store kind cannot be decrypted under another.
    pub fn new(inner: Arc<S>, provider: Arc<P>) -> Self {
        Self::with_store_kind(inner, provider, CONFIG_STORE_KIND)
    }

    /// Like `new` but with an explicit store kind (for example
    /// `"shadow-security"`). The kind is bound into the AAD of every
    /// envelope, cryptographically separating stores that share a backend
    /// and key provider.
    pub fn with_store_kind(inner: Arc<S>, provider: Arc<P>, store_kind: impl Into<String>) -> Self {
        Self {
            inner,
            provider,
            store_kind: Arc::<str>::from(store_kind.into()),
            marker: PhantomData,
        }
    }

    /// Returns the wrapped backend, which only ever observes sealed records:
    /// schema digest and commit metadata in the clear, payload as ciphertext.
    pub fn inner(&self) -> &Arc<S> {
        &self.inner
    }

    /// Returns the key provider used for envelope encryption; keys are
    /// resolved per record using the committing principal's tenant, so one
    /// tenant's records cannot be opened with another tenant's keys.
    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }

    /// Returns the store kind bound into every envelope's AAD; mismatched
    /// kinds make decryption fail closed with a crypto error.
    pub fn store_kind(&self) -> &str {
        &self.store_kind
    }
}

impl<C, P, S> EncryptingManagedDatastore<C, P, S>
where
    C: OpcConfig + Serialize + DeserializeOwned,
    P: KeyProvider + ?Sized,
    S: ManagedDatastore<SealedConfig<C>> + ?Sized,
{
    async fn encrypt_record(
        &self,
        mut record: StoredConfig<C>,
    ) -> Result<StoredConfig<SealedConfig<C>>, StoreError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&record.config)
                .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?,
        );
        record.plaintext_digest = Some(compute_plaintext_digest(plaintext.as_slice()));
        let aad = build_config_envelope_aad(&record, self.store_kind())?;
        let schema_digest = record.schema_digest;
        record.encrypted_blob =
            encrypt_envelope(self.provider.as_ref(), &aad, plaintext.as_slice())
                .await
                .map_err(|_| StoreError::crypto(CONFIG_ENVELOPE_ENCRYPT_FAILED_MESSAGE))?;
        Ok(record.with_config(SealedConfig::new(schema_digest)))
    }

    async fn decrypt_record(
        &self,
        record: StoredConfig<SealedConfig<C>>,
    ) -> Result<StoredConfig<C>, StoreError> {
        if record.encrypted_blob.is_empty() {
            let Some(config) = record.config.legacy_plaintext_config().cloned() else {
                return Err(StoreError::crypto(CONFIG_ENVELOPE_MISSING_BLOB_MESSAGE));
            };
            verify_legacy_plaintext_digest(&record, &config)?;
            if config.schema_digest() != record.schema_digest {
                return Err(StoreError::restore_schema_mismatch(
                    RESTORE_SCHEMA_MISMATCH_MESSAGE,
                ));
            }
            return Ok(record.with_config(config));
        }

        let aad = build_config_envelope_aad(&record, self.store_kind())?;
        let plaintext = decrypt_envelope(self.provider.as_ref(), &aad, &record.encrypted_blob)
            .await
            .map_err(|_| StoreError::crypto(CONFIG_ENVELOPE_DECRYPT_FAILED_MESSAGE))?;
        verify_plaintext_digest(&record, plaintext.as_slice())?;
        let config: C = serde_json::from_slice(plaintext.as_slice())
            .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?;
        if config.schema_digest() != record.schema_digest {
            return Err(StoreError::restore_schema_mismatch(
                RESTORE_SCHEMA_MISMATCH_MESSAGE,
            ));
        }
        Ok(record.with_config(config))
    }
}

#[async_trait]
impl<C, P, S> ManagedDatastore<C> for EncryptingManagedDatastore<C, P, S>
where
    C: OpcConfig + Serialize + DeserializeOwned,
    P: KeyProvider + ?Sized,
    S: ManagedDatastore<SealedConfig<C>> + ?Sized,
{
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        match self.inner.load_latest().await? {
            Some(record) => self.decrypt_record(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig<C>, StoreError> {
        let record = self.inner.load_rollback(target).await?;
        self.decrypt_record(record).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        match self.inner.load_by_idempotency_key(idempotency_key).await? {
            Some(record) => self.decrypt_record(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        let record = self.encrypt_record(commit).await?;
        self.inner.append_commit(record).await
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

fn build_config_envelope_aad<C: OpcConfig>(
    record: &StoredConfig<C>,
    store_kind: &str,
) -> Result<EnvelopeAad, StoreError> {
    let principal = serde_json::to_string(&record.principal)
        .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?;
    let metadata = ConfigAad::new(
        record.tx_id,
        record.parent_tx_id,
        record.committed_at,
        principal,
        record.schema_digest,
        store_kind,
    )
    .map_err(|_| StoreError::crypto(CONFIG_ENVELOPE_AAD_FAILED_MESSAGE))?;
    Ok(EnvelopeAad::config(
        record.principal.tenant.clone(),
        record.version.get(),
        metadata,
    ))
}

fn compute_plaintext_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn verify_plaintext_digest<C: OpcConfig>(
    record: &StoredConfig<C>,
    plaintext: &[u8],
) -> Result<(), StoreError> {
    let Some(expected) = record.plaintext_digest else {
        return Ok(());
    };
    let actual = compute_plaintext_digest(plaintext);
    if actual != expected {
        return Err(StoreError::crypto(
            "config envelope plaintext digest mismatch",
        ));
    }
    Ok(())
}

fn verify_legacy_plaintext_digest<C>(
    record: &StoredConfig<SealedConfig<C>>,
    config: &C,
) -> Result<(), StoreError>
where
    C: OpcConfig + Serialize,
{
    let Some(expected) = record.plaintext_digest else {
        return Ok(());
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(config)
            .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?,
    );
    let actual = compute_plaintext_digest(plaintext.as_slice());
    if actual != expected {
        return Err(StoreError::crypto(
            "config envelope plaintext digest mismatch",
        ));
    }
    Ok(())
}

/// Non-durable in-process [`ManagedDatastore`] for local development, CI, and
/// management-only bootstrap.
///
/// This backend preserves the same commit-bus invariants expected from a real
/// store while the process is alive: append ordering, rollback lookup,
/// idempotency-key replay, recovery markers, and commit-confirmed marker
/// updates. It does **not** write to durable storage, does **not** survive
/// process restart, and must not be used as production configuration storage.
pub struct InMemoryManagedDatastore<C: OpcConfig> {
    state: AsyncMutex<InMemoryStoreState<C>>,
}

struct InMemoryStoreState<C: OpcConfig> {
    latest: Option<StoredConfig<C>>,
    history: Vec<StoredConfig<C>>,
    rollback_labels: HashMap<String, usize>,
}

impl<C: OpcConfig> InMemoryManagedDatastore<C> {
    /// Creates an empty store. It enforces the same append invariants as a
    /// real backend (unique tx ids and versions, no rollback to pending
    /// commit-confirmed records) but keeps everything in process memory, so
    /// nothing survives a restart.
    pub fn new() -> Self {
        Self {
            state: AsyncMutex::new(InMemoryStoreState {
                latest: None,
                history: Vec::new(),
                rollback_labels: HashMap::new(),
            }),
        }
    }

    /// Returns a copy of every appended record in commit order, letting tests
    /// assert on lineage, recovery markers, and fingerprints directly.
    pub async fn history(&self) -> Vec<StoredConfig<C>> {
        self.state.lock().await.history.clone()
    }

    /// Returns a copy of the most recently appended record (including
    /// in-place updates from confirm/recovery clearing), or `None` while the
    /// store is empty.
    pub async fn latest(&self) -> Option<StoredConfig<C>> {
        self.state.lock().await.latest.clone()
    }

    /// Seeds a record directly without uniqueness checks. Use only for test fixture setup.
    pub async fn seed(&self, record: StoredConfig<C>) {
        let mut state = self.state.lock().await;
        let index = state.history.len();
        if let Some(label) = record.rollback_label.clone() {
            state.rollback_labels.insert(label, index);
        }
        state.latest = Some(record.clone());
        state.history.push(record);
    }
}

impl<C: OpcConfig> Default for InMemoryManagedDatastore<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for InMemoryManagedDatastore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        Ok(self.state.lock().await.latest.clone())
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig<C>, StoreError> {
        let state = self.state.lock().await;
        let record = match target {
            RollbackTarget::Previous => {
                let latest_confirmed = state
                    .history
                    .iter()
                    .rev()
                    .find(|record| record.confirmed_deadline.is_none())
                    .ok_or_else(|| {
                        StoreError::not_found("no confirmed config present in in-memory store")
                    })?;

                let parent_tx = latest_confirmed.parent_tx_id.ok_or_else(|| {
                    StoreError::not_found("latest confirmed config has no parent rollback point")
                })?;

                state
                    .history
                    .iter()
                    .rev()
                    .find(|record| record.tx_id == parent_tx)
                    .cloned()
                    .ok_or_else(|| {
                        StoreError::not_found("parent transaction not found in in-memory store")
                    })?
            }
            RollbackTarget::Version(version) => state
                .history
                .iter()
                .rev()
                .find(|record| record.version == version)
                .cloned()
                .ok_or_else(|| {
                    StoreError::not_found(format!(
                        "rollback version {version} not present in in-memory store"
                    ))
                })?,
            RollbackTarget::TxId(tx_id) => state
                .history
                .iter()
                .rev()
                .find(|record| record.tx_id == tx_id)
                .cloned()
                .ok_or_else(|| {
                    StoreError::not_found(format!(
                        "rollback transaction {tx_id} not present in in-memory store"
                    ))
                })?,
            RollbackTarget::Label(label) => state
                .rollback_labels
                .get(&label)
                .and_then(|idx| state.history.get(*idx))
                .cloned()
                .ok_or_else(|| {
                    StoreError::not_found(format!(
                        "rollback label '{label}' not present in in-memory store"
                    ))
                })?,
        };

        if record.confirmed_deadline.is_some() {
            return Err(StoreError::unavailable(
                "cannot rollback to a pending commit",
            ));
        }

        Ok(record)
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .history
            .iter()
            .rev()
            .find(|record| record.idempotency_key.as_ref() == Some(idempotency_key))
            .cloned())
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        if state
            .history
            .iter()
            .any(|record| record.tx_id == commit.tx_id)
        {
            return Err(StoreError::internal(format!(
                "duplicate transaction {} rejected by in-memory store",
                commit.tx_id
            )));
        }
        if state
            .history
            .iter()
            .any(|record| record.version == commit.version)
        {
            return Err(StoreError::internal(format!(
                "duplicate config version {} rejected by in-memory store",
                commit.version
            )));
        }
        let index = state.history.len();
        if let Some(label) = commit.rollback_label.clone() {
            state.rollback_labels.insert(label, index);
        }
        state.latest = Some(commit.clone());
        state.history.push(commit);
        Ok(())
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let index = state
            .history
            .iter()
            .position(|record| record.tx_id == tx_id)
            .ok_or_else(|| {
                StoreError::not_found(format!(
                    "transaction {tx_id} not present in in-memory store for recovery update"
                ))
            })?;

        state.history[index].recovery_required = false;
        if state
            .latest
            .as_ref()
            .is_some_and(|record| record.tx_id == tx_id)
        {
            state.latest = Some(state.history[index].clone());
        }
        Ok(())
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        let mut state = self.state.lock().await;
        let index = state
            .history
            .iter()
            .position(|record| record.tx_id == tx_id)
            .ok_or_else(|| {
                StoreError::not_found(format!(
                    "transaction {tx_id} not present in in-memory store for confirmation"
                ))
            })?;
        state.history[index].confirmed_deadline = None;
        if state
            .latest
            .as_ref()
            .is_some_and(|record| record.tx_id == tx_id)
        {
            state.latest = Some(state.history[index].clone());
        }
        Ok(())
    }
}

/// Compatibility alias for tests and older SDK consumers.
///
/// New product code that needs a non-production backend should prefer
/// [`InMemoryManagedDatastore`] so runtime composition does not imply a mock.
pub type MockManagedDatastore<C> = InMemoryManagedDatastore<C>;
