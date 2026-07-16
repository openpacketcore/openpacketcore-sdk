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

use opc_config_model::{IdempotencyKey, OpcConfig, RequestId, RequestSource, RollbackTarget};
use opc_crypto::{decrypt_envelope, encrypt_attested_envelope};
use opc_key::{ConfigAad, EnvelopeAad, KeyProvider, Zeroizing};
use opc_types::TxId;

use crate::types::{
    CommitWrite, ConfirmedCommitResolution, SealedConfig, StoreError, StoredConfig,
    StoredRequestFingerprint,
};

const CONFIG_STORE_KIND: &str = "running";
const CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE: &str = "config envelope serialization failed";
const CONFIG_ENVELOPE_ENCRYPT_FAILED_MESSAGE: &str = "config envelope encryption failed";
const CONFIG_ENVELOPE_DECRYPT_FAILED_MESSAGE: &str = "config envelope decryption failed";
const CONFIG_ENVELOPE_MISSING_BLOB_MESSAGE: &str = "config envelope ciphertext is missing";
const CONFIG_ENVELOPE_AAD_FAILED_MESSAGE: &str = "config envelope AAD construction failed";
const RESTORE_SCHEMA_MISMATCH_MESSAGE: &str = "stored running config schema digest mismatch";
const CONFIG_PLAINTEXT_V2_MAGIC: &[u8] = b"\x89OPCCFG\x02\r\n\x1a\n";
const IDEMPOTENCY_LOOKUP_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/config-bus/idempotency-lookup/v1\0";
const REQUEST_LOOKUP_DIGEST_DOMAIN: &[u8] = b"openpacketcore/config-bus/request-lookup/v1\0";
const REPLAY_LOOKUP_BINDING_FAILED_MESSAGE: &str = "config envelope replay lookup binding mismatch";

#[derive(Serialize)]
struct ConfigPlaintextV2Ref<'a, C> {
    config: &'a C,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<RequestSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<&'a IdempotencyKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apply_plan: Option<&'a opc_config_model::ApplyPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_fingerprint: Option<&'a StoredRequestFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<opc_config_model::RequestId>,
}

#[derive(serde::Deserialize)]
struct ConfigPlaintextV2<C> {
    config: C,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<RequestSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<IdempotencyKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    apply_plan: Option<opc_config_model::ApplyPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_fingerprint: Option<StoredRequestFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_id: Option<opc_config_model::RequestId>,
}

/// Durable backend contract consumed by the commit worker.
///
/// A process has one logical commit worker, but HA leaders can race across a
/// failover boundary. Implementations therefore must compare the expected
/// durable head at apply time and make every mutation atomic and durable before
/// returning `Ok` — a commit the worker reports as persisted must be visible
/// after a crash, and a definite failed append must leave no partial record.
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
    /// Compatibility lookup for records written before encrypting stores
    /// replaced the caller's raw idempotency key with a digest-only index.
    /// New persistence adapters that never stored raw keys override this with
    /// `Ok(None)`; the default preserves legacy in-memory/custom stores.
    #[doc(hidden)]
    async fn load_by_legacy_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.load_by_idempotency_key(idempotency_key).await
    }
    /// Looks up a durable record by its original request identifier. This is
    /// the reconciliation path for an `OutcomeUnknown` write whose caller did
    /// not supply an idempotency key.
    ///
    /// The default fails closed; stores that cannot perform an authoritative
    /// lookup must not guess from only the latest record.
    async fn load_by_request_id(
        &self,
        _request_id: RequestId,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        Err(StoreError::unavailable(
            "authoritative config request lookup is unsupported",
        ))
    }
    /// Durably appends an ordinary commit record.
    ///
    /// This is the pre-atomic-extension API retained for source compatibility.
    /// The config bus itself uses [`ManagedDatastore::append_commit_write`];
    /// production backends must override that method so compare-and-append and
    /// commit-confirmed resolution cannot be split. Built-in backends route
    /// this legacy entry point through their atomic implementation.
    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        self.append_commit_write(CommitWrite::new(commit)).await
    }
    /// Durably applies one compare-and-append write. The backend must compare
    /// [`CommitWrite::expected_current_tx_id`] with its applied latest record,
    /// append the successor, and apply any confirmed-commit resolution as one
    /// indivisible state-machine operation. It must report
    /// [`crate::StoreErrorCode::OutcomeUnknown`] whenever the write may have
    /// committed but its acknowledgement was lost; every other returned error
    /// guarantees that no part of the write applied.
    ///
    /// The default fails closed so existing external datastore implementations
    /// continue to compile but cannot accidentally provide non-atomic HA
    /// semantics. Such implementations must explicitly add this method before
    /// they can serve writes from the updated config bus.
    async fn append_commit_write(&self, _commit: CommitWrite<C>) -> Result<(), StoreError> {
        Err(StoreError::unavailable(
            "atomic config compare-and-append is unsupported",
        ))
    }
    /// Durably clears the commit-fencing marker on `tx_id` after the snapshot
    /// swap. If this fails the bus fences itself, because a restart would
    /// otherwise refuse to republish the record.
    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError>;
    /// Legacy explicit confirmation hook retained for external datastore API
    /// compatibility. The config bus resolves confirmation together with its
    /// successor through [`ManagedDatastore::append_commit_write`].
    ///
    /// The default fails closed; built-in backends retain strict support for
    /// callers that still invoke this method directly.
    async fn mark_confirmed(&self, _tx_id: TxId) -> Result<(), StoreError> {
        Err(StoreError::unavailable(
            "standalone commit confirmation is unsupported",
        ))
    }
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

    async fn load_by_legacy_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        (**self)
            .load_by_legacy_idempotency_key(idempotency_key)
            .await
    }

    async fn load_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        (**self).load_by_request_id(request_id).await
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        (**self).append_commit(commit).await
    }

    async fn append_commit_write(&self, commit: CommitWrite<C>) -> Result<(), StoreError> {
        (**self).append_commit_write(commit).await
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
    /// schema/lifecycle and digest-only lookup metadata in the clear, while
    /// the config and original replay metadata remain ciphertext.
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
        let plaintext_v2 = ConfigPlaintextV2Ref {
            config: &record.config,
            source: Some(record.source),
            idempotency_key: record.idempotency_key.as_ref(),
            apply_plan: record.apply_plan.as_ref(),
            request_fingerprint: record.request_fingerprint.as_ref(),
            request_id: record.request_id,
        };
        // Serialize directly into zeroizing storage. Wrapping a `to_vec`
        // result only after serialization would leave both its error path and
        // any copied intermediate allocation able to retain config and raw
        // replay metadata in allocator memory.
        let mut encoded = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *encoded, &plaintext_v2)
            .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            CONFIG_PLAINTEXT_V2_MAGIC
                .len()
                .saturating_add(encoded.len()),
        ));
        plaintext.extend_from_slice(CONFIG_PLAINTEXT_V2_MAGIC);
        plaintext.extend_from_slice(&encoded);
        record.plaintext_digest = Some(compute_plaintext_digest(plaintext.as_slice()));
        record.idempotency_key =
            replay_lookup_digest(record.idempotency_key.as_ref(), record.request_id)?;
        record.apply_plan = None;
        record.request_fingerprint = None;
        record.request_id = None;
        let aad = build_config_envelope_aad(&record, self.store_kind(), None)?;
        let schema_digest = record.schema_digest;
        let envelope =
            encrypt_attested_envelope(self.provider.as_ref(), &aad, plaintext.as_slice())
                .await
                .map_err(|_| StoreError::crypto(CONFIG_ENVELOPE_ENCRYPT_FAILED_MESSAGE))?;
        record.encrypted_blob = envelope.encoded().to_vec();
        Ok(record.with_config(SealedConfig::newly_encrypted(schema_digest, envelope)))
    }

    async fn decrypt_record(
        &self,
        mut record: StoredConfig<SealedConfig<C>>,
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

        let aad =
            build_config_envelope_aad(&record, self.store_kind(), record.config.aad_principal())?;
        let plaintext = decrypt_envelope(self.provider.as_ref(), &aad, &record.encrypted_blob)
            .await
            .map_err(|_| StoreError::crypto(CONFIG_ENVELOPE_DECRYPT_FAILED_MESSAGE))?;
        verify_plaintext_digest(&record, plaintext.as_slice())?;
        let (config, metadata) = if let Some(encoded) =
            plaintext.as_slice().strip_prefix(CONFIG_PLAINTEXT_V2_MAGIC)
        {
            let plaintext: ConfigPlaintextV2<C> = serde_json::from_slice(encoded)
                .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?;
            verify_replay_lookup_binding(
                record.idempotency_key.as_ref(),
                plaintext.idempotency_key.as_ref(),
                plaintext.request_id,
            )?;
            (
                plaintext.config,
                Some((
                    plaintext.source,
                    plaintext.idempotency_key,
                    plaintext.apply_plan,
                    plaintext.request_fingerprint,
                    plaintext.request_id,
                )),
            )
        } else {
            // Records written before the v2 plaintext envelope contained only
            // the serialized config. The binary magic above cannot prefix a
            // valid JSON value, making this compatibility path unambiguous.
            let config: C = serde_json::from_slice(plaintext.as_slice())
                .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?;
            (config, None)
        };
        if config.schema_digest() != record.schema_digest {
            return Err(StoreError::restore_schema_mismatch(
                RESTORE_SCHEMA_MISMATCH_MESSAGE,
            ));
        }
        if let Some((source, idempotency_key, apply_plan, request_fingerprint, request_id)) =
            metadata
        {
            if let Some(source) = source {
                record.source = source;
            }
            record.idempotency_key = idempotency_key;
            record.apply_plan = apply_plan;
            record.request_fingerprint = request_fingerprint;
            record.request_id = request_id;
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
        let lookup_digest = idempotency_lookup_digest(idempotency_key)?;
        let encrypted = match self.inner.load_by_idempotency_key(&lookup_digest).await? {
            Some(record) => Some(record),
            None => {
                self.inner
                    .load_by_legacy_idempotency_key(idempotency_key)
                    .await?
            }
        };
        match encrypted {
            Some(record) => {
                let record = self.decrypt_record(record).await?;
                if record.idempotency_key.as_ref() != Some(idempotency_key) {
                    return Err(StoreError::crypto(REPLAY_LOOKUP_BINDING_FAILED_MESSAGE));
                }
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    async fn load_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        let lookup_digest = request_lookup_digest(request_id)?;
        match self.inner.load_by_idempotency_key(&lookup_digest).await? {
            Some(record) => {
                let record = self.decrypt_record(record).await?;
                if record.request_id != Some(request_id) {
                    return Err(StoreError::crypto(REPLAY_LOOKUP_BINDING_FAILED_MESSAGE));
                }
                Ok(Some(record))
            }
            None => match self.inner.load_by_request_id(request_id).await? {
                Some(record) => {
                    let record = self.decrypt_record(record).await?;
                    if record.request_id != Some(request_id) {
                        return Err(StoreError::crypto(REPLAY_LOOKUP_BINDING_FAILED_MESSAGE));
                    }
                    Ok(Some(record))
                }
                None => Ok(None),
            },
        }
    }

    async fn append_commit_write(&self, commit: CommitWrite<C>) -> Result<(), StoreError> {
        let (record, resolution) = commit.into_parts();
        let record = self.encrypt_record(record).await?;
        let write = match resolution {
            Some(resolution) => CommitWrite::resolving(record, resolution)?,
            None => CommitWrite::new(record),
        };
        self.inner.append_commit_write(write).await
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
    persisted_principal: Option<&str>,
) -> Result<EnvelopeAad, StoreError> {
    let principal = match persisted_principal {
        Some(principal) => principal.to_owned(),
        None => serde_json::to_string(&record.principal)
            .map_err(|_| StoreError::internal(CONFIG_ENVELOPE_SERIALIZATION_FAILED_MESSAGE))?,
    };
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

fn idempotency_lookup_digest(
    idempotency_key: &IdempotencyKey,
) -> Result<IdempotencyKey, StoreError> {
    encode_lookup_digest(
        IDEMPOTENCY_LOOKUP_DIGEST_DOMAIN,
        idempotency_key.as_str().as_bytes(),
    )
}

fn request_lookup_digest(request_id: RequestId) -> Result<IdempotencyKey, StoreError> {
    encode_lookup_digest(
        REQUEST_LOOKUP_DIGEST_DOMAIN,
        request_id.as_uuid().as_bytes(),
    )
}

fn replay_lookup_digest(
    idempotency_key: Option<&IdempotencyKey>,
    request_id: Option<RequestId>,
) -> Result<Option<IdempotencyKey>, StoreError> {
    match (idempotency_key, request_id) {
        (Some(idempotency_key), _) => idempotency_lookup_digest(idempotency_key).map(Some),
        (None, Some(request_id)) => request_lookup_digest(request_id).map(Some),
        (None, None) => Ok(None),
    }
}

fn encode_lookup_digest(domain: &[u8], value: &[u8]) -> Result<IdempotencyKey, StoreError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len().saturating_mul(2));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    IdempotencyKey::new(encoded)
        .map_err(|_| StoreError::internal("replay lookup digest construction failed"))
}

fn verify_replay_lookup_binding(
    stored_lookup_digest: Option<&IdempotencyKey>,
    plaintext_key: Option<&IdempotencyKey>,
    plaintext_request_id: Option<RequestId>,
) -> Result<(), StoreError> {
    let expected = replay_lookup_digest(plaintext_key, plaintext_request_id)?;
    if stored_lookup_digest != expected.as_ref() {
        return Err(StoreError::crypto(REPLAY_LOOKUP_BINDING_FAILED_MESSAGE));
    }
    Ok(())
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

    async fn load_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        let state = self.state.lock().await;
        Ok(state
            .history
            .iter()
            .rev()
            .find(|record| record.request_id == Some(request_id))
            .cloned())
    }

    async fn append_commit_write(&self, commit: CommitWrite<C>) -> Result<(), StoreError> {
        let (commit, resolution) = commit.into_parts();
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

        let current_tx_id = state.latest.as_ref().map(|record| record.tx_id);
        if current_tx_id != commit.parent_tx_id {
            return Err(StoreError::unavailable(
                "config write parent is not the applied latest transaction",
            ));
        }

        if let Some(current) = state.latest.as_ref() {
            let expected_version = current
                .version
                .next()
                .ok_or_else(|| StoreError::internal("config version counter is exhausted"))?;
            if commit.version != expected_version {
                return Err(StoreError::internal(
                    "config write version is not the applied successor",
                ));
            }
        }

        let current_is_pending = state
            .latest
            .as_ref()
            .is_some_and(|record| record.confirmed_deadline.is_some());
        let confirm_index = match (current_is_pending, resolution) {
            (false, None) => None,
            (true, Some(ConfirmedCommitResolution::Confirm { pending_tx_id }))
                if Some(pending_tx_id) == current_tx_id =>
            {
                Some(
                    state
                        .history
                        .iter()
                        .position(|record| record.tx_id == pending_tx_id)
                        .ok_or_else(|| {
                            StoreError::internal(
                                "pending config transaction is absent from history",
                            )
                        })?,
                )
            }
            (true, Some(ConfirmedCommitResolution::Rollback { pending_tx_id }))
                if Some(pending_tx_id) == current_tx_id =>
            {
                None
            }
            (true, None) => {
                return Err(StoreError::unavailable(
                    "pending confirmed commit requires an atomic decision",
                ));
            }
            (false, Some(_)) => {
                return Err(StoreError::unavailable(
                    "confirmed commit decision is no longer current",
                ));
            }
            (true, Some(_)) => {
                return Err(StoreError::unavailable(
                    "confirmed commit decision targets a stale transaction",
                ));
            }
        };

        if let Some(index) = confirm_index {
            state.history[index].confirmed_deadline = None;
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
        let latest_is_target = state
            .latest
            .as_ref()
            .is_some_and(|record| record.tx_id == tx_id && record.confirmed_deadline.is_some());
        if !latest_is_target {
            return Err(StoreError::unavailable(
                "confirmed commit decision is no longer current",
            ));
        }
        let index = state
            .history
            .iter()
            .position(|record| record.tx_id == tx_id)
            .ok_or_else(|| {
                StoreError::internal("current pending config transaction is absent from history")
            })?;
        state.history[index].confirmed_deadline = None;
        state.latest = Some(state.history[index].clone());
        Ok(())
    }
}

/// Compatibility alias for tests and older SDK consumers.
///
/// New product code that needs a non-production backend should prefer
/// [`InMemoryManagedDatastore`] so runtime composition does not imply a mock.
pub type MockManagedDatastore<C> = InMemoryManagedDatastore<C>;
