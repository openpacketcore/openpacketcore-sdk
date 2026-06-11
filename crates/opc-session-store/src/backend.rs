use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use futures_util::future::join_all;
use opc_key::KeyProvider;
use opc_types::Timestamp;

use crate::{
    capability::BackendCapabilities,
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{FenceToken, Generation, OwnerId, SessionKey},
    record::{EncryptedSessionPayload, StoredSessionRecord},
};

/// Atomic compare-and-set operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareAndSet {
    pub key: SessionKey,
    /// Lease credential authorizing this fenced mutation.
    pub lease: LeaseGuard,
    /// `None` means the key must not exist yet.
    pub expected_generation: Option<Generation>,
    pub new_record: StoredSessionRecord,
}

/// Outcome of a compare-and-set operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum CompareAndSetResult {
    Success,
    Conflict {
        /// The current record, if any.
        current: Option<StoredSessionRecord>,
    },
}

/// A single operation inside a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SessionOp {
    Get { key: SessionKey },
    CompareAndSet(CompareAndSet),
    DeleteFenced { lease: LeaseGuard },
    RefreshTtl { lease: LeaseGuard, ttl: Duration },
}

/// Result of a single batched operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOpResult {
    Get(Result<Option<StoredSessionRecord>, StoreError>),
    CompareAndSet(Result<CompareAndSetResult, StoreError>),
    DeleteFenced(Result<(), StoreError>),
    RefreshTtl(Result<(), StoreError>),
}

/// Storage backend trait for session state.
///
/// Implementations MUST enforce their declared [`BackendCapabilities`]. In
/// particular, backends that do not support `atomic_compare_and_set` or
/// `monotonic_fencing_token` MUST reject the corresponding operations.
///
/// Durable adapters that reconstruct [`StoredSessionRecord`] from persisted
/// bytes MUST preserve payload encoding explicitly: use
/// [`EncryptedSessionPayload::envelope`] for RFC 003 ciphertext rows and
/// [`EncryptedSessionPayload::legacy_plaintext`] only for intentional
/// migrations of pre-envelope plaintext rows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplicationEntry {
    pub sequence: u64,
    pub tx_id: String,
    pub op: ReplicationOp,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReplicationOp {
    CompareAndSet {
        key: SessionKey,
        expected_generation: Option<Generation>,
        new_record: StoredSessionRecord,
    },
    DeleteFenced {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
    },
    RefreshTtl {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        ttl: Duration,
    },
    AcquireLease {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        ttl: Duration,
    },
    RenewLease {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        ttl: Duration,
    },
    ReleaseLease {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
    },
    Batch {
        ops: Vec<ReplicationOp>,
    },
}

#[async_trait]
pub trait SessionBackend: Send + Sync {
    /// Return the capability declaration for this backend.
    async fn capabilities(&self) -> BackendCapabilities;

    /// Retrieve a record by key.
    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError>;

    /// Atomically compare the current generation and write the new record if it
    /// matches. Implementations MUST require a current [`LeaseGuard`] and MUST
    /// reject writes whose record owner/fence do not match that lease.
    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError>;

    /// Delete a record using the caller's current lease credential.
    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError>;

    /// Refresh the TTL of a record using the caller's current lease credential.
    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError>;

    /// Execute a batch of operations. The batch is processed sequentially; partial
    /// failure is represented by individual [`SessionOpResult`] variants.
    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError>;

    /// Check if this backend is suitable for a specific session state profile.
    async fn assert_suitable_for(
        &self,
        profile: crate::capability::SessionStateProfile,
    ) -> Result<(), crate::capability::CapabilityError> {
        let caps = self.capabilities().await;
        crate::capability::validate_backend_for_profile(profile, &caps)
    }

    /// Get the maximum sequence number in the replication log.
    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Retrieve log entries in the range [start, start + limit).
    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Append a replication log entry and apply its mutation locally in a single atomic transaction.
    async fn replicate_entry(&self, _entry: ReplicationEntry) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Replace local replicated state with a verified committed log prefix.
    ///
    /// Replicated coordinators use this to repair stale replicas and to discard
    /// uncommitted tails after failed quorum writes. Implementations must rebuild
    /// both durable state and the local replication log from the supplied entries.
    async fn rebuild_replication_state(
        &self,
        _entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Watch for session changes starting from a specific sequence number.
    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        Err(StoreError::CapabilityNotSupported("watch".into()))
    }

    /// Get the next fence and credential ID globals for lease coordination.
    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        Ok((1, 1))
    }
}

/// Session-backend wrapper that encrypts payloads before persistence and
/// decrypts them on reads using `opc-crypto` / `opc-key`.
#[derive(Clone)]
pub struct EncryptingSessionBackend<B: ?Sized, P: ?Sized> {
    inner: Arc<B>,
    provider: Arc<P>,
    backend_namespace: Arc<str>,
}

impl<B: ?Sized, P: ?Sized> EncryptingSessionBackend<B, P> {
    pub fn new(inner: Arc<B>, provider: Arc<P>, backend_namespace: impl Into<String>) -> Self {
        Self {
            inner,
            provider,
            backend_namespace: Arc::<str>::from(backend_namespace.into()),
        }
    }

    pub fn inner(&self) -> &Arc<B> {
        &self.inner
    }

    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }

    pub fn backend_namespace(&self) -> &str {
        &self.backend_namespace
    }
}

impl<B, P> EncryptingSessionBackend<B, P>
where
    B: SessionBackend + ?Sized,
    P: KeyProvider + ?Sized,
{
    async fn encrypt_record(
        &self,
        mut record: StoredSessionRecord,
    ) -> Result<StoredSessionRecord, StoreError> {
        record.payload = EncryptedSessionPayload::encrypt(
            self.provider.as_ref(),
            &record,
            self.backend_namespace(),
        )
        .await?;
        Ok(record)
    }

    async fn decrypt_record(
        &self,
        mut record: StoredSessionRecord,
    ) -> Result<StoredSessionRecord, StoreError> {
        let plaintext = record
            .payload
            .decrypt(
                self.provider.as_ref(),
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                self.backend_namespace(),
            )
            .await?;
        record.payload = EncryptedSessionPayload::new_zeroizing(plaintext);
        Ok(record)
    }

    async fn decrypt_optional_record(
        &self,
        record: Option<StoredSessionRecord>,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        match record {
            Some(record) => self.decrypt_record(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn decrypt_cas_result(
        &self,
        result: CompareAndSetResult,
    ) -> Result<CompareAndSetResult, StoreError> {
        match result {
            CompareAndSetResult::Success => Ok(CompareAndSetResult::Success),
            CompareAndSetResult::Conflict { current } => Ok(CompareAndSetResult::Conflict {
                current: self.decrypt_optional_record(current).await?,
            }),
        }
    }

    async fn decrypt_batch_result(&self, result: SessionOpResult) -> SessionOpResult {
        match result {
            SessionOpResult::Get(result) => SessionOpResult::Get(match result {
                Ok(record) => self.decrypt_optional_record(record).await,
                Err(err) => Err(err),
            }),
            SessionOpResult::CompareAndSet(result) => {
                SessionOpResult::CompareAndSet(match result {
                    Ok(result) => self.decrypt_cas_result(result).await,
                    Err(err) => Err(err),
                })
            }
            SessionOpResult::DeleteFenced(result) => SessionOpResult::DeleteFenced(result),
            SessionOpResult::RefreshTtl(result) => SessionOpResult::RefreshTtl(result),
        }
    }

    async fn encrypt_op(&self, op: ReplicationOp) -> Result<ReplicationOp, StoreError> {
        match op {
            ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                new_record,
            } => {
                let encrypted = self.encrypt_record(new_record).await?;
                Ok(ReplicationOp::CompareAndSet {
                    key,
                    expected_generation,
                    new_record: encrypted,
                })
            }
            ReplicationOp::Batch { ops } => {
                let mut encrypted_ops = Vec::with_capacity(ops.len());
                for o in ops {
                    match o {
                        ReplicationOp::CompareAndSet {
                            key,
                            expected_generation,
                            new_record,
                        } => {
                            let encrypted = self.encrypt_record(new_record).await?;
                            encrypted_ops.push(ReplicationOp::CompareAndSet {
                                key,
                                expected_generation,
                                new_record: encrypted,
                            });
                        }
                        other => encrypted_ops.push(other),
                    }
                }
                Ok(ReplicationOp::Batch { ops: encrypted_ops })
            }
            other => Ok(other),
        }
    }

    async fn decrypt_op(&self, op: ReplicationOp) -> Result<ReplicationOp, StoreError> {
        match op {
            ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                new_record,
            } => {
                let decrypted = self.decrypt_record(new_record).await?;
                Ok(ReplicationOp::CompareAndSet {
                    key,
                    expected_generation,
                    new_record: decrypted,
                })
            }
            ReplicationOp::Batch { ops } => {
                let mut decrypted_ops = Vec::with_capacity(ops.len());
                for o in ops {
                    match o {
                        ReplicationOp::CompareAndSet {
                            key,
                            expected_generation,
                            new_record,
                        } => {
                            let decrypted = self.decrypt_record(new_record).await?;
                            decrypted_ops.push(ReplicationOp::CompareAndSet {
                                key,
                                expected_generation,
                                new_record: decrypted,
                            });
                        }
                        other => decrypted_ops.push(other),
                    }
                }
                Ok(ReplicationOp::Batch { ops: decrypted_ops })
            }
            other => Ok(other),
        }
    }
}

async fn decrypt_record_helper<P: KeyProvider + ?Sized>(
    provider: &P,
    mut record: StoredSessionRecord,
    backend_namespace: &str,
) -> Result<StoredSessionRecord, StoreError> {
    let plaintext = record
        .payload
        .decrypt(
            provider,
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            backend_namespace,
        )
        .await?;
    record.payload = EncryptedSessionPayload::new_zeroizing(plaintext);
    Ok(record)
}

async fn decrypt_op_helper<P: KeyProvider + ?Sized>(
    provider: &P,
    op: ReplicationOp,
    backend_namespace: &str,
) -> Result<ReplicationOp, StoreError> {
    match op {
        ReplicationOp::CompareAndSet {
            key,
            expected_generation,
            new_record,
        } => {
            let decrypted = decrypt_record_helper(provider, new_record, backend_namespace).await?;
            Ok(ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                new_record: decrypted,
            })
        }
        ReplicationOp::Batch { ops } => {
            let mut decrypted_ops = Vec::with_capacity(ops.len());
            for o in ops {
                match o {
                    ReplicationOp::CompareAndSet {
                        key,
                        expected_generation,
                        new_record,
                    } => {
                        let decrypted =
                            decrypt_record_helper(provider, new_record, backend_namespace).await?;
                        decrypted_ops.push(ReplicationOp::CompareAndSet {
                            key,
                            expected_generation,
                            new_record: decrypted,
                        });
                    }
                    other => decrypted_ops.push(other),
                }
            }
            Ok(ReplicationOp::Batch { ops: decrypted_ops })
        }
        other => Ok(other),
    }
}

enum EncryptedBatchSlot {
    BackendResult,
    SyntheticResult(Box<SessionOpResult>),
}

#[async_trait]
impl<B, P> SessionBackend for EncryptingSessionBackend<B, P>
where
    B: SessionBackend + 'static + ?Sized,
    P: KeyProvider + 'static + ?Sized,
{
    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let record = self.inner.get(key).await?;
        self.decrypt_optional_record(record).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let encrypted_record = self.encrypt_record(op.new_record).await?;
        let result = self
            .inner
            .compare_and_set(CompareAndSet {
                key: op.key,
                lease: op.lease,
                expected_generation: op.expected_generation,
                new_record: encrypted_record,
            })
            .await?;
        self.decrypt_cas_result(result).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        if !self.inner.capabilities().await.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let mut encrypted_ops = Vec::with_capacity(ops.len());
        let mut slots = Vec::with_capacity(ops.len());
        for op in ops {
            match op {
                SessionOp::Get { key } => {
                    encrypted_ops.push(SessionOp::Get { key });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
                SessionOp::CompareAndSet(cas) => match self.encrypt_record(cas.new_record).await {
                    Ok(new_record) => {
                        encrypted_ops.push(SessionOp::CompareAndSet(CompareAndSet {
                            key: cas.key,
                            lease: cas.lease,
                            expected_generation: cas.expected_generation,
                            new_record,
                        }));
                        slots.push(EncryptedBatchSlot::BackendResult);
                    }
                    Err(err) => {
                        slots.push(EncryptedBatchSlot::SyntheticResult(Box::new(
                            SessionOpResult::CompareAndSet(Err(err)),
                        )));
                    }
                },
                SessionOp::DeleteFenced { lease } => {
                    encrypted_ops.push(SessionOp::DeleteFenced { lease });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    encrypted_ops.push(SessionOp::RefreshTtl { lease, ttl });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
            }
        }

        let backend_results = if encrypted_ops.is_empty() && !slots.is_empty() {
            Vec::new()
        } else {
            self.inner.batch(encrypted_ops).await?
        };

        let mut backend_results = backend_results.into_iter();
        let mut decrypted = vec![None; slots.len()];
        let mut pending = Vec::new();
        for (index, slot) in slots.into_iter().enumerate() {
            match slot {
                EncryptedBatchSlot::BackendResult => {
                    let Some(result) = backend_results.next() else {
                        return Err(StoreError::BackendUnavailable(
                            "session batch returned fewer results than requested".into(),
                        ));
                    };
                    pending.push(async move { (index, self.decrypt_batch_result(result).await) });
                }
                EncryptedBatchSlot::SyntheticResult(result) => decrypted[index] = Some(*result),
            }
        }

        if backend_results.next().is_some() {
            return Err(StoreError::BackendUnavailable(
                "session batch returned more results than requested".into(),
            ));
        }

        for (index, result) in join_all(pending).await {
            decrypted[index] = Some(result);
        }

        decrypted
            .into_iter()
            .map(|result| {
                result.ok_or_else(|| {
                    StoreError::BackendUnavailable(
                        "session batch returned fewer results than requested".into(),
                    )
                })
            })
            .collect()
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let mut entries = self.inner.get_replication_log(start, limit).await?;
        for entry in &mut entries {
            entry.op = self.decrypt_op(entry.op.clone()).await?;
        }
        Ok(entries)
    }

    async fn replicate_entry(&self, mut entry: ReplicationEntry) -> Result<(), StoreError> {
        entry.op = self.encrypt_op(entry.op).await?;
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        mut entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        for entry in &mut entries {
            entry.op = self.encrypt_op(entry.op.clone()).await?;
        }
        self.inner.rebuild_replication_state(entries).await
    }

    fn watch<'life0, 'async_trait>(
        &'life0 self,
        start_sequence: u64,
    ) -> std::pin::Pin<
        Box<
            dyn futures_util::Future<
                    Output = Result<
                        futures_util::stream::BoxStream<
                            'static,
                            Result<ReplicationEntry, StoreError>,
                        >,
                        StoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let inner = self.inner.clone();
        let provider = self.provider.clone();
        let backend_namespace = self.backend_namespace.clone();
        Box::pin(async move {
            let stream = inner.watch(start_sequence).await?;
            use futures_util::StreamExt;
            let stream = stream.then(move |res| {
                let provider = provider.clone();
                let backend_namespace = backend_namespace.clone();
                async move {
                    match res {
                        Ok(mut entry) => {
                            match decrypt_op_helper(provider.as_ref(), entry.op, &backend_namespace)
                                .await
                            {
                                Ok(dec) => {
                                    entry.op = dec;
                                    Ok(entry)
                                }
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
            });
            Ok(stream.boxed())
        })
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait]
impl<B, P> SessionLeaseManager for EncryptingSessionBackend<B, P>
where
    B: SessionLeaseManager + Send + Sync + ?Sized,
    P: KeyProvider + ?Sized,
{
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: crate::model::OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.inner.release(lease).await
    }
}
