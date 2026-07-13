//! Single-owner session helper.
//!
//! [`OwnedSession`] bundles a [`SessionKey`], a [`LeaseGuard`], and a
//! background renewal task for the common case where one owner holds one
//! session record. It removes the per-write lease-acquisition boilerplate that
//! the lower-level [`SessionBackend`] + [`SessionLeaseManager`] traits require.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::error::LeaseError;
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{FenceToken, Generation, OwnerId, SessionKey};
use crate::record::StoredSessionRecord;
use crate::store::SessionStore;
use crate::{CompareAndSet, CompareAndSetResult, SessionBackend, StoreError};

/// Error returned by [`OwnedSession`] fenced mutation helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnedSessionMutationError {
    /// The successor generation would overflow `u64`.
    #[error("owned session generation overflow")]
    GenerationOverflow,
    /// The caller-built record does not match the owned session key, owner,
    /// fence, or successor generation.
    #[error("owned session record does not match lease context: {0}")]
    InvalidRecord(&'static str),
    /// The lease expired before the mutation reached the backend.
    #[error("owned session lease lost")]
    LeaseLost,
    /// A newer owner/fence has superseded this owned session.
    #[error("owned session stale fence")]
    StaleFence,
    /// Backend or quorum was unavailable.
    #[error("owned session backend unavailable")]
    BackendUnavailable,
    /// Payload exceeded the backend limit.
    #[error("owned session payload too large: actual {actual} exceeds maximum {max}")]
    PayloadTooLarge {
        /// Rejected payload size.
        actual: usize,
        /// Backend maximum payload size.
        max: usize,
    },
    /// Backend rejected the mutation for another stable reason.
    #[error("owned session store rejected mutation: {code}")]
    StoreRejected {
        /// Stable SDK error code.
        code: &'static str,
    },
}

impl OwnedSessionMutationError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::GenerationOverflow => "generation-overflow",
            Self::InvalidRecord(_) => "invalid-record",
            Self::LeaseLost => "lease-lost",
            Self::StaleFence => "stale-fence",
            Self::BackendUnavailable => "backend-unavailable",
            Self::PayloadTooLarge { .. } => "payload-too-large",
            Self::StoreRejected { code } => code,
        }
    }
}

/// Current lease context supplied to [`OwnedSession::compare_and_set_with`].
#[derive(Debug, Clone, Copy)]
pub struct OwnedSessionMutationContext<'a> {
    key: &'a SessionKey,
    owner: &'a OwnerId,
    fence: FenceToken,
    expected_generation: Option<Generation>,
    successor_generation: Generation,
}

impl<'a> OwnedSessionMutationContext<'a> {
    /// Session key owned by the handle.
    pub const fn key(&self) -> &'a SessionKey {
        self.key
    }

    /// Owner identity held by the handle.
    pub const fn owner(&self) -> &'a OwnerId {
        self.owner
    }

    /// Current fence token from the renewed lease guard.
    pub const fn fence(&self) -> FenceToken {
        self.fence
    }

    /// CAS expectation supplied by the caller.
    pub const fn expected_generation(&self) -> Option<Generation> {
        self.expected_generation
    }

    /// Generation the new record must carry.
    pub const fn successor_generation(&self) -> Generation {
        self.successor_generation
    }
}

/// A single-owner session handle with automatic lease renewal.
///
/// Acquiring an `OwnedSession` obtains a [`LeaseGuard`] for `key` and spawns a
/// background task that renews the lease at `renewal_interval` until the
/// session is released or the renewal fails. Renewal failures are published on
/// a [`watch::Receiver`] because it decouples the owner from the renewal task
/// and allows multiple observers to subscribe to the same outcome without
/// lifetime constraints.
///
/// The handle is cheap to clone: clones share the same lease and renewal task.
/// Dropping the last handle aborts the renewal task; the lease then expires
/// naturally unless [`Self::release`] was called first. Explicit release is
/// recommended for graceful shutdown.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use opc_session_store::{
///     FakeSessionBackend, OwnedSession, SessionKey, SessionKeyType, SessionStore,
/// };
/// use opc_types::{NetworkFunctionKind, TenantId};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let store = SessionStore::new(FakeSessionBackend::new());
/// let owner = opc_session_store::OwnerId::new("smf-01")?;
/// let key = SessionKey {
///     tenant: TenantId::new("ref-smf")?,
///     nf_kind: NetworkFunctionKind::new("smf")?,
///     key_type: SessionKeyType::PduSession,
///     stable_id: bytes::Bytes::from_static(b"seid-1").try_into()?,
/// };
/// let (session, mut failures) = OwnedSession::acquire(
///     store,
///     key,
///     owner,
///     Duration::from_secs(60),
///     Duration::from_secs(30),
/// )
/// .await?;
///
/// // Check for renewal failures in your task loop.
/// if let Err(_e) = failures.borrow_and_update().as_ref() {
///     // handle renewal failure
/// }
/// # Ok(())
/// # }
/// ```
pub struct OwnedSession<B: SessionBackend + SessionLeaseManager + 'static> {
    store: SessionStore<B>,
    key: SessionKey,
    owner: OwnerId,
    lease: Arc<Mutex<LeaseGuard>>,
    renewal_handle: JoinHandle<()>,
    // Held to keep the failure watch channel open for the lifetime of the session.
    _failure_tx: watch::Sender<Result<(), LeaseError>>,
}

impl<B: SessionBackend + SessionLeaseManager + 'static> std::fmt::Debug for OwnedSession<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedSession")
            .field("key", &self.key)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl<B: SessionBackend + SessionLeaseManager + 'static> OwnedSession<B> {
    /// Acquire a lease for `key` and start a background renewal task.
    ///
    /// `ttl` is the lease duration passed to the backend on each acquisition
    /// and renewal. `renewal_interval` is how long the task waits between
    /// renewals; it should be well under half of `ttl` so a transient failure
    /// can be retried before the lease expires.
    ///
    /// On success returns the session handle and a watch receiver that starts
    /// at `Ok(())` and is set to `Err(LeaseError)` if a renewal ever fails.
    pub async fn acquire(
        store: SessionStore<B>,
        key: SessionKey,
        owner: OwnerId,
        ttl: Duration,
        renewal_interval: Duration,
    ) -> Result<(Self, watch::Receiver<Result<(), LeaseError>>), LeaseError> {
        let lease = store.acquire(&key, owner.clone(), ttl).await?;
        let lease = Arc::new(Mutex::new(lease));
        let (failure_tx, failure_rx) = watch::channel(Ok(()));
        let store_clone = store.clone();
        let lease_clone = lease.clone();
        let task_failure_tx = failure_tx.clone();
        let handle = tokio::spawn(async move {
            run_renewal_loop(
                store_clone,
                lease_clone,
                ttl,
                renewal_interval,
                task_failure_tx,
            )
            .await;
        });

        Ok((
            Self {
                store,
                key,
                owner,
                lease,
                renewal_handle: handle,
                _failure_tx: failure_tx,
            },
            failure_rx,
        ))
    }

    /// The session key this owned session covers.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// The owner identity bound to this session.
    pub fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Access the lease guard protected by the renewal task.
    ///
    /// The lock should be held only briefly; the renewal task also needs it.
    pub fn lease(&self) -> &Arc<Mutex<LeaseGuard>> {
        &self.lease
    }

    /// Fenced compare-and-set using a complete caller-built record.
    ///
    /// The helper validates that `new_record` matches the owned session key,
    /// owner, current fence, and successor generation before submitting one
    /// SDK CAS operation. CAS conflicts are returned as
    /// [`CompareAndSetResult::Conflict`] so callers can re-read and retry with
    /// product payload logic outside this helper.
    pub async fn compare_and_set_record(
        &self,
        expected_generation: Option<Generation>,
        new_record: StoredSessionRecord,
    ) -> Result<CompareAndSetResult, OwnedSessionMutationError> {
        let lease = self.lease.lock().await.clone();
        let successor_generation = successor_generation(expected_generation)?;
        validate_owned_record(
            &self.key,
            &self.owner,
            &lease,
            successor_generation,
            &new_record,
        )?;
        self.store
            .compare_and_set(CompareAndSet {
                key: self.key.clone(),
                lease,
                expected_generation,
                new_record,
            })
            .await
            .map_err(OwnedSessionMutationError::from_store_error)
    }

    /// Build and write a fenced record from the current owned lease context.
    ///
    /// This is the preferred helper for product-owned payloads: the SDK
    /// selects the successor generation and supplies the current key, owner,
    /// and fence; the caller only builds the full record body.
    pub async fn compare_and_set_with<F>(
        &self,
        expected_generation: Option<Generation>,
        build: F,
    ) -> Result<CompareAndSetResult, OwnedSessionMutationError>
    where
        F: FnOnce(
            OwnedSessionMutationContext<'_>,
        ) -> Result<StoredSessionRecord, OwnedSessionMutationError>,
    {
        let lease = self.lease.lock().await.clone();
        let successor_generation = successor_generation(expected_generation)?;
        let context = OwnedSessionMutationContext {
            key: &self.key,
            owner: &self.owner,
            fence: lease.fence(),
            expected_generation,
            successor_generation,
        };
        let new_record = build(context)?;
        validate_owned_record(
            &self.key,
            &self.owner,
            &lease,
            successor_generation,
            &new_record,
        )?;
        self.store
            .compare_and_set(CompareAndSet {
                key: self.key.clone(),
                lease,
                expected_generation,
                new_record,
            })
            .await
            .map_err(OwnedSessionMutationError::from_store_error)
    }

    /// Explicitly release the lease and stop the renewal task.
    ///
    /// After this call the lease is returned to the backend and the owner is
    /// no longer authorized to mutate the session record. This is the graceful
    /// counterpart to drop-based expiration.
    pub async fn release(self) -> Result<(), LeaseError> {
        self.renewal_handle.abort();
        let lease = self.lease.lock().await;
        self.store.release(lease.clone()).await
    }
}

fn successor_generation(
    expected_generation: Option<Generation>,
) -> Result<Generation, OwnedSessionMutationError> {
    match expected_generation {
        Some(generation) => generation
            .next()
            .ok_or(OwnedSessionMutationError::GenerationOverflow),
        None => Ok(Generation::new(1)),
    }
}

fn validate_owned_record(
    key: &SessionKey,
    owner: &OwnerId,
    lease: &LeaseGuard,
    successor_generation: Generation,
    record: &StoredSessionRecord,
) -> Result<(), OwnedSessionMutationError> {
    if record.key != *key {
        return Err(OwnedSessionMutationError::InvalidRecord(
            "record key does not match owned session",
        ));
    }
    if record.owner != *owner {
        return Err(OwnedSessionMutationError::InvalidRecord(
            "record owner does not match owned session",
        ));
    }
    if record.fence != lease.fence() {
        return Err(OwnedSessionMutationError::InvalidRecord(
            "record fence does not match current lease",
        ));
    }
    if record.generation != successor_generation {
        return Err(OwnedSessionMutationError::InvalidRecord(
            "record generation is not the expected successor",
        ));
    }
    Ok(())
}

impl OwnedSessionMutationError {
    fn from_store_error(error: StoreError) -> Self {
        match error {
            StoreError::LeaseExpired => Self::LeaseLost,
            StoreError::StaleFence => Self::StaleFence,
            StoreError::BackendUnavailable(_) => Self::BackendUnavailable,
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge { actual, max },
            StoreError::InvalidKey(_) => Self::InvalidRecord("backend rejected record shape"),
            StoreError::InvalidReplicationSequence => Self::StoreRejected {
                code: "invalid-replication-sequence",
            },
            StoreError::InvalidReplicationLogRange => Self::StoreRejected {
                code: "invalid-replication-log-range",
            },
            StoreError::ReplicationLogPageTooLarge { .. } => Self::StoreRejected {
                code: "replication-log-page-too-large",
            },
            StoreError::ReplicationLogCursorCompacted { .. } => Self::StoreRejected {
                code: "replication-log-cursor-compacted",
            },
            StoreError::ReplicationWatchCatchUpRequired => Self::StoreRejected {
                code: "replication-watch-catch-up-required",
            },
            StoreError::ReplicationOperationLimitExceeded => Self::StoreRejected {
                code: "replication-operation-limit-exceeded",
            },
            StoreError::InvalidSessionTtl => Self::StoreRejected {
                code: "invalid-session-ttl",
            },
            StoreError::InvalidRecordExpiry => Self::StoreRejected {
                code: "invalid-record-expiry",
            },
            StoreError::RecordExpiryPreflightLimitExceeded => Self::StoreRejected {
                code: "record-expiry-preflight-limit-exceeded",
            },
            StoreError::NotFound => Self::StoreRejected { code: "not-found" },
            StoreError::CasConflict => Self::StoreRejected {
                code: "cas-conflict",
            },
            StoreError::CasIdempotencyConflict => Self::StoreRejected {
                code: "cas-idempotency-conflict",
            },
            StoreError::CasIdempotencyOutcomeUnavailable => Self::StoreRejected {
                code: "cas-idempotency-outcome-unavailable",
            },
            StoreError::BackendOperationOutcomeUnavailable => Self::StoreRejected {
                code: "backend-operation-outcome-unavailable",
            },
            StoreError::CapabilityNotSupported(_) => Self::StoreRejected {
                code: "capability-not-supported",
            },
            StoreError::LeaseHeld => Self::StoreRejected { code: "lease-held" },
            StoreError::Crypto(_) => Self::StoreRejected { code: "crypto" },
            StoreError::Serialization(_) => Self::StoreRejected {
                code: "serialization",
            },
            StoreError::InvalidRestoreScanRequest(_) => Self::StoreRejected {
                code: "invalid-restore-scan-request",
            },
            StoreError::InvalidRestoreScanResponse(_) => Self::StoreRejected {
                code: "invalid-restore-scan-response",
            },
            StoreError::RestoreScanPageTooLarge { .. } => Self::StoreRejected {
                code: "restore-scan-page-too-large",
            },
            StoreError::RestoreScanCursorStale => Self::StoreRejected {
                code: "restore-scan-cursor-stale",
            },
            StoreError::RestoreScanWorkBudgetExceeded => Self::StoreRejected {
                code: "restore-scan-work-budget-exceeded",
            },
            StoreError::RestoreScanResponseTooLarge { .. } => Self::StoreRejected {
                code: "restore-scan-response-too-large",
            },
        }
    }
}

impl<B: SessionBackend + SessionLeaseManager + 'static> Drop for OwnedSession<B> {
    fn drop(&mut self) {
        // Abort the renewal task. The lease is not released synchronously here
        // because Drop cannot await; it will expire naturally at its TTL. Callers
        // that need immediate cleanup should use `release`.
        self.renewal_handle.abort();
    }
}

async fn run_renewal_loop<B: SessionBackend + SessionLeaseManager + 'static>(
    store: SessionStore<B>,
    lease: Arc<Mutex<LeaseGuard>>,
    ttl: Duration,
    interval: Duration,
    failure_tx: watch::Sender<Result<(), LeaseError>>,
) {
    loop {
        tokio::time::sleep(interval).await;
        let mut current = lease.lock().await;
        match store.renew(&current, ttl).await {
            Ok(new_lease) => {
                *current = new_lease;
            }
            Err(e) => {
                let _ = failure_tx.send(Err(e));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Generation, SessionKeyType, StateClass, StateType};
    use crate::record::{EncryptedSessionPayload, StoredSessionRecord};
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("ref-smf"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"seid-1")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn record_from_context(
        context: OwnedSessionMutationContext<'_>,
        payload: &'static [u8],
    ) -> StoredSessionRecord {
        StoredSessionRecord {
            key: context.key().clone(),
            generation: context.successor_generation(),
            owner: context.owner().clone(),
            fence: context.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("pdu-session"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(payload)),
        }
    }

    #[tokio::test]
    async fn fake_backend_owned_session_acquires_and_releases() {
        let store = SessionStore::new(crate::FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = test_key();
        let (session, _failures) = OwnedSession::acquire(
            store.clone(),
            key.clone(),
            owner.clone(),
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire");

        assert_eq!(session.key(), &key);
        assert_eq!(session.owner(), &owner);

        // The lease authorizes a fenced write.
        let lease_guard = session.lease.lock().await;
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: crate::model::Generation::new(1),
            owner: owner.clone(),
            fence: lease_guard.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("pdu-session"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
        };
        let result = store
            .compare_and_set(crate::backend::CompareAndSet {
                key,
                lease: lease_guard.clone(),
                expected_generation: None,
                new_record: record,
            })
            .await
            .expect("cas");
        assert!(matches!(
            result,
            crate::backend::CompareAndSetResult::Success
        ));
        drop(lease_guard);

        session.release().await.expect("release");
    }

    #[tokio::test]
    async fn owned_session_compare_and_set_with_writes_successor_records() {
        let store = SessionStore::new(crate::FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = test_key();
        let (session, _failures) = OwnedSession::acquire(
            store.clone(),
            key.clone(),
            owner,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire");

        let first = session
            .compare_and_set_with(None, |context| {
                Ok(record_from_context(context, b"payload-1"))
            })
            .await
            .expect("first write");
        assert_eq!(first, CompareAndSetResult::Success);

        let second = session
            .compare_and_set_with(Some(Generation::new(1)), |context| {
                assert_eq!(context.expected_generation(), Some(Generation::new(1)));
                Ok(record_from_context(context, b"payload-2"))
            })
            .await
            .expect("second write");
        assert_eq!(second, CompareAndSetResult::Success);

        let stored = store.get(&key).await.expect("get").expect("record");
        assert_eq!(stored.generation, Generation::new(2));
        assert_eq!(stored.payload.as_bytes(), b"payload-2");

        session.release().await.expect("release");
    }

    #[tokio::test]
    async fn owned_session_compare_and_set_returns_conflict_without_error() {
        let store = SessionStore::new(crate::FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = test_key();
        let (session, _failures) = OwnedSession::acquire(
            store,
            key,
            owner,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire");

        assert_eq!(
            session
                .compare_and_set_with(None, |context| {
                    Ok(record_from_context(context, b"payload-1"))
                })
                .await
                .expect("first write"),
            CompareAndSetResult::Success
        );

        let conflict = session
            .compare_and_set_with(None, |context| {
                Ok(record_from_context(context, b"payload-conflict"))
            })
            .await
            .expect("conflict result");

        match conflict {
            CompareAndSetResult::Success => panic!("expected conflict"),
            CompareAndSetResult::Conflict { current } => {
                assert_eq!(current.expect("current").payload.as_bytes(), b"payload-1");
            }
        }

        session.release().await.expect("release");
    }

    #[tokio::test]
    async fn owned_session_compare_and_set_rejects_malformed_record() {
        let store = SessionStore::new(crate::FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = test_key();
        let (session, _failures) = OwnedSession::acquire(
            store,
            key,
            owner,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire");

        let err = session
            .compare_and_set_with(None, |context| {
                let mut record = record_from_context(context, b"payload");
                record.generation = Generation::new(99);
                Ok(record)
            })
            .await
            .unwrap_err();

        assert_eq!(err.code(), "invalid-record");
        assert!(!format!("{err:?}").contains("payload"));

        session.release().await.expect("release");
    }

    #[tokio::test]
    async fn owned_session_compare_and_set_reports_generation_overflow() {
        let store = SessionStore::new(crate::FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = test_key();
        let (session, _failures) = OwnedSession::acquire(
            store,
            key,
            owner,
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire");

        let err = session
            .compare_and_set_with(Some(Generation::new(u64::MAX)), |context| {
                Ok(record_from_context(context, b"unreachable"))
            })
            .await
            .unwrap_err();

        assert_eq!(err, OwnedSessionMutationError::GenerationOverflow);

        session.release().await.expect("release");
    }

    #[tokio::test(start_paused = true)]
    async fn owned_session_compare_and_set_reports_lost_lease() {
        let store = SessionStore::new(crate::FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = test_key();
        let (session, _failures) = OwnedSession::acquire(
            store,
            key,
            owner,
            Duration::from_secs(5),
            Duration::from_secs(60),
        )
        .await
        .expect("acquire");

        tokio::time::advance(Duration::from_secs(6)).await;

        let err = session
            .compare_and_set_with(None, |context| Ok(record_from_context(context, b"payload")))
            .await
            .unwrap_err();

        assert_eq!(err.code(), "lease-lost");
    }
}
