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
use crate::model::{OwnerId, SessionKey};
use crate::store::SessionStore;
use crate::SessionBackend;

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
///     stable_id: bytes::Bytes::from_static(b"seid-1"),
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
    use crate::model::{SessionKeyType, StateClass, StateType};
    use crate::record::{EncryptedSessionPayload, StoredSessionRecord};
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("ref-smf"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"seid-1"),
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
}
