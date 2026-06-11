use std::time::Duration;

use async_trait::async_trait;
use opc_types::Timestamp;

use crate::{
    error::LeaseError,
    model::{FenceToken, OwnerId, SessionKey},
};

/// Opaque lease credential returned after a successful acquisition or renewal.
///
/// Callers can inspect the lease metadata, but only the lease manager can mint
/// a valid guard, which makes the guard suitable as proof for fenced mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGuard {
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    acquired_at: Timestamp,
    expires_at: Timestamp,
    credential_id: u64,
}

impl LeaseGuard {
    pub(crate) fn new(
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        acquired_at: Timestamp,
        expires_at: Timestamp,
        credential_id: u64,
    ) -> Self {
        Self {
            key,
            owner,
            fence,
            acquired_at,
            expires_at,
            credential_id,
        }
    }

    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    pub fn owner(&self) -> &OwnerId {
        &self.owner
    }

    pub fn fence(&self) -> FenceToken {
        self.fence
    }

    pub fn acquired_at(&self) -> Timestamp {
        self.acquired_at
    }

    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    pub(crate) fn credential_id(&self) -> u64 {
        self.credential_id
    }
}

/// Lease manager for single-owner session mutation.
///
/// Every successful acquisition MUST produce a monotonic fencing token for the
/// session key. Writes with a lower token MUST be rejected by the backend.
#[async_trait]
pub trait SessionLeaseManager: Send + Sync {
    /// Acquire a lease for `key` on behalf of `owner` with the given `ttl`.
    ///
    /// Returns a [`LeaseGuard`] containing a fresh [`FenceToken`]. Fails if the
    /// key is already leased by a different owner and the lease has not expired.
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError>;

    /// Renew an existing lease before it expires.
    ///
    /// Returns an updated [`LeaseGuard`] with an extended `expires_at`. The
    /// fence token MUST remain the same across renewals.
    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError>;

    /// Release a lease explicitly.
    ///
    /// After release the fence token is NOT reduced; it remains the current
    /// recorded token so that stale owners cannot write.
    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError>;
}
