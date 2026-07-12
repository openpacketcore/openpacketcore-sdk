//! Lease manager and fencing rules for single-owner session mutation
//! (RFC 004 §9).
//!
//! A lease grants one owner the right to mutate a session for a bounded TTL;
//! the fence token minted at acquisition is what actually protects the data.
//! Lease expiry is a liveness mechanism only — safety comes from backends
//! rejecting writes whose fence token is lower than the key's recorded token,
//! so an owner that pauses past its TTL can never overwrite its successor.

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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    /// Session key this lease covers; fenced mutations must target exactly
    /// this key or backends reject them as invalid.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Replica the lease was granted to. Records written under this lease
    /// must carry the same owner or the write is rejected as stale.
    pub fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Fence token minted when the lease was acquired. It is constant across
    /// renewals, and release does not lower the key's recorded token — only a
    /// later acquisition mints a higher one.
    pub fn fence(&self) -> FenceToken {
        self.fence
    }

    /// When this guard was issued by the lease manager's clock (some
    /// implementations preserve the original acquisition time across
    /// renewals, others restamp it at renewal).
    pub fn acquired_at(&self) -> Timestamp {
        self.acquired_at
    }

    /// Deadline after which the guard is no longer valid: fenced mutations
    /// presented later fail with a lease-expired error and the key becomes
    /// acquirable by other owners. Renew well before this point — RFC 004
    /// §9.3 recommends before 50 percent of the TTL has elapsed — and stop
    /// authoritative writes immediately if a renewal fails.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Opaque credential identifier retained across renewal.
    ///
    /// Reading this identifier does not permit callers to mint a valid guard:
    /// guard construction remains crate-private. Transport and backend adapters
    /// use it to reject renewal responses that silently replace credentials.
    pub fn credential_id(&self) -> u64 {
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
