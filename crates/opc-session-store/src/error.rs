//! Error types shared by the storage, lease, and capability layers.
//!
//! Variants distinguish transient faults that are safe to retry (such as
//! `StoreError::BackendUnavailable`) from outcomes that mean the caller has
//! lost write authority and MUST stop mutating under its current lease
//! (`StoreError::StaleFence`, `StoreError::LeaseExpired`). Per RFC 004 §9.3,
//! an owner that cannot confirm its lease state must treat the lease as lost.

use thiserror::Error;

/// Error type for session store operations.
#[derive(Debug, Clone, PartialEq, Eq, Error, serde::Serialize, serde::Deserialize)]
pub enum StoreError {
    /// No live record exists for the key: it was never written, was deleted,
    /// or has passed its TTL `expires_at` and is treated as absent.
    #[error("record not found")]
    NotFound,
    /// The supplied fence token is lower than the token currently recorded for
    /// the key, meaning a newer owner has been fenced in (RFC 004 §9.2). The
    /// caller's lease is permanently dead for writes; do not retry with the
    /// same guard — re-acquire the lease and re-read before mutating again.
    #[error("stale fence: current fence is higher")]
    StaleFence,
    /// The record's current generation did not match the compare-and-set
    /// expectation. The store was not modified; re-read the record, re-derive
    /// the mutation against the observed generation, and retry.
    #[error("compare-and-set conflict")]
    CasConflict,
    /// The operation requires a capability (named in the payload) that this
    /// backend did not declare in its `BackendCapabilities`. Retrying cannot
    /// succeed; choose a backend that satisfies the required profile.
    #[error("capability not supported: {0}")]
    CapabilityNotSupported(String),
    /// The backend could not be reached or a replica quorum could not be
    /// formed. Transient: callers may retry, but until the retry succeeds they
    /// must treat any in-flight lease state as unknown — i.e. lost — and stop
    /// authoritative writes (RFC 004 §9.3).
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    /// The operation's keys are inconsistent (for example a compare-and-set
    /// whose lease key, op key, and record key disagree) or otherwise
    /// malformed. This indicates a caller bug, not a transient fault.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// A replication entry used sequence zero, or a replication prefix/page
    /// was not strictly 1-based and contiguous. The error intentionally
    /// carries no caller-controlled value so it is safe to expose to peers.
    #[error("invalid replication sequence")]
    InvalidReplicationSequence,
    /// A replication operation tree exceeded the SDK-wide depth or node-count
    /// limit. The error intentionally carries no observed count, depth, path,
    /// key, or transaction data, so it is safe to expose to authenticated
    /// peers without turning validation into a shape oracle.
    #[error("replication operation limit exceeded")]
    ReplicationOperationLimitExceeded,
    /// A lease or record-refresh TTL exceeded the SDK maximum, or its absolute
    /// deadline could not be represented. The error intentionally carries no
    /// caller-controlled duration or timestamp, so it is safe to expose to
    /// authenticated peers.
    #[error("invalid session TTL")]
    InvalidSessionTtl,
    /// Another owner currently holds an unexpired lease on the key, so this
    /// caller cannot acquire single-writer authority for it.
    #[error("lease held by another owner")]
    LeaseHeld,
    /// The presented lease credential has passed its TTL expiry. The holder
    /// must stop authoritative writes immediately and re-acquire (receiving a
    /// fresh, higher fence token) before mutating the session again.
    #[error("lease expired")]
    LeaseExpired,
    /// Payload encryption or decryption failed: missing key, AEAD AAD
    /// mismatch, or corrupt envelope. The message is intentionally coarse so
    /// that callers cannot be used as a decryption oracle.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Encoding or decoding of a record, envelope, or replication log entry
    /// failed. Usually indicates corrupt persisted data or a schema mismatch;
    /// retrying with the same input will fail again.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// The record payload exceeds the backend's declared `max_value_bytes`
    /// capability. Nothing was written; shrink the payload or pick a backend
    /// with a larger limit.
    #[error("payload too large: {actual} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge {
        /// Size in bytes of the rejected payload.
        actual: usize,
        /// The backend's `max_value_bytes` limit that was exceeded.
        max: usize,
    },
    /// Restore scan request is malformed, for example a zero page size. The
    /// message is SDK-controlled and must not include raw session keys or
    /// product payload fields.
    #[error("invalid restore scan request: {0}")]
    InvalidRestoreScanRequest(String),
    /// A backend returned a restore page that violated the request contract.
    /// The message is SDK-controlled and must not include record keys or payloads.
    #[error("invalid restore scan response: {0}")]
    InvalidRestoreScanResponse(String),
    /// Restore scan page size exceeds the SDK maximum. Nothing was read.
    #[error("restore scan page too large: requested {requested} exceeds maximum {max}")]
    RestoreScanPageTooLarge {
        /// Requested page size.
        requested: usize,
        /// Maximum supported page size.
        max: usize,
    },
    /// A restore-scan response could not fit within the configured response
    /// budget, either because the budget is below the protocol minimum or one
    /// record is too large. Increase the frame limit or reduce the stored value.
    #[error("restore scan response exceeds the {max_bytes}-byte response limit")]
    RestoreScanResponseTooLarge {
        /// Maximum encoded response size accepted by the caller.
        max_bytes: usize,
    },
}

/// Error type for lease operations.
#[derive(Debug, Clone, PartialEq, Eq, Error, serde::Serialize, serde::Deserialize)]
pub enum LeaseError {
    /// A different owner holds an unexpired lease on the key. Acquisition can
    /// be retried later; it succeeds only once the holder releases or the
    /// lease's TTL elapses.
    #[error("lease already held by another owner")]
    AlreadyHeld,
    /// The lease's TTL elapsed before this operation. The holder no longer has
    /// write authority and must re-acquire; a fresh acquisition mints a higher
    /// fence token, so any writes still using the old guard will be fenced out.
    #[error("lease expired")]
    Expired,
    /// The lease's fence token is lower than the token currently recorded for
    /// the key — a newer owner exists. Renew/release with this guard can never
    /// succeed; abandon it and re-acquire.
    #[error("stale fence: current fence is higher")]
    StaleFence,
    /// No lease entry exists for the key (it was never acquired here, or was
    /// pruned after expiry). Re-acquire instead of renewing.
    #[error("lease not found")]
    NotFound,
    /// The requested lease TTL exceeded the SDK maximum, or its absolute
    /// deadline could not be represented. No lease state was changed.
    #[error("invalid session TTL")]
    InvalidSessionTtl,
    /// The underlying store failed (see the wrapped message). Treat as
    /// transient like `StoreError::BackendUnavailable`, but consider the lease
    /// state unknown — and therefore lost — until a renew succeeds.
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<StoreError> for LeaseError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::LeaseHeld => LeaseError::AlreadyHeld,
            StoreError::LeaseExpired => LeaseError::Expired,
            StoreError::StaleFence => LeaseError::StaleFence,
            StoreError::NotFound => LeaseError::NotFound,
            StoreError::InvalidSessionTtl => LeaseError::InvalidSessionTtl,
            other => LeaseError::Backend(other.to_string()),
        }
    }
}

/// Error type for capability validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    /// The backend's declared capability set does not satisfy the requested
    /// state profile (e.g. no atomic CAS or monotonic fencing for
    /// `authoritative-session`). Per RFC 004 §6 the backend MUST be rejected
    /// for that state class rather than used with weaker semantics.
    #[error("backend lacks capabilities required for profile '{profile}': {missing:?}")]
    MissingCapabilities {
        /// The profile whose requirements were not met.
        profile: crate::capability::SessionStateProfile,
        /// Names of the specific `BackendCapabilities` fields that are missing
        /// for this profile.
        missing: Vec<&'static str>,
    },
}
