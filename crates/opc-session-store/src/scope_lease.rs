//! Strict scope leases with admitted execution selection and timed permits.
//!
//! One bounded authority checkpoint holds the selection, grant floor and exact
//! last operation. Every mutation is one native consensus command. Membership
//! changes preserve the stable scope; admission still checks the current epoch.
//! Ordinary consumer record APIs cannot mutate this reserved record type.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    SessionConsensusClusterId, SessionConsensusIdentity, SessionConsumerIdentity, SessionKey,
    SessionKeyType, StableId,
};

pub(crate) mod service;
mod state;

pub(crate) use service::is_scope_lease_key;
pub use service::{ScopeLeaseAction, ScopeLeaseAdmission, ScopeLeaseStore};

const RECORD_TYPE: &str = "opc-scope-lease";
const RECORD_MAGIC: &[u8; 5] = b"OPSL\x02";
/// Maximum plaintext size of the fixed scope authority record.
pub const MAX_SCOPE_LEASE_RECORD_BYTES: usize = 4096;
/// Healthy renewal interval fixed by the scope lease profile.
pub const SCOPE_RENEWAL_INTERVAL: Duration = Duration::from_secs(1);
/// Forwarding grace following the next scheduled renewal.
pub const SCOPE_FORWARDING_GRACE: Duration = Duration::from_secs(60);
/// Additional exclusion after the permit's absolute stop deadline.
pub const SCOPE_CLOCK_GUARD: Duration = Duration::from_secs(1);

/// Stable, value-free reason for refusing a scope lease operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeLeaseError {
    /// A field is empty, out of bounds, or inconsistent.
    #[error("scope_lease_invalid_request")]
    InvalidRequest,
    /// Authentication or platform admission did not authorize this operation.
    #[error("scope_lease_unauthorized")]
    Unauthorized,
    /// The exact expected scope revision no longer exists.
    #[error("scope_lease_conflict")]
    Conflict,
    /// A retained request ID was reused with different content.
    #[error("scope_lease_idempotency_conflict")]
    IdempotencyConflict,
    /// A predecessor may still use its packet permit.
    #[error("scope_lease_held")]
    Held,
    /// The complete supplied permit is no longer current.
    #[error("scope_lease_stale_permit")]
    StalePermit,
    /// An intervening selection or a consumed selection forbids this grant.
    #[error("scope_lease_superseded")]
    Superseded,
    /// Renewal cannot extend an expired permit; explicit resume is required.
    #[error("scope_lease_expired")]
    Expired,
    /// The trusted clock cannot currently establish the required time bounds.
    #[error("scope_lease_clock_uncertain")]
    ClockUncertain,
    /// This record is not the exact supported scope profile.
    #[error("scope_lease_format_mismatch")]
    FormatMismatch,
    /// This service requires strictly durable consensus persistence.
    #[error("scope_lease_durable_consensus_required")]
    DurableConsensusRequired,
    /// The operation might have committed; resolve its exact request by retry.
    #[error("scope_lease_outcome_unknown")]
    OutcomeUnknown,
    /// The authoritative backend could not be reached or validated.
    #[error("scope_lease_unavailable")]
    Unavailable,
}

/// Exact store, tenant, network function and opaque stable slot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeLeaseId {
    store: SessionConsensusClusterId,
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
    slot: [u8; 32],
}

impl ScopeLeaseId {
    /// Bind an opaque nonzero slot to the stable cluster identity.
    /// Configuration changes do not change the resulting scope.
    pub fn new(
        store: SessionConsensusIdentity,
        tenant: TenantId,
        nf_kind: NetworkFunctionKind,
        slot: [u8; 32],
    ) -> Result<Self, ScopeLeaseError> {
        if slot == [0; 32] {
            return Err(ScopeLeaseError::InvalidRequest);
        }
        Ok(Self {
            store: store.cluster_id(),
            tenant,
            nf_kind,
            slot,
        })
    }

    /// Return the stable cluster identity, independent of membership epochs.
    pub const fn store(&self) -> SessionConsensusClusterId {
        self.store
    }

    /// Return the tenant admitted by the service.
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Return the network-function namespace admitted by the service.
    pub const fn nf_kind(&self) -> &NetworkFunctionKind {
        &self.nf_kind
    }

    /// Return the opaque stable slot.
    pub const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(crate) fn key(&self) -> Result<SessionKey, ScopeLeaseError> {
        Ok(SessionKey {
            tenant: self.tenant.clone(),
            nf_kind: self.nf_kind.clone(),
            key_type: SessionKeyType::other(RECORD_TYPE)
                .map_err(|_| ScopeLeaseError::InvalidRequest)?,
            stable_id: StableId::new(Bytes::copy_from_slice(&self.slot))
                .map_err(|_| ScopeLeaseError::InvalidRequest)?,
        })
    }
}

/// An admitted process, distinct from the stable scope it may own.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeExecution {
    #[serde(with = "identity_claim")]
    identity: SessionConsumerIdentity,
    admission_generation: u64,
    incarnation: [u8; 16],
    workload: [u8; 16],
    process: [u8; 16],
}

// This wire value is a claim. Authentication still comes from the transport,
// never by deserializing a SessionConsumerIdentity out of this record.
mod identity_claim {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        value: &SessionConsumerIdentity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SessionConsumerIdentity, D::Error> {
        let value = String::deserialize(deserializer)?;
        SessionConsumerIdentity::new(value).map_err(serde::de::Error::custom)
    }
}

impl ScopeExecution {
    /// Describe an execution for the trusted platform admission policy.
    ///
    /// These bytes are claims, not credentials. The service independently
    /// checks them against the authenticated peer through its admission policy.
    pub fn new(
        identity: SessionConsumerIdentity,
        admission_generation: u64,
        incarnation: [u8; 16],
        workload: [u8; 16],
        process: [u8; 16],
    ) -> Result<Self, ScopeLeaseError> {
        let value = Self {
            identity,
            admission_generation,
            incarnation,
            workload,
            process,
        };
        value.validate()?;
        Ok(value)
    }

    /// Authenticated consumer identity which owns this execution.
    pub const fn identity(&self) -> &SessionConsumerIdentity {
        &self.identity
    }
    /// Monotonic platform-admitted generation, verified independently of the
    /// caller. A stale generation cannot be restaged using a fresh revision.
    pub const fn admission_generation(&self) -> u64 {
        self.admission_generation
    }
    /// Opaque controller-admitted incarnation.
    pub const fn incarnation(&self) -> &[u8; 16] {
        &self.incarnation
    }
    /// Opaque platform-authenticated workload identity.
    pub const fn workload(&self) -> &[u8; 16] {
        &self.workload
    }
    /// Nonce unique to this process execution, never reused after restart.
    pub const fn process(&self) -> &[u8; 16] {
        &self.process
    }

    fn validate(&self) -> Result<(), ScopeLeaseError> {
        if self.admission_generation == 0
            || self.admission_generation > i64::MAX as u64
            || self.incarnation == [0; 16]
            || self.workload == [0; 16]
            || self.process == [0; 16]
        {
            return Err(ScopeLeaseError::InvalidRequest);
        }
        Ok(())
    }
}

/// A conservative interval containing current real time in one common domain.
///
/// The trusted clock provider must include cross-host offset, drift, suspend
/// and sampling error. A wall-time reading alone is not such a bound. No
/// default system-clock implementation is supplied. Intervals wider than the
/// fixed guard are refused. A gate uses the upper bound to stop; a successor
/// uses the lower bound to establish that exclusion has ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ScopeClockBounds {
    earliest: Timestamp,
    latest: Timestamp,
}

impl<'de> Deserialize<'de> for ScopeClockBounds {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            earliest: Timestamp,
            latest: Timestamp,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.earliest, wire.latest).map_err(serde::de::Error::custom)
    }
}

impl ScopeClockBounds {
    /// Validate a trusted clock observation without narrowing its uncertainty.
    pub fn new(earliest: Timestamp, latest: Timestamp) -> Result<Self, ScopeLeaseError> {
        let width = *latest.as_offset_datetime() - *earliest.as_offset_datetime();
        if width.is_negative() || width > time::Duration::SECOND {
            return Err(ScopeLeaseError::ClockUncertain);
        }
        Ok(Self { earliest, latest })
    }
    /// Earliest possible current time, used only for exclusion expiry.
    pub const fn earliest(self) -> Timestamp {
        self.earliest
    }
    /// Latest possible current time, used for stopping an existing permit.
    pub const fn latest(self) -> Timestamp {
        self.latest
    }
}

/// Trusted platform time boundary; unavailable or unbounded time fails closed.
pub trait ScopeLeaseClock: Send + Sync {
    /// Sample a current interval, including elapsed time during suspend.
    fn bounds(&self) -> Result<ScopeClockBounds, ScopeLeaseError>;
}

/// Immutable timed grant description retained in a committed scope record.
///
/// A stored or deserialized permit is not fresh authority. It must match the
/// admitted scope/execution and a gate's current generation, and its absolute
/// deadline must still be live. Delivery delays and retries never extend it.
/// Gate adapters accept [`CommittedScopePermit`], not these deserializable claims.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePermit {
    scope: ScopeLeaseId,
    execution: ScopeExecution,
    selection: u64,
    grant_epoch: u64,
    issued_at: Timestamp,
    renew_by: Timestamp,
    stop_at: Timestamp,
    excluded_until: Timestamp,
}

impl ScopePermit {
    /// Exact store and stable scope bound by this grant.
    pub const fn scope(&self) -> &ScopeLeaseId {
        &self.scope
    }
    /// Exact process admitted by this grant.
    pub const fn execution(&self) -> &ScopeExecution {
        &self.execution
    }
    /// Monotonic admitted selection at grant time.
    pub const fn selection(&self) -> u64 {
        self.selection
    }
    /// Monotonic grant epoch; renew/resume preserve it.
    pub const fn grant_epoch(&self) -> u64 {
        self.grant_epoch
    }
    /// Original absolute issuance time; never rebased on receipt.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
    /// Deadline for the next healthy renewal attempt.
    pub const fn renew_by(&self) -> Timestamp {
        self.renew_by
    }
    /// Absolute deadline at which all gated traffic must have stopped.
    pub const fn stop_at(&self) -> Timestamp {
        self.stop_at
    }
    /// Earliest time at which a remote successor may obtain a new grant.
    pub const fn excluded_until(&self) -> Timestamp {
        self.excluded_until
    }
    /// Whether a trusted current clock interval is wholly before expiry.
    pub fn is_live_at(&self, now: ScopeClockBounds) -> bool {
        now.latest < self.stop_at
    }
}

/// Opaque evidence that an authenticated grant completed through this SDK.
///
/// Only [`ScopeLeaseStore::grant`] constructs this value. It cannot be created
/// from serialized claims. A gate must additionally check exact execution,
/// current local generation and trusted time, and permanently retire it on
/// release. This token supplies no kernel enforcement by itself.
///
/// ```compile_fail
/// use opc_session_store::scope_lease::CommittedScopePermit;
/// let forged: CommittedScopePermit = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedScopePermit {
    permit: ScopePermit,
    revision: u64,
}

impl CommittedScopePermit {
    /// Exact immutable grant and absolute deadlines confirmed by the store.
    pub const fn permit(&self) -> &ScopePermit {
        &self.permit
    }
    /// Scope revision at which the original grant completed.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Explicit acknowledgement that the caller has closed the exact permit's gate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeGateClosed {
    permit: ScopePermit,
}

impl ScopeGateClosed {
    /// Acknowledge gate closure after stopping all traffic and queued effects.
    ///
    /// This is a trusted effect-boundary assertion, not a kernel proof. Callers
    /// must first honor emergency-session holds, close the gate and confirm
    /// closure. They must never reinstall this permit after release is sent,
    /// even if its response is lost. A crash before release falls back to the
    /// unchanged exclusion deadline. Kernel enforcement is a separate adapter.
    pub const fn after_gate_closed(permit: ScopePermit) -> Self {
        Self { permit }
    }
}

/// One scope mutation; every request includes an exact expected revision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ScopeLeaseOperation {
    /// Stage a newer platform-admitted generation after the old permit has
    /// expired or been released, permanently fencing old resume.
    Select {
        /// Complete platform-admitted successor execution.
        execution: ScopeExecution,
    },
    /// Acquire the selected execution after prior exclusion or graceful release.
    Acquire {
        /// Exact execution named by the current selection.
        execution: ScopeExecution,
        /// Monotonic selection which this acquisition consumes.
        selection: u64,
    },
    /// Renew an exact still-live permit without changing its grant epoch.
    Renew {
        /// Complete current immutable grant.
        permit: ScopePermit,
    },
    /// Reopen the same retained execution after expiry and no intervening selection.
    ResumeSameExecution {
        /// Complete expired grant retained by the same running execution.
        permit: ScopePermit,
    },
    /// Release an exact gate-closed execution, without waiting for expiry.
    Release {
        /// Acknowledgement issued after closing the exact current gate.
        closed: ScopeGateClosed,
    },
}

impl ScopeLeaseOperation {
    fn execution(&self) -> &ScopeExecution {
        match self {
            Self::Select { execution } | Self::Acquire { execution, .. } => execution,
            Self::Renew { permit } | Self::ResumeSameExecution { permit } => &permit.execution,
            Self::Release { closed } => &closed.permit.execution,
        }
    }
}

/// Retain this complete request until its outcome is known.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeLeaseRequest {
    scope: ScopeLeaseId,
    request_id: [u8; 16],
    expected_revision: u64,
    operation: ScopeLeaseOperation,
}

impl ScopeLeaseRequest {
    /// Construct one bounded request. A new revision needs a new request ID.
    pub fn new(
        scope: ScopeLeaseId,
        request_id: [u8; 16],
        expected_revision: u64,
        operation: ScopeLeaseOperation,
    ) -> Result<Self, ScopeLeaseError> {
        if request_id == [0; 16] || expected_revision > i64::MAX as u64 {
            return Err(ScopeLeaseError::InvalidRequest);
        }
        operation.execution().validate()?;
        Ok(Self {
            scope,
            request_id,
            expected_revision,
            operation,
        })
    }
    /// Exact stable scope of the mutation.
    pub const fn scope(&self) -> &ScopeLeaseId {
        &self.scope
    }
    /// Caller-retained operation identity.
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    /// Expected current record revision, zero only before the first selection.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    /// Complete original operation.
    pub const fn operation(&self) -> &ScopeLeaseOperation {
        &self.operation
    }
}

/// Current fixed-size authority state; observations alone do not grant permits.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeLeaseView {
    scope: ScopeLeaseId,
    revision: u64,
    selection: u64,
    selected: Option<ScopeExecution>,
    grant_floor: u64,
    granted_selection: u64,
    permit: Option<ScopePermit>,
}

impl ScopeLeaseView {
    /// Scope observed by this read or mutation result.
    pub const fn scope(&self) -> &ScopeLeaseId {
        &self.scope
    }
    /// Exact revision for the next mutation's compare-and-set.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Monotonic selection floor, retained across expiry and release.
    pub const fn selection(&self) -> u64 {
        self.selection
    }
    /// Current admitted selection, which may differ from the retiring owner.
    pub const fn selected(&self) -> Option<&ScopeExecution> {
        self.selected.as_ref()
    }
    /// Latest grant epoch, retained after release.
    pub const fn grant_floor(&self) -> u64 {
        self.grant_floor
    }
    /// Current permit, possibly expired or superseded by a pending selection.
    pub const fn permit(&self) -> Option<&ScopePermit> {
        self.permit.as_ref()
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })+ };
}
redacted_debug!(
    ScopeLeaseId,
    ScopeExecution,
    ScopePermit,
    CommittedScopePermit,
    ScopeGateClosed,
    ScopeLeaseOperation,
    ScopeLeaseRequest,
    ScopeLeaseView,
    ScopeState
);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeState {
    pub(crate) view: ScopeLeaseView,
    last_request_id: [u8; 16],
    last_digest: [u8; 32],
    last_time: Timestamp,
}

mod command;
pub(crate) use command::checkpoint_state;
#[cfg(target_os = "linux")]
pub(crate) use command::ScopeCheckpointFacts;
pub use command::{ScopeLeaseCheckpoint, ScopeLeaseCommand};

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod service_tests;
