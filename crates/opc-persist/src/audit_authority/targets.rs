//! Versioned NETCONF results, separate from running configuration revisions.
//! These values describe results; decoding one grants no effect authority.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{AuditAuthorityError, AuditOperationHandle};
use crate::ConfigConsensusIdentity;

// Preserve the existing identity's bytes while rejecting unknown fields inside
// the new target-v1 format. The legacy identity codec is not changed.
pub(crate) mod identity {
    use super::*;
    use crate::{
        ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    };

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        cluster_id: ConfigConsensusClusterId,
        configuration_id: ConfigConsensusConfigurationId,
        configuration_epoch: ConfigConsensusConfigurationEpoch,
    }

    pub(crate) fn serialize<S: serde::Serializer>(
        value: &ConfigConsensusIdentity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ConfigConsensusIdentity, D::Error> {
        let value = Body::deserialize(deserializer)?;
        Ok(ConfigConsensusIdentity::new(
            value.cluster_id,
            value.configuration_id,
            value.configuration_epoch,
        ))
    }
}

// The target format rejects extra caller fields without changing the legacy
// projected event or operation-handle encoding.
pub(crate) mod caller {
    use super::super::{AuditCaller, AuditToken};
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        tenant: AuditToken,
        principal: AuditToken,
    }

    pub(crate) fn serialize<S: serde::Serializer>(
        value: &AuditCaller,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AuditCaller, D::Error> {
        let value = Body::deserialize(deserializer)?;
        Ok(AuditCaller {
            tenant: value.tenant,
            principal: value.principal,
        })
    }
}

macro_rules! counter {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        /// Zero describes only the initial absent state. A counter is an
        /// expectation, not an authorization capability or running revision.
        #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[serde(with = "identity")]
            pub(crate) authority: ConfigConsensusIdentity,
            pub(crate) value: u64,
        }

        impl $name {
            /// Configuration authority to which this counter belongs.
            pub const fn authority(self) -> ConfigConsensusIdentity {
                self.authority
            }

            /// Numeric counter, never implicitly convertible to a running version.
            pub const fn get(self) -> u64 {
                self.value
            }

            /// Compute the next expectation without wrapping or granting authority.
            /// The state machine must still compare the exact current counter.
            pub fn checked_next(self) -> Result<Self, AuditAuthorityError> {
                Ok(Self {
                    authority: self.authority,
                    value: self.value.checked_add(1).ok_or(AuditAuthorityError::Full)?,
                })
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

counter!(
    CandidateGeneration,
    "Authority-scoped retained candidate generation, including tombstones."
);
counter!(
    StartupRevision,
    "Authority-scoped retained startup revision, including tombstones."
);

macro_rules! scoped_token {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        /// This identifies a result; it is not a session, device or lock capability.
        #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[serde(with = "identity")]
            pub(crate) authority: ConfigConsensusIdentity,
            pub(crate) value: [u8; 16],
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

scoped_token!(
    NetconfPendingConfirmation,
    "Opaque authority-scoped identity of one exact pending confirmation."
);
scoped_token!(
    NetconfIncarnation,
    "Opaque authority-scoped incarnation of one retained lifecycle result."
);

/// Disjoint outcomes of the retained target authority.
///
/// A decoded value is untrusted until covered by an authenticated applied
/// receipt. Existing running commits retain their separate `Committed` outcome.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum NetconfAppliedOutcome {
    /// Candidate stage or discard applied, advancing even an absent tombstone.
    Candidate {
        /// Resulting candidate generation.
        generation: CandidateGeneration,
    },
    /// Startup replacement or deletion applied.
    Startup {
        /// Resulting startup revision.
        revision: StartupRevision,
    },
    /// Exact source was copied to running without retiring that source.
    CopiedRunning {
        /// Applied running revision.
        running_version: u64,
    },
    /// Running commit and exact candidate retirement applied atomically.
    Promoted {
        /// Applied running revision.
        running_version: u64,
        /// Resulting candidate tombstone generation.
        retired_generation: CandidateGeneration,
    },
    /// Tentative running commit, retirement and pending ownership applied together.
    Tentative {
        /// Applied running revision.
        running_version: u64,
        /// Resulting candidate tombstone generation.
        retired_generation: CandidateGeneration,
        /// Exact retained pending confirmation.
        pending: NetconfPendingConfirmation,
    },
    /// Exact pending ownership was confirmed without another running commit.
    Confirmed {
        /// Pending confirmation that was resolved.
        pending: NetconfPendingConfirmation,
    },
    /// Exact pending ownership was resolved by its rollback successor.
    RolledBack {
        /// Applied running revision.
        running_version: u64,
        /// Pending confirmation that was resolved.
        pending: NetconfPendingConfirmation,
    },
    /// A device, session or lock lifecycle effect was retained.
    Lifecycle {
        /// Incarnation of the applied lifecycle effect.
        incarnation: NetconfIncarnation,
    },
}

impl NetconfAppliedOutcome {
    /// A running revision only for effects that actually produced one.
    pub const fn running_version(self) -> Option<u64> {
        match self {
            Self::CopiedRunning { running_version }
            | Self::Promoted {
                running_version, ..
            }
            | Self::Tentative {
                running_version, ..
            }
            | Self::RolledBack {
                running_version, ..
            } => Some(running_version),
            Self::Candidate { .. }
            | Self::Startup { .. }
            | Self::Confirmed { .. }
            | Self::Lifecycle { .. } => None,
        }
    }

    fn valid_in(self, authority: ConfigConsensusIdentity) -> bool {
        let pending_ok = |pending: NetconfPendingConfirmation| {
            pending.authority == authority && pending.value != [0; 16]
        };
        let generation_ok = |generation: CandidateGeneration| {
            generation.authority == authority && generation.value > 0
        };
        if self
            .running_version()
            .is_some_and(|version| version == 0 || version > i64::MAX as u64)
        {
            return false;
        }
        match self {
            Self::Candidate { generation } => generation_ok(generation),
            Self::Startup { revision } => revision.authority == authority && revision.value > 0,
            Self::CopiedRunning { .. } => true,
            Self::Promoted {
                retired_generation, ..
            } => generation_ok(retired_generation),
            Self::Tentative {
                retired_generation,
                pending,
                ..
            } => generation_ok(retired_generation) && pending_ok(pending),
            Self::Confirmed { pending } | Self::RolledBack { pending, .. } => pending_ok(pending),
            Self::Lifecycle { incarnation } => {
                incarnation.authority == authority && incarnation.value != [0; 16]
            }
        }
    }
}

impl fmt::Debug for NetconfAppliedOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfAppliedOutcome(<redacted>)")
    }
}

// Store the common authority once. The wire body still carries and validates
// each scoped public value. This keeps the existing Copy receipt contract without
// adding a heap allocation or retaining several copies of the same authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutcomeBody {
    Candidate(u64),
    Startup(u64),
    CopiedRunning(u64),
    Promoted(u64, u64),
    Tentative(u64, u64, [u8; 16]),
    Confirmed([u8; 16]),
    RolledBack(u64, [u8; 16]),
    Lifecycle([u8; 16]),
}

impl From<NetconfAppliedOutcome> for OutcomeBody {
    fn from(value: NetconfAppliedOutcome) -> Self {
        match value {
            NetconfAppliedOutcome::Candidate { generation } => Self::Candidate(generation.value),
            NetconfAppliedOutcome::Startup { revision } => Self::Startup(revision.value),
            NetconfAppliedOutcome::CopiedRunning { running_version } => {
                Self::CopiedRunning(running_version)
            }
            NetconfAppliedOutcome::Promoted {
                running_version,
                retired_generation,
            } => Self::Promoted(running_version, retired_generation.value),
            NetconfAppliedOutcome::Tentative {
                running_version,
                retired_generation,
                pending,
            } => Self::Tentative(running_version, retired_generation.value, pending.value),
            NetconfAppliedOutcome::Confirmed { pending } => Self::Confirmed(pending.value),
            NetconfAppliedOutcome::RolledBack {
                running_version,
                pending,
            } => Self::RolledBack(running_version, pending.value),
            NetconfAppliedOutcome::Lifecycle { incarnation } => Self::Lifecycle(incarnation.value),
        }
    }
}

/// Target-v1 outcome and its authenticated retained-state anchor.
///
/// This is a payload, not an applied receipt. Decoding does not prove an effect,
/// independently checkpointed admission, or current device ownership.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResultBody", into = "ResultBody")]
pub struct NetconfTargetResult {
    authority: ConfigConsensusIdentity,
    profile_incarnation: [u8; 16],
    state_digest: [u8; 32],
    outcome: OutcomeBody,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBody {
    #[serde(with = "identity")]
    authority: ConfigConsensusIdentity,
    profile_incarnation: [u8; 16],
    state_digest: [u8; 32],
    outcome: NetconfAppliedOutcome,
}

impl TryFrom<ResultBody> for NetconfTargetResult {
    type Error = AuditAuthorityError;

    fn try_from(body: ResultBody) -> Result<Self, Self::Error> {
        Self::new(
            body.authority,
            body.profile_incarnation,
            body.state_digest,
            body.outcome,
        )
    }
}

impl From<NetconfTargetResult> for ResultBody {
    fn from(value: NetconfTargetResult) -> Self {
        Self {
            authority: value.authority,
            profile_incarnation: value.profile_incarnation,
            state_digest: value.state_digest,
            outcome: value.outcome(),
        }
    }
}

impl NetconfTargetResult {
    pub(crate) fn new(
        authority: ConfigConsensusIdentity,
        profile_incarnation: [u8; 16],
        state_digest: [u8; 32],
        outcome: NetconfAppliedOutcome,
    ) -> Result<Self, AuditAuthorityError> {
        // Validate supplied scopes before folding them into the common scope.
        if profile_incarnation == [0; 16] || !outcome.valid_in(authority) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(Self {
            authority,
            profile_incarnation,
            state_digest,
            outcome: outcome.into(),
        })
    }

    /// Authority scope bound into this result's authenticated receipt.
    pub const fn authority(self) -> ConfigConsensusIdentity {
        self.authority
    }

    /// Applied target or lifecycle outcome, distinct from a running-only commit.
    pub const fn outcome(self) -> NetconfAppliedOutcome {
        let authority = self.authority;
        match self.outcome {
            OutcomeBody::Candidate(value) => NetconfAppliedOutcome::Candidate {
                generation: CandidateGeneration { authority, value },
            },
            OutcomeBody::Startup(value) => NetconfAppliedOutcome::Startup {
                revision: StartupRevision { authority, value },
            },
            OutcomeBody::CopiedRunning(running_version) => {
                NetconfAppliedOutcome::CopiedRunning { running_version }
            }
            OutcomeBody::Promoted(running_version, value) => NetconfAppliedOutcome::Promoted {
                running_version,
                retired_generation: CandidateGeneration { authority, value },
            },
            OutcomeBody::Tentative(running_version, generation, pending) => {
                NetconfAppliedOutcome::Tentative {
                    running_version,
                    retired_generation: CandidateGeneration {
                        authority,
                        value: generation,
                    },
                    pending: NetconfPendingConfirmation {
                        authority,
                        value: pending,
                    },
                }
            }
            OutcomeBody::Confirmed(value) => NetconfAppliedOutcome::Confirmed {
                pending: NetconfPendingConfirmation { authority, value },
            },
            OutcomeBody::RolledBack(running_version, value) => NetconfAppliedOutcome::RolledBack {
                running_version,
                pending: NetconfPendingConfirmation { authority, value },
            },
            OutcomeBody::Lifecycle(value) => NetconfAppliedOutcome::Lifecycle {
                incarnation: NetconfIncarnation { authority, value },
            },
        }
    }

    pub(crate) const fn profile_incarnation(self) -> [u8; 16] {
        self.profile_incarnation
    }

    /// Digest of the complete resulting profile, targets and lifecycle state.
    pub const fn state_digest(self) -> [u8; 32] {
        self.state_digest
    }

    pub(crate) fn validate_for(
        self,
        handle: &AuditOperationHandle,
    ) -> Result<(), AuditAuthorityError> {
        if self.authority != handle.body.identity
            || handle.body.mutation.is_none()
            || !(matches!(
                handle.body.event.transport,
                crate::ManagementAuditTransportCode::NetconfSsh
                    | crate::ManagementAuditTransportCode::NetconfTls
            ) || (handle.body.event.transport
                == crate::ManagementAuditTransportCode::Internal
                && matches!(
                    self.outcome(),
                    NetconfAppliedOutcome::Lifecycle { .. }
                        | NetconfAppliedOutcome::RolledBack { .. }
                )))
            || handle.body.event.outcome != crate::ManagementAuditOutcomeCode::Intent
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for NetconfTargetResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfTargetResult(<redacted>)")
    }
}

/// SDK preparation for one explicit device-start transition. Preparing it does
/// not establish device ownership. Preserve its original handle before intent
/// admission, then claim ownership from the exact applied receipt.
///
/// The worker binding is deliberately neither serialized nor reconstructible
/// from recovery bytes. A replacement worker must reconcile old work and start
/// a fresh device incarnation before it can acquire its own serving capability.
#[derive(Clone)]
pub struct PreparedNetconfDevice {
    pub(crate) worker: NetconfWorkerBinding,
    pub(crate) prepared: super::PreparedTargetMutation,
}

impl PreparedNetconfDevice {
    /// Exact closed lifecycle effect for the required intent/result protocol.
    pub fn mutation(&self) -> &super::PreparedTargetMutation {
        &self.prepared
    }
}

impl fmt::Debug for PreparedNetconfDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedNetconfDevice(<redacted>)")
    }
}

/// One established device incarnation bound to the exact issuing store worker.
/// This is not a principal, a numeric NETCONF session ID, or a lock lease.
/// Every subsequent operation must also check current retained ownership and
/// configuration authority; possession alone does not establish liveness.
#[derive(Clone)]
pub struct NetconfDeviceOwner {
    pub(crate) worker: NetconfWorkerBinding,
    pub(crate) authority: ConfigConsensusIdentity,
    pub(crate) profile_incarnation: [u8; 16],
    pub(crate) device_incarnation: [u8; 16],
    pub(crate) caller: super::AuditCaller,
}

impl fmt::Debug for NetconfDeviceOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfDeviceOwner(<redacted>)")
    }
}

#[derive(Clone)]
pub(crate) struct NetconfWorkerBinding {
    worker: std::sync::Weak<dyn std::any::Any + Send + Sync>,
}

impl NetconfWorkerBinding {
    pub(crate) fn new<T: Send + Sync + 'static>(worker: &std::sync::Arc<T>) -> Self {
        let erased: std::sync::Arc<dyn std::any::Any + Send + Sync> = worker.clone();
        Self {
            worker: std::sync::Arc::downgrade(&erased),
        }
    }

    pub(crate) fn belongs_to<T: Send + Sync + 'static>(&self, worker: &std::sync::Arc<T>) -> bool {
        let erased: std::sync::Arc<dyn std::any::Any + Send + Sync> = worker.clone();
        self.worker.ptr_eq(&std::sync::Arc::downgrade(&erased))
    }
}

/// Datastore protected by a retained NETCONF lock. These codes do not identify
/// a session or grant any permission to read or mutate that datastore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetconfLockDatastore {
    /// The current running configuration.
    Running,
    /// The retained candidate configuration.
    Candidate,
    /// The retained startup configuration.
    Startup,
}

impl NetconfLockDatastore {
    pub(crate) fn slot(self) -> usize {
        match self {
            Self::Running => 0,
            Self::Candidate => 1,
            Self::Startup => 2,
        }
    }
}

struct NetconfSessionState {
    incarnation: [u8; 16],
    active: std::sync::atomic::AtomicBool,
    cleanup: std::sync::Mutex<Option<NetconfCleanupAttempt>>,
}

/// Authenticated session incarnation under one SDK-issued device owner.
/// Numeric protocol session IDs are not accepted as ownership evidence.
/// This token is local and cannot be reconstructed from a saved request.
#[derive(Clone)]
pub struct NetconfSessionOwner {
    pub(crate) device: NetconfDeviceOwner,
    pub(crate) caller: super::AuditCaller,
    state: std::sync::Arc<NetconfSessionState>,
}

impl NetconfSessionOwner {
    pub(crate) fn new(
        device: NetconfDeviceOwner,
        caller: super::AuditCaller,
        incarnation: [u8; 16],
    ) -> Result<Self, AuditAuthorityError> {
        if incarnation == [0; 16] {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(Self {
            device,
            caller,
            state: std::sync::Arc::new(NetconfSessionState {
                incarnation,
                active: std::sync::atomic::AtomicBool::new(true),
                cleanup: std::sync::Mutex::new(None),
            }),
        })
    }

    /// Immediately revoke this local session and every clone. This does not
    /// acknowledge durable unlock, candidate discard, or confirmed rollback.
    /// The owning worker must retain and complete the exact cleanup operation
    /// before permitting subsequent effects; dropping an RPC future is not
    /// that worker's lifetime boundary.
    pub fn invalidate(&self) {
        self.state
            .active
            .store(false, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn require_active(&self) -> Result<(), AuditAuthorityError> {
        if self.state.active.load(std::sync::atomic::Ordering::Acquire) {
            Ok(())
        } else {
            Err(AuditAuthorityError::BindingMismatch)
        }
    }

    pub(crate) fn incarnation(&self) -> [u8; 16] {
        self.state.incarnation
    }

    pub(crate) fn same_session(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.state, &other.state)
    }
}

impl fmt::Debug for NetconfSessionOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfSessionOwner(<redacted>)")
    }
}

/// Closed acquisition or release preparation bound to the original session.
/// Retain its mutation before admission and recover only that original handle.
#[derive(Clone)]
pub struct PreparedNetconfLock {
    pub(crate) session: NetconfSessionOwner,
    pub(crate) datastore: NetconfLockDatastore,
    pub(crate) prepared: super::PreparedTargetMutation,
}

impl PreparedNetconfLock {
    /// Exact closed lock effect for required intent and result admission.
    pub fn mutation(&self) -> &super::PreparedTargetMutation {
        &self.prepared
    }
}

impl fmt::Debug for PreparedNetconfLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedNetconfLock(<redacted>)")
    }
}

/// An applied, checkpointed retained lease belonging to one exact session.
/// Possession alone does not prove the lease is still current.
#[derive(Clone)]
pub struct NetconfLockLease {
    pub(crate) session: NetconfSessionOwner,
    pub(crate) datastore: NetconfLockDatastore,
    pub(crate) incarnation: u64,
}

impl fmt::Debug for NetconfLockLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfLockLease(<redacted>)")
    }
}

struct NetconfCleanupAttempt {
    prepared: super::PreparedTargetMutation,
    predecessor: Option<AuditOperationHandle>,
}

impl NetconfSessionOwner {
    pub(crate) fn cleanup_context(
        &self,
        event: &super::ProjectedAuditEvent,
    ) -> Result<(), AuditAuthorityError> {
        if self.require_active().is_ok()
            || event.caller != self.caller
            || event.transport != crate::ManagementAuditTransportCode::Internal
            || event.operation != crate::ManagementAuditOperationCode::Exec
            || event.outcome != crate::ManagementAuditOutcomeCode::Intent
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    fn matching_cleanup(
        original: &super::PreparedTargetMutation,
        event: &super::ProjectedAuditEvent,
        lifetime: std::time::Duration,
    ) -> Result<super::PreparedTargetMutation, AuditAuthorityError> {
        if original.handle.body.event != *event
            || lifetime.subsec_nanos() != 0
            || original
                .handle
                .body
                .expires_at
                .checked_sub(original.handle.body.issued_at)
                != i64::try_from(lifetime.as_secs()).ok()
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(original.clone())
    }

    fn cleanup_preparation_lifetime(
        &self,
        prepared: &super::PreparedTargetMutation,
    ) -> Result<std::time::Duration, AuditAuthorityError> {
        self.cleanup_context(&prepared.handle.body.event)?;
        let seconds = prepared
            .handle
            .body
            .expires_at
            .checked_sub(prepared.handle.body.issued_at)
            .filter(|seconds| (1..=3600).contains(seconds))
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        if !prepared.is_session_cleanup_for(self) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(std::time::Duration::from_secs(seconds as u64))
    }

    pub(crate) fn original_cleanup(
        &self,
        event: &super::ProjectedAuditEvent,
        lifetime: std::time::Duration,
    ) -> Result<Option<super::PreparedTargetMutation>, AuditAuthorityError> {
        self.cleanup_context(event)?;
        let slot = self
            .state
            .cleanup
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        slot.as_ref()
            .map(|current| Self::matching_cleanup(&current.prepared, event, lifetime))
            .transpose()
    }

    pub(crate) fn retain_cleanup(
        &self,
        prepared: super::PreparedTargetMutation,
    ) -> Result<super::PreparedTargetMutation, AuditAuthorityError> {
        let lifetime = self.cleanup_preparation_lifetime(&prepared)?;
        let event = prepared.handle.body.event.clone();
        let mut slot = self
            .state
            .cleanup
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        // No await or authority mutation occurs under this bounded local lock.
        let original = slot.get_or_insert(NetconfCleanupAttempt {
            prepared,
            predecessor: None,
        });
        Self::matching_cleanup(&original.prepared, &event, lifetime)
    }

    fn cleanup_successor_context(
        &self,
        previous: &super::PreparedTargetMutation,
        event: &super::ProjectedAuditEvent,
    ) -> Result<(), AuditAuthorityError> {
        self.cleanup_context(event)?;
        self.cleanup_preparation_lifetime(previous)?;
        if event.request == previous.handle.body.event.request
            || event.projection != previous.handle.body.event.projection
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn successor_cleanup(
        &self,
        previous: &super::PreparedTargetMutation,
        event: &super::ProjectedAuditEvent,
        lifetime: std::time::Duration,
    ) -> Result<Option<super::PreparedTargetMutation>, AuditAuthorityError> {
        self.cleanup_successor_context(previous, event)?;
        let slot = self
            .state
            .cleanup
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let current = slot.as_ref().ok_or(AuditAuthorityError::BindingMismatch)?;
        if current.prepared == *previous {
            return Ok(None);
        }
        if current.predecessor.as_ref() != Some(previous.handle()) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Self::matching_cleanup(&current.prepared, event, lifetime).map(Some)
    }

    pub(crate) fn retain_cleanup_successor(
        &self,
        previous: &super::PreparedTargetMutation,
        prepared: super::PreparedTargetMutation,
        ledger: &super::ledger::LedgerState,
        key: &crate::AuditKey,
        now: i64,
    ) -> Result<super::PreparedTargetMutation, AuditAuthorityError> {
        self.cleanup_successor_context(previous, &prepared.handle.body.event)?;
        let lifetime = self.cleanup_preparation_lifetime(&prepared)?;
        if prepared.handle.body.issued_at < previous.handle.body.expires_at {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        prepared.verify_effect(key)?;
        previous.verify_settled_cleanup_rejection(self, ledger, key, now)?;
        let mut slot = self
            .state
            .cleanup
            .lock()
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        let current = slot.as_ref().ok_or(AuditAuthorityError::BindingMismatch)?;
        if current.prepared == *previous {
            // Retain at most one prepared attempt and its immediate predecessor,
            // never an unbounded local history. Old handles remain in the ledger.
            *slot = Some(NetconfCleanupAttempt {
                prepared: prepared.clone(),
                predecessor: Some(previous.handle().clone()),
            });
            return Ok(prepared);
        }
        if current.predecessor.as_ref() != Some(previous.handle()) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        // A concurrent identical preparation gets the first selected original.
        // Another event, predecessor or lifetime cannot replace that winner.
        Self::matching_cleanup(&current.prepared, &prepared.handle.body.event, lifetime)
    }
}

/// A source and running destination frozen before copy content is prepared.
/// Its private fields retain the original session, source generation or
/// fallback, running version and running lock. Consumers cannot construct or
/// decode this value; reading it grants no mutation authority.
pub struct NetconfRunningCopyRead {
    pub(crate) source: NetconfTargetRead,
    pub(crate) running_lock_incarnation: u64,
    pub(crate) running_lock_session: Option<[u8; 16]>,
}

impl NetconfRunningCopyRead {
    /// The original candidate/startup source, including its encrypted content
    /// and pinned running fallback. Decrypt with the expected tenant through
    /// the existing provider, then authorize and validate the configuration.
    pub fn source(&self) -> &NetconfTargetRead {
        &self.source
    }

    pub(crate) fn verify_session(
        &self,
        session: &NetconfSessionOwner,
    ) -> Result<(), AuditAuthorityError> {
        self.source.verify_session(session)
    }
}

impl fmt::Debug for NetconfRunningCopyRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfRunningCopyRead(<redacted>)")
    }
}

/// An encrypted running copy paired with its original frozen source and
/// destination. The existing provider authenticates both configurations;
/// request metadata may differ, but copied configuration bytes must match.
/// This input grants no permission and retains no provider after preparation.
pub struct NetconfRunningCopy<'a> {
    pub(crate) frozen: &'a NetconfRunningCopyRead,
    pub(crate) commit: crate::AttestedConfigCommit,
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
}

impl<'a> NetconfRunningCopy<'a> {
    /// Pair the original read with the exact proposed running envelope.
    /// Preparation refuses a different session, stale original expectations,
    /// or a commit carrying a confirmed-resolution obligation.
    pub fn new(
        frozen: &'a NetconfRunningCopyRead,
        commit: crate::AttestedConfigCommit,
        provider: &'a dyn opc_key::KeyProvider,
    ) -> Self {
        Self {
            frozen,
            commit,
            provider,
        }
    }
}

impl fmt::Debug for NetconfRunningCopy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfRunningCopy(<redacted>)")
    }
}

/// An actual staged candidate and running destination frozen for ordinary
/// promotion. The SDK verifies the original staging session, caller and running
/// base before returning this value. It has no consumer constructor or decoder.
/// A running fallback is not a staged candidate and cannot produce this read.
pub struct NetconfCandidatePromotionRead {
    pub(crate) copy: NetconfRunningCopyRead,
}

impl NetconfCandidatePromotionRead {
    /// Original staged content and generation. Decrypt through the existing
    /// provider and expected tenant, then authorize and validate that content.
    pub fn candidate(&self) -> &NetconfTargetRead {
        self.copy.source()
    }

    pub(crate) fn verify_session(
        &self,
        session: &NetconfSessionOwner,
    ) -> Result<(), AuditAuthorityError> {
        self.copy.verify_session(session)
    }
}

impl fmt::Debug for NetconfCandidatePromotionRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfCandidatePromotionRead(<redacted>)")
    }
}

/// An original staged candidate paired with its proposed running envelope.
/// Preparation authenticates exact configuration equality through the provider;
/// admission and atomic promotion remain separate required authority steps.
pub struct NetconfCandidatePromotion<'a> {
    pub(crate) frozen: &'a NetconfCandidatePromotionRead,
    pub(crate) commit: crate::AttestedConfigCommit,
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
}

impl<'a> NetconfCandidatePromotion<'a> {
    /// Pair the original read and exact attested running envelope. This input
    /// cannot confirm a pending operation or install a confirmation deadline.
    /// The provider is borrowed only for preparation and is never retained.
    pub fn new(
        frozen: &'a NetconfCandidatePromotionRead,
        commit: crate::AttestedConfigCommit,
        provider: &'a dyn opc_key::KeyProvider,
    ) -> Self {
        Self {
            frozen,
            commit,
            provider,
        }
    }
}

impl fmt::Debug for NetconfCandidatePromotion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfCandidatePromotion(<redacted>)")
    }
}

/// A frozen encrypted candidate/startup read from one authenticated authority
/// transaction. Its private binding names the original session, worker, target
/// counter, running base and lock. It cannot be constructed or decoded by a
/// consumer. Reading it grants no permission to admit or apply a mutation.
///
/// An absent candidate selects the exact current running fallback when one
/// exists. An absent startup has no content. Neither case creates target state.
pub struct NetconfTargetRead {
    pub(crate) session: NetconfSessionOwner,
    pub(crate) datastore: NetconfLockDatastore,
    pub(crate) counter: u64,
    pub(crate) running_base: u64,
    pub(crate) lock_incarnation: u64,
    pub(crate) lock_session: Option<[u8; 16]>,
    pub(crate) fallback: bool,
    pub(crate) content: Option<NetconfTargetReadContent>,
}

pub(crate) struct NetconfTargetReadContent {
    pub(crate) schema: opc_types::SchemaDigest,
    pub(crate) plaintext_digest: [u8; 32],
    pub(crate) encrypted: Vec<u8>,
}

impl NetconfTargetRead {
    /// Original destination, never running.
    pub fn datastore(&self) -> NetconfLockDatastore {
        self.datastore
    }

    /// Exact candidate counter, including an absent-state tombstone.
    pub fn candidate_generation(&self) -> Option<CandidateGeneration> {
        (self.datastore == NetconfLockDatastore::Candidate).then_some(CandidateGeneration {
            authority: self.session.device.authority,
            value: self.counter,
        })
    }

    /// Exact startup counter, including an absent-state tombstone.
    pub fn startup_revision(&self) -> Option<StartupRevision> {
        (self.datastore == NetconfLockDatastore::Startup).then_some(StartupRevision {
            authority: self.session.device.authority,
            value: self.counter,
        })
    }

    /// Running version captured with the target, not a target counter.
    pub fn running_base_version(&self) -> u64 {
        self.running_base
    }

    /// Whether this absent candidate selects its pinned running configuration.
    pub fn uses_running_fallback(&self) -> bool {
        self.fallback
    }

    /// Original bounded ciphertext. Decrypt through the existing provider and
    /// expected tenant, then validate the configuration before preparing an edit.
    /// The ciphertext is protected input, not suitable for diagnostic output.
    pub fn encrypted_configuration(&self) -> Option<&[u8]> {
        self.content
            .as_ref()
            .map(|content| content.encrypted.as_slice())
    }

    /// Schema of the exact encrypted source, when content exists.
    pub fn schema(&self) -> Option<opc_types::SchemaDigest> {
        self.content.as_ref().map(|content| content.schema)
    }

    pub(crate) fn verify_session(
        &self,
        session: &NetconfSessionOwner,
    ) -> Result<(), AuditAuthorityError> {
        session.require_active()?;
        if !self.session.same_session(session) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for NetconfTargetRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfTargetRead(<redacted>)")
    }
}

/// Immutable serialized replacement supplied to SDK target preparation. The
/// embedding worker must first authorize and validate the configuration model.
/// Preparation checks bounds and creates the destination envelope through the
/// existing provider. This input contains no claimed ciphertext or outcome.
/// The provider and plaintext borrow are never retained in a command or row.
pub struct NetconfTargetReplacement<'a> {
    pub(crate) frozen: &'a NetconfTargetRead,
    pub(crate) plaintext: &'a [u8],
    pub(crate) schema: opc_types::SchemaDigest,
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
    pub(crate) operation: crate::ManagementAuditOperationCode,
}

impl<'a> NetconfTargetReplacement<'a> {
    /// Replacement computed by an edit against the accompanying frozen read.
    /// Required audit must describe an Update intent.
    pub fn edit(
        frozen: &'a NetconfTargetRead,
        plaintext: &'a [u8],
        schema: opc_types::SchemaDigest,
        provider: &'a dyn opc_key::KeyProvider,
    ) -> Self {
        Self {
            frozen,
            plaintext,
            schema,
            provider,
            operation: crate::ManagementAuditOperationCode::Update,
        }
    }

    /// Explicit inline copy content, with a Replace intent. This constructor
    /// does not assert a relationship to any source datastore. Datastore copy
    /// requires its own authenticated source selection and cannot use this as
    /// a substitute for that binding.
    pub fn inline_copy(
        frozen: &'a NetconfTargetRead,
        plaintext: &'a [u8],
        schema: opc_types::SchemaDigest,
        provider: &'a dyn opc_key::KeyProvider,
    ) -> Self {
        Self {
            frozen,
            plaintext,
            schema,
            provider,
            operation: crate::ManagementAuditOperationCode::Replace,
        }
    }
}

impl fmt::Debug for NetconfTargetReplacement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfTargetReplacement(<redacted>)")
    }
}

/// Source and destination of one datastore copy, frozen together with their
/// authenticated ledger and checkpoint. This SDK-issued value cannot be
/// constructed or decoded by a consumer and grants no admission authority.
pub struct NetconfTargetCopyRead {
    pub(crate) destination: NetconfTargetRead,
    pub(crate) source: NetconfTargetRead,
}

impl NetconfTargetCopyRead {
    /// Original destination and its exact counter, running base and lock.
    pub fn destination(&self) -> &NetconfTargetRead {
        &self.destination
    }

    /// Source datastore selected in the same transaction as the destination.
    pub fn source_datastore(&self) -> NetconfLockDatastore {
        self.source.datastore()
    }

    /// Schema of the exact authenticated source. Copy preserves this schema.
    pub fn schema(&self) -> Option<opc_types::SchemaDigest> {
        self.source.schema()
    }

    /// Whether the original absent candidate selects its exact running fallback.
    pub fn uses_running_fallback(&self) -> bool {
        self.source.uses_running_fallback()
    }
}

impl fmt::Debug for NetconfTargetCopyRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfTargetCopyRead(<redacted>)")
    }
}

/// Validated serialized copy content paired with its original SDK source read.
/// Preparation verifies exact configuration equality through the provider;
/// new replay metadata may differ. Plaintext and provider borrows are not
/// retained in a command, handle or target row.
pub struct NetconfTargetCopy<'a> {
    pub(crate) frozen: &'a NetconfTargetCopyRead,
    pub(crate) plaintext: &'a [u8],
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
}

impl<'a> NetconfTargetCopy<'a> {
    /// Pair the authorized, validated destination wrapper with its original
    /// source/destination read. This constructor does not authenticate content
    /// or grant admission. The SDK preparation port performs those checks.
    pub fn new(
        frozen: &'a NetconfTargetCopyRead,
        plaintext: &'a [u8],
        provider: &'a dyn opc_key::KeyProvider,
    ) -> Self {
        Self {
            frozen,
            plaintext,
            provider,
        }
    }
}

impl fmt::Debug for NetconfTargetCopy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfTargetCopy(<redacted>)")
    }
}

/// Exact tentative promotion input paired with the original staged read.
/// The envelope carries a fixed confirmed deadline and original running parent.
/// A persistent credential is borrowed only during provider-backed preparation.
/// This input grants no admission and never confers signing authority.
pub struct NetconfTentativePromotion<'a> {
    pub(crate) frozen: &'a NetconfCandidatePromotionRead,
    pub(crate) commit: crate::AttestedConfigCommit,
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
    pub(crate) persist: Option<&'a str>,
}

impl<'a> NetconfTentativePromotion<'a> {
    /// Pair the original candidate with its exact tentative running envelope.
    /// `None` retains session-only ownership; a nonempty credential selects
    /// persistent ownership under the same original projected caller and tenant.
    pub fn new(
        frozen: &'a NetconfCandidatePromotionRead,
        commit: crate::AttestedConfigCommit,
        provider: &'a dyn opc_key::KeyProvider,
        persist: Option<&'a str>,
    ) -> Self {
        Self {
            frozen,
            commit,
            provider,
            persist,
        }
    }
}

impl fmt::Debug for NetconfTentativePromotion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfTentativePromotion(<redacted>)")
    }
}

/// One original pending confirmation read with authenticated authority state.
/// It has no consumer constructor or decoder and exposes no credential bytes.
/// The exact worker, session, pending identity and candidate state remain bound
/// through provider preparation; stale admission must reject those expectations.
pub struct NetconfPendingRead {
    pub(crate) session: NetconfSessionOwner,
    pub(crate) view: crate::consensus::audit_targets::NetconfPendingView,
}

impl fmt::Debug for NetconfPendingRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfPendingRead(<redacted>)")
    }
}

/// Credential input for confirming an original pending operation without
/// another running commit. Staged changes require separate promotion with
/// resolution. No credential or provider is retained by the prepared command.
pub struct NetconfEmptyConfirmation<'a> {
    pub(crate) frozen: &'a NetconfPendingRead,
    pub(crate) provider: &'a dyn opc_key::KeyProvider,
    pub(crate) persist_id: Option<&'a str>,
}

impl<'a> NetconfEmptyConfirmation<'a> {
    /// Pair the original pending read with its provider and, only for
    /// persistent ownership, the exact original confirmation credential.
    pub fn new(
        frozen: &'a NetconfPendingRead,
        provider: &'a dyn opc_key::KeyProvider,
        persist_id: Option<&'a str>,
    ) -> Self {
        Self {
            frozen,
            provider,
            persist_id,
        }
    }
}

impl fmt::Debug for NetconfEmptyConfirmation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfEmptyConfirmation(<redacted>)")
    }
}
