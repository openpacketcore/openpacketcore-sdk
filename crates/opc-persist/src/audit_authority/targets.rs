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
