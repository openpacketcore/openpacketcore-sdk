//! Closed, value-free protocol results derived from authenticated SDK receipts.

use std::fmt;

use opc_config_model::{CommitError, CommitErrorCode};
use opc_persist::audit_authority::{
    AuditAuthorityError, AuditOperationHandle, AuditOperationState, NetconfAppliedOutcome,
};

use super::{store::TargetReply, worker::OriginalReply};

/// Opaque, bounded identity for recovery of one original NETCONF operation.
///
/// This is protected recovery material, not a log or protocol correlation value.
/// Decoding grants no authority; recovery independently authenticates its caller
/// and validates the handle against the original retained operation.
#[derive(Clone, PartialEq, Eq)]
pub struct NetconfRecoveryHandle {
    pub(super) original: AuditOperationHandle,
}

impl NetconfRecoveryHandle {
    /// Encode for protected client recovery storage, never diagnostics.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        self.original.encode()
    }

    /// Decode bounded untrusted recovery data without admitting an effect.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        Ok(Self {
            original: AuditOperationHandle::decode(bytes)?,
        })
    }
}

impl fmt::Debug for NetconfRecoveryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfRecoveryHandle(<redacted>)")
    }
}

/// An authenticated original target result, independent of later reporting.
#[derive(Clone)]
pub struct NetconfAppliedReceipt {
    outcome: NetconfAppliedOutcome,
    recovery: NetconfRecoveryHandle,
    terminal_recorded: bool,
    completion_pending: bool,
    lock_ready: bool,
}

impl NetconfAppliedReceipt {
    /// Whether this original's required session lease publication completed.
    /// This is a historical acknowledgement, not a current lease capability;
    /// release still requires the SDK lease held by the original worker session.
    pub const fn lock_ready(&self) -> bool {
        self.lock_ready
    }
    /// The original disjoint target/lifecycle outcome, never an invented version.
    pub const fn outcome(&self) -> NetconfAppliedOutcome {
        self.outcome
    }

    /// Protected identity for authorized readback of this same operation.
    pub fn recovery_handle(&self) -> &NetconfRecoveryHandle {
        &self.recovery
    }

    /// Whether terminal persistence is known to have succeeded.
    /// Independent checkpoint acknowledgement can still be owed.
    pub const fn terminal_recorded(&self) -> bool {
        self.terminal_recorded
    }

    /// Whether the retained terminal/checkpoint obligation still needs recovery.
    pub const fn completion_pending(&self) -> bool {
        self.completion_pending
    }
}

impl fmt::Debug for NetconfAppliedReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfAppliedReceipt(<redacted>)")
    }
}

/// An authenticated rejection of the original, with its owed audit completion.
///
/// Rejection does not imply that terminal persistence or independent checkpoint
/// acknowledgement has finished. Keep the protected handle across a worker or
/// process restart when either obligation is still pending.
#[derive(Clone)]
pub struct NetconfRejectedReceipt {
    recovery: NetconfRecoveryHandle,
    terminal_recorded: bool,
    completion_pending: bool,
}

impl NetconfRejectedReceipt {
    /// Protected identity for authorized readback of this same rejection.
    pub fn recovery_handle(&self) -> &NetconfRecoveryHandle {
        &self.recovery
    }

    /// Whether the original rejection's terminal persistence is known complete.
    /// Independent checkpoint acknowledgement can still be owed.
    pub const fn terminal_recorded(&self) -> bool {
        self.terminal_recorded
    }

    /// Whether this rejection's retained terminal/checkpoint obligation is owed.
    pub const fn completion_pending(&self) -> bool {
        self.completion_pending
    }
}

impl fmt::Debug for NetconfRejectedReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetconfRejectedReceipt(<redacted>)")
    }
}

/// Result of one closed NETCONF submission or original-operation recovery.
///
/// An unresolved original grants no permission to prepare or submit replacement
/// work. Authenticated applied and rejected results retain their original result
/// and protected recovery handle when terminal/checkpoint reporting fails.
pub enum NetconfMutationResult {
    /// The original effect and this result were authenticated atomically.
    Applied(NetconfAppliedReceipt),
    /// The original was authoritatively rejected; audit completion can be owed.
    Rejected(NetconfRejectedReceipt),
    /// This admission was refused, without an authenticated original result.
    /// This does not resolve any other possibly transmitted operation.
    Refused(CommitError),
    /// Only lookup/completion of this original may resolve its outcome.
    Unknown(NetconfRecoveryHandle),
}

impl fmt::Debug for NetconfMutationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Applied(_) => "NetconfMutationResult::Applied(<redacted>)",
            Self::Rejected(_) => "NetconfMutationResult::Rejected(<redacted>)",
            Self::Refused(_) => "NetconfMutationResult::Refused(<redacted>)",
            Self::Unknown(_) => "NetconfMutationResult::Unknown(<redacted>)",
        })
    }
}

pub(super) fn from_original(original: OriginalReply) -> NetconfMutationResult {
    let recovery = NetconfRecoveryHandle {
        original: original.handle,
    };
    match original.result {
        TargetReply::Known {
            receipt,
            completion_pending,
        } if receipt.handle() == &recovery.original => match receipt.state() {
            AuditOperationState::TargetV1(result) => {
                NetconfMutationResult::Applied(NetconfAppliedReceipt {
                    outcome: result.outcome(),
                    recovery,
                    terminal_recorded: receipt.terminal_recorded() || !completion_pending,
                    completion_pending,
                    lock_ready: original.lock_ready,
                })
            }
            AuditOperationState::Rejected => {
                NetconfMutationResult::Rejected(NetconfRejectedReceipt {
                    recovery,
                    terminal_recorded: receipt.terminal_recorded() || !completion_pending,
                    completion_pending,
                })
            }
            _ => NetconfMutationResult::Unknown(recovery),
        },
        TargetReply::Refused(error) => NetconfMutationResult::Refused(match error {
            AuditAuthorityError::RecoveryRequired => {
                CommitError::recovery_required("NETCONF original recovery required")
            }
            _ => CommitError::new(
                CommitErrorCode::AdmissionRejected,
                "NETCONF operation admission was refused",
            ),
        }),
        TargetReply::Known { .. } | TargetReply::Unknown => {
            NetconfMutationResult::Unknown(recovery)
        }
    }
}
