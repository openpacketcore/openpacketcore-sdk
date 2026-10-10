//! Exact profile activation bound to the admitted configuration and all voters.

use super::*;
use sha2::{Digest, Sha256};

/// Internal certificate established by unanimous activation or carried through
/// an exact membership transition with committed joining-voter evidence.
/// Its durable row is separate from request receipts and checked again at apply.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeProfileActivation {
    pub(crate) identity: SessionConsensusIdentity,
    pub(crate) voters: [u8; 32],
    pub(crate) profile: [u8; 32],
}

pub(crate) fn scope_profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/scope-store/profile/4/untimed-authority/boot-key-1/closure-1/stable-counter-birth-floors/initialized-ledger-1/namespace-1/batch-3/lanes-8/independent-lanes-1/exact-cancel-1/complete-read-set-1/coherent-reopen-1/monotone-lane-receipts-1/membership-continuity-1/coherent-restore-scan-1\0");
    for limit in [
        MAX_SCOPE_AUTHORITY_RECORD_BYTES,
        crate::scope_batch::MAX_SCOPE_BATCH_CHILDREN,
        crate::scope_batch::MAX_SCOPE_BATCH_COMMAND_BYTES,
        crate::scope_batch::MAX_SCOPE_BATCH_LEDGER_BYTES,
        crate::scope_batch::MAX_SCOPE_BATCH_REOPEN_BYTES,
        crate::scope_batch::MAX_SCOPE_CHILD_VALUE_BYTES,
        crate::scope_batch::MAX_SCOPE_CHILD_CLAIMS,
        crate::scope_batch::SCOPE_COUNTERS,
        crate::scope_batch::SCOPE_BATCH_LANES,
    ] {
        hash.update((limit as u64).to_le_bytes());
    }
    hash.finalize().into()
}

impl ScopeProfileActivation {
    pub(crate) fn new(identity: SessionConsensusIdentity, voters: [u8; 32]) -> Self {
        Self {
            identity,
            voters,
            profile: scope_profile_digest(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ScopeAuthorityError> {
        if self.profile != scope_profile_digest() || self.voters == [0; 32] {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(())
    }

    pub(crate) fn matches(&self, identity: SessionConsensusIdentity, voters: [u8; 32]) -> bool {
        self.validate().is_ok() && self.identity == identity && self.voters == voters
    }
}

redacted_debug!(ScopeProfileActivation);

/// Replicated attestation that every joining voter supports the exact active
/// profile. It is bound to one transition and both of its voter configurations;
/// a process-local capability probe never authorizes the successor by itself.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeProfileContinuation {
    pub(crate) transition_id: [u8; 16],
    pub(crate) transition_digest: [u8; 32],
    pub(crate) predecessor: ScopeProfileActivation,
    pub(crate) successor: ScopeProfileActivation,
}

impl ScopeProfileContinuation {
    pub(crate) fn validate(&self) -> Result<(), ScopeAuthorityError> {
        self.predecessor.validate()?;
        self.successor.validate()?;
        if self.predecessor.identity.cluster_id() != self.successor.identity.cluster_id()
            || self
                .predecessor
                .identity
                .configuration_epoch()
                .get()
                .checked_add(1)
                != Some(self.successor.identity.configuration_epoch().get())
        {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(())
    }
}

redacted_debug!(ScopeProfileContinuation);
