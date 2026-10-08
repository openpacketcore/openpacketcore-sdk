//! Exact profile activation bound to the admitted configuration and all voters.

use super::*;
use sha2::{Digest, Sha256};

/// Internal certificate established only after the leader probes every voter.
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
    hash.update(b"openpacketcore/scope-store/profile/2/authority-rows/batch-1/lanes-8\0");
    for limit in [
        MAX_SCOPE_LEASE_RECORD_BYTES,
        crate::scope_batch::MAX_SCOPE_BATCH_CHILDREN,
        crate::scope_batch::MAX_SCOPE_BATCH_COMMAND_BYTES,
        crate::scope_batch::MAX_SCOPE_CHILD_VALUE_BYTES,
        crate::scope_batch::MAX_SCOPE_CHILD_CLAIMS,
        crate::scope_batch::SCOPE_COUNTERS,
        crate::scope_batch::SCOPE_BATCH_LANES,
    ] {
        hash.update((limit as u64).to_le_bytes());
    }
    for duration in [
        SCOPE_RENEWAL_INTERVAL,
        SCOPE_FORWARDING_GRACE,
        SCOPE_CLOCK_GUARD,
    ] {
        hash.update(duration.as_nanos().to_le_bytes());
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

    pub(crate) fn validate(&self) -> Result<(), ScopeLeaseError> {
        if self.profile != scope_profile_digest() || self.voters == [0; 32] {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        Ok(())
    }

    pub(crate) fn matches(&self, identity: SessionConsensusIdentity, voters: [u8; 32]) -> bool {
        self.validate().is_ok() && self.identity == identity && self.voters == voters
    }
}

redacted_debug!(ScopeProfileActivation);
