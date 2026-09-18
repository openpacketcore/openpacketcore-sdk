use super::AuditKeyRing;
use crate::audit_authority::ledger::{authenticate, verify, LedgerState};
use crate::audit_authority::AuditAuthorityError;
use crate::ConfigConsensusIdentity;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

const CHECKPOINT_DOMAIN: &[u8] = b"openpacketcore/management-audit/external-checkpoint/v1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointBody {
    pub(crate) version: u16,
    pub(crate) identity: ConfigConsensusIdentity,
    pub(crate) sequence: u64,
    pub(crate) root_anchor: [u8; 32],
    pub(crate) anchor: [u8; 32],
    pub(crate) epoch_at_sequence: u64,
    pub(crate) signing_epoch: u64,
    pub(crate) acknowledged_export: [u8; 32],
}

/// SDK-authenticated monotonic high-water mark. The platform stores this opaque
/// object outside the database's backup/restore and authorization domain.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpoint {
    pub(crate) body: CheckpointBody,
    mac: [u8; 32],
}

impl AuditCheckpoint {
    /// Bounded opaque platform representation; not a diagnostic value.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        let bytes = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if bytes.len() > 4096 {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(bytes)
    }
    /// Decode untrusted platform bytes. Only SDK verification admits this value.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        if bytes.len() > 4096 {
            return Err(AuditAuthorityError::InvalidInput);
        }
        serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)
    }
    /// Non-secret monotonic ordinal the external authority may compare for its
    /// own CAS policy. This accessor does not authenticate the object.
    pub const fn sequence(&self) -> u64 {
        self.body.sequence
    }

    pub(crate) fn issue(
        keys: &AuditKeyRing,
        body: CheckpointBody,
    ) -> Result<Self, AuditAuthorityError> {
        let mac = authenticate(keys.key(body.signing_epoch)?, CHECKPOINT_DOMAIN, &body)?;
        Ok(Self { body, mac })
    }
    pub(crate) fn verify(
        &self,
        keys: &AuditKeyRing,
        identity: ConfigConsensusIdentity,
    ) -> Result<(), AuditAuthorityError> {
        if self.body.version != 1 || self.body.identity != identity {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(
            keys.key(self.body.signing_epoch)?,
            CHECKPOINT_DOMAIN,
            &self.body,
            &self.mac,
        )
    }
}

impl std::fmt::Debug for AuditCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditCheckpoint(<redacted>)")
    }
}

/// An ambiguous CAS is not an acknowledgement. The SDK must read back before
/// issuing any pruning authority; a definitive conflict also requires readback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditCheckpointAdvance {
    /// The exact requested value is durable in the external monotonic authority.
    Applied,
    /// Another value won the CAS; no advance is assumed.
    Conflict,
    /// The operation may have applied and must be reconciled by lookup.
    Unknown,
}

/// Platform-owned monotonic persistence and recipient/administrative
/// authorization. Implementations must not share the SQLite restore domain,
/// decrease the sequence, replace an equal sequence, or implement blind writes.
/// The SDK authenticates all bytes and verifies each compare/advance by readback.
#[async_trait]
pub trait AuditCheckpointPort: Send + Sync {
    /// Read the current value under the platform's authoritative consistency rule.
    async fn load(
        &self,
        identity: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError>;
    /// Atomically compare the complete opaque prior value and advance. `None`
    /// means explicit provisioning of an absent external row, never a reset.
    async fn compare_advance(
        &self,
        identity: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError>;
}

impl LedgerState {
    pub(crate) fn matches_checkpoint(
        &self,
        checkpoint: &AuditCheckpoint,
    ) -> Result<(), AuditAuthorityError> {
        let chain = self
            .continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let body = &checkpoint.body;
        if body.identity != self.identity {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if body.sequence > self.sequence {
            return Err(AuditAuthorityError::RollbackDetected);
        }
        if body.sequence < self.floor {
            return Err(AuditAuthorityError::RollbackDetected);
        }
        let (root, anchor, epoch) = if body.sequence == self.floor {
            (self.predecessor, chain.floor_anchor, chain.floor_epoch)
        } else {
            let index = usize::try_from(body.sequence - self.floor - 1)
                .map_err(|_| AuditAuthorityError::BindingMismatch)?;
            let entry = self
                .entries
                .get(index)
                .ok_or(AuditAuthorityError::BindingMismatch)?;
            let row = chain
                .rows
                .get(index)
                .ok_or(AuditAuthorityError::BindingMismatch)?;
            let epoch = match &entry.payload {
                crate::audit_authority::ledger::EntryPayload::KeyTransition(t) => t.body.to_epoch,
                _ => row.epoch,
            };
            (entry.mac, row.signature, epoch)
        };
        if body.root_anchor != root || body.anchor != anchor || body.epoch_at_sequence != epoch {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }
}
