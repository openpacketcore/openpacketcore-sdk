//! Authenticated signing epochs, frozen exports and external rollback checkpoints.
//!
//! These keys do not replace configuration integrity or operation-handle keys.
//! A required checkpoint provider must live outside the database restore domain.

mod keys;
pub use keys::{AuditKeyRing, AuditKeyTransition, AuditSigningKey, MAX_AUDIT_SIGNING_EPOCHS};

pub(crate) mod chain;
pub(crate) mod checkpoint;
pub(crate) mod export;
pub use checkpoint::{AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort};
pub use export::{
    AuditExportCursor, AuditExportManifest, AuditExportPage, AuditExportSession,
    AuditExportVerifier, VerifiedAuditExport,
};

#[cfg(test)]
mod tests;

use super::AuditAuthorityError;
use std::sync::Arc;

/// Required signing/checkpoint providers and fixed local resource bounds.
/// Merely provisioning a newer epoch in `keys` never activates it.
pub struct AuditContinuityPolicy {
    pub(crate) keys: Arc<AuditKeyRing>,
    pub(crate) checkpoints: Arc<dyn AuditCheckpointPort>,
    pub(crate) initial_epoch: u64,
    pub(crate) exports: Arc<tokio::sync::Semaphore>,
}

impl AuditContinuityPolicy {
    /// Configure one through eight simultaneous frozen exports, each bounded by
    /// the ledger's maximum 4096 rows and 16 MiB representation. Provider I/O is
    /// bounded by the existing configuration operation timeout.
    pub fn new(
        keys: AuditKeyRing,
        checkpoints: Arc<dyn AuditCheckpointPort>,
        initial_epoch: u64,
        max_exports: usize,
    ) -> Result<Self, AuditAuthorityError> {
        keys.key(initial_epoch)?;
        if !(1..=8).contains(&max_exports) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(Self {
            keys: Arc::new(keys),
            checkpoints,
            initial_epoch,
            exports: Arc::new(tokio::sync::Semaphore::new(max_exports)),
        })
    }
}

impl std::fmt::Debug for AuditContinuityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditContinuityPolicy(<redacted>)")
    }
}
