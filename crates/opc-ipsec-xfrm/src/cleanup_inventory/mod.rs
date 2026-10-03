//! Internal, cleanup-only persistence foundation. No kernel removal authority.

mod api;
mod codec;
mod filesystem;
mod index;
mod node;
mod store;
mod tree;

pub(crate) use api::{BoundInventory, PendingInventory};
pub use api::{
    XfrmCleanupInventoryBinding, XfrmCleanupInventoryBindingConfig, XfrmCleanupInventoryConfig,
    XfrmCleanupInventoryKey, XfrmCleanupInventoryLimits, XfrmCleanupInventoryOpenMode,
    XfrmCleanupInventoryStatus,
};

use std::fmt;

use crate::{PolicyParameters, SaRelocationIdentity};

// These semantic bounds are provisional until the measured format review.
const CANDIDATES_PER_OBJECT: usize = 2;
const COVERAGE_MEMBERS: usize = crate::XFRM_OBJECT_ROSTER_MAX_MEMBERS;
const POLICY_TEMPLATES: usize = 6;

/// Value-free cleanup-inventory failure. No path, record or key is rendered.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum XfrmCleanupInventoryError {
    #[error("xfrm_cleanup_inventory_unavailable")]
    /// The retained writer can no longer be used.
    Unavailable,
    #[error("xfrm_cleanup_inventory_malformed")]
    /// A persisted value or structure is malformed.
    Malformed,
    #[error("xfrm_cleanup_inventory_capacity")]
    /// Configured capacity or a byte budget is insufficient.
    Capacity,
    #[error("xfrm_cleanup_inventory_allocation")]
    /// A bounded allocation could not be reserved.
    Allocation,
    #[error("xfrm_cleanup_inventory_authentication")]
    /// Authentication or key validation failed.
    Authentication,
    #[error("xfrm_cleanup_inventory_wrong_binding")]
    /// The namespace, directory, revision or store binding changed.
    WrongBinding,
    #[error("xfrm_cleanup_inventory_duplicate")]
    /// Conflicting ownership or duplicated records were found.
    Duplicate,
    #[error("xfrm_cleanup_inventory_exact_removal_unavailable")]
    /// The exact-removal prerequisite is unavailable.
    ExactRemovalUnavailable,
    #[error("xfrm_cleanup_inventory_storage")]
    /// A storage operation failed.
    Storage,
    #[error("xfrm_cleanup_inventory_store_busy")]
    /// Another holder owns the permanent directory lease.
    StoreBusy,
    #[error("xfrm_cleanup_inventory_invalid_root")]
    /// The configured directory path or metadata is untrusted.
    InvalidRoot,
}

type InventoryError = XfrmCleanupInventoryError;

#[derive(Clone, PartialEq, Eq)]
enum CleanupImage {
    Sa {
        identity: SaRelocationIdentity,
        immutable_fingerprint: [u8; 32],
    },
    Policy(PolicyParameters),
}

#[derive(Clone, PartialEq, Eq)]
struct CandidateImage {
    image: CleanupImage,
    pre_effect_absence: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectPhase {
    Reserved,
    Issuing,
    Owned,
    Indeterminate,
}

// Position is only a locator. Every use must also validate the serial and kind.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RecordLink {
    position: u32,
    serial: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct ObjectRecord {
    serial: u64,
    generation: u64,
    phase: ObjectPhase,
    reserved_images: u8,
    candidates: Vec<CandidateImage>,
    coverage: Option<RecordLink>,
}

#[derive(Clone, PartialEq, Eq)]
struct CoverageMember {
    object: RecordLink,
    absence: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionFamily {
    Object,
    Relocation,
    Roster,
}

#[derive(Clone, PartialEq, Eq)]
struct CoverageRecord {
    serial: u64,
    inventory_generation: u64,
    family: TransactionFamily,
    store_incarnation: [u8; 16],
    correlation: [u8; 16],
    operation_generation: u64,
    request_fingerprint: [u8; 32],
    members: Vec<CoverageMember>,
    settlement: Option<[u8; 32]>,
}

#[derive(Clone, PartialEq, Eq)]
enum InventoryRecord {
    Object(ObjectRecord),
    Coverage(CoverageRecord),
}

impl fmt::Debug for InventoryRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InventoryRecord(<redacted>)")
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod existing_auth_tests;
