//! # Operator Lifecycle Foundation Crate
//!
//! Exposes structures and algorithms for Kubernetes operator lifecycle states,
//! config application decisions, preflight admission checks, and upgrade/drain planning.

#![forbid(unsafe_code)]

pub mod admission;
pub mod compatibility;
pub mod config_apply;
pub mod drain_upgrade;
pub mod phase;

// Re-export key types
pub use admission::{
    evaluate_admission, sanitize_denial_message, AdminAuthSpec, AdmissionRequest,
    AdmissionResponse, AdmissionStatus, IdentitySpec, ResourceProfileSpec,
};
pub use compatibility::{
    CompatibilityBlockReason, CompatibilityDecision, CompatibilityEvidence, CompatibilityFeature,
    CompatibilityMatrix, CompatibilityRule, MigrationCompatibility, NfReleaseDescriptor,
    OperatorReleaseDescriptor, SupportedVersionRange,
};
pub use config_apply::{
    evaluate_config_apply, evaluate_rollback_target, CandidateMetadata, ConfigApplyDecision,
    PendingConfirmationState, StoredConfigMetadata,
};
pub use drain_upgrade::{generate_upgrade_plan, UpgradeAction, UpgradePlan};
pub use phase::{
    ConditionSeverity, ConditionStatus, LifecycleCondition, LifecyclePhase, LifecycleStatus,
};
