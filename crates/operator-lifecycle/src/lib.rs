//! # Operator Lifecycle Foundation Crate
//!
//! Exposes structures and algorithms for Kubernetes operator lifecycle states,
//! config application decisions, preflight admission checks, and upgrade/drain planning.

#![forbid(unsafe_code)]

/// Contract version for the Rust↔Go JSON CLI boundary.
/// Increment this when the request/response envelope shape changes.
pub const CONTRACT_VERSION: u32 = 1;

pub mod admission;
pub mod compatibility;
pub mod config_apply;
pub mod drain_upgrade;
pub mod phase;
pub mod reconcile;

// Re-export key types
pub use admission::{
    evaluate_admission, ipsec_gateway_profile_from_spec, sanitize_denial_message, AdminAuthSpec,
    AdmissionRequest, AdmissionResponse, AdmissionStatus, IdentitySpec, IpsecNetworkAttachmentSpec,
    ResourceProfileSpec,
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
pub use reconcile::{
    lifecycle_condition_intent, reject_app_config_fields, AlarmConditionIntent, AlarmEventIntent,
    AppConfigMetadata, BootstrapRef, BootstrapRefKind, CnfImageIntent, CnfWorkloadIntent,
    ConflictRetryIntent, ManagementExposureIntent, NetworkAttachmentIntent, NetworkAttachmentKind,
    PlacementIntent, ReconcileIntentError, ReplicaIntent, SessionStoreRef, StatusPatchIntent,
    TrafficStatusIntent, UpgradeDrainPolicy,
};
