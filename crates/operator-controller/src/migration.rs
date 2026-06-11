//! YANG and state migration orchestration (GAP-009-005)
//!
//! Enforces explicit migration plans, preflight safety gates, and fail-closed execution.
//! Unsafe migrations are blocked if commit confirmations are pending, critical alarms are active,
//! recovery is required, or preflight admission fails.

use opc_alarm::{Alarm, ReadinessImpact};
use opc_types::ConfigVersion;
use operator_lifecycle::{
    evaluate_admission, AdmissionRequest, LifecyclePhase, LifecycleStatus, PendingConfirmationState,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyClassification {
    /// Safe to apply online during normal operation.
    SafeOnline,
    /// Unsafe online; requires traffic/session draining.
    UnsafeOnline,
    /// High-risk; requires workload fencing or full offline execution.
    HighRiskOffline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MigrationStep {
    /// Validate source YANG configuration / state schema.
    ValidateSourceSchema,
    /// Apply YANG schema transformer over the config database.
    ApplyYangSchemaTransform { xpath: String },
    /// Apply state/session store column/table/key schema migration.
    MigrateSessionStoreSchema { table: String },
    /// Run integrity validation checks on target config / state.
    VerifyTargetIntegrity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationPlan {
    pub source_version: ConfigVersion,
    pub target_version: ConfigVersion,
    pub steps: Vec<MigrationStep>,
    pub rollback_eligible: bool,
    /// References to evidence artifacts (e.g., schemas, signatures, pre-checks).
    pub evidence_ids: Vec<String>,
    pub safety_classification: SafetyClassification,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MigrationBlockReason {
    #[error("Migration blocked: invalid migration plan: {0}")]
    InvalidPlan(String),
    #[error("Migration blocked: node is currently in RecoveryRequired state")]
    RecoveryRequired,
    #[error("Migration blocked: critical readiness-impact alarm is active on the node")]
    CriticalAlarmsActive,
    #[error("Migration blocked: another configuration change is currently pending confirmation")]
    PendingCommitConfirmation,
    #[error("Migration blocked: preflight admission check failed: {0}")]
    AdmissionFailed(String),
}

fn invalid_plan(message: &str) -> MigrationBlockReason {
    MigrationBlockReason::InvalidPlan(operator_lifecycle::sanitize_denial_message(message))
}

/// Validates the static migration plan before runtime readiness checks execute.
pub fn validate_migration_plan(plan: &MigrationPlan) -> Result<(), MigrationBlockReason> {
    if plan.target_version <= plan.source_version {
        return Err(invalid_plan(
            "target version must be greater than source version",
        ));
    }

    if plan.steps.is_empty() {
        return Err(invalid_plan(
            "migration plan must contain at least one step",
        ));
    }

    if plan.evidence_ids.is_empty() || plan.evidence_ids.iter().any(|id| id.trim().is_empty()) {
        return Err(invalid_plan(
            "migration plan must reference non-empty evidence identifiers",
        ));
    }

    for step in &plan.steps {
        match step {
            MigrationStep::ApplyYangSchemaTransform { xpath } if xpath.trim().is_empty() => {
                return Err(invalid_plan("migration step contains an empty YANG path"));
            }
            MigrationStep::MigrateSessionStoreSchema { table } if table.trim().is_empty() => {
                return Err(invalid_plan("migration step contains an empty state table"));
            }
            _ => {}
        }
    }

    if matches!(
        plan.safety_classification,
        SafetyClassification::UnsafeOnline | SafetyClassification::HighRiskOffline
    ) && !plan.rollback_eligible
    {
        return Err(invalid_plan(
            "unsafe migration plans must declare confirmed rollback eligibility",
        ));
    }

    Ok(())
}

/// Evaluates if a migration plan is safe to execute under the current system state.
pub fn evaluate_migration_readiness(
    plan: &MigrationPlan,
    status: &LifecycleStatus,
    pending_confirmation: Option<&PendingConfirmationState>,
    active_alarms: &[Alarm],
    admission_request: &AdmissionRequest,
) -> Result<(), MigrationBlockReason> {
    validate_migration_plan(plan)?;

    // 1. Block if node is in RecoveryRequired state
    if status.phase == LifecyclePhase::RecoveryRequired {
        return Err(MigrationBlockReason::RecoveryRequired);
    }

    // 2. Block if critical alarms are active
    let has_critical_alarm = active_alarms
        .iter()
        .any(|alarm| alarm.readiness_impact() == ReadinessImpact::ForceNotReady);
    if has_critical_alarm {
        return Err(MigrationBlockReason::CriticalAlarmsActive);
    }

    // 3. Block if a config confirmation is pending
    if pending_confirmation.is_some() {
        return Err(MigrationBlockReason::PendingCommitConfirmation);
    }

    // 4. Block if preflight admission fails
    let admission_resp = evaluate_admission(admission_request);
    if !admission_resp.allowed {
        let reason = if let Some(ref s) = admission_resp.status {
            s.message.clone()
        } else {
            "Admission denied without details".to_string()
        };
        return Err(MigrationBlockReason::AdmissionFailed(reason));
    }

    // 5. Evaluate compatibility matrix and migration path
    if let Some(ref matrix) = admission_request.compatibility_matrix {
        let op = match admission_request.operator_release.as_ref() {
            Some(o) => o,
            None => {
                return Err(MigrationBlockReason::AdmissionFailed(
                    "Missing operator release descriptor in admission request".to_string(),
                ))
            }
        };
        let nf = match admission_request.nf_release.as_ref() {
            Some(n) => n,
            None => {
                return Err(MigrationBlockReason::AdmissionFailed(
                    "Missing NF release descriptor in admission request".to_string(),
                ))
            }
        };
        let ev = match admission_request.evidence.as_ref() {
            Some(e) => e,
            None => {
                return Err(MigrationBlockReason::AdmissionFailed(
                    "Missing evidence list in admission request".to_string(),
                ))
            }
        };
        let available_evidence: HashSet<&str> = ev
            .iter()
            .map(|evidence| evidence.evidence_id.as_str())
            .collect();
        let missing_evidence: Vec<_> = plan
            .evidence_ids
            .iter()
            .filter(|evidence_id| !available_evidence.contains(evidence_id.as_str()))
            .cloned()
            .collect();
        if !missing_evidence.is_empty() {
            let msg = format!(
                "Migration plan references evidence ids not present in the admission compatibility evidence: {}",
                missing_evidence.join(", ")
            );
            return Err(MigrationBlockReason::AdmissionFailed(
                operator_lifecycle::sanitize_denial_message(&msg),
            ));
        }

        let src_str = format!("{}.0.0", plan.source_version.get());
        let tgt_str = format!("{}.0.0", plan.target_version.get());

        match matrix.evaluate_migration(op, nf, &src_str, &tgt_str, ev) {
            operator_lifecycle::CompatibilityDecision::Allowed => {}
            operator_lifecycle::CompatibilityDecision::Blocked(reason) => {
                return Err(MigrationBlockReason::AdmissionFailed(format!(
                    "Migration path not allowed by policy: {}",
                    reason
                )));
            }
        }

        // Reject unsafe or high-risk migration steps unless explicitly allowed by policy and rollback constraints are satisfied.
        if matches!(
            plan.safety_classification,
            SafetyClassification::UnsafeOnline | SafetyClassification::HighRiskOffline
        ) {
            match matrix.migration_allows_rollback(op, nf, &src_str, &tgt_str, ev) {
                operator_lifecycle::CompatibilityDecision::Allowed => {}
                operator_lifecycle::CompatibilityDecision::Blocked(reason) => {
                    return Err(MigrationBlockReason::AdmissionFailed(format!(
                        "Unsafe or high-risk migration steps require policy to explicitly permit rollback: {}",
                        reason
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Interface driver for state / schema modifications during migration.
pub trait MigrationDriver {
    /// Executes a single migration step.
    fn execute_step(&mut self, step: &MigrationStep) -> Result<(), String>;
    /// Marks the target version as successfully published/committed.
    fn publish_success(&mut self, target_version: ConfigVersion) -> Result<(), String>;
}

/// Runs a migration plan sequentially. If any step fails, the migration is aborted
/// and fails closed; the target version is never published.
pub fn execute_migration<D: MigrationDriver>(
    plan: &MigrationPlan,
    driver: &mut D,
) -> Result<(), String> {
    if let Err(err) = validate_migration_plan(plan) {
        return Err(operator_lifecycle::sanitize_denial_message(
            &err.to_string(),
        ));
    }

    for step in &plan.steps {
        if let Err(e) = driver.execute_step(step) {
            let sanitized = operator_lifecycle::sanitize_denial_message(&e);
            return Err(format!("Migration aborted during step: {}", sanitized));
        }
    }

    // Finalize publish success
    if let Err(e) = driver.publish_success(plan.target_version) {
        let sanitized = operator_lifecycle::sanitize_denial_message(&e);
        return Err(format!("Migration finalize failed: {}", sanitized));
    }

    Ok(())
}
