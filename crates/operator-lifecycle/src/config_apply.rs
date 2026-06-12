use crate::phase::{LifecyclePhase, LifecycleStatus};
use opc_alarm::{Alarm, ReadinessImpact};
use opc_types::{ConfigVersion, SchemaDigest};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Metadata for a candidate configuration being evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMetadata {
    pub version: ConfigVersion,
    pub schema_digest: SchemaDigest,
    pub is_commit_confirmed: bool,
    pub confirm_timeout_secs: Option<u64>,
    pub operator_release: Option<crate::compatibility::OperatorReleaseDescriptor>,
    pub nf_release: Option<crate::compatibility::NfReleaseDescriptor>,
    pub compatibility_matrix: Option<crate::compatibility::CompatibilityMatrix>,
    pub evidence: Option<Vec<crate::compatibility::CompatibilityEvidence>>,
}

/// Representation of a pending commit-confirmed state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConfirmationState {
    pub version: ConfigVersion,
    pub previous_confirmed_version: ConfigVersion,
    pub applied_at: OffsetDateTime,
    pub timeout_secs: u64,
}

/// Decisions returned by the config-apply decision logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigApplyDecision {
    /// Proceed with config application.
    Apply,
    /// Configuration matches current running config; nothing to do.
    NoOp,
    /// Configuration is rejected. Contains sanitized redaction-safe reason.
    Reject(String),
    /// Trigger a rollback to the specified target version.
    Rollback {
        target_version: ConfigVersion,
        reason: String,
    },
    /// The system is in RecoveryRequired state; manual/automated recovery is required first.
    RecoveryRequired(String),
    /// Wait for session draining or workload preparation before applying.
    WaitForDrain,
}

/// Evaluates desired config application request and returns the decision.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_config_apply(
    desired_generation: i64,
    current_observed_generation: i64,
    current_version: ConfigVersion,
    current_digest: SchemaDigest,
    candidate: Option<&CandidateMetadata>,
    lifecycle_status: &LifecycleStatus,
    active_alarms: &[Alarm],
    pending_confirmation: Option<&PendingConfirmationState>,
    preflight_report: Option<&opc_node_resources::DataPlanePreflightReport>,
    current_time: OffsetDateTime,
) -> ConfigApplyDecision {
    // 1. RecoveryRequired blocks new config apply
    if lifecycle_status.phase == LifecyclePhase::RecoveryRequired {
        return ConfigApplyDecision::RecoveryRequired(
            "State machine recovery required before new configurations can be applied".to_string(),
        );
    }

    // 2. Critical active alarm blocks readiness/admission for rollout
    let has_critical_alarm = active_alarms
        .iter()
        .any(|alarm| alarm.readiness_impact() == ReadinessImpact::ForceNotReady);
    if has_critical_alarm {
        return ConfigApplyDecision::Reject(
            "Rollout blocked: one or more critical alarms are active on the node".to_string(),
        );
    }

    // 2b. Data-plane preflight check must pass
    if let Some(preflight) = preflight_report {
        if !preflight.passed {
            return ConfigApplyDecision::Reject(format!(
                "Rollout blocked: data-plane preflight check failed: {}",
                preflight.messages.join("; ")
            ));
        }
    }

    // Compatibility policy check
    if let Some(cand) = candidate {
        if let Some(ref matrix) = cand.compatibility_matrix {
            let op = match cand.operator_release.as_ref() {
                Some(o) => o,
                None => {
                    return ConfigApplyDecision::Reject(
                        "Missing operator release descriptor in candidate".to_string(),
                    )
                }
            };
            let nf = match cand.nf_release.as_ref() {
                Some(n) => n,
                None => {
                    return ConfigApplyDecision::Reject(
                        "Missing NF release descriptor in candidate".to_string(),
                    )
                }
            };
            let ev = match cand.evidence.as_ref() {
                Some(e) => e,
                None => {
                    return ConfigApplyDecision::Reject(
                        "Missing evidence list in candidate".to_string(),
                    )
                }
            };

            // Evaluate general target compatibility (support for NF, config/state schema versions)
            match matrix.evaluate_compatibility(
                op,
                nf,
                opc_runtime::profile::RuntimeMode::Production,
                "consensus",
                "quorum",
                true,
                true,
                true,
                ev,
            ) {
                crate::compatibility::CompatibilityDecision::Allowed => {}
                crate::compatibility::CompatibilityDecision::Blocked(reason) => {
                    return ConfigApplyDecision::Reject(format!(
                        "Compatibility check blocked: {reason}"
                    ));
                }
            }

            // Check migration path if this is a change in version
            if cand.version != current_version {
                let src_str = format!("{}.0.0", current_version.get());
                let tgt_str = format!("{}.0.0", cand.version.get());

                match matrix.evaluate_migration(op, nf, &src_str, &tgt_str, ev) {
                    crate::compatibility::CompatibilityDecision::Allowed => {}
                    crate::compatibility::CompatibilityDecision::Blocked(reason) => {
                        return ConfigApplyDecision::Reject(format!(
                            "Migration path blocked: {reason}"
                        ));
                    }
                }
            }
        }
    }

    // 3. Enforce commit-confirmed deadlines and rollback target selection
    if let Some(pc) = pending_confirmation {
        let expiration = pc.applied_at + time::Duration::seconds(pc.timeout_secs as i64);
        if current_time > expiration {
            // Rollback deadline expired: Choose previous confirmed config (never pending/unconfirmed config)
            return ConfigApplyDecision::Rollback {
                target_version: pc.previous_confirmed_version,
                reason: "Commit-confirmed deadline expired without operator confirmation"
                    .to_string(),
            };
        }

        // Pending confirmation is active (not expired).
        // Check if an unsafe upgrade is attempted while a configuration is still pending confirmation.
        if let Some(cand) = candidate {
            if cand.version != pc.version {
                return ConfigApplyDecision::Reject(
                    "Unsafe upgrade blocked: another configuration is currently pending confirmation".to_string(),
                );
            }
        }
    }

    // 4. Degraded-but-serving state allows only explicitly safe operations
    if lifecycle_status.phase == LifecyclePhase::Degraded {
        if let Some(cand) = candidate {
            // In Degraded mode, let's say only configs that are rollbacks (target matches current_version
            // or is an older version than current_version) are safe, or if candidate has a digest that
            // equals the current running digest.
            let is_downgrade = cand.version <= current_version;
            if !is_downgrade {
                return ConfigApplyDecision::Reject(
                    "Upgrade rejected: node is in Degraded state. Only rollback or safe recovery operations are permitted".to_string(),
                );
            }
        }
    }

    // 5. NoOp vs Apply
    if let Some(cand) = candidate {
        if desired_generation == current_observed_generation
            && cand.version == current_version
            && cand.schema_digest == current_digest
        {
            ConfigApplyDecision::NoOp
        } else {
            ConfigApplyDecision::Apply
        }
    } else if desired_generation == current_observed_generation {
        ConfigApplyDecision::NoOp
    } else {
        ConfigApplyDecision::Apply
    }
}

/// Selects the rollback version given target target and configuration history,
/// ensuring only confirmed configs are chosen.
pub fn evaluate_rollback_target(
    target: opc_config_model::RollbackTarget,
    history: &[StoredConfigMetadata],
) -> Result<ConfigVersion, String> {
    use opc_config_model::RollbackTarget;

    match target {
        RollbackTarget::Previous => {
            // Find the most recent confirmed config in the history, excluding any unconfirmed configs.
            for meta in history.iter().rev() {
                if meta.is_confirmed {
                    return Ok(meta.version);
                }
            }
            Err(
                "Rollback failed: no previously confirmed configuration found in history"
                    .to_string(),
            )
        }
        RollbackTarget::Version(v) => {
            if let Some(meta) = history.iter().find(|m| m.version == v) {
                if meta.is_confirmed {
                    Ok(meta.version)
                } else {
                    Err("Rollback failed: selected target version is not confirmed".to_string())
                }
            } else {
                Err("Rollback failed: selected target version not found in history".to_string())
            }
        }
        RollbackTarget::TxId(tx) => {
            if let Some(meta) = history.iter().find(|m| m.tx_id == tx) {
                if meta.is_confirmed {
                    Ok(meta.version)
                } else {
                    Err("Rollback failed: selected target transaction is not confirmed".to_string())
                }
            } else {
                Err("Rollback failed: selected target transaction not found in history".to_string())
            }
        }
        RollbackTarget::Label(lbl) => {
            if let Some(meta) = history.iter().find(|m| m.label.as_ref() == Some(&lbl)) {
                if meta.is_confirmed {
                    Ok(meta.version)
                } else {
                    Err("Rollback failed: selected target label is not confirmed".to_string())
                }
            } else {
                Err("Rollback failed: selected target label not found in history".to_string())
            }
        }
    }
}

/// Metadata stored in history for rollback target evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConfigMetadata {
    pub version: ConfigVersion,
    pub tx_id: opc_types::TxId,
    pub parent_tx_id: Option<opc_types::TxId>,
    pub is_confirmed: bool,
    pub label: Option<String>,
}
