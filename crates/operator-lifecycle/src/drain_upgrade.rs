use crate::config_apply::PendingConfirmationState;
use crate::phase::LifecyclePhase;
use opc_alarm::{Alarm, ReadinessImpact};
use opc_types::ConfigVersion;
use serde::{Deserialize, Serialize};

/// Concrete actions representing steps in a rollout or upgrade plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeAction {
    /// Deregister the network function instance from NRF.
    DeregisterFromNrf,
    /// Drain active user sessions from this network function instance.
    DrainSessions,
    /// Apply the desired configuration.
    ApplyConfig,
    /// Confirm the pending commit-confirmed configuration.
    ConfirmConfig,
    /// Rollback the config to the previous confirmed configuration.
    RollbackConfig,
    /// Run recovery reconciliation.
    TriggerRecovery,
    /// Fence traffic/workload administratively.
    FenceWorkload,
    /// Wait for session store replication/quorum.
    WaitForQuorum,
}

impl UpgradeAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeregisterFromNrf => "DeregisterFromNrf",
            Self::DrainSessions => "DrainSessions",
            Self::ApplyConfig => "ApplyConfig",
            Self::ConfirmConfig => "ConfirmConfig",
            Self::RollbackConfig => "RollbackConfig",
            Self::TriggerRecovery => "TriggerRecovery",
            Self::FenceWorkload => "FenceWorkload",
            Self::WaitForQuorum => "WaitForQuorum",
        }
    }
}

/// A plan produced by the operator drain/upgrade planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePlan {
    /// Sequence of actions to perform.
    pub actions: Vec<UpgradeAction>,
    /// Whether rollback is available if this plan fails.
    pub rollback_eligible: bool,
    /// Whether the plan is currently blocked from execution.
    pub is_blocked: bool,
    /// The sanitized reason if the plan is blocked.
    pub block_reason: Option<String>,
}

/// Primitives to plan drains and upgrades.
#[allow(clippy::too_many_arguments)]
pub fn generate_upgrade_plan(
    current_phase: LifecyclePhase,
    runtime_ready: bool,
    active_alarms: &[Alarm],
    current_config_version: ConfigVersion,
    desired_config_version: ConfigVersion,
    pending_confirmation: Option<&PendingConfirmationState>,
    session_ha_healthy: bool,
    recovery_fence_active: bool,
    rollback_available: bool,
) -> UpgradePlan {
    let mut actions = Vec::new();
    let is_blocked = false;
    let block_reason = None;

    // 1. Critical active alarms block any rollout/upgrade
    let has_critical_alarm = active_alarms
        .iter()
        .any(|alarm| alarm.readiness_impact() == ReadinessImpact::ForceNotReady);
    if has_critical_alarm {
        return UpgradePlan {
            actions: vec![],
            rollback_eligible: rollback_available,
            is_blocked: true,
            block_reason: Some(
                "Critical active alarm blocks readiness/admission for rollout".to_string(),
            ),
        };
    }

    // 2. Recovery required state or active recovery fence blocks upgrades
    if current_phase == LifecyclePhase::RecoveryRequired || recovery_fence_active {
        return UpgradePlan {
            actions: vec![UpgradeAction::TriggerRecovery],
            rollback_eligible: rollback_available,
            is_blocked: true,
            block_reason: Some(
                "Upgrade blocked: system is in RecoveryRequired state or recovery fence is active"
                    .to_string(),
            ),
        };
    }

    // 3. Pending commit-confirmed config blocks unsafe upgrades
    if let Some(pc) = pending_confirmation {
        if desired_config_version != pc.version {
            return UpgradePlan {
                actions: vec![UpgradeAction::ConfirmConfig, UpgradeAction::RollbackConfig],
                rollback_eligible: rollback_available,
                is_blocked: true,
                block_reason: Some("Pending commit-confirmed config blocks unsafe upgrade until confirmed or rolled back".to_string()),
            };
        } else {
            // If the goal is to confirm the pending config, that's allowed!
            actions.push(UpgradeAction::ConfirmConfig);
            return UpgradePlan {
                actions,
                rollback_eligible: rollback_available,
                is_blocked: false,
                block_reason: None,
            };
        }
    }

    // 4. Session HA check
    if !session_ha_healthy {
        actions.push(UpgradeAction::WaitForQuorum);
    }

    // 5. Config change planning: requires graceful drain of user sessions and NRF deregistration
    if current_config_version != desired_config_version {
        if runtime_ready {
            actions.push(UpgradeAction::DeregisterFromNrf);
            actions.push(UpgradeAction::DrainSessions);
        }
        actions.push(UpgradeAction::ApplyConfig);
    }

    UpgradePlan {
        actions,
        rollback_eligible: rollback_available,
        is_blocked,
        block_reason,
    }
}
