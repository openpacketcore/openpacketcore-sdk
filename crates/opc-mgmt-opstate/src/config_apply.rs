//! Generic operational-state projection helpers for config apply plans.

use opc_config_model::{ApplyPlan, ConfigWorkflowRequirement, YangPath};
use opc_types::{ConfigVersion, TxId};
use serde::{Deserialize, Serialize};

use crate::{OperationalValue, OperationalValueError};

/// Protocol-neutral operational state for the most recent config apply plans.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigApplyPlanState {
    /// Last apply plan accepted for the running config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_accepted_apply_plan: Option<ApplyPlan>,
    /// Last apply plan rejected before durable append/publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rejected_apply_plan: Option<ApplyPlan>,
    /// Active running config version when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_config_version: Option<ConfigVersion>,
    /// Active running config transaction id when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_tx_id: Option<TxId>,
    /// Whether the accepted running config should block traffic until an
    /// external workflow completes.
    pub traffic_blocked_until_workflow: bool,
    /// Machine-readable reason for the active traffic block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_block_reason_code: Option<String>,
}

impl ConfigApplyPlanState {
    /// Builds empty apply-plan operational state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches active running config identity when known.
    pub fn with_active_config(
        mut self,
        version: Option<ConfigVersion>,
        tx_id: Option<TxId>,
    ) -> Self {
        self.active_config_version = version;
        self.active_tx_id = tx_id;
        self
    }

    /// Attaches the last accepted apply plan and derives active traffic-block
    /// status from it.
    pub fn with_last_accepted_apply_plan(mut self, plan: ApplyPlan) -> Self {
        if plan.blocks_traffic_until_workflow() {
            let requirement = plan.workflow_requirement();
            self.traffic_blocked_until_workflow = true;
            self.traffic_block_reason_code = requirement.map(|req| req.reason_code);
        }
        self.last_accepted_apply_plan = Some(plan);
        self
    }

    /// Attaches the last rejected apply plan.
    pub fn with_last_rejected_apply_plan(mut self, plan: ApplyPlan) -> Self {
        self.last_rejected_apply_plan = Some(plan);
        self
    }

    /// Returns the active workflow requirement from the accepted plan, if any.
    pub fn workflow_requirement(&self) -> Option<ConfigWorkflowRequirement> {
        self.last_accepted_apply_plan
            .as_ref()
            .filter(|plan| plan.blocks_traffic_until_workflow())
            .and_then(ApplyPlan::workflow_requirement)
    }

    /// Converts this state into an RFC 7951-compatible JSON value.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self)
            .expect("ConfigApplyPlanState serialization should not fail for JSON values")
    }

    /// Converts this state into an RFC 7951-compatible JSON string.
    pub fn to_value_json(&self) -> String {
        serde_json::to_string(self)
            .expect("ConfigApplyPlanState serialization should not fail for JSON values")
    }

    /// Builds a validated [`OperationalValue`] at the caller-supplied root path.
    pub fn to_operational_value(
        &self,
        root_path: YangPath,
    ) -> Result<OperationalValue, OperationalValueError> {
        OperationalValue::new(root_path, self.to_value_json())
    }
}
