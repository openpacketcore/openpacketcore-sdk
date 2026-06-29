//! Generic operational-state projection helpers for config apply plans.

use opc_config_model::{ApplyPlan, ChangeImpactClass, ConfigWorkflowRequirement, YangPath};
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
    /// Product-supplied active running revision label when version or
    /// transaction identity is not enough for the product's status model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_revision_label: Option<String>,
    /// Completed workflow metadata for the active running config, if an
    /// accepted workflow-required plan has completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_completion: Option<ConfigWorkflowCompletion>,
    /// Whether the accepted running config should block traffic until an
    /// external workflow completes.
    pub traffic_blocked_until_workflow: bool,
    /// Machine-readable reason for the active traffic block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_block_reason_code: Option<String>,
}

/// Completion identity and metadata for an accepted config workflow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigWorkflowCompletion {
    /// Completed running config version, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<ConfigVersion>,
    /// Completed running config transaction id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<TxId>,
    /// Product-supplied completed revision label, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
    /// Completed workflow impact class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_class: Option<ChangeImpactClass>,
    /// Machine-readable reason code from the completed workflow requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_reason_code: Option<String>,
}

impl ConfigWorkflowCompletion {
    /// Build completion metadata keyed by running config version.
    pub const fn for_config_version(config_version: ConfigVersion) -> Self {
        Self {
            config_version: Some(config_version),
            tx_id: None,
            revision_label: None,
            workflow_class: None,
            workflow_reason_code: None,
        }
    }

    /// Build completion metadata keyed by running config transaction id.
    pub const fn for_tx_id(tx_id: TxId) -> Self {
        Self {
            config_version: None,
            tx_id: Some(tx_id),
            revision_label: None,
            workflow_class: None,
            workflow_reason_code: None,
        }
    }

    /// Build completion metadata keyed by product-supplied revision label.
    pub fn for_revision_label(revision_label: impl Into<String>) -> Self {
        Self {
            revision_label: normalize_revision_label(revision_label),
            ..Self::default()
        }
    }

    /// Add a running config version to this completion identity.
    #[must_use]
    pub const fn with_config_version(mut self, config_version: ConfigVersion) -> Self {
        self.config_version = Some(config_version);
        self
    }

    /// Add a running config transaction id to this completion identity.
    #[must_use]
    pub const fn with_tx_id(mut self, tx_id: TxId) -> Self {
        self.tx_id = Some(tx_id);
        self
    }

    /// Add a product-supplied revision label to this completion identity.
    #[must_use]
    pub fn with_revision_label(mut self, revision_label: impl Into<String>) -> Self {
        self.revision_label = normalize_revision_label(revision_label);
        self
    }

    /// Whether this completion carries any usable identity key.
    pub const fn has_identity(&self) -> bool {
        self.config_version.is_some() || self.tx_id.is_some() || self.revision_label.is_some()
    }

    fn with_requirement(mut self, requirement: ConfigWorkflowRequirement) -> Self {
        self.workflow_class = Some(requirement.class);
        self.workflow_reason_code = Some(requirement.reason_code);
        self
    }
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

    /// Attaches a product-supplied active running revision label.
    ///
    /// The label must already be safe for northbound operational state. Empty
    /// or whitespace-only labels are ignored.
    pub fn with_active_revision_label(mut self, revision_label: impl Into<String>) -> Self {
        self.active_revision_label = normalize_revision_label(revision_label);
        self
    }

    /// Attaches the last accepted apply plan and derives active traffic-block
    /// status from it.
    pub fn with_last_accepted_apply_plan(mut self, plan: ApplyPlan) -> Self {
        self.workflow_completion = None;
        if plan.blocks_traffic_until_workflow() {
            let requirement = plan.workflow_requirement();
            self.traffic_blocked_until_workflow = true;
            self.traffic_block_reason_code = requirement.map(|req| req.reason_code);
        } else {
            self.traffic_blocked_until_workflow = false;
            self.traffic_block_reason_code = None;
        }
        self.last_accepted_apply_plan = Some(plan);
        self
    }

    /// Records completion for an accepted external workflow.
    ///
    /// Completion only clears the active traffic block when the supplied
    /// identity matches the currently active config version, transaction id, or
    /// revision label, and the last accepted plan still requires workflow.
    /// Stale or unkeyed completions are ignored.
    pub fn with_workflow_completion(mut self, completion: ConfigWorkflowCompletion) -> Self {
        let Some(requirement) = self.accepted_workflow_requirement() else {
            return self;
        };
        if !self.completion_matches_active_config(&completion) {
            return self;
        }

        self.traffic_blocked_until_workflow = false;
        self.traffic_block_reason_code = None;
        self.workflow_completion = Some(completion.with_requirement(requirement));
        self
    }

    /// Attaches the last rejected apply plan.
    pub fn with_last_rejected_apply_plan(mut self, plan: ApplyPlan) -> Self {
        self.last_rejected_apply_plan = Some(plan);
        self
    }

    /// Returns the active workflow requirement from the accepted plan, if any.
    pub fn workflow_requirement(&self) -> Option<ConfigWorkflowRequirement> {
        if !self.traffic_blocked_until_workflow {
            return None;
        }
        self.accepted_workflow_requirement()
    }

    fn accepted_workflow_requirement(&self) -> Option<ConfigWorkflowRequirement> {
        self.last_accepted_apply_plan
            .as_ref()
            .filter(|plan| plan.blocks_traffic_until_workflow())
            .and_then(ApplyPlan::workflow_requirement)
    }

    fn completion_matches_active_config(&self, completion: &ConfigWorkflowCompletion) -> bool {
        if !completion.has_identity() {
            return false;
        }

        let mut matched_any_known_key = false;

        if let Some(config_version) = completion.config_version {
            if let Some(active_config_version) = self.active_config_version {
                if config_version != active_config_version {
                    return false;
                }
                matched_any_known_key = true;
            }
        }

        if let Some(tx_id) = completion.tx_id {
            if let Some(active_tx_id) = self.active_tx_id {
                if tx_id != active_tx_id {
                    return false;
                }
                matched_any_known_key = true;
            }
        }

        if let Some(revision_label) = completion.revision_label.as_deref() {
            if let Some(active_revision_label) = self.active_revision_label.as_deref() {
                if revision_label != active_revision_label {
                    return false;
                }
                matched_any_known_key = true;
            }
        }

        matched_any_known_key
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

fn normalize_revision_label(revision_label: impl Into<String>) -> Option<String> {
    let revision_label = revision_label.into();
    let trimmed = revision_label.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
