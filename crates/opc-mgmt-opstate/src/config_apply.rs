//! Generic operational-state projection helpers for config apply plans.

use opc_config_model::{
    ApplyPlan, ChangeImpactClass, CommitError, CommitResult, ConfigWorkflowRequirement, YangPath,
};
use opc_mgmt_errors::{commit_error_to_netconf, commit_error_to_status};
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
    /// Pending or rejected candidate metadata, if the product has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_status: Option<ConfigCandidateStatus>,
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

/// Product-neutral state for candidate config metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigCandidateState {
    /// Candidate exists but has not replaced running config.
    #[default]
    Pending,
    /// Candidate was rejected before replacing running config.
    Rejected,
}

/// Redaction-safe metadata for a pending or rejected config candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigCandidateStatus {
    /// Candidate state.
    pub state: ConfigCandidateState,
    /// Candidate base or target running config version, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<ConfigVersion>,
    /// Candidate transaction id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<TxId>,
    /// Product-supplied candidate revision label, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
    /// Count of apply-plan warnings without copying warning messages.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub warning_count: usize,
    /// Stable warning codes from the candidate apply plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warning_codes: Vec<String>,
    /// Stable error codes from the commit rejection and apply plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_codes: Vec<String>,
    /// Primary SDK commit rejection code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_code: Option<String>,
    /// gNMI-aligned management status for the rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_status: Option<String>,
    /// NETCONF `<rpc-error>` error-type for the rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netconf_error_type: Option<String>,
    /// NETCONF `<rpc-error>` error-tag for the rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netconf_error_tag: Option<String>,
    /// Strongest impact class from the rejected or validated apply plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_plan_class: Option<ChangeImpactClass>,
}

impl ConfigCandidateStatus {
    /// Build pending candidate metadata keyed by running config version.
    pub const fn pending_config_version(config_version: ConfigVersion) -> Self {
        Self {
            state: ConfigCandidateState::Pending,
            config_version: Some(config_version),
            tx_id: None,
            revision_label: None,
            warning_count: 0,
            warning_codes: Vec::new(),
            error_codes: Vec::new(),
            rejection_code: None,
            management_status: None,
            netconf_error_type: None,
            netconf_error_tag: None,
            apply_plan_class: None,
        }
    }

    /// Build pending candidate metadata keyed by candidate transaction id.
    pub const fn pending_tx_id(tx_id: TxId) -> Self {
        Self {
            state: ConfigCandidateState::Pending,
            config_version: None,
            tx_id: Some(tx_id),
            revision_label: None,
            warning_count: 0,
            warning_codes: Vec::new(),
            error_codes: Vec::new(),
            rejection_code: None,
            management_status: None,
            netconf_error_type: None,
            netconf_error_tag: None,
            apply_plan_class: None,
        }
    }

    /// Build pending candidate metadata keyed by product-supplied revision label.
    pub fn pending_revision_label(revision_label: impl Into<String>) -> Self {
        Self {
            revision_label: normalize_revision_label(revision_label),
            ..Self::default()
        }
    }

    /// Build rejected candidate metadata keyed by running config version.
    pub fn rejected_config_version(config_version: ConfigVersion, error: &CommitError) -> Self {
        Self::pending_config_version(config_version).with_rejection(error)
    }

    /// Build rejected candidate metadata keyed by candidate transaction id.
    pub fn rejected_tx_id(tx_id: TxId, error: &CommitError) -> Self {
        Self::pending_tx_id(tx_id).with_rejection(error)
    }

    /// Build rejected candidate metadata keyed by product-supplied revision label.
    pub fn rejected_revision_label(revision_label: impl Into<String>, error: &CommitError) -> Self {
        Self::pending_revision_label(revision_label).with_rejection(error)
    }

    /// Add a running config version to this candidate identity.
    #[must_use]
    pub const fn with_config_version(mut self, config_version: ConfigVersion) -> Self {
        self.config_version = Some(config_version);
        self
    }

    /// Add a candidate transaction id to this candidate identity.
    #[must_use]
    pub const fn with_tx_id(mut self, tx_id: TxId) -> Self {
        self.tx_id = Some(tx_id);
        self
    }

    /// Add a product-supplied revision label to this candidate identity.
    #[must_use]
    pub fn with_revision_label(mut self, revision_label: impl Into<String>) -> Self {
        self.revision_label = normalize_revision_label(revision_label);
        self
    }

    /// Add warning metadata from an apply plan without copying warning messages.
    #[must_use]
    pub fn with_apply_plan_metadata(mut self, plan: &ApplyPlan) -> Self {
        self.warning_count = plan.warnings.len();
        self.warning_codes = plan
            .warnings
            .iter()
            .filter_map(|warning| normalize_status_code(&warning.code))
            .collect();
        normalize_status_codes(&mut self.warning_codes);
        self.apply_plan_class = Some(plan.strongest_class());
        self
    }

    /// Add rejection metadata from an SDK commit error without copying the error
    /// message or raw config payload.
    #[must_use]
    pub fn with_rejection(mut self, error: &CommitError) -> Self {
        self.state = ConfigCandidateState::Rejected;
        let rejection_code = error.code.as_str();
        self.rejection_code = Some(rejection_code.to_string());
        self.error_codes.push(rejection_code.to_string());

        let management_status = commit_error_to_status(error.code);
        self.management_status = Some(management_status.as_str().to_string());

        let netconf_error = commit_error_to_netconf(error.code);
        self.netconf_error_type = Some(netconf_error.error_type.as_str().to_string());
        self.netconf_error_tag = Some(netconf_error.tag.as_str().to_string());

        if let Some(plan) = error.apply_plan.as_deref() {
            self = self.with_apply_plan_metadata(plan);
            self.error_codes.extend(
                plan.hard_errors
                    .iter()
                    .filter_map(|hard_error| normalize_status_code(&hard_error.code)),
            );
        }

        normalize_status_codes(&mut self.error_codes);
        self
    }

    /// Whether this candidate carries any usable identity key.
    pub const fn has_identity(&self) -> bool {
        self.config_version.is_some() || self.tx_id.is_some() || self.revision_label.is_some()
    }

    fn into_pending(mut self) -> Self {
        self.state = ConfigCandidateState::Pending;
        self.error_codes.clear();
        self.rejection_code = None;
        self.management_status = None;
        self.netconf_error_type = None;
        self.netconf_error_tag = None;
        self
    }

    fn into_rejected(mut self) -> Self {
        self.state = ConfigCandidateState::Rejected;
        normalize_status_codes(&mut self.error_codes);
        self
    }
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

/// Running config identity targeted by a config-workflow action.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigWorkflowActionTarget {
    /// Target running config version, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<ConfigVersion>,
    /// Target running config transaction id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<TxId>,
    /// Product-supplied target revision label, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
}

/// Stable result status for a config-workflow action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigWorkflowActionStatus {
    /// The required workflow marker was completed for the active running
    /// config.
    Completed,
    /// The action was rejected with a machine-readable conflict reason.
    Rejected,
}

impl ConfigWorkflowActionStatus {
    /// Stable machine-readable status code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
        }
    }
}

/// Stable conflict reason for a rejected config-workflow action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigWorkflowActionConflictReason {
    /// No running config identity is known.
    NoRunningConfig,
    /// The requested target does not match the active running config.
    RevisionMismatch,
    /// The active running config has no incomplete required workflow.
    NoWorkflowRequired,
}

impl ConfigWorkflowActionConflictReason {
    /// Stable machine-readable conflict code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRunningConfig => "no-running-config",
            Self::RevisionMismatch => "revision-mismatch",
            Self::NoWorkflowRequired => "no-workflow-required",
        }
    }
}

/// Redaction-safe result of a config-workflow action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigWorkflowActionResult {
    /// Action status.
    pub status: ConfigWorkflowActionStatus,
    /// Rejection reason when [`Self::status`] is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<ConfigWorkflowActionConflictReason>,
    /// Caller-requested workflow target.
    pub requested: ConfigWorkflowActionTarget,
    /// Active running config identity observed while evaluating the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<ConfigWorkflowActionTarget>,
    /// Completion metadata recorded on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<ConfigWorkflowCompletion>,
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

impl ConfigWorkflowActionTarget {
    /// Build an action target keyed by running config version.
    pub const fn for_config_version(config_version: ConfigVersion) -> Self {
        Self {
            config_version: Some(config_version),
            tx_id: None,
            revision_label: None,
        }
    }

    /// Build an action target keyed by running config transaction id.
    pub const fn for_tx_id(tx_id: TxId) -> Self {
        Self {
            config_version: None,
            tx_id: Some(tx_id),
            revision_label: None,
        }
    }

    /// Build an action target keyed by product-supplied revision label.
    pub fn for_revision_label(revision_label: impl Into<String>) -> Self {
        Self {
            revision_label: normalize_revision_label(revision_label),
            ..Self::default()
        }
    }

    /// Add a running config version to this action target.
    #[must_use]
    pub const fn with_config_version(mut self, config_version: ConfigVersion) -> Self {
        self.config_version = Some(config_version);
        self
    }

    /// Add a running config transaction id to this action target.
    #[must_use]
    pub const fn with_tx_id(mut self, tx_id: TxId) -> Self {
        self.tx_id = Some(tx_id);
        self
    }

    /// Add a product-supplied revision label to this action target.
    #[must_use]
    pub fn with_revision_label(mut self, revision_label: impl Into<String>) -> Self {
        self.revision_label = normalize_revision_label(revision_label);
        self
    }

    /// Whether this target carries any usable identity key.
    pub const fn has_identity(&self) -> bool {
        self.config_version.is_some() || self.tx_id.is_some() || self.revision_label.is_some()
    }
}

impl From<ConfigWorkflowActionTarget> for ConfigWorkflowCompletion {
    fn from(target: ConfigWorkflowActionTarget) -> Self {
        Self {
            config_version: target.config_version,
            tx_id: target.tx_id,
            revision_label: target.revision_label,
            workflow_class: None,
            workflow_reason_code: None,
        }
    }
}

impl ConfigWorkflowActionResult {
    fn completed(
        requested: ConfigWorkflowActionTarget,
        running: ConfigWorkflowActionTarget,
        completion: ConfigWorkflowCompletion,
    ) -> Self {
        Self {
            status: ConfigWorkflowActionStatus::Completed,
            reason: None,
            requested,
            running: Some(running),
            completion: Some(completion),
        }
    }

    fn rejected(
        reason: ConfigWorkflowActionConflictReason,
        requested: ConfigWorkflowActionTarget,
        running: Option<ConfigWorkflowActionTarget>,
    ) -> Self {
        Self {
            status: ConfigWorkflowActionStatus::Rejected,
            reason: Some(reason),
            requested,
            running,
            completion: None,
        }
    }

    /// Whether the action completed.
    pub const fn is_completed(&self) -> bool {
        matches!(self.status, ConfigWorkflowActionStatus::Completed)
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

    /// Applies a successful SDK commit result to this projection.
    ///
    /// Results that publish a new running config update active version/tx-id,
    /// clear rejected candidate metadata, and attach the accepted apply plan
    /// when one is available. Validate-only results intentionally leave running
    /// status unchanged.
    pub fn with_commit_result(mut self, result: &CommitResult) -> Self {
        let Some(new_version) = result.new_version else {
            return self;
        };

        self.active_config_version = Some(new_version);
        self.active_tx_id = Some(result.tx_id);
        self.candidate_status = None;
        self.last_rejected_apply_plan = None;

        if let Some(plan) = result.apply_plan.clone() {
            self = self.with_last_accepted_apply_plan(plan);
        }

        self
    }

    /// Attaches pending candidate metadata. Unkeyed candidate metadata is
    /// ignored so rollback/control-action errors are not mistaken for app
    /// candidate status.
    pub fn with_pending_candidate(mut self, candidate: ConfigCandidateStatus) -> Self {
        let candidate = candidate.into_pending();
        if candidate.has_identity() {
            self.candidate_status = Some(candidate);
        }
        self
    }

    /// Attaches rejected candidate metadata. Unkeyed candidate metadata is
    /// ignored so rollback/control-action errors are not mistaken for app
    /// candidate status.
    pub fn with_rejected_candidate(mut self, candidate: ConfigCandidateStatus) -> Self {
        let candidate = candidate.into_rejected();
        if candidate.has_identity() {
            self.candidate_status = Some(candidate);
        }
        self
    }

    /// Attaches rejected candidate metadata from a candidate identity and SDK
    /// commit error.
    pub fn with_rejected_candidate_error(
        self,
        candidate: ConfigCandidateStatus,
        error: &CommitError,
    ) -> Self {
        self.with_rejected_candidate(candidate.with_rejection(error))
    }

    /// Applies a config-workflow completion action to this projection.
    ///
    /// The returned state is updated only when the action completes. Rejected
    /// actions return the original state plus a redaction-safe conflict result
    /// that northbound adapters can map to HTTP, gNMI, NETCONF, or YANG action
    /// responses.
    #[must_use]
    pub fn complete_workflow_action(
        mut self,
        target: ConfigWorkflowActionTarget,
    ) -> (Self, ConfigWorkflowActionResult) {
        let requested = target;
        let Some(running) = self.active_workflow_target() else {
            let result = ConfigWorkflowActionResult::rejected(
                ConfigWorkflowActionConflictReason::NoRunningConfig,
                requested,
                None,
            );
            return (self, result);
        };

        if !self.action_target_matches_active_config(&requested) {
            let result = ConfigWorkflowActionResult::rejected(
                ConfigWorkflowActionConflictReason::RevisionMismatch,
                requested,
                Some(running),
            );
            return (self, result);
        }

        let Some(requirement) = self.workflow_requirement() else {
            let result = ConfigWorkflowActionResult::rejected(
                ConfigWorkflowActionConflictReason::NoWorkflowRequired,
                requested,
                Some(running),
            );
            return (self, result);
        };

        let completion =
            ConfigWorkflowCompletion::from(requested.clone()).with_requirement(requirement);
        self.traffic_blocked_until_workflow = false;
        self.traffic_block_reason_code = None;
        self.workflow_completion = Some(completion.clone());

        let result = ConfigWorkflowActionResult::completed(requested, running, completion);
        (self, result)
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
        self.identity_matches_active_config(
            completion.config_version,
            completion.tx_id,
            completion.revision_label.as_deref(),
        )
    }

    fn action_target_matches_active_config(&self, target: &ConfigWorkflowActionTarget) -> bool {
        self.identity_matches_active_config(
            target.config_version,
            target.tx_id,
            target.revision_label.as_deref(),
        )
    }

    fn identity_matches_active_config(
        &self,
        config_version: Option<ConfigVersion>,
        tx_id: Option<TxId>,
        revision_label: Option<&str>,
    ) -> bool {
        let mut matched_any_known_key = false;

        if let Some(config_version) = config_version {
            if let Some(active_config_version) = self.active_config_version {
                if config_version != active_config_version {
                    return false;
                }
                matched_any_known_key = true;
            }
        }

        if let Some(tx_id) = tx_id {
            if let Some(active_tx_id) = self.active_tx_id {
                if tx_id != active_tx_id {
                    return false;
                }
                matched_any_known_key = true;
            }
        }

        if let Some(revision_label) = revision_label {
            if let Some(active_revision_label) = self.active_revision_label.as_deref() {
                if revision_label != active_revision_label {
                    return false;
                }
                matched_any_known_key = true;
            }
        }

        matched_any_known_key
    }

    fn active_workflow_target(&self) -> Option<ConfigWorkflowActionTarget> {
        let target = ConfigWorkflowActionTarget {
            config_version: self.active_config_version,
            tx_id: self.active_tx_id,
            revision_label: self.active_revision_label.clone(),
        };
        if target.has_identity() {
            Some(target)
        } else {
            None
        }
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

fn normalize_status_code(code: &str) -> Option<String> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_status_codes(codes: &mut Vec<String>) {
    codes.retain(|code| !code.trim().is_empty());
    for code in codes.iter_mut() {
        if code.len() != code.trim().len() {
            *code = code.trim().to_string();
        }
    }
    codes.sort();
    codes.dedup();
}

const fn is_zero(value: &usize) -> bool {
    *value == 0
}
