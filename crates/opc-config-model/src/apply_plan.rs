use serde::{Deserialize, Serialize};

use crate::{ConfigError, OpcConfig, RollbackTarget, ValidationContext, YangPath};

/// Built-in hard-error code used when a live commit would require an explicit
/// maintenance workflow.
pub const FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW: &str =
    "forbidden_live_requires_maintenance_workflow";

const DEFAULT_HOT_REASON_CODE: &str = "config_changed";
const CONFIG_WORKFLOW_REQUIRED_REASON_CODE: &str = "config_workflow_required";

/// Stable operational impact class for a config change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeImpactClass {
    /// The change is immediately safe for existing and new traffic.
    Hot,
    /// The change is accepted live, but only new work observes the new value.
    Warm,
    /// The change is accepted, but traffic must drain before it is safe.
    DrainRequired,
    /// The change is accepted, but the CNF must restart before it is safe.
    RestartRequired,
    /// The change is not allowed as a live commit without a maintenance flow.
    ForbiddenLive,
}

impl ChangeImpactClass {
    /// Returns the stable kebab-case wire string for this impact class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::DrainRequired => "drain-required",
            Self::RestartRequired => "restart-required",
            Self::ForbiddenLive => "forbidden-live",
        }
    }

    /// Returns true when an admitted plan requires external operator workflow.
    pub const fn requires_external_workflow(self) -> bool {
        matches!(self, Self::DrainRequired | Self::RestartRequired)
    }

    /// Returns true when this class is forbidden for live commit by default.
    pub const fn is_forbidden_live(self) -> bool {
        matches!(self, Self::ForbiddenLive)
    }
}

impl std::fmt::Display for ChangeImpactClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One classified config path in an apply plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlanChange {
    /// SDK-canonical YANG path affected by the change.
    pub path: YangPath,
    /// Operational impact class for this path.
    pub class: ChangeImpactClass,
    /// Machine-readable, redaction-safe reason code.
    pub reason_code: String,
    /// Optional estimate of affected sessions for this change.
    pub affected_sessions_estimate: Option<u64>,
}

/// Aggregate impact for a complete apply plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeImpact {
    /// Strongest impact class in the plan.
    pub class: ChangeImpactClass,
    /// Saturating sum of known per-change estimates, or `None` when no
    /// estimate is known.
    pub affected_sessions_estimate: Option<u64>,
    /// Whether an admitted plan requires external operator workflow.
    pub requires_external_workflow: bool,
}

impl ChangeImpact {
    fn from_changes(class: ChangeImpactClass, changes: &[ApplyPlanChange]) -> Self {
        Self {
            class,
            affected_sessions_estimate: aggregate_session_estimates(changes),
            requires_external_workflow: class.requires_external_workflow(),
        }
    }
}

/// Structured, redaction-safe apply-plan rejection detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlanError {
    /// Machine-readable error code.
    pub code: String,
    /// Optional SDK-canonical YANG path associated with the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<YangPath>,
    /// Redaction-safe human-oriented message.
    pub message: String,
}

/// Structured, redaction-safe apply-plan warning detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlanWarning {
    /// Machine-readable warning code.
    pub code: String,
    /// Optional SDK-canonical YANG path associated with the warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<YangPath>,
    /// Redaction-safe human-oriented message.
    pub message: String,
}

/// Complete config apply plan produced during commit admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyPlan {
    /// Strongest impact class for the plan.
    pub class: ChangeImpactClass,
    /// Classified changed paths.
    pub changes: Vec<ApplyPlanChange>,
    /// Aggregate operational impact.
    pub impact: ChangeImpact,
    /// Rollback target associated with the plan when one is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_target: Option<RollbackTarget>,
    /// Hard errors that reject the plan before durable append/publication.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hard_errors: Vec<ApplyPlanError>,
    /// Non-fatal warnings associated with the plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ApplyPlanWarning>,
}

impl ApplyPlan {
    /// Builds the default live-safe plan for authoritative changed paths.
    pub fn default_hot(
        changed_paths: Vec<YangPath>,
        rollback_target: Option<RollbackTarget>,
    ) -> Self {
        let changes = changed_paths
            .into_iter()
            .map(|path| ApplyPlanChange {
                path,
                class: ChangeImpactClass::Hot,
                reason_code: DEFAULT_HOT_REASON_CODE.to_string(),
                affected_sessions_estimate: None,
            })
            .collect::<Vec<_>>();
        Self {
            class: ChangeImpactClass::Hot,
            impact: ChangeImpact::from_changes(ChangeImpactClass::Hot, &changes),
            changes,
            rollback_target,
            hard_errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Returns whether the plan may be durably committed.
    pub fn commit_allowed(&self) -> bool {
        self.hard_errors.is_empty() && !self.strongest_class().is_forbidden_live()
    }

    /// Returns whether an admitted running config should block traffic until
    /// an external workflow completes.
    pub fn blocks_traffic_until_workflow(&self) -> bool {
        self.commit_allowed() && self.strongest_class().requires_external_workflow()
    }

    /// Returns the strongest class declared by the aggregate or path entries.
    pub fn strongest_class(&self) -> ChangeImpactClass {
        self.changes
            .iter()
            .map(|change| change.class)
            .chain(std::iter::once(self.class))
            .max()
            .unwrap_or(ChangeImpactClass::Hot)
    }

    /// Canonicalizes aggregate fields and injects the built-in forbidden-live
    /// hard error when needed.
    pub fn normalize(mut self) -> Self {
        let class = self.strongest_class();
        self.class = class;
        self.impact = ChangeImpact::from_changes(class, &self.changes);
        if class.is_forbidden_live()
            && !self
                .hard_errors
                .iter()
                .any(|error| error.code == FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW)
        {
            self.hard_errors.push(ApplyPlanError {
                code: FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW.to_string(),
                path: None,
                message: "live config apply requires an explicit maintenance workflow".to_string(),
            });
        }
        self
    }

    /// Returns the generic operator workflow requirement implied by this plan.
    pub fn workflow_requirement(&self) -> Option<ConfigWorkflowRequirement> {
        ConfigWorkflowRequirement::from_apply_plan(self)
    }
}

/// Generic operator handoff for apply plans that require external workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigWorkflowRequirement {
    /// Strongest workflow-relevant impact class.
    pub class: ChangeImpactClass,
    /// Machine-readable, redaction-safe reason code.
    pub reason_code: String,
    /// SDK-canonical affected paths.
    pub affected_paths: Vec<YangPath>,
    /// Optional aggregate affected-session estimate.
    pub affected_sessions_estimate: Option<u64>,
}

impl ConfigWorkflowRequirement {
    /// Builds a workflow requirement for drain, restart, or forbidden-live
    /// plans. Returns `None` for hot and warm plans.
    pub fn from_apply_plan(plan: &ApplyPlan) -> Option<Self> {
        let class = plan.strongest_class();
        if matches!(class, ChangeImpactClass::Hot | ChangeImpactClass::Warm) {
            return None;
        }

        let affected_paths = strongest_affected_paths(plan, class);
        let reason_code = workflow_reason_code(plan, class);

        Some(Self {
            class,
            reason_code,
            affected_paths,
            affected_sessions_estimate: plan.impact.affected_sessions_estimate,
        })
    }
}

/// Product-supplied classifier for commit apply-plan admission.
pub trait ConfigImpactClassifier<C: OpcConfig>: Send + Sync {
    /// Classifies a validated candidate against the running config and
    /// authoritative SDK-derived changed paths.
    fn classify(
        &self,
        ctx: &ValidationContext<C>,
        previous: Option<&C>,
        candidate: &C,
        changed_paths: &[YangPath],
    ) -> Result<ApplyPlan, ConfigError>;
}

/// Default classifier that preserves legacy behavior by marking all changes hot.
#[derive(Debug, Default)]
pub struct HotConfigImpactClassifier;

impl<C: OpcConfig> ConfigImpactClassifier<C> for HotConfigImpactClassifier {
    fn classify(
        &self,
        _ctx: &ValidationContext<C>,
        _previous: Option<&C>,
        _candidate: &C,
        changed_paths: &[YangPath],
    ) -> Result<ApplyPlan, ConfigError> {
        Ok(ApplyPlan::default_hot(changed_paths.to_vec(), None))
    }
}

fn aggregate_session_estimates(changes: &[ApplyPlanChange]) -> Option<u64> {
    let mut saw_estimate = false;
    let sum = changes.iter().fold(0u64, |acc, change| {
        if let Some(estimate) = change.affected_sessions_estimate {
            saw_estimate = true;
            acc.saturating_add(estimate)
        } else {
            acc
        }
    });
    saw_estimate.then_some(sum)
}

fn strongest_affected_paths(plan: &ApplyPlan, class: ChangeImpactClass) -> Vec<YangPath> {
    let paths = plan
        .changes
        .iter()
        .filter(|change| change.class == class)
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        plan.changes
            .iter()
            .map(|change| change.path.clone())
            .collect()
    } else {
        paths
    }
}

fn workflow_reason_code(plan: &ApplyPlan, class: ChangeImpactClass) -> String {
    if class.is_forbidden_live() {
        return plan
            .hard_errors
            .first()
            .map(|error| error.code.clone())
            .unwrap_or_else(|| FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW.to_string());
    }

    plan.changes
        .iter()
        .find(|change| change.class == class)
        .map(|change| change.reason_code.clone())
        .unwrap_or_else(|| CONFIG_WORKFLOW_REQUIRED_REASON_CODE.to_string())
}
