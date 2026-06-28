use crate::phase::{ConditionSeverity, ConditionStatus, LifecycleCondition};
use opc_alarm::{Alarm, ReadinessImpact};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// Desired container image for a CNF workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfImageIntent {
    /// Image repository/name without mutable app config.
    pub repository: String,
    /// Optional image tag. Production callers should prefer digest pinning.
    pub tag: Option<String>,
    /// Optional immutable image digest.
    pub digest: Option<String>,
}

/// Desired replica count and availability envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaIntent {
    /// Desired pod replica count.
    pub replicas: u32,
    /// Optional minimum available replicas during rollout/drain.
    pub min_available: Option<u32>,
}

/// Generic placement hooks for a CNF workload.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PlacementIntent {
    /// Node selector labels.
    pub node_selector: BTreeMap<String, String>,
    /// Toleration identifiers or policy names understood by the platform adapter.
    pub tolerations: Vec<String>,
    /// Optional scheduler/affinity class name.
    pub affinity_class: Option<String>,
}

/// Network attachment class requested by the CNF workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkAttachmentKind {
    /// Default pod network.
    Default,
    /// Multus-style secondary network attachment.
    Multus,
    /// SR-IOV virtual-function attachment.
    Sriov,
    /// IPsec/XFRM gateway attachment.
    IpsecGateway,
    /// Operator-defined attachment class.
    Other(String),
}

/// Desired network attachment intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAttachmentIntent {
    /// Stable platform attachment name.
    pub name: String,
    /// Attachment class.
    pub kind: NetworkAttachmentKind,
    /// Optional interface name inside the pod/network namespace.
    pub interface_name: Option<String>,
}

/// Management endpoints the platform should expose for the CNF.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ManagementExposureIntent {
    /// Expose health/readiness probes.
    pub health: bool,
    /// Expose metrics endpoint.
    pub metrics: bool,
    /// Expose authenticated admin endpoint.
    pub admin: bool,
    /// Stable service names or endpoint aliases.
    pub service_names: Vec<String>,
}

/// Supported platform bootstrap reference classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootstrapRefKind {
    /// Kubernetes Secret or equivalent secret reference.
    Secret,
    /// Kubernetes ConfigMap or equivalent non-secret reference.
    ConfigMap,
    /// Mounted volume or projected volume reference.
    Volume,
    /// Operator-defined bootstrap reference.
    Other(String),
}

/// Reference to platform-owned bootstrap material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapRef {
    /// Reference name.
    pub name: String,
    /// Reference kind.
    pub kind: BootstrapRefKind,
}

/// Reference to the session-store substrate for a CNF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStoreRef {
    /// Backend profile name, such as quorum or single-node lab backend.
    pub backend_profile: String,
    /// Optional platform secret reference for credentials.
    pub credential_ref: Option<String>,
    /// Optional platform config reference for endpoint/bootstrap metadata.
    pub config_ref: Option<String>,
}

/// Generic upgrade and drain policy for a CNF rollout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeDrainPolicy {
    /// Whether session or traffic drain is required before replacement.
    pub drain_required: bool,
    /// Maximum unavailable replicas during the operation.
    pub max_unavailable: u32,
    /// Grace period for drain/shutdown in seconds.
    pub grace_period_seconds: u32,
}

impl Default for UpgradeDrainPolicy {
    fn default() -> Self {
        Self {
            drain_required: true,
            max_unavailable: 1,
            grace_period_seconds: 30,
        }
    }
}

/// Desired platform-owned workload intent for a CNF.
///
/// This type deliberately omits raw app configuration. Product YANG/gNMI/
/// NETCONF config should be carried through app-owned config APIs, not a
/// platform reconcile spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfWorkloadIntent {
    /// CNF image.
    pub image: CnfImageIntent,
    /// Replica intent.
    pub replicas: ReplicaIntent,
    /// Placement hooks.
    pub placement: PlacementIntent,
    /// Network attachments.
    pub network_attachments: Vec<NetworkAttachmentIntent>,
    /// Management endpoint exposure.
    pub management: ManagementExposureIntent,
    /// Platform bootstrap references.
    pub bootstrap_refs: Vec<BootstrapRef>,
    /// Optional session-store reference.
    pub session_store: Option<SessionStoreRef>,
    /// Upgrade/drain policy.
    pub upgrade_drain: UpgradeDrainPolicy,
}

impl CnfWorkloadIntent {
    /// Validate the intent without looking at product app config.
    pub fn validate(&self) -> Result<(), ReconcileIntentError> {
        validate_non_empty("image.repository", &self.image.repository)?;
        if self
            .image
            .tag
            .as_deref()
            .is_none_or(|tag| tag.trim().is_empty())
            && self
                .image
                .digest
                .as_deref()
                .is_none_or(|digest| digest.trim().is_empty())
        {
            return Err(ReconcileIntentError::InvalidIntent(
                "image tag or digest is required".to_string(),
            ));
        }

        if let Some(min_available) = self.replicas.min_available {
            if min_available > self.replicas.replicas {
                return Err(ReconcileIntentError::InvalidIntent(
                    "min_available cannot exceed replicas".to_string(),
                ));
            }
        }

        for attachment in &self.network_attachments {
            validate_non_empty("network attachment name", &attachment.name)?;
            if let Some(interface_name) = attachment.interface_name.as_deref() {
                validate_non_empty("network attachment interface", interface_name)?;
            }
        }
        for bootstrap_ref in &self.bootstrap_refs {
            validate_non_empty("bootstrap ref name", &bootstrap_ref.name)?;
        }
        if let Some(session_store) = &self.session_store {
            validate_non_empty(
                "session store backend profile",
                &session_store.backend_profile,
            )?;
        }
        Ok(())
    }
}

/// Redaction-safe app-config metadata for status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfigMetadata {
    /// Opaque app config version, not raw config.
    pub version: Option<String>,
    /// Opaque schema/config digest, not raw config.
    pub digest: Option<String>,
    /// Whether the metadata was accepted by the app config pipeline.
    pub accepted: bool,
}

/// Traffic readiness status-patch intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficStatusIntent {
    /// Whether traffic readiness may be claimed.
    pub traffic_ready: bool,
    /// Machine-readable reason.
    pub reason: String,
    /// Redaction-safe message.
    pub message: String,
}

impl TrafficStatusIntent {
    /// Construct a redaction-safe traffic-ready status.
    pub fn ready(reason: impl Into<String>, message: impl AsRef<str>) -> Self {
        Self {
            traffic_ready: true,
            reason: reason.into(),
            message: crate::sanitize_denial_message(message.as_ref()),
        }
    }

    /// Construct a redaction-safe traffic-blocked status.
    pub fn blocked(reason: impl Into<String>, message: impl AsRef<str>) -> Self {
        Self {
            traffic_ready: false,
            reason: reason.into(),
            message: crate::sanitize_denial_message(message.as_ref()),
        }
    }
}

/// Kubernetes-style condition derived from an SDK alarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlarmConditionIntent {
    /// Condition type.
    pub r#type: String,
    /// Condition status.
    pub status: ConditionStatus,
    /// Kubernetes-style reason.
    pub reason: String,
    /// Redaction-safe condition message.
    pub message: String,
    /// Readiness impact of the alarm.
    pub readiness_impact: ReadinessImpact,
}

impl AlarmConditionIntent {
    /// Build a generic alarm condition intent from an SDK alarm.
    pub fn from_alarm(alarm: &Alarm) -> Self {
        let readiness_impact = alarm.readiness_impact();
        let status = if readiness_impact == ReadinessImpact::NoImpact {
            ConditionStatus::False
        } else {
            ConditionStatus::True
        };
        Self {
            r#type: "AlarmActive".to_string(),
            status,
            reason: alarm.probable_cause.to_string(),
            message: crate::sanitize_denial_message(alarm.text.as_str()),
            readiness_impact,
        }
    }
}

/// Event intent derived from a redaction-safe alarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlarmEventIntent {
    /// Event type, usually `Normal` or `Warning`.
    pub event_type: String,
    /// Machine-readable event reason.
    pub reason: String,
    /// Redaction-safe event message.
    pub message: String,
}

impl AlarmEventIntent {
    /// Build a generic event intent from an SDK alarm.
    pub fn from_alarm(alarm: &Alarm) -> Self {
        let event_type = if alarm.readiness_impact() == ReadinessImpact::NoImpact {
            "Normal"
        } else {
            "Warning"
        };
        Self {
            event_type: event_type.to_string(),
            reason: alarm.probable_cause.to_string(),
            message: crate::sanitize_denial_message(alarm.text.as_str()),
        }
    }
}

/// Conflict retry policy for status patch operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRetryIntent {
    /// Retry status patches that fail with a resource-version conflict.
    pub retry_on_conflict: bool,
    /// Maximum retry attempts.
    pub max_attempts: u8,
    /// Initial backoff in milliseconds.
    pub initial_backoff_millis: u64,
}

impl Default for ConflictRetryIntent {
    fn default() -> Self {
        Self {
            retry_on_conflict: true,
            max_attempts: 5,
            initial_backoff_millis: 50,
        }
    }
}

/// Complete status patch intent produced by a generic CNF reconciler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusPatchIntent {
    /// Observed generation to write.
    pub observed_generation: i64,
    /// Lifecycle conditions to patch.
    pub lifecycle_conditions: Vec<LifecycleCondition>,
    /// Alarm-derived conditions to patch.
    pub alarm_conditions: Vec<AlarmConditionIntent>,
    /// Alarm-derived events to emit.
    pub alarm_events: Vec<AlarmEventIntent>,
    /// Redaction-safe app-config metadata only.
    pub app_config: Option<AppConfigMetadata>,
    /// Traffic readiness status.
    pub traffic: TrafficStatusIntent,
    /// Conflict retry behavior.
    pub conflict_retry: ConflictRetryIntent,
}

impl StatusPatchIntent {
    /// Build a minimal status patch with no app config payload.
    pub fn new(observed_generation: i64, traffic: TrafficStatusIntent) -> Self {
        Self {
            observed_generation,
            lifecycle_conditions: Vec::new(),
            alarm_conditions: Vec::new(),
            alarm_events: Vec::new(),
            app_config: None,
            traffic,
            conflict_retry: ConflictRetryIntent::default(),
        }
    }

    /// Add a lifecycle condition.
    #[must_use]
    pub fn with_lifecycle_condition(mut self, condition: LifecycleCondition) -> Self {
        self.lifecycle_conditions.push(condition);
        self
    }

    /// Add alarm condition and event intents from active alarms.
    #[must_use]
    pub fn with_alarms(mut self, alarms: &[Alarm]) -> Self {
        for alarm in alarms {
            self.alarm_conditions
                .push(AlarmConditionIntent::from_alarm(alarm));
            self.alarm_events.push(AlarmEventIntent::from_alarm(alarm));
        }
        self
    }

    /// Validate status-patch semantics.
    pub fn validate(&self) -> Result<(), ReconcileIntentError> {
        if self.observed_generation < 0 {
            return Err(ReconcileIntentError::InvalidIntent(
                "observed generation must be non-negative".to_string(),
            ));
        }
        validate_non_empty("traffic reason", &self.traffic.reason)?;
        if self.conflict_retry.retry_on_conflict && self.conflict_retry.max_attempts == 0 {
            return Err(ReconcileIntentError::InvalidIntent(
                "conflict retry max_attempts must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Error returned by reconcile intent validators.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReconcileIntentError {
    /// Intent field is structurally invalid.
    #[error("invalid reconcile intent: {0}")]
    InvalidIntent(String),
    /// Platform spec contains a raw app-config field.
    #[error("platform spec contains app config field: {field}")]
    AppConfigFieldRejected {
        /// Rejected field name.
        field: String,
    },
}

/// Reject raw app-config fields at a platform CR/spec boundary.
///
/// The helper walks object keys recursively and rejects common app config
/// containers. It allows references and metadata, but not inline YANG, gNMI,
/// NETCONF, running, or candidate config payload fields.
pub fn reject_app_config_fields(value: &serde_json::Value) -> Result<(), ReconcileIntentError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if is_app_config_key(key) {
                    return Err(ReconcileIntentError::AppConfigFieldRejected {
                        field: key.clone(),
                    });
                }
                reject_app_config_fields(child)?;
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                reject_app_config_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), ReconcileIntentError> {
    if value.trim().is_empty() {
        return Err(ReconcileIntentError::InvalidIntent(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn is_app_config_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "appconfig"
            | "yang"
            | "yangconfig"
            | "gnmi"
            | "gnmiconfig"
            | "netconf"
            | "netconfconfig"
            | "runningconfig"
            | "candidateconfig"
    )
}

/// Build a lifecycle condition for status patch tests or pure reconcilers.
pub fn lifecycle_condition_intent(
    r#type: impl Into<String>,
    status: ConditionStatus,
    reason: impl Into<String>,
    message: impl AsRef<str>,
    observed_generation: i64,
    severity: ConditionSeverity,
    now: OffsetDateTime,
) -> LifecycleCondition {
    LifecycleCondition {
        r#type: r#type.into(),
        status,
        reason: reason.into(),
        message: crate::sanitize_denial_message(message.as_ref()),
        observed_generation,
        last_transition_time: now,
        severity,
        redaction_safe_text: true,
    }
}
