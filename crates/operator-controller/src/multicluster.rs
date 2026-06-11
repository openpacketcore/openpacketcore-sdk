//! Multi-cluster rollout status model (GAP-009-008)
//!
//! Aggregates deployment status across clusters, regions, or cells, preventing a single
//! healthy cluster from masking errors in blocked or degraded clusters. Includes monotonic
//! generation checking, stale status rejection, and safety condition sanitization.

use operator_lifecycle::{ConditionSeverity, ConditionStatus, LifecycleCondition, LifecyclePhase};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum MultiClusterRolloutPhase {
    Ready,
    Progressing,
    Degraded,
    Blocked,
    RollbackRequired,
    Unknown,
}

impl MultiClusterRolloutPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Progressing => "Progressing",
            Self::Degraded => "Degraded",
            Self::Blocked => "Blocked",
            Self::RollbackRequired => "RollbackRequired",
            Self::Unknown => "Unknown",
        }
    }
}

/// Represents the reported status from a single cluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterRolloutStatus {
    #[serde(alias = "cluster_id")]
    pub cluster_id: String,
    #[serde(alias = "observed_generation")]
    pub observed_generation: i64,
    #[serde(alias = "resource_version")]
    pub resource_version: u64,
    pub phase: LifecyclePhase,
    pub conditions: Vec<LifecycleCondition>,
}

/// Aggregated multi-cluster rollout status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MultiClusterRolloutStatus {
    #[serde(alias = "observed_generation")]
    pub observed_generation: i64,
    #[serde(alias = "aggregated_phase")]
    pub aggregated_phase: MultiClusterRolloutPhase,
    pub clusters: HashMap<String, ClusterRolloutStatus>,
    pub conditions: Vec<LifecycleCondition>,
}

impl MultiClusterRolloutStatus {
    /// Creates a new empty multi-cluster status.
    pub fn new(initial_generation: i64) -> Self {
        Self {
            observed_generation: initial_generation,
            aggregated_phase: MultiClusterRolloutPhase::Unknown,
            clusters: HashMap::new(),
            conditions: Vec::new(),
        }
    }

    /// Updates status for a single cluster. Rejects if incoming observed_generation is stale.
    pub fn update_cluster_status(
        &mut self,
        cluster_id: &str,
        incoming: ClusterRolloutStatus,
    ) -> Result<(), String> {
        if incoming.cluster_id != cluster_id {
            let err_msg = format!(
                "Cluster status identity mismatch: map key {} does not match payload cluster {}",
                cluster_id, incoming.cluster_id
            );
            return Err(operator_lifecycle::sanitize_denial_message(&err_msg));
        }

        if let Some(existing) = self.clusters.get(cluster_id) {
            if incoming.observed_generation < existing.observed_generation {
                let err_msg = format!(
                    "Stale status update rejected for cluster {}: incoming generation {} is less than existing {}",
                    cluster_id, incoming.observed_generation, existing.observed_generation
                );
                return Err(operator_lifecycle::sanitize_denial_message(&err_msg));
            }

            if incoming.observed_generation == existing.observed_generation
                && incoming.resource_version < existing.resource_version
            {
                let err_msg = format!(
                    "Stale status update rejected for cluster {}: incoming resource version {} is less than existing {}",
                    cluster_id, incoming.resource_version, existing.resource_version
                );
                return Err(operator_lifecycle::sanitize_denial_message(&err_msg));
            }

            if incoming.observed_generation == existing.observed_generation
                && incoming.resource_version == existing.resource_version
                && incoming != *existing
            {
                let err_msg = format!(
                    "Conflicting status update rejected for cluster {}: payload changed without advancing resource version {}",
                    cluster_id, incoming.resource_version
                );
                return Err(operator_lifecycle::sanitize_denial_message(&err_msg));
            }
        }

        self.clusters.insert(cluster_id.to_string(), incoming);
        self.reaggregate();
        Ok(())
    }

    /// Computes the aggregated rollout phase and conditions.
    pub fn reaggregate(&mut self) {
        if self.clusters.is_empty() {
            self.aggregated_phase = MultiClusterRolloutPhase::Unknown;
            self.conditions.clear();
            return;
        }

        let mut has_rollback_required = false;
        let mut has_blocked = false;
        let mut has_degraded = false;
        let mut has_progressing = false;

        let mut min_generation = i64::MAX;

        for status in self.clusters.values() {
            min_generation = min_generation.min(status.observed_generation);

            match status.phase {
                LifecyclePhase::Failed
                | LifecyclePhase::RecoveryRequired
                | LifecyclePhase::RollingBack => {
                    has_rollback_required = true;
                }
                LifecyclePhase::Pending => {
                    // Check if there is an active "Blocked" condition
                    let is_blocked = status
                        .conditions
                        .iter()
                        .any(|c| c.r#type == "Blocked" && c.status == ConditionStatus::True);
                    if is_blocked {
                        has_blocked = true;
                    } else {
                        has_progressing = true;
                    }
                }
                LifecyclePhase::Degraded => {
                    has_degraded = true;
                }
                LifecyclePhase::Installing
                | LifecyclePhase::Starting
                | LifecyclePhase::Draining
                | LifecyclePhase::Upgrading => {
                    has_progressing = true;
                }
                LifecyclePhase::Ready => {}
            }
        }

        if min_generation != i64::MAX {
            self.observed_generation = min_generation;
        }

        // Precedence: RollbackRequired > Blocked > Degraded > Progressing > Ready
        if has_rollback_required {
            self.aggregated_phase = MultiClusterRolloutPhase::RollbackRequired;
        } else if has_blocked {
            self.aggregated_phase = MultiClusterRolloutPhase::Blocked;
        } else if has_degraded {
            self.aggregated_phase = MultiClusterRolloutPhase::Degraded;
        } else if has_progressing {
            self.aggregated_phase = MultiClusterRolloutPhase::Progressing;
        } else {
            self.aggregated_phase = MultiClusterRolloutPhase::Ready;
        }

        // Regenerate aggregated status conditions
        let current_time = OffsetDateTime::now_utc();
        self.conditions.clear();

        let (ready_status, reason, message) = match self.aggregated_phase {
            MultiClusterRolloutPhase::Ready => (
                ConditionStatus::True,
                "AllClustersReady",
                "All registered clusters have completed rollout successfully.",
            ),
            MultiClusterRolloutPhase::RollbackRequired => (
                ConditionStatus::False,
                "RollbackRequired",
                "Rollout failure detected on one or more clusters. Rollback is required.",
            ),
            MultiClusterRolloutPhase::Blocked => (
                ConditionStatus::False,
                "RolloutBlocked",
                "Rollout sequence is blocked on one or more clusters due to preflight or safety checks.",
            ),
            MultiClusterRolloutPhase::Degraded => (
                ConditionStatus::False,
                "ClusterDegraded",
                "One or more clusters are reporting Degraded status.",
            ),
            MultiClusterRolloutPhase::Progressing => (
                ConditionStatus::False,
                "RolloutProgressing",
                "Rollout is in progress across the cluster fleet.",
            ),
            MultiClusterRolloutPhase::Unknown => (
                ConditionStatus::Unknown,
                "UnknownStatus",
                "Fleet status cannot be determined.",
            ),
        };

        // Sanitize the condition message
        let sanitized_msg = operator_lifecycle::sanitize_denial_message(message);

        self.conditions.push(LifecycleCondition {
            r#type: "Ready".to_string(),
            status: ready_status,
            reason: reason.to_string(),
            message: sanitized_msg,
            observed_generation: self.observed_generation,
            last_transition_time: current_time,
            severity: if ready_status == ConditionStatus::True {
                ConditionSeverity::Info
            } else if self.aggregated_phase == MultiClusterRolloutPhase::RollbackRequired {
                ConditionSeverity::Error
            } else {
                ConditionSeverity::Warning
            },
            redaction_safe_text: true,
        });
    }
}
