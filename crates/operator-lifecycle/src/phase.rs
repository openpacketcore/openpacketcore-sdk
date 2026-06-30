use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

mod k8s_condition_time {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use time::{format_description::well_known::Rfc3339, Date, OffsetDateTime, UtcOffset};

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        time::serde::rfc3339::serialize(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        match OffsetDateTimeWire::deserialize(deserializer)? {
            OffsetDateTimeWire::Rfc3339(value) => {
                OffsetDateTime::parse(&value, &Rfc3339).map_err(de::Error::custom)
            }
            OffsetDateTimeWire::LegacyTuple((
                year,
                ordinal,
                hour,
                minute,
                second,
                nanosecond,
                offset_hours,
                offset_minutes,
                offset_seconds,
            )) => Date::from_ordinal_date(year, ordinal)
                .and_then(|date| date.with_hms_nano(hour, minute, second, nanosecond))
                .and_then(|datetime| {
                    UtcOffset::from_hms(offset_hours, offset_minutes, offset_seconds)
                        .map(|offset| datetime.assume_offset(offset))
                })
                .map_err(de::Error::custom),
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OffsetDateTimeWire {
        Rfc3339(String),
        LegacyTuple((i32, u16, u8, u8, u8, u32, i8, i8, i8)),
    }
}

/// Operator-facing lifecycle phases from GAP-009-002.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LifecyclePhase {
    Pending,
    Installing,
    Starting,
    Ready,
    Degraded,
    Draining,
    Upgrading,
    RollingBack,
    Failed,
    RecoveryRequired,
}

impl LifecyclePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Installing => "Installing",
            Self::Starting => "Starting",
            Self::Ready => "Ready",
            Self::Degraded => "Degraded",
            Self::Draining => "Draining",
            Self::Upgrading => "Upgrading",
            Self::RollingBack => "RollingBack",
            Self::Failed => "Failed",
            Self::RecoveryRequired => "RecoveryRequired",
        }
    }
}

impl std::fmt::Display for LifecyclePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Status values for Kubernetes conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

impl ConditionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::True => "True",
            Self::False => "False",
            Self::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity level for condition evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionSeverity {
    Info,
    Warning,
    Error,
}

/// Kubernetes-style status condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleCondition {
    /// Type of condition, e.g. "Ready", "Progressing", "Degraded".
    #[serde(rename = "type")]
    pub r#type: String,
    /// Status of the condition: True, False, or Unknown.
    pub status: ConditionStatus,
    /// UpperCamelCase machine-readable reason code.
    pub reason: String,
    /// Human-readable explanation. Must be redaction-safe.
    pub message: String,
    /// Desired config generation observed when evaluating this condition.
    #[serde(alias = "observed_generation")]
    pub observed_generation: i64,
    /// Time when the condition status last transitioned.
    #[serde(alias = "last_transition_time", with = "k8s_condition_time")]
    pub last_transition_time: OffsetDateTime,
    /// Severity level of the condition.
    pub severity: ConditionSeverity,
    /// Flag proving the text has been sanitized of secrets, paths, and identifiers.
    #[serde(alias = "redaction_safe_text")]
    pub redaction_safe_text: bool,
}

/// Stable status status representing the operator state envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleStatus {
    /// The high-level lifecycle phase.
    pub phase: LifecyclePhase,
    /// List of Kubernetes-style conditions.
    pub conditions: Vec<LifecycleCondition>,
    /// The current observed generation of the desired specification/configuration.
    #[serde(alias = "observed_generation")]
    pub observed_generation: i64,
}

impl LifecycleStatus {
    /// Creates a new initial `LifecycleStatus` at `Pending`.
    pub fn new(observed_generation: i64) -> Self {
        Self {
            phase: LifecyclePhase::Pending,
            conditions: Vec::new(),
            observed_generation,
        }
    }

    /// Sets or updates a condition, guaranteeing monotonic transitions of time and generation.
    #[allow(clippy::too_many_arguments)]
    pub fn set_condition(
        &mut self,
        r#type: &str,
        status: ConditionStatus,
        reason: &str,
        message: &str,
        observed_generation: i64,
        severity: ConditionSeverity,
        _redaction_safe_text: bool,
        current_time: OffsetDateTime,
    ) {
        // Enforce that observed generation transitions monotonically (can't go backwards)
        if observed_generation < self.observed_generation {
            // Log or ignore stale update to preserve monotonicity
            return;
        }

        let message = crate::admission::sanitize_denial_message(message);
        let redaction_safe_text = true;

        if let Some(cond) = self.conditions.iter_mut().find(|c| c.r#type == r#type) {
            // Monotonic guard on per-condition observed generation
            if observed_generation < cond.observed_generation {
                return;
            }

            let changed = cond.status != status
                || cond.reason != reason
                || cond.message != message
                || cond.severity != severity
                || cond.redaction_safe_text != redaction_safe_text;

            if changed {
                cond.status = status;
                cond.reason = reason.to_string();
                cond.message = message;
                cond.observed_generation = observed_generation;
                cond.last_transition_time = current_time.max(cond.last_transition_time);
                cond.severity = severity;
                cond.redaction_safe_text = redaction_safe_text;
            } else {
                // Keep transition time unchanged but update generation
                cond.observed_generation = observed_generation;
            }
        } else {
            self.conditions.push(LifecycleCondition {
                r#type: r#type.to_string(),
                status,
                reason: reason.to_string(),
                message,
                observed_generation,
                last_transition_time: current_time,
                severity,
                redaction_safe_text,
            });
        }

        if observed_generation > self.observed_generation {
            self.observed_generation = observed_generation;
        }
    }

    /// Updates the operator phase.
    pub fn set_phase(&mut self, phase: LifecyclePhase) {
        self.phase = phase;
    }
}
