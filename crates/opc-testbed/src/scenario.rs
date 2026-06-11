//! Scenario DSL schema (RFC 012 §5).
//!
//! Declarative YAML/JSON scenarios for 5G procedures, topology, steps, and
//! assertions. Versioned and validated against
//! `schemas/rfc012/v1/scenario.schema.json`.
//!
//! The DSL accepts both the canonical RFC 012 wire format (e.g.
//! `- send_ngap: { from: ..., to: ... }`) and an explicit tagged form
//! (`- kind: send_ngap\n  from: ...`).  Assertions may be bare strings or
//! structured objects.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::assertions::Assertion;

/// Current DSL version. Bumped on backward-incompatible changes.
pub const DSL_VERSION: &str = "0.1.0";

fn missing_schema_version() -> String {
    String::new()
}

/// Internal struct used by the custom [`Deserialize`] impl for [`Scenario`].
/// Derives `Deserialize` with `deny_unknown_fields` so that unknown properties
/// are rejected *after* the raw authored document has been schema-validated.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioData {
    #[serde(default = "missing_schema_version")]
    schema_version: String,
    id: String,
    title: String,
    #[serde(default)]
    requirements: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    topology: Topology,
    steps: Vec<Step>,
    #[serde(default)]
    assertions: Vec<Assertion>,
}

impl From<ScenarioData> for Scenario {
    fn from(data: ScenarioData) -> Self {
        Self {
            schema_version: data.schema_version,
            id: data.id,
            title: data.title,
            requirements: data.requirements,
            seed: data.seed,
            topology: data.topology,
            steps: data.steps,
            assertions: data.assertions,
        }
    }
}

/// Top-level scenario document. Versioned for forward compatibility.
///
/// `Deserialize` is implemented manually so that **every** deserialization entry
/// point validates the raw authored value against the RFC 012 JSON Schema
/// *before* constructing the struct. This prevents authored `null` values (e.g.
/// `seed: null`, `image: null`) from being silently erased by
/// `skip_serializing_if` during later re-serialization.
#[derive(Debug, Clone, Serialize)]
pub struct Scenario {
    /// DSL schema version used when authoring the scenario.
    /// Must be present and equal to [`DSL_VERSION`].
    pub schema_version: String,
    /// Stable scenario identifier (e.g. "AMF-REG-001").
    pub id: String,
    pub title: String,
    /// Linked requirement IDs (RFC 006 style).
    pub requirements: Vec<String>,
    /// Optional deterministic seed for reproducible simulator behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    pub topology: Topology,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
}

impl<'de> Deserialize<'de> for Scenario {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let raw = serde_json::Value::deserialize(deserializer)?;
        crate::schema::validate_scenario_document(&raw)
            .map_err(|e| D::Error::custom(e.to_string()))?;
        let data: ScenarioData =
            serde_json::from_value(raw).map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(data.into())
    }
}

impl Scenario {
    /// Parse a scenario from YAML (the canonical format in RFC 012 examples).
    pub fn from_yaml(yaml: &str) -> Result<Self, crate::TestbedError> {
        serde_yaml::from_str(yaml).map_err(|e| crate::TestbedError::ScenarioParse(e.to_string()))
    }

    /// Parse a scenario from JSON.
    pub fn from_json(json: &str) -> Result<Self, crate::TestbedError> {
        serde_json::from_str(json).map_err(|e| crate::TestbedError::ScenarioParse(e.to_string()))
    }

    /// Basic structural validation (ids non-empty, at least one step, explicit
    /// schema version, valid requirement IDs, no unknown step kinds, etc.).
    pub fn validate(&self) -> Result<(), crate::TestbedError> {
        if self.id.trim().is_empty() {
            return Err(crate::TestbedError::Validation(
                "scenario id required".into(),
            ));
        }
        if self.title.trim().is_empty() {
            return Err(crate::TestbedError::Validation(
                "scenario title required".into(),
            ));
        }
        if self.steps.is_empty() {
            return Err(crate::TestbedError::Validation(
                "scenario must have at least one step".into(),
            ));
        }
        if self.schema_version.trim().is_empty() {
            return Err(crate::TestbedError::Validation(
                "schema_version is required".into(),
            ));
        }
        if self.schema_version != DSL_VERSION {
            return Err(crate::TestbedError::Validation(format!(
                "unsupported schema version '{}', expected '{}'",
                self.schema_version, DSL_VERSION
            )));
        }
        for (idx, step) in self.steps.iter().enumerate() {
            if matches!(step, Step::Other) {
                return Err(crate::TestbedError::Validation(format!(
                    "step {} is an unsupported/unknown step kind",
                    idx
                )));
            }
        }
        for req in &self.requirements {
            if req.trim().is_empty() {
                return Err(crate::TestbedError::Validation(
                    "scenario requirements must not contain blank entries".into(),
                ));
            }
            if opc_evidence::RequirementId::from_str(req).is_err() {
                return Err(crate::TestbedError::Validation(format!(
                    "scenario requirement '{req}' is not a valid RFC 006 requirement id"
                )));
            }
        }

        let json = serde_json::to_value(self).map_err(|err| {
            crate::TestbedError::Validation(format!(
                "scenario could not be normalized for schema validation: {err}"
            ))
        })?;
        crate::schema::validate_scenario_document(&json)
    }

    /// Deterministic seed for this scenario, defaulting to 0 if unspecified.
    pub fn deterministic_seed(&self) -> u64 {
        self.seed.unwrap_or(0)
    }
}

impl std::str::FromStr for Scenario {
    type Err = crate::TestbedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_yaml(s)
    }
}

/// Topology declares the NFs and simulators under test.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub nfs: std::collections::HashMap<String, NfSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulator: Option<String>,
}

/// A single step in the scenario (send/expect over NGAP, SBI, etc., or failure injection).
///
/// Serializes to the tagged wire form (`{ "kind": "send_ngap", ... }`) so
/// that JSON/YAML round-trips are symmetric with the custom deserializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    SendNgap {
        from: String,
        to: String,
        message: String,
    },
    ExpectSbi {
        from: String,
        to: String,
        operation: String,
    },
    ExpectNgap {
        from: String,
        to: String,
        message: String,
    },
    PeerUnavailable {
        target: String,
    },
    DelayedResponse {
        target: String,
        delay_ms: u64,
    },
    MalformedResponse {
        target: String,
    },
    DependencyTimeout {
        target: String,
    },
    ClockJump {
        duration_ms: u64,
    },
    ProcessRestart {
        target: String,
    },
    NetworkPartition {
        node_a: String,
        node_b: String,
    },
    Other,
}

impl Serialize for Step {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        match self {
            Step::SendNgap { from, to, message } => {
                map.serialize_entry("kind", "send_ngap")?;
                map.serialize_entry("from", from)?;
                map.serialize_entry("to", to)?;
                map.serialize_entry("message", message)?;
            }
            Step::ExpectSbi {
                from,
                to,
                operation,
            } => {
                map.serialize_entry("kind", "expect_sbi")?;
                map.serialize_entry("from", from)?;
                map.serialize_entry("to", to)?;
                map.serialize_entry("operation", operation)?;
            }
            Step::ExpectNgap { from, to, message } => {
                map.serialize_entry("kind", "expect_ngap")?;
                map.serialize_entry("from", from)?;
                map.serialize_entry("to", to)?;
                map.serialize_entry("message", message)?;
            }
            Step::PeerUnavailable { target } => {
                map.serialize_entry("kind", "peer_unavailable")?;
                map.serialize_entry("target", target)?;
            }
            Step::DelayedResponse { target, delay_ms } => {
                map.serialize_entry("kind", "delayed_response")?;
                map.serialize_entry("target", target)?;
                map.serialize_entry("delay_ms", delay_ms)?;
            }
            Step::MalformedResponse { target } => {
                map.serialize_entry("kind", "malformed_response")?;
                map.serialize_entry("target", target)?;
            }
            Step::DependencyTimeout { target } => {
                map.serialize_entry("kind", "dependency_timeout")?;
                map.serialize_entry("target", target)?;
            }
            Step::ClockJump { duration_ms } => {
                map.serialize_entry("kind", "clock_jump")?;
                map.serialize_entry("duration_ms", duration_ms)?;
            }
            Step::ProcessRestart { target } => {
                map.serialize_entry("kind", "process_restart")?;
                map.serialize_entry("target", target)?;
            }
            Step::NetworkPartition { node_a, node_b } => {
                map.serialize_entry("kind", "network_partition")?;
                map.serialize_entry("node_a", node_a)?;
                map.serialize_entry("node_b", node_b)?;
            }
            Step::Other => {
                map.serialize_entry("kind", "other")?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(deserializer)?;

        if let Some(obj) = value.as_object() {
            // Tagged form: object contains "kind" key.
            if obj.contains_key("kind") {
                let tagged: TaggedStep = serde_json::from_value(value)
                    .map_err(|e| D::Error::custom(format!("invalid tagged step: {e}")))?;
                return Ok(tagged.into());
            }

            // Canonical RFC 012 form: single-key map (e.g. { "send_ngap": { ... } }).
            if obj.len() == 1 {
                if let Some((key, val)) = obj.iter().next() {
                    return parse_canonical_step::<D::Error>(key, val);
                } else {
                    return Err(D::Error::custom(
                        "unexpected empty object despite non-zero length",
                    ));
                }
            }
        }

        Ok(Step::Other)
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TaggedStep {
    SendNgap {
        from: String,
        to: String,
        message: String,
    },
    ExpectSbi {
        from: String,
        to: String,
        operation: String,
    },
    ExpectNgap {
        from: String,
        to: String,
        message: String,
    },
    PeerUnavailable {
        target: String,
    },
    DelayedResponse {
        target: String,
        delay_ms: u64,
    },
    MalformedResponse {
        target: String,
    },
    DependencyTimeout {
        target: String,
    },
    ClockJump {
        duration_ms: u64,
    },
    ProcessRestart {
        target: String,
    },
    NetworkPartition {
        node_a: String,
        node_b: String,
    },
    #[serde(other)]
    Other,
}

impl From<TaggedStep> for Step {
    fn from(t: TaggedStep) -> Self {
        match t {
            TaggedStep::SendNgap { from, to, message } => Step::SendNgap { from, to, message },
            TaggedStep::ExpectSbi {
                from,
                to,
                operation,
            } => Step::ExpectSbi {
                from,
                to,
                operation,
            },
            TaggedStep::ExpectNgap { from, to, message } => Step::ExpectNgap { from, to, message },
            TaggedStep::PeerUnavailable { target } => Step::PeerUnavailable { target },
            TaggedStep::DelayedResponse { target, delay_ms } => {
                Step::DelayedResponse { target, delay_ms }
            }
            TaggedStep::MalformedResponse { target } => Step::MalformedResponse { target },
            TaggedStep::DependencyTimeout { target } => Step::DependencyTimeout { target },
            TaggedStep::ClockJump { duration_ms } => Step::ClockJump { duration_ms },
            TaggedStep::ProcessRestart { target } => Step::ProcessRestart { target },
            TaggedStep::NetworkPartition { node_a, node_b } => {
                Step::NetworkPartition { node_a, node_b }
            }
            TaggedStep::Other => Step::Other,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendNgapCanonical {
    from: String,
    to: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectSbiCanonical {
    from: String,
    to: String,
    operation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectNgapCanonical {
    from: String,
    to: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerUnavailableCanonical {
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelayedResponseCanonical {
    target: String,
    delay_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MalformedResponseCanonical {
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyTimeoutCanonical {
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockJumpCanonical {
    duration_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRestartCanonical {
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPartitionCanonical {
    node_a: String,
    node_b: String,
}

fn parse_canonical_step<E>(kind: &str, val: &serde_json::Value) -> Result<Step, E>
where
    E: serde::de::Error,
{
    match kind {
        "send_ngap" => {
            let payload: SendNgapCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid send_ngap step: {e}")))?;
            Ok(Step::SendNgap {
                from: payload.from,
                to: payload.to,
                message: payload.message,
            })
        }
        "expect_sbi" => {
            let payload: ExpectSbiCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid expect_sbi step: {e}")))?;
            Ok(Step::ExpectSbi {
                from: payload.from,
                to: payload.to,
                operation: payload.operation,
            })
        }
        "expect_ngap" => {
            let payload: ExpectNgapCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid expect_ngap step: {e}")))?;
            Ok(Step::ExpectNgap {
                from: payload.from,
                to: payload.to,
                message: payload.message,
            })
        }
        "peer_unavailable" => {
            let payload: PeerUnavailableCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid peer_unavailable step: {e}")))?;
            Ok(Step::PeerUnavailable {
                target: payload.target,
            })
        }
        "delayed_response" => {
            let payload: DelayedResponseCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid delayed_response step: {e}")))?;
            Ok(Step::DelayedResponse {
                target: payload.target,
                delay_ms: payload.delay_ms,
            })
        }
        "malformed_response" => {
            let payload: MalformedResponseCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid malformed_response step: {e}")))?;
            Ok(Step::MalformedResponse {
                target: payload.target,
            })
        }
        "dependency_timeout" => {
            let payload: DependencyTimeoutCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid dependency_timeout step: {e}")))?;
            Ok(Step::DependencyTimeout {
                target: payload.target,
            })
        }
        "clock_jump" => {
            let payload: ClockJumpCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid clock_jump step: {e}")))?;
            Ok(Step::ClockJump {
                duration_ms: payload.duration_ms,
            })
        }
        "process_restart" => {
            let payload: ProcessRestartCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid process_restart step: {e}")))?;
            Ok(Step::ProcessRestart {
                target: payload.target,
            })
        }
        "network_partition" => {
            let payload: NetworkPartitionCanonical = serde_json::from_value(val.clone())
                .map_err(|e| E::custom(format!("invalid network_partition step: {e}")))?;
            Ok(Step::NetworkPartition {
                node_a: payload.node_a,
                node_b: payload.node_b,
            })
        }
        _ => Ok(Step::Other),
    }
}
