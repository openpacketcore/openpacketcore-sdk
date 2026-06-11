//! Evidence output for scenario runs (RFC 012 §14, RFC 006 §4.3).
//!
//! Each scenario execution emits a structured record consumed by the RFC 006
//! conformance pipeline. The record links requirements, seed, mode, artifacts,
//! and outcome so that conformance status can be calculated end-to-end.

use crate::fixtures::FixtureProvenance;
use opc_evidence::{ConformanceStatus, EvidenceRecord, RequirementId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use time::OffsetDateTime;

/// Outcome of a single scenario execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioOutcome {
    Pass,
    Fail,
    Skipped,
    Error,
}

/// Evidence record emitted by a scenario run, shaped per RFC 012 §14
/// and compatible with RFC 006 evidence consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEvidence {
    pub scenario_id: String,
    #[serde(default)]
    pub scenario_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixture_provenance: Vec<FixtureProvenance>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub simulator_versions: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_summary: Option<String>,
    /// Artifact paths collected during the scenario run.  These are *not*
    /// cryptographic digests; downstream evidence bundling computes
    /// `sha256:...` digests before storing them in [`EvidenceRecord`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    pub outcome: ScenarioOutcome,
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub started_at: Option<OffsetDateTime>,
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<OffsetDateTime>,
}

impl ScenarioEvidence {
    pub fn new(scenario_id: impl Into<String>, outcome: ScenarioOutcome) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            scenario_version: crate::scenario::DSL_VERSION.to_string(),
            requirements: Vec::new(),
            mode: None,
            runner_mode: None,
            seed: None,
            fixture_provenance: Vec::new(),
            simulator_versions: HashMap::new(),
            failure_summary: None,
            artifacts: Vec::new(),
            outcome,
            started_at: None,
            finished_at: None,
        }
    }

    /// Sets the failure summary, running it through the redaction sanitizer
    /// to ensure no secrets or customer info are leaked.
    pub fn set_failure_summary(&mut self, summary: &str) {
        let mut redaction_summary = opc_redaction::RedactionSummary::default();
        let redacted = opc_redaction::redact_text(summary, &mut redaction_summary);
        self.failure_summary = Some(redacted);
    }

    /// Convert this scenario evidence into RFC 006 [`EvidenceRecord`]s for
    /// each linked requirement.
    ///
    /// Status mapping:
    /// - Pass → `Tested` (tests exercised the requirement)
    /// - Fail → `Partial` (tests ran but did not fully pass)
    /// - Skipped / Error → `Gap` (evidence exists but is inconclusive)
    ///
    /// # Fail-closed behaviour
    ///
    /// Malformed requirement IDs are **not** silently dropped. Instead, the
    /// function returns `Err` so that data-quality issues surface immediately.
    pub fn to_evidence_records(&self) -> Result<Vec<EvidenceRecord>, crate::TestbedError> {
        if self.requirements.is_empty() {
            return Err(crate::TestbedError::Evidence(format!(
                "scenario '{}' has no linked requirements; evidence cannot be emitted",
                self.scenario_id
            )));
        }
        if self.requirements.iter().any(|r| r.trim().is_empty()) {
            return Err(crate::TestbedError::Evidence(format!(
                "scenario '{}' has no linked requirements; evidence cannot be emitted",
                self.scenario_id
            )));
        }

        let status = match self.outcome {
            ScenarioOutcome::Pass => ConformanceStatus::Tested,
            ScenarioOutcome::Fail => ConformanceStatus::Partial,
            ScenarioOutcome::Skipped | ScenarioOutcome::Error => ConformanceStatus::Gap,
        };

        let mut records = Vec::with_capacity(self.requirements.len());
        for req in &self.requirements {
            let rid = RequirementId::from_str(req).map_err(|e| {
                crate::TestbedError::Evidence(format!(
                    "malformed requirement id '{req}' in scenario '{}': {e}",
                    self.scenario_id
                ))
            })?;
            let mut rec = EvidenceRecord::new(rid, status);
            rec.test_refs.push(format!(
                "crates/opc-testbed/scenario/{}:run",
                self.scenario_id
            ));
            if !self.artifacts.is_empty() {
                rec.test_refs.extend(self.artifacts.iter().cloned());
            }
            records.push(rec);
        }
        Ok(records)
    }
}
