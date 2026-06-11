use crate::EvidenceError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Decisions matching the VEX schema
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexDecision {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl std::str::FromStr for VexDecision {
    type Err = EvidenceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "not_affected" | "not-affected" => Ok(VexDecision::NotAffected),
            "affected" => Ok(VexDecision::Affected),
            "fixed" => Ok(VexDecision::Fixed),
            "under_investigation" | "under-investigation" => Ok(VexDecision::UnderInvestigation),
            _ => Err(EvidenceError::GapGateFailed(format!(
                "malformed VEX status: {}",
                s
            ))),
        }
    }
}

/// Structured policy result matching vex-policy-result.schema.json
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VexPolicyResult {
    pub schema_version: String,
    pub generated_at: String,
    pub vulnerability_id: String,
    pub decision: VexDecision,
    pub justification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

impl VexPolicyResult {
    pub fn new(
        vulnerability_id: String,
        decision: VexDecision,
        justification: String,
        action: Option<String>,
    ) -> Result<Self, EvidenceError> {
        if vulnerability_id.trim().is_empty() {
            return Err(EvidenceError::GapGateFailed(
                "vulnerability_id cannot be empty".into(),
            ));
        }
        if justification.trim().is_empty() {
            return Err(EvidenceError::GapGateFailed(
                "justification cannot be empty".into(),
            ));
        }

        let timestamp = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| {
                EvidenceError::GapGateFailed(format!("failed to format timestamp: {}", e))
            })?;

        Ok(Self {
            schema_version: "1.0.0".to_string(),
            generated_at: timestamp,
            vulnerability_id,
            decision,
            justification,
            action,
        })
    }
}

/// A wrapper matching a VEX decision to a specific dependency package and version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VexRecord {
    pub package_name: String,
    pub package_version: String,
    pub policy_result: VexPolicyResult,
    pub source_evidence: Option<String>,
}

/// Validates the VexRecord to ensure it has all required fields.
pub fn validate_vex_record(record: &VexRecord) -> Result<(), EvidenceError> {
    if record.package_name.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "missing package name in VEX record".into(),
        ));
    }
    if record.package_version.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "missing package version in VEX record".into(),
        ));
    }
    if record.policy_result.vulnerability_id.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "missing vulnerability ID in VEX record".into(),
        ));
    }
    if record.policy_result.justification.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "missing justification in VEX record".into(),
        ));
    }
    Ok(())
}
