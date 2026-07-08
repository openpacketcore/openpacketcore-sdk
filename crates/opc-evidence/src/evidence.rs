use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ConformanceStatus, RequirementId};

/// A single evidence record linking a requirement to its implementation,
/// tests, gaps, and artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub requirement_id: RequirementId,
    pub status: ConformanceStatus,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub test_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub gap_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub waiver_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub artifact_digests: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub reviewed_by: Vec<String>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_updated: Option<OffsetDateTime>,
}

impl EvidenceRecord {
    pub fn new(requirement_id: RequirementId, status: ConformanceStatus) -> Self {
        Self {
            requirement_id,
            status,
            source_refs: Vec::new(),
            test_refs: Vec::new(),
            gap_refs: Vec::new(),
            waiver_refs: Vec::new(),
            artifact_digests: Vec::new(),
            reviewed_by: Vec::new(),
            last_updated: None,
        }
    }
}

/// A first-class waiver record for a temporarily waived requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaiverRecord {
    pub id: String,
    pub requirement_id: RequirementId,
    pub approver: String,
    pub justification: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub approved: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ticket_ref: Option<String>,
}
