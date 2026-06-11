//! Fixture provenance model (RFC 012 §8).
//!
//! Every protocol fixture (PCAP, JSON, binary) must carry machine-readable
//! provenance, sanitization status, and linkage to requirements. Real
//! subscriber data is forbidden.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Provenance record required for every fixture used in scenarios.
///
/// Per RFC 012 §8, every fixture must declare:
/// - the normative source standard reference,
/// - release / version,
/// - generation tool or capture provenance,
/// - whether synthetic or captured,
/// - sanitization status,
/// - expected decode result,
/// - linked requirement IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureProvenance {
    pub id: String,
    /// Human or tool that produced the fixture (provenance).
    pub source: String,
    /// Normative source standard reference (e.g. "3GPP TS 24.501").
    pub standard_ref: String,
    /// 3GPP / IETF release or version the fixture targets.
    pub release: String,
    /// Whether the data is purely synthetic or derived from a capture.
    pub synthetic: bool,
    /// Sanitization / redaction status. "none" is only acceptable for fully
    /// synthetic fixtures with no possibility of PII.
    pub sanitization: String,
    /// Expected decode result for this fixture (e.g. "DecodeSuccess(NasMessage)").
    pub expected_decode: String,
    /// RFC 006 style requirement IDs this fixture exercises.
    #[serde(default)]
    pub requirements: Vec<String>,
    /// Optional notes (e.g. generation command or PCAP link in private repo).
    #[serde(default)]
    pub notes: Option<String>,
}

impl FixtureProvenance {
    pub fn validate(&self) -> Result<(), crate::TestbedError> {
        if self.id.trim().is_empty() {
            return Err(crate::TestbedError::Fixture("id must be non-empty".into()));
        }
        if self.source.trim().is_empty() {
            return Err(crate::TestbedError::Fixture(
                "source must be non-empty".into(),
            ));
        }
        if self.standard_ref.trim().is_empty() {
            return Err(crate::TestbedError::Fixture(
                "standard_ref must be non-empty".into(),
            ));
        }
        if self.release.trim().is_empty() {
            return Err(crate::TestbedError::Fixture(
                "release must be non-empty".into(),
            ));
        }
        let san = self.sanitization.trim();
        if san.is_empty() {
            return Err(crate::TestbedError::Fixture(
                "sanitization must be non-empty".into(),
            ));
        }
        if !self.synthetic && san == "none" {
            return Err(crate::TestbedError::Fixture(
                "captured fixtures must declare a non-empty sanitization status other than 'none'"
                    .into(),
            ));
        }
        if self.expected_decode.trim().is_empty() {
            return Err(crate::TestbedError::Fixture(
                "expected_decode must be non-empty".into(),
            ));
        }
        if self.requirements.is_empty() {
            return Err(crate::TestbedError::Fixture(
                "requirements must contain at least one non-empty requirement id".into(),
            ));
        }
        if self.requirements.iter().any(|r| r.trim().is_empty()) {
            return Err(crate::TestbedError::Fixture(
                "requirements must not contain blank entries".into(),
            ));
        }
        for req in &self.requirements {
            if opc_evidence::RequirementId::from_str(req).is_err() {
                return Err(crate::TestbedError::Fixture(format!(
                    "requirement '{req}' is not a valid RFC 006 requirement id"
                )));
            }
        }
        Ok(())
    }
}

/// Registry stub. In full implementation this will support loading from
/// a fixtures/ directory with provenance sidecars.
#[derive(Default)]
pub struct FixtureRegistry {
    fixtures: std::collections::HashMap<String, FixtureProvenance>,
}

impl FixtureRegistry {
    pub fn register(&mut self, prov: FixtureProvenance) -> Result<(), crate::TestbedError> {
        prov.validate()?;
        if self.fixtures.contains_key(&prov.id) {
            return Err(crate::TestbedError::Fixture(format!(
                "id '{}' already registered",
                prov.id
            )));
        }
        self.fixtures.insert(prov.id.clone(), prov);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&FixtureProvenance> {
        self.fixtures.get(id)
    }
}
