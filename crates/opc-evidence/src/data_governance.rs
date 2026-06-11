use opc_data_governance::DataClass;
use serde::{Deserialize, Serialize};

/// Data governance evidence report for RFC 010 compliance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataGovernanceEvidenceReport {
    pub observed_data_classes: Vec<DataClass>,
    pub support_bundle_redaction_policy_version: String,
    pub retention_policy_ids: Vec<String>,
    pub minimization_policy_ids: Vec<String>,
    pub validation_status: String,
    pub sanitized_findings: Vec<String>,
}

impl DataGovernanceEvidenceReport {
    pub fn validate(&self) -> Result<(), String> {
        if self.observed_data_classes.is_empty() {
            return Err("data governance report has no observed data classes".to_string());
        }
        if self
            .support_bundle_redaction_policy_version
            .trim()
            .is_empty()
        {
            return Err("data governance report has no redaction policy version".to_string());
        }
        if self.retention_policy_ids.is_empty()
            || self
                .retention_policy_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return Err("data governance report has no retention policy evidence".to_string());
        }
        if self.minimization_policy_ids.is_empty()
            || self
                .minimization_policy_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return Err("data governance report has no minimization policy evidence".to_string());
        }

        let status = self.validation_status.trim().to_ascii_lowercase();
        if !matches!(status.as_str(), "pass" | "passed" | "success") {
            return Err("data governance report validation did not pass".to_string());
        }

        for finding in &self.sanitized_findings {
            if finding_has_unsafe_content(finding) {
                return Err("data governance report contains unsafe finding content".to_string());
            }
        }

        Ok(())
    }
}

fn finding_has_unsafe_content(finding: &str) -> bool {
    let lower = finding.to_ascii_lowercase();
    lower.contains("/users/")
        || lower.contains("/home/")
        || lower.contains("-----begin")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("authorization:")
        || lower.contains("bearer ")
        || lower.contains("private_key")
        || lower.contains("client_secret")
        || lower.contains("select ")
        || lower.contains("insert ")
        || lower.contains("delete from")
        || lower.contains("update ")
        || lower.contains("sqlite")
        || lower.contains(".db")
        || contains_ipv4(finding)
        || contains_long_digit_id(finding)
        || contains_subscriber_marker(&lower)
}

fn contains_ipv4(input: &str) -> bool {
    input
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|candidate| {
            let parts: Vec<&str> = candidate.split('.').collect();
            parts.len() == 4
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.len() <= 3 && part.parse::<u8>().is_ok())
        })
}

fn contains_long_digit_id(input: &str) -> bool {
    input
        .split(|c: char| !c.is_ascii_digit())
        .any(|part| part.len() >= 8)
}

fn contains_subscriber_marker(lower: &str) -> bool {
    const MARKERS: [&str; 6] = ["supi", "gpsi", "imsi", "msisdn", "guti", "pei"];
    MARKERS.iter().any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_data_governance::DataClass;

    fn valid_report() -> DataGovernanceEvidenceReport {
        DataGovernanceEvidenceReport {
            observed_data_classes: vec![DataClass::Public, DataClass::AnalyticsSensitive],
            support_bundle_redaction_policy_version: "1.0.0".to_string(),
            retention_policy_ids: vec!["ret-1".to_string()],
            minimization_policy_ids: vec!["min-1".to_string()],
            validation_status: "pass".to_string(),
            sanitized_findings: vec!["no sensitive findings".to_string()],
        }
    }

    #[test]
    fn validates_required_fields_and_status() {
        assert!(valid_report().validate().is_ok());

        let mut failed = valid_report();
        failed.validation_status = "fail".to_string();
        assert!(failed.validate().is_err());

        let mut missing = valid_report();
        missing.retention_policy_ids.clear();
        assert!(missing.validate().is_err());
    }

    #[test]
    fn rejects_unsafe_findings() {
        for finding in [
            "leaked imsi 208950000000001",
            "database /Users/example/private.db",
            "Authorization: Bearer token",
            "SELECT * FROM subscribers",
            "client 10.0.0.1",
        ] {
            let mut report = valid_report();
            report.sanitized_findings = vec![finding.to_string()];
            assert!(report.validate().is_err(), "{finding}");
        }
    }
}
