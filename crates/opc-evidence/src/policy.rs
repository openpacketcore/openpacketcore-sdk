use crate::{gap::GapStatus, ConformanceStatus, EvidenceError, EvidenceRecord, Gap, WaiverRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    PullRequest,
    Release,
}

#[derive(Debug, Clone)]
pub struct GatePolicy {
    pub mode: PolicyMode,
    pub require_sbom: bool,
    pub require_vex: bool,
    pub require_provenance: bool,
    pub require_performance: bool,
    pub require_data_governance: bool,
    pub allow_dirty_worktree: bool,
    pub expected_git_commit: Option<String>,
}

pub struct GateEvaluator<'a> {
    pub policy: &'a GatePolicy,
}

impl<'a> GateEvaluator<'a> {
    pub fn new(policy: &'a GatePolicy) -> Self {
        Self { policy }
    }

    /// Evaluates release and PR gate compliance.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        records: &[EvidenceRecord],
        gaps: &[Gap],
        bundle: Option<&crate::bundle::EvidenceBundle>,
        conformance_report: Option<&str>,
        sbom: Option<&str>,
        vex: Option<&str>,
        provenance: Option<&str>,
        performance_baseline: Option<&str>,
        data_governance_report: Option<&str>,
        verifier: Option<&dyn crate::bundle::BundleVerifier>,
        files: Option<&std::collections::HashMap<String, Vec<u8>>>,
    ) -> Result<(), EvidenceError> {
        self.evaluate_with_waivers(
            records,
            gaps,
            &[],
            bundle,
            conformance_report,
            sbom,
            vex,
            provenance,
            performance_baseline,
            data_governance_report,
            verifier,
            files,
        )
    }

    /// Evaluates release and PR gate compliance with explicit waiver records.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_waivers(
        &self,
        records: &[EvidenceRecord],
        gaps: &[Gap],
        waivers: &[WaiverRecord],
        bundle: Option<&crate::bundle::EvidenceBundle>,
        conformance_report: Option<&str>,
        sbom: Option<&str>,
        vex: Option<&str>,
        provenance: Option<&str>,
        performance_baseline: Option<&str>,
        data_governance_report: Option<&str>,
        verifier: Option<&dyn crate::bundle::BundleVerifier>,
        files: Option<&std::collections::HashMap<String, Vec<u8>>>,
    ) -> Result<(), EvidenceError> {
        // 1. conformance status is full/implemented/tested but required evidence is absent
        for record in records {
            let status = record.status;
            match status {
                ConformanceStatus::Full => {
                    if record.source_refs.is_empty() {
                        return Err(EvidenceError::GapGateFailed(format!(
                            "Requirement {} has status Full but missing source_refs",
                            record.requirement_id
                        )));
                    }
                    if record.test_refs.is_empty() {
                        return Err(EvidenceError::GapGateFailed(format!(
                            "Requirement {} has status Full but missing test_refs",
                            record.requirement_id
                        )));
                    }
                }
                ConformanceStatus::Implemented if record.source_refs.is_empty() => {
                    return Err(EvidenceError::GapGateFailed(format!(
                        "Requirement {} has status Implemented but missing source_refs",
                        record.requirement_id
                    )));
                }
                ConformanceStatus::Tested if record.test_refs.is_empty() => {
                    return Err(EvidenceError::GapGateFailed(format!(
                        "Requirement {} has status Tested but missing test_refs",
                        record.requirement_id
                    )));
                }
                ConformanceStatus::Waived => {
                    validate_waived_record(record, waivers)?;
                }
                _ => {}
            }

            // 2. partial status lacks a structured open gap
            if status == ConformanceStatus::Partial {
                if record.gap_refs.is_empty() {
                    return Err(EvidenceError::GapGateFailed(format!(
                        "Requirement {} has status Partial but no gap_refs",
                        record.requirement_id
                    )));
                }
                for gap_ref in &record.gap_refs {
                    let matching_gap = gaps.iter().find(|g| g.id == *gap_ref);
                    match matching_gap {
                        Some(gap) => {
                            if gap.status != GapStatus::Open && gap.status != GapStatus::Deferred {
                                return Err(EvidenceError::GapGateFailed(format!(
                                    "Requirement {} has status Partial but gap {} is closed",
                                    record.requirement_id, gap.id
                                )));
                            }
                        }
                        None => {
                            return Err(EvidenceError::GapGateFailed(format!(
                                "Requirement {} has status Partial but gap {} is not found in gaps database",
                                record.requirement_id, gap_ref
                            )));
                        }
                    }
                }
            }
        }

        // 3. SBOM/VEX/provenance/performance artifacts are missing when policy requires them
        if self.policy.require_sbom && sbom.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "SBOM is missing but required by policy".to_string(),
            ));
        }
        if self.policy.require_vex && vex.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "VEX is missing but required by policy".to_string(),
            ));
        }
        if self.policy.require_provenance && provenance.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "Provenance is missing but required by policy".to_string(),
            ));
        }
        if self.policy.require_performance && performance_baseline.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "Performance baseline is missing but required by policy".to_string(),
            ));
        }
        if self.policy.require_data_governance && data_governance_report.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "Data governance report is missing but required by policy".to_string(),
            ));
        }

        validate_json_artifact("SBOM", sbom)?;
        validate_json_artifact("VEX", vex)?;
        validate_json_artifact("provenance", provenance)?;
        validate_json_artifact("performance baseline", performance_baseline)?;
        validate_json_artifact("Data governance report", data_governance_report)?;

        if let Some(dg_str) = data_governance_report {
            let report: crate::data_governance::DataGovernanceEvidenceReport =
                serde_json::from_str(dg_str).map_err(|e| {
                    EvidenceError::GapGateFailed(format!(
                        "malformed data governance report JSON: {e}"
                    ))
                })?;
            report.validate().map_err(EvidenceError::GapGateFailed)?;
        }

        // 4. bundle signature or digest verification fails
        let release_requires_bundle = self.policy.mode == PolicyMode::Release
            && (self.policy.require_sbom
                || self.policy.require_vex
                || self.policy.require_provenance
                || self.policy.require_performance
                || self.policy.require_data_governance);
        if release_requires_bundle && bundle.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "release policy requires a signed evidence bundle".to_string(),
            ));
        }

        if let Some(b) = bundle {
            let verifier = verifier.ok_or_else(|| {
                EvidenceError::GapGateFailed("missing verifier for bundle verification".to_string())
            })?;
            let files = files.ok_or_else(|| {
                EvidenceError::GapGateFailed("missing files for bundle verification".to_string())
            })?;
            crate::bundle::verify_bundle(b, verifier, files)?;
        } else if verifier.is_some() || files.is_some() {
            return Err(EvidenceError::GapGateFailed(
                "verifier/files supplied without a bundle".to_string(),
            ));
        }

        // 5. provenance git commit does not match expected commit
        if let Some(prov_str) = provenance {
            let prov: crate::provenance::ProvenanceStatement = serde_json::from_str(prov_str)
                .map_err(|e| {
                    EvidenceError::GapGateFailed(format!("malformed provenance JSON: {e}"))
                })?;
            let prov_commit = &prov.predicate.invocation.environment.git_commit;

            if let Some(ref expected) = self.policy.expected_git_commit {
                if prov_commit != expected {
                    return Err(EvidenceError::GapGateFailed(format!(
                        "provenance git commit '{prov_commit}' does not match expected '{expected}'"
                    )));
                }
            }

            // 6. release policy sees dirty worktree unless explicitly allowed
            let is_dirty = prov.predicate.invocation.environment.worktree_dirty;
            if is_dirty
                && !self.policy.allow_dirty_worktree
                && self.policy.mode == PolicyMode::Release
            {
                return Err(EvidenceError::GapGateFailed(
                    "release policy does not allow dirty worktree".to_string(),
                ));
            }
        }

        // 7. generated evidence contains unsafe labels/paths/secrets
        let check_unsafe = |content: &str| -> Result<(), EvidenceError> {
            for line in content.lines() {
                if line.contains("/Users/") || line.contains("/home/") {
                    // Do not fail if it contains a known safe path like /home/runner/
                    if !line.contains("/home/runner/") {
                        return Err(EvidenceError::GapGateFailed(
                            "evidence contains unsafe absolute path".to_string(),
                        ));
                    }
                }

                let lower = line.to_lowercase();
                if lower.contains("password=")
                    || lower.contains("secret=")
                    || lower.contains("token=")
                    || lower.contains("authorization:")
                    || lower.contains("bearer ")
                    || lower.contains("-----begin")
                    || lower.contains("private_key")
                    || lower.contains("client_secret")
                {
                    return Err(EvidenceError::GapGateFailed(
                        "evidence contains potential secret".to_string(),
                    ));
                }

                if contains_ipv4(line) {
                    return Err(EvidenceError::GapGateFailed(
                        "evidence contains IPv4 address".to_string(),
                    ));
                }
                if contains_ipv6(line) {
                    return Err(EvidenceError::GapGateFailed(
                        "evidence contains IPv6 address".to_string(),
                    ));
                }
                if contains_raw_identifier_context(line) {
                    return Err(EvidenceError::GapGateFailed(
                        "evidence contains raw numeric identifier".to_string(),
                    ));
                }
            }
            Ok(())
        };

        if let Some(r) = conformance_report {
            check_unsafe(r)?;
        }
        if let Some(s) = sbom {
            check_unsafe(s)?;
        }
        if let Some(v) = vex {
            check_unsafe(v)?;
        }
        if let Some(p) = provenance {
            check_unsafe(p)?;
        }
        if let Some(pf) = performance_baseline {
            check_unsafe(pf)?;
        }
        if let Some(dg) = data_governance_report {
            check_unsafe(dg)?;
        }

        Ok(())
    }
}

fn validate_waived_record(
    record: &EvidenceRecord,
    waivers: &[WaiverRecord],
) -> Result<(), EvidenceError> {
    if record.waiver_refs.is_empty() {
        return Err(EvidenceError::GapGateFailed(format!(
            "Requirement {} has status Waived but no waiver_refs",
            record.requirement_id
        )));
    }

    let now = time::OffsetDateTime::now_utc();
    for waiver_ref in &record.waiver_refs {
        let waiver = waivers
            .iter()
            .find(|w| w.id == *waiver_ref)
            .ok_or_else(|| {
                EvidenceError::GapGateFailed(format!(
                    "Requirement {} references waiver {} but no waiver record was provided",
                    record.requirement_id, waiver_ref
                ))
            })?;

        if waiver.requirement_id != record.requirement_id {
            return Err(EvidenceError::GapGateFailed(format!(
                "Waiver {} applies to {} but record is for {}",
                waiver.id, waiver.requirement_id, record.requirement_id
            )));
        }
        if !waiver.approved {
            return Err(EvidenceError::GapGateFailed(format!(
                "Waiver {} for requirement {} is not approved",
                waiver.id, record.requirement_id
            )));
        }
        if waiver.approver.trim().is_empty() {
            return Err(EvidenceError::GapGateFailed(format!(
                "Waiver {} for requirement {} lacks an approver",
                waiver.id, record.requirement_id
            )));
        }
        if waiver.justification.trim().is_empty() {
            return Err(EvidenceError::GapGateFailed(format!(
                "Waiver {} for requirement {} lacks a justification",
                waiver.id, record.requirement_id
            )));
        }
        if waiver.expires_at <= now {
            return Err(EvidenceError::GapGateFailed(format!(
                "Waiver {} for requirement {} is expired",
                waiver.id, record.requirement_id
            )));
        }
    }

    Ok(())
}

fn validate_json_artifact(name: &str, content: Option<&str>) -> Result<(), EvidenceError> {
    if let Some(raw) = content {
        serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|e| EvidenceError::GapGateFailed(format!("{name} is not valid JSON: {e}")))?;
    }
    Ok(())
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

fn contains_ipv6(input: &str) -> bool {
    input
        .split(|c: char| !(c.is_ascii_hexdigit() || c == ':'))
        .any(|candidate| {
            let colon_count = candidate.chars().filter(|&c| c == ':').count();
            (candidate.contains("::") || colon_count >= 3)
                && candidate.chars().any(|c| c.is_ascii_hexdigit())
                && candidate.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        })
}

fn contains_raw_identifier_context(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    const MARKERS: [&str; 7] = [
        "subscriber",
        "supi",
        "gpsi",
        "imsi",
        "msisdn",
        "guti",
        "pei",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
        && input
            .split(|c: char| !c.is_ascii_digit())
            .any(|candidate| candidate.len() >= 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_detection_does_not_treat_times_as_addresses() {
        assert!(!contains_ipv6("timestamp 12:34:56"));
        assert!(contains_ipv6("peer 2001:db8::1"));
    }
}
