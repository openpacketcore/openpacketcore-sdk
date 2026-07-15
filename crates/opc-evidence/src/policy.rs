use crate::{
    gap::GapStatus, ConformanceStatus, EvidenceError, EvidenceRecord, Gap, Manifest, RequirementId,
    WaiverRecord,
};
use serde::{Deserialize, Serialize};

/// Signed-manifest metadata key binding the structured release-gate inputs.
pub const GATE_INPUTS_DIGEST_METADATA_KEY: &str = "openpacketcore.rfc006.gate-inputs.sha256";

/// Domain separator for the structured release-gate input digest.
pub const GATE_INPUTS_SIGNING_DOMAIN: &str = "openpacketcore:rfc006:gate-inputs:v1";

#[derive(Serialize)]
struct CanonicalGateInputsV1 {
    domain: &'static str,
    gaps: Vec<CanonicalGapV1>,
    records: Vec<CanonicalEvidenceRecordV1>,
    waivers: Vec<CanonicalWaiverV1>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct CanonicalEvidenceRecordV1 {
    artifact_digests: Vec<String>,
    gap_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_updated: Option<String>,
    requirement_id: String,
    reviewed_by: Vec<String>,
    source_refs: Vec<String>,
    status: ConformanceStatus,
    test_refs: Vec<String>,
    waiver_refs: Vec<String>,
}

#[derive(Serialize)]
struct CanonicalGapV1 {
    applies_to: Vec<String>,
    created: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitigation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    performance_impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_approval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_impact: Option<String>,
    severity: crate::GapSeverity,
    status: GapStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_release: Option<String>,
    title: String,
}

#[derive(Serialize)]
struct CanonicalWaiverV1 {
    approved: bool,
    approver: String,
    expires_at: String,
    id: String,
    justification: String,
    requirement_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ticket_ref: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedConformanceReport {
    schema_version: String,
    sdk_version: String,
    git_commit: String,
    generated_at: String,
    requirements: Vec<SignedConformanceRequirement>,
    summary: std::collections::BTreeMap<String, u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedConformanceRequirement {
    requirement_id: RequirementId,
    calculated_status: ConformanceStatus,
    raw_evidence: Vec<SignedEvidenceRecord>,
    #[serde(default)]
    gap_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEvidenceRecord {
    requirement_id: RequirementId,
    status: ConformanceStatus,
    #[serde(default)]
    source_refs: Vec<String>,
    #[serde(default)]
    test_refs: Vec<String>,
    #[serde(default)]
    gap_refs: Vec<String>,
    #[serde(default)]
    artifact_digests: Vec<String>,
    #[serde(default)]
    reviewed_by: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    last_updated: Option<time::OffsetDateTime>,
}

impl SignedEvidenceRecord {
    fn into_evidence_record(self) -> EvidenceRecord {
        EvidenceRecord {
            requirement_id: self.requirement_id,
            status: self.status,
            source_refs: self.source_refs,
            test_refs: self.test_refs,
            gap_refs: self.gap_refs,
            waiver_refs: Vec::new(),
            artifact_digests: self.artifact_digests,
            reviewed_by: self.reviewed_by,
            last_updated: self.last_updated,
        }
    }
}

/// Computes the canonical digest of every structured input that can influence
/// a release-gate decision.
pub fn gate_inputs_digest(
    records: &[EvidenceRecord],
    gaps: &[Gap],
    waivers: &[WaiverRecord],
) -> Result<String, EvidenceError> {
    let canonical = canonical_gate_inputs(records, gaps, waivers)?;
    let bytes = serde_json::to_vec(&canonical).map_err(|_| {
        EvidenceError::GapGateFailed(
            "failed to serialize structured release-gate inputs".to_string(),
        )
    })?;
    Ok(crate::manifest::compute_digest(&bytes))
}

/// Binds structured release-gate inputs into metadata covered by the manifest
/// and complete-bundle signatures.
pub fn bind_gate_inputs(
    manifest: &mut Manifest,
    records: &[EvidenceRecord],
    gaps: &[Gap],
    waivers: &[WaiverRecord],
) -> Result<(), EvidenceError> {
    let digest = gate_inputs_digest(records, gaps, waivers)?;
    manifest
        .metadata
        .insert(GATE_INPUTS_DIGEST_METADATA_KEY.to_string(), digest);
    Ok(())
}

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
        if self.policy.expected_git_commit.is_some() && provenance.is_none() {
            return Err(EvidenceError::GapGateFailed(
                "Provenance is missing but required by the expected-commit policy".to_string(),
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

        validate_json_artifact("conformance report", conformance_report)?;
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
        let release_artifact_supplied = conformance_report.is_some()
            || sbom.is_some()
            || vex.is_some()
            || provenance.is_some()
            || performance_baseline.is_some()
            || data_governance_report.is_some();
        let release_gate_inputs_supplied =
            !records.is_empty() || !gaps.is_empty() || !waivers.is_empty();
        let release_requires_bundle = self.policy.mode == PolicyMode::Release
            && (release_artifact_supplied
                || release_gate_inputs_supplied
                || self.policy.require_sbom
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
            if self.policy.mode == PolicyMode::Release
                && verifier.security() != crate::bundle::BundleVerifierSecurity::Release
            {
                return Err(EvidenceError::GapGateFailed(
                    "release policy requires a non-mock bundle verifier".to_string(),
                ));
            }
            if self.policy.mode == PolicyMode::Release && verifier.identity().is_none() {
                return Err(EvidenceError::GapGateFailed(
                    "release policy requires an authenticated bundle signing identity".to_string(),
                ));
            }
            let files = files.ok_or_else(|| {
                EvidenceError::GapGateFailed("missing files for bundle verification".to_string())
            })?;
            crate::bundle::verify_bundle(b, verifier, files)?;
            verify_signed_artifact_match(
                "conformance report",
                b.conformance_report.as_deref(),
                conformance_report,
            )?;
            verify_signed_artifact_match("SBOM", b.sbom.as_deref(), sbom)?;
            verify_signed_artifact_match("VEX", b.vex.as_deref(), vex)?;
            verify_signed_artifact_match("provenance", b.provenance.as_deref(), provenance)?;
            verify_signed_artifact_match(
                "performance baseline",
                b.performance_baseline.as_deref(),
                performance_baseline,
            )?;
            verify_signed_artifact_match(
                "data governance report",
                b.data_governance_report.as_deref(),
                data_governance_report,
            )?;
            if self.policy.mode == PolicyMode::Release {
                // Every release bundle binds the complete gate-input set,
                // including the empty set. Otherwise a caller could omit all
                // typed inputs and skip a non-empty signed binding.
                verify_gate_inputs_binding(&b.manifest, records, gaps, waivers)?;
                if let Some(report) = conformance_report {
                    verify_conformance_report_inputs(report, records, &b.manifest)?;
                }
            }
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
                    return Err(EvidenceError::GapGateFailed(
                        "provenance git commit does not match release policy".to_string(),
                    ));
                }
            }
            if bundle.is_some_and(|bundle| prov_commit != &bundle.manifest.git_commit) {
                return Err(EvidenceError::GapGateFailed(
                    "provenance git commit does not match the signed manifest".to_string(),
                ));
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

fn verify_signed_artifact_match(
    label: &str,
    signed: Option<&str>,
    evaluated: Option<&str>,
) -> Result<(), EvidenceError> {
    if signed == evaluated {
        return Ok(());
    }
    Err(EvidenceError::GapGateFailed(format!(
        "{label} does not exactly match the signed evidence bundle"
    )))
}

fn canonical_gate_inputs(
    records: &[EvidenceRecord],
    gaps: &[Gap],
    waivers: &[WaiverRecord],
) -> Result<CanonicalGateInputsV1, EvidenceError> {
    let records = records
        .iter()
        .map(|record| {
            let mut source_refs = record.source_refs.clone();
            source_refs.sort();
            let mut test_refs = record.test_refs.clone();
            test_refs.sort();
            let mut gap_refs = record.gap_refs.clone();
            gap_refs.sort();
            let mut waiver_refs = record.waiver_refs.clone();
            waiver_refs.sort();
            let mut artifact_digests = record.artifact_digests.clone();
            artifact_digests.sort();
            let mut reviewed_by = record.reviewed_by.clone();
            reviewed_by.sort();
            let last_updated = record
                .last_updated
                .map(|timestamp| {
                    timestamp
                        .to_offset(time::UtcOffset::UTC)
                        .format(&time::format_description::well_known::Rfc3339)
                        .map_err(|_| {
                            EvidenceError::GapGateFailed(
                                "failed to canonicalize structured release-gate inputs".to_string(),
                            )
                        })
                })
                .transpose()?;
            Ok(CanonicalEvidenceRecordV1 {
                artifact_digests,
                gap_refs,
                last_updated,
                requirement_id: record.requirement_id.to_string(),
                reviewed_by,
                source_refs,
                status: record.status,
                test_refs,
                waiver_refs,
            })
        })
        .collect::<Result<Vec<_>, EvidenceError>>()?;

    let mut gap_ids = std::collections::HashSet::new();
    let gaps = gaps
        .iter()
        .map(|gap| {
            if !gap_ids.insert(gap.id.clone()) {
                return Err(EvidenceError::GapGateFailed(
                    "structured release-gate inputs contain a duplicate gap".to_string(),
                ));
            }
            let mut applies_to = gap.applies_to.clone();
            applies_to.sort();
            let date_format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
                .map_err(|_| {
                    EvidenceError::GapGateFailed(
                        "failed to canonicalize structured release-gate inputs".to_string(),
                    )
                })?;
            let created = gap.created.format(&date_format).map_err(|_| {
                EvidenceError::GapGateFailed(
                    "failed to canonicalize structured release-gate inputs".to_string(),
                )
            })?;
            Ok(CanonicalGapV1 {
                applies_to,
                created,
                id: gap.id.clone(),
                mitigation: gap.mitigation.clone(),
                owner: gap.owner.clone(),
                performance_impact: gap.performance_impact.clone(),
                security_approval: gap.security_approval.clone(),
                security_impact: gap.security_impact.clone(),
                severity: gap.severity,
                status: gap.status,
                target_release: gap.target_release.clone(),
                title: gap.title.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut waiver_ids = std::collections::HashSet::new();
    let waivers = waivers
        .iter()
        .map(|waiver| {
            if !waiver_ids.insert(waiver.id.clone()) {
                return Err(EvidenceError::GapGateFailed(
                    "structured release-gate inputs contain a duplicate waiver".to_string(),
                ));
            }
            let expires_at = waiver
                .expires_at
                .to_offset(time::UtcOffset::UTC)
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| {
                    EvidenceError::GapGateFailed(
                        "failed to canonicalize structured release-gate inputs".to_string(),
                    )
                })?;
            Ok(CanonicalWaiverV1 {
                approved: waiver.approved,
                approver: waiver.approver.clone(),
                expires_at,
                id: waiver.id.clone(),
                justification: waiver.justification.clone(),
                requirement_id: waiver.requirement_id.to_string(),
                ticket_ref: waiver.ticket_ref.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CanonicalGateInputsV1 {
        domain: GATE_INPUTS_SIGNING_DOMAIN,
        gaps: sort_by_serialized_form(gaps)?,
        records: sort_by_serialized_form(records)?,
        waivers: sort_by_serialized_form(waivers)?,
    })
}

fn sort_by_serialized_form<T: Serialize>(values: Vec<T>) -> Result<Vec<T>, EvidenceError> {
    let mut keyed = Vec::with_capacity(values.len());
    for value in values {
        let bytes = serde_json::to_vec(&value).map_err(|_| {
            EvidenceError::GapGateFailed(
                "failed to canonicalize structured release-gate inputs".to_string(),
            )
        })?;
        keyed.push((bytes, value));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, value)| value).collect())
}

fn verify_gate_inputs_binding(
    manifest: &Manifest,
    records: &[EvidenceRecord],
    gaps: &[Gap],
    waivers: &[WaiverRecord],
) -> Result<(), EvidenceError> {
    let signed = manifest
        .metadata
        .get(GATE_INPUTS_DIGEST_METADATA_KEY)
        .ok_or_else(|| {
            EvidenceError::GapGateFailed(
                "release bundle does not bind structured gate inputs".to_string(),
            )
        })?;
    let evaluated = gate_inputs_digest(records, gaps, waivers)?;
    if signed != &evaluated {
        return Err(EvidenceError::GapGateFailed(
            "structured gate inputs do not match the signed evidence bundle".to_string(),
        ));
    }
    Ok(())
}

fn verify_conformance_report_inputs(
    raw: &str,
    evaluated_records: &[EvidenceRecord],
    manifest: &Manifest,
) -> Result<(), EvidenceError> {
    let report: SignedConformanceReport = serde_json::from_str(raw).map_err(|_| {
        EvidenceError::GapGateFailed(
            "signed conformance report has an invalid structure".to_string(),
        )
    })?;
    let valid_header = report.schema_version == "1.0.0"
        && !report.sdk_version.trim().is_empty()
        && report.sdk_version == manifest.sdk_version
        && !report.git_commit.is_empty()
        && report.git_commit == manifest.git_commit
        && time::OffsetDateTime::parse(
            &report.generated_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok()
        && !report.requirements.is_empty();
    if !valid_header {
        return Err(EvidenceError::GapGateFailed(
            "signed conformance report is inconsistent with the manifest".to_string(),
        ));
    }

    let mut expected_summary = std::collections::BTreeMap::new();
    for requirement in &report.requirements {
        *expected_summary
            .entry(conformance_status_name(requirement.calculated_status))
            .or_insert(0_u64) += 1;
    }
    let summary_is_consistent = report.summary.iter().all(|(status, count)| {
        is_conformance_status_name(status)
            && expected_summary.get(status.as_str()).copied().unwrap_or(0) == *count
    }) && expected_summary
        .iter()
        .all(|(status, count)| report.summary.get(*status) == Some(count));
    if !summary_is_consistent {
        return Err(EvidenceError::GapGateFailed(
            "signed conformance report summary is inconsistent".to_string(),
        ));
    }

    let mut report_records = Vec::new();
    for requirement in report.requirements {
        if requirement.raw_evidence.is_empty()
            || requirement
                .raw_evidence
                .iter()
                .any(|record| record.requirement_id != requirement.requirement_id)
            || requirement
                .raw_evidence
                .iter()
                .any(|record| !signed_evidence_record_matches_v1_schema(record))
            || requirement.gap_refs.iter().any(|gap| !is_gap_id(gap))
        {
            return Err(EvidenceError::GapGateFailed(
                "signed conformance report has inconsistent requirement evidence".to_string(),
            ));
        }

        let calculated_status = crate::calculate_status(&crate::StatusInputs {
            has_code: requirement
                .raw_evidence
                .iter()
                .any(|record| !record.source_refs.is_empty()),
            has_tests: requirement
                .raw_evidence
                .iter()
                .any(|record| !record.test_refs.is_empty()),
            has_blocking_gap: false,
            has_gap: requirement
                .raw_evidence
                .iter()
                .any(|record| !record.gap_refs.is_empty()),
            has_waiver: requirement
                .raw_evidence
                .iter()
                .any(|record| record.status == ConformanceStatus::Waived),
            reviewed_na: requirement
                .raw_evidence
                .iter()
                .any(|record| record.status == ConformanceStatus::NotApplicable),
        });
        if requirement.calculated_status != calculated_status {
            return Err(EvidenceError::GapGateFailed(
                "signed conformance report has an inconsistent calculated status".to_string(),
            ));
        }

        let mut declared_gap_refs = requirement.gap_refs;
        declared_gap_refs.sort();
        declared_gap_refs.dedup();
        let mut evidence_gap_refs = requirement
            .raw_evidence
            .iter()
            .flat_map(|record| record.gap_refs.iter().cloned())
            .collect::<Vec<_>>();
        evidence_gap_refs.sort();
        evidence_gap_refs.dedup();
        if declared_gap_refs != evidence_gap_refs {
            return Err(EvidenceError::GapGateFailed(
                "signed conformance report has inconsistent gap references".to_string(),
            ));
        }

        report_records.extend(
            requirement
                .raw_evidence
                .into_iter()
                .map(SignedEvidenceRecord::into_evidence_record),
        );
    }

    let signed_records = canonical_gate_inputs(&report_records, &[], &[])?.records;
    let evaluated_report_records = evaluated_records
        .iter()
        .cloned()
        .map(|mut record| {
            // Waiver references are part of the signed gate-input digest. They
            // are not a field in the frozen v1 conformance-report schema.
            record.waiver_refs.clear();
            record
        })
        .collect::<Vec<_>>();
    let evaluated_records = canonical_gate_inputs(&evaluated_report_records, &[], &[])?.records;
    if signed_records != evaluated_records {
        return Err(EvidenceError::GapGateFailed(
            "evaluated records do not match the signed conformance report".to_string(),
        ));
    }
    Ok(())
}

fn conformance_status_name(status: ConformanceStatus) -> &'static str {
    match status {
        ConformanceStatus::Implemented => "implemented",
        ConformanceStatus::Tested => "tested",
        ConformanceStatus::Partial => "partial",
        ConformanceStatus::NotImplemented => "not-implemented",
        ConformanceStatus::NotApplicable => "not-applicable",
        ConformanceStatus::Gap => "gap",
        ConformanceStatus::Waived => "waived",
        ConformanceStatus::Full => "full",
        ConformanceStatus::ImplementedUntested => "implemented-untested",
    }
}

fn is_conformance_status_name(value: &str) -> bool {
    matches!(
        value,
        "implemented"
            | "tested"
            | "partial"
            | "not-implemented"
            | "not-applicable"
            | "gap"
            | "waived"
            | "full"
            | "implemented-untested"
    )
}

fn signed_evidence_record_matches_v1_schema(record: &SignedEvidenceRecord) -> bool {
    record.source_refs.iter().all(|value| !value.is_empty())
        && record.test_refs.iter().all(|value| !value.is_empty())
        && record.gap_refs.iter().all(|value| is_gap_id(value))
        && record
            .artifact_digests
            .iter()
            .all(|value| is_sha256_digest(value))
        && record.reviewed_by.iter().all(|value| !value.is_empty())
}

fn is_gap_id(value: &str) -> bool {
    value
        .strip_prefix("GAP-")
        .is_some_and(|digits| digits.len() == 6 && digits.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
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
