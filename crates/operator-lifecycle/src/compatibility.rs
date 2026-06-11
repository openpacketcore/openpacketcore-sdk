use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CompatibilityFeature {
    ConsensusConfigBackend,
    QuorumSessionBackend,
    Kms,
    Spiffe,
    ResourceProfile,
}

impl std::fmt::Display for CompatibilityFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SupportedVersionRange(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationCompatibility {
    pub source_version_range: SupportedVersionRange,
    pub target_version_range: SupportedVersionRange,
    pub allowed_rollback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub evidence_id: String,
    pub approved_by: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorReleaseDescriptor {
    pub operator_version: String,
    pub sdk_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NfReleaseDescriptor {
    pub nf_kind: String,
    pub nf_version: String,
    pub crd_api_version: String,
    pub config_schema_version: String,
    pub state_schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityRule {
    pub rule_id: String,
    pub operator_version_range: SupportedVersionRange,
    pub sdk_version_range: SupportedVersionRange,
    pub nf_kind: String,
    pub nf_version_range: SupportedVersionRange,
    pub crd_api_version_range: SupportedVersionRange,
    pub config_schema_version_range: SupportedVersionRange,
    pub state_schema_version_range: SupportedVersionRange,
    pub required_features: Vec<CompatibilityFeature>,
    pub required_runtime_modes: Vec<opc_runtime::profile::RuntimeMode>,
    pub required_persistence_profiles: Vec<String>,
    pub allowed_migrations: Vec<MigrationCompatibility>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMatrix {
    pub rules: Vec<CompatibilityRule>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatibilityBlockReason {
    #[error("Unsupported operator version: actual {actual} does not match range {range}")]
    UnsupportedOperatorVersion { range: String, actual: String },

    #[error("Unsupported SDK version: actual {actual} does not match range {range}")]
    UnsupportedSdkVersion { range: String, actual: String },

    #[error("Unsupported NF kind: actual {actual}, expected {expected}")]
    UnsupportedNfKind { expected: String, actual: String },

    #[error("Unsupported NF version: actual {actual} does not match range {range}")]
    UnsupportedNfVersion { range: String, actual: String },

    #[error("Unsupported CRD API version: actual {actual} does not match range {range}")]
    UnsupportedCrdApiVersion { range: String, actual: String },

    #[error("Unsupported config schema version: actual {actual} does not match range {range}")]
    UnsupportedConfigSchemaVersion { range: String, actual: String },

    #[error("Unsupported state schema version: actual {actual} does not match range {range}")]
    UnsupportedStateSchemaVersion { range: String, actual: String },

    #[error("Missing required capability: {0}")]
    MissingRequiredFeature(CompatibilityFeature),

    #[error("Unsupported runtime mode: actual {actual:?}, expected one of {expected:?}")]
    UnsupportedRuntimeMode {
        expected: Vec<opc_runtime::profile::RuntimeMode>,
        actual: opc_runtime::profile::RuntimeMode,
    },

    #[error("Unsupported persistence profile: actual {actual}, expected one of {expected:?}")]
    UnsupportedPersistenceProfile {
        expected: Vec<String>,
        actual: String,
    },

    #[error("Migration path not allowed: source {source_version} to target {target_version}")]
    MigrationPathNotAllowed {
        source_version: String,
        target_version: String,
    },

    #[error("Rollback not allowed: target {target_version}")]
    RollbackNotAllowed { target_version: String },

    #[error("Missing required compatibility/migration evidence")]
    MissingEvidence,

    #[error("Invalid version format: {0}")]
    InvalidVersion(String),

    #[error("Malformed policy/matrix: {0}")]
    MalformedPolicy(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatibilityDecision {
    Allowed,
    Blocked(CompatibilityBlockReason),
}

impl CompatibilityMatrix {
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_compatibility(
        &self,
        operator: &OperatorReleaseDescriptor,
        nf: &NfReleaseDescriptor,
        runtime_mode: opc_runtime::profile::RuntimeMode,
        config_backend: &str,
        session_backend: &str,
        identity_kms: bool,
        identity_spiffe: bool,
        has_resource_profile: bool,
        evidence: &[CompatibilityEvidence],
    ) -> CompatibilityDecision {
        if let Some(reason) = validate_evidence(evidence) {
            return CompatibilityDecision::Blocked(reason);
        }

        let rule = match self.release_rule(operator, nf) {
            Ok(rule) => rule,
            Err(reason) => return CompatibilityDecision::Blocked(reason),
        };

        // Now evaluate the rule constraints:
        // 1. required_runtime_modes
        if !rule.required_runtime_modes.is_empty()
            && !rule.required_runtime_modes.contains(&runtime_mode)
        {
            return CompatibilityDecision::Blocked(
                CompatibilityBlockReason::UnsupportedRuntimeMode {
                    expected: rule.required_runtime_modes.clone(),
                    actual: runtime_mode,
                },
            );
        }

        // 2. required_features
        for feat in &rule.required_features {
            match feat {
                CompatibilityFeature::ConsensusConfigBackend => {
                    let canonical = config_backend
                        .trim()
                        .to_lowercase()
                        .replace(['_', ' '], "-");
                    if !matches!(
                        canonical.as_str(),
                        "consensus" | "consensus-config-store" | "consensusconfigstore"
                    ) {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::MissingRequiredFeature(*feat),
                        );
                    }
                }
                CompatibilityFeature::QuorumSessionBackend => {
                    let canonical = session_backend
                        .trim()
                        .to_lowercase()
                        .replace(['_', ' '], "-");
                    if !matches!(
                        canonical.as_str(),
                        "quorum" | "quorum-session-store" | "quorumsessionstore"
                    ) {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::MissingRequiredFeature(*feat),
                        );
                    }
                }
                CompatibilityFeature::Kms => {
                    if !identity_kms {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::MissingRequiredFeature(*feat),
                        );
                    }
                }
                CompatibilityFeature::Spiffe => {
                    if !identity_spiffe {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::MissingRequiredFeature(*feat),
                        );
                    }
                }
                CompatibilityFeature::ResourceProfile => {
                    if !has_resource_profile {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::MissingRequiredFeature(*feat),
                        );
                    }
                }
            }
        }

        // 3. required_persistence_profiles (config_backend / session_backend)
        if !rule.required_persistence_profiles.is_empty() {
            let config_matches = rule
                .required_persistence_profiles
                .iter()
                .any(|p| p.trim().to_lowercase() == config_backend.trim().to_lowercase());
            let session_matches = rule
                .required_persistence_profiles
                .iter()
                .any(|p| p.trim().to_lowercase() == session_backend.trim().to_lowercase());
            if !config_matches || !session_matches {
                return CompatibilityDecision::Blocked(
                    CompatibilityBlockReason::UnsupportedPersistenceProfile {
                        expected: rule.required_persistence_profiles.clone(),
                        actual: format!("config={}, session={}", config_backend, session_backend),
                    },
                );
            }
        }

        CompatibilityDecision::Allowed
    }

    pub fn evaluate_migration(
        &self,
        operator: &OperatorReleaseDescriptor,
        nf: &NfReleaseDescriptor,
        source_version: &str,
        target_version: &str,
        evidence: &[CompatibilityEvidence],
    ) -> CompatibilityDecision {
        if let Some(reason) = validate_evidence(evidence) {
            return CompatibilityDecision::Blocked(reason);
        }

        let rule = match self.release_rule(operator, nf) {
            Ok(rule) => rule,
            Err(reason) => return CompatibilityDecision::Blocked(reason),
        };

        self.evaluate_migration_path(rule, source_version, target_version, false)
    }

    pub fn migration_allows_rollback(
        &self,
        operator: &OperatorReleaseDescriptor,
        nf: &NfReleaseDescriptor,
        source_version: &str,
        target_version: &str,
        evidence: &[CompatibilityEvidence],
    ) -> CompatibilityDecision {
        if let Some(reason) = validate_evidence(evidence) {
            return CompatibilityDecision::Blocked(reason);
        }

        let rule = match self.release_rule(operator, nf) {
            Ok(rule) => rule,
            Err(reason) => return CompatibilityDecision::Blocked(reason),
        };

        self.evaluate_migration_path(rule, source_version, target_version, true)
    }

    fn evaluate_migration_path(
        &self,
        rule: &CompatibilityRule,
        source_version: &str,
        target_version: &str,
        require_rollback: bool,
    ) -> CompatibilityDecision {
        let src = match parse_semver_field("migration source version", source_version) {
            Ok(v) => v,
            Err(reason) => return CompatibilityDecision::Blocked(reason),
        };
        let tgt = match parse_semver_field("migration target version", target_version) {
            Ok(v) => v,
            Err(reason) => return CompatibilityDecision::Blocked(reason),
        };

        let is_rollback = tgt < src;

        let mut path_found = false;
        for mig in &rule.allowed_migrations {
            let src_req = match VersionReq::parse(&mig.source_version_range.0) {
                Ok(r) => r,
                Err(e) => {
                    return CompatibilityDecision::Blocked(
                        CompatibilityBlockReason::MalformedPolicy(format!(
                            "migration source_version_range: {e}"
                        )),
                    )
                }
            };
            let tgt_req = match VersionReq::parse(&mig.target_version_range.0) {
                Ok(r) => r,
                Err(e) => {
                    return CompatibilityDecision::Blocked(
                        CompatibilityBlockReason::MalformedPolicy(format!(
                            "migration target_version_range: {e}"
                        )),
                    )
                }
            };

            if is_rollback {
                if src_req.matches(&tgt) && tgt_req.matches(&src) {
                    path_found = true;
                    if !mig.allowed_rollback {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::RollbackNotAllowed {
                                target_version: target_version.to_string(),
                            },
                        );
                    }
                    break;
                }
            } else {
                if src_req.matches(&src) && tgt_req.matches(&tgt) {
                    path_found = true;
                    if require_rollback && !mig.allowed_rollback {
                        return CompatibilityDecision::Blocked(
                            CompatibilityBlockReason::RollbackNotAllowed {
                                target_version: target_version.to_string(),
                            },
                        );
                    }
                    break;
                }
            }
        }

        if !path_found {
            return CompatibilityDecision::Blocked(
                CompatibilityBlockReason::MigrationPathNotAllowed {
                    source_version: source_version.to_string(),
                    target_version: target_version.to_string(),
                },
            );
        }

        CompatibilityDecision::Allowed
    }

    pub fn is_crd_api_version_supported(&self, api_version: &str) -> bool {
        self.rules.iter().any(|rule| {
            crd_api_range_matches(&rule.crd_api_version_range.0, api_version).unwrap_or(false)
        })
    }

    fn release_rule(
        &self,
        operator: &OperatorReleaseDescriptor,
        nf: &NfReleaseDescriptor,
    ) -> Result<&CompatibilityRule, CompatibilityBlockReason> {
        let versions = parse_release_versions(operator, nf)?;
        let actual_kind = nf.nf_kind.trim();

        let kind_rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.nf_kind.trim().eq_ignore_ascii_case(actual_kind))
            .collect();
        if kind_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedNfKind {
                expected: expected_nf_kinds(&self.rules),
                actual: nf.nf_kind.clone(),
            });
        }

        let operator_rules = filter_rules(&kind_rules, |rule| {
            version_range_matches(&rule.operator_version_range.0, &versions.operator)
        })?;
        if operator_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedOperatorVersion {
                range: range_list(&kind_rules, |rule| &rule.operator_version_range.0),
                actual: operator.operator_version.clone(),
            });
        }

        let sdk_rules = filter_rules(&operator_rules, |rule| {
            version_range_matches(&rule.sdk_version_range.0, &versions.sdk)
        })?;
        if sdk_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedSdkVersion {
                range: range_list(&operator_rules, |rule| &rule.sdk_version_range.0),
                actual: operator.sdk_version.clone(),
            });
        }

        let nf_rules = filter_rules(&sdk_rules, |rule| {
            version_range_matches(&rule.nf_version_range.0, &versions.nf)
        })?;
        if nf_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedNfVersion {
                range: range_list(&sdk_rules, |rule| &rule.nf_version_range.0),
                actual: nf.nf_version.clone(),
            });
        }

        let crd_rules = filter_rules(&nf_rules, |rule| {
            crd_api_range_matches(&rule.crd_api_version_range.0, &nf.crd_api_version)
        })?;
        if crd_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedCrdApiVersion {
                range: range_list(&nf_rules, |rule| &rule.crd_api_version_range.0),
                actual: nf.crd_api_version.clone(),
            });
        }

        let config_rules = filter_rules(&crd_rules, |rule| {
            version_range_matches(&rule.config_schema_version_range.0, &versions.config_schema)
        })?;
        if config_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedConfigSchemaVersion {
                range: range_list(&crd_rules, |rule| &rule.config_schema_version_range.0),
                actual: nf.config_schema_version.clone(),
            });
        }

        let state_rules = filter_rules(&config_rules, |rule| {
            version_range_matches(&rule.state_schema_version_range.0, &versions.state_schema)
        })?;
        if state_rules.is_empty() {
            return Err(CompatibilityBlockReason::UnsupportedStateSchemaVersion {
                range: range_list(&config_rules, |rule| &rule.state_schema_version_range.0),
                actual: nf.state_schema_version.clone(),
            });
        }

        Ok(state_rules[0])
    }
}

struct ParsedReleaseVersions {
    operator: Version,
    sdk: Version,
    nf: Version,
    config_schema: Version,
    state_schema: Version,
}

fn parse_release_versions(
    operator: &OperatorReleaseDescriptor,
    nf: &NfReleaseDescriptor,
) -> Result<ParsedReleaseVersions, CompatibilityBlockReason> {
    Ok(ParsedReleaseVersions {
        operator: parse_semver_field("operator_version", &operator.operator_version)?,
        sdk: parse_semver_field("sdk_version", &operator.sdk_version)?,
        nf: parse_semver_field("nf_version", &nf.nf_version)?,
        config_schema: parse_semver_field("config_schema_version", &nf.config_schema_version)?,
        state_schema: parse_semver_field("state_schema_version", &nf.state_schema_version)?,
    })
}

fn parse_semver_field(field: &str, value: &str) -> Result<Version, CompatibilityBlockReason> {
    Version::parse(value.trim())
        .map_err(|err| CompatibilityBlockReason::InvalidVersion(format!("{field}: {err}")))
}

fn validate_evidence(evidence: &[CompatibilityEvidence]) -> Option<CompatibilityBlockReason> {
    if evidence.is_empty()
        || evidence.iter().any(|ev| {
            ev.evidence_id.trim().is_empty()
                || ev.approved_by.trim().is_empty()
                || ev.timestamp.trim().is_empty()
        })
    {
        Some(CompatibilityBlockReason::MissingEvidence)
    } else {
        None
    }
}

fn filter_rules<'a, F>(
    rules: &[&'a CompatibilityRule],
    mut matches_rule: F,
) -> Result<Vec<&'a CompatibilityRule>, CompatibilityBlockReason>
where
    F: FnMut(&CompatibilityRule) -> Result<bool, CompatibilityBlockReason>,
{
    let mut filtered = Vec::new();
    for &rule in rules {
        if matches_rule(rule)? {
            filtered.push(rule);
        }
    }
    Ok(filtered)
}

fn version_range_matches(range: &str, version: &Version) -> Result<bool, CompatibilityBlockReason> {
    let requirement = VersionReq::parse(range.trim()).map_err(|err| {
        CompatibilityBlockReason::MalformedPolicy(format!("version range '{range}': {err}"))
    })?;
    Ok(requirement.matches(version))
}

fn crd_api_range_matches(range: &str, api_version: &str) -> Result<bool, CompatibilityBlockReason> {
    let range = range.trim();
    let api_version = api_version.trim();
    if range == api_version {
        return Ok(true);
    }

    match VersionReq::parse(range) {
        Ok(requirement) => {
            let Ok(version) = Version::parse(api_version) else {
                return Ok(false);
            };
            Ok(requirement.matches(&version))
        }
        Err(err) if looks_like_semver_requirement(range) => {
            Err(CompatibilityBlockReason::MalformedPolicy(format!(
                "crd_api_version_range '{range}': {err}"
            )))
        }
        Err(_) => Ok(false),
    }
}

fn looks_like_semver_requirement(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || matches!(c, '>' | '<' | '=' | '^' | '~' | '*'))
}

fn range_list<F>(rules: &[&CompatibilityRule], field: F) -> String
where
    F: Fn(&CompatibilityRule) -> &str,
{
    let ranges: BTreeSet<_> = rules.iter().map(|rule| field(rule)).collect();
    ranges.into_iter().collect::<Vec<_>>().join(", ")
}

fn expected_nf_kinds(rules: &[CompatibilityRule]) -> String {
    let kinds: BTreeSet<_> = rules
        .iter()
        .map(|rule| rule.nf_kind.trim())
        .filter(|kind| !kind.is_empty())
        .collect();
    if kinds.is_empty() {
        "none configured".to_string()
    } else {
        kinds.into_iter().collect::<Vec<_>>().join(", ")
    }
}
