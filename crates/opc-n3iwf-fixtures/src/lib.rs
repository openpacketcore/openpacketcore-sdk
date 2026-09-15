//! SDK-owned synthetic N3IWF fixture contracts.
//!
//! This crate publishes independently reviewable wire and transport manifests
//! for the N3IWF primitive subsets tracked by issue 784. It owns fixture
//! metadata, digests, and completion records only. It does not activate a
//! codec, adapter, key handle, or transport runtime.
//!
//! @spec 3GPP TS24502 V18.8.0
//! @spec 3GPP TS29413 V18.5.0
//! @spec 3GPP TS38413 V18.10.0
//! @spec 3GPP TS38412 V18.1.0
//! @spec 3GPP TS29281 V18.4.0
//! @spec 3GPP TS38415 V18.2.0
//! @spec 3GPP TS33501 V18.12.0
//! @spec IETF RFC6083
//! @spec IETF RFC7296
//! @req REQ-3GPP-N3IWF-FIXTURE-CONTRACT-001
//! @conformance fixture-contracts-only — see CONFORMANCE.md

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Independently mergeable N3IWF fixture subsets.
pub const SUBSETS: &[&str] = &[
    "eap5g",
    "nwu-ike",
    "ngap",
    "n2-sctp",
    "gre-qfi",
    "n3-gtpu",
    "protocol-key",
    "nas-tcp",
    "xfrm-roster",
    "n2-dtls",
];

/// Case classes required on every subset.
pub const REQUIRED_CASE_CLASSES: &[&str] = &[
    "positive",
    "malformed",
    "duplicate",
    "unknown-critical",
    "ordering",
    "truncation",
    "bounded-overflow",
];

/// Allowed provenance classes for these contracts.
pub const ALLOWED_PROVENANCE_CLASSES: &[&str] = &[
    "spec-authored",
    "referenced-public-vector",
    "synthetic-negative",
    "synthetic-kat",
];

/// Constructed, receive, or explicitly unsupported fixture outcomes.
pub const ALLOWED_OUTCOMES: &[&str] = &[
    "constructed",
    "receive",
    "unsupported",
    "reject",
    "need-more-data",
    "ignore",
    "caller-policy",
];

const FORBIDDEN_TEXT: &[&str] = &[
    "aaron",
    "chartier",
    "-----begin",
    "private key",
    "aws_",
    "akia",
    "password=",
    "api_key",
];

/// Stable fixture-contract failure that never embeds wire or secret values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}")]
pub struct ContractError {
    code: ContractErrorCode,
}

impl ContractError {
    /// Build a redaction-safe contract error.
    #[must_use]
    pub const fn new(code: ContractErrorCode) -> Self {
        Self { code }
    }

    /// Stable machine-readable reason.
    #[must_use]
    pub const fn code(&self) -> ContractErrorCode {
        self.code
    }
}

/// Redaction-safe contract failure codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractErrorCode {
    /// A required manifest field is missing or empty.
    MissingField,
    /// A digest does not match the committed wire octets.
    DigestMismatch,
    /// `runtime_claim` is not exactly false.
    RuntimeClaimForbidden,
    /// Provenance is captured, customer, or otherwise non-synthetic.
    ForbiddenProvenance,
    /// A subset is missing a required case class.
    IncompleteSubset,
    /// A fixture identifier is duplicated.
    DuplicateFixtureId,
    /// Text looks like a secret, personal name, or production capture.
    ForbiddenContent,
    /// Completion record does not match the committed manifests.
    CompletionMismatch,
    /// Wire bytes are absent or unreadable.
    MissingWire,
    /// Publication metadata is incomplete.
    MissingPublication,
}

impl fmt::Display for ContractErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingField => "n3iwf_fixture_missing_field",
            Self::DigestMismatch => "n3iwf_fixture_digest_mismatch",
            Self::RuntimeClaimForbidden => "n3iwf_fixture_runtime_claim_forbidden",
            Self::ForbiddenProvenance => "n3iwf_fixture_forbidden_provenance",
            Self::IncompleteSubset => "n3iwf_fixture_incomplete_subset",
            Self::DuplicateFixtureId => "n3iwf_fixture_duplicate_id",
            Self::ForbiddenContent => "n3iwf_fixture_forbidden_content",
            Self::CompletionMismatch => "n3iwf_fixture_completion_mismatch",
            Self::MissingWire => "n3iwf_fixture_missing_wire",
            Self::MissingPublication => "n3iwf_fixture_missing_publication",
        })
    }
}

/// One sanitized field inventory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedField {
    /// Protocol or transport field name.
    pub name: String,
    /// How the field was replaced or withheld.
    pub treatment: String,
    /// Documentation-range or reserved-test classification.
    pub value_class: String,
}

/// Normative source citation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Specification document identifier.
    pub document: String,
    /// Exact release used to author the bytes.
    pub release: String,
    /// Clauses that control only this fixture's obligation.
    pub clauses: Vec<String>,
}

/// Independent provenance block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// ADR 0015 provenance class.
    pub class: String,
    /// Always true for this catalog.
    pub synthetic: bool,
    /// Captures are rejected.
    pub independent_capture: bool,
    /// Public path of a referenced existing SDK vector, if any.
    #[serde(default)]
    pub referenced_public_vector: Option<String>,
    /// Human-reviewable authoring note without private trackers.
    pub notes: String,
}

/// Wire locator and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRef {
    /// Path relative to the subset directory.
    pub path: String,
    /// SHA-256 of the exact committed octets, lowercase hex.
    pub digest_sha256: String,
}

/// One independently reviewable fixture manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureManifest {
    /// Stable SDK fixture identifier.
    pub sdk_fixture_id: String,
    /// Subset name.
    pub subset: String,
    /// Required case class.
    pub case_class: String,
    /// Exact source release and clauses.
    pub source: SourceRef,
    /// Direction of the synthetic exchange.
    pub direction: String,
    /// Role that owns the bytes.
    pub role: String,
    /// Prerequisite that is not itself a standards obligation.
    pub prerequisite: String,
    /// Independent provenance.
    pub provenance: Provenance,
    /// Sanitized-field inventory.
    pub sanitized_fields: Vec<SanitizedField>,
    /// Wire locator and digest.
    pub wire: WireRef,
    /// Semantic assertions that later codecs may consume.
    pub semantic_assertions: Vec<String>,
    /// Expected constructed/receive/unsupported or fail-closed outcome.
    pub expected_outcome: String,
    /// Must remain false; this crate makes no runtime claim.
    pub runtime_claim: bool,
}

/// Reviewed subset completion record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsetCompletion {
    /// Subset name.
    pub subset: String,
    /// `complete` when consumers may depend on this subset alone.
    pub status: String,
    /// Tracking issue for the fixture lane.
    pub issue: u32,
    /// Must remain false.
    pub runtime_claim: bool,
    /// Whether consumers may depend without the remaining subsets.
    pub consumers_may_depend: bool,
    /// Case classes present in the subset.
    pub case_classes: Vec<String>,
    /// Fixture identifiers in this subset.
    pub fixture_ids: Vec<String>,
    /// Constructed-send outcomes published by this subset.
    pub constructed: Vec<String>,
    /// Receive outcomes published by this subset.
    pub receive: Vec<String>,
    /// Explicitly unsupported outcomes.
    pub unsupported: Vec<String>,
}

/// Public SDK revision publication for these contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSdkPublication {
    /// Canonical public repository URL.
    pub repository: String,
    /// Public SDK base commit used as the reuse floor.
    pub base: String,
    /// Landing head commit or `landing-revision` before the first publish commit.
    pub head: String,
    /// Git tree path that owns the manifests.
    pub tree_path: String,
    /// Git tree object id when recorded, otherwise empty.
    #[serde(default)]
    pub tree: String,
    /// Reminder that round trips are not interoperability proof.
    pub interoperability_note: String,
}

/// Loaded catalog for one or every subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureCatalog {
    publication: PublicSdkPublication,
    completions: BTreeMap<String, SubsetCompletion>,
    manifests: Vec<(PathBuf, FixtureManifest, Vec<u8>)>,
}

impl FixtureCatalog {
    /// Directory that contains subset folders.
    #[must_use]
    pub fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    /// Load and structurally validate the committed catalog.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe [`ContractError`] when a manifest, digest,
    /// completion record, or publication file is incomplete or forbidden.
    pub fn load() -> Result<Self, ContractError> {
        Self::load_from(&Self::fixture_root())
    }

    /// Load from an explicit fixture root.
    ///
    /// # Errors
    ///
    /// Same as [`Self::load`].
    pub fn load_from(root: &Path) -> Result<Self, ContractError> {
        let publication = read_publication(&root.join("PUBLIC_SDK.json"))?;
        let mut completions = BTreeMap::new();
        let mut manifests = Vec::new();
        let mut seen_ids = BTreeSet::new();

        for subset in SUBSETS {
            let subset_dir = root.join(subset);
            let completion = read_completion(&subset_dir.join("COMPLETION.json"))?;
            if completion.subset != *subset
                || completion.status != "complete"
                || completion.runtime_claim
                || !completion.consumers_may_depend
                || completion.issue != 784
            {
                return Err(ContractError::new(ContractErrorCode::CompletionMismatch));
            }
            completions.insert((*subset).to_string(), completion);

            let entries = fs::read_dir(&subset_dir)
                .map_err(|_| ContractError::new(ContractErrorCode::MissingField))?;
            let mut json_paths: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok().map(|value| value.path()))
                .filter(|path| {
                    path.extension().and_then(|ext| ext.to_str()) == Some("json")
                        && path.file_name().and_then(|name| name.to_str())
                            != Some("COMPLETION.json")
                })
                .collect();
            json_paths.sort();

            for path in json_paths {
                let manifest = read_manifest(&path)?;
                if manifest.subset != *subset {
                    return Err(ContractError::new(ContractErrorCode::MissingField));
                }
                if !seen_ids.insert(manifest.sdk_fixture_id.clone()) {
                    return Err(ContractError::new(ContractErrorCode::DuplicateFixtureId));
                }
                let wire = read_wire(&subset_dir.join(&manifest.wire.path))?;
                manifests.push((path, manifest, wire));
            }
        }

        Ok(Self {
            publication,
            completions,
            manifests,
        })
    }

    /// Public SDK publication block.
    #[must_use]
    pub const fn publication(&self) -> &PublicSdkPublication {
        &self.publication
    }

    /// Completion records keyed by subset.
    #[must_use]
    pub const fn completions(&self) -> &BTreeMap<String, SubsetCompletion> {
        &self.completions
    }

    /// Loaded manifests and their wire octets.
    pub fn manifests(&self) -> impl Iterator<Item = (&FixtureManifest, &[u8])> {
        self.manifests
            .iter()
            .map(|(_, manifest, wire)| (manifest, wire.as_slice()))
    }

    /// Run every catalog detector.
    ///
    /// # Errors
    ///
    /// Returns the first redaction-safe violation.
    pub fn detect(&self) -> Result<(), ContractError> {
        detect_publication(&self.publication)?;
        detect_text(&serde_json::to_string(&self.publication).unwrap_or_default())?;

        for (subset, completion) in &self.completions {
            detect_completion(subset, completion, &self.manifests)?;
            detect_text(&serde_json::to_string(completion).unwrap_or_default())?;
        }

        let mut classes: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (path, manifest, wire) in &self.manifests {
            detect_manifest(manifest)?;
            detect_wire(manifest, wire)?;
            detect_text(&fs::read_to_string(path).unwrap_or_default())?;
            classes
                .entry(manifest.subset.as_str())
                .or_default()
                .insert(manifest.case_class.as_str());
        }

        for subset in SUBSETS {
            let present = classes.get(subset).cloned().unwrap_or_default();
            for required in REQUIRED_CASE_CLASSES {
                if !present.contains(required) {
                    return Err(ContractError::new(ContractErrorCode::IncompleteSubset));
                }
            }
        }
        Ok(())
    }
}

fn read_publication(path: &Path) -> Result<PublicSdkPublication, ContractError> {
    let raw = fs::read_to_string(path)
        .map_err(|_| ContractError::new(ContractErrorCode::MissingPublication))?;
    serde_json::from_str(&raw)
        .map_err(|_| ContractError::new(ContractErrorCode::MissingPublication))
}

fn read_completion(path: &Path) -> Result<SubsetCompletion, ContractError> {
    let raw = fs::read_to_string(path)
        .map_err(|_| ContractError::new(ContractErrorCode::CompletionMismatch))?;
    serde_json::from_str(&raw)
        .map_err(|_| ContractError::new(ContractErrorCode::CompletionMismatch))
}

fn read_manifest(path: &Path) -> Result<FixtureManifest, ContractError> {
    let raw = fs::read_to_string(path)
        .map_err(|_| ContractError::new(ContractErrorCode::MissingField))?;
    serde_json::from_str(&raw).map_err(|_| ContractError::new(ContractErrorCode::MissingField))
}

fn read_wire(path: &Path) -> Result<Vec<u8>, ContractError> {
    let raw =
        fs::read_to_string(path).map_err(|_| ContractError::new(ContractErrorCode::MissingWire))?;
    parse_hex(&raw).ok_or_else(|| ContractError::new(ContractErrorCode::MissingWire))
}

/// Parse whitespace-separated hex octets.
#[must_use]
pub fn parse_hex(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for token in input.split_whitespace() {
        if token.len() != 2 {
            return None;
        }
        out.push(u8::from_str_radix(token, 16).ok()?);
    }
    Some(out)
}

/// SHA-256 of wire octets as lowercase hex.
#[must_use]
pub fn wire_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn detect_publication(publication: &PublicSdkPublication) -> Result<(), ContractError> {
    if publication.repository != "https://github.com/openpacketcore/openpacketcore-sdk"
        || publication.base.len() != 40
        || !publication.base.chars().all(|ch| ch.is_ascii_hexdigit())
        || publication.head.is_empty()
        || publication.tree_path != "crates/opc-n3iwf-fixtures/fixtures"
        || !publication
            .interoperability_note
            .contains("do not prove external interoperability")
    {
        return Err(ContractError::new(ContractErrorCode::MissingPublication));
    }
    Ok(())
}

fn detect_completion(
    subset: &str,
    completion: &SubsetCompletion,
    manifests: &[(PathBuf, FixtureManifest, Vec<u8>)],
) -> Result<(), ContractError> {
    let ids: BTreeSet<&str> = manifests
        .iter()
        .filter(|(_, manifest, _)| manifest.subset == subset)
        .map(|(_, manifest, _)| manifest.sdk_fixture_id.as_str())
        .collect();
    let recorded: BTreeSet<&str> = completion.fixture_ids.iter().map(String::as_str).collect();
    if ids != recorded {
        return Err(ContractError::new(ContractErrorCode::CompletionMismatch));
    }
    for required in REQUIRED_CASE_CLASSES {
        if !completion
            .case_classes
            .iter()
            .any(|value| value == required)
        {
            return Err(ContractError::new(ContractErrorCode::IncompleteSubset));
        }
    }
    if completion.receive.is_empty() || completion.unsupported.is_empty() {
        return Err(ContractError::new(ContractErrorCode::CompletionMismatch));
    }
    Ok(())
}

fn detect_manifest(manifest: &FixtureManifest) -> Result<(), ContractError> {
    if manifest.sdk_fixture_id.is_empty()
        || !manifest.sdk_fixture_id.starts_with("opc.n3iwf.")
        || manifest.source.document.is_empty()
        || manifest.source.release.is_empty()
        || manifest.source.clauses.is_empty()
        || manifest.direction.is_empty()
        || manifest.role.is_empty()
        || manifest.prerequisite.is_empty()
        || manifest.provenance.notes.is_empty()
        || manifest.sanitized_fields.is_empty()
        || manifest.semantic_assertions.is_empty()
        || manifest.wire.path.is_empty()
        || manifest.wire.digest_sha256.len() != 64
    {
        return Err(ContractError::new(ContractErrorCode::MissingField));
    }
    if manifest.runtime_claim {
        return Err(ContractError::new(ContractErrorCode::RuntimeClaimForbidden));
    }
    if !manifest.provenance.synthetic
        || manifest.provenance.independent_capture
        || !ALLOWED_PROVENANCE_CLASSES.contains(&manifest.provenance.class.as_str())
    {
        return Err(ContractError::new(ContractErrorCode::ForbiddenProvenance));
    }
    if !REQUIRED_CASE_CLASSES.contains(&manifest.case_class.as_str()) {
        return Err(ContractError::new(ContractErrorCode::IncompleteSubset));
    }
    if !ALLOWED_OUTCOMES.contains(&manifest.expected_outcome.as_str()) {
        return Err(ContractError::new(ContractErrorCode::MissingField));
    }
    Ok(())
}

fn detect_wire(manifest: &FixtureManifest, wire: &[u8]) -> Result<(), ContractError> {
    if wire_digest(wire) != manifest.wire.digest_sha256 {
        return Err(ContractError::new(ContractErrorCode::DigestMismatch));
    }
    Ok(())
}

fn detect_text(text: &str) -> Result<(), ContractError> {
    let lowered = text.to_ascii_lowercase();
    if FORBIDDEN_TEXT.iter().any(|needle| lowered.contains(needle)) {
        return Err(ContractError::new(ContractErrorCode::ForbiddenContent));
    }
    Ok(())
}

/// Redacted debug helper used by detector tests.
pub fn redact_contract_debug(error: &ContractError) -> String {
    format!("contract_error={}", error.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_errors_never_embed_wire_or_names() {
        let rendered =
            redact_contract_debug(&ContractError::new(ContractErrorCode::DigestMismatch));
        assert_eq!(rendered, "contract_error=n3iwf_fixture_digest_mismatch");
        assert!(!rendered.contains("aaron"));
        assert!(!rendered.contains("192.0.2"));
    }
}
