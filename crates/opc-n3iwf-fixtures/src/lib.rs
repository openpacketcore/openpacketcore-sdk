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
//! @spec IETF RFC4555
//! @spec IETF RFC6083
//! @spec IETF RFC7296
//! @req REQ-3GPP-N3IWF-FIXTURE-CONTRACT-001
//! @conformance fixture-contracts-only — see CONFORMANCE.md

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

mod json;

use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
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
    /// An admitted NGAP outcome is missing its IE matrix.
    MissingMatrix,
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
            Self::MissingMatrix => "n3iwf_fixture_missing_matrix",
        })
    }
}

/// One sanitized field inventory entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedField {
    /// Protocol or transport field name.
    pub name: String,
    /// How the field was replaced or withheld.
    pub treatment: String,
    /// Documentation-range or reserved-test classification.
    pub value_class: String,
}

/// Normative source citation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    /// Specification document identifier.
    pub document: String,
    /// Exact release used to author the bytes.
    pub release: String,
    /// Clauses that control only this fixture's obligation.
    pub clauses: Vec<String>,
}

/// Independent provenance block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRef {
    /// Path relative to the subset directory.
    pub path: String,
    /// SHA-256 of the exact committed octets, lowercase hex.
    pub digest_sha256: String,
}

/// One independently reviewable fixture manifest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureManifest {
    /// Whether octets are protocol wire, metadata, scenario labels, or a construction argument.
    pub encoding: String,
    /// Exact validation layer; acceptance never implies validation of an opaque inner payload.
    pub validation_scope: String,
    /// Explicit caller bounds and preconditions, separate from normative wire fields.
    pub context: BTreeMap<String, serde_json::Value>,
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubsetCompletion {
    /// Completion applies only to the inventory at each declared validation scope.
    pub completion_scope: String,
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
    /// Admitted sent/received message names that publish a matrix.
    #[serde(default)]
    pub admitted_outcomes: Vec<String>,
    /// Relative matrix paths owned by this subset.
    #[serde(default)]
    pub matrices: Vec<String>,
    /// Limits NGAP admission to the first-CNF typed subset, if present.
    #[serde(default)]
    pub admission_scope: String,
}

/// One IE identifier/criticality/cardinality row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IeCardinality {
    /// NGAP ProtocolIE-ID.
    pub id: u16,
    /// Standardized IE name.
    pub name: String,
    /// `reject`, `ignore`, or `notify`.
    pub criticality: String,
    /// Top-level cardinality; first-CNF IEs are singleton.
    pub cardinality: String,
    /// Normative Release-18 presence: mandatory, optional, or conditional.
    pub presence: String,
}

/// Message/IE matrix for one admitted or explicitly unsupported NGAP outcome.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageIeMatrix {
    /// Message name.
    pub message: String,
    /// Procedure code.
    pub procedure_code: u8,
    /// `initiating`, `successful`, or `unsuccessful`.
    pub outcome: String,
    /// N3IWF/AMF direction.
    pub direction: String,
    /// TS 29.413 clause that admits or discards the message.
    pub ts29413_clause: String,
    /// `receive`, `constructed`, or `unsupported`.
    pub admitted_disposition: String,
    /// Constructed N3IWF send remains unsupported.
    pub constructed_send: bool,
    /// TS 38.413 message/IE definition.
    pub source: SourceRef,
    /// TS 29.413 application to non-3GPP access.
    pub application: SourceRef,
    /// Reminder that clause 5.3 ignore-on-receive is not encoded in the rows.
    #[serde(default)]
    pub n3iwf_content_exceptions: String,
    /// First-CNF typed subset vs the full 5.2 message list.
    #[serde(default)]
    pub admission_scope: String,
    /// Manifest that carries the admitted wire octets.
    #[serde(default)]
    pub wire_fixture_id: Option<String>,
    /// Identifier/criticality/cardinality rows.
    pub ies: Vec<IeCardinality>,
}

/// Public SDK revision publication for these contracts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureCatalog {
    publication: PublicSdkPublication,
    completions: BTreeMap<String, SubsetCompletion>,
    manifests: Vec<(PathBuf, FixtureManifest, Vec<u8>)>,
    ngap_matrices: Vec<MessageIeMatrix>,
    matrix_paths: BTreeSet<String>,
}

// Public data can be populated by callers as well as the reviewed catalog.
// Never derive Debug on a value-bearing surface, including nested metadata.
macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => { $(
        impl fmt::Debug for $kind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($kind), "(<redacted>)"))
            }
        }
    )+ };
}
redacted_debug!(
    SanitizedField,
    SourceRef,
    Provenance,
    WireRef,
    FixtureManifest,
    SubsetCompletion,
    IeCardinality,
    MessageIeMatrix,
    PublicSdkPublication,
    FixtureCatalog
);

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
        Self::load_selected(root, SUBSETS)
    }

    /// Load one independently consumable subset without reading its siblings.
    ///
    /// # Errors
    /// Returns a redacted error for an unknown subset or invalid selected content.
    pub fn load_subset_from(root: &Path, subset: &str) -> Result<Self, ContractError> {
        if !SUBSETS.contains(&subset) {
            return Err(ContractError::new(ContractErrorCode::IncompleteSubset));
        }
        Self::load_selected(root, &[subset])
    }

    fn load_selected(root: &Path, selected: &[&str]) -> Result<Self, ContractError> {
        require_directory(root)?;
        let publication = read_publication(&root.join("PUBLIC_SDK.json"))?;
        let mut completions = BTreeMap::new();
        let mut manifests = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let (matrix_paths, ngap_matrices) = if selected.contains(&"ngap") {
            require_directory(&root.join("ngap"))?;
            read_ngap_matrices(&root.join("ngap").join("matrices"))?
        } else {
            (BTreeSet::new(), Vec::new())
        };

        for subset in selected {
            let subset_dir = root.join(subset);
            require_directory(&subset_dir)?;
            require_directory(&subset_dir.join("wire"))?;
            let completion = read_completion(&subset_dir.join("COMPLETION.json"))?;
            if completion.subset != *subset
                || completion.status != "complete"
                || completion.completion_scope != "fixture-inventory-at-declared-validation-scopes"
                || completion.runtime_claim
                || !completion.consumers_may_depend
                || completion.issue != 784
            {
                return Err(ContractError::new(ContractErrorCode::CompletionMismatch));
            }
            completions.insert((*subset).to_string(), completion);

            let json_paths = json_files(&subset_dir, ContractErrorCode::MissingField)?;

            for path in json_paths {
                if path.file_name().and_then(|name| name.to_str()) == Some("COMPLETION.json") {
                    continue;
                }
                let manifest = read_manifest(&path)?;
                let stem = path
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| ContractError::new(ContractErrorCode::MissingField))?;
                if !valid_slug(stem)
                    || manifest.sdk_fixture_id != format!("opc.n3iwf.{subset}.v1.{stem}")
                    || manifest.wire.path != format!("wire/{stem}.hex")
                {
                    return Err(ContractError::new(ContractErrorCode::MissingWire));
                }
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

        let catalog = Self {
            publication,
            completions,
            manifests,
            ngap_matrices,
            matrix_paths,
        };
        catalog.detect()?;
        Ok(catalog)
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

    /// NGAP message/IE matrices for every admitted or 5.4-unsupported outcome.
    #[must_use]
    pub fn ngap_matrices(&self) -> &[MessageIeMatrix] {
        &self.ngap_matrices
    }

    /// Run every catalog detector.
    ///
    /// # Errors
    ///
    /// Returns the first redaction-safe violation.
    pub fn detect(&self) -> Result<(), ContractError> {
        detect_publication(&self.publication)?;
        detect_serialized(&self.publication)?;

        for (subset, completion) in &self.completions {
            detect_completion(subset, completion, &self.manifests)?;
            detect_serialized(completion)?;
        }

        let mut classes: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (_, manifest, wire) in &self.manifests {
            detect_manifest(manifest)?;
            detect_wire(manifest, wire)?;
            detect_serialized(manifest)?;
            classes
                .entry(manifest.subset.as_str())
                .or_default()
                .insert(manifest.case_class.as_str());
        }

        for subset in self.completions.keys() {
            let present = classes.get(subset.as_str()).cloned().unwrap_or_default();
            for required in REQUIRED_CASE_CLASSES {
                if !present.contains(required) {
                    return Err(ContractError::new(ContractErrorCode::IncompleteSubset));
                }
            }
        }
        if let Some(completion) = self.completions.get("ngap") {
            let recorded: BTreeSet<String> = completion.matrices.iter().cloned().collect();
            if recorded != self.matrix_paths || recorded.len() != completion.matrices.len() {
                return Err(ContractError::new(ContractErrorCode::MissingMatrix));
            }
            detect_ngap_matrices(Some(completion), &self.ngap_matrices, &self.manifests)?;
        }
        Ok(())
    }
}

// These limits bound catalog reads, not any protocol's runtime limits.
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 512;

fn require_directory(path: &Path) -> Result<(), ContractError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ContractError::new(ContractErrorCode::MissingField))?;
    if !metadata.file_type().is_dir() {
        return Err(ContractError::new(ContractErrorCode::MissingField));
    }
    Ok(())
}

fn json_files(dir: &Path, code: ContractErrorCode) -> Result<Vec<PathBuf>, ContractError> {
    require_directory(dir)?;
    let mut paths = Vec::new();
    let entries = fs::read_dir(dir).map_err(|_| ContractError::new(code))?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            return Err(ContractError::new(code));
        }
        let path = entry.map_err(|_| ContractError::new(code))?.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_text(path: &Path, code: ContractErrorCode) -> Result<String, ContractError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ContractError::new(code))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(ContractError::new(code));
    }
    let mut raw = String::new();
    fs::File::open(path)
        .map_err(|_| ContractError::new(code))?
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|_| ContractError::new(code))?;
    if raw.len() as u64 > MAX_FILE_BYTES {
        return Err(ContractError::new(code));
    }
    Ok(raw)
}

fn read_json<T: DeserializeOwned + Serialize>(
    path: &Path,
    code: ContractErrorCode,
) -> Result<T, ContractError> {
    let raw = read_text(path, code)?;
    let value: T = json::parse(&raw).map_err(|_| ContractError::new(code))?;
    detect_serialized(&value)?;
    Ok(value)
}

fn detect_serialized<T: Serialize>(value: &T) -> Result<(), ContractError> {
    let text = serde_json::to_string(value)
        .map_err(|_| ContractError::new(ContractErrorCode::MissingField))?;
    detect_text(&text)
}

fn read_publication(path: &Path) -> Result<PublicSdkPublication, ContractError> {
    read_json(path, ContractErrorCode::MissingPublication)
}

fn read_completion(path: &Path) -> Result<SubsetCompletion, ContractError> {
    read_json(path, ContractErrorCode::CompletionMismatch)
}

fn read_manifest(path: &Path) -> Result<FixtureManifest, ContractError> {
    read_json(path, ContractErrorCode::MissingField)
}

fn read_ngap_matrices(
    dir: &Path,
) -> Result<(BTreeSet<String>, Vec<MessageIeMatrix>), ContractError> {
    let paths = json_files(dir, ContractErrorCode::MissingMatrix)?;
    if paths.is_empty() {
        return Err(ContractError::new(ContractErrorCode::MissingMatrix));
    }
    let mut names = BTreeSet::new();
    let mut matrices = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ContractError::new(ContractErrorCode::MissingMatrix))?;
        names.insert(format!("matrices/{name}"));
        let matrix: MessageIeMatrix = read_json(&path, ContractErrorCode::MissingMatrix)?;
        let mut ids = BTreeSet::new();
        if matrix.message.trim().is_empty()
            || matrix.ies.is_empty()
            || matrix.ts29413_clause.is_empty()
            || matrix.admitted_disposition.is_empty()
            || matrix.source.document != "3GPP TS 38.413"
            || matrix.source.release != "V18.10.0"
            || matrix.application.document != "3GPP TS 29.413"
            || matrix.application.release != "V18.5.0"
            || !nonempty_strings(&matrix.source.clauses)
            || !nonempty_strings(&matrix.application.clauses)
        {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        }
        for ie in &matrix.ies {
            if !ids.insert(ie.id)
                || ie.name.trim().is_empty()
                || !matches!(ie.criticality.as_str(), "reject" | "ignore" | "notify")
                || ie.cardinality != "singleton"
                || !matches!(
                    ie.presence.as_str(),
                    "mandatory" | "optional" | "conditional"
                )
            {
                return Err(ContractError::new(ContractErrorCode::MissingMatrix));
            }
        }
        matrices.push(matrix);
    }
    Ok((names, matrices))
}

fn read_wire(path: &Path) -> Result<Vec<u8>, ContractError> {
    let raw = read_text(path, ContractErrorCode::MissingWire)?;
    let bytes =
        parse_hex(&raw).ok_or_else(|| ContractError::new(ContractErrorCode::MissingWire))?;
    if bytes.is_empty() {
        return Err(ContractError::new(ContractErrorCode::MissingWire));
    }
    detect_text(&String::from_utf8_lossy(&bytes))?;
    Ok(bytes)
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn nonempty_strings(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|value| !value.trim().is_empty())
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

fn is_sha(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn detect_publication(publication: &PublicSdkPublication) -> Result<(), ContractError> {
    if publication.repository != "https://github.com/openpacketcore/openpacketcore-sdk"
        || !is_sha(&publication.base, 40)
        || !is_sha(&publication.head, 40)
        || !is_sha(&publication.tree, 40)
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
    if ids != recorded || recorded.len() != completion.fixture_ids.len() {
        return Err(ContractError::new(ContractErrorCode::CompletionMismatch));
    }
    let actual_classes: BTreeSet<&str> = manifests
        .iter()
        .filter(|(_, manifest, _)| manifest.subset == subset)
        .map(|(_, manifest, _)| manifest.case_class.as_str())
        .collect();
    let recorded_classes: BTreeSet<&str> =
        completion.case_classes.iter().map(String::as_str).collect();
    if actual_classes != recorded_classes || recorded_classes.len() != completion.case_classes.len()
    {
        return Err(ContractError::new(ContractErrorCode::IncompleteSubset));
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
    if !nonempty_strings(&completion.receive)
        || !nonempty_strings(&completion.unsupported)
        || completion
            .constructed
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return Err(ContractError::new(ContractErrorCode::CompletionMismatch));
    }
    if subset == "ngap"
        && (completion.admitted_outcomes.is_empty()
            || completion.matrices.is_empty()
            || !completion
                .admission_scope
                .contains("first-cnf-typed-subset"))
    {
        return Err(ContractError::new(ContractErrorCode::MissingMatrix));
    }
    Ok(())
}

fn detect_ngap_matrices(
    completion: Option<&SubsetCompletion>,
    matrices: &[MessageIeMatrix],
    manifests: &[(PathBuf, FixtureManifest, Vec<u8>)],
) -> Result<(), ContractError> {
    let Some(completion) = completion else {
        return Err(ContractError::new(ContractErrorCode::MissingMatrix));
    };
    let matrix_messages: BTreeSet<&str> = matrices
        .iter()
        .map(|matrix| matrix.message.as_str())
        .collect();
    let admitted: BTreeSet<&str> = completion
        .admitted_outcomes
        .iter()
        .map(String::as_str)
        .collect();
    let expected_admitted: BTreeSet<&str> = matrix_messages
        .iter()
        .copied()
        .filter(|message| *message != "Paging")
        .collect();
    if admitted != expected_admitted || admitted.len() != completion.admitted_outcomes.len() {
        return Err(ContractError::new(ContractErrorCode::MissingMatrix));
    }
    if matrix_messages.len() != matrices.len() {
        return Err(ContractError::new(ContractErrorCode::MissingMatrix));
    }
    for admitted in &completion.admitted_outcomes {
        if !matrix_messages.contains(admitted.as_str()) {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        }
    }
    let fixture_ids: BTreeSet<&str> = manifests
        .iter()
        .filter(|(_, manifest, _)| manifest.subset == "ngap")
        .map(|(_, manifest, _)| manifest.sdk_fixture_id.as_str())
        .collect();
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("../oracles/ngap-rel18.json"))
            .map_err(|_| ContractError::new(ContractErrorCode::MissingMatrix))?;
    let oracle_rows: BTreeMap<String, Vec<IeCardinality>> = serde_json::from_value(
        oracle
            .get("messages")
            .cloned()
            .ok_or_else(|| ContractError::new(ContractErrorCode::MissingMatrix))?,
    )
    .map_err(|_| ContractError::new(ContractErrorCode::MissingMatrix))?;
    let mut saw_paging = false;
    for matrix in matrices {
        if oracle_rows.get(&matrix.message) != Some(&matrix.ies) {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        }
        let dispatch = &oracle["dispatch"][&matrix.message];
        if dispatch["procedure_code"].as_u64() != Some(u64::from(matrix.procedure_code))
            || dispatch["outcome"].as_str() != Some(matrix.outcome.as_str())
            || dispatch["direction"].as_str() != Some(matrix.direction.as_str())
        {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        }
        match matrix.ts29413_clause.as_str() {
            "5.2" => {
                if matrix.admitted_disposition != "receive" || matrix.constructed_send {
                    return Err(ContractError::new(ContractErrorCode::MissingMatrix));
                }
            }
            "5.4" => {
                if matrix.message != "Paging" || matrix.admitted_disposition != "unsupported" {
                    return Err(ContractError::new(ContractErrorCode::MissingMatrix));
                }
                saw_paging = true;
            }
            _ => return Err(ContractError::new(ContractErrorCode::MissingMatrix)),
        }
        let Some(fixture_id) = &matrix.wire_fixture_id else {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        };
        if !fixture_ids.contains(fixture_id.as_str()) {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        }
        let (_, manifest, wire) = manifests
            .iter()
            .find(|(_, manifest, _)| &manifest.sdk_fixture_id == fixture_id)
            .ok_or_else(|| ContractError::new(ContractErrorCode::MissingMatrix))?;
        let choice = match matrix.outcome.as_str() {
            "initiating" => 0,
            "successful" => 0x20,
            "unsuccessful" => 0x40,
            _ => return Err(ContractError::new(ContractErrorCode::MissingMatrix)),
        };
        if wire.first() != Some(&choice)
            || wire.get(1) != Some(&matrix.procedure_code)
            || wire.get(2).map(|octet| u64::from(*octet)) != dispatch["criticality_octet"].as_u64()
            || manifest.direction != matrix.direction
            || matrix.constructed_send
        {
            return Err(ContractError::new(ContractErrorCode::MissingMatrix));
        }
    }
    if !saw_paging || matrices.len() != completion.admitted_outcomes.len() + 1 {
        return Err(ContractError::new(ContractErrorCode::MissingMatrix));
    }
    Ok(())
}

fn detect_manifest(manifest: &FixtureManifest) -> Result<(), ContractError> {
    if ![
        "protocol-wire",
        "metadata-record",
        "scenario-label",
        "scenario-record",
        "construction-argument",
    ]
    .contains(&manifest.encoding.as_str())
        || manifest.validation_scope.trim().is_empty()
        || manifest.context.is_empty()
        || manifest.sdk_fixture_id.is_empty()
        || !manifest.sdk_fixture_id.starts_with("opc.n3iwf.")
        || manifest.source.document.is_empty()
        || manifest.source.release.is_empty()
        || !nonempty_strings(&manifest.source.clauses)
        || manifest.direction.is_empty()
        || manifest.role.is_empty()
        || manifest.prerequisite.is_empty()
        || manifest.provenance.notes.is_empty()
        || manifest.sanitized_fields.is_empty()
        || !nonempty_strings(&manifest.semantic_assertions)
        || manifest.sanitized_fields.iter().any(|field| {
            field.name.trim().is_empty()
                || field.treatment.trim().is_empty()
                || field.value_class.trim().is_empty()
        })
        || manifest.wire.path.is_empty()
        || !is_sha(&manifest.wire.digest_sha256, 64)
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
