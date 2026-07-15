//! Conformance evidence, gap tracking, and release-gate logic for OpenPacketCore.
//!
//! Implements the RFC 006 evidence pipeline: SBOM generation, VEX scanning,
//! bundle signing, and gate policy enforcement.

pub mod bundle;
pub mod data_governance;
pub mod dataplane;
pub mod error;
pub mod evidence;
pub mod extract;
pub mod gap;
pub mod manifest;
pub mod packet_core;
pub mod performance;
pub mod policy;
pub mod provenance;
pub mod requirement;
pub mod sbom;
pub mod status;
pub mod tag;
pub mod vex;

pub use bundle::{
    bundle_signing_bytes, manifest_signing_bytes, sign_bundle, validate_manifest_structure,
    verify_bundle, BundleSigner, BundleVerifier, BundleVerifierSecurity, EvidenceBundle,
    BUNDLE_SIGNING_DOMAIN, MANIFEST_SIGNING_DOMAIN,
};
pub use data_governance::DataGovernanceEvidenceReport;
pub use dataplane::{
    assert_packet_continuity_claim_allowed, assert_traffic_readiness_claim_allowed,
    DataplaneBearerSummary, DataplaneEvidenceError, DataplaneSessionSummary, DataplaneSnapshot,
    DataplaneSnapshotAsserter, DataplaneTrafficBlockReasonCode,
};
pub use error::EvidenceError;
pub use evidence::{EvidenceRecord, WaiverRecord};
pub use extract::{scan_directory, scan_file, ExtractedTag, ExtractionError};
pub use gap::{validate_status_for_gaps, Gap, GapError, GapOptions, GapSeverity, GapStatus};
pub use manifest::{compute_digest, Manifest, ManifestEntry};
pub use packet_core::{
    has_raw_sensitive_identifier, AttachProcedureEvidence, AttachProcedureResult, AttachStep,
    AttachStepResult, DataplaneCounter, KernelDataplaneEvidence, PacketCoreEvidencePack,
    PacketCoreMessageDirection, PacketCoreProtocolEvidence, PACKET_CORE_SCHEMA_VERSION,
};
pub use performance::{
    capture_environment, evaluate_threshold, redact_secrets_and_paths, EnvironmentMetadata,
    PerformanceBaseline, PerformanceMetric, RegressionStatus,
};
pub use policy::{
    bind_gate_inputs, gate_inputs_digest, GateEvaluator, GatePolicy, PolicyMode,
    GATE_INPUTS_DIGEST_METADATA_KEY, GATE_INPUTS_SIGNING_DOMAIN,
};
pub use provenance::{
    generate_provenance, BuildMetadata, BuilderIdentity, InvocationDetails, InvocationEnvironment,
    ProvenanceDigest, ProvenanceMaterial, ProvenancePredicate, ProvenanceStatement,
    ProvenanceSubject,
};
pub use requirement::RequirementId;
pub use sbom::{
    generate_sbom, generate_sbom_at, Sbom, SbomComponent, SbomDependency, SbomHash, SbomLicense,
    SbomLicenseChoice, SbomMetadata,
};
pub use status::{calculate_status, ConformanceStatus, StatusInputs};
pub use tag::{parse_tags, ConformanceTag};
pub use vex::{validate_vex_record, VexDecision, VexPolicyResult, VexRecord};
