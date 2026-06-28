use thiserror::Error;

/// Failure modes for the evidence pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// Requirement ID does not conform to the `REQ-<source>-<doc>-<rel>-<sec>-<ord>` schema.
    #[error("invalid requirement id: {0}")]
    InvalidRequirementId(String),

    /// Tag syntax is malformed or uses an unknown key.
    #[error("invalid tag: {0}")]
    InvalidTag(String),

    /// A serialized evidence value contains a raw sensitive identifier or key
    /// material, or otherwise violates a redaction invariant.
    #[error("redaction violation: {0}")]
    RedactionViolation(String),

    /// A gap record failed a release gate (missing owner, mitigation, etc.).
    #[error("gap gate failed: {0}")]
    GapGateFailed(String),

    /// Manifest digest does not match recomputed value — possible tampering.
    #[error("manifest tampered: digest mismatch")]
    ManifestTampered,

    /// A referenced file or artifact is missing from the manifest.
    #[error("missing artifact: {0}")]
    MissingArtifact(String),
}
