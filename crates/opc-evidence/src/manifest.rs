use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::EvidenceError;

/// Compute a SHA-256 digest of arbitrary bytes, returned as a lowercase hex string.
pub fn compute_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

/// Manifest entry for a single file or artifact inside an evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub digest: String,
}

/// Top-level manifest for an evidence bundle.
///
/// Per RFC 006 §10.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub sdk_version: String,
    pub git_commit: String,
    pub artifact_digests: Vec<ManifestEntry>,
    pub file_digests: Vec<ManifestEntry>,
    pub signing_identity: String,
    pub generation_tool: String,
    pub generation_tool_version: String,
    pub generation_timestamp: String,
    pub known_incomplete_sections: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, String>,
}

impl Manifest {
    /// Verifies that every file digest in the manifest still matches the
    /// supplied `expected_digests` map (path → digest).
    ///
    /// Note: Artifact digest verification is handled separately.
    ///
    /// Returns [`EvidenceError::ManifestTampered`] if any digest mismatches,
    /// or [`EvidenceError::MissingArtifact`] if a listed file is absent from
    /// the supplied map.
    pub fn verify_file_digests(
        &self,
        expected_digests: &HashMap<String, String>,
    ) -> Result<(), EvidenceError> {
        for entry in &self.file_digests {
            let expected = expected_digests
                .get(&entry.path)
                .ok_or_else(|| EvidenceError::MissingArtifact("<manifest entry>".to_string()))?;

            if *expected != entry.digest {
                return Err(EvidenceError::ManifestTampered);
            }
        }
        Ok(())
    }
}
