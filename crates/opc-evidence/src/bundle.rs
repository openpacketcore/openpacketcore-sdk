use crate::{EvidenceError, Manifest};
use serde::{Deserialize, Serialize};

/// Serializes the manifest into stable bytes for signing and verification.
///
/// The manifest contains maps in metadata. Routing signing through
/// `serde_json::Value` normalizes object key ordering under serde_json's
/// default map representation and keeps signatures stable for identical
/// manifest content.
pub fn manifest_signing_bytes(manifest: &Manifest) -> Result<Vec<u8>, EvidenceError> {
    let value = serde_json::to_value(manifest)
        .map_err(|e| EvidenceError::GapGateFailed(format!("failed to encode manifest: {e}")))?;
    serde_json::to_vec(&value).map_err(|e| {
        EvidenceError::GapGateFailed(format!("failed to serialize manifest signing bytes: {e}"))
    })
}

/// A signer trait for signing the bundle manifest.
pub trait BundleSigner {
    fn sign(&self, data: &[u8]) -> Result<String, EvidenceError>;
    fn identity(&self) -> String;
}

/// A verifier trait for verifying the signature of the bundle manifest.
pub trait BundleVerifier {
    fn verify(&self, data: &[u8], signature: &str) -> Result<(), EvidenceError>;
}

/// An in-process mock signer for testing and offline builds.
pub struct MockSigner {
    pub key: String,
}

impl MockSigner {
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

impl BundleSigner for MockSigner {
    fn sign(&self, data: &[u8]) -> Result<String, EvidenceError> {
        let digest = crate::manifest::compute_digest(data);
        Ok(format!("mock-sig:{}:{}", self.key, digest))
    }
    fn identity(&self) -> String {
        format!("mock-identity-{}", self.key)
    }
}

/// An in-process mock verifier matching `MockSigner`.
pub struct MockVerifier {
    pub key: String,
}

impl MockVerifier {
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

impl BundleVerifier for MockVerifier {
    fn verify(&self, data: &[u8], signature: &str) -> Result<(), EvidenceError> {
        let expected = format!(
            "mock-sig:{}:{}",
            self.key,
            crate::manifest::compute_digest(data)
        );
        if signature == expected {
            Ok(())
        } else {
            Err(EvidenceError::ManifestTampered)
        }
    }
}

/// Represents the packaged evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub manifest: Manifest,
    pub signature: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conformance_report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance_baseline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_governance_report: Option<String>,
}

/// Verifies the entire evidence bundle against a verifier and available files.
pub fn verify_bundle(
    bundle: &EvidenceBundle,
    verifier: &dyn BundleVerifier,
    files: &std::collections::HashMap<String, Vec<u8>>,
) -> Result<(), EvidenceError> {
    // 1. Verify schema version
    if bundle.manifest.schema_version != "1.0.0" {
        return Err(EvidenceError::GapGateFailed(format!(
            "unknown bundle schema version: {}",
            bundle.manifest.schema_version
        )));
    }

    // 2. Verify signature
    if bundle.signature.is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "missing signature".to_string(),
        ));
    }
    let manifest_bytes = manifest_signing_bytes(&bundle.manifest)?;
    verifier.verify(&manifest_bytes, &bundle.signature)?;

    // 3. Collect digests of files we have
    let mut expected_digests = std::collections::HashMap::new();
    for (path, content) in files {
        expected_digests.insert(path.clone(), crate::manifest::compute_digest(content));
    }

    // 4. Verify file digests listed in the manifest
    bundle.manifest.verify_file_digests(&expected_digests)?;

    // 5. Verify artifact digests listed in the manifest
    for entry in &bundle.manifest.artifact_digests {
        let actual_digest = expected_digests
            .get(&entry.path)
            .ok_or_else(|| EvidenceError::MissingArtifact(entry.path.clone()))?;
        if *actual_digest != entry.digest {
            return Err(EvidenceError::ManifestTampered);
        }
    }

    Ok(())
}
