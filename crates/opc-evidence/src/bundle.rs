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

/// Serializes the bytes that a bundle signature must cover: the manifest plus
/// the digest of every embedded blob (SBOM, VEX, conformance report, ...).
///
/// Signing only the manifest leaves the embedded blobs unprotected — they could
/// be swapped without invalidating the signature. Binding their digests here
/// makes any tamper detectable. A bundle with no embedded blobs produces bytes
/// identical to [`manifest_signing_bytes`], so blob-free signatures are
/// unchanged.
pub fn bundle_signing_bytes(bundle: &EvidenceBundle) -> Result<Vec<u8>, EvidenceError> {
    let mut bytes = manifest_signing_bytes(&bundle.manifest)?;
    let mut blobs: Vec<(&str, String)> = Vec::new();
    for (name, blob) in [
        ("conformance_report", &bundle.conformance_report),
        ("sbom", &bundle.sbom),
        ("vex", &bundle.vex),
        ("provenance", &bundle.provenance),
        ("performance_baseline", &bundle.performance_baseline),
        ("data_governance_report", &bundle.data_governance_report),
    ] {
        if let Some(b) = blob {
            blobs.push((name, crate::manifest::compute_digest(b.as_bytes())));
        }
    }
    blobs.sort();
    for (name, digest) in blobs {
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(digest.as_bytes());
    }
    Ok(bytes)
}

/// A signer trait for signing the bundle manifest.
pub trait BundleSigner {
    fn sign(&self, data: &[u8]) -> Result<String, EvidenceError>;
    fn identity(&self) -> String;
}

/// A verifier trait for verifying the signature of the bundle manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleVerifierSecurity {
    /// Verifier is backed by release-appropriate asymmetric verification.
    Release,
    /// Verifier is deterministic or otherwise forgeable and must only be used in tests.
    TestOnly,
}

pub trait BundleVerifier {
    fn verify(&self, data: &[u8], signature: &str) -> Result<(), EvidenceError>;
    fn security(&self) -> BundleVerifierSecurity;
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
    // The signature must cover the manifest AND every embedded blob, so a
    // swapped SBOM/VEX/report is detected.
    let signing_bytes = bundle_signing_bytes(bundle)?;
    verifier.verify(&signing_bytes, &bundle.signature)?;

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
