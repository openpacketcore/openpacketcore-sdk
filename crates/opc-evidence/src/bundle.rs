use crate::{EvidenceError, Manifest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Domain separator for standalone RFC 006 manifest signatures.
pub const MANIFEST_SIGNING_DOMAIN: &str = "openpacketcore:rfc006:manifest:v1";

/// Domain separator for complete RFC 006 evidence-bundle signatures.
pub const BUNDLE_SIGNING_DOMAIN: &str = "openpacketcore:rfc006:evidence-bundle:v1";

#[derive(Serialize)]
struct ManifestSigningPayload {
    domain: &'static str,
    manifest: serde_json::Value,
}

#[derive(Serialize)]
struct BundleSigningPayload {
    domain: &'static str,
    manifest: serde_json::Value,
    embedded_blob_digests: BTreeMap<&'static str, String>,
}

/// Serializes the manifest into stable bytes for signing and verification.
///
/// The manifest contains maps and set-like digest lists. This function sorts
/// the digest lists and routes the result through `serde_json::Value`, whose
/// default map representation orders object keys. The domain-separated result
/// is therefore stable for semantically identical manifest content.
pub fn manifest_signing_bytes(manifest: &Manifest) -> Result<Vec<u8>, EvidenceError> {
    let value = canonical_manifest_value(manifest)?;
    serde_json::to_vec(&ManifestSigningPayload {
        domain: MANIFEST_SIGNING_DOMAIN,
        manifest: value,
    })
    .map_err(|e| {
        EvidenceError::GapGateFailed(format!("failed to serialize manifest signing bytes: {e}"))
    })
}

fn canonical_manifest_value(manifest: &Manifest) -> Result<serde_json::Value, EvidenceError> {
    validate_manifest_structure(manifest)?;

    let mut canonical = manifest.clone();
    canonical.artifact_digests.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.digest.cmp(&right.digest))
    });
    canonical.file_digests.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.digest.cmp(&right.digest))
    });

    serde_json::to_value(canonical)
        .map_err(|e| EvidenceError::GapGateFailed(format!("failed to encode manifest: {e}")))
}

/// Serializes the bytes that a bundle signature must cover: the manifest plus
/// the digest of every embedded blob (SBOM, VEX, conformance report, ...).
///
/// Signing only the manifest leaves the embedded blobs unprotected — they could
/// be swapped without invalidating the signature. Binding their digests here
/// makes any tamper detectable. The explicit domain and structured digest map
/// also prevent a manifest signature from being replayed as a bundle signature.
pub fn bundle_signing_bytes(bundle: &EvidenceBundle) -> Result<Vec<u8>, EvidenceError> {
    let manifest = canonical_manifest_value(&bundle.manifest)?;
    let mut embedded_blob_digests = BTreeMap::new();
    for (name, blob) in [
        ("conformance_report", &bundle.conformance_report),
        ("sbom", &bundle.sbom),
        ("vex", &bundle.vex),
        ("provenance", &bundle.provenance),
        ("performance_baseline", &bundle.performance_baseline),
        ("data_governance_report", &bundle.data_governance_report),
    ] {
        if let Some(b) = blob {
            embedded_blob_digests.insert(name, crate::manifest::compute_digest(b.as_bytes()));
        }
    }

    serde_json::to_vec(&BundleSigningPayload {
        domain: BUNDLE_SIGNING_DOMAIN,
        manifest,
        embedded_blob_digests,
    })
    .map_err(|e| {
        EvidenceError::GapGateFailed(format!("failed to serialize bundle signing bytes: {e}"))
    })
}

/// A signer trait for signing the complete bundle signing payload.
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

    /// Returns the signing identity authenticated by this verifier.
    ///
    /// Release policy requires this value and binds it to the identity recorded
    /// inside the signed manifest. Test-only verifiers may leave it unspecified.
    fn identity(&self) -> Option<&str> {
        None
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

/// Signs a complete evidence bundle without taking custody of release keys.
///
/// The concrete signer may be backed by an HSM, Sigstore/Cosign adapter, or a
/// deterministic test implementation. The manifest identity must exactly match
/// the signer identity. A failed signing attempt leaves an existing signature
/// untouched.
pub fn sign_bundle(
    bundle: &mut EvidenceBundle,
    signer: &dyn BundleSigner,
) -> Result<(), EvidenceError> {
    validate_manifest_structure(&bundle.manifest)?;
    let signer_identity = signer.identity();
    if signer_identity.is_empty() || bundle.manifest.signing_identity != signer_identity {
        return Err(EvidenceError::GapGateFailed(
            "bundle signing identity does not match signer".to_string(),
        ));
    }

    let signing_bytes = bundle_signing_bytes(bundle)?;
    let signature = signer.sign(&signing_bytes)?;
    if signature.trim().is_empty() {
        return Err(EvidenceError::GapGateFailed(
            "bundle signer returned an empty signature".to_string(),
        ));
    }
    bundle.signature = signature;
    Ok(())
}

/// Validates the ambiguity-sensitive parts of an RFC 006 manifest.
pub fn validate_manifest_structure(manifest: &Manifest) -> Result<(), EvidenceError> {
    if manifest.signing_identity.trim().is_empty()
        || manifest.signing_identity.trim() != manifest.signing_identity
        || manifest.signing_identity.len() > 1024
        || manifest.signing_identity.chars().any(char::is_control)
    {
        return Err(EvidenceError::GapGateFailed(
            "manifest has an invalid signing identity".to_string(),
        ));
    }

    let mut paths = HashSet::new();
    for entry in manifest
        .artifact_digests
        .iter()
        .chain(&manifest.file_digests)
    {
        validate_manifest_path(&entry.path)?;
        validate_sha256_digest(&entry.digest)?;
        if !paths.insert(entry.path.as_str()) {
            return Err(EvidenceError::GapGateFailed(
                "manifest contains a duplicate path".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_manifest_path(path: &str) -> Result<(), EvidenceError> {
    let has_windows_prefix = path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic);
    let unsafe_path = path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || has_windows_prefix
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..");
    if unsafe_path {
        return Err(EvidenceError::GapGateFailed(
            "manifest contains an unsafe path".to_string(),
        ));
    }
    Ok(())
}

fn validate_sha256_digest(digest: &str) -> Result<(), EvidenceError> {
    let valid = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if !valid {
        return Err(EvidenceError::GapGateFailed(
            "manifest contains an invalid SHA-256 digest".to_string(),
        ));
    }
    Ok(())
}

/// Verifies the entire evidence bundle against a verifier and available files.
pub fn verify_bundle(
    bundle: &EvidenceBundle,
    verifier: &dyn BundleVerifier,
    files: &std::collections::HashMap<String, Vec<u8>>,
) -> Result<(), EvidenceError> {
    // 1. Verify schema version
    if bundle.manifest.schema_version != "1.0.0" {
        return Err(EvidenceError::GapGateFailed(
            "unknown bundle schema version".to_string(),
        ));
    }
    validate_manifest_structure(&bundle.manifest)?;

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
    if verifier
        .identity()
        .is_some_and(|identity| identity != bundle.manifest.signing_identity)
    {
        return Err(EvidenceError::ManifestTampered);
    }

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
            .ok_or_else(|| EvidenceError::MissingArtifact("<manifest entry>".to_string()))?;
        if *actual_digest != entry.digest {
            return Err(EvidenceError::ManifestTampered);
        }
    }

    Ok(())
}
