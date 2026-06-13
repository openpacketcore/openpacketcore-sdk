use crate::types::*;
use std::collections::BTreeSet;

pub fn validate_bpf_artifacts(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    af_xdp: &AfXdpProfile,
    report: &mut ValidationReport,
) {
    let production = profile.environment == Environment::Production;

    // A Production profile must ship at least one (signed, pinned) artifact.
    if production && af_xdp.bpf_artifacts.is_empty() {
        report.push_error(ValidationError::BpfArtifactMissing);
    }

    for artifact in &af_xdp.bpf_artifacts {
        // Structural checks run in EVERY environment. A lab AF_XDP profile may
        // run unsigned artifacts, but it must never load a program of the wrong
        // type, attach at an unexpected point, or request capabilities beyond
        // the data-plane set — those are capability-escalation vectors
        // regardless of environment.

        // Expected program type:
        if artifact.program_type != "xdp" {
            report.push_error(ValidationError::BpfWrongProgramType {
                artifact_name: artifact.name.clone(),
                expected: "xdp".to_string(),
                found: artifact.program_type.clone(),
            });
        }

        // Expected attach point matches a data-plane interface:
        if !context
            .data_plane_interfaces
            .contains(&artifact.expected_attach_point)
        {
            report.push_error(ValidationError::BpfWrongAttachPoint {
                artifact_name: artifact.name.clone(),
                expected: context.data_plane_interfaces.join(", "),
                found: artifact.expected_attach_point.clone(),
            });
        }

        // Allowed capabilities: no escalation beyond CapBpf, CapNetAdmin, CapNetRaw.
        let allowed_bpf_caps = BTreeSet::from([
            LinuxCapability::CapBpf,
            LinuxCapability::CapNetAdmin,
            LinuxCapability::CapNetRaw,
        ]);
        for cap in &artifact.allowed_capabilities {
            if !allowed_bpf_caps.contains(cap) {
                report.push_error(ValidationError::BpfCapabilityEscalation {
                    artifact_name: artifact.name.clone(),
                    capability: cap.clone(),
                });
            }
        }

        // Strict provenance (digest pinning + a trusted signer or evidence ID)
        // is required only in Production.
        if production {
            // Digest-pinned: non-empty, starts with "sha256:".
            if artifact.digest.is_empty() {
                report.push_error(ValidationError::BpfMissingDigest {
                    artifact_name: artifact.name.clone(),
                });
            } else if !artifact.digest.starts_with("sha256:") || artifact.digest.contains("latest")
            {
                report.push_error(ValidationError::BpfUnsignedArtifact {
                    artifact_name: artifact.name.clone(),
                });
            }

            // Trusted signer or evidence ID:
            let has_signature =
                !artifact.signature_ref.is_empty() && !artifact.signer_identity.is_empty();
            let has_evidence = artifact
                .evidence_id
                .as_ref()
                .map(|id| !id.is_empty())
                .unwrap_or(false);
            if !has_signature && !has_evidence {
                report.push_error(ValidationError::BpfWrongSigner {
                    artifact_name: artifact.name.clone(),
                    signer: artifact.signer_identity.clone(),
                });
            }
        }
    }
}

/// Returns `true` iff `path` is inside `/sys/fs/bpf` without traversing upward
/// past the bpffs root.  Paths must be canonical (no `.` or `..` segments) and
/// must not contain a trailing slash — callers should strip trailing `/` before
/// passing a path here.
pub fn is_controlled_bpffs_path(path: &str) -> bool {
    let Some(suffix) = path.strip_prefix("/sys/fs/bpf") else {
        return false;
    };

    if suffix.is_empty() {
        return true;
    }

    if !suffix.starts_with('/') {
        return false;
    }

    suffix[1..]
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
