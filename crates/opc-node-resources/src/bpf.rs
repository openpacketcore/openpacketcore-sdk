use crate::types::*;
use std::collections::BTreeSet;

pub fn validate_bpf_artifacts(
    profile: &ResourceProfile,
    context: &ValidationContext<'_>,
    af_xdp: &AfXdpProfile,
    report: &mut ValidationReport,
) {
    if profile.environment == Environment::Production {
        if af_xdp.bpf_artifacts.is_empty() {
            report.push_error(ValidationError::BpfArtifactMissing);
        }

        for artifact in &af_xdp.bpf_artifacts {
            // 1. Digest-pinned: non-empty, starts with "sha256:"
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

            // 2. Trusted signer or evidence ID:
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

            // 3. Expected program type:
            if artifact.program_type != "xdp" {
                report.push_error(ValidationError::BpfWrongProgramType {
                    artifact_name: artifact.name.clone(),
                    expected: "xdp".to_string(),
                    found: artifact.program_type.clone(),
                });
            }

            // 4. Expected attach point matches a data-plane interface
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

            // 5. Allowed capabilities: no capability escalation beyond CapBpf, CapNetAdmin, CapNetRaw
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
