use opc_runtime::profile::RuntimeMode;
use serde::{Deserialize, Serialize};

/// Structure representing a Kubernetes-style admission preflight check request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub uid: String,
    pub runtime_mode: RuntimeMode,
    pub claims_ha: bool,
    /// Type of config store backend, e.g. "sqlite", "consensus"
    pub config_backend: String,
    /// Type of session store backend, e.g. "sqlite", "fake", "quorum"
    pub session_backend: String,
    pub admin_auth: AdminAuthSpec,
    pub identity: IdentitySpec,
    pub resource_profile: Option<ResourceProfileSpec>,
    pub node_capabilities: Option<opc_node_resources::NodeCapabilityReport>,
    pub operator_release: Option<crate::compatibility::OperatorReleaseDescriptor>,
    pub nf_release: Option<crate::compatibility::NfReleaseDescriptor>,
    pub compatibility_matrix: Option<crate::compatibility::CompatibilityMatrix>,
    pub evidence: Option<Vec<crate::compatibility::CompatibilityEvidence>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthSpec {
    pub token_enabled: bool,
    pub admin_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySpec {
    pub kms_enabled: bool,
    pub spiffe_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceProfileSpec {
    pub nf_kind: String,            // "upf", "smf", "amf", etc.
    pub data_plane_profile: String, // "ControlPlaneOnly", "AfXdpFastPath", "SriovFastPath", etc.
    pub numa_policy: String,        // "Require", "Warn", "Ignore"
    pub generic_xdp_fallback_allowed: bool,
    pub isolated_cores: Vec<u16>,
    pub require_exclusive_cores: bool,
    #[serde(default)]
    pub data_plane_interfaces: Vec<String>,
    #[serde(default)]
    pub data_plane_numa_node: Option<u16>,
    #[serde(default)]
    pub hugepage_numa_node: Option<u16>,
    #[serde(default)]
    pub pod_security_evidence_id: Option<String>,
    #[serde(default)]
    pub bpf_artifacts: Vec<opc_node_resources::BpfArtifact>,
    #[serde(default)]
    pub sriov_resource_name: Option<String>,
    #[serde(default)]
    pub sriov_allowed_device_drivers: Vec<String>,
}

/// Structure representing the response sent back to a Kubernetes admission controller webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    pub status: Option<AdmissionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionStatus {
    pub code: i32,
    pub message: String,
    pub reason: String,
}

/// Helper function to sanitize admission denial messages, redacting pathnames,
/// auth tokens, IMSI/subscriber IDs, PEM certificates, SQL queries, and config blobs.
pub fn sanitize_denial_message(msg: &str) -> String {
    let mut sanitized = msg.to_string();

    // 1. Redact PEM blocks
    if sanitized.contains("-----BEGIN") || sanitized.contains("-----END") {
        return "[redacted-pem]".to_string();
    }

    // 2. Redact SQL clauses (case-insensitive checks)
    let lower = sanitized.to_lowercase();
    let is_sql = (lower.contains("select ") && lower.contains("from "))
        || lower.contains("insert into")
        || lower.contains("delete from")
        || (lower.contains("update ") && lower.contains("set "))
        || lower.contains("drop table")
        || lower.contains("create table")
        || lower.contains("alter table");
    if is_sql {
        return "[redacted-sql]".to_string();
    }

    // 3. Redact raw config blobs (JSON / XML / YAML style braces/brackets)
    if (sanitized.contains('{') && sanitized.contains('}'))
        || (sanitized.contains('[') && sanitized.contains(']'))
    {
        return "[redacted-config]".to_string();
    }

    // 4. Redact tokens, paths, and identifiers token-by-token
    let mut words: Vec<String> = sanitized
        .split_whitespace()
        .map(|w| w.to_string())
        .collect();
    let mut redact_next = false;
    for w in words.iter_mut() {
        let normalized = w
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '/' && c != '\\')
            .to_lowercase();

        if redact_next {
            *w = "[redacted-token]".to_string();
            redact_next = false;
            continue;
        }

        if contains_secret_assignment(&normalized) {
            *w = "[redacted-token]".to_string();
            redact_next = false;
            continue;
        }

        if normalized == "token"
            || normalized == "password"
            || normalized == "credential"
            || normalized == "secret"
            || normalized == "bearer"
            || normalized.ends_with("token")
        {
            redact_next = true;
            continue;
        }

        // Redact absolute and relative paths without treating slash-separated prose
        // such as "SQLite/Fake" or "insecure/unsafe" as paths.
        if looks_like_path(w) {
            *w = "[redacted-path]".to_string();
        }
        // Redact subscriber identifiers even when punctuation surrounds them.
        else if contains_digit_run(w, 8) {
            *w = "[redacted-subscriber-id]".to_string();
        }
        // Redact auth tokens / credentials.
        else if looks_like_token(w) {
            *w = "[redacted-token]".to_string();
        }
    }
    sanitized = words.join(" ");

    sanitized
}

fn canonical_backend_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

fn looks_like_path(value: &str) -> bool {
    if value.starts_with("http://") || value.starts_with("https://") {
        return false;
    }
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
        || value.contains('\\')
        || (value.contains('/') && value.contains('.'))
}

fn contains_digit_run(value: &str, threshold: usize) -> bool {
    let mut run = 0;
    for c in value.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= threshold {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn looks_like_token(value: &str) -> bool {
    let trimmed = value.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    trimmed.len() >= 16
        && trimmed.chars().all(|c| c.is_ascii_alphanumeric())
        && trimmed.chars().any(|c| c.is_ascii_alphabetic())
        && trimmed.chars().any(|c| c.is_ascii_digit())
}

fn contains_secret_assignment(value: &str) -> bool {
    ["token", "password", "credential", "secret", "bearer"]
        .iter()
        .any(|key| value.contains(&format!("{key}=")) || value.contains(&format!("{key}:")))
}

fn parse_data_plane_profile(value: &str) -> Option<opc_node_resources::DataPlaneProfile> {
    match value {
        "ControlPlaneOnly" => Some(opc_node_resources::DataPlaneProfile::ControlPlaneOnly),
        "SignalingHeavy" => Some(opc_node_resources::DataPlaneProfile::SignalingHeavy),
        "KernelNetworking" => Some(opc_node_resources::DataPlaneProfile::KernelNetworking),
        "AfXdpFastPath" => Some(opc_node_resources::DataPlaneProfile::AfXdpFastPath),
        "SriovFastPath" => Some(opc_node_resources::DataPlaneProfile::SriovFastPath),
        "IpsecGateway" => Some(opc_node_resources::DataPlaneProfile::IpsecGateway),
        _ => None,
    }
}

fn parse_numa_policy(value: &str) -> Option<opc_node_resources::NumaPolicy> {
    match value {
        "Require" => Some(opc_node_resources::NumaPolicy::Require),
        "Warn" => Some(opc_node_resources::NumaPolicy::Warn),
        "Ignore" => Some(opc_node_resources::NumaPolicy::Ignore),
        _ => None,
    }
}

fn parse_nf_kind(value: &str) -> opc_node_resources::NetworkFunctionKind {
    match value {
        "upf" => opc_node_resources::NetworkFunctionKind::Upf,
        "smf" => opc_node_resources::NetworkFunctionKind::Smf,
        "amf" => opc_node_resources::NetworkFunctionKind::Amf,
        "nrf" => opc_node_resources::NetworkFunctionKind::Nrf,
        other => opc_node_resources::NetworkFunctionKind::Custom(other.to_string()),
    }
}

fn infer_data_plane_numa_node(
    rp: &ResourceProfileSpec,
    node: &opc_node_resources::NodeCapabilityReport,
) -> Option<opc_node_resources::NumaNodeId> {
    if let Some(declared) = rp.data_plane_numa_node {
        return Some(declared);
    }

    if node.cpu.numa_nodes == 1 {
        return Some(0);
    }

    let mut observed = None;
    for core in &rp.isolated_cores {
        let numa = node.cpu.cpu_numa_map.get(core).copied()?;
        match observed {
            Some(existing) if existing != numa => return None,
            Some(_) => {}
            None => observed = Some(numa),
        }
    }
    observed
}

/// Evaluates an admission request and returns an allowed or denied response.
pub fn evaluate_admission(req: &AdmissionRequest) -> AdmissionResponse {
    let mut allowed = true;
    let mut message = String::new();
    let mut reason = "Success".to_string();

    // Only apply strict constraints in Production mode
    if req.runtime_mode == RuntimeMode::Production {
        let config_backend = canonical_backend_name(&req.config_backend);
        let session_backend = canonical_backend_name(&req.session_backend);

        // 1. HA backend requirements: single-node config/session backends cannot be used for HA claims
        if req.claims_ha && matches!(config_backend.as_str(), "sqlite" | "fake" | "mock") {
            allowed = false;
            message = "Production specification using standalone SQLite/Fake config backend is rejected for high-availability deployments.".to_string();
            reason = "HAClaimsRejectedWithSingleNodeConfigBackend".to_string();
        } else if req.claims_ha
            && !matches!(
                config_backend.as_str(),
                "consensus" | "consensus-config-store" | "consensusconfigstore"
            )
        {
            allowed = false;
            message =
                "Production high-availability specification must use the consensus config backend."
                    .to_string();
            reason = "HAConfigBackendUnsupported".to_string();
        } else if req.claims_ha && matches!(session_backend.as_str(), "sqlite" | "fake" | "mock") {
            allowed = false;
            message = "Production specification using standalone SQLite or Fake session backend is rejected for high-availability deployments.".to_string();
            reason = "HAClaimsRejectedWithSingleNodeBackend".to_string();
        } else if req.claims_ha
            && !matches!(
                session_backend.as_str(),
                "quorum" | "quorum-session-store" | "quorumsessionstore"
            )
        {
            allowed = false;
            message =
                "Production high-availability specification must use the quorum session backend."
                    .to_string();
            reason = "HASessionBackendUnsupported".to_string();
        }
        // 2. Admin auth requirements: token must be enabled and cannot be unsafe
        else if !req.admin_auth.token_enabled || req.admin_auth.admin_token.is_none() {
            allowed = false;
            message = "Production specification is missing required admin token authentication."
                .to_string();
            reason = "AdminTokenMissing".to_string();
        } else if let Some(ref token) = req.admin_auth.admin_token {
            let trimmed = token.trim();
            let unsafe_values = [
                "admin",
                "admin123",
                "password",
                "default",
                "openpacketcore",
                "secret",
            ];
            if trimmed.is_empty()
                || trimmed.len() < 16
                || unsafe_values.contains(&trimmed.to_lowercase().as_str())
            {
                allowed = false;
                message = format!(
                    "Production specification uses an insecure/unsafe admin token: {token}"
                );
                reason = "AdminTokenUnsafe".to_string();
            }
        }

        // 3. KMS/SPIFFE identity requirements
        if allowed && (!req.identity.kms_enabled || !req.identity.spiffe_enabled) {
            allowed = false;
            message = "Production specification is missing required KMS or SPIFFE identity configuration.".to_string();
            reason = "MissingKmsSpiffeIdentity".to_string();
        }

        // 4. Resource Profile Requirements & Platform Preflight
        if allowed {
            if let Some(ref rp) = req.resource_profile {
                let is_fast_path = rp.data_plane_profile == "AfXdpFastPath"
                    || rp.data_plane_profile == "SriovFastPath";

                // Fast path data-planes require exclusive CPU pinning and isolated cores in production
                if is_fast_path && (!rp.require_exclusive_cores || rp.isolated_cores.is_empty()) {
                    allowed = false;
                    message = "Production resource profile does not satisfy exclusive CPU/core requirements for fast-path data plane.".to_string();
                    reason = "FastPathCoresIncompatible".to_string();
                }

                // UPF requires high-performance packet path
                if rp.nf_kind == "upf" && rp.data_plane_profile == "ControlPlaneOnly" {
                    allowed = false;
                    message = "User Plane Function (UPF) cannot run with ControlPlaneOnly data plane profile in production.".to_string();
                    reason = "UpfDataPlaneInadequate".to_string();
                }

                // Production must never skip node capability validation. Without
                // an observed capability report, admission cannot prove that the
                // requested data-plane profile is schedulable on the target node.
                if allowed {
                    if let Some(ref node) = req.node_capabilities {
                        match (
                            parse_data_plane_profile(&rp.data_plane_profile),
                            parse_numa_policy(&rp.numa_policy),
                        ) {
                            (None, _) => {
                                allowed = false;
                                message = format!(
                                    "Production resource profile uses unsupported data-plane profile {}",
                                    rp.data_plane_profile
                                );
                                reason = "ResourceProfileInvalid".to_string();
                            }
                            (_, None) => {
                                allowed = false;
                                message = format!(
                                    "Production resource profile uses unsupported NUMA policy {}",
                                    rp.numa_policy
                                );
                                reason = "ResourceProfileInvalid".to_string();
                            }
                            (Some(data_plane_profile), Some(numa_policy)) => {
                                // Construct layout and profile
                                let mut profile = opc_node_resources::ResourceProfile::new(
                                    parse_nf_kind(&rp.nf_kind),
                                    data_plane_profile,
                                    opc_node_resources::Environment::Production,
                                );

                                profile.cpu_policy.require_exclusive_data_plane_cores =
                                    rp.require_exclusive_cores;
                                profile.cpu_policy.numa_locality = numa_policy;
                                profile.lab_fallback.allow_generic_xdp =
                                    rp.generic_xdp_fallback_allowed;
                                profile.pod_security =
                                    opc_node_resources::PodSecurityExceptionModel::minimal_required(
                                        data_plane_profile,
                                        rp.pod_security_evidence_id.clone(),
                                    );

                                if profile.data_plane_profile
                                    == opc_node_resources::DataPlaneProfile::AfXdpFastPath
                                {
                                    profile.af_xdp = Some(opc_node_resources::AfXdpProfile {
                                        minimum_kernel: opc_node_resources::KernelVersion::new(
                                            6, 8, 0,
                                        ),
                                        required_btf: true,
                                        required_xdp_mode: opc_node_resources::XdpMode::Native,
                                        required_capabilities: std::collections::BTreeSet::from([
                                            opc_node_resources::LinuxCapability::CapBpf,
                                            opc_node_resources::LinuxCapability::CapNetAdmin,
                                            opc_node_resources::LinuxCapability::CapNetRaw,
                                        ]),
                                        required_maps: vec!["/sys/fs/bpf/upf-fastpath".to_string()],
                                        required_pin_paths: vec!["/sys/fs/bpf".to_string()],
                                        generic_xdp_fallback_allowed: rp
                                            .generic_xdp_fallback_allowed,
                                        bpf_artifacts: rp.bpf_artifacts.clone(),
                                    });
                                } else if profile.data_plane_profile
                                    == opc_node_resources::DataPlaneProfile::SriovFastPath
                                {
                                    profile.sriov = Some(opc_node_resources::SriovProfile {
                                        resource_name: rp
                                            .sriov_resource_name
                                            .clone()
                                            .unwrap_or_else(|| "intel.com/ice_sriov".to_string()),
                                        vf_trust: false,
                                        spoof_check: true,
                                        vlan_policy: None,
                                        link_state_policy:
                                            opc_node_resources::LinkStatePolicy::Auto,
                                        allowed_device_drivers: rp
                                            .sriov_allowed_device_drivers
                                            .iter()
                                            .cloned()
                                            .collect(),
                                        ipam_mode: opc_node_resources::IpamMode::Static,
                                    });
                                }

                                let cpu_layout = opc_node_resources::CpuLayout {
                                    data_plane_cores: rp.isolated_cores.clone(),
                                    control_plane_cores: vec![],
                                    management_cores: vec![],
                                    numa_node: infer_data_plane_numa_node(rp, node),
                                };

                                let sriov_resource_name = profile
                                    .sriov
                                    .as_ref()
                                    .map(|sriov| sriov.resource_name.clone())
                                    .unwrap_or_else(|| "intel.com/ice_sriov".to_string());
                                let allowlist = opc_node_resources::SriovAllowlistPolicy {
                                    allowed_resources: std::collections::BTreeMap::from([(
                                        profile.nf_kind.clone(),
                                        std::collections::BTreeSet::from([sriov_resource_name]),
                                    )]),
                                };

                                let interfaces = rp.data_plane_interfaces.clone();

                                let context = opc_node_resources::ValidationContext {
                                    node,
                                    cpu_layout: &cpu_layout,
                                    data_plane_interfaces: &interfaces,
                                    hugepage_numa_node: rp.hugepage_numa_node,
                                    sriov_allowlist: &allowlist,
                                };

                                let preflight = opc_node_resources::run_data_plane_preflight(
                                    &profile, &context,
                                );
                                if !preflight.passed {
                                    allowed = false;
                                    message = format!(
                                        "Production admission blocked by data-plane preflight: {}",
                                        preflight.messages.join("; ")
                                    );
                                    reason = "DataPlanePreflightFailed".to_string();
                                }
                            }
                        }
                    } else {
                        allowed = false;
                        message = "Production admission requires an observed node capability report for data-plane preflight validation.".to_string();
                        reason = "NodeCapabilitiesMissing".to_string();
                    }
                }
            } else {
                allowed = false;
                message =
                    "Production specification is missing required resource profile.".to_string();
                reason = "ResourceProfileMissing".to_string();
            }
        }
    }

    if allowed {
        if req.runtime_mode == RuntimeMode::Production && req.claims_ha {
            if let (Some(op), Some(nf), Some(matrix), Some(ev)) = (
                req.operator_release.as_ref(),
                req.nf_release.as_ref(),
                req.compatibility_matrix.as_ref(),
                req.evidence.as_ref(),
            ) {
                match matrix.evaluate_compatibility(
                    op,
                    nf,
                    req.runtime_mode,
                    &req.config_backend,
                    &req.session_backend,
                    req.identity.kms_enabled,
                    req.identity.spiffe_enabled,
                    req.resource_profile.is_some(),
                    ev,
                ) {
                    crate::compatibility::CompatibilityDecision::Allowed => {}
                    crate::compatibility::CompatibilityDecision::Blocked(block_reason) => {
                        allowed = false;
                        message = format!("Compatibility policy block: {}", block_reason);
                        reason = format!("{:?}", block_reason);
                        reason = reason.chars().filter(|c| c.is_alphanumeric()).collect();
                    }
                }
            } else {
                allowed = false;
                message = "Production HA admission requires operator release, NF release, compatibility matrix, and evidence descriptors.".to_string();
                reason = "CompatibilityMetadataMissing".to_string();
            }
        } else if let Some(ref matrix) = req.compatibility_matrix {
            if let (Some(op), Some(nf), Some(ev)) = (
                req.operator_release.as_ref(),
                req.nf_release.as_ref(),
                req.evidence.as_ref(),
            ) {
                match matrix.evaluate_compatibility(
                    op,
                    nf,
                    req.runtime_mode,
                    &req.config_backend,
                    &req.session_backend,
                    req.identity.kms_enabled,
                    req.identity.spiffe_enabled,
                    req.resource_profile.is_some(),
                    ev,
                ) {
                    crate::compatibility::CompatibilityDecision::Allowed => {}
                    crate::compatibility::CompatibilityDecision::Blocked(block_reason) => {
                        allowed = false;
                        message = format!("Compatibility policy block: {}", block_reason);
                        reason = format!("{:?}", block_reason);
                        reason = reason.chars().filter(|c| c.is_alphanumeric()).collect();
                    }
                }
            } else {
                allowed = false;
                message = "Admission evaluation with compatibility matrix requires operator release, NF release, and evidence descriptors.".to_string();
                reason = "CompatibilityMetadataMissing".to_string();
            }
        }
    }

    let status = if !allowed {
        let sanitized_msg = sanitize_denial_message(&message);
        Some(AdmissionStatus {
            code: 400,
            message: sanitized_msg,
            reason,
        })
    } else {
        None
    };

    AdmissionResponse {
        uid: req.uid.clone(),
        allowed,
        status,
    }
}
