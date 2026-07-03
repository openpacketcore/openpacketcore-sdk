//! CLI interface exposing Rust SDK lifecycle contracts to Go controller-runtime operators via JSON.
//!
//! This is an internal binary crate and is not published.

use opc_node_resources::{
    CpuLayout, DataPlanePreflightReport, NodeCapabilityReport, SriovAllowlistPolicy,
    ValidationContext,
};
use opc_runtime::profile::RuntimeMode;
use operator_lifecycle::{
    evaluate_admission, evaluate_config_apply, ipsec_gateway_profile_from_spec,
    sanitize_denial_message, AdmissionRequest, CandidateMetadata, CompatibilityEvidence,
    CompatibilityMatrix, LifecycleStatus, NfReleaseDescriptor, OperatorReleaseDescriptor,
    PendingConfirmationState, CONTRACT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::str::FromStr;

use opc_types::{ConfigVersion, SchemaDigest};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize)]
pub struct CompatibilityRequest {
    pub operator: OperatorReleaseDescriptor,
    pub nf: NfReleaseDescriptor,
    pub runtime_mode: RuntimeMode,
    pub config_backend: String,
    pub session_backend: String,
    pub identity_kms: bool,
    pub identity_spiffe: bool,
    pub has_resource_profile: bool,
    pub compatibility_matrix: CompatibilityMatrix,
    pub evidence: Vec<CompatibilityEvidence>,
}

#[derive(Serialize, Deserialize)]
pub struct CliAlarm {
    pub alarm_id: String,
    pub alarm_type: String,
    pub severity: String,
    pub text: String,
    pub state: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigApplyRequest {
    pub desired_generation: i64,
    pub current_observed_generation: i64,
    pub current_version: u64,
    pub current_digest: String,
    pub candidate: Option<CandidateMetadata>,
    pub lifecycle_status: LifecycleStatus,
    pub active_alarms: Vec<CliAlarm>,
    pub pending_confirmation: Option<CliPendingConfirmationState>,
    pub preflight_report: Option<DataPlanePreflightReport>,
    pub current_time: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CliPendingConfirmationState {
    pub version: u64,
    pub previous_confirmed_version: u64,
    pub applied_at: String,
    pub timeout_secs: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PreflightRequest {
    pub resource_profile: operator_lifecycle::ResourceProfileSpec,
    pub node_capabilities: NodeCapabilityReport,
}

#[derive(Serialize)]
struct ErrorResponse {
    pub error: String,
    #[serde(rename = "contractVersion", skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
}

#[derive(Serialize)]
struct SuccessResponse<T> {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    #[serde(flatten)]
    pub payload: T,
}

#[derive(Serialize)]
struct VersionResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    #[serde(rename = "crateVersion")]
    pub crate_version: &'static str,
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
    rp: &operator_lifecycle::ResourceProfileSpec,
    node: &NodeCapabilityReport,
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

fn evaluate_preflight(req: &PreflightRequest) -> Result<DataPlanePreflightReport, String> {
    let rp = &req.resource_profile;
    let node = &req.node_capabilities;

    let dp_profile = parse_data_plane_profile(&rp.data_plane_profile)
        .ok_or_else(|| format!("Unsupported data-plane profile {}", rp.data_plane_profile))?;
    let numa_policy = parse_numa_policy(&rp.numa_policy)
        .ok_or_else(|| format!("Unsupported NUMA policy {}", rp.numa_policy))?;

    let mut profile = opc_node_resources::ResourceProfile::new(
        parse_nf_kind(&rp.nf_kind),
        dp_profile,
        opc_node_resources::Environment::Production,
    );

    profile.cpu_policy.require_exclusive_data_plane_cores = rp.require_exclusive_cores;
    profile.cpu_policy.numa_locality = numa_policy;
    profile.lab_fallback.allow_generic_xdp = rp.generic_xdp_fallback_allowed;
    profile.pod_security = opc_node_resources::PodSecurityExceptionModel::minimal_required(
        dp_profile,
        rp.pod_security_evidence_id.clone(),
    );

    if profile.data_plane_profile == opc_node_resources::DataPlaneProfile::AfXdpFastPath {
        profile.af_xdp = Some(opc_node_resources::AfXdpProfile {
            minimum_kernel: opc_node_resources::KernelVersion::new(6, 8, 0),
            required_btf: true,
            required_xdp_mode: opc_node_resources::XdpMode::Native,
            required_capabilities: std::collections::BTreeSet::from([
                opc_node_resources::LinuxCapability::CapBpf,
                opc_node_resources::LinuxCapability::CapNetAdmin,
                opc_node_resources::LinuxCapability::CapNetRaw,
            ]),
            required_maps: vec!["/sys/fs/bpf/upf-fastpath".to_string()],
            required_pin_paths: vec!["/sys/fs/bpf".to_string()],
            generic_xdp_fallback_allowed: rp.generic_xdp_fallback_allowed,
            bpf_artifacts: rp.bpf_artifacts.clone(),
        });
    } else if profile.data_plane_profile == opc_node_resources::DataPlaneProfile::SriovFastPath {
        profile.sriov = Some(opc_node_resources::SriovProfile {
            resource_name: rp
                .sriov_resource_name
                .clone()
                .unwrap_or_else(|| "intel.com/ice_sriov".to_string()),
            vf_trust: false,
            spoof_check: true,
            vlan_policy: None,
            link_state_policy: opc_node_resources::LinkStatePolicy::Auto,
            allowed_device_drivers: rp.sriov_allowed_device_drivers.iter().cloned().collect(),
            ipam_mode: opc_node_resources::IpamMode::Static,
        });
    } else if profile.data_plane_profile == opc_node_resources::DataPlaneProfile::IpsecGateway {
        profile.ipsec_gateway = Some(ipsec_gateway_profile_from_spec(rp));
    }

    let cpu_layout = CpuLayout {
        data_plane_cores: rp.isolated_cores.clone(),
        control_plane_cores: vec![],
        management_cores: vec![],
        numa_node: infer_data_plane_numa_node(rp, node),
    };

    let sriov_resource_name = profile
        .sriov
        .as_ref()
        .map(|s| s.resource_name.clone())
        .unwrap_or_else(|| "intel.com/ice_sriov".to_string());

    let allowlist = SriovAllowlistPolicy {
        allowed_resources: std::collections::BTreeMap::from([(
            profile.nf_kind.clone(),
            std::collections::BTreeSet::from([sriov_resource_name]),
        )]),
    };

    let interfaces = rp.data_plane_interfaces.clone();
    let context = ValidationContext {
        node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: &interfaces,
        hugepage_numa_node: rp.hugepage_numa_node,
        sriov_allowlist: &allowlist,
    };

    Ok(opc_node_resources::run_data_plane_preflight(
        &profile, &context,
    ))
}

fn write_error(err: &str) -> ! {
    let sanitized = sanitize_denial_message(err);
    let resp = ErrorResponse {
        error: sanitized,
        contract_version: Some(CONTRACT_VERSION),
    };
    let _ = serde_json::to_writer(io::stdout(), &resp);
    println!();
    std::process::exit(1);
}

fn write_contract_mismatch(expected: u64) -> ! {
    let resp = ErrorResponse {
        error: format!("Contract version mismatch: expected {expected}, actual {CONTRACT_VERSION}"),
        contract_version: Some(CONTRACT_VERSION),
    };
    let _ = serde_json::to_writer(io::stdout(), &resp);
    println!();
    std::process::exit(2);
}

fn write_success<T: Serialize>(val: &T) {
    let resp = SuccessResponse {
        contract_version: CONTRACT_VERSION,
        payload: val,
    };
    if let Err(e) = serde_json::to_writer(io::stdout(), &resp) {
        write_error(&format!("Failed to serialize response: {e}"));
    }
    println!();
    std::process::exit(0);
}

fn write_version() -> ! {
    let resp = VersionResponse {
        contract_version: CONTRACT_VERSION,
        crate_version: env!("CARGO_PKG_VERSION"),
    };
    if let Err(e) = serde_json::to_writer(io::stdout(), &resp) {
        write_error(&format!("Failed to serialize response: {e}"));
    }
    println!();
    std::process::exit(0);
}

fn parse_request<T: serde::de::DeserializeOwned>(buffer: &str, command_name: &str) -> T {
    let mut value: serde_json::Value = match serde_json::from_str(buffer) {
        Ok(v) => v,
        Err(e) => write_error(&format!("Invalid JSON: {e}")),
    };

    if let Some(expected) = value
        .get("expectedContractVersion")
        .and_then(|v| v.as_u64())
    {
        if expected as u32 != CONTRACT_VERSION {
            write_contract_mismatch(expected);
        }
    }

    // Remove expectedContractVersion so it does not interfere with deserialization.
    if let Some(obj) = value.as_object_mut() {
        obj.remove("expectedContractVersion");
    }

    match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => write_error(&format!("Invalid {command_name} JSON: {e}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        write_error(
            "Usage: operator-lifecycle-cli <admission|compatibility|config-apply|preflight|version>",
        );
    }

    let command = args[1].as_str();

    if command == "version" {
        write_version();
    }

    let mut buffer = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buffer) {
        write_error(&format!("Failed to read stdin: {e}"));
    }

    match command {
        "admission" => {
            let req: AdmissionRequest = parse_request(&buffer, "AdmissionRequest");
            let resp = evaluate_admission(&req);
            write_success(&resp);
        }
        "compatibility" => {
            let req: CompatibilityRequest = parse_request(&buffer, "CompatibilityRequest");
            let resp = req.compatibility_matrix.evaluate_compatibility(
                &req.operator,
                &req.nf,
                req.runtime_mode,
                &req.config_backend,
                &req.session_backend,
                req.identity_kms,
                req.identity_spiffe,
                req.has_resource_profile,
                &req.evidence,
            );
            write_success(&resp);
        }
        "config-apply" => {
            let req: ConfigApplyRequest = parse_request(&buffer, "ConfigApplyRequest");
            let current_digest = match SchemaDigest::from_str(&req.current_digest) {
                Ok(d) => d,
                Err(e) => write_error(&format!("Invalid SchemaDigest hex: {e}")),
            };
            let current_time = if let Some(ref t) = req.current_time {
                match OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339) {
                    Ok(odt) => odt,
                    Err(e) => write_error(&format!("Invalid Rfc3339 time format: {e}")),
                }
            } else {
                OffsetDateTime::now_utc()
            };
            let pending_confirmation = if let Some(ref pending) = req.pending_confirmation {
                let applied_at = match OffsetDateTime::parse(
                    &pending.applied_at,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    Ok(odt) => odt,
                    Err(e) => write_error(&format!(
                        "Invalid pending confirmation applied_at Rfc3339 time format: {e}"
                    )),
                };
                Some(PendingConfirmationState {
                    version: ConfigVersion::new(pending.version),
                    previous_confirmed_version: ConfigVersion::new(
                        pending.previous_confirmed_version,
                    ),
                    applied_at,
                    timeout_secs: pending.timeout_secs,
                })
            } else {
                None
            };

            let active_alarms: Vec<opc_alarm::Alarm> = req
                .active_alarms
                .iter()
                .map(|a| opc_alarm::Alarm {
                    alarm_id: opc_alarm::AlarmId::new(&a.alarm_id),
                    alarm_type: opc_alarm::AlarmType::new(&a.alarm_type),
                    severity: match a.severity.as_str() {
                        "critical" => opc_alarm::Severity::Critical,
                        "major" => opc_alarm::Severity::Major,
                        "minor" => opc_alarm::Severity::Minor,
                        "warning" => opc_alarm::Severity::Warning,
                        _ => opc_alarm::Severity::Cleared,
                    },
                    probable_cause: opc_alarm::ProbableCause::BackendTimeout,
                    affected_object: opc_alarm::AffectedObject::NfInstance {
                        kind: "upf".to_string(),
                        instance: "upf-1".to_string(),
                    },
                    tenant: None,
                    slice: None,
                    region: None,
                    text: opc_alarm::RedactedText::new(&a.text),
                    details: opc_alarm::AlarmDetails::empty(),
                    state: match a.state.as_str() {
                        "raised" => opc_alarm::AlarmState::Raised,
                        "cleared" => opc_alarm::AlarmState::Cleared,
                        _ => opc_alarm::AlarmState::Raised,
                    },
                    raised_at: time::OffsetDateTime::now_utc(),
                    updated_at: time::OffsetDateTime::now_utc(),
                    cleared_at: None,
                    correlation_id: None,
                })
                .collect();

            let resp = evaluate_config_apply(
                req.desired_generation,
                req.current_observed_generation,
                ConfigVersion::new(req.current_version),
                current_digest,
                req.candidate.as_ref(),
                &req.lifecycle_status,
                &active_alarms,
                pending_confirmation.as_ref(),
                req.preflight_report.as_ref(),
                current_time,
            );
            write_success(&resp);
        }
        "preflight" => {
            let req: PreflightRequest = parse_request(&buffer, "PreflightRequest");
            match evaluate_preflight(&req) {
                Ok(report) => write_success(&report),
                Err(e) => write_error(&e),
            }
        }
        other => {
            write_error(&format!("Unknown command: {other}"));
        }
    }
}
