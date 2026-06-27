//! # `opc-node-resources`
//!
//! Validates that a [`ResourceProfile`] (desired CNF data-plane configuration)
//! is compatible with the observed [`NodeCapabilityReport`] (node capabilities
//! as reported by the agent runtime).  This crate is a **pure model** — it
//! contains no syscalls and does not directly inspect the host.
//!
//! ## Core invariants
//!
//! - **CAP_SYS_ADMIN is never allowed in production** AF_XDP profiles.  Only
//!   `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_NET_RAW` are permitted in production.
//! - **NUMA locality** is enforced according to the configured [`NumaPolicy`]:
//!   `Require` → error, `Warn` → warning, `Ignore` → silent.
//! - **Lab fallback is always visible** — when a fast-path prerequisite is
//!   unavailable and `allow_software_packet_path` (or other lab fallbacks) is
//!   enabled, the [`FallbackStatus`] in the report is set to `active = true` so
//!   that the operator can observe the degraded mode rather than having it occur
//!   silently.
//!
//! ## Example
//!
//! ```ignore
//! let report = validate_resource_profile(&profile, &context);
//! assert!(report.is_eligible(), "{report:#?}");
//! ```

pub mod bpf;
pub mod cpu;
pub mod hugepages;
pub mod network;
pub mod numa;
pub mod pod_security;
pub mod types;
pub mod validation;

// Public re-exports
pub use types::{
    AfXdpProfile, BpfArtifact, BpfCapabilities, CpuId, CpuLayout, CpuManagerPolicy, CpuPolicy,
    DataPlanePreflightReport, DataPlaneProfile, Environment, FallbackMode, FallbackStatus,
    HostPathMount, HugepagePool, IpamMode, IpsecCapabilities, IpsecGatewayProfile,
    IpsecNetworkAttachment, KernelVersion, LabFallbackPolicy, LinkStatePolicy, LinuxCapability,
    NetworkFunctionKind, NicCapability, NodeCapabilityReport, NodeCpuCapabilities,
    NodeMemoryCapabilities, NumaComponent, NumaNodeId, NumaPolicy, PodSecurityExceptionModel,
    PreflightCheckResult, ResourceProfile, SeccompProfile, SriovAllowlistPolicy, SriovProfile,
    TopologyManagerPolicy, ValidationContext, ValidationError, ValidationReport, ValidationWarning,
    XdpMode,
};

pub use validation::{run_data_plane_preflight, validate_resource_profile};

#[cfg(test)]
mod tests;
