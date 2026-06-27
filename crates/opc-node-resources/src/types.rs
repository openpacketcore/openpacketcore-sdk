use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Logical CPU identifier used in core-pinning layouts.
pub type CpuId = u16;

/// NUMA node identifier.  Must be less than `node.cpu.numa_nodes`.
pub type NumaNodeId = u16;

/// Kernel version triple.  Used to gate AF_XDP minimum-kernel requirements.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct KernelVersion {
    /// Major version number.
    pub major: u16,
    /// Minor version number.
    pub minor: u16,
    /// Patch version number.
    pub patch: u16,
}

impl KernelVersion {
    /// Construct a [`KernelVersion`] from its three components.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Selects the data-plane fast-path technology for this CNF.
///
/// Variants are ordered from most-performant / most-restrictive to
/// least-performant / most-permissive.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DataPlaneProfile {
    /// No accelerated data plane; all packets traverse the kernel control plane.
    ControlPlaneOnly,
    /// Signalling-heavy workload (e.g. SMF) that benefits from CPU isolation
    /// but does not use a kernel-bypass fast path.
    SignalingHeavy,
    /// Kernel networking stack (standard socket / `AF_PACKET` path).
    KernelNetworking,
    /// AF_XDP fast-path resource profile for future UPF/data-plane workloads.
    ///
    /// This selects resource/admission checks only; it does not imply AF_XDP
    /// socket, UMEM, ring, or packet I/O implementation in this crate.
    AfXdpFastPath,
    /// SR-IOV direct assignment of a virtual function to the CNF pod.
    SriovFastPath,
    /// IPsec gateway resource profile for future ePDG/N3IWF workloads.
    ///
    /// This selects resource/admission checks only; it does not imply IKEv2,
    /// ESP, or xfrm protocol implementation in this crate.
    IpsecGateway,
}

/// Marks the deployment environment, which determines which security and
/// fallback rules apply.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Environment {
    /// Production environment — strict security policy enforced.
    Production,
    /// Lab / development environment — relaxed constraints with visible fallbacks.
    Lab,
}

/// 3GPP network-function category used for resource-policy decisions.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum NetworkFunctionKind {
    /// User Plane Function.
    Upf,
    /// Session Management Function.
    Smf,
    /// Access and Mobility Management Function.
    Amf,
    /// Network Repository Function.
    Nrf,
    /// Operator-defined network-function kind outside the built-in set.
    Custom(String),
}

/// Controls how Linux CPU management (e.g. `cpusets`) is configured for the CNF.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum CpuManagerPolicy {
    None,
    Static,
}

/// Topology Manager policy configured on the node.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum TopologyManagerPolicy {
    None,
    BestEffort,
    Restricted,
    SingleNumaNode,
}

/// NUMA locality enforcement policy used in CPU-layout validation.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum NumaPolicy {
    /// Ignore NUMA mismatches entirely; no error or warning.
    Ignore,
    /// Record a [`ValidationWarning::NumaMismatchWarning`] but do not fail.
    Warn,
    /// Emit a [`ValidationError::NumaMismatchError`] if any NUMA mismatch is detected.
    Require,
}

/// XDP attach mode.  `Native` is the high-performance option; `Generic` is
/// used for development / fallback.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum XdpMode {
    Native,
    Skb,
    Generic,
}

/// Linux capability that may be granted to a CNF pod.
///
/// In production AF_XDP deployments, only `CAP_BPF`, `CAP_NET_ADMIN`, and
/// `CAP_NET_RAW` are permitted.  `CAP_SYS_ADMIN` is **never** allowed in
/// production (it bypasses the BPF verifier sandbox).
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum LinuxCapability {
    CapBpf,
    CapNetAdmin,
    CapNetRaw,
    CapSysAdmin,
    Other(String),
}

/// Seccomp profile applied to the CNF pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SeccompProfile {
    /// Use the container runtime's default seccomp filter.
    RuntimeDefault,
    /// Disable seccomp filtering. This is forbidden by the secure default.
    Unconfined,
}

/// Administrative policy for the VF link state exposed to the pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LinkStatePolicy {
    /// Leave link-state handling to the platform default.
    Auto,
    /// Force the VF link state to `enable`.
    Enable,
    /// Force the VF link state to `disable`.
    Disable,
}

/// IP address management mode for SR-IOV virtual functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IpamMode {
    /// The VF receives an operator-managed static address configuration.
    Static,
    /// The VF receives address configuration dynamically (for example via DHCP).
    Dynamic,
}

/// Fallback modes that may be activated when a fast-path prerequisite is
/// unavailable in lab mode.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum FallbackMode {
    /// Replace native/SKB XDP with generic XDP in lab mode.
    GenericXdp,
    /// Bypass AF_XDP and use the software packet path in lab mode.
    SoftwarePacketPath,
    /// Replace direct device attachment with a `veth` pair in lab mode.
    Veth,
    /// Allow non-exclusive / non-isolated data-plane CPU placement in lab mode.
    RelaxedCpuPinning,
    /// Use a userspace ESP implementation when kernel ESP offload is unavailable
    /// in lab mode.
    UserspaceEsp,
    /// Run without the requested huge-page reservation in lab mode.
    ///
    /// **Reserved for future use.**  This variant is defined but no validator
    /// currently activates it.  `LabFallbackPolicy::allow_no_hugepages` and
    /// `NodeMemoryCapabilities::{hugepages_2mi,hugepages_1gi}` are similarly
    /// unused — huge-page availability is not yet enforced during validation.
    NoHugepages,
}

/// The NUMA-incoherent component that triggered a mismatch warning or error.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NumaComponent {
    /// A network interface whose NUMA affinity does not match the CPU layout.
    Interface(String),
    /// The huge-page memory region whose NUMA affinity does not match the CPU layout.
    Hugepages,
}

/// CPU allocation and isolation policy for a CNF pod.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CpuPolicy {
    /// When `true`, all data-plane cores must belong to the Linux `isolcpus`
    /// set (or equivalent) so that the scheduler never places non-data-plane
    /// threads on them.
    pub require_exclusive_data_plane_cores: bool,
    /// Policy for NUMA locality between CPUs and NIC / huge pages.
    pub numa_locality: NumaPolicy,
}

impl Default for CpuPolicy {
    fn default() -> Self {
        Self {
            require_exclusive_data_plane_cores: true,
            numa_locality: NumaPolicy::Require,
        }
    }
}

/// Pod Security Exception Model.
///
/// This struct encodes the *exception* granted to a CNF pod beyond the base
/// Kubernetes "restricted" Pod Security Standard.  The fields here mirror the
/// Kubernetes security context.
///
/// ### Relationship to K8s Pod Security Standards
///
/// The default values (`secure_default()`) match **Kubernetes "restricted" PSS**
/// semantics — the most restrictive tier — not the "baseline" tier (which
/// permits several dangerous capabilities).  Operators familiar with K8s PSS
/// should note that `secure_default()` is deliberately named to avoid ambiguity
/// with the far more permissive K8s baseline tier.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostPathMount {
    pub host_path: String,
    pub mount_path: String,
    pub read_only: bool,
}

/// ### Relationship to K8s Pod Security Standards
///
/// The default values (`secure_default()`) match **Kubernetes "restricted" PSS**
/// semantics — the most restrictive tier — not the "baseline" tier (which
/// permits several dangerous capabilities).  Operators familiar with K8s PSS
/// should note that `secure_default()` is deliberately named to avoid ambiguity
/// with the far more permissive K8s baseline tier.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PodSecurityExceptionModel {
    /// Containers must run as a non-root user.
    pub run_as_non_root: bool,
    /// The root filesystem must be read-only.
    pub read_only_root_filesystem: bool,
    /// Privilege escalation from the container's initial UID is forbidden.
    pub allow_privilege_escalation: bool,
    /// All Linux capabilities are dropped; only the container-default set
    /// (which omits `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, etc.) is retained.
    pub drop_all_capabilities: bool,
    /// Seccomp profile applied to all container processes.
    pub seccomp_profile: SeccompProfile,
    /// AppArmor profile (parsed from the `AppArmorProfile` annotation).
    pub apparmor_profile: Option<String>,
    /// SELinux security label (`ProcessLabel`).
    pub selinux_profile: Option<String>,
    /// Extra capabilities beyond the container-default set.  In production
    /// AF_XDP deployments, only `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW` are
    /// permitted; `CAP_SYS_ADMIN` is **always** forbidden in production.
    pub added_capabilities: BTreeSet<LinuxCapability>,
    /// Whether the pod runs in privileged mode.
    pub privileged: bool,
    /// Whether the pod has host network enabled.
    pub host_network: bool,
    /// Approved hostPath mounts.
    pub host_path_mounts: Vec<HostPathMount>,
    /// Evidence ID backing these security exceptions.
    pub security_evidence_id: Option<String>,
}

impl PodSecurityExceptionModel {
    /// Returns the **secure default** model, which enforces the same
    /// restrictions as the Kubernetes "restricted" Pod Security Standard:
    /// non-root, read-only root filesystem, no privilege escalation, all
    /// capabilities dropped, and runtime-default seccomp.
    ///
    /// Use this as the baseline for production CNF pods.  In production AF_XDP
    /// deployments you may **add** `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_NET_RAW`
    /// via [`added_capabilities`], but never `CAP_SYS_ADMIN`.
    ///
    /// [`added_capabilities`]: PodSecurityExceptionModel::added_capabilities
    pub fn secure_default() -> Self {
        Self {
            run_as_non_root: true,
            read_only_root_filesystem: true,
            allow_privilege_escalation: false,
            drop_all_capabilities: true,
            seccomp_profile: SeccompProfile::RuntimeDefault,
            apparmor_profile: None,
            selinux_profile: None,
            added_capabilities: BTreeSet::new(),
            privileged: false,
            host_network: false,
            host_path_mounts: Vec::new(),
            security_evidence_id: None,
        }
    }

    /// Generate minimal required pod security exceptions for a given data-plane profile.
    pub fn minimal_required(profile: DataPlaneProfile, evidence_id: Option<String>) -> Self {
        let mut model = Self::secure_default();
        model.security_evidence_id = evidence_id;

        match profile {
            DataPlaneProfile::AfXdpFastPath => {
                model.added_capabilities = BTreeSet::from([
                    LinuxCapability::CapBpf,
                    LinuxCapability::CapNetAdmin,
                    LinuxCapability::CapNetRaw,
                ]);
                model.host_path_mounts = vec![HostPathMount {
                    host_path: "/sys/fs/bpf".to_string(),
                    mount_path: "/sys/fs/bpf".to_string(),
                    read_only: false,
                }];
            }
            DataPlaneProfile::SriovFastPath => {
                model.added_capabilities =
                    BTreeSet::from([LinuxCapability::CapNetAdmin, LinuxCapability::CapNetRaw]);
                model.host_path_mounts = vec![HostPathMount {
                    host_path: "/dev/vfio".to_string(),
                    mount_path: "/dev/vfio".to_string(),
                    read_only: false,
                }];
            }
            DataPlaneProfile::IpsecGateway => {
                model.added_capabilities =
                    BTreeSet::from([LinuxCapability::CapNetAdmin, LinuxCapability::CapNetRaw]);
            }
            _ => {}
        }
        model
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BpfArtifact {
    pub name: String,
    pub digest: String,
    pub signature_ref: String,
    pub signer_identity: String,
    pub program_type: String,
    pub expected_attach_point: String,
    pub allowed_capabilities: BTreeSet<LinuxCapability>,
    pub evidence_id: Option<String>,
}

/// AF_XDP-specific fast-path profile.
///
/// Describes the kernel-version, BTF, XDP-mode, and capability requirements
/// that a node must satisfy for the AF_XDP fast path to be used.
///
/// This crate is a pure model: it performs only structural validation of BPF
/// map metadata (non-empty map identifiers and controlled bpffs pin paths) and
/// never inspects the host filesystem or kernel state directly.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AfXdpProfile {
    /// Minimum kernel version required for AF_XDP support.
    pub minimum_kernel: KernelVersion,
    /// Whether BPF Type Format (BTF) information is required.
    pub required_btf: bool,
    /// The XDP mode that must be available on all data-plane interfaces.
    pub required_xdp_mode: XdpMode,
    /// Exact set of Linux capabilities that the CNF pod must hold.
    pub required_capabilities: BTreeSet<LinuxCapability>,
    /// Names or identifiers of BPF maps that must be pre-created and pinned.
    pub required_maps: Vec<String>,
    /// bpffs paths that must already be pinned under a controlled `/sys/fs/bpf`
    /// prefix.
    pub required_pin_paths: Vec<String>,
    /// Whether `XdpMode::Generic` may be used as a lab fallback when the
    /// required mode is unavailable.
    pub generic_xdp_fallback_allowed: bool,
    /// BPF Artifacts governed by signed/digest-pinned policies.
    pub bpf_artifacts: Vec<BpfArtifact>,
}

/// SR-IOV direct-assignment fast-path profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SriovProfile {
    /// The resource name in the `DevicePlugin` API (e.g. `intel.com/ice_sriov`).
    pub resource_name: String,
    /// Whether the VF trust bit must be set.
    pub vf_trust: bool,
    /// Whether spoof-check must be enabled on the VF.
    pub spoof_check: bool,
    /// VLAN tagging policy.
    pub vlan_policy: Option<String>,
    /// Policy for the VF link state.
    pub link_state_policy: LinkStatePolicy,
    /// Set of allowed network device drivers (e.g. `ice`, `mlx5_core`).
    /// An empty set means any driver is accepted.
    pub allowed_device_drivers: BTreeSet<String>,
    /// IP address allocation mode for VFs.
    pub ipam_mode: IpamMode,
}

/// Constrained/custom CNI type for an IPsec gateway network attachment.
///
/// Matches the design §13.2 set: `{macvlan, ipvlan, sriov, host-network, custom}`.
/// Multus is attachment plumbing and is modeled separately (e.g. as an
/// annotation or network-selection policy), not as a CNI type here.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CniType {
    /// SR-IOV direct-assignment CNI.
    #[serde(rename = "sriov")]
    Sriov,
    /// MACVLAN CNI.
    #[serde(rename = "macvlan")]
    Macvlan,
    /// IPVLAN CNI.
    #[serde(rename = "ipvlan")]
    Ipvlan,
    /// Host-network attachment.
    #[serde(rename = "host-network")]
    HostNetwork,
    /// Operator-defined CNI type outside the built-in set.
    #[serde(rename = "custom")]
    Custom(String),
}

/// Kernel module identifier, normalized to lowercase for equality and ordering.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub struct KernelModuleId(String);

impl KernelModuleId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_lowercase())
    }

    /// Construct a [`KernelModuleId`] only if the supplied identifier is
    /// non-empty and not whitespace-only.
    pub fn try_new(name: impl AsRef<str>) -> Option<Self> {
        let name = name.as_ref();
        if name.trim().is_empty() {
            None
        } else {
            Some(Self::new(name))
        }
    }

    /// Returns `true` if the identifier is non-empty and not whitespace-only.
    pub fn is_valid(&self) -> bool {
        !self.0.trim().is_empty()
    }
}

impl<'de> serde::Deserialize<'de> for KernelModuleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(KernelModuleId::new)
    }
}

impl PartialEq for KernelModuleId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for KernelModuleId {}

impl Hash for KernelModuleId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialOrd for KernelModuleId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KernelModuleId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl From<String> for KernelModuleId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for KernelModuleId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for KernelModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ESP algorithm identifier, normalized to lowercase for equality and ordering.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub struct EspAlgorithmId(String);

impl EspAlgorithmId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_lowercase())
    }

    /// Construct an [`EspAlgorithmId`] only if the supplied identifier is
    /// non-empty and not whitespace-only.
    pub fn try_new(name: impl AsRef<str>) -> Option<Self> {
        let name = name.as_ref();
        if name.trim().is_empty() {
            None
        } else {
            Some(Self::new(name))
        }
    }

    /// Returns `true` if the identifier is non-empty and not whitespace-only.
    pub fn is_valid(&self) -> bool {
        !self.0.trim().is_empty()
    }
}

impl<'de> serde::Deserialize<'de> for EspAlgorithmId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(EspAlgorithmId::new)
    }
}

impl PartialEq for EspAlgorithmId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for EspAlgorithmId {}

impl Hash for EspAlgorithmId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialOrd for EspAlgorithmId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EspAlgorithmId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl From<String> for EspAlgorithmId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for EspAlgorithmId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for EspAlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// IPsec gateway network attachment requirement.
///
/// Declares the requested attachment prerequisites for an IPsec gateway
/// workload, such as the data-plane interface name, functional plane,
/// CNI type, and optional L2/L3 constraints.  This is a pure model: it does
/// not inspect the host network namespace or Multus state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpsecNetworkAttachment {
    /// Logical data-plane interface name (must match a declared data-plane
    /// interface in the validation context).
    pub interface_name: String,
    /// Functional plane of the attachment (e.g. `n3`, `n6`, `nwu`).
    pub plane: String,
    /// CNI type requested for this attachment.
    pub cni_type: CniType,
    /// Whether a static IP is required for this attachment.
    pub static_ip_required: bool,
    /// Optional statically requested IP address.  Required when
    /// `static_ip_required` is `true` and must be a valid IPv4 or IPv6
    /// address when present.
    pub static_ip: Option<String>,
    /// Optional minimum required MTU.  When present the attachment's `mtu`
    /// must be at least this value.
    pub minimum_mtu: Option<u16>,
    /// Optional requested MTU.  When present it must be at least
    /// `IPSEC_MINIMUM_MTU` and meet `minimum_mtu`.
    pub mtu: Option<u16>,
    /// Whether source routing is required for this attachment.
    pub source_route_required: bool,
    /// Optional source route configuration.  Required when
    /// `source_route_required` is `true`.
    pub source_route: Option<String>,
    /// Optional VLAN identifier.  When present it must be in the valid
    /// 802.1Q range.
    pub vlan_id: Option<u16>,
}

/// IPsec gateway resource profile.
///
/// Describes the kernel, XFRM, UDP encapsulation, SCTP, capability,
/// network-attachment, and ESP-fallback requirements that a node must satisfy
/// for an IPsec gateway workload (e.g. future ePDG/N3IWF untrusted-access
/// functions).
///
/// This crate is a pure model: it performs only structural validation of the
/// declared requirements against the observed [`NodeCapabilityReport`] and never
/// inspects the host filesystem or kernel state directly.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpsecGatewayProfile {
    /// Minimum kernel version required for the IPsec gateway profile.
    pub minimum_kernel: KernelVersion,
    /// Exact set of Linux capabilities that the CNF pod must hold.
    pub required_capabilities: BTreeSet<LinuxCapability>,
    /// Whether the node must report XFRM support.
    pub require_xfrm: bool,
    /// Whether the node must allow binding UDP port 500 (IKE).
    pub require_udp_500: bool,
    /// Whether the node must allow binding UDP port 4500 (NAT-T).
    pub require_udp_4500: bool,
    /// Whether the node must report SCTP support.
    pub require_sctp: bool,
    /// Kernel modules that must be available on the node (e.g. `xfrm_user`).
    pub required_kernel_modules: BTreeSet<KernelModuleId>,
    /// ESP algorithms that must be supported by the node (e.g. `aes-cbc`).
    pub required_esp_algorithms: BTreeSet<EspAlgorithmId>,
    /// Required network attachments for the IPsec gateway workload.
    pub network_attachments: Vec<IpsecNetworkAttachment>,
    /// Whether lab mode may fall back to userspace ESP when kernel ESP is
    /// unavailable.
    pub allow_userspace_esp_fallback: bool,
}

/// IPsec-related capabilities reported by the node agent.
///
/// This is a pure model owned by `opc-node-resources`.  It deliberately does
/// not depend on `opc-ipsec-xfrm`; products (or a dedicated adapter crate)
/// should translate any `opc-ipsec-xfrm::XfrmCapabilityReport` into this
/// structure at the integration boundary rather than pulling XFRM internals
/// into the resource-validation layer.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct IpsecCapabilities {
    /// Whether the kernel XFRM netlink interface is available.
    pub xfrm_netlink_available: bool,
    /// Whether the kernel XFRM user policy interface is available.
    pub xfrm_user_policy_available: bool,
    /// Whether the kernel supports ESP offload/processing.
    pub esp_supported: bool,
    /// Whether the node allows binding UDP port 500 (IKE).
    pub udp_500_bind_allowed: bool,
    /// Whether the node allows binding UDP port 4500 (NAT-T).
    pub udp_4500_bind_allowed: bool,
    /// Whether the node reports SCTP support.
    pub sctp_supported: bool,
    /// Kernel modules that are available on the node (e.g. `xfrm_user`).
    pub available_kernel_modules: BTreeSet<KernelModuleId>,
    /// ESP algorithms supported by the node.
    pub supported_esp_algorithms: BTreeSet<EspAlgorithmId>,
}

/// Lab-only fallback policy.  Each flag enables a degraded-mode escape hatch
/// that is **never** used in production.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LabFallbackPolicy {
    /// Allow `veth` pair networking (no SR-IOV / VF assignment).
    pub allow_veth: bool,
    /// Allow `XdpMode::Generic` when the required `Native` or `SKB` mode is
    /// unavailable.
    pub allow_generic_xdp: bool,
    /// Allow a pure software packet-processing path when all AF_XDP fast-path
    /// prerequisites are unavailable.
    pub allow_software_packet_path: bool,
    /// Allow data-plane cores that are not isolated via `isolcpus`.
    pub allow_relaxed_cpu_pinning: bool,
    /// Allow running without pre-allocated huge pages.
    ///
    /// **Reserved for future use.**  No validator currently reads this field or
    /// activates [`FallbackMode::NoHugepages`].  Huge-page availability is not
    /// yet enforced during profile validation.
    pub allow_no_hugepages: bool,
}

/// A complete description of the desired CNF data-plane configuration.
///
/// Combine this with a [`ValidationContext`] (observed node capabilities) and
/// pass both to `validate_resource_profile` to obtain a [`ValidationReport`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceProfile {
    /// The kind of network function (UPF, SMF, AMF, …).
    pub nf_kind: NetworkFunctionKind,
    /// Selected data-plane profile.
    pub data_plane_profile: DataPlaneProfile,
    /// Deployment environment — determines which security and fallback rules apply.
    pub environment: Environment,
    /// CPU allocation and isolation policy.
    pub cpu_policy: CpuPolicy,
    /// Pod security exception model.
    pub pod_security: PodSecurityExceptionModel,
    /// AF_XDP fast-path parameters.  Required when `data_plane_profile` is
    /// [`DataPlaneProfile::AfXdpFastPath`].
    pub af_xdp: Option<AfXdpProfile>,
    /// SR-IOV parameters.  Required when `data_plane_profile` is
    /// [`DataPlaneProfile::SriovFastPath`].
    pub sriov: Option<SriovProfile>,
    /// IPsec gateway parameters.  Required when `data_plane_profile` is
    /// [`DataPlaneProfile::IpsecGateway`].
    pub ipsec: Option<IpsecGatewayProfile>,
    /// Lab-only fallback policy.
    pub lab_fallback: LabFallbackPolicy,
}

impl ResourceProfile {
    /// Construct a new profile with the given NF kind, data-plane profile, and
    /// environment.  All policy fields are set to their defaults:
    /// - [`CpuPolicy::default()`] (exclusive data-plane cores, NUMA locality required)
    /// - [`PodSecurityExceptionModel::secure_default()`] (K8s "restricted" PSS)
    /// - No AF_XDP, SR-IOV, or IPsec gateway configuration (`None`)
    /// - All lab fallbacks disabled by default (opt-in)
    pub fn new(
        nf_kind: NetworkFunctionKind,
        data_plane_profile: DataPlaneProfile,
        environment: Environment,
    ) -> Self {
        let require_exclusive = match data_plane_profile {
            DataPlaneProfile::ControlPlaneOnly
            | DataPlaneProfile::SignalingHeavy
            | DataPlaneProfile::KernelNetworking => false,
            DataPlaneProfile::AfXdpFastPath
            | DataPlaneProfile::SriovFastPath
            | DataPlaneProfile::IpsecGateway => true,
        };
        let cpu_policy = CpuPolicy {
            require_exclusive_data_plane_cores: require_exclusive,
            ..Default::default()
        };

        Self {
            nf_kind,
            data_plane_profile,
            environment,
            cpu_policy,
            pod_security: PodSecurityExceptionModel::secure_default(),
            af_xdp: None,
            sriov: None,
            ipsec: None,
            lab_fallback: LabFallbackPolicy::default(),
        }
    }
}

/// BPF subsystem capabilities reported by the node agent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BpfCapabilities {
    /// Whether `CAP_BPF` is available (kernel 5.8+).
    pub cap_bpf: bool,
    /// Whether the kernel XDP hooks are functional.
    pub xdp_supported: bool,
    /// Whether BTF information is available (`CONFIG_DEBUG_INFO_BTF=y`).
    pub btf_available: bool,
    /// Whether this node requires `CAP_SYS_ADMIN` for AF_XDP.  On kernels
    /// ≥ 5.8 with `CAP_BPF`, AF_XDP does **not** need `CAP_SYS_ADMIN`.
    pub cap_sys_admin_required: bool,
    /// XDP attach modes supported by the kernel on at least one data-plane NIC.
    pub available_xdp_modes: BTreeSet<XdpMode>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HugepagePool {
    pub numa_node: NumaNodeId,
    pub size: String,
    pub total: u64,
    pub free: u64,
}

/// CPU capabilities reported by the node agent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeCpuCapabilities {
    /// Linux CPU management policy in use on this node.
    pub manager_policy: CpuManagerPolicy,
    /// Set of CPU IDs that are isolated from the scheduler via `isolcpus`.
    pub isolated_cores: BTreeSet<CpuId>,
    /// Total number of NUMA nodes on this machine.
    pub numa_nodes: NumaNodeId,
    /// Total set of CPU IDs available on the node.
    pub cpu_ids: BTreeSet<CpuId>,
    /// Set of CPU IDs reserved for system/host overhead.
    pub reserved_cores: BTreeSet<CpuId>,
    /// Topology Manager policy configured on the node.
    pub topology_manager_policy: TopologyManagerPolicy,
    /// Map from CPU ID to NUMA node affinity.
    pub cpu_numa_map: BTreeMap<CpuId, NumaNodeId>,
}

/// Memory capabilities reported by the node agent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeMemoryCapabilities {
    /// Number of 2 MiB huge pages available.
    pub hugepages_2mi: u64,
    /// Number of 1 GiB huge pages available.
    pub hugepages_1gi: u64,
    /// Hugepage pools by size and NUMA node.
    pub hugepage_pools: Vec<HugepagePool>,
}

/// Capabilities of a single network interface on the node.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NicCapability {
    /// Operating-system interface name (e.g. `ens5f0`).
    pub name: String,
    /// Kernel netdev driver name (e.g. `ice`, `mlx5_core`).
    pub driver: String,
    /// Maximum number of VFs that can be created via SR-IOV.
    pub sriov_vfs: u16,
    /// XDP attach modes supported by this NIC.
    pub xdp_modes: BTreeSet<XdpMode>,
    /// Number of TX/RX queues configured.
    pub queues: u16,
    /// NUMA node to which this NIC is locally attached.  `None` if unknown.
    pub numa_node: Option<NumaNodeId>,
}

/// Complete capability report for a node, as collected by the node agent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeCapabilityReport {
    /// Running kernel version.
    pub kernel: KernelVersion,
    /// BPF subsystem capabilities.
    pub bpf: BpfCapabilities,
    /// CPU capabilities.
    pub cpu: NodeCpuCapabilities,
    /// Memory capabilities.
    pub memory: NodeMemoryCapabilities,
    /// Capabilities of all observed network interfaces.
    pub nics: Vec<NicCapability>,
    /// IPsec-related capabilities.
    #[serde(default)]
    pub ipsec: IpsecCapabilities,
}

impl NodeCapabilityReport {
    /// Look up a NIC by name.
    pub fn nic(&self, name: &str) -> Option<&NicCapability> {
        self.nics.iter().find(|nic| nic.name == name)
    }
}

/// Physical CPU layout requested for a CNF pod.
///
/// All three core lists are validated for mutual overlaps. Data-plane cores are
/// additionally validated against the node's `isolated_cores` set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuLayout {
    /// CPU IDs allocated to the data-plane fast-path threads.
    pub data_plane_cores: Vec<CpuId>,
    /// CPU IDs allocated to control-plane threads (e.g. PFCP session management).
    pub control_plane_cores: Vec<CpuId>,
    /// CPU IDs allocated to management-plane threads (e.g. S-plane, metrics).
    pub management_cores: Vec<CpuId>,
    /// NUMA node on which the data-plane cores run.  Used for NUMA affinity
    /// checks against NICs and huge pages.
    pub numa_node: Option<NumaNodeId>,
}

/// SR-IOV resource allowlist policy.
///
/// Operator-defined policy that restricts which SR-IOV resource names may be
/// used by each NF kind.  A resource that is not explicitly allowlisted for a
/// given NF kind is rejected at validation time.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SriovAllowlistPolicy {
    /// Map from NF kind → set of allowlisted resource names.
    /// An NF kind with no entry (or an empty set) means **no** resource is
    /// allowlisted for that NF kind.
    pub allowed_resources: BTreeMap<NetworkFunctionKind, BTreeSet<String>>,
}

impl SriovAllowlistPolicy {
    /// Returns `true` iff `resource_name` is explicitly allowlisted for `nf_kind`.
    pub fn is_allowed(&self, nf_kind: &NetworkFunctionKind, resource_name: &str) -> bool {
        self.allowed_resources
            .get(nf_kind)
            .map(|resources| resources.contains(resource_name))
            .unwrap_or(false)
    }
}

/// Validation context: the observed node capabilities and layout against which
/// a [`ResourceProfile`] is being validated.
pub struct ValidationContext<'a> {
    /// Observed node capabilities.
    pub node: &'a NodeCapabilityReport,
    /// Requested CPU layout for the CNF pod.
    pub cpu_layout: &'a CpuLayout,
    /// Names of the data-plane network interfaces.
    pub data_plane_interfaces: &'a [String],
    /// NUMA node on which huge pages are allocated for this pod.
    pub hugepage_numa_node: Option<NumaNodeId>,
    /// SR-IOV resource allowlist policy.
    pub sriov_allowlist: &'a SriovAllowlistPolicy,
}

/// Describes which lab fallbacks are active and why.
///
/// When `active == false` the CNF is running with the full fast-path
/// configuration.  When `active == true` the operator can inspect `modes` and
/// `reasons` to understand which fast-path prerequisites were unavailable.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct FallbackStatus {
    /// `true` if at least one lab fallback has been activated.
    pub active: bool,
    /// Set of active fallback modes.
    pub modes: BTreeSet<FallbackMode>,
    /// Human-readable reasons for each activated fallback, in activation order.
    pub reasons: Vec<String>,
}

/// Non-fatal issues detected during validation.
///
/// Warnings are never fatal — a [`ValidationReport`] with warnings but no
/// errors is still eligible for scheduling.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidationWarning {
    /// A lab fallback has been activated because a fast-path prerequisite was
    /// unavailable.
    LabFallbackActivated {
        /// The fallback mode that was activated.
        mode: FallbackMode,
        /// Why the fallback was necessary.
        reason: String,
    },
    /// The NUMA affinity of a component does not match the CPU layout's NUMA
    /// node, and the policy is [`NumaPolicy::Warn`].
    NumaMismatchWarning {
        /// Component with mismatched NUMA affinity.
        component: NumaComponent,
        /// NUMA node the CPU layout expects.
        expected: NumaNodeId,
        /// NUMA node actually observed for this component.
        observed: NumaNodeId,
    },
    /// The huge-page NUMA node is missing on a multi-NUMA fast-path profile and the policy is `Warn` or `Ignore`.
    MissingHugepageNumaNode,
}

/// Fatal validation errors.
///
/// When any of these are present in a [`ValidationReport`] the CNF is **not**
/// eligible for scheduling on the target node until the error is resolved.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValidationError {
    /// A pod-security field violates the baseline model.
    BaselinePodSecurityViolated { field: String },
    /// [`DataPlaneProfile::AfXdpFastPath`] is selected but no `af_xdp` profile
    /// is configured.
    AfXdpProfileMissing,
    /// [`DataPlaneProfile::AfXdpFastPath`] is selected but no data-plane
    /// interfaces are specified (RFC 011 §9.1 requires named attachments).
    AfXdpNoDataPlaneInterfaces,
    /// [`DataPlaneProfile::SriovFastPath`] is selected but no `sriov` profile
    /// is configured.
    SriovProfileMissing,
    /// [`DataPlaneProfile::SriovFastPath`] is selected but no data-plane
    /// interfaces are specified (RFC 011 §9.1 requires named attachments).
    SriovNoDataPlaneInterfaces,
    /// [`DataPlaneProfile::IpsecGateway`] is selected but no `ipsec` profile
    /// is configured.
    IpsecProfileMissing,
    /// [`DataPlaneProfile::IpsecGateway`] is selected but no data-plane
    /// interfaces are specified (RFC 011 §9.1 requires named attachments).
    IpsecNoDataPlaneInterfaces,
    /// An IPsec gateway network attachment requirement is missing a required
    /// field or has an invalid value.
    IpsecNetworkAttachmentInvalid { detail: String },
    /// An IPsec gateway profile declares an empty or whitespace-only kernel
    /// module identifier.
    InvalidKernelModuleId { module: String },
    /// An IPsec gateway profile declares an empty or whitespace-only ESP
    /// algorithm identifier.
    InvalidEspAlgorithmId { algorithm: String },
    /// An SR-IOV data-plane interface exposes zero VFs, so no direct assignment
    /// is possible (RFC 011 §9.2).
    SriovNicZeroVfs { interface_name: String },
    /// A required capability is not present in `pod_security.added_capabilities`.
    MissingCapability { capability: LinuxCapability },
    /// A capability is present in `pod_security.added_capabilities` but is not
    /// permitted for the selected data-plane profile.
    CapabilityNotAllowed {
        capability: LinuxCapability,
        profile: DataPlaneProfile,
    },
    /// `CAP_SYS_ADMIN` appears in `added_capabilities` in a production
    /// environment, which is strictly forbidden.
    ProductionCapSysAdminForbidden,
    /// The node reports `cap_sys_admin_required == true` and no lab fallback is
    /// available to compensate.
    NodeRequiresCapSysAdmin,
    /// A required node capability (e.g. `cap_bpf`, `xdp_supported`) is absent.
    MissingNodeCapability { capability: String },
    /// The running kernel version is below the AF_XDP minimum.
    UnsupportedKernelVersion {
        found: KernelVersion,
        minimum: KernelVersion,
    },
    /// A required AF_XDP BPF map identifier is empty or whitespace-only.
    InvalidBpfMapName { map_name: String },
    /// A required AF_XDP pin path is empty or outside the controlled bpffs
    /// namespace.
    InvalidBpfPinPath { path: String },
    /// The required XDP mode is not available on any data-plane interface.
    XdpModeUnavailable {
        required: XdpMode,
        available: BTreeSet<XdpMode>,
    },
    /// Two or more CPU core lists contain the same core ID.
    CpuCoreOverlap { core: CpuId },
    /// The node's CPU Manager policy is incompatible with the profile's
    /// requirement for exclusive data-plane cores.
    CpuManagerPolicyIncompatible {
        required: CpuManagerPolicy,
        found: CpuManagerPolicy,
    },
    /// A data-plane core is not in the node's `isolated_cores` set.
    DataPlaneCoreNotIsolated { core: CpuId },
    /// A fast-path profile declares no data-plane cores, which is self-contradictory
    /// regardless of whether the node's CPU manager provides exclusive cores.
    FastPathRequiresDataPlaneCores,
    /// A requested data-plane interface is not present on the node.
    UnknownInterface { interface_name: String },
    /// The NUMA affinity of a component does not match the CPU layout's NUMA
    /// node, and the policy is [`NumaPolicy::Require`].
    NumaMismatchError {
        /// Component with mismatched NUMA affinity.
        component: NumaComponent,
        /// NUMA node the CPU layout expects.
        expected: NumaNodeId,
        /// NUMA node actually observed for this component.
        observed: NumaNodeId,
    },
    /// The requested SR-IOV resource name is not in the operator-defined allowlist
    /// for this NF kind.
    SriovResourceNotAllowlisted {
        nf_kind: NetworkFunctionKind,
        resource_name: String,
    },
    /// The NIC driver is not in the `allowed_device_drivers` set for this
    /// SR-IOV profile.
    UnsupportedSriovDriver {
        interface_name: String,
        driver: String,
    },
    /// The requested `cpu_layout.numa_node` value is greater than or equal to
    /// `node.cpu.numa_nodes`.
    NumaNodeOutOfRange {
        requested: NumaNodeId,
        available: NumaNodeId,
    },
    /// The profile requires NUMA locality on a multi-NUMA node but no `cpu_layout.numa_node` is declared.
    MissingNumaNode,
    /// The huge-page NUMA node is missing on a multi-NUMA fast-path profile and the policy is `Require`.
    MissingHugepageNumaNode,
    /// Lab fallback paths are forbidden in production mode.
    ProductionLabFallbackForbidden,
    /// Production AF_XDP requires at least one governed BPF artifact.
    BpfArtifactMissing,
    /// BPF artifact is not digest-pinned in production.
    BpfUnsignedArtifact { artifact_name: String },
    /// BPF artifact is missing a digest pin in production.
    BpfMissingDigest { artifact_name: String },
    /// BPF artifact has a mismatching attach point in production.
    BpfWrongAttachPoint {
        artifact_name: String,
        expected: String,
        found: String,
    },
    /// BPF artifact signature or evidence is missing/wrong.
    BpfWrongSigner {
        artifact_name: String,
        signer: String,
    },
    /// BPF artifact has a mismatching program type.
    BpfWrongProgramType {
        artifact_name: String,
        expected: String,
        found: String,
    },
    /// BPF artifact requests capability escalation in production.
    BpfCapabilityEscalation {
        artifact_name: String,
        capability: LinuxCapability,
    },
    /// Privileged mode requires a valid evidence ID in production.
    SecurityPrivilegedWithoutEvidence,
    /// Writable host mount requires a valid evidence ID in production.
    SecurityWritableHostMountWithoutEvidence { host_path: String },
    /// Host networking requires a valid evidence ID in production.
    SecurityHostNetworkWithoutEvidence,
    /// Host path mount is outside the approved prefixes in production.
    SecurityHostPathMountUnapproved { host_path: String },
    /// Topology Manager policy is incompatible.
    TopologyManagerPolicyIncompatible {
        required: TopologyManagerPolicy,
        found: TopologyManagerPolicy,
    },
    /// Data-plane core overlaps with reserved system cores.
    CpuCoreReservedOverlap { core: CpuId },
    /// Hugepages are missing or on the wrong NUMA node.
    HugepagesMissingOrWrongNuma { numa_node: NumaNodeId },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::BaselinePodSecurityViolated { field } => {
                write!(f, "baseline pod security model violated: {field}")
            }
            ValidationError::AfXdpProfileMissing => {
                write!(f, "AF_XDP profile selected but not configured")
            }
            ValidationError::AfXdpNoDataPlaneInterfaces => {
                write!(
                    f,
                    "AF_XDP fast path requires at least one named data-plane interface"
                )
            }
            ValidationError::SriovProfileMissing => {
                write!(f, "SR-IOV profile selected but not configured")
            }
            ValidationError::SriovNoDataPlaneInterfaces => {
                write!(
                    f,
                    "SR-IOV fast path requires at least one named data-plane interface"
                )
            }
            ValidationError::IpsecProfileMissing => {
                write!(f, "IPsec gateway profile selected but not configured")
            }
            ValidationError::IpsecNoDataPlaneInterfaces => {
                write!(
                    f,
                    "IPsec gateway requires at least one named data-plane interface"
                )
            }
            ValidationError::IpsecNetworkAttachmentInvalid { detail } => {
                write!(f, "IPsec network attachment invalid: {detail}")
            }
            ValidationError::InvalidKernelModuleId { module } => {
                write!(f, "invalid IPsec kernel module identifier: {module:?}")
            }
            ValidationError::InvalidEspAlgorithmId { algorithm } => {
                write!(f, "invalid IPsec ESP algorithm identifier: {algorithm:?}")
            }
            ValidationError::SriovNicZeroVfs { interface_name } => {
                write!(f, "SR-IOV interface {interface_name} exposes zero VFs")
            }
            ValidationError::MissingCapability { capability } => {
                write!(f, "missing required capability: {capability:?}")
            }
            ValidationError::CapabilityNotAllowed {
                capability,
                profile,
            } => {
                write!(
                    f,
                    "capability {capability:?} is not allowed for profile {profile:?}"
                )
            }
            ValidationError::ProductionCapSysAdminForbidden => {
                write!(f, "CAP_SYS_ADMIN is forbidden in production")
            }
            ValidationError::NodeRequiresCapSysAdmin => {
                write!(f, "node requires CAP_SYS_ADMIN for AF_XDP")
            }
            ValidationError::MissingNodeCapability { capability } => {
                write!(f, "node missing required capability: {capability}")
            }
            ValidationError::UnsupportedKernelVersion { found, minimum } => {
                write!(
                    f,
                    "kernel {found:?} does not meet minimum version {minimum:?}"
                )
            }
            ValidationError::InvalidBpfMapName { map_name } => {
                write!(f, "invalid AF_XDP required map identifier: {map_name:?}")
            }
            ValidationError::InvalidBpfPinPath { path } => {
                write!(f, "invalid AF_XDP bpffs pin path: {path:?}")
            }
            ValidationError::XdpModeUnavailable {
                required,
                available,
            } => {
                write!(
                    f,
                    "required XDP mode {required:?} unavailable; available: {available:?}"
                )
            }
            ValidationError::CpuCoreOverlap { core } => {
                write!(f, "CPU core {core} appears in multiple core lists")
            }
            ValidationError::CpuManagerPolicyIncompatible { required, found } => {
                write!(f, "CPU manager policy mismatch: profile requires {required:?}, node uses {found:?}")
            }
            ValidationError::DataPlaneCoreNotIsolated { core } => {
                write!(f, "data-plane core {core} is not isolated")
            }
            ValidationError::FastPathRequiresDataPlaneCores => {
                write!(f, "fast-path profile declares no data-plane cores")
            }
            ValidationError::UnknownInterface { interface_name } => {
                write!(f, "unknown data-plane interface: {interface_name}")
            }
            ValidationError::NumaMismatchError {
                component,
                expected,
                observed,
            } => {
                write!(f, "NUMA mismatch for {component:?}: expected node {expected}, observed {observed}")
            }
            ValidationError::SriovResourceNotAllowlisted {
                nf_kind,
                resource_name,
            } => {
                write!(
                    f,
                    "SR-IOV resource {resource_name:?} is not allowlisted for {nf_kind:?}"
                )
            }
            ValidationError::UnsupportedSriovDriver {
                interface_name,
                driver,
            } => {
                write!(
                    f,
                    "unsupported SR-IOV driver {driver:?} on interface {interface_name}"
                )
            }
            ValidationError::NumaNodeOutOfRange {
                requested,
                available,
            } => {
                write!(f, "requested NUMA node {requested} is out of range (node has {available} nodes, max index {max})", max = available.saturating_sub(1))
            }
            ValidationError::MissingNumaNode => {
                write!(f, "profile requires NUMA locality on a multi-NUMA node but no NUMA node is declared")
            }
            ValidationError::MissingHugepageNumaNode => {
                write!(f, "profile requires hugepages on a multi-NUMA fast-path profile but hugepage NUMA node is missing")
            }
            ValidationError::ProductionLabFallbackForbidden => {
                write!(f, "lab fallback is forbidden in production mode")
            }
            ValidationError::BpfArtifactMissing => {
                write!(
                    f,
                    "production AF_XDP requires at least one governed BPF artifact"
                )
            }
            ValidationError::BpfUnsignedArtifact { artifact_name } => {
                write!(
                    f,
                    "BPF artifact {artifact_name} must use a digest-pinned signature in production"
                )
            }
            ValidationError::BpfMissingDigest { artifact_name } => {
                write!(
                    f,
                    "BPF artifact {artifact_name} is missing a digest pin in production"
                )
            }
            ValidationError::BpfWrongAttachPoint {
                artifact_name,
                expected: _,
                found: _,
            } => {
                write!(
                    f,
                    "BPF artifact {artifact_name} has invalid attach point in production"
                )
            }
            ValidationError::BpfWrongSigner {
                artifact_name,
                signer: _,
            } => {
                write!(f, "BPF artifact {artifact_name} signature is not trusted or evidence is missing in production")
            }
            ValidationError::BpfWrongProgramType {
                artifact_name,
                expected: _,
                found: _,
            } => {
                write!(
                    f,
                    "BPF artifact {artifact_name} has wrong program type in production"
                )
            }
            ValidationError::BpfCapabilityEscalation {
                artifact_name,
                capability,
            } => {
                write!(
                    f,
                    "BPF artifact {artifact_name} requests capability escalation: {capability:?}"
                )
            }
            ValidationError::SecurityPrivilegedWithoutEvidence => {
                write!(
                    f,
                    "privileged mode requires a valid evidence ID in production"
                )
            }
            ValidationError::SecurityWritableHostMountWithoutEvidence { host_path: _ } => {
                write!(
                    f,
                    "writable host mount requires a valid evidence ID in production"
                )
            }
            ValidationError::SecurityHostNetworkWithoutEvidence => {
                write!(
                    f,
                    "host networking requires a valid evidence ID in production"
                )
            }
            ValidationError::SecurityHostPathMountUnapproved { host_path: _ } => {
                write!(
                    f,
                    "host mount path is not in the approved list for production"
                )
            }
            ValidationError::TopologyManagerPolicyIncompatible { required, found } => {
                write!(
                    f,
                    "topology manager policy mismatch: expected {required:?}, found {found:?}"
                )
            }
            ValidationError::CpuCoreReservedOverlap { core } => {
                write!(f, "data-plane core {core} overlaps with reserved cores")
            }
            ValidationError::HugepagesMissingOrWrongNuma { numa_node } => {
                write!(
                    f,
                    "hugepages are missing or not allocated on NUMA node {numa_node}"
                )
            }
        }
    }
}

impl Error for ValidationError {}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationWarning::LabFallbackActivated { mode, reason } => {
                write!(f, "lab fallback {mode:?} activated: {reason}")
            }
            ValidationWarning::NumaMismatchWarning {
                component,
                expected,
                observed,
            } => {
                write!(
                    f,
                    "NUMA mismatch for {component:?}: expected node {expected}, observed {observed}"
                )
            }
            ValidationWarning::MissingHugepageNumaNode => {
                write!(f, "profile requires hugepages on a multi-NUMA fast-path profile but hugepage NUMA node is missing")
            }
        }
    }
}

impl Error for ValidationWarning {}

/// Validation report produced by `validate_resource_profile`.
///
/// The report is **eligible** for scheduling (`is_eligible() == true`) iff
/// `errors` is empty.  Warnings do not affect eligibility.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ValidationReport {
    /// Fatal validation errors.  Empty list means the profile is eligible.
    pub errors: Vec<ValidationError>,
    /// Non-fatal warnings (e.g. NUMA mismatches under `Warn` policy).
    pub warnings: Vec<ValidationWarning>,
    /// Lab fallback activation status.  `active == true` means at least one
    /// fallback was used.
    pub fallback_status: FallbackStatus,
}

impl ValidationReport {
    /// Returns `true` when the validation found no errors and the profile is
    /// eligible for scheduling on the target node.
    pub fn is_eligible(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn push_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    pub fn push_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }

    pub fn activate_fallback(&mut self, mode: FallbackMode, reason: impl Into<String>) {
        let reason_str = reason.into();
        self.fallback_status.active = true;
        self.fallback_status.modes.insert(mode);
        self.fallback_status.reasons.push(reason_str.clone());
        self.push_warning(ValidationWarning::LabFallbackActivated {
            mode,
            reason: reason_str,
        });
    }
}

/// Preflight check details.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreflightCheckResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Report produced by running the data-plane preflight verification layer.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DataPlanePreflightReport {
    pub passed: bool,
    pub blocks_readiness: bool,
    pub messages: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub lab_fallback_active: bool,
    pub checks: Vec<PreflightCheckResult>,
}
