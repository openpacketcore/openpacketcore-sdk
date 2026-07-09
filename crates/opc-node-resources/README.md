# opc-node-resources

## Purpose

`opc-node-resources` validates that a desired `ResourceProfile` is compatible
with an observed `NodeCapabilityReport`. It is a pure model and validation
crate: callers provide node facts, CPU layout, interface names, and allowlists;
the crate does not inspect the host or call Kubernetes.

## API Shape

- Primary functions: `validate_resource_profile` and
  `run_data_plane_preflight`.
- Desired-state model: `ResourceProfile`, `DataPlaneProfile`, `Environment`,
  `NetworkFunctionKind`, `CpuPolicy`, `AfXdpProfile`, `SriovProfile`,
  `IpsecGatewayProfile`, `PodSecurityExceptionModel`, and `LabFallbackPolicy`.
- Observed-state model: `NodeCapabilityReport`, `BpfCapabilities`,
  `NodeCpuCapabilities`, `NodeMemoryCapabilities`, `NicCapability`,
  `IpsecCapabilities`, and `IpsecGatewayCapabilities`.
- Context and results: `ValidationContext`, `ValidationReport`,
  `ValidationError`, `ValidationWarning`, `FallbackStatus`,
  `PreflightCheckResult`, and `DataPlanePreflightReport`.
- Helpers cover BPF artifact governance, controlled bpffs paths, CPU isolation,
  NUMA policy, hugepage affinity, AF_XDP, SR-IOV, IPsec gateway attachments,
  pod-security exceptions, and available XDP modes.

## Usage

```rust,no_run
use opc_node_resources::{
    run_data_plane_preflight, CpuLayout, DataPlaneProfile, Environment,
    NetworkFunctionKind, ResourceProfile, SriovAllowlistPolicy, ValidationContext,
};

fn check(
    node: &opc_node_resources::NodeCapabilityReport,
    interfaces: &[String],
    allowlist: &SriovAllowlistPolicy,
) -> opc_node_resources::DataPlanePreflightReport {
    let profile = ResourceProfile::new(
        NetworkFunctionKind::Upf,
        DataPlaneProfile::ControlPlaneOnly,
        Environment::Production,
    );
    let cpu_layout = CpuLayout {
        data_plane_cores: Vec::new(),
        control_plane_cores: Vec::new(),
        management_cores: Vec::new(),
        numa_node: None,
    };
    let context = ValidationContext {
        node,
        cpu_layout: &cpu_layout,
        data_plane_interfaces: interfaces,
        hugepage_numa_node: None,
        sriov_allowlist: allowlist,
    };
    run_data_plane_preflight(&profile, &context)
}
```

## Relationships

- Used by `operator-lifecycle` admission/preflight decisions.
- Used by `operator-lifecycle-cli preflight` to expose the Rust checks to Go
  controller-runtime operators.
- Does not depend on Linux syscall crates; it validates reported capability
  evidence only.

## Status And Limits

- Production-oriented validation rules are present for AF_XDP, SR-IOV, IPsec
  gateway, pod security, CPU isolation, NUMA locality, hugepages, and BPF
  artifact provenance.
- Production AF_XDP profiles reject `CAP_SYS_ADMIN`; allowed capabilities are
  bounded to `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_NET_RAW`.
- Lab fallbacks are explicit in `FallbackStatus`; the crate does not silently
  downgrade fast-path requirements.
- Validation quality depends on the caller-provided `NodeCapabilityReport`.
  This crate does not prove the report is fresh or truthful.

## Roadmap

- Keep new dataplane profiles evidence-driven and fail closed in production.
- Add host-inspection agents outside this crate; keep this crate pure and easy
  to test.
- Version preflight evidence shape if external controllers begin persisting it.

## Verification

```sh
cargo test -p opc-node-resources
```
