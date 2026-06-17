# OPC-SDK-RFC-011: Node and Data-Plane Resource Contract

**Status**: Draft for Implementation  
**Version**: 1.0.0  
**Date**: 2026-05-19  
**Audience**: UPF/data-plane engineers, platform engineers, Kubernetes operators, security reviewers

## 1. Abstract

This RFC defines the node, kernel, NIC, CNI, CPU, memory, and pod-security
contract required by OpenPacketCore data-plane and signaling-heavy CNFs. It
standardizes how CNFs request and verify SR-IOV, Multus, AF_XDP, XDP/eBPF,
hugepages, NUMA alignment, CPU pinning, IRQ affinity, device plugins, kernel
features, and pod security exceptions.

The goal is to make data-plane performance and privilege requirements explicit,
admissible, testable, and portable across carrier Kubernetes environments.

## 2. Scope

### 2.1 In Scope

- Node capability discovery.
- Kubernetes scheduling/resource requests.
- Multus and SR-IOV attachment contracts.
- AF_XDP/XDP/eBPF requirements.
- CPU pinning, NUMA, hugepages, and IRQ affinity.
- Pod security exceptions and capability minimization.
- Data-plane preflight and readiness.
- Metrics and conformance tests for platform resources.

### 2.2 Out of Scope

- Packet parser behavior. See RFC 005.
- Session state consistency. See RFC 004.
- Runtime task supervision. See RFC 008.
- Vendor-specific NIC tuning beyond declared capability adapters.

## 3. Design Goals

### 3.1 Security

- Grant only the minimum Linux capabilities needed by each CNF.
- Bind privileged data-plane pods to explicitly labeled nodes.
- Prevent untrusted workloads from using OpenPacketCore data-plane device
  resources.
- Make kernel/eBPF program loading auditable.

### 3.2 Performance

- Preserve CPU, cache, NUMA, NIC queue, and IRQ locality.
- Avoid noisy-neighbor interference on data-plane cores.
- Provide deterministic preflight before declaring readiness.
- Expose packet drop and queue pressure metrics.

### 3.3 Maintainability

- One shared contract for platform assumptions.
- Per-NF specs declare deviations through structured resource profiles.
- Device and kernel feature detection is reusable.
- CI can verify chart/resource generation without real NICs.

### 3.4 Functionality

- Support UPF AF_XDP fast path.
- Support ePDG/N3IWF IPsec and tunnel workloads.
- Support L4 UDP fan-in proxy.
- Support SCTP-heavy AMF/SMS/IMS workloads.
- Support lab mode without hardware acceleration.

## 4. Resource Profiles

Each CNF declares a resource profile:

```rust
pub enum DataPlaneProfile {
    ControlPlaneOnly,
    SignalingHeavy,
    KernelNetworking,
    AfXdpFastPath,
    SriovFastPath,
    IpsecGateway,
}
```

Profiles determine required node labels, capabilities, CNI attachments, and
preflight checks.

`IpsecGateway` is a resource and admission profile only in the current SDK. It
does not imply that this repository ships IKEv2, ESP, xfrm orchestration, or
N3IWF/NWu procedure implementations. Those protocol crates are required for a
selected ePDG/N3IWF/untrusted-access product target, but are not a blocker for
the current AMF-lite/N2/N1 first-NF profile.

## 5. Node Capability Discovery

The platform MUST provide a node capability report:

```yaml
node:
  kernel: "6.8.0"
  bpf:
    cap_bpf: true
    xdp_supported: true
    btf_available: true
  cpu:
    manager_policy: static
    isolated_cores: "2-15"
    numa_nodes: 2
  memory:
    hugepages_2Mi: 4096
    hugepages_1Gi: 8
  nics:
    - name: ens5f0
      driver: ice
      sriov_vfs: 16
      xdp_modes: ["native", "skb"]
      queues: 32
```

The operator or node agent MUST publish this through labels, annotations, or a
custom resource.

## 6. Scheduling Contract

Data-plane CNFs MUST use:

- node selectors for required hardware,
- tolerations for dedicated nodes,
- pod anti-affinity where replicas need failure-domain separation,
- topology spread constraints,
- resource requests/limits matching CPU Manager static policy,
- hugepage requests where required,
- device plugin resource requests for SR-IOV or specialized devices.

The operator MUST reject a lifecycle CR if no eligible node can satisfy the
declared profile, unless lab mode allows software fallback.

## 7. CPU and NUMA

### 7.1 CPU Pinning

Data-plane workers SHOULD run on exclusive CPUs. Management and async control
tasks MUST NOT run on those same pinned data-plane CPUs.

The runtime receives an explicit CPU allocation:

```rust
pub struct CpuLayout {
    pub data_plane_cores: Vec<CpuId>,
    pub control_plane_cores: Vec<CpuId>,
    pub management_cores: Vec<CpuId>,
    pub numa_node: Option<NumaNodeId>,
}
```

### 7.2 NUMA Locality

NIC queues, AF_XDP UMEM, hugepages, and worker threads SHOULD be NUMA-local.
Preflight MUST warn or fail according to profile when locality is broken.

### 7.3 IRQ Affinity

The platform SHOULD pin NIC IRQs to the correct NUMA-local cores. The CNF MUST
report IRQ affinity mismatches when detectable.

## 8. Memory and Hugepages

CNFs using DPDK-like or AF_XDP memory pools MUST declare:

- hugepage size,
- hugepage count,
- per-queue buffer count,
- max packet size,
- headroom,
- NUMA node.

The pod MUST request hugepages explicitly. Overcommitting data-plane memory is
forbidden in production profiles.

## 9. Network Attachments

### 9.1 Multus

Each data-plane interface is a named attachment:

```yaml
multus:
  n3:
    networkAttachmentDefinition: upf-n3
    interfaceName: n3
  n4:
    networkAttachmentDefinition: upf-n4
    interfaceName: n4
  n6:
    networkAttachmentDefinition: upf-n6
    interfaceName: n6
```

Canonical YANG defines interface roles; lifecycle CR values reference attachment
objects only.

### 9.2 SR-IOV

SR-IOV profiles MUST define:

- resource name,
- VF trust/spoof-check settings,
- VLAN policy,
- link state policy,
- allowed device drivers,
- whether IPAM is static or dynamic.

The operator MUST validate that referenced SR-IOV resources are allowlisted for
the NF kind.

## 10. AF_XDP and XDP/eBPF

`AfXdpFastPath` is a resource and admission profile only in the current SDK. It
does not imply that this repository ships AF_XDP sockets, UMEM management, RX/TX
rings, or packet I/O runtime support. Those crates are required for a selected
UPF or other accelerated data-plane product target, but are not a blocker for
the current AMF-lite/N2/N1 first-NF profile.

### 10.1 Kernel Requirements

AF_XDP fast-path profiles MUST declare:

- minimum kernel version,
- required BPF features,
- required XDP mode,
- required capabilities,
- required maps and pin paths,
- whether generic XDP fallback is allowed.

### 10.2 Capabilities

Allowed capabilities for AF_XDP profile:

- `CAP_BPF`
- `CAP_NET_ADMIN`
- `CAP_NET_RAW`

`CAP_SYS_ADMIN` is forbidden in production profiles. If a kernel requires
`CAP_SYS_ADMIN`, the node is not eligible.

### 10.3 eBPF Program Governance

eBPF programs MUST be:

- built from source in release pipeline,
- included in SBOM/evidence,
- signed or digest-pinned,
- loaded only from approved paths,
- audited on load/unload,
- pinned under controlled bpffs path.

## 11. Pod Security Exceptions

Baseline pod security remains:

- run as non-root,
- read-only root filesystem,
- no privilege escalation,
- drop all capabilities except explicit allowlist,
- seccomp profile enabled,
- AppArmor/SELinux profile where supported.

Every exception MUST be declared in:

- per-NF spec,
- Helm values,
- operator admission policy,
- RFC 006 evidence.

## 12. Data-Plane Preflight

Before readiness, data-plane CNFs MUST verify:

- required interfaces exist,
- link state is up where required,
- MTU matches config,
- NIC driver and queues match profile,
- XDP attach succeeded,
- BPF maps created,
- hugepages allocated,
- CPU layout applied,
- session table initialized,
- drop counters accessible.

Failures mark readiness false and emit alarms.

## 13. Lab and Fallback Modes

Lab mode MAY use:

- veth instead of SR-IOV,
- generic XDP instead of native XDP,
- software packet path,
- relaxed CPU pinning,
- no hugepages.

Lab fallback MUST be visible in status and MUST NOT be silently used in
production.

## 14. Observability

Required metrics:

- `opc_node_capability_info{node,kernel,profile}`
- `opc_dataplane_interface_up{nf,interface}`
- `opc_dataplane_rx_packets_total{nf,interface}`
- `opc_dataplane_tx_packets_total{nf,interface}`
- `opc_dataplane_drops_total{nf,interface,reason}`
- `opc_dataplane_queue_fill_ratio{nf,interface,queue}`
- `opc_dataplane_xdp_attach_total{nf,outcome}`
- `opc_dataplane_bpf_map_entries{nf,map}`
- `opc_dataplane_numa_mismatch{nf}`
- `opc_dataplane_irq_affinity_mismatch{nf}`

## 15. Configuration Model

Shared YANG groupings SHOULD include:

- `resources/cpu`
- `resources/numa`
- `resources/hugepages`
- `resources/interfaces`
- `resources/xdp`
- `resources/sriov`
- `resources/preflight`

Lifecycle CRDs reference Kubernetes resource names; dense tuning lives in YANG.

## 16. Module Ownership

| Module | Responsibility |
| :--- | :--- |
| `opc-node-capabilities` | node feature report parser/model |
| `opc-resource-admission` | operator resource validation |
| `opc-cpu-layout` | CPU/NUMA layout helpers |
| `opc-net-attach` | Multus/SR-IOV model helpers |
| `opc-af-xdp-platform` | AF_XDP preflight and map metadata |
| `opc-bpf-governance` | BPF artifact digest/load audit |
| `opc-resource-testkit` | fake node capabilities and chart tests |

Agents implementing UPF or similar CNFs must consume these modules rather than
hard-coding node assumptions.

## 17. Testing Requirements

### 17.1 Unit Tests

- Node capability parsing.
- Resource profile validation.
- CPU layout validation.
- SR-IOV allowlist policy.
- Capability exception rendering.
- Lab fallback status.

### 17.2 Integration Tests

- Helm renders correct resource requests.
- Operator rejects unsatisfied node profile.
- AF_XDP preflight succeeds with fake capabilities.
- Production profile rejects `CAP_SYS_ADMIN`.
- Readiness false when required interface is missing.

### 17.3 Fault Injection

- XDP attach failure.
- Hugepage allocation failure.
- NIC link down.
- NUMA mismatch.
- IRQ affinity mismatch.
- Device plugin resource unavailable.

### 17.4 Performance Gates

- Preflight completes within configured startup budget.
- Data-plane metrics scrape does not stall packet workers.
- Resource admission for 1,000 CNF CRs stays within operator API budget.

## 18. Acceptance Criteria

This RFC is implemented when:

1. Data-plane CNFs declare structured resource profiles.
2. Operator admission rejects unsatisfied production resource requirements.
3. CPU, NUMA, hugepage, NIC, and CNI assumptions are explicit.
4. AF_XDP/eBPF programs are governed by signed/digest-pinned artifacts.
5. Pod security exceptions are minimal and evidence-linked.
6. Readiness depends on data-plane preflight.
7. Lab fallback cannot silently enter production.
