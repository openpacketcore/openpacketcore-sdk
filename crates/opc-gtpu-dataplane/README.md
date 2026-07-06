# opc-gtpu-dataplane

Safe Linux GTP-U user-plane dataplane backend model, mock backend, and
redaction-safe errors for OpenPacketCore.

This crate provides:

- `GtpuDataplaneBackend`: an async trait for creating/resolving/removing GTP-U
  dataplane devices and installing/removing PDP contexts.
- `MockGtpuDataplaneBackend`: a deterministic in-memory test double that
  records operations and supports injected failures.
- `LinuxGtpuDataplaneBackend`: a safe production backend that encodes SDK
  device and PDP-context requests into Linux rtnetlink/generic-netlink messages
  through `opc-linux-gtpu-sys`.
- `EbpfGtpuDataplaneBackend`: a tc clsact eBPF datapath backend for
  access-gateway roles (ePDG S2b-U, and by extension UPF/N3IWF-style CNFs)
  that need **uplink** GTP-U encapsulation — see below.
- `UnsupportedGtpuDataplaneBackend`: a backend that reports
  `UnsupportedPlatform` on all mutating operations for non-Linux or
  intentionally disabled builds.
- `GtpuError`: an error enum with payload-free labels and raw errno access safe
  for logs and support bundles.
- `GtpuProbe`: a capability probe covering route/generic netlink reachability,
  `gtp` family presence, effective `CAP_NET_ADMIN`, and UDP bind readiness.
- `resolve_device(name)`: a restore/adoption path for finding an existing
  `gtp` netdevice's ifindex without changing `create_device`'s exclusive-create
  semantics.

Raw Linux socket work is intentionally kept in `opc-linux-gtpu-sys`. This crate
does not implement GTP-U packet encoding/decoding, GTP-C, PFCP, route steering,
XFRM policy, namespace management, product deployment defaults, or
traffic-readiness decisions.

## Privileged integration testing

The live Linux path is covered by the `GTP-U privileged` GitHub Actions
workflow on pull requests, pushes to `main`, and manual dispatches. That
workflow runs the ignored Rust integration test inside a fresh network
namespace after loading the Linux `gtp` module, so normal developer test runs
do not mutate host networking while CI still exercises the kernel path.

The test creates a Linux `gtp` netdevice, installs one GTPv1 PDP context,
checks that the device is visible through `ip -d link show`, removes the
context, and destroys the device.

Run it in a fresh network namespace with `CAP_NET_ADMIN` and the `gtp` module
loaded:

```sh
sudo modprobe gtp
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test linux_gtpu_privileged -- --ignored --nocapture'
```

## eBPF tc datapath backend (`EbpfGtpuDataplaneBackend`)

### Why it exists

The mainline `gtp` netdevice selects the PDP context on transmit by matching
the packet's **destination** address to a subscriber address
(`ipv4_pdp_find(gtp, iph->daddr)`) — the GGSN/PGW "network → subscriber"
downlink model. An ePDG's S2b-U role is the opposite: it must encapsulate the
subscriber's **uplink** (post-IPsec-decap inner packet with `src = UE PAA`,
`dst = arbitrary host`). That packet never matches a PDP context, so the gtp
netdevice drops every uplink packet with `-ENOENT`, in both `ggsn` and `sgsn`
roles. `EbpfGtpuDataplaneBackend` replaces the netdevice with a pair of tc
`clsact` eBPF programs on the **S2b-U (PGW-facing) interface** that handle both
directions. No `gtp` netdevice or out-of-tree kernel module is involved.

### The two tc hooks

- **Egress — `opc_gtpu_uplink`**: parses the inner IPv4 packet routed to the
  S2b-U interface, looks up the **uplink FAR** map by the inner *source*
  (the UE PAA), prepends `[outer IPv4][UDP][GTPv1-U]` (outer `src` = local
  S2b-U address, outer `dst` = PGW peer, TEID = the PGW-assigned O-TEID), and
  re-resolves the L2 next hop for the new outer destination via
  `bpf_redirect_neigh` (kernel ≥ 5.10). FAR miss passes the packet through
  untouched (counted).
- **Ingress — `opc_gtpu_downlink`**: matches UDP/2152 GTPv1-U G-PDUs, looks up
  the **downlink PDR** map by the TEID, validates the inner IPv4 packet
  (including that its destination equals the session's UE PAA), strips the
  outer IPv4/UDP/GTP-U headers (handling the S/PN/E optional block and
  chained extension headers), and returns `TC_ACT_OK` so the inner packet
  continues up the stack. Unknown-TEID G-PDUs are dropped and counted.
  Non-G-PDU GTP-U (echo request/response, error indication) passes through
  untouched to the local control plane.

### Map schemas

Pinned under `<bpffs_pin_root>/<interface>/` (default
`/sys/fs/bpf/opc-gtpu/<interface>/`), so session state and the datapath
survive process restarts:

| map                 | key                              | value                                                              |
|---------------------|----------------------------------|--------------------------------------------------------------------|
| `GTPU_UPLINK_FAR`   | UE PAA, IPv4, 4 B network order  | 12 B: `peer_ip[4] \| local_ip[4] \| o_teid[4]` (all network order) |
| `GTPU_DOWNLINK_PDR` | local S2b-U TEID, 4 B net order  | 4 B: UE PAA (network order)                                        |
| `GTPU_COUNTERS`     | per-CPU array index              | u64 counters (encap, decap, far-miss, unknown-teid, malformed, dst-mismatch) |
| `GTPU_CONFIG`       | array slot 0                     | 4 B: local S2b-U IPv4, written at `create_device`, read on restore |

`install_pdp_context` inserts **both** directions from one `GtpPdpContext`
(`ms_address` → FAR key and PDR value, `peer_teid` → FAR `o_teid`,
`peer_address` → FAR `peer_ip`, `local_teid` → PDR key). Re-installing
identical state is idempotent success; conflicting state for the same UE PAA
or TEID reports `AlreadyExists`. `remove_pdp_context` deletes both entries and
treats absence as idempotent success. Only IPv4 is supported; IPv6 requests
are rejected as `InvalidConfig`.

### GTP-U wire format (TS 29.281)

Uplink encapsulation is exactly `[outer IPv4][UDP][GTPv1-U]`, 36 bytes:
outer IPv4 (IHL 5, TTL 64, protocol UDP, checksum computed), UDP with
`sport = dport = 2152` and checksum 0 (permitted for UDP over IPv4), GTPv1-U
flags `0x30` (version 1, PT=1, E=S=PN=0), message type `0xFF` (G-PDU),
length = inner packet length, TEID = O-TEID. On receive, G-PDUs carrying the
optional 4-byte Seq/N-PDU/Next-Ext block and chained extension headers are
accepted and stripped. The byte layouts live in `opc-gtpu-ebpf-common` and are
unit-tested without a kernel.

### Device lifecycle

- `create_device`: the request's `name` must be the **existing S2b-U
  interface** (no netdevice is created) and `bind_address` must be the
  concrete local S2b-U IPv4 (used as the outer encapsulation source). Loads
  the committed CO-RE object, pins the maps, and attaches both tc programs.
- `resolve_device`: adopts a previously provisioned interface after a process
  restart — reuses the pinned maps (sessions keep forwarding), re-attaches the
  programs, and recovers the local address from `GTPU_CONFIG`.
- `remove_device`: detaches the programs and removes the map pins. The
  `clsact` qdisc is left in place because other filters may share it.
- **Cleanup only ever touches its own programs.** Before detaching or
  replacing anything at its tc priority/handle slot, the backend reads the
  occupying filter back from the kernel and verifies the BPF program name is
  one of its own datapath programs (`opc_gtpu_uplink`/`opc_gtpu_downlink`).
  A foreign filter in the slot is never removed: provisioning fails with
  `AlreadyExists` and any partial attach and freshly created pins are rolled
  back. Stale filters from a crashed previous incarnation are replaced or
  removed only after that same ownership check.
- `probe`: reports `mutation_ready` only when bpffs is available, kernel BTF
  is present, and both `CAP_NET_ADMIN` and `CAP_BPF`/`CAP_SYS_ADMIN` are
  effective (`kind = LinuxEbpf`; `bpf_capable`/`btf_present` fields).

### XFRM interaction

Downlink decapsulation happens at tc ingress, **before** the IP stack, so the
decapped inner packet (`dst = UE PAA`) traverses normal routing and the
ePDG's XFRM output/forward policy (selector `dst = UE PAA`), which
ESP-encapsulates it toward the UE over SWu. Nothing in the datapath bypasses
XFRM. On uplink the eBPF program sees the inner packet only after XFRM input
has already decapsulated ESP and the stack has routed it to the S2b-U
interface.

### Product steering contract (consumer-facing)

The consuming gateway must:

1. Provision with `create_device(name = <S2b-U interface>, bind_address =
   <S2b-U IPv4>)` — the interface bound to `--gtpu-addr`, not a `gtp` device.
2. Route the post-XFRM-decap **uplink inner packet** (`src = UE PAA`) to the
   **S2b-U interface** (e.g. `ip rule`/table steering to `dev <s2bu>` with the
   PGW as the next hop). There must be **no** `dev gtp-*` route and no gtp
   netdevice; the tc egress program performs the encapsulation.
3. Leave downlink alone: G-PDUs arriving on UDP/2152 are decapsulated in tc
   ingress and re-enter the stack, where the existing XFRM policy toward the
   UE applies. No downlink route toward a gtp device is needed (the old
   `dev gtp` downlink route model is superseded).
4. Keep at least 36 bytes of MTU headroom between the UE-facing MTU and the
   S2b-U interface MTU for the added outer headers.
5. Install one `GtpPdpContext` per session (`link_ifindex` = the S2b-U
   ifindex returned by `create_device`/`resolve_device`); on HA restore call
   `resolve_device` first, then re-install contexts (idempotent).

### eBPF artifact

The tc programs are Rust (`aya-ebpf`), built to a committed CO-RE object at
`crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o` and embedded into
this crate at compile time. Rebuild with `scripts/build-gtpu-ebpf.sh` (pinned
nightly toolchain + `bpf-linker`); CI rebuilds it and fails on structural
drift. No clang, kernel headers, or compiler is needed at runtime on targets.

### Privileged eBPF integration test

The `ebpf_gtpu_privileged` test builds a three-netns topology
(UE ↔ ePDG ↔ PGW), drives a real uplink UDP flow through tc-egress
encapsulation, asserts the exact G-PDU bytes at the PGW, sends downlink
G-PDUs (with and without sequence numbers) back through tc-ingress
decapsulation and stack forwarding to the UE, and verifies unknown-TEID
drops, echo passthrough, restore/adoption, and idempotent teardown:

```sh
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test ebpf_gtpu_privileged -- --ignored --nocapture'
```
