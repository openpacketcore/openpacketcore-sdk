# opc-gtpu-dataplane

## Purpose

`opc-gtpu-dataplane` is the safe Rust control surface for OpenPacketCore
GTP-U dataplane state. It models GTP devices and PDP contexts, provides Linux,
eBPF, mock, and unsupported backends, and keeps raw syscalls in
`opc-linux-gtpu-sys`.

The crate does not implement GTP-C, PFCP, packet parsing, namespace management,
route steering, XFRM policy, deployment defaults, or traffic-readiness policy.

## API Shape

- `GtpuDataplaneBackend`: async port for `create_device`, `resolve_device`,
  `remove_device`, `install_pdp_context`, `remove_pdp_context`, and `probe`.
- `LinuxGtpuDataplaneBackend`: safe adapter over the Linux `gtp` netdevice and
  GTP generic-netlink family.
- `EbpfGtpuDataplaneBackend`: tc `clsact` eBPF datapath adapter for
  uplink-capable access-gateway roles where the mainline `gtp` netdevice cannot
  select PDP context by inner source address.
- `MockGtpuDataplaneBackend`: deterministic in-memory backend with operation
  capture and failure injection.
- `UnsupportedGtpuDataplaneBackend`: reports unsupported-platform results while
  preserving trait-object usage on non-Linux or disabled builds.
- Model exports include `CreateGtpDeviceRequest`, `GtpDevice`,
  `GtpPdpContext`, `RemovePdpContextRequest`, `Teid`, `GtpuProbe`,
  `GtpuBackendKind`, `GtpuCapability`, `DscpCodepoint`, `GtpRole`,
  `GtpVersion`, `GtpAddressFamily`, and `GTPU_PORT`.
- `GtpuError` is intentionally redaction-safe; TEIDs and addresses are not
  emitted by `Debug`/`Display`.

## Usage

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};

use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpPdpContext, GtpVersion, GtpuDataplaneBackend,
    MockGtpuDataplaneBackend, RemovePdpContextRequest, Teid,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = MockGtpuDataplaneBackend::new();
    let device = backend
        .create_device(CreateGtpDeviceRequest::new("gtp-test"))
        .await?;

    let context = GtpPdpContext {
        local_teid: Teid::new(0x1000_0001).unwrap(),
        peer_teid: Teid::new(0x2000_0001).unwrap(),
        ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
        peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        link_ifindex: device.ifindex,
        gtp_version: GtpVersion::V1,
        egress_dscp: None,
    };

    backend.install_pdp_context(context.clone()).await?;
    backend
        .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
        .await?;
    backend.remove_device(&device).await?;
    Ok(())
}
```

## Backend Notes

`LinuxGtpuDataplaneBackend` creates and removes real Linux `gtp` netdevices and
programs PDP contexts through rtnetlink and generic netlink. It requires Linux
GTP kernel support and effective `CAP_NET_ADMIN`.

`EbpfGtpuDataplaneBackend` attaches committed Rust/aya tc programs to an
existing S2b-U style interface. `create_device.name` is the existing attach
interface and `bind_address` is the local outer IPv4 address. It pins maps under
`/sys/fs/bpf/opc-gtpu/<interface>/` by default, installs both uplink FAR and
downlink PDR state from one `GtpPdpContext`, and supports restore through
`resolve_device`. It only supports IPv4 session state today.

The eBPF backend also owns an additive `GTPU_UPLINK_DSCP` map keyed by UE PAA.
Setting `GtpPdpContext::egress_dscp` stamps that validated codepoint on the
newly generated outer uplink IPv4 header and includes it in the header
checksum. `None` preserves the exact legacy encapsulation bytes and existing
FAR/PDR layouts. Installs publish DSCP before FAR/PDR reachability and roll it
back on later failure; removals clear FAR, then DSCP, and retain the PDR as a
UE-key journal until both uplink resources are gone. This makes a failed or
crashed removal safely retryable. Exact FAR/PDR
reconciliation can atomically add, replace, or remove only the DSCP entry.
An exact retry also reconciles a DSCP-only publication orphan left by a crash
before FAR/PDR insertion; one-sided FAR or PDR state remains an ambiguous
conflict. Legacy pinned datapaths gain the additive map during one-time
adoption. A durable schema marker in the existing FAR map distinguishes that
migration from later DSCP-pin loss; an adopted pin set with a missing DSCP map
fails closed before the loader can silently recreate empty state.

`GtpuProbe::egress_dscp_marking` reports `Unknown` while a capable environment
awaits its first device attach, then becomes `Available` only when both exact
live tc filters are the loaded uplink/downlink artifacts and reference every
exact required pinned FAR, PDR, DSCP, configuration, and counter map. Runtime
filter or map identity loss is `Missing` and blocks marked session mutation.
The mainline Linux `gtp`, mock, and unsupported
backends report `Missing` and reject `Some` rather than carrying an unmarked
request.

All mutations through clones of one backend are serialized as one
three-map reconciliation. Independently constructed backends and processes
cannot own the same `(network namespace, canonical pin directory, interface)`
at the same time: a kernel-lifetime abstract socket provides exclusive
ownership and a second live reconciler receives `AlreadyExists`. Process exit
releases the ownership automatically, allowing a replacement to call
`resolve_device` and adopt the surviving pins. A rolling handoff must therefore
stop the old writer before the new writer adopts the interface.

The runtime takes both tc links out of Aya loader ownership, so dropping an old
loader cannot detach a static filter that an external actor subsequently
placed at the same priority/handle. `remove_device` preflights both live hooks
against the exact loaded kernel program IDs before touching either and repeats
that check before each explicit detach. A replacement already visible at
preflight returns `AlreadyExists` without unlinking pins or filters. Before map
unpin, every named bpffs path is re-opened and its kernel map ID is compared
with the identity held by the loader.

Provisioning also reconciles a failed classic-tc attach ACK against the live
slot. An exact newly loaded program is adopted with a kernel-owned handle; only
an originally empty slot subsequently proven empty is an ordinary attach
failure. Every other uncertain read, attach, replacement, or rollback is
`StateIndeterminate`. A rollback after replacing an earlier exact program is
also indeterminate because deleting the new program cannot restore the old
one. Ordinary fresh-pin cleanup re-proves every held map ID against its named
path and requires either a confirmed empty pre-attach state or a transaction
proof that no desired hook remains. That latter proof applies only to a fresh
pin set: a static foreign filter predates and cannot reference the new map IDs;
it does not claim safety against concurrent external mutation. Pre-existing
pin sets and every indeterminate outcome are retained for inspection.

Classic tc netlink deletion and bpffs pathname unlink have no conditional
delete-by-object-ID primitive. The abstract-socket reconciler lease is therefore
the safety boundary: every SDK, operator, and maintenance writer of these tc
slots or pin paths must acquire/observe that exclusive boundary. Uncoordinated
concurrent `tc` or bpffs mutation is unsupported. A netlink-uncertain first
detach, any second-hook failure after the first was removed, or any post-detach
pin mismatch/unlink failure returns `StateIndeterminate`; an operator must then
inspect and reconcile both hooks and all named pins before retrying.

The eBPF map and wire layouts live in `opc-gtpu-ebpf-common`. The eBPF program
crate is `opc-gtpu-dataplane-ebpf`; its committed object is embedded from
`crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o`.

## Status And Limits

- This is an unpublished workspace crate (`publish = false`).
- The safe Rust crate forbids `unsafe`; kernel UAPI work is isolated in
  `opc-linux-gtpu-sys`.
- The Linux netdevice backend follows mainline `gtp` behavior and is not the
  ePDG uplink datapath.
- The eBPF backend requires bpffs, kernel BTF, tc/eBPF privileges
  (`CAP_NET_ADMIN` and `CAP_BPF` or `CAP_SYS_ADMIN`), and enough MTU headroom
  for 36 bytes of outer IPv4/UDP/GTP-U headers.
- eBPF cleanup checks exact BPF program IDs and named pin map IDs, but classic
  tc/bpffs cleanup requires the documented exclusive-writer boundary; it does
  not claim atomic conditional deletion against uncoordinated external writers.

## Roadmap

- Expand eBPF datapath support beyond IPv4 only when the map schema and tests
  cover it.
- Keep privileged integration tests as the source of truth for Linux kernel and
  tc behavior.
- Add product-level route/XFRM/namespace orchestration in consumer crates rather
  than in this backend crate.

## Verification

```sh
cargo test -p opc-gtpu-dataplane
sudo modprobe gtp
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test linux_gtpu_privileged -- --ignored --nocapture'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test ebpf_gtpu_privileged -- --ignored --nocapture'
```
