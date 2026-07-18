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
  select PDP context by inner source address. Its `datapath_snapshot` method
  returns identity-bound aggregate counters from the exact live programs and
  pinned map.
- `MockGtpuDataplaneBackend`: deterministic in-memory backend with operation
  capture and failure injection.
- `UnsupportedGtpuDataplaneBackend`: reports unsupported-platform results while
  preserving trait-object usage on non-Linux or disabled builds.
- Model exports include `CreateGtpDeviceRequest`, `GtpDevice`,
  `GtpPdpContext`, `GtpBearerMark`, `RemovePdpContextRequest`, `Teid`,
  `GtpuProbe`, `GtpuBackendKind`, `GtpuCapability`,
  `EbpfGtpuDatapathSnapshot`, `EbpfGtpuDatapathCounters`, `DscpCodepoint`,
  `GtpRole`, `GtpVersion`, `GtpAddressFamily`, and `GTPU_PORT`.
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
        bearer_mark: None,
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

### Downlink outer-envelope validation

The tc ingress program validates the complete unfragmented outer envelope
before reading PDR state. IPv4 version, variable IHL, Total Length, accessible
bytes, and the checksum over the complete option-bearing header must agree.
UDP Length must contain its header plus the mandatory GTP-U header and end
exactly at IPv4 Total Length. The GTP-U Length field must then end exactly at
the UDP payload boundary. Optional fields, extension headers, and the minimum
inner IPv4 header are loaded only within that proven GTP-U end.

Ethernet bytes beyond IPv4 Total Length are legal layer-2 padding, not UDP or
GTP-U payload. The program trims such padding before front decapsulation, so it
cannot survive as unauthenticated inner bytes. Bytes inside the declared UDP
payload but beyond the GTP-U Length are malformed rather than padding.

An IPv4 UDP checksum field of zero is legal omission only after the program
rules out a pending zero-seed `CHECKSUM_PARTIAL` operation. The checksum-level
query cannot make that distinction. Instead, a non-pseudoheader 16-bit
`bpf_l4_csum_replace` probe changes an ordinary checksum field but is a stable
no-op for `CHECKSUM_PARTIAL`. The program snapshots the checksum bytes, probes
and reverses a fixed delta, restores the exact snapshot with zero store flags,
and reloads it before accepting omission or software verification. Any probe,
reverse, store, or reload failure drops before PDR lookup; the packet retains
the exact original checksum bytes.

For a non-zero checksum, only a positive `BPF_CSUM_LEVEL_QUERY` result is
trusted. At this hook the GTP-U UDP checksum is the current outermost checksum,
so `CHECKSUM_UNNECESSARY` with checksum level zero is sufficient. A negative
query includes `CHECKSUM_NONE`, `CHECKSUM_COMPLETE`, `CHECKSUM_PARTIAL`, and
helper failure. The reversible probe must first prove the state is not
`CHECKSUM_PARTIAL`; only then can exact software verification over the IPv4
pseudo-header and declared UDP bytes authorize a completed wire checksum. A
pending checksum is rejected even if its current bytes happen to satisfy the
final checksum equation. The program never repairs or trusts an unfinished
checksum.

After UDP/2152 identifies a candidate, every malformed declaration or
unverified checksum increments the existing bounded `downlink_malformed`
counter and drops before TEID/PDR lookup, decapsulation, or inner-destination
validation. Addresses, TEIDs, lengths, checksum values, and payload bytes are
not emitted. Non-UDP traffic, other UDP ports, fragments awaiting host-stack
policy, and structurally valid non-G-PDU GTP-U control traffic retain their
pass-through behavior.

The privileged proof covers a legal zero `CHECKSUM_NONE` omission, non-zero
software-verified bytes, authenticated zero and non-zero
`CHECKSUM_UNNECESSARY`, and genuine zero-seed, non-zero-seed, and already
checksum-valid-byte `CHECKSUM_PARTIAL` frames. The positive fixture uses
WireGuard AEAD authentication of the complete inner IPv4 packet before Linux
publishes checksum metadata and forwards the current UDP packet into the real
tc hook. Every partial form fails before PDR/decap counters, while both legal
zero cases decapsulate only after the exact checksum bytes are restored. A
boundary mismatch with trusted metadata proves metadata never bypasses
structural validation.

### Per-bearer packet marks

The eBPF backend can install a default bearer and multiple dedicated bearers
that share one UE PAA. Set `GtpPdpContext::bearer_mark` to `None` for the
default bearer. For a dedicated bearer, a request literal can use
`bearer_mark: GtpBearerMark::new(0x1001)`. The constructor returns `None` for
zero because it is reserved for the default bearer; every non-zero `u32`,
including `u32::MAX`, is valid. A local TEID must be unique across the default
and marked PDR maps, and `(UE PAA, mark)` must identify exactly one marked
uplink FAR.

The S2b-U eBPF boundary owns the complete 32-bit `skb->mark`; it does not
support masked sharing with unrelated mark users. Mark zero selects the
default bearer. A non-zero mark selects the exact dedicated FAR keyed by
`(UE PAA, mark)`. An unknown non-zero mark, or any non-encapsulating error on
that path, is dropped rather than passed as clear subscriber traffic. After a
successful marked encapsulation, the program clears the consumed mark before
neighbour redirect so the generated outer GTP-U packet cannot be classified
again as subscriber traffic. The mark-zero FAR-miss/error behavior remains the
legacy pass-through behavior.

Downlink PDR state carries the same complete selector. After a G-PDU has passed
TEID, length, and inner-destination validation and has been decapsulated, a
marked PDR writes its non-zero mark for XFRM output-policy selection. A valid
default PDR deliberately writes zero rather than preserving metadata from the
outer GTP-U packet. This normalization changes `skb` metadata, not packet or
GTP-U wire bytes, and prevents an outer transport mark from selecting a
dedicated Child SA accidentally.

Pair this contract with exact full-mask XFRM configuration. The inbound
default Child SA must clear the complete mark with value `0` and mask
`u32::MAX`; each inbound dedicated Child SA must set its `GtpBearerMark` value
with mask `u32::MAX`. Outbound policies must likewise match default
`(0, u32::MAX)` or the dedicated `(mark, u32::MAX)`. A partial mask is not a
compatible configuration: preserved bits change the exact GTP-U lookup key
and can select no bearer. TFT classification, mark allocation, XFRM policy/SA
installation, and collision avoidance with other Linux mark users remain
product responsibilities.

For redaction-safe live diagnostics, call
`EbpfGtpuDataplaneBackend::datapath_snapshot(&device)`. Under the backend's
required exclusive-writer contract, a successful call re-opens every named
bpffs pin, verifies the full map-ID sets referenced by the held uplink and
downlink programs, verifies both exact program IDs are still in their tc slots,
reads the held `GTPU_COUNTERS` map directly, aggregates every per-CPU value,
then repeats the identity proof. The returned
`EbpfGtpuDatapathSnapshot` contains only kernel-local program/map IDs and
aggregate counters; it contains no addresses, TEIDs, packet marks, or payloads.
This avoids `bpftool map dump name GTPU_COUNTERS`, which can select an unrelated
same-name map when stale or concurrently loaded objects exist. The method
returns `StateIndeterminate` rather than presenting counters as authoritative
if a hook or pin mismatch is visible at either identity check. An external-root
replace-and-restore between checks is outside the exclusive-writer contract and
cannot be distinguished by this diagnostic.

The existing counter schema remains unchanged and aggregates default and
dedicated bearers. Use counter deltas to prove that the attached uplink/downlink
programs ran; use the peer's observed GTP-U TEID for per-bearer correlation.
An all-zero identity-bound snapshot during a claimed GTP-U round trip means the
traffic did not traverse these exact programs, not that a marked lookup chose
the default entry.

Existing `GtpPdpContext` literals must add `bearer_mark: None` to retain the
default path, or construct a non-zero `GtpBearerMark` for a dedicated bearer.
Code that constructs `GtpuProbe` literals must also initialize the new
`per_bearer_marking` field. Consumers must gate `bearer_mark: Some(_)` on
`GtpuProbe::per_bearer_marking == GtpuCapability::Available`; it becomes
available only after both exact live tc programs and every exact v2 map pin
have been verified. The mainline Linux `gtp`, mock, and unsupported backends
report `Missing` and reject marked requests. This API requires no Cargo feature
and introduces no dependency.

### DSCP and reconciliation

The eBPF backend owns `GTPU_UPLINK_DSCP` for default bearers and an additive
marked DSCP map keyed by `(UE PAA, mark)`. Setting
`GtpPdpContext::egress_dscp` stamps that validated codepoint on the newly
generated outer uplink IPv4 header and includes it in the header checksum.
`None` preserves the exact legacy encapsulation bytes.

Default-bearer reconciliation retains the existing map protocol: installation
publishes DSCP before FAR/PDR reachability and rolls it back after a reported
later failure, while removal retains the PDR as its lookup-key journal until
FAR and DSCP have been cleared. An exact retry can reconcile a DSCP-only
publication orphan. One-sided default FAR or PDR state remains an ambiguous
conflict and fails closed.

Marked bearers use a stronger, additive owner journal keyed by `(UE PAA,
mark)`. Its value binds the local TEID, complete uplink FAR, optional DSCP, and
one of three phases. Installation publishes `Pending` before any forwarding
resource, reconciles only an exact matching request, then publishes `Active`
last. Both classifiers require an exact active owner and matching FAR/DSCP/PDR
state, so a crash or map error at any earlier point leaves the bearer
non-forwarding and safely retryable. A DSCP update is phase-gated by the same
protocol. Removal publishes `Removing` first, deletes FAR, DSCP, and PDR, then
deletes the owner last; an interrupted removal cannot resume forwarding and an
exact removal retry finishes it. Linux/Aya reports deletion of an absent hash
entry as syscall `ENOENT`; the runtime classifies that result as idempotent
absence, including when an optional DSCP entry was never installed. An install
that encounters a valid persisted `Removing` owner also finishes that committed
deletion, but never resurrects the bearer or reports `AlreadyExists` in the
same call. It returns
`GtpuError::RetryRequired { operation: "ebpf_install_after_removal" }`; the
caller must submit a fresh install after that result. This remains true when
the fresh request changes the endpoint, DSCP, local TEID, or selector. On
attach or adoption the runtime validates the whole owner/resource graph and
rebuilds a bounded TEID-to-owner index once, rather than scanning maps for each
operation. Malformed owners, duplicate TEIDs, dual-schema ownership, unowned
marked resources, mismatched resources, and incomplete active owners all fail
closed before either tc hook is changed.

All PDP cleanup first verifies that every named pin is the exact map held by
the runtime. Each tc slot must contain either that runtime's exact program or
be positively absent; an absent hook does not prevent cleanup because removal
only reduces reachability. A foreign hook, unreadable slot, or replaced pin
returns `StateIndeterminate` before any cross-map query or mutation.

`GtpuProbe::egress_dscp_marking` and `GtpuProbe::per_bearer_marking` report
`Unknown` while a capable environment awaits its first device attach. DSCP
becomes `Available` only when the exact uplink path is live; per-bearer marking
requires both exact uplink and downlink programs and all exact default and
marked map pins. Runtime program or map identity loss reports `Missing` and
blocks new marked state publication, while identity-safe cleanup remains
available under the rule above.

### Pinned-map and live-program migration

The v2 schema is additive. The legacy `GTPU_UPLINK_FAR`,
`GTPU_UPLINK_DSCP`, and `GTPU_DOWNLINK_PDR` names, key/value sizes, and default
bearer encodings are unchanged; marked FAR, DSCP, PDR, and owner-journal state
lives in four new maps: `GTPU_ULM_FAR`, `GTPU_ULM_DSCP`, `GTPU_DLM_PDR`, and
`GTPU_M_OWNER`. With `bearer_mark: None` and `egress_dscp: None`, uplink GTP-U
bytes remain byte-for-byte compatible. The owner lookup is skipped on the
mark-zero uplink path. The only intentional default-path behavior change is
the downlink mark-zero metadata normalization described above.

A durable v2 value at the reserved impossible-PAA key in the legacy FAR map is
the schema commit. It is written atomically only after all named map identities
are verified and both v2 tc programs have been attached and read back by exact
program ID. A committed v2 marker with a missing required pin, an unknown
marker, or a foreign tc occupant fails closed before Aya can recreate empty
state. A positively absent current hook may be repaired. The older v1 loader
does not recognize the v2 marker, which prevents an accidental downgrade.

Live v1 adoption is authorized only by the frozen
`bpf/opc-gtpu-datapath-v1.bpf.o` fixture. It is the DSCP-generation artifact
from commit `4fd43cf1465a46b6afa35348b2463fa9c497fce4`, with SHA-256
`f31ccc2914f2fd61ae8f1e892e9ac0342f9e81350a4a065d5d8dcfcc9f7a943f`.
The loader binds that object to the exact retained v1 map IDs and compares the
live program name, type, tag, and complete map-ID set before replacement. The
fixture is migration authority only; it is never selected as the running v2
datapath. CI verifies its hash and old-only program/map inventory.

Classic-tc replacement uses Aya's atomic `attach_to_link` netlink path, not a
detach-then-attach window. Both hook occupants are proven before either is
touched. If the second replacement is uncertain, the first exact v2 hook is
retained and the exact old/current second hook is left for an idempotent retry;
the migration returns `StateIndeterminate` instead of creating an empty live
slot. The same retained, retryable rule applies if schema or runtime-state
commit fails after replacing an existing datapath. Fresh provisioning still
rolls back a first hook that it created in an originally empty slot.

All mutations through clones of one backend are serialized as one
reconciliation. Independently constructed backends and processes
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

Provisioning also reconciles a failed classic-tc attach acknowledgement against
the live slot. An exact newly loaded program is adopted with a kernel-owned
handle. A fresh transaction may clean up only when its originally empty slot is
subsequently proven empty and no desired hook remains. Every other uncertain
read, attach, replacement, or rollback retains the exact resources that can
still be identified and returns `StateIndeterminate` for an idempotent retry.
Fresh-pin cleanup re-proves every held map ID against its named path. Its
transaction proof applies only to a fresh pin set: a static foreign filter
predates and cannot reference the new map IDs, and this does not claim safety
against concurrent external mutation. Pre-existing pin sets and every
indeterminate outcome are retained for inspection.

Classic tc netlink deletion and bpffs pathname unlink have no conditional
delete-by-object-ID primitive. The abstract-socket reconciler lease is therefore
the safety boundary: every SDK, operator, and maintenance writer of these tc
slots or pin paths must acquire/observe that exclusive boundary. Uncoordinated
concurrent `tc` or bpffs mutation is unsupported. During explicit
`remove_device` teardown, a netlink-uncertain first detach, any second-hook
failure after the first was removed, or any post-detach pin mismatch/unlink
failure returns `StateIndeterminate`; an operator must then inspect and
reconcile both hooks and all named pins before retrying.

The eBPF map and wire layouts live in `opc-gtpu-ebpf-common`. The standalone
`opc-gtpu-dataplane-ebpf` program crate contains verifier-bound kernel access.
Aya exposes a safe mark setter but no getter, so reading the ingress mark uses
one isolated, aligned `__sk_buff::mark` context-field read there; payload bytes
and application memory are not read through that operation. The userspace
`opc-gtpu-dataplane` crate remains entirely safe Rust. Its committed current
object is embedded from
`crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o`; the frozen v1 object is
retained only for the exact migration proof described above.

## Status And Limits

- This is an unpublished workspace crate (`publish = false`).
- The userspace crate forbids `unsafe`; raw kernel UAPI work is isolated in
  `opc-linux-gtpu-sys`, while verifier-bound packet/map/helper access and the
  isolated ingress-mark read remain in the standalone eBPF program crate.
- The Linux netdevice backend follows mainline `gtp` behavior and is not the
  ePDG uplink datapath.
- The eBPF backend requires bpffs, kernel BTF, tc/eBPF privileges
  (`CAP_NET_ADMIN` and `CAP_BPF` or `CAP_SYS_ADMIN`), and enough MTU headroom
  for 36 bytes of outer IPv4/UDP/GTP-U headers. The current object also uses
  the bounded `bpf_loop` helper (available in mainline Linux 5.17 and newer)
  to checksum the complete declared UDP range without verifier unrolling; the
  repository's documented production node profile remains Linux 6.8 or newer.
- The ignored privileged eBPF proof additionally requires the `gtp` and
  `wireguard` kernel modules plus `ip`, `tc`, `ethtool`, `nft`, `wg`, and
  Python 3. CI preflights and installs these prerequisites. A platform without
  them is explicitly unavailable for this proof; an ignored or skipped run is
  not positive datapath evidence.
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
sudo modprobe wireguard
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test linux_gtpu_privileged -- --ignored --nocapture'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test ebpf_gtpu_privileged -- --ignored --nocapture'
```
