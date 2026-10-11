# opc-gtpu-dataplane

## Purpose

`opc-gtpu-dataplane` is the safe Rust control surface for OpenPacketCore
GTP-U dataplane state. It models GTP devices and PDP contexts, provides Linux,
eBPF, mock, and unsupported backends, and keeps raw syscalls in
`opc-linux-gtpu-sys`.

The crate does not implement GTP-C, PFCP, namespace management, route steering,
XFRM policy, deployment defaults, or traffic-readiness policy.

## Experimental N3 packet and intent boundary

The `n3` module keeps received uplink UPF TNL information separate from
locally supplied downlink N3IWF TNL information. `N3ForwardingIntent` records
those directions and a caller-selected QFI/complete-mark association; it is
not an authorized install request or readback receipt. `N3ForwardingRole` is
separate from the Linux GTP netdevice role.

`N3UplinkEncapsulation` appends a canonical G-PDU with one uplink PSC using
the existing `opc-proto-gtpu` encoders. `N3PacketView` borrows a complete
G-PDU and exposes validated direction/QFI/RQI/PPI metadata and an opaque
nonempty inner payload. It rejects trailing datagrams, duplicate/missing PSC,
unsupported required extensions, zero TEID, and direction mismatches. Parsing
does not authenticate a packet or establish session/selector ownership.

`GtpuSessionEntry::from_n3` projects an intent into the existing grouped
selector-authority path. The eBPF attachment can expose
`n3_fixed_flow_capability`: one fixed QFI per inner-family entry, uplink PSC
insertion, matching downlink PSC, complete bearer marks, and exact atomic
generation readback. Installation and retirement require the protected opaque
selector namespace. See [fixed-flow forwarding](../../docs/n3-fixed-flow-forwarding.md)
for the wire layout, native evidence and limits.

`send_n3_end_markers` consumes an exact retired claim and submits markers on
the original IPv4 tunnels after classifier quiescence. It reuses the managed
UDP/2152 control socket. Its completion reports local submission; it grants
no selector reuse or peer-delivery authority. See
[End Marker retirement](../../docs/n3-end-marker-retirement.md) for unsupported
profiles, cancellation, retry and ordering limits.

All shipped adapters still return `GtpuCapability::Missing` from the broader
`n3_forwarding_capability(N3ForwardingRole::N3iwf)`. Multiple QFIs for the same
PAA, reflective QoS, in-place QFI replacement and full-profile End Marker
support remain unavailable. Linux kernel-GTP, mock and unsupported
adapters return `Missing` for the new attachment-scoped capability. The software
packet helpers alone confer no install authority; see [N3 conformance](CONFORMANCE.md).

## Grouped device shutdown for retained restart

`EbpfGtpuDataplaneBackend::suspend_grouped_device` detaches both exact owned tc
hooks while preserving the complete map graph and selector-authority markers.
Use it after stopping producers when a protected grouped namespace must reopen
its existing ledger. Success invalidates the backend's old managed attachment;
recreate the exact stable device/endpoints and open the retained authority before
resuming group work. Active and retired history remain subject to the existing
ownership and selector-reuse checks.

Ordinary `remove_device` still detaches and unpins its graph. It is unsuitable
for a protected namespace that must retain kernel history across restart.
Suspension refuses ordinary, cleanup-only and unadmitted successor handles,
foreign hooks, replaced pins and incomplete identities. Cancellation before
dispatch has no effect; after dispatch the owned worker completes under the
operation/namespace locks. Partial detach remains an error with pins retained.

This operation does not restore missing maps, relocate used authority to a new
control root, reset a namespace, or prove packet continuity. The privileged
dual-stack lane checks exact map-object preservation and retired-history reopen.
The `selector_retained_restart` example additionally reopens an encrypted,
file-backed ledger with active and retired groups. Run it only through an
isolated, operator-authorized Linux mount/network namespace with private bpffs
and the documented synthetic interface; it is not a live deployment command.

## API Shape

The experimental protected selector coordinator exposes an explicit
`relocate_never_admitted_protected` operation for a namespace whose complete
permanent ledger proves no group has ever been admitted or sealed. It retains
the same ledger and secret, commits an exact replacement before its backend
effect, and resumes only that replacement after interruption. Ordinary open
and provision operations remain strict. Any prior session history excludes
this operation; it is not general restart or packet-continuity recovery. See
[RFC 018](../../docs/rfc/018-never-admitted-selector-relocation.md).

The [`control_port` module](docs/control-port.md) adds bounded control
datagrams and response plans on the existing Linux IPv4 reassembly socket.
One consumer shares its UDP/2152 queue with user-packet reassembly. Plans
preserve message-specific response tuples and require the exact receiving
socket; admission and aggregate rate policy remain with the caller. This
does not yet expose Linux kernel-GTP sockets or qualify backend parity,
End Marker ordering or N3 forwarding.
On an eBPF attachment, `try_receive_downlink` on the same port is the
backend-authoritative consumer for kernel-reassembled and handed-off G-PDUs:
it authorizes against the backend's own grouped and v5 maps (commit read
last) and returns the exact inner packet and bearer mark, or a value-free
drop.

**Raw injection requires consumer-owned containment:** retain a lower-priority
outbound block policy over the subscriber pool for the entire lifetime of the
plaintext source, with `disable_xfrm=0` on both `all` and the egress device,
and no higher-priority intersecting plaintext bypass. A namespace default
outbound block is another option for non-loopback output, at the cost of
explicit policies for every other permitted non-loopback flow.
`GtpuDownlinkInjector::raw_ipv4()` injects
`Decapsulated` or `Fragmented` outcomes using `IP_HDRINCL`, `IP_NODEFRAG`, the
exact bearer mark and the inner source through `IP_PKTINFO`. It sends fragments
in order. A policy query cannot be an atomic containment receipt; losing the
block between a query and a send can leak plaintext. The injector installs and
queries no policies.

Zero-ID non-DF fragments and batches are refused with a typed error and
counter. A batch with zero ID is one re-fragmented piece of an origin-fragmented
datagram, so inventing an ID cannot agree with its separate siblings. The raw
path loses that datagram; the interface-bound contract in issue #1085 has no
such limit. Keeping DF on pieces from a DF-fragment source would preserve zero
through raw output. Choosing those flags belongs to the fragmenter and its MTU
policy, not the injector. Non-initial fragments match `ct state invalid` with
`IP_NODEFRAG`, so an output filter can refuse them.

The constructor probes mark privileges; send errors distinguish would-block,
MTU, buffer, policy/filter and access-denied failures. Raw block and MTU refusals
return local errors; the native all-device trace observes no generated ICMP
with a usable route toward the inner source. Partial acceptance means the datagram
is lost; no remainder can be resumed through this API. Success is local
acceptance, not protection or delivery proof. `GtpuDownlinkInjectionPort` and
the outcome factories in `testkit` support consumer fakes. See
[raw IPv4 injection](docs/control-port.md#raw-ipv4-injection).

`GtpuDownlinkInjector::xfrm_interface_ipv4(ifindex, if_id)` adds an optional
interface-bound contract for consumers that scope their policies and SAs to a
nonzero XFRM interface ID. It binds once to a validated XFRM device, preserves
every validated IPv4 byte including zero-ID fragments, and prevents plaintext
fallback of the original packet when policies/SAs disappear, routes change,
or the bound device is replaced. Missing policy/SA and DF path-MTU failures can
still emit ordinarily routed ICMP errors containing plaintext quotes. The
consumer must continuously retain output containment for those errors; the
guide provides a verified rule scoped to the quoted subscriber pool.
Construction detects device replacement across its identity reads and bind.
The consumer owns the interface and privileged configuration; send success
still means local acceptance and can accompany a kernel drop. See
[interface-bound IPv4 injection](docs/control-port.md#xfrm-interface-bound-ipv4-injection)
for the interface-ID migration, ICMP rule and output-hook differences. All inner
packets match `ct state invalid` at POST_ROUTING, so invalid-drop rules there
drop them. A receive filter installed before bind keeps the send socket's
queue empty. Missing/retired and down devices have named refusal classes.

With an optional per-context `GtpPdpContext::downlink_inner_mtu`, tc
steers an over-MTU DF downlink IPv4 packet to a dedicated backend-owned queue
instead of letting the host drop it with its own error. The consumer then
applies the context's RFC 4459 policy:

- **Default** (`GtpuDownlinkInnerMtu::new`): clear DF and fragment the inner
  packet before encapsulation (RFC 4459 section 3.4). `try_receive_downlink`
  returns RFC 791 fragments of at most the MTU, with the bearer mark, for the
  caller to inject toward XFRM; the UE reassembles them. Fragmenting a DF
  datagram is an owner-approved deviation from RFC 791, RFC 1191 and RFC 6864
  DF semantics, and the originator's PMTUD never learns the tunnel MTU.
- **Opt-in** (`GtpuDownlinkInnerMtu::in_tunnel_packet_too_big`): drop the
  packet and signal it at most once inside the UE's default-bearer uplink
  G-PDU (RFC 1191). The error's source is the subscriber's own PAA, the only
  address the PGW's anti-spoofing admits; this departs from RFC 1812 4.3.2.4,
  and the originator attributes the error to the subscriber.

Inner IPv6 contexts refuse both policies: IPv6 has no in-network
fragmentation (RFC 8200).

Under either policy, tc also steers every other inner IPv4 fragment of such
a context (More Fragments set, or a non-zero fragment offset) to a second
backend-owned queue, and `try_receive_downlink` returns it as `Decapsulated`
with its bearer mark. A fragment that exceeds the MTU with Don't Fragment set
follows the policy above. All fragments of one datagram then leave through
the caller. Before it returns any inner IPv4 packet, the consumer validates the
header as the kernel's IPv4 input does for a packet that tc decapsulated, and
trims octets after the total length; a packet that fails is dropped.
Otherwise a datagram could be split between the consumer, which
receives a fragment whose G-PDU was fragmented on the outer path, and the
host's forwarding path, where netfilter connection tracking holds the rest
until it expires. A returned fragment is authorized like any G-PDU and takes
no rate-limit token. Each hand-off queue is bounded by its own socket receive
buffer, and the two are served in turn, so a flood of fragments cannot
displace over-MTU packets. A packet above the MTU without Don't Fragment is
still returned unfragmented (#1023).

Open the control port right after creating or adopting the attachment, and
keep draining it. While its queues are not bound, tc drops the steered
packets and counts them (`downlink_missing_consumer`), so the host answers
none of them with an ICMP error toward the peer, and they are not forwarded.
MTU-bearing contexts must be drained before an SDK downgrade. See
[control port](docs/control-port.md).

- `GtpuDataplaneBackend`: async port for device and PDP lifecycle, typed PDP
  readback, classified installation, authority-safe exact removal, and probes.
  New trait ports retain default unsupported bodies for third-party backend
  compatibility. Grouped request construction is intentionally source-
  breaking: production callers now enter through the protected selector
  coordinator and cannot construct fresh/reused authority themselves.
- `LinuxGtpuDataplaneBackend`: safe adapter over the Linux `gtp` netdevice and
  GTP generic-netlink family.
- `EbpfGtpuDataplaneBackend`: tc `clsact` eBPF datapath adapter for
  uplink-capable access-gateway roles where the mainline `gtp` netdevice cannot
  select PDP context by inner source address. Its `datapath_snapshot` method
  returns identity-bound aggregate counters from the exact live programs and
  pinned map. `managed_device_inventory` returns a mutex-coherent view, ordered
  by ifindex, of only the managed interface names and indexes, bounded by
  `MAX_EBPF_MANAGED_DEVICE_IDENTITIES`; typed completeness tells callers when
  absence from that view is inconclusive.
- `MockGtpuDataplaneBackend`: deterministic in-memory backend with operation
  capture and failure injection.
- `UnsupportedGtpuDataplaneBackend`: reports unsupported-platform results while
  preserving trait-object usage on non-Linux or disabled builds.
- Model exports include `CreateGtpDeviceRequest`, `GtpDevice`,
  `GtpPdpContext`, `GtpBearerMark`, `RemovePdpContextRequest`, `Teid`,
  `GtpuProbe`, `GtpuBackendKind`, `GtpuCapability`,
  `GtpuDownlinkEndpoint`, `GtpuSourcePortPolicy`, `GtpuSourcePortRange`,
  `PdpContextSelector`, `PdpContextReadback`, `PdpContextInstallOutcome`,
  `PdpContextRemovalOutcome`, `PdpContextConflict`,
  `PdpContextMismatchField`, `PdpContextIndeterminateReason`, and
  `PdpContextReconciliationCapabilities`, `CurrentEbpfGraphRecoveryRequest`,
  `CurrentEbpfGraphWriterProof`, `CurrentEbpfGraphDrainProof`,
  `CurrentEbpfGraphRecoveryOutcome`, `CurrentEbpfGraphRecoveryRefusal`, and
  `CurrentEbpfGraphRecoveryProgress`,
  `HistoricalEbpfGraphGeneration`, `HistoricalEbpfGraphRecoveryRequest`,
  `HistoricalEbpfGraphRecoveryIntent`, `HistoricalEbpfGraphRecoveryAuthority`,
  `HistoricalEbpfGraphRecoveryCurrentnessGuard`,
  `HistoricalEbpfGraphWriterProof`, `HistoricalEbpfGraphDrainProof`,
  `HistoricalEbpfGraphRecoveryReceipt`, `HistoricalEbpfGraphRecoveryOutcome`, `HistoricalEbpfGraphRecoveryRefusal`,
  and `HistoricalEbpfGraphRecoveryProgress`,
  `GtpuLocalEndpointSet`, `GtpuSessionAttachmentSelector`,
  `GtpuSessionGroup`, `GtpuSessionGroupReconcileRequest`,
  `GtpuSessionSelectorProvenance`, and `GtpuSessionSelectorReuseProof`,
  `EbpfGtpuDatapathSnapshot`, `EbpfGtpuDatapathCounters`, `DscpCodepoint`,
  `EbpfManagedDeviceIdentity`, `EbpfManagedDeviceInventory`,
  `EbpfManagedDeviceInventoryCompleteness`,
  `MAX_EBPF_MANAGED_DEVICE_IDENTITIES`, `GtpRole`, `GtpVersion`,
  `GtpAddressFamily`, and `GTPU_PORT`.
  The provenance and reuse-proof exports are read-only backend projections,
  not authority: their production constructors and request constructors are
  SDK-private, and every effect additionally consumes an opaque admission.
- `TftUplinkClassifier` is a backend-neutral, bounded classifier contract for
  multiple GTP-U contexts sharing one PAA on an unmarked uplink packet path. It
  uses the canonical `opc-proto-tft` model, accepts only complete
  uplink-capable TFT snapshots and packet-filter components the
  backend-neutral parser can represent (including IPv4 and IPv6 semantics),
  and returns a pre-existing bearer mark or a silent drop. The unfiltered
  bearer is the explicit default fallback for a valid no-match; absent one,
  no-match packets drop. The stateless packet-only classifier always rejects
  malformed, fragmented, unsafe-to-parse, and foreign-PAA packets. The native
  unmarked IPv4 path additionally supports
  [bounded fragment affinity](#bounded-inner-ipv4-tft-fragment-affinity).
  Its typed `TftUplinkPaaSet` holds at most one IPv4 `/32` and one canonical IPv6
  `/64`; any inner source inside the IPv6 prefix matches, and an IPv4v6 PDN
  uses one classifier for both families. The native eBPF ABI remains
  IPv4-only and rejects an IPv6 or dual-family set.
  `GtpuDataplaneBackend::tft_uplink_classification_capability` is separate from
  `per_bearer_marking`: a backend must not advertise it until its actual
  dataplane program and exact readback ABI support it. The deterministic mock
  implements exact install, idempotence, atomic self-owned replacement,
  readback, and exact removal lifecycle proof. A differing complete
  self-owned snapshot is replaced without a transient absent or wrong-bearer
  publication; foreign ownership conflicts and partial, mixed, or stale state
  is indeterminate. Native exact removal first publishes a SHA-256-bound
  metadata tombstone, removes only canonical rows under the current
  authority, and removes the tombstone last. The tc program classifies a
  tombstone whose classifier has a default bearer as absent, so default-bearer
  uplink continues through removal without any row being read. A fragment with
  retained affinity instead drops on the now-stale identity; it cannot use
  that default fallback. A tombstone without a default bearer drops. Before
  deleting any row, each removal attempt waits for every tc invocation that
  could have copied the active selector before the tombstone. The adapter
  prefers the qualified GLOBAL membarrier grace. If GLOBAL is unavailable,
  including on `nohz_full`, TFT uses a successful userspace update of a private,
  unpinned ARRAY_OF_MAPS.
  The reviewed kernel path waits for a full RCU grace for non-sleepable TC
  readers. This fallback requires the recognized non-realtime SMP build
  profile and Linux 6.8–6.19, 7.0–7.2, or `5.14.0-427.*el9_4*`; object
  loadability and exact graph/schema readback remain separate prerequisites.
  Both private map creation and a real update must succeed before the fallback
  is offered, and every reclamation performs a fresh wait. Reusing a retained
  inactive bank also waits before deleting or overwriting its rows. Where
  neither grace is qualified and usable, TFT classification reports `Missing`,
  and both reconciliation that
  would install or replace a classifier and exact removal refuse with
  `UnsupportedFeature` before any mutation, leaving any published classifier
  complete. A wait that fails after the tombstone is published deletes
  nothing and returns `Indeterminate` for a retry; a failed bank-reuse wait
  preserves both banks and the active selector.
  `tft_uplink_classification_unavailable_reason` adds a value-free diagnostic
  reason without granting mutation authority. PREEMPT_RT, unreviewed fallback
  releases, and unknown build profiles remain refused. This does not change
  grouped-selector grace or qualify sleepable BPF, packet drain, or latency.
  See the [kernel grace contract](../../docs/rfc/016-opaque-gtpu-selector-namespace.md#tft-reader-grace).
  Its durable
  dense-rank cursor authorizes each active-row deletion before it occurs, so a
  retry accepts only the exact remaining suffix plus any acknowledged-loss
  rows in the authorized prefix; an unexplained missing row fails closed.
  Retries also prove the exact fingerprint. This fingerprint is a consistency proof, not
  authentication against a privileged raw map writer. Native eBPF TFT
  adoption rejects partial pin graphs and promotes an all-zero schema marker
  only after the metadata, filter, and fragment-affinity maps are proven empty
  before hook mutation and rechecked empty immediately before publication.
  Native eBPF TFT classifier ABI/schema v5 remains IPv4-only: filter-map keys
  include the current owner and snapshot generations, and each value carries
  its dense precedence rank. TC therefore finds only rows named by validated
  metadata; exact userspace readback verifies the redundant value identity and
  rank.
  This is a consistency boundary, not protection from a privileged actor that
  can co-mutate raw maps. IPv6 PAA, IPv6 components, and flow-label filters
  are rejected before any map mutation. This contract does not claim IPv6
  native packet execution. Linux `gtp` and unsupported adapters
  fail closed as unsupported rather than simulate packet proof.
- `GtpuError` is intentionally redaction-safe; TEIDs and addresses are not
  emitted by `Debug`/`Display`. A `BPF_PROG_LOAD` failure is reported as one of
  two variants, preserving only its stable operation, I/O kind, and errno:
  - `GtpuError::ProgramLoadRejected` -- the kernel reached a verdict. This
    kernel cannot run this object; move the workload or ship a different one.
  - `GtpuError::ProgramLoadRefused` -- the load was refused before the verifier
    ran. The node is fine and will accept the program once the environment is
    fixed. `GtpuError::load_refusal` returns a `ProgramLoadRefusal` saying
    which: `Unprivileged` (`EPERM` -- `CAP_BPF`/`CAP_PERFMON` or
    `RLIMIT_MEMLOCK`), `PolicyDenied` (an LSM denied `bpf { prog_load }`), or
    `Indeterminate`.

  The split exists because aya funnels every `bpf(2)` failure at this boundary
  into one error without inspecting errno, so a missing capability would
  otherwise be indistinguishable from a verifier rejection -- and reporting the
  first as the second permanently excludes healthy capacity.
  `GtpuError::is_verifier_rejection` answers that question directly rather than
  asking callers to reimplement the errno rules.

  Three limits are deliberate, and all three resolve toward *not* condemning a
  node, because that is the direction that costs capacity:

  - `bpf(2)` reports an LSM denial and a verifier rejection with the same
    `EACCES`, so the two are separated by whether the kernel returned verifier
    output, not by errno.
  - Verifier output proves the verifier **ran**, not that it **rejected**. The
    kernel prints `processed N insns` on successful verification too, and
    `bpf_prog_load` can still fail afterwards allocating a program id or an fd.
    A load that verified cleanly and then hit `EMFILE` therefore carries a full
    verifier log while being purely environmental. Verifier output only
    promotes an errno the verifier itself can return (`EACCES`, `E2BIG`,
    `EINVAL`); anything else stays a refusal regardless of the log.
  - Conversely, one of those errnos arriving with *no* verifier output is
    `Indeterminate` rather than a verdict. The loader always retries with a log
    buffer, so a genuine verifier failure cannot arrive silent -- a silent
    `EINVAL` is a failed program allocation under a memory limit, and a silent
    `E2BIG` is the pre-verification instruction-count check, which is itself
    capability dependent.

  Rust also maps both `EPERM` and `EACCES` to `ErrorKind::PermissionDenied`, so
  a failure carrying no errno at all is `Indeterminate` rather than guessed.
  Capability, bpffs, and other I/O failures remain `GtpuError::Io`. The verifier
  log is inspected only to establish that the verifier ran, and is never
  retained.

## Usage

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};

use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpPdpContext, GtpVersion, GtpuDataplaneBackend,
    GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy, MockGtpuDataplaneBackend,
    RemovePdpContextRequest, Teid,
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
        downlink_source_port_policy: GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
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

The attach interface must be the one on which IP input receives the
endpoint's packets. The backend refuses an interface from which another
device takes the frames after tc ran, because tc's decision about a hand-off
would then not describe the delivery:

- an interface whose master is anything but a VRF, such as a port of a
  bridge, a bond, a team or a virtual switch, with
  `GtpuError::UnsupportedFeature { feature: ATTACHMENT_ON_ENSLAVED_INTERFACE }`;
- an interface below a macvlan, an ipvlan, a MACsec device or any other
  device of the namespace that names it as its lower link and is not known to
  leave its frames alone, with `ATTACHMENT_BELOW_STACKED_DEVICE`;
- every interface of a namespace that holds an HSR or PRP device, with
  `ATTACHMENT_IN_NAMESPACE_WITH_HSR_DEVICE`. The kernel does not always
  report the interlink port of an HSR device, so the backend cannot tell
  which interfaces such a device takes frames from; a PRP device is a link of
  the same kind.

Attach to the device that receives instead, for a bridge, bond or team the
master itself. VLAN devices above the interface are accepted. The VLAN device
receives what arrives in its VLAN, and tc's lookup on the interface does not
describe the delivery there, so tc gives a hand-off from there to no socket:
it drops and counts it. For an endpoint that lives on a VLAN device, attach to
that device. `create_device` pins its maps under the interface's name, and
bpffs accepts no dot in a name, so that device needs a name without one.
Ordinary creation, adoption, cleanup-only acquisition, and legacy successor
preparation reject a dotted name with `InvalidConfig { field: "device.name", .. }`
explaining this bpffs restriction before publishing or fencing an attachment.
Grouped attachments created with
`create_device_with_endpoints` use a device-ID pin directory and accept dotted
interface names. See
[control port](docs/control-port.md#hand-offs-need-a-bound-consumer) for what
is and is not enforced; a device that is stacked on the interface from
another network namespace is not detected.

### Generation-fenced traffic-continuity proof

`GtpuDataplaneBackend` exposes an additive, session-scoped traffic-proof port.
Only the production `EbpfGtpuDataplaneBackend` can implement that port;
structural reconciliation, object readback, aggregate counters, the mock
backend, and unsupported adapters cannot mint a proof. The ownership boundary
is one complete `GtpuSessionGroup`, matching the unit whose entries and indexes
are activated under one dataplane generation. It is not a pod-wide aggregate
and evidence from separate groups is never combined.

The product begins an attempt with the exact desired group, its nonzero owner
generation, a nonzero 128-bit reconcile fence, a nonzero reconcile revision,
and an immutable `TrafficContinuityPolicy`. The dataplane generation is never
caller supplied: the adapter obtains it from a stable, complete `Active`
group readback and binds it into the private attempt. A successful proof retains
all of those dimensions plus the exact device attachment, backend incarnation,
observation-source epoch, and monotonic-clock origin. Validation repeats the
live readback under the adapter's writer authority; equality of a previously
read object is not sufficient.

Native traffic observation and fragment-namespace empty proofs assume the
backend runs without a time namespace: userspace `CLOCK_BOOTTIME` must share
the kernel boot-clock origin used by tc. Time-namespace offsets are unsupported.
In particular, a positive offset can make live fragment slots appear expired
to an empty proof, while a negative offset can delay acceptance of expired slots.

When reconciliation changes the exact desired group, callers consume a lease
from the canonical store with
`GtpuDataplaneBackend::rebind_gtpu_traffic_proof_authority` only after the
normal grouped reconcile succeeds. Rebind closes the old authority gate before
waiting for existing leases, retires old attempts and registrations, performs
one final exact active readback of the new group, and only then publishes the
new authority. A failed, canceled, stale, or concurrently mutated rebind
leaves the old authority terminal and never reports an authority gap as traffic
evidence. The trait's inherited implementation first authenticates the store
and lease as belonging to that backend. A production-proof wrapper may delegate
that ownership check and will terminally revoke before returning
`UnsupportedFeature`; a mock, unsupported, or foreign backend cannot establish
ownership and returns unsupported without mutating another backend's authority.
The publish transaction is crate-private, so only SDK-owned trusted adapters
can complete rebind.

For an unchanged canonical authority, `renew_gtpu_traffic_proof` starts a new
assessment while the predecessor remains valid through its original expiry.
Pass the current opaque proof and a lease from the same registered store. The
eBPF adapter retains at most two attempts for that group, inside its existing
global capacity: one issued predecessor and one successor. The successor gets
a fresh registration, publication identity, secret and sample stream; it must
collect its own paired bidirectional observations. Its traffic cannot extend
the predecessor's assessment. Ordinary `begin_gtpu_traffic_proof` still
supersedes the group's existing attempts.

Keep the predecessor session until the successor has yielded an opaque proof
and the product has validated and published it under its current guards. Then
close the predecessor before another renewal. This exact cleanup cannot delete
the successor registration. During collection, validation of the predecessor
checks the SDK-owned successor relation and its current registration, source,
attachment, group and canonical authority. Old challenges cannot prove the
successor. Source loss, malformed or stale observations, hook drift and
authority replacement still fail closed; no positive readiness flag is cached.

Cancellation before session delivery leaves one pending successor recoverable
by repeating renewal with the same current predecessor. No third registration
is allocated. Closing or dropping the predecessor retires an undelivered
successor; after delivery the new session owns its own cleanup. Expiry during
the async handoff refuses delivery, and the caller must close the predecessor
before beginning a fresh assessment. Failed publication remains terminal and
exactly recoverable; renewal does not promise continuity across an uncertain
kernel effect. Unsupported backends inherit a fail-closed default.

Scheduling early enough to gather the replacement observations, publishing
under product guards, and qualifying uninterrupted readiness remain CNF
responsibilities. The renewal tests exercise the adapter with a fake runtime;
they are not live packet-forwarding or carrier qualification evidence.

The product drives an authenticated ICMP Echo challenge through the live
session by calling `GtpuTrafficProofSession::challenge` with a distinct nonzero
sample ID. The sample's high and low 16-bit halves are the exact ICMP Echo
identifier and sequence. Every request starts `CoreToAccess`; accepting an
`AccessToCore`-initiated request would expose its private return capability on
the untrusted core side and is therefore deliberately unsupported. The public
fixed-size request payload commits to the attempt's private registration,
publication identity, sample, identifier, sequence, and request role.

### Independent core-side challenge delivery

`GtpuDataplaneBackend::dispatch_gtpu_traffic_proof_challenge` is the production
delivery boundary. The caller supplies its affine session, an independent
`GtpuTrafficProofDispatchPort`, one inner address family present in the exact
live group, and a distinct nonzero sample. While holding the canonical
authority-version lease, the SDK selects that group entry and builds the
complete plain G-PDU plus optionless/unfragmented IPv4 or base IPv6 ICMP Echo
Request with materialized checksums. After route resolution and construction,
the owning backend performs a final revalidation of the exact attempt,
authority-store version, dataplane generation, observation source, and
readback before any transport effect. It never accepts caller-provided PAA,
TEID, group, generation, challenge tag, or packet bytes.

The port resolves one atomic deployment-configured
`GtpuTrafficProofDispatchRoute`; the SDK checks its core origin, exact
access-side destination (including a full IPv6 IID within the selected PAA),
and outer source port against the selected entry before handoff. The request is
opaque and redacted in diagnostics, although its transport implementation can
read its exact packet and route solely to send it. The SDK defines no local
ingress, AF_PACKET, or tc self-injection fallback: the default
`UnsupportedGtpuTrafficProofDispatchPort` fails closed, and deployments must
place their port on an independently trusted core-side path.

A `GtpuTrafficProofDispatchReceipt` means only local transport handoff. It is
not delivery, continuity, or proof evidence, and cannot advance or mint a
`GtpuTrafficProof`. After handoff begins the sample is retired—even on a
transport error or canceled caller future—because a remote send cannot be
retracted honestly. The session bounds this retired-sample ledger by its
continuity policy. Separate monotonic gates bind the current product-authority
version and the individual attempt: closing or completing one attempt does not
revoke a later attempt under the same unchanged product authority. Authority
replacement, group mutation or removal, device detach, backend restart, and
attempt close revoke the applicable gate and cancel a cooperative pending
handoff. Source loss and generation/readback drift observed during final
preflight prevent the port call; if they race an already irreversible remote
send, the next poll or validation invalidates the attempt or proof. No receipt
or stale packet is evidence, so neither can produce a current proof.

After exact packet, checksum, binding, generation, publication, and request-tag
validation, the trusted downlink tc program replaces the public request tag
with a distinct private return tag and repairs the ICMP checksum before the
packet enters the access-side stack. The ordinary ICMP Echo Reply copies that
private tag. The trusted uplink program accepts only that private-tagged reply,
with the exact identifier and sequence. It never exposes the private payload in
the supported product API, event ABI, product readback, log, metric, or
diagnostic. The unpublished low-level common crate carries the secret-bearing
registration only through its hidden trusted loader/tc map ABI; that privileged
wire boundary is not re-exported here. Consequently,
copying the public request into a syntactically valid reply cannot fabricate a
return leg. Ordinary subscriber TCP, UDP, ICMP, counters, structural readback,
and mock packets never mint proof evidence.

Direction is relative to the access gateway and describes the two halves of a
validated challenge round trip:

- `AccessToCore` is emitted only after a grouped inner packet has been
  successfully submitted to the local GTP-U uplink redirect.
- `CoreToAccess` is emitted only after a grouped G-PDU has passed the live
  downlink checks, been decapsulated, and been accepted past the local tc
  ingress hook into the access-side network stack.

These are authenticated challenge observations at the local forwarding
boundaries, not peer authentication or a claim that a remote endpoint received
the packet. The private return tag is a one-attempt bearer capability. The
proof is sound when the trusted downlink rewrite feeds immediately into the
product's protected access path; a principal that can inspect plaintext after
that rewrite, or a compromised peer, is outside this proof's trust boundary.
An end-to-end claim must compose this boundary proof with protocol-specific
delivery authority and a disposable real protected-path round trip. The
observation ABI carries no addresses, TEIDs,
SPIs, packet lengths, packet bytes, subscriber fields, or reusable raw flow
identifier. Its challenge-stream correlation is opaque, freshly keyed per
attempt, and never logged. Parsing accepts only exact, unfragmented IPv4 or
IPv6 ICMP Echo messages with the fixed challenge payload, exact Echo header
fields, and valid network/transport checksums; other protocols, fragments,
malformed messages, and trailing bytes continue through normal forwarding
policy but do not contribute proof evidence.

Continuity is deliberately policy-bound instead of inferred from one packet or
from aggregate traffic. One authenticated challenge stream must independently
have at least `minimum_samples_per_direction` observations in both directions, and each
direction's first-to-last span must be at least the nonzero
`minimum_window_per_direction`. The last sample in each direction must be no
older than `maximum_freshness`, every retained sample must fit within
`maximum_evidence_age`, and storage is capped by `maximum_retained_events`.
The retention cap must hold at least the minimum sample count for both
directions combined, so a constructed policy is achievable.
The product selects these nonzero bounded values for its operational readiness
window; the proof retains the exact policy so a weaker assessment cannot be
relabeled under a stronger one.

The production adapter drains the attachment's bounded kernel ring, rejects
malformed or excess records, and brackets every drain with the saturating
per-CPU loss counter. Only after that producer-gap fence succeeds does it sort
trusted boot-monotonic timestamps, breaking valid cross-CPU clock ties with a
distinct global producer sequence. A reused sequence or replayed record fails
closed. The sequence may be sparse, so it does not replace the kernel loss
counter: that independently bracketed counter is the authoritative
producer-gap fence.

Each registration also receives a finite, monotonically allocated publication
identity retained in the pinned attachment state. It remains a capacity and
same-graph replacement fence: the downlink path captures it before
decapsulation and verifies it again at the final observation boundary. Source
reset never rewinds that allocator, invalid or uncertain readback burns the
candidate identity, and exhaustion fails closed. Publication readback alone is
not packet-causal: the per-attempt challenge tag additionally prevents a
packet queued under an earlier registration from being relabeled when it is
processed after a replacement.

Uplink neighbour redirect uses a separate `GTPU_OBS_REDIR` authority: the
registration's private CSPRNG-filled correlation secret is reused as the exact
per-attempt redirect nonce, and the 20-byte tc scratch area contains only an
ownership marker plus all 16 nonce bytes. The nonce is never logged, emitted,
or exposed as a metric; event correlation is instead a one-way keyed
derivation from that secret. At publication the host atomically installs and
reads back `nonce -> group` with `BPF_NOEXIST` alongside the exact group
registration. Re-entry resolves the nonce through that map and then requires
an active exact group registration with matching binding, publication identity,
and nonce before emitting. Revocation and source reset delete both maps and
prove them empty. Thus a delayed skb from an unpinned graph cannot be relabeled
after a fresh graph restarts its finite publication sequence at one:
publication high-water alone does not span graph recreation, while the fresh
nonce closes that ABA without relying on queue quiescence.

Proof lifetime is a half-open monotonic interval. Its exclusive end is the
earliest of issuance plus `maximum_assessment_lifetime`, either direction's
last sample plus `maximum_freshness`, and the oldest retained sample plus
`maximum_evidence_age`. The adapter reads Linux boot-monotonic time itself;
caller time never validates a proof. Expiry,
event loss, malformed or overflowing observation state, a registration or
source reset, backend restart, group restore, any generation/phase/model/index
change, reconcile-fence drift, attachment or pinned-map/hook replacement, or
an indeterminate readback permanently invalidates the attempt or proof. A
fresh attempt uses a new source epoch, correlation key, and publication
identity plus a newly authenticated challenge payload, so packets queued under
an earlier generation, registration, or process cannot be replayed as current
evidence.

The port reports packet-continuity evidence only. Products must not derive
PodReady, process health, structural convergence, or service admission from
prior subscriber traffic: doing so would deadlock a correctly converged cold
start before its first subscriber packet. A product may use a current proof as
one input to a separate traffic-readiness condition while keeping those
control-plane decisions independent.

### Conflict-safe PDP reconciliation

Use `read_pdp_context` to inspect either the local/downlink TEID axis or the
uplink `(UE PAA, optional bearer mark)` axis. `PdpContextLocalTeidSelector`
requires the address family explicitly so a backend cannot call an IPv4-only
lookup and report an IPv6 context absent. Both selector constructors reject
ifindex zero. `Present` returns the complete typed context needed for equality;
its `Debug` output redacts TEIDs, addresses, marks, and source-port policy.

`install_pdp_context_classified` inspects both desired selector axes under one
backend operation boundary. Its outcomes distinguish a new exact install,
exact state already present, valid conflicting state, and indeterminate
evidence. Conflict diagnostics expose only occupied axes and names of differing
fields, never values. This strict method does not perform the legacy eBPF peer
relocation behavior. A caller that owns a stale eBPF context can first invoke
`remove_pdp_context_exact(stale)` and, only after `Removed`, install the desired
context. Those are two separate operations and therefore have a bounded
forwarding gap; the SDK does not claim atomic replacement.

```rust,no_run
use opc_gtpu_dataplane::{
    GtpPdpContext, GtpuDataplaneBackend, PdpContextInstallOutcome,
    PdpContextRemovalOutcome,
};

async fn converge(
    backend: &dyn GtpuDataplaneBackend,
    desired: GtpPdpContext,
    owned_stale: Option<GtpPdpContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(stale) = owned_stale {
        match backend.remove_pdp_context_exact(stale).await? {
            PdpContextRemovalOutcome::Removed | PdpContextRemovalOutcome::AlreadyAbsent => {}
            _ => {
                return Err("stale PDP context was not proven removable".into());
            }
        }
    }
    match backend.install_pdp_context_classified(desired).await? {
        PdpContextInstallOutcome::Installed
        | PdpContextInstallOutcome::ExactAlreadyPresent => Ok(()),
        _ => {
            Err("desired PDP context did not converge".into())
        }
    }
}
```

The eBPF adapter treats its held reconciler lease, exact tc program identity,
and exact named-map identities as mutation authority. It reconstructs default
and marked contexts only from a complete FAR/PDR/endpoint-binding/DSCP/active
owner graph. A host-only default `(ifindex, UE PAA) -> local TEID` reverse index
is rebuilt from validated pinned current-schema state on adoption and maintained inside the
same serialized publication/removal boundary. It is not a new datapath map and
does not change the pinned schema. Partial graphs, transitional marked owners,
index disagreement, changed observations, a second writer, or lost program/map
identity return indeterminate without deleting state. Exact removal uses the
same authority and confirms both selector axes absent afterward.

The Linux `gtp` adapter uses response-required generic-netlink `GETPDP` queries
for both axes and requires two identical bounded observations. It validates the
kernel origin of every ACK and readback datagram, the outer generic-family
message type, the kernel's historical family-ID-in-command reply quirk (or a
future canonical `GETPDP` command), every known attribute, MS/PAA-family
consistency, selector correlation, and the complete returned identity.
`GTPA_FAMILY` describes only the inner MS/PAA lookup key; the outer peer family
follows the GTP device's UDP socket and may differ. Current kernels may omit
`GTPA_FAMILY`; one unambiguous MS/PAA attribute still determines its family
independently of the required peer attribute. Linux currently stores an IPv6
MS/PAA as a canonical `/64` prefix. A kernel that cannot perform the requested
family lookup fails closed rather than reporting absence. Mainline Linux
exposes unconditional `DELPDP` but no compare-delete primitive, so exact removal
is built on a cross-process recovery authority instead; see the next section.

### Linux kernel-GTP readiness

`probe().mutation_ready` and the `classified_install` reconciliation capability
accept IPv4 UDP/2152 already owned by this backend or its clones. Ordinary
creation may bind any IPv4 address and retains the exclusive userspace socket
through the probe; recoverable creation requires wildcard IPv4 and records the
verified v2 kernel-socket incarnation. Every probe rechecks the current network
namespace and live name/ifindex, plus the exact incarnation for a recoverable
device. Deleted, renamed, replaced or unreadable identity evidence cannot
establish socket ownership.

After restart, successful exact `acquire_retained_device_identity` records the
same kernel-socket ownership. Name-only resolution and PDP cleanup APIs do
not implicitly adopt a device for serving. Kernel ownership records are keyed
by namespace and interface index separately from held userspace sockets;
recoverable creation or acquisition does not replace a held socket at the same
index in another namespace. Removal releases only records whose namespace
matches the namespace captured before deletion. Missing namespace evidence
does not change successful creation or acquisition, but cannot establish
ownership or authorize closing an unproven socket.

Without proven ownership of an IPv4 service socket, the probe still requires
a fresh wildcard bind, so a foreign socket alone cannot establish readiness.
A foreign socket on another IPv4 address does not withdraw readiness for the
backend's proven endpoint. IPv6 sockets and other ports do not substitute for
IPv4 UDP/2152 readiness. Identity read failures also use the fresh-bind path;
they never reuse cached positive ownership and have no separate probe
diagnostic. Read-only probes retain stale records to avoid closing a held
socket after a transient identity failure or rename. Normal matched removal
or dropping the last shared backend reference releases held userspace sockets;
clones and admitted blocking operations retain that shared reference. An
externally deleted userspace-socket device can leave its port occupied until
then. Kernel ownership metadata alone retains no socket descriptor.

Platform, netlink, GTP-module and `CAP_NET_ADMIN` prerequisites remain required.
Probes and the synchronous capability getters wait behind in-flight device and
PDP operations while they revalidate ownership; readiness is an observation,
not a reservation for a later mutation.

### Linux PDP restart recovery authority

`LinuxGtpuDataplaneBackend::recover_pdp_context_exact` is the supported
durable-reconciliation primitive for the process-loss case: the kernel-GTP PDP
context and the GTP device that owns it both survive the writer, and an
ePDG-style consumer must prove either exact removal or exact absence of a
durable descriptor before protocol egress. Mainline Linux has no atomic
compare-delete, so the SDK supplies the missing cross-process writer authority
and the authoritative readback that together make exact removal safe.

Bind the authority before exposing the backend or creating a recoverable
device:

```rust
let backend = LinuxGtpuDataplaneBackend::new()
    .with_pdp_recovery_root("/var/lib/my-service/gtp-recovery")?;
```

`with_pdp_recovery_root` returns `Result`, validates an absolute non-root path,
and records one non-rebindable root in state shared by every existing and future
backend clone. Repeating the same binding is allowed; attempting to bind a
different root fails. Every cooperating process that can write the same GTP
devices must bind the same root. Once it is bound, device creation/removal,
ordinary PDP installation/removal, classified installation, and restart
recovery all acquire cross-process `flock` authority. Topology mutations take
the topology lease; operations against a live device then take its per-device
lease in that fixed order. This fences replacement as well as PDP mutation
rather than protecting only the final recovery transaction.

The root, every ancestor, and the filesystem providing `flock` are trusted,
stable security infrastructure. Do not use a path whose components can be
renamed, replaced, or pre-created by an untrusted principal, such as an
unhardened world-writable `/tmp`. A privileged writer that mutates GTP state
without these locks, or a principal that controls the root or its ancestors, is
outside the supported coordination model; the SDK makes no safety or liveness
claim in their presence.

For each new kernel device incarnation, generate a cryptographically
unpredictable, nonzero `PdpDeviceIncarnation` and durably persist it with the
device's recovery descriptors before performing the create effect. Never reuse
an incarnation. Create the device through
`create_recoverable_device(request, incarnation)`, which stamps and verifies the
incarnation in the kernel link's `IFLA_IFALIAS` while holding topology
authority. It first proves the requested name absent, and reconciles an
ambiguous create acknowledgement before publishing the verified link. It uses
`IFLA_GTP_CREATE_SOCKETS`, so the netdevice rather than the creating process
owns the GTP sockets and a retained link remains serviceable after process
loss. The supported recoverable profile is intentionally limited to
`0.0.0.0:2152` with no userspace-socket fallback; the kernel also reserves its
standard GTPv0 port 3386. Consequently only one wildcard kernel-owned GTP
device can own those ports in a network namespace at a time. A kernel without
`IFLA_GTP_CREATE_SOCKETS` support rejects creation rather than weakening the
contract. Ordinary `create_device` retains its userspace-FD socket and custom
bind-address/port behavior, but does not establish the identity needed for
later exact restart recovery.

The published `opc-pdp-recovery-v2` alias attests this kernel-owned socket
profile as well as the incarnation. A legacy `v1` alias can name a link whose
userspace socket was detached when its creator exited, so retained acquisition
and exact recovery fail closed for it. There is no in-place adoption or alias
upgrade: drain/remove the legacy link and create a fresh recoverable device
with a newly minted incarnation. Process loss before the method returns can
still leave an unstamped link; exact recovery classifies that as structural
repair and never treats it as owned PDP state.

Build `PdpRestartRecoveryRequest` from the durably recorded device name and
ifindex, incarnation, complete expected PDP context, and
`PdpRestartRecoveryProof::previous_writer_stopped()`. Under the topology and
per-device locks, `recover_pdp_context_exact` proves that the name still
resolves to the expected ifindex and that the live kernel `IFLA_IFALIAS`
contains the expected incarnation. A replaced, renamed, unstamped, or removed
device returns `RepairRequired(DeviceIdentityChanged)` without touching its PDP
state. A concurrent lock owner returns retryable
`Indeterminate(AuthorityUnavailable)`.

After proving the device incarnation, recovery takes stable `GETPDP` readbacks
on both selector axes before admitting the unconditional `DELPDP`. Unknown
attributes and any flagged attribute type in a `GETPDP` reply fail closed as
structurally unrepresentable state; they are never ignored to authorize a
delete. Recovery then classifies:

- `Removed` — the resident context matched the complete expected identity, an
  admitted `DELPDP` ran, and the post-mutation readback proves both axes absent.
- `AlreadyAbsent` — both selector axes were already authoritatively absent; no
  mutation occurred. Re-running after a confirmed removal is idempotent.
- `Conflict(_)` — valid resident state occupies a selector but differs from the
  expected identity; it is never touched. Diagnostics carry only occupied axes
  and differing field names, never values.
- `Indeterminate(_)` — state changed during observation, evidence was incomplete,
  or the final mutation could not be confirmed; retry the exact request.
- `RepairRequired(_)` — a structural precondition (for example a stale device
  identity) failed closed; retrying the identical request cannot succeed without
  repair.

The kernel API still cannot compare-and-delete, so the admission boundary is the
authoritative dual-axis readback immediately before `DELPDP`, held under the
two-level authority. Dropping the returned future does not cancel its detached
blocking worker: the worker retains both locks until the transaction finishes.
A concurrent retry is therefore fenced (and may report authority unavailable),
and a later retry re-reads the converged state, making confirmed removal
idempotent as `AlreadyAbsent`. Process exit releases `flock`, allowing the next
retry to reclassify state safely.

The trait method
`GtpuDataplaneBackend::remove_pdp_context_exact(GtpPdpContext)` remains
`UnsupportedFeature` on Linux, and its `exact_removal` capability remains
`Missing`, even when a recovery root is bound. Its request has no durable device
incarnation and therefore cannot authorize restart cleanup. Linux callers must
use the authority-bearing
`GtpuDataplaneBackend::recover_pdp_context_exact(PdpRestartRecoveryRequest)`
method, which is also exposed on the concrete Linux backend; without a bound
root, that method is also unsupported. `Debug` output for the request and every
outcome redacts TEIDs, addresses, and device identity.

Readback/classified-install/generationless-exact-removal capabilities are
reported through `pdp_context_reconciliation_capabilities`; authority-bearing
Linux restart recovery is reported separately through
`pdp_restart_recovery_capability`. They are not inferred from packet-processing
fields in `GtpuProbe`. The mock implements the full stateful
contract for default and marked contexts, exposes `MockPdpContextFault` for
corrupt, transitional, and changing-readback tests, and records the additive
calls separately through `pdp_context_reconciliation_operations`. The original
externally exhaustive `MockOperation` variants remain unchanged.

Calls execute blocking kernel/map work behind an async boundary. Dropping an
in-flight future is not proof that its blocking operation stopped. A caller
must retry through classified readback; deterministic pre-mutation validation,
capability, and permission errors remain errors, while ACK-uncertain or partial
mutation failures are re-read and returned as exact, conflict, or indeterminate
state. Product policy decides which stale context it owns, coordinates drain,
and sequences route/XFRM/session changes.

### Linux live-writer exact PDP removal authority

`LinuxGtpuDataplaneBackend::remove_pdp_context_exact_live_writer` is the
same-process replacement companion of restart recovery. A subscriber-session
replacement must remove the prior session's kernel-GTP PDP context with exact
authority before the replacement dataplane can be proven converged, and during
that ordered teardown the cooperating writer is still live: the product
process, its network namespace, the durable device incarnation, and its
Recovery claim all remain live. Supplying
`PdpRestartRecoveryProof::previous_writer_stopped()` there would assert
something false, and the unconditional lifecycle `remove_pdp_context` cannot
prove exact dual-selector identity, so neither can safely satisfy a
convergence or Recovery mutation proof.

After binding the recovery root, call
`GtpuDataplaneBackend::acquire_pdp_live_writer_proof` on the same concrete
backend that will perform removal (or through its trait object). Acquisition
is the caller's explicit attestation that it is the current cooperating writer
and owns the live mutation namespace; it never claims that a prior writer
stopped. It returns one affine, opaque `PdpLiveWriterProof` bound to the exact
configured root and the current worker thread's network-namespace identity.
Move that proof into `PdpLiveWriterRemovalRequest`; it cannot be cloned or statically
constructed. Build the request from the live writer's device name and ifindex,
the device's non-reusable incarnation, the complete expected PDP context, and
the acquired proof. The removal checks the proof's root and namespace again,
under the operation guard, before any link/netlink read or mutation. A stale,
wrong-root, or wrong-namespace proof returns retryable
`Indeterminate(AuthorityUnavailable)` with no netlink activity.

The removal serializes under the same topology and per-device `flock` writer
gates as every other cooperating mutation, proves the kernel-bound incarnation
exactly as restart recovery does, and then runs the identical dual-selector
exact-removal transaction:
authoritative `GETPDP` readbacks on both axes before admitting the
unconditional `DELPDP`, and classification from the post-mutation readback
rather than from the delete's own acknowledgement. The classified outcomes are
the same `Removed` / `AlreadyAbsent` / `Conflict(_)` / `Indeterminate(_)` /
`RepairRequired(_)` family, with identical meanings.

The live-writer authority is distinct from restart recovery and does not
weaken it: the two request families carry different proof types that cannot
substitute for each other, they report independent capabilities
(`pdp_live_writer_removal_capability` versus
`pdp_restart_recovery_capability`), and the generationless
`remove_pdp_context_exact` trait method remains `UnsupportedFeature` with a
`Missing` capability even after a root is bound. Dropping the returned future
does not cancel the detached blocking worker: it retains both writer
authorities until the transaction reaches its terminal classified result, so
a concurrent cooperating mutation cannot overlap it and a later retry
re-reads the converged state.

### Linux retained device identity acquisition

`LinuxGtpuDataplaneBackend::acquire_retained_device_identity` is the
identity-bearing, mutation-free companion of the restart-recovery primitive.
An ePDG-style consumer that stops after creating a shared recoverable device
but before admitting any PDP effect can restart to find the device retained by
the kernel with no effect-possible PDP descriptor. The consumer must clear
provably unpolled work without an adapter call, then choose between serving
reuse and fresh creation. `create_recoverable_device` correctly refuses a
retained device, `resolve_device` proves only name and ifindex, and
`recover_pdp_context_exact` proves the incarnation only as part of a
PDP-context recovery request that may remove an exact resident context. This
primitive closes that gap without a compatibility path, name-only fallback, or
any device mutation.

Build `RetainedDeviceIdentityRequest` from the durably recorded device name,
the optional exact ifindex, the non-reusable `PdpDeviceIncarnation` minted
before the create effect, and
`PdpRestartRecoveryProof::previous_writer_stopped()`. Pass `None` for the
ifindex while the durable record is still prepared: this includes process loss
after `create_recoverable_device` created and stamped the link but before its
result was durably published. Pass `Some(ifindex)` only after that exact result
was committed. The recovery root must already be bound.

Under shared topology authority, a prepared acquisition performs an
authoritative read-only `RTM_GETLINK` lookup by name, acquires the discovered
per-device authority, then re-proves the exact name, ifindex, and kernel
`IFLA_IFALIAS` incarnation by ifindex. An active-record acquisition takes its
committed per-device authority directly and proves that exact link; if the
ifindex is absent, it also proves whether the name is absent or occupied by a
replacement. Resource or transport errors never become `Absent`, and
contradictory or malformed netlink evidence fails closed. The operation never
reads, installs, or deletes a PDP context and never mutates the device.

Only the `v2` alias written by the kernel-owned recoverable creation path can
authorize `Retained`. A `v1` userspace-socket alias is a conflicting identity,
even when its name, ifindex, and incarnation bytes otherwise match, because
link identity alone cannot prove that its GTP socket survived process loss.

`RetainedDeviceIdentityAcquisition::outcome()` returns a typed, value-free
classification:

- `Retained` — the exact name, ifindex, and kernel-bound incarnation were all
  proven live. `retained_device()` or `into_retained_device()` returns the
  exact `GtpDevice`; a prepared caller must durably publish its discovered
  ifindex before serving reuse.
- `Absent` — the recorded name is authoritatively absent under topology
  authority and, when supplied, the exact expected ifindex is absent too. One
  fresh `create_recoverable_device` call with a newly minted incarnation is
  the supported next step; no name-only adoption occurs.
- `Conflict(ReplacementIdentity)` — the name is occupied by a different
  ifindex, or the name and ifindex are occupied with a different kernel-bound
  identity (including a renamed expected-ifindex link and foreign or malformed
  alias content). The live state is left untouched; the durable record must be
  reconciled against the replacement.
- `Indeterminate(AuthorityUnavailable)` — a concurrent cooperating writer
  holds the topology or per-device authority; retry the identical request.
- `RepairRequired(Unstamped)` — a link matching the expected name and ifindex
  carries no incarnation stamp: it was never published as recoverable (for
  example, process loss interrupted provisioning before publication). Retrying
  cannot succeed without repair.

Renamed, removed, unstamped, malformed-alias, and unrepresentable states are
all structurally distinct from transient authority unavailability:
unrepresentable link evidence fails closed as an error rather than any
classification. Because the operation never mutates, an idempotent retry
returns the same classified identity state while live state is unchanged.

Dropping the returned future does not cancel its detached blocking worker: the
worker retains every acquired writer authority until the classification
finishes, so a retry cannot overlap an admitted acquisition (it may observe
authority unavailable) and later re-reads the unchanged state. The acquisition
does not extend the writer authorities past its return; subsequent device and
PDP mutations are fenced independently by the existing lease hierarchy.
Request, acquisition, and outcome diagnostics are redaction-safe: they expose
no device identity, incarnation, endpoint, TEID, packet, or descriptor values.

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

After UDP/2152 and an accessible mandatory GTP-U header identify a candidate,
classification separates pass-only control traffic from G-PDU decapsulation.
Non-G-PDU traffic passes unchanged to the kernel and local typed control
consumer, which own checksum completion and message validation; it cannot
reach TEID/PDR lookup, decapsulation, or datapath mutation. Every malformed
G-PDU declaration or unverified checksum increments the existing bounded
`downlink_malformed` counter and drops before TEID/PDR lookup, decapsulation,
or inner-destination validation. Addresses, TEIDs, lengths, checksum values,
and payload bytes are not emitted. Non-UDP traffic and other UDP ports also
retain their pass-through behavior. Outer IPv4 fragments pass to the stack
unchanged; the complete contract for them is defined in
[Downlink outer-fragment handling](#downlink-outer-fragment-handling).

The privileged proof covers a legal zero `CHECKSUM_NONE` omission, non-zero
software-verified bytes, authenticated zero and non-zero
`CHECKSUM_UNNECESSARY`, and genuine zero-seed, non-zero-seed, and already
checksum-valid-byte `CHECKSUM_PARTIAL` frames. The positive fixture uses
WireGuard AEAD authentication of the complete inner IPv4 packet before Linux
publishes checksum metadata and forwards the current UDP packet into the real
tc hook. Every partial form fails before PDR/decap counters, while both legal
zero cases decapsulate only after the exact checksum bytes are restored. A
boundary mismatch with trusted metadata proves metadata never bypasses
structural validation. A separate Echo Response fixture proves that an
offload-owned control datagram reaches the local socket unchanged without
moving malformed, unknown-TEID, or decapsulation counters.

### Downlink endpoint provenance

Every eBPF downlink PDR is paired with one canonical endpoint binding keyed by
the same local TEID. The binding records the outer peer address, concrete local
destination, address family, exact ingress interface index, and an explicit
bounded UDP source-port policy. `GtpuSourcePortPolicy::Any` is the deliberate
dynamic-source-port policy described by TS 29.281 section 4.4.2;
`Exact(port)` or `inclusive_range(first, last)` provides a narrower site or
peer contract. Missing state is never interpreted as `Any`.

`GtpPdpContext::downlink_source_port_policy` is therefore required for every
install. The eBPF adapter derives the rest of the public
`GtpuDownlinkEndpoint` from the request's peer, the managed device's concrete
local address, and the attachment ifindex. The semantic API accepts canonical
IPv4 or IPv6 endpoint pairs so adapters can share one contract. The
grouped-session API and current tc object support independent inner and outer
IPv4/IPv6 families, including cross-family transport and simultaneous IPv4v6
entries.

### Inner IPv6 on an ordinary attachment

The single-context PDP API (`install_pdp_context`,
`install_pdp_context_classified`, `read_pdp_context`, `remove_pdp_context`,
`remove_pdp_context_exact`) accepts an IPv6 `ms_address` on an ordinary eBPF
attachment when `pdp_inner_ipv6_capability()` reports `Available`. The address
must be the PDN connection's canonical `/64` prefix with a zero interface
identifier (TS 23.401 clause 5.3.1.2.2, TS 29.274 clause 8.14); readback returns
that canonical form. tc selects uplink traffic by the inner source `/64` plus
the complete packet mark, so temporary and privacy addresses (RFC 8981) inside
the prefix match, and decapsulates downlink only toward a destination inside
it. The peer must use the attachment's IPv4 S2b-U family: inner IPv6 is carried
over IPv4 GTP-U transport, and an IPv6 peer is `UnsupportedFeature`.

An IPv4v6 PDN connection is two family-scoped contexts that may share the
bearer's local and peer TEIDs, peer, mark, DSCP, and source-port policies.
`PdpContextLocalTeidSelector` and `RemovePdpContextRequest` carry the address
family, so reading or removing one family never touches the other.

Each IPv6 context is stored in the family-tagged tc authority as one
single-entry record and exactly its uplink and downlink selectors, under the
ordinary per-device writer gate; IPv4 contexts keep their byte-exact v5 maps.
The first IPv6 install publishes the attachment's IPv4 endpoint and a random
device identity in `GTPU_CONFIG6` and then `GTPU_SCHEMA6`. The removal that
drains the last IPv6 record, selector and journal retires both (schema, then
config), so a drained attachment is identical to one that never carried inner
IPv6 and legacy terminal-successor recovery accepts it. Publication writes the
downlink selector, the uplink selector, then the record, so tc drops rather
than falls back while it is incomplete; removal deletes the record, the uplink
selector, then the downlink selector. The downlink selector is thus present in
every interrupted selector update, and family-scoped removal by local TEID
reaches its residue. An interrupted publication or removal that leaves a
partial selector pair reads back as indeterminate. Once both selectors are
absent, readback is `Absent`, even if authority retirement is unfinished.
The next family-scoped plain or exact removal completes that retirement;
exact removal also does so on cleanup-only attachments before returning
`AlreadyAbsent`. Cleanup-only recovery accepts this ordinary family
authority (its own IPv4 endpoint, no IPv6 endpoint, no grouped journal),
including a config-only authority left between the two initialization writes,
and removes stale IPv6 contexts exactly. Outer-IPv4 fragments carrying an inner
IPv6 G-PDU are passed to the host, as for the grouped path, and are not
reassembled into the datapath.

After the complete outer IPv4/UDP/GTP-U envelope has passed its existing
structural and checksum checks, the tc ingress program selects exactly one
default or marked PDR and requires its endpoint binding. It then compares the
packet's outer source, outer destination, current tc attachment, family, and
source port before examining or delivering the inner packet. A missing,
non-canonical, wrong-family, wrong-peer, wrong-local, wrong-interface, or
wrong-port record drops fail closed. The six fixed aggregate reason counters
are `invalid`, `family`, `peer`, `local`, `ingress`, and `source_port`; they do
not contain addresses, ports, TEIDs, interface names, or payload values.

Fresh default installs publish the binding before making the PDR reachable.
An exact peer/local/policy relocation stages the new uplink resources and uses
one binding-map replacement as the downlink authorization cutover; a reported
failure restores the old binding and forwarding resources. Marked bearers also
embed the exact binding in their owner journal. Their `Active` owner and live
binding must agree byte-for-byte, so a replacement interval authorizes neither
the old nor the new endpoint, never both. Removal phase-gates marked state and
removes binding reachability before deleting the PDR and journal. Restart
adoption validates the complete FAR/PDR/binding/owner graph before either tc
hook is accepted.

Consumers must require
`GtpuProbe::downlink_endpoint_binding == GtpuCapability::Available` before
declaring an eBPF S2b-U attachment traffic-ready. `Unknown` means a capable
environment has not attached a device yet; `Missing` means the exact live
downlink program, binding map, bounded counter map, or attachment identity is
not usable. The Linux `gtp` adapter preserves its existing behavior only for
the explicit `Any` policy, rejects narrower policies with
`UnsupportedFeature`, and reports this capability as `Missing` because its
kernel interface cannot prove the same per-PDR endpoint binding.

### Bounded inner IPv4 TFT fragment affinity

The native unmarked uplink path keeps a bounded bearer decision for inner IPv4
fragments. It forwards each original fragment independently; it does not
buffer payloads or reassemble a datagram. Only fragment zero (offset zero,
`MF=1`) with a valid envelope and all required visible transport fields may
establish affinity. TCP requires its complete declared header, UDP its complete
header and a larger declared datagram length, and ESP its complete eight-byte
header. ESP matches address, protocol 50, SPI, and supported traffic-class
filters; its bytes are never interpreted as TCP/UDP ports. A valid first
fragment may select a dedicated bearer or the classifier's explicit default.

The key is the exact `(ifindex, PAA, source, destination, protocol, IPv4 ID)`.
The retained mark is bound to the classifier owner, owner generation, snapshot
generation, and fingerprint. A later fragment must find that live key and the
same current classifier identity. Every selected mark still goes through the
existing exact downstream peer/F-TEID authority lookup. Affinity does not grant
forwarding authority or introduce a protocol Recovery-event API. Native owner
and owner generation derive from namespace identity, interface index and pinned
map IDs, so they remain fixed for the fragment map's lifetime. Replacement and
reinstall change snapshot generation and fingerprint; replacement also changes
the bank, while reinstall after removal starts at bank 0. Removal makes the
current classifier absent. These transitions invalidate entries without a
userspace scan. PDP/bearer revocation is enforced by the downstream authority
lookup; it does not change the TFT owner generation. A stale retained entry drops even when the
removed classifier had a default bearer. When neither a classifier nor a live
entry exists, the previous ordinary forwarding behavior remains.

The per-attachment table has 16,384 independently locked buckets with four
slots each, for at most 65,536 concurrent datagram identities. A full bucket
refuses a new datagram even if another bucket is free. Each entry tracks at
most 64 fragment ranges, including the first, and expires exactly two seconds
after admission in boot-time nanoseconds. No live entry is evicted, including
poisoned or completed entries. Expired slots are reused in place; neither a
successful later fragment nor a duplicate first fragment extends the deadline.
This is a concurrent-datagram budget shared by the attachment, not a reserved
slot per subscriber; hash collisions can exhaust a bucket before the global
limit is reached. There is no per-subscriber admission bound: one subscriber
can keep all slots occupied and deny new fragmented datagrams to every other
classified subscriber on the attachment. The host `TftUplinkFragmentTable`
allocates approximately 24.5 MiB per attachment.

A duplicate first fragment is accepted only when its parsed classifier fields,
selected mark, header length, and first range agree. A conflicting first
fragment, overlap (including a duplicate later fragment), inconsistent final
range, or range-limit exhaustion poisons the entry until its original expiry.
Malformed envelopes (including DF or reserved flags on a fragment), a UDP
length contradiction and a stale classifier identity also poison a retained
entry. A version nibble other than four bypasses IPv4 classification on both
host and tc and leaves affinity untouched.
Later fragments received before their first fragment, or after its expiry,
drop while a classifier owns the PAA. Valid non-overlapping later fragments
may arrive in either order after admission. IPv4 ID reuse requires expiry;
replacement does not clear the old key early. Rejections use the existing
aggregate TFT malformed, no-match, and invalid-state counters without packet
values or per-datagram labels. Invalid-state includes ordinary fragment events
such as orphan, expiry, capacity refusal and overlap, as well as inconsistent
classifier state; capacity refusal has no distinct slot in the pinned counter
map.

`GTPU_TFT_FRAG` is a pinned BTF ARRAY with one spin lock per bucket. Each slot
is 392 bytes; four slots occupy 1,568 bytes, and the lock makes the BTF value
1,572 bytes. The kernel's eight-byte stride alignment makes value storage
1,576 bytes per bucket, or 24.625 MiB per attachment before map metadata.
The ARRAY is preallocated per attachment, independently of registered UE
count; registration does not allocate fragment slots.

Admission or lookup examines at most four slots and 64 ranges. Fragment zero
also runs the existing classifier, bounded to 256 filters. Packet reads,
classification, clock reads, counters, and forwarding lookups occur outside the
lock; the protected state mutation performs no allocation or helper call.
Userspace does not delete or refresh packet entries. Exact graph teardown
removes the affinity map with the other owned pins.

The stateless `TftUplinkClassifier::classify` and shared packet parser retain
their strict fragment rejection. For the host model, construct a
`TftUplinkFragmentSnapshot` from the complete classifier and its owner and
publication generations. Keep one `TftUplinkFragmentTable` per attachment
across replacement, removal, and revocation, and supply nondecreasing boot-time
nanoseconds to `classify`. Snapshot construction derives the native canonical
rows and fingerprint; callers cannot pair a classifier with unrelated metadata.
The model returns a classifier decision, which still requires the existing
downstream authority lookup. Native TFT fragment affinity remains IPv4-only.
See the [upgrade and rollback contract](#tft-fragment-affinity-upgrade-and-rollback)
before adopting or replacing retained maps.

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
reads the held `GTPU_COUNTERS` and fixed `GTPU_DL_DROP` maps directly,
aggregates every per-CPU value, then repeats the identity proof. The returned
`EbpfGtpuDatapathSnapshot` contains only kernel-local program/map IDs and
aggregate counters; it contains no addresses, TEIDs, packet marks, or payloads.
This avoids `bpftool map dump name GTPU_COUNTERS`, which can select an unrelated
same-name map when stale or concurrently loaded objects exist. The method
returns `StateIndeterminate` rather than presenting counters as authoritative
if a hook or pin mismatch is visible at either identity check. An external-root
replace-and-restore between checks is outside the exclusive-writer contract and
cannot be distinguished by this diagnostic.

Both bounded counter schemas aggregate default and dedicated bearers. Use
counter deltas to prove that the attached uplink/downlink programs ran; use the
peer's observed GTP-U TEID for per-bearer correlation.
An all-zero identity-bound snapshot during a claimed GTP-U round trip means the
traffic did not traverse these exact programs, not that a marked lookup chose
the default entry.

`uplink_encapsulated` counts encapsulations handed to `bpf_redirect_neigh`, not
packets the peer received. `bpf_redirect_neigh` only records the target ifindex
and returns `TC_ACT_REDIRECT`; route and neighbour resolution, and any
resulting drop, happen later in `skb_do_redirect()` after the classifier has
already returned. A total uplink outage whose cause sits downstream of the
classifier -- no route covering the outer destination, no resolvable
neighbour -- therefore still shows `uplink_encapsulated` rising 1:1 with
subscriber traffic.

`uplink_redirects_resolved` is the other half, and closes issue number 564. A
redirect that resolves puts the outer frame back on the same tc egress hook
(`skb_do_redirect()` -> `__bpf_redirect_neigh_v4()` -> `bpf_out_neigh_v4()` ->
`neigh_output()` -> `dev_queue_xmit()` -> `sch_handle_egress()`); one that finds
no usable route is freed before it gets there. The uplink program recognizes its
own re-emitted outer frame on that second traversal, so -- absent the locally
originated traffic described below -- this counter rises 1:1 with
`uplink_encapsulated` on a healthy uplink and stays flat while
`uplink_encapsulated` keeps rising during a redirect-stage outage. No GPL-only
helper is involved: the check reads the existing configuration maps and the
frame's own outer header.

Three limits remain.

- It proves the frame reached `dev_queue_xmit`, not that the peer received it,
  so corroborate delivery against egress interface counters.
- An unresolved neighbour lags rather than reads wrong: the skb waits in the
  neighbour's `arp_queue` and is counted late if resolution eventually
  succeeds, never if it does not.
- The counter is unauthenticated. The datapath identifies its own re-emitted
  frame by what the frame is, so any locally originated packet sourced from
  this attachment's S2b-U endpoint to UDP/2152 carrying a GTPv1 G-PDU header
  increments it as well, and an unprivileged co-located process can send one.
  A noisy or hostile process on the host can therefore inflate this counter
  while `uplink_encapsulated` stays flat, which is the inverse of the outage
  signature above -- so a divergence in that direction says to look at the host,
  not at the uplink. Only observability is affected: no forwarding decision
  reads this counter, and no subscriber traffic can present that source, since
  both schemas reject a UE PAA that aliases the local outer endpoint. This is
  not closable by tightening the check; every discriminator available inside
  the program is in-band and so forgeable by a local sender.

`uplink_far_misses` no longer counts the datapath's own re-emitted outer
frames. Their source is the local S2b-U address rather than a UE PAA, so before
the redirect outcome was recognized this counter rose once per *successfully
delivered* uplink IPv4 packet and made a healthy uplink read as session-state
corruption. It remains a miss counter for every other mark-zero IPv4 frame
leaving the attachment whose source is not a provisioned UE PAA -- locally
originated traffic from the host included -- so read a nonzero value as a
prompt to investigate rather than as proof of session-state corruption.

`downlink_missing_consumer` counts the hand-offs that tc gave to no UDP
socket, because none was bound to receive them or they arrived in a VLAN above
the attachment's interface. tc leaves some datagrams to a socket on the
gateway instead of decapsulating them: a steered over-MTU Don't Fragment
packet or inner fragment (UDP/2153, UDP/2154), a G-PDU for no tunnel or with
a required unknown extension (UDP/2152), and an outer-fragmented UDP/2152
datagram, judged by its first fragment. Each is passed on only while a socket
is bound for it, because the kernel would otherwise answer with ICMP Port
Unreachable toward the peer and quote the start of the subscriber's inner
packet. A rising value means that hand-offs arrive while nothing drains them:
the control port was not opened yet, the process was down, or it restarted
and has not reopened the port. Those packets are lost, as they were before
this counter existed; the host no longer answers them. A hand-off that
arrives in a VLAN above the attachment's interface is counted here whatever
is bound, so a value that rises while the port is open and drained can mean
that the peer sends in such a VLAN. A G-PDU for no tunnel is counted in
`downlink_unknown_teid` first, so it can raise both. A socket counts when UDP
input will accept it for a datagram that arrives on the attachment's
interface, and an interface that is enslaved to a VRF changes which sockets
those are. See
[control port](docs/control-port.md#hand-offs-need-a-bound-consumer).

Existing `GtpPdpContext` literals must add `bearer_mark: None` to retain the
default path, or construct a non-zero `GtpBearerMark` for a dedicated bearer;
they must also choose an explicit `downlink_source_port_policy` and an explicit
`uplink_source_port_policy` (`LegacyServicePort` retains prior bytes). Code
that constructs `GtpuProbe` literals must initialize `per_bearer_marking`,
`downlink_endpoint_binding`, and `uplink_source_port_selection`. Consumers must
gate `bearer_mark: Some(_)` on
`GtpuProbe::per_bearer_marking == GtpuCapability::Available`; it becomes
available only after both exact live tc programs and every exact schema map
pin have been verified. The mainline Linux `gtp`, mock, and unsupported backends
report `Missing` and reject marked requests. This API requires no Cargo feature
and introduces no dependency.

`EbpfGtpuDatapathCounters` gained `uplink_redirects_resolved` and, later,
`downlink_missing_consumer`. The type is deliberately exhaustive, like every
other public struct in this module, so any struct literal or exhaustive
destructuring of it outside this crate must add each new field. Nothing
in-tree constructs it by literal outside the crate, and the crate is
`publish = false`.

### DSCP and reconciliation

The eBPF backend owns `GTPU_UPLINK_DSCP` for default bearers and an additive
marked DSCP map keyed by `(UE PAA, mark)`. Setting
`GtpPdpContext::egress_dscp` stamps that validated codepoint on the newly
generated outer uplink IPv4 header and includes it in the header checksum.
`None` preserves the exact legacy encapsulation bytes.

Default-bearer reconciliation publishes DSCP and FAR before the endpoint
binding and publishes the PDR last. Removal retains the PDR as its lookup-key
journal until FAR, DSCP, and binding state have been cleared. An exact retry
can reconcile a pre-reachability publication orphan. One-sided FAR/PDR state,
or reachable PDR state without its exact binding, remains an ambiguous conflict
and fails closed.

Marked bearers use a stronger, additive owner journal keyed by `(UE PAA,
mark)`. Its value binds the local TEID, complete uplink FAR, exact downlink
endpoint binding, optional DSCP, and one of three phases. Installation
publishes `Pending` before any forwarding resource, reconciles only an exact
matching request, then publishes `Active` last. Both classifiers require an
exact active owner and matching FAR/DSCP/PDR/binding state, so a crash or map
error at any earlier point leaves the bearer non-forwarding and safely
retryable. A DSCP or endpoint update is phase-gated by the same protocol.
Removal publishes `Removing` first, deletes FAR, DSCP, binding, and PDR, then
deletes the owner last; an interrupted removal cannot resume forwarding and an
exact removal retry finishes it. Linux/Aya reports deletion of an absent hash
entry as syscall `ENOENT`; the runtime classifies that result as idempotent
absence, including when an optional DSCP entry was never installed. An install
that encounters a valid persisted `Removing` owner also finishes that
committed deletion, but never resurrects the bearer or reports `AlreadyExists`
in the same call. It returns
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

`GtpuProbe::egress_dscp_marking`, `GtpuProbe::per_bearer_marking`, and
`GtpuProbe::downlink_endpoint_binding` report `Unknown` while a capable
environment awaits its first device attach. DSCP becomes `Available` only when
the exact uplink path is live; per-bearer marking requires both exact programs
and all exact schema map pins; endpoint binding additionally verifies the exact
downlink attachment plus its binding and fixed counter maps. Runtime program or
map identity loss reports `Missing` and blocks new state publication, while
identity-safe cleanup remains available under the rule above.

### Uplink UDP source-port selection

TS 29.281 section 4.4.2 fixes the GTP-U destination service port at 2152 and
leaves the UDP source port dynamic. `GtpPdpContext::uplink_source_port_policy`
makes that choice explicit per PDP context.
`GtpuUplinkSourcePortPolicy::LegacyServicePort` is the pre-feature behavior and
emits exactly the legacy source/destination 2152 bytes.
`GtpuUplinkSourcePortPolicy::selected(port)` persists one stable per-context
port. Port zero is reserved, and 2152 has the sole canonical representation
`LegacyServicePort`; both invalid `Selected` values fail closed at the checked
constructor or userspace map boundary.

The eBPF backend owns additive `GTPU_UL_SPORT` (default bearers) and
`GTPU_ULM_SPORT` (keyed by `(UE PAA, mark)`) maps. Each value is a fixed 68-byte
commit record: its first 64 bytes use the marked-owner layout to bind the FAR,
DSCP, local TEID, endpoint binding, and publication phase; bytes 64..66 hold the
explicit big-endian source port, including legacy 2152; bytes 66..68 are zero.
The record, rather than an individual component map, is the traffic authority.
Userspace writes `Pending` first, mutates every component, and publishes
`Active` last. Removal writes `Removing` first, deletes the components, and
deletes the commit record last. Both tc directions accept only an `Active`
record whose complete selected graph matches those committed bytes exactly.

Restart recovery treats `Pending` and `Removing` identically as non-forwarding
transactions: it validates their bounded ownership graph, removes every owned
component to proven absence, and removes the commit record last. Recovery can
resume after interruption at every mutation boundary. Current-process TEID
reservations are established when the commit record is inserted and remain
held until its final deletion, preventing a partially published transaction
from colliding with another context.

Before a populated v3 graph can run the v4 program, migration derives a complete
legacy-2152 commit record for each already validated default and marked context,
recovers any transitional record to absence, validates the complete graph,
attaches the exact program, and only then commits `OPC-SPORT-v4`. Once v4 is
committed, a missing, zero, malformed, unowned, or mixed record fails adoption
and PDP read-back; both tc directions drop a packet whose exact complete context
does not match its `Active` record. There is no runtime fallback to 2152. The
selected port survives process restarts, is returned by PDP read-back, and is
reported in conflict evidence only as the `UplinkSourcePortPolicy` field name.
The uplink selection is independent of `downlink_source_port_policy`: the
backend never assumes a peer returns traffic from the selected port.

Consumers using the eBPF backend must require
`GtpuProbe::uplink_source_port_selection == GtpuCapability::Available` before
installing any context because legacy is explicit state too; the capability
follows the same `Unknown`/`Missing` transitions as DSCP. The Linux `gtp`, mock,
and unsupported backends report `Missing` and reject a non-legacy policy with
`UnsupportedFeature`, preserving their exact established behavior for the
explicit legacy policy.

The separate 64-byte marked-bearer owner journal remains wire-compatible for
marked-context provenance. The 68-byte source-port-map commit record repeats
that canonical owner layout and adds the source port, making it the common
commit authority for default and marked contexts. For marked contexts, the
owner journal and commit record must agree exactly. Every `Active` commit must
have one complete canonical graph, and every graph must have one commit;
missing, orphaned, or structurally inconsistent state blocks restart adoption
before either hook changes. Runtime loss also makes read-back indeterminate and
packet processing drop, so a map loss cannot silently change a bearer to legacy
behavior. The exclusive-writer boundary documented above remains the integrity
boundary for exact policy values.

### Uplink MTU and outer-fragmentation policy

`CreateGtpDeviceRequest::uplink_mtu_policy` carries an explicit, device-level
`GtpuUplinkMtuPolicy`: the effective S2b-U link MTU (bounded so the fixed
36-byte IPv4/UDP/GTP-U encapsulation plus the RFC 791 minimum 68-byte inner
packet always fits) and the outer-fragmentation choice. The legacy
`inner_mtu()` accessor is the IPv4 headroom calculation. The grouped tc path
selects the overhead from the authoritative outer family: 36 bytes for outer
IPv4 and 56 bytes for outer IPv6, and rejects a packet when the corresponding
total exceeds the effective link MTU. `None` requests no change: a fresh
device gets the legacy total-length-only behavior and a device with a
persisted policy keeps it.

`decide_uplink_encap` in `opc-gtpu-ebpf-common` is the shared typed decision
used by host callers and, through `apply_uplink_mtu_policy`, by the tc uplink
program itself:

- `Emit` within the effective MTU, with the remaining headroom; under the
  default `SignalPacketTooBig` policy the outer DF bit is stamped and the
  outer checksum refreshed.
- `RequiresOuterFragmentation` when a host caller selects
  `RequireOuterFragmentation`: the typed action contains the unfragmented
  header and bounded excess, but does not claim that the oversized packet was
  emitted. The caller must fragment the complete outer IPv4 packet before
  transmission.
- `RejectTooBig` otherwise: a fail-closed, counted drop. On the eBPF tc
  backend this is *silent* toward the inner source — the kernel datapath
  emits no ICMP — so operators must size the inner MTU out of band (for
  example MSS clamping), or consume the typed signal in a host component:
  `build_icmpv4_packet_too_big` / `build_icmpv6_packet_too_big` turn a
  `GtpuPmtuSignal` into a wire RFC 1191 / RFC 8201 Packet-Too-Big packet for
  host callers of `decide_uplink_encap`. The inner packet is never emitted
  unencapsulated and, under the strict policy, the encapsulation never
  exceeds the effective MTU.

The eBPF backend rejects `RequireOuterFragmentation`: tc egress transmits via
`bpf_redirect_neigh`, which bypasses the kernel's `ip_fragment` path, so it
cannot execute that host action. Consequently, eBPF never emits a packet over
the configured effective MTU. It persists an executable strict policy in the
additive single-slot
`GTPU_PMTU_CFG` map at device creation (only when `Some` is requested) and
rejects a configured policy when the loaded datapath cannot honor it.
`set_uplink_mtu_policy(device, policy)` is the supported mutation for a live
device — an atomic slot write converging any out-of-band drift — and
`effective_uplink_mtu_policy` reads the effective policy back; adoption and
read-back fail closed (`StateIndeterminate`) on corrupt persisted bytes
rather than blackholing uplink silently. Over-MTU rejects and corrupt-policy
drops are separate snapshot counters (`uplink_mtu_rejected` and the
external-writer canary `uplink_mtu_policy_corrupt`, both from the
`GTPU_PMTU_DROP` per-CPU map). The mock and Linux `gtp` backends report
`uplink_pmtu_enforcement` missing and reject a configured policy fail
closed; the netlink driver leaves outer MTU/fragmentation to the kernel
routing layer.

### Unknown required extensions

The current tc IPv4/IPv6 parsers and post-reassembly parser hand complete
unknown-required-extension chains to the control plane before tunnel lookup
or decapsulation. Optional extensions retain their endpoint skip behavior;
malformed chains still drop. The existing shared IPv4 control socket supplies
bounded notification plans. See the [exact contract and native evidence](docs/required-extensions.md).
This does not enable N3 forwarding or change selector authority.

### Downlink outer-fragment handling

`GtpuProbe::downlink_outer_fragment_handling` states each backend's outer-IPv4
contract explicitly; there is no implicit behavior. A legacy v5 eBPF
attachment is *handoff-capable* (`KernelReassemblyHandoff`): the tc ingress
program passes outer IPv4 fragments to the kernel stack unchanged, the kernel
reassembles under its bounded `net.ipv4.ipfrag_*` accounting (reported from
the live sysctls, absent when unreadable — never fabricated defaults), and
exactly one complete UDP/2152 datagram is delivered to a socket bound on the
concrete local S2b-U address. The contract is complete only while the operator
runs an SDK consumer on that socket. Without one, tc counts each set at its
first fragment (`downlink_missing_consumer`) and marks that fragment, so that
UDP input discards the reassembled datagram: the packet is lost, no fragment
stays in the kernel's reassembly queue, and the host sends no ICMP error
toward the PGW.

Grouped fragmentation is reported separately per attachment through
`GtpuIpFamilyCapabilities::downlink_outer_ipv4_fragment_handling` and
`downlink_outer_ipv6_fragment_handling`; both are currently `Unsupported`.
Although grouped outer-IPv4 fragments reach the kernel, the existing consumer
authorizes only the legacy v5 graph and cannot safely deliver a grouped TEID.
The bounded IPv6 extension walker accepts an atomic Fragment header, but
packets requiring IPv6 reassembly likewise pass to the host without a matching
grouped consumer authority. Complete fragmented grouped GTP-U therefore
requires a separately qualified consumer and cannot be inferred from
unfragmented `outer_ipv4` or `outer_ipv6` support.

The Linux `gtp` backend reports this contract as `Unsupported`: discovering
the generic-netlink family proves that the driver is present, but does not
prove that fragmented outer packets re-enter its UDP consumer exactly once.
That backend must remain fail closed until an equivalent live Linux-`gtp`
proof is part of its capability probe.

`GtpuReassemblyConsumer` is that consumer. It mirrors the tc fast path's
PDR resolution (including dual-map-TEID and reserved-zero-mark corruption,
which fail closed as malformed), canonical endpoint-binding validation,
complete commit-authorized PDP graph validation for default and marked
bearers (one typed selector derived from the current PDR keys the FAR, DSCP,
marked-owner, and commit reads; component state is read before the
authoritative `Active` commit is observed last, so old-selector/new-PDR mixes
and install, relocation, or removal windows cannot deliver through the socket
what tc would drop), and
inner-family/destination checks, returning the decapsulated inner packet
with its output bearer mark at most once per reassembled datagram.
Provenance comes from the kernel, not configuration:
`GtpuReassemblySocket::bind` derives the positive ifindex from an interface
name, applies `SO_BINDTODEVICE` before binding the concrete IPv4 S2b-U address
on UDP/2152, enables `IP_PKTINFO`, and verifies exact kernel readback. See
[Linux `SO_BINDTODEVICE` capability contract](#linux-so_bindtodevice-capability-contract)
for what that device bind does and does not require.
Each receive checks the sealed device/address identity
both before and after blocking. A positive packet-info ifindex must match; a
zero ifindex, which some kernels report after reassembly, is accepted only
through that kernel-enforced sealed socket identity. Truncated payload/control
envelopes fail closed before provenance is returned, and no API can wrap an
ordinary unbound socket as authoritative. Documented divergences from the tc
path: checksum verification is the kernel's (socket delivery implies
acceptance), and
envelope padding strictness differs — tc requires `udp_end == ip_end` and
drops padded envelopes, while the kernel strips layer-2 padding before
socket delivery, so a padded envelope tc would drop unfragmented is accepted
after reassembly. Malformed, unknown-TEID, binding-mismatch,
destination-mismatch, and oversized inputs fail closed into fixed-cardinality typed
counters; non-G-PDU GTP-U is handed to the control plane. The SDK never
holds a userspace fragment cache, so reordered, duplicated, overlapping,
incomplete, and timed-out fragment sets remain bounded by the kernel's
configured limits. Duplicate-fragment handling is kernel-version-dependent;
applications receive only complete UDP datagrams and the SDK processes each
socket delivery once.

The consumer's counters are userspace-side and deliberately *not* part of
the identity-bound `datapath_snapshot` (which aggregates only the tc
datapath's per-CPU maps); monitor both. On Linux,
`read_linux_ipv4_reassembly_stats` provides a bounded, strictly parsed
`/proc/net/snmp` snapshot of received fragments, successful reassemblies,
timeouts, and aggregate failures. Linux does not split conflicting overlap
from resource-pressure and other `ReasmFails`, so the API does not invent
per-cause counters. Socket lifecycle guidance for the
embedding ePDG: use `GtpuReassemblySocket::set_receive_buffer_size` and retain
its effective `SO_RCVBUF` readback for the expected reassembled burst (kernel
UDP buffer overruns drop silently and are not visible in the consumer
counters), and shut down in reverse order — detach the tc datapath before
closing the consumer socket — because a fragment set whose first fragment
passed while the socket was bound, and which completes after it closed, is
answered with ICMP port unreachable toward the PGW. A set that begins after
the close is counted by tc and discarded. Linux `gtp`, mock, and unsupported
backends report `Unsupported`.

The privileged suite proves the contract end-to-end: a valid two-fragment
G-PDU, a reordered set, and a set with a duplicated first fragment each
re-enter the consumer exactly once and decapsulate to a byte-exact original
inner packet against the pinned complete graph; a conflicting overlapping
set is rejected on the qualified kernel; an incomplete set is evicted at the
configured timeout and its late tail never re-enters; bounded fragment-memory
pressure causes kernel reassembly failures rather than unbounded growth; and
a fragment set from an unauthorized outer peer is reassembled by the kernel
but rejected by the consumer's binding check. The uplink suite proves the
strict policy drops an over-MTU encapsulation with only the reject counter
moving, stamps DF on fitting packets, rejects the host-only fragmentation
policy without map drift, and routes corrupt policy bytes to the canary
counter with indeterminate read-back.

### Linux `SO_BINDTODEVICE` capability contract

`GtpuReassemblySocket::bind` applies `SO_BINDTODEVICE` to a socket it has just
created. The kernel's own check is in `sock_bindtoindex_locked()`
(`net/core/sock.c`) and reads `sk->sk_bound_dev_if &&
!ns_capable(net->user_ns, CAP_NET_RAW)`, so it applies only to a socket that is
*already* device-bound:

- A socket that is **not yet device-bound** is **not** capability-gated for its
  first `SO_BINDTODEVICE`. That holds on upstream mainline since v5.7 (commit
  `c427bfec18f2`, "net: core: enable SO_BINDTODEVICE for non-root users");
  upstream mainline before v5.7 gates every device bind on `CAP_NET_RAW`, in a
  function then named `sock_setbindtodevice_locked()`. Distribution kernels
  backport independently of the mainline release, so the mainline version is
  not a statement about any vendor kernel. Verified separately: the relaxed
  form is present in the CentOS Stream 9 `net/core/sock.c`, the tree RHEL 9
  derives from.
- A socket that **is** already device-bound still requires `CAP_NET_RAW` to be
  re-bound — including re-bound to the **same** device — or unbound. The
  capability is evaluated by `ns_capable(net->user_ns, ...)`, that is, in the
  **user namespace that owns** the socket's network namespace; this is not
  "`CAP_NET_RAW` in the network namespace".
- A socket can arrive already device-bound: a `sock_create` cgroup hook may
  write `sk_bound_dev_if` during `socket(2)` (`ip vrf exec` is one such
  mechanism), so a freshly created socket is not guaranteed to be unbound.
- An **unknown interface is rejected before any capability question arises**:
  `bind` fails its own `if_nametoindex` lookup with `InvalidInput`, so the name
  never reaches the kernel option at all. Had it reached the kernel, upstream
  mainline since v5.1 would return `-ENODEV` regardless of capabilities,
  because `sock_setbindtodevice()` resolves the name before
  `sock_bindtoindex_locked()` is reached; upstream mainline before v5.1 tests
  the capability first and returns `-EPERM` without resolving the name.

This describes the kernel's own capability check only. LSM policy (for example
SELinux) and seccomp policy are out of scope and can deny the call
independently. The rest of the reassembly consumer's privileged prerequisites
are unchanged.

### Pinned-map and live-program migration

#### TFT fragment-affinity upgrade and rollback

The current attachment requires all 35 named maps, including the pinned
`GTPU_TFT_FRAG` BTF ARRAY, and TFT marker `OPC-TFT-IPv4-v5`. An old 34-map graph
without this map, a retained v4 TFT marker, or any partial TFT graph is refused
before attachment mutation. The loader does not fill in the new map beside an
old classifier. Fresh creation initializes the map to zero. Promotion of an
all-zero TFT marker requires a complete current TFT graph with empty metadata,
filters, and affinity state, checked before hook mutation and again before
marker publication. The independent PMTU-v5 and grouped-session markers do
not establish TFT compatibility.

Upgrade requires stopping new traffic and producers, draining represented
sessions and in-flight traffic, then using the prior version's exact device
removal or authorized graph-recovery procedure to remove its owned hooks and
pins. The destination version then needs a fresh attachment and reinstallation
of classifier/session state in an authorized namespace that passes its
creation checks. Graph cleanup alone does not establish namespace eligibility.
Retaining pins with `suspend_grouped_device` does not perform this migration.
Rollback follows the same sequence using this version to clean up its 35-map
graph before the older version creates its own graph. Neither direction
supports an in-place live schema change or packet continuity across the
drained replacement.

The wider map identity changes current recovery proof magic from `OPCCURR7` to
`OPCCURR8` and terminal WAL codec from
`opc.gtpu.current-ebpf-recovery-terminal-wal.r2` to
`opc.gtpu.current-ebpf-recovery-terminal-wal.r3`. Older proofs/WALs are not
converted, and an older binary cannot consume the new ones. Finish pending
recovery with the version that wrote its records. Terminal recovery retains
`GTPU_CURRENT_RECOVERY_TERMINAL_V1` even after graph removal; recovery to a
current successor persists `GTPU_CURRENT_RECOVERY_FINALIZED_RECEIPT_V1`.
Finishing old recovery therefore does not necessarily make that namespace
reusable. These retained records have the old width and codec commitments,
and this version rejects them, including finalized receipts. If any
incompatible proof, WAL, or finalized receipt remains, preserve it and use a
separate, freshly authorized namespace. Do not delete or rewrite authority
evidence to force attachment through an authority-bearing recovery flow. An
unbound, exclusively owned workload may instead discard its entire graph using
[`reset_exclusive_workload_graph`](#isolated-workload-lifecycle), after abandoning
retained-graph recovery and stopping the old writer. This never erases selector
history. Rollback has the same constraint in the opposite direction; no
cross-version record conversion is implemented.

Ordinary fresh creation in a previously used namespace requires exact graph
cleanup, no selector-authority markers, no recovery proof, terminal WAL, or
finalized receipt, and successful pristine-namespace checks. Adoption of a
present current graph also validates any finalized receipt. Completing graph
cleanup with an older binary cannot bypass either check.

Receipt and transfer codec names remain r2, but their commitments bind the WAL
codec. The maintenance-only shipped-25 graph retains its frozen TFT v4
recognition and separate recovery authority; it is not an adoption route for
the former 34-map graph.

The new map participates in exact pin identity checks, program/map references,
cleanup-only acquisition, ordinary teardown, current recovery, and fresh-attach
rollback. Failed attachment removes only exactly owned fresh resources when
the existing rollback proof permits it; indeterminate or pre-existing graphs
remain retained for reconciliation. Classifier replacement/removal invalidates
affinity by identity, while physical map removal belongs to graph teardown.

#### Earlier endpoint and MTU schema transitions

The endpoint-bound v3 schema keeps the legacy default FAR, DSCP, and PDR
names/layouts and the v2 marked FAR/DSCP/PDR names. It adds
`GTPU_DL_BIND` for the canonical per-TEID endpoint identity and
`GTPU_DL_DROP` for six fixed mismatch counters. The marked owner journal now
embeds that complete binding, so its map value is intentionally incompatible
with endpoint-unbound v2 pins. With an explicit `Any` source-port policy,
`bearer_mark: None`, and `egress_dscp: None`, uplink wire bytes remain
byte-for-byte compatible; downlink authorization is deliberately stricter.

The durable schema marker at the reserved impossible-PAA key in the legacy
FAR map is the schema commit. The current `OPC-PMTU-v5` value additionally
proves the additive uplink MTU policy maps; the `OPC-SPORT-v4` value remains
the commit for the source-port schema below it, and the endpoint-bound
`OPC-PEER-v3` value for the provenance schema below that. A marker is written
only after every named map identity is verified, the complete map graph is
canonical, and both current tc programs have been attached and read back by
exact program ID. A committed marker with a missing required pin, an unknown
marker, or a foreign tc occupant fails closed before Aya can recreate empty
state. A positively absent current hook may be repaired. The v3-to-v4 step is
additive and resumable: after validating v3 state, the loader materializes a
complete `Active` legacy-2152 commit record for every context before attaching
the v4 program and committing the marker. Any transitional migration record is
recovered to absence before migration resumes. A partial migration may contain
only records derived exactly from the validated v3 graph; any selected, zero,
malformed, orphaned, or mixed record fails closed. The v4-to-v5 step is purely
additive: an all-zero MTU policy slot selects the legacy total-length-only
behavior, so populated v4 state upgrades in place.

There is no implicit endpoint migration for populated older state. A committed
v2 pin set is rejected and requires an explicit traffic drain followed by pin
removal and reprovisioning. Which redaction-safe error names it depends on how
far the graph gets: the pre-load map-layout guard described below now sees a v2
bearer pin first, because that generation's owner value is a different width,
and names it `ebpf_pin_map_abi`; a v2 graph that reaches the endpoint preflight
is still named `ebpf_endpoint_schema`. Both refuse before either hook changes,
and the operator remedy is the same.
An uncommitted, legacy-v0, or DSCP-v1 schema can advance only when it is empty,
its retained maps already satisfy the current ABI, and no historical hook is
live. An authentic frozen-v1 graph has a six-slot counter map and historical
program tags, so it now requires a drained pin removal and reprovision instead
of automatic hook replacement. The same holds for the counter map's second
growth: `GTPU_COUNTERS` has sixteen slots since the missing-consumer counter,
and every earlier build published seven or fewer. A graph retained from such
a build is refused before anything is read through a typed binding or
changed: with `DatapathGenerationMismatch` while its hooks are still
attached, and with `ebpf_pin_map_abi` when only its pins remain. Drain it,
remove the retained graph with the build that created it (or remove its pins
once nothing references them), and provision again. Eight of the sixteen
slots are reserved, so that the next counter does not change the width
again. Any retained PDR/FAR without an exact binding
is indeterminate and fails before either hook changes. The SDK never invents
`Any`, derives a peer from an untrusted packet, or labels endpoint-unbound
forwarding state production-ready.

#### Isolated workload lifecycle

`EbpfGtpuDataplaneBackend::for_workload(EbpfWorkloadScope)` gives one stable
workload its own bpffs root and local writer locks. Supply a collision-resistant
digest of the tenant and stable workload slot; retain it across process and pod
replacements. It is a naming boundary, not protection against another privileged
host process. This mode needs no cluster API or resident node agent.

After invalidating the previous forwarding generation and isolating ingress,
call `reset_workload_graph(scope, interface)` before normal attachment. The SDK
acquires the existing writer and operation locks, inspects every present pin,
verifies local hooks and global program references, detaches owned hooks, and
removes the recognized, unbound IPv4 interface graph. Inspection
failure, a live writer, foreign objects, an older schema, selector-authority or
decommission markers, or external recovery
authority refuses cleanup. No sessions are preserved by this reset.

Cleanup accepts a recognized partial pin set and is repeatable after process
loss at any effect boundary. It does not need a cleanup journal: each attempt
enumerates the stable, exclusively owned namespace again. Unknown entries are
never deleted. On orderly shutdown, stop producers, call `remove_device`, then
reset the workload graph to verify absence. Grouped dual-stack selector
namespaces retain their separate lifecycle and cannot use this reset. Empty lock
directories remain to preserve lock-inode identity.

The operation sees only the current node. A workload moved elsewhere cannot
collect the old node's state until it returns, unless an external administrator
does so. Pins retain kernel memory until unpinned or rebooted. Pins alone do not
execute programs, but surviving hooks or other references may keep an old graph
active; local interface absence is never treated as proof of their absence.
This API scans loaded programs and refuses references outside the verified local
hooks. Shared-root and historical migration continue to use their separate
authority-bearing APIs below.

For a workload that exclusively owns its entire scope root, use
`reset_exclusive_workload_graph(scope, interface)` instead. Stop the previous
writer, invalidate its forwarding generation and isolate ingress on all of its
interfaces first. Do not combine reset with externally authorized retained-graph
recovery. A scope that was ever bound to a selector namespace cannot use this
operation; its permanent history has a separate lifecycle.

For several interfaces in one scope, reset each intended interface before the
first `create_device`. With missing pins, neither leaf names nor map references
can identify the other interfaces, so naming each one matters. Once this backend
manages any device, every reset is refused until its managed devices are removed.

This declaration covers the named interface and every root leaf that resolves
to an interface in the current network namespace. On those devices the reset
removes the configured clsact ingress/egress slots (chain zero, `ETH_P_ALL`,
configured priority, handle `0:1`), every SDK-named filter that ordinary attach
would reject, and any filter whose program references a scope map. SDK detection
uses exactly the ordinary attach predicate; it does not depend on program tags,
generations, priorities, handles, protocols or chains. Map references also locate
renamed interfaces in the current namespace; only the referencing filters on
such a device are removed. Filters meeting none of these rules remain untouched.
Declared interfaces are inspected first by their kernel index, including when
the caller uses an alternative name. Discovery visits other interfaces only for
unaccounted scope-map references, skips failed or oversized dumps and non-UTF-8
names, and leaves the map-reference guard to refuse any unresolved reference.
Direct tc deletion stays in the calling network namespace.

The reset removes unknown names, incompatible map shapes, recovery/terminal/
successor records, partial nested layouts, and program and link pins throughout
the root. Unlinking a scope's pinned link detaches that link's attachment wherever
it is, including another interface, namespace or hook type, when the final link
reference ends. The declaration that every object pinned in the root belongs to
the workload covers this effect. Empty
writer-lock directories and all existing exclusion markers retain their inodes;
all inventoried interface names receive an ordinary-attach exclusion marker.
After detaching and removing object pins, the reset waits up to **250 ms** for
retired program IDs and scope-map references to disappear, then checks references
before each map unpin. A retry also waits when it detached nothing itself, so a
previous call's deferred kernel teardown can settle before being classified as
external. Normal hook teardown needs no caller retry loop.

Refusals are distinct:

- `RetryRequired` with `ebpf_workload_cleanup_writer_busy`: a writer or operation
  lock is held. It ends when the holder releases the lock or exits.
- `StateIndeterminate` with `ebpf_exclusive_workload_external_program_reference`:
  a program this reset did not detach still uses a scope map after the bounded
  wait. Both reference errors can be retried with back-off while ingress stays
  isolated. Delayed kernel release may finish, but a live external namespace,
  program pin or descriptor must retire; repeated reset does not force it away.
- `StateIndeterminate` with `ebpf_exclusive_workload_detached_program_reference`:
  a detached or unpinned program still uses a scope map after the bounded wait.
  Delayed kernel release may finish by itself; an external holder must release
  its reference. Both reference errors keep maps pinned and block attachment.
- Selector-authority, decommission or legacy selector-terminal markers, and a
  pending terminal admission on this backend, return `UnsupportedFeature`.
  They require the separate authority-bearing lifecycle, not repeated reset.
- Wrong root, invalid interface and locally managed devices require correcting
  the caller's setup. Inspection or identity failures fail closed. A concurrent
  rename/replacement can settle, but denied permissions, missing procfs,
  symlinks, nested mounts or invalid retained lock metadata require correcting
  the environment. Repetition alone does not fix them.

The operation needs `CAP_NET_ADMIN` for tc and `CAP_SYS_ADMIN` for system-wide
program enumeration whenever a map or retired program must be inspected;
`CAP_BPF` alone is insufficient. It also needs access to bpffs and procfs and
permission to use `bpf`, netlink, `openat2` and filesystem operations. Scope and
retained lock directories must have the current effective uid/gid and mode
`0700`.

An absent scope may acquire a root and empty lock hierarchy before inspection.
If reset is interrupted, complete it with the next **exclusive** reset; ordinary
attach and conservative reset may refuse its unfinished exclusion marker until
then. Success is repeatable and permits ordinary attachment on the same backend.
`reset_workload_graph` keeps its conservative contract.

Foreign filters outside the ordinary owned slot can survive a successful reset
and still make ordinary attachment refuse: another handle or protocol at the
configured priority in chain zero (including other classifier kinds, such as
u32), or a non-SDK `ETH_P_ALL` filter at handle `0:1` in another chain. A directory
named `GTPU_CURRENT_HISTORICAL_25_EXCLUSION_V1` inside a retained writer or
operation-lock directory also survives. Existing SDK generations create none of
these layouts. The strict form below also removes them when the caller can
assert its additional ownership contract.

##### Strict reset of a never-provisioned scope

Call `reset_strict_exclusive_workload_graph(scope, interface)` to make two
additional assertions: **no selector namespace has ever been provisioned in
this scope**, and **the caller owns the whole configured tc priority on the
interface named in this call, in every chain**. This is a separate entry point;
existing reset calls retain their behavior and errors.

With that assertion, selector-authority, decommission and legacy
selector-terminal markers protect no valid selector history in the scope and
are removed, including partial contents. On the named interface, every clsact
ingress/egress filter at the configured priority is removed, regardless of
classifier kind, protocol, handle or chain. At every other priority on that
interface, SDK hooks and filters whose programs reference the product's own
scope maps are removed individually, as in ordinary exclusive reset. Foreign
filters beside them survive. A predecessor at an old priority therefore cannot
strand the next ordinary attach, including when its map pins are already gone.

Declared interfaces are the name passed to the call and interface-shaped names
of scope-root entries. Alternative names resolve to the same kernel index.
On other interfaces in the calling network namespace, SDK hooks found through
those entries or scope-map references are removed, as are filters whose
programs reference recognized product maps. These removals use individual
handles; non-SDK filters count as foreign. Other namespace references, outside
program/link pins, live descriptors, non-tc attachments and references on
interfaces whose filter dumps are skipped during discovery keep the ordinary
reference refusals. Direct tc deletion stays in the calling network namespace.

A map is the product's when this build recognizes its pin name, kernel name
and definition. An unrecognized map is treated as foreign and unpinned without
an external-reference wait, even if it is a product map whose pin was renamed
or whose generation is unknown after a rollback. Another SDK workload's
recognized map pinned into this scope counts as this product's, as in ordinary
reset; recognition does not prove workload ownership. Foreign-map references
only locate filters matching the SDK attach predicate, which are removed as
the product's own hooks. They confer no authority over other filters and do not
block map unpinning. A link pinned in the scope is released when the reset
removes its pin, wherever it is attached, regardless of who created it.
Scope-wide pin cleanup otherwise follows ordinary exclusive reset.

Misplaced exclusion-marker directories are removed throughout the scope. Inside
a retained lock directory the ordinary preservation rule remains, except for an
operation lock or the writer lock of an interface known to this call. Valid
ordinary exclusions keep their inodes even for interfaces absent from the
namespace. Unfinished exclusions of known interfaces are completed before
success. Lock inodes stay held and unchanged. Resetting every intended interface
before creating any of them therefore preserves each completed exclusion.

**A false assertion can erase permanent selector authority and retirement
fences, permit reuse of a retired namespace, detach another owner's forwarding
or security policy, or destroy its recovery exclusion.** Writer and reference
guards cannot prove the absence of selector authority elsewhere. This reset is
outside [RFC 016's lifecycle](../../docs/rfc/016-opaque-gtpu-selector-namespace.md#12-security-and-privacy-analysis)
and must never be used in a selector-provisioned scope, including after
decommission.

The non-exhaustive `EbpfStrictWorkloadResetReport` has identifier-free counts of
confirmed removals that indicate foreign origin:

| Field | Removed during this attempt |
|:---|:---|
| `selector_markers` | Authority, decommission and legacy terminal marker entries. |
| `tc_filters` | Kernel filter entries that do not match the SDK's ordinary attach predicate. |
| `exclusion_marker_directories` | Misplaced exclusion directories, excluding valid ordinary exclusions and SDK publication staging directories directly under the control directory. |

A clean repeated call or a restart with only SDK leftovers reports all zeros.
Ordinary pins and other directories are not counted. Released pinned links are
also uncounted: the SDK has no ownership catalog to classify them as foreign.
If an attempt fails after confirmed foreign removals,
`GtpuError::StrictWorkloadResetIncomplete` carries its report and original error
as `source`; the variant is non-exhaustive, so external matches include `..`.
Other errors keep their original variant. Retain reports across retries: a
later success cannot recount earlier removals. Failed-attempt counts are lower
bounds, and ACK-uncertain removals remain unknown; a zero retry report does not
establish that the whole sequence found nothing foreign. Busy writers and
surviving program references keep their distinct underlying reasons and bounded
wait above; pending terminal admissions still refuse. Descriptor-relative
traversal still refuses symlinks and cross-device paths.

Strict startup cleanup and repetition after interruption need no manual node
cleanup or replacement Pod for these three layouts under these assertions.
Keep ingress isolated until it succeeds, then attach normally. Sessions and
in-flight traffic are discarded: drain or transfer emergency sessions before any
voluntary teardown. Reset does not implement drain or cross-node collection.
See [ADR 0028](../../docs/adr/0028-strict-exclusive-workload-reset.md) for the safety
argument and lifecycle contract.

#### Orphaned current-schema graph recovery

`GtpuDataplaneBackend::recover_orphaned_current_ebpf_graph_with_authority` is
the supported maintenance boundary for a current-schema graph whose original
process and interface namespace are gone while its map graph remains in
node-persistent bpffs. Product code must not unlink those pins directly. The
legacy unbound `recover_orphaned_current_ebpf_graph` deliberately returns
`AuthorityRequired` before observation or mutation. The optional replacement
interface is validated independently and may have a different ifindex; neither
the old nor replacement ifindex contributes to the persistent graph lease
identity.

Before constructing `CurrentEbpfGraphWriterProof`, the caller must establish
that the prior process cannot write the graph. A graph with retained forwarding
entries is refused unless the caller additionally supplies
`CurrentEbpfGraphDrainProof` after draining every represented session and all
traffic. These attestations do not replace SDK evidence. Before any pin is
removed, the eBPF backend:

- acquires a nonblocking exclusive `flock` on a permanent control-directory
  inode keyed only by the validated pin namespace below the canonical shared
  bpffs root;
- validates the canonical graph directory and the exact current 35-map names,
  ABIs, schema markers, configuration, PMTU state, and kernel map IDs;
- loads the committed current classifier artifacts against those exact maps
  only after the read-only inventory succeeds, derives their exact program
  identity, then unloads the temporary programs;
- enumerates all loaded BPF programs and refuses any exact live SDK program or
  foreign program that references a graph map; and
- when a replacement is supplied, proves both of its configured tc slots are
  empty immediately before proof publication and throughout cleanup.

The loaded-program scan is system-wide rather than tied to the caller's current
network namespace. It therefore detects a surviving program reference even
when the old tc hook cannot be named from the replacement namespace. An
unavailable program map-ID inventory, interrupted hook observation, changed
pin, foreign object, or inconsistent observation fails closed.

```rust,no_run
use opc_gtpu_dataplane::{
    CurrentEbpfGraphDrainProof, CurrentEbpfGraphRecoveryAuthority,
    CurrentEbpfGraphRecoveryIntent, CurrentEbpfGraphRecoveryOutcome,
    CurrentEbpfGraphRecoveryRefusal, CurrentEbpfGraphWriterProof, GtpDevice,
    GtpuDataplaneBackend,
};

# fn acquire_live_authority() -> Result<CurrentEbpfGraphRecoveryAuthority, Box<dyn std::error::Error>> { unimplemented!() }
# async fn recover(
#     backend: &dyn GtpuDataplaneBackend,
#     replacement: GtpDevice,
#     drained: bool,
# ) -> Result<(), Box<dyn std::error::Error>> {
let mut intent = CurrentEbpfGraphRecoveryIntent::new(
    "s2bu",
    CurrentEbpfGraphWriterProof::previous_writer_stopped(),
)
.with_replacement_device(replacement);
if drained {
    intent = intent.with_drain_proof(
        CurrentEbpfGraphDrainProof::sessions_and_traffic_drained(),
    );
}

loop {
    // Acquire a fresh external node fence and live async guard for every
    // attempt. The authority-bearing request is intentionally not Clone.
    let authority = acquire_live_authority()?;
    match backend
        .recover_orphaned_current_ebpf_graph_with_authority(
            intent.clone().into_request_with_authority(authority),
        )
        .await?
    {
        CurrentEbpfGraphRecoveryOutcome::Removed
        | CurrentEbpfGraphRecoveryOutcome::AlreadyAbsent => break,
        CurrentEbpfGraphRecoveryOutcome::Partial(_) => {
            // Preserve the cloneable intent and reacquire authority.
        }
        CurrentEbpfGraphRecoveryOutcome::Refused(
            CurrentEbpfGraphRecoveryRefusal::NotCurrentSchema,
        ) => {
            // Only this exact discriminator may start a separate historical
            // R5 attempt, with a newly acquired historical authority.
            break;
        }
        CurrentEbpfGraphRecoveryOutcome::Refused(reason) => {
            return Err(std::io::Error::other(format!(
                "current graph recovery refused: {reason:?}",
            ))
            .into());
        }
        _ => return Err(std::io::Error::other("unknown recovery outcome").into()),
    }
}
# Ok(())
# }
```

The first authorized mutation publishes a checksummed proof map bound to the
namespace hash, canonical graph device/inode, all 35 exact map IDs, populated
state authorization, and the proof map's own kernel ID. Normal create/adopt
fences on that reserved proof. Every surviving map and the proof remain open by
FD during cleanup. An ordinary unlink or final directory-removal failure
repins and reads back the same kernel objects before returning typed `Partial`
progress; callers retry the same request instead of handling a post-commit
transport error. If exact proof restoration cannot be established, recovery
never republishes an unfenced complete map graph. An abrupt process crash leaves
the proof pinned and an exact retry continues from the recorded map IDs. The
proof-aware state machine also keeps a disappeared, renamed, reindexed, or
newly managed replacement retry in typed `Partial` state after publication;
those changes cannot turn committed cleanup into terminal refusal. The proof
map is promoted to its terminal phase and second-pinned as a checksummed,
fsynced authority-leaf WAL before the in-graph proof is removed. Only that WAL
authorizes the final empty-directory removal or a later `AlreadyAbsent`
classification. A missing graph, empty graph directory, marker, or legacy
outcome without the exact WAL remains indeterminate and is never treated as
fresh absence.

The receipt API projects an authenticated terminal WAL into a bounded,
redaction-safe terminal receipt. If the process loses the response after WAL
publication, a fresh live target authority may use
`inspect_current_ebpf_graph_terminal` to authenticate the unchanged terminal
without creating or deleting state. The returned fixed-width r2 transfer
record includes the exact prior authority and receipt commitment and can be
persisted by an external broker. A later transfer authority must carry the
record's domain-separated predecessor-basis commitment; target equality alone
is insufficient. Transfer revalidates the graph, hooks, loaded-program
references, source receipt, locks, canonical paths, and an empty selector
authority/decommission inventory before and after rewriting the same WAL. A
wrong target, stale receipt, surviving authority, held lease, malformed source,
or changed live guard fails closed and leaves the WAL in place.

The permanent control directory is intentionally not deleted, avoiding an
inode-replacement lease split between cooperating processes. The lock cannot
fence a privileged external actor that ignores the SDK boundary. The
maintenance window must therefore still exclude out-of-band bpffs and tc
mutation. Product-owned writer shutdown, session drain, traffic gating,
finalizer retry policy, and replacement provisioning remain downstream.

#### Maintenance-only shipped-25 graph retirement

`EbpfGtpuDataplaneBackend::recover_orphaned_historical_ebpf_graph` is the sole
SDK maintenance boundary for the exact
`PreSessionSelectorStampTrafficObservationV1` generation. That generation is
sealed by the embedded
`bpf/opc-gtpu-datapath-pre-selector-stamp-traffic-observation-v1.bpf.o`
artifact (SHA-256
`a4f91b08bbd6eed69d46bf9301390e40bd9d713dff9a454ab6d98a1208cc7ac3`),
its complete 25-map ABI, canonical fixed-array values, exact program tags and
map references when hooks survive, and its predecessor leaf-hash authority
layout. The detached form is accepted only when both recorded hook slots and
all loaded program references are conclusively absent; map shape alone is not
provenance. An exact historical attached pair is reported as
`ActiveHistoricalAttachment` and is never detached by this primitive.

The request is intentionally separate from ordinary create, resolve, and
cleanup-only startup. It requires explicit stopped-writer and drained-traffic
attestations, an exact replacement name/ifindex, and the named frozen
generation. It also consumes a non-`Clone` R5
`HistoricalEbpfGraphRecoveryAuthority`: opaque scope, predecessor-basis,
host/root/leaf commitments, a nonzero fence epoch, and a nonzero operation ID
plus an asynchronous live-currentness guard. A caller retains a cloneable
`HistoricalEbpfGraphRecoveryIntent` and obtains a newly live authority for
each retry with `into_request_with_authority`; an authority-bearing request is
not reusable. Those attestations never replace live evidence: the backend takes
the predecessor and root-bound current flocks in a fixed order, proves exact
same-owner namespace/graph/authority identities, rejects populated or malformed
maps, and awaits the guard after both locks, immediately before and after every
irreversible proof/pin/directory/leaf/terminal-write effect, and before a
terminal return. Foreign layouts, held leases,
unknown children, wrong ownership or mode, partial observations, and name or
ifindex races remain fail-closed.

Caller cancellation has one explicit boundary. If the public future is
dropped before its blocking worker claims execution, the recovery closure is
not entered and no graph or authority byte changes. After the worker claims
execution, recovery is intentionally uncancellable: it completes under the
same affine authority and operation lock even if the observing task is
dropped. The exact same authority-bound request can then be reconstructed from
the retained intent and retried to retrieve the durable terminal receipt. A
lost observer is never permission to roll back or infer absence.

Recovery publishes one proof map through a deterministic private staging leaf,
dual-pins it under both authority generations, and atomically installs the
current leaf before any pin unlink. Phase and identity readback makes every
published boundary retryable: each recorded pin unlink, graph absence,
legacy-proof removal, namespace-local handoff marker, legacy-leaf retirement,
and terminal publication. `Removed` leaves the exact current `Terminal`
receipt in place. An authenticated terminal `AlreadyAbsent` requires that
same request-bound detached receipt, the handoff marker, and authoritative
absence of the graph, legacy leaf, and staging state. A genuinely never-created
target is separately reported as read-only `PristineAbsence`: it still needs
live external authority and conclusive target absence, but writes no receipt,
marker, root, or synthetic graph provenance. Every call returns
`HistoricalEbpfGraphRecoveryReceipt`, binding the
R5 authority projection, recovery/artifact/ABI/KAT/codec identities, typed
outcome, terminal-absence proof, and—on terminal success—the exact persisted
graph commitment. Unpublished `OPCH25R4` proof records decode only as unbound
predecessors and refuse without migration or mutation; ownership is never
inferred from them.

`historical_ebpf_recovery_compatibility_kat(challenge)` is an unprivileged,
pure build-artifact check. Its typed receipt binds the shipped generation,
embedded-object SHA-256, exact 25-map ABI digest, program section/tag
expectations, 25-entry namespace-commitment vector, R5 contract IDs, and a
domain-separated response to `challenge`. Its
`compatibility_contract_digest().as_bytes()` is a stable, non-sensitive
32-byte SHA-256 value for cross-language policy pins: it hashes the literal
`opc.gtpu.historical-ebpf-recovery-kat\0compatibility-contract\0r5` domain,
authority/recovery/R5-codec/KAT identities, fixed `GTPU_RECONCILER_LOCKS`
control-root identity, shipped-generation byte `0x05`, embedded object and ABI
digests, ordered section/tag expectations, and all 25 ordered namespace
commitments. For this SDK artifact it is
`530aef1851738480a3cbea857019fc0d6bdcdf6c7e1cc857f4663994d7d0e718`.
`verify_challenge_response` verifies SHA-256 over the distinct
`opc.gtpu.historical-ebpf-recovery-kat\0challenge-response\0r5` domain, that
contract digest, and the caller's 32-byte challenge. It exposes no object bytes
and makes no kernel or bpffs claim.

Ordinary entrypoints perform only an exhaustive read-only compatibility
preflight. Any complete or partial shipped-25 graph, legacy leaf, staging leaf,
or nonterminal receipt blocks before ordinary authority creation. Only an exact
terminal handoff can admit the normal current lifecycle, and it authorizes only
the bound pin namespace under the shared predecessor root. Maintenance code
must never replace this API with raw bpffs unlinking or broad root cleanup.

The terminal handoff is not itself permission to drop authority before the
replacement graph is durable. The broker first admits the authenticated
historical terminal, then the exact typed ordinary-create target publishes and
seals the complete current map/program/hook/configuration graph while retaining
that predecessor authority. If the process loses the finalization response,
`inspect_current_ebpf_graph_successor` reauthenticates the same sealed graph,
consumed terminal receipt, target kind, configuration, and unchanged authority
without mutation. Its opaque fixed-width receipt uses
`CURRENT_EBPF_GRAPH_RECOVERY_SUCCESSOR_RECEIPT_CODEC_ID`; every byte is
checksummed and its `Debug` surface is redacted. After the broker durably
acknowledges that receipt, `admit_current_ebpf_graph_successor` rechecks the
complete graph and live guard immediately before retiring each exact authority
leaf. The same process then activates only its exact retained odd traffic-gate
generation; a response-lost retry returns `AlreadyFinalized` without another
gate write only when that exact active generation, authentic R5 provenance,
and twice-stable successor still match. A fresh process instead receives the
bounded `ebpf_current_successor_typed_create` retry and must re-enter the exact
ordinary typed-create target, which reloads the retained pins before enabling
traffic. If an activation error cannot prove the paired even generation, the
SDK fences only the receipt-bound tc hooks, proves their absence, preserves all
graph/provenance pins, and requires that same typed-create retry. Partial or
ambiguous fencing remains indeterminate. Wrong tenant/fence/generation, wrong
target or configuration, live ownership, a surviving or partial authority
layout, malformed/populated pins, cancellation, and concurrent replacement
remain no-effect refusals. The ordinary create/read/mutation surfaces keep the
successor inaccessible until this sequence has completed.

#### Cleanup-only retained graph recovery authority

`EbpfGtpuDataplaneBackend::acquire_cleanup_only_recovery` is the supported
durable-reconciliation primitive for the complementary process-loss case: the
original writer is gone but the interface (and therefore its ifindex) and the
retained pin graph both survive. It takes ownership of the exact retained
current-schema graph and fences the forwarding tc hooks so the consumer can
read back and remove stale PDP contexts without reactivating the stale graph.
Product code must not manipulate those pins or hooks directly.

This primitive occupies the gap between the ordinary lifecycle and orphaned
recovery:

- `create_device`/`resolve_device` both reach program attachment, so they
  re-enable forwarding the instant retained entries exist — before the consumer
  has had a chance to remove stale contexts. Cleanup-only acquisition never
  attaches or reattaches the forwarding hooks before cleanup is complete.
- `recover_orphaned_current_ebpf_graph_with_authority` deletes the whole graph
  only under a freshly live affine external authority and requires the old
  interface namespace to be gone. The unbound method refuses with
  `AuthorityRequired`. Cleanup-only acquisition never deletes the graph and
  requires the interface to still resolve to the expected ifindex.

Before granting authority the backend proves the expected name/ifindex pair,
then performs a complete read-only inventory and ABI/capacity validation of all
35 current map pins before binding CONFIG or any other typed map. Only the exact
current PMTU-v5 and TFT-v5 graph is accepted: cleanup acquisition never creates
a missing pin, migrates an older schema, or advances a schema marker. A
canonical nonzero endpoint is then compared with the caller's configured local
S2b-U address. The independent grouped authority must still be uninitialized:
`GTPU_CONFIG6` and `GTPU_SCHEMA6` must both be all-zero and all four grouped
hash maps must be empty. A committed, populated, or malformed grouped state is
refused as `NotCurrentSchema`; this legacy IPv4 recovery path never adopts grouped
authority. Identity and retained pin/config/schema structural refusals happen
before graph mutation. Acquisition then holds the host-global namespace lease,
fences any retained live hook it owns, and recovers interrupted current-schema
commit records with forwarding disabled. Stable malformed legacy PDP content
found during that recovery is also `NotCurrentSchema`, but may be diagnosed only
after the safety fence or partial recovery; kernel/map observation and mutation
failures remain retryable `IndeterminateState`. If a later fencing step becomes
indeterminate after an earlier hook was detached, no authority is granted and
the exact request must be retried to re-observe and converge the fence.

While authority is held, the ordinary
`GtpuDataplaneBackend::read_pdp_context` and
`GtpuDataplaneBackend::remove_pdp_context_exact` boundaries operate against a
cleanup-safe datapath posture: every named pin still identifies the held map and
both forwarding hooks are authoritatively absent. Classified installation,
ordinary non-exact removal, and unrelated datapath mutation remain denied in
cleanup-only mode even if a hook reappears out of band. Reconciliation
capabilities therefore advertise exact readback and exact removal independently
from classified installation, which remains unavailable while fenced.
`activate_cleanup_recovery` is the sole explicit step that reattaches the
forwarding hooks and returns the device to normal management.

Acquisition returns an affine, supervised completion handle. Awaiting it drives
the bounded acquisition on an owned blocking worker; dropping the observing
future cannot cancel that worker, which converges the graph state under the
namespace lease and operation lock regardless. A retry therefore never overlaps
the same graph: it either observes the converged cleanup-managed state
(idempotently `Acquired`) or is refused while the prior acquisition still holds
the lease. An unexpected panic in the acquisition is caught and reported as
retryable `IndeterminateState` so the handle never hangs; the affected backend
then fails closed while its operation lock is poisoned, and recovery proceeds
on a fresh backend instance, which re-validates from kernel state.

```rust,no_run
use opc_gtpu_dataplane::{
    CurrentEbpfGraphWriterProof, EbpfGtpuDataplaneBackend, GtpDevice, GtpPdpContext,
    PdpContextLocalTeidSelector, PdpContextReadback, PdpContextRemovalOutcome,
    PdpContextSelector, RetainedGraphCleanupClassification, RetainedGraphCleanupRequest,
};
use std::net::Ipv4Addr;

# async fn reconcile(
#     backend: &EbpfGtpuDataplaneBackend,
#     device: GtpDevice,
#     local_endpoint: Ipv4Addr,
#     stale: GtpPdpContext,
# ) -> Result<(), Box<dyn std::error::Error>> {
let request = RetainedGraphCleanupRequest::new(
    device.clone(),
    local_endpoint,
    CurrentEbpfGraphWriterProof::previous_writer_stopped(),
);
loop {
    match backend.acquire_cleanup_only_recovery(request.clone()).await? {
        RetainedGraphCleanupClassification::Acquired => break,
        RetainedGraphCleanupClassification::AlreadyAbsent => return Ok(()),
        RetainedGraphCleanupClassification::Refused(reason) if reason.is_retryable() => {
            // Back off and retry the exact request.
        }
        RetainedGraphCleanupClassification::Refused(reason) => {
            return Err(std::io::Error::other(format!(
                "cleanup-only recovery refused: {reason:?}",
            ))
            .into());
        }
        _ => return Err(std::io::Error::other("unknown cleanup outcome").into()),
    }
}

// Forwarding stays disabled while stale contexts are reconciled.
let selector = PdpContextSelector::LocalTeid(
    PdpContextLocalTeidSelector::from_context(&stale).expect("local TEID selector"),
);
if backend.read_pdp_context(selector).await? == PdpContextReadback::Present(stale.clone()) {
    assert_eq!(
        backend.remove_pdp_context_exact(stale).await?,
        PdpContextRemovalOutcome::Removed
    );
}

// The sole step that reattaches forwarding.
backend.activate_cleanup_recovery(&device).await?;
# Ok(())
# }
```

Refusals deliberately separate ownership/configuration conflicts
(`InterfaceIdentityChanged`, `LocalEndpointMismatch`, `ManagedAttachment`),
retryable indeterminate evidence (`ActiveOwner`, `IndeterminateState`), and
structural repairs (`NotCurrentSchema`, `IdentityMismatch`); `is_retryable`
reports which are safe to retry with the exact request. The request, the
completion handle, and every diagnostic redact interface, endpoint, TEID, and
subscriber values.

Cleanup-only authority is retained until explicit activation or until the
backend is dropped; dropping the handle alone never reattaches forwarding and
never releases the fence. Grouped (dual-stack) attachments are not covered by
this legacy IPv4 primitive and are explicitly refused when their independent
authority is initialized or populated.

#### Drained v2 teardown for current-schema reprovisioning

`GtpuDataplaneBackend::teardown_drained_v2` is the only supported SDK path for
removing a committed endpoint-unbound v2 graph. It is an explicit maintenance
operation, not part of startup or adoption. Normal `resolve_device` continues
to reject v2, and consumers must not replace this operation with blind bpffs
unlinking or ad hoc tc changes.

Before constructing `GtpuV2DrainProof`, the caller must stop every application
writer for the target attachment, prevent new traffic, drain every PDP/session
record, and retain the exact interface name and ifindex observed for that
drain. The attestation does not override the SDK's checks: the eBPF backend
acquires the same exclusive reconciler lease, resolves the name back to the
same ifindex, rejects a normally managed attachment, proves the complete v2
program/map/hook identity, requires both exact legacy hooks before creating the
first durable teardown proof, rejects same-name duplicates and cross-direction
legacy SDK programs at every priority and handle, and independently verifies
that all forwarding and session maps are empty before changing anything. Every
proof-backed retry repeats both complete hook scans before mutation. An absent
hook is admissible only while resuming a proof that the SDK committed before
detaching either hook; map names, ABI, and the schema marker alone are never
ownership.
If the configured pin namespace is already absent, `AlreadyAbsent` is returned
only after complete ingress and egress dumps also prove that neither legacy SDK
program name exists at any priority or handle on the exact interface. A stale
hook installed with a historical non-default priority therefore fails closed
instead of being hidden by the backend's current priority.

The maintenance window must also exclude uncoordinated interface rename or
deletion, tc mutation, bpffs pin replacement, and any writer that bypasses the
SDK reconciler lease. The permanent host-global control-inode lease serializes
cooperating SDK backends by canonical pin namespace; it cannot authorize or
fence an external privileged process. The
backend repeats authoritative readback around each destructive step, but this
exclusive-writer condition is what excludes an external replace-and-restore
inside the remaining kernel check/use windows.

```rust,no_run
use opc_gtpu_dataplane::{
    DrainedV2TeardownOutcome, DrainedV2TeardownProgress,
    DrainedV2TeardownRequest, GtpDevice, GtpuDataplaneBackend,
    GtpuV2DrainProof,
};

# async fn maintenance(
#     backend: &dyn GtpuDataplaneBackend,
#     drained_device: GtpDevice,
# ) -> Result<(), Box<dyn std::error::Error>> {
let request = DrainedV2TeardownRequest::new(
    drained_device,
    GtpuV2DrainProof::sessions_and_traffic_drained(),
);

loop {
    match backend.teardown_drained_v2(request.clone()).await? {
        DrainedV2TeardownOutcome::Removed
        | DrainedV2TeardownOutcome::AlreadyAbsent => break,
        DrainedV2TeardownOutcome::Partial(
            DrainedV2TeardownProgress::PopulatedStateObserved,
        ) => {
            // Stop here. Re-establish the drain before retrying this request.
            return Err(std::io::Error::other(
                "legacy state appeared after teardown began",
            )
            .into());
        }
        DrainedV2TeardownOutcome::Partial(_) => {
            // Persist the progress evidence, then retry this exact request.
        }
        DrainedV2TeardownOutcome::Refused(reason) => {
            // Preserve the graph and resolve the typed refusal operationally.
            return Err(std::io::Error::other(format!(
                "drained v2 teardown refused: {reason:?}",
            ))
            .into());
        }
        _ => {
            return Err(std::io::Error::other(
                "unrecognized drained v2 teardown outcome",
            )
            .into());
        }
    }
}

// Only now may the caller provision the current source-port-v4 attachment.
# Ok(())
# }
```

The first authorized mutation commits a pinned, checksummed teardown proof
containing the exact interface, hook-program, live-tag, nine-map identities,
and the proof map's own immutable kernel ID. Every retry revalidates that
self-ID, the proof map's complete array ABI, and both recorded tags against the
hash-pinned frozen artifact before trusting the record.
That proof survives hook and pin cleanup and is removed only after a fresh
directory inventory proves it is the sole remaining entry. A retry therefore
continues only against surviving objects with the recorded IDs and ABI. Once
both hooks, every recorded map, and the exact proof are authoritatively absent,
failure to remove the now-cosmetic empty directory still returns `Removed`; it
must not manufacture an unfenced retry state. Before every individual pin
unlink, every surviving forwarding/session map is checked again for state. If
state reappears, cleanup stops with
`Partial(PopulatedStateObserved)`; the caller must stop the writer and drain
again before submitting the same request. Other `Partial` outcomes are durable
progress classifications for an exact-request retry. `Refused` means the SDK
made no intentional graph mutation. The caller may reprovision the current
source-port-v4 schema only after
`Removed` or `AlreadyAbsent`. While the proof pin remains, normal create and
adopt preflight returns the typed `ebpf_legacy_v2_teardown_pending`
indeterminate error instead of treating a proof-only crash state as fresh
source-port-v4 state.

Hook ownership readback is authoritative only after an uninterrupted
multipart rtnetlink dump completes with a zero status. Every data reply must
match the requested interface, clsact parent, and Ethernet protocol, and every
reply must match the request sequence and the socket's kernel-assigned local
port ID;
interrupted dumps, overruns, malformed completion, and duplicate exact-slot
owners leave teardown indeterminate and preserve the durable proof.

The identity authority for this path is the frozen
`bpf/opc-gtpu-datapath-v2.bpf.o` object from commit
`8fa98f275eea35cd16add149b609992345603c8c`, with SHA-256
`7d0c1b452ad562d4c8c286bf05a4c5308f6fd5b4c677cc3c2125b194860464a5`.
Production code parses that object in userspace solely to identify the exact
legacy programs, maps, relocations, and portable kernel tag candidates. It is
never loaded, attached, or executed by the production source-port-v4 runtime: the frozen
bytes are private to a parse-only child module whose production API exposes
only the derived, provenance-checked program tags. The privileged qualification
test loads and attaches it without traffic in a fresh, ephemeral network
namespace solely to prove the real frozen tags, program-to-map bindings, exact
detach, and pin cleanup. CI verifies the committed bytes against the exact
historical repository blob and separately compares a source rebuild's public
program/map inventory. The rebuild comparison is structural evidence; it is not
a byte-for-byte reproducible-build claim because the historical linker output
is host-sensitive.

The frozen object and its corresponding source are licensed under this
repository's Apache-2.0 license. The byte-exact authority can be restored from
the recorded Git object without rebuilding it:

```bash
git cat-file blob \
  '8fa98f275eea35cd16add149b609992345603c8c:crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o' \
  > crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath-v2.bpf.o
echo '7d0c1b452ad562d4c8c286bf05a4c5308f6fd5b4c677cc3c2125b194860464a5  crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath-v2.bpf.o' \
  | sha256sum -c -
```

Rebuilding the historical source with `scripts/build-gtpu-ebpf.sh` is useful
for program/map inventory review, but exact-byte reproduction is not currently
supported or claimed.

The frozen `bpf/opc-gtpu-datapath-v1.bpf.o` fixture is retained only as exact
generation evidence. It is the DSCP-generation artifact from commit
`4fd43cf1465a46b6afa35348b2463fa9c497fce4`, with SHA-256
`f31ccc2914f2fd61ae8f1e892e9ac0342f9e81350a4a065d5d8dcfcc9f7a943f`.
The loader validates that provenance, its old-only map inventory, and its
six-slot counter map before deriving its program tags. It does not load or
attach the object as replacement authority: a live matching hook reports the
named `PreBearerMark` generation and requires a drained reprovision. CI
independently verifies the hash and old-only program/map inventory.

Classic-tc replacement of an exact current hook still uses Aya's atomic
`attach_to_link` netlink path, not a detach-then-attach window. Both hook
occupants are proven before either is touched. Fresh provisioning rolls back a
first hook that it created in an originally empty slot; an exact pre-existing
current hook is retained if a later schema or runtime-state commit becomes
indeterminate.

All mutations through clones of one backend are serialized as one
reconciliation. Cooperating independently constructed backends and processes
cannot own the same canonical pin namespace at the same time: a nonblocking
exclusive `flock` is held on a permanent control-directory inode below the
canonical shared bpffs root, keyed only by the validated pin-namespace leaf and
independent of network namespace, interface name, and ifindex. A second live
reconciler receives `AlreadyExists`. Process exit closes the lock FD and releases
ownership automatically; the persistent control directory is not deleted, so
cooperating processes cannot split the lease through inode replacement. A
replacement can then call `resolve_device` and adopt the surviving pins. A
rolling handoff must therefore stop the old writer before the new writer adopts
the interface. Privileged processes that bypass this lease remain outside the
supported mutation model.

Selector-namespace effects additionally take a bounded `flock` on a distinct,
persistent operation-lock inode derived from the same opaque namespace hash.
This lets each durable effect release its critical section without releasing
the process-lifetime writer lease. The original control-directory inode remains
the lifetime lease so cooperating older and newer SDK writers contend on the
same upgrade-compatible safety boundary. Its exact sibling component is the
64-byte lowercase namespace hash followed by `-operation-v1`; the dot-free
component is valid on bpffs, which reserves names containing a dot.

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
delete-by-object-ID primitive. The host-global persistent control-directory
`flock` is therefore the cooperating-writer safety boundary: every SDK,
operator, and maintenance writer of these tc slots or pin paths must
acquire/observe that exclusive boundary. Uncoordinated concurrent `tc` or bpffs
mutation is unsupported. During explicit
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
retained only for exact historical-generation evidence, the frozen v2 object is
retained only for the explicit drained teardown identity proof, and the frozen
pre-redirect object is retained only to derive the program tags described in
the next section. The sealed pre-selector/stamp/traffic-observation object is
retained only to authenticate the maintenance-only shipped-25 graph. None of
the four legacy objects runs as the current datapath.

#### Map ABI and program generations across an upgrade

Two separate things can differ between the build that published a pin graph and
the build now trying to attach to it: the shape of the pinned maps, and the
instruction stream of the programs on the tc hooks. They fail in different
ways, so the loader classifies both before it changes anything.

**Map layout.** Before the object is loaded, every pin that exists is compared
against this build's map specification using kernel metadata only -- map type,
name, key size, value size and flags -- with no value type bound to any of
them. A divergence fails the attach with
`GtpuError::Io { operation: "ebpf_pin_map_abi" }`. This runs before the schema
preflight, which reads the marker out of the FAR map through a typed
`BpfHashMap` binding: a foreign-shaped FAR pin is therefore named as a shape
mismatch rather than surfacing as a schema error from an accessor that had
already assumed the shape.

`max_entries` is not part of that comparison, because a map of the wrong
capacity still binds: it is a separate hazard with its own guard, not a shape
mismatch. This layout guard is also not a generation test. The v1 and
pre-redirect generations do share this build's layout for every map they pin,
but the frozen bearer-v2 generation does not — its owner value is a different
width — so a retained v2 pin set is named here as the shape mismatch it is.

**Map capacity.** Capacity is checked separately, on every retained graph
whatever schema marker it carries, and fails with the same `ebpf_pin_map_abi`
error before anything is loaded.

Judging only graphs that already carry the current marker would leave a graph
this build itself creates permanently unusable: migrating a pre-v5 graph
advances the marker to v5 while the loader adopts the retained counter pin
unchanged, so a narrower map would pass the gate on the way in and then fail it
on every attach afterwards, with no path back. Refusing before that migration
leaves the graph exactly as it was found, so a drained reprovision still
resolves it. The cost is real and is not hidden: an upgrade that grows a counter
slot now requires a drained reprovision, where it previously succeeded and
miscounted.

This is the case nothing else can see. A counter map retained from a build with
fewer slots has exactly the key and value type this build expects, so every
typed accessor binds to it happily, and the kernel silently discards each write
to a slot at or past its `max_entries`. Adopting it produces a counter that is
permanently zero -- a wrong operator-facing number rather than an error.
Growing `COUNTER_SLOTS` therefore now makes a retained current-schema graph
refuse until it is reprovisioned.

A graph still carrying a pre-v5 marker is judged on capacity too. Otherwise an
empty-graph migration could advance the marker while retaining a narrower
counter pin and leave a current-marker graph that can never satisfy this build.
The frozen v1 and pre-redirect artifacts both carry six-slot counter maps, so
their authentic retained graphs require drained reprovisioning rather than
automatic migration. The map has grown once more since, from seven to sixteen
slots for the missing-consumer counter, and a graph retained with the
seven-slot map is refused in the same way. Eight of the sixteen slots are
reserved, so that the next counter leaves the width as it is.

**Program generation and graph identity.** Replacing a hook in place requires
exact program-tag equality, because the replacement is a single
`RTM_NEWTFILTER` against the existing filter rather than a detach followed by
an attach. A live hook running an older generation can never satisfy that.
Before pin-graph or forwarding-state mutation, the loader completes both
clsact ingress and egress filter dumps and inventories every SDK-named
occupant on either hook at any protocol, priority, handle or chain. Each
occupant retains that complete placement identity, so an off-slot duplicate
cannot hide behind an empty or current configured slot.

Each tc program ID is then correlated with one unambiguous entry from a
complete loaded-program listing. Its tag is compared against tags derived
offline from the objects this build carries. A recognised historical
generation, or an SDK-named program whose tag matches no generation this build
can name, fails with `GtpuError::DatapathGenerationMismatch`, naming the
observed and expected generation. Positive historical or unrecognised evidence
takes precedence over every current-generation placement or pin-graph
conflict, so dump order cannot change the refusal.

When all observed SDK programs are current, each must be the sole instance of
its ingress or egress SDK program role and occupy its configured parent,
Ethernet protocol, priority, handle and default chain. An extra or misplaced
current program returns `GtpuError::AlreadyExists`. A current program whose
exact required pin paths are all conclusively absent does too: creating new pin
names cannot prove ownership of maps already bound to a live program.

For each exactly placed current program, the loader reads its complete kernel
map-ID set and independently opens every exact required named pin for that
program. The two complete, duplicate-free ID sets must be equal before any map
value is read through a typed binding. A complete but different graph returns
`GtpuError::AlreadyExists`. Any missing or ambiguous program identity,
incomplete loaded-program listing, nonempty proper subset of the required pins,
or unreadable named pin graph returns `GtpuError::StateIndeterminate` with
operation `ebpf_generation_identity`.

That refusal removes no pin, creates no pin, writes no policy or config, and
replaces no hook, and `create_device`, `resolve_device` and
`create_device_with_endpoints` all behave the same way.

The ordering is the whole point. Such an attach is going to fail whatever else
happens, so discovering it only at the hook means everything ahead of it has
already run against a datapath this process does not own: pins materialized for
maps the older generation never had, and commit-record recovery writing into
forwarding maps a live program is reading. Deciding first turns a guaranteed
failure into one that changed nothing.

It is also why no automatic counter rebuild is performed here. Unlinking a
counter pin and republishing it while an unreplaceable hook stays attached
would split metrics between the map the live program still writes and the map
the pin now names, and no retry could converge, because the pin would by then
be this build's shape while the tag still differed.

The frozen v1 generation is recognised as
`EbpfHistoricalDatapathGeneration::PreBearerMark`. Its exact tags improve the
diagnostic; they do not authorize replacement. A complete live v1 graph is
therefore rejected by the generation guard before pin-graph or
forwarding-state mutation and before map ABI or schema reads. If the hooks are
already absent but the v1 pins remain, the capacity guard names the six-slot
counter map as `ebpf_pin_map_abi`. Both paths leave the graph untouched and
require the same drained reprovision.

There is no automatic live migration across generations. The remedy for a
refusal is the documented one: drain the device, remove the pins, and
reprovision. Because the refusal leaves the live datapath exactly as it was
found, that remedy is still available after any number of refused attempts.

**Counters and re-baselining.** A rebuilt counter map starts at zero.
`EbpfGtpuDatapathSnapshot` publishes the kernel map ID of every counter map
whose values it reports -- `counters_map_id`,
`downlink_binding_counters_map_id` and `uplink_pmtu_counters_map_id` -- and an
ID changes only when that map is rebuilt. On an identity change, discard prior
deltas and re-baseline from the new value; do not alert on the step. A consumer
that treats these counters as monotonic and ignores the identity will read a
rebuild as either a negative delta or a full-value spike, depending on how it
clamps. Kernel map IDs are per-boot and are recycled, so a baseline persisted
across a host reboot may observe the same ID for a different map; pair the ID
with a boot identity if a baseline has to outlive the host.

### Grouped dual-stack eBPF contract

#### Selector namespace admission

Products open `GtpuSessionSelectorNamespaceAuthority` only through
`open_protected`, using an SDK-owned `EncryptingSessionBackend` or
`RemoteSealingSessionBackend` around the durable store, then call
`reconcile_fresh` rather than constructing a grouped reconcile request. The
SDK derives the ledger key from that sealed payload boundary, the explicit
tenant/NF storage scope, and the stable device; products cannot select a raw
namespace key or assert their own protection boundary. It creates the private
request around an opaque, affine `GtpuSessionSelectorAdmission`, binding the
stable device namespace, exact group ID, canonical complete set of uplink
`(family, PAA, mark)` and downlink `(outer family, inner family, local TEID)`
selector atoms, and a nonzero authority generation. `Fresh` is not a public
assertion and no public constructor can replay or cross-bind an admission.

`GtpuSessionSelectorNamespaceAuthority` owns this transition over the
SDK-protected `SessionStore` boundary. The store persists the entire opaque,
versioned ledger as one durable multiprocess compare-and-swap record, sealed
before reaching its underlying adapter. It includes all atom claims, group/set
bindings, permanent tombstones, the authority generation, and committed
device/key/capacity configuration, so the ordinary sequential session-store
batch API is not sufficient. The supplied
`InMemoryGtpuSessionSelectorNamespaceStore` is only a deterministic
conformance model, not a production authority. On ambiguous durable
completion, the coordinator reads back the exact mutation fingerprint; if it
is not exact, it fails closed. A durable adapter retains a Retiring or Poisoned
state for unresolved external teardown. Retire the authority claim before
dataplane removal and require an SDK/backend-qualified drain/RCU receipt before
reissuing a retired selector set. Product assertions do not qualify.
Diagnostics expose only bounded state classifications,
never selector, subscriber, or digest values.

For a returning single-bearer session with the retired PAA/mark and a new local
TEID, call `reconcile_reattached`. The SDK finds the unique completely retired
predecessor in the same protected ledger, obtains exact backend retirement and
reader-quiescence proof, and commits one successor edge plus the never-published
TEID and complete install intent in one transaction. Active, stale, incomplete,
changed, or already-consumed predecessors cannot authorize reuse. Old TEIDs and
all history remain reserved. This bounded admission preserves the original
`reconcile_fresh` and whole-set reuse checks; it does not implement general
mixed-selector admission or backend-loss restore. Its first claim upgrades the
ledger to `OPCSN17`, which older readers refuse. Pending intent recovery uses
the same supervised exact recovery path after reopen or caller cancellation.
The record and permanent-group capacity limits remain unchanged.

For a marked voice bearer sharing a current unmarked IPv4 default, use
`reconcile_bearer` with the exact parent claim, parent group and new child group.
The bounded profile permits one live or unresolved child per default. It
retains the default's installed context and authority rather than retiring it.
The child has a distinct local TEID and owns its exact `(PAA, full-mask mark)`
selector, so unrelated default PAAs may use the same numeric mark. Legacy
canonical fingerprints and `Fresh` mark reservations are unchanged. The
protected `OPCSN18` ledger records the immutable child-parent relationship;
parent retirement waits for exact child retirement.

When the caller needs no separate parent capability, use
`reconcile_bearer_under_active_parent` with the complete parent and child
groups. It resolves the exact existing Active parent inside the child
operation's fenced lease, eliminating a separate `recover_active` operation.
The protected parent descriptor and fresh backend qualification remain
mandatory, as do all three child writes and their durable readbacks. Missing,
changed, marked or retired parents are refused; this entry point cannot repair
or reattach a parent. The concurrent operations handle reserves both groups
and all conflicting selectors before resolution. Cancellation detaches only
the observer, and independent groups retain the same bounded progress rules.

Use the ordinary exact child recovery and retirement operations after a failed
or cancelled call. Mark reuse requires source quiescence and a fresh local TEID;
reuse after default reattach additionally requires the protected predecessor
chain to the current parent. A stale parent or another subscriber cannot claim
that history. Child changes invalidate issued and pending parent traffic proof
before possible map mutation. Product classifier/owner settlement and new
traffic proof remain necessary afterward. See
[RFC 016 §5.5](../../docs/rfc/016-opaque-gtpu-selector-namespace.md#55-marked-child-under-a-resident-default).
`testkit::GroupedGtpuDataplaneSimulation` composes the protected coordinator,
adapter codecs, index construction and inventory validation for structural
consumer tests. Its in-memory effects are atomic; it does not model staged
kernel IO faults or proof revocation and refuses live proof issuance.

The built-in eBPF quiescence mechanism requires a qualified non-realtime Linux
XDP/TC profile with non-expedited `MEMBARRIER_CMD_GLOBAL` available. Exact
retirement and selector absence are checked before and after that boundary
under the host effect lock and current durable lease. Realtime/unknown kernel
profiles, `nohz_full`, denied syscalls, or changed authority fail closed; there
is no delay or expedited-barrier fallback. See [RFC 016 §5.4](../../docs/rfc/016-opaque-gtpu-selector-namespace.md#54-single-bearer-reattach)
for the kernel assumptions and durable codec. Simulated adapter regressions
prove lifecycle decisions, not real kernel RCU or forwarding qualification.

Each process admits a bounded queue of selector operations but polls exactly
one worker per protected storage-scope commitment from durable lease
acquisition through release. This is part of the fence: a same-owner
`SessionStore` acquire is replica recovery and replaces the prior credential,
so concurrent local workers must never mint overlapping backend windows.
Dropping an operation observer, including `open_protected`, does not cancel
the owned worker or release that gate. Across processes, every replica must
use the stable, replica-unique `OwnerId` required by the session-store
contract; reusing one owner identity in multiple live processes is not a
supported concurrency model.

The backend trait expansion is additive, and existing `GtpuProbe` fields and
legacy v5 map-key bytes are unchanged. The grouped-session construction
migration is deliberately not additive: public `Fresh` assertion and public
request construction are removed, so callers must use the protected
coordinator. The current eBPF backend opts in only
after the live attachment proves its exact schema, configuration, named map
identities, tc programs, and held namespace lease. The async, fallible
`gtpu_ip_family_capabilities` query accepts a
`GtpuSessionAttachmentSelector` containing the stable device identity, exact
live name/ifindex, and endpoint set, so evidence is never reported globally
for a backend that manages several attachments. Missing, mismatched, or
changing attachment evidence withdraws the capability. Ordinary Linux
generic-netlink GTP remains `Unsupported` for atomic grouped reconciliation
because its per-context commands have no external activation gate.

`CreateGtpDeviceEndpointSetRequest` binds a cryptographically stable device
identity to an exact local set containing at most one IPv4 and one IPv6
endpoint. That identity selects the pin namespace independently of a mutable
ifindex. Every reconcile, readback, and adoption must revalidate both the live
interface identity and exact endpoint membership. Capability evidence repeats
the exact named-map identity around schema, configuration, and live-hook
inspection. Create and adoption preflight the exact pin namespace and both tc
slots before publication. Partial, foreign, or changing identity evidence
fails closed.

A `GtpuSessionGroup` has a caller-owned cryptographically unique ID and one or
two canonical inner-family entries. Inner IPv4 is a `/32`; an IPv6 PAA is
projected explicitly to the TS 29.274 `/64` forwarding identity. The owned
public context is normalized to that address, so equality and restart readback
never depend on an interface identifier omitted by the ABI. Outer peer and
local addresses remain exact `/32` or `/128` endpoints and may use a family
independent of the inner slot. Removed group IDs are permanently retired by
the caller for that stable pin namespace lifetime; the dataplane does not
accumulate permanent tombstones.

The separate family-tagged schema uses one ordinary non-per-CPU HASH authority
value updated only by whole-element replacement. Fresh creation publishes a
fenced Pending generation 1, stages exact `NOEXIST` indexes, then commits
Active. Update leaves Active generation N authoritative while it stages
dual-candidate N/N+1 selector values, replaces the authority once with Active
N+1, verifies it, and removes exact N candidates. Removal writes Removing
first, deletes exact owned indexes, and deletes authority last. The journal
stores byte-exact base and desired graphs only while an operation is in flight;
missing or mismatched recovery evidence never authorizes guessed cleanup.
The authority map, transaction journal, and each selector index are sized for
65,536 entries per attachment. Each dual-stack group consumes two entries in
the uplink index and two in the downlink index, so the selector budget limits
an all-dual-stack attachment to 32,768 groups rather than 65,536.

A tc consumer retains the decoded index value first, extracts the group ID,
performs one authority lookup, validates the selected generation and slot, and
never re-reads the index. An old RCU holder may finish with its retained values.
Consequently, `GtpuSessionGroupReconcileRequest` requires explicit selector
provenance. `Fresh` attests through the SDK's protected selector ledger that an
introduced selector has never been published in the pin namespace. Reuse
carries the complete exact retired source group plus an attestation that
traffic was drained or an RCU grace period completed after exact removal.
For whole-set reuse, one retired proof must cover every selector introduced
relative to the active base generation. The separately issued `Reattached`
profile reserves one never-published local TEID with the exact retired PAA/mark
as described above; combining selectors from several retired groups fails closed.
Direct transfer from a live source group remains forbidden, and cross-device
or same-group reuse evidence is rejected before mutation.

The shared IPv6 envelope contract keeps a dual-purpose tc hook transparent to
unrelated IPv6 traffic: non-GTP-U traffic, packets requiring reassembly, and
unsupported AH/ESP processing pass to the host stack. Once UDP/2152 is proven,
malformed IPv6/UDP/GTP-U boundaries or an invalid mandatory IPv6 UDP checksum
become reject candidates before session lookup.

Uplink outer-IPv6 checksum support has one explicit qualification contract:
`MaterializedOnly`. Before `bpf_skb_adjust_room`, tc rejects non-zero
`gso_size`, then performs a reversible non-pseudo
`bpf_l4_csum_replace` probe on a safe even 16-bit word. The first update must
change the word and the reverse update must restore and reload the exact
snapshot; any error drops. Because Linux leaves the target unchanged for
`CHECKSUM_PARTIAL`, only fully materialized, non-GSO bytes proceed to software
IPv6 UDP checksum generation. This contract does not claim GSO or checksum
offload support.

## Status And Limits

- This is an unpublished workspace crate (`publish = false`).
- The userspace crate forbids `unsafe`; raw kernel UAPI work is isolated in
  `opc-linux-gtpu-sys`, while verifier-bound packet/map/helper access and the
  isolated ingress-mark read remain in the standalone eBPF program crate.
- Linux is the supported platform. Retained non-Linux code and tests are
  compile-checked for `x86_64-unknown-freebsd` with default features and
  `--all-targets`; CI does not execute them on non-Linux hosts. The Apple check
  excludes this crate because its dependencies require an Apple C toolchain.
  `aya`, `aya-obj`, `rustix`, `nix` and `sha1`
  are declared only under `cfg(target_os = "linux")`, and so
  are the kernel runtime, the reassembly socket, and the `/proc` and sysctl
  readers. The Linux-only part of the public surface is the eBPF backend's
  `new`, `with_config` and `Default` constructors and the `reassembly` sysctl,
  statistics and socket exports; everything else exported from `lib.rs` is
  available off Linux, including the model, `MockGtpuDataplaneBackend`,
  `UnsupportedGtpuDataplaneBackend`, the redaction-safe errors, the ICMP
  builders and `probe_committed_classifier_load`, which answers
  `ClassifierLoadBlocker::PlatformUnsupported` there. Because the eBPF backend
  has no non-Linux constructor, the portable trait-object path off Linux is
  `UnsupportedGtpuDataplaneBackend`. The probe helper that fills
  `downlink_outer_fragment_handling` nonetheless answers
  `GtpuDownlinkFragmentContract::Unsupported` off Linux and never a kernel
  reassembly handoff -- the handoff names a Linux `ipfrag` stack that is not
  present, and its `bounds: None` would say only that the stack's limits were
  unreadable. The unit test
  `downlink_fragment_contract_reports_kernel_handoff_only_on_linux` contains
  the off-Linux assertion for this crate-internal invariant; CI compiles that
  assertion for FreeBSD but does not execute it. CI validates Linux, including
  a separate build with
  `RUSTFLAGS="--cfg opc_linux_gtpu_sys_force_unsupported"` and
  `--no-default-features` that exercises unsupported-backend behavior on Linux.
- The Linux netdevice backend follows mainline `gtp` behavior and is not the
  ePDG uplink datapath.
- The eBPF backend requires bpffs, kernel BTF, tc/eBPF privileges
  (`CAP_NET_ADMIN` and `CAP_BPF` or `CAP_SYS_ADMIN` for loading;
  `CAP_SYS_ADMIN` for the global program scans used by reset and retained-graph
  inspection), and enough MTU headroom
  for 36 bytes of outer IPv4/UDP/GTP-U headers or 56 bytes of outer
  IPv6/UDP/GTP-U headers. The current object also uses the bounded `bpf_loop`
  helper (available in mainline Linux 5.17 and newer) to checksum the complete
  declared UDP range and walk IPv6 extension headers without verifier
  unrolling. The full privileged datapath suite runs against two profiles:
  Linux 6.8 or newer, and the RHEL 9.4 `5.14.0-427` line described below. Do
  not read either as a version floor to compare against.
  CI loads both committed classifiers on exact Linux 6.8.0-134 as a verifier
  compatibility gate in addition to running the full privileged datapath suite.
- Helper availability is not loadability, and the `bpf_loop` note above is not
  a supported-kernel floor. Whether a kernel accepts this object depends on how
  its verifier accounts for the checksum callback chain against the cumulative
  512-byte BPF stack limit, and that can differ between kernels that all expose
  the helper. A `bpftool feature probe kernel` inventory reports helper *names*
  only; it cannot detect a verifier rejection of the committed object, so a node
  admitted on that basis can still fail `BPF_PROG_LOAD` with no symptom beyond
  zero forwarding.
- **The RHEL 9.4 / `5.14.0-427` kernel line is gated for verifier
  loadability and datapath behavior.** That is the line Red Hat CoreOS ships
  for OpenShift 4.18, and it is an enterprise backport rather than a mainline
  kernel, so helper availability alone would not have settled it. CI boots a
  digest-pinned Rocky 9.4 image, asserts the guest is on `5.14.0-427.*el9_4*`,
  loads both committed classifiers there, and runs the full privileged datapath
  suite on that kernel on every run.
- **What that gate does and does not establish.** It proves both classifiers
  pass `BPF_PROG_LOAD`, and it runs the privileged datapath suite on that
  kernel in a fresh network namespace: attach, encap/decap, PMTU and fragment
  handling, checksum boundaries, counter aggregation and ownership-safe
  teardown. It says nothing about a node's SELinux policy for a confined
  container domain or a reduced-capability deployment (CI runs as root),
  in-pod bpffs availability under an immutable host, MTU headroom against a
  given CNI, or coexistence with another tc/eBPF program on the same
  interface. It also runs one digest-pinned z-build: the guest assertion
  accepts any `5.14.0-427.*el9_4*`, but an OpenShift 4.18.z node will be on a
  z-build this gate has never executed. Treat it as necessary, not sufficient,
  for a given cluster.
- A loadability verdict here is about this object only. It does not speak for
  whatever node-admission policy a deployment configures, and it is not itself
  an admission decision.
- Other kernels — outside both the 6.8-or-newer profile and the gated 5.14 line
  — are **unqualified rather than known-good or known-bad**: this repository
  states no verdict, because CI proves the load only on the kernels it gates. Do
  not infer support from a version comparison in either direction. Establish it
  on the node with [`probe_committed_classifier_load`], which attempts the real
  committed load and answers `Loadable`, `VerifierRejected`, or
  `UnableToAttempt`, attaching nothing and leaving no pinned state behind.
- The ignored privileged eBPF proof additionally requires the `wireguard`
  kernel module plus `ip`, `tc`, `ethtool`, `nft`, `wg`, and Python 3. It does
  **not** require the `gtp` kernel module: this is the tc/eBPF path, and `gtp`
  is a prerequisite of the separate netdevice suite only. CI preflights and
  installs these prerequisites. A platform without them is explicitly
  unavailable for this proof, and both gates fail rather than pass when a test
  reports itself skipped, because a skipped run counts as a pass to the test
  harness and is not positive datapath evidence.
- eBPF cleanup checks exact BPF program IDs and named pin map IDs, but classic
  tc/bpffs cleanup requires the documented exclusive-writer boundary; it does
  not claim atomic conditional deletion against uncoordinated external writers.

## Scoped local lifecycle

`EbpfGtpuDataplaneBackend::for_local_scope` binds the backend to the shared
[`LocalKernelLifecycle`](../opc-local-kernel-lifecycle/README.md). All three
legacy workload resets refuse with `LegacyResetOnLocalScope`; ordinary retained
graph mutation/adoption entry points are unavailable on this binding.

After contained reset, `rebuild_local_graph` loads the current embedded image,
initializes and verifies its grouped configuration, PMTU state and packet gate,
then publishes an empty graph. `install_scoped` requires a real
`CommittedScopeEffect` and stages exact selectors before publishing the group.
Successful lifecycle opening removes every containment filter.

The actor owns partial effects and exact undo after cancellation. Published
retry and `read_scoped` use local readback during store outages;
`remove_scoped` removes only its receipt's group and selectors, with qualified
kernel-reader synchronization. Changed values and stale receipts cannot remove
a successor. Occupied selectors and admission saturation wait with backpressure.
Dropping a published receipt preserves forwarding. Normal shutdown uses the
shared contained reset, including XFRM and DSCP participants.
Confirmed removal drops the actor's full request and reservation. Caller-held
receipts retain a retirement marker, and recovered activation tokens share
bounded consumption bits; no actor tombstone list grows with session churn.
Consumers still enforce durable `GtpuSessionGroupId` non-reuse. An opening that
exceeds ten seconds restores containment and returns `OpeningAttemptExpired`
once closure is verified; the supervisor does not restart opening indefinitely.

This path adds no durable journal or old-image compatibility reader. Its native
lifecycle tests are separate from the established privileged datapath suite;
qualification of that suite alone does not qualify this lifecycle on a kernel.
Graph inspection uses retained load/private-pin descriptors and exact tc
observations, without BPF ID reopen or node-wide enumeration. Undeclared BPF
neighbors remain untouched and refuse the reference proof. TCX query support
and the existing `CAP_BPF`/`CAP_NET_ADMIN` profile are required; this scoped
path adds no `CAP_SYS_ADMIN` requirement. See RFC 025's
[native prerequisites](../../docs/rfc/025-local-kernel-lifecycle.md#native-prerequisites).

## Roadmap

- Qualify a bounded grouped outer-IPv4/IPv6 fragment-reassembly consumer before
  advertising either independent per-family capability.
- Qualify additional checksum/GSO offload states before broadening the
  `MaterializedOnly` outer-IPv6 contract.
- Keep privileged integration tests as the source of truth for Linux kernel and
  tc behavior.
- Add product-level route/XFRM/namespace orchestration in consumer crates rather
  than in this backend crate.

## Verification

```sh
cargo test -p opc-gtpu-dataplane
sudo modprobe gtp
sudo modprobe wireguard
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test linux_gtpu_privileged -- --ignored --nocapture --test-threads=1'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test ebpf_gtpu_privileged -- --ignored --nocapture'
```

The backend trait exposes `open_gtpu_control_port` for eBPF attachments with
an IPv4 endpoint. Handles share one queue and lose access on removal,
replacement, backend loss or observed hook loss. Linux kernel/mock adapters
return an exact unsupported result. See the [control-port contract](docs/control-port.md)
for socket lifetime, response budgets and the remaining backend limitations.
Validated nonzero unknown-TEID G-PDUs can reach only the configured local
control endpoint without decapsulation. Retained inconsistent ownership stays
dropped. The consumer must establish current absence and its response policy;
receiving a packet does not authorize a tunnel change or automatic reply.
