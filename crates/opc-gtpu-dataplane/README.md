# opc-gtpu-dataplane

## Purpose

`opc-gtpu-dataplane` is the safe Rust control surface for OpenPacketCore
GTP-U dataplane state. It models GTP devices and PDP contexts, provides Linux,
eBPF, mock, and unsupported backends, and keeps raw syscalls in
`opc-linux-gtpu-sys`.

The crate does not implement GTP-C, PFCP, packet parsing, namespace management,
route steering, XFRM policy, deployment defaults, or traffic-readiness policy.

## API Shape

- `GtpuDataplaneBackend`: async port for device and PDP lifecycle, typed PDP
  readback, classified installation, authority-safe exact removal, and probes.
  The reconciliation methods are additive defaults, so existing third-party
  implementations remain source-compatible and report typed unsupported
  results until they opt in.
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
  `GtpuDownlinkEndpoint`, `GtpuSourcePortPolicy`, `GtpuSourcePortRange`,
  `PdpContextSelector`, `PdpContextReadback`, `PdpContextInstallOutcome`,
  `PdpContextRemovalOutcome`, `PdpContextConflict`,
  `PdpContextMismatchField`, `PdpContextIndeterminateReason`, and
  `PdpContextReconciliationCapabilities`,
  `EbpfGtpuDatapathSnapshot`, `EbpfGtpuDatapathCounters`, `DscpCodepoint`,
  `GtpRole`, `GtpVersion`, `GtpAddressFamily`, and `GTPU_PORT`.
- `GtpuError` is intentionally redaction-safe; TEIDs and addresses are not
  emitted by `Debug`/`Display`.

## Usage

```rust,no_run
use std::net::{IpAddr, Ipv4Addr};

use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpPdpContext, GtpVersion, GtpuDataplaneBackend,
    GtpuSourcePortPolicy, MockGtpuDataplaneBackend, RemovePdpContextRequest,
    Teid,
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
is rebuilt from validated pinned v3 state on adoption and maintained inside the
same serialized publication/removal boundary. It is not a new datapath map and
does not change the pinned schema. Partial graphs, transitional marked owners,
index disagreement, changed observations, a second writer, or lost program/map
identity return indeterminate without deleting state. Exact removal uses the
same authority and confirms both selector axes absent afterward.

The Linux `gtp` adapter uses response-required generic-netlink `GETPDP` queries
for both axes and requires two identical bounded observations. It validates the
outer generic-family message type, the kernel's historical family-ID-in-command
reply quirk (or a future canonical `GETPDP` command), every known attribute,
MS/PAA-family consistency, selector correlation, and the complete returned
identity. `GTPA_FAMILY` describes only the inner MS/PAA lookup key; the outer
peer family follows the GTP device's UDP socket and may differ. Current kernels
may omit `GTPA_FAMILY`; one unambiguous MS/PAA attribute still determines its
family independently of the required peer attribute. Linux currently stores an
IPv6 MS/PAA as a canonical `/64` prefix. A kernel that cannot perform the
requested family lookup fails closed rather than reporting absence. Mainline
Linux exposes unconditional `DELPDP` but no compare-delete primitive or
cross-process writer lease, so `remove_pdp_context_exact` is intentionally
unsupported there.

Readback/classified-install/exact-removal capabilities are reported separately
through `pdp_context_reconciliation_capabilities`; they are not inferred from
packet-processing fields in `GtpuProbe`. The mock implements the full stateful
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
IPv4 or IPv6 endpoint pairs so adapters can share one contract; the current tc
object remains IPv4-only and rejects IPv6 before publishing any state.

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

Existing `GtpPdpContext` literals must add `bearer_mark: None` to retain the
default path, or construct a non-zero `GtpBearerMark` for a dedicated bearer;
they must also choose an explicit `downlink_source_port_policy`. Code that
constructs `GtpuProbe` literals must initialize `per_bearer_marking` and
`downlink_endpoint_binding`. Consumers must gate `bearer_mark: Some(_)` on
`GtpuProbe::per_bearer_marking == GtpuCapability::Available`; it becomes
available only after both exact live tc programs and every exact v3 map pin
have been verified. The mainline Linux `gtp`, mock, and unsupported backends
report `Missing` and reject marked requests. This API requires no Cargo feature
and introduces no dependency.

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
and all exact v3 map pins; endpoint binding additionally verifies the exact
downlink attachment plus its binding and fixed counter maps. Runtime program or
map identity loss reports `Missing` and blocks new state publication, while
identity-safe cleanup remains available under the rule above.

### Pinned-map and live-program migration

The endpoint-bound v3 schema keeps the legacy default FAR, DSCP, and PDR
names/layouts and the v2 marked FAR/DSCP/PDR names. It adds
`GTPU_DL_BIND` for the canonical per-TEID endpoint identity and
`GTPU_DL_DROP` for six fixed mismatch counters. The marked owner journal now
embeds that complete binding, so its map value is intentionally incompatible
with endpoint-unbound v2 pins. With an explicit `Any` source-port policy,
`bearer_mark: None`, and `egress_dscp: None`, uplink wire bytes remain
byte-for-byte compatible; downlink authorization is deliberately stricter.

The durable `OPC-PEER-v3` value at the reserved impossible-PAA key in the
legacy FAR map is the schema commit. It is written only after every named map
identity is verified, the complete map graph is canonical, and both current tc
programs have been attached and read back by exact program ID. A committed v3
marker with a missing required pin, an unknown marker, or a foreign tc occupant
fails closed before Aya can recreate empty state. A positively absent current
hook may be repaired.

There is no implicit endpoint migration for populated older state. A committed
v2 pin set is rejected with the redaction-safe `ebpf_endpoint_schema` error and
requires an explicit traffic drain followed by pin removal and reprovisioning.
An uncommitted, legacy-v0, or DSCP-v1 graph can advance only when it is empty;
any retained PDR/FAR without an exact binding is indeterminate and fails before
either hook changes. The SDK never invents `Any`, derives a peer from an
untrusted packet, or labels endpoint-unbound forwarding state production-ready.

#### Drained v2 teardown for v3 reprovisioning

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
SDK reconciler lease. The abstract-socket lease serializes cooperating SDK
backends; it cannot authorize or fence an external privileged process. The
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

// Only now may the caller provision the endpoint-bound v3 attachment.
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
made no intentional graph mutation. The caller may reprovision v3 only after
`Removed` or `AlreadyAbsent`. While the proof pin remains, normal create and
adopt preflight returns the typed `ebpf_legacy_v2_teardown_pending`
indeterminate error instead of treating a proof-only crash state as fresh v3
state.

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
never loaded, attached, or executed by the production v3 runtime: the frozen
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

Empty v0/v1 hook replacement is authorized only by the frozen
`bpf/opc-gtpu-datapath-v1.bpf.o` fixture. It is the DSCP-generation artifact
from commit `4fd43cf1465a46b6afa35348b2463fa9c497fce4`, with SHA-256
`f31ccc2914f2fd61ae8f1e892e9ac0342f9e81350a4a065d5d8dcfcc9f7a943f`.
The loader binds that object to the exact retained old map IDs and compares the
live program name, type, tag, and complete map-ID set before replacement. The
fixture is migration authority only; it is never selected as the running v3
datapath. CI verifies its hash and old-only program/map inventory.

Classic-tc replacement uses Aya's atomic `attach_to_link` netlink path, not a
detach-then-attach window. Both hook occupants are proven before either is
touched. If the second replacement is uncertain, the first exact v3 hook is
retained and the exact old/current second hook is left for an idempotent retry;
the migration returns `StateIndeterminate` instead of creating an empty live
slot. The same retained, retryable rule applies if schema or runtime-state
commit fails after replacing an existing datapath. Fresh provisioning still
rolls back a first hook that it created in an originally empty slot.

All mutations through clones of one backend are serialized as one
reconciliation. Cooperating independently constructed backends and processes
cannot own the same `(network namespace, canonical pin directory, interface)`
at the same time: a kernel-lifetime abstract socket provides exclusive
ownership and a second live reconciler receives `AlreadyExists`. Process exit
releases the ownership automatically, allowing a replacement to call
`resolve_device` and adopt the surviving pins. A rolling handoff must therefore
stop the old writer before the new writer adopts the interface. Privileged
processes that bypass this lease remain outside the supported mutation model.

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
retained only for the exact automatic empty-graph migration proof described
above, and the frozen v2 object is retained only for the explicit drained
teardown identity proof. Neither legacy object runs as the v3 datapath.

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
