# Shared GTP-U control receive queue

`control_port::GtpuControlPort` defines bounded, nonblocking receive and
response operations. The first implementation is the existing Linux IPv4
`GtpuReassemblySocket`. Both its legacy `receive` and new
`try_receive_datagram` consume the **same UDP/2152 queue**. One consumer must
demultiplex that queue; a competing reuse-port listener can steal controls
or reassembled user packets.

Each non-cloneable `GtpuControlDatagram` retains exact received bytes,
length, peer/local tuple and kernel ingress provenance. It reports typed
control, structurally complete G-PDU, unsupported required extension,
unmodelled message, or malformed input. G-PDU framing alone grants no
decapsulation authority: installed-selector and current-generation checks
remain in the existing consumer. Unknown optional extension bytes remain
in the original datagram. Required unknown extensions cannot enter its
G-PDU classification.

| Response plan | Transport and wire behavior |
| --- | --- |
| Echo Response | Reverse the request's exact IP/UDP tuple, retain sequence, emit Recovery zero |
| Unknown-tunnel Error Indication | Caller first establishes absence of a tunnel; copy nonzero triggering TEID, original local destination into Peer Address, and triggering UDP source-port extension; send to peer UDP/2152 |
| Supported Extension Headers Notification | Only a framed request/G-PDU with an unsupported required extension; caller supplies the bounded type list; send to peer UDP/2152 |

These rules come from
[TS 29.281 V18.4.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf),
clauses 4.4.2.2, 4.4.3.2, 5.1, 5.2.1, 7.2, 7.3.1 and 8.2.
Encoding and typed procedure validation reuse `opc-proto-gtpu`; this port
does not define a second codec. Receiver-ignored header fields and Recovery
values keep that codec's semantics. No received Recovery value changes a
generation, authorizes restart, or produces another Echo Response.

Planning consumes the receive event. Sending consumes the plan, including
on an error. The socket checks its private instance identity and exact live
local/device binding before sending and rechecks that binding afterward.
An identically addressed replacement socket refuses the old plan. Success
counts UDP payload bytes accepted by the local kernel; it does not prove
peer receipt. There is no automatic reply, retry queue or timeout worker.

Receive capacity is 8–65,507 bytes; truncation of either payload or control
metadata is an error. Per-response policy is a positive byte cap and integer
amplification cap of 1–16. The 16-fold ceiling and codec walk limits of 256
are SDK resource bounds, not 3GPP rate recommendations. The caller chooses
peer admission, an aggregate limiter, supported extension types, and whether
a G-PDU really has no tunnel. Invalid zero, unspecified, multicast or
limited-broadcast response tuples are refused. Directed-broadcast and
deployment-specific admission remain caller policy. Debug/errors contain
only static classes and lengths; packet and deployment values are exposed
only by explicit processing getters.

`GtpuDataplaneBackend::open_gtpu_control_port` exposes the queue for an
existing eBPF attachment with a concrete IPv4 endpoint. Repeated opens share
one backend-owned socket. This includes a grouped attachment with IPv4;
an IPv6-only attachment returns `UnsupportedFeature { feature:
"gtpu_control_port_ipv6" }`. Linux kernel-GTP, mock and unsupported backends
return `UnsupportedFeature { feature: "gtpu_control_port" }`. They do not
open another listener or expose their private file descriptors.

The backend checks its exact current tc hooks/maps and serializes each socket
operation per attachment, through that registration's socket slot. PDP
installs, replacements and removals on any attachment do not block or defer
the queue: authorization reads the commit-last graph exactly like tc, so a
sustained PDP churn (for example a mass re-attach after failover) cannot
starve Echo or reassembled G-PDUs. Device removal holds the slot across its
hook change and then retires it, so a socket operation linearizes entirely
before or after removal; a replaced or fenced registration is detected under
the slot before anything is received or sent. External attachment changes
are refused when observed by the live hook/binding checks. Removal closes the queue and invalidates all old
ports, including when a replacement has the same name, ifindex and address.
Ports hold weak references; keeping them alive cannot keep the backend or
its socket alive. Observed attachment loss retires the queue. Restoring hooks
alone cannot reopen that retired instance; callers must recreate/adopt the
attachment under the existing backend lifecycle. Socket bind failure leaves
no published socket and can be retried. An external listener produces a bind
error; no reuse-port distribution is enabled.

The port grants no tunnel installation, selector provenance, peer admission,
or forwarding authority. Kernel/eBPF/mock parity, IPv6 typed responses,
outgoing Echo requests, per-tunnel End Marker ordering and installed N3
forwarding remain tracked by #341 and #790.
Existing forwarding capabilities and checksum-offload control pass-through
are unchanged.

After validating the outer envelope and complete extension chain, the eBPF
classifier sends a G-PDU with a nonzero, unselected TEID to this queue only
when its outer destination is a configured local endpoint. It preserves the
GTP-U bytes and never forwards the inner packet. The unknown-TEID counter
still counts the lookup miss. A retained grouped selector with invalid
authority, or a legacy endpoint binding without its PDR, remains a drop;
neither becomes an unknown-tunnel event. This lookup-miss path refuses zero
TEID and malformed packets. Grouped IPv6 attachments deliver the raw G-PDU to
the local UDP stack, but the typed IPv6 port remains unsupported.

An observed lookup miss is not an absence receipt. Installed state can
change before a consumer processes the datagram, and the queue also serves
reassembled packets. The caller must establish current tunnel absence and
apply its peer/rate policy before consuming the event into an Error
Indication plan. There is no automatic GTP-U response or packet-driven state
mutation. This implements the receive boundary needed by TS 29.281 clause
7.3.1 while retaining the SDK's existing bounded IP-payload parser profile.

Validation uses independently authored packet literals, all 65,536 source
ports at four sequence boundaries, all 255 nonterminal extension types,
all 256 received Recovery values, malformed framing and explicit byte/ratio
boundaries. The independent standard-library Python generator
`tests/fixtures/control_port.py` produces 1,204 receive/response records:
283 controls, 129 G-PDUs, 127 required-extension events, 250 unmodelled
messages and 415 malformed inputs. TSV SHA-256:
`7b474796a8318ec926f931a86c98f535bd207545a01a6ecaa9be7c38698da783`.
CI checks byte-exact regeneration. A separate private-network-namespace UDP peer checks actual
reply bytes/tuples, the single queue, truncation, foreign and replaced socket
plans, and interface-rename refusal. It does not attach a tc program or GTP
netdevice and therefore cannot qualify their behavior. The native runner
requires exactly one executed test, its completion marker and zero ignored
tests. The PR records guard-removal results and public base/head/tree.

Separate native eBPF tests now obtain this same port through the public
backend trait. They attach the committed classifier and check all 127 unknown
required extension identifiers, original tuple/bytes, bounded notification
responses, all 127 optional identifiers and malformed suffix rejection.
The IPv6 parser handoff still uses an ordinary UDP receiver and does not
qualify IPv6 typed responses. A second native case checks dynamic-port Echo
bytes, shared-queue behavior, external-listener exclusion, kernel-observed
queued receive retirement, same-tuple reinstall, old-plan rejection, backend
loss and live hook loss. Its completion marker and exact native inventory
are required by both full privileged CI lanes. Only synthetic packets and
namespace-local addresses are used.

The backend implementation adds two unit cases for writer contention and
poisoned serialization, plus an exact unsupported-result contract test for
Linux kernel, mock and unsupported adapters. Independent Echo wire literals
exercise both legacy and grouped IPv4 attachments; IPv6-only attachments
refuse explicitly. The original parent lacks the backend method, retained
as a compile-time API detector. Four separate production guard removals
(backend exposure, live-hook check, weak backend ownership and socket release)
and an independent Echo sequence mutation each compile and fail during the
native scenario. Restored native cases pass. The PR retains exact public
base/head/tree and complete repository/hosted qualification.

The unknown-TEID native case uses the real committed tc object on both legacy
and grouped attachments. It checks exact independent Error Indication bytes,
the triggering dynamic UDP source-port extension and response service port,
both sequence-block forms, unchanged IPv6 delivery, no inner delivery,
wrong-local-endpoint refusal, zero TEID, malformed length/checksum, and retained
inconsistent ownership. Restoring the known context resumes ordinary
decapsulation without a control event. Both privileged CI lanes require its
completion marker and include it in their exact ignored-test inventory.
The original committed object fails the receive deadline. Seven separate
production guard removals (both handoffs, both local-endpoint checks, retained
legacy binding and each retained grouped-state check) and an independent
triggering-TEID mutation compile and fail at the packet assertions. Restored
sources and the rebuilt object are byte-identical and pass. The local endpoint
check adds the existing IPv4 configuration map to the downlink program's exact
map-identity set; map layouts, pin inventory and frozen historical objects do
not change.

## Backend-authoritative downlink consumer

`GtpuControlPort::try_receive_downlink` is the production consumer for G-PDUs
the kernel delivers to this queue: outer-fragmented downlink G-PDUs after
kernel reassembly (TS 29.281 clauses 4.2.4 and 4.2.5) and unknown-TEID
handoffs. Receive and authorization run under the attachment's own socket
slot, never behind unrelated backend mutation.

A consumer-decapsulated grouped packet emits no traffic observation record.
tc publishes those records to a kernel ring with a kernel-owned sequence that
userspace cannot advance atomically, so the post-reassembly path cannot join
that ordered stream. Traffic-continuity proofs therefore see only tc-path
packets; missing observations can only withhold a proof, never create one.

Authorization repeats the tc downlink decisions with the shared wire
validators and the backend's own map reads:

1. The loader traffic gate must be open. While it is closed tc passes
   packets untouched, so nothing is decapsulated on its behalf.
2. The grouped downlink index is read first. A present index never falls
   back: the Active generation, device, inner-family slot, local and peer
   endpoints, source-port policy, inner destination and any N3 PSC must
   match, and the inner length must be exact.
3. On a true index miss the v5 PDR, endpoint binding, owner journal, FAR and
   DSCP are read and the Active `PdpContextCommit` is read last as the
   publication fence. Pending, Removing, absent or mixed graphs fail closed.

**Inner IPv4 header.** The consumer stands in for tc and also for the
kernel's IPv4 input, which validated every inner packet that tc decapsulated.
Before an authorized inner IPv4 packet is returned as `Decapsulated`, its
header must pass the same checks (`ip_rcv_core`; RFC 1122 section 3.2.1.2,
RFC 1812 section 5.2.2):

- version 4, and a header length of at least five words that lies within the
  packet;
- a correct header checksum, over the options too;
- a total length that covers the header and does not exceed the received
  length.

A failure is a `Malformed` drop. Octets after the total length are not part
of the datagram and are trimmed, as the kernel trims them. The check applies
to every route into the consumer: a reassembled G-PDU, a hand-off from tc,
and grouped as well as ordinary attachments.

It matters because of the injection. An `IP_HDRINCL` send rewrites the header
checksum and the total length. A header that the kernel discarded would
otherwise be repaired and sent on, and trailing octets would become part of
the datagram.

| Event | Meaning |
| --- | --- |
| `Decapsulated` | The inner packet, its family and bearer mark (default bearer is `None`). An IPv4 packet has a validated header and ends at its total length. The caller injects it toward XFRM with that mark. The packet can be an inner IPv4 fragment; see [Inner fragments](#inner-fragments). |
| `Control` | Non-G-PDU message; use the response planners above. |
| `UnknownTunnel` | Untouched G-PDU whose TEID selects no tunnel. An observation, not an absence receipt. |
| `Dropped` | Value-free `GtpuDownlinkDrop`: malformed (including an inner IPv4 header that fails the checks above), binding mismatch, destination mismatch, state unavailable, or an over-MTU packet refused by the inner fragmenter (rate limited, or carrying IPv4 options). |
| `Fragmented` | An over-MTU DF IPv4 packet split into RFC 791 inner fragments under the default policy below, with the bearer mark. The caller injects every fragment, in order, toward XFRM with that mark. |
| `PacketTooBig` | An over-MTU DF IPv4 packet under the explicit in-tunnel Packet Too Big opt-in below; never forwarded. |

`downlink_counters` returns bounded, value-free counters for the current
attachment registration. The ordinary legacy socket port keeps the default
`Unsupported` result. Apart from the over-MTU handling below, the consumer
does not inject packets, admit peers, rate limit, or plan Error Indications.
Grouped attachments with an IPv4 outer
endpoint report `KernelReassemblyHandoff` for outer IPv4 fragments; outer IPv6
fragments remain unsupported. An ordinary attachment's inner-IPv6 contexts
live in the family-tagged authority under the attachment's own published
configuration, which is bound to its IPv4 endpoint. The consumer reads and
checks that configuration, exactly as tc selects those contexts, so
reassembled inner-IPv6 G-PDUs decapsulate on ordinary attachments too. An
IPv6 T-PDU that only reaches the IPv4-only v5 maps stays malformed, as in tc.

Native evidence runs the committed classifier on ordinary and grouped
attachments: in-order, reordered, duplicated head and tail, missing,
foreign-TEID, wrong-peer, wrong-destination, stale Pending/Removing commit,
owner-only Pending, mixed binding, closed gate, stale grouped generation,
retirement and removal. Both privileged lanes require the
`OPC_GTPU_BACKEND_REASSEMBLY_CONSUMER_PROVEN` and
`OPC_GTPU_BACKEND_GROUPED_REASSEMBLY_CONSUMER_PROVEN` markers.

### Hand-offs need a bound consumer

tc leaves some downlink datagrams to a UDP socket on the gateway instead of
decapsulating them:

| Hand-off | Queue |
| --- | --- |
| An authorized over-MTU Don't Fragment packet of a context with a downlink inner MTU | UDP/2153 |
| Every other authorized inner fragment of such a context | UDP/2154 |
| A G-PDU for one of the attachment's endpoints whose TEID selects no tunnel | UDP/2152 |
| A G-PDU for one of the attachment's endpoints with a required unknown extension | UDP/2152 |
| An outer-fragmented datagram for UDP/2152 on one of the attachment's IPv4 endpoints, which the kernel reassembles | UDP/2152 |

The kernel answers a UDP datagram for a port without a socket with ICMP Port
Unreachable (RFC 1122 section 4.1.3.1). Toward the core, that error would
quote the outer headers and the start of the subscriber's inner packet in
plaintext: up to 548 octets of the datagram over IPv4 (RFC 1812 section
4.3.2.3), and up to 1,232 over IPv6 (RFC 4443 section 2.4).

tc therefore passes a hand-off on only while a UDP socket is bound for it.
Otherwise the datagram is dropped and counted, and the host sends nothing.
This holds whenever the tc programs run with an open traffic gate: before the
control port is first opened, while the process is down, after a restart
until the port is reopened, and after a retirement. The dropped packets are
lost, as they were before; the host no longer answers them.

**The attachment's interface.** Everything below assumes that IP input
receives the endpoint's packets on the interface that tc is attached to. tc
looks for the consumer on that interface, and it cannot see what happens to a
frame after it has passed it on.

Three kinds of device take a frame from an interface after tc ran:

- **A master.** The interface is a port of a bridge, a bond, a team or a
  virtual switch. The master's receive handler moves the frame to the master
  device, or forwards it by its own flows. A bridge also sets the frame's
  type back to "host".
- **A device stacked on the interface.** A macvlan, an ipvlan and a MACsec
  device register a receive handler on the interface below them without
  becoming its master. So does an HSR or PRP device on its ports before Linux
  6.18; from then on it is their master. A macvlan takes the frames for its
  own link address, or every frame in passthru mode, and sets the frame's
  type back to "host". An ipvlan takes the packets for its own addresses.
- **A VLAN device.** The kernel gives a frame that carries a VLAN tag to the
  VLAN device of that VLAN above the interface.

The VRF and the socket bindings of the device that finally receives then
decide the delivery, and tc's lookup on the interface below does not describe
them. Measured before this exclusion existed:

- With the endpoint on a bridge or on a passthru macvlan in a VRF, and an
  unrelated socket in the default VRF: before Linux 6.5 every hand-off was
  answered with Port Unreachable. From Linux 6.5 an unfragmented hand-off was
  assigned to that socket across the VRF boundary, because the lookup scopes
  by the interface below, and a fragmented one was answered.
- With the endpoint on a macvlan or an ipvlan and a consumer on the interface
  below, on every kernel: a fragmented hand-off was answered, because the
  stacked device received the reassembled datagram.
- With a VLAN device above the interface and a consumer on the interface, on
  every kernel: tc assigned a hand-off that arrived in the VLAN to that
  consumer, although the VLAN device received the frame. A fragmented one
  passed its first-fragment check; the host delivered the reassembled
  datagram to a socket on the VLAN device, or answered it with Port
  Unreachable when there was none.

The backend refuses an interface of the first two kinds, and tc gives a
hand-off that arrives in a VLAN to no socket.

*Refused interfaces.* The backend asks the kernel for the interface's master
and for every link of the attachment's namespace. It refuses the interface

- with `GtpuError::UnsupportedFeature { feature:
  ATTACHMENT_ON_ENSLAVED_INTERFACE }` when it has a master other than a VRF;
- with `GtpuError::UnsupportedFeature { feature:
  ATTACHMENT_BELOW_STACKED_DEVICE }` when another device of the namespace
  names it as its lower link;
- with `GtpuError::UnsupportedFeature { feature:
  ATTACHMENT_IN_NAMESPACE_WITH_HSR_DEVICE }` when the namespace holds an HSR
  or PRP device.

A device that names the interface as its link is not refused when it is of a
kind that leaves the frames of that link alone:

- a VLAN device with a VLAN ID other than 0;
- the other end of a `veth`, `vxcan` or `netkit` pair;
- a tunnel or an XFRM interface that is bound to the interface: `ipip`, `gre`,
  `gretap`, `erspan`, `ip6gre`, `ip6gretap`, `ip6erspan`, `sit`, `ip6tnl`,
  `vti`, `vti6`, `xfrm`.

Every other kind is refused, whatever it does with the frames, and so is a
device that does not name its kind. That covers `macvlan`, `macvtap`,
`ipvlan`, `ipvtap` and `macsec`, and the remaining kinds that report a lower
link in Linux 5.14 and 6.8.

An HSR or PRP device names no lower link. Both are links of the kind `hsr`,
and the kernel's answer for such a device names its two ring ports. From
Linux 6.10 an HSR device can have a third port, the interlink, and it takes
the frames that arrive on it. From Linux 6.10 to 6.17 nothing in the kernel's
answer ties that port to the device: the device does not name it, which it
does from Linux 6.19, and the port names no master, which it does from Linux
6.18. The backend cannot tell which interface is the interlink, so the
presence of the device decides, on every kernel: while the namespace holds an
HSR or PRP device, every interface of it is refused. That includes an
interface that the device names as a port, one that it does not name, and the
device itself. The kernel refuses an interlink for a PRP device and names
both of its ports; the rule follows the link kind all the same. An
attachment's namespace must not hold an HSR or PRP device.

The master is asked first, so a port that names the device as its master,
from Linux 6.18, is refused as an enslaved interface. A stacked device is
named before an HSR or PRP device when both refuse the interface. All three
refusals apply in the same calls:

- `create_device` and `create_device_with_endpoints` do not attach to the
  interface.
- `resolve_device` does not adopt a retained attachment on it, and does not
  hand out one that this process already manages.
- A sealed successor on it is neither inspected nor admitted, and a
  cleanup-only attachment is not activated on it.
- `open_gtpu_control_port` does not open the consumer on it, and the socket
  that sends N3 End Markers is not bound on it.

A refusal changes nothing: no hook, no pin and no socket is added or removed.
An interface that is enslaved to a VRF is accepted: tc's lookup accounts for
the VRF, as described under "An interface in a VRF". Every other master is
refused, also one whose receive path would leave the frame alone. Attach to
the device on which IP input receives the endpoint's packets: for a bridge, a
bond or a team that is the master device itself. An interface cannot carry an
attachment while a refused device is stacked on it in the same namespace, or
while that namespace holds an HSR or PRP device.

*Frames with a VLAN tag.* The kernel takes the outermost VLAN tag out of a
received frame before tc runs, whether or not the adapter stripped it, and
keeps it beside the frame; tc reads it there. A frame whose tag has a VLAN ID
other than 0 is never received by IP input on the interface: after tc the
kernel gives it to the VLAN device of that ID, or discards it when there is
none.

tc handles such a frame as any other, with one exception. A hand-off ends at
a socket. tc looks for that socket on the attachment's interface, and for a
datagram that the VLAN device receives that lookup describes the wrong
device: no socket bound to the interface takes the datagram, and which other
socket UDP input accepts depends on the VLAN device, which tc does not see
from below. So tc treats a hand-off in such a frame as one without a
consumer, whatever is bound. It gives the datagram to no socket, also not to
one that is bound to no device or to the VLAN device, and makes no lookup for
it.

- An unfragmented datagram is dropped and counted in
  `downlink_missing_consumer`. The host does not see it.
- The first fragment of an outer-fragmented one is counted and marked like
  any first fragment without a consumer. The host reassembles the datagram on
  the VLAN device, and UDP input discards it before it looks for a socket.

In both cases no socket receives the datagram, and the host does not answer
it with Port Unreachable. What "Not covered" below says about a fragmented
datagram holds here too: one that never completes is still reported with ICMP
Time Exceeded.

Everything else is unchanged: a G-PDU of one of the attachment's tunnels is
decapsulated whether or not its frame carries a tag. So:

- An interface with VLAN devices above it is accepted.
- An attachment on the interface below a VLAN device that holds the endpoint
  still decapsulates the G-PDUs of its tunnels that arrive in the VLAN. Its
  hand-offs reach neither the control port nor an application's socket: they
  are dropped and counted. For the hand-offs to be consumed, attach to the
  device on which IP input receives the endpoint's packets, here the VLAN
  device. `create_device` pins its maps under the interface's name, and bpffs
  accepts no dot in a name, so give that VLAN device a name without one.
- An attachment judges the G-PDUs of every VLAN above its interface, as it
  always did. Do not keep one attachment on the interface and another on a
  VLAN device above it: the one below sees the frames first.
- A priority tag has the VLAN ID 0. The kernel receives such a frame on the
  interface itself, and tc treats it as the interface's own, hand-offs
  included. A VLAN device with the ID 0 would take those frames, so the
  backend refuses an interface below one.

*The boundary.* The backend refuses what the kernel's answer for the links of
the attachment's namespace reports: a master other than a VRF, a device that
names the interface as its lower link and is not of a kind in the list above,
and an HSR or PRP device in the namespace. It reads nothing else. What that
answer does not report is not detected, and is a precondition that the
deployer must meet:

- **A device that takes frames without reporting it.** A device of a kind
  that takes frames from an interface, and reports neither itself as the
  interface's master nor the interface as its lower link, is not seen. No
  such device may be above the attachment's interface.
- **A device in another network namespace.** The backend reads the links of
  the attachment's namespace. A device that is stacked on the interface and
  lives in another namespace is not among them. The interface itself reports
  nothing about it, and sysfs links an interface to a device above it only
  within one namespace. The kernel gives that namespace an ID in this one
  when a device is moved there, but not when the device is created there,
  and reading its links needs privileges in it. So the backend does not look,
  and the endpoint's frames must stay on the interface:
  - A macvlan takes the frames for its own link address, an ipvlan the
    packets for its own addresses and a VLAN device the frames of its VLAN.
    They leave the endpoint's frames on the interface while the endpoint
    lives on the interface.
  - A passthru macvlan takes every frame. Do not stack one on the
    attachment's interface, in any namespace.
  - If the endpoint lives on such a device, its address is not local to the
    attachment's namespace. The control port cannot bind it there
    (`ebpf_control_port_bind`), so the attachment never gets its consumer.
    That is not a supported topology.
  - Before Linux 6.18 an HSR or PRP device can be created in one namespace
    over ports of another. It is then not among the links of its ports'
    namespace. Do not make the attachment's interface a port of one.
- **A change after the check.** The backend asks when one of the calls above
  runs, not at every packet and not on every operation of an open control
  port. tc itself can see neither a master nor a stacked device. If the
  interface of an attachment is enslaved later, a device is stacked on it
  later, or it becomes a port of an HSR or PRP device later, the pinned
  programs keep deciding hand-offs by a lookup on the interface, which no
  longer describes where the stack delivers, and the guarantees of this
  section do not hold until the attachment is removed or the interface
  receives its own frames again. The next call above reports it.

One consequence of a refusal is left to the operator:

- **Removal after a restart.** The process that manages the attachment can
  still remove it with `remove_device`. A restarted process does not adopt
  the attachment while its interface is refused, so it cannot remove it
  either, and the pinned programs keep running. It can acquire a retained
  ordinary attachment for cleanup-only recovery, which fences its forwarding
  hooks, but it cannot activate or remove it. Release the interface from its
  master, remove the stacked device, or take the HSR or PRP device out of
  the namespace; the attachment is then adopted and can be removed.

**What counts as bound.** tc uses the kernel's UDP socket lookup
(`bpf_sk_lookup_udp`) with the datagram's addresses and ports, in the
namespace and on the device of the attachment. A socket counts when UDP input
will accept it for a datagram that arrives on that device:

- a socket bound to the attachment's interface (`SO_BINDTODEVICE`), as the
  backend's own sockets are;
- a socket bound to no device, such as an application's own socket on
  UDP/2152, which is the only consumer an IPv6 endpoint can have. If the
  interface is enslaved to a VRF, such a socket belongs to the default VRF
  and counts only with `udp_l3mdev_accept`; see "An interface in a VRF"
  below.

The check is per datagram: a socket on UDP/2152 does not make UDP/2153 bound.

**A socket that closes after the check.** A lookup is a snapshot, and the
stack looks again when it delivers. For a datagram that is not fragmented on
the outer path, tc therefore also assigns the socket it found to the datagram
(`bpf_sk_assign`), and UDP input delivers to that socket without a second
lookup. A socket that closes in between receives the datagram in a queue
that is freed with it, and nothing is sent. If the socket has already gone
when tc assigns it, tc drops and counts the datagram. In one case tc assigns
nothing to an unfragmented datagram; it is described under "An interface in a
VRF" below, and there the type of the frame keeps the host from answering.

**Outer fragments.** Only the first fragment carries the UDP header, so tc
judges an outer-fragmented datagram by that fragment. While no socket is
bound for the datagram, tc counts it. It does not drop the fragment, because
of what would happen to the others:

- The other fragments carry no port and must be passed to the host. Without
  their first fragment they would wait in the host's reassembly queue until
  `ipfrag_time` expires.
- A steady stream of them fills the namespace's reassembly budget
  (`ipfrag_high_thresh`), and every other IPv4 reassembly in the namespace
  then fails. Measured on Linux 7.1 with the defaults: about 3,600 stranded
  36-octet fragments fill the 4 MiB budget, and an unrelated fragmented
  datagram is lost until they expire after 30 seconds.

Instead tc sets the UDP Length of the first fragment to 65,535, which no
datagram can have. The host reassembles the datagram and frees the queue at
once. UDP input discards a datagram whose Length exceeds its size before it
looks for a socket, and sends nothing; it counts the datagram in its
`InErrors`.

Reassembly takes time, and it discards an assigned socket, so tc only looks
the socket up for a first fragment. If the socket closes after that fragment
passed and before the datagram is complete, the kernel answers the
reassembled datagram with Port Unreachable. tc cannot close this window,
because it sees fragments and never the reassembled datagram.

**Kernels.** The lookup is available to tc programs since Linux 4.20 and the
assignment since Linux 5.7; neither is GPL-only. Where the result depends on
the kernel or on the device:

- Before Linux 6.6 the assignment refuses a socket with `SO_REUSEPORT`. Such
  a socket is bound, so tc passes the datagram on and the stack's own lookup
  finds it; a socket that closes in between is then not covered. The
  backend's sockets never set that option.
- Before Linux 6.5 the lookup does not know the VRF of the attachment's
  device; see the next paragraph.

**An interface in a VRF.** The attachment's interface can be enslaved to a
VRF. UDP input then accepts, for a datagram that arrives on it, a socket
bound to the interface or to the VRF device, and a socket bound to no device
only with `udp_l3mdev_accept`.

tc must not take a socket for the consumer that the stack will refuse, or
that the stack would not choose. A first fragment would pass because of it,
and the host would answer the reassembled datagram with Port Unreachable. A
datagram that tc assigns would be delivered to it, even across the VRF
boundary, because an assigned datagram bypasses the stack's own lookup.

From Linux 6.5 the lookup applies the VRF scope of the device itself. Before,
it takes the scope from the IP control block, which is not initialized at tc,
and it cannot tell tc whether the device is enslaved. So tc decides in two
steps, on every kernel:

1. It looks the socket up without a VRF scope. A socket bound to the
   attachment's interface is eligible in every VRF, and it is the consumer.
2. Otherwise it looks again with the VRF scope engaged. If that lookup still
   finds a socket bound to no device, `udp_l3mdev_accept` admits that socket
   to every VRF, and it is the consumer. From Linux 6.5 both lookups apply
   the device's scope, and the second returns what the first found.

Before Linux 6.5 two results remain that tc cannot settle, because they
depend on whether the interface is in a VRF:

- The second lookup finds nothing. The socket bound to no device is eligible
  outside a VRF and not inside one.
- The second lookup finds a socket bound to a device. UDP input chooses the
  first socket outside a VRF and the second one inside.

tc does not decide these. It assigns nothing and passes the datagram on as a
link-layer multicast frame (`bpf_skb_change_type`). The frame keeps that type
up to UDP input as long as no other device takes it on the way; "The
attachment's interface" above says which devices the backend excludes and
which it cannot see. The stack's own lookup then applies the real scope:

- Outside a VRF, and inside one that has an eligible socket, the socket that
  UDP input chooses receives the datagram.
- Inside a VRF without an eligible socket, UDP input discards the datagram.
  It counts in the host's `Udp` `NoPorts`, and not in
  `downlink_missing_consumer`.
- The host sends no ICMP error about a datagram in such a frame. IPv4 sends
  none at all. IPv6 sends only Packet Too Big and a Parameter Problem for an
  unrecognized option, and a hand-off raises neither.

The frame type has side effects on the way to the socket:

- IP input drops the datagram while `drop_unicast_in_l2_multicast` is set
  for the interface; IPv4 input also while it is set for `all`.
- IPv6 input drops a datagram that carries a Routing header.
- A packet filter's packet-type match sees a multicast frame.
- UDP early demultiplexing is skipped, which costs time and nothing else.

Where one of the first three would cost hand-offs, bind the consumer to the
attachment's interface, as the backend binds its own sockets.

tc does not see a socket that is bound to the VRF device itself, on any
kernel, because the lookup runs on the attachment's device. It acts on the
sockets it does see:

- With no other socket bound for the datagram, it drops and counts the
  hand-offs of such a consumer.
- With a socket bound to no device as well, the result depends on the kernel
  and on `udp_l3mdev_accept`. tc leaves the datagram to the stack, which
  delivers it to the socket on the VRF device (before Linux 6.5, without
  `udp_l3mdev_accept`); or it drops and counts it (from Linux 6.5, without
  `udp_l3mdev_accept`); or it assigns it to the socket bound to no device,
  although UDP input would prefer the one on the VRF device (with
  `udp_l3mdev_accept`).

Bind such a consumer to the attachment's interface instead.

**Counter.** `EbpfGtpuDatapathCounters::downlink_missing_consumer`, from
`datapath_snapshot`, counts every datagram refused this way, an
outer-fragmented one at its first fragment. A rising value means that
hand-offs are arriving while nothing drains them. On an IPv6 endpoint only an
application's own socket can drain them, so without one the counter rises
while the control port is open too. A G-PDU for no tunnel still counts as a
lookup miss in `downlink_unknown_teid`, so one such datagram can raise both.
A datagram that tc left to the stack's own lookup (see "An interface in a
VRF" above) is not counted here. A hand-off that arrives in a VLAN above the
interface is counted here, whatever is bound; see "The attachment's
interface".

**Not covered.**

- Echo and other non-G-PDU messages on UDP/2152 that are not fragmented on
  the outer path are not hand-offs of subscriber packets. tc passes them as
  before, and while nothing is bound the host answers them with Port
  Unreachable, quoting only the GTP-U message. An outer-fragmented datagram
  for UDP/2152 is different: tc judges it by its first fragment without
  reading the GTP-U message type, so a fragmented Echo without a consumer is
  counted and discarded like a fragmented G-PDU.
- A G-PDU with a required unknown extension for an address that is not one
  of the attachment's endpoints is not this attachment's hand-off. tc passes
  it to the host as before.
- Outer IPv6 fragments are passed to the host as before. The backend has no
  IPv6 consumer, and tc does not look into a fragmented IPv6 packet.
- A datagram that a sender addresses to UDP/2153 or UDP/2154 itself is not
  steered by tc. The host answers it like any datagram for a closed port.
- While the loader holds the traffic gate closed, tc passes every packet
  untouched, as if no program were attached, and the host's own behaviour
  applies.
- The reassembly window described above.
- An outer-fragmented datagram that never completes although its first
  fragment arrived, for example because a later fragment was lost. The host
  reports the reassembly timeout to the sender with ICMP Time Exceeded,
  quoting up to 548 octets of the first fragment (RFC 792, RFC 1122 section
  3.3.2), with and without a bound consumer. The exception is a first
  fragment that tc passed on as a multicast frame, as described under "An
  interface in a VRF": the host sends no ICMP error about it.

Native evidence runs the committed classifier with no consumer bound: on a
fresh attachment whose port was never opened, while only UDP/2152 is bound,
while the process is down, and after a retained graph is adopted and before
the port is reopened; over IPv4, and over IPv6 on a grouped attachment. Each
hand-off is counted and not delivered, a capture on the core side holds no
ICMP error, and the host's ICMP counters do not move. An outer-fragmented
datagram is reassembled and discarded by UDP input, and no fragment stays in
a reassembly queue. With a consumer bound every hand-off is delivered, to a
`SO_REUSEPORT` socket too. The runner lane and the two pinned-kernel lanes
(Linux 6.8 and the RHEL 9 kernel) require the
`OPC_GTPU_DOWNLINK_HAND_OFF_CONSUMER_PROVEN` marker.

With two application sockets bound, one on the endpoint's address and bound
to no device and one on every address and bound to the interface, the hand-off
reaches the first, as UDP input chooses.

A second run attaches to an interface that is enslaved to a VRF, with no
eligible consumer and an unrelated socket in the default VRF that listens on
UDP/2152 on every address. That socket receives no hand-off and the core
receives no ICMP error: for a G-PDU for no tunnel over IPv4 and over IPv6,
with and without `SO_REUSEPORT` on that socket, and for an outer-fragmented
G-PDU over IPv4 in either fragment order. Each datagram is either dropped and
counted by tc or discarded by the host's own socket lookup; on a kernel from
Linux 6.5 the run requires that tc counted every one. With
`udp_l3mdev_accept`, with a consumer on the attachment's interface, and with
the control port open, every hand-off is delivered. The
runner lane and the RHEL 9 lane require the
`OPC_GTPU_DOWNLINK_HAND_OFF_VRF_PROVEN` marker; the RHEL 9 kernel is the one
whose lookup does not know the VRF. The pinned Linux 6.8 image has no VRF
driver.

A third run makes the attachment's interface a port of a bridge that holds
the endpoint. `create_device`, `create_device_with_endpoints` and
`resolve_device` refuse it before a hook or a pin exists. When the interface
of an existing attachment is enslaved, the control port and the adoption
after a restart are refused, and the program on each hook and the pinned
objects stay what they were. The process that made the attachment still
removes it; a restarted one cannot, and adopts and removes it once the
interface is released. A restarted process fences the retained attachment
for cleanup while the interface is a bridge port, cannot activate it, and
activates it once the interface is released. All three lanes require the
`OPC_GTPU_ATTACHMENT_RECEIVE_INTERFACE_PROVEN` marker.

A fourth run stacks a device on the attachment's interface: a passthru
macvlan and an ipvlan that hold the endpoint, and a VLAN device with the
ID 0. The same three calls refuse the interface before a hook or a pin
exists. When a macvlan is stacked on the interface of an existing attachment,
the control port, the hand-out and the activation after a cleanup are
refused, nothing changes, and the process that made the attachment still
removes it. All three lanes require the
`OPC_GTPU_ATTACHMENT_BELOW_STACKED_DEVICE_PROVEN` marker. A fifth run repeats
the refusal with the passthru macvlan enslaved to a VRF, next to an unrelated
socket in the default VRF; the runner lane and the RHEL 9 lane require the
`OPC_GTPU_ATTACHMENT_BELOW_MACVLAN_IN_VRF_PROVEN` marker. No lane creates an
HSR or PRP device. Unit tests cover that refusal on the kernel's answer for
the links, among them an answer that omits an actual interlink as a kernel
from Linux 6.10 to 6.17 writes it.

A sixth run attaches to an interface with a VLAN device above it and sends
every kind of hand-off in that VLAN, with the tag in the frame and beside it:
a G-PDU for no tunnel over IPv4 and over IPv6, an over-MTU packet and an
inner fragment of a context with a downlink inner MTU, and a G-PDU with a
required unknown extension. tc drops and counts each while a consumer is
bound on the attachment's interface and a socket listens on the VLAN device,
and a G-PDU for no tunnel also while only a socket bound to no device
listens. No socket receives it, and the same G-PDU without the tag reaches
the consumer, or the socket bound to no device. tc counts and marks the first
fragment of an outer-fragmented G-PDU; the host reassembles the datagram on
the VLAN device and discards it, with and without a socket there. The host
generates no ICMP error in any of these cases. A G-PDU of a provisioned
tunnel is decapsulated in the VLAN as outside it, and a frame with a priority
tag is handled as the interface's own, hand-offs included. An attachment on
the VLAN device itself judges the frames of its VLAN. All three lanes require
the `OPC_GTPU_DOWNLINK_VLAN_FRAMES_PROVEN` marker. That tc makes no lookup
for such a frame is a property of the program's source. A host test of the
eBPF crate checks it there: the socket lookup is called from the consumer
decision alone, after that decision has judged the tag.

### Downlink tunnel-MTU enforcement

`GtpPdpContext::downlink_inner_mtu` is optional per context. It carries the
session's downlink inner MTU: for an ePDG, the SWu access MTU minus the
negotiated ESP/UDP/IP overhead, from 576 (RFC 791) to 32,767. It also
carries the policy for an authorized inner IPv4 packet with Don't Fragment
set that exceeds the MTU:

- `GtpuDownlinkInnerMtu::new(mtu)` selects the **default**, inner
  fragmentation before encapsulation (RFC 4459 section 3.4);
- `GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(mtu)` is the **explicit
  opt-in** alternative, one in-tunnel RFC 1191 error.

Under either policy, tc also hands every inner IPv4 fragment of the context
to this consumer; see [Inner fragments](#inner-fragments).

`None` keeps today's behaviour: tc decapsulates every packet, fragment or
not, and the host drops an over-MTU Don't Fragment packet with its own
Fragmentation Needed toward the core.

**Storage.** The field lives in the previously reserved bytes 66..68 of the
Active `PdpContextCommit`, so it is published, replaced and read back
atomically with the rest of the graph. The MTU is in the low 15 bits; bit 15
is set only for the in-tunnel Packet Too Big opt-in. A record without an MTU
is byte-identical to the original layout, so retained graphs are unchanged.
An older SDK does not tolerate a record carrying an MTU: its retained-graph
recovery rejects the non-canonical commit and refuses the whole attachment
as indeterminate, not just that context. Before downgrading, drain every
MTU-bearing context (reinstall it with `None`, or remove it).

**Refusals and capability.** The in-tunnel Packet Too Big opt-in requires
the legacy service-port uplink policy; the default fragmentation sends
nothing uplink and accepts either. Grouped entries and ordinary inner-IPv6
contexts refuse both policies. The eBPF probe reports
`downlink_inner_mtu_enforcement`. `Available` covers the datapath only:
fragments are produced, and errors sent, only while the application drains
this port.

**Binding and integration order.** The backend binds UDP/2152, UDP/2153 and
UDP/2154 when the control port is first opened for the attachment. It keeps
them until the attachment is removed or its queue is retired. If any of the
three cannot be bound, no port is published. Nothing is bound:
- before that first open;
- while the process is down across a restart, because tc keeps running from
  the pinned graph;
- after a retirement, until the attachment is re-created or adopted and the
  port reopened.

In those windows tc drops every hand-off and counts it; see
[Hand-offs need a bound consumer](#hand-offs-need-a-bound-consumer). The host
forwards neither an over-MTU Don't Fragment packet nor an inner fragment of a
context with a downlink inner MTU, and it answers none of them.

Open the control port right after creating or adopting the attachment, and
keep draining it for the attachment's lifetime. Packets that are handed off
before the port is open are lost.

tc rewrites the destination port before netfilter sees the packet. A host
filter on the INPUT path that selects GTP-U by UDP destination port must
therefore also admit UDP/2153 and UDP/2154 from the GTP-U peers.

**tc.** When an authorized inner IPv4 packet with Don't Fragment set exceeds
the MTU, tc does not decapsulate it, so the host never forwards it. The host
also never emits its own error: while the hand-off queue is not bound, tc
drops the packet (see above). tc rewrites only the UDP destination port,
with an incremental checksum update, to the backend-owned packet-too-big
queue on the same local address (`GTPU_PACKET_TOO_BIG_QUEUE_PORT`, 2153). tc
reads only the MTU bits, so it steers identically under both policies. Outer
fragments are reassembled first and arrive on the shared queue.

Every other authorized inner IPv4 fragment of such a context is steered the
same way to the backend-owned inner-fragment queue
(`GTPU_INNER_FRAGMENT_QUEUE_PORT`, 2154); see
[Inner fragments](#inner-fragments).

**Queue priority.** `try_receive_downlink` serves the shared UDP/2152 queue
first, so a backlog of hand-offs cannot crowd out Echo or reassembled G-PDUs.
That priority holds for a run of at most eight datagrams. After a full run,
the hand-off queues get one turn, and they also get a turn whenever the
shared queue is empty:

- Echo and unknown-TEID G-PDUs reach the shared queue from any source. With
  absolute priority, sustained input there would keep the consumer from both
  hand-off queues, and the packets waiting in them would overflow. With the
  bounded run, the hand-off queues together receive at least one of every
  nine datagrams served.
- A hand-off backlog delays the shared queue by at most one hand-off
  datagram per run of eight. A hand-off turn that finds both queues empty
  costs the shared queue nothing.
- The two hand-off queues take their turns alternately: a hand-off queue
  that holds a datagram is served at least every second hand-off turn,
  however long the other queue's backlog is.

**No authority in the port.** A datagram is authorized in full whatever queue
delivered it. A queue's port neither grants nor replaces any check.

#### Inner fragments

A context with a downlink inner MTU has tc hand over every authorized inner
IPv4 fragment: a packet with More Fragments set or a non-zero fragment offset
(RFC 791 section 3.1), whatever its size. The hand-off is the one used for an
over-MTU packet: tc does not decapsulate, and rewrites only the UDP
destination port, to the inner-fragment queue (UDP/2154). A fragment that
also exceeds the MTU with Don't Fragment set is an over-MTU packet first and
goes to the packet-too-big queue, as before. A context without a downlink
inner MTU is unchanged: tc decapsulates its fragments.

**Why.** The fragments of one datagram arrive in separate G-PDUs. A G-PDU
that outgrows the S2b-U link is fragmented on the outer path, so its inner
fragment reaches this consumer through kernel reassembly. A sibling whose
G-PDU fits would be decapsulated by tc and forwarded by the host. Where
connection tracking is active in the namespace, netfilter then reassembles
the two halves in different queues: the forwarded half at PRE_ROUTING, the
injected half at LOCAL_OUT. Neither queue completes, and both halves expire
after `ipfrag_time` without any error. With every fragment handed over, the
whole datagram takes one path, which the application controls.

**Consumer.** The G-PDU is re-authorized like any other, and its inner header
is validated as above. A fragment that is not an over-MTU Don't Fragment
packet is then returned as `Decapsulated`, unmodified, with its tunnel's
bearer mark. The consumer does not reassemble, and keeps no state per
datagram.

The three decisions that this hand-off needed:

1. **Rate limits: a returned fragment takes no token.**
   - The inner fragmentation budget bounds fragmentation work and the use of
     fresh Identifications per destination. A returned fragment is not
     fragmented and keeps its own Identification.
   - The Packet Too Big limit bounds in-tunnel errors. None is sent for a
     returned fragment.
   - Charging either budget would drop legitimate datagrams: one 64 KiB
     datagram arrives as 45 back-to-back fragments.
   - A fragment that exceeds the MTU with Don't Fragment set is still an
     over-MTU packet. It is fragmented under its destination's budget, within
     its own offset range and with its own Identification, or signalled
     under its session's limit. Only a first fragment is ever answered.
   - The load of returned fragments is bounded by the queue budget instead.
2. **Queue budget: inner fragments have their own queue.**
   - Each hand-off queue is one UDP socket with the receive buffer the kernel
     gives a new socket (`net.core.rmem_default`, 212,992 octets by default).
     That buffer is the queue's whole budget and its memory bound. Linux
     charges a datagram the size of its buffer, not of its payload: on
     Linux 7.1, a default buffer held 92 G-PDUs of 1,404 octets.
   - Beyond the budget the kernel drops silently, and `SO_RXQ_OVFL` counts
     the drops per queue (`inner_fragment_queue_drops`). An overflow never
     produces an ICMP error.
   - A flood of inner fragments fills only the inner-fragment queue. It
     cannot take room from over-MTU packets, Echo or reassembled G-PDUs, and
     the turn-taking above keeps it from delaying over-MTU packets by more
     than one datagram each. An over-MTU flood cannot starve fragments
     either.
   - The consumer holds one datagram at a time, so it adds no queue of its
     own.
3. **Authorization: every fragment carries its own, first or not.**
   - A non-first fragment has no transport header, and downlink authorization
     needs none. A G-PDU is authorized by its tunnel (TEID), its outer peer,
     local endpoint and source port, the complete Active graph, and its inner
     destination, the session PAA. Each fragment carries all of that in its
     own G-PDU.
   - Each fragment is therefore authorized on its own, and an unauthorized
     one is dropped for the same reasons as any G-PDU. Nothing is inferred
     from a first fragment, so fragments that never had one fill no table.
   - The bearer mark is that of the tunnel the fragment arrived in. The core
     gateway chose that bearer when it encapsulated the fragment (TS 23.401
     downlink bearer binding). Fragments of one datagram that the core sent
     on different bearers are returned with different marks.
   - Injection needs nothing more either. The returned mark selects the
     Child SA; a port or protocol selector, which a non-first fragment could
     not match, is not involved (see Injection below).

**Costs.**

- **Slow path.** Every inner fragment of such a context costs a receive, a
  re-authorization and the caller's injection, where tc forwarded it in the
  kernel. Fragmented traffic is expected to be rare; its rate is capped by
  how fast the application drains the queue.
- **Reordering.** A fragment can arrive after later packets of the same
  flow that took the tc fast path.
- **No queue sizing.** The queue budget is the kernel's default receive
  buffer. This port offers no call to change it.

**Limits.**

- **A fragment above the MTU without Don't Fragment** is returned as it
  arrived, like any such packet after outer reassembly. The caller's
  injection may then fragment the ESP packet on the outer header, or refuse
  a packet above the egress device MTU (an `IP_HDRINCL` send fails with
  `EMSGSIZE`). Before this hand-off, the host forwarded such a fragment when
  its G-PDU fit the S2b-U link. Fragmenting these packets to the MTU is part
  (ii) of #1023.
- **While nothing is bound on the queues** (see the binding windows above),
  tc drops the hand-offs. The inner fragments of contexts with a downlink
  inner MTU are then not forwarded; without this hand-off the host would
  forward them.
- **Other senders can crowd fragments out.** The queue budget separates the
  two hand-off classes from each other. It does not protect a class from
  datagrams that tc did not steer:
  - the hand-off queues are unconnected UDP sockets on the S2b-U address. A
    sender that reaches UDP/2154 directly uses the queue's buffer, and one of
    the consumer's turns per datagram, before the consumer can refuse it;
  - the shared queue is served first for runs of eight, and tc passes Echo
    and unknown-TEID G-PDUs to it from any source. A sender that keeps
    UDP/2152 busy takes eight of every nine of the consumer's turns. The
    hand-off queues keep the ninth, so they are slowed but not starved.

  Inner fragments that arrive faster than the remaining share overflow their
  queue, where tc used to forward them whatever the consumer was doing.
  UDP/2153 has always been exposed in the same way. Admit UDP/2152 to
  UDP/2154 on the S2b-U address only from the GTP-U peers.
- **Contexts without a downlink inner MTU** are unchanged: tc decapsulates
  their fragments. One of their datagrams can still be split when a G-PDU is
  fragmented on the outer path and the application drains this port. Give
  the context a downlink inner MTU to send every fragment through the
  consumer, and give it to every bearer of the session: a core gateway may
  send the fragments of one datagram on different bearers. Grouped entries
  and ordinary inner-IPv6 contexts cannot carry one.

#### Default: inner fragmentation

The G-PDU is re-authorized against the same Active commit. Then, in order:

1. **Header validation** (RFC 1812 section 5.2.2): version 4, a header
   length of at least 20, a valid header checksum, and a total length that
   covers the header and is not truncated. A failure is a `Malformed` drop.
   Octets after the total length are not part of the datagram and are
   ignored, as the kernel's receive path trims them.
2. **IPv4 options** are not fragmented: this path implements neither the
   RFC 791 option copy rules nor a router's Record Route and Timestamp
   processing. Such a packet is dropped as `InnerUnfragmentable`.
3. **Budget.** One token bucket per destination (the session PAA):
   `GtpuInnerFragmentRateLimit`, a burst of 64 with one token per 4 ms by
   default, set by `set_inner_fragment_rate_limit`. At most 4,096
   destinations are tracked per attachment, least recently used first out;
   a refused admission still counts as a use. An evicted destination
   restarts with a full bucket, so past 4,096 concurrently tracked
   destinations the per-destination bound does not hold (#1018). An empty
   bucket is an `InnerFragmentRateLimited` drop. Steps 1 and 2 take no
   token.
4. **Fragmentation** by the RFC 791 section 3.2 procedure, generalized to
   an n-way split. Every fragment except the last carries the largest
   multiple of 8 data octets that fits the MTU, so the count is minimal
   and the fragments are in order (RFC 1812 section 4.2.2.7). The original
   header is copied; the total length, More Fragments flag (the original's
   on the last fragment), fragment offset (the original's plus the
   fragment's own) and header checksum are set per fragment. TTL, TOS,
   protocol and addresses are copied unchanged.
5. **Identification.** All fragments carry one Identification (RFC 791).
   A packet that is itself a fragment keeps its own, which its sibling
   fragments share. An atomic datagram (DF set, not a fragment) has no
   meaningful Identification (RFC 6864 section 4.1), and senders often use
   zero or a constant, so the fragments get the destination's next value
   from a sequence that starts at a random non-zero value and never uses
   zero. A budget admits at most `burst` + ⌈255 s / interval⌉ packets in
   any 255 seconds (64 + 63,750 by default), and
   `GtpuInnerFragmentRateLimit::new` refuses any limit above 65,535. While
   the destination stays tracked under one unchanged limit, its sequence
   therefore cannot repeat within the maximum datagram lifetime (RFC 791
   Time to Live; RFC 6864 sections 4.3 and 5.2). Past 4,096 concurrently
   tracked destinations, an evicted destination restarts from a fresh
   keyed-random value, so uniqueness is probabilistic. A new attachment
   registration (a process restart, a re-adoption or a re-created
   attachment) likewise restarts every destination from a new random value
   and a full bucket, possibly within 255 seconds of the previous
   registration's Identifications. Admissions before and after a limit
   replacement are not counted together (#1018).

The result is `GtpuDownlinkEvent::Fragmented`: the fragments in offset order,
the MTU and the bearer mark. Its `Debug` output shows only the fragment
count and MTU.

**Injection.** `GtpuDownlinkInjector::raw_ipv4()` injects either a
`Decapsulated` packet or every packet of a `Fragmented` outcome, in order,
with the returned bearer mark. The consumer must continuously retain a
pool-wide outbound block policy below the bearer policies. The injector
installs no containment configuration and a policy query cannot provide an
atomic receipt. See [Raw IPv4 injection](#raw-ipv4-injection) for the exact
obligation, zero-Identification handling and limits.
Consumers whose policies and SAs already carry an XFRM interface ID can use
the optional [interface-bound contract](#xfrm-interface-bound-ipv4-injection).

**Owner-approved policy.** Fragmenting a datagram with Don't Fragment set is
not standard router behaviour. RFC 791 section 2.3 and RFC 6864 section 4.3
forbid fragmenting it or clearing DF in transit; RFC 1191 section 4 has a
router discard it and signal the originator instead. RFC 4459 section 3.4
describes clearing DF before encapsulation as a non-compliant but deployed
tunnel practice. The ePDG owner chose it as the default because it delivers
the packet whatever the originator does, and sources nothing from the
subscriber's address.

**Costs of the policy.**

- **PMTUD.** The originator's Path MTU Discovery never learns the tunnel
  MTU, so every oversized DF packet takes this slower path, and the UE must
  reassemble.
- **Rate cap.** Over-MTU DF traffic toward one destination is capped by its
  budget: 250 packets per second by default, after a burst of 64. Excess
  packets are dropped silently (`InnerFragmentRateLimited`). No Packet Too
  Big is sent, so the sender never learns to send smaller packets.
- **Reordering.** Slow-path packets can be reordered: a fragmented packet
  can arrive after later packets of the same flow that fit the MTU and took
  the tc fast path.
- **Identification space.** Fresh Identifications share the (source,
  destination, protocol) space with the originator's own non-atomic
  datagrams, which this path cannot see.
  - **The requirement.** RFC 6864 section 5.3.1 requires a device that
    rewrites datagrams to generate their Identifications "as if the datagram
    were sourced by that device": unique for that tuple within the maximum
    datagram lifetime (section 4.3). This path cannot meet that against the
    originator's own Identifications.
  - **Owner-approved policy.** The deviation is inherent to clearing DF and
    fragmenting. It is part of the default decided on #1002 as product
    policy, not standard behaviour.
  - **The hazard.** A collision can misassemble at the UE. RFC 6864 section
    5.2 calls the UDP and TCP checksums "weak in this regard, but better than
    nothing" against such errors, and an IPv4 UDP datagram may carry no
    checksum at all.

#### Opt-in: in-tunnel Packet Too Big

With `GtpuDownlinkInnerMtu::in_tunnel_packet_too_big`, the re-authorized
G-PDU produces `GtpuDownlinkEvent::PacketTooBig`. At most one RFC 792/1191
Destination Unreachable (Fragmentation Needed) error is sent:

- **Bearer.** The error goes on the UE's default-bearer uplink (mark zero),
  proven by its own complete Active graph with the UDP/2152 source port. Under
  TS 23.401 uplink bearer binding, a dedicated bearer's TFT may admit only its
  media flows. If there is no usable default bearer, nothing is sent.
- **Addresses.** The source is the session PAA and the destination is the
  originator. Nothing is ever sent unencapsulated.
- **Quote.** The invoking IPv4 header plus its first 64 data bits.
- **Never answered** (RFC 1122 3.2.2), checked before any rate-limit token
  is taken:
  - an originator in 0/8, 127/8, 224/4 or 240/4 (including the limited
    broadcast);
  - a non-initial fragment;
  - an ICMP error (types 3, 4, 5, 11 and 12). Informational ICMP, such as
    Echo, is answered.
- **Header validation.** An invoking packet with a bad header checksum, or
  one shorter than its total length, is silently discarded (RFC 1812 section
  5.2.2, RFC 1122 section 3.2.1.2) and counted as unsendable.
- **Rate limit.** One token bucket per offending session (RFC 1812 section
  4.3.2.8): a burst of 16 with one token per 10 ms by default, set by
  `set_packet_too_big_rate_limit`. At most 4,096 sessions are tracked per
  attachment, least recently used first out. While the session stays
  tracked, a flood toward one PAA exhausts only that session's budget. Past
  4,096 concurrently tracked sessions, a re-tracked session restarts with a
  full bucket (#1018).
- **Tradeoff.** The error's source is the subscriber's own address. The ePDG
  is routing, so RFC 1812 4.3.2.4 would have it use its own address, but the
  PGW's per-PDN anti-spoofing admits only the PAA. The originator therefore
  attributes the error to the subscriber.

**Counters.** Value-free counters report fragmented packets and fragments,
rate-limited and unfragmentable packets under the default policy, and
too-big, signalled, rate-limited and unsendable packets under the opt-in.
`decapsulated_inner_fragments` reports the decapsulated packets that were
inner fragments. `SO_RXQ_OVFL` reports kernel drops from the shared queue,
from the packet-too-big queue and from the inner-fragment queue. The kernel
reports a queue's drop count with each datagram received from it, so each of
these three counters shows the drops up to the last datagram read from its
queue. Drops since then, or from a queue that is not being served, are not
visible yet.

**Limits.**

- tc has no hand-off counter and no in-kernel policer. Either would add a map
  and change the retained pin inventory and the durable recovery records.
- A flood toward one PAA can still fill a hand-off queue. When it does, the
  kernel drops further hand-offs of that class from any session, and those
  drops are counted. It can never affect the other hand-off queue or the
  shared queue.

**IPv6.** IPv6 has no in-network fragmentation: only the source fragments
(RFC 8200 sections 4.5 and 5), and a router answers an oversized packet with
Packet Too Big (RFC 4443 section 3.2). Ordinary inner-IPv6 contexts (#998) are
stored as family-tagged entries, and those entries have no MTU field, so an
inner-IPv6 context with a downlink inner MTU is refused with
`downlink_inner_mtu_inner_ipv6` under either policy rather than installed
without enforcement. Inner IPv6 Packet Too Big (#1007) needs three pieces:
- an MTU in the family-tagged entry wire, which is shared with grouped
  records and the protected selector ledger;
- the same steering in tc's family-tagged decapsulation;
- the existing ICMPv6 builder, quoting up to 1,232 octets.

**Native evidence.** The committed classifier is exercised with:

- the default policy: a 1,450-octet DF datagram over a 1,400-octet access
  link:
  - on the default bearer;
  - after outer reassembly;
  - with a zero outer UDP checksum;
  - on a dedicated bearer through its real ESP Child SA.

  The UE receives the exact payload. Captures show two RFC 791 fragments
  with one non-zero Identification and Don't Fragment clear, and one
  dedicated-SPI ESP packet per fragment. The default-bearer legs are plainly
  routed; a default-bearer Child SA leg is tracked in #1020. The
  per-destination budget drops a second datagram without forwarding it.
  Datagrams sent straight to UDP/2153 are dropped, never exposed as control
  or unknown-tunnel events;
- the opt-in: default, dedicated (answered on the default-bearer uplink) and
  outer-fragmented oversized DF packets; the exact error bytes, the 28-octet
  quote and the next-hop MTU; the per-session rate limit; an Echo served
  ahead of a 40-packet hand-off backlog; never-answer packets that consume no
  token;
- fitting DF packets and oversized non-DF packets, which tc forwards;
- zero plaintext ICMP in the peer and UE namespaces, and an unchanged host
  `OutDestUnreachs`.

A baseline test pins the unchanged default without an MTU: the host emits
its own error, quoting 548 octets toward the core.

A further native test covers inner fragments, with one connection-tracking
rule active in the gateway namespace:

- a 2,600-octet datagram that the core fragments at 1,500. The first
  fragment's G-PDU arrives as two outer fragments and the last one's fits.
  Both come back as `Decapsulated`, the UE receives the exact payload, and
  each fragment leaves as its own packet. The host reassembles the two outer
  fragments and nothing else, and no reassembly fails;
- three fragments in reverse order, none of which enters a host reassembly
  queue;
- a 28-octet first fragment with one flipped header checksum octet. Without
  a downlink inner MTU, tc decapsulates it and the kernel's IPv4 input
  discards it (`InHdrErrors`). With one, the consumer drops it as
  `Malformed`, and nothing is sent toward the UE. The same holds for a
  fragment whose total length claims one octet more than arrived;
- two fragments followed by six octets beyond their total length. They come
  back trimmed, and the UE reassembles the exact datagram;
- a dedicated bearer through its real ESP Child SA: one dedicated-SPI ESP
  packet per inner fragment, none fragmented on the outer header;
- a context without a downlink inner MTU, and a packet that is not a
  fragment, which tc still decapsulates;
- the queue budget: with nobody draining, a flood larger than the receive
  buffer leaves at most one buffer of fragments queued, and every other one
  dropped and counted (on Linux 7.1 with a 212,992-octet buffer, 92 of 272
  queued and 180 dropped). Twenty Echo Requests are served in runs of eight
  with one hand-off turn after each run, and three over-MTU packets
  alternate with the fragment backlog. No Echo and no over-MTU packet is
  lost;
- an Echo Request and a G-PDU for no tunnel sent straight to UDP/2154, which
  are dropped;
- zero plaintext ICMP toward the core, and an unchanged host
  `OutDestUnreachs`.

Both privileged lanes require `OPC_GTPU_DOWNLINK_INNER_FRAGMENTATION_PROVEN`,
`OPC_GTPU_DOWNLINK_INNER_FRAGMENT_HAND_OFF_PROVEN`,
`OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_PROVEN` and
`OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_BASELINE_PROVEN`.


### Raw IPv4 injection

**Containment is the consumer's obligation.** Before opening
`GtpuDownlinkInjector::raw_ipv4()`, install a lower-priority OUT block policy
over the complete subscriber address pool, matching every source, mark and
protocol. Keep it for the **whole lifetime of the plaintext source**, not
just while a bearer policy is present. A lower priority has a larger numeric
priority value than each intended bearer protection policy. Keep both
`net.ipv4.conf.all.disable_xfrm=0` and
`net.ipv4.conf.<egress>.disable_xfrm=0`, and admit no higher-priority
intersecting bypass policy that could pass the packet without a required
transform. `disable_policy` relaxes inbound checks; auditing it cannot prevent
this outbound bypass. The native negative control shows plaintext despite a
retained pool block and `disable_policy=0` when either effective `disable_xfrm`
setting is enabled.

For example, for a synthetic subscriber pool whose bearer policies have
priorities below 10,000:

```sh
ip xfrm policy add dir out dst 203.0.113.0/24 priority 10000 action block
```

The block has no source, protocol or mark constraint. All outbound bearer
policies, including the default bearer, must match the actual inner source
and destination and require their intended SA. Route rules, addresses and
policy ownership remain application configuration. The injector installs,
removes and queries none of them. Establish these obligations before enabling
any plaintext source and retain them across process restarts, policy
replacements and bearer teardown.

**A diagnostic is not a guard.** A read such as `ip xfrm policy get dir out
dst 203.0.113.0/24` is a snapshot, not a lease or atomic containment receipt.
Neither checking twice nor watching asynchronous netlink notifications can
recall a packet already sent. If the consumer violates its lifetime
obligation, the block can disappear after the last successful read and before
any fragment's kernel policy lookup. This interval has no fixed upper bound;
plaintext may continue until protection is restored or sending stops. No
read-only diagnostic is included because it cannot turn that observation into
send authority.

The kernel does the FIB lookup before XFRM. An ordinary route must therefore
exist even when a bearer policy protects traffic. A blackhole, unreachable
or prohibit FIB route can reject the lookup before a valid SA is selected.
Without a matching policy, the default ACCEPT behavior uses the ordinary
route and can emit plaintext. The retained pool block makes a missing bearer
policy refuse at the XFRM lookup instead. Construction and send success never
prove containment or peer receipt.

**Namespace default block.** On kernels and iproute2 versions providing the
namespace default-policy API, another option is:

```sh
ip xfrm policy setdefault out block
ip xfrm policy getdefault
```

The default is separate from ordinary SPD entries: deleting the pool block,
or even flushing all ordinary policies, does not remove it. An unmatched
non-loopback output flow then fails instead of taking the plain route, so
this option removes the deleted-pool-block window while the namespace
default remains block. Its cost is namespace-wide: every other permitted
non-loopback output flow needs an explicit policy too. The kernel exempts
loopback routes from this default; this is not a loopback containment guard.
A higher-priority explicit plaintext allow can still bypass the intended
protection and must not intersect the subscriber flow. The consumer owns
these settings continuously; a readback is still only a snapshot.

The native test deletes the ordinary block, proves refusal under the namespace
default, demonstrates that a deliberate explicit allow emits plaintext, and
restores encryption under the same default block. Upstream Linux 5.14 lacks
this API; the pinned enterprise 5.14.0-427 line carries its backport.
Consumers on kernels without it must retain the pool block or select another
supported send contract.

**API and send behavior.** The constructor opens one nonblocking,
close-on-exec raw IPv4 socket in the current network namespace. The socket
stays there. It requires `CAP_NET_RAW`, and `SO_MARK` also requires
`CAP_NET_ADMIN` on kernels before Linux 5.17. The constructor probes `SO_MARK`
and reads back `IP_HDRINCL` and `IP_NODEFRAG`: an initial mark-privilege gap is
reported as a socket construction/configuration error. Required privileges
must remain available for later per-packet mark changes.

```rust
use opc_gtpu_dataplane::{GtpuDownlinkEvent, GtpuDownlinkInjector};

// First establish the containment obligation above in this namespace.
let mut injector = GtpuDownlinkInjector::raw_ipv4()?;
match event {
    GtpuDownlinkEvent::Decapsulated(packet) => {
        injector.inject((&packet).into())?;
    }
    GtpuDownlinkEvent::Fragmented(batch) => {
        injector.inject((&batch).into())?;
    }
    _ => { /* Process the other control-port outcomes normally. */ }
}
```

`GtpuDownlinkInjectionPort` is an object-safe seam that a consumer can fake
without a socket. `testkit::decapsulated_downlink` and
`testkit::fragmented_downlink` build structural inputs from synthetic bytes
for those tests, including deliberately malformed fixtures. They grant no
receive or forwarding authority; production outcomes come from the control
port. An external-crate test exercises both factories with a consumer fake.

The real injector takes exclusive mutable access so a bearer mark cannot
change partway through a batch. Each send uses:

- `IP_HDRINCL`, retaining the validated caller header; Linux recalculates
  its total length and checksum;
- `SO_MARK` equal to the outcome's bearer mark, explicitly zero for the
  default bearer even after a marked send;
- `IP_PKTINFO` with `ipi_spec_dst` equal to the inner source. Linux builds
  this flow from the socket and ancillary data, not the supplied IP header.
  HDRINCL implies `FLOWI_FLAG_ANYSRC`, allowing a nonlocal source. Selectors
  must not rely on inner protocol or ports: this raw flow has protocol
  `IPPROTO_RAW` and zero ports;
- `IP_NODEFRAG`, so connection tracking does not gather the inner fragments
  at LOCAL_OUT and recombine them into an oversized packet before ESP.

`IP_NODEFRAG` does not make every fragment a tracked flow. A non-initial
fragment has no usable transport header for conntrack, remains without a
connection entry and matches `ct state invalid` (not the explicit nftables
`untracked` state). A common output-chain `ct state invalid drop` rule refuses
it even while its matching XFRM policy and SA remain installed. The native
proof checks the independent invalid-fragment counter, the refusal class and
zero wire output. Consumers must account for this when defining output rules.

The whole batch is validated before its first send, then sent in offset order.
Successful calls count local kernel acceptance. A failure stops at the first
failed packet and reports earlier acceptance in `Send { class, packets_sent }`.
The value-free `GtpuDownlinkSendFailure` classes distinguish `WouldBlock`,
`MessageTooLarge`, `NoBufferSpace`, `PolicyOrFilterRefused`, `AccessDenied`,
`ShortWrite` and `Other`. Pool/default-block and netfilter refusals normally use
`PolicyOrFilterRefused`; the errno cannot identify which policy or filter
refused the packet. Revoking mark privileges after construction can also
produce this class. Linux `EACCES` is separately `AccessDenied`, including
prohibit-route and disallowed-broadcast failures; it is not an XFRM diagnosis.

Raw-mode pool/default-block refusals return a local error before packet output.
Device-MTU and DF tunnel path-MTU refusals likewise return `MessageTooLarge`:
`raw_send_hdrinc` uses `ip_local_error`, and `xfrm4_tunnel_check_size` uses
`xfrm_local_error` for the attached full raw socket rather than sending ICMP.
The native proof supplies a route and an explicit output allow toward the
inner source, including under default block, and observes no ICMP on any
namespace device for these cases. This observation does not cover arbitrary
consumer routes, redirects or firewall rules that generate their own errors.

After partial acceptance the datagram is lost: accepted pieces cannot be
recalled and this API cannot resume or resend the remainder. Do not resend the
whole outcome. There is no automatic retry or packet queue. Errors, `Debug`
and counters contain only static classes and counts, never addresses, marks,
SPIs or bytes. IPv6 is unsupported. An unspecified source is refused because
Linux would replace it. TTL is not decremented and IPv4 options are preserved
without router processing.

**Identification zero.** Zero is legal under RFC 6864, but Linux
`raw_send_hdrinc()` calls `ip_select_ident()` when it sees zero with DF clear.
Sibling fragments can therefore receive different IDs and never reassemble.
Both a `Fragmented` batch with zero ID and DF clear and an independent
`Decapsulated` fragment (MF or nonzero offset) with zero ID and DF clear are
refused with `GtpuDownlinkInjectionError::ZeroIdentificationFragment` before
anything is sent. `zero_identification_refusals` counts refused outcomes,
one per independent fragment or batch, not inferred datagrams.

The crate emits `Fragmented` only for DF sources. An atomic source already
receives a fresh nonzero ID from the fragmenter. A zero-ID batch is therefore
one re-fragmented piece of an origin-fragmented datagram, whose siblings arrive
as separate outcomes. Inventing an ID for that piece cannot agree with those
siblings. The injector allocates no IDs and keeps no correlation cache.

The lost traffic is an origin-fragmented zero-ID datagram that requires any
non-DF raw send, either as received or after the fragmenter clears DF. For
uniformly numbered sources this is about one affected datagram in 65,536;
sources repeatedly using zero can lose every affected datagram. Fitting DF
fragments keep zero, and an unfragmented zero-ID packet may be numbered by
Linux. Nonzero IDs are preserved. Keeping DF on pieces made from a DF-fragment
source would let zero survive raw output. Choosing those flags changes the
fragmenter's MTU/fragmentation policy and belongs there, not in this injector.
The interface-bound sender in [#1085](https://github.com/openpacketcore/openpacketcore-sdk/issues/1085)
preserves zero and does not have this raw-path limit.

**Evidence.** The independent Python peer in
`tests/fixtures/downlink_injection.py` configures synthetic private namespaces,
observes encrypted egress and decrypted fragments, and receives exact
reassembled UDP payloads. The native Rust test exercises both marks, nonlocal
source selectors, ordered fragments with conntrack active, zero-ID refusals,
pool/default-block containment, `disable_xfrm` bypass, query/delete/send and
invalid-filter controls, and no ICMP for block and MTU refusals with a usable
return route. Its sender trace records every device without an address filter.
The shared runner requires each native case exactly
once, zero ignored executions and `OPC_GTPU_RAW_INJECTION_PROVEN`.

The privileged backend fragmentation and hand-off suites feed actual
`try_receive_downlink` outcomes to the production injector. They prove normal
fragment delivery and the zero-ID origin-fragment case: the re-fragmented
batch is refused before sending; its fitting DF sibling keeps zero, and the
datagram is lost. Native, pinned Linux 6.8 and enterprise lanes register the
raw proof; their kernels provide the namespace default-policy facility.

Source checks cover Linux v7.1.8:
[`raw_sendmsg`/`raw_send_hdrinc`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/raw.c),
[`ip_cmsg_send`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/ip_sockglue.c),
[`inet_sk_flowi_flags`](https://github.com/gregkh/linux/blob/v7.1.8/include/net/inet_sock.h),
[`ip_select_ident`](https://github.com/gregkh/linux/blob/v7.1.8/include/net/ip.h),
[`__mkroute_output` and `ip_route_output_flow`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/route.c),
[`xfrm_lookup_with_ifid`, including `nopol`](https://github.com/gregkh/linux/blob/v7.1.8/net/xfrm/xfrm_policy.c),
[`xfrm4_tunnel_check_size`](https://github.com/gregkh/linux/blob/v7.1.8/net/xfrm/xfrm_output.c),
[`xfrm4_local_error`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/xfrm4_output.c),
[conntrack defrag](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/netfilter/nf_defrag_ipv4.c),
and [`ipv4_get_l4proto`/`nf_conntrack_in`](https://github.com/gregkh/linux/blob/v7.1.8/net/netfilter/nf_conntrack_core.c).
The [enterprise default-policy backport](https://gitlab.com/redhat/centos-stream/src/kernel/centos-stream-9/-/blob/kernel-5.14.0-427.el9/net/xfrm/xfrm_user.c)
provides SETDEFAULT/GETDEFAULT. Identification semantics follow
[RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html).

### XFRM-interface-bound IPv4 injection

**The consumer owns the XFRM interface and its configuration.**
`GtpuDownlinkInjector::xfrm_interface_ipv4(ifindex, if_id)` selects an
additional contract for a local, fixed-ID XFRM interface with a nonzero
`if_id`. Outbound policies and SAs must carry that same interface ID and
require their intended transforms. Policies and SAs without an interface ID
need an explicit consumer-owned migration before using this constructor.
The existing raw constructor remains available for that configuration.

The consumer creates and brings up the device in the selected namespace,
installs its route, policies and SAs, and supplies its interface index and
expected XFRM ID. For example, with an existing synthetic `underlay0`:

```sh
ip link add xfrm0 type xfrm dev underlay0 if_id 19
ip link set xfrm0 up
ip route add 203.0.113.0/24 dev xfrm0
# The matching outbound policy and SA also need: if_id 19
# Install the ICMP containment rule below before enabling injection.
```

```rust
use opc_gtpu_dataplane::GtpuDownlinkInjector;

// interface_index identifies the consumer-managed device in this namespace.
let mut injector = GtpuDownlinkInjector::xfrm_interface_ipv4(interface_index, 19)?;
// Use the same borrowed Decapsulated/Fragmented inputs as the raw constructor.
injector.inject((&packet).into())?;
```

This path enters the bound XFRM device with `AF_PACKET/SOCK_DGRAM`. The device
requires an actual transform with its interface ID. A missing matching policy
or SA drops the original packet instead of returning an ordinary plaintext
route. That does **not** imply silence: the failure can generate an ICMP error
containing original packet bytes, as described below.
Changing the ordinary route does not change the packet-socket binding.
Deleting or moving the bound device invalidates that binding permanently,
including after another device reuses its name and ifindex. The consumer
must explicitly construct a new injector to use a replacement.

**Generated ICMP and consumer containment.** On missing policy or SA,
`xfrmi_xmit2` invokes `dst_link_failure`; IPv4 responds with ICMP destination
unreachable, host-unreachable code (type 3, code 1). A DF packet larger than
the tunnel path MTU, but small enough for the packet socket's device-MTU
check, invokes `icmp_ndo_send` with fragmentation-needed (type 3, code 4).
These messages contain the original IPv4 header and initial payload bytes.
Linux limits the IPv4 error message to 576 bytes (or a smaller route MTU),
and normally rate-limits errors. It generates them only for whole packets
and first fragments, subject to the usual ICMP exclusions, such as no error
in response to an ICMP error. Rate limits and the absence of a current return
route are not containment guarantees.

The error takes a separate route lookup toward the original source (or an
echoed source-route option), with ordinary output policy/hook processing. The
packet-socket binding does not constrain this lookup. **Before injection, the
consumer must install and continuously retain containment for these ICMP
quotes in the injection namespace.** The primitive neither installs nor
audits that configuration. For the synthetic subscriber pool above, this
nftables example drops locally generated destination-unreachable messages
whose quoted IPv4 destination belongs to that pool:

```sh
nft add table inet injection_containment
nft 'add chain inet injection_containment output { type filter hook output priority -300; }'
nft 'add rule inet injection_containment output icmp type destination-unreachable @th,192,32 & 0xffffff00 == 0xcb007100 counter drop'
nft -a list chain inet injection_containment output
```

`@th,192,32` reads the quoted destination: the eight-byte ICMP header plus
16 bytes into the quoted IPv4 header. This offset also works with IPv4
options. Change the mask and network for each actual subscriber pool and
cover every injectable destination. The rule covers both error codes and
all bearer marks and inner sources; matching only the outer ICMP destination,
output interface or a mark would miss legitimate configurations. It runs
before connection tracking and stops the generated error before device
output, including loopback. It does not prevent error generation or suppress
the original injected packet's internal XFRM-device trace. It also suppresses
legitimate local destination-unreachable errors quoting that pool, including
PMTU feedback; consumers must accept that cost and handle MTU appropriately.
Privileged rules that redirect or mirror packets before this guard remain
outside the contract. Keep the guard across policy/SA replacement and process
restarts, for the entire lifetime of the plaintext source.

Verify this configuration with the native proof and in the deployment's own
namespace: supply a usable route toward a synthetic inner source, observe
every device without an address filter, and trigger both missing-policy/SA
and DF tunnel-MTU failures for each bearer. First observe the ICMP quotes
without the guard in an isolated test namespace; with the guard installed,
its counter must increase while the same trace shows no ICMP on any device.
Also verify normal encrypted delivery still works. An empty trace without
those positive controls could merely reflect missing routes or rate limiting.

**Construction and lifetime.** Before sending any bytes, the constructor:

1. Subscribes to kernel link notifications, then reads the requested link.
   It requires XFRM kind, the expected nonzero `if_id`, fixed metadata, and
   a policy namespace local to the current network namespace.
2. Creates the packet socket with protocol zero, attaches a reject-all receive
   filter, then binds once with `ETH_P_IP` and probes `SO_MARK`. The receive
   hook required by that protocol still runs, but the filter discards incoming
   packets before receive queueing. Filter failure refuses construction.
   It then requests a second
   link identity over the same subscribed netlink socket. Link changes to
   that index cause a refusal, even if a replacement has identical attributes.
   The RTNL-serialized response follows earlier link notifications;
   notification loss, truncation,
   malformed data and exhausted receive/deadline bounds also refuse.
3. Checks the retained socket's own binding. It never exposes or rebinds that
   descriptor. Every send omits the destination sockaddr, so the kernel uses
   its retained device rather than resolving the index again.

The initial identity read selects the device for this construction attempt;
an integer index cannot identify an earlier incarnation that disappeared
before that read. Notifications bridge the read-to-bind interval, while the
kernel's retained binding covers the send lifetime. This is device identity
acquisition, not a read-only containment audit of the entire namespace. There
is a one-second identity deadline and a 256-datagram receive-work limit. A
kernel syscall or scheduler stall can delay returning the deadline error.
Renaming or otherwise changing the device during construction may cause a
conservative refusal. The caller may retry construction after configuration
has settled, before releasing any outcome for injection.
In particular, a deferred `NEWLINK` following device-up can refuse an attempt;
retry with a fresh monitor and socket rather than ignoring the notification.
The native construction-race test verifies the replacement hook actually ran,
so an unrelated early notification cannot pass that assertion.

A missing device at construction is
`GtpuDownlinkInjectionError::InterfaceUnavailable`.
A retired send binding is `GtpuDownlinkSendFailure::InterfaceUnavailable`
(`ENXIO`/`ENODEV`); it needs an explicit new constructor. A down device reports
`InterfaceDown` (`ENETDOWN`). Linux can also retain a down notification on the
socket and report it once after the device comes up. Neither is `Other`.
Only a failure with zero accepted packets can be considered for a new explicit
send after resolving the device condition; never retry partially accepted batches.

The socket needs `CAP_NET_RAW`; setting each bearer mark also needs
`CAP_NET_ADMIN` on kernels before Linux 5.17. A missing initial mark privilege
is a construction error; those privileges must remain available for sends.
The socket remains in its creation namespace. The consumer must keep
privileged redirection/mirroring before XFRM out of this path and retain the
intended interface configuration.
Changing the live device's `if_id`, selecting an unrelated SA or deliberately
redirecting plaintext is outside this contract. A retained descriptor cannot
freeze configuration owned by another privileged actor.

**Bytes, hooks and results.** Every validated IPv4 byte is preserved, including
source, TTL, options, checksum and Identification zero. Both independently
received `Decapsulated` fragments and SDK `Fragmented` batches can therefore
retain zero without a correlation cache or ID allocation. The raw-mode zero-ID
refusal counter remains zero for this constructor. Whole-batch validation,
exclusive mutable access, exact mark resets, ordering and partial-acceptance
reporting are shared with raw mode. IPv6 is unsupported.

The inner packet starts at device egress, bypassing the inner IPv4 LOCAL_OUT
path and its conntrack defragmentation, so it does not use `IP_NODEFRAG`.
Device egress hooks and inner IPv4 POST_ROUTING still apply before encryption.
The freshly allocated packet has no conntrack entry on that first POST_ROUTING
pass. With conntrack active, **every inner packet**, including a whole packet
or first fragment, matches nftables `ct state invalid` (not `untracked`). A
postrouting invalid-drop rule drops all of them. This differs from raw mode,
whose later fragments have that limitation. The native proof counts every
inner packet's invalid state and demonstrates drops of a whole packet and
both fragment positions. Consumers must scope their postrouting rules to
permit the intended interface injection path; inner LOCAL_OUT exceptions
cannot achieve this.
XFRM obtains the source and actual IP protocol from the packet; address, mark
and protocol selectors work, while transport
ports are unavailable on later fragments. After the transform, ordinary
outer-packet IP output hooks apply. Consumers must account for this difference
when placing firewall or observation rules; an inner LOCAL_OUT rule is not
an enforcement point for this constructor.

A successful send still means local kernel acceptance. XFRM-interface drops
can return success, including with a missing policy/SA and generated ICMP.
No delivery or encryption
receipt is returned, and no automatic retry, policy/SA installation or fallback
to another send contract occurs. Device MTU and IPsec path-MTU constraints
still apply. The injector does not decrement TTL or process options as a router.
Errors, counters and `Debug` remain value-free, and the same consumer-fake port
can stand in for either constructor.

**Evidence and kernel coverage.** The native independent peer observes exact
decrypted packets and reassembled payloads for both bearers, source/protocol
selectors, zero/nonzero IDs in batches and separate outcomes, options, and
active sender conntrack. Independent firewall counters verify that inner
LOCAL_OUT is bypassed while plaintext POST_ROUTING is retained and matches the
invalid tracking state. A return route to the inner source and an unfiltered
all-device trace expose ICMP host-unreachable and fragmentation-needed quotes;
the proof checks their original bytes, type/code and bounded length, including
first-fragment generation and later-fragment silence. With the documented
consumer output guard, counters prove those errors are dropped and no ICMP
leaves on any device for either bearer. Policy/SA loss and ordinary-route
replacement are exercised with that guard. The trace also observes decrypted
inbound traffic while a peek proves the production send socket's receive queue
is empty. Device-down, deletion/recreation and missing-constructor cases assert
their named error classes. A
deterministic replacement between the first identity read and bind uses the
same ifindex, kind and `if_id`; construction must refuse it, then an explicit
fresh constructor must work.

The shared qualification runner requires all three native cases exactly once
and zero ignored executions. Host, pinned Linux 6.8 and enterprise 5.14 lanes
read the running kernel's configuration. `CONFIG_XFRM_INTERFACE=y` or `m`
requires `OPC_GTPU_XFRM_INTERFACE_INJECTION_PROVEN`. A configured absence must
produce the kernel's explicit unsupported result on interface creation
(`EOPNOTSUPP`, with `Unknown device type` extack on current iproute2) and
the production constructor's `UnsupportedInterface` refusal on a substitute
device, with no wire output, yielding
`OPC_GTPU_XFRM_INTERFACE_UNSUPPORTED_PROVEN`. Missing configuration, failed
module loading, privilege errors and other setup failures do not count as an
unsupported pass. The unsupported result is distinct from datapath proof.
The native test also requests a deliberately unavailable link kind to exercise
the real unknown-kind diagnostic matcher on kernels that support XFRM interfaces.

Source checks cover
[`packet_do_bind`, `packet_snd`, `packet_getname`, `packet_notifier`](https://github.com/gregkh/linux/blob/v7.1.8/net/packet/af_packet.c),
[`rtnl_getlink` and the RTNL dispatcher](https://github.com/gregkh/linux/blob/v7.1.8/net/core/rtnetlink.c),
[`xfrmi_xmit` and `xfrmi_xmit2`](https://github.com/gregkh/linux/blob/v7.1.8/net/xfrm/xfrm_interface_core.c),
and [`xfrm_output_resume`](https://github.com/gregkh/linux/blob/v7.1.8/net/xfrm/xfrm_output.c).
[`xfrm4_output`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/xfrm4_output.c)
enters inner POST_ROUTING before the transform.
[`ipv4_link_failure`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/route.c)
and [`__icmp_send`/`icmp_route_lookup`](https://github.com/gregkh/linux/blob/v7.1.8/net/ipv4/icmp.c)
explain the error quotes, limits and separate route lookup;
[`nft_ct_get_eval`](https://github.com/gregkh/linux/blob/v7.1.8/net/netfilter/nft_ct.c)
classifies the absent conntrack entry as invalid.
[`sock_alloc_send_pskb`](https://github.com/gregkh/linux/blob/v7.1.8/net/core/sock.c)
consumes a pending socket error after a device-up transition.
The retained packet binding and required-transform checks also exist in the
[Linux 5.14 packet path](https://github.com/torvalds/linux/blob/v5.14/net/packet/af_packet.c)
and [XFRM interface](https://github.com/torvalds/linux/blob/v5.14/net/xfrm/xfrm_interface.c).
