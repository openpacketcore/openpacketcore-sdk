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

| Event | Meaning |
| --- | --- |
| `Decapsulated` | Exact inner packet, inner family and bearer mark (default bearer is `None`). The caller injects it toward XFRM with that mark. |
| `Control` | Non-G-PDU message; use the response planners above. |
| `UnknownTunnel` | Untouched G-PDU whose TEID selects no tunnel. An observation, not an absence receipt. |
| `Dropped` | Value-free `GtpuDownlinkDrop`: malformed, binding mismatch, destination mismatch or state unavailable. |

`downlink_counters` returns bounded, value-free counters for the current
attachment registration.

### Downlink tunnel-MTU enforcement

`GtpPdpContext::downlink_inner_mtu` is an optional per-session inner MTU
supplied by the consumer: for an ePDG, the SWu access MTU minus the negotiated
ESP/UDP/IP overhead. It is stored in the previously reserved bytes 66..68 of
the Active `PdpContextCommit`, so it is published and read back atomically
with the rest of the graph, and a record without an MTU is byte-identical to
the original layout. An older SDK treats a record carrying an MTU as
non-canonical and fails that context closed. The value is at least 576
(RFC 791). It requires the legacy service-port uplink policy because the
error leaves through the UDP/2152 socket. Grouped entries refuse it, and the
eBPF probe reports `downlink_inner_mtu_enforcement`.

When an authorized downlink inner IPv4 packet with Don't Fragment set exceeds
that MTU, tc does not decapsulate it. The host therefore never forwards it
toward XFRM and never generates its own Fragmentation Needed, which would
leave unencapsulated from a host address and quote up to 548 octets of the
subscriber packet. tc hands the exact authorized G-PDU to this queue, and
the kernel reassembles outer fragments first. `try_receive_downlink`
re-authorizes the G-PDU against the same Active commit and returns
`GtpuDownlinkEvent::PacketTooBig`. At most one RFC 792/1191 Destination
Unreachable, Fragmentation Needed error is sent:

- The error is carried in the session's plain uplink G-PDU, from the
  committed local UDP/2152 tuple to the committed peer UDP/2152 with the
  committed peer TEID. Nothing is ever sent unencapsulated.
- Source address policy: the session PAA, which is the invoking packet's
  destination. This is the only inner source that the peer's per-PDN uplink
  anti-spoofing admits. The destination is the invoking packet's source.
- Quote: exactly the invoking IPv4 header and its first 64 data bits, as
  RFC 792 requires. No further application payload is quoted.
- No error is sent for a non-initial fragment, an ICMP error, or an unusable
  destination (RFC 1122 3.2.2).
- Rate limit: a per-registration token bucket, by default a burst of 16 with
  one token per 10 ms. `set_packet_too_big_rate_limit` replaces it.
  Suppressed or unsendable errors are counted and nothing is sent.

Oversized packets without DF are fragmentable and are decapsulated normally.
Inner IPv6 Packet Too Big (RFC 4443 / RFC 8201) is designed to use the same
path and the IPv6 builder once the ordinary inner-IPv6 PDP path lands.

Native evidence on the committed classifier covers:

- default, dedicated and outer-fragmented oversized DF packets;
- the exact error bytes, peer TEID, source and destination;
- the 28-octet quote and the next-hop MTU;
- fitting DF and oversized non-DF packets that are forwarded;
- the rate limit;
- zero plaintext ICMP frames in the peer and UE namespaces;
- an unchanged host `OutDestUnreachs` counter.

Both privileged lanes require `OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_PROVEN`. The ordinary legacy socket port keeps the default
`Unsupported` result. The consumer does not inject packets, admit peers, rate
limit, or plan Error Indications. Grouped attachments with an IPv4 outer
endpoint report `KernelReassemblyHandoff` for outer IPv4 fragments; outer IPv6
fragments remain unsupported. Inner IPv6 on the ordinary v5 path is
malformed, as in tc, until that path supports it.

Native evidence runs the committed classifier on ordinary and grouped
attachments: in-order, reordered, duplicated head and tail, missing,
foreign-TEID, wrong-peer, wrong-destination, stale Pending/Removing commit,
owner-only Pending, mixed binding, closed gate, stale grouped generation,
retirement and removal. Both privileged lanes require the
`OPC_GTPU_BACKEND_REASSEMBLY_CONSUMER_PROVEN` and
`OPC_GTPU_BACKEND_GROUPED_REASSEMBLY_CONSUMER_PROVEN` markers.
