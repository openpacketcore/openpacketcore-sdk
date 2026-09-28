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

### Downlink tunnel-MTU enforcement (opt-in)

`GtpPdpContext::downlink_inner_mtu`
(`GtpuDownlinkInnerMtu::in_tunnel_packet_too_big`) is an explicit per-context
opt-in. It carries the session's downlink inner MTU: for an ePDG, the SWu
access MTU minus the negotiated ESP/UDP/IP overhead, at least 576 (RFC 791).

**Storage.** The MTU lives in the previously reserved bytes 66..68 of the
Active `PdpContextCommit`, so it is published, replaced and read back
atomically with the rest of the graph. A record without it is byte-identical
to the original layout. An older SDK does not tolerate a record carrying an MTU: its retained-graph
recovery rejects the non-canonical commit and refuses the whole attachment
as indeterminate, not just that context. Before downgrading, drain every
MTU-bearing context (reinstall it with `None`, or remove it).

**Refusals and capability.** The legacy service-port uplink policy is
required. Grouped entries refuse the field. The eBPF probe reports
`downlink_inner_mtu_enforcement`. `Available` covers the datapath only: an
error is sent only while the application drains this port.

**tc.** When an authorized inner IPv4 packet with Don't Fragment set exceeds
the MTU, tc does not decapsulate it, so the host never forwards it and never
emits its own error. tc rewrites only the UDP destination port, with an
incremental checksum update, to the backend-owned packet-too-big queue on the
same local address (`GTPU_PACKET_TOO_BIG_QUEUE_PORT`, 2153). Outer fragments
are reassembled first and arrive on the shared queue.

**Queue priority.** `try_receive_downlink` always serves the shared UDP/2152
queue first. A backlog of hand-offs therefore cannot delay or crowd out Echo
or reassembled G-PDUs.

**Signalling.** The G-PDU is re-authorized against the same Active commit and
`GtpuDownlinkEvent::PacketTooBig` is returned. At most one RFC 792/1191
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
- **Rate limit.** One token bucket per offending session (RFC 4443 2.4 (f)):
  a burst of 16 with one token per 10 ms by default, set by
  `set_packet_too_big_rate_limit`. At most 4,096 sessions are tracked per
  attachment, least recently used first out. A flood toward one PAA exhausts
  only that session's budget.
- **Counters.** Value-free counters report too-big, signalled, rate-limited
  and unsendable packets. `SO_RXQ_OVFL` reports kernel drops from the shared
  queue and from the packet-too-big queue.

**Limits.**

- tc has no hand-off counter and no in-kernel policer. Either would add a map
  and change the retained pin inventory and the durable recovery records.
- A flood toward one PAA can still fill the packet-too-big queue. When it
  does, the kernel drops further hand-offs from any session, and those drops
  are counted. It can never affect the shared queue.

**Tradeoff.** The error's source is the subscriber's own address. The ePDG is
routing, so RFC 1812 4.3.2.4 would have it use its own address, but the PGW's
per-PDN anti-spoofing admits only the PAA. The originator therefore attributes
the error to the subscriber. RFC 4459 alternatives are:

- clearing the inner DF bit and fragmenting the inner packet before
  encryption;
- MSS clamping plus SIP over TCP for large requests.

This path implements only the in-tunnel error.

**IPv6.** Inner IPv6 Packet Too Big (RFC 4443 / RFC 8201) is designed to use
the same path and the IPv6 builder once the ordinary inner-IPv6 PDP path
lands.

**Native evidence.** The committed classifier is exercised with:

- default, dedicated (answered on the default-bearer uplink) and
  outer-fragmented oversized DF packets;
- the exact error bytes, the 28-octet quote and the next-hop MTU;
- fitting DF packets and oversized non-DF packets, which are forwarded;
- the per-session rate limit;
- an Echo served ahead of a 40-packet hand-off backlog;
- never-answer packets that consume no token;
- zero plaintext ICMP in the peer and UE namespaces, and an unchanged host
  `OutDestUnreachs`.

A baseline test pins the unchanged default without the opt-in: the host emits
its own error, quoting 548 octets toward the core.

Both privileged lanes require `OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_PROVEN` and
`OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_BASELINE_PROVEN`.
`Unsupported` result. The consumer does not inject packets, admit peers, rate
limit, or plan Error Indications. Grouped attachments with an IPv4 outer
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
