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
| `Dropped` | Value-free `GtpuDownlinkDrop`: malformed, binding mismatch, destination mismatch, state unavailable, or an over-MTU packet refused by the inner fragmenter (rate limited, or carrying IPv4 options). |
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

`None` keeps today's behaviour: tc decapsulates the packet and the host
drops it with its own Fragmentation Needed toward the core.

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

**Binding and integration order.** The backend binds UDP/2152 and UDP/2153
when the control port is first opened for the attachment. It keeps them until
the attachment is removed or its queue is retired. Nothing is bound:
- before that first open;
- while the process is down across a restart, because tc keeps steering from
  the pinned graph;
- after a retirement, until the attachment is re-created or adopted and the
  port reopened.

In those windows the kernel answers each steered packet with ICMP Port
Unreachable toward the peer (RFC 1122 section 4.1.3.1). The error quotes as
much of the datagram as fits in 576 octets (RFC 1812 section 4.3.2.3): up to
about 512 octets of the inner packet, in plaintext, toward the core. The
UDP/2152 hand-offs of #1003 have always behaved the same way.

Open the control port right after creating or adopting the attachment, before
installing any context with a downlink inner MTU. Keep draining it for the
attachment's lifetime. Enforcement is tracked in #1019.

**tc.** When an authorized inner IPv4 packet with Don't Fragment set exceeds
the MTU, tc does not decapsulate it, so the host never forwards it. The host
also never emits its own error, as long as the hand-off queue is bound (see
above). tc rewrites only the UDP destination port, with an
incremental checksum update, to the backend-owned packet-too-big queue on the
same local address (`GTPU_PACKET_TOO_BIG_QUEUE_PORT`, 2153). tc reads only
the MTU bits, so it steers identically under both policies. Outer fragments
are reassembled first and arrive on the shared queue.

**Queue priority.** `try_receive_downlink` always serves the shared UDP/2152
queue first. A backlog of hand-offs therefore cannot delay or crowd out Echo
or reassembled G-PDUs.

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
   keyed-random value, so uniqueness is probabilistic. Admissions before
   and after a limit replacement are not counted together (#1018).

The result is `GtpuDownlinkEvent::Fragmented`: the fragments in offset order,
the MTU and the bearer mark. Its `Debug` output shows only the fragment
count and MTU.

**Injection.** The caller injects every fragment, in order, toward XFRM
with the returned mark, exactly as for a `Decapsulated` packet. On Linux an
`IPPROTO_RAW` socket (`IP_HDRINCL`) does this with `SO_MARK` set to the
bearer mark (zero for the default bearer). Linux builds the XFRM flow for
such a socket from the socket, not the packet: pass the inner source as the
`IP_PKTINFO` source so a source-specific OUT selector matches, and do not
rely on port or protocol selectors. Linux also replaces an Identification
of zero on an `IP_HDRINCL` send, which would break reassembly; fragments of
an atomic datagram never carry zero, but a received DF fragment's own
Identification is preserved as it is. Unlike a forwarding router (RFC 1812
section 5.3.1), the consumer does not decrement TTL, for fragments or for
`Decapsulated` packets. This is a documented limitation of this path.

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
  datagrams, which this path cannot see. A collision can misassemble at the
  UE: the hazard RFC 6864 section 5.3.1 describes for devices that rewrite
  datagrams. UDP and TCP checksums catch most such errors (RFC 6864 section
  5.2).

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
`SO_RXQ_OVFL` reports kernel drops from the shared queue and from the
packet-too-big queue.

**Limits.**

- tc has no hand-off counter and no in-kernel policer. Either would add a map
  and change the retained pin inventory and the durable recovery records.
- A flood toward one PAA can still fill the packet-too-big queue. When it
  does, the kernel drops further hand-offs from any session, and those drops
  are counted. It can never affect the shared queue.

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

Both privileged lanes require `OPC_GTPU_DOWNLINK_INNER_FRAGMENTATION_PROVEN`,
`OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_PROVEN` and
`OPC_GTPU_DOWNLINK_PACKET_TOO_BIG_BASELINE_PROVEN`.
