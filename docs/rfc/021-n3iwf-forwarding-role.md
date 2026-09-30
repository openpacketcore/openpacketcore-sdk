# RFC 021: N3IWF forwarding role between NWu GRE and N3 GTP-U

**Status:** Proposed contract. Maintainer-approved merge of
[#1029](https://github.com/openpacketcore/openpacketcore-sdk/pull/1029)
records acceptance; until then it is a proposal.
Acceptance approves the boundary and the three decisions below. It does not
qualify an implementation, and every shipped adapter keeps reporting the
N3IWF forwarding role as `Missing` until the evidence in §10 exists.

**Date:** 2026-09-30

**Version:** 0.1.0

**Tracking:** [SDK #1028](https://github.com/openpacketcore/openpacketcore-sdk/issues/1028).
It follows the closed N3 PSC work in
[#790](https://github.com/openpacketcore/openpacketcore-sdk/issues/790),
composes the closed NWu GRE codec in
[#789](https://github.com/openpacketcore/openpacketcore-sdk/issues/789) and the
closed overlapping Child SA work in
[#793](https://github.com/openpacketcore/openpacketcore-sdk/issues/793), and
succeeds the closed tracker
[#795](https://github.com/openpacketcore/openpacketcore-sdk/issues/795).
Related: [RFC 016](016-opaque-gtpu-selector-namespace.md),
[N3 fixed-flow forwarding](../n3-fixed-flow-forwarding.md),
[N3 End Marker retirement](../n3-end-marker-retirement.md),
[installed Child SA roster](../n3-installed-child-sa-roster.md) and the
[GTP-U control-port contract](../../crates/opc-gtpu-dataplane/docs/control-port.md).

## 1. Problem and decisions

The SDK can already frame every NWu and N3 user-plane packet that the N3IWF
role needs. #789 provides the keyed GRE codec, #790 the PSC codec and a bounded
fixed-flow classifier, and #793 installed overlapping Child SAs with distinct
full-mask marks. It cannot relay one PDU session between those legs, so
`GtpuDataplaneBackend::n3_forwarding_capability(N3ForwardingRole::N3iwf)`
returns `Missing` for every adapter.

Three properties of the role rule out reusing the S2b and fixed-flow shapes
unchanged:

- There is no PDU address to key on. The N3IWF receives the UPF tunnel, the
  session type and the QoS flows over N2. The PDU address reaches the UE end
  to end in a NAS message that the N3IWF only relays (TS 23.502 V18.10.0
  §4.12.5 step 5), and non-IP sessions have none.
- A session carries a QoS flow table. Up to 64 QFIs map onto Child SAs chosen
  by N3IWF policy, and "there shall be one and only one Default Child SA per
  PDU session" (TS 23.502 §4.12.5 steps 3 and 4a; TS 24.502 V18.8.0 §9.3.1.1).
- The NWu leg is keyed GRE inside an inner IP datagram addressed to the N3IWF
  itself (TS 24.502 §8.3.2). After XFRM input it is local traffic, not
  forwarded traffic.

This RFC decides the three questions that #1028 leaves open:

| Question | Decision |
| --- | --- |
| 1. Where the NWu GRE leg runs | A tc classifier from the existing committed eBPF object, attached at the ingress of a caller-provisioned Linux XFRM interface. Downlink traffic leaves through that interface's egress. There is no kernel GRE device. A bounded handoff through the existing backend-owned consumer pattern covers only fragmented inner GRE and oversized downlink datagrams (§4). |
| 2. Lifecycle shape | A versioned composite session record on the ordinary durable path, not the grouped selector namespace. One map element holds the whole session, so a PDU session modification swaps the QFI and Child SA tables for both directions in one element replacement (§5). |
| 3. Receiver dispositions | Each one is labelled 3GPP, SDK policy or caller policy (§6). Uplink admission accepts exactly the Child SA that the UE is required to use. An unknown downlink QFI follows a choice the caller declares per session. Teardown withdraws classification before a Child SA or tunnel retires. |

## 2. Scope

In scope are the forwarding role for PDU sessions over untrusted non-3GPP
access, the typed session intent and its lifecycle, the eBPF map ABI and
classifier behaviour that implement it, and the capability that reports it.

Out of scope are NGAP and IKE procedures, QoS policy and admission, the number
of Child SAs and the grouping of QFIs (N3IWF policy, TS 23.502 §4.12.5 step
3), mark and TEID allocation, XFRM state and policy installation (owned by
`opc-ipsec-xfrm`), PFCP, additional or redundant N3 tunnels, QoS monitoring,
MBS, inter-system data forwarding (TS 29.281 V18.4.0 §7.3.2.3), relocation of
the UPF tunnel of a live session, and any product, interoperability or
conformance claim.

## 3. Obligations and labels

Each source controls only its own wire obligation. *SDK policy* marks a choice
the standards leave open. *Caller policy* marks a decision that the SDK exposes
but does not make.

| Obligation | Source | Label |
| --- | --- | --- |
| GRE header with C=0, K=1, S=0 and Protocol Type set to zero | TS 24.502 §8.3.2 a0), table 9.3.3-2 | 3GPP |
| Receiver ignores the Protocol Type value | TS 24.502 table 9.3.3-2 NOTE | 3GPP; narrows the RFC 2784 §2.4 SHOULD for this profile |
| Key carries the QFI (octet 5, bits 5–0) and the downlink RQI (octet 8, bit 7); there is no PPI | TS 24.502 figure 9.3.3-3, table 9.3.3-3; RFC 2890 §2.1 | 3GPP |
| Uplink RQI is "not indicated" | TS 24.502 §8.3.2 d) | 3GPP for the sender; rejection on receive is the #789 SDK receive profile |
| Inner datagram addresses and protocol 47 | TS 24.502 §8.3.2 a) 1) and b) 1) | 3GPP |
| The inner datagram may be fragmented before ESP | TS 24.502 §8.3.2 (RFC 791, RFC 8200); TS 23.501 V18.12.0 §8.3.2 | 3GPP |
| The UE selects the Child SA of the QFI, otherwise the default Child SA | TS 24.502 §8.3.1 | 3GPP, UE obligation |
| Exactly one default Child SA per PDU session | TS 23.502 §4.12.5 step 4a | 3GPP |
| Downlink Child SA chosen from the QFI and PDU session; QFI copied; RQI may be included | TS 23.502 §4.12.5 step 8; TS 23.501 §5.7.5.3 NOTE 2 | 3GPP |
| A QFI is unique within a PDU session; the default QoS flow always exists | TS 23.501 §5.7.1.1 | 3GPP |
| N3 packet marking per QoS flow | TS 23.501 §6.2.9 | 3GPP function; values are caller policy |
| Outer NWu DSCP per Child SA | TS 24.502 §8.3.2 a) 3), §9.3.1.1 | 3GPP; applied by `opc-ipsec-xfrm`, not by this RFC |
| One uplink PSC of type 1; one downlink PSC of type 0 | TS 38.415 V18.2.0 §5.5.2.1, §5.5.2.2; TS 29.281 §5.2.2.7 | 3GPP |
| G-PDU with an unknown TEID | TS 29.281 §7.3.1 | 3GPP; existing control handoff |
| End Marker receive and send | TS 29.281 §4.4.2.6, §4.4.3.6, §7.3.2.1 | 3GPP |
| At most eight Child SAs per session; map capacities | — | SDK policy |

## 4. Decision 1: the NWu leg is a classifier at an XFRM interface

### 4.1 Anchor

The caller provisions one Linux XFRM interface (link type `xfrm`, nonzero
`if_id`) for the NWu user plane. It installs every user-plane Child SA of an
N3IWF session with that `if_id`, a distinct nonzero inbound set-mark with the
full mask, and outbound policies that select the same mark and `if_id`. The
#793 contract already carries the XFRM interface scope in Child SA identity;
this RFC requires it for the N3IWF role. The signalling Child SA may use the
same interface.

The SDK attaches one new classifier from the committed object at that
interface's tc ingress. That classifier is the *NWu hook* of exactly one N3
attachment, and it uses the attachment's existing pinned map graph. The role
therefore adds one program to one object, one map graph and one generation
guard. It is not a second datapath.

The design relies on the following Linux behaviour, checked against the v6.8
sources:

- XFRM input applies the Child SA's set-mark to the decrypted packet
  (`xfrm_input`: `skb->mark = xfrm_smark_get(skb->mark, x)`) and re-injects a
  tunnel-mode packet through `gro_cells_receive`. With an XFRM interface,
  `xfrmi_rcv_cb` moves the packet to that interface, so its tc ingress sees
  the decrypted inner datagram together with its secpath and mark.
- Transmission on an XFRM interface looks up policy with the packet mark and
  the interface `if_id` (`__xfrm_decode_session` copies `skb->mark`;
  `xfrm_lookup_with_ifid`). `xfrmi_xmit2` drops the packet when no state
  matches (`if (!x) goto tx_err_link_failure`), so a missing Child SA drops
  downlink traffic instead of sending it in clear.
- `bpf_skb_get_xfrm_state` is available to tc classifiers, is not GPL-only,
  and reads the secpath entries.

### 4.2 Uplink

For each packet at the NWu hook:

1. A packet whose IPv4 protocol or IPv6 next header is not 47 passes
   unchanged. The classifier takes no ownership of it. IPv6 GRE is recognised
   directly or behind the existing bounded extension walker.
2. Every GRE packet belongs to the N3IWF role. It is forwarded, handed off as
   a fragment (§4.6) or dropped; none reaches the host GRE stack.
3. Provenance (§4.5): the secpath holds exactly one XFRM state, and the packet
   mark is nonzero and indexed to an Active session record that contains a
   Child SA with that mark. Mark zero never selects an N3IWF session.
4. Selector: the inner source equals that Child SA's UE inner address and the
   inner destination equals its UP address. The tc redirect runs before the
   kernel's inbound policy check (`__xfrm_policy_check` matches the SA
   selector at local delivery), so the classifier re-establishes that check
   itself.
5. GRE: the flags word satisfies `flags & 0xfc07 == 0x2000` (C=0, K=1, S=0,
   version 0; bits 6–12 are ignored as RFC 2784 §2.3 requires). The Protocol
   Type is never read, key spare bits are ignored, RQI must be clear and the
   payload must be nonempty. This is byte for byte the uplink receive rule of
   `opc_proto_gre::NwuGrePacket::decode`.
6. Admission follows rows U1 to U4 of §6.
7. Encapsulation removes the inner IP and GRE headers and prepends outer IP,
   UDP and GTP-U with exactly one uplink PSC of type 1 carrying the GRE QFI,
   as the fixed-flow insertion does. It applies the flow's N3 DSCP when one is
   configured, the session's uplink source-port policy and the attachment's
   existing MTU policy, then clears the mark. Because the NWu hook is a layer
   3 device, the classifier pushes a placeholder link header
   (`bpf_skb_change_head` documents this use) and redirects with
   `bpf_redirect_neigh` to the N3 attachment, as the existing uplink does. The
   existing egress program recognises the re-emitted frame as its own.

### 4.3 Downlink

The existing tc ingress program of the N3 attachment keeps its envelope, TEID
and endpoint-binding checks unchanged. After them:

1. A local TEID owned by an N3IWF record requires that record to be Active and
   the packet to carry exactly one downlink PSC of type 0, using the fixed-flow
   receive subset (TS 38.415 §5.5.2.1).
2. The Child SA is selected by rows D1 to D3 of §6.
3. The classifier removes the outer IP, UDP and GTP-U headers with their
   extension headers. It adds an inner IP header from the Child SA's UP
   address to its UE inner address with protocol 47 (TS 24.502 §8.3.2 a) 1) B)
   and b) 1) B)), and a GRE header with flags `0x2000`, Protocol Type zero, the
   QFI and a transparent copy of the PSC's RQI. PPI cannot be represented in
   the key and is discarded. The inner header carries DSCP zero and Not-ECT;
   `opc-ipsec-xfrm` applies the Child SA's outer DSCP (TS 24.502 §8.3.2 a) 3)).
4. The classifier sets the Child SA's full mark and redirects the datagram to
   the XFRM interface's egress (`bpf_redirect` without `BPF_F_INGRESS`). The
   payload stays opaque for every PDU session type (TS 23.501 §5.7.1.1).

### 4.4 GRE header rules

Transmission always writes the eight-byte header
`20 00 00 00 QQ 00 00 R0`, where `QQ` is the QFI and `R` is `8` when RQI is
indicated. This is the #789 encoder output. Reception ignores the Protocol
Type: TS 24.502 table 9.3.3-2 states that "the receiving entity shall ignore
value of the Protocol Type field", which controls this profile over the RFC
2784 §2.4 recommendation to discard unlisted types. The Key field follows RFC
2890 §2.1 with the content that TS 24.502 figure 9.3.3-3 defines. Checksum,
sequence number and routing fields are never present in this profile.

### 4.5 Child SA provenance

Four facts bind an uplink packet to one logical Child SA:

1. It arrived at the XFRM interface's ingress, which only XFRM input for an SA
   with that `if_id` reaches.
2. Its secpath holds exactly one state.
3. It carries that Child SA's full mark.
4. Its inner addresses match that Child SA's selector.

Together with the exact full-mask marks and writer exclusion of #793, these
identify the child without trusting any caller label. Rekeying under the #793
overlap keeps the logical child's mark, so it needs no dataplane change. The
mark is cleared after encapsulation and never leaves the host.

### 4.6 Fragmentation and path MTU

**Uplink.** The UE may fragment the inner datagram (TS 24.502 §8.3.2; TS
23.501 §8.3.2: "Large GRE packets may be fragmented by the 'inner IP' layer").
A tc classifier cannot reassemble, and a non-first fragment carries no GRE
header. The fragment profile therefore works as follows:

- The classifier applies every provenance, mark and address check that does
  not need the GRE header to each fragment. It passes only matching fragments
  to the host stack.
- The kernel reassembles under its bounded `net.ipv4.ipfrag_*` and IPv6
  equivalents, as it already does for downlink outer fragments.
- A backend-owned raw GRE socket bound to the XFRM interface receives the
  complete datagram. `SO_RCVMARK` supplies the reassembled packet's mark and
  packet information supplies its interface and destination. The kernel's
  inbound policy check has already run at that socket.
- The consumer re-applies the complete uplink validation and admission against
  the same authoritative record, observing the Active record last. It then
  transmits the G-PDU through the managed GTP-U socket.

Kernels without `SO_RCVMARK` (introduced in Linux 5.19) refuse this profile
precisely. Record format 1 drops inner fragments and counts them.

**Downlink.** The N3IWF originates the inner datagram, so it may fragment that
datagram before ESP (TS 24.502 §8.3.2; RFC 791 §2.3; RFC 8200 §4.5) without
touching the opaque payload. Record format 2 adds a per-Child SA NWu inner
MTU. The classifier hands a larger packet, still encapsulated, to the
backend-owned consumer. The consumer builds and fragments the inner datagram
and transmits the fragments through the XFRM interface with the Child SA's
mark. Format 1 carries no MTU. Its IPv4 inner datagrams leave DF clear, so the
kernel fragments an oversized one after ESP. Its IPv6 inner datagrams above
the XFRM path MTU are dropped at the interface. Neither format-1 behaviour
qualifies the role.

### 4.7 Rejected placements

- **A kernel GRE device (`ip_gre`).** Its receive path takes the inner protocol
  from the Protocol Type (`__iptunnel_pull_header`: `skb->protocol =
  inner_proto`), so Protocol Type zero has no handler and cannot be ignored.
  Its transmit path writes the payload's ethertype instead of zero. Its output
  key is fixed per device, so the per-packet QFI and RQI would need one device
  per key and per session. It breaks table 9.3.3-2 in both directions.
- **A classifier on the physical NWu device with policy-based SAs.** The
  decrypted inner GRE is addressed to a local UP address and never reaches the
  N3 egress hook. The rebuilt downlink datagram has a local source address,
  which the receive path rejects as martian unless `accept_local` is set
  (`fib_validate_source`). `bpf_redirect_neigh` calls `neigh_output` directly
  and never enters XFRM output, so it would send the inner datagram in clear.
- **A userspace relay for every packet.** That is a second datapath with a
  per-packet system-call cost and its own provenance problem. It is kept only
  for fragments and oversized datagrams (§4.6).

## 5. Decision 2: a versioned composite entry on the ordinary durable path

### 5.1 Why not the grouped selector namespace

RFC 016 gives the grouped namespace permanent anti-reuse history. Every
admission permanently consumes a group record and its selector atoms, and
retirement never frees them. The reference profile caps permanent group
records at 1,024 and live groups at 512 inside one encrypted whole-ledger
record of at most 512 KiB (RFC 016 §5.2, §5.3). A role whose sessions come and
go would exhaust that history. Lifting the caps means designing a sharded
ledger with its own proofs. Its 208-byte group record holds two inner-family
entries keyed by PAA; it has no room for a QoS flow table and there is no PAA
to key on.

3GPP requires no permanent history for N3 TEIDs or Child SA marks. The
contracts that #1028 asks to carry over are those of the ordinary path: exact
classified install, exact readback, fenced exact removal, restart recovery and
an Active state published last. The composite record keeps all of them.

The trade-off is the absence of permanent anti-ABA history. A local TEID or
mark may be reused once exact removal has returned, and removal completes
classifier quiescence before it returns (§5.5). This matches ordinary S2b
contexts. The caller must not reuse either value earlier.

### 5.2 Typed session intent

The first slice adds these experimental types to `opc_gtpu_dataplane::n3`.
All of them redact their complete `Debug` output, and their errors carry only
static reasons.

| Type | Contract |
| --- | --- |
| `N3iwfN3Tunnel` | The N3 link ifindex, the received UPF TNL (`ReceivedN3UplinkTnl`), the locally supplied N3IWF TNL (`LocalN3DownlinkTnl`) and both source-port policies. Both TNLs use one address family. |
| `N3iwfQosFlow` | One QoS flow of the session as received over N2: its `N3Qfi` and an optional N3 uplink DSCP. |
| `N3iwfQfiSet` | Allocation-free set of QFIs 0–63. Adding a QFI twice is an error. |
| `N3iwfChildSa` | One logical user-plane Child SA: its full `GtpBearerMark`, the UE inner address (`INTERNAL_IP*_ADDRESS`), the UP address (`UP_IP*_ADDRESS`) and the QFIs explicitly associated with it (the `5G_QOS_INFO` QFI list). |
| `N3iwfDownlinkUnknownQfi` | The caller's declared disposition for a downlink QFI outside the session: `Drop` or `DefaultChildSa`. |
| `N3iwfSessionIntent` | The complete desired session in canonical order: flows by QFI and Child SAs by mark. It names the default Child SA and has no PAA. |
| `N3iwfSessionModelError` | Value-free validation refusal. |

Construction validates the following rules exactly and refuses everything else:

| Rule | Basis |
| --- | --- |
| At least one QoS flow; every QFI is unique | TS 23.501 §5.7.1.1 |
| One to eight Child SAs with distinct marks | Eight is SDK policy (§5.4) and stays within the #793 roster bound of 32 pairs |
| The default Child SA is one of the session's Child SAs | TS 23.502 §4.12.5 step 4a |
| Every explicitly associated QFI is a session flow, and no QFI is associated with two Child SAs | TS 24.502 §8.3.1 a) selects a single Child SA; §9.3.1.1 lists the QFIs of each Child SA |
| A session flow without an explicit association uses the default Child SA | TS 24.502 §8.3.1 b) |
| UE inner and UP addresses of one Child SA share a family, are concrete unicast and non-loopback, and differ | TS 24.502 §8.3.2 a) and b) |
| At most one UE inner address per family in the session | TS 24.502 §8.3.2: one `INTERNAL_IP4_ADDRESS` or `INTERNAL_IP6_ADDRESS` from IKE_AUTH |
| A UE inner address equals no UP address and neither N3 endpoint, and a UP address differs from the UPF address | SDK policy against aliasing |
| Nonzero N3 link ifindex; both N3 TNLs in one family | Existing N3 intent rules |
| A canonical uplink source-port policy (no port zero and no `Selected(2152)`) | Existing ordinary GTP-U rule |

A Child SA with no explicit QFIs is valid, because `5G_QOS_INFO` allows "zero
or more QFIs". The pure functions `uplink_admission` and `downlink_selection`
on the intent encode rows U1 to U4 and D1 to D3 of §6. Backends and tests use
them as the reference model, so datapath behaviour can be compared with them.

### 5.3 Lifecycle operations

`GtpuDataplaneBackend` gains these methods. Each default returns
`GtpuError::UnsupportedFeature` with the exact label shown, so existing
implementations compile unchanged and fail closed.

| Method | Contract | Default label |
| --- | --- | --- |
| `read_n3iwf_session` | Exact readback by local downlink TNL or by Child SA mark: `Absent`, or `Present` with the complete intent and the backend-issued `N3iwfSessionGeneration`. Partial, transitional or inconsistent state is an error, never `Absent`. | `n3iwf_session_readback` |
| `install_n3iwf_session_classified` | Classified install: `Installed`, `ExactAlreadyPresent`, `Conflict` or `Indeterminate`. It never treats uninspected occupancy as success. | `n3iwf_session_classified_install` |
| `reconcile_n3iwf_session_flows` | Atomic flow-table swap from an exact expected session and generation to a desired intent with the same N3 tunnel: `Reconciled`, `ExactAlreadyPresent`, `Absent`, `Conflict` or `Indeterminate`. | `n3iwf_session_flow_reconcile` |
| `remove_n3iwf_session_exact` | Removal of exactly the expected session and generation. | `n3iwf_session_exact_removal` |
| `recover_n3iwf_session_exact` | Exact removal after the prior writer stopped, bound to the device identity and incarnation (`PdpRestartRecoveryProof`). | `n3iwf_session_restart_recovery` |
| `remove_n3iwf_session_exact_live_writer` | Exact removal under the affine `PdpLiveWriterProof`. | `n3iwf_session_live_writer_removal` |
| `n3iwf_session_lifecycle_capabilities` | Reports each operation separately. The default reports every one as `Missing`. | — |

Outcomes reuse the value-free `PdpContextIndeterminateReason` and
`PdpContextRepairReason`. `N3iwfSessionConflict` reports only which selectors
are occupied (`LocalTeid`, `ChildSaMark`, `Both` or `OtherRole`) and the names
of the differing fields, never values. A generation is an observation token
that fences stale writers. It is not authority, and forging one can at most
produce a `Conflict`.

A flow update that changes the N3 tunnel is refused at construction. Changing
the UPF tunnel of a live session is a separate relocation operation that is out
of scope; until it exists, the caller removes and installs the session.

### 5.4 Proposed map ABI, record format 1

Two maps join the attachment's pinned graph. Both are hash maps without
preallocation, updated only by whole-element operations.

| Map | Key | Value |
| --- | --- | --- |
| `GTPU_N3IWF_SESS` (65,536 entries) | 8 bytes: N3 outer family tag (`4` or `6`), three zero bytes, local TEID (big-endian, nonzero) | 512-byte session record below |
| `GTPU_N3IWF_UL` (131,072 entries) | 4 bytes: Child SA mark (big-endian, nonzero) | 8-byte session key of the owning record |

An uplink index entry authorizes nothing by itself: the classifier forwards
only when the owning record is Active and contains that mark.

Session record, format 1. Integers are big-endian and addresses use 16-byte
slots, with IPv4 in the first four bytes and a zero tail:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | Format version, `1` |
| 1 | 1 | Phase: `1` Pending, `2` Active, `3` Removing |
| 2 | 1 | Flags: bit 0 set when an unknown downlink QFI uses the default Child SA; other bits zero |
| 3 | 1 | Child SA count, 1–8 |
| 4 | 8 | Generation, nonzero and never wrapping |
| 12 | 1 | Default Child SA slot |
| 13 | 1 | N3 outer family tag |
| 14 | 1 | Downlink source-port policy kind (`0` any, `1` exact, `2` range) |
| 15 | 1 | Uplink source-port policy kind (`0` legacy service port, `1` selected) |
| 16 | 4 | Downlink source port first and last |
| 20 | 2 | Uplink source port, `2152` for the legacy policy |
| 22 | 2 | Zero |
| 24 | 4 | UPF TEID |
| 28 | 4 | Local TEID, equal to the key |
| 32 | 16 | UPF N3 address |
| 48 | 16 | Local N3 address |
| 64 | 64 | QFI table: for QFI *q*, byte *q* is `0xff` (not a session flow), `0xfe` (session flow using the default Child SA) or a Child SA slot |
| 128 | 64 | N3 uplink DSCP table: `0xff` for none, otherwise the codepoint |
| 192 | 320 | Eight 40-byte Child SA slots: mark (4), inner family tag (1), zero (3; format 2 places the NWu inner MTU here), UE inner address (16), UP address (16). Slots are sorted by mark; unused slots are all zero. |

Decoding requires the exact canonical encoding and re-encoding, as the
existing fixed-flow entries do. Eight Child SAs keep the record at 512 bytes
and let the classifier search a session's slots in a verifier-bounded loop.
They leave room well above the single Child SA carrying every QoS flow that
TS 23.502 §4.12.5 step 3 gives as its example. Raising the bound, or giving
meaning to a reserved byte, requires a new format version.

### 5.5 Ordering, readback and recovery

Every mutation runs under the attachment's existing exclusive writer lease and
first proves that the current program generation, including the NWu hook, is
exactly attached. Otherwise it returns `UnsupportedFeature`.

- **Install.** Insert the record as Pending (no-exist), insert each index entry
  (no-exist), replace Pending with Active, then read back the record and the
  complete index closure. Active is published last. An occupied key, a mark
  indexed to another session or a TEID held by another role is a `Conflict`
  with no mutation.
- **Flow swap.** Insert index entries for new marks. Replace Active generation
  *N* with Active generation *N*+1 in one element update; this is the single
  cutover for both directions. Delete index entries for removed marks, but only
  while they still name this session. When a Child SA leaves the table,
  complete the existing qualified classifier grace before returning. Packets
  already holding the old element finish with the old table; no packet sees a
  mix of the two.
- **Removal.** Replace Active with Removing, so both directions drop. Delete
  this session's index entries, delete the record, prove the absence of both
  and complete the classifier grace before returning `Removed`.
- **Readback.** `Present` requires an Active canonical record whose Child SA
  marks are all indexed to it, with no other entry naming it. Pending or
  Removing records, index residue, missing entries and non-canonical bytes are
  indeterminate. They are never collapsed into `Absent`.
- **Restart.** The pinned maps survive the process. Attach adoption validates
  every composite record canonically before either hook is accepted, as it
  already does for retained graphs; a malformed record refuses the attachment.
  The caller then reads back each durable descriptor. Restart recovery removes
  exact stale sessions, resolving Pending by removal and Removing by
  completion; it never publishes a session.

A crash between swap steps leaves an Active record and unreferenced index
entries. Those entries authorize nothing and appear as residue until an exact
reconcile or removal clears them. A generation counter that would wrap refuses
the swap without mutation.

### 5.6 Exclusivity

One attachment shares a local TEID space across ordinary, grouped or
fixed-flow, and composite state. Install refuses a TEID that another role holds
(`OtherRole`), and the downlink classifier drops a TEID found in more than one
namespace. Marks are unique per attachment in the uplink index, and mark zero
is never indexed.

## 6. Decision 3: receiver dispositions

| Row | Situation | Disposition | Label and basis |
| --- | --- | --- | --- |
| U1 | Uplink QFI explicitly associated with the receiving Child SA | Forward with an uplink PSC carrying that QFI | 3GPP: TS 24.502 §8.3.1 a); TS 23.502 §4.12.5 step 8; TS 38.415 §5.5.2.2 |
| U2 | Uplink on the default Child SA with a session QFI that has no explicit association | Forward | 3GPP: TS 24.502 §8.3.1 b); TS 23.502 §4.12.5 step 4a |
| U3 | Uplink session QFI associated with another Child SA (a QFI on a non-mapped SA) | Drop and count | SDK policy. TS 24.502 §8.3.1 binds only the UE. The N3IWF enforces the association it signalled, so a flow cannot take the QoS path negotiated for another. |
| U4 | Uplink QFI outside the session | Drop and count | SDK policy: the N3IWF forwards only QoS flows it received over N2 (TS 23.501 §5.7.1.1, §6.2.9) |
| U5 | Uplink RQI set, invalid flags or version, missing key, empty payload | Drop | SDK receive profile of #789: TS 24.502 §8.3.2 d), table 9.3.3-2; RFC 2784 §2.3; RFC 2890 |
| U6 | Nonzero received Protocol Type | Ignore the value | 3GPP: TS 24.502 table 9.3.3-2 NOTE |
| U7 | GRE without a single-state secpath, with mark zero or an unindexed mark, or failing the Child SA selector | Drop; never pass to the host | SDK policy for containment. Unlike the S2b mark-zero miss, nothing passes. |
| U8 | Inner fragments | Fragment profile of §4.6; dropped and counted in format 1 | 3GPP: TS 24.502 §8.3.2; TS 23.501 §8.3.2 |
| D1 | Downlink QFI explicitly associated | That Child SA | 3GPP: TS 23.502 §4.12.5 step 8 |
| D2 | Downlink session QFI without an explicit association | The default Child SA | SDK policy, mirroring the UE rule of TS 24.502 §8.3.1 b) and TS 23.502 §4.12.5 step 4a |
| D3 | Downlink QFI outside the session | `Drop` or `DefaultChildSa`, declared per session. There is no implicit default. | Caller policy |
| D4 | Downlink RQI and PPI | RQI copied into the GRE key; PPI discarded | 3GPP: TS 23.501 §5.7.5.3 NOTE 2; TS 24.502 §8.3.2 c), figure 9.3.3-3 |
| D5 | Missing or duplicate PSC, uplink PSC type, unsupported conditional fields | Drop | Existing fixed-flow subset: TS 38.415 §5.5.2.1; TS 29.281 §5.2.2.7 |
| D6 | Unknown TEID | Existing control handoff; zero TEID or malformed envelope drops | 3GPP: TS 29.281 §7.3.1 |
| E1 | End Marker for a composite session's TEID | Validated handoff to the control endpoint with no forwarding and no state change. Later G-PDUs are not discarded automatically. | SDK handoff. Whether to retire is caller policy: TS 29.281 §7.3.2.1 says such G-PDUs "may be silently discarded". |
| E2 | End Marker for an unknown TEID | Ignored, with no Error Indication | 3GPP: TS 29.281 §7.3.2.1 |
| E3 | End Marker sent at retirement | The existing retirement submission: IPv4 outer and UDP port 2152 on both sides. Outer IPv6 or a selected source port returns a typed `Unsupported` before anything is sent. | SDK capability boundary; the timing is caller policy (TS 29.281 §4.4.2.6, §4.4.3.6) |
| T1 | Teardown order | Removal and swaps withdraw classification in one record update and return only after classifier quiescence. The caller deletes a Child SA's XFRM state and policy only after that, and installs them before a swap references the Child SA. A violation drops at the XFRM interface instead of leaking. | Caller policy with an SDK guarantee: TS 23.502 §4.12.6 step 4c, §4.12.7 step 5; TS 24.502 §7.7 |

TS 24.502 §7.6.3 lets the UE reject a Child SA modification. The caller then
swaps back with a second reconcile from the new generation. Both directions
use the same atomic operation.

## 7. Preserved contracts and compatibility

- **Bytes.** Ordinary S2b maps, the grouped 208-byte group record, 80-byte
  entries, 464-byte journal and selector stamps, version-2 fixed-flow entries,
  and the `n3-gtpu` and `gre-qfi` fixture bytes are unchanged. Composite state
  lives only in the two new maps.
- **Behaviour.** The S2b mark-zero pass-through, unknown-TEID handoff,
  checksum-offload control pass-through (#644), Echo and Error Indication
  rules, and the fixed-flow and End Marker profiles are unchanged. Composite
  sessions reuse the existing control port.
- **Older programs.** An older generation never reads the new maps. It treats
  composite TEIDs as unknown, handing them to the control endpoint without
  decapsulation, and GRE at the XFRM interface meets no classifier. The loader
  refuses composite mutations unless the current generation and the NWu hook
  are exactly attached. A format-1 program drops a record of any other format
  version. Downgrading requires draining composite sessions first, as it does
  for MTU-bearing contexts today.
- **API.** The Rust surface is additive: new types and trait methods with
  unsupported defaults. Existing public APIs stay source-compatible.

## 8. Security, privacy and observability

The classifier trusts no caller label at packet time. Provenance rests on the
XFRM interface, the secpath, the full mark and the Child SA selector (§4.5).
Every NWu GRE packet is forwarded, handed off or dropped; errors drop. The
downlink leaves only through the XFRM interface, where a missing Child SA
drops the packet.

The new types redact their complete `Debug` output. Errors are static strings.
Counters are fixed-cardinality aggregates, with one per-CPU slot per drop
reason (no secpath, unindexed mark, inactive record, selector mismatch, invalid
GRE, uplink RQI, wrong Child SA, unknown QFI, fragment, invalid PSC). There
are no per-session, QFI, mark or address metrics, logs or labels. Test vectors
are synthetic.

## 9. Capability reporting

`n3iwf_session_lifecycle_capabilities` reports the state lifecycle only. It is
not a forwarding claim. A later slice adds an attachment-scoped
`n3iwf_forwarding_capability`, keyed by the N3 attachment and its NWu hook. It
reports `Available` only for an attachment whose exact current program
generation, maps, hooks and kernel profile are qualified by §10. The coarse
`n3_forwarding_capability(N3ForwardingRole::N3iwf)` then follows it. The
Linux kernel-GTP and unsupported adapters stay `Missing`. The mock implements
readback, classified install, the flow swap and exact removal for tests, with
the ordering and conflict rules of §5.5, and reports those four as available.
It has no durable writer authority, so restart recovery and live-writer
removal stay `Missing`, and it keeps reporting forwarding as `Missing` because
it forwards no packets.

## 10. Delivery plan and acceptance evidence

1. This RFC, the typed intent, the default-unsupported trait methods, the mock
   state lifecycle and contract tests. There is no eBPF change.
2. The format-1 codec in `opc-gtpu-ebpf-common`: canonical encode and decode,
   independent literal vectors, and refusal of every single-byte mutation.
3. The eBPF slice: the NWu classifier, the composite downlink branch, map
   materialization and the generation guard, for unfragmented traffic. Native
   topology tests use real tunnel-mode ESP from a peer namespace through an
   XFRM interface, with a signalling SA, two overlapping user-plane SAs for
   one session and a second session, and check literal GRE and PSC bytes.
4. The fragment and oversize consumer (format 2), End Marker receive handoff
   and send at retirement for composite sessions, and eBPF restart recovery
   and live-writer removal.
5. Qualification and the capability report: privileged suites on the native,
   EL9 and Linux 6.8 lanes with zero ignored tests and a positive
   `OPC_GTPU_N3IWF_FORWARDING_PROVEN:` marker.

The acceptance criteria of #1028 apply unchanged. They cover the topology,
every NWu inner and N3 outer family pair, two or more QFIs on one Child SA,
default fallback, negative packets that drop without leaking, a flow-table
swap under traffic that reaches no wrong or default Child SA, stale-writer
refusal, restart adoption, removal ordering, End Marker behaviour, conformance
vectors extending `tests/n3_reference.py` with independent GRE key to PSC
vectors, unchanged S2b and fixed-flow bytes, and retained detector,
fix-removal and mutation evidence.

## 11. Open questions for maintainers

1. Is requiring an XFRM interface (`if_id`-scoped Child SAs) for the NWu leg
   acceptable, leaving policy-based deployments without the role?
2. Is eight Child SAs per session the right SDK bound, against 16 or the full
   #793 roster bound of 32?
3. `SO_RCVMARK` needs Linux 5.19. Should the fragment profile be refused on
   EL9 kernels that lack a backport, or should it bind provenance another way?
4. Does the eBPF profile need distinct restart-recovery and live-writer
   methods, or is exact removal under the re-acquired attachment lease enough?
5. Should uplink admission offer an opt-in that accepts a session QFI on any of
   the session's Child SAs (row U3), or stay strict?
