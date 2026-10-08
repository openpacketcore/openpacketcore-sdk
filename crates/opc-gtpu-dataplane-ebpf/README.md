# opc-gtpu-dataplane-ebpf

## Purpose

`opc-gtpu-dataplane-ebpf` contains the Rust/aya tc programs used by
`opc-gtpu-dataplane`'s `EbpfGtpuDataplaneBackend`.

It is not a normal workspace library. It targets `bpfel-unknown-none`, builds a
CO-RE object, and is intentionally excluded from the SDK workspace.

## API Shape

The crate exposes tc entry points, not a Rust library API:

- `opc_gtpu_uplink`: tc egress program. It resolves an IPv4 `/32` or canonical
  IPv6 `/64` UE source plus the complete packet mark through the grouped
  uplink index, retains that index value, and performs exactly one
  generation/slot-authority lookup. The selected entry may use an independent
  outer IPv4 or IPv6 endpoint family. It then prepends the corresponding
  `[outer IP][UDP][GTPv1-U]` header, consumes a nonzero mark, and redirects
  toward the peer. A present but malformed, transitional, stale, or
  mismatched grouped reference drops fail closed; only a true grouped-index
  miss may use the frozen v5 IPv4 maps. Outer IPv6 requires fully materialized,
  non-GSO bytes, gets a mandatory software-generated UDP checksum, and accounts
  56 bytes against the effective link MTU; outer IPv4 accounts 36 bytes and
  retains the strict DF behavior. The UDP destination port is always 2152.
  The host-only `RequireOuterFragmentation` policy remains non-executable
  because `bpf_redirect_neigh` bypasses the kernel fragmentation path.
  Before resolving an unmarked inner IPv4 packet, an owned TFT classifier may
  select its bearer. Fragment zero with `MF=1` must expose all required header
  fields to establish bounded affinity; later fragments reuse that decision
  only under the same classifier identity. ESP classification uses protocol
  50 and visible SPI, never protected TCP/UDP ports. Every fragment still
  passes the existing downstream exact peer/F-TEID authority lookup.
- `opc_gtpu_downlink`: tc ingress program. It matches UDP/2152 GTPv1-U G-PDUs,
  proves the complete outer IPv4 or IPv6 envelope and checksum boundary,
  derives the independent inner family, and resolves `(outer family, inner
  family, local TEID)` through the retained grouped index and one authority
  lookup. Only an exact `Active` generation/slot, attachment configuration,
  outer peer/local endpoint, UDP source-port policy, and inner destination may
  decapsulate. The program strips the proven outer envelope, writes the
  dedicated-bearer mark (or zero), and continues through the ePDG's XFRM
  output policy. On the legacy path, an authorized inner IPv4 packet with
  Don't Fragment set that exceeds the Active commit's optional downlink inner
  MTU is not decapsulated. tc rewrites only its UDP destination port (with an
  incremental checksum update) to the backend-owned packet-too-big queue
  (`GTPU_PACKET_TOO_BIG_QUEUE_PORT`, 2153). Its consumer fragments the inner
  packet by default, or sends at most one in-tunnel RFC 1191 error when the
  session opted in; tc reads only the MTU bits and steers identically under
  both policies. Every other authorized inner IPv4 fragment of a session with
  a downlink inner MTU (More Fragments set, or a non-zero fragment offset) is
  handed off the same way, to the backend-owned inner-fragment queue
  (`GTPU_INNER_FRAGMENT_QUEUE_PORT`, 2154). Its consumer validates the inner
  header, as the kernel's IPv4 input would after a decapsulation, and returns
  the fragment unmodified with its bearer mark, so that every fragment of one
  datagram
  leaves through the application and none through the host's forwarding
  path, where netfilter connection tracking could strand it. The decision is
  `opc-gtpu-ebpf-common`'s `downlink_ipv4_hand_off_port`, taken only after the
  complete authorization and before decapsulation. A session without a
  downlink inner MTU hands nothing off. A hand-off flood therefore never
  fills the shared UDP/2152 queue, and a flood of one hand-off class never
  fills the other's queue. tc does not police hand-offs: a policing map would
  change the retained pin inventory and durable recovery records. A true
  grouped-index miss alone may enter the legacy IPv4 PDR/commit path.
- A hand-off needs a bound consumer. tc passes a datagram on to a UDP socket
  of this host only while one is bound for it: a steered packet on its
  hand-off port; a G-PDU for no tunnel, or with a required unknown extension,
  on UDP/2152 of one of the attachment's endpoints; and an outer-fragmented
  UDP/2152 datagram for an IPv4 endpoint, judged by its first fragment.
  Otherwise the datagram is counted in `COUNTER_DL_MISSING_CONSUMER` and
  never delivered, because the kernel would answer with ICMP Port Unreachable
  toward the peer, quoting the start of the subscriber's inner packet. The
  backend binds its queues when the control port is first opened, and they
  close with the process, while tc keeps running from the pinned graph. tc
  finds the socket with `bpf_sk_lookup_udp` and, except for a fragment,
  assigns it to the datagram with `bpf_sk_assign`, so that a socket closing
  after the check is not answered either. Neither helper is GPL-only; the
  assignment needs Linux 5.7. A socket counts only when UDP input will
  accept it for a datagram that arrives on the attachment's device, which
  can be enslaved to a VRF: a socket bound to that device, or a socket bound
  to no device that the lookup finds under the device's VRF scope. Before
  Linux 6.5 the lookup does not know that scope, so tc decides in two steps:
  a lookup without a VRF scope, which establishes a socket bound to the
  device, and otherwise a lookup with the scope engaged, which establishes
  a socket bound to no device. What neither establishes is not assigned: tc
  passes the datagram on as a link-layer multicast frame
  (`bpf_skb_change_type`), so that the stack's own lookup chooses the socket
  and the host sends no ICMP error if there is none.
  All of this assumes that IP input receives on the device of the hook. A
  receive handler runs after tc, can take the frame to another device and
  can reset its type, and the program cannot see one. The loader refuses an
  interface that has a master other than a VRF (a bridge, a bond, a team, a
  virtual switch), one below a device of its namespace that can take its
  frames (a macvlan, an ipvlan, a MACsec device), and every interface of a
  namespace that holds an HSR or PRP device; it cannot see such a device in
  another namespace. A frame that carries a VLAN tag with a VLAN ID is
  received by the VLAN device above the hook's device, or by nothing. Where
  the downlink program decides a hand-off, it reads the tag from the context
  (`vlan_present`, `vlan_tci`): a hand-off in such a frame has no consumer,
  whatever is bound, and is dropped and counted without a lookup. A priority
  tag (VLAN ID 0) leaves the frame on the device.
  tc drops an unfragmented datagram without a consumer itself. It
  lets the first fragment of a fragmented one pass with a UDP Length that no
  datagram can have (`UDP_LENGTH_OF_NO_DATAGRAM`): the host then reassembles
  the datagram and UDP input discards it unanswered, where a dropped first
  fragment would strand the other fragments in the reassembly queue.
  The control-port guide in `opc-gtpu-dataplane` states the limits: the
  reassembly window, unfragmented non-G-PDU messages, outer IPv6 fragments,
  a socket bound to a VRF device, and what differs on older kernels.
  Outer-IPv4 fragments, legacy or grouped, retain the bounded
  kernel-reassembly handoff; the backend-owned consumer
  (`GtpuControlPort::try_receive_downlink`) authorizes the reassembled G-PDU
  against the same grouped and legacy state. Grouped outer-IPv6 packets
  requiring reassembly pass to the host, and the backend reports that
  capability as unsupported because no IPv6 consumer exists. A bounded IPv6 extension walk
  accepts canonical Hop-by-Hop, Destination Options,
  Routing-with-zero-Segments-Left, and atomic Fragment headers. AH, ESP, active
  routing, discard-required options, non-atomic fragments, or chains outside
  the bounded contract are left to the host before any grouped session is
  authorized. IPv6 UDP checksums are mandatory.

Map names, counter indexes, program names, and byte layouts are imported from
`opc-gtpu-ebpf-common`. `GTPU_COUNTERS` is a sixteen-slot per-CPU map
(`COUNTER_SLOTS`), of which eight carry a counter (`COUNTER_SLOTS_IN_USE`).
The seventh is `COUNTER_UL_REDIRECT_RESOLVED`, described under Status And
Limits, and the eighth is `COUNTER_DL_MISSING_CONSUMER`. The other eight are
reserved and read zero, so that the next counter does not change the width
of the pinned map: a pin graph retained from a build with another width is
refused and needs a drained reprovision.
`GTPU_DL_DROP` is a fixed six-slot per-CPU counter map for invalid, family,
peer, local, ingress, and source-port binding failures. Its values are
aggregate and contain no rejected endpoint or session fields.

`GTPU_TFT_FRAG` is the pinned BTF ARRAY for inner IPv4 fragment affinity. A
bounded hash selects its four-slot bucket by a `u32` array index. Each slot
retains the exact interface, PAA, source, destination, protocol, and IPv4 ID,
plus the selected mark, classifier owner, owner generation, snapshot generation,
fingerprint, and bounded fragment ranges. The program forwards original
fragments without buffering payloads or reassembling them. A stale retained key
drops after classifier removal or replacement even when the classifier had a
default bearer. Without either a classifier or a live key, ordinary forwarding
behavior remains.

## Relationships

- `opc-gtpu-ebpf-common`: shared no-std layout and classification crate.
- `opc-gtpu-dataplane`: userspace loader and safe backend that pins maps,
  attaches/detaches tc programs, and embeds the built object.
- `crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o`: committed artifact
  produced from this crate.

## Status And Limits

- Unpublished standalone crate (`publish = false`) with its own `Cargo.lock`.
- Build profile uses `panic = "abort"` and optimized BPF codegen.
- Fragment affinity has 16,384 four-way buckets (65,536 slots), at most 64
  ranges per datagram, and a fixed two-second boot-time expiry. A full bucket
  refuses admission even if others have room. No live slot is evicted or
  refreshed, including completed or poisoned slots. A matching duplicate
  first fragment is accepted without a state refresh; a conflicting first
  fragment, overlap, inconsistent final range, or range-limit exhaustion
  poisons the entry until its original deadline. Under an owned classifier,
  orphan, expired, stale, ambiguous, and capacity-refused fragments drop
  through existing aggregate TFT counters. Expired IPv4 IDs may be admitted by
  a new classifiable first fragment.
- One spin lock per bucket protects all CPUs' in-place mutations. Packet
  reads, other map lookups, classification, clock reads, counter updates, and
  forwarding authority lookups occur outside the lock. The protected
  transition examines at most four slots and 64 ranges, with no helper calls,
  allocations, or whole-entry copies. First fragments also use the existing
  classifier bound of 256 filters; later fragments never parse transport fields.
- Each affinity slot is 392 bytes. Four slots plus the lock make a 1,572-byte
  BTF value; the kernel's 1,576-byte stride allocates 24.625 MiB of value storage
  per attachment before map metadata. Capacity is per concurrent datagram and
  shared by the attachment; bucket collisions can refuse admission before
  the global slot limit is reached. There is no userspace packet-expiry scan
  or live map-value replacement.
- The complete graph now has 35 maps and TFT schema v5. Former 34-map graphs
  missing `GTPU_TFT_FRAG`, old TFT markers, and partial TFT graphs are refused
  before attachment mutation. Current recovery uses `OPCCURR8` proofs and
  terminal WAL r3. Creation, adoption, cleanup, and rollback belong to the
  loader; upgrade or downgrade requires a drain, exact cleanup with the
  generation's compatible version, and fresh attachment. Incompatible retained
  proofs, WALs, or finalized receipts continue to fence the namespace after
  graph cleanup. No record conversion is implemented: preserve them and use a
  separate, freshly authorized namespace. See the
  [upgrade and rollback contract](../opc-gtpu-dataplane/README.md#tft-fragment-affinity-upgrade-and-rollback).
  Frozen shipped-25 recovery recognition remains separate and unchanged.
- The grouped datapath supports all four independent outer/inner IPv4/IPv6
  combinations and simultaneous IPv4v6 session groups. The frozen v5 maps
  remain an IPv4-only compatibility fallback and are never consulted after a
  grouped selector has been observed.
- Missing, corrupt, transitional, or mismatched grouped authority, index,
  attachment configuration, legacy commit record, or endpoint binding fails
  closed before inner packet delivery.
- IPv6 extension and checksum processing use bounded `bpf_loop` callbacks.
  The committed classifiers are verifier-loaded on exact Linux 6.8 in CI so
  their complete call chains remain below that kernel's cumulative 512-byte
  BPF stack limit without reducing checksum coverage. The RHEL 9.4 `5.14.0-427`
  line that Red Hat CoreOS ships for OpenShift 4.18 is gated the same way and
  additionally runs the full privileged datapath suite, because the limit is
  cumulative over the callback chain and an enterprise backport can account for
  it differently: exposing `bpf_loop` does not by itself imply this object
  loads, and loading does not by itself imply it forwards. Both gates require
  the datapath suite to run every test the committed source declares, and to
  prove it ran rather than reporting itself skipped, so a test that cannot run
  on el9 fails the gate rather than shrinking it. Kernels outside the gated
  lines are unqualified rather than unsupported, and `opc-gtpu-dataplane`'s
  `probe_committed_classifier_load` establishes the answer on the node.
- Grouped entry validation keeps each address check in a separate BPF call.
  Combining the N3 endpoint checks with the remaining entry checks causes LLVM
  register spills that exceed the cumulative stack limit on Linux 6.8 and
  RHEL 9. The wire checks and accepted address sets are unchanged by this split;
  both kernel jobs must load the committed object and execute forwarding tests.
- Outer IPv6 is `MaterializedOnly`: GSO and pending
  `CHECKSUM_PARTIAL` state are rejected before encapsulation. Outer IPv6
  fragment reassembly is not claimed; only atomic Fragment headers are handled
  by the fast path. Grouped outer-IPv4 fragment reassembly is also unsupported;
  the qualified IPv4 reassembly consumer remains specific to the legacy maps.
- The S2b-U boundary owns the complete 32-bit packet mark; masked sharing is
  unsupported. The userspace crate remains safe Rust. Aya exposes a safe mark
  setter but no getter, so the verifier-bound program uses one isolated,
  aligned raw read of `__sk_buff::mark` in addition to its existing raw
  map/helper accesses.
- `COUNTER_UL_ENCAP` counts encapsulations handed to `bpf_redirect_neigh`, not
  packets delivered. The helper validates only its own arguments -- it returns
  `TC_ACT_SHOT` solely for `(plen && plen < sizeof(*params)) || flags` -- then
  records the target ifindex and returns `TC_ACT_REDIRECT`. Both call sites
  pass `plen == 0` and `flags == 0`, which is exactly the shape that condition
  can never hold for, so the helper returns `TC_ACT_REDIRECT` unconditionally
  and a counter keyed on its *return value* would read zero forever. Both
  uplink completion sites still fail closed on a non-redirect verdict; that
  `else` arm is unreachable at the current argument shape and exists only as
  defensive symmetry, so a future call with a nonzero `plen`/`flags` cannot
  emit an encapsulated frame still carrying the inner route's L2 destination.
- The redirect *outcome* is nevertheless observable in-program, and
  `COUNTER_UL_REDIRECT_RESOLVED` reports it. Route lookup and neighbour
  resolution happen later in `skb_do_redirect()`, but a redirect that succeeds
  comes back through this same tc egress hook -- `skb_do_redirect()` ->
  `__bpf_redirect_neigh_v4()` -> `bpf_out_neigh_v4()` -> `neigh_output()` ->
  `dev_queue_xmit()` -> `sch_handle_egress()` -- while one that finds no route,
  or a route type that is neither `RTN_UNICAST` nor `RTN_LOCAL`, is
  `kfree_skb`'d before it gets there, as is one whose link-layer destination is
  a multicast address, which `__bpf_redirect_neigh()` rejects before the route
  lookup. An unresolvable neighbour is *not* in that list; it is the lag case
  below. The uplink program recognizes its own re-emitted outer frame on that
  second traversal and counts it. Closing issue 564 therefore needs no
  `bpf_fib_lookup` and no GPL-only helper: the discriminator uses only
  `bpf_map_lookup_elem` and `bpf_skb_load_bytes`, both already called here and
  both `gpl_only = false`, and the signal is unaffected by the IPv4 forwarding
  sysctl that would have made a `bpf_fib_lookup` status ambiguous.
- The discriminator is what the frame *is*, never a stamp the program writes:
  `skb->mark` carries the bearer identity and is left alone. A frame is
  recognized as re-entry only with mark zero, an outer IPv4 or IPv6 UDP/2152
  GTPv1 G-PDU envelope of exactly the shape this program stamps, and an outer
  source that is one of the attachment's own local S2b-U endpoints
  (`GTPU_CONFIG` for the frozen v5 schema, `GTPU_CONFIG6` for grouped
  attachments, the latter bound to the observed ifindex). No provisioned
  subscriber can present that source: both schemas reject a UE PAA that aliases
  the local outer endpoint, so no FAR or grouped selector could have matched it
  either. The GTP-U message-type check keeps locally originated echo and error
  indication traffic out of the counter.
- Three caveats belong to the counter and are documented on the public field.
  It proves the frame cleared FIB and neighbour resolution and reached
  `dev_queue_xmit`; it does not prove the peer received it, so a later qdisc,
  driver, or on-wire loss is still unobservable here. An unresolved neighbour
  lags rather than reads wrong: the skb waits in the neighbour's `arp_queue`
  and is counted late if resolution eventually succeeds, never if it does not.
  And the counter is unauthenticated: because the discriminator is the frame
  itself, any locally originated packet sourced from this attachment's own
  S2b-U endpoint to UDP/2152 with a GTPv1 G-PDU header increments it too, and
  an unprivileged co-located process can send one. Only the counter is
  affected -- no forwarding decision reads it -- and tightening cannot close
  it, because every discriminator available in-program is in-band and so
  forgeable by a local sender. Stamping `skb->mark` to make the frame
  self-identifying is refused on separate grounds: that field carries bearer
  identity and this boundary owns all 32 bits of it.
- It does not load itself, manage bpffs pins, manage sessions, or implement
  product policy; those live in the userspace backend.

## Build

Do not build this crate with normal workspace commands. Use the pinned helper:

```sh
./scripts/build-gtpu-ebpf.sh
```

Prerequisites:

```sh
rustup toolchain install nightly-2026-06-22 --profile minimal --component rust-src
cargo install bpf-linker --version 0.10.3 --locked
```

The helper also requires a GNU-compatible `readelf` (from binutils). It checks
that both the built and copied object contain exactly the kernel-readable
`Dual MIT/GPL\0` declaration also used by `opc-egress-fence-ebpf` and
`opc-ipsec-xfrm-ebpf`.
CI checks the committed object's declaration before rebuilding, so a missing
license section cannot silently fall back to the loader's default.

## Roadmap

- Keep the committed object reproducible from source and checked in CI.
- Extend map schemas only through `opc-gtpu-ebpf-common` so loader and program
  stay byte-for-byte compatible.
- Add protocol support only with matching unit tests and privileged datapath
  coverage.

## Verification

```sh
./scripts/build-gtpu-ebpf.sh
cargo test -p opc-gtpu-ebpf-common
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_GTPU_RUN_PRIVILEGED=1 cargo test -p opc-gtpu-dataplane --test ebpf_gtpu_privileged -- --ignored --nocapture'
```
