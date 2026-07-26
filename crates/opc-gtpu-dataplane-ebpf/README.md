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
- `opc_gtpu_downlink`: tc ingress program. It matches UDP/2152 GTPv1-U G-PDUs,
  proves the complete outer IPv4 or IPv6 envelope and checksum boundary,
  derives the independent inner family, and resolves `(outer family, inner
  family, local TEID)` through the retained grouped index and one authority
  lookup. Only an exact `Active` generation/slot, attachment configuration,
  outer peer/local endpoint, UDP source-port policy, and inner destination may
  decapsulate. The program strips the proven outer envelope, writes the
  dedicated-bearer mark (or zero), and continues through the ePDG's XFRM
  output policy. A true grouped-index miss alone may enter the legacy IPv4
  PDR/commit path. Legacy outer-IPv4 fragments retain the bounded
  kernel-reassembly handoff. Grouped outer-IPv4 and outer-IPv6 packets
  requiring reassembly pass to the host, but the backend reports both
  per-family grouped fragment capabilities as unsupported because the current
  consumer cannot authorize the grouped graph. A bounded IPv6 extension walk
  accepts canonical Hop-by-Hop, Destination Options,
  Routing-with-zero-Segments-Left, and atomic Fragment headers. AH, ESP, active
  routing, discard-required options, non-atomic fragments, or chains outside
  the bounded contract are left to the host before any grouped session is
  authorized. IPv6 UDP checksums are mandatory.

Map names, counter indexes, program names, and byte layouts are imported from
`opc-gtpu-ebpf-common`. `GTPU_COUNTERS` is a seven-slot per-CPU map; the
seventh slot is `COUNTER_UL_REDIRECT_RESOLVED`, described under Status And
Limits.
`GTPU_DL_DROP` is a fixed six-slot per-CPU counter map for invalid, family,
peer, local, ingress, and source-port binding failures. Its values are
aggregate and contain no rejected endpoint or session fields.

## Relationships

- `opc-gtpu-ebpf-common`: shared no-std layout and classification crate.
- `opc-gtpu-dataplane`: userspace loader and safe backend that pins maps,
  attaches/detaches tc programs, and embeds the built object.
- `crates/opc-gtpu-dataplane/bpf/opc-gtpu-datapath.bpf.o`: committed artifact
  produced from this crate.

## Status And Limits

- Unpublished standalone crate (`publish = false`) with its own `Cargo.lock`.
- Build profile uses `panic = "abort"` and optimized BPF codegen.
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
