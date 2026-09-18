# Experimental N3 packet/intent support

This document covers the additive `n3` module only. Existing GTP dataplane
qualification remains documented in [README.md](README.md). This slice is
held (`publish = false`) and does not complete [#790](https://github.com/openpacketcore/openpacketcore-sdk/issues/790).

## Support boundary

| Surface | Supported | Explicit limit |
| --- | --- | --- |
| Directional intent | Received uplink UPF TNL, locally supplied downlink N3IWF TNL, N3IWF role and caller-selected QFI/complete-mark association | No authentication, address ownership, selector allocation, route selection, SA mapping, match priority or default-flow decision |
| Constructed send | Canonical uplink G-PDU, nonzero TEID, one first PSC, QFI 0–63, opaque nonempty inner payload | Software buffer construction only; no downlink constructor, packet transmission, UDP/IP header, checksum or offload claim |
| Receive | Complete G-PDU; one PSC; uplink QFI or downlink QFI/RQI/optional PPI; caller-supplied expected direction | Shared PSC conditional-field subset; no monitoring timestamps, delay results, sequence-field extensions or MBS support |
| Receive framing | Exact datagram length, bounded extension walk, duplicate PSC refusal, endpoint comprehension bits | Optional unknowns can appear before/after the PSC and remain in the borrowed original datagram; no raw re-encoder |
| Linux, eBPF, mock, unsupported adapter | Exact coarse N3 capability result is `GtpuCapability::Missing` for each shipped adapter | No N3 install, runtime classifier/marking, generation readback, stale-writer fencing or removal/End Marker ordering is qualified |

The two TNL types are not convertible. `N3ForwardingIntent` is desired data,
not a receipt or mutation authority. Mark `None` explicitly requests zero;
`Some(GtpBearerMark)` uses the existing complete 32-bit mark convention.
The intent chooses no protection policy, and its address families need not
match. Concrete-unicast constructor checks are an SDK input rule, not proof
of binding, reachability or an authorized peer.

The receive helper requires a nonempty inner payload as an SDK
forwarding-input contract. A PSC-only GTP-U message remains valid at the
generic codec/fixture boundary. It does not validate the opaque payload as
IP, Ethernet, NAS, or a subscriber packet. PPI metadata alone does not prove
the PDU session is of IP type or authorize its use for paging.

## Wire sources and policy separation

- [TS 29.281 V18.4.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf), sections 5.1, 5.2.1 and 5.2.2.7: GTP-U/extension framing and PSC carriage. The reserved header bit is ignored on receive. PSC-first is a sender recommendation; reception does not reject a PSC merely because an optional extension precedes it.
- [TS 38.415 V18.2.0](https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/18.02.00_60/ts_138415v180200p.pdf), sections 5.5.2 and 5.5.3.1–7: direction, QFI, downlink RQI, PPP/PPI, spare fields and alignment. PPI applies to IP-type PDU sessions.

`DecodeContext.max_message_len`, `max_ies` and `max_depth` remain active in
the shared framing decoder. Every validation level enforces this endpoint
profile; caller duplicate/unknown policies cannot admit duplicate PSC or
unsupported required extensions. Generic Strict reserved-bit rejection is
avoided by using structural framing plus explicit endpoint semantics. The
on-wire version is checked; an absent-version hint cannot override it.
Receive allocates zero memory; `allocation_budget` is advisory.

Constructed uplink output always emits version 1/PT, clears reserved and
sequence/N-PDU fields, and inserts one uplink PSC before the payload. The
cap counts only the new G-PDU, excluding an existing destination prefix.
The caller cap, GTP-U 16-bit length field and destination-length overflow
are checked before writes. UDP/IP size and path-MTU limits are additional
transport obligations outside this helper. Allocation failure follows the
allocator/`BytesMut` behaviour, not a recoverable protocol error.

No new runtime counters, logs or reports are emitted. All value-bearing N3
types redact their complete `Debug` representation, and errors contain only
static reasons. Explicit getters are for packet processing, not logging.

## Dependency and fixture provenance

The public SDK base is `89b307767cd3cb497b6cc6eb0a9c70f6b71fe578`.
The reviewed [#830](https://github.com/openpacketcore/openpacketcore-sdk/pull/830)
fixture head is `b1570ed8dc03ca9aaa23bd0b281f8d3d13341a8d`, merged through
`987246c8be773b19304f059231c39baa8d54d123`. The `n3-gtpu` subset remains
unchanged at tree `1309416492cd398ea932c515a3ea58e0444789ee`; its completion
file SHA-256 is `010395aea965f6cbeb7b06272c46859e4101f5afe7c8b58cf67190a5bfaba37f`.
The PR records the final public implementation head and tree.

All 11 published cases are synthetic fixture contracts. In particular,
their positive PSC examples have no inner payload and assert generic
`gtpu-message` validation, with `runtime_claim: false`. Their admission is
not an installed forwarding result. This slice adds separate synthetic
packets with an opaque inner payload and changes no published fixture wire.

The merged shared codecs already provide PSC construction/parsing and typed
controls. [#341](https://github.com/openpacketcore/openpacketcore-sdk/issues/341)
still owns the backend-neutral control-datagram port; this module adds none.
Exact selector operations already use opaque requests/receipts. Remaining
per-selector provenance/coordinator work belongs to
[#663](https://github.com/openpacketcore/openpacketcore-sdk/issues/663), and
external adapter operation-stamp contracts to
[#671](https://github.com/openpacketcore/openpacketcore-sdk/issues/671).
No caller-created generation receipt substitutes for those authorities.
The checksum-offload control pass-through fixed in
[#644](https://github.com/openpacketcore/openpacketcore-sdk/issues/644) is
unchanged. Echo port rules, zero transmitted Recovery, ignored received
Recovery authority, and End Marker lifecycle ordering still require those
existing control/runtime interfaces; they are not claims of this slice.

## Evidence and reproducibility

`tests/n3_reference.py` is a standalone, spec-authored byte generator with
no SDK codec or fixture-catalog imports. Its checked-in TSV has **2,604
cases: 1,511 accepted and 1,093 rejected**, SHA-256
`31da0a1658218432817bc181be4233fadd4fd1f36c36f3d29f087bc131b8424a`.
It covers all 64 QFIs, all downlink RQI/absent-or-present PPI combinations,
all first-header octets, all other message types, declared-length variants,
every nonzero non-PSC extension type before/after PSC, spare/padding fields,
wrong direction, duplicate PSC, prefixes, tails and unsupported conditionals.

`tests/n3_contract.rs` verifies those authored bytes, all 256 QFI constructor
inputs, all context policy combinations, exact cap/length limits, output
atomicity, redaction, zero allocation and the four shipped unsupported
capability results. `fuzz/n3_packet` exercises bounded complete-packet
reception and uplink insertion, with a 4,096-byte input cap and 64-extension
bounds. The fuzz workflow runs it in PR smoke and scheduled lanes.

```sh
python3 crates/opc-gtpu-dataplane/tests/n3_reference.py --check
cargo test --locked -p opc-gtpu-dataplane --test n3_contract
cargo test --locked -p opc-gtpu-dataplane --doc
# From crates/opc-gtpu-dataplane:
cargo +nightly-2026-07-23 fuzz run n3_packet -- -max_total_time=60 -max_len=4096
```

The PR retains the initial missing-API compiler detector, production-guard
removal failures and a separately corrupted golden vector with recomputed
digest. Compiler/API absence is not reported as a runtime failure. Local
and hosted gate results are reported for their exact revision. Synthetic
byte tests and round trips do not establish captured-traffic compatibility,
independent live-peer interoperability, production N3 forwarding or full
standards conformance.
