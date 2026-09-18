# NWu GRE conformance boundary

This is the experimental fixed NWu profile for SDK #789 / tracking #795.
It is not a general GRE implementation or a complete N3IWF dataplane.
The [ADR 0015 NWu clarification](../../docs/adr/0015-protocol-codec-conformance-policy.md)
records why canonical-only transmission and explicitly directional decoding
are required here; no direction is guessed by framework trait adapters.

| Obligation | Source and implemented behavior |
| --- | --- |
| Complete packet | TS 24.502 V18.8.0 §9.3.3 figure/table 9.3.3-1: header octets 1–8, then one opaque user packet. Empty payload rejected; inner packet validity belongs to the caller. |
| Transmit flags | §9.3.3 table 9.3.3-2: C=0, K=1, S=0. RFC 2784 §2.3/§2.3.1: other transmitted flags and version zero. |
| Receive flags | RFC 2784 §2.3 with RFC 2890 Key extension: RFC bits 1–5 unsupported except K; NWu excludes C/S. Bits 6–12 ignored, version zero required. |
| Protocol Type | TS table 9.3.3-2 NOTE explicitly overrides generic RFC 2784 §2.4 receive disposition: all values accepted and ignored. Canonical send zero. |
| QFI / RQI | TS §8.3.2, figure/table 9.3.3-3: six-bit QFI in octet 5; RQI in octet 8 bit 7, downlink only. Checked QFI construction and explicit out-of-band direction. |
| Key spare fields | Figure 9.3.3-3 codes transmit spares zero. This SDK accepts/drops nonzero received Key spare bits. This receive choice is not attributed to the EAP-5G spare rule in §9.3.2.1. |
| Default association | §8.3.1 describes QFI associations and a default in the same PDU session. The SDK models exact matches before caller-declared fallback candidates; it does not create SAs or choose among candidates. |

Primary sources:

- [TS 24.502 V18.8.0](https://www.etsi.org/deliver/etsi_ts/124500_124599/124502/18.08.00_60/ts_124502v180800p.pdf), PDF SHA-256 `25c75b0ba4253275fd03c200c37bbacd80ab5344d979acb28fe6ad7e7c56f67b`.
- [RFC 2784](https://www.rfc-editor.org/rfc/rfc2784.html), §2.3–2.4.
- [RFC 2890](https://www.rfc-editor.org/rfc/rfc2890.html), §2.

Caller-selected message/count limits, mapping input order, Key spare receive
acceptance, and the requirement for an authenticated session/direction context
are explicitly SDK boundaries. No allocation, subscriber policy, QoS
preference, liveness, default-SA authorization, or convergence is inferred.

## Evidence and supported outcomes

The reviewed `gre-qfi` fixture prerequisite was merged in PR #830 (reviewed
head `b1570ed8dc03ca9aaa23bd0b281f8d3d13341a8d`, merge
`987246c8be773b19304f059231c39baa8d54d123`). All eight published wire files
remain byte-identical. This change clarifies misleading payload/QFI prose and
fixes the separate Python oracle's legacy-flag and uplink-RQI validation.
`opc-n3iwf-fixtures/tests/gre_packets.rs` executes those eight reviewed cases
through the new runtime boundary, including the constructor-only QFI 64 case.
The original fixture gate's `gre-header` scope remains a header oracle;
the runtime and new reference require a nonempty user packet.

`tests/reference.py` independently assembles synthetic fields from TS octet
positions and RFC bit numbering. It imports no production codec or catalog
oracle. Its 1,203 checked-in rows comprise 1,113 accepted packets and 90
rejections; the companion SHA-256 is
`621322fab77062056bfab676bf23ba75b21fa17ba8078a86946cdd4b9fa16b26`.
There are 192 distinct constructed directional QFI/RQI combinations, tested
against five received Protocol Types, all combinations of the seven ignored
RFC bits, each Key spare bit, all forbidden flag/version bits, missing Key,
every short prefix, empty payload, and all 64 illegal uplink-RQI cases.
These additional runtime vectors do not enlarge the published #784 catalog.

The Rust tests also exhaust all 65,536 flag words in both directions, all
65,536 received Protocol Types, all 256 one-octet QFI inputs, all QFI set bits,
and an independent 256-scenario mapping matrix. They check exact size limits,
unchanged destinations on encoding failures, owned conversion, every
validation level, redacted diagnostics, and zero-allocation borrowed
decode/mapping. The `nwu` fuzz target bounds work to 4,096 input octets and
64 mapping entries, checks arbitrary directional admission, canonical output,
limits, mapping results against input tuples, and value-free diagnostics.
Both PR smoke and scheduled fuzz matrices include this crate.

Unsupported: checksums, sequence/routing extensions, other GRE versions,
directionless decode, raw-preserving output, parsing the inner user packet,
session isolation or authentication, SA allocation/selection, QoS policy,
XFRM installation, and runtime supervision. No external peer capture or live
interop is claimed; round trips and synthetic reference agreement alone do
not prove interoperability. Exact public base/head/tree and local/hosted
qualification evidence belong to the PR record. This remains a reviewable
experimental implementation until all required gates and independent review.
