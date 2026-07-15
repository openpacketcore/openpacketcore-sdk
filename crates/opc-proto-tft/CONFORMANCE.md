# Traffic Flow Template codec conformance

This document defines the conformance boundary and evidence for
`opc-proto-tft`. The claim is a complete, strict codec for the shared TFT value;
it is not a claim that either GTPv2-C or IKEv2 bearer procedures are complete.

## Specification baseline

| Specification | Version | Claimed scope |
|:--|:--|:--|
| 3GPP TS 24.008 | V18.8.0, Release 18 | Clause 10.5.6.12, figures 10.5.144 through 10.5.144c and table 10.5.162 |
| 3GPP TS 23.060 | V18.0.0, Release 18 | Clause 15.3.2 and table 12 packet-filter attribute combinations |
| 3GPP TS 24.302 | V17.9.0, Release 17 | Clause 8.2.9.11 transport embedding boundary only |
| 3GPP TS 29.274 | V18.8.0, Release 18 | Clause 8.19 transport embedding boundary only |

The encoded boundary begins at the TFT operation octet (TS 24.008 octet 3)
and ends after the optional parameter list. The type-4 IEI and outer length are
not part of this crate. TS 24.302's one-octet TFT Value length is likewise an
IKEv2 Notify wrapper field, not part of `TrafficFlowTemplate`.

## Supported model and wire format

- Operations: Ignore, Create new, Delete existing, Add filters, Replace
  filters, Delete filters, and No TFT operation.
- Independent E-bit parameter-list handling, including a parameter list on
  Delete existing while its packet-filter count/list remain zero.
- Identifier-only delete lists and full filters with direction, evaluation
  precedence, content length, and preserved component ordering.
- All twenty Release 18 component identifiers and their normative fixed
  lengths: IPv4 remote/local address and mask; IPv6 remote address and mask;
  IPv6 remote/local address and prefix; protocol/next-header; local/remote
  single ports and ranges; IPsec SPI; ToS/traffic class and mask; flow label;
  destination/source MAC; C-TAG/S-TAG VID and PCP/DEI; and EtherType.
- Authorization Token, Flow Identifier, and Packet Filter Identifier
  parameters. Unsupported parameter identifiers are preserved in order.
- Deterministic encode preserving valid filter, component, parameter, and
  unknown-parameter ordering.

## Validation contract

The codec rejects before returning a model when any of these standalone
invariants fail:

- the value is outside 1 through 255 octets or exceeds caller limits;
- operation, E-bit, filter count, filter-list form, or trailing-data framing is
  inconsistent;
- a declared filter, component value, or parameter is truncated;
- a reserved operation/component or non-zero spare bit appears;
- a full filter is empty, exceeds one-octet length, repeats a component, or
  violates TS 24.008/TS 23.060 component-exclusion rules;
- an address prefix, port range, flow label, VLAN ID, or VLAN priority is out
  of range;
- identifiers or evaluation precedence values repeat within one operation;
- a standardized parameter has the wrong size, a filter-identifier parameter
  is empty/invalid, or an Authorization Token is not followed by at least one
  Flow Identifier; or
- checked offset/length arithmetic or the caller's element budget fails.

The decoder bounds source length at 255 octets and every allocation is bounded
by that source. It has no recursion and uses checked arithmetic. The crate
forbids unsafe code and production panic/unwrap/expect paths.

`TftErrorKind` is a stable structured classification and `TftError::offset`
identifies the value-relative wire position where available. Diagnostics retain
no packet bytes or classifier values. Custom `Debug` implementations redact
addresses, ports, SPIs, MACs, authorization tokens, unknown parameter contents,
and ignored contents.

## Extensibility behavior

TS 24.008 reserves every unrecognized packet-filter component identifier, so
the decoder rejects it. The specification permits unsupported parameter
identifiers to be discarded; this codec instead preserves their identifier,
contents, and ordering so a transport can forward an accepted value without
destroying an extension. All standardized fields remain typed and inspectable.

For `Ignore this IE` with E=0 and count=0, the receiving side is explicitly
instructed not to interpret the remaining contents. Those bytes are the only
operation body exposed as uninterpreted data.

## Procedure boundary

The following rules require installed bearer/TFT state or transport procedure
context and are intentionally not guessed by this value codec:

- whether Create, Add, Replace, Delete-filter, or Delete-existing is legal for
  the currently installed TFT;
- collisions with identifiers or precedence values in previously installed
  filters or other bearer TFTs;
- whether the resulting TFT has an uplink-applicable filter;
- mapping a codec failure to a GTP Cause or IKEv2 Notify; and
- allocation, policy, transaction replay, Child-SA, or dataplane behavior.

GTPv2-C and IKEv2 typed procedure views must enforce those rules at their own
boundaries while reusing this exact model and codec.

## Evidence

- `tests/tft_codec.rs` contains independently hand-authored octet fixtures for
  every operation, every Release 18 component, all parameter kinds, valid
  TS 23.060 combination types, legal E-bit forms, and byte-exact round trips.
- The same suite covers malformed headers/lists, every proper structural
  truncation, reserved/spare values, fixed-length failures, duplicate and
  conflicting fields, parameter errors, size/count bounds, framework limit
  mapping, redaction, and destination atomicity.
- `tests/properties.rs` runs 10,000 generated valid-model round trips, 10,000
  unknown-parameter preservation cases, and 50,000 bounded arbitrary-input
  panic-safety cases on stable Rust.
- `tests/corpus_replay.rs` replays committed fuzz seeds, their truncations, and
  hostile inputs through decode and accepted-value re-encode in ordinary CI.
- `fuzz/fuzz_targets/decode_tft.rs` and `roundtrip_tft.rs` exercise strict
  decode and canonical stability under libFuzzer. They are registered in the
  repository PR-smoke and weekly fuzz matrix. Registration and smoke execution
  are evidence; no unperformed deep-fuzz duration is claimed here.

Fixture provenance details live in `tests/fixtures/README.md`.

## Known missing items within this codec scope

None. Future 3GPP releases that add a component or parameter require an
explicit baseline update, typed representation, fixtures, and compatibility
review. Procedure and product work listed above is outside this crate's scope,
not deferred codec work.
