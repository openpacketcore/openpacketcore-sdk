# ADR 0015: Protocol Codec Conformance Policy

## Status

Accepted

## Date

2026-06-11

## Context

The SDK ships wire codecs for 3GPP protocols (GTP-U, PFCP, NAS-5GS, with
NGAP planned). Codec bugs are uniquely dangerous: an encoder and decoder
written by the same hand are *internally consistent*, so round-trip tests
pass perfectly while every byte on the wire is wrong for a real peer. This
failure mode occurred twice during development — a scrambled PFCP header
flag layout and a byte-swapped Outer Header Creation description field —
and in both cases the existing test suite was green because the fixtures
had been derived from the codec's own output.

## Decision

Every protocol codec crate (`opc-proto-*`) MUST satisfy all of the
following before it is merged, and CONFORMANCE.md must claim nothing the
tests do not prove:

1. **Spec-authored fixtures.** Conformance tests include byte fixtures
   hand-authored from the 3GPP specification (or captured from an
   independent implementation), with octet-level comments citing the spec
   section. Fixtures derived from this codec's own encoder do not count as
   conformance evidence — they detect regressions, not wire-format errors.
2. **Byte-exact round-trips.** `decode → encode` must reproduce the input
   bytes exactly for every fixture, including unknown/vendor-extension
   elements, which must be preserved raw.
3. **Declared canonicalization.** Where a typed view legitimately
   normalizes (zeroing spare bits, dropping forward-compatibility trailing
   octets that the spec requires receivers to ignore), CONFORMANCE.md must
   say so explicitly, and a raw byte-preserving layer must remain available
   for forwarding paths.
4. **Hostile-input safety.** No panics on any input: checked arithmetic on
   all length/offset math, enforced decode limits (message length, element
   count, recursion depth), and negative tests for truncation, overflow,
   and depth bombs.
5. **Fuzzing.** A fuzz target over the decode surface with a seed corpus of
   spec-valid messages, registered in the fuzz CI workflow. The fuzz crate
   must compile in CI even when fuzzing is not executed.
6. **Framework fit.** Codecs implement the `opc-protocol` traits
   (`BorrowDecode`/`OwnedDecode`/`Encode`) and carry `@spec`/`@req`
   traceability tags so RFC 006 evidence tooling can index them.
7. **CONFORMANCE.md** enumerates exactly which messages, elements, and
   fields are covered, at which 3GPP release, and what is out of scope.

## Consequences

- Writing a codec costs more up front: authoring fixtures from the spec is
  slower than round-tripping the encoder. That cost is the point — it is
  the only test construction that catches self-consistent wire errors.
- Reviews of codec changes start from the fixtures: a reviewer verifies
  bytes against the cited spec section before reading the implementation.
- `opc-proto-gtpu`, `opc-proto-pfcp`, and `opc-proto-nas` conform today and
  serve as the templates; future codecs (NGAP per ADR 0013) inherit the
  same bar.
