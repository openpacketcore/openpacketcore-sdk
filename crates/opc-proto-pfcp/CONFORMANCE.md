# PFCP Protocol Conformance

This document defines the conformance of the `opc-proto-pfcp` crate against
3GPP TS 29.244.

## Specification Baseline

- **Document**: 3GPP TS 29.244
- **Release**: Release 18 (R18)
- **Status**: v0 — experimental, partial coverage

## Supported Features (v0)

### 1. Message Header (§7.4.1)
- Version 1 parsing and validation.
- Octet-1 flag layout per §7.4.1.1: bits 8–6 version, bits 5–4 spare,
  bit 3 FO, bit 2 MP, bit 1 S — asserted against hand-authored spec bytes
  in the test suite (not merely against this codec's own encoder).
- S-flag (SEID presence).
- MP flag: message priority carried in the high nibble of the final
  header octet, preserved byte-exact across decode → encode.
- FO flag parsing (rejected in strict mode, must be 0).
- Sequence number (24-bit).
- Spare bits validation (must be 0 in strict mode).
- The header Length field is honored: the message ends `4 + Length`
  octets in; shorter input is rejected as truncated, a Length smaller
  than the header's own SEID/sequence octets is rejected as structural,
  and trailing bytes are returned to the caller as the unconsumed
  remainder (also exposed as `Message::tail`).

### 2. Generic IE TLV Layer (§8.1.1)
- Type/Length framing for standard IEs (type < 32768).
- Vendor-specific IEs (type ≥ 32768): the Length field includes the
  2-octet Enterprise ID per §8.1.1; lengths < 2 are rejected.
- Unknown IEs preserved byte-exact for re-encode (raw-preserving
  round-trip), verified by byte-identity tests and a quickcheck property
  over arbitrary IE types and values.
- Truncated TLV rejection (header and value).
- Overflow length rejection.

### 3. Messages
- Heartbeat Request (1) / Response (2)
- Association Setup Request (5) / Response (6)
- Association Release Request (9) / Response (10)
- Session Establishment Request (50) / Response (51)
- Session Modification Request (52) / Response (53)
- Session Deletion Request (54) / Response (55)
- Session Report Request (56) / Response (57)

  *Note: v0 supports header parsing and raw IE preservation for all listed
  message types. Typed IE decoding is limited to the subset listed below.*

### 4. Typed IEs (v0)
- None yet — all IEs decode as `InformationElement` with raw value
  preservation. The `IeType` enum provides constants for the IE types in
  the v1 typed-decoding scope, but no typed IE structs exist in v0.

## Out of Scope (v0+)

- Typed IE decoding (Cause, F-TEID, F-SEID, Node ID, etc.) — planned for v1.
- Grouped IE recursion with depth limits — structural framing only in v0.
- Message-specific semantic validation.
- PFD Management, Subscriber Management, and other non-SMF/UPF messages.
