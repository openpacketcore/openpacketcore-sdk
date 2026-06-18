# GTP-U Protocol Conformance

This document defines the conformance of the `opc-proto-gtpu` crate against the 3GPP GTP-U specification.

## Specification Baseline
- **Document**: 3GPP TS 29.281
- **Release**: Release 18 (R18)
- **Status**: Full support for User Plane GTPv1-U framing

## Supported Features

### 1. GTPv1-U Header Parsing and Validation
- **GTPv1-U Fixed Header** (§5.1): Eagerly validates Version (must be 1) and Protocol Type (must be true/1).
- **Optional Fields** (§5.1): Parses Sequence Number, N-PDU Number, and Next Extension Header Type when E, S, or PN flags are set.
- **Strict Reserved Validation**: In `Strict` and `ProcedureAware` validation levels, verifies that the Reserved bit is zero.

### 2. Extension Headers (§5.2.1)
- **Zero-Allocation Eager Validation**: Eagerly traverses and verifies the extension header chain structure during `decode` to prevent infinite loops, out-of-bounds slicing, or stack/CPU exhaustion DoS.
- **Lazy Zero-Allocation Iteration**: Exposes `GtpuExtensionHeaderIterator` to walk extension headers on-demand without any heap allocations.
- **Nesting and IE Count Limits**: Enforces `max_depth` and `max_ies` limits from the `DecodeContext`.

### 3. PDU Session Container (§5.2.2.7)
- **5G SA QoS Flow Identifier (QFI)**: Decodes downlink and uplink PDU Session Container extension headers.
- **Paging Policy Indicator (PPI)**: Decodes PPI when the PPP flag is set in DL PDU Session Information.
- **Reflective QoS Indicator (RQI)**: Decodes RQI flag in DL PDU Session Information.

### 4. Zero-Copy and Memory Safety
- **Borrowed Views**: `GtpuMessage<'a>` binds parsed fields to the lifetime of the input buffer with zero copy.
- **Owned Slicing**: `OwnedGtpuMessage` implements cheap reference-counted slicing of `bytes::Bytes` for thread-safe boundaries.

---

## Unsupported Features & Exclusions

### 1. GTPv0-U
- **Description**: Older GTPv0-U packets are not supported.
- **Reason**: The crate strictly handles GTPv1-U which is standard for modern 3GPP LTE and 5G networks.

### 2. Control Plane GTP-C
- **Description**: Crate is dedicated to the User Plane (GTP-U). GTP-C messages (TS 29.274) belong to a separate control-plane codec boundary.

---

## Robustness & Fuzzing

Decode paths carry no `unsafe`, use checked length arithmetic, and never
preallocate from a wire-declared length. Three layers guard them:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  corpus entry, byte-truncations of each, and hostile constant inputs through
  `GtpuMessage::decode` at every validation level (HeaderOnly, Structural, Strict,
  ProcedureAware) and asserts the raw-preserving and canonical round-trip
  invariants, under `catch_unwind`. Runs in ordinary `cargo test`; no nightly
  toolchain or libFuzzer required.
- **Scheduled fuzzing** — `fuzz/fuzz_targets/decode.rs` and
  `fuzz/fuzz_targets/roundtrip.rs` with a seeded corpus, registered in
  `.github/workflows/fuzz.yml` and run weekly.
- **Verification** — a deep `cargo-fuzz` pass over the decode and round-trip
  targets completed ~730M executions with no crash, leak, OOM, or round-trip
  violation.
