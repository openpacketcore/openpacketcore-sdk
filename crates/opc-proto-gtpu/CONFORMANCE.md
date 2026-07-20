# GTP-U Protocol Conformance

This document defines the conformance of the `opc-proto-gtpu` crate against the 3GPP GTP-U specification.

## Specification Baseline
- **Document**: 3GPP TS 29.281
- **Release**: Release 18 (R18)
- **Status**: Full support for User Plane GTPv1-U framing and the typed control-codec subset listed below

## Supported Features

### 1. GTPv1-U Header Parsing and Validation
- **GTPv1-U Fixed Header** (§5.1): Eagerly validates Version (must be 1) and Protocol Type (must be true/1).
- **Optional Fields** (§5.1): Parses Sequence Number, N-PDU Number, and Next Extension Header Type when E, S, or PN flags are set.
- **Spare-bit receive and encoding profiles**: generic `GtpuMessage` decode in
  `Strict` and `ProcedureAware` remains a sender-canonicality profile that
  requires the §5.1 spare bit to be zero. Generic structural decode plus
  explicit raw-preserving encode retains a received non-zero bit, while
  generic canonical encode clears it. The typed control NETWORK receive
  boundary follows §5.1 receiver behavior instead: it ignores the spare bit at
  every supported validation level, and typed canonical encoding clears it.

### 2. Extension Headers (§5.2.1)
- **Zero-Allocation Eager Validation**: Eagerly traverses and verifies the extension header chain structure during `decode` to prevent infinite loops, out-of-bounds slicing, or stack/CPU exhaustion DoS.
- **Lazy Zero-Allocation Iteration**: Exposes `GtpuExtensionHeaderIterator` to walk extension headers on-demand without any heap allocations.
- **Nesting and IE Count Limits**: Enforces `max_depth` and `max_ies` limits from the `DecodeContext`.

### 3. PDU Session Container base subset (§5.2.2.7; TS 38.415 §5.5.2)
- **5G SA QoS Flow Identifier (QFI)**: Decodes base downlink and uplink PDU Session Container extension headers.
- **Paging Policy Indicator (PPI)**: Decodes PPI when the PPP flag is set in DL PDU Session Information.
- **Reflective QoS Indicator (RQI)**: Decodes RQI in DL PDU Session Information.
- **Fail-closed subset boundary**: PDU types 2–15 are rejected. Presence flags
  for QMP timestamps, QFI sequence numbers, MBS sequence numbers, delay
  results, congestion information, or future fields are rejected instead of
  being partially represented by the QFI/PPI/RQI model. Extension alignment,
  the PPP-dependent PPI width, and the exact supported base-frame width are
  checked before values are exposed.
- **Fail-closed construction and encode**: validated downlink/uplink
  constructors reject oversized QFI/PPI values. Public direct construction is
  retained for source compatibility, but fallible `validate`/`encode` rejects
  reserved PDU types and uplink PPI/RQI instead of truncating or discarding
  them. Every typed extension/control builder uses that same boundary.

### 4. Zero-Copy and Memory Safety
- **Borrowed Views**: `GtpuMessage<'a>` binds parsed fields to the lifetime of the input buffer with zero copy.
- **Owned Slicing**: `OwnedGtpuMessage` implements cheap reference-counted slicing of `bytes::Bytes` for thread-safe boundaries.

### 5. Extension-header comprehension (§5.2.1)
- **Typed classes**: all four bits-8/7 comprehension classes are exposed for
  endpoint and intermediate recipients, including the type `0xc0` SGW/G-PDU
  exception.
- **Unknown behavior**: endpoint-optional headers are structurally skipped and
  raw-preserved; endpoint-required unsupported headers fail with a typed,
  value-free classification suitable for a downstream Supported Extension
  Headers Notification plan.
- **Known-but-inapplicable behavior**: all standardized Release 18.4.0 types in
  figure 5.2.1-3 are classified separately. A type standardized for G-PDU only,
  including both PDU Set Information Container assignments, is rejected as
  procedure-inapplicable on typed signalling even when its comprehension bits
  are optional.
- **Known control extension**: the optional UDP Port extension on Error
  Indication is decoded and canonically encoded with exact four-octet length.

### 6. Path and tunnel-management codec (§§7.2.1–7.2.3, 7.3.1–7.3.2, 8.1–8.6, 8.8)
- **Echo Request/Response**: exact zero TEID and S-flag checks, sequence copying,
  mandatory Recovery, optional Recovery Time Stamp, and repeatable Private
  Extensions. Received Recovery counters are ignored and canonical output is
  always zero.
- **Error Indication**: mandatory non-zero TEID Data I and IPv4/IPv6 GTP-U Peer
  Address, receiver-ignored sequence semantics, optional UDP Port extension,
  Recovery Time Stamp, and repeatable Private Extensions.
- **Supported Extension Headers Notification**: mandatory, duplicate-free
  Extension Header Type List (including the specification-permitted empty
  list) and receiver-ignored sequence semantics.
- **End Marker** (§7.3.2.3): S flag zero, tunnel TEID preserved (including the
  specified backward-compatibility zero case), repeatable Private Extensions, and a
  structurally validated PDU Session Container where permitted for 5GS
  forwarding. Container semantics remain exposed through the shared extension
  model rather than duplicated in the control codec.
- **IE invariants**: ascending type order, exact TV/TLV lengths,
  mandatory/singleton cardinality, configured IE/message bounds, unknown TLV
  preserve/drop/reject policy, and fail-closed unknown TV behavior. Canonical
  encoding checks the model IE count and exact final datagram/u16 length before
  allocating or writing its serialized IE payload.
- **Validated conversion boundary**: `GtpuControlMessage::from_message`
  reapplies the supplied message-length, extension-depth, extension-count, and
  IE-count limits, plus generic version, PT, declared-length, and optional
  header contracts. This prevents a frame decoded under a looser context or
  assembled directly from bypassing the typed network boundary. The shared
  allocation budget remains advisory as documented by `opc-protocol`; actual
  typed allocations are bounded by the enforced message and count limits.
- **Diagnostics**: typed errors contain only stable codes, offsets, and protocol
  type identifiers; typed TEID, peer-address, private, unknown, and raw-chain
  `Debug` output is redacted or count-only. PDU semantic errors distinguish
  reserved types, unsupported downlink/uplink conditional fields, and duplicate
  containers at the offending extension-header offset.
- **Mutation preservation**: adding/replacing the applicable UDP Port or PDU
  Session Container extension rebuilds the chain while retaining unrelated
  decoded optional unknown headers; inconsistent retained chains fail
  explicitly.
- **Explicit exclusion**: Tunnel Status (§7.3.3 and §8.7) is not implemented
  by this codec slice and is rejected as a known procedure-inapplicable IE.

---

## Unsupported Features & Exclusions

### 1. GTPv0-U
- **Description**: Older GTPv0-U packets are not supported.
- **Reason**: The crate strictly handles GTPv1-U which is standard for modern 3GPP LTE and 5G networks.

### 2. Control Plane GTP-C
- **Description**: Crate is dedicated to the User Plane (GTP-U). GTP-C messages (TS 29.274) belong to a separate control-plane codec boundary.

### 3. Control datagram transport and policy
- **Description**: backend-neutral receive/send ports, Linux/eBPF socket or tc
  integration, peer admission, rate limits, response tuple selection, unknown-
  TEID lookup, and End Marker ordering policy are not implemented by this codec
  slice.
- **Tracking**: these runtime/dataplane acceptance items remain open under
  issue #341. Typed-codec tests do not claim Linux/eBPF behavioral parity or
  production qualification.

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
