# GTP-U Protocol Conformance

This document defines the conformance of the `opc-proto-gtpu` crate against the 3GPP GTP-U specification.

## Specification Baseline
- **Document**: 3GPP TS 29.281
- **Release**: Release 19 (TS 29.281 V19.2.0)
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
- **Paging Policy Indicator (PPI)**: Encodes and decodes bits 7..5 when the PPP
  flag is set in DL PDU Session Information (TS 38.415 figure 5.5.2.1-1).
  Senders zero the lower five bits. Receivers ignore bits 4..2, but reject
  BSSI/TTNBI in bits 1..0, identified in TS 38.415 V19.1.0 figure 5.5.2.1-1,
  because this model does not represent their burst fields (#1520).
- **Reflective QoS Indicator (RQI)**: Decodes RQI in DL PDU Session Information.
- **Fail-closed subset boundary**: PDU types 2–15 are rejected. Presence flags
  for QMP timestamps, QFI sequence numbers, MBS sequence numbers, delay
  results, congestion information, burst size / time to next burst, or future
  fields are rejected instead of being partially represented by the QFI/PPI/RQI
  model. Extension alignment,
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
- **Typed values**: `GtpuTypedExtension` decodes/encodes UDP Port, short PDCP,
  18-bit Long PDCP, Service Class Indicator, and the existing PSC subset. RAN,
  Xw RAN and NR RAN container bytes are borrowed and opaque. Fixed lengths,
  aligned container bounds, 18-bit send limits and SCI send values 0–15 are
  checked. Receive ignores spare bits; typed send clears them. Short PDCP
  interface-specific 12/15-bit restrictions remain caller policy.
- **Long PDCP assignments**: figure 5.2.1-3 notes 2/3 require current senders
  to use `0x03`; `0x82` is the earlier-release receive form (the issue's legacy
  wording was reversed). Both have typed decode; explicit legacy encoding is
  available for interop, not the current sender default.
- **Comprehension scope**: wire-format recognition is separate from endpoint
  comprehension. Both the control-port and N3 endpoint profiles comprehend PSC
  only; 0x81–0x84 and 0xC0 require notification and discard at an endpoint even
  though typed format decoding exists. The SGW/G-PDU exception for 0xC0 remains.
  Structural GTP-U decode retains raw known extensions;
  `ProcedureAware`, the typed decode and comprehension scan check fixed lengths.
  Unknown required types still fail under `Reject`. PDU Set containers `0x04`
  and `0x86` remain unimplemented pending that feature's TS 38.415 semantics.
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

### 6. Path and tunnel-management codec (§§7.2.1–7.2.3, 7.3.1–7.3.3, 8.1–8.8)
- **Echo Request/Response**: exact zero TEID and S-flag checks, sequence copying,
  mandatory Recovery, optional Recovery Time Stamp, and repeatable Private
  Extensions. Received Recovery counters are ignored and canonical output is
  always zero.
- **Error Indication**: mandatory non-zero TEID Data I and IPv4/IPv6 GTP-U Peer
  Address, receiver-ignored sequence semantics, optional UDP Port extension,
  Recovery Time Stamp, and repeatable Private Extensions.
- **Supported Extension Headers Notification**: mandatory, duplicate-free
  Extension Header Type List (including the specification-permitted empty
  list), a one-octet count as specified by figure 8.5-1, and receiver-ignored
  sequence semantics. The previous two-octet list encoding was incorrect;
  it is not a compatibility profile. Other TLVs retain their two-octet
  lengths. See [the correction evidence](docs/extension-list-wire.md).
- **End Marker** (§7.3.2.3): S flag zero, tunnel TEID preserved (including the
  specified backward-compatibility zero case), repeatable Private Extensions, and a
  structurally validated PDU Session Container where permitted for 5GS
  forwarding. Container semantics remain exposed through the shared extension
  model rather than duplicated in the control codec.
- **IE receiver rules** (TS 29.281 §9.1, TS 29.060 §§11.1.9–11.1.12):
  ascending type order, complete TV/TLV framing, mandatory presence and configured
  IE/message bounds remain enforced. Known unexpected IEs are skipped, including
  GTP-C TV elements whose lengths are defined in TS 29.060 Table 37. First
  occurrences win regardless of `DuplicateIePolicy`; Private Extensions may repeat.
  Unknown TLVs are opaque under `Preserve`, skipped under both `Drop` and `Reject`.
  Known limitation: unknown TVs currently reject the whole message, although
  §11.1.9 permits discarding only the remainder when mandatory information is
  complete. Malformed optional Recovery Time Stamp and Private Extension IEs
  also still reject the message instead of being treated as absent (§11.1.13).
  These receiver-tolerance corrections remain follow-up work. Canonical
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
  explicitly. End Marker canonical encoding reconstructs the known PDU Session
  Container from its typed semantic value, clears receiver-ignored spare bits,
  and places it first as required by TS 29.281 figure 5.2.1-3 note 4. Unrelated
  optional unknown headers retain their relative order. Generic raw-preserving
  encoding continues to retain the accepted bytes exactly.
- **Tunnel Status** (§7.3.3 and §8.7): S flag zero, tunnel TEID, mandatory
  Tunnel Status Information with SPOC, and repeatable Private Extensions.
  Received spare bits are exposed but cleared on canonical send; future octets
  are retained. The dataplane port classifies a valid message as `TunnelStatus`
  for consumers to ignore when unsupported or when no tunnel exists. It grants
  no charging or response authority. Tunnel lookup, pause-of-charging application
  and upstream forwarding require consumer policy.

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
- **Runtime implementation**: the [dataplane control port](../opc-gtpu-dataplane/docs/control-port.md)
  supplies retained Linux/eBPF sockets, IPv4/IPv6 tuples and typed responses for
  #341. Peer admission, response pacing and lifecycle policy remain caller-owned.
  Codec tests alone do not qualify backend behavior or live-peer interoperability.

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
