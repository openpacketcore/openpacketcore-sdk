# OPC-SDK-RFC-005: Zero-Copy Protocol Framework

**Status**: Draft for Implementation  
**Version**: 2.0.0  
**Date**: 2026-05-19  
**Audience**: SDK implementers, protocol crate authors, fuzzing engineers, NF teams

## 1. Abstract

This RFC defines the protocol codec framework for OpenPacketCore. It covers
zero-copy parsing, encoding, lifetime discipline, allocation budgets, parser
security, fuzzing, conformance tags, and implementation layout for 3GPP and
IETF protocol crates.

The initial draft correctly required `nom`, `bytes`, fuzzing, and exact spec
citations. It was incomplete in two areas: the codec trait did not express
borrowed lifetimes safely, and the round-trip property was too simplistic for
protocols with canonical encodings, unknown fields, padding, or lossy
normalization. This version corrects those issues.

## 2. Scope

### 2.1 In Scope

- Binary protocol parsing and encoding.
- Borrowed zero-copy PDU views.
- Owned conversion for async and cross-thread use.
- Length, bounds, recursion, and integer safety.
- Fuzzing, property tests, and corpus management.
- Spec traceability for RFC 006.
- Protocol crate layout and module boundaries.

### 2.2 Out of Scope

- Management config projection. See RFC 002.
- Session persistence. See RFC 004.
- Full NF procedure state machines.
- Kernel bypass packet I/O frameworks, except for buffer ownership contracts.

## 3. Design Goals

### 3.1 Security

- No out-of-bounds reads or writes.
- No panics on untrusted input.
- No unbounded recursion, loops, allocation, or CPU use from hostile packets.
- Constant-time comparison for secrets, MACs, authentication tags, and keys.
- Strict validation of length fields, IE cardinality, duplicate handling, and
  unknown critical elements.

### 3.2 Performance

- Parse common fast-path headers without heap allocation.
- Avoid copying payloads where a borrowed view is sufficient.
- Encode into caller-provided buffers with exact or bounded capacity planning.
- Support partial decode when only routing keys are needed.
- Provide per-protocol allocation and latency budgets.

### 3.3 Maintainability

- Each protocol crate uses the same module layout.
- Every message and field cites the exact spec section/table.
- Parser errors are structured and stable.
- Unsafe code is forbidden by default.
- Generated tables are separated from hand-written parser logic.

### 3.4 Functionality

- Support borrowed and owned message representations.
- Support streaming/incomplete input where protocols require reassembly.
- Support extension headers and unknown IE preservation when required.
- Support canonical encoding and raw-preserving encoding modes.

## 4. Parsing Model

### 4.1 Borrowed Views

Protocol decoders SHOULD return borrowed views over the input buffer:

```rust
pub struct GtpHeader<'a> {
    pub flags: u8,
    pub msg_type: u8,
    pub length: u16,
    pub teid: u32,
    pub payload: &'a [u8],
}
```

Borrowed views MUST NOT outlive the input buffer. They MUST NOT store pointers
into mutable buffers that can be changed while the view exists.

### 4.2 Owned Messages

Every borrowed PDU that may cross an async boundary, thread boundary, queue, or
long-lived store MUST provide an owned conversion:

```rust
pub trait ToOwnedPdu {
    type Owned;
    fn to_owned_pdu(&self) -> Self::Owned;
}
```

Owned PDUs MAY use `bytes::Bytes` to retain cheap shared ownership of the
original packet.

### 4.3 No Self-Referential Types

Generated or hand-written protocol structs MUST NOT be self-referential. If a
message needs both raw bytes and parsed fields, use either:

- borrowed view tied to external input lifetime, or
- owned `Bytes` plus offsets validated at construction.

## 5. Codec Traits

The SDK defines separate traits for borrowed decode, owned decode, and encode.

```rust
pub type DecodeResult<'a, T> = Result<(&'a [u8], T), DecodeError>;

pub trait BorrowDecode<'a>: Sized {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self>;
}

pub trait OwnedDecode: Sized {
    fn decode_owned(input: bytes::Bytes, ctx: DecodeContext) -> Result<Self, DecodeError>;
}

pub trait Encode {
    fn encode(&self, dst: &mut bytes::BytesMut, ctx: EncodeContext) -> Result<(), EncodeError>;
    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError>;
}
```

This avoids pretending that a borrowed PDU can be represented by a lifetime-free
`Self`.

### 5.1 Decode Context

```rust
pub struct DecodeContext {
    pub protocol_version: ProtocolVersion,
    pub max_depth: usize,
    pub max_ies: usize,
    pub max_message_len: usize,
    pub unknown_ie_policy: UnknownIePolicy,
    pub duplicate_ie_policy: DuplicateIePolicy,
    pub validation_level: ValidationLevel,
}
```

Protocol crates MUST define safe defaults.

### 5.2 Error Model

```rust
pub struct DecodeError {
    pub code: DecodeErrorCode,
    pub offset: usize,
    pub spec_ref: Option<SpecRef>,
}
```

Errors MUST be safe to expose in logs. They MUST NOT include raw packet payload
unless debug packet capture is explicitly enabled.

## 6. `nom` Usage

`nom` is the default parser combinator framework for binary TLV, bitfield, and
header-oriented protocols.

Rules:

- Use `nom::number::complete` or `nom::number::streaming` deliberately.
- Map `nom::Err::Incomplete` to a structured incomplete-input error.
- Do not discard remaining input unless the message definition allows trailing
  padding.
- Wrap `nom` errors at module boundaries; do not expose combinator internals in
  public API.
- Prefer small named parser functions over deeply nested combinator expressions.

Protocols based on ASN.1 PER, JSON, HTTP/2, or other specialized encodings MAY
use proven dedicated parsers instead of `nom`, but they must implement the same
SDK codec, error, fuzzing, and evidence contracts.

## 7. Buffer Management

Encoders MUST use `bytes::BytesMut` or `bytes::BufMut`.

Encoding rules:

- `wire_len` MUST use checked arithmetic.
- `encode` MUST fail before writing if required capacity exceeds configured
  maximum.
- Encoders SHOULD reserve exact capacity when cheap to compute.
- Encoders MUST produce canonical output unless raw-preserving mode is selected.
- Partial writes on error SHOULD be avoided. If unavoidable, document the
  behavior and do not reuse the buffer without caller awareness.

## 8. Allocation Budgets

Each protocol crate MUST define an allocation profile:

```rust
pub struct AllocationBudget {
    pub decode_heap_allocations_fast_path: usize,
    pub decode_max_temporary_bytes: usize,
    pub encode_max_temporary_bytes: usize,
}
```

Default fast-path target:

- Fixed header decode: 0 heap allocations.
- Routing-key partial decode: 0 heap allocations.
- Full message decode: protocol-specific, bounded.

Variable IE lists SHOULD use:

- iterators over borrowed IE views,
- `smallvec` for small bounded lists,
- caller-provided scratch buffers, or
- validated owned vectors when required.

## 9. Security Invariants

### 9.1 Length and Offset Safety

All length calculations MUST use checked arithmetic. Parsers MUST verify:

- field length is within remaining input,
- nested IE length does not exceed parent length,
- padding length is valid,
- extension header chains terminate,
- total parsed elements do not exceed `max_ies`,
- recursion or nesting does not exceed `max_depth`.

### 9.2 Integer Safety

All offset, length, and capacity calculations MUST use:

- `checked_add`
- `checked_sub`
- `checked_mul`
- `usize::try_from`

Integer truncation with `as` is forbidden in parser and encoder length paths.

### 9.3 Constant-Time Operations

Constant-time comparison is REQUIRED for:

- MACs
- authentication tags
- keys
- nonces when secrecy or oracle behavior matters
- authentication tokens

Checksums over public packet data do not require constant-time comparison, but
checksum parsing must still be bounds-safe and panic-free.

### 9.4 Denial of Service Controls

Every decoder MUST enforce:

- maximum message length,
- maximum IE count,
- maximum nesting depth,
- maximum extension chain length,
- maximum decompressed length if compression exists,
- maximum parse time indirectly through bounded loops.

Protocol crates MUST expose these limits through profile configuration.

## 10. Validation Levels

The decoder supports levels:

```rust
pub enum ValidationLevel {
    HeaderOnly,
    Structural,
    Strict,
    ProcedureAware,
}
```

- `HeaderOnly`: parse enough for routing.
- `Structural`: verify lengths and container structure.
- `Strict`: enforce field cardinality, enum ranges, and critical IE rules.
- `ProcedureAware`: call NF-specific semantic validators.

Data-plane fast paths SHOULD use the minimum level needed for safe routing and
leave expensive semantic validation to control-plane paths where appropriate.

## 11. Unknown and Duplicate Elements

Protocol crates MUST define:

- Unknown IE behavior.
- Duplicate IE behavior.
- Critical/mandatory IE behavior.
- Extension preservation behavior.

If a protocol requires preserving unknown elements for forwarding or
round-trip, the borrowed view MUST expose raw slices and owned conversion MUST
retain them.

## 12. Round-Trip Properties

The simplistic property `encode(decode(input)) == input` is not universally
valid. The SDK requires three properties:

### 12.1 Canonical Round Trip

For generated valid model values:

```text
decode(encode(model)) == model
```

### 12.2 Raw-Preserving Round Trip

For accepted inputs where unknown/padding preservation is enabled:

```text
encode_raw_preserving(decode_raw_preserving(input)) == input
```

### 12.3 Reject Stability

For rejected inputs, the decoder returns a structured error and never panics,
hangs, or allocates beyond budget.

## 13. Fuzzing

Every protocol crate MUST include fuzz targets for:

- full decode,
- header-only decode,
- encode after generated model mutation,
- round-trip properties,
- length and extension chains,
- security fields where applicable.

Fuzz gates SHOULD be time and coverage based, not only iteration-count based.
Minimum admission gate:

- 30 minutes sanitizer-enabled fuzzing per new parser target in CI or nightly.
- 1,000,000 generated cases for property tests where practical.
- All crashes minimized and committed as regression tests.

Required sanitizers where supported:

- AddressSanitizer for native dependencies.
- UndefinedBehaviorSanitizer for C/C++ parser dependencies.
- Miri for unsafe Rust, if any unsafe exception is approved.

## 14. Spec Traceability

Every public PDU, IE, field enum, and procedure-relevant constant MUST cite:

- standards body,
- document number,
- release or revision where applicable,
- section,
- table or figure where applicable,
- conformance status.

Example:

```rust
/// @3gpp TS 29.281 Release 18, Section 5.1, Table 5.1-1
/// @conformance full
pub struct Gtpv1uHeader<'a> { ... }
```

These tags feed RFC 006 evidence extraction.

## 15. Protocol Crate Layout

Each protocol crate MUST use:

```text
crates/opc-proto-<name>/
  src/
    lib.rs
    error.rs
    context.rs
    header.rs
    ie.rs
    message.rs
    parser.rs
    encode.rs
    validate.rs
    spec.rs
    generated/
      tables.rs
  tests/
    corpus.rs
    roundtrip.rs
    conformance.rs
  fuzz/
    fuzz_targets/
      decode.rs
      header.rs
      roundtrip.rs
```

For protocols without IEs, `ie.rs` may be omitted. Generated tables MUST live
under `generated/` and be reproducible.

## 16. Implementation Contracts

Contributors implementing protocol crates MUST follow these rules:

- Start from `spec.rs` constants and conformance tags.
- Implement `error.rs` and `context.rs` before parser logic.
- Implement header parsing before full message parsing.
- Add fuzz target with the first parser.
- Do not add `unsafe`.
- Do not use `unwrap`, `expect`, or indexing on untrusted input.
- Keep parser functions small and named after spec structures.
- Add one regression test per newly handled malformed input class.

Agents may work independently on:

- header parser,
- IE parser,
- encoder,
- validation,
- fuzz/test corpus,
- generated spec tables.

## 17. Testing Requirements

### 17.1 Unit Tests

- Minimum and maximum length messages.
- Truncated input at every byte position for fixed headers.
- Invalid enum values.
- Duplicate IE policies.
- Unknown IE policies.
- Extension header chain termination.
- Checked arithmetic overflow cases.

### 17.2 Integration Tests

- Decode real capture fixtures.
- Encode/decode canonical known-good messages.
- Partial decode for routing keys.
- Owned conversion across async boundary.
- Protocol-specific strict validation.

### 17.3 Performance Tests

Each protocol crate MUST benchmark:

- header-only decode,
- full structural decode,
- strict validation,
- encode,
- owned conversion.

Benchmarks MUST report:

- p50/p99 latency,
- heap allocations,
- bytes copied,
- throughput in messages/second.

### 17.4 Negative Corpus

Every parser MUST maintain a negative corpus:

- truncated,
- overlong,
- nested too deep,
- duplicate mandatory fields,
- unknown critical fields,
- invalid length,
- invalid padding,
- integer overflow candidate.

## 18. Acceptance Criteria

This RFC is implemented when:

1. Borrowed decoders express lifetimes safely and owned conversion is available.
2. Fast-path header decode is allocation-free for supported protocols.
3. All length and offset math is checked.
4. Decoders reject hostile input without panic, hang, or unbounded allocation.
5. Round-trip tests distinguish canonical and raw-preserving modes.
6. Fuzz targets and regression corpora exist for every protocol crate.
7. Spec traceability tags feed RFC 006 evidence.
8. Protocol modules follow the standard layout for parallel implementation.
