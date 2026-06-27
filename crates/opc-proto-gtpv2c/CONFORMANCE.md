# opc-proto-gtpv2c conformance shell

## Scope

- **Specification family:** 3GPP TS 29.274 (GTPv2-C), Release 18 naming.
- **Crate status:** scaffold / v0 shell for an S2b-focused subset.
- **Implemented evidence:** common-header structural parsing, raw TLIV IE
  boundary validation, raw-preserving encode/decode, and `opc-protocol` trait
  integration.

## Covered in this scaffold

1. **Common header**
   - Version field must be GTPv2-C version 2.
   - TEID-present and no-TEID header layouts are parsed.
   - The Length field is interpreted as excluding the first four octets.
   - Strict validation rejects non-zero spare bits in the flags octet and
     sequence spare octet.
   - Raw-preserving encode keeps decoded spare bits and message boundaries;
     canonical encode zeroes common-header spare fields.

2. **Raw IE region**
   - IE type, length, instance, spare bits, and value bytes are preserved.
   - IE lengths are checked with bounded arithmetic.
   - `DecodeContext::max_ies` limits raw IE iteration.
   - Strict validation rejects non-zero IE spare bits.
   - Unknown/private IEs remain byte-exact in the raw IE region for
     decode → encode forwarding paths.

3. **OpenPacketCore protocol framework fit**
   - `Message<'_>` implements `BorrowDecode`, `Encode`, and `ToOwnedPdu`.
   - `OwnedMessage` implements `OwnedDecode` and `Encode`.
   - Decode errors use structured `opc-protocol` error types with spec refs.

4. **Fuzz shell**
   - `fuzz/Cargo.toml` and `fuzz/fuzz_targets/decode_message.rs` compile the
     decode/owned-decode/IE-iteration surfaces under cargo-fuzz.
   - The repository fuzz workflow includes this crate in its scheduled matrix.

## Explicitly out of scope

- Typed Create Session, Modify Bearer, Delete Session, or other S2b procedure
  models.
- Mandatory IE, conditional IE, semantic, state-machine, or peer-role checks.
- GTPv1-C, GTP-U, Diameter, S1AP, PMIP, or a production ePDG/PGW control plane.
- Claims of carrier acceptance or interoperability beyond this structural shell.

## Canonicalization policy

Raw-preserving encoding keeps the decoded header spare bits and raw IE bytes.
Canonical encoding recomputes the Length field and emits version 2 with spare
bits zeroed, while still carrying the raw IE region unchanged until typed IE
models are added.

## Fixture provenance

The initial unit fixtures are hand-authored from the TS 29.274 common-header
and IE TLIV layouts:

- Echo Request without TEID: validates the no-TEID common-header shape.
- Create Session Request shell with TEID and one private raw IE: validates the
  TEID common-header shape and raw IE boundary handling without claiming APN or
  procedure-level conformance.
- Header, raw IE, and malformed-input integration tests under `tests/` extend
  those fixtures with raw-preserving spare-bit round trips, multi-IE unknown
  TLIV preservation, truncation/count-limit errors, and prefix/malformed input
  no-panic regressions.

Future typed S2b work must add spec-authored fixtures for every message and IE
it claims, with octet-level comments and byte-exact decode → encode tests per
ADR 0015.
