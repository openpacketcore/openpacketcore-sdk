# opc-proto-gtpv2c conformance subset

## Scope

- **Specification family:** 3GPP TS 29.274 (GTPv2-C), Release 18 naming.
- **Crate status:** experimental S2b-focused typed subset with a raw-preserving
  message/IE shell.
- **Implemented evidence:** common-header structural parsing, raw TLIV IE
  boundary validation, raw-preserving encode/decode, typed S2b IE examples,
  and typed S2b views for Echo plus Create/Modify/Delete/Update
  Session-oriented procedures.

## Covered in this subset

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
   - Unknown/private/unsupported IEs remain byte-exact in the raw IE region for
     decode → encode forwarding paths.

3. **Typed S2b IE subset**
   - IMSI, Cause, Recovery, APN, Aggregate Maximum Bit Rate, EPS Bearer ID,
     MEI, MSISDN, PDN Address Allocation, RAT Type, Serving Network, F-TEID,
     Bearer Context, PDN Type, APN Restriction, and Selection Mode have typed
     decode/encode support.
   - Bearer Context is decoded as a grouped IE with bounded recursion and raw
     fallback for unsupported nested members.
   - Unsupported S2b-adjacent IEs such as Protocol Configuration Options remain
     available as `TypedIeValue::Raw` and re-encode byte-exact.

4. **S2b message views**
   - `S2bMessage` decodes Echo Request/Response, Create Session
     Request/Response, Modify Bearer Request/Response (the S2b Modify Session
     view), Delete Session Request/Response, and Update Bearer
     Request/Response (the S2b Update Session view).
   - `ValidationLevel::ProcedureAware` checks the mandatory IE subset claimed
     by this crate's S2b examples: Echo Response Recovery; Create Session
     Request IMSI/RAT Type/Serving Network/Sender F-TEID/APN/Selection
     Mode/PDN Type/PAA/Bearer Context with nested EBI; Create Session Response
     Cause/Sender F-TEID/Bearer Context; Modify and Update request Bearer
     Context; Delete request linked EBI; and response Cause IEs.
   - Non-S2b message types fall back to the raw `Message` shell.

5. **OpenPacketCore protocol framework fit**
   - `Message<'_>` implements `BorrowDecode`, `Encode`, and `ToOwnedPdu`.
   - `OwnedMessage` implements `OwnedDecode` and `Encode`.
   - `S2bMessage<'_>` and `S2bProcedureMessage<'_>` implement `Encode`, and
     `S2bMessage<'_>` implements `BorrowDecode`.
   - Decode errors use structured `opc-protocol` error types with spec refs.

6. **Fuzz shell**
   - `fuzz/Cargo.toml` and `fuzz/fuzz_targets/decode_message.rs` compile the
     decode/owned-decode/IE-iteration surfaces under cargo-fuzz.
   - The repository fuzz workflow includes this crate in its scheduled matrix.

## Explicitly out of scope

- A full Release 18 GTPv2-C implementation or a complete S2b IE/procedure
  matrix beyond the typed subset listed above.
- Conditional IE, cross-message state-machine, peer-role, charging, QoS policy,
  or bearer lifecycle semantic validation beyond the ProcedureAware mandatory
  subset claimed here.
- GTPv1-C, GTP-U, Diameter, S1AP, PMIP, or a production ePDG/PGW control plane.
- Claims of carrier acceptance or interoperability beyond this experimental
  S2b typed subset.

## Canonicalization policy

Raw-preserving encoding keeps the decoded header spare bits and raw IE bytes.
Canonical encoding recomputes the Length field, emits version 2 with header and
IE spare bits zeroed for typed IEs, encodes TBCD/APN/PLMN/PAA/F-TEID fields in
canonical form, and still carries unsupported IEs through the raw fallback.
Use the raw `Message` layer or `EncodeContext { raw_preserving: true, .. }` on a
freshly decoded S2b view for byte-exact forwarding.

## Fixture provenance

The initial unit fixtures are hand-authored from the TS 29.274 common-header
and IE TLIV layouts:

- Echo Request without TEID validates the no-TEID common-header shape.
- Create Session Request without TEID validates mandatory S2b request examples:
  IMSI, RAT Type, Serving Network, Sender F-TEID, APN, Selection Mode, PDN
  Type, PAA, Bearer Context/EBI, and raw fallback for an unsupported PCO IE.
- Create Session Response with TEID validates response Cause, Sender F-TEID,
  PAA, and Bearer Context examples.
- Modify Bearer, Delete Session, and Update Bearer fixtures validate the S2b
  Modify/Delete/Update Session-oriented views and ProcedureAware mandatory
  checks.
- Header, raw IE, malformed-input, and S2b integration tests under `tests/`
  exercise raw-preserving spare-bit round trips, multi-IE unknown TLIV
  preservation, truncation/count-limit errors, prefix/malformed input no-panic
  regressions, typed decode → encode fixtures, and missing-mandatory-IE
  rejection.

Future typed S2b expansion must add spec-authored fixtures for every newly
claimed message and IE, with octet-level comments and byte-exact decode → encode
tests per ADR 0015.
