# opc-proto-gtpv2c conformance subset

## Scope

- **Specification family:** 3GPP TS 29.274 (GTPv2-C), Release 18 naming.
- **Crate status:** experimental S2b-focused typed subset with a raw-preserving
  message/IE shell.
- **Implemented evidence:** common-header structural parsing, raw TLIV IE
  boundary validation, raw-preserving encode/decode, provenance-labeled fixture
  corpus replay, malformed-input replay, typed S2b IE examples, and typed S2b
  views for Echo plus Create/Modify/Delete/Update Session-oriented procedures.

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
     MEI, MSISDN, Indication, Protocol Configuration Options, PDN Address
     Allocation, Bearer QoS, RAT Type, Serving Network, F-TEID, Bearer
     Context, Charging ID, PDN Type, APN Restriction, Selection Mode, and
     Additional Protocol Configuration Options have typed decode/encode
     support.
   - PCO/APCO and Indication are typed as opaque byte-preserving containers so
     nested or future protocol options/flags are not silently dropped.
   - Bearer QoS decodes the fixed 22-octet shape into priority/QCI plus
     40-bit maximum and guaranteed bit-rate fields; Charging ID decodes as a
     four-octet identifier.
   - Cause decoding preserves the mandatory flags/locality octet and opaque
     offending-IE bytes; one-octet Cause values are rejected as malformed.
   - F-TEID uses the TS 29.274 V4/V6 flag bits (`0x80`/`0x40`) and rejects
     surplus value bytes after the declared IPv4/IPv6 address fields. F-TEID
     values with neither V4 nor V6 set are rejected.
   - Non-IP, Ethernet, and unknown PAA typed values are accepted only in their
     one-octet form; over-long shapes are rejected instead of silently
     canonicalized.
   - Bearer Context is decoded as a grouped IE with bounded recursion and raw
     fallback for unsupported nested members.
   - Top-level and grouped typed IE sequences enforce
     `DecodeContext::duplicate_ie_policy` by IE type and instance.
   - Unsupported/private/future IEs outside the typed subset remain available as
     `TypedIeValue::Raw` and re-encode byte-exact.

4. **S2b message views**
   - `S2bMessage` decodes Echo Request/Response, Create Session
     Request/Response, Modify Bearer Request/Response (the S2b Modify Session
     view), Delete Session Request/Response, and Update Bearer
     Request/Response (the S2b Update Session view).
   - `ValidationLevel::ProcedureAware` checks the mandatory IE subset claimed
     by this crate's S2b examples: Echo Request/Response Recovery; Create
     Session Request IMSI/RAT Type/Serving Network/Sender F-TEID/APN/Selection
     Mode/PDN Type/PAA/Bearer Context with nested EBI; Create Session Response
     Cause/Sender F-TEID/Bearer Context; Modify and Update request Bearer
     Context; Delete request linked EBI; and response Cause IEs.
   - Non-S2b message types fall back to the raw `Message` shell.

5. **OpenPacketCore protocol framework fit**
   - `Message<'_>` implements `BorrowDecode`, `Encode`, and `ToOwnedPdu`.
   - `OwnedMessage` implements `OwnedDecode` and `Encode`.
   - `MessageType` provides a public typed message-type enum with
     `Unknown(u8)` fallback; raw and S2b message views expose conversion
     helpers without losing unsupported values.
   - `S2bMessage<'_>` and `S2bProcedureMessage<'_>` implement `Encode`, and
     `S2bMessage<'_>` implements `BorrowDecode`.
   - Decode errors use structured `opc-protocol` error types with spec refs.
   - `Debug` output for S2b typed message views redacts IMSI/MEI/MSISDN digits
     and summarizes raw IE buffers by length.

6. **Fixture and corpus replay**
   - `tests/fixtures/spec/` contains the ADR 0015 conformance fixtures for the
     S2b subset. The accompanying `tests/fixtures/README.md` records
     octet-level comments for each spec-authored fixture.
   - `tests/fixtures/independent/` is intentionally empty except for a README;
     no independent GTPv2-C capture is claimed until capture provenance,
     license/permission, implementation version, redaction status, and expected
     re-encode behavior are documented.
   - `tests/fixtures/epdg-parity/` contains parity/regression bytes only. These
     inputs exercise raw/private IE preservation but are not counted as
     conformance evidence.
   - `tests/fixtures/malformed/` contains synthetic hostile inputs for
     truncation, declared-length overrun, strict spare-bit rejection,
     grouped-IE recursion-depth rejection, and low-limit IE-count paths.
   - `tests/corpus_replay.rs` replays fixture and fuzz corpora through raw
     decode, owned decode, strict/procedure-aware decode, typed S2b decode,
     IE iteration, raw-preserving encode, and truncation/adversarial no-panic
     checks.

7. **Fuzz shell**
   - `fuzz/Cargo.toml`, `fuzz/fuzz_targets/decode_message.rs`,
     `fuzz/fuzz_targets/decode_s2b.rs`, and
     `fuzz/fuzz_targets/roundtrip.rs` compile decode, typed S2b, owned-decode,
     IE-iteration, and raw-preserving round-trip surfaces under cargo-fuzz.
   - The repository fuzz workflow includes this crate in its scheduled matrix.

## Known limitations

- The common-header flags octet bit 3 is the Message Priority (MP) flag in
  TS 29.274 R18, but this scaffold folds the low three bits into a single
  `spare` field. Strict-mode decode rejects non-zero values there, so
  otherwise-valid GTPv2-C messages that set MP=1 will fail strict validation.
  Future typed S2b work must add explicit MP-flag handling before claiming
  support for priority-bearing messages.

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
IE spare bits zeroed for typed IEs, encodes TBCD/APN/PLMN/PAA/F-TEID/Bearer QoS
fields in canonical form, preserves opaque PCO/APCO/Indication bytes, and still
carries unsupported IEs through the raw fallback.
Use the raw `Message` layer or `EncodeContext { raw_preserving: true, .. }` on a
freshly decoded S2b view for byte-exact forwarding.

## Fixture provenance

The committed fixture corpus is split by provenance class:

- **Spec-authored conformance fixtures** live in `tests/fixtures/spec/`. They
  are hand-authored from the TS 29.274 common-header and IE TLIV layouts and
  are the only GTPv2-C fixtures currently counted as conformance evidence:
  - Echo Request without TEID validates the no-TEID common-header shape and
    mandatory Recovery IE.
  - Create Session Request without TEID validates mandatory S2b request
    examples: IMSI, RAT Type, Serving Network, Sender F-TEID, APN, Selection
    Mode, PDN Type, PAA, Bearer Context/EBI, nested Bearer QoS and Charging ID,
    typed PCO, Indication, APCO, and raw fallback for an unsupported private
    IE.
  - Create Session Response with TEID validates response Cause, Sender F-TEID,
    PAA, and Bearer Context examples.
  - Modify Bearer, Delete Session, and Update Bearer fixtures validate the S2b
    Modify/Delete/Update Session-oriented views and ProcedureAware mandatory
    checks.

- **Independent-capture fixtures** would live in `tests/fixtures/independent/`.
  None are committed yet, so this crate makes no independent-peer
  interoperability claim.
- **ePDG parity fixtures** live in `tests/fixtures/epdg-parity/`. They are
  regression seeds for raw/private IE and piggybacking preservation only. They
  are not spec-authored, not independently captured, and must not be cited as
  SDK wire-format conformance evidence.
- **Synthetic malformed fixtures** live in `tests/fixtures/malformed/`; they
  exercise hostile-input no-panic behavior and expected structured rejection,
  including low-limit grouped Bearer Context recursion-depth rejection.
- The fuzz seed corpus mirrors the full spec fixture set plus representative
  parity and malformed inputs under `fuzz/corpus/` so scheduled fuzzing starts
  from the same S2b conformance cases that `tests/corpus_replay.rs` replays
  deterministically.

Header, raw IE, malformed-input, corpus-replay, and S2b integration tests under
`tests/` exercise raw-preserving spare-bit round trips, multi-IE unknown TLIV
preservation, truncation/count-limit errors, prefix/malformed input no-panic
regressions, typed decode → encode fixtures, and missing-mandatory-IE
rejection.

Future typed S2b expansion must add spec-authored fixtures for every newly
claimed message and IE, with octet-level comments and byte-exact decode → encode
tests per ADR 0015.
