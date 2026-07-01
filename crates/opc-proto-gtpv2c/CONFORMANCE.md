# opc-proto-gtpv2c conformance subset

## Scope

- **Specification family:** 3GPP TS 29.274 (GTPv2-C), Release 18 naming.
- **Crate status:** S2b-focused typed subset with a raw-preserving message/IE
  shell and S2b Production Profile v1 available for the documented boundary.
- **Implemented evidence:** common-header structural parsing, raw TLIV IE
  boundary validation, raw-preserving encode/decode, provenance-labeled fixture
  corpus replay, malformed-input replay, profile-critical negative fixture
  replay, typed S2b IE examples, and typed S2b views for Echo plus
  Create/Modify/Delete/Update Session-oriented procedures.
  The transport-neutral Echo peer helper also tracks Recovery restart counters
  and rejects new Echo exchanges while restart reconciliation is required.
  Public profile constructors cover Echo, Create Session, Modify Bearer,
  Delete Session, and Update Bearer profile-owned request/response shapes.

## S2b Production Profile v1 — Target Boundary

S2b Production Profile v1 is the first production-ready boundary for
`opc-proto-gtpv2c`. The profile is a **codec, typed-view, validation, and
transport-neutral helper profile** for ePDG/PGW S2b integration. It does not
claim to implement a PGW, ePDG, UDP transport, retransmission loop, bearer
policy engine, APN/DNN authorization service, charging policy, roaming policy,
or carrier-accepted control-plane product.

### Profile-owned procedures

The profile owns typed decode, encode, construction, and procedure-aware
validation for these S2b procedure messages:

| Procedure | Message types | Profile requirement |
|:---|:---|:---|
| Echo | Request (1), Response (2) | Recovery IE decode/encode, no-TEID header shape, sequence preservation, restart-counter evidence. |
| Create Session | Request (32), Response (33) | S2b request/response mandatory IE validation, response Cause classification, Sender F-TEID and bearer-context projection. |
| Modify Bearer / S2b Modify Session | Request (34), Response (35) | Bearer Context request validation and Cause-bearing response validation. |
| Delete Session | Request (36), Response (37) | Linked EPS Bearer ID request validation and Cause-bearing response validation. |
| Update Bearer / S2b Update Session | Request (97), Response (98) | Bearer Context request validation and Cause-bearing response validation. |

### Profile-owned IE families

The profile owns the typed IE families required by the S2b messages above:

- Node and liveness IEs: Recovery.
- Subscriber/session IEs: IMSI, APN, PDN Type, PAA, Selection Mode, RAT Type,
  Serving Network, MEI, MSISDN.
- Tunnel and bearer IEs: Sender F-TEID, Bearer Context, EPS Bearer ID, Bearer
  QoS, Charging ID, AMBR, APN Restriction.
- Response and policy containers: Cause, Indication, PCO, APCO.
- Unknown, private, and unsupported future IEs remain raw-preserved and are not
  interpreted as product policy.

### Required semantic validation

Profile-v1 validation must separate structural decode failures from S2b profile
failures and must cover at least these rules:

- Echo messages must be no-TEID messages and must include Recovery.
- Create Session Request must include IMSI, RAT Type, Serving Network, Sender
  F-TEID, APN, Selection Mode, PDN Type, PAA, and Bearer Context with nested
  EBI.
- Create Session Response must include Cause, Sender F-TEID, and Bearer Context
  for accepted responses; rejected responses may expose Cause-only summaries.
- Modify Bearer and Update Bearer requests must include Bearer Context.
- Delete Session Request must include linked EPS Bearer ID.
- Procedure responses must include Cause where the profile claims response
  semantics.
- F-TEID and PAA typed validation must reject ambiguous malformed address
  shapes instead of silently canonicalizing them.
- Duplicate singleton IEs must be rejected according to the selected
  `DecodeContext::duplicate_ie_policy`.

### Compatibility and API guarantees

- The raw `Message` and `OwnedMessage` layers remain byte-preserving for
  unknown and vendor-specific IEs.
- Typed builders added for this profile must not construct messages missing
  mandatory profile-owned IEs.
- Procedure-aware validation APIs and stable projection/error codes must remain
  additive under semver once this profile is marked production-ready.
- Product code must continue to enforce APN/DNN policy, bearer policy, roaming
  policy, charging policy, persistence, and transport behavior outside this
  crate.

### Graduation status

No open graduation blockers remain for the documented S2b Production Profile v1
boundary. Future expansion of this boundary must add the same constructor,
ProcedureAware validation, positive fixture, malformed negative fixture, example,
and fuzz-seed mirror evidence before claiming additional production coverage.

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

5. **Echo peer helper**
   - `Gtpv2cEchoPeer` tracks Echo request/response liveness, sequence mismatch,
     missed-response degradation/failure, peer Recovery restart-counter changes,
     and redaction-safe readiness blockers.
   - With `Gtpv2cEchoPeerPolicy::require_restart_reconciliation = true`, a
     changed Recovery restart counter enters `ReconciliationRequired` and
     `echo_request_sent` returns
     `Gtpv2cEchoPeerError::RestartReconciliationRequired` until the caller
     completes product reconciliation via `restart_reconciled()`.
   - With restart reconciliation disabled, restart-counter changes remain
     observable but do not fence Echo traffic.

6. **OpenPacketCore protocol framework fit**
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

7. **Fixture and corpus replay**
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

8. **Fuzz shell**
   - `fuzz/Cargo.toml`, `fuzz/fuzz_targets/decode_message.rs`,
     `fuzz/fuzz_targets/decode_s2b.rs`, and
     `fuzz/fuzz_targets/roundtrip.rs` compile decode, typed S2b, owned-decode,
     IE-iteration, and raw-preserving round-trip surfaces under cargo-fuzz.
   - `fuzz/corpus/decode_message/`, `fuzz/corpus/decode_s2b/`, and
     `fuzz/corpus/roundtrip/` are the target-specific seed directories used by
     cargo-fuzz when the workflow runs `cargo +nightly fuzz run "$target"`
     without explicit corpus arguments. Each directory contains a flat,
     provenance-prefixed mirror of the committed spec, ePDG-parity, and
     malformed seed files.
   - Two legacy flat seeds, `fuzz/corpus/echo_request` and
     `fuzz/corpus/create_session_shell`, remain at the corpus root for backward
     compatibility and are replayed by the never-panic corpus test.
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
  subset and transport-neutral Echo/client-transaction helpers claimed here.
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
- The fuzz seed corpus keeps provenance source directories under
  `fuzz/corpus/spec/`, `fuzz/corpus/epdg-parity/`, and
  `fuzz/corpus/malformed/`. Because cargo-fuzz uses one corpus directory per
  target by default, the same seed bytes are also copied into
  `fuzz/corpus/decode_message/`, `fuzz/corpus/decode_s2b/`, and
  `fuzz/corpus/roundtrip/` using names like
  `spec__echo_request_recovery.bin`. Scheduled fuzzing therefore starts each
  registered target from the same S2b conformance, parity, and malformed cases
  that `tests/corpus_replay.rs` replays deterministically; the replay test also
  asserts those target-specific mirrors match the provenance source bytes.

Header, raw IE, malformed-input, corpus-replay, and S2b integration tests under
`tests/` exercise raw-preserving spare-bit round trips, multi-IE unknown TLIV
preservation, truncation/count-limit errors, prefix/malformed input no-panic
regressions, typed decode → encode fixtures, missing-mandatory-IE rejection, and
malformed profile-critical F-TEID/PAA rejection.

`examples/production_profile_v1.rs` exercises the downstream constructor path
for Echo, Create Session, Modify Bearer, Delete Session, and Update Bearer S2b
messages by performing typed construction → encode → decode → ProcedureAware
validation without manual raw byte assembly.

Future typed S2b expansion must add spec-authored fixtures for every newly
claimed message and IE, with octet-level comments and byte-exact decode → encode
tests per ADR 0015.
