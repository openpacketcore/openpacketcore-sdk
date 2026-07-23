# opc-proto-ngap conformance — v1 subset

3GPP release: TS 38.413 R18. ASN.1 types generated offline from the 3GPP
modules mirrored by Wireshark at pinned commit
`d296f939b42891994714939384adc3deaef3f180` (see
`scripts/generate-ngap.py`); APER via `rasn`.

## Coverage

✅ = proven by a conformance fixture per ADR 0015 (externally sourced or
hand-authored from the specification with octet comments). 🧪 = structural
typed dispatch is tested with explicit APER wrapper/body fixtures and fuzzed,
but no external field-level fixture proves the IE mapping yet.

| Layer | Item | Status | Evidence |
|---|---|---|---|
| NGAP-PDU framing | InitiatingMessage | ✅ | External NGSetupRequest fixture round-trip |
| NGAP-PDU framing | SuccessfulOutcome | ✅ | Hand-authored wrapper fixture (octet comments, X.691 CHOICE index 1); body kept raw |
| NGAP-PDU framing | UnsuccessfulOutcome | ✅ | Hand-authored wrapper fixture (CHOICE index 2); body kept raw |
| Typed decode | NGSetupRequest | ✅ | 78-byte external fixture; IE ids, RANNodeName content, and DefaultPagingDRX value asserted |
| Typed decode | NGSetupResponse / NGSetupFailure | 🧪 | Successful/unsuccessful outcome dispatch with hand-authored empty-IE APER fixtures; malformed recognized bodies fail closed |
| Typed decode | InitialUEMessage | 🧪 | Initiating-message dispatch with hand-authored empty-IE APER fixture; external field fixture pending |
| Typed decode | DownlinkNASTransport / UplinkNASTransport | 🧪 | First-CNF N2 dispatch with hand-authored empty-IE APER fixtures |
| Typed decode | InitialContextSetup Request/Response/Failure | 🧪 | Outcome-aware first-CNF N2 dispatch with hand-authored empty-IE APER fixtures |
| Typed decode | PDUSessionResourceSetup Request/Response | 🧪 | Outcome-aware first-CNF N2 dispatch with hand-authored empty-IE APER fixtures |
| Typed decode | PDUSessionResourceRelease Command/Response | 🧪 | Outcome-aware first-CNF N2 dispatch with hand-authored empty-IE APER fixtures |
| Typed decode | UEContextRelease Command/Complete | 🧪 | Outcome-aware first-CNF N2 dispatch with hand-authored empty-IE APER fixtures |
| Typed decode | Paging | 🧪 | Initiating-message dispatch with hand-authored empty-IE APER fixture |

Dispatch is outcome-aware: procedure code 21 decodes as NGSetupRequest only
on an initiating message, NGSetupResponse on a successful outcome, and
NGSetupFailure on an unsuccessful outcome. The same outcome-aware rule is
applied to the first-CNF N2 subset above.

## Protocol-IE policy and cardinality

The wrapper carries procedure/outcome-specific metadata transcribed from the
pinned TS 38.413 Release-18 ASN.1 object sets for every typed row above:
recognized top-level IE identifiers, expected criticality, and
singleton/repeatable cardinality.

- Known identifiers are accepted only with their specified criticality.
- `UnknownIePolicy::Preserve` retains the generated entry and opaque open-type
  value; `Drop` removes it from the typed container; and `Reject` returns a
  stable value-free decode error.
- An unknown IE carrying `criticality=reject` returns
  `DecodeErrorCode::UnknownCriticalIe` under `Reject`, `Strict`, or
  `ProcedureAware`. Structural validation with `Preserve` or `Drop` remains the
  explicit compatibility path for such an entry.
- `DuplicateIePolicy::First` and `Last` select deterministically in original
  wire order, while `Reject` returns `DecodeErrorCode::DuplicateIe`.
  Repeatable metadata exempts legal repetition. The current typed Release-18
  top-level object sets contain only singleton identifiers; list-valued IEs
  encode their repetition inside one IE value.
- Presence and conditional-presence rules, and semantic validation inside each
  opaque IE value, remain outside this framing subset.

These policies filter the typed generated container, not the preserved wire
image. `Pdu::raw` remains the immutable received bytes. Raw-preserving encode
therefore reproduces unknown or duplicate entries removed by `Drop`, `First`,
or `Last`; it is not a sanitized typed-view encoder.

Public `Debug` output for the wrapper and message enums is redacted to
procedure/outcome metadata, lengths, variant names, and IE counts. It does not
render `Pdu::raw`, opaque IE values, or NAS payload bytes.

## Encoding mode

- **Raw-preserving**: byte-exact `decode → encode` is proven for every
  fixture above; the original PDU bytes are preserved and re-emitted.
- **Canonical typed encode**: unsupported in the v1 subset and rejected with an
  error.
  `rasn` 0.28's APER encoder does not reproduce the octet alignment of the
  external fixtures for the inner message types (and its output for those
  types does not survive its own decoder), so this codec profile preserves raw
  bytes instead of constructing new NGAP messages from typed values.
  Raw-preserving encode also rejects PDUs without decoded raw bytes.

## Fixtures

- `NGSetupRequest`: 78-byte APER PDU captured from an independent
  `asn1c`-based implementation (libngap): GlobalRANNodeID, RANNodeName
  ("My little gNB"), SupportedTAList, DefaultPagingDRX(v64). Field-level
  content is asserted, not just the decoded type.
- Successful/unsuccessful outcome wrappers and empty-IE message bodies:
  hand-authored from TS 38.413 §9.2 and X.691 aligned-PER rules with
  octet-level comments. These prove routing and raw-preserving behavior, not
  complete IE semantic conformance for those message types.

## Robustness & Fuzzing

The decode path carries no `unsafe` and uses checked length arithmetic. For
typed procedures it parses the exact aligned-PER container prefix before
`rasn`: the fixed-width 16-bit `ProtocolIE-Container` count must satisfy
`DecodeContext::max_ies` and the minimum physical bytes required by that many
entries before `SequenceOf` materialization. Three additional layers guard it:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  corpus entry, byte-truncations of each, and hostile constant inputs through
  `Pdu::decode_owned` under `catch_unwind`. Runs in ordinary `cargo test`; no
  nightly toolchain or libFuzzer required.
- **Scheduled fuzzing** — `fuzz/fuzz_targets/decode_ngap.rs` with a seeded
  corpus, registered in `.github/workflows/fuzz.yml` and run weekly.
- **Verification** — a deep `cargo-fuzz` pass over the decoder completed ~26M
  executions with no crash, leak, or OOM.

## Codec Boundary (v1 subset)

- Canonical (typed) encoding of any message.
- External field-level fixtures for the structural typed-dispatch subset above.
- Typed decode of procedures outside the first-CNF N2 subset above; preserved
  raw as `Message::Unknown`.
- UPER encoding.
- Semantic validation of IE contents or mandatory/conditional presence beyond
  the top-level identifier, criticality, and cardinality contract above.
