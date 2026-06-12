# opc-proto-ngap conformance — v0

3GPP release: TS 38.413 R18. ASN.1 types generated offline from the 3GPP
modules (see `scripts/generate-ngap.py`); APER via `rasn`.

## Coverage

✅ = proven by a conformance fixture per ADR 0015 (externally sourced or
hand-authored from the specification with octet comments). ⚠️ = decode path
exists and is fuzzed, but no external fixture proves the field mapping yet.

| Layer | Item | Status | Evidence |
|---|---|---|---|
| NGAP-PDU framing | InitiatingMessage | ✅ | External NGSetupRequest fixture round-trip |
| NGAP-PDU framing | SuccessfulOutcome | ✅ | Hand-authored wrapper fixture (octet comments, X.691 CHOICE index 1); body kept raw |
| NGAP-PDU framing | UnsuccessfulOutcome | ✅ | Hand-authored wrapper fixture (CHOICE index 2); body kept raw |
| Typed decode | NGSetupRequest | ✅ | 78-byte external fixture; IE ids, RANNodeName content, and DefaultPagingDRX value asserted |
| Typed decode | InitialUEMessage | ⚠️ | Decode path compiled and fuzzed; no external fixture yet |
| Typed decode | NGSetupResponse / NGSetupFailure | ❌ | Intentionally not decoded in v0: without external fixtures, decoding them risks mislabeling peer messages. Surfaced as `Message::Unknown` with the body preserved raw. |

Dispatch is outcome-aware: procedure code 21 decodes as NGSetupRequest only
on an initiating message; the successful/unsuccessful outcomes of the same
procedure remain raw until fixtures exist for them.

## Encoding mode

- **Raw-preserving**: byte-exact `decode → encode` is proven for every
  fixture above; the original PDU bytes are preserved and re-emitted.
- **Canonical typed encode**: unsupported in v0 and rejected with an error.
  `rasn` 0.28's APER encoder does not reproduce the octet alignment of the
  external fixtures for the inner message types (and its output for those
  types does not survive its own decoder), so constructing new NGAP
  messages from typed values is out of scope until that is resolved
  upstream or replaced.

## Fixtures

- `NGSetupRequest`: 78-byte APER PDU captured from an independent
  `asn1c`-based implementation (libngap): GlobalRANNodeID, RANNodeName
  ("My little gNB"), SupportedTAList, DefaultPagingDRX(v64). Field-level
  content is asserted, not just the decoded type.
- Successful/unsuccessful outcome wrappers: hand-authored from
  TS 38.413 §9.2 and X.691 aligned-PER rules with octet-level comments.

## Fuzzing

`fuzz/fuzz_targets/decode_ngap.rs` with a seeded corpus, registered in
`.github/workflows/fuzz.yml` and exercised by the scheduled fuzz workflow.

## Out of scope (v0)

- Canonical (typed) encoding of any message.
- Typed decode of NGSetupResponse, NGSetupFailure, and all procedures other
  than the two listed above — preserved raw as `Message::Unknown`.
- UPER encoding.
- Semantic validation of IE values beyond structural decode.
