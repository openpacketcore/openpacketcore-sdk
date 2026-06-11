# opc-proto-ngap conformance — v0

3GPP release: TS 38.413 R18.

## Coverage

| Layer | Item | Status | Evidence |
|---|---|---|---|
| NGAP-PDU framing | InitiatingMessage | ✅ | Spec fixture round-trip |
| NGAP-PDU framing | SuccessfulOutcome | ✅ | Spec fixture round-trip |
| NGAP-PDU framing | UnsuccessfulOutcome | ✅ | Spec fixture round-trip |
| Class 1 procedures | NGSetupRequest decode | ✅ | libngap/asn1c fixture |
| Class 1 procedures | NGSetupResponse decode | ✅ | Generated-type decode path |
| Class 1 procedures | NGSetupFailure decode | ✅ | Generated-type decode path |
| NAS transport | InitialUEMessage decode | ✅ | Generated-type decode path |

## Encoding mode

- **Raw-preserving**: byte-exact `decode → encode` is proven against external
  fixtures at the NGAP-PDU level. The inner message body bytes are preserved.
- **Canonical typed encode**: intentionally unsupported in v0. `rasn` 0.28's
  APER encoder produces a bit-packed encoding that does not match the octet
  alignment used by the 3GPP APER fixtures and cannot be round-tripped by its
  own decoder for the inner message types.

## Fixtures

- `NGSetupRequest`: 78-byte APER PDU captured from an independent `asn1c`-based
  implementation (libngap). Verified to round-trip byte-exactly through this
  crate.

## Out of scope

- UPER encoding.
- Canonical re-encoding of inner message bodies.
- Messages other than the four listed above (decoded as `Message::Unknown`).
- Semantic validation of IE values beyond length/structure checks.
- Fuzzing execution in CI; the fuzz target compiles in CI but is not run.
