# opc-proto-ngap

NGAP (NG Application Protocol, 3GPP TS 38.413) v0 codec for OpenPacketCore.

## Purpose

This crate provides the first NGAP codec in the SDK, built on the `rasn`
ASN.1 / APER toolchain per ADR 0013. It currently covers:

- NGAP-PDU framing: initiating message, successful outcome, unsuccessful outcome.
- Typed decoding of the v0 message subset:
  - `NGSetupRequest`
  - `NGSetupResponse`
  - `NGSetupFailure`
  - `InitialUEMessage`
- Byte-exact raw-preserving round-trip at the NGAP-PDU level.

## Important caveat

`rasn` 0.28 decodes NGAP APER correctly but its encoder does not reproduce the
octet alignment used by independent APER implementations for the inner message
bodies. Because ADR 0015 requires byte-exact round-trips against spec-authored
fixtures, v0 encoding is **raw-preserving only**: the message body captured
during decode is re-emitted byte-identically inside a freshly encoded NGAP-PDU
wrapper. A non-raw-preserving typed encode will return an error until the
underlying encoder issue is resolved.

## Regenerating

`src/generated.rs` is committed; cargo builds never run the generator. To
regenerate (requires Python 3.9+, `rasn-compiler` 0.16, and network access):

```bash
make generate-ngap
```

Inputs are fetched from Wireshark's ASN.1 dissector files and patched to fix
`rasn-compiler` import emission. The output is deterministic for a given
Wireshark Git SHA.

## Conformance

See [CONFORMANCE.md](CONFORMANCE.md) for the exact coverage matrix and known
gaps.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
