# opc-proto-ngap

NGAP (NG Application Protocol, 3GPP TS 38.413) v1 subset codec for
OpenPacketCore.

## Purpose

This crate provides the NGAP codec in the SDK, built on the `rasn` ASN.1 /
APER toolchain per ADR 0013. It currently covers:

- NGAP-PDU framing: initiating message, successful outcome, unsuccessful outcome.
- Fixture-proven typed decoding for `NGSetupRequest`.
- Structural typed dispatch for the first AMF N2 procedure subset:
  `NGSetupResponse`, `NGSetupFailure`, `InitialUEMessage`,
  `DownlinkNASTransport`, `UplinkNASTransport`,
  `InitialContextSetup{Request,Response,Failure}`,
  `PDUSessionResourceSetup{Request,Response}`,
  `PDUSessionResourceRelease{Command,Response}`,
  `UEContextRelease{Command,Complete}`, and `Paging`.
- Byte-exact raw-preserving round-trip at the NGAP-PDU level.

## Important caveat

`rasn` 0.28 decodes NGAP APER correctly but its encoder does not reproduce the
octet alignment used by independent APER implementations for the inner message
bodies. Because ADR 0015 requires byte-exact round-trips against spec-authored
fixtures, encoding is **raw-preserving only**: the message body captured
during decode is re-emitted byte-identically. Raw-preserving encode also
requires decoded raw bytes; constructing a typed PDU from scratch is rejected
until the underlying encoder issue is resolved.

## Regenerating

`src/generated.rs` is committed; cargo builds never run the generator. To
regenerate (requires Python 3.9+, `rasn-compiler` 0.16, and network access):

```bash
make generate-ngap
```

Inputs are fetched from Wireshark's ASN.1 dissector files at pinned commit
`d296f939b42891994714939384adc3deaef3f180` and patched to fix
`rasn-compiler` import emission. The output is deterministic for that commit.

## Conformance

See [CONFORMANCE.md](CONFORMANCE.md) for the exact coverage matrix and known
gaps.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
