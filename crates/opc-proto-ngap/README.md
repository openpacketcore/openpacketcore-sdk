# opc-proto-ngap

Experimental NGAP APER codec subset for OpenPacketCore.

## Purpose

`opc-proto-ngap` provides a Release 18 NGAP-PDU framing and typed-dispatch
surface built on `rasn`. The current scope is the v1 subset documented in
`CONFORMANCE.md`.

It is not a full NGAP implementation and does not provide SCTP transport, AMF
or gNB procedure state, NAS handling, or semantic validation of NGAP IE values.

## API Shape

- `Pdu` stores the decoded PDU kind plus the raw bytes needed for byte-exact
  re-encode.
- `PduKind` distinguishes initiating, successful, and unsuccessful NGAP-PDU
  wrappers and exposes procedure code and criticality.
- `Message` is the supported typed message-body subset with `Unknown(Bytes)`
  fallback for unsupported procedure/outcome combinations.
- `messages` re-exports the generated message body types used in `Message`.
- `Criticality` and `ProcedureCode` are re-exported from generated ASN.1 types.
- `decode` and `Pdu::decode` parse one APER PDU. `Pdu::decode_owned` rejects
  trailing bytes after a complete PDU.
- `encode` and the `Encode` implementation support raw-preserving output only.

## Usage

```rust,no_run
use bytes::{Bytes, BytesMut};
use opc_proto_ngap::{Message, Pdu};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};

let packet = Bytes::from_static(&[]); // replace with one complete APER NGAP-PDU
let pdu = Pdu::decode_owned(packet, DecodeContext::default())?;

if let opc_proto_ngap::PduKind::Initiating { message, .. } = &pdu.kind {
    if let Message::NgSetupRequest(req) = message {
        let _ie_count = req.protocol_ies.0.len();
    }
}

let mut out = BytesMut::new();
pdu.encode(
    &mut out,
    EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    },
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status And Limits

The crate is experimental and `publish = false`. Fixture-proven coverage exists
for NGAP-PDU framing and `NGSetupRequest`. Several first-CNF AMF N2 messages
have structural typed dispatch with hand-authored APER fixtures, but not yet
external field-level fixtures.

Canonical typed encode is intentionally unsupported. `rasn` 0.28 decodes the
covered APER fixtures, but its encoder does not reproduce the byte alignment
required by the SDK's byte-exact fixture policy for inner message bodies. For
now, encode requires raw bytes captured during decode and
`EncodeContext::raw_preserving = true`.

## Generated types

`src/generated.rs` is committed. Cargo builds never run the generator. To
regenerate it:

```bash
make generate-ngap
```

The generator requires Python 3.9+, `rasn-compiler` 0.16, and network access.
Inputs are fetched from Wireshark ASN.1 files at pinned commit
`d296f939b42891994714939384adc3deaef3f180`; output is deterministic for that
commit.

## Roadmap

- Resolve or work around the APER encoder alignment issue before enabling
  constructed typed NGAP messages.
- Add external field-level fixtures for the structural typed-dispatch subset.
- Expand procedure coverage only with fixture evidence and raw-preserving
  regression tests.
- Add semantic validation in consuming AMF/N2 code, not in this framing crate.

## Verification

```bash
cargo check -p opc-proto-ngap --all-targets --all-features
cargo test -p opc-proto-ngap --all-features
(cd crates/opc-proto-ngap && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
