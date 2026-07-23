# opc-proto-ngap

Experimental NGAP APER codec subset for OpenPacketCore.

## Purpose

`opc-proto-ngap` provides a Release 18 NGAP-PDU framing and typed-dispatch
surface built on `rasn`. The current scope is the v1 subset documented in
`CONFORMANCE.md`.

It is not a full NGAP implementation and does not provide SCTP transport, AMF
or gNB procedure state, NAS handling, or semantic validation of NGAP IE
contents. The typed boundary does validate top-level identifiers, criticality,
cardinality, and configured decode policies.

## API Shape

- `Pdu` stores the policy-filtered decoded PDU kind plus the immutable raw bytes
  needed for byte-exact re-encode.
- `PduKind` distinguishes initiating, successful, and unsuccessful NGAP-PDU
  wrappers and exposes procedure code and criticality.
- `Message` is the supported typed message-body subset with `Unknown(Bytes)`
  fallback for unsupported procedure/outcome combinations.
- `messages` re-exports the generated message body types used in `Message`.
- `Criticality` and `ProcedureCode` are re-exported from generated ASN.1 types.
- `decode` and `Pdu::decode` parse one APER PDU. `Pdu::decode_owned` rejects
  trailing bytes after a complete PDU.
- `encode` and the `Encode` implementation support raw-preserving output only.

## Typed IE policy boundary

Each currently typed procedure/outcome has Release-18 metadata for its known
top-level protocol-IE identifiers, required wire criticality, and
singleton/repeatable cardinality. Before `rasn` materializes a typed
`ProtocolIE-Container`, the decoder reads its exact aligned-PER 16-bit count,
applies `DecodeContext::max_ies`, and rejects a count that cannot fit in the
available message bytes.

The remaining `DecodeContext` policies apply as follows:

- `UnknownIePolicy::Preserve` retains an unknown entry and its opaque raw value
  in the typed generated container.
- `UnknownIePolicy::Drop` removes unknown entries from the typed container.
- `UnknownIePolicy::Reject` rejects every unknown entry. A `reject`-criticality
  entry uses the stable `UnknownCriticalIe` code; `ignore` and `notify` use a
  value-free structural error.
- Strict and procedure-aware validation always reject an unknown
  `reject`-criticality IE, including when the selected unknown policy is
  `Preserve` or `Drop`. Structural validation leaves that choice to the
  unknown-IE policy.
- `DuplicateIePolicy::{First,Last,Reject}` acts on singleton identifiers.
  Repeatable identifiers retain every occurrence. All top-level IEs in the
  current typed subset are singleton; list-valued IEs carry repetition inside
  their value.
- Known identifiers must carry their TS 38.413 criticality. A mismatch fails
  with a stable, value-free structural error.

Filtering changes only the typed view. `Pdu::raw` is never rewritten, and the
only supported encoder is raw-preserving. Consequently, encoding a PDU decoded
with `Drop`, `First`, or `Last` emits the original wire entries, not a
sanitized reconstruction. A consumer that needs a sanitized canonical message
must wait for or provide a canonical typed encoder; it must not treat
raw-preserving encode as typed-view serialization.

`Debug` for `Pdu`, `PduKind`, and `Message` reports only outcome/procedure
metadata, lengths, variant names, and IE counts. It never renders raw PDU
bytes, opaque IE values, or embedded NAS payloads.

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
