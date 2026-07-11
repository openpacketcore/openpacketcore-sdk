# opc-proto-gtpu

GTPv1-U codec for OpenPacketCore user-plane packets.

## Purpose

`opc-proto-gtpu` implements the GTP-U framing boundary from 3GPP TS 29.281
Release 18. It is aimed at safe decode/encode of user-plane GTPv1-U packets,
including optional fields, extension-header chains, and the 5G PDU Session
Container extension.

It does not implement GTPv0, GTP-C, tunnel lifecycle, UDP sockets, packet
scheduling, or user-plane forwarding policy.

## API Shape

- `GtpuMessage<'a>` is the borrowed zero-copy packet view.
- `OwnedGtpuMessage` stores raw extension headers and payload as `bytes::Bytes`
  slices for async or thread handoff.
- `GtpuHeader` exposes fixed-header fields, optional sequence/N-PDU fields, and
  raw optional-field values for raw-preserving re-encode.
- `GtpuMessage::extensions()` and `OwnedGtpuMessage::extensions()` return a
  lazy `GtpuExtensionHeaderIterator`.
- `PduSessionContainer` decodes and encodes the 5G PDU Session Container QFI,
  PPI, and RQI fields.
- `GtpuExtensionChain` summarizes and validates raw extension chains and can
  build a chain containing a single PDU Session Container.
- `GtpuMessage` implements `BorrowDecode`, `Encode`, and `ToOwnedPdu`;
  `OwnedGtpuMessage` implements `OwnedDecode` and `Encode`.

## Example

```rust
use opc_proto_gtpu::GtpuMessage;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [
    0x30, 0xff, 0x00, 0x04, // flags, G-PDU type, payload length
    0x00, 0x00, 0x00, 0x01, // TEID
    0xde, 0xad, 0xbe, 0xef, // payload
];

let (tail, msg) = GtpuMessage::decode(&packet, DecodeContext::default())?;
assert!(tail.is_empty());
assert_eq!(msg.header.teid, 1);
assert_eq!(msg.payload, &[0xde, 0xad, 0xbe, 0xef]);
# Ok::<(), opc_protocol::DecodeError>(())
```

## Relationships

This crate depends on `opc-protocol` for codec contracts and structured errors.
Control-plane GTPv2-C is intentionally separate in `opc-proto-gtpv2c`.

## Status And Limits

The documented GTPv1-U framing and PDU Session Container surface is a
conditional codec candidate, not a current production approval.
`CONFORMANCE.md` records the TS 29.281 baseline, supported features, fuzzing,
and explicit exclusions. A broader maturity claim still requires redaction-safe
payload diagnostics, distinct unknown-extension drop/preserve behavior, and
independently sourced maximum-boundary and unknown-extension fixtures.

Canonical encode normalizes header bits where appropriate. Raw-preserving encode
uses `EncodeContext { raw_preserving: true, .. }` and is the mode to use when
byte-exact forwarding of accepted input matters.

## Roadmap

- Add typed extension headers only when a downstream profile needs them.
- Keep expanding fixture and fuzz corpora for malformed extension chains and
  payload-boundary cases.
- Keep tunnel management, transport, and forwarding policy outside this codec
  crate.

## Verification

```bash
cargo check -p opc-proto-gtpu --all-targets --all-features
cargo test -p opc-proto-gtpu --all-features
(cd crates/opc-proto-gtpu && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
