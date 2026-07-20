# opc-proto-gtpu

GTPv1-U codec for OpenPacketCore user-plane packets.

## Purpose

`opc-proto-gtpu` implements the GTP-U framing boundary from 3GPP TS 29.281
Release 18. It is aimed at safe decode/encode of user-plane GTPv1-U packets,
including optional fields, extension-header chains, and the 5G PDU Session
Container extension. It also provides typed path/tunnel-management codecs for
Echo Request/Response, Error Indication, Supported Extension Headers
Notification, and End Marker.

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
- `PduSessionContainer` decodes and fallibly encodes the base 5G PDU Session
  Container QFI/PPI/RQI subset. `new_downlink` and `new_uplink` are the
  validated construction paths. Reserved PDU types, oversized QFI/PPI values,
  direction-incompatible fields, and flags requiring unmodelled TS 38.415
  conditional fields fail closed rather than being masked or discarded.
- `GtpuExtensionChain` summarizes and validates raw extension chains and can
  build a chain containing a single PDU Session Container. Generic
  raw-preserving encode retains accepted extension bytes exactly. Typed End
  Marker canonical encode instead rebuilds the known container from its typed
  value, clears its sender-spare bits, places it first, and retains unrelated
  optional unknown headers in their received relative order.
- `GtpuExtensionHeaderType` exposes the TS 29.281 comprehension class and
  endpoint/intermediate requirements instead of treating every unknown header
  identically. `first_unsupported_required_extension` provides an
  allocation-free pre-decap check on borrowed and owned messages.
- `GtpuControlMessage` decodes and canonically encodes the typed signalling
  procedures. `GtpuEchoResponse::for_request` copies the request sequence and
  always emits the required `Recovery=0`.
- `GtpuErrorIndication` carries a redaction-safe typed TEID and peer address,
  and can include the optional triggering UDP source-port extension header.
- Unknown TLV IEs follow `DecodeContext::unknown_ie_policy`; preserved values
  round-trip while their `Debug` output reports lengths only. Unknown TV IEs
  fail closed because their boundary cannot be inferred safely.
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

Typed Echo handling is a separate, explicit boundary:

```rust
use opc_proto_gtpu::{GtpuControlMessage, GtpuEchoResponse};
use opc_protocol::{DecodeContext, EncodeContext};

let request = [
    0x32, 0x01, 0x00, 0x04, // v1/PT/S, Echo Request, length
    0, 0, 0, 0,             // TEID = 0
    0x12, 0x34, 0, 0,       // sequence and receiver-ignored fields
];
let request = GtpuControlMessage::decode_datagram(&request, DecodeContext::conservative())?;
let GtpuControlMessage::EchoRequest(request) = request else {
    return Err("not an Echo Request".into());
};
let response = GtpuControlMessage::EchoResponse(GtpuEchoResponse::for_request(&request));
let wire = response.to_bytes(EncodeContext::default())?;
assert_eq!(wire[1], 2);
assert_eq!(&wire[12..], &[14, 0]); // mandatory canonical Recovery=0
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Compatibility and migration

This codec slice intentionally tightens three public boundaries:

- When the GTP-U E flag is clear, `GtpuHeader::next_ext_type` is now `None`
  even if the receiver-ignored optional-header octet is non-zero. Code that
  needs the received octet for byte-exact forwarding must use
  `GtpuHeader::raw_next_ext_type` together with raw-preserving encode.
- `PduSessionContainer::encode` now returns
  `Result<Vec<u8>, PduSessionContainerError>` instead of `Vec<u8>`. Callers
  should use `PduSessionContainer::new_downlink` or `new_uplink`, then propagate
  `encode()?`; directly constructed public models are validated again at
  encode. `GtpuErrorIndication::with_triggering_udp_source_port` is likewise
  fallible because it now refuses an inconsistent retained chain rather than
  dropping it. Both that mutator and
  `GtpuEndMarker::with_pdu_session_container` retain unrelated optional unknown
  extension headers. End Marker mutation and typed canonical encode now place
  the PDU Session Container first and rebuild it from the typed value; callers
  that require byte-exact forwarding of an accepted non-canonical container
  must remain on the generic raw-preserving boundary.
- Public error matches must account for the reason-bearing
  `GtpuExtensionChainMalformedReason::InvalidPduSessionContainer { reason }`,
  `GtpuExtensionChainError::InvalidPduSessionContainer { reason }`, and the new
  `GtpuControlCodecErrorCode` malformed-chain, malformed-PDU, and duplicate-PDU
  variants. Nested `PduSessionContainerError` values are stable,
  machine-readable, and contain no packet values.

## Relationships

This crate depends on `opc-protocol` for codec contracts and structured errors.
Control-plane GTPv2-C is intentionally separate in `opc-proto-gtpv2c`.

## Status And Limits

The documented GTPv1-U framing and PDU Session Container surface is a
conditional codec candidate, not a current production approval.
`CONFORMANCE.md` records the TS 29.281 baseline, supported features, fuzzing,
and explicit exclusions. Typed control codecs do not provide UDP socket access,
peer admission, response rate limiting, tunnel lookup, End Marker policy, or
Linux/eBPF control-datagram integration. Those runtime/backend parts of issue
#341 remain open and are required before a production dataplane claim.

Canonical encode normalizes header bits where appropriate. Raw-preserving encode
uses `EncodeContext { raw_preserving: true, .. }` and is the mode to use when
byte-exact forwarding of accepted input matters.

The §5.1 spare bit has two explicit receive profiles. Generic `GtpuMessage`
`Strict`/`ProcedureAware` decode requires the sender-canonical zero value;
generic structural decode followed by raw-preserving encode retains the
received bit, and generic canonical encode clears it. Typed
`GtpuControlMessage` NETWORK receive ignores the bit under conservative,
`Strict`, and `ProcedureAware` contexts as the specification requires, while
typed canonical output always clears it.

## Control-codec boundaries

- Received Recovery counter values and the sequence fields of Error Indication
  and Supported Extension Headers Notification are intentionally ignored as
  TS 29.281 directs; canonical encoding emits zero for those fields.
- Signalling IE ordering, mandatory/singleton cardinality, IPv4/IPv6 peer
  address lengths, extension-list uniqueness (with an empty list permitted by
  TS 29.281 §8.5), configured message/IE bounds,
  and procedure header flags/TEIDs fail closed.
- `GtpuControlMessage::from_message` is itself a validated boundary: it
  reapplies version/PT, declared-length and optional-header contracts together
  with configured message, extension-depth, extension-count, and IE limits.
  A generic frame decoded under a looser context cannot bypass those checks.
- The PDU Session Container extension is accepted on End Marker for applicable
  5GS forwarding and remains inspectable through `GtpuExtensionChain`; it is
  rejected on control procedures where it is not applicable.
  `GtpuEndMarker::with_pdu_session_container` provides the corresponding typed,
  procedure-safe build path. Receive ignores the container's permitted spare
  bits. Typed canonical encoding clears those bits, places the container first
  in the extension chain, and preserves all unrelated optional unknown headers
  deterministically. Generic raw-preserving encoding remains byte-exact.
- An unsupported comprehension-required extension produces the stable
  `gtpu_control_unsupported_required_extension` error with only its type. This
  is sufficient for a bounded downstream notification plan; the codec does not
  send traffic or decide amplification policy.
- Standardized Release 18 extension types are not treated as unknown merely
  because their comprehension bits are optional. G-PDU-only types, including
  the PDU Set Information Container, fail with
  `gtpu_control_unexpected_extension` on typed signalling procedures.
- Tunnel Status (§7.3.3 and §8.7) is outside this codec slice.
- TEID/address/private values are available through explicit accessors for
  protocol work, but typed `Debug`/errors redact them.

## Verification

```bash
cargo check -p opc-proto-gtpu --all-targets --all-features
cargo test -p opc-proto-gtpu --all-features
(cd crates/opc-proto-gtpu && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
