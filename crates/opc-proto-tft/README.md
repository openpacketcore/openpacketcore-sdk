# opc-proto-tft

`opc-proto-tft` is the canonical, product-neutral 3GPP Traffic Flow Template
(TFT) model and value-part codec for the OpenPacketCore SDK. GTPv2-C Bearer TFT
IEs and IKEv2 TFT Notify payloads use this crate instead of maintaining
transport-specific parsers.

## Scope

The implementation covers the complete TS 24.008 V18.8.0 clause 10.5.6.12
value format:

- all seven defined TFT operations, the E bit, full-filter and identifier-only
  lists, directions, identifiers, precedence, and packet-filter lengths;
- every Release 18 component type, including IPv4/IPv6 addresses, protocol,
  ports and ranges, SPI, ToS/traffic class, flow label, MAC, VLAN, and
  EtherType components;
- Authorization Token, Flow Identifier, Packet Filter Identifier, and
  order-preserving unknown parameter handling; and
- the TS 23.060 V18.0.0 packet-filter combination rules.

This crate encodes and decodes only the TFT **value part**, beginning with
octet 3 of the TS 24.008 type-4 IE. It does not include the TS 24.008 IEI or
outer length octet. A GTPv2-C IE codec owns its GTP IE header. An IKEv2 TFT
Notify codec owns its one-octet 3GPP inner length field.

## Example

```rust
use bytes::BytesMut;
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection,
    PacketFilterIdentifier, TrafficFlowTemplate,
};

let identifier = PacketFilterIdentifier::new(1)?;
let filter = PacketFilter::new(
    identifier,
    PacketFilterDirection::Bidirectional,
    10,
    vec![
        PacketFilterComponent::ProtocolIdentifierNextHeader(17),
        PacketFilterComponent::SingleRemotePort(4500),
    ],
)?;
let tft = TrafficFlowTemplate::create_new(vec![filter], Vec::new())?;

let mut value_bytes = BytesMut::new();
tft.encode_value(&mut value_bytes)?;
let decoded = TrafficFlowTemplate::decode_value(&value_bytes)?;
assert_eq!(decoded, tft);
# Ok::<(), opc_proto_tft::TftError>(())
```

Use `decode_value_with_context` when an application needs a smaller message or
element budget than the normative 255-octet maximum.

## Validation guarantees

Decode is strict, bounded, and fail-closed. It rejects malformed lengths,
truncation, trailing bytes when the E bit is clear, reserved operations and
components, non-zero spare bits, empty/oversized lists, duplicate identifiers,
duplicate precedence values, duplicate or conflicting components, invalid
ranges and prefixes, and invalid parameter structure. Encoding validates the
same invariants before appending anything to the destination.

Unknown packet-filter component identifiers are reserved by TS 24.008 and are
rejected. Unsupported parameter identifiers are extensible in TS 24.008 and
are preserved in order for byte-stable forwarding. Contents following the
`Ignore this IE` operation are preserved but deliberately not interpreted.

`Debug` and error values do not print addresses, ports, SPIs, MAC addresses,
authorization tokens, unknown contents, or source bytes. Errors expose a
stable classification and, for wire failures, a value-relative offset.

State-dependent bearer rules remain at the procedure boundary. Examples are
whether an existing TFT is present, whether a resulting dedicated-bearer TFT
has an uplink filter, and whether an identifier or precedence collides with a
previously installed TFT. See [CONFORMANCE.md](CONFORMANCE.md) for the exact
boundary and evidence.

## Verification

```bash
cargo test --locked -p opc-proto-tft --all-features
cargo clippy --locked -p opc-proto-tft --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked -p opc-proto-tft --all-features --no-deps
(cd crates/opc-proto-tft && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
