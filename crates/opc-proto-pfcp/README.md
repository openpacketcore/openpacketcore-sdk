# opc-proto-pfcp

PFCP codec for the 3GPP TS 29.244 N4 control-plane boundary.

## Purpose

`opc-proto-pfcp` provides PFCP message framing, raw IE preservation, typed IE
decode/encode for the session-management subset, and Production Profile v1
semantic validation for an N4 codec boundary.

It does not implement PFCP UDP transport, retransmission, SMF/UPF business
logic, node selection, rule persistence, charging policy, or high-availability
control-plane behavior.

## API Shape

- `Message<'a>` and `OwnedMessage` are the borrowed and owned PFCP messages.
- `Header` exposes version, S/MP/FO flags, SEID, sequence number, message
  priority, and length fields.
- `InformationElement` is the raw TLV layer. Unknown and vendor-specific IEs
  are preserved byte-exactly here.
- `ie::TypedIe` decodes known session-management IEs and falls back to
  `TypedIe::Raw` for unsupported IEs.
- `ie` re-exports grouped and simple typed IEs including `CreatePdr`, `Pdi`,
  `CreateFar`, `CreateQer`, `CreateUrr`, `UsageReport`, `Cause`, `NodeId`,
  `FSeid`, `FTeid`, `PdrId`, `FarId`, `QerId`, `UrrId`, `ApplyAction`,
  `NetworkInstance`, `UeIpAddress`, `OuterHeaderCreation`, and
  `RecoveryTimeStamp`.
- `profile::validate_production_v1` and
  `OwnedMessage::validate_production_v1` enforce profile-level semantics above
  structural decode.
- Root constructors build profile-owned messages such as
  `heartbeat_request_with_recovery`, `association_setup_request`,
  `session_establishment_request`, `session_modification_request_with_operations`,
  `session_deletion_request`, and `session_report_request_with_report_type`.

## Example

```rust
use opc_proto_pfcp::{heartbeat_request_with_recovery, ie::RecoveryTimeStamp, OwnedMessage};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};

let msg = heartbeat_request_with_recovery(42, RecoveryTimeStamp { seconds: 1 })?;
let mut buf = bytes::BytesMut::new();
msg.encode(&mut buf, EncodeContext::default())?;

let decoded = OwnedMessage::decode_owned(buf.freeze(), DecodeContext::default())?;
decoded.validate_production_v1(DecodeContext::default())?;
assert_eq!(decoded.header.sequence_number, 42);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Relationships

This crate depends on `opc-protocol` for codec traits and structured errors.
It is the PFCP/N4 mechanism crate; higher-level SMF and UPF crates own product
state and policy.

## Status And Limits

Production Profile v1 is production-ready for the documented N4 codec,
construction, typed decode/encode, and semantic validation boundary. The raw
layer is the byte-exact forwarding surface. The typed layer may canonicalize
spare bits and discard future extension octets it does not model, so use raw
IEs for arbitrary peer-traffic forwarding.

See [CONFORMANCE.md](CONFORMANCE.md) for the exact IE families, procedures,
semantic rules, fuzzing, and remaining codec boundary.

## Roadmap

- Add remaining TS 29.244 simple and grouped IEs as profile needs require.
- Broaden Session Report semantics beyond the currently decoded member set.
- Keep transport, retransmission, persistence, policy, and node lifecycle out
  of this crate.

## Verification

```bash
cargo check -p opc-proto-pfcp --all-targets --all-features
cargo test -p opc-proto-pfcp --all-features
cargo run -p opc-proto-pfcp --example production_profile_v1
(cd crates/opc-proto-pfcp && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
