# opc-proto-pfcp

PFCP codec (3GPP TS 29.244) for the N4 reference point, with **Production
Profile v1** available for the documented N4 codec and validation boundary.

## Status

- **Message layer**: spec-conformant header parsing (version, S/MP/FO flags,
  SEID, sequence, message priority) and the session-management message set
  (Heartbeat, Association Setup/Release, Session Establishment/Modification/
  Deletion/Report), with the header Length field honored and trailing bytes
  returned to the caller.
- **Raw IE layer**: generic TLV framing with byte-exact preservation of
  unknown and vendor-specific IEs (§8.1.1 enterprise-ID semantics).
- **Typed IE layer**: decode/encode for the session-management subset —
  Cause, Node ID, F-SEID, F-TEID, PDR/FAR/QER/URR IDs, Precedence, Apply
  Action, Source/Destination Interface, Network Instance, UE IP Address,
  Outer Header Creation/Removal, Recovery Time Stamp — plus grouped-IE
  recursion (Create PDR/FAR/QER/URR, PDI, Forwarding Parameters, Created
  PDR) with depth limits. Unknown IEs fall back to `TypedIe::Raw`. The
  typed layer canonicalizes spare bits and forward-compatibility trailing
  octets on re-encode; use the raw layer for byte-exact forwarding.

Conformance is proven against hand-authored spec-byte fixtures citing
TS 29.244 section numbers — see [CONFORMANCE.md](CONFORMANCE.md) for the
exact coverage, Production Profile v1 target, and codec boundary.

The production profile is scoped to N4 codec construction, typed decode/encode,
and semantic validation for Heartbeat, Association Setup/Release, Session
Establishment/Modification/Deletion, and Session Report procedures. It does not
claim PFCP UDP transport, SMF/UPF business logic, node selection, persistence,
charging policy, or high-availability control-plane behavior.

## Quick start

```rust
use opc_proto_pfcp::{heartbeat_request, OwnedMessage};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let msg = heartbeat_request(42);
    let mut buf = bytes::BytesMut::new();
    msg.encode(&mut buf, EncodeContext::default())?;

    let decoded = OwnedMessage::decode_owned(buf.freeze(), DecodeContext::default())?;
    assert_eq!(decoded.header.sequence_number, 42);
    Ok(())
}
```

Typed IE access goes through `opc_proto_pfcp::ie::TypedIe::decode` over the
raw `InformationElement` layer; see the crate documentation for the full API.

For the Production Profile v1 constructor and semantic-validation path, see
`examples/production_profile_v1.rs` and `tests/production_profile_v1.rs`. Those
fixtures construct Association Setup and Session Establishment messages through
typed APIs, encode/decode them, and validate the decoded messages without manual
raw IE construction.

## Reference

- 3GPP TS 29.244 — Packet Forwarding Control Plane protocol (N4/Sxa/Sxb)

## License

Apache-2.0. See [LICENSE](../../LICENSE).
