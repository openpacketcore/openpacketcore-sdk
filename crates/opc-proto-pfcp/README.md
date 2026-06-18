# opc-proto-pfcp

PFCP codec (3GPP TS 29.244) for the N4 reference point — **experimental**.

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
exact coverage and codec boundary.

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

## Reference

- 3GPP TS 29.244 — Packet Forwarding Control Plane protocol (N4/Sxa/Sxb)

## License

Apache-2.0. See [LICENSE](../../LICENSE).
