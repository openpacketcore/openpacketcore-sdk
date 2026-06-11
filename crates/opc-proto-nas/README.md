# opc-proto-nas

NAS-5GS (3GPP TS 24.501) codec for OpenPacketCore — **v0, experimental**.

## Purpose

The deliberately narrow first slice of NAS support, built on the
[`opc-protocol`](../opc-protocol/) zero-copy codec framework:

- **Plain 5GMM headers** (EPD `0x7E`, security header type 0): security
  header type, message type, raw body.
- **5GSM headers** (EPD `0x2E`): PDU session identity, PTI, message type,
  raw body.
- **Security-protected envelope recognition** (security header types 1–4):
  MAC and sequence number are framed but **never verified or deciphered** —
  NAS security is out of scope for this crate.
- **5GS mobile identity decoding** (§9.11.3.4): SUCI (IMSI and NAI formats,
  no de-concealment) and 5G-GUTI structured views; IMEI/IMEISV/5G-S-TMSI/
  MAC/EUI-64 length-validated with raw preservation. Chosen first because
  subscriber-identity awareness is what `opc-redaction` and logging
  boundaries need.
- **Message-type registries** for 5GMM and 5GSM (names and code points).

Message bodies and unparsed identity types are preserved raw, so
decode → encode is byte-exact (asserted by tests and a fuzz-adjacent
quickcheck property).

See [CONFORMANCE.md](CONFORMANCE.md) for the precise v0 boundary. IE-level
parsing of message bodies (Registration Request and friends) is v1 scope.

## Example

```rust
use opc_proto_nas::{MmMessageType, NasMessage};
use opc_protocol::{BorrowDecode, DecodeContext};

let frame = [0x7E, 0x00, 0x41]; // plain 5GMM Registration Request
let (rest, msg) = NasMessage::decode(&frame, DecodeContext::default())?;
assert!(rest.is_empty());
if let NasMessage::PlainMm(m) = &msg {
    assert_eq!(
        MmMessageType::from_u8(m.message_type),
        Some(MmMessageType::RegistrationRequest)
    );
}
# Ok::<(), opc_protocol::DecodeError>(())
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
