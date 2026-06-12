# opc-proto-nas

NAS-5GS (3GPP TS 24.501) codec for OpenPacketCore — **v1, experimental**.

## Purpose

A deliberately narrow but growing NAS codec built on the
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
  MAC/EUI-64 length-validated with raw preservation.
- **BCD digit unpacking** for PLMN (MCC/MNC, 2- and 3-digit MNC), routing
  indicator, and IMEI/IMEISV, including filler-nibble and odd-count cases.
- **IE-level parsing** for Registration Request (§8.2.6) and Registration
  Accept (§8.2.7): mandatory fields are structured, optional IEs are
  iterated and preserved raw so unknown IEs round-trip byte-exactly.
- **Message-type registries** for 5GMM and 5GSM (names and code points).

Unparsed bodies and unparsed identity types are preserved raw, so
decode → encode is byte-exact (asserted by tests, integration tests, and a
fuzz-adjacent quickcheck property).

See [CONFORMANCE.md](CONFORMANCE.md) for the precise boundary. Structured
parsing of other 5GMM/5GSM messages is future work.

## Example

```rust
use opc_proto_nas::{MmMessageType, NasMessage, RegistrationRequest};
use opc_protocol::{BorrowDecode, DecodeContext};

let frame = [0x7E, 0x00, 0x41, 0x01, 0x00, 0x0A,
             0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3,
             0x00, 0x00, 0x13, 0x57];
let (rest, msg) = NasMessage::decode(&frame, DecodeContext::default())?;
assert!(rest.is_empty());
if let NasMessage::PlainMm(m) = &msg {
    assert_eq!(
        MmMessageType::from_u8(m.message_type),
        Some(MmMessageType::RegistrationRequest)
    );
    let (_, req) = RegistrationRequest::decode_body(&m.body, DecodeContext::default())?;
    assert!(req.follow_on_request == false);
}
# Ok::<(), opc_protocol::DecodeError>(())
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
