# opc-proto-ikev2

`opc-proto-ikev2` is an experimental IKEv2 codec scaffold for OpenPacketCore
untrusted-access work.

Current scope is intentionally narrow:

- IKEv2 fixed-header decode/encode over the shared `opc-protocol` traits;
- raw-preserving generic payload-chain walking for unencrypted payloads;
- unknown non-critical payload preservation, while unknown critical payloads
  always fail closed per RFC 7296;
- protected-payload boundary metadata for `SK` and `SKF` payloads without
  decrypting or choosing algorithms; and
- a caller-supplied `CryptoProvider` trait boundary for downstream SA state,
  authentication, decryption, padding removal, and key policy.

It does **not** provide an IKE SA state machine, EAP-AKA procedure, cookie or
retransmission policy, 3GPP ePDG profile validation, Child SA installation,
XFRM/IPsec programming, carrier acceptance evidence, or a production ePDG
control-plane stack. See [CONFORMANCE.md](CONFORMANCE.md) for the precise
evidence boundary and payload-chain parser plan.

## Minimal use

```rust
use opc_proto_ikev2::Message;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0, 0, 0, 0, 0, 0, 0, 0,
    40, 0x20, 34, 0x08,
    0, 0, 0, 0,
    0, 0, 0, 36,
    0, 0, 0, 8, 0x11, 0x22, 0x33, 0x44,
];
let (_tail, message) = Message::decode(&packet, DecodeContext::default())?;
assert_eq!(message.payloads().count(), 1);
# Ok::<(), opc_protocol::DecodeError>(())
```

## Verification

```bash
cargo check -p opc-proto-ikev2 --all-targets --all-features
cargo test -p opc-proto-ikev2 --all-features
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz list)
```
