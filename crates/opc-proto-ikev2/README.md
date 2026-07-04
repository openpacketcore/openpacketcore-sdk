# opc-proto-ikev2

`opc-proto-ikev2` is an experimental IKEv2 codec scaffold for OpenPacketCore
untrusted-access work.

Current scope is intentionally narrow:

- IKEv2 fixed-header decode/encode over the shared `opc-protocol` traits;
- raw-preserving generic payload-chain walking for unencrypted payloads;
- unknown non-critical payload preservation, while unknown critical payloads
  always fail closed per RFC 7296;
- protected-payload boundary metadata for `SK` and `SKF` payloads without
  parsing ciphertext as cleartext;
- RFC 7383 `SKF` fragment-number/total-fragments structural helpers plus
  bounded reassembly for already-decrypted fragment cleartext;
- a caller-supplied `CryptoProvider` trait boundary for downstream SA state and
  key policy;
- an SA_INIT-derived AES-GCM-16 `SK` payload opener for callers that already
  selected an IKE SA profile, derived key material, and packet direction;
- a matching SA_INIT-derived AES-GCM-16 `SK` sealing helper for caller-built
  responder payloads;
- typed IKE_AUTH cleartext payload views/builders for IDi/IDr, AUTH, CERT,
  CERTREQ, EAP, CP, SA, TSi/TSr, Notify, and Delete payload chains;
- transcript-bound shared-key AUTH MIC computation and verification for
  EAP/AAA-supplied keying material;
- transcript-bound signature AUTH computation and verification for RSA Digital
  Signature (method 1, SHA-256) and RFC 7427 Digital Signature (method 14,
  RSA-SHA256 and ECDSA-P256/P384) against a caller-supplied pinned SPKI or the
  SubjectPublicKeyInfo of a caller-trusted X.509 certificate, without any
  certificate-chain validation;
- RFC 5998 `EAP_ONLY_AUTHENTICATION` notify decode and emission helpers; and
- product-neutral Child SA proposal/traffic-selector selection intent plus
  response SA/TS payload builders; and
- RFC 7296 NAT-D hash computation and semantic evaluation from typed Notify
  payloads and caller-supplied observed UDP endpoints.

It does **not** provide an IKE SA state machine, EAP-AKA procedure, cookie or
retransmission policy, NAT traversal policy, 3GPP ePDG profile validation,
Child SA lifecycle management, XFRM/IPsec programming, carrier acceptance
evidence, or a production ePDG control-plane stack. See
[CONFORMANCE.md](CONFORMANCE.md) for the precise evidence boundary.

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
cargo clippy -p opc-proto-ikev2 --all-targets -- -D warnings
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz list)
```
