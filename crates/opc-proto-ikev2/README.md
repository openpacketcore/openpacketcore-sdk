# opc-proto-ikev2

Experimental IKEv2 mechanism scaffold for OpenPacketCore untrusted-access work.

## Purpose

`opc-proto-ikev2` covers transport-neutral IKEv2 wire mechanisms that are safe
to expose as SDK primitives today: header decode/encode, unencrypted payload
walking, protected-payload boundaries, selected SA_INIT and IKE_AUTH helpers,
NAT detection, NAT-T datagram classification, and product-neutral Child SA
negotiation intent.

It does not implement an IKE SA state machine, EAP-AKA, retransmission policy,
cookie policy, Child SA lifecycle, XFRM/IPsec programming, 3GPP ePDG profile
validation, carrier acceptance evidence, or a production ePDG control-plane
stack.

## API Shape

- `Message<'a>` and `OwnedMessage` provide borrowed and owned IKEv2 messages.
- `header` exposes `Header`, `HeaderFlags`, `decode_header`, and
  `encode_header`.
- `payload` exposes `PayloadChain`, `RawPayload`, `RawPayloadIterator`,
  `PayloadType`, and `validate_payload_chain`.
- `crypto` defines the caller-supplied `CryptoProvider` boundary and protected
  payload open result types.
- `sa_init` and `sa_init_crypto` provide typed SA/KE/Nonce/Notify helpers,
  SA_INIT response builders, Diffie-Hellman group/profile types, and IKE/Child
  SA key-material derivation.
- `protected_payload_crypto` provides caller-keyed AES-GCM-16 `SK` open/seal
  helpers for already-derived SA_INIT key material.
- `ike_auth` and `ike_auth_signature` provide cleartext IKE_AUTH payload
  helpers, shared-key AUTH MIC helpers, signature AUTH helpers, and Child SA
  selector/proposal helpers.
- `device_identity` validates and builds TS 24.302 DEVICE_IDENTITY requests and
  responses using the redaction-safe exact-15-digit `Imei15` and `Imeisv`
  types. TBCD decoding preserves the received fifteenth IMEI digit (including
  a spare zero or non-Luhn digit) and enforces the terminal filler nibble.
- `fragmentation`, `notify`, `nat_detection`, `nat_traversal`, and `exchange`
  expose RFC-specific mechanism helpers without owning product state.

## Example

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

## Features

- `rsa-signing` enables RSA private-key signing for IKE_AUTH methods 1 and 14.
  It is off by default; RSA verification is still available in default builds.
- `testkit` exposes deterministic fixture builders for tests and downstream
  harnesses.

## Status And Limits

The crate is experimental and `publish = false`. It has structural coverage and
targeted crypto/helper tests for the documented scaffold, but it is not a full
IKEv2 implementation. Certificate-chain, validity-period, name, and key-usage
validation are caller responsibilities when using signature AUTH helpers.

DEVICE_IDENTITY carries equipment identity only; it does not define or weaken
IKE authentication. Emergency procedures continue to use the ordinary RFC 7296
method-2 shared-key AUTH helper with caller-supplied, procedure-derived keying
material. The product layer owns exchange correlation and authorization policy.

See [CONFORMANCE.md](CONFORMANCE.md) for the exact evidence boundary and
explicit non-goals.

## Roadmap

- Add independent-peer fixtures before claiming interoperability.
- Continue adding typed cleartext payload bodies with octet-level fixture
  evidence.
- Keep SA state machines, retransmission queues, cookie policy, EAP-AKA, Child
  SA installation, and ePDG product decisions outside this crate.

## Verification

```bash
cargo check -p opc-proto-ikev2 --all-targets --all-features
cargo test -p opc-proto-ikev2 --all-features
cargo clippy -p opc-proto-ikev2 --all-targets -- -D warnings
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz list)
```
