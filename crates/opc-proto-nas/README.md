# opc-proto-nas

Experimental NAS-5GS codec for OpenPacketCore.

## Purpose

`opc-proto-nas` implements a v2 subset of 3GPP TS 24.501 NAS-5GS. It covers
plain 5GMM framing, 5GSM framing, security-protected envelope framing, selected
5GMM message bodies, mobile identity helpers, BCD unpacking, and caller-owned
NAS security hooks and a RustCrypto NIA2 provider with NEA2 or NEA0. The separate `tcp` module implements bounded TS 24.502
NAS-over-TCP envelopes while leaving the enclosed NAS bytes opaque.

It does not implement NAS procedure state machines, key derivation or key
lifecycle, SUCI de-concealment, NIA1/NEA1 (SNOW 3G), NIA3/NEA3 (ZUC), EPS
NAS interworking, or AMF/SMF product policy.

## API Shape

- `tcp::NasTcpDecoder` incrementally frames one bounded NAS/TCP payload at a
  time; `feed` retains unread input in the caller's slice and `finish` detects
  terminal truncation. `tcp::decode_envelope` borrows one frame and its tail;
  `tcp::encode_envelope` writes an exact envelope into caller storage.
  See [TCP.md](TCP.md) for limits, finalization and independent evidence.
- `NasMessage` is the top-level decoded PDU: `PlainMm`, `SecurityProtected`,
  or `Sm`.
- `PlainMm::decode_body` dispatches registered 5GMM bodies into
  `MmMessageBody`.
- `Sm::decode_body` dispatches registered 5GSM bodies into `SmMessageBody`;
  current 5GSM bodies are raw-preserving named variants.
- `RegistrationRequest`, `RegistrationAccept`, `SecurityModeCommand`, and
  `SecurityModeComplete`, and Authentication Request/Response/Result/Failure/Reject
  are the structured 5GMM body subset. Authentication bodies use checked
  `NgKsi`, `Abba`, `EapMessage`, and `MmCause` values.
- `MobileIdentity`, `IdentityView`, `SuciView`, and `GutiView` parse and expose
  5GS mobile identity content while preserving raw bytes.
- `unpack_plmn`, `unpack_routing_indicator`, and `unpack_imei` provide BCD
  digit helpers.
- `NasSecurityContext`, `NasSecurityAlgorithms`, `NasCount`,
  and `NullNasSecurityAlgorithms` provide the security hook boundary.
- `NasReplayWindow` is a standalone monotonic COUNT check;
  `NasSecurityContext` does not use it.
- `AesNasSecurityAlgorithms` resolves already-derived `NasAesKey` values through
  a caller-supplied resolver, using the algorithm identity and the context's
  `NasConnectionId`. `NasCountState` restores full receive/transmit counters.
  `nia2_mac` and `nea2_cipher` expose validated bit-length primitives for the
  TS 33.401 test vectors; ordinary NAS envelopes are octet-aligned.
- `NasMessage` and implemented body structs use the shared `opc-protocol`
  decode/encode traits.

## Example

```rust
use opc_proto_nas::{MmMessageBody, MmMessageType, NasMessage};
use opc_protocol::{BorrowDecode, DecodeContext};

let frame = [
    0x7e, 0x00, 0x41, 0x01, 0x00, 0x0a,
    0x01, 0x02, 0xf8, 0x39, 0x21, 0xf3,
    0x00, 0x00, 0x13, 0x57,
];

let (rest, msg) = NasMessage::decode(&frame, DecodeContext::default())?;
assert!(rest.is_empty());

if let NasMessage::PlainMm(m) = &msg {
    assert_eq!(
        MmMessageType::from_u8(m.message_type),
        Some(MmMessageType::RegistrationRequest)
    );
    let body = m.decode_body(DecodeContext::default())?;
    if let MmMessageBody::RegistrationRequest(req) = body {
        assert!(!req.follow_on_request);
    }
}
# Ok::<(), opc_protocol::DecodeError>(())
```

## Relationships

This crate depends on `opc-protocol` for codec contracts and `opc-key` for
session-key handle validation in `NasSecurityContext`. NGAP carries NAS payloads
but is implemented separately in `opc-proto-ngap`.

## Status And Limits

The crate is experimental and `publish = false`. Decode and encode are
byte-exact for raw-preserved bodies and identity content. Authentication
encoding is canonical: known IEs in table order, then preserved extensions;
ignored duplicates and spare bits are not emitted. This also applies when
`EncodeContext::raw_preserving` is true; retain `PlainMm.body` for the original
wire image. Default decode follows receiver rules: optional presence is not
enforced, malformed/out-of-order optional IEs are ignored, and excess fixed-size
IE octets and EAP padding are discarded. Strict/ProcedureAware enforce table
order, exact lengths and sender presence rules; encoding always enforces these
rules. Mandatory fields and decoding limits remain checked at every level.

The AES provider supports NIA2 with NEA2 or NEA0 pass-through; NEA0 performs no
cipher-key lookup, even for a ciphered security header. Each `NasSecurityContext`
owns a `NasConnectionId` (3GPP=1, non-3GPP=2) and separate per-direction COUNT
state. A provider can serve both accesses. Its resolver must authorize the
handle and the algorithm-bearing `NasKeyUsage` before returning a derived key.
`NasSecurityContext` authenticates the sequence-number octet and transmitted
payload, and ciphers only the payload. `protect_payload` allocates a fresh COUNT
atomically, including through clones or concurrent calls, and burns it on
provider failure. Exhaustion refuses further protection. Restore the next
unused transmit COUNT and highest authenticated receive COUNT, with exclusive
ownership and no rollback under the same keys. Persistence, key replacement
and cross-process fencing remain caller-owned. The separate null provider
allows explicit NIA0, which provides no integrity or reliable replay detection.
Plain, protected and verified NAS payloads, 5GSM bodies and `RawMessageBody`
bytes are redacted in Debug output.

See [CONFORMANCE.md](CONFORMANCE.md) for the full v2 coverage and known
limitations, including the authentication IE matrix, vector sources and migration notes.

## Roadmap

- Add typed 5GMM and 5GSM bodies as consuming NF profiles need them.
- Replace optional-IE heuristics with explicit registry coverage for more IEs.
- Keep key derivation, SUCI de-concealment and procedure state in higher-level
  security and NF crates.

## Verification

```bash
cargo check -p opc-proto-nas --all-targets --all-features
cargo test -p opc-proto-nas --all-features
(cd crates/opc-proto-nas && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
