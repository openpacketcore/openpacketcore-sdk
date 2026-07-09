# opc-proto-nas

Experimental NAS-5GS codec for OpenPacketCore.

## Purpose

`opc-proto-nas` implements a v2 subset of 3GPP TS 24.501 NAS-5GS. It covers
plain 5GMM framing, 5GSM framing, security-protected envelope framing, selected
5GMM message bodies, mobile identity helpers, BCD unpacking, and caller-owned
NAS security hooks.

It does not implement NAS procedure state machines, key derivation or key
lifecycle, SUCI de-concealment, concrete non-null NAS algorithms, EPS NAS
interworking, or AMF/SMF product policy.

## API Shape

- `NasMessage` is the top-level decoded PDU: `PlainMm`, `SecurityProtected`,
  or `Sm`.
- `PlainMm::decode_body` dispatches registered 5GMM bodies into
  `MmMessageBody`.
- `Sm::decode_body` dispatches registered 5GSM bodies into `SmMessageBody`;
  current 5GSM bodies are raw-preserving named variants.
- `RegistrationRequest`, `RegistrationAccept`, `SecurityModeCommand`, and
  `SecurityModeComplete` are the structured 5GMM body subset.
- `MobileIdentity`, `IdentityView`, `SuciView`, and `GutiView` parse and expose
  5GS mobile identity content while preserving raw bytes.
- `unpack_plmn`, `unpack_routing_indicator`, and `unpack_imei` provide BCD
  digit helpers.
- `NasSecurityContext`, `NasSecurityAlgorithms`, `NasReplayWindow`, `NasCount`,
  and `NullNasSecurityAlgorithms` provide the security hook boundary.
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
byte-exact for accepted inputs because unparsed bodies, optional IEs, and
identity content are preserved raw. The in-tree null security provider is only
for NIA0/NEA0 and tests; production use of NIA1/2/3 or NEA1/2/3 must supply an
external `NasSecurityAlgorithms` implementation.

See [CONFORMANCE.md](CONFORMANCE.md) for the full v2 coverage and known
limitations, including optional-IE format heuristics.

## Roadmap

- Add typed 5GMM and 5GSM bodies as consuming NF profiles need them.
- Replace optional-IE heuristics with explicit registry coverage for more IEs.
- Keep key derivation, SUCI de-concealment, concrete algorithms, and procedure
  state in higher-level security and NF crates.

## Verification

```bash
cargo check -p opc-proto-nas --all-targets --all-features
cargo test -p opc-proto-nas --all-features
(cd crates/opc-proto-nas && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
