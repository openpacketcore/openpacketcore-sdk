# opc-proto-ikev2

Transport-neutral IKEv2 mechanisms for OpenPacketCore untrusted-access work.

## Purpose

`opc-proto-ikev2` covers transport-neutral IKEv2 wire mechanisms that are safe
to expose as SDK primitives today: header decode/encode, unencrypted payload
walking, protected-payload boundaries, selected SA_INIT and IKE_AUTH helpers,
NAT detection, NAT-T datagram classification, and product-neutral Child SA
negotiation intent. It also provides strict opened-payload primitives for the
TS 24.302 multiple-bearer profile: typed QoS/TFT/AMBR notifications, new
non-rekey dedicated-bearer Child SA establishment, bearer modification, and
bearer deletion.

It does not implement an IKE SA state machine, EAP-AKA, retransmission policy,
cookie policy, Child SA lifecycle, XFRM/IPsec programming, bearer admission or
allocation policy, carrier acceptance evidence, or a production ePDG
control-plane stack.

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
  SA key-material derivation. The notify-only error builder is deliberately
  bounded to one IKE-SA-shaped `NO_PROPOSAL_CHOSEN` or `INVALID_KE_PAYLOAD`;
  the latter has a convenience builder that writes the accepted non-zero group
  as exactly two big-endian octets. These failures are mutually exclusive, so
  the builder rejects a multi-Notify response rather than emitting ambiguity.
- `protected_payload_crypto` provides caller-keyed AES-GCM-16 `SK` open/seal
  helpers for already-derived SA_INIT key material.
- `ike_auth` and `ike_auth_signature` provide cleartext IKE_AUTH payload
  helpers, shared-key AUTH MIC helpers, signature AUTH helpers, and Child SA
  selector/proposal helpers.
- `device_identity` validates and builds TS 24.302 DEVICE_IDENTITY requests and
  responses using the redaction-safe exact-15-digit `Imei15` and `Imeisv`
  types. TBCD decoding preserves the received fifteenth IMEI digit (including
  a spare zero or non-Luhn digit) and enforces the terminal filler nibble.
- `dedicated_bearer` implements the TS 24.302 multiple-bearer Notify values and
  strict opened-payload views/builders for dedicated-bearer `CREATE_CHILD_SA`
  and `INFORMATIONAL` modification/deletion exchanges. TFT values use the
  canonical `opc-proto-tft` TS 24.008 codec shared with GTPv2-C. Response
  correlation checks the IKE SPIs, Message ID, exchange/flags, selected offered
  proposal/transforms, optional KE group, and traffic-selector narrowing.
- `fragmentation`, `notify`, `nat_detection`, `nat_traversal`, and `exchange`
  expose RFC-specific mechanism helpers without owning product state.

## Dedicated-bearer integration

The dedicated-bearer API consumes and emits the cleartext payload chain inside
an authenticated `SK` payload. The application remains responsible for IKE SA
state, message-ID allocation, encryption/authentication, timer policy, and
installing or deleting the resulting Child SA.

```rust
use opc_proto_ikev2::{
    build_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    Header, Ikev2DedicatedBearerCreateChildSaRequest,
    Ikev2DedicatedBearerCreateChildSaRequestBuild,
    Ikev2DedicatedBearerCreateChildSaResponse, PayloadType,
};

fn encode_new_bearer(
    input: &Ikev2DedicatedBearerCreateChildSaRequestBuild,
) -> Result<(PayloadType, bytes::Bytes), Box<dyn std::error::Error>> {
    let cleartext = build_ikev2_dedicated_bearer_create_child_sa_request(input)?;
    // Seal these exact bytes once, then cache the complete encrypted request
    // for retransmission; do not reseal retransmissions with a new IV.
    Ok(cleartext.into_parts())
}

fn accept_new_bearer_response<'a>(
    request_header: &Header,
    request: &Ikev2DedicatedBearerCreateChildSaRequest<'_>,
    response_header: &Header,
    first_payload: PayloadType,
    opened_payloads: &'a [u8],
) -> Result<Ikev2DedicatedBearerCreateChildSaResponse<'a>, Box<dyn std::error::Error>> {
    let response = decode_ikev2_dedicated_bearer_create_child_sa_response(
        response_header,
        first_payload,
        opened_payloads,
    )?;
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
        request_header,
        response_header,
        request,
        &response,
    )?;
    Ok(response)
}
```

Modification uses
`build_ikev2_dedicated_bearer_modification_request`; deletion uses
`build_ikev2_dedicated_bearer_delete_request`. A normal Delete response is
built/decoded with `build_ikev2_dedicated_bearer_delete_response` and
`decode_ikev2_dedicated_bearer_delete_response`: the ePDG request names its
inbound ESP SPI, while the UE response names the paired UE inbound ESP SPI.
Pass both values through `Ikev2DedicatedBearerDeleteResponseExpectation::PairedSa`
to `validate_ikev2_dedicated_bearer_delete_response_correlation` before changing
application state. An empty response is accepted only with the explicit
`SimultaneousDelete` expectation when RFC 7296 crossed Delete requests apply.
Modification responses remain empty or typed-error INFORMATIONAL responses and
use their corresponding decoder/correlation helper.
The IKE-only establishment-and-deletion flow is in
[`examples/dedicated_bearer_ikev2.rs`](examples/dedicated_bearer_ikev2.rs).
The complete SDK composition from a triggered GTPv2-C Create Bearer request,
through a correlated IKEv2 Child-SA exchange and GTP response commit, followed
by Delete Bearer and Child-SA deletion, is executable as
[`examples/dedicated_bearer_sdk_flow.rs`](examples/dedicated_bearer_sdk_flow.rs).
That example makes the application-owned admission, allocation, and dataplane
boundaries explicit and proves exact GTP retransmission replay.

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

The crate is experimental and `publish = false`. The dedicated-bearer wire
boundary has typed, fail-closed validation and specification-authored tests,
but this crate is not a full IKEv2 implementation. Certificate-chain,
validity-period, name, and key-usage validation are caller responsibilities
when using signature AUTH helpers.

IKE_SA_INIT error responses are unauthenticated. The product owns source
validation, response rate limiting, retransmission behavior, and other
anti-amplification policy. The cleartext builder intentionally rejects
`INVALID_SYNTAX`: RFC 7296 §3.10.1 only permits that error in an encrypted
packet after Message ID and cryptographic checksum validation.

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
- Keep SA state machines, retransmission queues, cookie policy, EAP-AKA, SPI
  allocation, Child SA installation, and ePDG product decisions outside this
  crate.

## Verification

```bash
cargo check -p opc-proto-ikev2 --all-targets --all-features
cargo test -p opc-proto-ikev2 --all-features
cargo clippy -p opc-proto-ikev2 --all-targets -- -D warnings
cargo run -p opc-proto-ikev2 --example dedicated_bearer_sdk_flow
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz list)
(cd crates/opc-proto-ikev2 && cargo +nightly fuzz run dedicated_bearer -- -runs=1000)
```
