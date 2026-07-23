# opc-proto-eap

`opc-proto-eap` provides a strict, allocation-bounded, product-neutral
projection for complete EAP-AKA (Type 23) and EAP-AKA-prime (Type 50) Request
and Response packets. It is shared by the IKEv2 and SWm Diameter-EAP
boundaries so products do not need a second method parser. The crate remains
an experimental workspace component and is not published independently until
its protocol surface graduates.

## Scope

The parser covers the RFC 4187 AKA subtypes Challenge,
Authentication-Reject, Synchronization-Failure, Identity, Notification,
Reauthentication, and Client-Error, plus the RFC 9048 EAP-AKA-prime
differences:

- exact complete-packet EAP framing and AKA method-header validation;
- bounded four-octet attribute framing and singleton cardinality;
- standardized attribute length, actual-length, and alignment validation;
- Request/Response direction and subtype-specific attribute rules;
- AKA-prime AT_KDF/AT_KDF_INPUT offers, negotiation responses,
  Synchronization-Failure KDF lists, reserved value zero, and legal re-offer duplicate
  shape;
- RFC 4187 Notification S/P phase semantics; and
- unknown mandatory rejection plus bounded counting of unknown skippable
  attributes.

Parsing borrows the supplied packet and allocates nothing. The borrowed bytes
remain private and have no accessor. Public evidence contains only typed
method/subtype/direction values, numeric protocol codes, booleans, and bounded
counts. It never exposes identities, RAND, AUTN, AUTS, RES, MAC, IV,
ciphertext, nonces, keys, realms, addresses, or packet-derived hashes.

## Example

```rust
use opc_proto_eap::{EapAkaPacket, EapAkaPacketKind};

fn claimed_kdf(packet: &[u8]) -> Result<Option<u16>, opc_proto_eap::EapAkaError> {
    let packet = EapAkaPacket::parse(packet)?;
    Ok(match packet.kind() {
        EapAkaPacketKind::AkaPrimeKdfNegotiationResponse(evidence) => {
            Some(evidence.claimed_kdf())
        }
        _ => None,
    })
}
```

IKEv2 consumers can opt in from an already decoded EAP payload:

```rust
# use opc_proto_ikev2::ike_auth::Ikev2EapPayload;
# fn inspect(payload: Ikev2EapPayload<'_>) -> Result<(), opc_proto_eap::EapAkaError> {
let projection = payload.project_aka()?;
let subtype = projection.subtype();
# let _ = subtype;
# Ok(())
# }
```

With `opc-proto-diameter`'s `app-swm` feature, use
`SwmDiameterEapRequest::project_eap_aka`,
`SwmDiameterEapAnswer::project_eap_payload_aka`, or the authenticated,
transaction-bound `SwmCorrelatedDiameterEapResponse` projection methods.
Generic EAP traffic remains opaque unless a caller explicitly opts in.

## Security boundary

This is structural evidence, not authentication evidence. The crate does not:

- verify AT_MAC, AUTN, AUTS, or RES;
- decrypt or parse AT_ENCR_DATA;
- correlate KDF re-offers or result-indication negotiation across packets;
- derive MSK/EMSK or other keys; or
- decide whether RFC 5998 EAP-only authentication is complete or safe.

Those operations require method keys and exchange state and remain with the
EAP method implementation or product. In particular, a structurally complete
Challenge Response and a structurally protected Success Notification are
reported as candidates only; callers must not treat them as cryptographically
verified.

See [CONFORMANCE.md](CONFORMANCE.md) for exact validation and evidence.

## Verification

```bash
cargo test --locked -p opc-proto-eap
cargo clippy --locked -p opc-proto-eap --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked -p opc-proto-eap --no-deps
(cd crates/opc-proto-eap && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
