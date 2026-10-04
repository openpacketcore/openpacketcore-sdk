# opc-proto-eap

`opc-proto-eap` provides method-independent EAP admission, typed Success and
Failure packets, a strict, allocation-bounded projection for complete EAP-AKA
(Type 23) and EAP-AKA-prime (Type 50) Request and Response packets, and a
bounded EAP-5G envelope codec. The AKA
projection is shared by the IKEv2 and SWm Diameter-EAP
boundaries so products do not need a second method parser. The crate remains
an experimental workspace component and is not published independently until
its protocol surface graduates.

## Scope

### Common admission and terminal packets

`EapPacket::parse` classifies the common header as `Request`, `Response`,
`Success` or `Failure`, without interpreting a method. `EapSuccess` and
`EapFailure` each hold an identifier and encode without allocation to exactly
`[3, identifier, 0, 4]` or `[4, identifier, 0, 4]`.

```rust
use opc_proto_eap::{EapFailure, EapPacket, EapPacketError, EapSuccess};

let last_response_identifier = 7;
let wire = EapSuccess::new(last_response_identifier).encode();
assert!(matches!(
    EapPacket::parse(&wire)?,
    EapPacket::Success(success)
        if success.matches_response_identifier(last_response_identifier)
));
assert_eq!(EapFailure::new(7).encode(), [4, 7, 0, 4]);
# Ok::<(), EapPacketError>(())
```

Admission rejects incomplete headers, unsupported codes, Length below four,
Length beyond the received slice, and Request/Response without a Type octet
inside Length. Terminals require Length exactly four: declared Data is invalid,
including zero-filled Data. Per [RFC 3748 section 4](https://www.rfc-editor.org/rfc/rfc3748.html#section-4),
octets **outside** Length are lower-layer padding and are ignored for all four
codes. Thus `[3, 7, 0, 5, 0]` is rejected, while `[3, 7, 0, 4, 0]` is admitted
and re-encodes to four octets.

`Request` and `Response` contain an `EapMethodPacket` borrowing only the
declared packet. Call `parse_aka()` or `parse_eap5g(limits)` on it to invoke the
existing method parsers. Method validation and EAP-5G caller limits still apply;
the packet length limit excludes ignored lower-layer padding. Direct calls to
the method parsers continue to require an exact complete packet. `EapCode`
remains the two-variant Request/Response direction type.

Per [RFC 3748 section 4.2](https://www.rfc-editor.org/rfc/rfc3748.html#section-4.2),
both terminal identifiers must equal the last Response being answered.
`matches_response_identifier` checks that equality against caller-owned state;
neither equality nor parsing proves authentication or completes IKE_AUTH.
Admission and terminal `Debug` output and errors contain no identifiers,
method values or padding bytes.

### EAP-5G envelopes

The separate [`eap5g`](src/eap5g.rs) module constructs and parses EAP-5G
Start, NAS Request/Response, Stop, and empty Notification envelopes. NAS is
opaque; typed AN values cover selected PLMN, GUAMI, requested NSSAI, cause,
selected NID, onboarding and GUAMI origin. Parsing allocates nothing and
canonical encoding checks the complete EAP length before reserving memory or
changing output. Every value-bearing type has redacted `Debug`.

```rust
use opc_proto_eap::eap5g::{Limits, Message, Packet};

let start = Packet::new(1, Message::Start).encode(Limits::default())?;
let received = Packet::parse(&start, Limits::default())?;
assert!(matches!(received.message(), Message::Start));
# Ok::<(), opc_proto_eap::eap5g::Error>(())
```

For an initial NAS response, call `AnParameters::validate_bootstrap` with
explicit `BootstrapRequirements` from the access context. This profile
requires selected PLMN and cause; the caller supplies NID/SNPN, GUAMI,
NSSAI-inclusion and onboarding conditions. Ordinary parsing admits subsequent
NAS responses with no AN parameters. The codec cannot infer those conditions
from opaque NAS or establish that an EAP session completed.

Receive-side parameter ordering is unrestricted. Duplicate singleton handling
is an explicit caller policy (`Reject` by default, or `FirstWins` with all
occurrences validated). Spare types and bits are ignored; canonical encoding
omits ignored fields and zeros spare bits. Known UE-identity parameters and
TNGF contact parameters return `UnsupportedParameter`; no identity parser is
exposed. See the [EAP-5G conformance boundary](CONFORMANCE.md#eap-5g-bootstrap-envelopes).

### AKA projections

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
remain private and have no raw accessor. Public evidence contains typed
method/subtype/direction values, numeric protocol codes, booleans, and bounded
counts, plus exactly one attribute value: the identity a peer asserts in
`AT_IDENTITY` (see [The asserted identity](#the-asserted-identity)). It never
exposes RAND, AUTN, AUTS, RES, MAC, IV, ciphertext, nonces, keys, realms,
addresses, or packet-derived hashes, and no identity reaches `Debug`.

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

### The asserted identity

`EapAkaPacket::asserted_identity` returns the `AT_IDENTITY` octets a peer
asserted, and `asserted_identity_is` compares against them without handing the
value out. Both use the RFC 4187 clause 10.1 Actual Identity Length, so the
padding that clause requires never participates in a comparison.

This is the one attribute value the crate exposes, because an `AKA-Identity`
exchange exists precisely so a peer can name a *different* identity than the
one already seen -- a permanent identity in place of a pseudonym. A relaying
node that tracks which subscriber an exchange belongs to cannot keep that in
step from presence alone: presence cannot separate "asserted the identity I
already know" from "asserted a different one". `asserted_identity_is` returns
`false` when the attribute is absent, so an absent attribute can never be read
as agreement.

The value is still withheld from `Debug`, which projects
`asserted_identity_len` instead, so diagnostics remain redaction-safe. Treat
the identity as subscriber-correlatable: it is an identifier the peer claims,
not an authenticated one, and nothing here verifies that claim.

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
