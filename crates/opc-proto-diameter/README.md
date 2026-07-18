# opc-proto-diameter

Experimental Diameter mechanism scaffold for OpenPacketCore.

## Purpose

`opc-proto-diameter` starts the SDK-owned Diameter surface described by ADR
0018. It provides RFC 6733 header and raw AVP framing, dictionary metadata,
feature-gated base peer procedure helpers, and early 3GPP application
dictionaries and typed helpers.

It does not provide peer transport, realm routing, AAA/HSS/CDF behavior,
charging decisions, watchdog policy, or a carrier-ready EPC/ePDG product claim.

## API Shape

- Root types include `Header`, `Message<'a>`, `OwnedMessage`, `AvpHeader`,
  `RawAvp<'a>`, `RawAvpIterator`, `ApplicationId`, `CommandCode`, `AvpCode`,
  `VendorId`, `CommandFlags`, and `AvpFlags`.
- `validate_avp_region` and `validate_avp_region_with_dictionary` enforce
  length, padding, count, duplicate-key, and dictionary-marked grouped-AVP
  recursion rules.
- `Message::decode_with_dictionary` and
  `OwnedMessage::decode_owned_with_dictionary` resolve exactly one command by
  application id, command code, and request/answer role before applying its
  top-level AVP cardinality. Missing or overlapping command profiles fail
  closed; raw `Message::decode` retains reject-all duplicate behavior.
- `error_answer` provides a bounded `DiameterRequestEnvelope`, typed RFC 6733
  request failures, redacted `DiameterFailedAvp` context, and one
  `build_diameter_error_answer` boundary. Classification produces a
  private-construction `DiameterBoundRequestFailure` tied to the inspected
  request digest; the builder accepts only that token. It preserves request
  identifiers, P, exact Session-Id value bytes, and ordered, canonically
  re-encoded Proxy-Info while never copying Destination-Host,
  Destination-Realm, Route-Record, or an unbounded suffix. Classification
  fails closed on ambiguous dictionaries, validates the command P bit and
  known AVP M/P/V rules, and selects an earlier proven failure over later
  parser evidence. Explicit `Forbidden` command rules fail during
  dictionary-aware decode and classification, and `ZeroOrOne` rules always
  select the second occurrence as the first excess value. Earlier unknown
  M-bit AVPs are classified as 5001, while unknown optional AVPs remain
  ignored. Ancestor-free received Failed-AVP evidence must be an exact
  top-level iterator entry; nested evidence is rebound only after every exact
  request range, digest, direct-parent containment, and unique Grouped
  definition is proven. Synthesized 5005 evidence additionally requires a
  declared grouped-child schema path and proves absence at the request root or
  received parent.
  Proxy-Info descent and child count honor `max_depth` and `max_ies`;
  truncation and resource-limit failures are explicitly unanswerable.
- `dictionary` exposes `Dictionary`, `DictionarySet`, `ApplicationDefinition`,
  `CommandDefinition`, `CommandAvpRule`, `AvpCardinality`, `AvpDefinition`,
  `AvpDataType`, `AvpFlagRules`, and related metadata types.
- The `peer` feature adds transport-neutral CER/CEA, DWR/DWA, DPR/DPA
  builders/parsers, capability negotiation helpers, result-code helpers, and
  `PeerSession` projection state. Its trusted CER/CEA command profiles permit
  the six explicitly repeatable RFC 6733 capability AVPs, including every
  advertised Host-IP-Address for an SCTP-multihomed peer; singleton fields and
  the watchdog/disconnect profiles retain conservative duplicate rejection.
- The `app-rf` feature adds typed Rf accounting helpers.
- The `app-swm` feature adds typed SWm Diameter-EAP DER/DEA helpers, including
  exact, fail-closed resolution of an opt-in top-level default
  `Context-Identifier` extension to one of its repeated APN configurations and
  the TS 29.273 DER-only Emergency-Services/Emergency-Indication bitmask. It
  also models the TS 33.402 unauthenticated-emergency identity-recovery
  exchange: 3GPP Experimental-Result 5001, retry DER Terminal-Information,
  final DEA Mobile-Node-Identifier and IMEI-derived MSK, and correlated,
  fail-closed authorization evidence. Public `emergency_nai` and bounded
  `build_eap_response_identity` helpers construct the exact matching
  User-Name and EAP identity contract without consumer-owned wire formatting.
  The top-level `Service-Selection` remains a distinct AVP and is not treated
  as that default pointer.
- `app-gx`, `app-s6a`, `app-s6b`, and `app-swx` currently provide dictionary
  slots rather than full typed application APIs.

## Example

```rust
use opc_proto_diameter::Message;
use opc_protocol::{BorrowDecode, DecodeContext};

let packet = [
    0x01, 0x00, 0x00, 0x14, // version, 24-bit length = 20
    0x80, 0x00, 0x01, 0x01, // request flag, command code 0x000101
    0x00, 0x00, 0x00, 0x00, // application id
    0x00, 0x00, 0x00, 0x01, // hop-by-hop id
    0x00, 0x00, 0x00, 0x02, // end-to-end id
];

let (tail, msg) = Message::decode(&packet, DecodeContext::default())?;
assert!(tail.is_empty());
assert_eq!(msg.header.length, 20);
# Ok::<(), opc_protocol::DecodeError>(())
```

Request-bound negative answers are constructed separately from ordinary full
decode so malformed input never has to be manually reflected:

```rust
use bytes::BytesMut;
use opc_proto_diameter::base;
use opc_proto_diameter::error_answer::{
    build_diameter_error_answer, inspect_diameter_request,
    DiameterErrorAnswerGrammar, DiameterErrorOrigin, DiameterRequestInspection,
};
use opc_proto_diameter::DictionarySet;
use opc_protocol::{DecodeContext, Encode, EncodeContext};

# let request = [
#     1, 0, 0, 20, 0x80, 0, 0xfe, 0xfe, 0, 0, 0, 0,
#     0, 0, 0, 1, 0, 0, 0, 2,
# ];
let origin = DiameterErrorOrigin::new("aaa.local", "local.test")?;
let dictionary_refs = [base::dictionary()];
let dictionaries = DictionarySet::new(&dictionary_refs);
if let DiameterRequestInspection::Request(envelope) =
    inspect_diameter_request(&request, DecodeContext::conservative())
{
    if let Some(failure) = envelope.classify(&request, dictionaries)? {
        let plan = build_diameter_error_answer(
            &envelope,
            &failure,
            &origin,
            DiameterErrorAnswerGrammar::Application,
            EncodeContext::default(),
        )?;
        let sizing = plan.amplification_metadata();
        assert!(sizing.planned_response_len <= EncodeContext::default().max_message_len);
        let mut response = BytesMut::new();
        plan.encode(&mut response, EncodeContext::default())?;
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Application` keeps E clear for 5xxx failures and is suitable only when the
builder's common fields satisfy the command answer grammar (including DWA and
DPA). Select `Rfc6733ErrorBitFallback` explicitly when composing the ordinary
CCF is not possible or efficient and RFC 6733 §7.1.5 permits the generic §7.2
grammar. Protocol errors always set E, so `plan.grammar()` reports the effective
§7.2 grammar for every 3xxx result regardless of the requested grammar. The
returned plan has redacted diagnostics and exact sizing; transport admission,
rate limits, peer lifecycle, and whether a fatal error closes a connection
remain consumer policy. `DiameterErrorAnswerPlan::to_owned_message` is an
explicit sensitive escape: `OwnedMessage` has raw-byte `Debug` output and must
not be logged.

Command-specific parsers use `DiameterRequestEnvelope::bind_application_failure`
or `DiameterRequestFailure::from_decode_error` to obtain the bound token. A
5009 mapping requires an explicit `ZeroOrOne` command rule; `ZeroOrMore`, a
missing rule, and ambiguous metadata never become 5009, and the first excess
occurrence is selected even if a parser reports a later duplicate. Likewise,
5008 is available only for an explicitly `Forbidden` command rule, which the
dictionary-aware decoder rejects on its first occurrence, while an unknown
M-bit AVP maps to 5001. Nested application failures use only their immediate
parent's declared grouped-child rule and preceding siblings; top-level command
rules are never reused for nested leaves. These fail-closed distinctions
prevent local parser or dictionary incompleteness from being reported as peer
fault.

## Features

| Feature | Default | Scope |
| --- | --- | --- |
| `base` | yes | RFC 6733 common application and raw base metadata. |
| `peer` | no | CER/CEA, DWR/DWA, DPR/DPA helpers and peer-session projections. |
| `app-rf` | no | Rf accounting dictionary plus typed ACR/ACA helpers. |
| `app-swm` | no | SWm dictionary plus typed Diameter-EAP DER/DEA helpers. |
| `app-gx` | no | Gx dictionary slot only. |
| `app-s6a` | no | S6a/S6d dictionary slot only. |
| `app-s6b` | no | S6b dictionary slot only. |
| `app-swx` | no | SWx dictionary slot only. |
| `all-apps` | no | Enables every `app-*` feature. |

## Status And Limits

The crate is experimental and `publish = false`. It has ADR 0015 evidence in
progress for the base header and AVP layer, but it is not a production Diameter
stack. Raw AVP bytes are not redacted; typed helper layers own their own
redaction policies.

Use `CONFORMANCE.md` for the precise fixture provenance, fuzz target status,
application dictionary status, and typed helper gaps.

`SwmDiameterEapAnswer` struct literals must initialize
`default_context_identifier`; use `None` to preserve the prior wire shape or
`Some(id)` only when the deployment's AAA profile projects the TS 29.272
APN-Configuration-Profile default pointer into the SWm DEA extension surface.
The baseline SWm DEA command ABNF does not enumerate that top-level AVP. SDK
receivers predating this field reject the extension emitted with its required
M-bit as unknown, so upgrade decoders before enabling its emission from
encoders. Peers using the projected APN profile should decode with
`Message::decode_with_dictionary(..., DecodeContext::conservative(),
apps::SWM_PROJECTED_PROFILE_DICTIONARIES)`. That explicit profile permits
repeated `APN-Configuration` and `State` while retaining `DuplicateIe` for
every singleton and duplicate unknown key. Baseline callers use
`apps::APP_DICTIONARIES`, where APN-Configuration remains singleton. Never
combine the baseline and projected SWm dictionaries: overlapping command
grammars are rejected as ambiguous. Typed `set_once` checks remain defense in
depth.

`SwmDiameterEapRequest` struct literals must initialize `emergency_services`
and `terminal_information`; `None` preserves the previous DER wire bytes.
`Some(SwmEmergencyServices::emergency_indication())` emits DER AVP 1538 as a
3GPP vendor-specific `Unsigned32`, with V set and M/P clear. Emergency-Services
is not valid on a DEA.

`SwmDiameterEapAnswer` represents either a base `Result-Code` or a grouped
`Experimental-Result`. The optional 3GPP result (vendor 10415, code 5001)
requests TS 33.402 device-identity recovery; it is not authorization. After
the UE returns a TS 24.302 `DEVICE_IDENTITY`, the retry DER carries the
recovered exact 15-digit IMEI in `Terminal-Information`. The recovery branch
accepts only the TS 23.003 IMSI emergency NAI forms for AKA/AKA-prime and an
exact EAP-Response/Identity whose bytes equal User-Name.

Emergency DER builders should use `emergency_nai(&imei)` for the direct IMEI
path and pass the exact resulting bytes to `build_eap_response_identity`;
recovery DER builders use the same EAP helper with their canonical IMSI
Emergency NAI. The returned IMEI NAI is sensitive equipment identity and must
not be logged.
Identity octets are copied verbatim, including an RFC-permitted empty body, and
only inputs that cannot fit EAP's two-octet packet length are rejected before
allocation. The emergency verifier still rejects empty or mismatched identity
material.

Emergency authorization consumes request/answer envelopes that retain both
Diameter transaction identifiers; the final DEA must have exact base
`DIAMETER_SUCCESS` (2001), an exact EAP Success with the matching Response
identifier, a nonempty TS 33.402 Annex A.4 MSK derived from the exact received
IMEI digits, and the same permanent identity in `Mobile-Node-Identifier`. A
live transport must also consume its matching pending request before invoking
the evidence API; `correlate_answer` consumes both envelopes and produces the
only opaque exchange accepted by the evidence constructor, but codec equality
does not make a replay live. The resulting
MSK feeds ordinary IKEv2 method-2 AUTH. No no-MSK or IKEv2 NULL-auth shortcut
is modeled or authorized.

`Dictionary::find_command` and `DictionarySet::find_command` now require an
`ApplicationId` before command code and role. Update callers that previously
looked up commands by code and role alone; wire encodings are unchanged.

## Roadmap

- Broaden typed application helpers beyond the current Rf and SWm subsets.
- Add independently sourced fixtures before raising interoperability claims.
- Keep transport, realm policy, watchdog thresholds, AAA/HSS/CDF behavior, and
  charging decisions in consuming products.

## Verification

```bash
cargo check -p opc-proto-diameter --all-targets --all-features
cargo test -p opc-proto-diameter --all-features
python3 crates/opc-proto-diameter/fuzz/generate_corpus.py self-test
(cd crates/opc-proto-diameter && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
