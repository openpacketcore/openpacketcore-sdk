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
- `parser_error` provides sealed, redaction-safe `DiameterParserError` and
  `DiameterMissingAvpProvenance`, grouped-parent, and grouped-set metadata. Additive
  `*_with_provenance` request parsers cover CER, DWR, DPR, and SWm DER/STR/ASR (plus
  their SWm transaction-envelope forms); legacy parser signatures delegate to
  them and still return the original `DecodeError`. Missing provenance exposes
  only numeric application/command/role metadata and the exact SDK-owned AVP
  definition needed to inspect its vendor-aware key, data type, and flag rules.
  The binding covers the declared Diameter message boundary, not unrelated
  bytes following it in a stream or datagram receive buffer.
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
- The `app-swm` feature adds typed SWm Diameter-EAP DER/DEA,
  Session-Termination STR/STA, and Abort-Session ASR/ASA helpers. Lifecycle
  envelopes bind both Diameter identifiers, the P bit, a present exact
  `Session-Id`, and ordered Proxy-Info. Outbound envelopes additionally require
  an authenticated connection-generation token and may apply an explicit
  direct-host, routed-realm, or connection-only Origin policy. RFC 6733 generic
  E-bit answers, including the permitted permanent-failure fallback, may omit
  Session-Id and skip logical-Origin policy, but still require the exact
  connection, transaction, P, and Proxy-Info chain. The
  initial outbound STR or ASR clears T, and each envelope exposes a one-way
  `mark_for_failover_retransmission` transition for queued, unacknowledged
  state resent after link failover or recovery; the transition atomically
  installs the replacement connection binding and its caller-reserved
  Hop-by-Hop Identifier while retaining End-to-End duplicate identity.
  SWm STR and ASR `User-Name` are required by the TS 29.273 procedure tables and
  retain
  sealed missing-AVP provenance despite the reused command CCF showing it as
  optional. The
  request-bound STA builder emits only fully modeled success, base
  `DIAMETER_UNKNOWN_SESSION_ID` (5002), and `DIAMETER_UNABLE_TO_COMPLY` (5012)
  contexts without misusing the E bit, and parsed answers require exact
  transaction, optional-present `Session-Id`, and Proxy-Info correlation.
  Received non-redirect base result
  codes remain receive-only projections; redirect 3006 is rejected until its
  required redirect semantics have a typed surface. Command occurrence metadata
  declares repeated ASA `Redirect-Host` and `Failed-AVP` fields, so conservative
  dictionary decoding recognizes their standard cardinality. The typed surface
  retains repeated `Failed-AVP` but rejects redirect AVPs and result 3006.
  `Redirect-Host-Usage` and `Redirect-Max-Cache-Time` remain singleton, and an
  undeclared wildcard extension never gains repeatability implicitly. Missing
  required STR and ASR fields retain sealed 5005 provenance for the generic RFC
  6733 error-answer mapper. Lifecycle ownership, duplicate-request cache
  lifetime, retries, teardown ordering, and compensation remain consumer policy.
  The DER/DEA surface includes
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

For an actual typed request-parser failure, use the provenance-aware entry
point and the dedicated mapper rather than matching a `DecodeError` reason:

```rust
use opc_proto_diameter::error_answer::DiameterRequestFailure;
use opc_proto_diameter::peer::parse_device_watchdog_request_with_provenance;
use opc_protocol::{DecodeContext, EncodeContext};

# use opc_proto_diameter::{DictionarySet, Message};
# use opc_proto_diameter::error_answer::DiameterRequestEnvelope;
# fn example(
#     message: &Message<'_>,
#     request: &[u8],
#     envelope: &DiameterRequestEnvelope,
#     dictionaries: DictionarySet<'_>,
# ) -> Result<(), Box<dyn std::error::Error>> {
if let Err(parser_error) = parse_device_watchdog_request_with_provenance(
    message,
    DecodeContext::conservative(),
) {
    let bound = DiameterRequestFailure::from_parser_error(
        envelope,
        request,
        &parser_error,
        DecodeContext::conservative(),
        dictionaries,
        EncodeContext::default(),
    )?;
    assert_eq!(bound.result_code(), 5005);
}
# Ok(())
# }
```

The mapper first reclassifies the exact inspected Diameter message, so a prior header,
application, command, P-bit, framing, dictionary-bit, unknown-M, forbidden, or
excess failure wins. It then verifies the sealed declared-message-boundary
parser fingerprint and
command/application identity, resolves exactly one vendor-aware AVP definition,
requires it to equal the sealed SDK definition, derives its minimum
`Failed-AVP` shape, and proves the field is absent through the existing checked
application binder. A typed parser error without missing provenance delegates
to the generic decode-error mapper unchanged. Missing, conflicting, or
ambiguous definitions, cross-request reuse, command mismatch, and local-policy
rejections fail closed as typed mapping errors.

Nested command grammar uses exact received-parent provenance. A CER
`Vendor-Specific-Application-Id` without Vendor-Id produces a nested minimum
Vendor-Id. When neither Auth-Application-Id nor Acct-Application-Id is present,
RFC 6733 §6.11's 5005 `Failed-AVP` contains minimum examples of both children;
when both are present, 5009 contains only those exact received children in wire
order. An optional-present SWm `Terminal-Information` without mandatory IMEI
similarly produces a nested vendor-correct minimum IMEI and never reflects its
Software-Version sibling.

Migration note: `DiameterRequestFailure` now includes
`MutuallyExclusiveAvps(DiameterFailedAvp)`. Exhaustive downstream matches must
add an arm; `result_code()` and `as_str()` intentionally classify it with the
existing 5009 `diameter_avp_occurs_too_many_times` family. Legacy parser
function signatures and their `DecodeError` values remain source-compatible.

## Features

| Feature | Default | Scope |
| --- | --- | --- |
| `base` | yes | RFC 6733 common application and raw base metadata. |
| `peer` | no | CER/CEA, DWR/DWA, DPR/DPA helpers and peer-session projections. |
| `app-rf` | no | Rf accounting dictionary plus typed ACR/ACA helpers. |
| `app-swm` | no | SWm dictionary plus typed Diameter-EAP DER/DEA, Session-Termination STR/STA, and Abort-Session ASR/ASA helpers. |
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

### SWm Session-Termination

An ePDG creates an outbound STR by binding typed facts to identifiers allocated
by its live Diameter transport:

```rust
use opc_proto_diameter::apps::swm::{
    build_swm_session_termination_request, SwmDiameterConnectionToken,
    SwmDiameterTransaction, SwmExpectedAnswerPeer, SwmSessionTerminationRequest,
    SwmSessionTerminationRequestEnvelope, SwmTerminationCause,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::{EncodeContext, EncodeError};

fn build_str(
    connection: SwmDiameterConnectionToken,
) -> Result<OwnedMessage, EncodeError> {
    let request = SwmSessionTerminationRequest {
        session_id: "session-id-from-the-established-DER".into(),
        origin_host: "epdg.example".into(),
        origin_realm: "example".into(),
        destination_realm: "example".into(),
        destination_host: None,
        termination_cause: SwmTerminationCause::Administrative,
        user_name: "permanent-user-identity@example".into(),
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let pending = SwmSessionTerminationRequestEnvelope::for_outbound(
        request,
        SwmDiameterTransaction::new(0x1020_3040, 0x5060_7080),
        SwmExpectedAnswerPeer::routed(connection),
    );
    build_swm_session_termination_request(&pending, EncodeContext::default())
}
```

The `connection` argument above is allocated by the transport when that exact
authenticated connection generation opens; it is never a constant or a peer
address-derived value.

If transport link failover requires resending that still-unacknowledged queued
request, retain the same envelope and identifiers, allocate a fresh token for
the replacement authenticated connection, call
`pending.mark_for_failover_retransmission(replacement_hop_by_hop,
SwmExpectedAnswerPeer::routed(new_connection))`, and rebuild it. The transport
must reserve that Hop-by-Hop Identifier as unique among pending requests on the
replacement connection. The transition atomically sets T and replaces both
hop-local correlation fields without changing the End-to-End Identifier or AVP
bytes. An ordinary timer retry does not call this transition. Retry timing,
identifier allocation, connection selection, and pending-request ownership
remain transport/product responsibilities.

`SwmExpectedAnswerPeer::routed(connection)` accepts the final logical Origin
behind a DRA/proxy/relay while still requiring the exact authenticated
connection generation. `direct(connection, host, realm)` additionally binds
one final server, while `routed_in_realm(connection, realm)` permits a trusted
server pool. FQDN and realm comparisons use ASCII case-insensitive
DiameterIdentity semantics. Destination-Host and Destination-Realm are routing
instructions, not authentication evidence, and the SDK never derives a
logical-Origin policy from them. Generic E-bit answers can be originated by an
intermediary and skip only the optional logical-Origin check; they never skip
connection binding.

An AAA endpoint parses an inbound envelope before session lookup and constructs
an STA from that exact request. The inbound envelope intentionally has no
outbound peer binding. The answer builder copies identifiers, `Session-Id`, P,
and the ordered Proxy-Info chain without comparing the local Origin to request
Destination AVPs; applications do not hand-format an error answer:

```rust
use opc_proto_diameter::Message;
use opc_proto_diameter::apps::swm::{
    build_swm_session_termination_answer,
    parse_swm_session_termination_request_envelope,
    SwmSessionTerminationAnswer, SwmSessionTerminationResult,
};
use opc_protocol::{DecodeContext, EncodeContext};

# fn answer(message: &Message<'_>) -> Result<(), Box<dyn std::error::Error>> {
let request = parse_swm_session_termination_request_envelope(
    message,
    DecodeContext::conservative(),
)?;
let answer = SwmSessionTerminationAnswer::for_request(
    &request,
    SwmSessionTerminationResult::UnknownSession,
    "aaa.example",
    "example",
);
let sta_message = build_swm_session_termination_answer(
    &request,
    &answer,
    EncodeContext::default(),
)?;
# let _ = sta_message;
# Ok(())
# }
```

For an outbound STR, consume the transport's pending-request entry and parse an
STA with `parse_swm_session_termination_answer_envelope_from_connection(message,
received_on, context)`, then call `pending.correlate_answer(sta)`. Codec
correlation does not make a replay live and does not own the product session
registry. The typed answer parser validates the application, command, and
answer direction and retains the transport-supplied connection generation;
ordinary STA answers require the exact Session-Id, while an RFC 6733 generic
E-bit answer may omit it and remains bound by connection, both transaction
identifiers, P, and the exact ordered Proxy-Info chain. This includes the
section 7.1.5 permanent-failure fallback. A present Session-Id must match.
Consumers allocate process-unique nonzero connection tokens and must allocate
a new one for every reconnect. The values and logical identities are redacted
from diagnostics.

For a retransmitted duplicate STR, cache and replay the committed application
answer after application completion. A duplicate retaining the same Hop-by-Hop
Identifier produces a byte-identical STA. A failover duplicate with a newly
reserved Hop-by-Hop Identifier produces the same flags and AVPs with that new
identifier, as RFC 6733 permits. Cache lifetime, duplicate lookup, and
committed-response ownership remain transport policy.

### SWm Abort-Session

An ePDG receiving an ASR parses the request envelope before touching session
state, applies its product-owned abort exactly once, and builds the ASA against
that same envelope:

```rust
use opc_proto_diameter::Message;
use opc_proto_diameter::apps::swm::{
    build_swm_abort_session_answer, parse_swm_abort_session_request_envelope,
    SwmAbortSessionAnswer, SwmAbortSessionResult,
};
use opc_protocol::{DecodeContext, EncodeContext};

# fn answer(message: &Message<'_>) -> Result<(), Box<dyn std::error::Error>> {
let request = parse_swm_abort_session_request_envelope(
    message,
    DecodeContext::conservative(),
)?;
# // Perform the product-owned, exactly-once session abort here.
let answer = SwmAbortSessionAnswer::for_request(
    &request,
    SwmAbortSessionResult::Success,
    "epdg.example",
    "example",
);
let asa_message = build_swm_abort_session_answer(
    &request,
    &answer,
    EncodeContext::default(),
)?;
# // Commit the exact ASA bytes before acting on the follow-on disposition.
let follow_on = request.post_abort_session_termination(
    &answer,
    EncodeContext::default(),
)?;
# let _ = asa_message;
# let _ = follow_on;
# Ok(())
# }
```

The envelope retains the request T bit for duplicate classification, but ASA
construction always clears T and preserves the request identifiers, P bit,
Session-Id, and ordered Proxy-Info chain; the caller supplies the local ASA
Origin explicitly rather than inferring authenticated identity from Destination
AVPs. A duplicate retaining the same Hop-by-Hop Identifier produces a
byte-identical ASA. A failover duplicate with a newly reserved Hop-by-Hop
Identifier produces the same flags and AVPs with that new identifier, as RFC
6733 permits. The product must key and bound its duplicate-request cache, commit
the encoded ASA bytes before publishing success, and replay those exact cached
bytes without repeating teardown side effects.

For outbound ASR, construct the request with a transport-owned
`SwmDiameterConnectionToken` and `SwmExpectedAnswerPeer`, then parse the ASA with
`parse_swm_abort_session_answer_envelope_from_connection(message, received_on,
context)`. Tokens must be process-unique and renewed on reconnect. An outbound
envelope starts with T clear;
`mark_for_failover_retransmission(replacement_hop_by_hop_identifier, new_peer)`
is only for a queued, unacknowledged ASR resend after link failover or equivalent
recovery, not an ordinary timer retry.

Ordinary E-clear ASAs require Session-Id and correlate it exactly. A received
generic E-bit answer may omit Session-Id under RFC 6733's error-answer grammar,
including the permitted permanent-failure fallback; when present it must still
match. Generic errors skip only logical-Origin policy; connection generation,
transaction, P, Proxy-Info, and overload-control correlation remain mandatory.
Such an error never enters the successful post-abort STR path.

The RFC 4005-derived metadata recognizes repeated ASA `Redirect-Host` and
`Failed-AVP` occurrences. Base definitions require the RFC 6733 M bit, validate
fixed widths, and apply a bounded DiameterURI grammar. The typed ASA boundary
retains repeated `Failed-AVP` but rejects all redirect AVPs and result 3006 until
redirect semantics are fully modeled; it does not originate, route, or rebuild
redirect context. `Redirect-Host-Usage` and `Redirect-Max-Cache-Time` are
singleton. ASR explicitly forbids these answer-only fields. RFC 4005 ASR also
declares singleton `State` and repeated `Reply-Message`; ASA keeps `State` and
wildcard `Class` singleton. An undeclared extension wildcard remains singleton.

The typed ASR profile requires `User-Name`. TS 29.273 V19.2.0's command ABNF
prints it as optional, but the procedure table marks Permanent User Identity
mandatory and the abort matching procedure requires the same Session-Id and
User-Name. This stricter mechanical boundary prevents ambiguous session aborts.
An omitted `Auth-Session-State` is treated as `STATE_MAINTAINED`, as required by
RFC 6733. At the ePDG, after successfully building and committing the ASA, call
`request.post_abort_session_termination(&answer, context)`: maintained state
yields typed STR facts with `ADMINISTRATIVE` termination cause, while
`NO_STATE_MAINTAINED` and an unsuccessful ASA yield explicit no-STR
dispositions. This method lives on the inbound request envelope because TS
29.273 requires the ePDG, not the AAA originator correlating an ASA, to send the
follow-on STR. The SDK cannot prove response commitment; the consumer allocates
a fresh STR transaction and peer binding, drives teardown/STR ordering, and owns
STR retry and compensation state.

Known additional STR/STA AVPs are not merely framed: dictionary fixed widths,
Address, UTF-8, DiameterIdentity, and grouped framing are validated on both
decode and encode. RFC 7683 OC-Supported-Features/OC-OLR and RFC 8583 Load use
their bounded child schemas, reject duplicate or unknown mandatory children,
and enforce their flag and value contracts using the full vendor-aware AVP key.
Unknown optional grouped children obey preserve/drop policy. The typed answer surface selects
only RFC 7683's loss algorithm. Received OC-OLR/Load groups retain RFC-defined
optional children after validating every present child; an originated loss OLR
must include OC-Reduction-Percentage, and an originated Load must include
Load-Type, Load-Value, and SourceID. Originated DRMP and Load AVPs always clear
M; as required by TS 29.273 table 7.2.3.1/2 note 2, the receiver tolerates an
M-bit mismatch for those recognized AVPs while continuing to enforce V, P,
type, grouped-child, and cardinality rules. An OC offer permits, but does not
require, a reporting-node selection in the answer; an emitted selection still
must be offered, and OC-OLR still requires same-answer OC support.

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
