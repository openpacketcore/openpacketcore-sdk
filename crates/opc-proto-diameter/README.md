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
  `*_with_provenance` request parsers cover CER, DWR, DPR, and SWm
  DER/STR/ASR/RAR/AAR (plus their SWm transaction-envelope forms); legacy
  parser signatures delegate to
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
  Session-Termination STR/STA, Abort-Session ASR/ASA, Re-Auth RAR/RAA, and AA
  AAR/AAA helpers. Typed DER and DEA builders emit every ordered, opaque `State`
  value with the mandatory bit required by RFC 4005 sections 9.3 and 9.3.4;
  callers return received values byte-for-byte without interpreting them. The
  lifecycle envelopes bind both Diameter identifiers, the P bit, a present
  exact `Session-Id`, and ordered Proxy-Info. Outbound envelopes additionally
  require an authenticated connection-generation token and may apply an
  explicit direct-host, routed-realm, or connection-only routed Origin policy;
  RFC 6733 generic E-bit answers, including the permitted permanent-failure
  fallback, may omit Session-Id and skip logical-Origin policy, but still
  require the exact connection, transaction, P, and Proxy-Info chain. The
  initial outbound STR, ASR, RAR, or AAR clears T, and each envelope exposes a
  one-way
  `mark_for_failover_retransmission` transition for queued, unacknowledged
  state resent after link failover or recovery; the transition atomically
  installs the replacement connection binding and its caller-reserved
  Hop-by-Hop Identifier while retaining End-to-End duplicate identity.
  SWm STR and ASR `User-Name` are required by the TS 29.273 procedure tables and
  retain
  sealed missing-AVP provenance despite the reused command CCF showing it as
  optional. RAR/RAA and AAR/AAA use the same connection-bound answer contract
  and add checked request omission provenance, typed authorization-update
  state, exact ordinary-answer session/user/proxy correlation, generic E-bit
  error reception, and failover-only T-bit transitions that atomically replace
  the Hop-by-Hop Identifier and authenticated peer binding. The
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
  Diameter-EAP DER/DEA also expose typed `MIP6-Feature-Vector` and repeated
  3GPP `Supported-Features`; DER additionally exposes `UE-Local-IP-Address`,
  RFC 5777 `QoS-Capability`, `Visited-Network-Identifier`,
  `AAA-Failure-Indication`, reused `High-Priority-Access-Info`, and the RFC
  7683 baseline overload offer. DEA exposes the correlated loss-algorithm
  selection/report and ordered RFC 8583 Load reports.
  DER and DEA also expose distinct, sealed parser-populated `extensions`
  collections for the trailing command wildcard. `UnknownIePolicy::Preserve`
  retains at most 128 command-unmodeled optional M-clear AVPs in received
  order, `Drop` accepts and discards them, and `Reject` or an unknown M-bit AVP
  fails closed. The
  collections expose only by-value code, vendor, flags, and length metadata;
  neither `SwmAdditionalAvp` wrappers nor values are directly exposed by that
  metadata API. Parser-retained values can only be replayed through the
  same-role typed builder. There is no public nonempty constructor or mutation
  API. Use `Default::default()` for
  originated struct literals. Rebuilding a parsed typed endpoint message moves retained
  extensions to the trailing wildcard and canonicalizes framing, so an exact
  relay or proxy must continue forwarding the raw `Message` bytes instead.
  M-set routing AVPs are modeled separately: DER retains ordered
  `Proxy-Info` and `Route-Record`, while DEA retains ordered `Proxy-Info` and
  forbids `Route-Record` reflection. Generic E-bit answers use the strict
  response/correlation boundary described below.
  `SwmMip6FeatureVector::gtpv2_only()` emits the exact
  `0x0000400000000000` capability; despite the legacy AVP name, that bit is
  independent of bearer IP family and is not limited to IPv6. Meanwhile,
  `SwmRequestedSupportedFeatures::swm_discovery()` emits SWm list identity
  `(10415, 1)` with value zero and request M clear. Correlation requires exact
  `DIAMETER_SUCCESS` before a DEA can authorize mobility, accepts the TS
  collective PMIP6/GTPv2 selection, and rejects unoffered non-NBM bits.
  The codec does not own a multi-round EAP procedure state machine: a consumer
  must carry the same access context into each continuation DER. For an attach
  where all four conditional access-context facts have independently been
  established, a GTPv2-only deployment can build the request without raw AVPs:

  ```rust
  use std::net::IpAddr;
  use opc_proto_diameter::apps::swm::{
      build_swm_diameter_eap_request_with_access_context,
      SwmAaaFailureIndication, SwmConditionalValue, SwmDerAccessContext,
      SwmBuiltDerAccessContextRequest, SwmDiameterEapRequest,
      SwmHighPriorityAccessInfo, SwmMip6FeatureVector, SwmQosCapability,
      SwmQosProfileTemplate, SwmRequestedSupportedFeatures,
      SwmVisitedNetworkIdentifier,
  };
  use opc_proto_diameter::VendorId;
  use opc_protocol::EncodeContext;

  fn build_access_context(
      request: &mut SwmDiameterEapRequest,
      ue_ip: IpAddr,
      hop_by_hop_identifier: u32,
      end_to_end_identifier: u32,
  ) -> Result<SwmBuiltDerAccessContextRequest, Box<dyn std::error::Error>> {
      request.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());
      request.supported_features =
          vec![SwmRequestedSupportedFeatures::swm_discovery()];
      request.ue_local_ip_address = Some(ue_ip);

      let access_context = SwmDerAccessContext {
          qos_capability: SwmConditionalValue::LocallyConfigured(
              SwmQosCapability::new(vec![
                  SwmQosProfileTemplate::new(VendorId::new(0), 0),
              ])?,
          ),
          visited_network_identifier: SwmConditionalValue::LocallyConfigured(
              SwmVisitedNetworkIdentifier::new("001", "01")?,
          ),
          aaa_failure_indication: SwmConditionalValue::AaaDerived(
              SwmAaaFailureIndication::previously_assigned_server_unavailable(),
          ),
          high_priority_access_info: SwmConditionalValue::UeProvided(
              SwmHighPriorityAccessInfo::configured(),
          ),
      };
      Ok(build_swm_diameter_eap_request_with_access_context(
          request,
          access_context,
          hop_by_hop_identifier,
          end_to_end_identifier,
          EncodeContext::default(),
      )?)
  }
  ```

  Use `SwmConditionalValue::Absent` for each condition that does not apply;
  in particular, omit the visited-network identifier at home and omit the AAA
  failure indication during an ordinary server selection. Provenance is a
  local construction fact and is intentionally not inferred by the wire
  parser. The checked builder owns the typed request, encoded message, and an
  informational source snapshot in one immutable wrapper while it is retained.
  Consuming `into_parts` ends that coupling. The ordinary typed
  wire builder remains available for parser replay but cannot attest source.
  Debug output exposes only source/presence/count metadata. Builders
  set the current TS 29.273 flags, while understood outer M-bit mismatches are
  accepted and canonicalized on rebuild. RFC 5777 optional grouped extensions
  follow `UnknownIePolicy`; unknown mandatory children always fail.

  Preserve these fields when replacing the EAP payload and `State` values for
  a subsequent round; parsing and rebuilding a typed request retains the exact
  vector value.
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
Missing Vendor-Id, Feature-List-ID, or Feature-List inside a DER
Supported-Features group uses the same sealed nested provenance and produces a
vendor-correct minimum child inside the exact received group header.

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
| `app-swm` | no | SWm dictionary plus typed DER/DEA, STR/STA, ASR/ASA, RAR/RAA, and AAR/AAA helpers. |
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

Typed helpers distinguish diagnostic redaction from sensitive ownership.
`avp::dictionary::Redacted<T>` hides `Debug` and `Display` only;
`avp::dictionary::Sensitive<T>` additionally keeps its owned value in
zeroizing storage. Each `Sensitive` clone owns independently zeroizing storage.
STR/STA `Session-Id` and permanent `User-Name` fields use `Sensitive<String>`;
direct struct construction accepts string literals or owned strings through
`.into()`. `Sensitive::from_zeroizing` adopts an existing `Zeroizing` owner
without copying, and consumers that move a value into longer-lived state can
call `Sensitive::into_zeroizing` to retain the erasure contract.

This is best-effort process-memory hygiene, not a claim that all copies are
erasable. Previously reallocated memory, raw decoded input, encoded Diameter
messages, transport retry caches, swap, and kernel/network buffers are outside
the wrapper's ownership and must be governed separately.

Use `CONFORMANCE.md` for the precise fixture provenance, fuzz target status,
application dictionary status, and typed helper gaps.

### SWm Diameter-EAP overload and load context

`SwmDiameterEapRequest::oc_supported_features` carries the optional RFC 7683
reacting-node offer. `SwmDiameterEapAnswer::{oc_supported_features, oc_olr}`
carry the reporting-node selection and loss report, and `load_reports` retains
bounded RFC 8583 Load AVPs in wire order. All four new request/answer fields
remain optional, so initializing them as `None`, `None`, `None`, and
`Vec::new()` preserves the earlier DER/DEA wire shape. Grouped unknown optional
children are retained privately under
`UnknownIePolicy::Preserve`; callers cannot inject raw overload children.

This surface deliberately implements the RFC 7683 baseline loss algorithm for
SWm. The later RFC 8581 peer-overload report extension (`OC_PEER_REPORT`, peer
report type, `OC-Peer-Algo`, and overload `SourceID`) is not an executable
selection in this slice. Received request capability vectors may retain
extension bits for inspection, but builders reject re-originating any vector
other than loss. Do not describe this as complete/current DOIC support.

Overload response AVPs are strictly request-conditioned. The answer-local
`build_swm_diameter_eap_answer` rejects `OC-Supported-Features` and `OC-OLR`;
use `build_swm_diameter_eap_answer_for` so the SDK proves that the DER offered
the selected algorithm. The same validation applies when request and answer
envelopes are correlated. An offered request may receive no selection from a
non-reporting node. Load is independent of that negotiation and can be encoded
at the answer-local boundary.

```rust
use opc_proto_diameter::apps::swm::{
    build_swm_diameter_eap_answer_for, SwmDiameterEapAnswer,
    SwmDiameterEapRequestEnvelope, SwmLoad, SwmLoadType, SwmOcOlr,
    SwmOcReportType, SwmOcSupportedFeatures,
};
use opc_protocol::EncodeContext;

fn add_overload_context(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &mut SwmDiameterEapAnswer,
) -> Result<(), Box<dyn std::error::Error>> {
    // The corresponding DER set request.oc_supported_features to loss().
    answer.oc_supported_features = Some(SwmOcSupportedFeatures::loss());
    answer.oc_olr = Some(SwmOcOlr::new_loss(
        7,
        SwmOcReportType::Host,
        Some(60),
        25,
    )?);
    answer.load_reports.push(SwmLoad::new(
        SwmLoadType::Host,
        50_000,
        "aaa.example.invalid",
    )?);
    let _message = build_swm_diameter_eap_answer_for(
        request,
        answer,
        EncodeContext::default(),
    )?;
    Ok(())
}
```

`SwmOcOlr` exposes both exact wire values and safe effective values. An absent
or greater-than-86400 validity duration yields the RFC default of 30 seconds;
a reduction percentage greater than 100 is exposed as non-actionable. Such
received values parse for standards-compatible observation but cannot be
re-originated. A received Load group may omit its individually optional
children; `complete_tuple()` then returns `None`, and builders reject it.
Before applying a `PEER` Load report, call `actionable_for_peer` with the
authenticated connection's DiameterIdentity; a mismatched SourceID is ignored
as RFC 8583 requires. Consumers still own overload state, expiry timers,
routing decisions, and authenticated transport identity.

OC AVPs accept the application-controlled M bit and require V/P clear. Builders
emit M clear. Load builders also emit M clear, while received Load ignores a
known M mismatch under TS 29.273 table 7.2.3.1/2 note 2. Use
`Message::decode_with_dictionary` with the SWm dictionary when conservative
duplicate rejection is enabled so only declared repeated Load AVPs bypass the
blanket duplicate pre-scan.

### SWm DEA authorization timers

`SwmDiameterEapAnswer::session_timeout` is an optional
`SwmSessionTimeout`. `None` means the AAA server supplied no timeout, while
`Some(SwmSessionTimeout::unlimited())` preserves an explicit RFC 6733 zero
value. TS 29.273 conditions this field on successful authentication and
authorization, so the codec permits it only with exact base
`DIAMETER_SUCCESS` (2001), not another 2xxx or an experimental result. The SDK
reports the value but does not schedule re-authentication or session teardown.

The base Diameter grammar permits omission, and existing SWm peers and public
typed literals predate this field. The parser and builder therefore preserve
an absent value and its prior bytes. A deployment applying the stricter TS
29.273 initial-authorization condition should require it at the product policy
boundary.

`authorization_lifetime`, `auth_grace_period`, and
`re_auth_request_type` expose the related RFC 6733 answer context. Positive
`Authorization-Lifetime` requires a typed `SwmReAuthRequestType`. When both
timers are finite and nonzero, `Session-Timeout` cannot be smaller than
`Authorization-Lifetime`; explicit timeout zero is unlimited. No relationship
is invented for `Auth-Grace-Period`. TS 29.273 requires SWm to omit
`Auth-Session-State`, so the parser rejects it even if its M bit is clear and
the configured unknown-AVP policy would otherwise drop it.

```rust
use opc_proto_diameter::apps::swm::{
    SwmDiameterEapAnswer, SwmReAuthRequestType, SwmSessionTimeout,
};

fn set_success_timers(answer: &mut SwmDiameterEapAnswer) {
    answer.session_timeout = Some(SwmSessionTimeout::from_seconds(3_600));
    answer.authorization_lifetime = Some(3_000);
    answer.auth_grace_period = Some(60);
    answer.re_auth_request_type = Some(SwmReAuthRequestType::AuthorizeOnly);
}
```

Diagnostics expose only timer presence.

### SWm DEA serving and emergency gateway context

`SwmDiameterEapAnswer::gateway_context()` exposes parsed RFC 5447
`MIP6-Agent-Info` and 3GPP `Emergency-Info` as redaction-safe typed wire facts.
The shared `SwmMip6AgentInfo` model retains up to two home-agent addresses in
wire order, an optional `Destination-Realm`/`Destination-Host` indirection,
an optional 17-octet IPv6 home-link prefix, and bounded optional extension
children. Address presence has RFC selection precedence over host identity,
but the host is not discarded. Public `Debug` output reports only counts and
presence.

Top-level `MIP6-Agent-Info` identifies the Serving-GW only for chained S2b-S8.
Nested `Emergency-Info` identifies the dynamically allocated emergency PDN-GW
only for the authenticated, non-roaming, HSS-derived condition and an emergency
DER. Both require exact base `DIAMETER_SUCCESS`. The request-bound construction
API names these conditions instead of accepting raw provenance booleans:

```rust
use opc_proto_diameter::apps::swm::{
    build_swm_diameter_eap_answer_for_with_gateway_context,
    SwmDiameterEapAnswer, SwmDiameterEapRequestEnvelope, SwmMip6AgentInfo,
    SwmRequestBoundDeaGatewayContext,
};
use opc_protocol::EncodeContext;

fn build_chained_answer(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
    serving_gateway: SwmMip6AgentInfo,
) -> Result<opc_proto_diameter::OwnedMessage, opc_protocol::EncodeError> {
    let context = SwmRequestBoundDeaGatewayContext::chained_s2b_s8(
        request,
        serving_gateway,
    );
    build_swm_diameter_eap_answer_for_with_gateway_context(
        request,
        answer,
        &context,
        EncodeContext::default(),
    )
}
```

Parsed identities are intentionally not authorization evidence. On a live
client connection, parse with
`parse_swm_diameter_eap_response_envelope_from_connection`, correlate through
`SwmDiameterEapRequestEnvelope::correlate_response`, and only then call
`authorize_chained_s2b_s8_gateway` or
`authorize_authenticated_non_roaming_emergency_gateway` with the corresponding
caller-assertion token on the resulting `SwmCorrelatedDiameterEapResponse`.
That path checks the authenticated connection generation as well as exact
message/result/request correlation. The consumer remains responsible for
establishing the routing, authentication, roaming, and HSS-provenance
assertions. The answer-envelope correlation API remains available to a trusted
server-side/originated boundary, but it is not a substitute for transport peer
authentication on received network traffic.

Canonical builders set M on every `MIP6-Agent-Info`. TS 29.272/29.273 require
receivers that understand this reused AVP to ignore an M-bit mismatch, so both
M values are accepted at DEA top level and inside `Emergency-Info`; V and P
remain prohibited. `Emergency-Info` sets vendor 10415, clears P, and accepts
either standards-permitted M value. Unknown optional grouped children follow
`UnknownIePolicy` and share the DEA retention count/byte budget; unknown
mandatory children fail closed.
### SWm DEA subscriber authorization facts

`SwmDiameterEapAnswer::subscriber_authorization` groups the finite top-level
subscriber rows from TS 29.273 V19.2: `APN-OI-Replacement`, the RFC 4006
E.164 `Subscription-Id` form, `3GPP-Charging-Characteristics`,
`UE-Usage-Type`, `Core-Network-Restrictions`, and `MPS-Priority`. Existing
answer struct literals must add
`subscriber_authorization: SwmDeaSubscriberAuthorization::default()`; an empty
bundle emits no AVPs and preserves the prior DEA bytes.

The types enforce wire syntax rather than product authorization policy.
`SwmE164Number` accepts one through fifteen decimal digits beginning with 1
through 9; dialling prefixes, `+`, whitespace, separators, zero-prefixed
numbers, and all-zero dummy values are not E.164 numbers on this wire. Its
retained allocation is redacted and zeroized on drop.
`SwmApnOiReplacement` accepts the case-insensitive suffix
`mncNNN.mccNNN.gprs`, with exactly three digits per PLMN label and optional
valid DNS-style prefix labels.
`SwmChargingCharacteristics` exposes the defining two octets while the codec
accepts upper- or lowercase hexadecimal and emits four uppercase characters.
Core-network and MPS bitmasks expose only assigned bits; deprecated or unknown
received bits are discarded before canonical replay. `UE-Usage-Type` is
bounded to the standardized/operator range 0 through 255. When MPS-Priority is
present on SWm, `MPS-EPS-Priority` must be set; all-zero and CS- or
messaging-only masks fail on parse and build.

`APN-OI-Replacement` is the one request/result-conditioned value in this
bundle: it requires exact base `DIAMETER_SUCCESS`, a non-emergency DER, and a
correlated effective network-based mobility mode. A DER offer of either PMIPv6
or GTPv2 permits the collective network-based mobility selection defined by TS
29.273. An explicit DEA `MIP6-Feature-Vector` is AAA-derived and always takes
precedence. When the DEA omits that vector, an application may attach trusted
local mode provenance to the retained request envelope with
`with_locally_configured_mobility_mode`; parsed and default envelopes invent no
such provenance and fail closed for APN-OI. Originate APN-OI only through
`build_swm_diameter_eap_answer_for`, which checks this boundary. After answer
correlation, `effective_mobility_mode()` and `mobility_mode_source()` expose
the selected mode and whether it came from AAA or local configuration. The
other five rows are typed subscriber facts and may occur on an ordinary
non-success DEA; their presence never turns that result into authorization
success.

```rust
use opc_proto_diameter::apps::swm::{
    build_swm_diameter_eap_answer_for, SwmApnOiReplacement,
    SwmChargingCharacteristics, SwmDeaSubscriberAuthorization,
    SwmDiameterEapAnswer, SwmDiameterEapRequestEnvelope, SwmE164Number,
    SwmLocallyConfiguredMobilityMode, SwmSubscriptionId, SwmUeUsageType,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::EncodeContext;

fn build_dea_with_subscriber_facts(
    request: SwmDiameterEapRequestEnvelope,
    mut answer: SwmDiameterEapAnswer,
) -> Result<OwnedMessage, Box<dyn std::error::Error>> {
    // This trusted site policy is retained beside the transaction. It is used
    // only because this answer intentionally carries no explicit AAA mobility
    // selection.
    let request = request.with_locally_configured_mobility_mode(
        SwmLocallyConfiguredMobilityMode::NetworkBased,
    );
    answer.mip6_feature_vector = None;
    answer.subscriber_authorization = SwmDeaSubscriberAuthorization::new()
        .with_apn_oi_replacement(SwmApnOiReplacement::new(
            "mnc001.mcc001.gprs",
        )?)
        .with_subscription_id(SwmSubscriptionId::e164(SwmE164Number::new(
            "15551234567",
        )?))
        .with_charging_characteristics(SwmChargingCharacteristics::from_octets([
            0x01, 0x02,
        ]))
        .with_ue_usage_type(SwmUeUsageType::new(128));
    Ok(build_swm_diameter_eap_answer_for(
        &request,
        &answer,
        EncodeContext::default(),
    )?)
}
```

RFC 4006 permits P on the `Subscription-Id` group and its two required
children; TS 29.061 likewise permits P on charging characteristics. Parsers
accept those forms and builders emit canonical P-clear AVPs. Under TS 29.273's
understood-AVP rule, APN-OI, the outer Subscription-Id group, charging
characteristics, UE usage, core restrictions, and MPS priority accept either
received M value. Builders still emit their exact canonical M values: set for
APN-OI and outer Subscription-Id, clear for the other four. Subscription-Id's
required children remain M-set on receive and encode. Optional unknown
children follow `UnknownIePolicy`: Preserve retains them in a sealed,
value-redacted collection for replay, Drop discards them, Reject refuses them,
and unknown M-set children always fail. All six top-level rows remain singleton
and are rejected on DER. The Rf and SWm dictionaries share P-permitted
metadata, but Rf retains RFC 4006's required outer M bit. Only the SWm
application dictionary tolerates either outer M shape. SWm required children
remain strict, and Rf's established parser behavior is unchanged.

A vendor-specific child that reuses the core Subscription-Id-Type or
Subscription-Id-Data code is rejected even when valid IETF children are also
present; it never enters optional-extension retention. The six top-level
subscriber codes likewise require their exact IETF/3GPP vendor identity under
every unknown-AVP policy, including explicit Vendor-Id zero.
### SWm Diameter-EAP generic errors, routing, and redirect

`parse_swm_diameter_eap_response` selects the response grammar from the
Diameter E bit. E-clear responses use the ordinary TS 29.273 DEA model. E-set
responses use RFC 6733 section 7.2's generic grammar and therefore do not
require application-only `Auth-Application-Id`, `Auth-Request-Type`, or EAP
AVPs. The generic parser requires base `Result-Code`, accepts the RFC-permitted
3xxx and permanent/unrecognized fallback families, and keeps an accompanying
`Experimental-Result` distinct. The numeric value 3006 has redirect semantics
only when carried as the base `Result-Code` with E set.

Inbound redirect targets are sealed until the answer has been correlated with
the retained DER. A live transport supplies a process-unique
`SwmDiameterConnectionToken`; correlation then checks that connection
generation, both Diameter identifiers, P, the exact ordered `Proxy-Info`
chain, and `Session-Id` when the generic answer carries it. An ordinary answer
also checks the configured logical-Origin policy and application fields. A
generic error may be originated by an intermediary, so it skips only that
logical-Origin check. Never make a redirect decision from the answer-local
parser:

```rust
use opc_proto_diameter::apps::swm::{
    parse_swm_diameter_eap_response_envelope_from_connection,
    SwmDiameterConnectionToken, SwmDiameterEapRequestEnvelope,
};
use opc_proto_diameter::Message;
use opc_protocol::DecodeContext;

fn correlate_response<'a>(
    pending: SwmDiameterEapRequestEnvelope,
    message: &Message<'a>,
    connection: SwmDiameterConnectionToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let received = parse_swm_diameter_eap_response_envelope_from_connection(
        message,
        connection,
        DecodeContext::conservative(),
    )?;
    let correlated = pending.correlate_response(received)?;
    if let Some(redirect) = correlated.redirect() {
        // Target selection, connection establishment, cache storage, and
        // expiry are product policy. Do not log the target values.
        let _ordered_targets = redirect.hosts();
        let _cache_scope = redirect.effective_usage();
        let _cache_seconds = redirect.max_cache_time();
    }
    Ok(())
}
```

`SwmDiameterRedirect` validates one or more DiameterURI targets and preserves
their wire order, but RFC 6733 does not define that order as target preference.
An absent `Redirect-Host-Usage` and explicit `DONT_CACHE` remain distinct;
both have an effective no-cache policy. `Redirect-Max-Cache-Time` is required
for a nonzero/cacheable usage and is preserved, but ignored for routing-cache
purposes, when usage is absent or `DONT_CACHE`. The type exposes the RFC cache
route precedence separately from the numeric enumerated order.

The public generic origination surface is intentionally limited to exact
`DIAMETER_REDIRECT_INDICATION` through
`SwmDiameterEapGenericErrorAnswer::new_redirect` and the request-bound
`build_swm_diameter_eap_response_for`. It copies Session-Id, P, both
identifiers, and exact Proxy-Info, clears R/T, sets E, and never reflects a DER
Route-Record. Other originated protocol or application failures must use
`error_answer::build_diameter_error_answer`, whose bound failure token proves
the request and any required Failed-AVP. A parsed generic response cannot be
re-encoded through the redirect builder; exact retransmission uses a cached
`OwnedMessage`.

Both routing roles share a 128-AVP retained count and the decode context's
message-byte bound. Proxy-Info requires exactly one nonempty ASCII Proxy-Host
and one opaque Proxy-State, applies the configured unknown-child policy, and
caps grouped children at 128. DER permits ordered repeated Route-Record;
every DEA profile forbids it. Ordinary E-clear DEA may receive repeated opaque
Failed-AVP for value-free metadata, but the mutable typed answer cannot
re-originate that evidence. Generic receive parsing enforces Failed-AVP for the
RFC result codes where its presence is a MUST while retaining the inner value
opaque, because RFC 6733 permits synthesized and malformed offending AVP
representations.

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

A server-side duplicate cache can compare two retained STR envelopes with
`initial.same_replay_payload(&candidate)`. On top of RFC 6733 duplicate
identity, the redaction-safe SDK guard requires the same End-to-End Identifier,
P bit, typed request facts, ordered Route-Record and extension AVPs, and exact
ordered Proxy-Info chain. It ignores the Hop-by-Hop Identifier, T bit, and
authenticated expected-answer peer binding that may change across failover.
It also ignores only the derived length within each retained AVP header, since
the encoder recomputes that field from the value. The operation neither exposes
raw AVP values nor decides duplicate-cache lifetime or active-session ownership.

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

A server-side duplicate cache can call
`initial.same_replay_payload(&candidate)` before replaying a committed ASA.
The redaction-safe boolean requires the same End-to-End Identifier, P bit,
typed ASR facts (including exact optional `Auth-Session-State` presence),
ordered Route-Record and retained extension AVPs, and exact ordered Proxy-Info
chain. It ignores only Hop-by-Hop, T, and the authenticated expected-answer
peer binding; retained AVP code, flags, Vendor-Id, and value remain exact while
their encoder-derived length is normalized. RFC 6733 and the SWm ASR grammar
define no dedicated Abort-Cause field: an abort-cause-like deployment extension
is retained and compared in `additional_avps`. Cache lifetime, live-session
authority, and replay disposition remain product policy.

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

### SWm authorization-information update

The TS 29.273 authorization-update boundary models the complete RAR/RAA then
AAR/AAA protocol sequence without owning subscriber policy or session lookup.
RAR and AAR request parsers have provenance-aware forms for checked 5005
answers. Request and answer envelopes retain both transaction identifiers, P,
present Session-Id/User-Name, the actual E bit, and the ordered Proxy-Info
chain. An outbound RAR or AAR additionally requires an authenticated
connection-generation token and an explicit direct, realm-routed, or routed
logical-Origin policy. Destination AVPs are not authentication evidence: an
AAR sent through a DRA should normally use `SwmExpectedAnswerPeer::routed`, so
the final AAA server's Origin remains valid. Generic E-bit agent errors may
omit the application CCF fields and are exempt from logical-Origin matching,
but still require the exact authenticated connection, transaction, P bit, and
Proxy-Info chain. Correlation also validates RFC 7683 overload negotiation.
The answer command metadata retains RFC 6733 Redirect-Host cardinality for the
generic error boundary, while typed RAA/AAA parsing and emission fail closed on
redirect contexts until their complete result-specific surface is modeled.

An endpoint acknowledges a valid RAR, then commits the follow-up AAR through
the public type-state sequence:

```rust
use opc_proto_diameter::Message;
use opc_proto_diameter::apps::swm::{
    parse_swm_re_auth_request_envelope, AuthRequestType,
    SwmAcceptedAuthorizationUpdate, SwmAuthorizationRequest,
    SwmDiameterConnectionToken, SwmDiameterTransaction, SwmExpectedAnswerPeer,
    SwmReAuthAnswer, SwmReAuthResult,
};
use opc_protocol::{DecodeContext, EncodeContext};

# fn update(
#     message: &Message<'_>,
#     local_origin_host: &str,
#     local_origin_realm: &str,
#     aar_connection: SwmDiameterConnectionToken,
#     replacement_connection: SwmDiameterConnectionToken,
# ) -> Result<(), Box<dyn std::error::Error>> {
let rar = parse_swm_re_auth_request_envelope(
    message,
    DecodeContext::conservative(),
)?;
let session_id = rar.request().session_id.clone();
let user_name = rar.request().user_name.clone();
let raa = SwmReAuthAnswer::for_request(
    &rar,
    SwmReAuthResult::Success,
    local_origin_host.to_owned(),
    local_origin_realm.to_owned(),
);
let accepted = SwmAcceptedAuthorizationUpdate::accept(
    rar,
    raa,
    EncodeContext::default(),
)?;
let mut pending = accepted.begin_authorization(
    SwmAuthorizationRequest {
        session_id,
        origin_host: "epdg.example".to_owned().into(),
        origin_realm: "example".to_owned().into(),
        destination_realm: "aaa.example".to_owned().into(),
        destination_host: None,
        user_name,
        auth_request_type: AuthRequestType::AuthorizeOnly,
        authorization_lifetime: None,
        auth_grace_period: None,
        aar_flags: None,
        ue_local_ip_address: None,
        high_priority_access_info: None,
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    },
    SwmDiameterTransaction::new(0x1020_3041, 0x5060_7081),
    SwmExpectedAnswerPeer::routed(aar_connection),
    EncodeContext::default(),
)?;
let initial_aar = pending.initial_authorization_request();
let retry_aar = pending.retransmit_authorization_request();
// Only after a link failover or equivalent recovery:
pending.mark_for_failover_retransmission(
    0x1020_3042,
    SwmExpectedAnswerPeer::routed(replacement_connection),
    EncodeContext::default(),
)?;
let failover_aar = pending.retransmit_authorization_request();
# let _ = (initial_aar, retry_aar, failover_aar);
# Ok(())
# }
```

The initial AAR and ordinary cached timer retry are byte-identical with T
clear. `mark_for_failover_retransmission` is the explicit one-way transition
that creates a stable T-set form for queued, unacknowledged state resent after
link failover or equivalent recovery. It atomically installs the caller-reserved
replacement Hop-by-Hop Identifier and authenticated connection binding while
preserving the End-to-End Identifier. RAR and AAR envelopes retain an inbound T
bit, while RAA and AAA always clear it.
`SwmAcceptedAuthorizationUpdate` also caches the committed RAA for exact
duplicate-request replay. The consumer still owns duplicate detection, cache
lifetime, retry timers, session mutation, and when an accepted RAA advances to
AAR.

Before replaying that committed RAA, a server-side duplicate cache can use
`initial.same_replay_payload(&candidate)`. The RAR operation applies the same
redaction-safe contract as ASR/STR: it requires the End-to-End Identifier, P,
every typed RAR fact (including `Re-Auth-Request-Type`), exact ordered
Route-Record, retained extension AVPs, and Proxy-Info, while ignoring only
Hop-by-Hop, T, and expected-answer peer binding. Retained AVP length is
normalized because the encoder derives it; code, flags, Vendor-Id, order, and
value are not. It does not choose cache policy or mutate authorization state.

RAR requires `AUTHORIZE_ONLY`, exact Session-Id/User-Name, and the addressed
Destination-Host used by the procedure. AAR/AAA require
`Auth-Request-Type = AUTHORIZE_ONLY`. AAA preserves exactly one base or grouped
experimental result and optionally exposes a typed APN-Configuration on exact
base success. RAA and AAA expose the optional typed Re-Auth-Request-Type and
preserve repeated Reply-Message values in their redaction-safe extension
collections; RAR declares Reply-Message as a singleton. A protocol-error-class
experimental result is rejected on origination because RFC 6733's E-bit
grammar requires a base Result-Code.
RAA and AAR expose singleton RFC 6733 `Authorization-Lifetime` and
`Auth-Grace-Period` values in seconds; AAA exposes both plus the singleton
TS 29.273 `Session-Timeout`. RAR forbids all three, and `Session-Timeout` is
forbidden in the other two SWm roles. A positive answer lifetime requires a
typed `Re-Auth-Request-Type`, and a nonzero AAA `Session-Timeout` cannot be
smaller than its `Authorization-Lifetime`. When AAR supplies an
`Authorization-Lifetime` maximum, every success-class AAA must return a
lifetime no greater than that request value; request-bound build and
correlation reject an omission or increase. Authorization lifetime zero means immediate
re-authorization, `u32::MAX` or absence means none is expected; session timeout
zero or absence means unlimited. Typed diagnostics expose only presence, never
timer values.
Typed AAR flags, UE local IP address, and high-priority access values are
canonicalized; originated UE-Local-IP-Address clears M. The RAA Origin values
must come from trusted local endpoint configuration and are never inferred
from request Destination AVPs. Received generic E-bit RAA/AAA errors require a
base Result-Code but may omit Session-Id, User-Name, Auth-Application-Id, and
Auth-Request-Type as allowed by RFC 6733's generic answer grammar. Following
TS 29.273 Table 7.2.3.1 Note 2, decode
ignores an M-bit mismatch on understood table AVPs; encode always emits the
table's canonical M bit. Unknown optional AVPs obey the configured preserve,
drop, or reject policy. All typed diagnostics redact subscriber, session,
address, proxy, and extension values.

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

For an ordinary base result, use
`SwmDiameterResult::is_diameter_authorization_rejected()` to identify exact
RFC 6733 `DIAMETER_AUTHORIZATION_REJECTED` (5003). The helper deliberately
returns false for base value 4001 (`DIAMETER_AUTHENTICATION_REJECTED`) and for
an `Experimental-Result` that happens to reuse numeric value 5003. Choosing an
IKEv2 or other access-protocol response from that wire fact remains product
policy; this crate does not translate between protocols.

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
