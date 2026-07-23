# opc-proto-gtpv2c

S2b-focused GTPv2-C codec for OpenPacketCore.

## Purpose

`opc-proto-gtpv2c` implements a bounded GTPv2-C subset for ePDG/PGW S2b work.
It combines a raw-preserving common-header and TLIV IE layer with typed S2b IE
and message views for Echo, session-oriented procedures, and the PGW-triggered
Create Bearer, Update Bearer, and Delete Bearer procedures.

It is not a complete GTPv2-C implementation and not an ePDG or PGW
control-plane stack.

## API Shape

- `header` exposes `Header`, the bounded `MessagePriority` value,
  `MessageType`, `decode_header`, and `encode_header`. TEID-present EPC
  headers accept the TS 29.274 MP flag and four-bit priority; no-TEID headers
  keep bit 3 as spare.
- `ie` exposes `RawIe`, `OwnedRawIe`, `RawIeIterator`, `validate_ie_region`,
  `TypedIe`, `TypedIeValue`, and typed S2b IE structs such as `Cause`,
  `Recovery`, `AccessPointName`, `BearerContext`, `FullyQualifiedTeid`, and
  `PdnAddressAllocation`, `ChargingCharacteristics`, `TraceInformation`, and
  Diameter/IKEv2-discriminated `RanNasCause`. IKEv2 release causes carry a
  validated `Ikev2ErrorNotifyType` in RFC 7296's `0..=16383` error range;
  `RanNasCause::ikev2` is fallible. S2b session context and tunnel updates
  additionally use redaction-safe typed `IpAddress`, `PortNumber`, complete
  bounded `TwanIdentifier`, and `TwanIdentifierTimestamp` values.
  Their Extendable IE decoders retain the
  known Release 18 prefix while raw-preserving message encode retains accepted
  later-release suffixes; canonical encode emits only understood fields and
  zero TWAN spare flags. PAA has explicit dynamic IPv4/IPv6/IPv4v6,
  AAA-provided static IPv4/IPv6/IPv4v6, Non-IP, and Ethernet constructors;
  encode validates that the selected family matches its address fields.
- `Message<'a>` and `OwnedMessage` provide the raw borrowed/owned message
  shells and implement the shared `opc-protocol` codec traits.
- `inspect_gtpv2c_request` and `Gtpv2cErrorResponsePlanner` form a separate
  zero-allocation error boundary. Inspection retains only a reply-safe fixed
  header envelope; planning returns either an explicit standards-required
  discard or a bounded Version Not Supported, Echo, or ordinary S2b response.
  Ordinary protocol failures require a caller-owned non-zero remote TEID or an
  explicit no-lookup TEID-zero choice. An unknown received non-zero TEID is a
  separate type that alone can produce Context Not Found; applying it to a
  legitimate zero-TEID initial request fails closed without a response plan.
- `S2bMessage<'a>` and `S2bProcedureMessage<'a>` provide typed S2b views and
  raw fallback for unsupported message types. `decode_with_diagnostics`
  additionally returns bounded, value-free `S2bReceiveDiagnostics` evidence
  for ignored duplicate singleton keys.
- `S2bCreateSessionIdentity`, `S2bCreateSessionContext`, and
  `S2bDeleteSessionContext` own the conditional S2b attach/detach fields.
  Product policy explicitly chooses optional presence and supplies subscriber,
  trace, charging, and location data. The builder validates the declared
  decision, exact instances, and cross-fields without fetching AAA/HSS data or
  inventing policy. `S2bUeEndpoint` separates UE local IP/NAT state from the
  Create-only Fixed Broadband ePDG IKEv2 endpoint. Matching receive projection
  methods expose the accepted context without logging values.
- `S2bUeIpsecTunnelUpdateRequest` is the S2b-specific Modify Bearer intent.
  WLAN location and timestamp are independently optional. Its endpoint enum
  makes the general and Fixed Broadband/local-policy forms distinct; UE UDP
  Port cannot be represented without UE Local IP. Procedure-aware receive
  keeps the first applicable singleton and discards the S5/S8 Bearer Context
  shape as a known unexpected IE before interpreting it. The request permits
  the Table 7.2.7-1 ePDG Overload Control Information only at instance 2.
  Request and response summary methods retain Cause, sequence, and TEID
  correlation metadata.
- `S2bCreateBearerRequest`/`Response`, `S2bUpdateBearerRequest`/`Response`,
  and `S2bDeleteBearerRequest`/`Response` project the complete S2b
  dedicated-bearer shapes claimed by this crate. Their builders enforce
  mandatory/conditional IE instances, APN-AMBR and per-bearer Update changes,
  mutually exclusive Delete forms, S2b-U F-TEID roles, per-bearer Causes, and
  exact request/response correlation.
- Bearer TFT IE values use the canonical `opc-proto-tft`
  `TrafficFlowTemplate`; GTPv2-C does not maintain a second TFT parser. Create
  Bearer additionally requires a Create-new TFT with at least one filter that
  definitely applies to uplink traffic. Projected semantic failures expose
  the applicable TS 29.274 Cause 74 or 76, while
  `dedicated_bearer_decode_rejection_cause` classifies malformed TFT wire
  values as Cause 75, 76, or 77 without exposing packet contents.
- PGW-triggered requests preserve the standardized request-only Load Control
  Information, Overload Control Information, and PGW Change Info IEs in wire
  order. Their Release 18 cardinalities are bounded before typed projection;
  responses retain strict singleton handling for these keys.
- `BearerQos` exposes typed allocation/retention priority and resource-type
  validation. GBR QCIs require a maximum rate in at least one direction and
  enforce each guaranteed rate no greater than its same-direction maximum;
  zero-rate directions remain representable. Standardized non-GBR QCIs require
  zero GBR/MBR fields. Operator-specific QCIs require an explicit
  caller-provided GBR/non-GBR classification.
- `PcoRequest` and `PcoAddressConfiguration` provide a bounded TS 24.008 inner
  codec for IPv4/IPv6 DNS and P-CSCF containers while the outer PCO/APCO IE
  transport remains opaque and byte-preserving.
  `PcoRequest::p_cscf_reselection_support` independently emits the exact empty
  request container `0x0012`; neither P-CSCF address-family flag implies the
  capability. Selected containers are encoded once in ascending identifier
  order, and `PcoRequest::none()` remains byte-empty.
- Public profile constructors build profile-valid owned messages:
  `s2b_echo_request`, `s2b_echo_response`,
  `s2b_create_session_request`,
  `s2b_create_session_accepted_response`,
  `s2b_create_session_rejected_response`,
  `s2b_ue_ipsec_tunnel_update_request`, `s2b_modify_bearer_response`,
  `s2b_delete_session_request`, `s2b_delete_session_response`,
  `s2b_update_bearer_request`, and `s2b_update_bearer_response`.
  The old bearer-context-shaped `s2b_modify_bearer_request` is deprecated and
  fails closed because that form belongs to S4/S11/S5/S8, not S2b.
- Accepted Create Session Responses use the PGW S2b control-plane F-TEID at
  instance 1 with interface type 32. The endpoint must carry a non-zero TEID
  and at least one IPv4 or IPv6 address. Instance-0 Sender F-TEID remains the
  Create Session Request role and is not substituted for the response role.
- `Gtpv2cEchoPeer` and the client-transaction helper types are
  transport-neutral state helpers; callers still own UDP, timers, persistence,
  and product policy.
- `Gtpv2cTriggeredTransactions` provides a bounded, transport-neutral inbound
  transaction boundary for Create, Update, and Delete Bearer. First
  observations dispatch generation-bound application work once, pending
  duplicates do not dispatch again, and committed duplicates replay the exact
  retained response bytes. A pending timeout becomes a retained
  cancellation-required tombstone; the application must cancel or roll back
  the identified generation and acknowledge it before that identity may
  dispatch again. Every observation requires the non-zero remote response
  TEID; response routing correlation cannot be disabled.

## Example

```rust
use bytes::BytesMut;
use opc_proto_gtpv2c::{s2b_echo_request, Recovery, S2bMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext, ValidationLevel};

let msg = s2b_echo_request(0x010203, Recovery { restart_counter: 7 })?;
let mut encoded = BytesMut::new();
msg.encode(&mut encoded, EncodeContext::default())?;

let ctx = DecodeContext {
    validation_level: ValidationLevel::ProcedureAware,
    ..DecodeContext::default()
};
let (tail, decoded) = S2bMessage::decode_with_diagnostics(&encoded, ctx)?;
assert!(tail.is_empty());
assert!(decoded.message().as_view().is_some());
assert!(decoded.diagnostics().is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

An S2b UE-initiated IPsec tunnel update uses the dedicated intent rather than
an S5/S8 bearer context:

```rust
use opc_proto_gtpv2c::{
    s2b_ue_ipsec_tunnel_update_request, IpAddress, PortNumber,
    S2bUeIpsecTunnelUpdateEndpoint, S2bUeIpsecTunnelUpdateRequest,
};

let update = s2b_ue_ipsec_tunnel_update_request(
    S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 0x010203,
        teid: 0x1122_3344,
        wlan_location: None,
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::FixedBroadband {
            ue_local_ip: IpAddress::Ipv4([198, 51, 100, 7]),
            // Presence means NAT was detected and UDP encapsulation applies.
            ue_udp_port: Some(PortNumber::new(45_000)),
        },
        additional_ies: Vec::new(),
    },
)?;
assert_eq!(update.header.message_type, 34);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Protocol-error planning remains independent of full decode, session lookup,
and transaction state:

```rust
use core::num::NonZeroU32;
use bytes::BytesMut;
use opc_proto_gtpv2c::{
    inspect_gtpv2c_request, Gtpv2cErrorResponseDecision,
    Gtpv2cErrorResponsePlanner, Gtpv2cOffendingIe, Gtpv2cProtocolError,
    Gtpv2cProtocolErrorKind, Gtpv2cProtocolErrorResponseTeid,
    Gtpv2cRequestFailure, Gtpv2cRequestInspection, Gtpv2cSequenceNumber,
    Recovery,
};
use opc_protocol::{Encode, EncodeContext};

let local_vns_sequence = Gtpv2cSequenceNumber::new(7)?;
let planner = Gtpv2cErrorResponsePlanner::new(
    local_vns_sequence,
    Recovery { restart_counter: 3 },
);
let offending = Gtpv2cOffendingIe::new(71, 0)?; // APN, instance 0.
let remote_teid = NonZeroU32::new(0x0102_0304).ok_or("remote TEID is zero")?;
let failure = Gtpv2cRequestFailure::Protocol(Gtpv2cProtocolError::new(
    Gtpv2cProtocolErrorKind::MissingMandatoryIe(offending),
    Gtpv2cProtocolErrorResponseTeid::Remote(remote_teid),
));
# let datagram = [0x48, 0x20, 0, 8, 0, 0, 0, 0, 0, 0, 1, 0];
let decision = match inspect_gtpv2c_request(&datagram) {
    Gtpv2cRequestInspection::Request(envelope) => {
        planner.plan_request_failure(envelope, failure)
    }
    Gtpv2cRequestInspection::UnsupportedVersion(envelope) => {
        Gtpv2cErrorResponseDecision::Respond(
            planner.plan_unsupported_version(envelope),
        )
    }
    Gtpv2cRequestInspection::Unanswerable(reason) => {
        Gtpv2cErrorResponseDecision::Unanswerable(reason)
    }
};
if let Gtpv2cErrorResponseDecision::Respond(plan) = decision {
    let sizing = plan.amplification_metadata();
    assert!(sizing.planned_output_len <= 22);
    let mut response = BytesMut::new();
    plan.encode(&mut response, EncodeContext::default())?;
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Message type 3 always uses the checked locally supplied sequence rather than
the received higher-version value. `plan_unsupported_version` therefore takes
only the proven envelope and never requires dummy decode-failure evidence.
Ordinary responses copy the request's 24-bit sequence and, when present,
Message Priority. The no-lookup path keeps the protocol-error Cause while
using header TEID zero; it cannot represent Context Not Found. Malformed Echo
IEs instead produce an Echo Response with the configured local Recovery IE and
no Cause. Unknown message types, responses, incomplete headers, piggybacked
inputs, lower versions, and the other TS 29.274 silent-discard cases do not
yield response bytes. A zero-TEID initial request misclassified as an unknown
received TEID is separately rejected as conflicting caller evidence. Plans
expose exact input/output sizing before encoding and redact TEID/peer/payload
values from `Debug`; the product still owns admission, reflection defense, rate
limits, UDP source selection, session lookup, and logging policy.

`ProcedureAware` is a receiver profile. In accordance with TS 29.274 clauses
7.7.9 and 7.7.10, it classifies each crate-known IE type/instance against one
message grammar keyed by procedure, direction, and exact enclosing Bearer
Context instance before decoding its value. The grammar applies explicit S2b
applicability where the profile assigns an exact endpoint role. It discards
unexpected known keys, preserves genuinely unknown optional keys, retains the
first non-repeatable type/instance key in each exact scope, ignores later
occurrences, and truncates declared lists at their procedure-table bounds.
Typed procedure projections enforce required presence, F-TEID interface/value
semantics, conditional S2b endpoint/context relationships, and correlation.
Length, mandatory-field, and semantic validation
of the first retained value still fail closed. Canonical builders deliberately
use a separate sender-validation path: duplicate profile-owned or additional
singleton keys remain construction errors and are never emitted.

The S2b Create Session sender profile emits PAA at instance 0 and never emits a
separate top-level PDN Type IE, as required by TS 29.274 Table 7.2.1-1 Note 1.
PAA carries the requested family. On receive, a conforming request without IE
99 is accepted; an unexpected known PDN Type IE is discarded under clause
7.7.9 while the rest of the request continues to be processed.

Create Session additionally owns MSISDN instance 0, Charging Characteristics
instance 0, Trace Information instance 0, UE Local IP/UDP instance 0, UE TCP
Port instance 2, optional Fixed Broadband ePDG IP instance 3, WLAN Location
instance 1, and WLAN Location Timestamp instance 0. NAT ports require UE Local
IP, and the UICC-less emergency identity requires that local IP. Delete Session
uses UE Local IP/UDP instance 0, UE TCP Port instance 1, WLAN Location and
Timestamp instance 1, and optional Diameter/IKEv2 RAN/NAS Cause instance 0;
it has no ePDG-IP instance-3 role. Procedure-aware receive discards wrong known
instances and retains genuinely unknown optionals. Canonical sender
`additional_ies` apply that same per-procedure type/instance grammar, while
still preserving genuinely unknown and private extensions.

The runnable [`dedicated_bearer` example](examples/dedicated_bearer.rs) shows
the GTP transaction boundary for receiving a triggered request, projecting its
typed bearer data, committing a correlated response, and replaying the exact
response for a retransmission. The same example covers dedicated-bearer
deletion. The cross-crate
[`dedicated_bearer_sdk_flow` example](../opc-proto-ikev2/examples/dedicated_bearer_sdk_flow.rs)
additionally invokes the real typed IKEv2 Child-SA create/delete APIs between
the GTP request and response. The SDK does not allocate EBIs, TEIDs, or SPIs
and does not program XFRM/eBPF state.

Applications can attach scheduling metadata to a TEID-present EPC header
without assembling flag or octet-12 bits manually:

```rust
use opc_proto_gtpv2c::{Header, MessagePriority};

let priority = MessagePriority::new(3)?;
let header = Header::with_teid(32, 0x0102_0304, 0x000102)
    .with_message_priority(priority);
assert!(header.message_priority_flag);
assert_eq!(header.message_priority().map(MessagePriority::get), Some(3));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Zero is the highest relative priority and 15 is the lowest. Constructors
remain priority-free by default. Strict and `ProcedureAware` decode accept a
well-formed priority while rejecting non-zero header spare bits and an octet-12
priority without MP. Canonical encode emits the typed value and zero spare
bits; raw-preserving encode retains ignored/spare wire bits without changing
the typed priority. Priority validation errors contain scheduling metadata
only and never include payloads, subscriber identifiers, TEIDs, or addresses.
For a Triggered Reply, TS 29.274 says the request priority should normally be
copied. The typed response builders accept that conventional copy, while
response correlation deliberately permits an explicit PLMN policy to strip or
override priority. Exact retransmission replay always returns the byte-identical
committed response.

## Migration notes

`S2bCreateSessionRequest::pdn_type` has been removed. S2b callers must select
the family and dynamic/static intent through `paa`; do not append a PDN Type IE
through `additional_ies` because the S2b builder rejects it. Other interface
profiles may continue to use the separately exported `PdnType` IE.

```rust
use opc_proto_gtpv2c::{
    PdnAddressAllocation, S2bCreateSessionContext, S2bCreateSessionIdentity,
    S2bCreateSessionRequest,
};

# let sequence_number = 1;
# let imsi = opc_proto_gtpv2c::TbcdDigits::new("001010123456789");
# let rat_type = opc_proto_gtpv2c::RatType { value: opc_proto_gtpv2c::RatTypeValue::Wlan };
# let serving_network = opc_proto_gtpv2c::ServingNetwork { plmn: opc_proto_gtpv2c::PlmnId::new("001", "01") };
# let sender_f_teid = opc_proto_gtpv2c::FullyQualifiedTeid { interface_type: 30, teid: 1, ipv4: Some([192, 0, 2, 1]), ipv6: None };
# let apn = opc_proto_gtpv2c::AccessPointName::new(vec!["internet".to_string()]);
# let selection_mode = opc_proto_gtpv2c::SelectionMode { value: opc_proto_gtpv2c::SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified };
# let bearer_context = opc_proto_gtpv2c::BearerContext { members: Vec::new() };
let request = S2bCreateSessionRequest {
    sequence_number,
    identity: S2bCreateSessionIdentity::subscriber(imsi),
    rat_type,
    serving_network,
    sender_f_teid,
    apn,
    selection_mode,
    paa: PdnAddressAllocation::dynamic_ipv4v6(),
    bearer_context,
    context: S2bCreateSessionContext::default(),
    additional_ies: Vec::new(),
};

let static_ipv4 = PdnAddressAllocation::static_ipv4([198, 51, 100, 7])?;
# let _ = (request, static_ipv4);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Static IPv6 constructors require the TS 29.274 assigned prefix length /64 and
reject all-zero values that would be ambiguous with dynamic allocation. A
dual-stack static allocation accepts either family or both and encodes an
unprovided family as the required all-zero value.

`S2bCreateSessionRequest::imsi` has been replaced by the explicit `identity`
field, and `context` is new. Existing IMSI callers should use
`S2bCreateSessionIdentity::subscriber(imsi)` plus
`S2bCreateSessionContext::default()`, then opt into typed conditional fields.
UICC-less emergency callers select `UiccLessEmergency` with MEI and a UIMSI
Indication, and must supply `context.ue_endpoint`. `S2bDeleteSessionRequest`
now requires `S2bDeleteSessionContext` with a `S2bUeEndpoint`, because Table
7.2.9.1-1 makes UE Local IP mandatory on S2b. Exhaustive matches must handle
the new `TypedIeValue::{ChargingCharacteristics,TraceInformation,RanNasCause}`
variants and `S2bSessionContextProjectionError` variants. No Cargo feature is
required. IKEv2 release-cause callers must handle the `Result` returned by
`RanNasCause::ikev2`; higher-range Notify types cannot be represented as
release causes.

Accepted Create Session Response callers must replace
`S2bCreateSessionAcceptedResponse::sender_f_teid` with
`pgw_control_f_teid` and supply `FullyQualifiedTeid` interface type
`INTERFACE_TYPE_S2B_PGW_GTP_C` (32), a non-zero control-plane TEID, and at
least one address. Consumers of `CreateSessionAcceptedResponseSummary` must
likewise read `pgw_control_f_teid` instead of `sender_f_teid`. Exhaustive
matches over `CreateSessionResponseSummaryError` must replace
`AcceptedResponseMissingSenderFTeid` with
`AcceptedResponseMissingPgwControlFTeid` and handle the new typed
`AcceptedResponsePgwControlFTeidInterfaceMismatch`,
`AcceptedResponseZeroPgwControlFTeid`, and
`AcceptedResponseMalformedPgwControlFTeid` variants. The wire role changes
from IE 87 instance 0 to instance 1; applications must not rewrite the
request-side Sender F-TEID role.

```rust
use opc_proto_gtpv2c::{
    FullyQualifiedTeid, S2bCreateSessionAcceptedResponse,
    INTERFACE_TYPE_S2B_PGW_GTP_C,
};

# let bearer_context = opc_proto_gtpv2c::BearerContext { members: Vec::new() };
let response = S2bCreateSessionAcceptedResponse {
    sequence_number: 0x010203,
    response_teid: 0x1020_3040,
    pgw_control_f_teid: FullyQualifiedTeid {
        interface_type: INTERFACE_TYPE_S2B_PGW_GTP_C,
        teid: 0x5060_7080,
        ipv4: Some([192, 0, 2, 20]),
        ipv6: None,
    },
    bearer_context,
    additional_ies: Vec::new(),
};
```

The former loose Update Bearer shell with a single `bearer_context` has been
replaced by the strict dedicated-bearer API. Construct
`S2bUpdateBearerRequest` with mandatory `apn_ambr` and one to fifteen
`bearer_contexts`; each context identifies an EBI and may carry typed TFT and
Bearer QoS changes. `S2bUpdateBearerResponse` now requires one correlated
per-bearer result even when the whole message is rejected. The historical
`Procedure::UpdateSession` and `S2bMessage::UpdateSession*` variant names remain
as source-compatible names for wire message types 97/98; their strict typed
projection is Update Bearer.

Triggered transaction callers must retain the `Gtpv2cTriggeredWorkToken`
returned by `Dispatch` and pass it to `commit_response`. If the registry
returns `CancellationRequired`, cancel or roll back exactly that work
generation and call `acknowledge_cancellation` before accepting redispatch.

## Relationships

This crate depends on `opc-protocol` for decode/encode contracts. GTP-U user
plane framing lives in `opc-proto-gtpu`; Diameter, PFCP, NAS, NGAP, and IKEv2
are separate protocol boundaries.

## Status And Limits

`S2b Production Profile v1` is the retained identifier for an experimental
codec, typed-view, `ProcedureAware` validation, fixture-replay, and
transport-neutral helper candidate. The name does not confer production
approval, and the crate remains `publish = false`.

Known limits include no full Release 18 GTPv2-C matrix, no independent-peer
interoperability claim, and no product bearer-policy/dataplane state machine.
The triggered transaction helper is in-memory and transport-neutral; callers
own UDP I/O, persistence across process loss, cancellation/rollback of timed-out
application work, and the monotonic clock. The PCO inner codec is limited to
DNS/P-CSCF address projection and safely skips other well-formed containers.

## Roadmap

- Expand typed IE/procedure coverage only with matching constructor,
  ProcedureAware validation, malformed fixtures, examples, and fuzz seeds.
- Add licensed independent captures before claiming interoperability evidence.

## Verification

```bash
cargo check -p opc-proto-gtpv2c --all-targets --all-features
cargo test -p opc-proto-gtpv2c --all-features
cargo run -p opc-proto-gtpv2c --example production_profile_v1
cargo run -p opc-proto-gtpv2c --example dedicated_bearer
(cd crates/opc-proto-gtpv2c && cargo +nightly fuzz list)
(cd crates/opc-proto-gtpv2c && cargo +nightly fuzz run error_response_plans -- -runs=1000)
```

See [CONFORMANCE.md](CONFORMANCE.md) and `examples/production_profile_v1.rs`
for the precise profile boundary and end-to-end constructor path.
