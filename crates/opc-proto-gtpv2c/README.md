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
  `PdnAddressAllocation`.
- `Message<'a>` and `OwnedMessage` provide the raw borrowed/owned message
  shells and implement the shared `opc-protocol` codec traits.
- `S2bMessage<'a>` and `S2bProcedureMessage<'a>` provide typed S2b views and
  raw fallback for unsupported message types.
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
- Public profile constructors build profile-valid owned messages:
  `s2b_echo_request`, `s2b_echo_response`,
  `s2b_create_session_request`,
  `s2b_create_session_accepted_response`,
  `s2b_create_session_rejected_response`,
  `s2b_modify_bearer_request`, `s2b_modify_bearer_response`,
  `s2b_delete_session_request`, `s2b_delete_session_response`,
  `s2b_update_bearer_request`, and `s2b_update_bearer_response`.
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
let (tail, decoded) = S2bMessage::decode(&encoded, ctx)?;
assert!(tail.is_empty());
assert!(decoded.as_view().is_some());
# Ok::<(), Box<dyn std::error::Error>>(())
```

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
```

See [CONFORMANCE.md](CONFORMANCE.md) and `examples/production_profile_v1.rs`
for the precise profile boundary and end-to-end constructor path.
