# opc-proto-ngap

Experimental NGAP APER codec subset for OpenPacketCore.

## Purpose

`opc-proto-ngap` provides an NGAP-PDU framing and typed-dispatch surface built
on `rasn`, with independent TS 38.413 V18.10.0 fixture evidence. The generated
schema is V19.2.0 and admits later extensions. The current scope is the v1
subset documented in [CONFORMANCE.md](CONFORMANCE.md).

It is not a full NGAP implementation and does not provide SCTP transport, AMF
or gNB procedure state, or NAS message processing. Its optional `n3iwf`
module validates the documented individual fields, NAS and UE requests,
NG Setup, context/session setup and release subsets. The container boundary
validates top-level identifiers, criticality, cardinality, and configured
decode policies.

## API Shape

- `Pdu` stores the policy-filtered decoded PDU kind plus the immutable raw bytes
  needed for byte-exact re-encode.
- `PduKind` distinguishes initiating, successful, and unsuccessful NGAP-PDU
  wrappers and exposes procedure code and criticality.
- `Message` is the supported typed message-body subset with `Unknown(Bytes)`
  fallback for unsupported procedure/outcome combinations.
- `messages` re-exports the generated message body types used in `Message`.
- `Criticality` and `ProcedureCode` are re-exported from generated ASN.1 types.
- `decode` and `Pdu::decode` parse one APER PDU. `Pdu::decode_owned` rejects
  trailing bytes after a complete PDU.
- `Pdu::from_protocol_ies(MessageType, &[ProtocolIe], DecodeContext)` builds a
  supported container from borrowed, independently encoded IE values, with no
  received packet. `MessageType` fixes the procedure/outcome/criticality tuple.
- `encode` and `Encode` default to canonical root-container output. Explicit
  `raw_preserving` mode replays the original receive bytes.

## N3IWF procedure routing

Use `n3iwf::applicability::inspect` before generic decoding on an N3IWF
interface. It distinguishes 23 qualified field subsets, 17 applicable outcomes
requiring a handler, and procedures absent from N3IWF applicability. It checks
complete envelope framing, assigned Release 18 metadata and direction without
allocating a body. The result does not admit fields; keep the same context for
generic decoding and typed admission. `ApplicableMessage::local_trigger` gates
wire capability and leaves all pending codecs disabled. `Outcome` is public
metadata. See [the receive/error and trigger matrix](N3IWF-PROCEDURES.md) for
required caller behavior and value-free unsupported-procedure diagnostics.

## Typed IE policy boundary

Each currently typed procedure/outcome has pinned ASN.1 metadata for its known
top-level protocol-IE identifiers, required wire criticality, and
singleton/repeatable cardinality. Before `rasn` materializes a typed
`ProtocolIE-Container`, the decoder reads its exact aligned-PER 16-bit count,
applies `DecodeContext::max_ies`, and rejects a count that cannot fit in the
available message bytes.

The remaining `DecodeContext` policies apply as follows:

- `UnknownIePolicy::Preserve` retains an unknown entry and its opaque raw value
  in the typed generated container.
- `UnknownIePolicy::Drop` removes unknown entries from the typed container.
- `UnknownIePolicy::Reject` rejects every unknown entry. A `reject`-criticality
  entry uses the stable `UnknownCriticalIe` code; `ignore` and `notify` use a
  value-free structural error.
- Strict and procedure-aware validation always reject an unknown
  `reject`-criticality IE, including when the selected unknown policy is
  `Preserve` or `Drop`. Structural validation leaves that choice to the
  unknown-IE policy.
- `DuplicateIePolicy::{First,Last,Reject}` acts on singleton identifiers.
  Repeatable identifiers retain every occurrence. All top-level IEs in the
  current typed subset are singleton; list-valued IEs carry repetition inside
  their value.
- Known procedures and IE identifiers must carry their TS 38.413 criticality.
  A mismatch fails with a stable, value-free structural error.

Filtering changes only the typed view. `Pdu::raw` is never rewritten.
Raw-preserving encoding emits the original wire entries, including those
filtered by `Drop`, `First`, or `Last`. Canonical encoding serializes the
filtered typed view instead. It preserves that view's IE order and opaque IE
value bytes, normalizes container padding and length determinants, and writes
only root components (no SEQUENCE extension additions). It checks the mutable
wrapper/message tuple, known IE criticality and singleton cardinality before
allocating output, and rejects unknown reject-criticality IEs. Unknown
ignore/notify IEs may be emitted; `Message::Unknown` requires raw preservation.
This is container reconstruction, not semantic sanitization of nested values.

`Debug` for `Pdu`, `PduKind`, and `Message` reports only outcome/procedure
metadata, lengths, variant names, and IE counts. It never renders raw PDU
bytes, opaque IE values, or embedded NAS payloads.

## Usage

```rust,no_run
use bytes::{Bytes, BytesMut};
use opc_proto_ngap::{Message, Pdu};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};

let packet = Bytes::from_static(&[]); // replace with one complete APER NGAP-PDU
let pdu = Pdu::decode_owned(packet, DecodeContext::default())?;

if let opc_proto_ngap::PduKind::Initiating { message, .. } = &pdu.kind {
    if let Message::NgSetupRequest(req) = message {
        let _ie_count = req.protocol_ies.0.len();
    }
}

let mut out = BytesMut::new();
pdu.encode(
    &mut out,
    EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    },
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status And Limits

`n3iwf::resource_request::SetupRequestTransfer` constructs and admits the
nested request transfer for a bounded non-GBR 5QI 9 subset. It requires an UL
tunnel, session AMBR, session type and unique QoS flows. `resource_fields`
keeps uplink and downlink endpoint types separate. Optional `security` and
`network_instance` fields use bounded `security_fields` roots. Integrity
Required/Preferred requires an explicit UL rate; decoding installs no protection.
Data Forwarding Not Possible is receiver-ignored outside handover and omitted
from semantic reconstruction. Other QoS profiles and unqualified optional
transfer fields fail explicitly. `resource_results` adds
a single-downlink setup response with unique accepted/failed QFI results,
an optional peer report through `with_security_result` / `security_result`, and
a root-Cause unsuccessful transfer. `session_lists` adds bounded request,
successful and failed session lists for context and PDU Setup procedures,
with unique session IDs, optional NAS, slice values and disjoint partial
results. Initial Context Request also preserves optional old/extended AMF
names, masked identity, partial slices and bounded root Trace Activation
parameters. Partial slices retain combined-count and overlap checks; trace
parameters do not start tracing. See the [field contract](CONFORMANCE.md#initial-context-and-pdu-session-resource-setup-messages).
`resource_setup` composes these fields into Initial Context Setup
Request/Response/Failure and PDU Session Resource Setup Request/Response.
Admission checks required and conditional presence, contained transfers and
partial results; these values do not configure a session or tunnel. Requests
with resource lists require an explicit `DecodeContext::max_depth` of at least
17. See the message matrix in [CONFORMANCE.md](CONFORMANCE.md).

`resource_release` admits and constructs PDU Session Resource Release Command
and Response. It includes unique session lists, per-session root Causes,
empty response transfers, optional opaque NAS and optional N3IWF location.
The caller correlates requests and performs cleanup; decoding a peer report
does not prove that resources have been removed.

NG Setup Response/Failure, Initial Context Setup Response/Failure, PDU Session
Resource Setup/Release Response and UE Context Release Complete accept optional
`diagnostics`. Absence differs from a present empty root. Responses reject
procedure code and triggering outcome, which belong only in Error Indication.
Diagnostic lists preserve repeated IDs and need total message depth at least 8
(6 without items), alongside existing field depth requirements. Affected public
struct literals and the Release Complete variant now require the new field.

UE Context Release Complete also accepts optional `sessions`. The nonempty
`release_sessions::ContextReleasedSessions` list preserves up to 256 unique
session IDs and distinguishes an absent transfer from a present empty release
response transfer. Lists require field depth 3, or 6 with transfers; complete
messages require at least 7 or 10 respectively. Other fields retain their depth
requirements. Complete variant literals and exhaustive patterns must include or
allow `sessions`. The caller correlates these reports with its resource state.

`ue_requests` admits and constructs NAS Non-Delivery Indication and UE Context
Release Request, including mandatory root Cause and optional unique session IDs.
NAS stays opaque and borrows contiguous input. Context correlation, deciding when
to send a request and resource release remain caller-owned. Root Cause decoding
now rejects nonzero final padding that the generated decoder previously ignored.

`reset` admits and constructs NG Reset, Reset Acknowledge and Error Indication.
Callers explicitly supply non-UE or UE-associated signalling context. Partial
Reset lists preserve order, repeated identifiers and legal empty items;
`nonempty()` omits items that receivers must ignore. Root diagnostics enforce
their procedure-specific applicability. Error Indication requires Cause or
diagnostics, and both UE identifiers for UE-associated signalling. The caller
chooses procedure triggers, correlates acknowledgements and performs cleanup.

`notify` admits and constructs PDU Session Resource Notify with typed flow
notifications, released flows and whole-session release reports. Present lists
are nonempty, with unique and disjoint session/QFI domains. The caller verifies
association, session ownership and whether a notified QFI is an established GBR
flow; admission neither infers that state nor performs cleanup. The qualified
root subset requires depth 10–12 depending on the contained reports. Alternative
QoS, feedback and usage-report extensions remain unsupported.

`modify_fields` supplies standalone add/modify QFI lists with absent or explicit
non-GBR 5QI 9 parameters, successful QFI reports, QFI/Cause lists and ordered
uplink/downlink tunnel modification pairs. Parameter absence is preserved;
these fields do not infer existing state or supply defaults. `modify_request`
composes optional session AMBR, tunnel modifications, add/modify flows and
release causes into a bounded Modify Request Transfer. It preserves empty
roots and absent AMBR, rejects cross-list QFI overlap, and applies the shared
IE selection policies after complete physical preflight. Request/response
correlation, conditional NAS forwarding and resource effects remain caller-owned.
`modify_results` supplies optional directional tunnel and unique/disjoint QFI
reports, plus unsuccessful transfers with root Causes and response diagnostics.
Empty response roots and absent versus empty diagnostics stay distinct. The
caller checks conditional presence, request correspondence and resource effects.
`modify_lists` adds bounded session requests/results with optional NAS/S-NSSAI,
unique IDs and contained diagnostics. `modify` constructs and admits complete
Modify Request/Response messages with partial or all-failed results, optional
N3IWF location and response diagnostics. RAN Paging Priority is receiver-ignored.
Callers retain session correlation, prescribed error responses and trigger policy.
The two new public `Message`/`MessageType` variants require exhaustive match
updates; procedure-26 Request/Response now receives typed structural dispatch.

`n3iwf::context_fields` supplies standalone `Guami` and `AllowedNssai` codecs
and `SecurityAlgorithmMasks` construction. Allowed slices reuse `opc_types::Snssai`;
the codec validates their wire shape without authorizing any slice. TS 29.413
requires N3IWF receivers to ignore UE Security Capabilities contents, so the
mask helper adds no receive decoder. Context-message admission checks mandatory
capability presence while ignoring its contents; construction requires explicit
masks. Keys remain borrowed, redacted values with no installation or use.

The crate is experimental and `publish = false`. The independent N3IWF corpus
proves framing and each decoded IE's identifier, criticality and opaque bytes
for 15 admitted message outcomes. Its reference gate validates nested ASN.1
values and enumerated N3IWF conditions; SDK semantic admission covers only
the explicitly documented field and message subsets below. See the
[evidence guide](../../docs/n3iwf-fixture-contracts.md).

Canonical encoding uses explicit aligned-PER container framing instead of
`rasn` 0.28's misaligned generated inner-container encoder. This includes
one/two-octet lengths and 16K–64K open-type fragments. It matches the independent
Release 18 bytes for the 15 published-corpus outcomes, both additional UE request
procedures, Reset/Reset Acknowledge/Error Indication, PDU Resource Notify, both Modify outcomes, and 54 independent
fragmentation boundary cases. The caller supplies already-encoded IE values; typed N3IWF
resource transfers and presence rules beyond the documented NAS, release, NG Setup
and context/session setup, release, UE request, Reset/Error, Notify and Modify subsets
remain pending under #787. The shared contained-field reader also rejects
nonminimal length determinants for short values. No
live AMF exchange or full N3IWF send capability is claimed. Paging remains structurally covered only.

`from_protocol_ies` applies the existing `DecodeContext` policies and checks
depth, IE count and complete wire length before payload allocation. It returns
empty `Pdu::raw`, so raw-preserving encoding fails. Canonical encoding checks
`EncodeContext::max_message_len` before output allocation or destination writes;
`wire_len` performs the same validation without heap allocation. The generic
`allocation_budget` remains advisory.

## Generated types

`src/generated.rs` is committed. Cargo builds never run the generator. To
regenerate it:

```bash
make generate-ngap
```

The generator requires Python 3.9+, `rasn-compiler` 0.16, and network access.
Inputs are fetched from Wireshark ASN.1 files at pinned commit
`d296f939b42891994714939384adc3deaef3f180` (TS 38.413 V19.2.0); output is
deterministic for that commit.

## Roadmap

- Add external field-level fixtures for Paging and further procedures.
- Expand procedure coverage only with fixture evidence and raw-preserving
  regression tests.
- Add typed inner IE and presence validation with canonical construction
  under [#787](https://github.com/openpacketcore/openpacketcore-sdk/issues/787).
  Procedure state and subscriber policy remain consumer responsibilities.

## Verification

```bash
cargo check -p opc-proto-ngap --all-targets --all-features
cargo test -p opc-proto-ngap --all-features
(cd crates/opc-proto-ngap && cargo +nightly fuzz list)
```

## N3IWF field codecs

`n3iwf::{RanUeId, AmfUeId}` distinguish the local 32-bit and peer 40-bit
identifiers. `NasPdu` borrows opaque NAS or coalesces fully checked fragments;
it does not process NAS security or infer an association. `TrackingArea`
reuses `opc_types::PlmnId` and carries a three-octet TAC. `N3iwfLocation`
explicitly selects IPv4/IPv6, with/without a port, and optional TAI.

Each field encodes an `EncodedValue` without its enclosing protocol-IE length.
Borrow `as_bytes()` into `ProtocolIe::new` and use `Pdu::from_protocol_ies`.
The latter remains a structural constructor: these field codecs do not check
message-wide mandatory/conditional presence or authorize procedure triggers.
51 independent Release 18 field vectors and two complete uplink NAS messages
exercise the field-to-container composition.

`SecurityKey` borrows exactly 32 octets. It is redacted, has no Clone/equality/
hash/serialization implementation, and has no key-provider effects.
`EncodedValue` clears its buffer on drop. The caller must protect the source
key and all generic-PDU/wire copies: clearing one buffer does not clear copies.
All field wrappers redact their contents in Debug; byte/identity getters are
explicit disclosure boundaries.

Field receive limits apply to the encoded field: `max_message_len`, depth one
for simple fields or four for location, and `max_ies` for location extensions.
The allocation budget is advisory. Location supports only the N3IWF choices
and known with-port TAI extension. Other nested extensions/choices return an
explicit error under every context policy, without changing generic PDU
preservation or duplicate selection. TAI extension additions are unsupported.

Error Indication separately supports optional `fiveg_s_tmsi` with IE 26/ignore,
using the same bounded identity type as Initial UE. Its reported identity does
not replace the caller's signalling context, required UE identifiers or error
basis. See the [Reset/Error matrix](CONFORMANCE.md#reset-and-error-indication).

## Initial UE and NAS transport

`n3iwf::nas::NasMessage` constructs and validates the admitted Initial UE,
Downlink NAS and Uplink NAS fields. Call `from_pdu` on a generic decoded PDU to
check mandatory fields and get typed values, an ignored-IE count, and any
unknown-notify diagnostic identifiers. `construct` writes those typed fields
into a canonical PDU. Both directions validate the same bounded field subset.

The [NAS conformance matrix](CONFORMANCE.md#n3iwf-nas-message-admission) names
supported optional fields, receiver-ignored IEs and explicit unsupported gates.
Downlink UE AMBR is applicable to N3IWF and is validated. Other recognized
fields without a codec fail admission; they do not become a partial success.
Initial UE and Downlink NAS also accept optional root Allowed NSSAI; Downlink
NAS accepts optional root Old AMF. They reuse the redacted `AllowedNssai` and
`AmfName` leaf types, preserving generic duplicate selection and raw bytes.
Both messages admit `PartiallyAllowedNssai`, enforcing a combined maximum of
eight slices and disjointness with Allowed NSSAI. Initial UE also admits the
fixed 44-bit `SelectedNid`, with exact length and zero padding. Network and
slice authorization remain caller-owned.

`nas_fields` supplies bounded AMF Set ID, 5G-S-TMSI and opaque AMF reroute
containers for Initial UE, plus Masked IMEISV and Extended Old AMF for Downlink
NAS. Extended names preserve independent optional VisibleString/UTF8String
values, including both present or an empty root; each present name has 1–150
characters. The two AMF Set IDs remain separate, and all identity/name
diagnostics are redacted.

Caller-owned association, NAS security, access conditions, Error Indication
and procedure side effects remain separate.

## UE context release

`n3iwf::release::ReleaseMessage` constructs and admits Release Command and
Complete. `UeIdentifiers` supports both the AMF/RAN pair and the AMF-only form
when the RAN identifier is unavailable. `Cause` admits the five standard root
classes and their 64 root codes. Complete can carry an optional N3IWF location.

The [release matrix](CONFORMANCE.md#n3iwf-ue-release-field-admission) records
required, ignored and unsupported fields. Association lookup, resource cleanup
and acknowledgement ordering remain caller-owned. No protocol/backend effect
occurs when a message passes admission.

## NG Setup

`n3iwf::setup` provides Request, Response and Failure construction and
`SetupMessage::from_pdu` admission. Root identities, tracking areas, PLMNs,
slices, AMF name/capacity and retry delay have independent field and complete
message evidence. Request construction takes an explicit `PagingDrx`; receive
checks that mandatory IE's presence and ignores its payload per TS 29.413.
Optional root RAN/extended names, UE-retention reports, extended AMF names and
served-GUAMI backup names are preserved and compared with independent complete
messages. Use `ServedGuamiList::with_backups` and `entries` to retain backup names;
the existing `new` and `values` API still exposes identities alone. Request and
Response struct literals gain explicit optional name/retention fields.

The [setup matrix](CONFORMANCE.md#n3iwf-ng-setup-admission) describes nested
item/depth bounds, unsupported optional fields and the two list layouts that
need explicit framing around proven runtime alignment defects. Admission does
not select an AMF, authorize a slice or activate an association.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
