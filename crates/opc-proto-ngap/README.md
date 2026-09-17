# opc-proto-ngap

Experimental NGAP APER codec subset for OpenPacketCore.

## Purpose

`opc-proto-ngap` provides an NGAP-PDU framing and typed-dispatch surface built
on `rasn`, with independent TS 38.413 V18.10.0 fixture evidence. The generated
schema is V19.2.0 and admits later extensions. The current scope is the v1
subset documented in [CONFORMANCE.md](CONFORMANCE.md).

It is not a full NGAP implementation and does not provide SCTP transport, AMF
or gNB procedure state, or NAS message processing. Its optional `n3iwf`
module validates the individual fields, three NAS outcomes, two UE release
outcomes and the three NG Setup outcomes below. The container boundary
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

`n3iwf::context_fields` supplies standalone `Guami` and `AllowedNssai` codecs
and `SecurityAlgorithmMasks` construction. Allowed slices reuse `opc_types::Snssai`;
the codec validates their wire shape without authorizing any slice. TS 29.413
requires N3IWF receivers to ignore UE Security Capabilities contents, so the
mask helper adds no receive decoder. Initial Context Setup message admission
and nested resource transfers remain pending. See the context-field boundary
in [CONFORMANCE.md](CONFORMANCE.md).

The crate is experimental and `publish = false`. The independent N3IWF corpus
proves framing and each decoded IE's identifier, criticality and opaque bytes
for 15 admitted message outcomes. Its reference gate validates nested ASN.1
values and enumerated N3IWF conditions; SDK semantic admission covers only
the explicitly documented field and message subsets below. See the
[evidence guide](../../docs/n3iwf-fixture-contracts.md).

Canonical encoding uses explicit aligned-PER container framing instead of
`rasn` 0.28's misaligned generated inner-container encoder. This includes
one/two-octet lengths and 16K–64K open-type fragments. It matches the independent
Release 18 bytes for all 15 admitted outcomes and 54 independent fragmentation
boundary cases. The caller supplies already-encoded IE values; typed N3IWF
resource transfers and presence rules beyond the admitted NAS/release subset remain
pending under #787; the field codecs cover IDs, NAS framing, keys and locations. No
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

The [setup matrix](CONFORMANCE.md#n3iwf-ng-setup-admission) describes nested
item/depth bounds, unsupported optional fields and the two list layouts that
need explicit framing around proven runtime alignment defects. Admission does
not select an AMF, authorize a slice or activate an association.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
