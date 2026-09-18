# opc-proto-ngap conformance — v1 subset

Fixture profile: TS 38.413 V18.10.0. ASN.1 types generated offline from the V19.2.0
modules mirrored by Wireshark at pinned commit
`d296f939b42891994714939384adc3deaef3f180` (see
`scripts/generate-ngap.py`); APER via `rasn`. The generated object set includes
later extensions. It is not the source of the independent Release 18 corpus.

## Coverage

✅ = proven at the stated boundary by a conformance fixture per ADR 0015.
🧪 = structural dispatch only. An IE mapping check proves its identifier,
criticality and opaque open-type bytes; it does not validate the field's
internal semantics in the SDK.

| Layer | Item | Status | Evidence |
|---|---|---|---|
| NGAP-PDU framing | All three outcomes | ✅ | Complete messages independently encoded from the Release 18.10 schema |
| Constructed root containers | 23 admitted outcomes | ✅ | 21 published-corpus construction cases, 291 UE request cases, 189 Reset/Error cases, 43 Notify cases and 63 Modify cases below |
| Constructed length determinants | All three outcomes; short, two-octet and fragmented open types | ✅ | 54 independent Pycrate cases, including inner/outer 128, 16384 and 65536 boundaries |
| Typed IE mapping | NGSetup Request/Response/Failure | ✅ | Every IE compared with independent reference bytes |
| Typed IE mapping | InitialUEMessage; Downlink/UplinkNASTransport | ✅ | Complete N3IWF messages, including IPv4/IPv6 location |
| Typed IE mapping | InitialContextSetup Request/Response/Failure | ✅ | Complete context and nested resource fields |
| Typed IE mapping | PDUSessionResourceSetup Request/Response | ✅ | Nested setup transfers and partial resource results |
| Typed IE mapping | PDUSessionResourceRelease Command/Response | ✅ | Nested release transfers |
| Typed IE mapping | UEContextRelease Command/Complete | ✅ | UE identifier pair and N3IWF location |
| Typed IE mapping | NASNonDeliveryIndication; UEContextReleaseRequest | ✅ | Independent complete requests, root Causes and session IDs |
| Typed IE mapping | NGReset; NGResetAcknowledge; ErrorIndication | ✅ | Independent complete messages, fragmented connection lists and root diagnostics |
| Typed IE mapping | PDUSessionResourceNotify | ✅ | Independent flow/session reports, root Causes and optional N3IWF location |
| Typed IE mapping | PDUSessionResourceModify Request/Response | ✅ | Three independent session lists and complete procedure messages, including partial results |
| Typed decode | Paging | 🧪 | Initiating-message dispatch with hand-authored empty-IE APER fixture |

Dispatch is outcome-aware: procedure code 21 decodes as NGSetupRequest only
on an initiating message, NGSetupResponse on a successful outcome, and
NGSetupFailure on an unsuccessful outcome. The same outcome-aware rule is
applied to the first-CNF N2 subset above.

## Protocol-IE policy and cardinality

The wrapper carries procedure/outcome-specific metadata transcribed from the
pinned generated ASN.1 object sets for every typed row above:
recognized top-level IE identifiers, expected criticality, and
singleton/repeatable cardinality.

- Known procedures and IE identifiers are accepted only with their specified
  criticality. The procedure check runs before typed-body materialization.
- `UnknownIePolicy::Preserve` retains the generated entry and opaque open-type
  value; `Drop` removes it from the typed container; and `Reject` returns a
  stable value-free decode error.
- An unknown IE carrying `criticality=reject` returns
  `DecodeErrorCode::UnknownCriticalIe` under `Reject`, `Strict`, or
  `ProcedureAware`. Structural validation with `Preserve` or `Drop` remains the
  explicit compatibility path for such an entry.
- `DuplicateIePolicy::First` and `Last` select deterministically in original
  wire order, while `Reject` returns `DecodeErrorCode::DuplicateIe`.
  Repeatable metadata exempts legal repetition. The current typed Release-18
  top-level object sets contain only singleton identifiers; list-valued IEs
  encode their repetition inside one IE value.
- Presence and conditional-presence rules, and semantic validation inside each
  opaque IE value, remain outside this framing subset.

These policies filter the typed generated container, not the preserved wire
image. `Pdu::raw` remains the immutable received bytes. Raw-preserving encode
therefore reproduces unknown or duplicate entries removed by `Drop`, `First`,
or `Last`. Canonical encoding serializes the resulting typed container. Neither
mode performs nested semantic admission.

Public `Debug` output for the wrapper and message enums is redacted to
procedure/outcome metadata, lengths, variant names, and IE counts. It does not
render `Pdu::raw`, opaque IE values, or NAS payload bytes.

## Encoding mode

- **Raw-preserving**: byte-exact `decode → encode` is proven for every
  fixture above; the original PDU bytes are preserved and re-emitted.
- **Canonical container encode**: explicitly writes the supported typed root
  PDU/IE containers using TS 38.413 9.4 and X.691 aligned BASIC-PER. This avoids
  the generated `rasn` 0.28 inner-container encoder alignment defect. The
  mode name describes SDK reconstruction, not ASN.1 CANONICAL-PER. IE order
  and opaque IE value bytes are preserved; alignment bits are zero, length
  determinants are minimal, large open types use the largest permitted 16K
  multiple up to 64K followed by a terminating determinant (including zero),
  and no message SEQUENCE extension additions are written. Use raw mode when
  received extensions or ignored bytes must survive exactly.
- Construction accepts `MessageType` plus borrowed `ProtocolIe` values and
  applies the existing receive policies, including caller-selected unknown
  and duplicate handling. It bounds count/depth/complete wire size before
  payload allocation. Returned `raw` is empty. Canonical send revalidates the
  mutable wrapper/message tuple, known criticality and singleton uniqueness;
  unknown reject-criticality IEs and unknown message bodies fail. Capacity
  errors leave the destination unchanged; `wire_len` allocates no heap memory.
- General typed IE construction, required/conditional presence, and nested
  resource validation remain outside container construction. The optional
  individual-field subset below validates its own values. A malformed
  opaque leaf can be structurally constructed; the API does not claim semantic
  send admission. Raw-preserving encode rejects PDUs without received bytes.

## Typed N3IWF field subset

TS 29.413 V18.5.0 5.3 and TS 38.413 V18.10.0 9.3 govern these field values.
The individual ASN.1 constraints are independently compiled from the pinned
Release 18 publication; field limits and the closed extension subset are SDK
admission choices, not additional standards requirements.

| Field | Construct / receive | Boundary |
|---|---|---|
| RAN UE NGAP ID / AMF UE NGAP ID | Both | Distinct local/peer types; 32/40 bits |
| NAS-PDU | Both | Opaque OCTET STRING, including empty and fragmented values |
| Security Key | Both | Borrowed exactly 256 bits; K_N3IWF meaning, no key-provider effects |
| TAI | Both | Shared validated PLMN plus three-octet TAC; no extensions |
| N3IWF ULI with port | Both | IPv4/IPv6, optional TAI extension 213 |
| N3IWF ULI without port | Both | Choice extension 439, IPv4/IPv6, optional TAI |

The [field oracle](tests/fixtures/n3iwf-fields.json) has 51 independently
encoded cases: integer boundaries, NAS lengths through 131072, a nonzero key,
two-/three-digit MNCs, and all 16 address/port/TAI/PLMN combinations. Reproduce
with `scripts/generate-ngap-n3iwf-field-fixtures.py --spec PATH --output PATH`
in the pinned reference environment. Published corpus bytes are unchanged.
Two complete UL NAS messages also construct entirely from typed field values
and match the published IPv4/IPv6 oracle. Additional tests cover byte mutations,
truncation, trailing data, forged extension counts, capacity and redaction.

The generated TAI decoder mishandles alignment of its three-octet PLMN after
SEQUENCE flags. Its without-port location CHOICE encoder also misaligns the
extension container ID. Bounded explicit receive layout and a fixed aligned
CHOICE wrapper avoid those defects; qualified generated encoders handle the
inner structures. NAS shares the independently tested open-type length codec.

All wrappers redact identity, NAS, key and peer values. Security Key decoding
borrows the input without copying; encoded buffers use `zeroize::Zeroizing`.
Caller-owned input, generic PDU and final wire copies remain caller custody.
No association authorization, derivation, import, cryptographic decision or
backend effect occurs. Location addressing/port assignment, required TAI and
message-level presence remain caller responsibilities. Nested extensions other
than the enumerated TAI fail explicitly regardless of context policy; the
existing outer decoder's unknown/duplicate behavior is unchanged.

## N3IWF NAS message admission

`n3iwf::nas::NasMessage` adds complete field construction and required-field
admission for Initial UE Message, Downlink NAS Transport and Uplink NAS
Transport. It consumes the generic decoder's policy-filtered view, revalidates
mutable wrapper/IE metadata, and retains the original PDU unchanged. It has no
AMF-selection, identifier-binding, NAS-delivery, key or backend effects.

| Outcome | Required typed IEs | Optional typed IEs | N3IWF disposition |
|---|---|---|---|
| Initial UE (initiating 15) | RAN UE ID 85, NAS 38, ULI 121, establishment cause 90 | Selected PLMN 174; UE context request 112 | Ignore 201/224/225/227/259/333/402/427 as required by TS 29.413 5.2 |
| Downlink NAS (initiating 4) | AMF UE ID 10, RAN UE ID 85, NAS 38 | UE aggregate bit rate 110 | Ignore 83/36/31/177/205/206/209/222/117/228/226/264/334/400; **110 is applicable** for N3IWF |
| Uplink NAS (initiating 46) | AMF UE ID 10, RAN UE ID 85, NAS 38, ULI 121 | None in this admitted subset | W-AGF/TNGF/TWIF identity IEs 239/246/247 fail this N3IWF boundary |

Every other recognized IE fails admission explicitly. This includes applicable
fields still awaiting codecs (Old AMF, Allowed/Partially Allowed NSSAI,
5G-S-TMSI, AMF set, reroute information, Selected NID) and fields belonging to
other access profiles. Those fields are not relabeled as unknown procedures
and cannot silently disappear into an admitted NAS message. SNPN selection
and other access conditions outside this subset must be handled by the caller
before constructing these messages. The codec does not authorize a local
procedure trigger or make an association/application decision.

Unknown reject-criticality IEs fail. Preserved unknown-ignore IEs contribute
to an ignored count; preserved unknown-notify IEs return identifier-only
criticality-diagnostics obligations. The caller owns Error Indication and
procedure processing. Generic Drop/First/Last selection still affects only the
typed view; the raw PDU retains discarded entries. Known receiver-ignored
values are not decoded. Downlink AMBR is decoded, with separate UL/DL values
in bits/s and the ASN.1 root maximum of 4,000,000,000,000. Extended bitrate
ranges and nested AMBR extensions are outside the admitted subset.

Field depth starts after the four enclosing layers: simple messages need
five, AMBR six, and location eight. Message byte/count bounds are also checked.
The allocation budget remains advisory. Debug and errors expose no NAS, peer
or identifier values. Application/subscriber authorization is separate.

The [NAS oracle](tests/fixtures/n3iwf-nas.json) supplies 44 independently
encoded complete messages and independent mandatory/duplicate validation.
It includes 21 positive constructor cases, all 11 missing-mandatory cases,
three duplicate cases and nine unknown-criticality cases. Tests verify the
received typed values, constructor bytes, generic duplicate/unknown policies,
receiver-ignored malformed fields, unsupported known fields and mutable
wrapper rejection. Reproduce using `scripts/generate-ngap-nas-fixtures.py`
with the pinned reference tools and PDF.

## N3IWF UE release field admission

`n3iwf::release` implements the root Cause field, UE identifier choice and
the following optional typed boundary. Sources: TS 38.413 V18.10.0 8.3.3,
9.2.2.5–9.2.2.6 and 9.3.1.2; TS 29.413 V18.5.0 5.2–5.3. The existing release corpus
metadata is corrected to those message clauses; its wire bytes are unchanged.

| Outcome | Required typed IEs | Optional typed IEs | N3IWF disposition |
|---|---|---|---|
| UE Context Release Command (initiating 41) | UE NGAP IDs 114, Cause 15 | None | AMF/RAN pair or AMF-only when RAN ID is unavailable |
| UE Context Release Complete (successful 41) | AMF UE ID 10, RAN UE ID 85 | N3IWF ULI 121 | Ignore paging IEs 32/207; resource list 60 and diagnostics 19 explicitly await codecs |

Both outcomes support canonical construction and receive admission. The generic
decoder applies unknown/duplicate policies first; typed admission revalidates
the mutable wrapper and mandatory fields without changing the original PDU.
Unknown-ignore entries are counted and unknown-notify identifiers are returned
for caller-owned diagnostics. Unknown reject-criticality and unimplemented
recognized fields fail explicitly.

`UeIdentifiers` separates local and peer IDs in a pair and retains the valid
AMF-only choice. Fixed choice/SEQUENCE flags reject extensions before generated
collection decoding. `Cause` admits all 64 standard root values in five classes;
extension values and the choice-extension branch are outside this subset.
Both fields use qualified generated encoders/decoders. Numeric cause getters
and UE identifier fields are explicit access; Debug and errors redact values.

The [release oracle](tests/fixtures/n3iwf-release.json) independently compiles
94 field cases and 109 complete messages, including 97 constructions, all four
missing-mandatory cases, duplicates and each unknown criticality. It covers
every root Cause and AMF/RAN variable-length integer boundary. Tests compare
decoded values and complete constructor bytes, then mutate/truncate every
independent input. Reproduce with `scripts/generate-ngap-release-fixtures.py`
and the pinned reference environment/PDF. Published wire inventory is unchanged.

Message byte/count limits are checked; fields start after four enclosing
layers. Identifier choices need depth three, causes two and location four.
The allocation budget is advisory. The caller resolves association/UE ownership,
releases signaling and user-plane resources, orders completion, and handles
applicable optional resource/diagnostic fields before selecting this subset.
No resource effect or acknowledgement is performed here. UE Release Request
and other procedure outcomes remain pending under #787.

## N3IWF NG Setup admission

`n3iwf::setup` admits the Request, Response and Failure root subsets below
(TS 38.413 V18.10.0 9.2.6.1–3; TS 29.413 V18.5.0 5.3). It validates the
filtered generic PDU without changing its raw image or activating an association.

| Outcome | Required fields | Optional fields admitted | Receiver-ignored IEs |
|---|---|---|---|
| Request | Global RAN Node ID 27 restricted to N3IWF; Supported TA List 102; presence of Default Paging DRX 21 | None | 21, 204 |
| Response | AMF Name 1; Served GUAMI List 96; Relative AMF Capacity 86; PLMN Support List 80 | None | 200, 404 |
| Failure | Cause 15 | Root Time To Wait 107 | None |

Default Paging DRX remains mandatory on the wire, but its received contents
are ignored. `NgSetupRequest::construct` takes an explicit `PagingDrx`;
`SetupMessage::from_pdu` returns only the interpreted request fields and the
ignored count. Unknown-notify IDs are caller-owned diagnostics. Other
recognized optional IEs fail explicitly, including names/retention/diagnostics
outside the table. Served GUAMI backup names and all nested extensions are
unsupported; their values are never silently discarded into a successful view.

`setup_fields` uses shared `PlmnId` and `Snssai` values. Root counts are
TA/GUAMI 1..=256, PLMN 1..=12 and slices 1..=1024. Before each receive list
allocation, its count must fit the remaining physical bits and the cumulative
field-local `max_ies` item budget. Every TA, GUAMI, PLMN and slice consumes an
item; this extra bound is an SDK admission choice, separate from the outer IE
count. `allocation_budget` remains advisory. Field depth is four for global
N3IWF ID/served GUAMIs, six for PLMN support, eight for supported TAs and one
for AMF name. Message admission adds four enclosing layers: Request twelve,
Response ten and Failure six. The conservative depth-eight context thus needs
an explicit increase for Request/Response. Field bytes and complete-message
bytes are bounded separately. Encode preflights exact sizes before allocating
wire buffers or generated collections. Diagnostics expose no field values.

Independent bytes expose the runtime's fixed-octet receive alignment defect
in all four nested identity/list fields. The generated encoder also loses
parent bit offsets in PLMN/slice lists (the single-PLMN vector is already
wrong). Explicit root readers and the two list writers are qualified against
the independent oracle; zero padding is required on this receive boundary.
Generated encoders remain qualified for global N3IWF ID, served GUAMIs, AMF
name, capacity and timers. General ASN.1 extensions remain outside this narrow
exception, documented in ADR 0013.

The [setup oracle](tests/fixtures/n3iwf-setup.json) contains 63 independent
fields and 87 complete messages: 67 constructive cases, every missing
mandatory field, duplicates and all unknown criticalities. It includes both
MNC widths, integer limits, optional slice differentiators, maximum list
counts and root name/timer values. Reproduce using
`scripts/generate-ngap-setup-fixtures.py --spec PATH --output PATH` and the
pinned Pycrate/pypdf reference environment. All 150 vectors seed fuzz/replay;
ordinary tests exercise every truncation and sampled byte mutations across
large list vectors. No AMF selection, slice authorization, timer/retry,
configuration application or live peer interoperability is established.

## Initial context individual fields

`n3iwf::context_fields` adds three individual fields needed by Initial Context
Setup. Whole-message presence, conditional AMBR, key custody and nested resource
rules are composed separately by `resource_setup`, documented below.

| Field | Construction | Receive | Bounds |
| --- | --- | --- | --- |
| GUAMI | Qualified generated encoder | Bounded root reader | PLMN, 8-bit region, 10-bit set, 6-bit pointer; depth 2 |
| Allowed NSSAI | Bounded root writer | Bounded root reader | 1–8 shared S-NSSAI values; depth 4; count charged to `max_ies` before allocation |
| UE Security Capabilities | Qualified generated encoder | Contents receiver-ignored under TS 29.413 5.3 | Four explicit 16-bit masks; no algorithm selection |

All field encoders preflight the exact size against `max_message_len` before
allocating encoded buffers. Receivers bound bytes/depth, require zero padding
and reject SEQUENCE and IE extensions. Debug is redacted; value getters are
explicit. Slice authorization and cryptographic policy remain caller-owned.

The [context-field oracle](tests/fixtures/n3iwf-context-fields.json) contains
98 independent Release 18 values: eight GUAMIs, 24 Allowed NSSAI combinations
covering every root list length with absent/mixed/present SD, and 66 security
mask cases including all 64 individual bits. Reproduce using
`scripts/generate-ngap-context-field-fixtures.py --spec PATH --output PATH`
with the same pinned PDF and Python reference environment as NG Setup.
Generated GUAMI receive misaligns fixed PLMN octets; generated Allowed NSSAI
receive and optional-SD construction differ from these independent bytes.
The existing bounded root reader/writer is reused for those qualified shapes.
The generated security-mask encoder is retained. All 98 vectors seed fuzz
and replay; tests also cover every truncation and byte mutation.

## N3IWF resource setup-request transfer

TS 38.413 V18.10.0 9.3.4.1 defines this nested transfer. The opt-in
`n3iwf::resource_request` boundary admits the independently qualified
standardized non-GBR 5QI 9 subset. Enclosing Initial Context Setup and PDU Session
Resource Setup admission is a separate `resource_setup` boundary below.

| Field | IE | Criticality | Construction / receive |
| --- | --- | --- | --- |
| Session aggregate maximum bit rate | 130 | reject | Required for this non-GBR subset by 8.2.1.4; distinct UL/DL root rates |
| UL NG-U UP transport information | 139 | reject | Mandatory single IPv4/IPv6 GTP tunnel |
| PDU session type | 134 | reject | Mandatory; all five root payload kinds |
| QoS flow setup request list | 136 | reject | Mandatory 1–64 unique root QFIs; 5QI 9 and root ARP priority/flags |

All recognized optional transfer IEs outside these four fail explicitly,
including extra/redundant tunnels, security indication and network instance.
The shared IE policy implementation handles unknown criticality and
Drop/Preserve/Reject and duplicate First/Last/Reject before field admission.
Retained unknown-ignore entries are counted; notify IDs are returned without
values; retained unknown-reject entries prevent semantic admission. Structural
Drop keeps its existing generic behavior, including discarding unknown-reject
entries. Strict/ProcedureAware contexts reject them before dropping.
Typed construction emits the four admitted fields; callers retaining original
transfer bytes retain custody of that separate input.

`resource_fields` exposes distinct UplinkTransport and DownlinkTransport types
with explicit address and 32-bit TEID getters. IPv4/IPv6 roots are qualified;
dual-address bit strings and extensions are unsupported. The codec permits
all wire address/TEID values; endpoint validation and installation are external.
Session AMBR reuses the byte-identical two-BitRate root layout with a distinct
public type, qualified by independent session vectors. Root QFI values are
0–63; allocation policy is external. Other QoS descriptors, optional flow
parameters, E-RAB fields and nested extensions fail explicitly.

Transfer receive requires depth ten, with four levels subtracted before leaf
decoding. Flow lists require depth six and enforce `max_ies` and physical
count feasibility before allocation. Byte limits apply to the entire input
and each leaf. Container/list counts use separate field-local limits;
`allocation_budget` remains advisory. Known constructed roots are below
512 bytes; all fields are bounded and complete framing is checked before the
final allocation. Fragmented unknown values use the existing physical-length
preflight before coalescing. Debug/errors redact values; encoded buffers clear
on drop. No NAS/key processing, resource allocation, endpoint assignment,
pre-emption action, backend effect or live interoperability is established.

The [request oracle](tests/fixtures/n3iwf-resource-request.json) contains 225
fields and 49 transfers, including 30 complete constructions, every missing
required/conditional field, duplicates, wrong criticalities, duplicate QFIs,
unknown policies and independent 16K/64K fragments. It covers both address
families, TEID/rate boundaries, every QFI, all ARP values/flag combinations and
every flow-list length. Regenerate with
`scripts/generate-ngap-resource-request-fixtures.py --spec PATH --output PATH`
in the pinned Release 18 reference environment. Generated tunnel codecs match
the independent values and bytes. Generated QoS list codecs differ; a bounded
root reader/writer covers only the qualified 5QI 9 shape. The transfer reuses
the existing canonical container framing. All 274 vectors seed fuzz/replay;
ordinary tests exercise every truncation and bounded byte mutations.

Remaining work includes additional applicable fields/QoS profiles and
whole-message presence rules. The qualified resource-result transfers and
outer session lists are described below. No local procedure trigger is enabled here.

## N3IWF resource setup-result transfers

`n3iwf::resource_results` admits and constructs the following Release 18 roots
(TS 38.413 9.3.4.2 and 9.3.4.16):

| Transfer | Admitted contents | Explicitly unsupported |
| --- | --- | --- |
| Setup response | One downlink IPv4/IPv6 GTP tunnel; 1–64 accepted QFIs; optional failed QFIs with root Cause | Additional tunnels, security result, per-flow mapping indications, all extensions |
| Setup unsuccessful | Root Cause in any of the five classes | Criticality diagnostics and extensions |

Accepted/failed QFIs must be unique across both lists. The entirely failed case
uses the unsuccessful transfer; the response always has at least one accepted
flow. These are reports only. Request correlation, cause selection, supported
security policy, endpoint ownership and resource changes remain caller-owned.
An absent result/security field does not establish a successful security or
QoS operation. No enclosing context/session procedure is admitted here.

Response receive requires depth six. `max_ies` limits the combined result count;
physical count feasibility is checked before each vector allocation. Fixed
IPv4/IPv6 buffers avoid address allocation. Known optional/extension flags,
nonzero padding and trailing bytes fail explicitly. Response construction
checks its exact bounded length before allocating; the unsuccessful root is
at most two bytes and has a capacity/framing check around generated encoding
and decoding. Errors and Debug redact values; encoded buffers clear on drop.

The [result oracle](tests/fixtures/n3iwf-resource-results.json) contains 547
independent vectors: 539 admitted and eight negative/unsupported cases. It
covers all 64 root Causes, all QFIs and accepted-list sizes, each partial-result
split, Cause fields at every offset produced by the accepted list, IP/TEID
boundaries, duplicate/conflicting results and recognized unsupported fields.
Regenerate using `scripts/generate-ngap-resource-result-fixtures.py` with the
same `--spec`/`--output` arguments and pinned Release 18 environment.

Generated failure-transfer encode/decode matches all 128 positive probes;
explicit final-padding validation closes its permissive padding behavior.
Generated response transfer construction/receive fails 196 of 198 independent
probes. The bounded qualified root writer/reader covers that response layout,
including unaligned root Cause fields. All vectors seed fuzz/replay; ordinary
tests exercise every truncation and three mutations of every reference byte,
plus size/count/depth, extension, padding and redaction checks. This establishes
neither additional profile coverage nor live peer interoperability.

## N3IWF session setup lists

`n3iwf::session_lists` admits seven independently qualified Release 18 list
roots. The public types group only layouts proven to have identical bytes:

| Type | Qualified ASN.1 roots | Receive depth |
| --- | --- | --- |
| `SessionSetupRequests` | `PDUSessionResourceSetupListCxtReq`, `PDUSessionResourceSetupListSUReq` | 13 |
| `SuccessfulSessions` | `PDUSessionResourceSetupListCxtRes`, `PDUSessionResourceSetupListSURes` | 9 |
| `FailedSessions` | `PDUSessionResourceFailedToSetupListCxtFail`, `PDUSessionResourceFailedToSetupListCxtRes`, `PDUSessionResourceFailedToSetupListSURes` | 6 |

Each list requires 1–256 distinct root session IDs (0–255), preserving input
order. Request items include S-NSSAI, optional NAS (absent and present-empty
remain distinct), and an admitted non-GBR request transfer. Results use the
qualified response/unsuccessful transfers. `SessionResults` rejects a session
appearing in both result lists. Empty paired results are representable because
context setup may request no resources; enclosing PDU Setup admission must
require a nonempty result. Request/result correlation remains caller-owned.

Counts must fit physical input and `max_ies` before list allocation. The outer
count and each contained transfer have field-local count limits; the enclosing
byte bound applies to their combined wire input. Nested decoders retain caller
unknown/duplicate policies and the remaining depth. Strict unknown-critical
rejection still precedes Drop; per-session ignored counts and unknown-notify
identifiers are returned without their values. Malformed later entries reject
the entire list. Optional extensions, nonzero padding and trailing bytes fail.
Ordinary NAS borrows input; fragmented NAS is coalesced only after physical
framing checks. Encoders preflight total size before writing NAS; encoded output
clears on drop, and Debug/errors redact session values.

Generated construction/receive is retained for the five result-list roots,
with bounded receive preflight. The request reader reuses qualified root and
open-type helpers because generated receive misreads aligned SD and fragmented
fields. Fuzzing also exposed generated NAS construction repeating the wrong
prefix in a fragmented remainder. Nonrepeating independent NAS vectors confirm
that fault at each 16K fragment boundary; the request writer composes the existing
S-NSSAI and open-type helpers after exact size preflight. Across 93 positive
cases, generated construction fails 16 probes and receive fails 36, all in
request lists. This exception adds no general ASN.1 codec.

The [list oracle](tests/fixtures/n3iwf-session-lists.json) has 102 cases (93
admitted, nine negative), including all seven roots, counts 1/2/15/16/255/256,
session-ID boundaries, SD values, absent/empty/fragmented NAS through 65,537
bytes, nested policy cases, partial IPv6 flow results and duplicate sessions.
NAS bytes use distinct SHA-256-derived synthetic blocks so fragment substitution
cannot be masked by a repeating byte ramp.
Regenerate with `scripts/generate-ngap-session-list-fixtures.py --spec PATH
--output PATH` in the pinned reference environment. The unmodified Pycrate
0.8.1 plain decoder mishandles alignment after a nonempty fragmented remainder;
the generator uses `from_aper_ws`, requires both reference encoders to agree,
and verifies exact values and reencoding. Both modes use the independently
compiled Release 18 schema, never the SDK codec.

All cases and the original fuzz reproducer seed fuzz/replay. Tests check independent semantic values and bytes,
size/count/depth limits, borrowing, redaction, policy propagation, disjoint
partial results, truncations and bounded byte mutations. Enclosing context/PDU
Setup admission is documented below; no resource effects are enabled.

## Initial Context and PDU Session Resource Setup messages

`n3iwf::resource_setup` composes the qualified fields, lists and transfers.
It admits five outcomes from a decoded `Pdu` and constructs canonical messages
from typed fields. The matrix covers TS 38.413 V18.10.0 9.2.2.1–9.2.2.3 and
9.2.1.1–9.2.1.2, with N3IWF receiver exceptions from TS 29.413 V18.5.0 5.3.

| Outcome | Required fields | Admitted optional/conditional fields | Encode / receive |
| --- | --- | --- | --- |
| Initial Context Setup Request | AMF/RAN UE IDs, GUAMI, Allowed NSSAI, UE Security Capabilities presence, Security Key | Session setup requests, opaque NAS; UE AMBR required when session requests exist | Canonical / typed |
| Initial Context Setup Response | AMF/RAN UE IDs | Disjoint successful and failed session lists; both may be absent | Canonical / typed |
| Initial Context Setup Failure | AMF/RAN UE IDs, root Cause | Failed session list | Canonical / typed |
| PDU Session Resource Setup Request | AMF/RAN UE IDs, session setup request list | Opaque NAS, UE AMBR | Canonical / typed |
| PDU Session Resource Setup Response | AMF/RAN UE IDs, at least one result list | Successful/failed lists, N3IWF location | Canonical / typed |

Every top-level IE is singleton with the existing procedure-specific criticality.
Admission consumes the generic decoder's selected unknown/duplicate policy view
and rechecks mutable wrapper metadata, criticality, bytes and counts. Use the
same context for decoding and admission; filtering already performed by the
generic decoder cannot be undone. Contained request transfers receive the
same validation/unknown/duplicate policy and remaining depth. Unknown-ignore
counts and unknown-notify identifiers are returned without opaque values.
Strict unknown-critical rejection precedes Drop at both nesting levels.

Context capability contents and the 39 other context IEs in the explicit
TS 29.413 receiver-ignore list are skipped even if their opaque values are
malformed. The capability IE must still exist; construction requires four
caller-provided masks. RAN Paging Priority and UE Slice Maximum Bit Rate List
are receiver-ignored on PDU setup requests. Trace Activation and UE AMBR are
applicable to N3IWF under the non-trusted-access exceptions: bitrate is decoded,
while Trace Activation fails explicitly until its contract is implemented.
Other recognized applicable fields outside this subset, including Criticality
Diagnostics, also fail explicitly. Ignored fields are omitted by construction,
apart from mandatory capabilities. No ignored bytes are exposed as semantic data.

Requests with a resource list need total depth 17; a context-only request needs
8. Responses need 13 with successful results, 10 with only failures, or 5 for an
empty context response. Context failure needs 10 with failed sessions and 6
without them. These explicit limits exceed the default depth for resource
requests. Each list and contained transfer uses the caller's field-local
`max_ies`; complete input/output is bounded by `max_message_len`. Physical
preflight, unique session IDs, disjoint partial results and fragment handling
come from the qualified nested codecs. A failed-only PDU setup result still
uses the successful outcome wrapper; there is no separate unsuccessful outcome.

The [message oracle](tests/fixtures/n3iwf-resource-setup.json) has 122 independently
encoded Release 18 cases: 83 admitted and 39 negative. It covers all required
fields, conditional AMBR, empty/partial results, 256 sessions, 64 flows, absent/
empty/fragmented NAS with distinct synthetic blocks, nested unknown policies,
malformed receiver-ignored values, duplicate singleton/session IDs and result
overlap. Canonical transfer IE ordering is derived from the independent schema.
Regenerate with `scripts/generate-ngap-resource-setup-fixtures.py --spec PATH
--output PATH` using the pinned PDF and reference environment. Both reference
encoders must agree; structured decode validates the independently admitted
values. Receiver-ignored malformed values intentionally need not decode as
their ASN.1 leaf type. All cases seed fuzz/replay; tests add truncated/mutated
nested framing, key lengths, metadata, bounds and policy changes.

Security Key borrows exactly 32 bytes without installation or cryptographic
use. NAS remains opaque; Debug and failures redact values. UE ownership,
request/result correlation, slice authorization, tunnel/resource changes and
local procedure triggers remain caller-owned. Other QoS profiles, optional
fields and procedures under #787 are still pending; no live interoperability
is established.

## PDU Session Resource Release

`n3iwf::resource_release` admits and constructs the two release outcomes from
TS 38.413 V18.10.0 9.2.1.3–9.2.1.4 and the contained transfers from
9.3.4.12 and 9.3.4.21. TS 29.413 V18.5.0 5.3 makes RAN Paging Priority
receiver-ignored. The complete wire and typed leaf values are independently
qualified for this root-only subset.

| Boundary | Required fields / limits | Optional fields | Construction / receive |
| --- | --- | --- | --- |
| Release Command Transfer | One root Cause; depth 3; 1–2 bytes | None admitted | Qualified generated codec with exact framing/padding preflight |
| Release Response Transfer | Empty root; depth 1; exactly one zero octet | None admitted | Qualified generated codec with exact framing/padding preflight |
| Requested-session list | 1–256 unique session IDs and command transfers; depth 6 | None admitted | Qualified generated codec with physical count, duplicate, flag and length preflight |
| Released-session list | 1–256 unique session IDs and empty response transfers; depth 4 | None admitted | Qualified generated codec with the same bounded preflight |
| Release Command | AMF/RAN UE IDs and requested-session list; depth 10 | Opaque NAS; RAN Paging Priority contents ignored | Canonical / typed |
| Release Response | AMF/RAN UE IDs and released-session list; depth 8 | N3IWF location | Canonical / typed |

All top-level fields are singleton with existing procedure-specific criticality.
There is no unsuccessful outcome. Required lists cannot be empty, and each
contained transfer must be admitted before the complete list is returned.
Known applicable unimplemented fields, including Criticality Diagnostics and
transfer extensions, fail explicitly. Ordinary NAS borrows input; fragments
are physically preflighted before coalescing. Unknown/duplicate policies are
selected by generic decoding and remain authoritative; use the same context
for typed admission. Mutable metadata, bytes, counts and remaining depth are
rechecked. Diagnostics expose only ignored counts and unknown-notify IE IDs.

The [independent oracle](tests/fixtures/n3iwf-resource-release.json) contains
579 fields (577 admitted and two duplicate-ID negatives) and 28 complete
messages (15 admitted and 13 negatives). Fields cover all 64 root Causes and
every list length from 1 through 256; 1,154 independent generated encode/decode
comparisons pass. Messages cover mandatory presence, duplicate selection,
unknown criticality, ignored malformed priority, fragmented synthetic NAS and
IPv4/IPv6 location. Regenerate with
`scripts/generate-ngap-resource-release-fixtures.py --spec PATH --output PATH`
using the pinned PDF and reference environment. Both reference encoders agree;
structured decoding verifies reference values and wire bytes. All 607 cases
seed fuzz/replay. Tests also corrupt every unused transfer padding bit, nested
extensions, lengths, count/size/depth limits, metadata and sampled input bytes.

Generated codecs are retained after independent qualification; this adds no
new handwritten ASN.1 layout. Shared result-list and root-Cause helpers perform
preflight. Exact output size is checked before allocating list encodings. Debug
and errors redact values. Session ownership, request/response correlation,
resource teardown, response triggering and live interoperability remain outside
this codec boundary.

## UE reports and context release requests

`n3iwf::ue_requests` admits and constructs the two initiating messages in
TS 38.413 V18.10.0 9.2.5.4 and 9.2.2.4. Their outer criticality is ignore;
TS 29.413's N3IWF profile retains their listed fields.

| Boundary | Mandatory fields | Optional fields | Required depth |
| --- | --- | --- | --- |
| NAS Non-Delivery Indication (19) | AMF/RAN UE IDs, opaque NAS, root Cause | None | 6 |
| UE Context Release Request (42) | AMF/RAN UE IDs, root Cause | Session ID list | 6 without list; 7 with list |
| Context release session list | 1–256 unique session IDs | None; root only | 3 |

AMF/RAN IDs and the session list have reject criticality; NAS and Cause have
ignore criticality. All fields are singleton. Optional list absence is valid;
an empty list is invalid. NAS may be empty, borrows contiguous input, and
physically preflights fragments before coalescing. The list uses independently
qualified generated codecs with bounded physical counts, unique IDs, exact
framing, zero padding and trailing-byte checks before generated allocation.
Exact output capacity is checked before list encoding allocation. Unsupported
extensions fail. Generic IE policies remain authoritative; use the same
context for generic and semantic admission. Metadata, count, byte and remaining
depth limits are rechecked. Unknown-ignore counts and unknown-notify identifiers
are reported without exposing values.

The [independent oracle](tests/fixtures/n3iwf-ue-requests.json) contains 257
session lists (256 admitted, one duplicate negative) and 291 complete messages
(144 admitted, 147 negative). It covers every list length, all 64 root Causes,
nonzero Cause padding, missing fields, wrong criticality, duplicate policies,
unknown policies, optional lists and distinct synthetic NAS at fragment
boundaries. Both reference encoders agree; the structured reference decoder
verifies values and framing. All 512 generated list constructor/typed-decoder
comparisons pass. Regenerate with
`scripts/generate-ngap-ue-request-fixtures.py --spec PATH --output PATH` using
the pinned Release 18 PDF and reference environment. All 548 cases seed
fuzz/replay, whose successful semantic round trips compare all admitted values.

The shared `release::Cause` decoder previously accepted nonzero final padding.
An explicit root framing check now rejects it before generated decoding.
All 64 valid root Causes remain admitted, and all 297 independent single-bit
padding mutations reject. This tightens malformed-input acceptance for every
procedure using Cause. New `Message` and `MessageType` variants require updates
to downstream exhaustive matches. No schema regeneration or dependency change
is involved. Tests also cover every session-item flag/padding bit, capacity,
depth, counts, metadata mutation, truncation and bounded hostile mutations.

These APIs do not establish UE ownership, prove delivery status, choose local
procedure triggers, or perform resource release. Remaining #787 procedures and
live interoperability evidence are still pending.

## Reset and Error Indication

`n3iwf::reset` constructs and admits the three outcomes in TS 38.413 V18.10.0
8.7.4–8.7.5 and 9.2.6.11–9.2.6.13. Signalling context is an explicit caller
argument; peer identifier presence does not establish an association.

| Boundary | Required fields and conditions | Optional fields | Required depth |
| --- | --- | --- | --- |
| NG Reset (initiating 20/reject) | Cause, Reset Type; non-UE signalling | None | 6 for All; 8 for Part |
| Reset Acknowledge (successful 20/reject) | Non-UE signalling | Connection list, diagnostics | 5 empty; 7 with connections; up to 8 with diagnostics |
| Error Indication (initiating 9/ignore) | Cause or diagnostics; both AMF/RAN IDs for UE-associated signalling | AMF/RAN IDs, Cause, diagnostics subject to those rules | 6 without diagnostic items; 8 with items |
| Connection list | 1–65536 ordered items; either, both or neither ID may be present | AMF/RAN IDs per item | 3 |
| Reset Type | Explicit All or Part choice | None | 2 for All; 4 for Part |
| Criticality Diagnostics | Root fields all optional; IE list has 1–256 items when present | Procedure code/outcome/criticality, IE list | 2 without items; 4 with items |

TS 38.413 8.7.4.4 requires receivers to ignore connection items with neither
identifier and permits acknowledging or omitting them. Admission preserves
these items, repeated IDs and received order, reports their count, and exposes
a `nonempty()` receiver view. An all-empty partial list remains Part; it never
becomes All. Correlating IDs, preserving requested acknowledgement order,
waiting for release completion and executing resource effects are caller duties.
There is no Reset unsuccessful outcome.

Diagnostic IE criticality is reject or notify: ignore is explicitly inapplicable
under 9.3.1.3 even though ASN.1 can encode it. Procedure code and triggering
outcome belong only in Error Indication diagnostics and reject in Reset
Acknowledge. Empty root diagnostics are legal; repeated diagnostic IDs retain
order. Error Indication's known FiveG-S-TMSI IE is explicitly unsupported in
this subset. All message fields are singleton. Generic unknown/duplicate and
criticality policies remain authoritative; use the same context for generic
and semantic admission. Unknown-ignore counts and unknown-notify IDs disclose
no opaque values. Public field and message Debug output is redacted.

The [independent field corpus](tests/fixtures/n3iwf-reset-fields.json) has 1,093
cases (1,079 admitted, 14 semantic negatives). It covers ID width boundaries,
every list count through 256, larger counts and all element-fragment boundaries
through 65,536, empty/repeated items, diagnostic presence combinations and enum
roots. The [complete-message corpus](tests/fixtures/n3iwf-reset.json) has 189
cases (165 admitted, 24 negative), including all root Causes, required and
conditional fields, signalling context, metadata, policies and canonical output.
Regenerate with `scripts/generate-ngap-reset-field-fixtures.py` and
`scripts/generate-ngap-reset-fixtures.py`, each taking `--spec PATH --output PATH`,
using the pinned Release 18 PDF and reference environment.

Generated probes fail all 366 connection-list encode/decode cases and all 366
partial Reset cases; generated All encoding/decoding passes. Diagnostics has
304/360 encode failures and 256/360 decode failures. These fields therefore use
bounded explicit root layouts that preserve parent bit offsets, with generated
All retained. Complete physical preflight checks flags, count fragments,
cumulative `max_ies`, minimal integer widths, zero padding, exact framing and
remaining depth before vector allocation. Encoding measures exact capacity
before allocating a zeroized output buffer. The connection-list upper bound
65,536 requires unconstrained element-count determinants and fragmentation,
rather than a fixed-width constrained count. Schema and dependencies are unchanged.

Pycrate 0.8.1's plain fragmented SEQUENCE OF encoder calls the missing
`ASN1CodecPER.encode_pas`. The generators use its unmodified structured
`to_aper_ws`/`from_aper_ws` path and compare the plain encoder wherever it works;
`plain_encoder` records those cases. No reference-package patch is used.
Tests cover all complete maximum-size vectors, malformed/truncated framing,
nonzero padding and exact/one-short depth, count and byte limits. Fuzz/replay
compares all successfully admitted values. The 1,282 new seeds comprise 1,274
complete vectors and eight bounded prefixes for vectors above the fuzz target's
131,072-byte input limit; the complete large vectors remain ordinary tests.

The new public message variants require downstream exhaustive-match updates.
Admission does not choose Error Indication triggers, prove transport/UE
ownership, correlate requests or perform reset actions. Remaining #787
procedures, optional fields and live interoperability evidence are pending.

## PDU Session Resource Notify

`n3iwf::notify::ResourceNotify` constructs and admits initiating procedure
30/ignore under TS 38.413 V18.10.0 8.2.4 and 9.2.1.7. TS 29.413 5.1–5.2
lists the procedure as applicable to N3IWF; 5.3 supplies no Notify-specific
receiver-ignore exception. The admitted root transfers follow 9.3.4.5 and
9.3.4.13.

| Boundary | Required fields and conditions | Optional fields | Required depth |
| --- | --- | --- | --- |
| Complete Notify | AMF/RAN IDs; at least one session-report list | Notified list 66/reject, released list 67/ignore, N3IWF location 121/ignore | 10 for released sessions; 11 for notifications; 12 with released flows |
| Notify transfer | At least one flow-report list; each present list has 1–64 entries | Root fulfilled/not-fulfilled notifications, released QFI/Cause reports | 4 for notifications; 5 with released flows |
| Notify released transfer | Root Cause | None | 3 |
| Notified session list | 1–256 unique session IDs and typed Notify transfers | None | 7 for notifications; 8 with released flows |
| Released session list | 1–256 unique session IDs and typed released transfers | None | 6 |

Session IDs are unique and disjoint across the two complete-message lists.
QFIs are unique and disjoint across both lists within each Notify transfer.
All top-level IEs are singleton; both required IDs use reject criticality.
Generic duplicate selection, unknown-IE and criticality policies remain
authoritative; use the same context for generic and semantic admission.
Unknown-ignore counts and unknown-notify identifiers expose no opaque values.
Debug output for typed fields and messages is redacted.

The [field corpus](tests/fixtures/n3iwf-notify-fields.json) has 971 independent
cases (964 admitted, seven negative), including every flow/session list count,
both root notification states for every QFI, all 64 root Causes, mixed flow
reports and maximum-width contained transfers. The
[message corpus](tests/fixtures/n3iwf-notify.json) has 43 cases (27 admitted,
16 negative), including fragmented complete PDUs, ID widths, IPv4/IPv6 location,
missing/conflicting reports, distinct duplicate values and unknown criticalities.
Regenerate with `scripts/generate-ngap-notify-field-fixtures.py` and
`scripts/generate-ngap-notify-fixtures.py`, each taking `--spec PATH --output PATH`,
using the pinned Release 18 PDF and reference environment. Both unmodified
reference encoders agree; its structured decoder verifies the input values.

Generated probes match all 388 Notify-transfer encodings, but decode only the
empty ASN.1 root: 387 nonempty decodes fail. Only that nested receiver uses an
explicit root layout. Generated released-transfer encoding/decoding passes all
64 cases; generated notified/released session lists pass all 262/257 cases in
both directions. Preserve those qualified generated paths. Physical preflight
checks flags, exact framing, padding, cumulative counts and remaining depth
before vector allocation; encoders check exact capacity before constructing
generated values. `max_ies` bounds the total flow count within a transfer and
each outer list. Schema and dependencies are unchanged.

The shared contained-field reader now rejects a two-octet length determinant
for a value below 128 bytes. The initial regression accepted that malformed
form; this tightens contained-field framing for existing callers as well.
Tests cover exact and one-short byte/count/depth limits, malformed flags and
padding, truncation and trailing bytes. Fuzz/replay compares admitted fields
and canonical messages using all 1,014 complete independent seeds.

The new public message variant requires downstream exhaustive-match updates.
The caller checks session/QFI ownership and the established GBR classification
of notification reports, selects triggers and performs resource effects.
Construction does not override TS 29.413's receiver-ignore rules for Notification
Control in Setup/Modify or establish eligibility to generate a notification.
Alternative QoS, feedback, RAT usage and other extensions remain explicitly
unsupported. Remaining #787 work includes Modify, applicable optional fields,
the broader procedure applicability/receive/error matrix and live interoperability.

## PDU Session Resource Modify root fields

`n3iwf::modify_fields` adds four standalone root lists from TS 38.413 V18.10.0
9.3.4.3–4, using the QFI, QoS and Cause definitions in 9.3.1.12–13 and 9.3.1.51.
These are field codecs; the request-transfer composition is qualified below.
Complete Modify messages and request/response conditions remain pending.
No additional PDU outcome is admitted.

| Field | Qualified root | Required depth |
| --- | --- | --- |
| `QosFlowModifications` | 1–64 unique QFIs; absent parameters or explicit standardized non-GBR 5QI 9 with root ARP | 3 for identifiers only; 6 with parameters |
| `ModifiedQosFlows` | 1–64 unique reported QFIs | 3 |
| `QosFlowCauses` | 1–64 unique QFI/root-Cause pairs | 4 |
| `UplinkModifications` | 1–4 ordered UL/DL GTP-tunnel pairs; IPv4 or IPv6 per endpoint | 5 |

Request parameter absence is represented separately from supplied parameters;
it does not establish that a flow exists or provide default QoS. Root ARP has
priority 1–15 and explicit pre-emption flags. E-RAB identifiers, other QoS
profiles and optional/extension fields are unsupported in this initial subset.
QFI values 0–63 and all wire endpoint/TEID values are representable; reservation,
ownership and endpoint policy are caller duties. Directional endpoint types stay
distinct. Tunnel pairs preserve repetition and order without inventing a
uniqueness requirement. Each list uses `max_ies` and exact byte/depth limits.
Public formatting is redacted.

The [independent oracle](tests/fixtures/n3iwf-modify-fields.json) contains 687
cases (682 admitted, three duplicate negatives and two unsupported profiles).
It covers every list count, every QFI with and without parameters, all root
Causes, all ARP priorities/pre-emption combinations, mixed parameter presence,
both IP families, endpoint/TEID boundaries and repeated tunnel pairs. Both
unmodified reference encoders agree and structured reference decoding verifies
values. Regenerate with `scripts/generate-ngap-modify-field-fixtures.py
--spec PATH --output PATH` and the pinned Release 18 PDF/reference environment.

Generated probes across all 687 cases find 253/383 request-list encode failures
and 380/383 decode failures, 0/129 response-list encode and 129/129 decode
failures, 0/130 Cause-list encode and 129/130 decode failures, and 45/45 tunnel
list failures in both directions. Retain the generated response/Cause encoders
and all 129 admitted identifier-only request encodings. Only request lists
containing parameters, tunnel encoding and the failed receivers use explicit
bounded layouts. Two-pass decoding checks all physical framing, root flags,
zero padding, counts and uniqueness before allocating vectors. Exact sizing
precedes output allocation; schema and dependencies are unchanged.

Tests compare all admitted values and exact independent bytes, exact/one-short
limits, unsupported fields, truncations, trailing bytes and flag/padding
mutations. Shared fuzz/replay assertions include all 687 complete independent
seeds. Complete Modify request/response support must also enforce TS 29.413's
receiver-ignore rules and retain caller-owned request correlation, conditional
NAS forwarding, abnormal-condition responses and resource effects (#787).

## PDU Session Resource Modify Request Transfer

`n3iwf::modify_request::ModifyRequestTransfer` admits the bounded root subset
of TS 38.413 V18.10.0 8.2.3 / 9.3.4.3. Session AMBR (130), uplink tunnel
modifications (140), flow additions/modifications (135) and flow releases (137)
are independently optional and reject-criticality. An empty root is preserved.
Unlike Setup's non-GBR admission, Modify does not require a new AMBR: an existing
session can retain its prior limits. Absent QoS parameters remain absent.
The type neither asserts an existing session nor applies previous values.

| Present root field | Required depth | Nested count bound |
| --- | --- | --- |
| None | 4 | Zero IEs is valid |
| Session AMBR | 6 | No list |
| Identifier-only add/modify requests | 7 | 1–64 |
| Release QFI/Cause pairs | 8 | 1–64 |
| UL/DL tunnel modification pairs | 9 | 1–4 |
| Add/modify requests with parameters | 10 | 1–64 |

All QFIs are unique and disjoint across add/modify and release lists. The
container and each nested list separately use `max_ies`; byte/depth limits
are explicit SDK caller limits and `allocation_budget` stays advisory.
Complete container framing, flags, minimal determinants and zero padding are
checked before allocating entries. Entries borrow original IE frames; discarded
or unknown values are not coalesced. Shared duplicate/unknown/validation policies
select fields before semantic admission. Retained unknown reject IEs fail;
ignore IEs produce only a count and notify IEs only identifiers. Known optional
fields outside the subset are recognized and fail explicitly even under Drop.
SecurityIndication is ignore-criticality here, unlike Setup. Formatting is redacted.

The [independent oracle](tests/fixtures/n3iwf-modify-request.json) supplies 380
complete transfers: 363 admitted and 17 negative. Both unmodified reference
encoders agree, and structured decoding verifies the container, nested values
and classification. It covers all 16 presence combinations, every flow count,
63 disjoint QFI splits, AMBR bounds, tunnel forms, distinct duplicate values,
known unsupported fields, unknown criticalities and 16K/64K fragmentation.
Regenerate with `scripts/generate-ngap-modify-request-fixtures.py --spec PATH
--output PATH`; the separately qualified field corpus is hash-recorded as input.

Generated enclosing encoding matches only the empty transfer (1/380), while
receiving fails the two fragmented cases (378/380 pass). Reuse qualified bounded
container framing and nested field codecs, without changing the schema or
runtime. Exact field and complete-container sizing precede output allocation.
Tests compare independent field values and canonical bytes, first/last selection,
metadata, empty/absent values, exact/one-short limits, overlap, malformed framing,
all truncations and bounded mutations. All 380 full vectors seed shared replay
and fuzz assertions.

This is a transfer boundary, not an additional admitted NGAP PDU. The caller
checks session/bearer ownership and conditional presence, correlates requests,
constructs the abnormal-condition response required by 8.2.3.4, forwards NAS
only after qualifying success and performs resource effects. A decode error
alone is not that response. Enclosing Modify messages and other #787
applicability/receive/error rules remain pending. Response/failure roots follow.

## PDU Session Resource Modify result transfers

`n3iwf::modify_results` qualifies the roots of TS 38.413 V18.10.0 8.2.3,
9.3.4.4 and 9.3.4.17. `ModifyResponseTransfer` has independently optional
N3IWF downlink and core uplink endpoints, accepted QFIs and failed QFI/Cause
reports. QFIs are unique and disjoint; present lists contain 1–64 entries.
An empty or failed-flow-only root can accompany a successful AMBR, tunnel or
release change. The codec therefore preserves these shapes without asserting
request correspondence or that an operation succeeded. Additional per-tunnel
lists, non-root address choices and extensions remain unsupported.

`ModifyFailureTransfer` carries a mandatory root Cause and optional root
Criticality Diagnostics. Absent and empty diagnostics remain distinct. Diagnostic
lists contain 1–256 items and preserve repeated identifiers. TS 38.413 9.3.1.3
makes procedure code and triggering outcome inapplicable in same-procedure
responses, so construction and admission reject them. The qualified diagnostic
item type excludes ignore criticality; reported procedure criticality may still
be ignore. A failed session belongs in a Modify Response session list, not an
unsuccessful procedure-26 PDU.

| Transfer shape | Required depth | Count bound |
| --- | --- | --- |
| Empty response | 1 | No list |
| Response with tunnels and/or accepted QFIs | 4 | Accepted list 1–64 |
| Response with failed QFIs | 5 | Each list 1–64; combined count uses caller budget |
| Failure Cause and optional diagnostics without items | 3 | No list |
| Failure with diagnostic items | 5 | 1–256, repeats retained |

Complete flags, counts, enums, unique QFIs, padding and exact framing preflight
precedes vector allocation. Exact output sizing precedes generated materialization
or bounded output allocation. Nested layouts retain their actual parent bit
offsets. The combined accepted/failed QFI count uses `max_ies`; allocation-budget targets remain
advisory. Public formatting is redacted. Internal transport, Cause and diagnostic
helpers are reused without changing their public field contracts.

The [independent oracle](tests/fixtures/n3iwf-modify-results.json) supplies 1,436
complete transfers: 852 responses and 584 unsuccessful transfers, with 1,423
admissions and 13 negative cases. Both unmodified reference encoders agree;
structured decoding verifies explicit models and admission classifications.
Coverage includes all 16 response presence combinations, directional IPv4/IPv6
endpoint bounds, all QFI counts and disjoint splits, every root Cause at eight
list offsets, all diagnostic counts, repeated identifiers, absence, empty roots,
inapplicable diagnostics and unsupported extensions/additional tunnels.
Regenerate with `scripts/generate-ngap-modify-result-fixtures.py --spec PATH
--output PATH` in the pinned Release 18 reference environment.

Generated probes cover 1,433 modeled root cases, excluding the three explicit
unsupported extension/additional-tunnel examples. The empty response passes
both directions. All 773 QFI-only response encodings pass while all their
decodings fail. Tunnel responses encode 4/76 and decode 55/76 correctly.
Cause-only unsuccessful transfers pass all 64 in both directions; diagnostics
encode 149/519 and decode 284/519 correctly. Keep generated encoding for
responses without tunnels, empty-response decoding, and Cause-only failure
encoding/decoding. Explicit bounded layouts handle the failed shapes. Schema,
runtime and reference packages are unchanged.

Tests compare independent values and exact output, constructor negatives,
exact/one-short byte/depth/count bounds, unsupported flags, parent-offset padding,
all truncations and bounded mutations. All 1,436 complete vectors seed shared
replay and fuzz assertions. Enclosing session lists/messages, request correlation,
conditional NAS forwarding, response selection, rollback and resource effects
remain separate; this adds no admitted PDU outcome and does not complete #787.

## Complete PDU Session Resource Modify

`n3iwf::modify_lists` and `n3iwf::modify` compose the transfer roots above into
TS 38.413 V18.10.0 8.2.3 / 9.2.1.5–6 messages. Procedure 26 has reject
criticality, an initiating Request and a successful Response. Session failures
are entries in Response; no unsuccessful procedure outcome is defined.

| Outcome | Mandatory singleton IEs | Optional singleton IEs | Receive behavior |
| --- | --- | --- | --- |
| Request | AMF UE ID 10, RAN UE ID 85, nonempty Modify List 64 (all reject) | RAN Paging Priority 83 (ignore) | Ignore 83 contents as required by TS 29.413 5.3; omit it from typed construction |
| Response | AMF UE ID 10, RAN UE ID 85 (both ignore) | Modified List 65, Failed List 54, N3IWF location 121, Criticality Diagnostics 19 (all ignore) | At least one result list; disjoint session IDs; diagnostics omit procedure code/triggering outcome under 9.3.1.3 |

All three lists contain 1–256 unique session IDs. Request items preserve optional
opaque NAS (absent and empty are distinct) and optional S-NSSAI extension 148
with reject criticality. Exactly one such extension is supported; duplicate
S-NSSAI, Expected UE Activity Behaviour 281 and other item extensions explicitly
reject in this initial subset, including under unknown-IE Drop. No slice default
or authorization is inferred. Failed results retain their qualified response
diagnostics; repeated diagnostic IE identifiers remain representable.

Request lists require depth 7–13 (three layers plus the contained transfer).
Successful lists require depth 4 for empty transfers, 7 with tunnels/accepted
QFIs and 8 with failed QFIs. Failed lists require depth 6, or 8 with diagnostic
items. Complete messages add four enclosing layers; optional top-level fields
retain their own qualified depth requirements. Outer lists, the top container,
and each contained transfer independently use `max_ies`. Counts are caller
limits, not extra standards cardinality. Complete physical framing of every
list item and fragment is checked before list materialization or NAS/transfer
coalescing. Ordinary NAS borrows the input; fragmented NAS is bounded by actual
physical bytes. Exact output size precedes list allocation; allocation-budget
targets remain advisory.

Both boundaries use the same `DecodeContext`. Duplicate First/Last/Reject and
unknown Preserve/Drop/Reject policies remain authoritative at the outer and
contained request levels; previously dropped fields cannot be recovered.
Retained unknown reject IEs fail typed admission. Unknown-ignore counts and
notify IDs propagate as value-free diagnostics, including per-session evidence.
Construction emits canonical known fields in schema order. All formatting
remains redacted. Exhaustive users of public `Message`/`MessageType` must handle
the two new Modify variants; previously unknown procedure-26 Request/Response
bodies now receive typed structural dispatch and its IE policy checks.

The independent [list oracle](tests/fixtures/n3iwf-modify-lists.json) has 1,062
cases (1,051 admitted, 11 negative), including every list count and SST, NAS
fragment boundaries through 65,537 bytes, optional slices, nested unknown IEs,
duplicates and unsupported extensions. Its inputs name and hash the qualified
transfer corpora. The [message oracle](tests/fixtures/n3iwf-modify.json) has 63
complete messages (35 admitted, 28 negative), with partial/all-failed results,
location, diagnostics, receiver-ignore, missing fields and criticality policies.
Both unmodified reference encoders agree and structured decoding verifies values
and admission classifications. Regenerate with
`scripts/generate-ngap-modify-list-fixtures.py --spec PATH --fixtures DIR --output PATH`
and `scripts/generate-ngap-modify-fixtures.py --spec PATH --output PATH`.

Generated probes cover all 1,051 admitted list cases. Request encoders pass
525/533 and decoders 521/533; failures involve fragmented NAS or contained
transfers. Both directions pass all 260 response and 258 failure lists. Retain
those generated result paths after physical preflight; use the already qualified
fragment writer and borrowed reader for requests. The pinned generated schema
and dependencies remain unchanged. All complete vectors seed bounded shared
replay/fuzz checks, with exact limits and malformed flags, padding and lengths.

The caller checks exact request/result coverage, established session and QFI
ownership, conditional NAS forwarding and optional-field applicability to its
session state; it selects and constructs the abnormal-condition responses of
8.2.3.4. Returning a typed decode error does not send those responses. Actual
resource modifications, rollback and procedure triggers remain outside the codec.
Additional applicable fields and the broader applicability/receive/error/trigger
matrix remain open under #787. This evidence does not claim live interoperability.

## Fixtures

- [Independent N3IWF corpus](../opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json):
  complete messages for its 15 published outcomes, encoded by Pycrate 0.8.1
  compiled directly from the exact ETSI Release 18.10 publication. The
  [SDK field comparison](../opc-n3iwf-fixtures/tests/ngap_messages.rs) verifies
  every decoded IE and raw-preserving output. The separate reference gate
  validates mandatory fields and nested ASN.1 values. Construction tests use
  independently encoded leaf bytes as inputs and compare complete output
  with the published PDU. This proves container construction, not SDK semantic
  admission of those leaf values.
- [Constructed framing oracle](tests/fixtures/constructed-framing.json):
  SHA-256 and length of 54 independently encoded root containers with a
  deterministic synthetic unknown ignore-criticality IE. These are structural
  containers, not complete procedures. Reproduce with the pinned reference
  Python environment and local hash-checked ETSI V18.10.0 PDF:
  `python scripts/generate-ngap-constructed-fixtures.py --spec PATH --output PATH`.
  Tests cover exact/one-short bounds, fragmented inner and outer open types,
  all outcomes, zero-length values and terminating zero determinants.
- Legacy `NGSetupRequest`: 78-byte structural derivative of the libngap
  literal. Its erroneous outer criticality is corrected from ignore to reject;
  the original literal remains as provenance. It is not a complete N3IWF peer
  exchange. Existing field-level assertions are retained.
- Successful/unsuccessful outcome wrappers and empty-IE message bodies:
  hand-authored from TS 38.413 §9.2 and X.691 aligned-PER rules with
  octet-level comments. These prove routing and raw-preserving behavior, not
  complete IE semantic conformance for those message types.

## Robustness & Fuzzing

The decode path carries no `unsafe` and uses checked length arithmetic. Root
PDU/IE open types are preflighted through their final length determinant before
fragment coalescing; the claimed fragment must physically fit. For typed
procedures the fixed-width 16-bit `ProtocolIE-Container` count must satisfy
`DecodeContext::max_ies` and the minimum physical bytes required by that many
entries before materialization. Generated types decode fixed IE headers;
fragments cannot consume a following IE or PDU. Trailing bytes inside a root
container are rejected. SEQUENCE extension additions retain the earlier
generated decoder path; fragmented additions are not qualified. Three
additional layers guard it:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  corpus entry, byte-truncations of each, and hostile constant inputs through
  `Pdu::decode_owned` under `catch_unwind`. Runs in ordinary `cargo test`; no
  nightly toolchain or libFuzzer required.
- **Scheduled fuzzing** — `fuzz/fuzz_targets/decode_ngap.rs` with a seeded
  corpus, registered in `.github/workflows/fuzz.yml` and run weekly. The target
  also constructs bounded borrowed IE lists, exercises duplicate policies,
  and checks canonical lengths and structural replay.
- **Verification** — a deep `cargo-fuzz` pass over the decoder completed ~26M
  executions with no crash, leak, or OOM.

## Codec Boundary (v1 subset)

- Typed semantic encoding of IE values beyond the explicitly admitted
  N3IWF field subset, including resource transfers.
- External field-level fixtures for Paging and procedures outside the admitted
  N3IWF corpus.
- Typed decode of procedures outside the first-CNF N2 subset above; preserved
  raw as `Message::Unknown`.
- UPER encoding.
- Semantic validation of IE contents or mandatory/conditional presence beyond
  the explicitly documented field/message admission subsets above.
