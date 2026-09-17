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
| Constructed root containers | All 15 admitted outcomes | ✅ | 21 independent complete-message/order/extension cases built from oracle IE values without receive bytes |
| Constructed length determinants | All three outcomes; short, two-octet and fragmented open types | ✅ | 54 independent Pycrate cases, including inner/outer 128, 16384 and 65536 boundaries |
| Typed IE mapping | NGSetup Request/Response/Failure | ✅ | Every IE compared with independent reference bytes |
| Typed IE mapping | InitialUEMessage; Downlink/UplinkNASTransport | ✅ | Complete N3IWF messages, including IPv4/IPv6 location |
| Typed IE mapping | InitialContextSetup Request/Response/Failure | ✅ | Complete context and nested resource fields |
| Typed IE mapping | PDUSessionResourceSetup Request/Response | ✅ | Nested setup transfers and partial resource results |
| Typed IE mapping | PDUSessionResourceRelease Command/Response | ✅ | Nested release transfers |
| Typed IE mapping | UEContextRelease Command/Complete | ✅ | UE identifier pair and N3IWF location |
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
Setup. This is not whole-message admission; the required-field, conditional
AMBR, key custody and nested resource rules remain separate pending work.

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

## Fixtures

- [Independent N3IWF corpus](../opc-n3iwf-fixtures/oracles/ngap-rel18-messages.json):
  complete messages for all 15 admitted outcomes, encoded by Pycrate 0.8.1
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
