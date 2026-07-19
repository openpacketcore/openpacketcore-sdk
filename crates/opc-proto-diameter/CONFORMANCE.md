# opc-proto-diameter Conformance

This document defines the conformance status of the `opc-proto-diameter` crate.

## Specification Baseline

- **Document**: IETF RFC 6733 — *Diameter Base Protocol*
- **3GPP references**: 3GPP TS 32.299 (Rf offline charging), 3GPP TS 29.273
  (SWm Diameter-EAP), 3GPP TS 33.402 (non-3GPP access security and emergency
  attach), 3GPP TS 29.272 (Terminal-Information), 3GPP TS 29.212 (Gx), and
  3GPP TS 29.273 (S6b/SWx).
- **Status**: experimental scaffold with ADR 0015 evidence in progress

## Implemented scaffold

### 1. Message Header (RFC 6733 §3)

- Version 1 parsing and validation.
- 24-bit message length field honored: shorter input rejected as truncated,
  length smaller than the 20-octet header rejected as structural, length
  exceeding `DecodeContext::max_message_len` rejected as too large.
- Command flags: Request (`R`), Proxiable (`P`), Error (`E`), Potentially
  Retransmitted (`T`); reserved bits rejected in strict mode.
- 24-bit command code parsing; `CommandCode::fits_wire` rejects overflow at
  encode time.
- 32-bit application identifier, hop-by-hop identifier, and end-to-end
  identifier parsing and preservation.
- `Message::tail` returns unconsumed bytes after the header-declared boundary.

### 2. Generic AVP TLV Layer (RFC 6733 §4)

- Non-vendor AVP header (8 octets) and vendor-specific AVP header
  (12 octets, V bit + Vendor-Id) parsing.
- 24-bit AVP length field honored; length shorter than the header rejected,
  length beyond input rejected as truncated.
- Four-octet padding to boundary; strict mode rejects non-zero padding bytes.
- Reserved AVP flag bits rejected in strict mode.
- Vendor-specific AVPs with `Vendor-Id = 10415` (3GPP) recognized in
  dictionary lookups.

### 3. AVP-region validation

- Per-region AVP count limit via `DecodeContext::max_ies`.
- Duplicate AVP-key policy: `Reject`, `First`, `Last`.
- Trusted command-aware validation resolves application id, command code, and
  request/answer role uniquely, then permits a duplicate only when that
  command profile explicitly marks the vendor-aware AVP key repeatable.
- Missing and ambiguous command profiles fail closed. Raw/non-command decode
  retains blanket duplicate rejection under `DuplicateIePolicy::Reject`.
- Dictionary-defined grouped AVP recursion bounded by
  `DecodeContext::max_depth`.
- Raw AVP-region validation checks lengths, counts, duplicates, padding, and
  dictionary-defined grouped-AVP recursion; it preserves unknown AVPs as opaque
  bytes. Unknown-mandatory rejection is a typed-layer policy enforced by the
  `peer` and application parsers (see below), not by the raw or command-
  cardinality validator.

### 4. Request-bound error answers (RFC 6733 §6.2 and §7)

- `inspect_diameter_request` requires a complete trusted request header and a
  message boundary within `DecodeContext::max_message_len`; fragments,
  answers, impossible lengths, and AVP-count excess are unanswerable.
  Proxy-Info descent requires `max_depth >= 1`, and its child count is checked
  against `max_ies` before child decoding or canonical-output allocation.
- `DiameterRequestEnvelope` retains the command/application, P bit, both
  identifiers, a SHA-256 binding to the exact request, a bounded redacted
  exact-copy Session-Id, and ordered redacted Proxy-Info AVPs. Proxy-Info and
  its opaque children are copied in order through a canonical encoder; invalid
  padding or flags are never reflected. One selected offending AVP may also be
  retained in a redacted `DiameterFailedAvp`; the envelope never retains an
  arbitrary suffix. Classification returns a private-construction
  `DiameterBoundRequestFailure` tied to that request digest. The answer builder
  accepts only this bound token, not an unbound failure enum.
- Typed failures cover RFC result codes 3001, 3007, 3008, 3009, 5001, 5004,
  5005, 5008, 5009, 5011, 5013, and 5014. Reserved Diameter-header bits map to
  5013, while an E/P combination inconsistent with a uniquely resolved command
  maps to 3008. Dictionary lookup distinguishes missing application/command
  profiles from locally ambiguous profiles. Generic `DecodeError` mapping
  requires the byte-identical request, an exact AVP header/value offset, one
  application and command grammar, the received M bit, and explicit command
  occurrence provenance. 5009 requires `ZeroOrOne`; a repeatable or absent
  rule produces no peer error plan, and classification selects the second
  occurrence even when later duplicate evidence is supplied. 5008 requires an
  explicit `Forbidden` rule; command-aware decode and classification reject
  its first occurrence. An unknown M-bit AVP with no unique definition maps to
  5001 during central classification, while an optional unknown rejected only
  by local policy remains local. Nested 5008/5009 application evidence uses
  only the immediate Grouped parent's declared child rule and preceding direct
  siblings; top-level command rules/counts never authorize a nested leaf.
  Header/P/dictionary failures and AVP offsets have deterministic first-failure
  precedence across classification, decoder mapping, application binding, and
  answer construction.
- `DiameterParserError` retains the original `DecodeError` plus a private
  fingerprint of the exact declared Diameter message boundary (following
  transport-buffer bytes are deliberately outside the binding). Its optional
  sealed `DiameterMissingAvpProvenance`
  exposes only the request role plus numeric application, command, vendor-aware
  AVP key, data type, and flag-rule schema metadata. Provenance-aware CER, DWR,
  DPR, and SWm DER/STR/RAR/AAR parsers cover every required top-level field, CER's nested
  Vendor-Id and Auth/Acct one-of grammar, and SWm DER's optional-present
  Terminal-Information mandatory IMEI child while their legacy entry points
  delegate and retain the original return type.
  `DiameterRequestFailure::from_parser_error`
  reclassifies the exact request first, verifies the declared-message-boundary
  parser fingerprint and
  command/application identity, resolves exactly one vendor-aware dictionary
  definition, requires it to equal the sealed SDK definition, derives its fixed
  or variable minimum shape, and invokes the checked absence binder before
  returning bound 5005. Received grouped parents are bound by exact key,
  offset, wire length, and digest. RFC 6733 §6.11 missing-one-of evidence emits
  both minimum Auth/Acct child examples inside that parent; simultaneous Auth
  and Acct maps to 5009 and copies only those exact received children in wire
  order. Ordinary duplicate Auth or Acct remains ordinary singleton 5009.
  Non-missing parser failures delegate to generic offset mapping.
  Missing/conflicting/ambiguous schema, cross-message reuse, command mismatch,
  and unsealed reason-string-only errors never become peer errors.
  The additive `DiameterRequestFailure::MutuallyExclusiveAvps` variant requires
  a new arm in downstream exhaustive matches; it retains the existing 5009
  result and stable diagnostic family.
- `DiameterFailedAvp` copies one complete offender, derives a zero-filled
  missing shape from dictionary type/flag/vendor metadata, safely synthesizes
  short or overlong AVP headers, rejects values beyond Diameter's U24 limit
  before allocation, and can retain a bounded received or synthesized grouped
  hierarchy. Invalid-length fixed-width AVPs are finalized only against one
  unique dictionary definition and receive its normative zero-filled minimum;
  unknown and Grouped definitions use an empty minimum. Missing leaves have no
  fictitious request offset. Every received grouped ancestor retains private
  key/range/digest provenance and is rebound only after its complete request
  bytes, unique Grouped dictionary definition, direct-child containment, and
  exact top-level outer root are proven. Ancestor-free received evidence must
  itself match an exact top-level iterator entry, so AVP-shaped bytes inside an
  OctetString cannot be rebound. Synthesized ancestors require canonical
  encoding, a unique Grouped definition, and declared direct-child schema
  metadata; 5005 also proves that the leaf or outer missing group is absent at
  the request root, or that the leaf is absent from its received direct parent.
  Both the caller's inspection limit and a fixed defensive ceiling bound
  hierarchy depth. Diagnostics expose only code, vendor, optional offset,
  length, depth, and retained size.
- `build_diameter_error_answer` clears R/T, preserves P and both identifiers,
  copies the Session-Id value bytes and Proxy-Info order, adds local Origin
  identity and Result-Code/Failed-AVP, and never copies destination/routing
  fields. It rejects a token produced for any other request envelope.
  Protocol errors set E and always report the effective RFC 6733 §7.2 grammar.
  Permanent errors keep E clear unless the caller explicitly selects the
  §7.1.5-permitted §7.2 fallback grammar.
- Independently authored fixtures cover 3001, 3007, 5001, 5004, 5005, 5008,
  and 5009 across base and SWm requests. Focused tests also cover the remaining
  listed result codes, DWA/DPA application-grammar decoding, P-bit and
  dictionary ambiguity, M/P/V and Vendor-Id-zero handling, canonical
  Proxy-Info, copied/missing/duplicate/malformed/nested Failed-AVP, malformed
  DWR/DPR/SWm requests, explicit/absent/repeatable cardinality, triple
  singleton first-excess selection, one/two forbidden Result-Code occurrences,
  grouped-child 5008/5009 precedence, unknown M-bit first-failure selection,
  the actual SWm DER forbidden Result-Code parser path, every required
  CER/DWR/DPR/SWm DER omission, nested VSAI/Terminal-Information omissions,
  VSAI one-of and mutual-exclusion behavior, dictionary-derived Address/Unsigned32/
  Enumerated and variable minimum shapes, sealed synthetic vendor provenance,
  parser request/command/application mismatch, application/AVP ambiguity,
  fixed-width base/vendor and grouped/unknown malformed shapes, Proxy-Info
  depth/count limits, pre-allocation U24 bounds, exact correlation, unrelated,
  non-Grouped, mislocated, embedded-OctetString, root/path-presence,
  unknown-schema, and excessive-depth ancestry rejection, and redaction.
  Corpus replay and `decode_message`
  fuzzing run the inspector under conservative, zero-depth, and one-IE limits
  on hostile and truncated input.

Transport admission, response rate limits, connection-close policy, and
application authorization remain downstream policy. A caller may select the
ordinary application answer grammar only when the common generated fields
satisfy that command's answer CCF. When composing that CCF is not possible or
efficient, RFC 6733 §7.1.5 permits the caller to deliberately select the §7.2
E-bit grammar for a permanent failure; the SDK does not claim that fallback is
valid merely because an application field was omitted.
The existing CEA/DWA/DPA APIs share the same canonical AVP encoder;
request-correlated negative answers use the new common boundary.

### 5. Base peer procedures (RFC 6733 §5.3–5.5)

Feature-gated under the `peer` feature.

| Procedure | Request | Answer | Notes |
|:----------|:--------|:-------|:------|
| Capabilities-Exchange | CER | CEA | Full capability AVPs, plus minimal protocol-error answer helper. |
| Device-Watchdog | DWR | DWA | Optional `Origin-State-Id`. |
| Disconnect-Peer | DPR | DPA | `Disconnect-Cause` enumeration. |

Peer helpers include:
- Capability intersection (`CapabilityNegotiation`) with Relay Application Id
  awareness.
- Result-code family classification and E-bit derivation per RFC 6733 §7.2.
- Optional answer diagnostics (`Error-Message`, raw `Failed-AVP` values).
- Provenance-aware CER, DWR, and DPR request parsers; their legacy forms return
  byte-for-byte equivalent `DecodeError` values.
- Unknown AVP handling in typed peer/application parsers: mandatory unknown
  AVPs are rejected; `Reject` also rejects non-mandatory unknown AVPs. `Drop`
  and `Preserve` both accept non-mandatory unknown AVPs, but typed projections
  do not retain those opaque AVPs. Use the raw AVP iterators for lossless
  preserve/forward behavior.

The trusted CER and CEA command profiles mark only the six explicitly
repeatable RFC 6733 capability fields as repeatable: Host-IP-Address,
Supported-Vendor-Id, Auth-Application-Id, Inband-Security-Id,
Acct-Application-Id, and Vendor-Specific-Application-Id. In particular,
Failed-AVP remains singleton. DWR, DWA, DPR, and DPA declare no repeatable
known base AVPs, and raw decode retains blanket duplicate rejection. That raw
rejection is not sufficient provenance for a 5009 answer: error mapping emits
5009 only when the selected command profile explicitly declares `ZeroOrOne`.

### 6. Application dictionaries

Feature-gated per application. Dictionary metadata (applications, commands,
AVPs, data types, flag rules) is present; typed builders/parsers are limited to
`app-rf` and `app-swm`.

| Feature | Application | Command | Typed helpers |
|:--------|:------------|:--------|:--------------|
| `app-rf` | 3GPP Rf accounting (id 3) | Accounting-Request / Accounting-Answer (271) | `RfAccountingRequest`, `RfAccountingAnswer` |
| `app-swm` | 3GPP SWm (id 16_777_264) | DER/DEA (268); RAR/RAA (258); AAR/AAA (265); ASR/ASA (274); STR/STA (275) | Typed Diameter-EAP, authorization-update, Abort-Session, and Session-Termination request/answer models and envelopes |
| `app-gx` | 3GPP Gx (id 16_777_238) | — | dictionary only |
| `app-s6a` | 3GPP S6a/S6d (id 16_777_251) | — | dictionary only |
| `app-s6b` | 3GPP S6b (id 16_777_272) | — | dictionary only |
| `app-swx` | 3GPP SWx (id 16_777_265) | — | dictionary only |

The SWm typed helpers validate the ePDG-required Diameter-EAP subset at both
encode and parse boundaries: `Auth-Request-Type` must be
`AUTHORIZE_AUTHENTICATE`, DER `EAP-Payload` must be present and nonempty,
optional EAP/State material must not be empty when present, and a success DEA
must carry EAP challenge/reissued payload or MSK material. Emergency
authorization additionally requires the correlated evidence described below.
These checks are mechanical message-shape validation only; AAA challenge
selection, subscriber authorization, local emergency policy, realm routing,
transport state, and EAP-AKA policy remain downstream product work.

The SWm DER parser and transaction-envelope parser have additive provenance-
aware entry points. Missing Session-Id, Auth-Application-Id, Origin-Host,
Origin-Realm, Destination-Realm, Auth-Request-Type, or EAP-Payload can therefore
be mapped to checked request-bound 5005 without downstream command-grammar
duplication or human-readable reason matching.
The STR parser and transaction-envelope parser use the same sealed boundary for
missing Session-Id, Origin-Host, Origin-Realm, Destination-Realm,
Auth-Application-Id, and Termination-Cause.
The ASR parser and transaction-envelope parser cover missing Session-Id,
Origin-Host, Origin-Realm, Destination-Realm, Destination-Host,
Auth-Application-Id, and User-Name through that same checked 5005 boundary.
When optional Terminal-Information is received, its mandatory IMEI child is
also covered: 5005 contains a vendor-correct minimum IMEI nested inside the
exact received Terminal-Information header, without reflecting Software-Version.

The typed DER surface models TS 29.273 `Emergency-Services` as its actual 3GPP
vendor-specific `Unsigned32` AVP (code 1538), with the V bit set and M/P bits
clear. It is not grouped. Bit zero is `Emergency-Indication`; undefined
received bits are discarded and never re-emitted. The field is a singleton at
both command-dictionary and typed-parser boundaries. TS 29.273 enumerates the
AVP on the DER only. It is not modeled as a DEA field and can never become an
authorization signal; conservative decoding rejects it as an unknown DEA AVP.

The DEA result is a typed, mutually exclusive base `Result-Code` or grouped
`Experimental-Result`. In the TS 33.402 §13.3 recovery path, 3GPP vendor
10415 / experimental code 5001 requests the UE's device identity. It is a
continuation signal, not an authorization result. After the UE returns a TS
24.302 `DEVICE_IDENTITY`, the ePDG sends a correlated retry DER containing the
same emergency indication and the recovered IMEI in the TS 29.272
`Terminal-Information` grouped AVP (code 1401). The IMEI child (code 1402)
preserves exact 14- or 15-digit wire values. DEVICE_IDENTITY and the KDF use a
separate exact-15-digit type, so the received spare/check digit is neither
normalized nor silently replaced.

A terminal emergency-success observation is issued only after correlating the
exchange and checking all of the following: the initial payload is an exact
EAP-Response/Identity bound byte-for-byte to a TS 23.003 IMSI emergency NAI;
each DEA preserves its DER's Hop-by-Hop and End-to-End identifiers; the final
DEA has exact base `DIAMETER_SUCCESS` (2001); its EAP payload is exactly an EAP
Success with the correlated Response identifier; its EAP-Master-Session-Key is
nonempty and equals the TS 33.402 Annex A.4 HMAC-SHA-256 result keyed by the
exact 15 received IMEI digits; and `Mobile-Node-Identifier` contains that same
IMEI Emergency NAI. A live Diameter transport must consume the matching
pending request before invoking the codec evidence API. The verified MSK is
then used for ordinary IKEv2 method-2 AUTH. Evidence accepts only the opaque
exchange produced by consuming and correlating the two transaction envelopes.
A standalone answer, stale or
out-of-order transaction, experimental result, absent MSK, mismatched identity,
or IKEv2 NULL-auth path cannot produce this evidence.

Consumers construct the direct IMEI identity with the public `emergency_nai`
helper and pass its exact bytes to the public `build_eap_response_identity`
helper. The same EAP helper accepts a canonical IMSI Emergency NAI for the
identity-recovery path. It preserves opaque identity octets and rejects an
identity larger than 65,530 octets before allocation because the complete EAP
packet cannot fit its two-octet Length field. This is construction safety and
wire-drift coverage, not validation that arbitrary input is a canonical NAI;
the correlated emergency evidence remains the fail-closed validator.

The SWm DEA parse matches vendor-specific AVPs by (vendor-id, code); only
genuinely unknown AVPs fall through to the unknown-AVP policy (mandatory
unknown AVPs remain fail-closed). The typed DEA surface decodes and encodes
`APN-Configuration` (TS 29.272 §7.3.35), top-level `Service-Selection` (RFC
5778), an optional top-level `Context-Identifier`, and
`Mobile-Node-Identifier` (RFC 5779).

The top-level default pointer is an explicit interoperability extension, not a
baseline SWm conformance claim. TS 29.273's SWm DEA command ABNF enumerates one
optional `APN-Configuration` and a trailing extension-AVP wildcard; it does not
enumerate a top-level `Context-Identifier`. TS 29.272 instead defines that
pointer inside `APN-Configuration-Profile`. The SDK accepts profiles that
project the pointer and repeated APN configurations into the DEA extension
surface, but products must enable emission only when peer support is part of
their deployment contract. Generated round trips for this extension are
regression/interoperability evidence, not independently authored SWm
conformance evidence.

Top-level `Service-Selection` is not interpreted as the subscription default.
`SwmDiameterEapAnswer::default_apn_configuration` resolves the top-level
Context-Identifier to its exact child APN configuration.

Context identifiers and APN Service-Selection values are validated at both
encode and parse boundaries. Child identifiers must be nonzero and unique,
child Service-Selection values must be nonempty and unique, and a present
nonzero default identifier must resolve to a supplied configuration. APN
profile material is accepted only when Result-Code is exactly
`DIAMETER_SUCCESS` (2001), not merely another 2xxx result. A missing default
remains `None`; an unresolved or ambiguous profile fails closed, and the
resolver independently returns `None` for any invalid profile.

The baseline SWm command profile marks `State` repeatable and keeps
`APN-Configuration` singleton. The separate
`SWM_PROJECTED_PROFILE_DICTIONARIES` profile also marks APN-Configuration
repeatable for explicitly configured peers. `Message::decode_with_dictionary`
supports both with `DecodeContext::conservative()` while all undeclared,
unknown, and nested grouped keys retain duplicate rejection. Supplying both
profiles is ambiguous and fails closed; typed `set_once` checks independently
protect singleton fields. The opt-in profile remains an interoperability
extension and is not a baseline SWm cardinality claim.

The modeled APN-Configuration child subset is `Context-Identifier`,
`Service-Selection`, `PDN-Type`, `EPS-Subscribed-QoS-Profile` (QCI +
Allocation-Retention-Priority), and `AMBR`. The remaining APN-Configuration
children (for example `VPLMN-Dynamic-Address-Allowed`,
`PDN-GW-Allocation-Type`, `MIP6-Agent-Info`, and
`3GPP-Charging-Characteristics`) are deliberately not modeled yet and are
handled by the unknown-AVP policy.

#### SWm Session-Termination scope

The typed TS 29.273 V19.2.0 STR/STA slice covers command 275 under application
id 16_777_264. STR requires P plus Session-Id, Origin-Host, Origin-Realm,
Destination-Realm, Auth-Application-Id, Termination-Cause, and User-Name; it
permits the specified DRMP, Destination-Host, overload offer, ordered
Proxy-Info/Route-Record, repeated RFC 6733 Class state, and extension surfaces.
Ordinary STA requires P plus Session-Id, base Result-Code, Origin-Host, and Origin-Realm,
permits DRMP, the specified overload/Load AVPs, repeated Class state, and
extension surfaces, and rejects request-only AVPs. RFC 6733 generic E-bit
answers instead permit zero or one Session-Id, including the section 7.1.5
permanent-failure fallback. The profile always requires the base Result-Code;
generic E-bit answers may additionally preserve one structurally validated
Experimental-Result, while ordinary STA rejects that combination.

TS 29.273 V19.2.0 section 7.1.2.3.1 table 7.1.2.3.1/1 classifies the permanent
user identity carried in User-Name as mandatory, and section 7.1.2.3.2 requires
session lookup against both Session-Id and User-Name. Section 7.2.2.2.1's
reused command CCF nevertheless renders User-Name as optional. This typed SWm
procedure boundary applies the stricter semantic-table requirement and returns
sealed 5005 provenance when User-Name is absent.

`SwmSessionTerminationRequestEnvelope` binds the typed request to Hop-by-Hop
and End-to-End identifiers, P, exact Session-Id, and a bounded ordered
Proxy-Info chain. An inbound envelope has no outbound correlation authority but
remains usable for local processing and STA construction until the caller
explicitly binds authenticated outbound routing state. `for_outbound` requires
`SwmExpectedAnswerPeer`: `routed` binds only the
opaque authenticated connection generation, while `direct` and
`routed_in_realm` add caller-proven logical-Origin constraints using ASCII
case-insensitive DiameterIdentity comparison. Destination AVPs never imply an
Origin policy. An unbound envelope cannot encode an
outbound STR or correlate an STA. A newly created outbound envelope clears T;
after an
unacknowledged request is recovered for resend following link failover,
`mark_for_failover_retransmission` atomically installs the replacement
connection binding plus its caller-reserved, connection-unique Hop-by-Hop
Identifier and performs a one-way transition that sets T while preserving the
End-to-End Identifier and AVP bytes. An answer arriving on the old connection,
or using the old Hop-by-Hop Identifier on the replacement connection, then
fails correlation. Ordinary timer retries do not set T.
`build_swm_session_termination_answer` can answer only that
envelope and copies all correlation material and Proxy-Info in wire order.
`correlate_answer` consumes independently parsed request/answer envelopes and
rejects connection generation, identifier, P, present Session-Id, exact ordered
Proxy-Info, or unsolicited overload-control drift. It also rejects an ordinary
answer whose Origin identity violates an explicit direct/realm policy. A
generic E-bit answer without Session-Id can originate at an intermediary and
therefore skips only that logical-Origin policy; connection, transaction, P,
Proxy-Info, and overload checks remain mandatory. The correlation-capable
answer parser requires the authenticated connection token and enforces
application, command, and R-bit direction. Connection-token allocation,
authentication, dispatch, and realm-routing policy remain consumer
responsibilities.

Duplicate/retransmission fixtures prove that the initial T-clear STR and its
same-Hop T-set duplicate build byte-identical committed success and
unknown-session STA responses. A failover duplicate using a newly allocated
Hop-by-Hop Identifier produces the same flags and AVPs with only the permitted
hop-local identifier difference. The consumer still owns duplicate lookup,
identifier allocation, committed-response caching, and replay lifetime.
RFC 7683 capability correlation permits an answer to omit
OC-Supported-Features after the request offered it, representing a selected
server that is not a reporting node. A returned selection must have been
offered, and OC-OLR cannot substitute for same-answer OC support.
OC-Supported-Features and OC-OLR use explicit
RFC 7683 child schemas, accept RFC-permitted M-bit selection, require the exact
non-vendor AVP keys with P clear, reject duplicates, malformed known children,
and unknown mandatory children, and limit typed selection to the loss
algorithm. Numeric collisions under another Vendor-Id remain distinct unknown
extensions. A received loss OC-OLR may omit
the optional reduction child, but an originated one may not. RFC 8583 Load
applies the same child/flag/duplicate boundary. Originated DRMP and top-level
Load clear M under the TS 29.273 SWm override; table 7.2.3.1/2 note 2 makes a
known inbound M-bit mismatch non-fatal, without relaxing V, P, type, child, or
cardinality validation. Every known received Load child is
value-validated without treating RFC-optional children as mandatory, while an
originated report requires Load-Type, Load-Value, and SourceID. Unknown
optional children are framing-checked and preserved or removed according to
the decode policy; unknown mandatory children fail closed.
`SwmSessionTerminationResult` distinguishes success, unknown session (5002),
unable to comply (5012), and other received base result codes. The typed STA
builder intentionally emits only 2001, 5002, and 5012 because those result AVP
contexts are completely modeled; `Other` is receive-only. Redirect 3006 is
rejected on receive until Redirect-Host and its related context are typed and
semantically modeled. The lifecycle command definitions nevertheless carry
the standard occurrence rules: ASA permits repeated Redirect-Host and
Failed-AVP under its RFC 4005-derived CCF, redirect usage and cache-time fields
are singleton, and request roles explicitly forbid those answer-only fields.
RFC 6733 base definitions enforce redirect M-bit and data-type contracts,
including a bounded DiameterURI grammar. The typed ASA surface preserves
repeated Failed-AVP but rejects every redirect field and result 3006; only
conservative dictionary cardinality inspection accepts repeated Redirect-Host.
A trailing extension wildcard is singleton unless an explicit rule declares
otherwise.
Received 3xxx protocol errors require E. Informational, success, and transient
results require E clear. Permanent and unrecognized result classes accept
either their ordinary E-clear application CCF or RFC 6733's generic E-bit
fallback. The typed builder emits 5002 and 5012 only in ordinary E-clear STA.

The redacted additional-AVP surface applies dictionary-driven value validation
on decode and encode: fixed-width primitives, Address, UTF-8,
DiameterIdentity, and grouped framing are checked, while dictionary grammars
without a complete typed validator fail closed. Group-only children are
rejected at command top level. Unknown optional extensions remain preservable.
Command-owned host, realm, route, and Proxy-Host fields pass through the same
nonempty ASCII DiameterIdentity contract; Session-Id and User-Name retain their
dictionary UTF8String representation.

Independent fixtures in `tests/swm_lifecycle.rs` are hand-authored from RFC
6733 framing and TS 29.273 sections 7.2.2.2.1-.2. They prove byte-exact STR and
STA parse/build, declared Proxy-Info/Route-Record/Class repetition, exact
response correlation, 5002/5012, receive-side 3xxx and permanent-fallback E-bit
handling, initial and failover-retransmitted outbound/inbound STR handling,
unknown optional preservation, and ordered Proxy-Info answer copying. Negative
cases cover every required STR omission through checked 5005 provenance,
duplicate core and extension singletons, wrong
role/vendor/type/command/application, malformed dictionary values, OC/Load
group semantics, unknown mandatory AVPs, exact 129th-entry count bounds, and
redacted diagnostics.

#### SWm Abort-Session scope

The typed TS 29.273 V19.2.0 ASR/ASA slice covers command 274 under application
id 16_777_264. ASR requires P plus Session-Id, Origin-Host, Origin-Realm,
Destination-Realm, Destination-Host, Auth-Application-Id, and User-Name; it
permits DRMP, Auth-Session-State, Origin-State-Id, overload offer, singleton
State, repeated Class and Reply-Message, ordered Proxy-Info/Route-Record, and
unknown optional extensions.
TS 29.273's ASR ABNF prints User-Name as optional, while the procedure table
marks Permanent User Identity mandatory and section 7.1.2.4.2 requires abort
matching by the same Session-Id and User-Name. The typed profile deliberately
enforces that stricter procedure invariant rather than exposing an ambiguous
abort target. An omitted Auth-Session-State has RFC 6733's effective
`STATE_MAINTAINED` value.

An ordinary E-clear ASA requires P plus Session-Id, base Result-Code,
Origin-Host, and Origin-Realm. A received generic E-bit ASA may omit Session-Id
under RFC 6733's error-answer grammar, including the permitted permanent-failure
fallback; if present it remains correlated exactly. ASA permits the specified
DRMP, User-Name, singleton State and Class, diagnostic, overload, Load,
Proxy-Info, repeated Failed-AVP, and extension surfaces, and rejects
request-only AVPs. The request-bound builder emits only fully modeled success
(2001), unknown session (5002), and unable to comply (5012), all with E clear.
Other non-redirect base results are receive-only. A 3xxx protocol error must
set E; informational, success, and transient failures must clear it; and 5xxx
or an unrecognized permanent class may use either its ordinary E-clear CCF or
RFC 6733's generic E-bit fallback. Redirect 3006 remains rejected until its
required context is typed.
The shared SWm Load definition applies TS 29.273's explicit outer-M-bit
override asymmetrically: builders must clear M, while a receiver that
understands Load ignores a peer's mismatched M bit as required by table 2 note
2. DRMP follows the same receive-tolerant/originate-clear rule. V, P, type,
length, value, and grouped-child validation remain strict.

`SwmAbortSessionRequestEnvelope` retains Hop-by-Hop and End-to-End identifiers,
P, T, exact request Session-Id and permanent identity, and a bounded ordered
Proxy-Info chain. An inbound envelope has no outbound correlation authority but
remains usable for local processing and ASA construction. `for_outbound`
requires the same `SwmExpectedAnswerPeer` connection/direct/routed policy used
by STR/STA; Destination AVPs never prove the answer Origin. An unbound envelope
cannot encode an outbound ASR or correlate an ASA. The ASA builder copies the
identifiers/P/Proxy-Info, always clears T, and requires the caller's explicit
local Origin rather than deriving it from request routing AVPs.

Fresh outbound envelopes clear T. For queued, unacknowledged ASR state resent
after failover, `mark_for_failover_retransmission` atomically installs a new
connection binding and caller-reserved Hop-by-Hop Identifier, sets T, and
preserves End-to-End duplicate identity and AVPs; ordinary timer retries do not
call it. The correlation-capable ASA parser requires the transport-supplied
connection token. Correlation rejects missing binding, connection generation,
transaction, P, present Session-Id, optional-present User-Name, exact ordered
Proxy-Info, overload, and explicit logical-Origin-policy drift. A correctly
formed agent-originated generic E-bit error skips only logical-Origin policy;
the connection and all other checks remain mandatory. DiameterIdentity host and
realm matching is ASCII case-insensitive. An answer arriving on the old
connection, or using the old Hop-by-Hop Identifier on the replacement
connection, fails closed.

For the same typed ASA, T-clear and same-Hop T-set duplicates rebuild
byte-identical answer bytes. A failover duplicate with a newly allocated
Hop-by-Hop Identifier has the same flags, End-to-End Identifier, and AVPs with
only the permitted hop-local identifier difference. The consumer still owns
duplicate detection, identifier allocation, a bounded cache and its lifetime,
exactly-once teardown, and replay of the exact committed encoded bytes.

At the ePDG, after the request-bound ASA has been successfully built and its
bytes committed, `SwmAbortSessionRequestEnvelope::post_abort_session_termination`
validates the same answer facts and deterministically maps omitted/
`STATE_MAINTAINED` state to typed STR facts with administrative termination
cause. It maps `NO_STATE_MAINTAINED` and an unsuccessful ASA to explicit no-STR
dispositions. The method deliberately lives on the inbound request envelope:
TS 29.273 requires the ePDG to send this STR, while the AAA originator that
correlates the ASA only releases its local resources. The SDK cannot prove
commit ordering. The consumer owns fresh STR transaction and peer-binding
allocation, ordering against local teardown, transport pending state, retry,
timeout, compensation, and durable session authority.

Independent fixtures in `tests/swm_abort_lifecycle.rs` are hand-authored from
RFC 6733 framing and TS 29.273 sections 7.1.2.4 and 7.2.2.3.1-.2. They prove
byte-exact ASR/ASA parse/build, both Auth-Session-State values and its default,
deterministic administrative STR derivation, request T handling and exact ASA
replay, ordinary and generic permanent-fallback E-bit handling, correlation,
checked 5005 provenance for every required ASR field, extension preserve/drop,
bounded grouped/count behavior,
and redacted diagnostics. Negative cases cover wrong role/vendor/type/header/
application, duplicate singletons, peer/session/user/proxy/overload drift,
malformed OC/Load groups, unknown mandatory AVPs, and the TS-specific Load
and DRMP receive-tolerant/originate-clear M-bit contract.

This is protocol machinery, not a live-session authority. Active-session
lookup, duplicate/retry timers, transport pending-request consumption,
teardown ordering, compensation, and evidence publication remain product
owned. Broader application procedures outside the declared matrix remain
separate coverage.

#### SWm authorization-information update scope

The typed TS 29.273 V19.2.0 authorization slice covers Re-Auth command 258 and
AA command 265 under application id 16_777_264. RAR requires P, Session-Id,
Origin-Host/Realm, Destination-Realm/Host, the exact SWm
Auth-Application-Id, `Re-Auth-Request-Type = AUTHORIZE_ONLY`, and User-Name.
Ordinary RAA clears R/T, preserves P, and requires Session-Id, one base
Result-Code, Origin-Host/Realm, and User-Name. It exposes the optional typed
Re-Auth-Request-Type, Authorization-Lifetime, and Auth-Grace-Period and
preserves repeated Reply-Message values. A positive Authorization-Lifetime
requires Re-Auth-Request-Type. The emitted
RAA result surface is deliberately limited to 2001, 5002, and 5012, which are
the result contexts specified by the authorization-update procedure.

AAR requires P, Session-Id, the SWm Auth-Application-Id,
Origin-Host/Realm, Destination-Realm, `Auth-Request-Type = AUTHORIZE_ONLY`, and
User-Name. It types optional AAR-Flags, UE-Local-IP-Address,
High-Priority-Access-Info, Authorization-Lifetime and Auth-Grace-Period hints,
DRMP, routing, proxy, overload, and extension state.
Ordinary AAA clears R/T, requires the correlated session/request type/user and exactly
one base Result-Code or grouped Experimental-Result, and exposes an optional
typed APN-Configuration only on exact base `DIAMETER_SUCCESS`. It exposes the
optional typed Re-Auth-Request-Type, Authorization-Lifetime,
Auth-Grace-Period, and TS 29.273 Session-Timeout, and preserves repeated
Reply-Message values. All timer AVPs are singleton Unsigned32 values with
RFC 6733 M=1/V=0/P=0 flags. A positive answer lifetime requires
Re-Auth-Request-Type, and a nonzero Session-Timeout must not be smaller than
Authorization-Lifetime. Every success-class AAA answering an AAR that supplied
an Authorization-Lifetime maximum must include a value no greater than that
maximum; request-bound construction and correlation enforce the ceiling with
value-free errors. Non-success answers need not grant a lifetime. Zero and
absent lifetime/timeout semantics are preserved distinctly on the typed wire
surface; diagnostics expose presence only. RAR forbids all three timers, while
Session-Timeout is forbidden in RAA and AAR.
Redirect 3006 fails closed until its required Redirect-Host context is modeled. The AAA
command definition intentionally follows §7.2.2.1.4 prose and clears R; the
displayed request token in that section's ABNF is treated as an editorial
error.

Received RFC 6733 generic E-bit RAA/AAA errors require a base Result-Code and
Origin-Host/Realm, but may omit the application CCF's Session-Id, User-Name,
Auth-Application-Id, and Auth-Request-Type. A supplemental structurally valid
Experimental-Result may be retained, but it cannot replace the generic base
Result-Code. Permanent 5xxx failures may use either the ordinary E-clear CCF
or the generic E-bit fallback; protocol 3xxx results require E.

Inbound request envelopes retain T but have no outbound answer-correlation
authority. An originated or retained outbound RAR/AAR must bind a
`SwmExpectedAnswerPeer` containing its authenticated connection generation and
an explicit direct, routed-realm, or connection-only routed logical-Origin
policy. Destination AVPs never imply authentication evidence. Request envelopes
expose a one-way `mark_for_failover_retransmission` transition for queued,
unacknowledged state resent only after link failover or equivalent recovery; it
atomically replaces the Hop-by-Hop Identifier and connection binding while
preserving the End-to-End Identifier and request AVPs. Ordinary retries keep T
clear and byte-identical. Answer builders always clear T. The public `SwmAcceptedAuthorizationUpdate` and
`SwmPendingAuthorizationUpdate` type-state sequence commits an exact RAA,
requires the follow-up AAR to preserve Session-Id/User-Name, caches the initial
T-clear AAR plus a byte-identical ordinary retry; its explicit failover
transition caches that replacement-bound T-set form and correlates the terminal AAA. RAA duplicate
replay and repeated AAR retrieval are byte-identical within each state.
Duplicate detection, retry timers, cache lifetime, session lookup, and policy
mutation remain downstream responsibilities.

Both exchanges correlate the authenticated connection generation, Hop-by-Hop
and End-to-End identifiers, P, every present Session-Id/User-Name, the ordered
byte-exact Proxy-Info chain, request type where applicable, and overload-control
offer/answer state. Ordinary answers must also satisfy the caller-selected
logical-Origin policy. Generic E-bit agent errors are exempt only from that
logical-Origin policy and remain connection-bound. Request omissions
use sealed vendor-aware `DiameterParserError` provenance for the checked 5005
mapper. Core and extension counts are independently bounded at 128. Duplicate
singletons, wrong role/vendor/type/flags, malformed grouped state, unknown
mandatory AVPs, and unmodeled originated result contexts fail closed. Other
received RAA base results remain forward-compatible `Other` projections.
Command definitions are also the typed parser/builder source of truth for
known additional-AVP occurrence rules: RAA and AAA preserve bounded repeated
`Failed-AVP` and `Reply-Message`, RAR declares `Reply-Message` singleton,
RAR/RAA/AAA preserve repeated `Class`, AAR forbids `Class`, and
all four authorization-update roles forbid lifecycle `Termination-Cause` and
`Auth-Session-State`. Request roles reject answer diagnostics. An originated
request also rejects redirect-only AVPs. RAA/AAA command metadata preserves
RFC 6733's repeatable Redirect-Host plus singleton usage/cache AVPs, but the
typed parsers and builders reject every redirect result context until its
complete surface is modeled. An originated experimental 3xxx AAA is rejected
because RFC 6733's generic E-bit grammar requires a base Result-Code rather
than an Experimental-Result-only body.
Unknown optional
extensions obey preserve/drop/reject policy. Dictionary-known additional AVPs
receive fixed-width, Address, UTF-8, DiameterIdentity, or bounded grouped-value
validation before retention.

TS 29.273 Table 7.2.3.1/2 flag values are canonical on encode. Per Table
7.2.3.1 Note 2, decode ignores an M-bit mismatch for understood table AVPs
while still enforcing V, P, vendor identity, type, and value semantics. In
particular, AAR-Flags, UE-Local-IP-Address, High-Priority-Access-Info, DRMP,
and Load have direct asymmetric regression evidence. Originated
UE-Local-IP-Address clears M as required by TS 29.212 Table 5.3.0.1.
Undefined AAR-Flags and High-Priority-Access-Info bits are discarded on
receive and never re-emitted.

Independent fixtures in `tests/swm_authorization.rs` are hand-authored from
RFC 6733 framing and TS 29.273 §§7.2.2.4.1-.2 and §§7.2.2.1.3-.4. They cover
all four message roles, exact rebuild, the AAA R-bit editorial regression,
base and experimental results, typed APN and AAR vendor state, T-bit
retransmission, exact proxy correlation, checked omission provenance, unknown
policy, authorization-timer role/cardinality/type and cross-field semantics,
zero/absent/maximum timer values, dictionary and role failures, 129th-entry
bounds, canonical flags, public sequence replay, and redacted diagnostics.

### 7. Redaction

Sensitive typed fields are wrapped in `Redacted<T>` or redaction-safe identity
newtypes. Their `Debug` and `Display` output never exposes the underlying
value; equality, cloning, and hashing still support business logic.

Covered redacted fields:
- `RfAccountingRequest` / `RfAccountingAnswer`: `Session-Id`, `Origin-Host`,
  `Origin-Realm`, `Destination-Realm`, `Destination-Host`, `User-Name`,
  `SubscriptionId::subscription_id_data`, IP addresses inside `PsInformation`.
- `SwmDiameterEapRequest` / `SwmDiameterEapAnswer`: `Session-Id`, `Origin-Host`,
  `Origin-Realm`, `Destination-Realm`, `Destination-Host`, `User-Name`,
  `EAP-Payload`, `EAP-Reissued-Payload`, `EAP-Master-Session-Key`,
  Terminal-Information IMEI and Software-Version, `Mobile-Node-Identifier`,
  `Service-Selection` (top level and inside
  `ApnConfiguration::service_selection`). `SwmDiameterEapAnswer` debug output
  shows only the count of `apn_configurations`, never their contents. Context
  identifiers are numeric selectors and are not treated as subscriber data.
- `SwmSessionTerminationRequest` / `SwmSessionTerminationAnswer`: Session-Id,
  origin/destination identities, User-Name, Route-Record, retained Proxy-Info,
  and all additional AVP values. Diagnostics expose only enum values, counts,
  numeric AVP keys, and value lengths.
- `SwmAbortSessionRequest` / `SwmAbortSessionAnswer`: Session-Id,
  origin/destination identities, permanent User-Name, Route-Record, retained
  Proxy-Info, Error-Message/Error-Reporting-Host, and all additional AVP values.
  Correlation errors expose stable codes rather than either side's values.
- `SwmReAuthRequest` / `SwmReAuthAnswer` and `SwmAuthorizationRequest` /
  `SwmAuthorizationAnswer`: session, user, origin/destination, routing, proxy,
  address, APN, and extension values are redacted. Authorization-Lifetime,
  Auth-Grace-Period, and Session-Timeout remain available through typed fields,
  while diagnostics disclose only whether each value is present.

Raw AVP bytes are **not** redacted: the raw layer is intentionally a
byte-preserving forwarding surface, and redaction is a typed-layer policy.

## Robustness & Fuzzing

Decode paths carry no `unsafe`, use checked length arithmetic, and never
preallocate from a wire-declared length. Three layers guard them:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  fuzz corpus entry, byte-truncations of each entry, and hostile constant
  inputs through raw, owned, dictionary-command, and AVP decode entry points
  under `catch_unwind`. Empty DWR, DPR, and SWm DER seeds exercise sealed
  mandatory-field provenance (the existing header-only CER seed covers CER).
  Dedicated CER seeds cover VSAI missing Vendor-Id, missing Auth/Acct one-of,
  and simultaneous Auth/Acct; a SWm seed covers Terminal-Information missing
  IMEI. Seeds also include repeated SWm State and the explicit projected two-APN
  profile. The SWm set covers the DER-only emergency indication, 3GPP
  experimental result 5001, the Terminal-Information retry, and final
  EAP-Success/MSK/Mobile-Node-Identifier material. STR/STA seeds cover one
  routed termination exchange and missing Termination-Cause provenance.
  ASR/ASA seeds cover a routed maintained-state abort, a successful answer,
  and missing Destination-Host provenance.
  RAR/RAA and AAR/AAA seeds cover one complete authorization update, typed
  authorization timers, the AAA answer-role regression, and missing
  request-type provenance for each request.
  Runs in ordinary `cargo test`; no nightly toolchain or libFuzzer required.
- **Corpus generator helper guard** — `fuzz/generate_corpus.py self-test`
  exercises the `avp()` helper's acceptance of valid flags and rejection of
  reserved AVP flag bits, and pins the emergency KDF fixture to a fixed
  independently checked vector. The per-PR `.github/workflows/ci.yml` gate
  runs this self-test without regenerating the committed corpus.
- **Fuzz target registration and scheduled coverage** — `fuzz/Cargo.toml`
  registers `fuzz/fuzz_targets/decode_message.rs` and
  `fuzz/fuzz_targets/decode_avp.rs`. The repository-level
  `.github/workflows/fuzz.yml` matrix is the source of truth for weekly/manual
  fuzz-smoke scheduling; keep that matrix aligned with this document before
  citing scheduled CI coverage. When the workflow includes `opc-proto-diameter`,
  it runs `cargo +nightly fuzz list` and then executes the registered targets
  for a bounded smoke interval. Each target seeds *only* from its own directory
  under `fuzz/corpus/<target>/`; no committed seed file lives solely in a
  provenance or documentation directory.
- **Fuzz target compilation** — the per-PR `.github/workflows/ci.yml` gate runs
  the corpus generator self-test but does not currently run
  `cargo +nightly fuzz list`; local fuzz-target registration is checked with
  `cargo +nightly fuzz list` (and, when needed, `cargo +nightly fuzz build`)
  from `crates/opc-proto-diameter`.

### On-disk corpus layout

```text
fuzz/corpus/
├── decode_message/           # seeds for the decode_message fuzz target
│   ├── header_only_cer-*
│   ├── cer_request-*
│   ├── cea_success-*
│   ├── dwr_request-*
│   ├── dpr_request-*
│   ├── rf_acr_start-*
│   ├── swm_der-* / swm_dea-*       # normal and emergency recovery stages
│   ├── swm_str-* / swm_sta-*       # Session-Termination and omission seeds
│   ├── swm_asr-* / swm_asa-*       # Abort-Session and omission seeds
│   └── malformed_*-*         # hostile seeds: truncation, duplicate, depth, flags
└── decode_avp/               # seeds for the decode_avp fuzz target
    ├── ietf_origin_host-*
    ├── vendor_ps_info-*
    ├── grouped_failed_avp-*
    ├── padded_single_octet-*
    ├── arbitrary_avp_tree-*
    └── malformed_*-*         # hostile seeds: length, padding, duplicate, depth
```

The `fuzz/generate_corpus.py` script is the source of truth for the named
spec-valid and malformed seeds; running it regenerates the files above. Any
additional hash-only files in these directories are libFuzzer-discovered
regression seeds from prior runs.

## Fixture provenance

Test bytes are divided into four categories. Only categories 1 and 2 count as
ADR 0015 conformance evidence; categories 3 and 4 are parity or regression
evidence only.

1. **RFC-authored fixtures** (`tests/fixture_provenance.rs` and the spec-valid
   seeds in `fuzz/corpus/*/`) — hand-built from RFC 6733 §3 (header), §4 (AVP
   framing), and the cited AVP sections. These are the only fixtures counted as
   ADR 0015 conformance evidence for the base header and AVP layer.
2. **3GPP-authored fixtures** (`tests/fixture_provenance.rs` and the spec-valid
   seeds in `fuzz/corpus/*/`) — hand-built from RFC 6733 wire framing plus
   3GPP TS 32.299 §5.1/§7.1 (Rf), TS 29.273 §7.1.2.4/§7.2 (SWm command and
   AVP codes), TS 29.272 §7.3 (Terminal-Information), and TS 33.402 Annex
   A.4 (IMEI-derived emergency MSK). They are application-dictionary evidence,
   not full application-conformance evidence.
3. **ePDG parity bytes** — *not imported*. The source plan references ePDG
   local-builder cases; those remain external **parity-only** seeds until a
   later fixture-intake task records provenance, license, and capture metadata.
   They are deliberately **not** treated as conformance evidence.
4. **Generated codec round trips** (`tests/fixture_provenance.rs` and existing
   `tests/app_dictionaries.rs`) — built with this crate's own encoder. Useful
   regression tests, but they do not prove wire conformance by themselves.

## Codec Boundary

The following are outside the current crate scope:

- Full RFC 6733 typed AVP value decoding for every base AVP.
- Typed helpers for `app-gx`, `app-s6a`, `app-s6b`, `app-swx`.
- Full message-specific semantic validation (e.g., mandatory-AVP presence for
  every command) beyond what the Rf/SWm typed helpers enforce.
- Complete 3GPP Rf/SWm/Gx/S6a/S6b/SWx application coverage beyond the current
  Rf accounting and SWm Diameter-EAP/Session-Termination/Abort-Session typed
  subsets.
- Transport operations, TCP/SCTP transport, TLS/TLS-PSK handling, realm routing,
  peer topology, watchdog thresholds, failover state machines, AAA/HSS/CDF
  behavior, charging decisions, and deployment readiness policy.
