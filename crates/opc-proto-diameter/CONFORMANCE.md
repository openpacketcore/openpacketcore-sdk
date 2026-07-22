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
  and `Preserve` both accept non-mandatory unknown AVPs. Most typed projections
  do not retain those opaque AVPs; the SWm DER/DEA endpoint exception is
  documented below. Use the raw AVP iterators for lossless preserve/forward
  behavior.

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

`SwmDiameterResult::is_diameter_authorization_rejected` classifies only the
base RFC 6733 permanent-failure value 5003. It returns false for base value
4001 (`DIAMETER_AUTHENTICATION_REJECTED`) and for an experimental result with
the same numeric code. An independently constructed DEA fixture proves the
exact M-set Result-Code AVP bytes. Selecting or constructing a response in a
different access protocol remains outside this Diameter boundary.

SWm DER and DEA each carry a role-specific sealed collection for
command-unmodeled optional AVPs at the trailing command wildcard. Under
`Preserve`, the typed parser retains at most 128 well-formed M-clear AVPs and
no more cumulative bytes than
`DecodeContext::max_message_len`, using checked arithmetic before copying.
`Drop` discards them, while `Reject` and unknown M-bit AVPs return the existing
unknown-critical failure at the offending offset. Vendor-aware duplicate keys
remain subject to `DuplicateIePolicy::Reject` even under `Drop`; `First` and
`Last` retain wildcard repetitions in received order because the ABNF wildcard
does not assign value-selection semantics. Exact keys modeled by the DER/DEA
parser never enter the collection; a foreign-vendor AVP with the same numeric
code remains command-unmodeled. Public access reveals only redaction-safe
header/length metadata; raw values can only be replayed by the typed builder
and cannot be injected through
the public collection API. Endpoint rebuilds canonicalize these AVPs to the
trailing wildcard. This is not a byte-preserving relay/proxy contract; exact
forwarding uses the raw `Message` path.
M-set routing AVPs do not enter the optional-extension collections. The typed
routing surface separately validates and retains ordered DER/DEA `Proxy-Info`,
retains ordered DER `Route-Record`, and forbids `Route-Record` on every DEA
profile.

The finite DEA authorization-timer rows are modeled as follows. Every field
remains absent by default, preserving prior canonical message bytes.

| AVP | TS 29.273 presence | Wire identity and cardinality | Typed SDK field | Positive / negative evidence |
|:----|:-------------------|:------------------------------|:----------------|:-----------------------------|
| `Session-Timeout` | Conditional on successful authentication and authorization | IETF 27, `Unsigned32`, V/P clear and M set, singleton | `SwmDiameterEapAnswer::session_timeout` / `SwmSessionTimeout` | Absent, zero/unlimited, nonzero, and `u32::MAX` round trip. Invalid IETF flags/width, duplicates, and every result other than exact base `DIAMETER_SUCCESS` fail. A nonzero-vendor code collision is a distinct unknown AVP governed by `UnknownIePolicy`; M-set unknown AVPs still fail. Diagnostics omit the value. |
| `Authorization-Lifetime` | Optional authorization lifetime | IETF 291, `Unsigned32`, V/P clear and M set, singleton | `SwmDiameterEapAnswer::authorization_lifetime` | Zero and positive values round trip. A positive value without `Re-Auth-Request-Type`, duplicates, invalid IETF flags/width, and a finite value larger than finite `Session-Timeout` fail. Nonzero-vendor code collisions follow the unknown-AVP policy. |
| `Auth-Grace-Period` | Optional | IETF 276, `Unsigned32`, V/P clear and M set, singleton | `SwmDiameterEapAnswer::auth_grace_period` | Zero and `u32::MAX` round trip independently. No relationship to another timer is invented. Invalid IETF flags/width and duplicates fail; nonzero-vendor code collisions follow the unknown-AVP policy. |
| `Re-Auth-Request-Type` | Conditional with positive authorization lifetime | IETF 285, `Enumerated`, V/P clear and M set, singleton | `SwmDiameterEapAnswer::re_auth_request_type` / `SwmReAuthRequestType` | Both assigned values round trip; unknown enum values, invalid IETF flags/width, and duplicates fail. Nonzero-vendor code collisions follow the unknown-AVP policy. |
| `Auth-Session-State` | Shall be omitted on SWm | IETF 277 | no field | Both command dictionaries mark it forbidden and the typed parser rejects the exact IETF key for M-clear/M-set under every unknown-AVP policy. A nonzero-vendor code collision remains a distinct unknown AVP governed by `UnknownIePolicy`; M-set unknown AVPs still fail. |

The RFC 6733 base grammar permits an absent `Session-Timeout`; the codec keeps
that established inbound and origination compatibility instead of changing
the bytes of existing typed answers. Deployments applying TS 29.273's strict
initial-authorization condition should require the field at their policy
boundary. Explicit zero means unlimited and is therefore not smaller than a
positive `Authorization-Lifetime`. Timeout enforcement, re-authorization
scheduling, and teardown remain product policy.

The finite DEA serving/emergency gateway rows are modeled through one shared
canonical RFC 5447 codec. Parsed values are inspectable wire facts only;
acting on them from received network traffic requires authenticated connection
generation plus exact transaction/application/session/proxy correlation and a
named caller assertion at the trusted product boundary. The authenticated
`SwmCorrelatedDiameterEapResponse` is the production client path.

| AVP | TS/IETF presence | Wire identity and cardinality | Typed SDK surface | Positive / negative evidence |
|:----|:-----------------|:------------------------------|:------------------|:-----------------------------|
| Top-level `MIP6-Agent-Info` | DEA Serving-GW only for chained S2b-S8 and exact `DIAMETER_SUCCESS` | IETF 486, Grouped, singleton in SWm DEA; V/P clear; canonical emission uses the defining M setting, while TS 29.273's SWm re-use table 7.2.3.1/2 note 2 makes an understood inbound M mismatch non-fatal | `SwmDeaGatewayContext::chained_s2b_s8_serving_gateway` / `SwmMip6AgentInfo` | Independent M-set/M-clear fixtures parse. Request-bound construction emits M set. Wrong vendor/P, duplicate outer AVPs, empty identity, non-success results, and unbound re-origination fail. |
| `MIP-Home-Agent-Address` | At least one address or host is required | IETF 334, Address, zero to two in one Agent-Info, V/P clear and M set | ordered `SwmMip6AgentInfo::home_agent_addresses` | IPv4/IPv6 and two same-family addresses preserve wire order. A third address, wrong family/length/flags/vendor, and truncation fail. Addresses take selection precedence without discarding the host. |
| `MIP-Home-Agent-Host` | Optional identity indirection | IETF 348, Grouped singleton; exactly one nonempty ASCII IETF `Destination-Realm` and one `Destination-Host`; V/P clear and M set | `SwmMipHomeAgentHost` | Host-only and address-plus-host fixtures parse; missing/empty/duplicate children, duplicate host groups, wrong flags/vendor, and unknown mandatory children fail. Diagnostics never reveal either identity. |
| `MIP6-Home-Link-Prefix` | Optional | IETF 125, OctetString singleton, exactly one prefix-length octet plus 16 IPv6 octets; V/P clear and M set | `SwmMip6HomeLinkPrefix` | Prefixes 0 through 128 with zero trailing bits are representable. Wrong width, length above 128, nonzero host bits, duplicates, and wrong flags/vendor fail. Diagnostics redact the prefix. |
| `Emergency-Info` | DEA emergency PDN-GW only for an emergency DER, authenticated non-roaming user, HSS provenance, and exact `DIAMETER_SUCCESS` | 3GPP 1687/vendor 10415, Grouped singleton; V set/P clear/M may; exactly one usable nested `MIP6-Agent-Info` is required by the defining prose | `SwmDeaGatewayContext::emergency_info` / `SwmEmergencyInfo` | Both outer M values and nested Agent-Info M-set/M-clear fixtures parse; canonical emission uses outer M clear and nested M set. Missing/duplicate nested identity, wrong vendor/P, non-emergency construction, result mismatch, and request-binding mismatch fail. |

Every grouped level caps direct children at 128. Preserved unknown optional
children share the existing DEA-wide `DiameterEapRetention` 128-entry and
`DecodeContext::max_message_len` byte budgets, including mixed top-level and
nested input; unknown mandatory children always fail. Exact address, host,
prefix, extension, and emergency values are absent from errors and diagnostics.
For received client traffic, `SwmCorrelatedDiameterEapResponse` adds the
authenticated connection-generation check. The trusted server-side/originated
`SwmCorrelatedDiameterEapExchange` helper assumes its caller already owns that
transport boundary.
The SDK does not infer chained routing, roaming status, authentication, HSS
provenance, or gateway selection policy.

#### SWm DEA subscriber authorization facts

The following finite rows implement TS 29.273 V19.2 section 7.2.2.1.2 using
the defining TS 29.272 V19.5, TS 29.061 V19.1, and RFC 4006 wire contracts.
Every field is absent by default and is held in the non-exhaustive
`SwmDeaSubscriberAuthorization` bundle. Presence is a typed fact, not an
authorization-success signal.

| AVP | TS 29.273 presence/condition | Wire identity, flags, and typed field | Positive / negative evidence |
|:----|:-----------------------------|:--------------------------------------|:-----------------------------|
| `APN-OI-Replacement` | Conditional on exact `DIAMETER_SUCCESS`, non-emergency access, and proven network-based mobility | 3GPP 10415/1427, UTF8String, canonical V/M set and P clear, singleton; understood outer M mismatch accepted; `SwmApnOiReplacement` | Checked construction and raw parse require case-insensitive `[prefix.]mncNNN.mccNNN.gprs`, with exactly three PLMN digits. Empty/overlong/malformed suffixes, P/vendor, duplicate occurrence, direct-builder use, emergency/result/local-assignment/absent-provenance, and explicit AAA override cases are covered. |
| `Subscription-Id` (MSISDN) | Conditional only on the MSISDN being available | IETF 443 Grouped, canonical V clear/M set/P permitted, singleton; understood outer M mismatch accepted. Required IETF 450 `END_USER_E164` and 444 UTF8String children remain V clear/M set/P permitted; `SwmSubscriptionId` / `SwmE164Number` | One-to-fifteen decimal digits beginning 1..9 round trip in redacted zeroize-on-drop storage. Wrong type, zero prefix/dummy, `+`/separator syntax, overlength, missing/duplicate child, strict child flags, unknown M-set child, and duplicate outer group fail. Optional unknown children are bounded and sealed under Preserve, discarded under Drop, and replayed after the canonical required children. |
| `3GPP-Charging-Characteristics` | Optional subscriber charging fact | 3GPP 10415/13, UTF8String, canonical V set/M clear/P permitted, singleton; understood outer M mismatch accepted; `SwmChargingCharacteristics` | Exactly four upper/lowercase hexadecimal characters decode to two octets; builders emit uppercase and P clear. Non-hex, wrong length/vendor, and duplicates fail. Diagnostics do not expose the value. |
| `UE-Usage-Type` | Conditional on subscription information being available | 3GPP 10415/1680, Unsigned32, V set/P clear and understood M mismatch accepted, singleton; `SwmUeUsageType` | Values 0..=255 round trip; 256, wrong width/vendor/P, and duplicates fail. Builders emit M clear and diagnostics hide the classification. |
| `Core-Network-Restrictions` | Conditional on subscription information being available | 3GPP 10415/1704, Unsigned32, V set/P clear and understood M mismatch accepted, singleton; `SwmCoreNetworkRestrictions` | Assigned bit 1 is retained. Deprecated bit 0 and unassigned bits are discarded; builders emit the canonical assigned mask with M clear. Width/vendor/P/cardinality negatives fail. |
| `MPS-Priority` | Conditional on an HSS MPS subscription; `MPS-EPS-Priority` must be set | 3GPP 10415/1616, Unsigned32, canonical V set/M/P clear, singleton; understood outer M mismatch accepted; `SwmMpsPriority` | Assigned CS, EPS, and messaging bits round trip; unknown bits are discarded. All-zero, CS-only, messaging-only, P, wrong width/vendor, and duplicates fail on parse and build. |

The typed parser rejects a foreign or absent vendor identity reusing any of the
six top-level subscriber codes under every unknown-AVP policy, including
Vendor-Id zero. A vendor-specific child reusing core code 450 or 444 inside
Subscription-Id fails before optional-extension retention even when the valid
IETF child is also present. Genuinely unrelated optional extensions retain the
established policy behavior. The command dictionary marks all six rows
forbidden on DER and singleton on both baseline and projected-profile DEA.
Independent raw fixtures assert exact code/vendor,
width, flags, canonical bytes, result/request conditions, redaction, grouped
extension retention, both understood outer M shapes, and absent-byte
compatibility. Product code still owns MSISDN availability, charging and MPS
policy, restriction enforcement, trusted local mobility configuration, and the
final authorization decision.

The request envelope can retain one explicit
`SwmLocallyConfiguredMobilityMode` without changing DER bytes. Parsed and
default envelopes carry no local provenance, fail closed for APN-OI, preserve
the attached mode across failover retransmission, and include it in replay
payload equality. A DEA vector takes precedence: any PMIPv6/GTPv2 bit maps to
effective `NetworkBased`, `ASSIGN_LOCAL_IP` maps to
`LocalIpAddressAssignment`, and a vector with neither selection maps to no
effective mode without falling back. Only an absent DEA vector permits the
retained local mode. `SwmCorrelatedDiameterEapExchange` exposes both
`effective_mobility_mode()` and `mobility_mode_source()`. Network-based offers
and selections retain TS 29.273's collective PMIPv6/GTPv2 semantics rather
than requiring the same protocol bit on both sides.

The shared Rf and SWm RFC 4006 definitions both mark P as permitted on the
`Subscription-Id` group and its required children. Rf dictionary metadata and
its typed parser retain RFC 4006's canonical outer M-set rule. The SWm
application dictionary alone tolerates either received outer M shape;
required grouped children remain strict on SWm and Rf's established child
parser behavior is unchanged.
The finite SWm DEA access-location rows are modeled below. TS 29.273 does not
enumerate either row in the baseline DER command grammar, so DER has no typed
field for them; an optional DER occurrence remains governed by the existing
bounded trailing-extension policy.

| AVP | TS 29.273 presence | Wire identity and cardinality | Typed SDK field | Positive / negative evidence |
|:----|:-------------------|:------------------------------|:----------------|:-----------------------------|
| `Access-Network-Info` | Optional DEA access-location context | 3GPP 10415/1526, `Grouped`, singleton, V set and P clear; understood M mismatch accepted under table 7.2.3.1/1 note 2 | `SwmDiameterEapAnswer::set_wlan_location_with_time` / `set_wlan_location_without_time`; received values through `SwmCorrelatedDiameterEapResponse::wlan_location` and `SwmAccessNetworkInfo` | Independent raw fixture and typed builder cover canonical order, exact headers, strict P rejection, parse/rebuild, explicit locator-omission evidence, redaction, duplicates, type/length, malformed grouped children, and full-key vendor-collision extension policy. |
| `User-Location-Info-Time` | Optional last-known time conditional on WLAN location | 3GPP 10415/2812, Diameter `Time`, singleton, exactly four NTP-seconds octets; canonical V set/M clear/P clear, defining P and understood M mismatch accepted | Originated through `SwmDiameterEapAnswer::set_wlan_location_with_time`; received through `SwmCorrelatedWlanLocation::user_location_info_time` / `user_location_info_time_omission` | Independent raw and typed fixtures cover exact bytes, explicit originated omission, tolerated received omission, rejection without Access-Network-Info, duplicate/wrong-vendor/wrong-width failures, defining TS 29.212 provenance, and presence-only diagnostics. |

The raw parsed-answer location API exposes only `has_wlan_location` and
`has_wlan_location_time`; it has no SSID, BSSID, civic, operator,
logical-access, or timestamp accessor. Typed access to a received value becomes
available only from `SwmCorrelatedDiameterEapResponse::wlan_location` after authenticated
connection generation, both transaction identifiers, P, ordered Proxy-Info,
Session-Id, application fields, and the configured logical Origin have all
matched the retained DER. Location freshness and how the location influences
authorization remain product policy after that correlation boundary.

`Access-Network-Info` requires its 1..32-octet UTF-8 SSID and at least one
BSSID, civic access-point address, or Logical-Access-ID unless the originator
provides typed `OmittedByOperatorPolicy` evidence. A received SSID-only value
remains interoperable but retains `AbsentOnReceive` rather than inventing that
policy provenance. A BSSID is exposed as six validated individual, nonzero
octets. Common colon/dash and upper/lower input spellings decode, while encode
uses the canonical 17-octet upper-case dash-separated representation. Lengths
are checked before copying attacker-controlled SSID/BSSID text. The TS 29.273 civic profile requires paired
RFC 5580 `Location-Information` and `Location-Data`: code is exactly zero,
association indexes match, and the entity must be `AccessNetwork`. The former
has the RFC 5580 21..251-octet payload bound. Method tokens use the IANA Method
Tokens snapshot dated 2022-09-15 for both origination and receive; an
unregistered later token fails closed until that snapshot is updated. The
latter contains a bounded RFC
4776 uppercase country code plus ordered UTF-8 civic elements. CAtype
membership uses the IANA snapshot dated 2014-04-11, including language and
ISO-15924 script validation. RFC 6848 CAtype 40 accepts an arbitrary bounded
`namespace-URI SP XML-local-name SP nonempty-text` triple, including private
and future namespaces, while rejecting malformed URIs/names/separators,
truncation, and values beyond the one-octet bound. CAtype 29 uses the IANA
Location Types snapshot dated 2024-07-08. One-sided,
truncated, overlong, mismatched-index, invalid-code, invalid-method, invalid
country, and malformed element inputs fail closed.

Operator-Name admits only namespace `1` registered ASCII realm form or
namespace `2` five/six-digit E.212 form. Logical-Access-ID remains an opaque,
nonempty ETSI OctetString. ETSI defines no common size limit for its
technology-independent form, so the enclosing `DecodeContext` and
`EncodeContext` provide the allocation/message bound; a caller originating an
RFC 3046 Circuit-ID must separately honor that format's one-octet length.
Unknown optional group children share the answer-wide budget of at most 128
retained entries and no more bytes than `DecodeContext::max_message_len`, and
expose metadata only. Retained children and receive-only locator/time-omission
provenance can be emitted only through the immutable parsed answer envelope. A
parser-created access value remains receive-derived after every public mutator;
copying or transplanting it into an ordinary builder fails closed, and a caller
must construct a fresh complete originated value. Unknown mandatory children
fail. Numeric collisions with top-level or nested location codes under another
vendor identity are distinct unknown AVPs: optional occurrences follow
`UnknownIePolicy` plus the shared retention budget, while M-set occurrences
fail closed. A timestamp without WLAN
location fails; a received location without a timestamp is tolerated and an
originated omission requires typed evidence. Location/timestamp source,
freshness, authorization use, and logging/export policy remain product-owned.

#### SWm Diameter-EAP generic error and routing scope

Diameter-EAP responses are selected by the header E bit. E-clear messages use
the TS 29.273 application DEA grammar and reject base 3xxx results. E-set
messages use RFC 6733 section 7.2's generic answer grammar: optional
`Session-Id`, mandatory `Origin-Host`, `Origin-Realm`, and base `Result-Code`,
followed by bounded diagnostics/routing and extension AVPs. The generic grammar
does not require SWm `Auth-Application-Id`, `Auth-Request-Type`, or EAP AVPs.
The parser accepts valid 3xxx, 5xxx, and unrecognized fallback families and
rejects 1xxx, 2xxx, 4xxx, and values below 1000. `Experimental-Result` can be
present only in addition to the base result and never supplies E-bit or
redirect semantics. Known application AVPs in the generic wildcard retain
their typed flags/width validation; an optional `Auth-Application-Id` must
match header application 16_777_264. Destination-Host, Destination-Realm,
Route-Record, vendor-id zero, and unknown M-set AVPs fail closed.
Exact base 3002/3004 apply a narrower DRA-delivery profile: every known SWm
application-only DEA field is rejected, while generic base/RFC extension AVPs,
full-key foreign-vendor collisions, and unknown optional AVPs keep the bounded
section 7.2 wildcard behavior. Result 3004 becomes actionable only when the
correlated DER selected a specific server with Destination-Host, as required
by RFC 6733 section 7.1.3. Both results require the DER's exact Session-Id
and the authenticated Diameter agent's exact Origin-Host/Origin-Realm pair
before they become actionable.

| Routing/error AVP or signal | Wire rule | Typed guarantee and evidence |
|:----------------------------|:----------|:-----------------------------|
| Header R/P/E/T | DER sets R/P and clears E. DEA clears R/T, sets P, and selects ordinary/generic grammar with E. | Raw negative fixtures cover DER E, DEA P/T, ordinary E parsing, and base 3xxx on E-clear DEA. Failover retransmission alone sets DER T while retaining End-to-End identity and allocating a replacement Hop-by-Hop identifier/connection binding. |
| `Proxy-Info` | IETF 284, M set, repeated; grouped exact-once `Proxy-Host` and `Proxy-State` | The grouped parser requires nonempty ASCII Proxy-Host, retains opaque Proxy-State privately, applies unknown-child policy, caps children at 128, and matches full vendor-aware keys. Builders echo the exact ordered request chain after diagnostics and before generic wildcard redirect AVPs. Correlation requires byte-identical order/content. Values never appear in diagnostics. |
| `Route-Record` | IETF 282, M set, repeated on DER; forbidden on DEA | DER retains ordered nonempty ASCII identities and emits them after Proxy-Info. No answer builder reflects them; baseline and projected DEA dictionaries mark the AVP `Forbidden`, and typed parsing rejects it independently. |
| Base `Result-Code` 3006 plus `Redirect-Host` | Redirect-Indication requires one or more repeated IETF 292 DiameterURI values | `SwmDiameterRedirect` preserves bounded wire order without assigning target preference. Only exact base 3006 with E set creates redirect semantics; experimental numeric 3006 remains ordinary/opaque. Missing, invalid, excessive, or out-of-context targets fail. Target values remain sealed until correlation. |
| Base `Result-Code` 3002 / 3004 | `DIAMETER_UNABLE_TO_DELIVER` / `DIAMETER_TOO_BUSY`, E set; R/T clear; request P and identifiers preserved | `SwmDiameterEapAgentDeliveryFailure` admits only these exact values. `new_agent_delivery_failure_for` records a private zeroized binding over the complete canonical request envelope before the shared generic builder copies Session-Id and ordered Proxy-Info. Mutation, transplant to a conflicting request, application-only AVPs, redirect/experimental context, and parsed-answer re-origination fail closed. Result 3004 additionally requires request Destination-Host. Received failures require the exact request Session-Id and a separate exact, ASCII-case-insensitive authenticated-agent Origin pair; missing and mismatched authority have stable value-free errors. They become typed only after the transport atomically removes the pending connection-generation/Hop-by-Hop entry and the SDK validates End-to-End plus the complete request correlation. Independent literal exact-wire fixtures cover both values. |
| `Redirect-Host-Usage` / `Redirect-Max-Cache-Time` | IETF 261/262, singleton | Absence and explicit `DONT_CACHE` are preserved distinctly and both produce effective no-cache. A nonzero usage requires Max-Cache-Time. RFC does not forbid Max-Cache-Time with absent/zero usage, so it is preserved but is not actionable cache policy. The typed precedence accessor follows RFC 6733's route precedence rather than numeric enum order. |
| `Failed-AVP` | IETF 279, M set, repeated | Generic E parsing validates the outer AVP and keeps its inner representation opaque, including synthesized/malformed representations permitted by RFC 6733. The explicit MUST-presence codes 5001, 5004, 5007, 5008, 5009, 5014, and 5016 fail when absent; 3009 and 5005 retain their non-MUST compatibility. Ordinary E-clear RFC 4072 DEA retains repeated values for value-free metadata but refuses typed re-origination to prevent evidence rebinding. |
| Retained routing/error budget | Combined Proxy-Info, Route-Record, redirect, Failed-AVP, and generic wildcard values | Checked arithmetic caps retained entries at 128 and bytes at `DecodeContext::max_message_len`. Redirect construction accounts for usage/cache AVPs before it can produce an unencodable plan. |

`parse_swm_diameter_eap_response_envelope_from_connection` binds received
responses to an authenticated, process-unique connection generation.
`SwmDiameterEapRequestEnvelope::correlate_response` then requires matching
connection, Hop-by-Hop and End-to-End identifiers, P, exact Proxy-Info, and a
matching Session-Id when the generic grammar carries one. Ordinary application
answers additionally satisfy the configured direct/routed logical-Origin
policy and request application/authentication facts. Generic errors skip only
terminal logical-Origin matching because an RFC 6733 intermediary may originate
them. Exact 3002/3004 additionally require Session-Id presence and exact match,
plus an exact ASCII-case-insensitive Origin-Host/Origin-Realm match against the
authenticated dialed agent. `SwmExpectedAnswerPeer::routed_via` carries that
agent pair independently of terminal AAA authority; plain `routed` carries no
agent authority and fails closed. A direct binding derives agent authority from
the exact negotiated peer identity. Destination values never supply either
authority. Parsed Redirect-Host values are inaccessible and cannot be
re-encoded before that complete gate succeeds.

The public generic origination path is restricted to request-bound base 3006
through `SwmDiameterEapGenericErrorAnswer::new_redirect` and exact base
3002/3004 through `new_agent_delivery_failure_for`; all finish through
`build_swm_diameter_eap_response_for`. Arbitrary originated errors use the
existing `error_answer::build_diameter_error_answer` boundary, which binds
failure evidence to the inspected request. Exact response retransmission uses
the cached `OwnedMessage`, not a mutable parsed value. Target selection,
connection attempts, redirect-cache keying and expiry, and route policy remain
consumer-owned. Pending-request consumption and duplicate-response handling
are also consumer-owned, but are prerequisites rather than optional policy:
the transport must atomically remove one entry keyed by authenticated
connection generation and Hop-by-Hop Identifier before correlation. A
same-generation duplicate must find no live entry; codec equality alone is not
replay protection.

The typed DER surface also carries optional `RAT-Type` and
`Service-Selection` authorization context. `RAT-Type` uses vendor 10415, code
1032, a four-octet Enumerated value, and exact V/M/P flag validation;
`Service-Selection` uses the vendor-neutral RFC 5778 code 493 and requires the
M bit. Both fields are singleton. Service-Selection must be an ASCII,
dot-separated APN with nonempty DNS labels of at most 63 octets, and an
emergency DER cannot carry it. The product remains responsible
for supplying Service-Selection only from a UE-requested APN and choosing WLAN
or the TS 29.273 VIRTUAL fallback from trusted access provenance.

The DER/DEA surface models RFC 5447 `MIP6-Feature-Vector` (code 124) as a
retained typed `Unsigned64`. Builders set M; parsers apply the TS 29.273
understood-AVP override and accept either M value while requiring V/P clear.
The exact Release 19 mobility bits are named, including GTPv2
`0x0000400000000000`. A DER cannot originate the answer-only
`ASSIGN_LOCAL_IP` selection. A DEA cannot combine that selection with
PMIP6/GTPv2. Request-bound correlation permits mobility authorization only on
exact base `DIAMETER_SUCCESS`: success requires presence to match the request,
non-success forbids the vector, non-NBM bits must be a subset of the offer,
and an offer containing either PMIP6 or GTPv2 authorizes the TS-defined
collective NBM response containing either or both bits.
The codec preserves the exact vector across typed parse/rebuild cycles. Because
the generic Diameter model does not own the consumer's multi-round EAP state,
the consumer remains responsible for carrying the initial access context into
each continuation DER; a regression fixture proves that changing only EAP and
State data retains the identical vector wire value on the next round.

Repeated vendor-10415 `Supported-Features` (628) groups preserve wire order and
reject duplicate `(Vendor-Id, Feature-List-ID)` identities. Vendor-Id, 3GPP
Feature-List-ID (629), and Feature-List (630) are mandatory children with
exact widths and vendor-aware cardinality. Request entries retain an explicit
outer-M policy: M-clear discovery is legal only for a zero list; answer groups
always clear M. The SWm convenience value is `(10415, 1, 0)`. Under Preserve,
bounded optional extension children retain exact header/value/order and are
re-emitted; Drop sanitizes them, Reject refuses them, and unknown M-set
children always fail. Missing required children retain sealed grouped-parent
provenance for nested request-bound 5005 `Failed-AVP` generation.

DER `UE-Local-IP-Address` (2805) uses the RFC 6733 Address codec for IPv4 and
IPv6, requires vendor 10415 and P clear, and tolerates either received M value
for this understood reused AVP while builders emit M clear. It is singleton,
malformed families/lengths fail closed, and diagnostic output reveals only
presence. All three additions are optional, so absent fields preserve the
previous DER/DEA bytes exactly.

The Diameter-EAP overload/load slice completes the finite TS 29.273 V19.2
rows below without exposing a raw additional-AVP field. Its public model and
codec are shared with the established SWm lifecycle commands.

| AVP | TS 29.273 presence | Wire identity and cardinality | Typed SDK field | Positive / negative evidence |
|:----|:-------------------|:------------------------------|:----------------|:-----------------------------|
| DER `OC-Supported-Features` | Optional reacting-node capability | IETF 621, Grouped, singleton, V/P clear and application-controlled M; optional singleton IETF 622 `Unsigned64` child | `SwmDiameterEapRequest::oc_supported_features` / `SwmOcSupportedFeatures` | Absent, implicit loss, explicit loss, M-set/M-clear, and extension-bit request fixtures parse; zero, missing-loss, duplicate, wrong V/P/vendor/type/length, and unknown mandatory children fail. Extension-bearing received offers cannot be re-originated. |
| DEA `OC-Supported-Features` | Conditional on the DER offer | Same IETF 621 group and flags, singleton | `SwmDiameterEapAnswer::oc_supported_features` | Request-bound build and envelope correlation reject unsolicited or unoffered selections; an offer may receive no selection. The executable profile selects only RFC 7683 loss. |
| DEA `OC-OLR` | Optional report from a reporting node | IETF 623, Grouped, singleton, V/P clear; required sequence/report-type and optional reduction/validity children | `SwmDiameterEapAnswer::oc_olr` / `SwmOcOlr` | Loss requires same-answer support plus Reduction-Percentage. Host/realm reports round trip; missing/duplicate required children, invalid type/width/flags, and unknown mandatory children fail. Received validity above 86400 maps to effective 30 seconds and reduction above 100 becomes non-actionable; neither can be originated. |
| DEA `Load` | Optional and repeatable | IETF 650, Grouped, bounded ordered `*`; V/P clear, application M accepted and canonical origin M clear; optional singleton type/value/source children | `SwmDiameterEapAnswer::load_reports` / `SwmLoad` | Multiple host/peer reports preserve order; the 129th fails. Received incomplete groups are retained but non-complete and cannot be originated. Type, 0..65535 value, nonempty ASCII SourceID, duplicate child, flags, and unknown-child policy are tested. `actionable_for_peer` enforces authenticated-peer SourceID equality for peer reports. |

This is an explicitly bounded RFC 7683 baseline loss profile. RFC 8581's
peer-overload extension (`OC_PEER_REPORT`, report type 2, `OC-Peer-Algo`, and
overload `SourceID`) is not executable here; unknown optional children remain
retained as typed-endpoint rebuild metadata, but this is not a byte-preserving
Diameter relay boundary and the SDK does not claim complete current DOIC.
RFC 8583 Load is supported independently. Overload state storage, timer
application, traffic abatement, transport authentication, and routing policy
remain consumer responsibilities.

The remaining non-overload DER access-context slice is mapped below. Canonical
builders use the TS 29.273 V19.2.0 flags; receivers enforce V/P and apply table
7.2.3.1/1 note 2 by ignoring an understood outer M-bit mismatch.

| AVP | TS 29.273 presence | Wire identity and cardinality | Typed SDK field | Positive / negative evidence |
|:----|:-------------------|:------------------------------|:----------------|:-----------------------------|
| `QoS-Capability` | Optional capability announcement | IETF 578, Grouped, M set, V/P clear, singleton; contains one or more ordered RFC 5777 `QoS-Profile-Template` 574 groups | `SwmQosCapability` / `SwmQosProfileTemplate` | Multiple profiles and repeated complete identities round trip; empty groups, missing/duplicate required children, wrong widths/flags, excessive counts, and unknown mandatory children fail |
| `Visited-Network-Identifier` | Conditional: present when the ePDG is outside the UE home network | 3GPP 10415/600, OctetString, V+M set, P clear, singleton | `SwmVisitedNetworkIdentifier` | Two-digit MNC canonicalization and roaming fixture; malformed PLMN domains, vendor, flags, and duplicates fail |
| `AAA-Failure-Indication` | Optional: only after a previously assigned AAA server is determined unavailable | 3GPP 10415/1518, Unsigned32, V set, M/P clear, singleton | `SwmAaaFailureIndication` | Defined bit zero round trips; a present zero mask and malformed width fail; reserved received bits are discarded and never re-originated as required by §8.2.3.21 |
| `High-Priority-Access-Info` | Conditional: UE access-priority indication admitted by operator policy | 3GPP 10415/1542, Unsigned32, V set, M/P clear, singleton | reused `SwmHighPriorityAccessInfo` | Configured bit round trips; a present zero mask, malformed width, and invalid provenance fail; reserved received bits are discarded |

`SwmDerAccessContext` is an application-side checked-construction input, not
wire metadata. `SwmConditionalValue` distinguishes absent, locally configured,
UE-provided, and AAA-derived values without logging values. The checked
outbound builder accepts locally configured QoS/visited-PLMN data, an
AAA-transport-derived server failure, and UE-provided high-priority access.
Every other source and every prepopulated raw context field fails before
encoding. It returns a wrapper that creates the typed request, encoded message,
and an informational source snapshot together and exposes them immutably while
the wrapper is retained. `into_parts` explicitly consumes that coupling; the
snapshot then describes only the returned request/message at construction time.
The ordinary builder remains a source-agnostic wire-validation and parser-replay
boundary. Diameter does not encode provenance, so decode never guesses it.
Product code still decides whether roaming, QoS announcement, server failover,
and operator priority-admission conditions apply.

RFC 5777 grouped values are bounded. Required `Vendor-Id` and
`QoS-Profile-Id` children are exact singleton Unsigned32 values with strict
base M/V/P flags. Complete profile templates remain ordered and repeatable as
the RFC grammar permits. Under Preserve, optional extension children at both
group levels are retained and re-emitted without a public raw-injection API;
Drop removes them, Reject refuses them, and unknown M-set children always
fail. Known grouped occurrence metadata now exempts only explicitly repeatable
children from conservative duplicate rejection; undeclared nested keys remain
singleton by default. An empty capability retains typed missing-template
provenance, and a profile missing either required child retains the exact
received `QoS-Capability` → `QoS-Profile-Template` path. The request-bound
error-answer mapper can therefore synthesize the corresponding nested 5005
`Failed-AVP` without parsing error text or choosing the wrong repeated profile.

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
encode and parse boundaries. Child identifiers must be nonzero and unique.
Child Service-Selection values must be unique APN Network Identifiers under TS
23.003 section 9.1.1: their label-length encoding is at most 63 octets, labels
have the required ASCII syntax and boundaries, reserved
`rac`/`lac`/`sgsn`/`rnc` prefixes and a terminal `gprs` label are forbidden,
and case is insignificant. Exact `*` is accepted as a typed DER request for
the subscription default and as a raw TS 29.272 wildcard configuration. A
nonempty wildcard response profile requires a nonzero projected default
identifier that resolves to a supplied configuration. `Specific-APN-Info` is
typed as an ordered concrete APN/gateway pair and may satisfy exact named DER
correlation. The codec does not choose among repeated pairs, and a wildcard
parent remains ineligible as a broad policy authorization. APN profile material
is accepted only when Result-Code is exactly
`DIAMETER_SUCCESS` (2001), not merely another 2xxx result. A missing default
remains `None`; an unresolved or ambiguous profile fails closed, and the
resolver independently returns `None` for any invalid profile.

The baseline SWm command profile marks `State` repeatable and keeps
`APN-Configuration` singleton. Its RFC 4005 State definition requires V clear
and M set while permitting P. Typed DER/DEA builders emit P clear, the canonical
profile recommended by RFC 6733 while no end-to-end security mechanism is
specified; parsers accept either P value and retain every opaque State value
byte-for-byte and in wire order for a subsequent Diameter-EAP round. The separate
`SWM_PROJECTED_PROFILE_DICTIONARIES` profile also marks APN-Configuration
repeatable for explicitly configured peers. `Message::decode_with_dictionary`
supports both with `DecodeContext::conservative()` while all undeclared,
unknown, and undeclared nested grouped keys retain duplicate rejection. Supplying both
profiles is ambiguous and fails closed; typed `set_once` checks independently
protect singleton fields. The opt-in profile remains an interoperability
extension and is not a baseline SWm cardinality claim.

The SWm authorization projection of the TS 29.272 V19.5.0 APN value is split
between the typed `ApnConfiguration` wire core and a sealed ordered supplement.
`SwmAuthorizedApnConfiguration` is the originated construction boundary. A
supplement stores an exact snapshot of its entire core and revalidates it
before exposure or encoding; equality is ordinary structural equality.
Reordering cores or changing Context-Identifier, Service-Selection, PDN-Type,
QoS, or AMBR fails closed instead of transplanting addresses or gateway facts.
There is no answer-local or transaction-only supplemental APN getter.
`SwmCorrelatedDiameterEapResponse::apn_configuration_views` provides
structurally checked wire facts only after the response is bound to the expected
authenticated connection generation and Origin-Host/Realm as well as the full
DER/DEA transaction and application facts. Its
`authorized_apn_configurations` method additionally rejects wildcard parents
and unsupported PDN enum values as broad authorization grants. Both remain
preserved and re-encodable on the raw answer core surface.

The understood outer `APN-Configuration` requires V, clears P, and accepts
either inbound M shape under TS 29.273 table 7.2.3.1/1 note 2; canonical
encoding always sets M. Every understood nested APN, QoS, ARP, and AMBR child
likewise ignores only a received M-bit mismatch while still enforcing exact V,
P, type, width, and cardinality, then emits the defining canonical M value.

| APN child | Typed surface and wire contract | Validation evidence |
|---|---|---|
| `Context-Identifier`, `Service-Selection`, `PDN-Type` | Typed core; 3GPP Context/PDN children canonically set V/M and clear P, while IETF Service-Selection clears V/P and sets M | Required singletons; identifiers are nonzero/unique; named APNs satisfy the complete TS 23.003 Network-Identifier grammar and are unique case-insensitively. Exact request wildcard selection resolves only through the default pointer. Raw wildcard profiles and unknown PDN enum values round-trip but are rejected by the authorization view. |
| `Served-Party-IP-Address` | Ordered `IpAddr` slice; code 848/vendor 10415, Address, canonical V/M set and P clear; TS 32.299 section 7.2.187 | Zero to two values, no repeated family, IPv6 lower 64 bits zero, assignable unicast semantics, and family compatibility with PDN-Type. Truncation, third values, duplicate families, unspecified/broadcast/multicast/loopback/link-local values, and noncanonical prefixes fail. Private, CGNAT, ULA, and documentation ranges remain representable. |
| `EPS-Subscribed-QoS-Profile`, `Allocation-Retention-Priority` | `SwmQosClassIdentifier`, `SwmPriorityLevel`, and typed pre-emption enums; all grouped/leaf values canonically set V/M and clear P | QCI admits assigned 1-9, 65-67, 69-76, 79-80, 82-85 and operator-specific 128-254 values; spare/reserved values fail. Priority is 1-15; both pre-emption fields are 0/1 with their specified absent defaults. Missing/duplicate children, wrong widths, V/P, or nested cardinality fail. |
| `AMBR` | Exact `SwmBandwidth` UL/DL values; base codes 516/515 plus extended codes 555/554, all canonical V/M set and P clear | Values 1 through `u32::MAX` use the base AVP. Higher exactly representable multiples of 1000 use a saturated base plus extended kbps through `u32::MAX * 1000` bps. Zero, the 4,294,967,296-4,294,967,999 gap, inconsistent extended/base pairs, overflow, missing/duplicate children, and wrong flags fail. It is NBM-only. |
| `VPLMN-Dynamic-Address-Allowed` | `SwmVplmnDynamicAddressAllowed`; code 1432/vendor 10415, Enumerated, V/M set and P clear | Width, enum, flags, vendor, and singleton violations fail. |
| `MIP6-Agent-Info` | Reuses the canonical `SwmMip6AgentInfo` codec | Empty identity, excessive addresses, host/prefix/cardinality/depth violations, and unknown mandatory children fail. APN nested extensions consume the same DEA retention budget. |
| `Visited-Network-Identifier`, `PDN-GW-Allocation-Type` | Reuses `SwmVisitedNetworkIdentifier` plus `SwmPdnGwAllocationType`; allocation code 1438/vendor 10415 is Enumerated with V/M set and P clear | Allocation cannot appear without a gateway. A visited identifier requires explicit Dynamic allocation; Dynamic does not require the optional identifier. |
| `Specific-APN-Info` | `SwmSpecificApnInfo`; code 1472/vendor 10415, Grouped and repeatable only below parent `Service-Selection == "*"`; canonical outer V/M set and P clear; exactly one concrete IETF Service-Selection, exactly one canonical IETF MIP6-Agent-Info, optional singleton 3GPP Visited-Network-Identifier, then sealed optional extensions | Missing/duplicate known children, nested wildcard/invalid APN, concrete parent, wrong type/vendor/V/P/length, malformed gateway or visited network, excessive count/depth, and unknown mandatory children fail. Received M mismatches are tolerated for understood values and rebuild canonically. Repeated ordered APN/gateway pairs—including the same APN—remain distinct; product selection is outside the codec. Unknown optional children share the DEA retention budget. |
| `3GPP-Charging-Characteristics`, `APN-OI-Replacement` | Reuses the canonical subscriber-profile `SwmChargingCharacteristics` and `SwmApnOiReplacement` values | Exact width/string grammar, flags, vendor, singleton cardinality, and NBM request conditioning are shared with the DEA subscriber authorization surface. |
| `Interworking-5GS-Indicator` | `SwmInterworking5gsIndicator`; code 1706/vendor 10415, Enumerated, V set and M/P clear | Only values 0 and 1 are accepted; absent means not subscribed. It is NBM-only. |
| trailing optional `AVP` | Sealed ordered extension replay with value-free metadata | `Preserve` retains optional M-clear exact bytes, `Drop` discards, `Reject` fails, and unknown mandatory children always fail. Nested APN, nested MIP6, and top-level DEA extensions share one 128-entry plus retained-byte budget. |

The request-bound mutator is atomic and requires an exact DER envelope, exact
base `DIAMETER_SUCCESS`, a non-emergency request, request/answer identity and
mobility correlation, and inclusion of an explicitly requested APN. Explicit
DEA PMIPv6/GTPv2 selection takes precedence. Otherwise typed local
`NetworkBased` provenance permits the NBM field set, while
`LocalIpAddressAssignment` restricts each APN to HA-APN plus PDN-GW identity
for IKEv2 Home-Agent discovery. An explicit local/non-NBM DEA vector must also
set `MIP6_INTEGRATED`; contradictory AAA evidence fails rather than falling
back to local provenance. Product APN selection and gateway policy remain
outside the codec.

Only the nine exact TS 29.273 section 8.2.3.7 prohibited child identities are
rejected: LIPA-Permission, Restoration-Priority,
SIPTO-Local-Network-Permission, WLAN-Offloadability,
Non-IP-PDN-Type-Indicator, Non-IP-Data-Delivery-Mechanism, SCEF-Realm,
Preferred-Data-Mode, and SCEF-ID. Specific-APN-Info is a typed repeatable group
under the conservative dictionary. SIPTO-Permission,
PDN-Connection-Continuity, RDS-Indicator, and Ethernet-PDN-Type-Indicator are
not hard-rejected; they follow the unknown policy until a typed SWm meaning is
modeled. Foreign-vendor numeric collisions likewise remain ordinary unknown
optional AVPs. Synthetic independent fixtures cover exact identities,
canonical flags/order, byte-exact replay, shared retention exhaustion,
semantic contradictions, and redaction-safe diagnostics.

The request-bound 3002/3004 agent-delivery classifier includes the exact SWm
application-only 3GPP identities `(554, 10415)`, `(555, 10415)`,
`(848, 10415)`, `(1432, 10415)`, `(1438, 10415)`, `(1472, 10415)`, and
`(1706, 10415)`. Numeric-code or foreign-vendor collisions are not members of
that set.

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
`same_replay_payload` adds a stricter typed-payload guard on top of RFC 6733
duplicate identity. It gives a server-side duplicate cache a redaction-safe
boolean comparison over the End-to-End Identifier, P bit, every typed request
fact, ordered Route-Record and extension AVPs, and the exact ordered Proxy-Info
chain. It ignores the Hop-by-Hop Identifier, T bit, and authenticated
expected-answer peer binding that may legitimately change across failover. For
retained AVPs it ignores only the derived header length, which encoding
recomputes from the value; code, flags, Vendor-Id, and value must match. The
operation does not expose a digest, raw AVP bytes, or retained values.
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

`SwmAbortSessionRequestEnvelope::same_replay_payload` provides the stricter
typed-payload preflight needed before a duplicate cache reuses a committed ASA.
It requires the End-to-End Identifier, P, every typed request field, exact
optional-field presence, ordered Route-Record/additional AVPs, and the raw
ordered Proxy-Info chain. It ignores Hop-by-Hop, T, expected-answer peer
binding, and only the derived retained-AVP length; retained code, flags,
Vendor-Id, and value stay exact. The standardized SWm ASR grammar has no
dedicated Abort-Cause field. `Auth-Session-State` is compared exactly, and any
abort-cause-like deployment extension remains an opaque additional AVP whose
header, value, and order are compared without exposing them.

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
and DRMP receive-tolerant/originate-clear M-bit contract. Public replay-payload
regressions independently cover failover equality, each authorized exclusion,
every typed field, retained AVP identity/order, Proxy-Info and Route-Record
order, encode/parse normalization, and redacted diagnostics.

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
complete `SwmAuthorizedApnConfiguration` only on exact base
`DIAMETER_SUCCESS`. Parsing preserves the APN supplement rather than reducing
it to the five-field core, and encoding restores the complete value. A plain
parsed AAA exposes only `.core()` wire facts; addresses, gateway, charging,
APN-OI, interworking, and sealed extension metadata become visible only through
`SwmCorrelatedAuthorizationExchange::apn_configuration_view` after authenticated
connection, expected-Origin, and complete AAR/AAA request correlation.
Unsupported raw PDN enum values fail at this authorization boundary. It exposes the
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

`SwmReAuthRequestEnvelope::same_replay_payload` gives a server-side duplicate
cache the corresponding RAR preflight. It requires the End-to-End Identifier,
P, every typed request fact including Re-Auth-Request-Type, ordered
Route-Record/additional AVPs, and the exact Proxy-Info chain. Hop-by-Hop, T,
expected-answer peer binding, and encoder-derived retained-AVP length are the
only exclusions; code, flags, Vendor-Id, value, and ordering remain exact. The
boolean result and diagnostics expose none of those retained values, and the
operation owns no cache or authorization policy.

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

#### Complete public SWm lifecycle acceptance

`tests/swm_public_lifecycle.rs` is a compiler-external integration fixture, so
it can use only exported crate APIs. Its first deterministic synthetic session
performs DER/DEA establishment, the public RAR/RAA then AAR/AAA type-state
update, and ePDG-originated STR/STA termination. A separate deterministic
session performs DER/DEA establishment, an inbound maintained-state ASR/ASA,
and the administrative STR/STA derived only after constructing the exact
request-bound ASA bytes. Every request and answer is independently encoded,
decoded, parsed into public envelopes, and correlated. The fixture checks exact
application, command, direction, P/T/E flags, both Diameter identifiers,
connection and logical-Origin policy where supported, canonical rebuild bytes,
byte-identical committed retry/replay, and redaction of session, user, and peer
host/realm identities plus DER/DEA EAP and master-session-key material.

This evidence completes the generic typed SWm lifecycle surface requested by
#351. It does not make the SDK an active-session authority and does not change
the broader experimental Diameter conformance status. Session lookup,
authorization, transport pending state, retry/cache lifetime, teardown and
compensation ordering, and product side effects remain downstream.

### 7. Redaction and retained sensitive ownership

Typed fields use `Redacted<T>`, `Sensitive<T>`, or redaction-safe identity
newtypes. All three diagnostic surfaces hide the underlying value.
`Redacted<T>` is diagnostics-only; it does not promise memory erasure.
`Sensitive<T>` owns a `zeroize::Zeroizing<T>`, implements
`ZeroizeOnDrop`, and gives each clone independently zeroizing storage while
preserving equality and hashing for correlation. Its `into_zeroizing` method
lets a consumer transfer ownership without returning to an ordinary value.

The typed STR/STA `Session-Id` and permanent `User-Name` fields use
`Sensitive<String>`. The STR and STA facts, their request/answer envelopes,
and the correlated exchange expose an explicit `ZeroizeOnDrop` contract for
those retained owners. Parsing moves newly allocated strings directly into
`Sensitive`; answer construction and request-envelope cloning clone only into
another `Sensitive` owner. The canonical wire fixtures and correlation rules
are unchanged.

Zeroization covers the wrapper's current owned allocation on a best-effort
basis. It cannot erase allocator copies left by earlier reallocation, raw
input, already encoded messages, transport caches, swap, or kernel/network
buffers. Those are separate product and transport lifecycle concerns.

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
- `SwmSessionTerminationRequest` / `SwmSessionTerminationAnswer`: Session-Id
  and User-Name are both redacted and zeroizing; origin/destination identities,
  Route-Record, retained Proxy-Info, and all additional AVP values are
  redacted. Diagnostics expose only enum values, counts, numeric AVP keys, and
  value lengths.
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
  Rf accounting and SWm Diameter-EAP, Session-Termination, Abort-Session,
  Re-Auth, and AA typed subsets.
- Transport operations, TCP/SCTP transport, TLS/TLS-PSK handling, realm routing,
  peer topology, watchdog thresholds, failover state machines, AAA/HSS/CDF
  behavior, charging decisions, and deployment readiness policy.
