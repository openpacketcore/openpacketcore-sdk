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
  the actual SWm DER forbidden Result-Code parser path, application/AVP ambiguity,
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
| `app-swm` | 3GPP SWm (id 16_777_264) | Diameter-EAP-Request / Diameter-EAP-Answer (268) | `SwmDiameterEapRequest`, `SwmDiameterEapAnswer` |
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

Raw AVP bytes are **not** redacted: the raw layer is intentionally a
byte-preserving forwarding surface, and redaction is a typed-layer policy.

## Robustness & Fuzzing

Decode paths carry no `unsafe`, use checked length arithmetic, and never
preallocate from a wire-declared length. Three layers guard them:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  fuzz corpus entry, byte-truncations of each entry, and hostile constant
  inputs through raw, owned, dictionary-command, and AVP decode entry points
  under `catch_unwind`. Seeds include repeated SWm State and the explicit
  projected two-APN profile. The SWm set also covers the DER-only emergency
  indication, 3GPP experimental result 5001, the Terminal-Information retry,
  and final EAP-Success/MSK/Mobile-Node-Identifier material.
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
   3GPP TS 32.299 §5.1/§7.1 (Rf), TS 29.273 §7.2 (SWm command and
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
  Rf accounting and SWm Diameter-EAP typed subsets.
- Transport operations, TCP/SCTP transport, TLS/TLS-PSK handling, realm routing,
  peer topology, watchdog thresholds, failover state machines, AAA/HSS/CDF
  behavior, charging decisions, and deployment readiness policy.
