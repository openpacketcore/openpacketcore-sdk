# PFCP Protocol Conformance

This document defines the conformance of the `opc-proto-pfcp` crate against
3GPP TS 29.244.

## Specification Baseline

- **Document**: 3GPP TS 29.244
- **Release**: Release 18 API baseline; wire registries and citations verified
  against TS 29.244 V19.6.0 (R19), without claiming every R19 procedure.
- **Status**: v3 — session-management codec subset implemented and published;
  `Production Profile v1` is a compatibility identifier for the N4 codec
  candidate below, not a current production approval

The Cause registry and the F-TEID / UE IP Address wire layouts are checked
against [TS 29.244 V19.6.0](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/19.06.00_60/ts_129244v190600p.pdf)
Tables/Figures 8.2.1-1, 8.2.3-1, and 8.2.62-1. This adds named Cause values;
it does not claim complete Release 19 procedure support.

### Wire corrections and source migration (#1512–#1514)

- Cause 66 is `MandatoryIeMissing`; cause 72 is
  `NoEstablishedPfcpAssociation`. Named values cover 1–3 and 64–92.
  Unknown values round-trip, and `is_acceptance` / `is_rejection` classify
  the full 1–63 / 64–255 ranges; reserved zero belongs to neither.
- F-TEID CHOOSE requests carry address-family flags and an optional CHOOSE ID,
  with no TEID or address bytes. Both decode and encode reject CHID without
  CH, missing address families, or fields inconsistent with their flags.
- `UeIpAddress.v4` uses bit 2 and `v6` uses bit 1. Remove the old `ipv4d`,
  `ipv4_prefix_length`, and `ch` fields from struct literals. IPv6 delegation
  uses `ipv6d` and `ipv6_prefix_delegation_bits`; explicit IPv6 prefix lengths
  use the new `ip6pl` flag and `ipv6_prefix_length`. CHV4/CHV6 use bits 5/6.
  Bit 8 is ignored on receive and cleared on encode. Inconsistent allocation
  flags, IPv6D with IP6PL, and truncated fields are rejected at all validation
  levels. Encoders reject fields inconsistent with their flags.

Both address IEs are **Extendable** in Table 8.1.2-1: §8.1.2 requires receivers
to ignore unknown trailing octets. The exact-length rejection requested in
#1513 would violate this rule. Typed decoding accepts these extensions and
re-encodes the known fields; use `InformationElement` for byte-exact forwarding.

The previous address layouts and shifted Cause values were incorrect wire
encodings and are not supported as a compatibility mode. Downstream exhaustive
matches on `CauseValue` must account for the added variants. Independent byte
and malformed-input regressions are in `tests/spec_wire_regressions.rs`.

## Production Profile v1 — N4 Codec and Validation

`opc-proto-pfcp` retains `Production Profile v1` as its public **codec and
validation profile** identifier for SMF/UPF N4 integration. The identifier does
not attest production maturity. The profile includes typed construction,
decode, encode, and semantic validation for the procedures below. It does not
claim to implement an SMF, UPF, PFCP transport stack, node selection, local
policy, charging, persistence, or high-availability control-plane behavior.

### Profile-owned procedures

The profile checks the mandatory top-level IEs and header class below. New
node/session-set messages use raw IEs when no typed value model exists; their
conditional groups and procedure state remain caller-owned. Typed convenience
builders cover the previously supported heartbeat/association/session subset.

| Procedure | Message types | Profile requirement |
|:---|:---|:---|
| Heartbeat | Request (1), Response (2) | Recovery Time Stamp decode/encode and correlation-friendly sequence preservation. |
| PFD Management | Request (3), Response (4) | Cause on response; request has no unconditional mandatory IE. |
| Association Update | Request (7), Response (8) | Node ID on both; Cause on response. |
| Version Not Supported | Response (11) | Header only. |
| Node Report | Request (12), Response (13) | Node ID on both; Node Report Type on request, Cause on response. |
| Session Set Deletion | Request (14), Response (15) | Node ID on both; Cause on response. |
| Session Set Modification | Request (16), Response (17) | Node ID on both; one or more Session Change Info on request, Cause on response. |
| Association Setup | Request (5), Response (6) | Node ID, Recovery Time Stamp, and Cause on response. |
| Association Release | Request (9), Response (10) | Node ID on both messages and Cause on response. |
| Session Establishment | Request (50), Response (51) | Node ID, request F-SEID and Create PDR/FAR groups; Cause and successful-response F-SEID; request rule references. |
| Session Modification | Request (52), Response (53) | Validate supplied rule groups; existing-rule references are resolved by the session owner. |
| Session Deletion | Request (54), Response (55) | SEID-bearing request/response validation and Cause on response. |
| Session Report | Request (56), Response (57) | Report Type, Usage Report groups, UR-SEQN, and Cause on response. |

### Profile-owned IE families

The named profile owns the IE families needed for N4 session-management
flows:

- Node and recovery IEs: Node ID, Recovery Time Stamp, Cause, Offending IE.
- Session identity IEs: F-SEID, SEID-bearing message header validation.
- Rule identity IEs: PDR ID, FAR ID, QER ID, URR ID, Remove PDR/FAR/QER/URR.
- Packet detection IEs: Create/Update PDR, PDI, Precedence, Source Interface,
  F-TEID, Network Instance, UE IP Address, QFI, Outer Header Removal.
- Forwarding IEs: Create/Update FAR, Forwarding Parameters, Apply Action,
  Destination Interface, Outer Header Creation.
- QoS IEs: Create/Update QER, Gate Status, MBR, GBR, QFI.
- Usage-reporting IEs: Create/Update URR, Measurement Method, Reporting
  Triggers, Volume/Time Threshold, Volume/Time Quota, Monitoring Time, Usage
  Report Trigger, Volume Measurement, Duration Measurement, UR-SEQN, Report
  Type, Usage Report.

### Required semantic validation

Profile-v1 validation must separate structural decode failures from semantic
profile failures and must cover at least these rules:

- Message header SEID presence must match the procedure class.
- Heartbeat messages must not require SEID and must preserve sequence numbers.
- Association Setup Request must include Node ID and Recovery Time Stamp.
- Association Setup Response must include Node ID, Recovery Time Stamp, and
  Cause. Offending IE is retained when present but is not required by the validator.
- Session Establishment Request must include Node ID, CP F-SEID and at least one Create
  PDR and Create FAR.
- Create PDR requires PDR ID, Precedence and PDI. Update PDR requires PDR ID;
  Precedence and PDI are optional changes.
- PDI requires Source Interface. Source-interface-only matching is valid.
  Traffic Endpoint ID excludes Local F-TEID, Local Ingress Tunnel, Network
  Instance and UE IP Address.
- Create FAR requires FAR ID and Apply Action; Update FAR requires FAR ID.
  Apply Action selects exactly one primary action (FSSM/MBSU count together),
  NOCP/BDPN require BUFF, and DFRT requires FORW. A forwarding action in
  Create FAR requires Forwarding Parameters with Destination Interface;
  Update FAR permits those unchanged parameters to be omitted.
- Establishment PDR references to FAR/QER/URR IDs must resolve in that message.
  Modification references may identify existing rules; the session owner must
  resolve them against stored state. Modification has no unconditional
  mandatory operation: parameter-only and empty requests are accepted.
- Session Deletion Request/Response must be SEID-bearing.
- Session Report Request must include Report Type and include Usage Report when
  the report type requires it.
- The current validator rejects duplicate singleton IEs unless the procedure
  permits multiplicity; its §7.6.10 receiver limitation is documented below.
- Unknown non-mandatory IEs must be preserved by the raw layer; unsupported or
  malformed profile-critical IEs must produce typed validation errors.

### Compatibility and API guarantees

- The raw `InformationElement` layer remains byte-preserving for unknown and
  vendor-specific IEs.
- The typed layer may canonicalize spare bits and discard future extension
  octets as documented below; callers needing byte-exact forwarding must use
  the raw layer.
- Builder APIs added for this profile must not construct messages missing
  mandatory profile-owned IEs.
- Semantic validation APIs must be additive and stable under semver if this
  profile is later graduated.

### Explicit non-goals

- PFCP UDP transport, retransmission timers, peer liveness management, and
  request/response transaction orchestration.
- SMF/UPF business logic, node selection, rule persistence, charging policy,
  traffic steering policy, or product-specific admission decisions.
- PFD Management, Subscriber Management, and non-N4/Sxa/Sxb procedures outside
  the profile-owned list.
- Full typed coverage for every TS 29.244 IE outside the session-management
  profile.

The PFD Management message envelope is decoded and validated, but the codec
does not implement PFD storage or the full management procedure.

## Supported Features

### 1. Message Header (§7.2.2)
- Version 1 parsing and validation.
- Octet-1 flag layout per §7.2.2.1: bits 8–6 version, bits 5–4 spare,
  bit 3 FO, bit 2 MP, bit 1 S — asserted against hand-authored spec bytes
  in the test suite (not merely against this codec's own encoder).
- S-flag (SEID presence).
- MP flag: message priority carried in the high nibble of the final
  header octet, preserved byte-exact across decode → encode.
- FO is accepted at every validation level and exposed as `Header.fo`.
- Sequence number (24-bit).
- Received header spare bits are ignored at all levels and cleared on encode.
- The header Length field is honored: the message ends `4 + Length`
  octets in; shorter input is rejected as truncated, a Length smaller
  than the header's own SEID/sequence octets is rejected as structural,
  and trailing bytes are returned to the caller as the unconsumed
  remainder (also exposed as `Message::tail`).

### 2. Generic IE TLV Layer (§8.1.1)
- Type/Length framing for standard IEs (type < 32768).
- Vendor-specific IEs (type ≥ 32768): the Length field includes the
  2-octet Enterprise ID per §8.1.1; lengths < 2 are rejected.
- Unknown IEs are always preserved byte-exact in the raw
  `InformationElement` layer. The typed sequence boundary applies
  `UnknownIePolicy`: `Drop` omits them, `Preserve` retains `TypedIe::Raw` in
  wire order, and `Reject` returns `UnknownCriticalIe`, recursively through
  grouped IEs. Assigned but unmodelled types are preserved raw under every
  policy. `IE_DEFINITIONS` contains all 400 assigned R19 types; reserved/spare
  codes remain unknown. `tools/generate-ie-registry.py` regenerates it from
  the standard PDF converted by `pdftotext -layout`; `--check` verifies it.
- Truncated TLV rejection (header and value).
- Overflow length rejection.

### 3. Messages
- Heartbeat Request (1) / Response (2)
- PFD Management (3/4), Association Update (7/8), Version Not Supported (11),
  Node Report (12/13), Session Set Deletion (14/15), Session Set Modification (16/17)
- Association Setup Request (5) / Response (6)
- Association Release Request (9) / Response (10)
- Session Establishment Request (50) / Response (51)
- Session Modification Request (52) / Response (53)
- Session Deletion Request (54) / Response (55)
- Session Report Request (56) / Response (57)

### 4. Typed Simple IEs (§8.2)
All decode/encode round-trips are verified with hand-authored spec-byte
fixtures citing section numbers. No panics on hostile input: checked
arithmetic, truncation/overflow rejection, and negative tests.

| IE | Type | Section | Notes |
|:---|:---|:---|:---|
| Cause | 19 | §8.2.1 | V19.6.0 registry, `Unknown(u8)` fallback, acceptance/rejection classification; typed encoding rejects reserved zero. |
| Node ID | 60 | §8.2.38 | IPv4/IPv6/FQDN; IP addresses require their known width and ignore trailing extensions. |
| F-SEID | 57 | §8.2.37 | V4/V6 flags, SEID (8 octets), address order. |
| F-TEID | 21 | §8.2.3 | V4/V6/CH/CHID flags; CH omits TEID and addresses; conditional Choose ID. |
| PDR ID | 56 | §8.2.36 | 2 octets. |
| FAR ID | 108 | §8.2.74 | 4 octets. |
| QER ID | 109 | §8.2.75 | 4 octets. |
| URR ID | 81 | §8.2.54 | 4 octets. |
| Precedence | 29 | §8.2.11 | 4 octets. |
| Apply Action | 44 | §8.2.26 | Accepts the original one-octet form (Table 8.1.2-1); missing later flags are zero. Encodes two octets, including FSSM/MBSU. |
| Source Interface | 20 | §8.2.2 | 1 octet; spare nibble preserved. |
| Destination Interface | 42 | §8.2.24 | 1 octet; spare nibble preserved. |
| Network Instance | 22 | §8.2.4 | Variable-length DNN octet string. |
| UE IP Address | 93 | §8.2.62 | V6/V4/SD/IPv6D/CHV4/CHV6/IP6PL flags; IPv6 delegation and prefix length. Requires an address family or CHOOSE request. |
| Outer Header Creation | 84 | §8.2.56 | 16-bit description (octet 5 = high byte); TEID iff GTP-U (octet 5 bits 1-2), UDP port iff non-GTP UDP (bits 3-4), addresses per bits 1/3/5 and 2/4/6; C-TAG/S-TAG. |
| Outer Header Removal | 95 | §8.2.64 | 1 octet description. |
| User Plane Inactivity Timer | 117 | §8.2.83 | Four-octet inactivity duration in seconds. |
| Recovery Time Stamp | 96 | §8.2.65 | 4 octets, NTP short-format seconds (RFC 5905, 1900 era), carried opaquely. |
| QoS Flow Identifier (QFI) | 124 | §8.2.89 | 1 octet; 6-bit QFI value, spare high bits emitted as zero. |
| Remove PDR | 15 | §7.5.4.6 | 2 octets; wraps PDR ID. |
| Remove FAR | 16 | §7.5.4.7 | 4 octets; wraps FAR ID. |
| Remove URR | 17 | §7.5.4.8 | 4 octets; wraps URR ID. |
| Remove QER | 18 | §7.5.4.9 | 4 octets; wraps QER ID. |
| Volume Threshold | 31 | §8.2.13 | 1 flag octet + optional Total/Uplink/Downlink 8-octet volumes. |
| Time Threshold | 32 | §8.2.14 | 4 octets; duration in seconds. |
| Monitoring Time | 33 | §8.2.15 | 4 octets; NTP short-format seconds. |
| Reporting Triggers | 37 | §8.2.19 | 3 octets; bits 3-8 of octet 7 emitted as zero. |
| Report Type | 39 | §8.2.21 | 1 octet; bit 8 spare emitted as zero. |
| Offending IE | 40 | §8.2.22 | 2 octets; offending IE type. |
| Gate Status | 25 | §8.2.7 | 1 octet; UL gate (bits 2-1), DL gate (bits 4-3). Open=0, Closed=1. |
| Maximum Bit Rate (MBR) | 26 | §8.2.8 | 10 octets; UL/DL 40-bit rates in kbps (binary). |
| Guaranteed Bit Rate (GBR) | 27 | §8.2.9 | 10 octets; UL/DL 40-bit rates in kbps (binary). |
| Measurement Method | 62 | §8.2.40 | 1 octet; bits 8-4 spare emitted as zero. |
| Usage Report Trigger | 63 | §8.2.41 | 3 octets; bits 7-8 of octet 7 emitted as zero. |
| Volume Measurement | 66 | §8.2.44 | 1 flag octet + optional volume/packet 8-octet counters. |
| Duration Measurement | 67 | §8.2.45 | 4 octets; duration in seconds. |
| Volume Quota | 73 | §8.2.50 | 1 flag octet + optional Total/Uplink/Downlink 8-octet volumes. |
| Time Quota | 74 | §8.2.51 | 4 octets; duration in seconds. |
| UR-SEQN | 104 | §8.2.71 | 4 octets; usage report sequence number. |

#### Canonicalizing re-encode

The typed layer canonicalizes on re-encode: spare flag bits that the spec
requires to be zero are emitted as zero, and trailing octets beyond the
fields this release knows (which §8.1.2 forward compatibility requires a
receiver to ignore) are dropped rather than preserved. A typed decode →
encode round-trip is therefore byte-exact for spec-canonical messages —
which is what every fixture in the test suite asserts — but not for
messages carrying non-zero spare bits or future extension octets. Use the
raw `InformationElement` layer when byte-exact forwarding of arbitrary
peer traffic is required. Filtering a typed view with `Drop` does not mutate
the raw IEs retained by an enclosing message and is therefore not a sanitized
raw-preserving re-encode.

Apply Action combination rules belong to `validate_production_v1`, above the
typed bit-field codec: one primary action (FSSM/MBSU together count as one),
NOCP/BDPN only with BUFF, and DFRT only with FORW. A typed decode or encode
alone does not establish that a FAR is semantically valid. Source Interface,
Destination Interface and Apply Action retain received spare fields for
inspection but always clear them on typed encode, including when
`EncodeContext::raw_preserving` is set.

Create FAR with FORW requires Forwarding Parameters and Destination Interface.
Update FAR validates supplied members and action flags without requiring those
unchanged parameters to be repeated (§5.6.3, Tables 7.5.4.3-1 and 7.5.4.3-2).

The profile currently rejects semantically invalid optional typed IEs, including
PDI F-TEID and UE IP Address, as `TypedDecode` errors. It does not implement the
§7.6.8 rule to discard such an optional IE and continue. Its singleton checks
also reject duplicate IEs under every context instead of applying §7.6.10
first-occurrence handling. Version Not Supported Response currently requires
version 1 and an empty body; accepting a peer's other version (§7.4.4.7) and
discarding unexpected body IEs (§7.6.9) remain receiver limitations.

### 5. Typed Grouped IEs (§7.5.2)
Grouped IEs decode their members recursively as `TypedIe`, enforcing
`DecodeContext::max_depth` to prevent unbounded recursion on hostile
input. Byte-exact round-trip verified for all listed grouped IEs.

| IE | Type | Section | Member decode |
|:---|:---|:---|:---|
| Create PDR | 1 | §7.5.2.2-1 | Typed members with depth limit. |
| PDI | 2 | §7.5.2.2-2 | Typed members with depth limit. |
| Create FAR | 3 | §7.5.2.3-1 | Typed members with depth limit. |
| Forwarding Parameters | 4 | §7.5.2.3-2 | Typed members with depth limit. |
| Create URR | 6 | §7.5.2.4-1 | Typed members with depth limit. |
| Create QER | 7 | §7.5.2.5-1 | Typed members with depth limit. |
| Update PDR | 9 | §7.5.4.2-1 | Typed members with depth limit. |
| Update FAR | 10 | §7.5.4.3-1 | Typed members with depth limit. |
| Update Forwarding Parameters | 11 | §7.5.4.3-2 | Typed members with depth limit. |
| Update URR | 13 | §7.5.4.4 | Typed members with depth limit. |
| Update QER | 14 | §7.5.4.5 | Typed members with depth limit. |
| Created PDR | 8 | §7.5.3.2-1 | Typed members with depth limit. |
| Usage Report (Session Report Request) | 80 | §7.5.8.3-1 | Typed members with depth limit. |

## Robustness & Fuzzing

Decode paths carry no `unsafe`, use checked length arithmetic, and never
preallocate from a wire-declared length. Three layers guard them:

- **Per-PR regression guard** — `tests/corpus_replay.rs` replays every committed
  corpus entry, byte-truncations of each, and hostile constant inputs through the
  decode entry points (`Message::decode`, `OwnedMessage::decode_owned`, and
  depth-limited typed-IE decode) at the Structural and Strict validation levels,
  under `catch_unwind`. Runs in ordinary `cargo test`; no nightly toolchain or
  libFuzzer required.
- **Scheduled fuzzing** — `fuzz/fuzz_targets/decode_message.rs` with a seeded
  corpus, registered in `.github/workflows/fuzz.yml` and run weekly.
- **Verification** — a deep `cargo-fuzz` pass over the decoder completed ~41M
  executions with no crash, leak, or OOM.

## Production Profile v1 Evidence

- Profile-level builder APIs cover Heartbeat, Association Setup/Release,
  Session Establishment/Modification/Deletion, and Session Report messages.
- `validate_production_v1` enforces the semantic rules above without requiring
  callers to manually inspect raw IEs.
- Unit tests cover the profile builders and validation failures for rule-graph,
  duplicate-singleton, and Session Report mandatory-IE errors.
- `tests/production_profile_v1.rs` shows typed construction, validation,
  encode, decode, and decoded-message revalidation without manual raw IE
  construction.
- `examples/production_profile_v1.rs` is the runnable profile-v1 integration
  example for downstream SDK users.

## Remaining Graduation Boundary

The profile is not currently production-approved. Graduation requires fixing
encoder capacity and header/length invariants, scoping declared-PDU limits to
the decoded message rather than unrelated tail bytes, and adding independent N4
fixture/peer evidence. The following also remain outside the candidate boundary
unless a future profile explicitly adds them.

## Codec Boundary (v1+)

- Remaining simple IEs not listed above (e.g., Packet Rate, DL Flow Level
  Marking, SDF Filter, Application ID, Traffic Endpoint, BAR, MAR,
  Subsequent Volume/Time Threshold/Quota, Event Quota/Threshold, etc.).
- Session-Report-specific Usage Report semantics beyond member decode
  (e.g., Start/End Time, Application Detection Information).
- Full message-specific semantic validation (e.g., mandatory-IE presence).
- PFD Management, Subscriber Management, and other non-SMF/UPF messages.

### Compliance migration and bundle handling (#1359, #1516, #1518–#1525)

`session_establishment_request` now requires the sending Node ID after `seid`.
Association release builders require Node ID after `seq`.
`session_establishment_response` requires Node ID and `Option<FSeid>` after
`seid`; successful responses require `Some`. These changes prevent convenience
builders from constructing messages missing mandatory identity information.
`ApplyAction` literals gain `fssm` and `mbsu`; `spare` now describes only octet 6
bits 6–8. Exhaustive matches must account for new `MessageType` variants,
`TypedIe::UserPlaneInactivityTimer` and `ProfileValidationError::InvalidCombination`.
The legacy `MissingOperation`/`MissingTrafficMatch` variants are no longer emitted.

To walk a bundled datagram, call `Message::decode` on the remaining slice.
Its returned remainder begins at `4 + header.length`. Continue when `header.fo`
is true, requiring another complete message; the final message has FO false
and must exhaust the datagram. Use the returned remainder, not an inferred IE
boundary. `tests/spec_receivers.rs` exercises two independent heartbeat wire
images, mandatory-IE removal, SEID class, extension policies and action flags.
Header encoders retain FO and clear spare bits, including the final spare octet.

The registry supplies each typed IE error's defining subclause/table. Table
8.1.2-1 has typographical errors for IE 55–57 and 299; the generator verifies
and uses their actual clause headings (8.2.35–37 and 8.2.205).
