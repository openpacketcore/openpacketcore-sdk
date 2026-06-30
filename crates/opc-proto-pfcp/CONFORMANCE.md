# PFCP Protocol Conformance

This document defines the conformance of the `opc-proto-pfcp` crate against
3GPP TS 29.244.

## Specification Baseline

- **Document**: 3GPP TS 29.244
- **Release**: Release 18 (R18)
- **Status**: v3 — session-management codec subset complete and published;
  Production Profile v1 is implemented for the N4 codec and validation boundary
  defined below

## Production Profile v1 — N4 Codec and Validation

`opc-proto-pfcp` Production Profile v1 is intentionally a **codec and
validation profile** for SMF/UPF N4 integration. It includes typed construction,
decode, encode, and semantic validation for the profile-owned procedures below.
It does not claim to implement an SMF, UPF, PFCP transport stack, node
selection, local policy, charging, persistence, or high-availability
control-plane behavior.

### Profile-owned procedures

The production profile owns typed decode, encode, construction, and semantic
validation for these PFCP procedures:

| Procedure | Message types | Profile requirement |
|:---|:---|:---|
| Heartbeat | Request (1), Response (2) | Recovery Time Stamp decode/encode and correlation-friendly sequence preservation. |
| Association Setup | Request (5), Response (6) | Node ID, Recovery Time Stamp, Cause on response, and Offending IE on rejection paths. |
| Association Release | Request (9), Response (10) | Cause on response and graceful unsupported-IE handling. |
| Session Establishment | Request (50), Response (51) | F-SEID and Create PDR/FAR/QER/URR groups with cross-reference validation. |
| Session Modification | Request (52), Response (53) | Update/Remove/Create PDR/FAR/QER/URR groups with cross-reference validation. |
| Session Deletion | Request (54), Response (55) | SEID-bearing request/response validation and Cause on response. |
| Session Report | Request (56), Response (57) | Report Type, Usage Report groups, UR-SEQN, and Cause on response. |

### Profile-owned IE families

The production profile owns the IE families needed for N4 session-management
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
  Cause; rejection responses should expose Offending IE when present.
- Session Establishment Request must include CP F-SEID and at least one Create
  PDR and Create FAR.
- Create/Update PDR must include PDR ID, Precedence, and PDI.
- PDI must include Source Interface and at least one traffic-match primitive
  from the profile-owned packet-detection set.
- Create/Update FAR must include FAR ID and Apply Action; forwarding action
  must include Forwarding Parameters with Destination Interface.
- PDR references to FAR/QER/URR IDs must resolve to rule IDs present in the
  same message when those references create or update local rule graph state.
- Session Modification Request must contain at least one create/update/remove
  rule operation.
- Session Deletion Request/Response must be SEID-bearing.
- Session Report Request must include Report Type and include Usage Report when
  the report type requires it.
- Duplicate singleton IEs must be rejected by the semantic validator unless the
  TS 29.244 profile explicitly allows multiplicity.
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
- Semantic validation APIs must be additive and stable under semver once this
  profile is marked production-ready.

### Explicit non-goals

- PFCP UDP transport, retransmission timers, peer liveness management, and
  request/response transaction orchestration.
- SMF/UPF business logic, node selection, rule persistence, charging policy,
  traffic steering policy, or product-specific admission decisions.
- PFD Management, Subscriber Management, and non-N4/Sxa/Sxb procedures outside
  the profile-owned list.
- Full typed coverage for every TS 29.244 IE outside the session-management
  profile.

## Supported Features

### 1. Message Header (§7.4.1)
- Version 1 parsing and validation.
- Octet-1 flag layout per §7.4.1.1: bits 8–6 version, bits 5–4 spare,
  bit 3 FO, bit 2 MP, bit 1 S — asserted against hand-authored spec bytes
  in the test suite (not merely against this codec's own encoder).
- S-flag (SEID presence).
- MP flag: message priority carried in the high nibble of the final
  header octet, preserved byte-exact across decode → encode.
- FO flag parsing (rejected in strict mode, must be 0).
- Sequence number (24-bit).
- Spare bits validation (must be 0 in strict mode).
- The header Length field is honored: the message ends `4 + Length`
  octets in; shorter input is rejected as truncated, a Length smaller
  than the header's own SEID/sequence octets is rejected as structural,
  and trailing bytes are returned to the caller as the unconsumed
  remainder (also exposed as `Message::tail`).

### 2. Generic IE TLV Layer (§8.1.1)
- Type/Length framing for standard IEs (type < 32768).
- Vendor-specific IEs (type ≥ 32768): the Length field includes the
  2-octet Enterprise ID per §8.1.1; lengths < 2 are rejected.
- Unknown IEs preserved byte-exact for re-encode (raw-preserving
  round-trip), verified by byte-identity tests and a quickcheck property
  over arbitrary IE types and values.
- Truncated TLV rejection (header and value).
- Overflow length rejection.

### 3. Messages
- Heartbeat Request (1) / Response (2)
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
| Cause | 19 | §8.2.1 | Value registry with `Unknown(u8)` fallback. |
| Node ID | 60 | §8.2.38 | IPv4/IPv6/FQDN; length validated per type. |
| F-SEID | 57 | §8.2.40 | V4/V6 flags, SEID (8 octets), address order. |
| F-TEID | 21 | §8.2.5 | V4/V6/CH/CHID flags, TEID, Choose ID. |
| PDR ID | 56 | §8.2.36 | 2 octets. |
| FAR ID | 108 | §8.2.50 | 4 octets. |
| QER ID | 109 | §8.2.37 | 4 octets. |
| URR ID | 81 | §8.2.71 | 4 octets. |
| Precedence | 29 | §8.2.20 | 4 octets. |
| Apply Action | 44 | §8.2.26 | 2 octet flags (DROP, FORW, BUFF, …); spare bits preserved. |
| Source Interface | 20 | §8.2.2 | 1 octet; spare nibble preserved. |
| Destination Interface | 42 | §8.2.3 | 1 octet; spare nibble preserved. |
| Network Instance | 22 | §8.2.4 | Variable-length DNN octet string. |
| UE IP Address | 93 | §8.2.62 | V4/V6/SD/IPv4D/IPv6D/CHV4/CHV6/CH flags; prefix lengths. |
| Outer Header Creation | 84 | §8.2.56 | 16-bit description (octet 5 = high byte); TEID iff GTP-U (octet 5 bits 1-2), UDP port iff non-GTP UDP (bits 3-4), addresses per bits 1/3/5 and 2/4/6; C-TAG/S-TAG. |
| Outer Header Removal | 95 | §8.2.57 | 1 octet description. |
| Recovery Time Stamp | 96 | §8.2.69 | 4 octets, NTP short-format seconds (RFC 5905, 1900 era), carried opaquely. |
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
fields this release knows (which §8.1.1 forward compatibility requires a
receiver to ignore) are dropped rather than preserved. A typed decode →
encode round-trip is therefore byte-exact for spec-canonical messages —
which is what every fixture in the test suite asserts — but not for
messages carrying non-zero spare bits or future extension octets. Use the
raw `InformationElement` layer when byte-exact forwarding of arbitrary
peer traffic is required.

### 5. Typed Grouped IEs (§7.5.2)
Grouped IEs decode their members recursively as `TypedIe`, enforcing
`DecodeContext::max_depth` to prevent unbounded recursion on hostile
input. Byte-exact round-trip verified for all listed grouped IEs.

| IE | Type | Section | Member decode |
|:---|:---|:---|:---|
| Create PDR | 1 | §7.5.2.1 | Typed members with depth limit. |
| PDI | 2 | §7.5.2.2 | Typed members with depth limit. |
| Create FAR | 3 | §7.5.2.3 | Typed members with depth limit. |
| Forwarding Parameters | 4 | §7.5.2.2.1 | Typed members with depth limit. |
| Create URR | 6 | §7.5.2.5 | Typed members with depth limit. |
| Create QER | 7 | §7.5.2.4 | Typed members with depth limit. |
| Update PDR | 9 | §7.5.4.2 | Typed members with depth limit. |
| Update FAR | 10 | §7.5.4.3 | Typed members with depth limit. |
| Update Forwarding Parameters | 11 | §7.5.4.3-2 | Typed members with depth limit. |
| Update URR | 13 | §7.5.4.4 | Typed members with depth limit. |
| Update QER | 14 | §7.5.4.5 | Typed members with depth limit. |
| Created PDR | 8 | §7.5.2.6 | Typed members with depth limit. |
| Usage Report (Session Report Request) | 80 | §7.5.8.3 | Typed members with depth limit. |

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

## Remaining Production Boundary

The profile is production-ready only for the N4 codec and validation boundary
documented above. The following are outside the production claim unless a future
profile explicitly adds them.

## Codec Boundary (v1+)

- Remaining simple IEs not listed above (e.g., Packet Rate, DL Flow Level
  Marking, SDF Filter, Application ID, Traffic Endpoint, BAR, MAR,
  Subsequent Volume/Time Threshold/Quota, Event Quota/Threshold, etc.).
- Session-Report-specific Usage Report semantics beyond member decode
  (e.g., Start/End Time, Application Detection Information).
- Full message-specific semantic validation (e.g., mandatory-IE presence).
- PFD Management, Subscriber Management, and other non-SMF/UPF messages.
