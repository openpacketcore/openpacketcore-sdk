# ADR 0013: NGAP ASN.1 Strategy

## Status

Accepted — amended 2026-06 with first implementation experience and 2026-09 with bounded container framing

## Date

2026-06-11

## Context

NGAP (NG Application Protocol, 3GPP TS 38.413) is required for gNodeB↔AMF and
AMF↔SMF signaling. Unlike GTP-U (fixed binary headers) or PFCP (TLV IEs), NGAP
is defined in ASN.1 using APER (Aligned Packed Encoding Rules). Hand-writing an
APER codec is error-prone, high-maintenance, and incompatible with the SDK's
goal of spec-traceable, fuzz-safe protocol code.

The SDK currently has:
- `opc-protocol` — zero-copy codec framework with `BorrowDecode`/`Encode`
- `opc-proto-gtpu` — GTP-U codec following the above framework
- `opc-proto-pfcp` — PFCP codec (planned, TS 29.244)

NGAP is the next mandatory codec after PFCP, but its ASN.1 nature makes it
structurally different from the existing binary codecs.

## Decision

We will **not** hand-write general NGAP ASN.1 parsing or code-generation.
The bounded root-container exception below covers proven runtime framing
defects; nested ASN.1 schema types remain generated.

Instead, we will evaluate and adopt a maintained Rust ASN.1 / APER toolchain
that can consume the 3GPP ASN.1 modules directly. The evaluation criteria are:

1. **MSRV 1.81 compatibility** — must compile on the SDK's declared MSRV.
2. **License compatibility** — Apache-2.0 or MIT, no copyleft dependencies.
3. **`#![forbid(unsafe_code)]`** — generated and runtime code must be pure safe Rust.
4. **Fuzzability** — the generated codec must integrate with `cargo-fuzz` and
   tolerate hostile inputs without panics.
5. **Maintenance risk** — actively maintained, responsive to security issues,
   ideally with existing 3GPP or telecom user base.

## Options Evaluated

### Option A: `hampi` / `rasn` ecosystem

- **hampi** (GitHub: `repnop/hampi`) — ASN.1 compiler generating Rust structs
  with APER/UPER/OER support.
- **rasn** (GitHub: `XAMPPRocky/rasn`) — runtime ASN.1 codec library with
  derive macros.

**Pros:** Pure Rust, `no_std` capable, active development, Apache-2.0.
**Cons:** hampi's APER support is partial (v0.x); no proven 3GPP NGAP corpus
  yet; smaller community than protobuf alternatives.
**Verdict:** Leading candidate. Requires a spike to compile 3GPP R18 NGAP ASN.1
  modules and validate against known-good PCAPs.

### Option B: Generated code from `asn1-codecs` (ERI framework)

The `asn1-codecs` family (used by some telecom OSS projects) generates Rust
from ASN.1 via an intermediate representation.

**Pros:** Explicitly designed for telecom ASN.1 modules.
**Cons:** Mixed maintenance status; some forks carry unsafe code; licensing
  unclear on some forks; heavy dependency tree.
**Verdict:** Fallback if Option A fails the spike. Requires legal review of
  upstream license before adoption.

### Option C: FFI to `srsRAN` / `OAI` C NGAP codec

Reuse the established C NGAP implementations from srsRAN or OpenAirInterface.

**Pros:** Battle-tested against live networks; spec-complete.
**Cons:** FFI requires `unsafe` blocks, violating the SDK's `#![forbid(unsafe_code)]`
  invariant. Cross-compilation for musl/target environments adds complexity.
  Memory-safety bugs in C code become SDK security issues.
**Verdict:** Rejected. The `forbid(unsafe_code)` constraint is architectural and
  non-negotiable for a carrier-grade CNF security substrate.

### Option D: Hand-written subset

Implement only NGSetupRequest/Response and InitialUEMessage by hand and omit the
rest.

**Pros:** Zero new dependencies; full control over decode limits and fuzzing.
**Cons:** Maintenance nightmare on every 3GPP release; no spec-traceability to
  ASN.1 modules; high bug rate.
**Verdict:** Rejected. The SDK explicitly rejected hand-written ASN.1 for NGAP
  at the architecture level.

## Recommendation

**Proceed with Option A (`hampi`/`rasn`).**

Phased plan:

1. **Spike (v0.2.x follow-up):** Compile 3GPP R18 NGAP ASN.1 modules with
   `hampi`/`rasn`, generate structs, and validate against a small corpus of
   known-good NGAP PDUs (extracted from 3GPP test specifications or
   `opc-testbed` fixtures).
2. **Subset crate (v0.3.0):** Create `opc-proto-ngap` wrapping only
   `NGSetupRequest/Response` and `InitialUEMessage` to prove the integration
   pattern with `opc-protocol`'s decode-context limits.
3. **Full message surface (v0.4.0+):** Expand to the full NGAP message and IE
   surface required by the AMF-lite reference implementation.

## Consequences

- The SDK gains a maintainable, spec-traceable NGAP codec path.
- Downstream NF operators must accept a generated-code dependency (acceptable
  given the alternative of FFI or hand-written bugs).
- If `hampi`/`rasn` fails the spike, we fall back to Option B with a license
  review gate.

## Implementation experience (2026-06)

The first `opc-proto-ngap` attempt followed the phased plan and stalled at
step 1 on toolchain compatibility, not on the codec approach itself:

- **`rasn` (0.22 and 0.25) failed the then-declared MSRV of 1.81.** Its
  derive implementation transitively requires `uuid ^1.11`, which resolves
  to a `getrandom` release whose manifest uses `edition2024` — unparseable
  by Cargo 1.81. No pinning escape existed within `rasn`'s requirements.
- Investigating the failure exposed that the **workspace's own dependency
  graph had already drifted past MSRV 1.81** through the same `getrandom`
  release (reached via `uuid`, `tempfile`, and `quickcheck`), i.e. the MSRV
  declaration no longer reflected reality independent of NGAP.
- **`hampi` was not pursued**: no meaningful release since 2021 and its APER
  encoder was still marked work-in-progress then — unacceptable abandonment
  risk for a protocol codec.

Consequences acted on:

- The workspace MSRV was raised to **1.88**, the actual floor of the
  resolved dependency graph (set by `time`; `edition2024` support needs
  ≥ 1.85, the `icu` stack ≥ 1.86). This repairs the MSRV gate and removes
  the blocker on Option A. See ADR 0014 for the toolchain/dependency policy.
- The Option A spike should be re-run against `rasn` on the raised MSRV before
  any consideration of Option B (`asn1-codecs`, which still carries its
  license-review gate per the comparison above).

## Bounded container framing amendment (2026-09)

Independent Release 18 message bytes demonstrate a `rasn` 0.28 generated
inner-container encoder alignment defect. A separate 54-case Pycrate oracle
also exposes the runtime decoder's handling of fragmented open types: it
misreports the final determinant/remainder and can consume following fields.

The SDK may explicitly frame the three root NGAP-PDU choices and their
ProtocolIE-Containers. The exception is limited to aligned fixed headers,
16-bit IE counts, open-type length determinants and fragmentation. Generated
types still define the message/IE representation and decode fixed IE headers;
the existing procedure-specific policy tables remain authoritative. Nested IE
values stay opaque at this boundary. Fragmented SEQUENCE extension additions
are outside the implemented root-container subset.

Canonical SDK encoding writes the typed container, preserves its order and
opaque values, and normalizes container padding and length determinants. It
does not implement ASN.1 CANONICAL-PER or semantic N3IWF send admission.
Raw-preserving encoding remains available for exact forwarding. Decoder limits
and structural/strict, unknown-IE and duplicate policies continue to apply.
Construction and output bounds precede payload allocation or destination writes.

The exception requires independent bytes/digests, malformed-fragment tests,
fuzz coverage, and an explicit conformance boundary. The broader generated
schema strategy and experimental maturity are unchanged. Evidence is linked
from `crates/opc-proto-ngap/CONFORMANCE.md`; Refs #787.

## Bounded N3IWF field amendment (2026-09)

Independent Release 18 field vectors additionally reveal a generated TAI
receive alignment defect (three-octet PLMN after SEQUENCE flags) and a
without-port location CHOICE extension-container encode alignment defect.
The field layer may explicitly read the fixed admitted TAI/location layouts
and frame the known choice extension 439. It rejects unimplemented SEQUENCE
additions and nested extensions before collection decoding; it does not become
a general handwritten ASN.1 decoder. Independently qualified generated
encoders still encode the inner structures and the bounded UE identifiers.
NAS OCTET STRING reuses the container length/fragment scanner. Security Key
is a borrowed fixed 256-bit view; its encoded buffer is cleared on drop.

The original generic PDU policy remains unchanged. New individual field APIs
have explicit narrower extension admission and field-local limits. The field
oracle, complete uplink-message comparison, mutation tests and fuzz target
qualify this exception; broader procedure admission remains open under #787.

## Optional NAS message admission amendment (2026-09)

An opt-in typed boundary validates the filtered generic PDU for Initial UE,
Downlink NAS and Uplink NAS. It enforces their mandatory fields, admits a
documented optional subset, and applies TS 29.413 receiver-ignore rules.
Other recognized fields fail explicitly until their applicable codecs exist.
Unknown-notify identifiers become caller-owned diagnostics; the generic
decoder's preservation, duplicate selection and raw image remain unchanged.

Construction and receive use the same field admission. Generated codecs handle
the bounded establishment cause, context-request and AMBR fields; no further
manual ASN.1 exception is introduced. Complete independent Release 18 bytes,
missing-field and policy cases, mutation detectors and fuzzing qualify this
subset. The API does not authorize procedure triggers or perform association,
identifier binding, NAS security/delivery or backend effects.

## UE release admission amendment (2026-09)

The same opt-in boundary extends to UE Context Release Command and Complete.
Independent Release 18 fields and complete messages qualify generated codecs
for both UE identifier choices and all standard root Cause values. Fixed flags
reject unsupported choice/SEQUENCE extensions before collection decoding; this
does not add a handwritten ASN.1 encoder or a general decoder. Other applicable
optional fields fail until qualified codecs exist. The boundary returns fields
and diagnostics without releasing resources or acknowledging a procedure.

## Evidence

- Gap register updated: `GAP-PROTO-003` now records the partially closed codec
  boundary.
- `docs/implementation-status.md` linked.

## Bounded NG Setup field amendment (2026-09)

Independent Release 18 vectors extend the fixed-octet receive defect to Global
N3IWF ID, served GUAMIs, supported TAs and PLMN/slice lists. In addition, the
`rasn` 0.28 SEQUENCE OF encoder loses the parent bit offset: even one PLMN with
one slice differs from the independently compiled reference. The field layer
may explicitly read these root shapes and write the two PLMN/slice list shapes.
It bounds counts before each allocation, rejects every unsupported extension,
requires zero padding, and preflights exact encoded size. Generated encoders
remain in use for global identity, served GUAMIs, AMF name, capacity and timers.
This exception does not authorize a general handwritten ASN.1 implementation.

All three setup outcomes admit mandatory fields and a documented optional
subset. Mandatory DRX is supplied explicitly for construction; receive checks
presence and ignores its payload as TS 29.413 requires. Independent field and
complete-message bytes, mutation detectors, maximum-count tests and fuzzing
qualify the exception. Association state, selection and configuration effects
remain caller-owned, and #787 remains incomplete beyond the admitted subset.

## Initial-context individual-field amendment (2026-09)

Standalone GUAMI reuses the qualified generated encoder and bounded PLMN
reader. Independently compiled Allowed NSSAI bytes demonstrate the same
generated nested-list defect: one slice with SD 010203 must encode as
`02 01 01 02 03`, which the generated encoder does not produce. The bounded
root list reader/writer may cover Allowed NSSAI with shared S-NSSAI values,
1–8 elements, exact sizing, extension rejection and allocation preflight.
The existing NG Setup list codecs share only their qualified internal root
helpers; their independent vectors continue to apply.

Generated UE Security Capabilities construction is qualified against every
mask bit. TS 29.413 specifies receiver-ignore semantics for its contents;
no receive codec or algorithm selection is added. The 98 independent fields
do not establish Initial Context Setup or resource-transfer admission.

## Non-GBR setup-request transfer amendment (2026-09)

Independent constructor and typed-value probes qualify the generated GTP
tunnel codec for IPv4/IPv6 and TEID boundaries. The same probes show generated
QoS setup-list construction differs even for one standardized non-GBR 5QI 9
flow; most generated receive values differ too. The bounded root reader/writer
may cover only this proven list shape, with 1–64 unique QFIs, root ARP values,
exact sizing, physical count preflight and rejection of all other choices,
optional fields and extensions. Independent vectors cover every root length,
QFI, ARP priority and flag combination. Other QoS profiles remain unsupported.

Nested request transfers reuse the existing fragment framing and IE policy
implementation, with independently compiled Release 18 metadata. They require
the conditional AMBR for admitted non-GBR flows and return identifier-only
unknown-notify diagnostics. Uplink and downlink transport have separate public
types; session AMBR remains distinct from UE AMBR while reusing the qualified
identical wire layout. This adds no session/tunnel effect or enclosing-message
admission, and does not authorize a general handwritten ASN.1 codec.

## Setup-result transfer amendment (2026-09)

Independent Release 18 probes qualify generated unsuccessful-transfer
construction and typed receive for every root Cause (128 comparisons). Keep
that generated codec, with explicit fixed-shape preflight because generated
receive does not reject final nonzero padding.

The generated response-transfer codec fails 196 of 198 independent constructor
and typed-value probes, including its nested transport/list layout. Extend the
bounded root helper exception only to one IPv4/IPv6 downlink transport with
1–64 accepted QFIs and optional failed QFIs/root Causes. Preflight exact output
size, cumulative input counts and physical input; reject duplicates, overlap,
unsupported optionals, extensions, padding and trailing bytes. The independent
547-case oracle covers all root Causes at all four first-failure offsets, every
accepted-list size and partial-result split. Reuse shared Cause values and
distinct downlink transport, without adding general ASN.1 behavior or any
resource/procedure side effect. Outer session-list admission is qualified below.

## Session setup-list amendment (2026-09)

Retain generated construction and receive for the five successful/failed list
roots after physical count, flag, length, duplicate and padding preflight.
Thirty-six of 93 generated receive probes fail, all in the two request-list
roots with aligned SD or fragmented fields. The bounded reader exception covers
those request layouts using qualified S-NSSAI and open-type helpers.

Fuzzing found a generated request encoder defect masked by the original repeating
NAS ramp: a one-byte mutation in the fragmented remainder was lost on reencoding.
Strengthened independent vectors use distinct SHA-256-derived synthetic blocks
and cover both sides of every 16K boundary through 65,537 bytes. They expose
16 generated encode failures, including two retained unknown-transfer fragments.
The request writer may compose existing S-NSSAI and fragment helpers after exact
size preflight. Preserve ordinary NAS borrowing, nested caller policies, unique
session IDs and disjoint partial results. The 102-case reference corpus and the
original fuzz reproducer guard this bounded exception; no general ASN.1 codec
is introduced.

The reference generator uses unmodified Pycrate structured decoding because its
plain fragment decoder advances the final remainder's alignment offset in
octets instead of bits. Both independent encoder modes must agree, and the
structured decoder must reproduce the source values and bytes. Keep this
reference-tool limitation visible; successful round trips alone do not prove
live interoperability. Enclosing procedure admission is qualified separately below.

## Context and session setup message amendment (2026-09)

Compose the qualified fields and nested lists into all three Initial Context
Setup outcomes and both PDU Session Resource Setup outcomes. Keep container
policies authoritative and pass them through nested admission with remaining
depth. Require conditional UE AMBR when context resources are requested;
require a nonempty overall PDU setup result while permitting context-only
success. Partial result lists remain disjoint.

TS 29.413 requires capability contents to be receiver-ignored but retains the
mandatory IE. Construction therefore takes explicit capability masks instead
of replaying unvalidated input. Keep the complete receiver-ignore allowlist
explicit, including its non-trusted-access exceptions: UE AMBR applies and
Trace Activation must fail until supported. Other applicable unimplemented
IEs also fail explicitly. The 122 independent complete-message vectors qualify
this composition; no additional generated-code workaround is needed. Bounded
fuzz/replay compares every admitted field, including synthetic NAS/key bytes
without rendering them. Admission establishes neither request correlation nor
resource effects, and does not enable local procedure triggers.

## Resource release amendment (2026-09)

Retain generated construction and receive for release command/response
transfers and their two session-list roots. All 1,154 independent encode/decode
comparisons pass across every root Cause and list length. Reuse the qualified
result-list and root-Cause preflight helpers to reject duplicate session IDs,
unbounded counts, extensions, malformed nested lengths, trailing bytes and
nonzero padding before materialization. Exact list size precedes encoding
allocation. No new handwritten ASN.1 codec is justified or introduced.

Compose the mandatory AMF/RAN IDs and nonempty lists into Release Command and
Response, with optional opaque NAS and N3IWF location. Ignore RAN Paging Priority
contents under TS 29.413 while retaining generic criticality/cardinality checks;
fail on recognized applicable unsupported fields. These APIs validate a peer's
request or report, and do not correlate transactions or perform resource cleanup.

## UE request and Cause framing amendment (2026-09)

Retain generated codecs for the context-release session list after 512
independent constructor/typed-receive comparisons covering every root count.
Preflight physical counts, unique IDs, flags and padding before allocation;
use exact output sizing. Compose both UE request procedures from qualified
AMF/RAN IDs, root Cause, opaque NAS and the optional session list. Independent
Release 18 metadata supplies the new container registrations and IE policies;
291 complete-message vectors qualify presence, policy and fragment behavior.

The generated root Cause decoder ignores unused final bits. Preserve generated
value decoding but require exact root length and zero final padding first.
The regression fails before this check and after its removal; all 64 valid
Causes and 297 individual padding mutations qualify the check. This tightens
malformed input handling across existing procedures. No new handwritten ASN.1
codec is justified. Context ownership, delivery state, procedure triggers and
resource release remain caller-owned.

## Reset and Error Indication amendment (2026-09)

Independent Release 18 probes demonstrate failure for all 366 generated
connection-list encode/decode cases, all 366 partial Reset cases, and 304/360
Diagnostics encode and 256/360 decode cases. Retain generated Reset All, whose
independent case passes. Use explicit bounded root layouts only for the failed
shapes, preserving parent bit offsets and unconstrained element-count
fragmentation at the connection-list upper bound of 65,536. Validate complete
physical framing, counts, flags, integer minimality and padding before vector
allocation; measure exact output size before allocating the zeroized buffer.
Schema and dependencies remain unchanged.

The oracle's unmodified structured encoder/decoder supplies 1,093 field cases
and 189 messages. Its plain SEQUENCE OF fragment encoder calls a missing
`encode_pas`; record that limitation and compare both encoders where the plain
path works. Do not modify the reference package or use SDK output as an oracle.

Expose optional connection IDs without inventing uniqueness. Preserve legal
empty items and order, expose a filtered receiver view, and never promote an
all-empty partial list into Reset All. Require caller-supplied signalling
context, Error Indication's Cause/diagnostics basis and conditional UE IDs.
Restrict diagnostic IE criticality to reject/notify and reject Error-only
diagnostic header fields in Reset Acknowledge. These checks qualify fields;
the caller still owns correlation, trigger selection, acknowledgement timing
and resource effects.

## PDU Session Resource Notify amendment (2026-09)

Independent Release 18 probes qualify all 388 generated Notify-transfer
encodings, but 387 nonempty generated decodes fail. The sole successful decode
is an empty ASN.1 root without a report. Use a bounded explicit receiver only
for that nested transfer, preserving generated encoding. Generated released
transfers pass all 64 cases and both session-list roots pass all 262/257 cases
in both directions; retain these paths with physical preflight.

The independent oracle supplies 971 fields and 43 complete messages. Both
unmodified reference encoders agree and the structured decoder checks the
input values. Enforce complete root framing, zero padding, count/depth/byte
budgets and unique, disjoint identifiers before materializing output vectors.
Generated encoders receive an exact output-capacity check first. Reject
nonminimal contained-field length determinants: an initial regression accepted
the two-octet form for a short value, so this shared guard tightens existing
contained-field readers too. Schema and dependencies remain unchanged.

Expose root notification status, released QFI/Cause reports and whole-session
release reports without inferring resource state. Require at least one report
at each message/transfer boundary. Caller-owned state determines association,
session/QFI ownership and whether a notified QFI is an established GBR flow;
the codec does not choose triggers or perform cleanup. Extension reports need
separate independent qualification before admission.

## PDU Session Resource Modify field amendment (2026-09)

Independent root-field probes cover 687 cases. Generated request-list encoding
fails 253/383 and decoding fails 380/383 cases; response-list encoding passes
129/129 but decoding fails all; Cause-list encoding passes 130/130 while decoding
fails 129/130. Tunnel-pair list encoding/decoding fails all 45 cases. Retain
qualified generated response/Cause encoders and all 129 admitted identifier-only
request encodings. Use explicit layouts only for parameter-bearing requests,
tunnel-pair encoding and the failed receivers, preserving parent bit offsets.

Complete physical preflight precedes vector allocation. Exact output sizing
precedes generated-value materialization or zeroized buffer allocation. Both
unmodified reference encoders agree; structured reference decoding verifies
values. No schema, dependency or reference-package changes are needed.

Represent absent request parameters distinctly from standardized non-GBR 5QI 9
parameters. Preserve directional endpoint types and repeated tunnel pairs;
do not infer session state, defaults, bearer ownership or request correlation.
The new lists are standalone fields, not complete Modify transfer/procedure
admission. Additional profiles and optional fields require further qualification.


## Modify Request Transfer amendment (2026-09)

Independent Release 18 probes find 379/380 generated enclosing encode failures;
the empty root is the only match. Receiving matches 378/380 but fails both
fragmented unknown-IE cases. Reuse qualified bounded root-container framing
and the qualified Modify fields. A no-allocation scan validates every physical
IE before the entry vector; selected entries borrow original IE frames, so
unknown and discarded values need no fragment materialization. Minimal lengths,
zero padding, exact consumption and shared metadata/policies remain enforced.

The 380 independent cases include 363 admissions and 17 negatives. Both
unmodified reference encoders agree, and structured decode checks classifications.
Retain optional AMBR and empty roots: Modify may keep prior session limits,
and absent flow parameters supply no defaults. Cross-list QFI overlap fails
typed admission and construction; it does not itself send the abnormal-condition
response. Session correlation, conditional presence, NAS forwarding and resource
effects belong to the caller. No enclosing PDU outcome, schema or dependency
changes are introduced. Response/failure transfers and procedure admission
still need independent qualification.


## Modify result transfer amendment (2026-09)

The independent 1,436-case oracle covers response and unsuccessful transfer
roots, including optional response diagnostics. Probe 1,433 modeled roots:
empty response passes both directions; QFI-only responses encode 773/773 and
decode 0/773; tunnel responses encode 4/76 and decode 55/76. Cause-only failures
pass all 64 in both directions; diagnostic failures encode 149/519 and decode
284/519. Keep the generated no-tunnel response encoder, empty response decoder
and Cause-only failure codec. Use bounded explicit layouts for the failed shapes,
sharing internal transport, Cause and diagnostic helpers at their parent offsets.

Whole-transfer preflight precedes list materialization; exact sizing precedes
output allocation. Both unmodified reference encoders agree and structured
values/classifications are checked. No schema or dependency changes are needed.
Preserve empty responses and absent versus empty diagnostics. Reported QFI lists
are unique/disjoint; diagnostic repetitions stay intact. Same-procedure response
diagnostics reject procedure code/triggering outcome, and diagnostic item ignore
criticality remains inapplicable. Request correlation, conditional NAS forwarding,
resource effects and rollback belong to the caller; no NGAP PDU outcome is added.
