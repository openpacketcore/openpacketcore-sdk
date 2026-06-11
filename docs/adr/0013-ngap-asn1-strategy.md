# ADR 0013: NGAP ASN.1 Strategy

## Status

Accepted — amended 2026-06 with first implementation experience

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

We will **not** hand-write NGAP APER parsing or code-generation.

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

Implement only NGSetupRequest/Response and InitialUEMessage by hand, deferring
the rest.

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

## Evidence

- Gap register updated: `GAP-PROTO-003` (NGAP codec) status changed from
  `not-implemented` to `tracked-deferred`, target v0.3.0.
- `docs/implementation-status.md` linked.
