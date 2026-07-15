# OPC-SDK-RFC-006: Conformance and Evidence Pipeline

**Status**: Draft for Implementation  
**Version**: 2.0.0  
**Date**: 2026-05-19  
**Audience**: release engineers, security engineers, standards reviewers, SDK implementers, NF teams

## 1. Abstract

This RFC defines the OpenPacketCore evidence pipeline: standards conformance
mapping, test evidence, SBOM generation, VEX, provenance, artifact signing,
performance baselines, known-gap management, and release gates.

The purpose is not to create marketing compliance claims. The purpose is to
produce machine-readable, signed evidence that states exactly what is
implemented, tested, partially implemented, not implemented, or intentionally
out of scope.

The initial draft correctly required conformance tags, SBOMs, signed bundles,
and performance baselines. This version expands those into a full evidence
system suitable for high-integrity carrier CNFs and parallel implementation.

## 2. Scope

### 2.1 In Scope

- Standards requirement inventory.
- Code-to-spec and test-to-spec mapping.
- Conformance status extraction.
- Known-gap registry.
- SBOM and VEX generation.
- Build provenance and artifact signing.
- Performance baseline capture.
- Evidence bundle format.
- Release and PR gates.

### 2.2 Out of Scope

- Legal certification by standards bodies.
- Operator-specific acceptance testing.
- Live-network certification.
- Runtime audit storage. See RFC 003.

## 3. Design Goals

### 3.1 Security

- Evidence must be tamper-evident and tied to artifact digests.
- Supply-chain metadata must include source, dependencies, build environment,
  container base images, and vulnerability status.
- Claims must be traceable to tests, source, and reviewed gaps.
- Signing keys or identities must be auditable.

### 3.2 Performance

- Evidence generation must be incremental for PR workflows.
- Full release evidence may be more expensive but must be reproducible.
- Performance baselines must record environment details so regressions are
  meaningful.

### 3.3 Maintainability

- Conformance tags must use a strict schema.
- Known gaps must be first-class records, not prose-only notes.
- Evidence tools must fail closed when claims are ambiguous.
- Output formats must be stable for downstream automation.

### 3.4 Functionality

- Produce human-readable and machine-readable reports.
- Support partial, full, not-implemented, not-applicable, and gap statuses.
- Attach tests and benchmark results to claims.
- Sign artifacts and attestations.
- Support release promotion gates.

## 4. Evidence Model

### 4.1 Claim Types

The evidence pipeline recognizes:

| Claim | Meaning |
| :--- | :--- |
| `implemented` | Code exists for the requirement |
| `tested` | Automated tests exercise the requirement |
| `partial` | Some required behavior is missing |
| `not-implemented` | No implementation exists |
| `not-applicable` | Requirement does not apply to this SDK/NF/profile |
| `gap` | Known missing behavior with owner and mitigation |
| `waived` | Temporary exception approved by policy |

No release may claim `full` conformance for a requirement unless it has both
`implemented` and `tested` evidence, plus no open blocking gap.

### 4.2 Requirement IDs

Every tracked requirement receives a stable ID:

```text
REQ-<source>-<document>-<release>-<section>-<ordinal>
```

Example:

```text
REQ-3GPP-TS29281-R18-5.1-001
```

Requirement IDs are stored in a versioned inventory file. Comments in code may
reference IDs, but comments do not define the inventory.

### 4.3 Evidence Records

```json
{
  "requirement_id": "REQ-3GPP-TS29281-R18-5.1-001",
  "status": "partial",
  "source_refs": ["crates/opc-proto-gtp/src/header.rs:Gtpv1uHeader"],
  "test_refs": ["crates/opc-proto-gtp/tests/roundtrip.rs:test_gtpu_header"],
  "gap_refs": ["GAP-000123"],
  "artifact_digests": ["sha256:..."],
  "reviewed_by": ["standards-reviewer"],
  "last_updated": "2026-05-19T00:00:00Z"
}
```

The pipeline MUST validate evidence records against a JSON schema.

## 5. Conformance Tracking

### 5.1 Inventory

The repository MUST maintain:

```text
evidence/
  requirements/
    3gpp-ts-29.281-r18.yaml
    ietf-rfc-7951.yaml
  mappings/
    code-map.yaml
    test-map.yaml
  gaps/
    known-gaps.yaml
```

Requirement inventories SHOULD be generated from structured sources when
available. When manual extraction is required, each requirement must include
source document, release/revision, section, and reviewer.

### 5.2 Code Tags

Code tags use strict syntax:

```rust
/// @spec 3GPP TS 29.281 R18 5.1 Table 5.1-1
/// @req REQ-3GPP-TS29281-R18-5.1-001
/// @conformance partial
/// @gap GAP-000123
pub struct Gtpv1uHeader<'a> { ... }
```

Allowed tag keys:

- `@spec`
- `@req`
- `@conformance`
- `@gap`
- `@security`
- `@performance`
- `@test`

Unknown tags MUST fail evidence extraction in release mode.

### 5.3 Test Tags

Tests SHOULD reference requirement IDs:

```rust
#[test]
#[req("REQ-3GPP-TS29281-R18-5.1-001")]
fn gtpu_header_roundtrip() { ... }
```

The extraction tool MUST support Rust test attributes or a sidecar test mapping
file. A requirement with code but no test remains `implemented`, not `full`.

### 5.4 Status Rules

Status calculation:

| Inputs | Result |
| :--- | :--- |
| code + passing tests + no blocking gaps | `full` |
| code + some tests + open nonblocking gaps | `partial` |
| code + no tests | `implemented-untested` |
| gap with no code | `not-implemented` |
| reviewed N/A record | `not-applicable` |
| approved waiver | `waived` |

The machine-readable report MUST include both raw evidence and calculated
status.

## 6. Known Gaps

### 6.1 Gap Record

Known gaps MUST be structured:

```yaml
id: GAP-000123
title: GTP-U extension headers not fully decoded
status: open
severity: medium
applies_to:
  - REQ-3GPP-TS29281-R18-5.2-004
owner: opc-proto-gtp
created: 2026-05-19
target_release: 0.3.0
mitigation: Reject unsupported extension headers in strict mode.
security_impact: Low if strict mode is enabled.
performance_impact: None.
```

### 6.2 Gap Gates

Release mode MUST fail when:

- A `partial` or `not-implemented` status has no gap.
- A gap has no owner.
- A gap has no mitigation or explicit "no mitigation" rationale.
- A gap target release is overdue.
- A security-critical gap lacks security approval.

The root `known-gaps.md` MAY be generated from `known-gaps.yaml`, but the YAML
is the source of truth.

## 7. SBOM and VEX

### 7.1 SBOM Requirements

Every release MUST include CycloneDX JSON SBOMs for:

- Rust workspace dependencies.
- Container images.
- Helm charts and embedded images.
- Generated artifacts where dependencies differ.
- Native libraries linked into binaries.

SBOMs MUST include:

- direct and transitive dependencies,
- package URLs where available,
- license data,
- hashes,
- supplier/source repository where available,
- build target,
- feature flags,
- container base image digests.

### 7.2 VEX Requirements

VEX records MUST state vulnerability applicability:

- affected,
- not affected,
- fixed,
- under investigation.

Each VEX decision MUST include:

- CVE or advisory ID,
- package and version,
- scanner database timestamp,
- justification,
- reviewer or automated policy source,
- expiry for temporary decisions.

Release mode MUST fail on unresolved critical vulnerabilities unless an
approved VEX record exists.

## 8. Provenance and Signing

### 8.1 Artifact Digests

Every artifact must be addressed by digest:

- binaries,
- container images,
- Helm charts,
- SBOMs,
- evidence bundles,
- performance reports,
- conformance reports.

Tags are not sufficient.

### 8.2 Provenance

Release builds MUST produce SLSA-style provenance, preferably in in-toto/DSSE
format, including:

- source repository URL,
- commit SHA,
- dirty tree status,
- builder identity,
- build workflow reference,
- build inputs,
- dependency lockfiles,
- environment image digest,
- output artifact digests.

### 8.3 Signing

Release artifacts and attestations MUST be signed with Sigstore/Cosign or an
approved offline carrier signing profile.

Keyless profile:

- OIDC issuer and subject must be policy-allowed.
- Transparency log entry must be verifiable.
- Certificate identity must match release workflow.

Offline profile:

- Public key must be published through an approved channel.
- Signing key custody and rotation must be documented.
- Transparency log use SHOULD be retained where possible.

### 8.4 Bundle Signing

Signing only `evidence-bundle.tar.gz` is not enough. The bundle MUST include a
manifest of file digests, and the manifest or DSSE envelope MUST be signed.
Individual high-value artifacts SHOULD also carry their own attestations.

## 9. Performance Evidence

### 9.1 Benchmark Classes

Performance evidence MUST cover:

- RFC 001 config commit phases.
- RFC 002 generated validation and patch application.
- RFC 004 session store operations.
- RFC 005 protocol decode/encode.
- Security operations from RFC 003 where relevant.

### 9.2 Environment Capture

`performance-baseline.json` MUST include:

- CPU model and count,
- memory size and speed where available,
- kernel version,
- container runtime,
- Kubernetes version when applicable,
- storage class for persistence tests,
- network plugin for distributed tests,
- compiler version,
- cargo profile,
- feature flags,
- git commit,
- date/time,
- benchmark tool version.

### 9.3 Regression Policy

Each benchmark defines:

- metric,
- baseline,
- allowed regression threshold,
- required sample count,
- noise handling,
- owner.

Data-plane PRs MUST fail when they exceed regression thresholds unless a
performance waiver is approved.

## 10. Evidence Bundle

### 10.1 Files

The release evidence bundle MUST contain:

```text
evidence-bundle/
  manifest.json
  conformance-report.json
  conformance-report.md
  known-gaps.json
  sbom/
    workspace.cdx.json
    containers.cdx.json
  vex/
    vex.json
  provenance/
    build.intoto.jsonl
  signatures/
    cosign.bundle
  performance/
    performance-baseline.json
    raw/
  tests/
    test-summary.json
    junit/
  security/
    vulnerability-report.json
    policy-results.json
```

### 10.2 Manifest

`manifest.json` MUST include:

- evidence schema version,
- SDK version,
- git commit,
- artifact digests,
- file digests,
- signing identity,
- generation tool version,
- generation timestamp,
- known incomplete sections.

Manifest file and artifact paths MUST be normalized relative bundle paths.
Absolute paths, parent/current-directory components, platform-specific path
prefixes, duplicate entries, conflicting digests, and malformed SHA-256 values
MUST fail closed before signing or verification.

Standalone manifest signatures and complete bundle signatures use distinct
versioned domain separators. Complete bundle signing bytes deterministically
bind the canonical manifest plus the digest of every embedded report. Canonical
manifest object fields, digest entries, and metadata keys use explicit lexical
ordering that MUST NOT vary with JSON-library map features. The authenticated
verifier identity MUST exactly match `signing_identity`; a release verifier
that cannot report its authenticated identity is insufficient. If a release
gate receives any artifact separately from the bundle, a verified signed bundle
is mandatory and the gate MUST evaluate the exact signed bytes rather than a
substitutable second copy. The signed manifest MUST also carry the
domain-separated canonical digest of every structured record, gap, and waiver
input used by the release gate. Raw records in a separately supplied signed
conformance report MUST match the v1 report projection of those bound inputs,
including gap references. Waiver references and full waiver records remain in
the signed gate-input digest because the frozen v1 report schema does not carry
them. A configured expected commit requires provenance, and the expected,
provenance, conformance-report, and manifest commit identities MUST agree.
Mismatch errors MUST NOT echo those values.

The domain-separated format intentionally does not verify signatures from the
pre-domain-separated implementation. Evidence producers upgrading to this
format MUST regenerate and re-sign their bundles; verifiers MUST NOT fall back
to the ambiguous legacy payload.

### 10.3 Packet-core evidence packs

A release evidence bundle MAY include one or more packet-core evidence packs
for protocol fixtures, attach procedure results, and kernel dataplane/XFRM
proof. These packs are intended to make smoke artifacts and test evidence from
different network functions comparable, not to create product-specific
certification claims.

Each pack is a JSON object conforming to `packet-core-evidence-pack.schema.json`
and contains:

- `protocol_evidence`: protocol fixture evidence records.
- `attach_evidence`: attach and session-establishment procedure results.
- `kernel_dataplane_evidence`: kernel dataplane, XFRM, routing, and firewall
  state summaries.

Packet-core evidence schemas are versioned independently within RFC 006 and
are currently **experimental**. A pack MUST declare `experimental: true` until
the schema graduates. Every pack MUST pass redaction validation before it is
included in a bundle; validation fails closed if any string field contains a
raw IMSI, MSISDN, IMEI, NAI, Session-Id, LI identifier, or key material.

Downstream products (for example, ePDG smoke artifacts) MAY map their own
evidence into this SDK format. Doing so documents how the product evidence
corresponds to SDK schema fields; it does not imply the SDK has certified the
product.

## 11. PR and Release Gates

### 11.1 PR Gates

Required for every PR:

- Build.
- Unit tests.
- Formatting and lint checks.
- Incremental evidence extraction.
- New public protocol/config items include spec or explicit non-spec tags.
- New gaps are structured and owned.
- Security-sensitive changes run targeted tests.

### 11.2 Release Gates

Required for every release:

- Full test suite.
- Fuzzing gate for changed protocol crates.
- SBOM generation.
- VEX evaluation.
- Vulnerability scan.
- Provenance generation.
- Artifact signing.
- Conformance report.
- Known-gap validation.
- Performance baseline.
- Evidence bundle signing.

Release MUST fail closed if evidence generation fails.

## 12. Implementation Evidence Requirements

Generated code is allowed only when evidence remains strict.

Rules:

- Every new protocol struct must include spec tags.
- Every new generated config item must include YANG path metadata.
- Every new security behavior must include a threat/test note.
- Every generated test must map to a requirement or state it is purely internal.
- Contributors must not mark conformance `full`; only the evidence calculator may
  calculate final status.
- Ambiguous or unsupported spec behavior must create a gap record.

The evidence pipeline is the guardrail that prevents plausible-looking code
from silently becoming unsupported compliance claims.

## 13. Tooling Architecture

```text
crates/opc-evidence/
  src/
    inventory.rs
    extract.rs
    conformance.rs
    sbom.rs
    vex.rs
    provenance.rs
    performance.rs
    bundle.rs
    policy.rs
    report.rs
```

Tool responsibilities:

- `inventory`: load and validate requirement inventories.
- `extract`: scan source and test tags.
- `conformance`: calculate status.
- `sbom`: invoke or parse SBOM generators.
- `vex`: correlate vulnerabilities and VEX decisions.
- `provenance`: collect build attestation metadata.
- `performance`: normalize benchmark output.
- `bundle`: create manifest and bundle.
- `policy`: enforce PR/release gates.
- `report`: emit Markdown and JSON.

## 14. Schemas

The repository MUST version JSON schemas for:

- requirement inventory,
- evidence record,
- conformance report,
- gap record,
- performance baseline,
- bundle manifest,
- VEX policy result,
- packet-core protocol evidence,
- packet-core attach evidence,
- packet-core kernel dataplane evidence,
- packet-core evidence pack.

Schema changes MUST be backward compatible within a major SDK release or
include a migration tool.

## 15. Testing Requirements

### 15.1 Unit Tests

- Tag parser accepts valid tags and rejects invalid tags.
- Requirement inventory schema validation.
- Gap gate logic.
- Status calculation matrix.
- Manifest digest calculation.
- VEX decision expiry.

### 15.2 Integration Tests

- End-to-end evidence generation on fixture crate.
- Release gate fails on undocumented partial conformance.
- Release gate fails on unsigned artifact.
- Release gate fails on unresolved critical CVE.
- Performance regression gate fails on threshold breach.
- Known-gaps Markdown generation from YAML.

### 15.3 Tamper Tests

- Modify artifact after manifest generation.
- Remove test evidence for full claim.
- Change SBOM after signing.
- Use disallowed signing identity.
- Replay old VEX with expired decision.

## 16. Acceptance Criteria

This RFC is implemented when:

1. Conformance claims are calculated from requirement inventory, code tags,
   tests, and gaps.
2. A requirement cannot silently remain partial without a structured known gap.
3. SBOM and VEX are generated and release-gated.
4. Provenance ties artifacts to source commit, builder, inputs, and digests.
5. Evidence bundles include signed manifests and verifiable artifact digests.
6. Performance baselines include environment details and regression thresholds.
7. PR and release gates fail closed on missing or inconsistent evidence.
8. Generated code must supply traceable tags and tests before it can support
   conformance claims.
