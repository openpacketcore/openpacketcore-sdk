# ADR 0010: Release Assurance Evidence Pipeline

## Status

Accepted

## Date

2026-06-08

## Context

The SDK needs release evidence that is machine-readable and fail-closed.
Manual claims like "tests passed" are insufficient for conformance, supply-chain
assurance, and auditability.

## Decision

`opc-evidence` is the RFC 006 release-assurance pipeline.

It provides:

- Source extraction for RFC 006 tags such as `@spec`, `@req`,
  `@conformance`, `@gap`, `@security`, `@performance`, and `@test`.
- Deterministic CycloneDX SBOM generation from local Cargo manifests and lock
  data.
- VEX policy result and record validation.
- SLSA/in-toto-style provenance tied to commit, builder, input materials,
  output digests, and dirty/clean worktree state.
- Bundle assembly and verification with canonical manifest signing bytes.
- Signer/verifier traits and deterministic in-process test signing.
- Performance baseline schema with redaction-safe environment metadata and
  regression status.
- PR/release gate policy that fails closed on missing evidence, missing
  signatures, tampering, mismatched commits, dirty release provenance, malformed
  JSON, or unsafe evidence content.

## Consequences

Release pipelines must treat evidence artifacts as required inputs, not as
optional reports.

Real Sigstore/Cosign keyless signing remains an external signer adapter
boundary. The SDK owns the signing/verifier interface and test verifier, not a
hard dependency on one hosted signing provider.

## Evidence

- `crates/opc-evidence/src/extract.rs`
- `crates/opc-evidence/src/sbom.rs`
- `crates/opc-evidence/src/vex.rs`
- `crates/opc-evidence/src/provenance.rs`
- `crates/opc-evidence/src/bundle.rs`
- `crates/opc-evidence/src/performance.rs`
- `crates/opc-evidence/src/policy.rs`
- `crates/opc-evidence/tests/evidence_pipeline.rs`

