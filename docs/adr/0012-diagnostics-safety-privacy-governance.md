# ADR 0012: Diagnostics Safety and Privacy Governance

## Status

Accepted

## Date

2026-06-08

## Context

Diagnostics, support bundles, exports, and evidence files pose a high risk of leaking sensitive subscriber identifiers (SUPI, IMSI, MSISDN), secrets, cryptographic credentials, database internals, and local filesystem paths. The SDK required a structured, fail-closed diagnostics and privacy boundary to satisfy RFC 010.

## Decision

Establish a clear, multi-crate boundary for diagnostics safety and privacy governance:

1. **Structured, Redacted Support Bundles**:
   - Diagnostic data is collected as structured `DiagnosticEntry` variants.
   - Support bundles are redacted prior to serialization using `redact_support_bundle`.
   - The engine cleans sensitive subscriber identifiers, IPs, SPIFFE IDs, JWTs, paths, database errors, and secrets, producing a `RedactionSummary`.
   - Unknown or unsafe attachments fail closed in Production mode.

2. **Declarative Retention & Legal Holds**:
   - `RetentionPolicy` schema in `opc-data-governance` dictates retention duration, data class, and disposal action.
   - Policies validate durational boundaries and block deletion/disposal decisions when a legal hold flag is active.

3. **Classification-Preserving Exports**:
   - `ExportedItem` in `opc-export` encapsulates the payload and `ExportMetadata`.
   - Production validation rejects raw sensitive payloads unless they are encrypted.

4. **Analytics Minimization**:
   - `MinimizationPolicy` in `opc-privacy` enforces k-anonymity cohort sizing thresholds, binning, and subscriber ID digest hashing.
   - Cohorts below the threshold or direct identifiers are rejected.

5. **Data-Governance Evidence Gating**:
   - Release gates require `DataGovernanceEvidenceReport` validation.
   - The evaluator parses the report and scans it to ensure no absolute paths, credentials, or raw IPs are present.

## Consequences

- Diagnostic attachments and support bundles cannot silently leak raw sensitive identifiers or secrets in Production mode.
- Downstream CNFs can safely collect support bundles and perform analytics exports without violating privacy regulations.
- Data-governance compliance is automatically checked and enforced at release compile/gate time.

## Evidence

- `crates/opc-redaction/src/support_bundle.rs`
- `crates/opc-data-governance/src/retention.rs`
- `crates/opc-export/src/lib.rs`
- `crates/opc-privacy/src/lib.rs`
- `crates/opc-evidence/src/data_governance.rs`
- `crates/opc-sdk-integration/tests/privacy_governance.rs`
