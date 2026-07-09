# opc-evidence

Evidence schemas, bundle verification, and gate policy evaluation.

## Purpose

`opc-evidence` holds the SDK-owned evidence record types used by conformance,
release gates, performance baselines, SBOM/VEX/provenance checks, and
packet-core experimental packs. It validates evidence structure and rejects
unsafe artifacts before they become release evidence.

## API Shape

- Bundle APIs: `EvidenceBundle`, `BundleSigner`, `BundleVerifier`,
  `BundleVerifierSecurity`, `manifest_signing_bytes`, `bundle_signing_bytes`,
  and `verify_bundle`.
- Requirement APIs: `RequirementId`, `EvidenceRecord`, `WaiverRecord`,
  `ConformanceTag`, `parse_tags`, `scan_file`, and `scan_directory`.
- Gap APIs: `Gap`, `GapOptions`, `GapSeverity`, `GapStatus`, and
  `validate_status_for_gaps`.
- Gate APIs: `GatePolicy`, `GateEvaluator`, `PolicyMode`, and waiver-aware
  evaluation.
- Artifact APIs: `Manifest`, `ManifestEntry`, `compute_digest`,
  `generate_sbom`, `generate_provenance`, VEX validation, and environment
  capture helpers.
- Packet-core experimental APIs:
  `PacketCoreEvidencePack`, protocol/dataplane evidence structs, redaction
  validation, and raw-sensitive-identifier detection.
- Dataplane APIs:
  `DataplaneSnapshot`, `DataplaneSnapshotAsserter`, and traffic-readiness or
  packet-continuity claim checks.

```rust
use opc_evidence::{ConformanceStatus, EvidenceRecord, RequirementId};
use std::str::FromStr;

let req = RequirementId::from_str("REQ-3GPP-TS23501-R18-6.2.2-001").expect("valid requirement");
let record = EvidenceRecord::new(req, ConformanceStatus::Tested);
assert_eq!(record.status, ConformanceStatus::Tested);
```

## Relationships

- Consumed by `opc-testbed` scenario evidence conversion.
- Uses redaction checks for packet-core and artifact validation.
- Connects generated SBOM, VEX, provenance, performance, and conformance
  artifacts into one gate-evaluable model.

## Status Notes

- Release gate evaluation requires `BundleVerifierSecurity::Release`; test or
  mock verifiers are rejected in release mode.
- Bundle verification checks schema version, signatures, file digests, and
  artifact digests.
- `PacketCoreEvidencePack` is explicitly experimental and must set
  `experimental: true`.
- Packet-core redaction validation rejects raw IMSI, MSISDN, IMEI, NAI,
  Session-Id, lawful-intercept identifiers, SPI/key material, and raw IPs.
- Dataplane traffic-readiness and packet-continuity claims must be explicitly
  proven true.

## Roadmap

- Keep release-gate checks conservative as evidence producers evolve.
- Stabilize packet-core evidence schemas only after downstream producers prove
  the current experimental model.
- Continue adding artifact validators where the SDK owns the schema contract.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, schema modules, fixtures, and
  evidence tests.
- Run with: `cargo test -p opc-evidence`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
