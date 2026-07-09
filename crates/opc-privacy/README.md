# opc-privacy

Privacy minimization helpers for aggregate and identifier-safe outputs.

## Purpose

`opc-privacy` provides small, deterministic helpers for k-anonymous cohort
aggregation, numeric binning, and keyed identifier hashing. It is intended for
analytics and diagnostics code that must avoid leaking direct subscriber
identifiers.

## API Shape

- `MinimizationPolicy` configures k-anonymity enforcement.
- `CohortRecord` carries an aggregate cohort key and count.
- `aggregate_cohorts` suppresses cohorts below the effective k-anonymity floor.
- `bin_value` and `try_bin_value` bucket numeric values.
- `hash_identifier` computes a keyed digest for an `IdentifierType`.
- `MinimizationError` reports rejected direct identifiers and invalid policy
  inputs.

```rust
use opc_data_governance::{DataClass, IdentifierType};
use opc_privacy::{aggregate_cohorts, CohortRecord, MinimizationPolicy};

let policy = MinimizationPolicy {
    policy_id: "analytics-safe".to_string(),
    min_cohort_size: 2,
    enforce_k_anonymity: true,
    allowed_classes: vec![DataClass::AnalyticsSensitive],
};
let cohorts = aggregate_cohorts(vec![
    vec!["region-a".to_string()],
    vec!["region-a".to_string()],
]);
policy.validate_cohorts(&cohorts).expect("safe cohort");
assert_eq!(cohorts[0].count, 2);
assert!(IdentifierType::Imsi.is_telco());
```

## Relationships

- Uses `opc-data-governance` identifier classes.
- Uses `opc-redaction::DigestKey` for keyed identifier hashing.
- Complements `opc-redaction`; this crate handles minimization decisions, not
  display formatting.

## Status Notes

- Direct `DataClass::SubscriberId` cohorts are rejected.
- Cohort keys that look like raw subscriber IDs or IPv4 addresses are rejected.
- Even with k-anonymity enforcement disabled, singleton cohorts are suppressed
  by an absolute floor of 2.
- This crate does not store data or enforce retention.

## Roadmap

- Keep aggregation deterministic and dependency-light.
- Add minimization helpers only when a caller has a concrete privacy boundary.
- Keep raw identifier detection conservative and fail closed.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and tests.
- Run with: `cargo test -p opc-privacy`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
