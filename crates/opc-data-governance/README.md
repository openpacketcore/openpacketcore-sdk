# opc-data-governance

Data classification and retention policy primitives for OpenPacketCore.

## Purpose

`opc-data-governance` provides the shared vocabulary for classifying telecom
data, mapping identifier types to sensitivity classes, and validating retention
policy metadata before export or deletion decisions.

## API Shape

- `DataClass` is the core classification enum. It includes public,
  operational, network-sensitive, subscriber, session, secret, charging, lawful
  intercept, analytics-sensitive, and audit-regulated classes.
- `IdentifierType` names telecom identifiers such as SUPI, SUCI, GPSI, MSISDN,
  PEI, IMSI, GUTI, IP address, MAC address, APN, TEID, SPI, Diameter
  Session-Id, TAI/ECGI/CGI, and lawful-intercept IDs.
- `TelcoIdentifierClass` groups identifiers into subscriber, session endpoint,
  security association, application, and lawful-intercept classes.
- `RetentionPolicy` records data class, optional duration, legal hold,
  disposal action, source policy ID, and tenant ID.
- `DisposalAction` supports purge, anonymize, archive, and immediate disposal.

```rust
use opc_data_governance::{DataClass, IdentifierType};

let id = IdentifierType::Imsi;
assert!(id.is_telco());
assert_eq!(id.default_data_class(), DataClass::SubscriberId);
assert!(!DataClass::SecuritySecret.allows_cleartext());
```

## Relationships

- `opc-redaction` uses these classes to choose mask, digest, and cleartext
  behavior.
- `opc-privacy` uses identifier and data classes for minimization checks.
- `opc-export` validates payload state and retention policy against these
  classifications.

## Status Notes

- `RetentionPolicy::validate(is_production)` fails closed for zero-duration
  retention unless immediate disposal is selected.
- Legal hold blocks purge, immediate disposal, and anonymize.
- Production validation requires a nonblank source policy ID.
- `SecuritySecret` and `LawfulIntercept` do not allow cleartext export.

## Roadmap

- Keep the taxonomy stable and additive for SDK consumers.
- Extend identifier coverage as protocol crates add new telecom metadata.
- Keep retention validation policy-only; this crate does not delete or archive
  data itself.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and tests.
- Run with: `cargo test -p opc-data-governance`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
