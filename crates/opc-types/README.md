# opc-types

Shared validated identifiers, versions, timestamps, and redaction wrappers.

## Purpose

`opc-types` is the low-level type crate used across the SDK. It keeps common
identifiers and version values strongly typed so higher-level crates do not
pass raw strings at trust boundaries.

## API Shape

- Identifier types: `TenantId`, `InstanceId`, `RegionId`, `SpiffeId`, `PlmnId`,
  `Snssai`, and redaction-safe `Imei`/`Imei15`/`Imeisv` device identities.
- Network-function types: `NfKind`, plus compatibility aliases
  `NetworkFunctionKind`, `NfType`, and `NfInstanceId`.
- Versioning/time types: `ConfigVersion`, `SchemaDigest`, `Timestamp`, and
  `TxId`.
- Redaction helpers: `Redacted<T>`, `redact(&value)`, `IntoRedacted`, and
  `RedactedDebug`.
- Errors: `ParseError`.

```rust
use opc_types::{ConfigVersion, NfKind, Redacted, SchemaDigest, TenantId};

let tenant = TenantId::new("tenant-a").expect("valid tenant");
let nf = NfKind::amf();
assert!(nf.is_known());

let next = ConfigVersion::INITIAL.next().expect("version overflow");
assert_eq!(next.get(), 1);

let digest = SchemaDigest::from_bytes([1u8; 32]);
assert_eq!(digest.as_bytes(), &[1u8; 32]);

let secret = Redacted::new(tenant);
assert_eq!(format!("{secret:?}"), "<redacted>");
```

## Relationships

- Used by identity, TLS, persistence, session, runtime, and evidence crates.
- Provides `SpiffeId` and NF identifiers consumed by `opc-identity`.
- Provides redaction wrappers used where values can be retained in memory but
  must not be printed.

## Status Notes

- Slug-like identifiers validate runtime input with `new`; `from_static`
  panics on invalid literals and is intended for tests/reference constants.
- `SpiffeId` validates the canonical SDK path layout:
  `/tenant/<tenant>/ns/<namespace>/sa/<service-account>/nf/<nf-kind>/instance/<instance>`.
- `NfKind::KNOWN_VALUES` lists the recognized 3GPP NF kinds; custom validated
  strings can still be constructed with `NfKind::new`.
- `Redacted<T>` hides values in `Debug` and `Display` but still allows explicit
  access with `expose` or `into_inner`.
- `Imei` preserves an exact 14- or 15-digit protocol value; it never adds or
  rejects the fifteenth digit using Luhn. `Imei15` requires all 15 transmitted
  digits for DEVICE_IDENTITY and KDF inputs. `Imeisv` accepts exactly 16 digits,
  exposes a typed split, returns its exact 14-digit equipment identity, and has
  a separately named presentation-only Luhn conversion. These types do not
  implement serde and redact `Debug`/`Display`; raw digits require explicit
  exposure methods.

## Roadmap

- Keep this crate dependency-light and stable.
- Add shared identifiers only when more than one SDK crate needs the boundary.
- Keep parsing strict and display output canonical.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, identity, NF, redaction, and
  versioning modules.
- Run with: `cargo test -p opc-types`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
