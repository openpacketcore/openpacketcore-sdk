# opc-redaction

Redaction, digesting, and support-bundle sanitization for OpenPacketCore.

## Purpose

`opc-redaction` centralizes how network-sensitive values are displayed,
digested, and sanitized before logs, metrics, diagnostics, or support bundles
leave a process boundary.

## API Shape

- `DigestKey::new([u8; 32])` and `compute_digest` produce HMAC-SHA256 digests
  over data class, identifier type, and raw value.
- `redact(value, data_class, level, id_type, digest_key)` returns a
  `RedactedValue`.
- `RedactionLevel` supports drop, mask, class, length class, digest, and
  cleartext requests.
- `TelcoIdentifier` classifies and redacts IMSI, MSISDN, IMEI, NAI, SIP, APN,
  DNN, TEID, SPI, Diameter Session-Id, and lawful-intercept IDs.
- `support_bundle` APIs sanitize logs, config snapshots, health/debug JSON,
  alarms, metrics text, runtime state, persistence errors, and explicit
  diagnostic attachments.
- `metrics_label_safe` and `metrics` helpers sanitize metric labels and export
  SDK counters.

```rust
use opc_data_governance::{DataClass, IdentifierType};
use opc_redaction::{redact, DigestKey, RedactionLevel};

let key = DigestKey::new([9u8; 32]);
let value = redact(
    "001010123456789",
    DataClass::SubscriberId,
    RedactionLevel::Digest,
    Some(IdentifierType::Imsi),
    Some(&key),
);
assert_ne!(value.to_string(), "001010123456789");
```

## Relationships

- Uses `opc-data-governance` for data and identifier classes.
- Used by observability, evidence, testbed, privacy, export, and persistence
  diagnostics.

## Status Notes

- `Display` and `Debug` for `RedactedValue` do not reveal raw values.
- `Cleartext` is denied for `SecuritySecret` and `LawfulIntercept`.
- Digest mode falls back to masking if key or identifier metadata is missing.
- Production support-bundle mode rejects unknown or unsafe diagnostic entries.
- APN/DNN handling defaults to network-sensitive classification unless policy
  says they should be treated as subscriber IDs.

## Roadmap

- Keep support-bundle sanitization fail closed for new diagnostic entry types.
- Extend telco identifier heuristics as protocol crates add new metadata.
- Keep metric-label sanitization strict enough for shared operational systems.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, support-bundle modules, metrics
  modules, and tests.
- Run with: `cargo test -p opc-redaction`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
