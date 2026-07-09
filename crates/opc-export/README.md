# opc-export

Export-safety metadata and validation for OpenPacketCore data items.

## Purpose

`opc-export` validates that an outbound item carries enough metadata,
retention policy, and payload-state information to be exported safely. It does
not write files or send data; it is the policy guard used before a caller hands
data to an export channel.

## API Shape

- `PayloadState` records whether the payload is raw, redacted, encrypted, or
  digest-only.
- `ExportMetadata` binds tenant, data class, redaction level, payload state,
  schema version, and retention policy.
- `ExportedItem` holds metadata plus payload bytes and exposes
  `validate_for_export(is_production)`.
- `ExportError` reports missing metadata, retention mismatches, invalid payload
  state, and production-sensitive raw exports.

```rust,no_run
use opc_export::{ExportedItem, PayloadState};

fn validate(item: &ExportedItem) -> Result<(), opc_export::ExportError> {
    item.validate_for_export(true)
}

let _state = PayloadState::DigestOnly;
```

## Relationships

- Uses `opc-data-governance` for data class, identifier type, and retention
  policy.
- Uses `opc-crypto::CryptoEnvelopeV1` to validate encrypted payload shape.

## Status Notes

- Production mode rejects raw sensitive payloads; only public and operational
  raw exports are allowed.
- Encrypted payloads must decode as `CryptoEnvelopeV1`.
- Digest-only payloads must be either 32 raw bytes or 64 lowercase/uppercase
  hexadecimal characters.
- Retention policy data class and tenant must match export metadata.

## Roadmap

- Keep this crate focused on validation, not transport.
- Extend payload-state validation only when new envelope or digest formats are
  introduced by SDK crates.
- Keep production raw-export rules conservative.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and tests.
- Run with: `cargo test -p opc-export`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
