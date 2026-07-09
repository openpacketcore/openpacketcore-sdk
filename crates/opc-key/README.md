# opc-key

Tenant- and purpose-scoped key abstractions for OpenPacketCore.

## Purpose

`opc-key` defines the key provider boundary used by encryption, persistence,
session, and Vault/KMS adapters. It keeps key material behind `KeyHandle`,
models authenticated-data domains, and exposes both in-memory and remote KMS
providers.

## API Shape

- `KeyProvider` is the async provider trait:
  `get_active_key`, `get_key_by_id`, and `rotate_key`.
- `KeyHandle` wraps zeroized key material and exposes
  `keyed_digest`, `encrypt_payload`, and `decrypt_payload`.
- `MemoryKeyProvider` is the in-process provider for tests and local fixtures.
- `KmsKeyProvider` talks to a Unix-socket or TLS/TCP JSON KMS endpoint using
  length-prefixed requests.
- `KeyPurpose` separates lanes such as `Config`, `Session`,
  `ShadowSecurity`, `IpsecSa`, `Audit`, and `Backup`.
- `EnvelopeAad`, `ConfigAad`, `SessionAad`, and `ShadowSecurityAad` build
  structured authenticated data.
- `AeadAlgorithm` currently exposes `Aes256GcmSiv`.

```rust,no_run
use opc_key::{EnvelopeAad, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, SessionAad, Zeroizing};
use opc_types::TenantId;

async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenant = TenantId::new("tenant-a")?;
    let provider = MemoryKeyProvider::new();
    provider.insert_active_key(
        KeyId::new("session-key-1")?,
        KeyPurpose::Session,
        tenant.clone(),
        Zeroizing::new([7u8; 32]),
    )?;

    let key = provider.get_active_key(KeyPurpose::Session, &tenant).await?;
    let aad = EnvelopeAad::session(
        tenant,
        1,
        SessionAad::new("amf", "session-digest", "subscriber-context", 1, 1, "sessions")?,
    );
    let encrypted = key.encrypt_payload(&aad, b"session-state", [1u8; 12])?;
    let plaintext = key.decrypt_payload(
        &aad,
        &encrypted.aad,
        &encrypted.ciphertext_and_tag,
        [1u8; 12],
    )?;
    assert_eq!(plaintext.as_ref(), b"session-state");
    Ok(())
}
```

## Relationships

- `opc-crypto` consumes `KeyProvider` and `KeyHandle` to build encoded
  envelopes.
- `opc-key-vault` implements the provider boundary for HashiCorp Vault Transit.
- `opc-persist` and `opc-session-store` use key purposes and AAD builders to
  bind stored ciphertext to tenant, version, namespace, and generation data.

## Status Notes

- Key material is zeroized on drop.
- `MemoryKeyProvider` is suitable for tests and fixtures, not production key
  custody.
- `KmsKeyProvider` redacts errors and requires TLS for TCP endpoints. Unix
  sockets are accepted for local KMS deployments.
- Rotation keeps historical keys addressable by key ID.
- `SessionAad` rejects NUL-containing fields; config AAD rejects blank principal
  and store kind values.

## Roadmap

- Keep `KeyProvider` small so new KMS adapters can implement it directly.
- Extend algorithm support only when consumers have a concrete migration path.
- Continue moving production key custody into provider implementations rather
  than exposing raw key bytes.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, `src/aad.rs`, provider modules,
  and tests.
- Run with: `cargo test -p opc-key`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
