# opc-crypto

Authenticated encryption envelope helpers for OpenPacketCore payloads.

## Purpose

`opc-crypto` turns `opc-key` key handles into versioned AEAD envelopes. It is
the small boundary used by config, session, and export code when bytes must be
encrypted with tenant/purpose-bound additional authenticated data.

## API Shape

- `CryptoEnvelopeV1` stores the algorithm, `KeyId`, nonce, AAD, and ciphertext
  plus tag. Use `encode` and `decode` for the stable wire form.
- `encrypt_envelope` and `decrypt_envelope` fetch keys from a `KeyProvider` and
  bind caller-supplied `EnvelopeAad`.
- `encrypt_envelope_with_handle`, `decrypt_envelope_with_handle`, and
  `decrypt_decoded_envelope_with_handle` operate on an already selected
  `KeyHandle`.
- `encrypt_envelope_with_nonce` and
  `encrypt_envelope_with_handle_and_nonce` are deterministic test-vector
  helpers. Do not use fixed nonces in production.
- `CryptoError` is intentionally small: invalid envelope, encryption failure,
  or decryption failure.

```rust,no_run
use opc_crypto::{decrypt_envelope, encrypt_envelope};
use opc_key::{EnvelopeAad, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, SessionAad, Zeroizing};
use opc_types::TenantId;

async fn seal() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let tenant = TenantId::new("tenant-a")?;
    let keys = MemoryKeyProvider::new();
    keys.insert_active_key(
        KeyId::new("session-key-1")?,
        KeyPurpose::Session,
        tenant.clone(),
        Zeroizing::new([7u8; 32]),
    )?;

    let aad = EnvelopeAad::session(
        tenant,
        1,
        SessionAad::new("amf", "session-digest", "subscriber-context", 1, 1, "sessions")?,
    );
    let envelope = encrypt_envelope(&keys, &aad, b"session-state").await?;
    let opened = decrypt_envelope(&keys, &aad, &envelope).await?;
    assert_eq!(&opened[..], b"session-state");
    Ok(envelope)
}
```

## Relationships

- Depends on `opc-key` for `KeyProvider`, `KeyHandle`, `KeyId`, and
  `AeadAlgorithm`.
- Used by persistence, session-store encryption, export validation, and
  integration crates that need stable encrypted payloads.

## Status Notes

- Safe Rust only.
- The implemented algorithm is AES-256-GCM-SIV through `opc-key`.
- Decryption fails closed for wrong key IDs, mismatched AAD, corrupt tags, and
  malformed envelopes. Errors do not expose plaintext or key material.
- The envelope format is versioned as `CryptoEnvelopeV1`; there is no streaming
  encryption API in this crate.

## Roadmap

- Keep `CryptoEnvelopeV1` stable for SDK-internal storage and test vectors.
- Add new envelope versions only when a concrete wire-format change is needed.
- Keep nonce-injection APIs constrained to deterministic tests and fixtures.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and crate tests.
- Run with: `cargo test -p opc-crypto`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
