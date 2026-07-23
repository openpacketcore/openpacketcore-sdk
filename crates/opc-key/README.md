# opc-key

Tenant- and purpose-scoped key abstractions for OpenPacketCore.

## Purpose

`opc-key` defines the key provider boundary used by encryption, persistence,
session, and Vault/KMS adapters. It keeps key material behind `KeyHandle`,
models authenticated-data domains, exposes both in-memory and remote KMS
providers, and offers an opt-in admitted boundary for sealing through a
provider that declares non-exportable custody.

## API Shape

- `KeyProvider` is the async provider trait:
  `get_active_key`, `get_key_by_id`, and `rotate_key`.
- `KeyHandle` wraps zeroized key material and exposes
  `keyed_digest`, `encrypt_payload`, and `decrypt_payload`.
- `MemoryKeyProvider` is the in-process provider for tests and local fixtures.
- `KmsKeyProvider` talks to a Unix-socket or TLS/TCP JSON KMS endpoint using
  length-prefixed requests.
- `RemoteSealProvider` delegates encryption to KMS/HKMS and receives the
  validated envelope key ID on unseal so historical reads never substitute the
  current active key.
- `KeyCustodyModule` composes `CryptoModule` evidence and
  `RemoteSealProvider` operations on one exact object.
- `install_key_custody_module` admits that object once per process and returns
  the exact bounded `CapabilityReport` used at admission.
- `AdmittedKeyCustody` is a non-forgeable `RemoteSealProvider` adapter obtained
  only after installation. Every operation rechecks the frozen complete grant
  against live module identity, validation declaration, advertisement, and
  readiness before dispatch, with no implicit fallback.
- `RemoteSealMaterialController` atomically publishes an active remote key and
  an opaque, constant-space process-local epoch. An in-flight seal keeps the
  snapshot it began with. Cloned controllers share state only within one
  process; the controller is not a cross-pod coordinator, watcher, or durable
  epoch source.
- `KeyPurpose` separates lanes such as `Config`, `Session`,
  `ShadowSecurity`, `IpsecSa`, `Audit`, and `Backup`.
- `EnvelopeAad`, `ConfigAad`, `SessionAad`, and `ShadowSecurityAad` build
  structured authenticated data.
- `AeadAlgorithm` exposes local `Aes256GcmSiv` and server-side `RemoteSeal`
  envelope modes.

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

### Admitted non-exportable custody

Install the selected composite module during the runtime `SecurityInit` phase,
then obtain the opaque adapter for persistence/session composition:

```rust,no_run
use std::sync::Arc;

use opc_key::{
    admitted_key_custody, install_key_custody_module, AdmittedKeyCustody, CapabilityReport,
    CryptoCapability, KeyCustodyModule, ProviderPolicy,
};

async fn admit_custody(
    module: Arc<dyn KeyCustodyModule>,
) -> Result<(CapabilityReport, AdmittedKeyCustody), Box<dyn std::error::Error + Send + Sync>> {
    let policy = ProviderPolicy::new()
        .require(CryptoCapability::SealedKeyStorage)
        .require(CryptoCapability::Zeroization);
    let report = install_key_custody_module(module, policy).await?;
    let custody = admitted_key_custody()?;
    Ok((report, custody))
}
```

The report contains module-declared evidence; the SDK does not independently
certify the provider's non-exportability or validation claims. Its self-test
result is admission-time evidence. Seal/unseal does not rerun an asynchronous
power-on self-test. A module whose later health or self-test state becomes
invalid must withdraw the affected capabilities from its live readiness; the
next operation then fails before provider dispatch.

Successful provider-returned bound AAD is limited to 64 KiB before parsing,
must decode in the canonical SDK representation, and must exactly reserialize
from the caller's AAD plus the returned key ID. Oversized, malformed,
non-canonical, or context-mismatched output fails with a fieldless stable code.

## Relationships

- `opc-crypto` consumes `KeyProvider` and `KeyHandle` to build encoded
  envelopes.
- `opc-crypto-provider` supplies the bounded evidence, module identity,
  capability, and policy-admission types used by admitted custody.
- `opc-key-vault` implements the provider boundary for HashiCorp Vault Transit.
- `opc-persist` and `opc-session-store` use key purposes and AAD builders to
  bind stored ciphertext to tenant, version, namespace, and generation data.

## Status Notes

- Key material is zeroized on drop.
- `MemoryKeyProvider` is suitable for tests and fixtures, not production key
  custody.
- `KmsKeyProvider` redacts errors and requires TLS for TCP endpoints. Unix
  sockets are accepted for local KMS deployments.
- Existing `KeyProvider`, `KeyHandle`, `KmsRemoteSealProvider`,
  `MemoryRemoteSealProvider`, and custom `RemoteSealProvider` implementations
  remain source- and wire-compatible. They are explicitly unadmitted unless
  the consumer composes the same object as a `KeyCustodyModule`; direct values
  cannot construct or impersonate `AdmittedKeyCustody`.
- An admitted provider must explicitly satisfy both `sealed_key_storage` and
  `zeroization`. Provider `NotFound` and `Unavailable` outcomes keep their
  existing public meaning; all other provider context is collapsed to a
  redaction-safe fieldless operation code.
- Rotation keeps historical keys addressable by key ID.
- `KmsRemoteSealProvider` keeps no local historical-key or authorization cache.
  Every unseal calls KMS/HKMS with the exact validated envelope key ID. KMS/HKMS
  owns retention and revocation; the SDK provides no retirement API or
  enforcement gate and cannot prevent an external retirement.
- `RemoteSealProvider::unseal` now takes `&KeyId`. Custom provider
  implementations and callers must upgrade together before publishing a new
  active ID. `KmsRemoteSealProvider::key_id()` is replaced by
  `material_controller()`, `publish_active_key()`, and `material_epoch()`;
  `MemoryRemoteSealProvider::key_id()` is replaced by async
  `active_key_id()`. Durable envelopes and KMS framing/schema are unchanged;
  decrypt request contents now select the historical envelope ID.
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
