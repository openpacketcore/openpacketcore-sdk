# Opc Key Vault

HashiCorp Vault Transit KMS adapter for `opc-key`.

## Status

**experimental**

## Reference

[RFC 003 — Security Substrate](../docs/rfc/003-security-substrate.md)

## Quick start

```rust,no_run
use opc_key_vault::VaultKeyProvider;
use opc_types::TenantId;

#[tokio::main]
async fn main() {
    let provider = VaultKeyProvider::new(
        "https://vault:8200".parse().unwrap(),
        "hvs.xxx".into(),
        "transit".into(),
    );

    let tenant = TenantId::new("tenant-a").expect("valid tenant");
    let handle = provider
        .get_active_key(opc_key::KeyPurpose::Config, &tenant)
        .await
        .expect("active key");

    // Use the handle with opc_crypto envelope encrypt/decrypt.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
