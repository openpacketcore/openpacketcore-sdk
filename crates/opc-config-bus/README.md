# Opc Config Bus

Transactional config bus supporting schema validation, tenant segregation, AAD-bound envelope encryption, and admission control.

Candidate-bearing `commit`, `commit-confirmed`, and `validate-only` requests now
produce a generic config apply plan after syntax/semantic validation and before
durable append or publication. The default classifier marks SDK-derived changed
paths as `hot`, so existing users do not need to configure anything. Products
that need stricter behavior can use the explicit classifier constructors and
provide an `opc_config_model::ConfigImpactClassifier`.

Apply-plan hard errors and `forbidden-live` plans fail closed before any durable
side effect. Successful `validate-only` and commit responses expose the admitted
plan on `CommitResult.apply_plan`; rejected plans are attached to
`CommitError.apply_plan` with `CommitErrorCode::ApplyPlanRejected`.

## Status

**Production-ready**

## Non-production bootstrap store

`InMemoryManagedDatastore<C>` is available for local development, CI, and
management-only bootstrap before a product has selected a durable production
config backend. It preserves config-bus append, restore, rollback,
idempotency, recovery-marker, and commit-confirmed behavior while the process
is alive, but it is non-durable and must not be used as production config
storage.

```rust,no_run
use opc_config_bus::{ConfigBus, InMemoryManagedDatastore};
use opc_config_model::OpcConfig;

async fn build_dev_bus<C: OpcConfig>(initial: C) -> Result<ConfigBus<C>, opc_config_bus::StoreError> {
    ConfigBus::restore_or_new_dev_only(initial, InMemoryManagedDatastore::new()).await
}
```

## Reference

[RFC](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/001-management-substrate.md)

## Quick start

```rust,no_run
use opc_config_bus::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
