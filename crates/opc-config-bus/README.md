# opc-config-bus

Sequenced configuration commit bus for OpenPacketCore CNFs.

This crate owns the runtime commit flow around `opc-config-model`: admission,
authorization, validation, durable append, snapshot publication, subscribers,
and recovery fencing. It does not define the CNF config schema itself.

## API Shape

Main exports:

- `ConfigBus`, the commit worker and snapshot publisher.
- `ConfigAuthorizer`, `AuthorizationContext`, `AuthorizationError`, and
  `AllowAllAuthorizer`.
- Datastore contracts and implementations:
  `ManagedDatastore`, `EncryptingManagedDatastore`,
  `InMemoryManagedDatastore`, and `MockManagedDatastore`.
- Snapshot/event types:
  `ConfigSnapshot`, `AtomicConfigSnapshot`, `PublishedSnapshot`,
  `ConfigChange`, `ConfigEvent`, and `ConfigReceiver`.
- Store and recovery types:
  `StoredConfig`, `SealedConfig`, `StoredRequestFingerprint`,
  `StoreError`, `StoreErrorCode`, `DriftState`, and `AuthorityMode`.
- Subscriber behavior: `SubscriberLagPolicy`.

Example imports:

```rust
use opc_config_bus::{ConfigBus, ConfigAuthorizer, ManagedDatastore};
use opc_config_model::OpcConfig;
```

`ConfigBus` runs a single sequenced commit worker behind a bounded queue. A
successful submission means the request passed authorization, validation,
durable append, and snapshot publication. A full queue fails admission
immediately. Recovery fencing returns `RecoveryRequired` until the backing store
is cleared.

## Relationships

- Consumes `OpcConfig` models from `opc-config-model`.
- Uses authorizers supplied by production policy layers such as
  `opc-mgmt-authz`.
- Can wrap sealed durable stores through `EncryptingManagedDatastore` using
  `opc-crypto` and `opc-key`.
- Publishes snapshots to subscribers used by CNF runtime components.

## Status And Limits

Current scope:

- Authoritative single-writer config commits.
- Bounded commit queue with immediate backpressure.
- Bounded subscriber lag policies:
  `DropOldest`, `DropNewest`, `DisconnectOnLag`, and `ForceResync`.
- Idempotency and rollback support through the datastore trait.

Production notes:

- `InMemoryManagedDatastore` and `MockManagedDatastore` are not durable
  production stores.
- Constructors with `*_dev_only` install `AllowAllAuthorizer` and must stay out
  of production wiring.
- Built-in constructors are authoritative; `AuthorityMode::Shadow` is reserved
  for future integration work.

## Roadmap

- Keep storage behind the datastore trait.
- Add production authority modes only when a durable coordination design exists.

## Verification

Run:

```sh
cargo test -p opc-config-bus
```
