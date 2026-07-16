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
  `StoredConfig`, `CommitWrite`, `ConfirmedCommitResolution`, `SealedConfig`,
  `StoredRequestFingerprint`,
  `StoreError`, `StoreErrorCode`, `DriftState`, and `AuthorityMode`.
- Subscriber behavior: `SubscriberLagPolicy`.

Example imports:

```rust
use opc_config_bus::{ConfigBus, ConfigAuthorizer, ManagedDatastore};
use opc_config_model::OpcConfig;
```

`ConfigBus` runs a single sequenced commit worker behind a bounded queue. A
successful submission means the request passed authorization, validation,
durable append, and snapshot publication. A caller deadline that expires while
an append is already running does not turn a later proven durable success into
failure. If the backend cannot prove whether a write committed, the bus returns
`OutcomeUnknown`, raises its recovery fence, and requires authoritative lookup
by the original request ID or idempotency key before any retry. Requests
without a key can call `ConfigBus::resolve_request_id`; keyed callers resubmit
the exact same request and key to replay the durable result, including on the
fenced bus. That replay is read-only: it does not publish the missing local
snapshot or clear the fence. A full queue fails admission immediately.
Recovery fencing returns `RecoveryRequired` for every new mutation until the
backing store is reconciled and the bus is rebuilt from authoritative state.

## Relationships

- Consumes `OpcConfig` models from `opc-config-model`.
- Uses authorizers supplied by production policy layers such as
  `opc-mgmt-authz`.
- Can wrap sealed durable stores through `EncryptingManagedDatastore` using
  `opc-crypto` and `opc-key`.
- Publishes snapshots to subscribers used by CNF runtime components.

## Status And Limits

Current scope:

- Authoritative sequenced config commits with applied-head compare-and-append
  across HA leader changes.
- Bounded commit queue with immediate backpressure.
- Bounded subscriber lag policies:
  `DropOldest`, `DropNewest`, `DisconnectOnLag`, and `ForceResync`.
- Idempotency and rollback support through the datastore trait.
- Atomic confirm-or-rollback plus successor append for commit-confirmed state.

Production notes:

- `InMemoryManagedDatastore` and `MockManagedDatastore` are not durable
  production stores.
- Constructors with `*_dev_only` install `AllowAllAuthorizer` and must stay out
  of production wiring.
- Built-in constructors are authoritative; `AuthorityMode::Shadow` is reserved
  for future integration work.
- Encrypted v2 config envelopes keep the original request source, idempotency
  key, request ID, request fingerprint, and apply plan inside AEAD ciphertext.
  Only a domain-separated lookup digest is stored in clear metadata. Legacy
  config-only envelopes remain readable.

### Datastore migration

The existing `ManagedDatastore::append_commit(StoredConfig)` and
`mark_confirmed` methods remain available for source compatibility. Config-bus
workers now call `append_commit_write(CommitWrite)` so the durable backend can
compare the current head and resolve a pending commit-confirmed decision in the
same atomic mutation. The default implementation fails closed. External
datastore implementations must override `append_commit_write` before upgrading
a live writer; do not emulate it by calling `mark_confirmed` and `append_commit`
as two operations. Built-in encrypted, in-memory, SQLite, and Openraft-backed
paths implement the atomic contract.

Treat `OutcomeUnknown` as a reconciliation result, not a blind retry hint. For
an unkeyed request, call `resolve_request_id(original_request_id)` and require a
matching durable result. For a keyed request, resubmit the exact original
operation, mode, candidate/rollback selector, caller-asserted base-version
precondition, principal context, and key; a semantic mismatch is an
idempotency collision. Issue no unrelated mutation
until the recovery fence has been cleared through the documented recovery
path. An exact keyed replay may establish the result while that fence remains
raised; it does not make the stale local snapshot writable. SQLite-backed
stores resolve either digest with one indexed, authoritative read, independent
of history length. If two authorities miss that index during a leadership
handoff, the compare-and-append loser reconciles from the same authoritative
index and returns the winner's exact result; its stale local snapshot remains
fenced until restore.

## Roadmap

- Keep storage behind the datastore trait.
- Add production authority modes only when a durable coordination design exists.

## Verification

Run:

```sh
cargo test -p opc-config-bus
```
