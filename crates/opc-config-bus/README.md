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
  `StoredConfig`, `CommitWrite`, `CommitWriteReceipt`,
  `ConfirmedCommitResolution`, `SealedConfig`, `StoredRequestFingerprint`,
  `StoreError`, `StoreErrorCode`, `DriftState`, and `AuthorityMode`.
- Writer-of-record gate types: `ConfigAuthorityPort`,
  `ConfigAuthorityOperation`, `ConfigAuthorityOutcome`,
  `ConfigProjectionHead`, and the bounded, redaction-safe `ConfigLeaderHint`.
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

`ConfigAuthorityPort` is the product-neutral management admission seam for an
HA writer of record. gNMI and NETCONF servers consult it before a write or an
opt-in linearizable read; `Retry` and `Unavailable` are fail-closed results.
The port does not create another election, membership, or replication
authority. `opc-config-bus-consensus` adapts the existing
`ConsensusConfigStore` Openraft result to this port.

`EncryptingManagedDatastore` returns a `CommitWriteReceipt` containing the
exact digest persisted with each new encrypted record. That SHA-256 value
covers the complete plaintext envelope bytes: the format marker plus the
serialized config, request source, idempotency key, apply plan, request
fingerprint, and request ID. It is not a hash of the naked config and must not
be used to compare config equality across otherwise different requests.

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
- Built-in constructors are authoritative. A management server presented with
  `AuthorityMode::Shadow` and no authority port rejects writes and
  linearizable reads; it never treats the local mirror as writer of record.
- Encrypted v2 config envelopes keep the original request source, idempotency
  key, request ID, request fingerprint, and apply plan inside AEAD ciphertext.
  Only a domain-separated lookup digest is stored in clear metadata. Legacy
  config-only envelopes remain readable. A record written before
  plaintext-digest persistence can also be restored and replayed, but its
  replay result has no `committed_revision`. The SDK never reconstructs a hash
  from reserialization. An authority-enabled management endpoint fails that
  response closed until an explicitly reconciled new write/reseal exists.

### Datastore migration

The existing `ManagedDatastore::append_commit(StoredConfig)` and
`mark_confirmed` methods remain available for source compatibility. Config-bus
workers now call `append_commit_write_with_receipt(CommitWrite)`. Its default
delegates to `append_commit_write(CommitWrite)`; receipt-capable wrappers opt in
through `commit_receipts_include_plaintext_digest`. The durable backend still
compares the current head and resolves a pending commit-confirmed decision in
the same atomic mutation. External datastore implementations must override
`append_commit_write` before upgrading a live writer; do not emulate it by
calling `mark_confirmed` and `append_commit` as two operations. Built-in
encrypted, in-memory, SQLite, and Openraft-backed paths implement the atomic
contract.

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

- Keep storage and authority admission behind their narrow ports.

## Verification

Run:

```sh
cargo test -p opc-config-bus
```
