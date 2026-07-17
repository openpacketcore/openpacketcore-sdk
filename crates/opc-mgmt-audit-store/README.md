# opc-mgmt-audit-store

Production SQLite adapter for `opc-mgmt-audit::AuditSink`.

The crate is currently source-build-only because its `opc-persist` dependency
remains behind the repository-wide issue #143 publication gate. That packaging
status does not weaken the runtime durability contract described below.

The adapter synchronously acknowledges an event only after the reference
`opc-persist` backend commits the event, retention update, and authenticated
anchor in one durable transaction. Opening the sink verifies the complete
retained chain and fails closed on unsafe/ephemeral storage, a wrong audit key,
or the first broken chain link.

```rust,no_run
use opc_mgmt_audit::AuditSink;
use opc_mgmt_audit_store::DurableAuditSink;
use opc_persist::{AuditKey, ManagementAuditRetention};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let key = AuditKey::new(load_audit_key_from_kms())?;
let retention = ManagementAuditRetention::try_new(100_000)?;
let sink = DurableAuditSink::open(
    "/var/lib/openpacketcore/management.db",
    128 * 1024 * 1024,
    key,
    retention,
)
.await?;

// Management servers use `&sink` or `Arc<dyn AuditSink>` and fail closed when
// `record` does not durably acknowledge the event.
let _sink: &dyn AuditSink = &sink;
# Ok(())
# }

# fn load_audit_key_from_kms() -> [u8; 32] { [7; 32] }
```

Only the existing structured audit fields are persisted: request id, tenant,
principal, stable transport/operation/outcome/reason codes, predicate-free
schema paths, and an optional bounded transaction id. Request values, payloads,
list-key predicates, and free-form backend error text are never accepted by the
durable schema.

Retained records are retrieved through bounded, absolute-sequence pages. A
cursor below the authenticated low-water mark returns a typed pruned-cursor
error; it never silently skips missing history.

Normal appends authenticate the retained low-water and terminal boundaries in
constant work. Because one append adds one record, fixed retention can prune at
most the already-authenticated low-water row; its successor must authenticate
as the next low-water before a later append can prune it. Changing the retention
cap first verifies the complete retained chain. SQLite's connection-local data
version detects commits from another connection and makes the next append run
the exceptional orphan-child check, while normal single-writer appends retain
their constant-work boundary.

The worker admits at most 64 queued operations. A full queue fails immediately,
and an admitted operation must acknowledge within five seconds. An
acknowledgement timeout is deliberately an outcome-unknown failure: the atomic
append may commit later, but the sink never reports success without the durable
acknowledgement. Shutdown also waits at most five seconds; a stalled worker is
detached and counted by `durable_audit_worker_detachments()` rather than hanging
process shutdown.

The authenticated local anchor detects record alteration, deletion, reordering,
and an anchor replay that disagrees with the retained rows. It cannot detect a
coherent rollback of the entire database (or matching older rows and anchor)
without an external monotonic checkpoint. Deployments requiring storage
anti-rollback must bind such a checkpoint through their KMS/platform controls;
that external authority is intentionally outside this local adapter.

## Verification

```sh
cargo test -p opc-mgmt-audit-store
cargo clippy -p opc-mgmt-audit-store --all-targets -- -D warnings
```
