# Durable non-voting configuration consumption

`DurableConfigConsumer<C>` composes the actual authenticated `RemoteConfigWatch`
with `opc-persist::ConsumerCheckpointStore`. It retains the original committed
transaction, configuration version and complete payload. Its local generation
is only a SQLite CAS fence. It cannot author a configuration revision, join a
voter set, infer authoring provenance or manufacture a commit receipt.

## Startup and ownership

Construct `ConsumerCheckpointBinding` from the independently configured exact
configuration-consensus identity/epoch, schema digest, consumer SPIFFE identity,
tenant and nonzero opaque backing identity. Supply an absolute file path,
explicit durability choice and byte/time bounds. Provision only for an explicitly
new consumer. Ordinary restart uses `reopen`; never catch missing, corrupt or
wrong-scope storage and provision in its place. The coordinator checks the actual
watch binding against the admitted checkpoint before making a remote request.

`Durable` requires SDK filesystem qualification and reserved space. `Ephemeral`
is an explicit operator choice that waives filesystem durability qualification;
it still enforces authentication, scope, exclusive ownership and reopen rules.
It does not supply general-purpose production durability.

The single-owner consumer owns its checkpoint and ordered remote tail. Product
code supplies `ConfigConsumerApplyPort<C>` and owns candidate validation, impact
classification, addresses, runtime effects, concrete readback and serving
readiness. The SDK never calls product apply from its recovery operation.

A typical caller performs these explicit operations:

```rust,ignore
// `remote` is the existing authenticated RemoteConfigWatch<MyConfig>.
let checkpoint = ConsumerCheckpointStore::reopen(options, key_provider).await?;
let mut consumer = DurableConfigConsumer::new(remote, checkpoint, call_timeout).await?;
consumer.reconcile_runtime(&mut product).await?;
consumer.replace_snapshot().await?;
consumer.apply_observed(&mut product).await?;
// Each accepted tail item is durable before this method returns.
consumer.accept_next().await?;
consumer.apply_observed(&mut product).await?;
consumer.shutdown().await?;
```

Failures are explicit outcomes, not a retry loop hidden in this example. After
an interrupted apply, call `reconcile_runtime`. After a retired/compacted tail,
call `replace_snapshot`. A readback also retires the old tail and remote
observation; recover a new snapshot before another application. An unresolved
product result or unavailable checkpoint never permits blind replay.

## Ordered durable facts

| Boundary | Durable fact | Allowed next effect |
| --- | --- | --- |
| New provision | Empty authenticated checkpoint | Product readback, then authenticated recovery |
| Authenticated snapshot/tail received | Complete accepted target and monotonic floor, persisted and read back | Stage application explicitly |
| Before calling product apply | Complete target and last-known-applied predecessor in `ApplyPending` | Only that exact product application |
| Product returns `Applied` | Complete applied target checkpointed and read back | Report local application |
| Product returns `Rejected` | Pending intent cleared; predecessor retained | Report rejection without changing applied state |
| Cancellation, timeout or possible partial effect | Pending intent or uncertain checkpoint retained | Readback only |
| Reopen | Historical accepted/applied/pending facts; no current runtime proof | Product readback and fresh remote recovery |

`ConfigRuntimeReadback` supplies complete pending target/predecessor and historical
applied facts separately. The product may prove the exact target, exact predecessor
or complete absence. Conflict and indeterminate outcomes retain unresolved state.
The SDK does not turn an observed target or a restored applied flag into current
runtime authority. A product `Rejected` promises no effect; partial application
must be `Indeterminate`.

An explicit replacement snapshot can advance over compacted revisions. The old
applied fact stays intact until the product applies or reconciles the new target;
skipped intermediate revisions are never labelled applied. An ordered tail must
advance exactly one version. Older revisions, gaps, missing original transactions,
wrong schema/scope and same-version conflicting transactions or canonical payloads
are rejected. Exact duplicates are idempotent. Object-map ordering alone does not
change the canonical payload. Typed JSON integer values retain their exact
precision through acceptance, application and checkpoint restart, including
`u128`/`i128` boundaries; canonicalization never converts them through floating
point. The accepted floor survives restart and rejects a
lagging follower even when that follower otherwise authenticates correctly.

## SDK storage and custody

The checkpoint database has one row and no voter, authoring, principal, parent
transaction or configuration-commit table. The SDK creates its database and
`.opc-retained` admission sidecar exclusively, using private regular files and
an exclusive lifetime lock. Expected storage authentication binds exact parent,
sidecar and database identities plus a random provisioning nonce. This shares
the low-level retained SQLite admission with SDK #800, not its configuration
voter state or decoder.

An established open validates a bounded private copy of the database and recovery
journals before original SQLite recovery. Wrong scope/key, corrupt/truncated
storage and missing state fail without repairing or recreating authority. Partial
provisioning artifacts remain for explicit recovery. Changing backing or file
identity requires a separately admitted replacement plan, not copying an existing
checkpoint and silently adopting it. This is cooperative admission within a trusted
local filesystem/process domain; external actors must not mutate or relink live
SQLite files or journals. It is not isolation from a malicious same-UID process,
root or a hostile filesystem.

`opc-key::KeyPurpose::ConfigConsumerCheckpoint` and `ConsumerCheckpointAad`
separate checkpoint custody from configuration authoring and session protection.
The existing `opc-crypto` envelope and `KeyProvider` operations encrypt all
configuration facts before SQLite receives them. Reads use the envelope's exact
historical key; writes use the active key. A successful replacement reseals the
complete checkpoint, allowing ordinary provider rotation without keeping an
immutable old-key admission header. Products must retain historical key access
until the replacement is proven. Key outages never permit plaintext fallback.
Key-provider custody/qualification remains the provider's existing contract.

Plaintext checkpoint buffers are zeroizing and formatting is redacted. Generic
product `C` values remain inside the trusted product boundary; this API cannot
promise zeroization for an arbitrary product type. Only a value-free phase and
remote-observation boolean appear in status. The database still exposes ordinary
SQLite metadata, local generation, ciphertext length and envelope metadata; this
is authenticated payload encryption, not whole-volume encryption.

## Bounds, cancellation and shutdown

The payload limit includes the entire accepted, applied and pending state, not
just one configuration. It is between 1 byte and 16 MiB. Capacity planning must
allow the complete apply intent and predecessor; insufficient aggregate space
fails before product effects without truncating content. The existing transport
has its separate 8 MiB response cap.

The database/journal budget is explicit, at most 1 GiB. Its minimum accounts for
the maximum encrypted envelope rounded to SQLite pages, including each overflow
page's pointer and both schema/table root pages, then reserves three database
images plus 64 KiB for journals and sidecars. For a 16 MiB payload limit, the
smallest accepted storage budget is 50,532,352 bytes. Hard page limits, bounded copies,
transactional overflow-page reuse and WAL checkpointing bound physical retention.
No revision archive is retained. Reads and CAS authenticate the complete state;
CAS checks the exact last-read local generation and envelope digest. Generation
exhaustion fails closed instead of wrapping.

Each handle allows one outstanding storage operation and retains its task after
cancellation. Four read/write/admission blocking operations may run concurrently
per process; excess admission returns a bounded outcome. Each I/O or key-provider
stage has a caller-selected timeout of at most one hour. Coordinator encoding,
transport and product calls are separately bounded by the consumer call timeout.
Possible post-dispatch mutation is indeterminate, and a later write requires
actual readback. A cancelled tail poll discards that in-memory cursor, so it
cannot skip an uncheckpointed revision.

`shutdown` consumes the consumer, retires its stream and waits for owned storage
work before closing SQLite off the async executor. Timeout reports indeterminate
and does not claim that a still-running task released its lock. Dropping a handle
requests cancellation; explicit shutdown is required when the caller needs positive
completion. Neither shutdown nor Drop erases an unresolved product intent.

The shared connection wrapper holds admission through SQLite close and its
earlier authorizer removal. After the final SDK owner finishes, its guard
explicitly unlocks; an unrelated child that inherited the descriptor cannot
extend the completed operation. Failed acquisition never owns an unlock, and
closing an old inherited descriptor cannot release a successor's admission.

## Freshness limit and verification

An intact local checkpoint can be coherently rolled back with its backing. Its
authentication cannot establish a fresh global target. A live handle rejects a
regressing local generation/floor; a restarted handle cannot detect coherent
whole-store rollback by itself. Products must use independently fresh configured
authority before making serving or convergence claims. A follower-local watch
proves its committed applied history, not that it currently holds the latest global
revision. `Applied` status is only a local exact-target statement; the remote
boolean is neither a lease nor traffic authority. SDK #798 remains separate.

Synthetic tests compose real mutual TLS and checkpoint persistence. They cover
restart floors, same-version conflict, compacted-tail replacement and exact
continuation, missing/wrong identity/key/storage, key rotation and outage,
resource exhaustion, process loss within product apply and real SQLite WAL
transactions, cancellation, rejection and readback. The ordering detector is also
run with checkpoint-before-apply removed, and the restore detector with a mutated
runtime-applied flag. These checks do not establish fleet or production readiness.
