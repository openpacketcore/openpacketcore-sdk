# opc-config-bus-consensus

`opc-config-bus-consensus` is the outbound persistence adapter between
`opc-config-bus` and the existing `opc-persist::ConsensusConfigStore` Openraft
authority. It does not implement election, terms, membership, replication, or
snapshots. Those remain exclusively owned by `opc-consensus` and
`ConsensusConfigStore`.

The production composition deliberately puts encryption above this crate:

```rust,ignore
use std::sync::Arc;

use opc_config_bus::{ConfigAuthorityPort, EncryptingManagedDatastore};
use opc_config_bus_consensus::RaftManagedDatastore;

// `consensus_store` was opened with a config-specific identity, voter set,
// SQLite path, snapshot directory, peers, and listener distinct from session
// consensus. Install `consensus_store.rpc_handler()` and initialize it first.
let durable = Arc::new(RaftManagedDatastore::<MyConfig>::new(Arc::new(
    consensus_store,
)));
let authority: Arc<dyn ConfigAuthorityPort> = Arc::new(durable.config_authority());
let managed = EncryptingManagedDatastore::new(Arc::clone(&durable), key_provider);

// Build ConfigBus from `managed`, then install the same `authority` on both
// the gNMI and NETCONF server cores with `with_config_authority(...)`.
```

`RaftManagedDatastore<C>` implements only
`ManagedDatastore<SealedConfig<C>>`. It cannot accept plaintext `C` and never
owns a `KeyProvider`; Openraft therefore receives authenticated ciphertext,
lineage/lifecycle metadata, a digest-only replay index, and a product-neutral
redacted root audit marker.

`RaftManagedDatastore::config_authority()` returns a
`ConsensusConfigAuthority` over that exact `ConsensusConfigStore`. The adapter
uses its local-only Openraft read-index/apply barrier, never a second leader
tracker. A local leader returns `LocalAuthority`; a follower returns `Retry`
with the stable numeric consensus node ID when known; unavailable leadership,
membership drift, or local apply lag fails closed. The numeric ID is only a
routing hint. Products that need a network endpoint must resolve it through
their fixed, authenticated roster rather than treating it as an address.

The authority check also compares the config bus's payload-free
`{tx_id, version}` projection head with the canonical local state-machine head
while all fixed proposal-admission slots are drained under the existing
operation deadline. A caught-up newly elected node with a stale process-local
projection is therefore unavailable, not authoritative. The guard releases all
proposal permits on every return path. When the canonical store is empty, an
empty bootstrap head may attempt only a `Write` so the genesis commit can be
created; `LinearizableRead` remains unavailable because no durable content yet
proves that every pod bootstrapped the same payload.

It also implements the explicit
`CommittedRevisionSource<SealedConfig<C>>` trust marker. Its committed-head,
ordered-history, and apply-notification methods read only the contiguous,
publication-safe prefix of the local Openraft state-machine-applied SQLite
view. A row remains hidden while its `recovery_required` marker is set; the
locally applied clear wakes waiters, which then repage. These methods do not
enter a linearizable read barrier, contact the leader, or fan out through the
writer.
A follower may therefore serve a gap-free local catch-up stream while
temporarily behind the leader; it never serves an entry Openraft has not
committed, applied, and cleared for publication locally. Durable repaging,
rather than the notification, is the ordering authority.

Composing `EncryptingManagedDatastore` outside this adapter propagates the
marker and decrypts the locally applied head and history pages. The marker is
not available for arbitrary `ManagedDatastore` implementations, so a Shadow
`ConfigBus` cannot accidentally be restored from an unproven feed.

Strict operational requirements:

- use a config-specific `ConfigConsensusIdentity`, roster, listener port,
  database path, and snapshot directory;
- install the authenticated consensus RPC handler before cluster
  initialization;
- compose `EncryptingManagedDatastore` outside the Raft adapter;
- treat `StoreErrorCode::OutcomeUnknown` as requiring authoritative replay
  lookup, not an unconditional retry;
- keep rollback labels operator-safe and free of secrets because labels are
  clear lifecycle metadata used for indexed lookup;
- serve committed watches from the local follower adapter and treat
  `HistoryCursorAhead` as local lag, never as authority to move a consumer
  backward;
- for command/RPC revision 3, drain config writers, stop the complete config
  voter set, upgrade every member, and restart the set together. Revisions 1
  and 2 remain replayable only under their original semantics; there is no
  mixed-revision downgrade.

The broader multi-group failure and restart qualification tracked by issue
`#250` remains required before this crate's source-build-only status can be
reconsidered. The frozen v2 and v4 session-HA candidate profiles deliberately
remain byte-identical and therefore retain their historical 26-crate closure;
they do not claim qualification for this adapter. A locked Cargo-metadata test
checks the current 27-crate source-build closure independently. An additive
follow-up qualification change under #250 must introduce candidate evidence
before this adapter can inherit a session-HA qualification claim.

The adapter does not expose a config-watch network protocol. It makes the
ordered stream serviceable inside each authority process and exposes
transport-neutral page/cursor types through `opc-config-bus`; a separate
authenticated, bounded RPC adapter is still required for a remote dataplane
process. Issue #256 remains open until that boundary and its process-level
qualification exist.
