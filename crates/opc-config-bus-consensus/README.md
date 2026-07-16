# opc-config-bus-consensus

`opc-config-bus-consensus` is the outbound persistence adapter between
`opc-config-bus` and the existing `opc-persist::ConsensusConfigStore` Openraft
authority. It does not implement election, terms, membership, replication, or
snapshots. Those remain exclusively owned by `opc-consensus` and
`ConsensusConfigStore`.

The production composition deliberately puts encryption above this crate:

```rust,ignore
use std::sync::Arc;

use opc_config_bus::EncryptingManagedDatastore;
use opc_config_bus_consensus::RaftManagedDatastore;

// `consensus_store` was opened with a config-specific identity, voter set,
// SQLite path, snapshot directory, peers, and listener distinct from session
// consensus. Install `consensus_store.rpc_handler()` and initialize it first.
let durable = Arc::new(RaftManagedDatastore::<MyConfig>::new(Arc::new(
    consensus_store,
)));
let managed = EncryptingManagedDatastore::new(durable, key_provider);
```

`RaftManagedDatastore<C>` implements only
`ManagedDatastore<SealedConfig<C>>`. It cannot accept plaintext `C` and never
owns a `KeyProvider`; Openraft therefore receives authenticated ciphertext,
lineage/lifecycle metadata, a digest-only replay index, and a product-neutral
redacted root audit marker.

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
- for command/RPC revision 3, drain config writers, stop the complete config
  voter set, upgrade every member, and restart the set together. Revisions 1
  and 2 remain replayable only under their original semantics; there is no
  mixed-revision downgrade.

The broader multi-group failure and restart qualification tracked by issue
`#250` remains required before this crate's source-build-only status can be
reconsidered.
