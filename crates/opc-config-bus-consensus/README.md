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

## Authenticated remote recovery and watch

`ConfigWatchServer` exposes the same follower-local, publication-safe view to
remote config consumers. It is deliberately a read adapter, not an Openraft
transport: its closed wire grammar contains only `Recover` and `Page`, and it
cannot vote, replicate, rebuild state, submit config, or enter a read-index
barrier. A consumer may connect to any configured follower without funneling
catch-up traffic through the writer. Construction fails unless the supplied
bus has `AuthorityMode::Shadow`; an authoritative writer bus cannot be exposed
accidentally.

Every bounded page uses a fresh mutual-TLS connection and proves all of the
following before dispatch:

- the dedicated `opc-config-watch/1` ALPN and exact contract profile;
- the existing `ConfigConsensusIdentity` (cluster, configuration, and epoch);
- the product's exact `SchemaDigest`, checked again on every decoded snapshot
  and page entry before caller visibility;
- the server's exact configured SPIFFE ID; and
- the client's exact configured SPIFFE ID and membership in the server's
  bounded reader allowlist.

Requests are limited to 16 KiB before allocation, responses to 8 MiB, pages to
64 complete revisions, long polls to 30 seconds, and one listener to 32 active
connections. Reads, writes, TLS/application handshakes, backend work, reconnect
backoff, and shutdown are time-bounded. A peer that disconnects while a page is
waiting cancels that read-only operation. A peer that stops reading cannot hold
a server slot past the write deadline. Oversized snapshots or one-entry pages
fail with `ConfigWatchError::FrameTooLarge`; configure the config bus's
serialized-candidate admission limit at or below the wire response budget,
including the small JSON envelope overhead.

The wire byte cap prevents untrusted peer-controlled allocation. The trusted
local `OpcConfig` source is materialized before JSON encoding, so a full
64-entry page can transiently retain up to 64 cloned configs even when adaptive
encoding later reduces the transmitted page. Products with large configs must
include that trusted heap bound in capacity planning and set candidate
admission limits accordingly; this adapter does not introduce a second payload
storage or streaming framework.

The remote payload is plaintext configuration protected by mutually
authenticated TLS and exact application authorization. At-rest ciphertext and
HKMS key handles remain unchanged: Openraft, its log, snapshots, and SQLite
still receive only the sealed representation. Decryption occurs in the local
`EncryptingManagedDatastore` before the trusted Shadow bus serves an authorized
consumer, just as it does for local config readers.

Minimal composition:

```rust,ignore
use std::sync::Arc;

use opc_config_bus::ConfigBus;
use opc_config_bus_consensus::{
    fixed_config_watch_endpoint, ConfigWatchClientBinding, ConfigWatchServer,
    ConfigWatchServerBinding, RemoteConfigWatch,
};

// `managed` is an EncryptingManagedDatastore over this node's local
// RaftManagedDatastore. It carries the CommittedRevisionSource trust marker.
let shadow = Arc::new(ConfigBus::restore_shadow(managed).await?);
let server_binding = ConfigWatchServerBinding::try_new(
    consensus_identity,
    local_server_spiffe_id,
    vec![authorized_consumer_spiffe_id.clone()],
)?;
let server = ConfigWatchServer::new(
    shadow,
    authenticated_server_tls,
    server_binding,
)?;
let (server_handle, bound_address) = server
    .listen(listen_address)
    .await?;

let remote = RemoteConfigWatch::<MyConfig>::new(
    ConfigWatchClientBinding::new(
        consensus_identity,
        authorized_consumer_spiffe_id,
        expected_server_spiffe_id,
        expected_schema_digest,
    ),
    fixed_config_watch_endpoint(bound_address),
    authenticated_client_tls,
);
let recovery = remote.recover_from(last_applied_version).await?;
let (snapshot, mut committed_tail) = recovery.into_parts();
install_complete_snapshot(snapshot)?;
while let Some(revision) = committed_tail.next().await {
    apply_committed_revision(revision?)?;
}

server_handle.shutdown().await;
```

`fixed_config_watch_endpoint` is convenient for an already-resolved address.
Production discovery can supply `ConfigWatchAddrResolver`; it runs before every
reconnect. Resolution never changes the exact expected server SPIFFE ID or
consensus scope. To move to a differently identified follower, construct a new
client binding and resume from the last caller-applied `ConfigVersion`.

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
- keep the remote server on a dedicated listener/ALPN, supply exact reader
  SPIFFE identities and the product schema digest, and set the config candidate
  byte admission limit so one complete revision fits the response-frame
  contract;
- for command/RPC revision 3, drain config writers, stop the complete config
  voter set, upgrade every member, and restart the set together. Revisions 1
  and 2 remain replayable only under their original semantics; there is no
  mixed-revision downgrade.

The broader multi-group failure and restart qualification tracked by
`GAP-001-006` remains required before this crate's source-build-only status can
be reconsidered. The frozen v2 and v4 session-HA candidate profiles deliberately
remain byte-identical and therefore retain their historical 26-crate closure;
they do not claim qualification for this adapter. A locked Cargo-metadata test
checks the current 27-crate source-build closure independently. An additive
follow-up qualification change must introduce candidate evidence before this
adapter can inherit a session-HA qualification claim.

The remote qualification uses real TCP and mutual TLS to prove fresh recovery,
lagging catch-up, exact identity and scope rejection, wrong-ALPN rejection,
schema/profile rejection, oversized and partial-frame failure, all-slot
cancellation isolation, material rotation, maximum-version EOF, adaptive page
continuation, and cursor-preserving follower replacement. The underlying
config-consensus tests separately prove that the served rows are identical local
state-machine-applied history across a real three-node Openraft leader change;
the transport deliberately reuses that authority instead of reproducing it.
