# opc-session-testkit

Internal Openraft and restore-evidence fixtures for session-store tests.

## Purpose

`opc-session-testkit` provides reusable test utilities for deterministic clock
skew, controllable in-process consensus paths, and restore-evidence assertions
around `opc-session-store`. It exercises the production
`ConsensusSessionStore` adapter; it does not implement a second quorum,
sequencing, or repair algorithm.

## API Shape

- `SkewableClock::new()` and `with_base` wrap a virtual clock. `set_skew`
  applies checked positive or negative skew, including saturation at timestamp
  limits.
- `ConsensusTestCluster::start(1)` forms an explicit Openraft lab singleton.
  `ConsensusTestCluster::start(3)` forms a descriptor-only, three-member
  Openraft fleet with one distinct file-backed SQLite database per member.
- `store(index)` returns a clone of that member's production
  `ConsensusSessionStore` adapter.
- `set_node_online(index, online)` enables or disables every in-process
  consensus path to and from one member. `wait_node_durable_ready(index)` waits
  for that member to complete a fresh Openraft linearizable barrier.
- `RestoreEvidenceAsserter::new(block_reasons)` exposes fluent assertions for
  stale-owner rejection, traffic blocking, and redaction-safe messages.

```rust,no_run
use opc_session_testkit::ConsensusTestCluster;

async fn partition_and_recover() {
    let cluster = ConsensusTestCluster::start(3).await;

    cluster.set_node_online(2, false);
    let store = cluster.store(0);
    assert_eq!(store.topology().configured_members(), 3);

    cluster.set_node_online(2, true);
    cluster.wait_node_durable_ready(2).await;
}
```

## Relationships

- Builds descriptor-only `ValidatedQuorumTopology` values and supplies each
  node's local SQLite backend and exact remote `SessionConsensusPeer` map
  separately.
- Uses controllable in-process peer adapters, not `opc-session-net`, mTLS, DNS,
  or a second consensus implementation.
- Used by AMF-lite, IPsec ownership, cache, and session-store tests.

## Status Notes

- `publish = false`; this crate is test-only.
- Synthetic `.invalid` endpoints and SPIFFE-like IDs are descriptor metadata,
  not live authenticated network membership evidence.
- Node isolation exercises Openraft quorum loss and healing after a fleet has
  formed. It does not by itself qualify cold-start races, multi-process
  restart/rejoin, legacy-fork repair, real mTLS transport, or carrier failover.
- Long-running network, resource, and soak qualification remains #143. Watch
  handoff and bounded replication-log cursor/retention semantics are
  implemented under #145/#171.
- Restore assertions panic like normal test assertions.

## Roadmap

- Add fault controls only when a session-store or CNF acceptance test needs a
  specific observable safety property.
- Keep consensus faults at the peer boundary so tests continue to exercise
  Openraft as the only authority.
- Keep the crate unpublished and test-only.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and dependent session tests.
- Run with: `cargo test -p opc-session-testkit`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
