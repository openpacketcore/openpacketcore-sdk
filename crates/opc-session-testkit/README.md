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

## Production-mTLS Candidate Harness

The private `opc-session-quorum-node` binary now has a default production-mTLS
path for qualification work. It loads one coherent Kubernetes-style projected
SVID generation through `ProjectedSvidSource`, pins the configured local SPIFFE
ID in one shared `TlsMaterialController`, and gives the resulting authenticated
client/server configs to
`RemoteSessionConsensusPeer::new_profiled_with_resolver` and
`SessionConsensusServer::new`. The manifest still performs the exact peer
SPIFFE-ID check after certificate-chain authentication.

The candidate build has no default features:

```console
cargo build -p opc-session-testkit --bin opc-session-quorum-node --no-default-features
cargo test -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features
```

Its strict node config accepts `projected_mtls` with an absolute projected
volume root inside the node workspace, normalized relative certificate/key/
bundle names, a bounded polling interval, and a finite validated connection
lifecycle policy. The control protocol exposes only redaction-safe evidence:
authoritative TLS material status and expiries, an explicit reauthentication
generation, a directed fresh authenticated-TLS plus exact manifest-bound
consensus-bootstrap proof, durable readiness, and fixed-cardinality lifecycle
counters. A directed proof succeeds only after that path's resolver count has
advanced at the requested reauthentication generation, independently of the
generation echoed in the control reply. It may end in the exact authenticated
`Protocol` application result and therefore does not claim valid private
ReadBarrier handler execution. The protocol never returns material, SPIFFE IDs,
routes, or filesystem paths.

`qualification/v1/session-mtls-candidate-evidence.schema.json` deliberately
requires `experimental = true`, `qualification_complete = false`,
`insecure_test_enabled = false`, and
`counts_for_seamless_tls_rotation = false`. This v1 schema accepts exactly the
current three-process test and its six directed paths, and requires all seven
coarse candidate gaps encoded by this checkpoint. Those seven gaps are not an
exhaustive #164 acceptance inventory. The checkpoint proves initial
projected-SVID mTLS fleet formation; it is not seamless-rotation qualification.

## Status Notes

- `publish = false`; this crate is test-only.
- Synthetic `.invalid` endpoints and SPIFFE-like IDs are descriptor metadata,
  not live authenticated network membership evidence.
- Node isolation exercises Openraft quorum loss and healing after a fleet has
  formed. The multi-process foundation additionally observes and stops the
  actual leader in 3- and 5-member fleets, requires a different higher-term
  survivor, records a generation read while the old leader is down, and bounds
  same-disk restart/catch-up.
  These loopback plaintext tests do not by themselves qualify cold-start races,
  deployed-network/mTLS behavior, complete crash matrices, multi-node
  restart/rejoin, legacy-fork repair, or carrier failover.
- The production-mTLS candidate does not yet cover five-member
  multiprocess/deployed evidence, old/new trust overlap, projected material
  replacement under continuous durable traffic, rejection after overlap
  removal, certificate-expiry retirement, bounded drain/reconnect evidence, or
  the platform/soak matrix. The three- and five-voter in-process mechanics are
  covered separately in `opc-session-net`; these remaining cases are still
  required before #164/#158 can be closed.
- Long-running network, resource, and soak qualification remains #143. Watch
  handoff and bounded replication-log cursor/retention semantics are
  implemented under #145/#171.
- The machine-readable profile remains `experimental` with
  `qualification_complete = false`. Its exact Openraft git pin and 26-crate
  source-build gate may be removed only after an official fixed stable release,
  registry checksum pin, and full #143 requalification.
- Restore assertions panic like normal test assertions.

## Roadmap

- Add fault controls only when a session-store or CNF acceptance test needs a
  specific observable safety property.
- Keep consensus faults at the peer boundary so tests continue to exercise
  Openraft as the only authority.
- Keep the crate unpublished and test-only.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and dependent session tests.
- Run production-mTLS qualification with:
  `cargo test -p opc-session-testkit --test qualification_mtls_multiprocess --no-default-features`.
- Run the historical plaintext foundation explicitly with:
  `cargo test -p opc-session-testkit --features foundation-insecure --test qualification_multiprocess`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
