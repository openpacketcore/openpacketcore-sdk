# opc-session-testkit

Internal chaos and restore-evidence fixtures for session-store tests.

## Purpose

`opc-session-testkit` provides reusable test utilities for clock skew, quorum
partitioning, replica lag, and restore-evidence assertions around
`opc-session-store`.

## API Shape

- `SkewableClock::new()` and `with_base` wrap a virtual clock and allow
  positive or negative skew through `set_skew`.
- `ChaosTestkit::new(num_replicas)` builds fake fenced replicas with shared
  virtual time.
- `build_coordinator(local_replica_id, reached_replica_ids)` creates a
  validated `QuorumSessionStore` view where one explicit logical member is
  local and only selected replicas are reachable.
- `validated_topology(local_replica_id)` supplies immutable test topology to a
  production-shaped consumer without discarding replica identity metadata.
- `set_lag`, `set_online`, and `set_clock_skew` inject replica faults.
- `RestoreEvidenceAsserter::new(block_reasons)` exposes fluent assertions for
  stale-owner rejection, traffic blocking, and redaction-safe messages.

```rust,no_run
use opc_session_testkit::ChaosTestkit;
use std::time::Duration;

async fn partition() {
    let kit = ChaosTestkit::new(3);
    kit.set_lag(1, Some(Duration::from_millis(50))).await;
    let _coordinator = kit.build_coordinator(0, &[0, 2]).unwrap();
}
```

## Relationships

- Built on `opc-session-store` fake backends, fenced replicas, quorum store, and
  restore block reasons.
- Used by AMF-lite and session HA tests.

## Status Notes

- `publish = false`.
- Intended for tests only.
- Synthetic `.invalid` endpoints and SPIFFE-like IDs are test metadata, not
  live authenticated membership evidence.
- Clock skew is deterministic and based on `TokioVirtualClock`.
- Restore assertions panic like normal test assertions.

## Roadmap

- Add chaos knobs only when session-store or CNF tests need them.
- Keep restore assertions focused on externally visible safety properties.
- Keep the crate unpublished and test-only.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and dependent session tests.
- Run with: `cargo test -p opc-session-testkit`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
