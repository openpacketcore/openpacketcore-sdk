# opc-session-cache

Read-through session cache with replication-watch coherence checks.

## Purpose

`opc-session-cache` wraps a `SessionBackend` with a local cache that consumes
the backend replication log. It is designed for fast reads without allowing
stale cached records to hide replication gaps.

## API Shape

- `SessionCache::new(Arc<dyn SessionBackend>)` starts a background watch loop
  and returns `Arc<SessionCache>`.
- `get` serves from cache only when the watch cursor is coherent; otherwise it
  reads through to the backend.
- `invalidate`, `clear`, `len`, and `is_empty` manage local entries.
- `last_sequence`, `resync`, `is_syncing`, `is_watch_ready`, and
  `watch_error_count` expose replication-watch state.
- `SessionCache` implements `SessionBackend` and invalidates affected keys on
  successful wrapper mutations.

```rust,no_run
use opc_session_cache::SessionCache;
use opc_session_store::{FakeSessionBackend, SessionBackend};
use std::sync::Arc;

async fn cache() {
    let backend: Arc<dyn SessionBackend> = Arc::new(FakeSessionBackend::new());
    let cache = SessionCache::new(backend);
    assert!(cache.is_empty().await);
}
```

## Relationships

- Wraps the `opc-session-store::SessionBackend` trait.
- Consumes `ReplicationEntry` watch streams and ordered replication log
  sequence numbers from `opc-session-store`.

## Status Notes

- If the backend lacks watch or ordered-log capability, local cache reads stay
  bypassed and operations read through to the backend.
- If `max_replication_sequence` shows the watch cursor is lagging, the cache is
  cleared and local reads are bypassed.
- Sequence-zero watch/mutation entries and malformed rebuild prefixes fail
  before cache invalidation or backend delegation. If a backend reports the
  terminal `u64::MAX` head, the checked next-cursor calculation clears and
  bypasses the cache while retrying; it never wraps or terminates the watch
  task with a panic.
- Expired records are evicted on read.
- The cache is not a durability layer.

## Roadmap

- Keep correctness tied to backend replication sequence checks.
- Add cache policy knobs only when callers have measured needs.
- Keep mutation behavior conservative by invalidating keys on successful writes.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and tests.
- Run with: `cargo test -p opc-session-cache`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
