# S-NAPTR path filtering

STATE: needs-review

Proposed addition to [bounded S-NAPTR discovery](../rfc/031-bounded-snaptr-discovery.md)
for [issue #1276](https://github.com/openpacketcore/openpacketcore-sdk/issues/1276).

## Tests first

These regressions precede implementation after design acceptance. Use synthetic
DNS fixtures, fixed seeds and controlled response ordering.

| Case | Required observation |
| --- | --- |
| Issue example | Direct `a` terminals have NAPTR orders 10, 20, 30: `u.example.invalid` reaches X, `b.example.invalid` reaches Y, `a.example.invalid` reaches X. Exclude only `u`. Require B/Y then A/X, including selection of A/X when Y is unusable. Assert that A's path establishes X's new rank. |
| Seeded ordering | Equal-order/preference RFC draws and equal-order 3GPP weighted draws preserve their original relative order with the same seed. Filtering must not draw again. Include nested delegation where ancestor rank outranks a child's numeric order. |
| SRV | Repeat shared-endpoint exclusion with SRV priority and weighted draws, including zero weights, explicit ports and multiple addresses. Assert the surviving SRV path and its raw selection fields. |
| Response order | Reverse wire RRset order and independently force replies to complete in reverse traversal order. The same seed and exclusions produce the same endpoints and ranking paths. |
| Provenance and references | Remove primary and alternate paths separately. Keep endpoints unique; promote the best surviving path; rebuild every host, candidate and path index. No reference or primary record chain may name excluded data. |
| Freshness | Remove a uniquely short-lived path and check expiry against the remaining original deadlines; retain shared RRset minima and both resolver freshness bounds. Cover staggered observations, zero/high-bit TTLs and already expired records. Filtering reads no clock and restarts no TTL. |
| Partial results and failures | Filter capped, omitted-alternate, refused and failed results. Preserve coverage, incomplete-host flags, failure bounds and response diagnostics; do not recover omitted paths or claim exhaustive coverage. |
| Empty and invalid inputs | Excluding every path returns `Ok(None)`. Address, SRV, legacy and mixed answers lacking complete S-NAPTR metadata return `InvalidQuery` without invoking the predicate. Neither case creates a DNS negative or fallback authority. |
| Identity and composition | Keeping every path returns an equal answer with identical order, weights, provenance, references, expiry and coverage. Repeated pure filtering equals conjunction of the predicates. Filtering a cached answer leaves the cache and its scheduling state unchanged. |
| Bounds | The predicate runs exactly once per retained path; no DNS I/O occurs. Include the retained ranks in the existing maximum-payload size regression. |

## API

Add one borrowed operation to `DnsAnswer`:

```rust,ignore
pub fn filter_snaptr_paths<F>(&self, keep: F) -> Result<Option<Self>, DnsError>
where
    F: FnMut(&SnaptrPath) -> bool;
```

`SnaptrPath` already exposes `terminal_host()`, timed records, NAPTR hops and
optional SRV provenance. The predicate returns true to retain that derivation.
Validate that the whole answer has S-NAPTR metadata and retained ranks before
calling it, then visit each retained path once in original traversal order.
`Some` contains a nonempty filtered answer; `None` means consumer policy excluded
every retained path. The borrowed original remains unchanged. No new DNS error
kind, resolver option or consumer-side traversal algorithm is needed.

## Rank and provenance

Keep each completed path's existing lexicographic traversal rank privately when
`dns_snaptr::Traversal::finish_answer` publishes it. Its components are positions
in the original seeded NAPTR and SRV orders, followed by the address position.
They preserve ancestor precedence, the selected NAPTR policy and SRV weighted
selection. Do not reconstruct ranks from raw order/preference/weight fields or
renumber these components after filtering. Path equivalence and deduplication
continue to ignore rank metadata; equivalent derivations retain their best rank.

Remove rejected paths, then drop endpoints with none left. For each survivor,
the minimum original rank of its remaining paths establishes endpoint order.
Sort by that rank, preserving input order for ties, and regenerate the existing
dense selection weights from the final endpoint indices. Keep remaining paths
in rank order: `candidate.snaptr().unwrap().paths()[0]` identifies the exact
ranking path, and `candidate.records()` refers to that path's record chain.
No public rank representation is needed.

Rebuild host groups and address/path references from the survivors. Preserve the
existing `SnaptrHost::rank()` meaning: the first endpoint index in the new answer.
Keep each surviving host group's original `complete()` value. Origins, filters,
terminal names, hops, SRV fields, labels, transports and ports retain their
original values. The identity predicate and ordinary unfiltered discovery keep
all existing public results unchanged.

## Freshness, coverage and ownership

Retained records keep their original TTLs and observation times, including
RRset minima established before discovery filtering. Compute answer expiry over
all remaining primary and alternate chains and preserve the original ordinary
and negative freshness bounds. Removing a path can remove its unique earlier
record deadline; it cannot remove a shared RRset minimum or either failure bound.
There is no new observation time or freshness grant for expired retained data.

Coverage describes the original bounded discovery. Copy every `SnaptrCoverage`
field unchanged; consumer exclusions do not increment application/protocol
`filtered_records` or erase omissions, refusals and failures. Filtering cannot
backfill an endpoint/path cap or evaluate a predicate against an unvisited or
failed path. Existing failure bounds remain conservative: do not reinterpret
which failures affect freshness using the reduced endpoint set. Response sources,
question outcomes, branch failures and root diagnostics remain on the original
`DnsClientResponse`; this answer-only operation does not rewrite them.

Apply the operation as a consumer selection view, including after cache lookup.
Publish the original DNS result to the shared cache: its key contains no consumer
predicate. A filtered answer's record expiry does not replace the cache's
`fresh_until`, retry state or last-good policy. `Ok(None)` is a local empty
selection, never authoritative absence or permission for protocol downgrade.

The operation uses only the retained bounded payload: at most 16 endpoints,
four paths per endpoint and 16 rank components per path. Account for rank storage
inside the existing 2 MiB metadata bound. No additional DNS work, dependencies,
background task or durable format is introduced. After acceptance, implement in
`opc-peer-discovery`, retain the behavioral failure evidence, and qualify the
crate and applicable repository gates on the final candidate.
