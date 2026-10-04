# ADR 0024: Route operation exclusion by conflicting keys

## Status

Implementation contract. Qualification and performance measurements are separate.

## Decision

Clones of one `LinuxRouteSteeringBackend` share a scheduler that excludes
intersecting kernel keys. An exact route reserves its canonical address family,
destination prefix, and table. An exact rule reserves its family and priority;
only same-table, source-only rules with proven disjoint non-wildcard source
prefixes may proceed concurrently at that priority. Scheduling uses the same
prefix predicate as Linux readback. Unknown, overlapping, destination-qualified,
mark-qualified, and wildcard relationships retain exclusion.

A paired operation reserves both keys together before dispatch. A collection
operation reserves its complete route family/table and rule family/priority.
Legacy mutation methods reserve the whole backend because they include broad
deletion semantics. Complete collection reconciliation retains its existing
authoritative desired-set and orphan-deletion contract. It must not be used to
submit a partial desired set for an active shared scope.

The scheduler admits at most 64 blocking workers per backend. Waiting callers
remain asynchronous and occupy no blocking worker. Earlier conflicting waiters
retain order, while unrelated waiters can progress. Consumers remain responsible
for bounded ingress and deadlines; this is a worker bound, not a request queue
capacity or throughput claim.

Cancellation before dispatch removes the queued request. Once dispatched, the
blocking worker retains its permit through effects, readback, and any inverse.
Dropping its async observer cannot allow a conflicting successor to overlap that
work. The caller must reconcile the result through the existing exact readback
contract. Scheduler state grants exclusion only: it does not replace ownership
markers, exact object identity, validation, or external writer fencing.

The deterministic mock uses the same source-only sibling predicate as Linux
for exact readback and removal. Foreign and ambiguous candidates are retained
and rejected. Independent scheduler admission does not make kernel multipart
dumps atomic or allow a partial dump to prove absence.

## Evidence and limits

The preserved initial tests fail when a paused transport blocks an unrelated
owned-scope snapshot and when mock exact-rule readback rejects an owned disjoint
sibling. Production-adapter tests additionally pause one pair during rule
creation, complete a different same-priority pair, reject the first create, and
verify that rollback removes only its route. The cancelled-observer variant
checks that a same-key follower remains excluded until that inverse completes.
Scheduler tests cover conflicting selectors, queued cancellation, and the worker
bound. Existing collision, unknown readback, marker, and collection-recovery
tests remain required.

These tests use synthetic transports. They do not establish privileged kernel
behavior, deployment capacity, latency, or packet forwarding. Separate backend
instances and external writers still require one coordinated namespace-local
ownership authority.
