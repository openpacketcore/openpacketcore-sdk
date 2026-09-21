# OPC-SDK-RFC-018: Never-Admitted Selector Namespace Relocation

**Status**: Experimental implementation candidate

**Version**: 1.0.0

**Date**: 2026-09-21

## Scope

RFC 016 binds a protected permanent selector ledger to one backend namespace.
An installation that has never admitted a group can nevertheless retain that
binding after its backend namespace is replaced. Ordinary opening and
provisioning correctly refuse the different binding. An empty replacement,
missing marker, different owner, or convenient device name cannot establish
the safety of admitting traffic in it.

This RFC defines a separate SDK operation,
`GtpuSessionSelectorNamespaceAuthority::relocate_never_admitted_protected`.
It consumes a backend-minted bootstrap and positive historical proof in the
same protected ledger. It does not reset, retire, replace or fork that ledger.
Ordinary opening and provisioning retain their exact-binding contract.

This operation cannot recover an active or formerly used namespace. RFC 017's
qualified mutable-graph restore remains separate and does not authorize lost
marker or binding recovery. General restart recovery, old kernel graph
retirement, traffic continuity and deployment readiness are outside this
narrow capability.

## Required historical proof

Under the existing exclusive durable worker lease, the SDK must read an
existing complete permanent ledger with the same stable device, protected
storage scope and capacity. Starting a relocation requires `Bound`, generation
zero, no decommission intent, and empty selectors, groups, unadmitted groups,
reattach edges, bearer edges, canonical desired descriptors, published atoms
and tombstones. Every prior relocation must have a valid permanent lineage.

Missing, legacy, corrupt and foreign records confer no authority. Active,
installing, retiring, retired, poisoned, sealed-unadmitted and decommissioned
histories all refuse relocation, including when a replacement backend is
empty. A nonzero generation alone is enough to refuse it.

Every group effect requires a prior durable admission CAS. An earlier worker
paused before that CAS cannot write through an expired or replaced fencing
credential. A worker paused after admission leaves permanent history that
rejects this operation. Thus the historical proof excludes group effects
without treating absence of a backend object as historical proof. The old
backend may still retain its empty binding; this operation grants no authority
to erase it.

## Commit and effect order

1. Acquire the unchanged protected worker lease and read the exact ledger.
2. Validate historical proof and the exact replacement bootstrap. A previously
   used pin commitment cannot become a successor, including a return to any
   older location.
3. Generate a fresh backend epoch. Preserve the ledger key, ledger identity,
   device, storage scope, capacity, selector secret and every history row.
4. Append the exact predecessor/successor row and CAS/read back `Initializing`
   before any replacement backend effect. Rebind the existing secret
   commitment to the successor pin; do not generate a new selector secret.
5. Attempt a separately typed, read-only pristine-binding inspection with a
   fresh mutation window. It must prove the exact marker, no terminal fence,
   current full graph and every empty authority map under the host lock. It
   can complete an earlier publication whose acknowledgement was lost. If no
   such proof is obtained, only the unchanged ordinary provisioning effect
   may run; its original fresh-empty/stopped-recovery requirements remain.
6. Consume the exact pristine-readback or provisioning receipt, CAS/read back
   `Bound`, then verify the complete binding and operation-stamp inventory.

The new `read_pristine_selector_namespace` backend port defaults to
`Unsupported`. Its affine `GtpuSessionSelectorPristineReadbackRequest` has no
caller constructor. Its receipt has a separate kind and coordinate from
ordinary provisioning. In the eBPF implementation, full program, hook, pin and
marker identity checks surround readback. An empty stamp map alone cannot
hide a retained group, transaction, selector, classifier or forwarding entry.

Protected-store calls occur outside the backend's bounded host lock. Lease,
effect and retry bounds are unchanged. The existing bounded supervisor owns
the work when the public result receiver is dropped.

An interrupted relocation remains `Initializing` with its exact successor.
Only the explicit relocation API with that same bootstrap may resume it;
ordinary provisioning and a third bootstrap are refused. A lost backend
acknowledgement does not generate another epoch. After the final CAS, an exact
repeat verifies the settled binding. Once any group obtains a permanent
record, further relocation is unavailable, even after complete teardown.

## Permanent codec

The first relocation promotes the existing record to `OPCSN19`. Readers of
`OPCSN15` through `OPCSN18` refuse that new version. Records without relocation
history preserve their prior encodings. The common header and existing
rosters are unchanged; version 19 includes the unadmitted, reattach and bearer
section counts even when zero, then a nonzero relocation count and ordered
128-byte rows:

| Field | Bytes |
| --- | ---: |
| Predecessor commitment | 32 |
| Predecessor pin commitment | 32 |
| Predecessor backend epoch | 16 |
| Successor pin commitment | 32 |
| Successor backend epoch | 16 |

The predecessor commitment uses the existing keyed-digest primitive with the
selector secret and domain `opc/gtpu-selector/pristine-predecessor/v1\0`.
Its canonical input concatenates the stable device, storage scope, ledger
identity, big-endian u32 capacity, predecessor pin, predecessor epoch,
big-endian u32 preceding row count and preceding lineage tip. The domain
denotes `Bound` with generation zero and the complete empty admission-history
predicate. The initial tip is zero. Every subsequent tip is SHA-256 over
`opc/gtpu-selector/pristine-lineage/v1\0` followed by the previous encoded row.
The NUL bytes are part of both domains.

Decoding checks the chain, every commitment, exact final pin and epoch,
nonzero coordinates and absence of repeated pins or epochs. It rejects
truncation, duplicate/cyclic lineage, field rebinding and schema downgrade.
Lineage remains present after group admission and decommission. Record growth
shares RFC 016's unchanged 512 KiB plaintext ceiling; insufficient capacity
refuses before any backend call. Validation is linear in the retained row
count, apart from bounded ordered-set uniqueness checks.

## Evidence and limits

Deterministic tests cover the original binding refusal, explicit successful
relocation with the same ledger, stale-writer fencing, interrupted precommit,
lost provisioning acknowledgement, exact continuation, forbidden third
targets, and refusal of historical session ownership. Codec tests preserve
old encodings and reject changed lineage. Fifteen readback fault cases retain
the injected state and refuse groups, indexes, transactions, stamps, forwarding
and classifier entries, observation state, terminal fences, missing or foreign
markers, changed pins, missing maps or hooks, and replaced graph identity.
Adapter composition tests use the
production protected coordinator and eBPF adapter with synthetic kernel IO;
they are not real kernel, restart, forwarding or capacity qualification.

The operation stays experimental. Full repository gates and downstream live
qualification are required independently; a focused synthetic pass alone
does not establish production recovery.
