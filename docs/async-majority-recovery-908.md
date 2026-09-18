# Async majority-restart recovery: SDK #908

The current SDK has no sound automatic recovery mechanism for an existing
Async root after losing the live majority. This investigation preserves a
failing availability regression and identifies authority missing from the
storage contract. It is not a fix or a successful recovery qualification.

## Executed baseline

The baseline is `76597d3ccd9438d956cb6257733cc7a256c5cc4c`. Before production
changes, `opc-session-net`'s `consensus_transport/majority_recovery.rs` forms
three fixed voters using real native storage and the production mutual-TLS
peer/server adapters. It commits a sealed record under a lease, drains local
Async persistence, closes two voters, preserves the original leader, and
reopens the same databases and snapshot directories under unchanged membership.
The stopped owners and listeners are joined; no root or authority is replaced.

The test requires normal initialization, fresh mode-aware traffic authority,
then a higher-fence acquisition, a successful successor CAS, rejection of a
delayed mutation carrying the previous lease, and readback of the successor.
Each call retains the SDK's ten-second default. The outer recovery observation
uses the existing transport suite's cluster-transition bound. A one-second
synthetic lease expires during the absence; this is not the product's
65-second CRC experiment.

```sh
cargo test --locked -p opc-session-net --all-features \
  --test consensus_transport majority_recovery:: -- --test-threads=1
```

The first focused run executed two tests: Async failed at usable-authority
recovery, and Durable passed through the successor operation and old-lease
rejection. Exit status was 101. The raw log SHA-256 is
`cdcfcc1d0a031997386f07d960154ee8e6ea2bfe2c5c6d0d3d305bab90f9752c`.
Rust was 1.98.0, with CI core debug/incremental settings disabled and a private
XFS `TMPDIR`. Earlier fixture compilation/sealing mistakes are retained
separately and are not counted as recovery REDs.

The expanded fixture separately exercises sequential returns and all-cold
returns. Its Async majority/all-cold assertions remain positive availability
requirements; they are neither ignored nor inverted into quarantine passes.

| Policy and restart | Executed result |
| --- | --- |
| Async, sequential retained-root return | Pass, including successor operation |
| Async, two of three retained roots return | Fail at usable-authority recovery |
| Async, all three retained roots return | Fail at usable-authority recovery |
| Durable, two of three retained roots return | Pass, including successor operation |
| Durable, all three retained roots return | Pass, including successor operation |

The five-test run exits 101; log SHA-256:
`9b0a54f69126d7c993a35f1d85abee638fd09fa98321bd9e3c6bce57e2973e97`.

## Missing authority, beyond the cold-barrier dependency

The store's `async_persistence/tests/majority_authority.rs` controls use real
three-voter Openraft operations and retained native roots. Their controllable
in-process authenticated-peer boundary is distinct from the mTLS reproduction.
Only generation I/O and network reachability are faulted; no admission gate,
vote, acknowledgement, selected generation, or membership is fabricated.

1. Commit a record and its lease and persist the initial generations.
2. Partition a follower, retaining its live process. Commit and persist a
   newer prefix on the other two voters so their retained state differs.
3. Fail the majority's subsequent generation writes with ENOSPC. The actual
   resident quorum still acknowledges a series of higher-fence leases. It
   rejects the initial credential, proving revocation before the restart.
4. Join those failed writers and reopen their original selected roots. A
   separate case closes and reopens the survivor as well.
5. Read the actual recovered native rows and allocator frontiers without
   invoking traffic admission. Every copy is below the issued fence and
   credential; the exact predecessor credential is present again. The newer
   external credential remains unexpired.

The checks of raw native fields are test-only observations. They do not apply
a mutation or relax quarantine. Passing these controls means missing evidence
was demonstrated; it never means service recovered. ENOSPC provides a
deterministic acknowledged volatile tail, not a power-loss simulation.
Both controls pass; log SHA-256:
`35c14c09df9c5834e73d81dc087385cab72e6f100574eec1650cdf4b4643045e`.

## Why local selection cannot safely fix it

`sqlite/consensus/wal/async_persistence.rs::admit` completes the storage
acknowledgement after resident projection. That includes the log adapter's
vote, append and commit operations. Generation selection happens later.
`consensus/native/ordinary.rs` advances `next_fence` and `next_credential` in
that same resident state when issuing leases. The retained root identifies the
storage lineage and mode; it does not reserve an upper bound for future
volatile allocations or identify a durably closed consensus incarnation.

The cold protocol therefore cannot distinguish a fully persisted safe cut from
an otherwise identical retained cut followed by lost acknowledged effects.
Increasing a retained scalar once does not solve this: arbitrarily many
allocations may have occurred before the loss, up to the existing counter
limit. Choosing that limit leaves no usable successor allocation. A surviving
process can also be the lagging voter excluded from all of those commits.

This leaves two obligations, neither supplied by a newer local snapshot:

- Recover or supersede vote/log authority without violating previous quorum
  decisions, with full vote/LogId, membership, root, mode and attempt binding.
- Preserve monotonic externally issued fences, or revoke the old incarnation
at every effect boundary before issuing successor authority. Local lease
expiry and accepted data loss are insufficient revocation evidence.

The existing operator-recovery API does not supply this missing authority.
`ConsensusSessionStore::commit_operator_recovery` first requires fixed-quorum
admission, then submits `FinalizeOperatorRecoveryV2` through the ordinary
leader proposal path. It cannot finalize a new epoch without the quorum whose
recovery is in question. Neither a larger local epoch number nor possession of
the product's existing Recovery object changes that requirement.

Lease expiry rejects the expired credential at the store. It does not recover
the lost scalar high-water mark: external fencing consumers may retain a
higher issued fence after expiry. For example, the XDP owner-install path
adopts persisted fencing evidence and rejects an older generation. Waiting
longer therefore cannot establish the required successor ordering.

## Required contract change

A future automatic protocol must establish durable authority before volatile
acknowledgement. Durable vote/log storage is one option, with different I/O and
data-loss semantics. A separate recovery-incarnation protocol would need
durable exclusive promises, authority allocation bounds, an authenticated
state-selection rule, and cancellation-safe retirement of accepted old work.
Its counter and epoch semantics must also be enforceable by downstream effect
consumers. These are requirements, not an implemented or proven protocol.

For roots that already lost such evidence, an explicit recovery capability
needs an independent authority able to revoke the lost scope and authorize the
successor, including external effects. It cannot derive that permission from a
local snapshot, the existing product Recovery object, an operator's acceptance
of data loss, or a fabricated quorum response. Retrospective metadata cannot
recover the missing issued-fence bound.

The missing transition must own four responsibilities: durably retire the
old authority scope, finish or revoke already accepted effects, authorize one
selected state under the exact retained membership/root/mode, and establish
successor authority that every affected consumer can enforce. Cancellation
after any accepted responsibility must leave a resumable owner; delayed
replies or an old process cannot complete the successor's transition. A new
SDK API would need authenticated evidence for these responsibilities, not an
unchecked operator flag. This draft implements neither that capability nor a
migration protocol for existing roots.

No production admission/storage behavior changes in this draft. Full SDK
qualification remains incomplete while its recovery acceptance tests fail.
After a recovery contract is implemented and SDK gates pass, the product must
repin the reviewed SDK and repeat Durable/Async retained-majority recovery
with its original worker and Recovery authority, followed by the common
service suite. This repository evidence makes no CRC recovery, all-cold
product, packet-continuity, audio, or production-HA claim.
