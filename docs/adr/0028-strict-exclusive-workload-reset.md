# ADR 0028: Strict reset of an unbound exclusive workload scope

## Status

Accepted.

## Context and safety argument

The reset in ADR 0027 preserves selector history, foreign filters outside chain
zero, and exclusion-marker directories inside retained locks. These protections
can prevent an ordinary workload from attaching when foreign objects appear in
a scope that it owns outright.

Three removals are safe only with an additional caller assertion:

1. No selector namespace is bound in the scope. Selector-authority,
   decommission and legacy selector-terminal markers therefore protect no valid
   selector history in this scope. Removing them discards foreign residue.
   If the assertion is false, removal erases permanent authority and retirement
   fences: a later attachment could reuse a retired namespace or conflict with
   a live selector owner. Writer and program-reference checks cannot establish
   that no selector authority exists elsewhere.
2. The caller owns the configured priority and handle on every declared
   interface, in every clsact ingress/egress chain and protocol. A filter at
   that placement, whatever its origin, is part of the discarded workload.
   Removing it cannot disrupt another owner under the assertion. A false
   assertion can detach another owner's forwarding or security policy.
3. The caller owns every object in the scope and abandons predecessor recovery.
   An exclusion-marker directory anywhere in that scope, including inside a
   writer or operation lock, can be removed with its contents. The lock inodes
   themselves remain held and unchanged. Reset then recreates the ordinary
   exclusion at its required location for every inventoried interface name.
   A false assertion can destroy another owner's recovery exclusion and permit
   an incompatible recovery or attach. No unpin is authorized by inspection
   failure, a symlink, a nested mount, or a held writer lock.

## Decision

Add `reset_strict_exclusive_workload_graph(scope, interface)` alongside the
unchanged reset APIs. Calling this separately named entry point makes the two
additional assertions explicit without a boolean at existing call sites.
It returns `EbpfStrictWorkloadResetReport`, containing only counts of selector
markers, detached tc filters and removed exclusion-marker directories. Counts
describe successful removals during this call, not proof of foreign provenance;
normal exclusion markers are included when removed and recreated. Errors can
follow partial cleanup and return no completion report.

Strict reset uses the same descriptor-relative inventory, locks, identity
checks, no-symlink/no-cross-device traversal, detach ordering and bounded
program-reference wait as ADR 0027. The extra tc authority applies only to
declared interfaces in the calling network namespace. Discovery of renamed
interfaces still authorizes only filters referencing scope maps. Scope-owned
pinned links retain ADR 0027's attachment-release contract.

Busy writers and surviving program references keep their distinct retryable
errors. Pending terminal admissions still refuse. The existing exclusive reset
retains all behavior and errors, including its selector refusal and the two
layouts it preserves. No dependency, persistent format or migration is added.

## Lifecycle

After the predecessor is stopped, its forwarding invalidated and ingress
isolated, strict reset can remove these leftovers on startup or after an
interrupted reset without manual node cleanup or Pod replacement. Repeating
strict reset completes interrupted work before ordinary attachment. Sessions
and in-flight traffic are not preserved. Callers must drain or transfer all
emergency sessions before any voluntary teardown; this API does not implement
drain or authorize cutting an emergency session. It does not change shutdown,
crash handling or cross-node collection: rescheduling uses the destination's
scope and does not reach into another node.

## Verification

Privileged fixtures cover each layout alone and together, with both APIs,
subsequent packet forwarding, live writer and external program-reference
refusals, and preservation of another scope, interface and network namespace.
Unit coverage checks API dispatch, report counts and strict slot selection.
The existing eight exclusive-reset fixtures remain unchanged.
