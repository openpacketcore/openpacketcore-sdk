# ADR 0028: Strict reset of a never-provisioned exclusive workload scope

## Status

Accepted.

## Context and safety argument

The reset in ADR 0027 preserves selector history, foreign filters outside its
ordinary slot, and exclusion-marker directories inside retained locks. These
protections can prevent an ordinary workload from attaching when foreign
objects appear in a scope that it owns outright.

Three removals are safe only with an additional caller assertion:

1. No selector namespace has ever been provisioned in the scope. Selector
   authority, decommission and legacy terminal markers therefore protect no
   valid history here. Removing them discards foreign residue. If the assertion
   is false, removal erases permanent authority and retirement fences: a later
   attachment could reuse a retired namespace or conflict with a selector owner.
   Writer and reference checks cannot establish historical absence. This reset
   is outside [RFC 016's lifecycle](../rfc/016-opaque-gtpu-selector-namespace.md#12-security-and-privacy-analysis)
   and is not a decommission operation, even for an already retired namespace.
2. The caller owns the entire configured priority on the interface named in the
   call, in every clsact ingress/egress chain. Every classifier kind, protocol
   and handle at that priority belongs to the discarded workload. Removing it
   cannot disrupt another owner under the assertion. A false assertion can
   detach another owner's forwarding or security policy. Other priorities on
   the named interface are never touched. A scope entry or map reference does
   not grant this foreign-filter authority on another interface.
3. The caller owns every object in the scope and abandons predecessor recovery.
   Misplaced exclusion-marker directories can be removed with their contents,
   including within operation locks and writer locks of known interfaces.
   Ordinary exclusions inside retained legacy or unidentified lock directories
   are preserved, including those of absent interfaces. Removing one without
   knowing its interface could leave that interface's exclusion unfinished.
   Known unfinished exclusions are completed before success. Lock inodes remain
   held and unchanged. A false ownership assertion can destroy another owner's
   recovery exclusion. Inspection failure, a symlink, a nested mount or a held
   writer lock never authorizes removal.

## Decision

Add `reset_strict_exclusive_workload_graph(scope, interface)` alongside the
unchanged reset APIs. A separate entry point makes the assertions explicit
without a boolean at existing call sites.

Declared interfaces are the explicitly named interface and interface-shaped
scope-root entry names. Only the named interface, resolved to its kernel index
including alternative names, receives whole-priority cleanup. Other declared
interfaces receive SDK-hook and scope-map-reference cleanup; discovery solely
by map reference authorizes only referencing filters. Direct tc operations stay
in the calling network namespace. Scope-wide pin cleanup and the pinned-link
release contract of ADR 0027 remain unchanged.

`EbpfStrictWorkloadResetReport` is non-exhaustive. Its identifier-free counts
cover selector entries, kernel filter entries that do not match the SDK attach
predicate, and misplaced exclusion directories. SDK hooks and valid exclusions
do not contribute: a clean repeat and a restart containing only SDK leftovers
report zeros. Ordinary pins and other directories are not counted.

`GtpuError` is already non-exhaustive, so adding
`StrictWorkloadResetIncomplete { report, source }` preserves the public method's
signature and existing error variants. A failed attempt with confirmed foreign
removals carries its partial report and the original failure as its source.
Other failures retain their original variant. Callers retain reports across
retries because a successful retry cannot recount removed objects. Failed
attempts report lower bounds; ACK-uncertain removals remain unknown, so a zero
retry report does not prove no foreign object was found during the sequence.

Strict reset keeps descriptor-relative inventory, locks, identity checks,
no-symlink/no-cross-device traversal, detach ordering and the bounded reference
wait. Busy writers and surviving program references retain distinct underlying
reasons. Pending terminal admissions still refuse. The ordinary exclusive reset
retains all behavior and errors. No dependency, persistent format or migration
is added.

## Lifecycle

After the predecessor is stopped, its forwarding invalidated and ingress
isolated, strict reset can remove these three leftover layouts on startup or
after an interrupted reset without manual node cleanup or Pod replacement.
Callers may reset every intended interface before creating any of them; each
completed ordinary exclusion survives the next call. Repeat strict reset to
complete interrupted work before ordinary attachment. Inherited inspection and
reference refusals remain outside this change.

Sessions and in-flight traffic are not preserved. Callers must drain or transfer
all emergency sessions before voluntary teardown; this API does not implement
drain or authorize cutting an emergency session. It does not change shutdown,
crash handling or cross-node collection: rescheduling uses the destination's
scope and does not reach into another node.

## Verification

Privileged fixtures cover each foreign layout alone and together, both APIs,
selector marker shapes, whole-priority classifier conflicts, forwarding after
strict reset, absent-interface startup orders, interrupted cleanup, writer and
live-reference guards with residue, counts across a failed attempt and retry,
and preservation of other interfaces, priorities, scopes and namespaces. A
scope-root entry does not widen foreign-filter authority. Unit coverage checks
dispatch, partial-error classification and filter-selection boundaries. Both
kernel guest lanes run all reset tests; Linux 6.8 also requires the TCX-link
proof. The existing eight exclusive-reset fixtures remain unchanged.
