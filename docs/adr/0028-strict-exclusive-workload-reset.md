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
   detach another owner's forwarding or security policy. At other priorities
   on the named interface, SDK hooks and filters referencing the product's own
   scope maps are removed individually, preserving foreign filters sharing a
   classifier. This retains ordinary reset's ability to clear an old priority,
   even when the predecessor's pins are gone. Recognized product-map references
   also authorize per-handle cleanup on other interfaces of this namespace, as
   in ordinary reset; a scope entry alone only identifies SDK hooks there.
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
including alternative names, receives whole-priority cleanup. Other interfaces
in the calling network namespace receive per-handle cleanup of SDK hooks found
through those entries or scope-map references, and of filters whose programs
reference recognized product maps. Non-SDK filters count as foreign. Other
namespace references, outside program/link pins and live descriptors keep the
ordinary reference refusals. Direct tc operations stay in this namespace.

A map is the product's when this build recognizes its pin name, kernel name and
definition. An unrecognized map is treated as foreign and unpinned without an
external-reference wait, even if it is a product map whose pin was renamed or
whose generation is unknown after a rollback. Another SDK workload's recognized
map pinned into this scope counts as this product's, as in ordinary reset;
recognition does not prove workload ownership. Foreign-map references only
locate filters matching the SDK attach predicate, which are removed as the
product's own hooks. They confer no authority over other filters and do not
block map unpinning. No map ownership record is introduced.

A link pinned in the scope is released when the reset removes its pin, wherever
it is attached, regardless of its creator. This is the pinned-link lifetime
contract of ADR 0027.

`EbpfStrictWorkloadResetReport` is non-exhaustive. Its identifier-free counts
cover selector entries, kernel filter entries that do not match the SDK attach
predicate, and misplaced exclusion directories. SDK hooks, valid exclusions
and interrupted SDK exclusion-publication staging directories directly under
the control directory do not contribute: a clean repeat and a restart containing
only SDK leftovers report zeros.
Ordinary pins and other directories are not counted. Released pinned links are
uncounted because the SDK has no catalog to classify their ownership.

`GtpuError` is already non-exhaustive, so adding
`StrictWorkloadResetIncomplete { report, source }` preserves the public method's
signature and existing error variants. The variant itself is non-exhaustive;
external matches include `..`. A failed attempt with confirmed foreign
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
scope-root entry or foreign map does not widen foreign-filter authority. The
map fixtures check unknown names, mismatched definitions and external references
to product maps; a foreign pinned link is released on another interface without
contributing to the report. Old-priority fixtures cover pins present or absent,
selector residue, alternative interface names and a foreign filter sharing the
old classifier. Unit coverage checks
dispatch, partial-error classification and filter-selection boundaries. Both
kernel guest lanes run all reset tests; Linux 6.8 also requires the TCX-link
proof. The existing eight exclusive-reset fixtures remain unchanged.
