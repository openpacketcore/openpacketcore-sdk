# opc-local-kernel-lifecycle

Local reset, containment and backend coordination are available without a
durable store dependency. Enable the opt-in `store` feature for
`ScopeKernelAuthority`, committed effects and activation-bound opening. XFRM
consumers enable that adapter through `opc-ipsec-xfrm`'s `scope-store` feature;
ordinary XFRM builds remain independent of consensus and SQLite.

This package is source-build-only (`publish = false`) while its optional
store adapter depends on the SDK's source-only consensus packages.

Shared contained reset, fresh rebuild and untimed activation for local GTP-U
and XFRM/DSCP backends. The coordinator retains one acquired namespace, private
bpffs root and exclusion lock for all participating backends. It does not
authenticate a worker, select an incarnation or authorize disruption.

## Lifecycle

1. Acquire `opc_linux_gtpu_sys::tc::LocalKernelScope` with exact data slots,
   two containment banks per covered hook, and a lock outside the replaceable
   bpffs mount. Declare every possible plaintext egress, including interfaces
   without DSCP marking. `LocalKernelLifecycle::new` binds the backend artifact
   catalogs and owned route collections to that scope. Reuse one installation
   owner cookie across restarts; a different predecessor cookie returns
   `ScopeError::OwnerCookieMismatch` before mutation.
2. Construct the scoped backend actors and `LocalResetParticipants`. Before
   admission, call `inspect_scope`: it queries TCX and topology on every hook,
   even without clsact, and inspects the registered effects without changing
   kernel state. This is an owner-process call using its held exclusive scope
   lock: a second process gets `Busy`, and an inspector retaining that lock
   prevents the owner from opening the scope until it is released.
   `LocalScopeInspectionResult::state()` returns `LocalScopeInspection`: `Empty`,
   `OwnedAndContained`, `OwnedPartialContainment` or `Uncontained`.
   Classification uses only owned state; preserved foreign filters still allow
   `Empty`. `foreign_filters_present()` is a diagnostic flag and never changes
   the decision. An owned
   partial predecessor bank is a normal result requiring authorized reset,
   not a reason to retry inspection until the bank repairs itself. Unsupported
   capabilities remain terminal `LocalLifecycleError::Unsupported` refusals.
   Inspection supplies no startup or mutation authority. A fresh
   `observe_empty` can produce `ExclusionHeldAndEmpty` startup evidence without
   containment. Exit-time containment instead reports
   `ExclusionHeldAndContained`. Otherwise, after the consumer authorizes disruption, `reset`
   contains the paths and retires XFRM, owned routes/rules, consumer companions,
   then all registered tc hooks and pins. ARP continues to pass.
3. Use the returned `LocalScopeResetReceipt` to admit the restricted XFRM
   profile and rebuild each current-image GTP-U/DSCP graph. The receipt grants
   structural rebuild only. Pin-less predecessors are reset together; no
   retained-graph adoption or historical object reader is used.
4. Construct `ScopeKernelAuthority` from the actual committed authority,
   independently verified execution and store services. `commit_activation`
   executes or recovers the exact child batch, uses the store's canonical
   outcome matcher, and verifies current authority, birth/revision and sealed
   payload before yielding a `CommittedScopeEffect`. The consumer defines the
   encrypted activation phase.
5. Install the required backend effects with that token, then call
   `LocalKernelLifecycle::open`. Every containment removal rechecks current
   execution and all declared graphs. Successful publication returns
   `KernelCompletion` and leaves no steady-state containment filter.
6. Read or remove individual effects with their backend receipts. For normal
   shutdown, obtain disruption authorization first, then call
   `ScopeKernelAuthority::shutdown_local`: it closes new local effects, drains
   admitted operations and supervises the same contained reset sequence.

`close_execution` only closes and drains local effect admission. Neither close
method certifies that peer-control paths stopped; the consumer must establish
that separately before committing durable execution closure.

## Failure and retry

The actor owns uncertain work after its first mutation, even when its caller
is cancelled. Unpublished failed installs converge through exact undo.
Published effects survive reply loss and are recovered by retrying the same
activation token and complete backend request. A changed request, stale epoch
or changed kernel occupant is refused. Capacity and occupied-key contention
wait with backpressure; targeted cleanup has separate admission.

Confirmed removal releases the actor's request and resource reservation. Retained
receipts carry their own retirement marker; the actor keeps no retirement list.
Recovered activation tokens share bounded, payload-free consumption bits retained
by the lifecycle. Rebuilding an authority adapter in the same writer domain does
not clear those bits, so outcome recovery cannot reinstall a completed effect.
The consumer remains responsible for durable identity non-reuse.

`LocalEffectError::RetryableNoEffect` distinguishes store conflicts and other
proven no-effect results from `Stale`, `WrongRequest` and `OutcomeUnknown`.
Re-read and replan conflicts; cancelled attempts require a successor, inactive
profiles permit exact retry, and uncertain outcomes need exact-request recovery.

New mutations require fresh untimed currentness checks. Exact local readback,
published retry and receipt-bound teardown do not require a reachable store.
A store outage does not expire forwarding. Whole-scope reset remains subject
to the consumer's protected-session disruption policy.

Cleanup uses ten-second attempts and jittered backoff capped at one second.
`cleanup_progress` and backend `scoped_cleanup_progress` expose attempt counts
and age since first failure; these clocks never grant ownership. Dropping an
unfinished rebuild transfers its guard and partial graph to supervised cleanup.
Opening also has a ten-second budget. Exhaustion stops opening, restores verified
containment, then returns `LocalLifecycleError::OpeningAttemptExpired`. If
closure is unresolved, the worker keeps the barrier and retries closure. A caller
may retry opening only after that terminal result, with fresh currentness checks.

Only verified local retirement permits rebuild. An observer's descriptor to
a detached old object is reported by `residue_count`/`observe_release` and does
not block it. Global release stays unproven; the count is a lower bound of
observed old IDs. Undeclared BPF attachments on covered hooks conservatively
block retirement because tc metadata cannot exclude a shared-map reference.
Inspection uses tc dumps and retained load/private-pin descriptors, without ID
reopen, node-wide enumeration or a claim of global reference absence.
Unknown pins, legacy recovery history, incomplete inspection and unproven
attachment ownership refuse without erasing that evidence.

## Platform and qualification

Linux containment requires software-only chain-zero tc coverage without TCX,
XDP on a covered ingress, shared blocks or earlier foreign classifiers. The
deployment owns the complete local writer domain; this is not exclusion of an
uncooperative privileged host process. Incompatible kernel/map layouts require
a fresh installation. No persistent object journal is added.

TCX query support is required (mainline Linux 6.6 or a qualified backport).
Missing query/revision support returns `ScopeError::Unsupported`, propagated as
`LocalLifecycleError::Unsupported`. This is a terminal admission refusal for
that kernel; `reset` and `shutdown_local` return it immediately when the first
TCX query fails before containment writes. Consumers must not treat it as
cleanup failure and restart again.
Permission, device-disappearance and I/O errors remain inspection failures.
The existing `CAP_BPF`/`CAP_NET_ADMIN` profile supports this scoped path;
no program/map ID reopen or added `CAP_SYS_ADMIN` privilege is required. See the exact
[native prerequisites](../../docs/rfc/025-local-kernel-lifecycle.md#native-prerequisites).

Deterministic tests cover failure boundaries and retry pacing. Ignored native
tests use private network/mount namespaces, actual BPF/XFRM objects and real
three-voter authority. The [qualification runner](../../ci/qualify-local-kernel-lifecycle.py)
uses `libseccomp.so.2` to deny program/map ID enumeration and reopening in every case.
This includes steady-state readback, retirement and predecessor discovery. It
builds and runs the required manifest in the existing privileged host CI job
and the pinned Rocky 9.4 guest lane (`5.14.0-427.x.el9_4`). The guest consumes
statically linked test binaries with the manifest, source/compiler identity and
binary hashes from the host build. Guest evidence records its own kernel and
every case result. Both paths reject missing, changed or skipped cases; the
actual TCX query decides support, never a version-based empty-hook fallback.
An unsupported case is not qualification.
See [RFC 025](../../docs/rfc/025-local-kernel-lifecycle.md)
for the complete contract and remaining supported-kernel acceptance gates.
