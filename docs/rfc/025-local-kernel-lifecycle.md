# RFC 025: Exact Local Kernel Lifecycle

Status: Implemented locally; final qualification and independent review pending.

## Purpose and boundary

Provide exact discovery, contained reset, readback and supervised undo for
workload-local kernel effects. A container can lose its private bpffs pins while
its network namespace retains GTP-U and DSCP tc filters. Startup must reclaim
that state without adopting an unproved graph or deleting a neighbor's filter.
Live operation failure must remove only that operation's objects.

This contract consumes the untimed execution fence replacing the timed checks
in [RFC 022](022-scope-leases.md). Authentication and admission belong to the
scope transport; durable incarnation floors and child apply checks belong to
the store. RFC 023's voter replacement is separate. Local kernel observations
cannot select a worker, retire an incarnation or prove a remote worker stopped.
There is no lease deadline, remote clock exclusion, timed gate adoption or
universal bound on already queued packets. A store outage does not expire
installed forwarding. A retired process may remove its own ended local effects
without new store authority; it may not install, restore or send peer teardown.

## Placement and API

Extend the shared [Linux UAPI boundary](../../crates/opc-linux-gtpu-sys/src/lib.rs)
with a focused `tc` module for complete dumps, held kernel descriptors and exact
slot operations. Keep artifact policy in the
[GTP-U backend](../../crates/opc-gtpu-dataplane/src/ebpf/workload_scope.rs) and
[XFRM/DSCP backend](../../crates/opc-ipsec-xfrm/src/dscp.rs). Extend their existing
operation actors and reuse qualified exact readback/removal mechanisms. Both
backends use the same tc parser and identity checks; neither depends on the
other backend.
Do not move product lifecycle, store authority or cryptography into the sys
crate. Unsupported platforms return typed unsupported results.

The lifecycle crate's `store` feature enables durable scope authority and
activation-bound opening. XFRM exposes it through its opt-in `scope-store`
feature. Default XFRM consumers retain local reset and containment support
without depending on the session store, consensus or SQLite; the dependency
contract is checked independently of workspace feature unification.

The shared reset barrier is implemented in the safe-Rust
`opc-local-kernel-lifecycle` crate. Both backends consume this coordinator;
neither depends on the other. It retains their common local guard, orders
backend-owned effects and existing route reconciliation, and withholds rebuild
until every registered graph is locally retired. Artifact recognition remains
in each backend and raw descriptor operations remain in the sys boundary.

The implemented interfaces are summarized below. See the
[coordinator guide](../../crates/opc-local-kernel-lifecycle/README.md) for the
consumer sequence. The concrete authority adapter currently uses the SDK's
`ScopeAuthorityStore` and `ScopeBatchStore`; transport authentication remains a
separate integration boundary.

| Interface | Contract |
| :--- | :--- |
| `LocalKernelScope::open(spec)` | Hold descriptors for the exact namespace, private bpffs root and stable exclusion-lock inode. Return a process-lifetime guard or `Busy`/typed refusal. The spec declares the finite owned data and containment slots. |
| `LocalKernelLifecycle::inspect_scope(participants)` | Read-only pre-admission inspection of TCX, topology and registered effects. Distinguish empty, owned complete containment, owned partial containment and uncontained effects. Missing capabilities are terminal refusals; an owned partial bank is a normal result requiring separately authorized reset. This grants no startup or mutation authority. |
| Backend `EbpfLocalGraph` / `XfrmDscpLocalGraph::inspect` | Produce an opaque descriptor-backed `ArtifactInventory` using the current embedded image. Incomplete inspection is an error, never an empty inventory. Discovery grants no mutation authority. |
| `LocalKernelScope::contain` | Close and read back the declared local paths after the consumer authorizes disruption. Return an opaque `ContainedScope` bound to this guard, namespace and observed containment objects. ARP continues to pass. |
| `LocalKernelLifecycle::reset` | Supervise contained XFRM, owned route/rule, companion and complete graph retirement. Return `LocalScopeResetReceipt` only after verified local retirement. Independent global-release observations do not gate rebuild. |
| Backend `rebuild_local_graph` / `rebuild_scoped_dscp` | Consume that reset receipt and publish fresh, empty current-image graphs. Abandoned partial builds retain their barrier through supervised exact retirement. Structural completion grants no session authority. |
| `ScopeKernelAuthority::commit_activation` | Execute or recover the exact batch through the actual store, then verify current authority and the child's resulting birth/revision and sealed body. Return a private-constructor `CommittedScopeEffect`; unknown outcomes grant no effect authority. |
| Backend `install_scoped` / `remove_scoped` / `read_scoped` | Bind actor-owned effects to the complete immutable activation request, child birth/revision, local epoch and backend object identity. Fresh installs recheck untimed currentness; receipt-bound undo removes only the exact local effect. |
| `LocalKernelLifecycle::open` | Recheck current execution and every declared graph before each containment removal. Publish `KernelCompletion` only after verified absence of all containment filters. An interrupted unpublished opening restores closure under retained supervision. |
| `KernelCompletion::recheck` | Passively verify the same published opening and local graph identities. Dropping the completion or losing the store does not expire forwarding. Reset receipts report global object residue separately. |
| `ScopeKernelAuthority::shutdown_local` | Close local effect admission, drain admitted work, then supervise the contained ordered reset after consumer disruption authorization. Caller cancellation does not abandon shutdown. This does not certify peer-control closure. |

All guards, inventories and completion receipts have private constructors and
are non-serializable. The supervisor retains the guard and required descriptors
even if an observer disappears. A public ownership spec is a deployment
assertion checked against local handles, not authentication against arbitrary
privileged host processes. A changed request digest under the same request ID
is refused. Another operation on an unresolved resource waits with backpressure.
Each effect rechecks its local writer/process fence at admission. This is not
an atomic transaction between consensus and the kernel.

## Native prerequisites

The scoped path requires `CAP_NET_ADMIN` for tc, XFRM and owned route effects,
a writable private bpffs root, the unchanged private exclusion inode, readable
proc descriptor metadata, and a kernel that loads the committed current image.
It requires TCX query support, introduced in mainline Linux 6.6; older version
strings require a separately qualified backport. This requirement does not
extend the classifier's existing kernel qualification to the lifecycle.

BPF map creation and classifier loading use the existing `CAP_BPF` and
`CAP_NET_ADMIN` profile. Discovery uses complete tc dumps, retained load FDs
and private-pin FDs; it neither enumerates nor reopens program/map IDs and does
not require `CAP_SYS_ADMIN`. TCX query uses `CAP_NET_ADMIN`. The upstream
[Linux BPF syscall implementation](https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/syscall.c)
and [capability helpers](https://github.com/torvalds/linux/blob/v6.6/include/linux/capability.h)
define these checks. No capability grant or deployment security policy is added.
Native packet tests additionally use `CAP_NET_RAW`; the harness creates private
mount/network namespaces before testing. Mount creation/replacement and entry
into another namespace remain environment setup, not BPF discovery operations.

## Exact identity and containment invariants

1. **One local writer domain.** Every startup, serving and cleanup path holds
   the same unchanged lock inode outside the replaceable private bpffs mount.
   Never unlink/recreate the lock or steal it after elapsed time. Bind the guard
   to the opened namespace and root identities; a logical workload name alone
   cannot authorize another namespace, root or incarnation. Reset drains local
   effect workers under an exclusive barrier before changing the graph.
2. **Complete coordinates.** A tc slot is namespace identity, interface index,
   hook/parent, chain, protocol, priority and nonzero handle. Interface names
   are lookup inputs, not identities. Recheck namespace/interface binding and
   all slot attributes, including classifier kind and direct-action flags.
   An interrupted, truncated, malformed, oversized, wrong-sequence or otherwise
   unverified multipart dump supplies no absence or ownership proof. Shared
   blocks, unsupported offload and ambiguous classifier layouts are refused.
3. **Current image and held FDs.** A fresh loader retains every program/map FD
   and proves the complete embedded-image definitions and map relationships
   before publishing readiness. Recheck those FDs and private pin bindings on
   every graph readback. Crash retirement can instead find an exact owned tc
   coordinate, classifier shape, current-image name and tag with no surviving
   pin. That narrower observation permits only contained retirement; it never
   reconstructs unseen maps, adopts the old graph or mints readiness. Private
   pins are checked by inode and descriptor metadata before unlink. Same-namespace
   container restarts use the same image; an image change requires a new namespace.
   This is not a historical-artifact compatibility reader.
4. **Exact deletion.** Re-dump and compare the complete occupant with the held
   inventory immediately before deletion. Legacy tc has no identity-conditional
   delete; the lifetime exclusion contract is mandatory across check and
   mutation. Delete one filter handle, never a qdisc or an entire priority.
   Unknown content is removable only inside an explicitly owned exact slot,
   under independently verified containment and a fresh complete recheck.
   Unknown content outside those slots is untouched and may block reset.
5. **Contain before removal.** Every path that removes a data/DSCP hook or
   resets XFRM state first proves containment, including startup, supervised
   undo, escalation and normal exit. Keep containment effective until rebuild
   and activation-bound opening succeed. Never remove the only containment
   bank to replace it; first establish and verify its independent alternate.
   This proves the declared local paths, not remote exclusion or drainage of
   every previously queued packet.

The broad priority ownership of `reset_strict_exclusive_workload_graph` does
not meet this contract. Its low-level mechanisms can be reused, but that public
operation cannot be used as this lifecycle's exact reset. A GTP-U backend bound to a local
scope returns a typed `LegacyResetOnLocalScope` refusal from all three legacy
resets: conservative, exclusive and strict-exclusive, before any effect. Other
consumers keep their contracts. Containment and data slots are disjoint.
Pin-less graphs never enter retained-graph adoption or cleanup-only acquisition.

## Containment coverage, artifact and opening

Reserve two containment banks, A and B, per covered hook. The chosen kernel
artifact needs no BPF object: each bank has an ARP-protocol `matchall` filter
with a `gact OK` action followed by an all-protocol `matchall` filter with a
`gact SHOT` action. These are two exact filter slots per bank; the ARP exception
therefore requires four reserved coordinates for gap-free A/B replacement.
Both actions carry the scope's owner cookie and use `skip_hw`. Fresh dumps
verify the complete coordinates, cookies, action order/verdicts and software
flags; names or a remembered successful attach are not proof. Re-verify a
predecessor's bank before taking it over. The consumer supplies a stable cookie
for the installation, reused across process/container restarts; a boot nonce
must not replace it. A different cookie in any reserved bank returns
`ScopeError::OwnerCookieMismatch` during acquisition or reset preflight, before
mutating any hook. It is never adopted, erased or retried indefinitely as a
containment failure. The policy drops every other frame,
including control traffic on covered hooks. IPv6 attachment support must add
the corresponding ND exception when its holder contract is qualified.

Coverage is a predicate on each hook, rechecked before every protected effect:

- The namespace and interface identity match the guard and declared data path;
  clsact is present, with no shared ingress or egress block.
- At least one complete verified containment bank precedes all other filters
  in chain zero: its ARP-pass priority is below its drop priority, and both
  priority numbers are strictly below every non-containment filter. Only an
  independently verified alternate bank is exempt from that last comparison.
  Equal-priority, foreign earlier, offloaded or `skip_sw` filters refuse proof.
- The covered hook has no TCX/mprog entries, established by a complete
  `BPF_TCX_INGRESS`/`BPF_TCX_EGRESS` query. This implementation requires TCX
  query support (mainline Linux 6.6 or a qualified backport); a pre-TCX kernel's
  `EINVAL` is `ScopeError::Unsupported`, propagated to the lifecycle caller as
  `LocalLifecycleError::Unsupported`. The older query's `ENOENT` without
  empty-hook revision readback and an unchanged revision sentinel have the same
  typed refusal. The fixed query validates its ifindex and sends no optional
  flags or output pointers. Permission, missing-device and I/O failures remain
  inspection errors. Unsupported capability is terminal for this kernel and
  must not trigger a cleanup/restart loop; none of these failures proves empty.
  `reset` and `shutdown_local` return `Unsupported` immediately from their
  supervised attempt when the first TCX query refuses, before containment writes.
  The [upstream empty-hook query fix](https://github.com/torvalds/linux/commit/edfa9af0a73ecc2000d7bb81d0b0fd3158cc9a65)
  defines the required zero-count and revision readback.
- A covered ingress additionally requires the absence of every XDP attachment
  on that interface. Incomplete or unsupported inspection fails closed.

Removing a data or DSCP filter requires coverage of its own hook. Any XFRM
SPD/SAD reset requires coverage of every declared egress that can carry
plaintext, including an egress with DSCP disabled. The scope's complete path
declaration is checked against the routes/interfaces it manages. Devices,
socket-policy companions and routes outside the declared ownership remain the
consumer's responsibility; they cannot silently bypass this predicate.

Opening takes fresh activation evidence, rechecks all data slots and the
current-execution guard, then removes exact containment occupants. A failed or
lost ACK is not an open result: re-establish a verified bank, report the
unresolved attempt and retry with new readback. A terminal failed-open result
requires verified closure; until then the supervisor retains the guard and
re-containment remains unresolved, with serving publication withheld. No caller
may use an uncertain containment observation for another protected effect.
Opening has a ten-second attempt budget. Exhaustion stops further opening and
supervises re-containment; once closure is verified, the call returns
`LocalLifecycleError::OpeningAttemptExpired`. It never repeats the same opening
forever. The caller can submit another opening with fresh checks after that
terminal result. If closure itself fails, the worker retains the barrier and
reports cleanup progress until closure succeeds.
Successful opening leaves **no containment filter**: steady-state inventory is
exactly the declared data/DSCP filters plus
preserved foreign filters. A later removal must contain afresh. Exit leaves
closure installed unless all possible plaintext sources are proved absent.

## Reset, readback and supervision

Startup first acquires exclusion and inventories the complete scope. Its
read-only `inspect_scope` call checks TCX and topology on every declared hook,
including hooks without a clsact qdisc, then inspects the artifact layout,
XFRM, owned routes and companions. It changes none of them and runs no cleanup
retry loop. It is an owner-process call using the already-held exclusive scope
file lock. A second process opening the scope gets `Busy`; an inspector holding
that lock likewise makes the owner's open return `Busy` until it releases it.
`LocalScopeInspectionResult::state()` classifies owned state only, with
`LocalScopeInspection` values `Empty`, `OwnedAndContained`,
`OwnedPartialContainment` and `Uncontained`. A scope containing only preserved
foreign filters reports `Empty`, as `observe_empty` does. The separate
`foreign_filters_present()` flag reports filters outside the declared data and
containment slots for diagnostics; it never changes that classification or the
admission/disruption decision. Any incomplete occupied bank, or
containment missing from a hook while present on another, reports
`OwnedPartialContainment` when every present bank component has the declared
cookie and role. A complete bank alongside a partial alternate also reports
partial. Foreign cookies, malformed occupants and topology bypasses refuse;
missing query support propagates as terminal `LocalLifecycleError::Unsupported`.
The lower-level `LocalKernelScope::inspect` exposes tc/topology observations
only and makes no claim about other effects.

An owned partial predecessor bank must reach the consumer's admission and
disruption decision, followed by authorized reset, instead of being retried
forever before admission. Inspection neither repairs it nor supplies a
startup, rebuild or effect token. `observe_empty` is a separate operation whose
startup observation distinguishes `ExclusionHeldAndEmpty` from
`ExclusionHeldAndContained`: a freshly verified empty namespace needs no
containment window to supply startup evidence. An empty data scope with verified
exit-time containment still reports `ExclusionHeldAndContained`; partial or
foreign containment is an error, never an empty observation. A pin-less predecessor graph is
reset in its entirety, never partly retained or adopted. If the consumer keeps
a live emergency on that graph and withholds disruption authorization, no
service in the scope can rebuild yet.

For a predecessor, verified containment precedes this reset order: XFRM
SPD/SAD; owned routes and rules; declared owned device/socket-policy companion
cleanup; tc data/DSCP hooks; program/link pins; map pins; then rebuild. Compose
the route backend's owned-collection reconciliation instead of flushing route
tables. Device and socket-policy lifecycle remains consumer-owned and must
return verified completion before the next phase. The coordinator orders the phase
barriers and does not acquire addresses or enter other namespaces. Pin
operations remain
descriptor-relative beneath the verified private root; reject symlinks,
mount crossings and root/lock replacement. Retain lock inodes. Existing
selector-history protections remain: ordinary reset does not erase selector
authority, terminal records or another lifecycle's durable history.
Pinned links whose attachment ownership or namespace cannot be proved are
conflicts; possession of their pin path alone does not authorize detachment.

Retain all available private-pin program/map FDs through their identity-sensitive
operations, closing program FDs after detach/program unpin and map FDs after
exact map unpin. A pinless predecessor is deleted only by fresh exact tc
readback under the held writer domain. No program or map is reopened by ID.
`LocalEffectsRetired` requires exact absence of every declared retired data
hook, no unproved pinned link, removal of owned pins and a verified local
reference boundary. Only this result gates rebuild. An observer's descriptor
to a detached program or map does not block it.

Discovery and graph readback never walk the node-wide BPF object lists.
Unrelated tenants' object counts cannot exhaust an inspection budget. The tc
dump can expose a program ID but cannot prove that a different program does not
reference an owned map. Therefore any undeclared BPF attachment on a covered
hook is preserved and refuses reset/readiness conservatively, even if its maps
might be unrelated. All cooperating GTP-U and DSCP slots must belong to the
same declared writer domain. An owned program appearing at another graph's
slot also refuses. Harmless recognized gact neighbors remain untouched.

Scoped receipts report `StillReferencedOrUnproven`, with a fixed lower bound
of observed prior IDs in `residue_count`/`observe_release`. A pinless graph's
unpinned map IDs may be unavailable. Neither zero, closing an external FD nor
elapsed time proves global reclamation. These diagnostics never reopen IDs,
request extra privilege or gate fresh rebuild.

The existing standalone and legacy ID-inspection APIs retain the narrow
[#1170](https://github.com/openpacketcore/openpacketcore-sdk/issues/1170) and
[#1180](https://github.com/openpacketcore/openpacketcore-sdk/issues/1180) rule:
only raw `ENOENT` from `BPF_PROG_GET_FD_BY_ID` denotes a retired ID. This scoped
lifecycle does not invoke that syscall. Unexpected `ENOENT` from held-FD info,
tc or pin operations remains a failed observation. A selected occupant changing
or disappearing requires fresh readback and never authorizes deleting its
replacement. ACK errors do not prove successful deletion.

A reset is repeatable after each mutation boundary and after process death;
fresh inventory decides the next action. Namespace-local GTP-U and DSCP cleanup
must reach `LocalEffectsRetired` before either backend attaches a new graph.
Global residue does not delay it. DSCP replaces the exact
predecessor whose pins vanished instead of returning permanent `AlreadyExists`.
Only subsequent admitted installation and exact readback can permit activation.
An exported startup observation binds the held local exclusion and closed
containment to the boot execution; the authenticated transport independently
binds that observation to its challenged connection. Observation alone cannot
mint a boot ticket or execution generation.

For live effects, the supervisor registers the exact operation before its first
mutation. Cancellation before that boundary has no effects. After it, dropping
the future cannot stop convergence: the worker finishes readback and, for an
unpublished failed/cancelled install, exact undo. Publication and cancellation
are serialized by the operation actor; an accepted published result is found
by exact retry and is not undone because its reply was lost. Publication
requires the matching committed outcome/current-execution check supplied by
the untimed fence adapter. A fresh install cannot replace that check with a
cached startup observation.

Confirmed removal drops the actor's complete request and resource reservation;
there is no retirement-history list or scan. A retained caller receipt carries
only its own retirement marker for idempotent removal. Recovered activation
tokens share payload-free consumption bits per child and backend role, bounded
by eight current lane receipts of at most 64 children each. The lifecycle keeps
that frontier for the held writer domain, including across authority-adapter
rebuilds. Advancing a lane drops the lifecycle's old bits; only caller-held tokens
retain them. A completed token cannot reinstall an effect, including after
store outcome recovery through a rebuilt adapter.
The consumer still owns durable identity non-reuse, including the
`GtpuSessionGroupId` retirement contract; local transient markers are not a
replacement for that registry.

Store conflicts, inactive-profile results and cancelled/no-effect batch results
map to `LocalEffectError::RetryableNoEffect`, separately from stale authority or
a changed request. Re-read and replan conflicts; a cancelled attempt requires a
successor, while an inactive profile permits exact retry. `OutcomeUnknown`
remains distinct and requires recovery of the exact submitted request.

Undo runs in reverse effect order and verifies each object still matches its
receipt. It cannot delete a successor birth, widen to whole-scope reset, send
peer traffic or require fresh admission to remove its own stale objects. A
partial effect or lost kernel ACK stays unresolved until exact readback proves
the postcondition. Catch worker panics as `Indeterminate` and retain enough
supervisor ownership for reconciliation. Process death loses in-memory receipts;
startup reconstructs kernel state under exclusion and containment, while the
consumer reconstructs session intent from the store's coherent read surface.

## Scoped XFRM effects

The Linux [`remove_sa_exact` implementation](../../crates/opc-ipsec-xfrm/src/linux.rs)
currently refuses, and remains unavailable as a generic deletion API. Add
actor-owned `install_scoped`/`remove_scoped` operations with complete transient
installation receipts; do not route them through that unsupported method or
introduce an object/roster journal. Startup may compose the existing exclusive
SAD/SPD reset only for a wholly owned, stopped namespace, under containment,
with every existing reset precondition and fresh empty-table readback.

The restricted profile owns every namespace XFRM writer from creation,
including policy and SPI-allocation writers. It uses mature ESP SAs with nonzero
SPIs, exact nonoverlapping lookup marks, explicit request IDs, and SPI-zero
policy templates selected by request ID. The scoped actor refuses `allocate_spi`
and performs no `ALLOCSPI`; it reserves the caller-selected mature SA deletion
key in its namespace-wide registry and installs with `NEWSA`/`EXCL`. It permits
no independent ALLOCSPI,
PF_KEY writer, per-socket policy or unsupported offload. Actor admission checks
the profile and key-readback capability before any session effect. A controlled
admission probe under containment must detect lockdown/redacted key readback
and return typed unsupported after its own verified cleanup. Admission cannot
defer that failure to every later undo. Serialize unresolved operations at the
actual kernel deletion key, not merely at child ID or interface ID.

This restriction addresses a specific race: Linux's
[ACQUIRE path](https://github.com/torvalds/linux/blob/v6.12/net/xfrm/xfrm_state.c#L940)
copies the template's SPI, while
[SA deletion lookup](https://github.com/torvalds/linux/blob/v6.12/net/xfrm/xfrm_user.c#L878)
uses destination/protocol/SPI/family and mark matching, without an installation
receipt comparison. SPI-zero templates and exclusion of allocating writers
are intended to keep larval acquisition out of an owned nonzero-SPI deletion
key, including after expiration. This is a design inference requiring race
qualification on every supported kernel, not an existing exact-delete proof.
The actor must compare the full held install request against fresh readback,
including algorithms/keys in zeroizing buffers; missing/redacted key evidence,
overlapping marks or an unproved producer exclusion refuse removal. Never
enable generic deletion from a successful snapshot alone.

The consumer's committed activation phase must precede installation of any
candidate inbound SA or usable outbound SA. A closed tc filter is insufficient
evidence that a pre-commit key was never used. Live undo removes only a receipt's
owned effects, keeps protective policy through removal and never flushes the
namespace. Startup reset and ordinary cleanup must also preserve continuously
held address ownership; neither performs address acquisition or release.

## Failure handling and lifecycle

| Observation | Required action |
| :--- | :--- |
| Lock busy | Backpressure; no mutation, lock replacement or timeout takeover. An unsupported sibling exits only itself. |
| Identity changed or uncertain ACK | Preserve containment/ownership; re-inventory the exact scope and resolve the same operation. Do not report absence or overwrite a new occupant. |
| Unknown exact owned occupant | Independently contain, recheck and remove that exact handle. If inspection or containment fails, return a typed escalation result without a broad delete. |
| Foreign program on a covered hook using an owned map | Refuse local retirement and retain protection. A later exact local observation may resolve the conflict; elapsed time never proves absence. |
| Outside FD retaining an already retired owned object | Report global residue and re-observe; permit rebuild once `LocalEffectsRetired` is proved. Never call the object reclaimed merely to make progress. |
| Repeated cleanup failure | Continue supervised targeted cleanup and surface `EscalationRequired` with fixed, identifier-free reasons. The consumer bounds attempts, cordons admission and automatically resets/restarts when its disruption policy permits. |
| Live protected/emergency session | No whole-scope containment, reset or voluntary restart. Keep healthy forwarding and targeted cleanup; the disruption hold is not overridden by retirement, a retry limit or a timer. |
| Retired or disconnected execution | Preserve installed forwarding under consumer policy. Retired execution performs only exact local teardown of ended effects; new mutations remain fenced. |

Each cleanup attempt has a ten-second monotonic budget, checked between bounded
kernel exchanges; a netlink exchange has a one-second deadline. Expiry retains
uncertain ownership and closure rather than guessing an outcome. Retry pacing
starts at 100 ms, doubles to a one-second cap, and applies jitter in the upper
half of that delay, so no attempt spins. Expose a saturating attempt count and
age since the first failure; neither resets merely because a new attempt starts.
The consumer chooses its escalation threshold. These clocks schedule work and
never grant ownership, declare absence or override a disruption hold.
Every tc exchange error discards its socket before the next attempt. A fresh
socket in the held namespace prevents late multipart replies from poisoning
subsequent readback; reopening never changes the client's receipt identity.

Normal shutdown stops new effects, joins supervised work, obtains disruption
authorization, establishes and verifies containment, then performs ordered
exact cleanup and closes owned descriptors. Forced process
loss is handled by next-start discovery; namespace destruction is qualified
separately. The consumer must wire escalation into automatic supervision, not a
permanent refuse-until-manual-repair branch. Uncooperative privileged mutation
and inaccessible namespaces violate the supported local-execution assumptions.
Harmless external FDs are allowed observational residue; they do not block
local progress and are never reported as physically reclaimed. Startup with no
serving sessions can escalate directly.

## Stored format

This lifecycle adds no durable object journal, roster record, session codec or wire format.
Guards, exact request supervision and inventories are process-local and cannot
be replayed as admission evidence. Existing bpffs objects are observed kernel
state, not an authority database. Incompatible kernel/map layout changes need
a fresh installation; no migration, old-image decoder or timed/untimed dual
reader is introduced. The store and authenticated transport declare their own
fresh-install boundaries before this API is activated. Any later proposal to
persist lifecycle metadata must declare its format boundary before implementation.

## Test plan and acceptance

Write deterministic failing tests before implementation and mutation-check the
safety predicates. Exercise the real state-machine driver through injected
kernel ports, then the production adapters in privileged Linux namespaces.

- Complete-dump tests cover every coordinate/flag mismatch, truncated or
  interrupted multipart replies, malformed attributes, limits, shared blocks,
  unavailable capabilities and namespace/interface/root replacement. Coverage
  negatives include TCX, XDP, earlier/equal-priority foreign filters and
  `skip_sw`; verify ARP passes while other frames are dropped.
- Replace an occupant between discovery and deletion, reuse IDs after release,
  change artifact/map identity, remove pins while retaining hooks, and inject
  unknown content inside/outside reserved slots. Neighbors at the same priority
  but other handles/protocols/chains must survive.
- Deny program/map `GET_NEXT_ID` and `GET_FD_BY_ID` throughout every native
  lifecycle case, including fresh readiness, retirement and pinless discovery.
  The standalone legacy inspector's busy-node regression observes only its
  explicit IDs, independent of 10,000 unrelated programs.
- Preserve the standalone legacy inspector's narrow `ENOENT` regressions;
  metadata and permission errors never prove release. Scoped discovery instead
  refuses any undeclared BPF neighbor without opening foreign descriptors.
  This RFC does not close #1180's remaining legacy scan-site work.
- Cut execution before/after every GTP-U and DSCP effect, lose each ACK, drop
  observers, race publication/cancellation, panic the worker and restart the
  process. Exact retry/undo converges without deleting a successor or leaking
  an unobserved candidate. Unknown store outcomes never publish activation.
- Race XFRM expiration/ACQUIRE with scoped SA removal; reject nonzero-template
  SPI, independent allocation, overlapping marks, unproved keys and foreign
  writers. Refuse `allocate_spi` and detect redacted keys at profile admission.
  Exercise same deletion key across different child/interface IDs,
  partial SA/policy installs, reverse undo and lost replies. No inbound or
  usable outbound candidate SA may exist before its committed activation phase.
- Prove independent closure persists during unknown-slot reset and replacement;
  keep healthy emergency neighbors forwarding during targeted failure and
  escalation holds. Store outage/clock changes do not expire installed traffic.
- Exercise activation-bound open, lost open ACK, crash after open, no extra
  steady-state filter, repeated A/B replacement and normal-exit plaintext
  suppression. Every hook-removal/reset path must pass the coverage predicate.
- Refuse all legacy reset methods on scoped backends without side effects;
  verify unchanged unscoped behavior. Prove fresh-empty startup evidence,
  all-or-nothing pin-less reset and XFRM/routes/companions/tc phase ordering.
- Advance a virtual monotonic clock through attempt limits and back-off;
  observe attempt count/first-failure age and continuing supervision without
  hot loops, implicit success or an emergency-hold override.
- Privileged tests recreate a private mount in the same namespace, restart
  GTP-U and DSCP together, retain an outside program/map FD, then release it.
  Permit rebuild with the harmless FD retained and block on an undeclared BPF
  attachment. Verify exact local retirement while global release stays explicitly
  unproven, including after the outside descriptor closes. Exercise
  ordinary exit, forced exit and namespace destruction with foreign filters.

The implementation includes deterministic fault ports and ignored native tests
for real packet containment/open/shutdown, actual XDP/TCX/earlier-filter refusal,
lost mutation/publication replies, caller cancellation, panics, XFRM
expiration/ACQUIRE, and private-bpffs replacement with the namespace retained.
The native tests compose fresh GTP-U and DSCP graphs with real committed
three-voter authority; global descriptor residue is observed separately.
The complete committed native manifest runs on the privileged host and in the
existing pinned Rocky 9.4 guest lane. That guest requires the
`5.14.0-427.x.el9_4` kernel family and executes the actual TCX query, including
empty ingress/egress and real TCX-occupant refusal. Static bundles bind the
source, compiler, manifest and binaries; guest results retain the observed
kernel and every case log, with no skipped-case success.

Positive packet observations block until the expected marked frame arrives;
actor shutdown uses thread completion, and object release/cleanup waits for
readback. Short release deadlines and packet-arrival windows are not correctness
assertions. The packet fixture retains a two-second negative window after a
positive ARP exchange and drains queued frames even after descheduling. This
window observes the synchronous private-veth fixture; it does not prove a
universal packet-lifetime bound. The runner bounds each complete case at 120
seconds, including quorum readiness and actor convergence. The expiration race
keeps larval acquisitions alive for 600 seconds, beyond that complete case
budget, while waiting for actual mature-SA expiration by readback.

Acceptance still requires the prescribed final candidate checks, independent
review and supported-kernel lifecycle qualification. A local kernel pass does
not qualify another kernel, an ignored case is not passing evidence, and no
universal packet-lifetime or deployment qualification is claimed.
