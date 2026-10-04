# RFC 021: Namespace-bound XFRM cleanup inventory

**Status:** Experimental persistence and closed actor composition for SDK #1058;
the cleanup lifecycle and activation remain proposed. The format and resource
profile are not qualified or frozen. Exact SA removal remains a blocking
prerequisite; the inventory refuses cleanup while it is unavailable.

**Date:** 2026-10-03

**Tracking:** [SDK #1058](https://github.com/openpacketcore/openpacketcore-sdk/issues/1058).

## Problem and boundary

The existing object, relocation and roster recovery stores retain keyed request
fingerprints for incomplete transactions. Their committed records surrender
cleanup authority and can be pruned. A consumer that intentionally keeps session
state only in memory cannot reconstruct requests after process loss. Resident
XFRM objects can therefore outlive both that state and the transaction records.

Add an opt-in, actor-owned lifetime inventory. It retains authenticated exact
cleanup descriptors before possible effects, including live committed objects,
and recovers only by proving absence or removing proved owned residue. It never
restores sessions or serializes cryptographic keys, replay positions or packets.
It never infers ownership from SPI, request ID, mark or kernel presence alone.

Existing constructors keep their current behavior. Inventory binding is atomic
with every configured transaction store and occurs before exposing a backend.
Create-new and reopen are distinct operations. Create-new requires a fresh
network namespace under the deployment's exclusive-writer contract; it cannot
adopt objects installed before the inventory existed. Reopen never substitutes
an empty inventory for a missing, unreadable or malformed store.

The initial experimental implementation exposes create-new/reopen binding,
explicit capacity budgets and authenticated status only. Status reauthenticates
the inventory root and every retained transaction-store incarnation and history.
It reports `ExactRemovalUnavailable`, which is not traffic readiness. Every other
actor command remains closed across all clones, including queries, capability
probes, DSCP activation and durable preparation. Returned transaction handles
permit inspection only. Eagerly initialized DSCP backends are refused before
binding; deferred DSCP initialization remains untouched.

The initial inventory format requires journal-backed roster stores. Create-new
initializes a roster directory only when it was absent; an existing directory
must already authenticate as a complete journal, without staging cleanup,
initialization, reconciliation or tail repair. Reopen has the same journal-only
invariant. A legacy named record could be an older public recovery handle
substituted for a removed journal, retaining the same store incarnation while
discarding later history. Such records are therefore refused by inventory
binding. Ordinary recovery APIs retain their existing legacy support. Any future
inventory migration needs a separately versioned and authenticated contract.

## Initial capability profile

The opt-in profile will support new SA/policy installation, new-SPI rekey as a
separate install/retirement lifecycle, and reviewed policy/relocation operations
whose complete effective images are known before issuance. Every physical
mutation, including calls inside durable flows, must cross its inventory adapter.
Unsupported operations are rejected before any transport effect.

The initial profile refuses every ALLOCSPI request, including equal minimum and
maximum values. Allocation creates kernel state before the ordinary returned
allocation is available as cleanup authority.

The initial profile also refuses every UPDSA operation. Linux can retain the old
cryptographic transforms while applying other requested fields. Recording only
the old and fully requested images would omit that hybrid result. Support needs
a separately reviewed model of every supported effective postimage. A regression
must retain the new-key/new-lifetime request with a lost-acknowledgment fault and
prove rejection before issuance. Existing constructors remain source-compatible.

Counter-only NEWAE operations require a proved owned SA and do not replace its
immutable cleanup image. Unclassified mutations fail closed. A capability report
must describe these restrictions before a consumer chooses this profile.

## Lifetime and startup state

Before an install, reserve capacity for the actual planned object, possible
candidate images and journal-settlement coverage. Persist its exact encrypted
descriptor and pre-effect absence evidence. Publish Issuing durably before the
kernel call. Lost acknowledgments retain possible ownership; success and consumer
commit retain live ownership. Only positive exact absence permits retirement.

Relocation retains old and effective target images together while unresolved.
Temporary and replacement policies have their own inventory entries. An
unresolved transition bars another mutation of that object. Retirement does not
erase transaction-settlement coverage.

A bound actor begins in Cleanup, even for an empty inventory. Ordinary mutation
and durable admission stay closed. Bounded cleanup commands report value-free
counts and categories. Complete cleanup produces an affine completion seal bound
to actor, namespace, inventory incarnation, generation and publication revision.
Activation validates the supplied seal before any journal-settlement write. Its
admitted command consumes the seal, durably settles the covered transaction
journals and publishes activation; only successful completion opens Live. A lost
seal can be reissued by a fresh complete observation; a stale or wrong-actor seal
cannot activate anything.
An interrupted activation reopens in Cleanup and validates its durable state;
no caller-side Boolean can open the actor. Cleanup cannot run on a Live actor.

Exact SA deletion must hold a proven exclusion interval across complete candidate
enumeration, immutable fingerprint comparison and deletion. A local SDK mutex
alone does not establish this contract. Until that prerequisite exists, the
implementation returns ExactRemovalUnavailable and issues no cleanup mutation.
It must not fall back to unconditional removal. This proposal does not solve or
qualify that separate prerequisite.

## Authenticated snapshot tree

Do not append frames and trim an incomplete tail. An acknowledged Issuing frame
could be lost by truncation, and its complete predecessor would still authenticate.
Do not rewrite the entire live inventory for each mutation either.

Use bounded complete snapshot shards below an authenticated commit root. The
proposed version-one tree has two fixed manifest levels and a record leaf:

- The root has 256 branch references; each branch has 256 leaf references.
- A leaf has 64 record slots, each with a bounded encoded record.
- Each reference authenticates the child's ciphertext digest, slot selection,
  record counts, reserved candidate-image counts and coverage counts.
- Every node binds its format, namespace, inventory incarnation, generation,
  publication revision, node kind and tree position. Addressing a node at another
  position cannot validate it. Empty references are explicit authenticated values.
- A child reference retains that child's exact creation generation and revision.
  Unchanged children keep those contexts; a new root authenticates their existing
  contexts and digests without requiring equality to its own newer revision.
  Advancing a generation changes the root's actor lifecycle, not the identities
  of still-retained older-generation cleanup or settlement records.
- The sole authoritative root has a fixed name. Each branch and leaf has two
  bounded physical slots. Only the slot reachable from the current root is live.
  Neither a prior root nor an alternate child is a recovery fallback.

For an update, read the current root, selected branch and leaf. Check the complete
authenticated path and capacity before changing anything. Write the changed leaf
to the inactive slot through an exclusive temporary file, sync the file, rename
it to that slot and sync the directory. Publish the changed branch the same way,
then publish and directory-sync the complete new root. Only successful completion
of that final barrier admits a kernel effect. Each publication retains its prior
reachable nodes until the new root is durable. A publication error poisons the
writer until reopen; it cannot continue from an assumed in-memory revision.

An atomic batch publishes every changed leaf and its changed ancestor before one
final root publication. The record-change budget is explicit and checked before
allocation. It includes object changes and their coverage-witness changes; it
cannot be derived solely from the number of protocol objects. A single-record
update's three-node bound is not claimed for a multi-record operation. Multiple
changes in one node share its one publication.

A crash before root publication leaves the prior complete tree authoritative.
An unreferenced partial child or temporary file is not acknowledged truth and
cannot be read as a current record. A crash after successful root publication
requires the complete referenced tree. Truncating a current root, branch or leaf,
including by a whole encoded record, fails authentication or exact-length checks.
A missing referenced file is fatal even if its alternate slot is valid. Full
tree validation precedes cleanup or activation, including on an apparently empty
subtree. No damaged current node is repaired by dropping its records.

Two slots bound obsolete material without a growing append log. Before reusing a
slot, determine reachability from the current root, never from a cached alternate
manifest. Files use only bounded tree positions and slot numbers, with no object
identity in a name. Strict directory accounting permits the known control/root,
node slots and bounded publication temporaries only. Reopen validates types,
ownership, modes, lengths and the complete reachable tree under the permanent
cross-process lease. It then revalidates the accepted root's descriptor/name
binding, syncs that accepted root file and syncs its containing directory. Both
barriers must succeed before slot reuse, unreferenced-publication cleanup, kernel
effects or activation. An error poisons/refuses the writer.

This reopen barrier is necessary even when every reachable node authenticates.
A process can die after root rename but before its directory sync. Its successor
can observe the new root from the filesystem cache, while a later machine/power
failure could still restore the prior root. Reusing an apparently unreferenced
old child before stabilizing the accepted root would then damage the restored
prior tree. Reopen must make its accepted root durable before it destroys any
such fallback storage. Tests must distinguish process-only restart from storage
rollback and cut after rename, at reopen barriers, and before old-slot reuse.

The root lives on trusted local storage that honors the sync/rename crash model
and does not restore an older complete authenticated store. Defending against
coherent whole-store rollback requires an external monotonic witness. This
exclusion does not permit accepting partial truncation or a missing current node.

## Format and resource bounds

Bounds are format/parser limits, not a claim about active-session capacity. The
two 8-bit manifest positions and 6-bit record position address at most 2^22
records. Counts and checked size arithmetic must reject overflow before
allocation or I/O. Consumers supply smaller explicit object, candidate-image,
coverage and total-storage limits. Live, unresolved and orphaned entries all
consume those limits until their appropriate terminal proof is durable.

The experimental codec reserves 1,024 bytes per record, with at most two
candidate images, six policy templates and eight coverage members. Exhaustive
variable-field fixtures derive record maxima of 418 bytes for an SA lifecycle,
752 for a policy lifecycle and 485 for coverage. Each node has a 134-byte
authenticated envelope. A fully occupied leaf needs at most 48,398 framed bytes
for the current record grammar; the reserved record ceiling allows 65,806.
Branch frames have a 16,384-byte cap. The root has a 20,480-byte cap including a
4,096-byte completion reservation whose current version and contents must all
be zero. Those reserved bytes do not grant completion or activation authority.

One changed leaf, branch and root currently need at most 84,605 framed bytes
with grammar-maximum records, or 102,670 under the reserved record ceiling.
Those figures describe one publication path; an atomic batch can change multiple
paths. Initial complete validation streams bounded leaves and rebuilds the
fixed locator index; its separately budgeted lifecycle-serial scratch space is
eight bytes per configured record. No allocation covers the whole address space.
The parser/publication budget also includes decoded values, root copies, changed
paths, index changes and change vectors. Logical byte budgets exclude allocator
metadata, thread stacks, filesystem metadata and block rounding. The measured
layout and prototype fault model do not freeze a production compatibility or
memory-usage contract.

Two physical slots per node bound stored snapshots. Temporary publication has
one bounded file at a time; publication sequencing and directory accounting must
enforce that bound after a crash. No acknowledged object or settlement record is
pruned to make capacity available. Reserving the actual operation's worst-case
states before admission prevents cleanup from requiring unreserved metadata.
There is no theoretical all-bearers reservation per session, and no derivation
of lifetime capacity from active sessions or the roster store's transaction cap.

The namespace actor rebuilds a private lookup index while streaming the current
tree. It maps domain-separated keyed hashes of candidate cleanup identities and
coverage correlations to record positions. The index only locates records;
the referenced authenticated descriptor, lifecycle serial and complete identity
comparison remain authoritative. Duplicate candidate identities across distinct
lifecycles or conflicting coverage correlations fail validation rather than
replace an index entry. Multiple images of one lifecycle sharing a cleanup key
use one locator while retaining each complete possible image in that record.

Use a fixed-capacity open-addressed table sized at the next power of two above
twice the configured candidate-image plus coverage limit. Checked arithmetic and
fallible exact reservation precede loading records. Each slot holds one 32-byte
digest, a 32-bit record position and state/kind metadata. Record measured Rust
slot size, allocation capacity and maximum probe work in evidence before freezing
the format and resource contract. The table never grows beyond that reservation;
lookup is bounded by its slot count, and deletion preserves probing correctness.
Hash equality is never sufficient ownership proof. Index buffers zeroize on drop.
At a provisional slot size of 40 bytes, 524,288 candidate images plus
131,072 coverage entries would require 2^21 slots, or 80 MiB; this is an example
of configured memory cost, not an application capacity or field-size guarantee.

Objects and coverage share leaf slots but retain separate admission counters.
Authenticated occupancy/free-slot bitmaps count every record kind. Allocation
walks free counts in the manifests and the leaf bitmap, so a free position does
not require scanning all objects or assuming positions are already known. Every
new record receives a monotonically allocated lifecycle serial authenticated by
the root; reusing a position never reuses its prior serial. Coverage refers to
lifecycle serials, not reusable positions. Object retirement first transfers its
absence witness to any unsettled coverage in the same atomic batch. Only then
may the object slot become free. Terminal journal settlement can independently
retire coverage while keeping a committed live object under inventory ownership.
Parser buffers, index memory, temporary page copies and maximum batch changes
are separate limits; the small parser envelope is not a total-memory claim.

## Confidentiality and exact descriptors

Encrypt exact selectors, endpoints, protocol identifiers, marks, interface
scope, policy parameters and immutable comparison fingerprints. Use the workspace
AES-256-GCM-SIV primitive with fresh random nonces and separately domain-derived
encryption and fingerprint keys from a dedicated 256-bit secret. Namespace,
incarnation, generation, revision, type and position are authenticated context.
Use zeroizing buffers for plaintext and transient key comparisons. Filenames,
Debug, Display, error messages and diagnostics contain no protocol identifiers,
addresses, selectors, key bytes or key-derived fingerprints.

An SA record contains key-free exact cleanup identity plus a private keyed
fingerprint of immutable readback material, including algorithm identifiers,
transient key bytes, raw selector, lifetime limits, replay configuration,
encapsulation and marks/interface. It excludes traffic-driven counters and replay
position. Unsupported or key-redacted readback is indeterminate. The inventory
never persists the transient SA key bytes used to compute the fingerprint.

## Transaction coverage and settlement

Coverage is its own retained record type, independent of object lifetime. Bind
every covered operation to its transaction family, exact store incarnation,
inventory incarnation and generation, operation correlation and generation, and
request fingerprints. A root-level family manifest retains the exact set of
bound transaction stores, including their incarnations, even after all their
objects have retired. Omitted, replaced or unexpectedly added stores cannot be
silently treated as empty. A legacy unresolved journal without coverage blocks
automatic activation.

Publish coverage before transaction preparation. A crash before that transaction
appears leaves harmless reserved coverage, resolved only by inspecting the same
leased store. A crash after preparation cannot leave an uncovered journal entry.
After all covered effects are proved absent, durably settle the corresponding
journal entry through a family-specific closure operation. Only its confirmed
durable settlement permits retiring coverage. A crash between settlement and
coverage retirement repeats the same idempotent settlement check. Compaction
must retain coverage and family bindings throughout this interval; it cannot
discard them because object counts reached zero. No directory reset, bypass of
an unresolved gate or lost caller request/key is part of this bridge.

## Evidence and staged delivery

A non-default test-support fixture will replace only the netlink transport below
the real Linux backend. It will preserve in-memory kernel objects across actor
reopen while the real codec, files, lease, namespace actor and recovery engine
run unchanged. It will not implement a second inventory. Ordinary builds must
not expose this fixture or a general raw-transport constructor.

Regression evidence must cover publication crash cuts, partial and whole-record
truncation, wrong keys/namespaces/incarnations, omitted covered stores, retained
coverage after object retirement, bounded capacity including orphan debt,
cancelled observers, lost seals, interrupted activation and pre-effect refusal of
unsupported mutations. Same-contract consumer tests must inject the backend
before startup. Kernel behavior and complete cleanup need separately qualified
exact-removal evidence; storage/mock results do not establish either claim.

Initial work is limited to the reviewed storage contract, deterministic fixture
and closed actor plumbing. No end-to-end recovery or deployment-maturity claim
is permitted while exact removal is unavailable.
