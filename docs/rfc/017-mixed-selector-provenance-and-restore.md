# OPC-SDK-RFC-017: Mixed Selector Provenance and Loss-Qualified Restore

**Status**: Proposed

**Version**: 1.0.0

**Date**: 2026-08-13

**Audience**: SDK dataplane implementers, durable-store implementers, backend
authors, security reviewers, and downstream packet-core product teams

## 1. Abstract

RFC 016 establishes one protected, device-scoped ledger for the opaque GTP-U
selector namespace. Its original admission forms deliberately admit either an
entire never-published group or an identical complete set transferred from one
retired group. Those forms cannot express an exact desired group made from
never-published atoms and atoms retired from several predecessor groups. Nor
can they honestly republish durable active groups after the complete mutable
backend graph has been independently lost.

This RFC extends that *same* protected ledger with per-atom provenance and
bounded lineage. A single ledger CAS admits every introduced atom exactly once:
an atom is either an SDK-issued never-published atom or is transferred from one
fully retired, drain-proven predecessor subset. The backend effect is still one
whole-group operation. This RFC does not create a second registry, a product
allocator, a new consensus system, or per-atom dataplane reconciliation.

The RFC also defines the narrow honest republish path. Exact retained state is
adopted, never republished. Republish is a namespace-wide recovery that enters
a separately fenced `RestorePending` state only from protected durable
authority and an opaque qualified receipt proving loss of the entire mutable
backend graph. It retains the exact RFC 016 marker, namespace binding, and
backend epoch while rebuilding every current active group and every permanent
stamp entry. A missing map, an empty semantic readback, a lost marker, a mock,
or traffic observation cannot prove this loss. The built-in eBPF backend
remains `Unsupported` for restore until it has a real privileged, isolated
total-mutable-loss qualification mechanism.

This is experimental SDK mechanism work. It neither claims forwarding,
carrier/product readiness, nor defines downstream allocation, drain, or
readiness policy.

## 2. Scope and Relationship to RFC 016

### 2.1 In Scope

- Exact per-atom and exact-subset opaque provenance under the RFC 016 protected
  selector ledger.
- One-CAS admission of never-published atoms and subsets from multiple fully
  retired and drain-proven predecessor groups.
- Permanent, bounded atom lineage and immutable transfer edges.
- Namespace-wide restore of all current active groups after qualified loss of
  the complete mutable backend graph while the exact immutable marker and
  binding remain retained.
- Canonical durable codecs, capability bindings, stamp ABI migration, bounded
  diagnostics, backend requirements, and RFC 006 evidence.

### 2.2 Out of Scope

- Selector allocation, subscription policy, traffic proof, product lifecycle,
  authorization, and operator workflows other than the bounded recovery
  boundary defined here.
- A second selector registry, a per-product provenance store, a new consensus
  engine, or a caller-provided evidence assertion.
- Partial predecessor drain: every predecessor used by mixed admission is
  completely retired before any subset can transfer.
- A generic eBPF restore implementation. Until its privileged qualification is
  real and conformance-tested, the built-in eBPF backend reports `Unsupported`.

### 2.3 Normative Relationship

RFC 016 remains authoritative for the device/pin namespace tuple, protected
storage gate, canonical selector atom bytes, marker filesystem discipline,
lease-then-host-lock order, operation supervision, decommission fence, and
redaction. This RFC changes neither the stable lookup key nor the one-ledger
rule. Its schema revision is an extension of the RFC 016 ledger record and is
opened only through the RFC 016 namespace authority.

Where this RFC says *atom*, it means the exact canonical `T`, `P`, or `M` atom
defined by RFC 016 §5.1. The existing group model remains the only source of
selector semantics. This RFC creates no per-atom map API.

RFC 016 permits one retired group tombstone to name at most one successor.
For a namespace that has completed the explicit v2 migration in §8, this RFC
supersedes that restriction only with the bounded per-atom transfer manifest
defined below. It does not weaken any other RFC 016 ownership, retirement, or
recovery invariant.

RFC 016 also makes a missing required control map after `Bound` terminally
closed. This RFC does not inspect a missing graph while remaining `Bound` and
then retroactively bless it. Section 7 defines the only precedence rule: after
explicit v2 migration, a consumed durable-active authority may first CAS the
namespace from `Bound` to `LossQualifying(QuiescePending)`, using the
loss/quiesce fence precommitted in `Bound`. Only the separately recorded
`LossQualifying(Quiesced)` state, after that fence advances under the host
lock, permits the SDK supervisor to classify missing reconstructible objects.
The original control root, marker, backend epoch, and v2 backend-mutation fence
must remain exact. Every missing-map observation made in `Bound`, every missing
retained-authority object, and every observation outside that one operation
remains closed under RFC 016.

### 2.4 Implemented V1 Baseline and Upgrade Boundary

The merged RFC 016 implementation is the v1 baseline, not an implementation of
this RFC. It admits either a fresh complete set or one identical complete set
from one retired predecessor. Its current public reuse proof/evidence helpers,
single-predecessor request, one-successor tombstone, and direct backend
quiescence response do not establish a durable RFC 017 drain qualification and
cannot be accepted as v2 provenance or restore authority.

RFC 017 implementation therefore includes an explicit API and durable-schema
migration. The v2 coordinator removes direct caller construction of reuse
evidence from every v2 path, consumes backend quiescence only into the durable
`Qualified` annotation, and admits subsets only from that annotation and the
current atom rows. Legacy `Fresh`, `Reused`, `GtpuSessionSelectorReuseProof`,
`GtpuSessionGroupReconcileRequest::new_reused`,
`GtpuSessionSelectorReuseRequest::{confirm_traffic_drained,
confirm_rcu_grace_period}`, and the `GtpuSessionSelectorReuseProof::after_*`
constructors, if retained for source compatibility, continue to produce only
their existing v1 values. No v2 request, receipt, coordinator method, backend
method, or record decoder accepts those Rust types, so they cannot open,
modify, restore, or decommission a v2 record. The v1 whole-set reconcile entry
point returns `Unsupported` when it reads a migrated namespace. The v1
`GtpuDataplaneBackend::authorize_selector_reuse` signature cannot qualify a v2
predecessor; RFC 017 adds separately named coordinator-minted drain,
loss-inspection, adoption, and restore requests and receipts, with default
`Unsupported` trait methods until a backend implements and qualifies them.
Compile-fail and runtime RED tests must prove that no v1 proof, request,
receipt, backend response, or direct `confirm_*` call can cross this boundary.

The current v1 lifecycle has no durable drain annotation, per-atom transfer
gate, loss-qualification state, retained backend-mutation fence, v2 stamp map,
or namespace restore operation. All of those are new RFC 017 SDK work. #671 is
required only to qualify external adapters against the new canonical boundary;
it does not authorize a product-local substitute and does not block defining or
testing the SDK-owned state machine and built-in profile here.

The standalone protected SQLite profile can advertise the §4.4 record ceiling.
The HA consensus profile remains capped at its smaller existing value limit
until [#683](https://github.com/openpacketcore/openpacketcore-sdk/issues/683)
raises and qualifies its command/RPC and consumer-response ceilings together.
A coordinator must return `Unsupported` when the selected protected backend
does not advertise the §4.4 minimum; it must not chunk this one-record CAS or
substitute product-local storage.

## 3. Terms and Safety Invariants

An *introduced atom* is every atom in the new candidate's canonical desired
complete set. This RFC does not use mixed admission to modify an existing
group. A *source* is one of:

- `NeverPublished`: the SDK observed the atom row absent in the expected
  complete ledger revision inside the one admission call; or
- `RetiredSubset`: the SDK observed the atom row available from one exact
  permanently `Retired` predecessor whose nested drain annotation is
  `Qualified`, while selecting a nonempty exact subset. The predecessor's one
  backend drain receipt was already consumed by that annotation transition.

`DrainedRetired` is API shorthand for this exact view; it is not a fifth group
lifecycle phase and is never encoded in an operation stamp. RFC 016 group
lifecycle remains `Installing | Active | Retiring | Retired | Poisoned`. A
retired group's nested drain annotation is exactly one of `Unqualified`,
`Qualifying { coordinate, backend_started }`, or
`Qualified { commitment }`.

A *provenance partition* is the sorted mapping from every introduced atom to
exactly one source. A source may cover more than one atom, but its subset is
canonical, nonempty, and duplicates are forbidden. The candidate's full set,
not a caller digest, determines its domain.

The following invariants are mandatory:

1. One RFC 016 protected device ledger is the sole atom-history and ownership
   authority. A second table, registry, cache, allocation service, or product
   database cannot mint or replace provenance.
2. In a successful mixed admission each introduced atom has exactly one source;
   coverage equals the complete introduced-atom set. An omitted atom is a gap,
   a repeated atom is overlap, an atom in two source kinds is contradiction,
   and an atom not in the desired set is invalid.
3. A `NeverPublished` source is valid only when every atom it covers has no
   immutable atom row in the expected ledger revision. It permanently creates
   those rows in the admission CAS.
4. A `RetiredSubset` source is valid only when each selected atom's current
   owner is its named predecessor, the predecessor is `Retired` with a
   `Qualified` drain annotation, and
   its immutable qualification binds the exact terminal-retired stamp, trusted
   removed generation, authoritative absence, device, group, set, generation,
   and epoch. A partial drain, an `Unqualified`/`Qualifying` or `Retiring`
   predecessor, or a foreign qualification is invalid.
5. The entire partition, every atom row change, all predecessor transfer-edge
   annotations, the successor `Installing` record, and reserved terminal
   coordinates commit in one whole-ledger CAS. If any source races, expires,
   is stale, or lacks capacity, no atom changes owner and no backend operation
   starts.
6. An atom can be owned by only one pending or active group. A retired atom is
   available for at most one winning successor transfer at a time. Transfers
   from one predecessor are serialized; a pending transfer blocks another and
   a poisoned transfer permanently blocks all remaining atoms. Lineage is
   append-only; no cleanup reopens an atom's first-publication or transfer
   history.
7. A complete trusted drain receipt is consumed once to change a retired
   predecessor's nested annotation from `Qualifying` to `Qualified`. It cannot
   be reused as a caller token. Later disjoint subset capabilities derive only
   from that durable qualified state and its current atom rows.
8. Durable active authority plus exactly retained backend state is adoption,
   not a new publication. Restore requires qualified loss of every mutable
   object while the exact marker, namespace binding, and backend epoch remain.
   Marker or binding loss requires a separately specified offline rebind and
   is `Unsupported` here.

## 4. Durable Record and Provenance Commitments

### 4.1 Atom Rows and Group Records

The RFC 016 ledger's permanent atom row becomes an immutable-root, mutable-tip
record. It contains only protected canonical values and keyed commitments:

```text
atom commitment and immutable first-publication group/generation
current disposition: Installing(owner) | Active(owner) |
  RetiredUnavailable(predecessor) | RetiredAvailable(predecessor) |
  TransferPending(predecessor, successor) | Poisoned
bounded append-only transfer-edge count and edge commitments
```

The immutable root is written once, when a `NeverPublished` source wins. It is
never reassigned. A transfer edge records the predecessor group commitment and
terminal-retired generation, successor group commitment and installing
generation, atom commitment, source-subset commitment, and immutable drain-
qualification commitment. It is appended in the same CAS that changes the tip
to `TransferPending`; finalization changes only the disposition to `Active`.
Failed or ambiguous backend work leaves the exact pending record recoverable or
poisoned; it never restores availability by inference.

Normal removal first settles the group as RFC 016 `Retired`, sets its nested
drain annotation to `Unqualified`, and settles all of its atoms as
`RetiredUnavailable`. Drain qualification is a no-dataplane-mutation protected
inspection. After preflighting the backend profile and supervisor capacity,
one CAS records nested `Qualifying`, a nonzero qualification generation/nonce,
a precommitted `Qualified` coordinate, and `backend_started = false`; the outer
group remains `Retired`, its terminal-retired v2 stamp is unchanged, and atom
tips remain unavailable. The recorded drain operation then follows the §7.1
fence-first protocol: its first intent target advances `backend_started`
one-way before the backend can receive the affine effect request. The backend
revalidates the complete predecessor, terminal-retired stamp, trusted removed
dataplane generation, exact absence, and drain/RCU boundary. The final
`Stable/complete` target CAS consumes its affine receipt, records an immutable
`DrainQualificationCommitment`, changes the nested annotation to `Qualified`, and
changes every still-owned atom to `RetiredAvailable`.

Caller cancellation or response loss never exposes the receipt. The supervisor
settles the same durable operation; after process death recovery may repeat the
trusted inspection under the same qualification coordinate, but only one final
CAS can consume a receipt. Exact qualified-retired response recovery returns a
new locator without invoking the backend. Subset admission never accepts the
original receipt; it derives authority from the durable qualification and
current atom rows.

Each drained predecessor also has one bounded transfer-manifest gate:
`Available`, `Pending(operation)`, or `Poisoned`. A subset admission atomically
changes the gate to `Pending` and the selected atom tips to
`TransferPending`; another subset from that predecessor cannot begin until the
recorded operation settles. Exact terminal success confirms the already
appended edge commitments and returns the gate to `Available` for any remaining
atoms.
Ambiguity remains `Pending` for exact recovery. Any contradiction poisons the
gate and permanently blocks all untransferred atoms from that predecessor.

Each group record retains the RFC 016 group/set/desired commitments, lifecycle
coordinates, and complete atom set. It additionally contains a canonical
`ProvenancePartitionCommitment`, a bounded ordered list of source commitments,
a drain qualification when applicable, the transfer-manifest gate, and a
`lineage-depth` bound. A mixed `Installing` record is therefore a durable
whole-group record, not a collection of independently live atom operations.
An `Installing` record with more than one source is specifically a
*mixed-pending record*; it retains the complete partition and every pending
transfer edge until the one terminal outcome settles. Mixed admission creates
a new group only: an exact existing `Active` group uses adoption, while any
overlap with a different `Active`, `Installing`, or `Retiring` group is
rejected.

Restore is one namespace operation. It preserves every original `Active`
record and appends one permanent restore edge per reconstructed group instead
of replacing activation history.

### 4.2 Exact Canonical Codecs

All inputs use the RFC 016 canonical atom and complete-set codecs. The SDK,
not callers or backends, constructs these additional padding-free codecs. In
this section, `namespace-binding commitment` is SHA-256 over the exact RFC 016
145-byte namespace binding and every other named commitment uses its stated
keyed domain:

```text
AtomSubsetCodecV1:
  version (u8 = 1) || atom-count (u16 big-endian) ||
  sorted unique (tag (u8) || byte-length (u16 big-endian) || atom bytes)

ProvenanceSourceCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) ||
  candidate group commitment (32 bytes) || candidate set commitment
  (32 bytes) || candidate desired-graph commitment (32 bytes) ||
  source-tag (u8: 1=never, 2=retired-subset) ||
  atom-subset byte length (u32 big-endian) || AtomSubsetCodecV1 ||
  for retired-subset only: predecessor group commitment (32 bytes) ||
  predecessor set commitment (32 bytes) || terminal-retired generation
  (u64 big-endian) || drain-qualification commitment (32 bytes)

ProvenancePartitionCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) ||
  candidate group commitment (32 bytes) || candidate set commitment
  (32 bytes) || candidate desired-graph commitment (32 bytes) ||
  source-count (u16 big-endian) || sources sorted lexicographically by their
  complete source codec, each prefixed by its u32 big-endian byte length

DrainQualificationCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) ||
  predecessor group commitment (32 bytes) || predecessor set commitment
  (32 bytes) || predecessor desired-graph commitment (32 bytes) ||
  terminal-retired authority generation (u64 big-endian) ||
  trusted removed dataplane generation (u64 big-endian) || qualification
  authority generation (u64 big-endian) || qualification operation nonce
  (16 bytes) || precommitted qualified-annotation authority generation
  (u64 big-endian) || precommitted qualified-annotation operation nonce (16 bytes)
  || selector-backend epoch (16 bytes) || terminal-stamp commitment (32 bytes)
  || exact authoritative-absence commitment (32 bytes) || backend drain-
  receipt commitment (32 bytes)

TransferEdgeCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || atom
  commitment (32 bytes) || predecessor group commitment (32 bytes) ||
  predecessor terminal-retired generation (u64 big-endian) || successor group
  commitment (32 bytes) || successor set commitment (32 bytes) || successor
  desired-graph commitment (32 bytes) || successor installing generation
  (u64 big-endian) || successor operation nonce (16 bytes) || source-subset
  commitment (32 bytes) || drain-qualification commitment (32 bytes)

LossInventoryCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) ||
  selector-backend epoch (16 bytes) || immutable control-root descriptor
  commitment (32 bytes) ||
  immutable-marker descriptor commitment (32 bytes) || retained backend-fence
  descriptor commitment (32 bytes) || retained prior backend-fence value
  commitment (32 bytes) || immutable backend-inventory-profile commitment
  (32 bytes) ||
  object-class count (u8) || sorted fixed-width object-class entries ||
  exact v1 stamp-inventory commitment (32 bytes) || exact v2 stamp-inventory
  commitment (32 bytes) || mutable-graph inventory commitment (32 bytes)

LossInventoryCodecV1 object-class entry:
  class tag (u8: 1=selector-map, 2=non-marker-pin, 3=program, 4=hook,
  5=journal, 6=v1-stamp-map, 7=v2-stamp-map, 8=backend-defined) ||
  backend-class commitment (32 bytes; zero for tags 1..7) ||
  expected-object count (u32 big-endian) || observed-absent count
  (u32 big-endian, must equal expected) || foreign-object count
  (u32 big-endian, must be zero) || expected-inventory commitment (32 bytes)
  || observed-enumeration commitment (32 bytes)

TotalLossReceiptCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || protected
  ledger revision (u64 big-endian) || selector-backend epoch (16 bytes) ||
  inspection authority generation (u64 big-endian) || inspection operation
  nonce (16 bytes) || durable-active-authority commitment (32 bytes) ||
  LossInventoryCodecV1 commitment (32 bytes) ||
  BackendLossQualificationCodecV1 commitment (32 bytes) || prior stable
  backend-fence commitment (32 bytes) || written loss-qualified backend-fence
  coordinate commitment (32 bytes; phase/outcome/generation/nonce only)

NamespaceRestorePlanCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || protected
  ledger revision (u64 big-endian) || unchanged selector-backend epoch
  (16 bytes) || restore authority generation (u64 big-endian) || restore
  operation nonce (16 bytes) || loss-receipt commitment (32 bytes) ||
  prior v1 stamp-inventory commitment (32 bytes) || prior v2 stamp-inventory
  commitment (32 bytes) || ordered inspection-chunk-plan commitment
  (32 bytes) || target next-loss-entry-schedule commitment (32 bytes) || active-group
  count (u16 big-endian) || active-group entries sorted lexicographically by
  their complete fixed-width encoding

NamespaceRestorePlanCodecV1 active-group entry:
  group commitment (32 bytes) || set commitment (32 bytes) || desired-graph
  commitment (32 bytes) || provenance-partition commitment (32 bytes) || prior
  active authority generation (u64 big-endian) || prior dataplane generation
  (u64 big-endian) || prior active operation nonce (16 bytes) || replacement
  authority generation (u64 big-endian) || replacement dataplane generation
  (u64 big-endian) || replacement operation nonce (16 bytes)

RestoreEdgeCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || unchanged
  selector-backend epoch (16 bytes) || namespace restore-plan commitment
  (32 bytes) || group commitment (32 bytes) || set commitment (32 bytes) ||
  desired-graph commitment (32 bytes) || provenance-partition commitment
  (32 bytes) || prior active authority generation (u64 big-endian) || prior
  dataplane generation (u64 big-endian) || prior active operation nonce
  (16 bytes) || replacement active authority generation (u64 big-endian) ||
  replacement dataplane generation (u64 big-endian) || restore operation nonce
  (16 bytes) || restore-verified backend-fence coordinate commitment
  (32 bytes; phase/outcome/generation/nonce only)

Rfc016UniformProvenanceCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || group
  commitment (32 bytes) || set commitment (32 bytes) || desired-graph
  commitment (32 bytes) || complete atom-subset byte length (u32 big-endian) ||
  AtomSubsetCodecV1 for the complete group

AuthorityDescriptorCodecV1:
  version (u8 = 1) || kind (u8: 1=control-root, 2=authority-marker,
  3=backend-fence-pin) || zero reserved (u16) || stable device ID (16 bytes) ||
  filesystem magic (u64 big-endian) || mount ID (u64 big-endian) || st_dev
  (u64 big-endian) || st_ino (u64 big-endian) || exact st_mode including file-
  type and special bits (u32 big-endian) || st_uid (u32 big-endian) || st_gid
  (u32 big-endian) || st_nlink (u64 big-endian) || canonical leaf-name
  commitment (32 bytes)

BackendInventoryProfileCodecV1:
  version (u8 = 1) || profile entry count (u8, maximum 255) || zero reserved
  (u8) || entries sorted
  by (class tag, backend-class commitment), each exactly: class tag (u8) ||
  backend-class commitment (32 bytes; zero for standard classes) || exact
  required count (u32 big-endian) || maximum enumeration count (u32 big-
  endian) || maximum encoded bytes (u32 big-endian) || namespace-location
  commitment (32 bytes) || descriptor-ABI commitment (32 bytes)

BackendObjectEnumerationCodecV1:
  version (u8 = 1) || object count (u32 big-endian) || sorted unique entries,
  each exactly: class tag (u8) || backend-class commitment (32 bytes) ||
  namespace-location commitment (32 bytes) || object-identity commitment
  (32 bytes) || descriptor commitment (32 bytes) || ABI commitment (32 bytes)

AuthoritativeAbsenceCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || group
  commitment (32 bytes) || terminal-retired stamp commitment (32 bytes) ||
  trusted removed dataplane generation (u64 big-endian) || inventory-profile
  commitment (32 bytes) || complete absence-enumeration commitment (32 bytes)

BackendDrainTranscriptCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || predecessor
  group commitment (32 bytes) || terminal-retired stamp commitment (32 bytes)
  || trusted removed dataplane generation (u64 big-endian) || authoritative-
  absence commitment (32 bytes) || immutable backend-inventory-profile
  commitment (32 bytes) || qualification generation (u64 big-endian) ||
  qualification nonce (16 bytes) || drain-boundary kind (u8: 1=synchronize-rcu,
  2=backend-versioned-equivalent) || zero reserved (7 bytes) || drain-boundary
  verifier commitment (32 bytes)

BackendLossQualificationCodecV1:
  version (u8 = 1) || qualification kind (u8: 1=built-in-eBPF,
  2=qualified-external-profile) || zero reserved (6 bytes) || namespace-
  binding commitment (32 bytes) || immutable backend-inventory-profile
  commitment (32 bytes) || LossInventoryCodecV1 commitment (32 bytes) ||
  inspection authority generation (u64 big-endian) || inspection operation
  nonce (16 bytes) || prior stable backend-fence coordinate commitment
  (32 bytes) || written loss-qualified backend-fence coordinate commitment
  (32 bytes) || exact backend observation commitment (32 bytes)

DurableActiveAuthorityCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || protected
  ledger revision (u64 big-endian) || namespace lifecycle tag (u8 = Bound) ||
  zero reserved (7 bytes) || selector-backend epoch (16 bytes) || backend-
  fence commitment (32 bytes) || current-v2-stamp-inventory commitment
  (32 bytes) || active-group-set commitment (32 bytes)

InspectionChunkPlanCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || whole-
  namespace expected-inventory commitment (32 bytes) || chunk count (u8) ||
  zero reserved (3 bytes) || chunks in strictly increasing object order, each:
  chunk index (u8, starting at zero) || zero reserved (3 bytes) || first-object
  order-key commitment (32 bytes) || last-object order-key commitment
  (32 bytes) || object count (u16 big-endian) || atom count (u16 big-endian) ||
  maximum encoded bytes (u32 big-endian)

BackendStepDescriptorCodecV2:
  version (u8 = 2) || operation kind (u8) || step kind (u8) || role (u8:
  1=object-order-key, 2=effect, 3=precondition, 4=postcondition, 5=readback) ||
  namespace-binding commitment (32 bytes) || descriptor byte length (u16 big-
  endian) || exact operation/step/role-specific canonical descriptor bytes.
  The closed step table below selects the descriptor codec; unknown bytes,
  zero-length required descriptors, trailing bytes, or a descriptor from a
  different role are rejected.

BackendStepDescriptorBodyCodecV1:
  version (u8 = 1) || backend object-class tag (u8: 1..7 are the corresponding
  standard LossInventoryCodecV1 classes, 8 is one closed RFC 017 meta-class)
  || multiplicity (u16 big-endian) || zero reserved (4 bytes) || backend-class
  commitment (32 bytes) || namespace-location commitment (32 bytes) || logical-
  subject-key commitment (32 bytes) || descriptor-ABI commitment (32 bytes) ||
  exact content-or-condition commitment (32 bytes) || related protected-
  authority commitment (32 bytes)

BackendStepMetaClassCodecV2:
  version (u8 = 2) || meta-class tag (u8: 1=namespace-inventory,
  2=retained-fence, 3=drain-barrier, 4=quiesce-barrier,
  5=terminal-authority) || zero reserved (6 bytes)

BackendStepSubjectCodecV2:
  version (u8 = 2) || operation kind (u8) || step kind (u8) || subject-selector
  tag (u8 from the closed table below) || zero-based subject ordinal (u16 big-
  endian) || multiplicity (u16 big-endian) || backend object-class tag (u8) ||
  zero reserved (7 bytes) || backend-class commitment (32 bytes) || namespace-
  location commitment (32 bytes) || logical-subject-key commitment (32 bytes)
  || descriptor-ABI commitment (32 bytes) || exact effect commitment (32
  bytes) || exact precondition commitment (32 bytes) || exact postcondition
  commitment (32 bytes) || exact readback commitment (32 bytes) || related
  protected-authority leaf commitment (32 bytes)

For RFC 017 step descriptors, `descriptor byte length` is exactly 200 and the
body is `BackendStepDescriptorBodyCodecV1`. The closed subject and role tables
below make every field constructible. `multiplicity` and all six commitments
are nonzero, except that `backend-class commitment` is zero for standard
profile classes 1..7 and nonzero for class 8. Class 8 is legal here only when
its backend-class commitment recomputes from one listed
`BackendStepMetaClassCodecV2`; arbitrary backend-defined classes remain
available only through #671's future explicitly versioned descriptor body.
The subject key is a logical canonical key, never a runtime object identity.
Planned private-object conditions therefore commit the closed no-object
predicate and exact target content without guessing a future kernel identity;
the observed post-state inventory independently binds the actual runtime
identity after publication. #671 may add a new explicitly versioned body
codec, never reinterpret this one.

Every selected `BackendStepSubjectCodecV2` is exactly 304 bytes. Its effect,
precondition, postcondition, readback, location, ABI, logical key, and authority
leaf are derived before the operation-claim CAS from the operation's local
semantic fields, immutable profile, and protected group/authority rows. None
may contain a journal, operation-plan, schedule, target-record, runtime-
inventory, or fence commitment; in particular, loss-settlement descriptors do
not consume its prebuilt successor-bundle commitment fields. The five role descriptors copy the subject's
class, multiplicity, backend class, location, logical key, ABI, and authority
leaf. Their `exact content-or-condition commitment` is respectively: the keyed
complete subject commitment for role 1, effect commitment for role 2,
precondition for role 3, postcondition for role 4, and readback for role 5.
This is the only role mapping; no field may be zeroed, substituted, or widened
by a backend.

BackendOperationJournalStepProjectionCodecV2:
  version (u8 = 2) || operation kind (u8: 1=stamp-migration, 2=group-install,
  3=group-remove, 4=drain-qualification, 5=loss-qualification,
  6=restore, 7=decommission) || step kind (u8, operation-specific closed
  table below) || effect class (u8: 1=pure-verification,
  2=atomic-state-transition, 3=repeat-safe-barrier,
  4=atomic-private-publish, 5=fence-bootstrap) || zero-based step index (u16 big-endian) ||
  zero reserved (u16) || intent fence generation (u64 big-endian) || intent
  nonce (16 bytes) || completion fence generation (u64 big-endian) ||
  completion nonce (16 bytes) || object-order-key commitment (32 bytes) ||
  effect-descriptor commitment (32 bytes) || required precondition-descriptor
  commitment (32 bytes) || required postcondition-descriptor commitment
  (32 bytes) || exact readback-descriptor commitment (32 bytes)

BackendOperationJournalStepCodecV2:
  exact 216-byte BackendOperationJournalStepProjectionCodecV2 || intent-fence
  commitment (32 bytes) || completion-fence commitment (32 bytes) || observed
  pre-state BackendInventoryProjectionCodecV2 commitment (32 bytes) ||
  observed post-state BackendInventoryProjectionCodecV2 commitment (32 bytes)

BackendOperationJournalPlanCodecV2:
  version (u8 = 2) || operation kind (u8) || step count (u16 big-endian,
  maximum 2,048) || namespace-binding commitment (32 bytes) || steps in
  strictly increasing zero-based order, each prefixed by its u16 big-endian
  byte length (exactly 216) and encoded only as
  BackendOperationJournalStepProjectionCodecV2 (never any of the two fence or
  two observed-inventory commitments)

BackendOperationPlanCodecV2:
  version (u8 = 2) || operation kind (u8) || zero reserved (6 bytes) ||
  namespace-binding commitment (32 bytes) || protected ledger revision
  at the operation-claim CAS (u64 big-endian) || operation authority generation (u64 big-endian) ||
  operation nonce (16 bytes) || operation-specific payload commitment
  (32 bytes) || operation-journal-plan commitment (32 bytes; zero only when
  the closed operation kind has no physical step) || immutable backend-
  inventory-profile commitment (32 bytes)

StampAbiMigrationPlanCodecV2:
  version (u8 = 2) || mode (u8: 1=v1-to-v2, 2=new-v2-initialization) || zero
  reserved (6 bytes) || namespace-binding commitment (32 bytes) || exact v1
  migration-snapshot commitment (32 bytes; zero only for mode 2) || immutable
  v2 capacity/profile commitment (32 bytes) || migrated group-set commitment
  (32 bytes) || target v2 stamp-inventory commitment (32 bytes) || retained-
  fence bootstrap descriptor commitment (32 bytes) || target next-loss-entry-
  schedule commitment (32 bytes)

GroupInstallOperationPayloadCodecV2:
  version (u8 = 2) || zero reserved (7 bytes) || namespace-binding commitment
  (32 bytes) || group commitment (32 bytes) || set commitment (32 bytes) ||
  desired-graph commitment (32 bytes) || provenance-partition commitment
  (32 bytes) || source-list commitment (32 bytes) || transfer-edge-list
  commitment (32 bytes) || pending-v2-stamp commitment (32 bytes) || terminal-
  active-v2-stamp commitment (32 bytes) || target next-loss-entry-schedule
  commitment (32 bytes)

GroupRemoveOperationPayloadCodecV2:
  version (u8 = 2) || zero reserved (7 bytes) || namespace-binding commitment
  (32 bytes) || group commitment (32 bytes) || set commitment (32 bytes) ||
  desired-graph commitment (32 bytes) || provenance-partition commitment
  (32 bytes) || prior-active-v2-stamp commitment (32 bytes) || pending-remove-
  v2-stamp commitment (32 bytes) || terminal-retired-v2-stamp commitment
  (32 bytes) || authoritative-absence-plan commitment (32 bytes) || target
  next-loss-entry-schedule commitment (32 bytes)

DrainQualificationOperationPayloadCodecV2:
  version (u8 = 2) || zero reserved (7 bytes) || namespace-binding commitment
  (32 bytes) || predecessor group commitment (32 bytes) || predecessor set
  commitment (32 bytes) || predecessor desired-graph commitment (32 bytes) ||
  terminal-retired-v2-stamp commitment (32 bytes) || trusted removed dataplane
  generation (u64 big-endian) || zero reserved (8 bytes) || authoritative-
  absence commitment (32 bytes) || drain-boundary descriptor commitment
  (32 bytes) || target qualified-annotation coordinate commitment (32 bytes) ||
  target next-loss-entry-schedule commitment (32 bytes)

LossQualificationOperationPayloadCodecV2:
  version (u8 = 2) || mode (u8: 1=quiesce, 2=retained-adoption-settlement,
  3=total-loss-settlement) || successor operation kind (u8: 0=none,
  6=restore) || zero reserved (5 bytes) || namespace-binding commitment
  (32 bytes) || durable-active-authority commitment (32 bytes) || inspection-
  chunk-plan commitment (32 bytes) || exact observation commitment (32 bytes;
  zero only for mode 1) || successor semantic-payload commitment (32 bytes) ||
  successor operation-plan commitment (32 bytes) || successor journal-plan
  commitment (32 bytes) || successor fence-schedule commitment (32 bytes) ||
  target next-loss-entry-schedule commitment (32 bytes). Mode 1 requires every
  successor and target-entry field zero; mode 2 requires successor fields zero
  and a nonzero target-entry field; mode 3 requires successor kind 6 and all
  four successor commitments nonzero while target-entry is zero.

DecommissionOperationPayloadCodecV2:
  version (u8 = 2) || zero reserved (7 bytes) || namespace-binding commitment
  (32 bytes) || terminal protected-authority commitment (32 bytes) || retained-
  authority inventory commitment (32 bytes) || reconstructible cleanup-plan
  commitment (32 bytes) || terminal decommission-fence coordinate commitment
  (32 bytes)

NextLossEntryScheduleCodecV2:
  version (u8 = 2) || zero reserved (7 bytes) || namespace-binding commitment
  (32 bytes) || expected Stable/complete backend-fence coordinate commitment
  (32 bytes) ||
  quiesce-intent fence generation (u64 big-endian) || quiesce-intent nonce
  (16 bytes) || quiesce-completion fence generation (u64 big-endian) ||
  quiesce-completion nonce (16 bytes)

BackendFenceCoordinateCodecV2:
  version (u8 = 2) || phase (u8 from BackendMutationFenceCodecV2) || outcome
  (u8: 1=pending, 2=complete) || zero reserved (5 bytes) || nonzero fence
  generation (u64 big-endian) || operation nonce (16 bytes)

BackendMutationFenceScheduleCodecV2:
  version (u8 = 2) || operation kind (u8) || fence-coordinate count (u16
  big-endian, maximum 4,096 and exactly twice the journal step count except
  that the one legal migration fence-bootstrap row contributes one completion
  coordinate and has a zero intent coordinate) ||
  namespace-binding commitment (32 bytes) ||
  BackendOperationPlanCodecV2 commitment (32 bytes) || coordinates in strict
  operation order, each exactly: phase (u8) || outcome (u8) || zero reserved
  (6 bytes) || nonzero fence generation (u64 big-endian) || operation nonce
  (16 bytes)

ProtectedStateProjectionCodecV2:
  version (u8 = 2) || namespace-binding commitment (32 bytes) || protected
  target ledger revision (u64 big-endian) || canonical target
  SelectorLedgerRecordCodecV2 byte length (u32 big-endian) || exact canonical
  target record bytes after replacing the header current-fence commitment;
  the namespace-operation current-fence commitment, its authorizing-plan
  commitment, and its inventory-projection commitment; and, when the row is
  retained, the current row's intent- or completion-fence commitment selected
  by this target with 32 zero bytes. The namespace-operation current-fence
  expected-prior-fence commitment is deliberately *not* normalized. No other
  field is normalized or omitted. For an intent fence the target is the exact
  `intent-recorded` record proposed by the next protected CAS. For a completion
  fence the target is the exact successor record proposed by the following
  protected CAS, including its next revision, state/gate, completed prefix,
  observed inventory projections, and successor operation plan or next-loss
  entry schedule. A terminal successor that clears the journal has no current-
  row field to normalize.

BackendStateInventoryCodecV2:
  version (u8 = 2) || zero reserved (7 bytes) || namespace-binding commitment
  (32 bytes) || immutable backend-inventory-profile commitment (32 bytes) ||
  complete BackendObjectEnumerationCodecV1 commitment (32 bytes) || exact
  reconstructible-graph content commitment (32 bytes) || exact frozen-v1
  stamp-inventory commitment (32 bytes) || exact current-v2 stamp-inventory
  commitment (32 bytes) || retained backend-fence descriptor commitment
  (32 bytes) || retained backend-fence value commitment (32 bytes)

BackendInventoryProjectionCodecV2:
  version (u8 = 2) || namespace-binding commitment (32 bytes) || immutable
  backend-inventory-profile commitment (32 bytes) || exact 264-byte
  BackendStateInventoryCodecV2 after replacing only its retained backend-fence
  value commitment with 32 zero bytes || separately supplied expected prior-
  fence commitment (32 bytes; zero only for migration fence bootstrap)

BackendMutationFenceCodecV2:
  version (u8 = 2) || phase (u8: 1=Stable, 2=StampAbiMigrating,
  3=GroupInstall, 4=GroupRemove, 5=DrainQualifying,
  6=LossQualifying, 7=LossQualified, 8=RestoreEffect,
  9=RestoreVerified, 10=Decommissioning, 11=Decommissioned) || outcome
  (u8: 1=pending, 2=complete) || zero reserved
  (5 bytes) || nonzero fence generation (u64 big-endian) || operation nonce
  (16 bytes) || selector-backend epoch (16 bytes) || namespace-binding
  commitment (32 bytes) || protected-state commitment (32 bytes) || backend-
  inventory commitment (32 bytes) || operation-plan commitment (32 bytes) ||
  target protected-ledger revision (u64 big-endian) || zero
  reserved (24 bytes)
```

Each operation-specific step-kind table fixes the only legal intent and
completion phase/outcome pair for that row. The two generations/nonces in its
projection must equal the corresponding adjacent coordinates in
`BackendMutationFenceScheduleCodecV2`; reordering, omitting, duplicating, or
changing either coordinate is a decode error. Only a closed terminal-
verification or settlement step kind may use a completion phase different from
its intent phase. Fence generations increase strictly in schedule order, the
first non-bootstrap generation is greater than the exact prior retained-fence
generation, and nonces are nonzero and distinct within the complete current
schedule. Strict generation monotonicity makes every generation/nonce pair
new without retaining cleared schedules. Bootstrap selects the first nonzero
generation; every later migration coordinate is greater.

The operation-kind to semantic-payload mapping is exhaustive: 1 uses
`StampAbiMigrationPlanCodecV2`, 2 uses
`GroupInstallOperationPayloadCodecV2`, 3 uses
`GroupRemoveOperationPayloadCodecV2`, 4 uses
`DrainQualificationOperationPayloadCodecV2`, 5 uses
`LossQualificationOperationPayloadCodecV2`, 6 uses
`NamespaceRestorePlanCodecV1`, and 7 uses
`DecommissionOperationPayloadCodecV2`. The namespace-operation row retains the
complete selected payload bytes. An unknown kind, wrong payload codec/domain,
or nonzero field prohibited by a mode is a decode error.

The step-kind/effect/phase table is also exhaustive. A `*` row may repeat only
in strictly increasing canonical object order; every other row occurs exactly
once and in the shown order relative to the other tags for that operation.

| Operation | Step tag and name | Effect class | Intent -> completion |
| :--- | :--- | :--- | :--- |
| 1 migration | 1 `fence-bootstrap` | 5 | no intent -> `StampAbiMigrating/complete` |
| 1 migration | 2 `publish-v2-stamp-map` | 4 | `StampAbiMigrating/pending` -> `StampAbiMigrating/complete` |
| 1 migration | 3 `verify-authority-maps` | 1 | `StampAbiMigrating/pending` -> `StampAbiMigrating/complete` |
| 1 migration | 4 `stable-settlement` | 1 | `StampAbiMigrating/pending` -> `Stable/complete` |
| 2 group install | 1 `write-pending-stamp` | 2 | `GroupInstall/pending` -> `GroupInstall/complete` |
| 2 group install | 2 `selector-atom-transition`* | 2 | `GroupInstall/pending` -> `GroupInstall/complete` |
| 2 group install | 3 `publish-private-object`* | 4 | `GroupInstall/pending` -> `GroupInstall/complete` |
| 2 group install | 4 `attach-hook`* | 2 | `GroupInstall/pending` -> `GroupInstall/complete` |
| 2 group install | 5 `write-terminal-stamp` | 2 | `GroupInstall/pending` -> `GroupInstall/complete` |
| 2 group install | 6 `exact-readback` | 1 | `GroupInstall/pending` -> `GroupInstall/complete` |
| 2 group install | 7 `stable-settlement` | 1 | `GroupInstall/pending` -> `Stable/complete` |
| 3 group remove | 1 `write-pending-stamp` | 2 | `GroupRemove/pending` -> `GroupRemove/complete` |
| 3 group remove | 2 `detach-hook`* | 2 | `GroupRemove/pending` -> `GroupRemove/complete` |
| 3 group remove | 3 `selector-atom-transition`* | 2 | `GroupRemove/pending` -> `GroupRemove/complete` |
| 3 group remove | 4 `unpublish-object`* | 2 | `GroupRemove/pending` -> `GroupRemove/complete` |
| 3 group remove | 5 `write-terminal-stamp` | 2 | `GroupRemove/pending` -> `GroupRemove/complete` |
| 3 group remove | 6 `exact-absence-readback` | 1 | `GroupRemove/pending` -> `GroupRemove/complete` |
| 3 group remove | 7 `stable-settlement` | 1 | `GroupRemove/pending` -> `Stable/complete` |
| 4 drain qualification | 1 `drain-boundary` | 3 | `DrainQualifying/pending` -> `DrainQualifying/complete` |
| 4 drain qualification | 2 `exact-retired-readback` | 1 | `DrainQualifying/pending` -> `DrainQualifying/complete` |
| 4 drain qualification | 3 `qualified-stable-settlement` | 1 | `DrainQualifying/pending` -> `Stable/complete` |
| 5 loss qualification | 1 `quiesce-boundary` | 3 | `LossQualifying/pending` -> `LossQualifying/complete` |
| 5 loss qualification | 4 `adoption-settlement` | 1 | `LossQualifying/pending` -> `Stable/complete` |
| 5 loss qualification | 5 `loss-settlement` | 1 | `LossQualifying/pending` -> `LossQualified/complete` |
| 6 restore | 1 `publish-frozen-v1-map` | 4 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 2 `publish-pending-v2-map` | 4 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 3 `publish-mutable-object`* | 4 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 4 `selector-atom-transition`* | 2 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 5 `write-terminal-v2-stamp`* | 2 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 6 `attach-hook`* | 2 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 7 `complete-readback` | 1 | `RestoreEffect/pending` -> `RestoreEffect/complete` |
| 6 restore | 8 `restore-verified` | 1 | `RestoreEffect/pending` -> `RestoreVerified/complete` |
| 6 restore | 9 `stable-settlement` | 1 | `RestoreEffect/pending` -> `Stable/complete` |
| 7 decommission | 1 `detach-hook`* | 2 | `Decommissioning/pending` -> `Decommissioning/complete` |
| 7 decommission | 2 `remove-reconstructible-object`* | 2 | `Decommissioning/pending` -> `Decommissioning/complete` |
| 7 decommission | 3 `verify-retained-authority` | 1 | `Decommissioning/pending` -> `Decommissioning/complete` |
| 7 decommission | 4 `terminal-settlement` | 1 | `Decommissioning/pending` -> `Decommissioned/complete` |

Loss mode 1 contains exactly step 1, mode 2 contains exactly step 4, and mode 3
contains exactly step 5. The exact quiesced readback is the readback role of
step 1; the exact settlement readback is the readback role of step 4 or 5, so
neither is a second physical journal row. Migration step 1 is the sole row with
zero intent generation/nonce/commitment and contributes only its completion
coordinate to the schedule. Every other row has two nonzero unique coordinates.

The subject-selector tags and their class rules are closed:

| Tag | Selector | Canonical subject list and class |
| :--- | :--- | :--- |
| 1 | retained fence | one fixed fence leaf; class 8 with meta-class `retained-fence` |
| 2 | frozen v1 map | one fixed `GTPU_SELECTOR_OPERATION_STAMPS` map; standard class 6 |
| 3 | current v2 map | one fixed `GTPU_SELECTOR_OPERATION_STAMPS_V2` map; standard class 7 |
| 4 | v2 stamp entry | exact operation-selected group-key entries sorted by protected group ID: the one candidate for install/remove and every current active group for restore; standard class 7 |
| 5 | selector transition | exact persistent selector-entry transitions derived from the canonical desired graph, sorted by `(class, location, logical key)`; standard class 1 |
| 6 | reconstructible object | exact maps, non-marker pins, programs, and journals derived from the desired graph and profile, excluding stamp maps, retained authorities, and hooks, sorted by `(class, location, logical key)`; standard class 1, 2, 3, or 5 |
| 7 | traffic hook | exact hook manifest derived from the desired graph and profile, sorted by `(location, logical key)`; standard class 4 |
| 8 | namespace inventory | one aggregate over the complete ordered immutable-profile enumeration; class 8 with meta-class `namespace-inventory` |
| 9 | drain barrier | one exact profiled drain-boundary predicate; class 8 with meta-class `drain-barrier` |
| 10 | quiesce barrier | one exact profiled namespace-quiesce predicate; class 8 with meta-class `quiesce-barrier` |
| 11 | terminal authority | one aggregate over the exact retained root, marker, fence, stamp inventories, and protected terminal authority; class 8 with meta-class `terminal-authority` |

Singleton selectors use ordinal zero and multiplicity one, except selectors 8
and 11 use the nonzero exact number of members in their committed ordered
aggregate. A `*` step expands to exactly one multiplicity-one row per entry of
its selector list and may be absent only when that exact list is empty. Its
ordinal is the entry's index in the stated ordering. Fixed map locations and
keys come from §§7.1 and 8; every other location, logical key, ABI, effect,
precondition, postcondition, and readback predicate is the unique value derived
by the built-in immutable profile from the exact protected desired bytes. A
profile that produces two encodings for one input, an unlisted class, or a
backend-defined class is `Unsupported` pending #671.

The operation/step-to-subject mapping is exhaustive; the order in each cell is
the exact step-tag order from the preceding table:

| Operation kind | Subject-selector tags by step |
| :--- | :--- |
| 1 migration | `1, 3, 8, 8` |
| 2 group install | `4, 5*, 6*, 7*, 4, 8, 8` |
| 3 group remove | `4, 7*, 5*, 6*, 4, 8, 8` |
| 4 drain qualification | `9, 8, 8` |
| 5 loss qualification mode 1 | `10` |
| 5 loss qualification mode 2 | `8` |
| 5 loss qualification mode 3 | `8` |
| 6 restore | `2, 3, 6*, 5*, 4*, 7*, 8, 8, 8` |
| 7 decommission | `7*, 6*, 11, 11` |

The related protected-authority leaf is likewise closed: migration uses its
v1 snapshot/initialization authority; install uses its pending-v2-stamp
commitment; remove uses its pending-remove-v2-stamp commitment; drain uses
the terminal-retired stamp plus target qualified-annotation coordinate
commitment; loss uses `DurableActiveAuthorityCodecV1`; restore uses the
qualified private `TotalLossReceiptCodecV1`; and decommission uses its terminal
protected-authority commitment. Where two leaves are named, their canonical
length-prefixed concatenation is committed under the subject domain. These are
semantic leaves from dependency step 1; none is an operation plan or fence.
The role mapping above plus these two tables is the complete operation × step ×
role descriptor table. An unknown selector, ordinal, multiplicity, class,
meta-class, authority leaf, or role combination is a decode error before a
fence write.

Effect class 1 performs no backend mutation other than its two fence writes;
it may repeat exact readback after restart. Class 2 names one atomic persistent
transition whose canonical precondition and postcondition must differ; exact
post-state forbids another effect. Class 3 is permitted only for a versioned,
explicitly repeat-safe monotonic barrier such as `synchronize_rcu`; repeating
it establishes an equal or stronger boundary, and any non-idempotent or
identity-bearing backend boundary is `Unsupported`. Class 4 may build and
validate an anonymous/private object containing many entries, but its sole
persistent effect is one atomic no-replace publication. A crash before publish
leaves no persistent object; exact post-publication state forbids republish;
a collision or partial publication is closed. Once a map is published, every
key mutation is its own class-2 row. Class 5 is only the migration bootstrap
specified in §8. No row may hide a multi-key update, hook batch, or other
partially persistent effect.

`BackendMutationFenceCodecV2` is exactly 208 bytes. Its fixed offsets are
`0` version, `1` phase, `2` outcome, `3..8` reserved, `8..16` fence
generation, `16..32` nonce, `32..48` epoch, `48..80` namespace binding,
`80..112` protected-state commitment, `112..144` inventory commitment,
`144..176` plan commitment, `176..184` target protected-ledger revision, and
`184..208` reserved. A decoder accepts only a 208-byte value, known tags and
legal phase/outcome pairs, a nonzero generation, and all-zero reserved ranges;
it rejects truncation, extension, noncanonical integers, and any field that
does not recompute from the protected operation. Here `protected-state
commitment` means only the target `ProtectedStateProjectionCodecV2`
commitment, `backend-inventory commitment` means only the target
`BackendInventoryProjectionCodecV2` commitment, and `operation-plan
commitment` means the `BackendOperationPlanCodecV2` commitment. It never
normalizes a fence.

The legal phase/outcome matrix is closed:

| Phase | Legal outcomes |
| :--- | :--- |
| `Stable` | `complete` |
| `StampAbiMigrating` | `pending`, `complete` |
| `GroupInstall` | `pending`, `complete` |
| `GroupRemove` | `pending`, `complete` |
| `DrainQualifying` | `pending`, `complete` |
| `LossQualifying` | `pending`, `complete` |
| `LossQualified` | `complete` |
| `RestoreEffect` | `pending`, `complete` |
| `RestoreVerified` | `complete` |
| `Decommissioning` | `pending`, `complete` |
| `Decommissioned` | `complete` |

Every other pair is a decode error. A physical journal step uses its unique
`pending` intent coordinate followed by its unique `complete` coordinate;
terminal state fences use only the closed `complete` rows above.

`AtomSubsetCodecV1` atom encodings are byte-for-byte the corresponding RFC 016
complete-set atom encodings. The SDK rejects a duplicate encoding before
sorting, unknown tag, noncanonical length, zero count, or a source whose subset
is not a subset of the desired complete set. It computes commitments with the
RFC 016 selector secret and these new ASCII NUL-terminated HMAC domains:

```text
opc/gtpu-selector/subset/v1\0
opc/gtpu-selector/rfc016-uniform-provenance/v1\0
opc/gtpu-selector/provenance-source/v1\0
opc/gtpu-selector/provenance-partition/v1\0
opc/gtpu-selector/transfer-edge/v1\0
opc/gtpu-selector/drain-qualification/v1\0
opc/gtpu-selector/authoritative-absence/v1\0
opc/gtpu-selector/backend-drain-transcript/v1\0
opc/gtpu-selector/backend-loss-qualification/v1\0
opc/gtpu-selector/authority-descriptor/v1\0
opc/gtpu-selector/backend-inventory-profile/v1\0
opc/gtpu-selector/backend-object-enumeration/v1\0
opc/gtpu-selector/durable-active-authority/v1\0
opc/gtpu-selector/inspection-chunk-plan/v1\0
opc/gtpu-selector/loss-inventory/v1\0
opc/gtpu-selector/loss-receipt/v1\0
opc/gtpu-selector/namespace-restore-plan/v1\0
opc/gtpu-selector/restore-edge/v1\0
opc/gtpu-selector/backend-step-descriptor/v2\0
opc/gtpu-selector/backend-step-meta-class/v2\0
opc/gtpu-selector/backend-step-subject/v2\0
opc/gtpu-selector/backend-operation-journal-step/v2\0
opc/gtpu-selector/backend-operation-journal-plan/v2\0
opc/gtpu-selector/backend-operation-plan/v2\0
opc/gtpu-selector/stamp-abi-migration-plan/v2\0
opc/gtpu-selector/group-install-operation/v2\0
opc/gtpu-selector/group-remove-operation/v2\0
opc/gtpu-selector/drain-qualification-operation/v2\0
opc/gtpu-selector/loss-qualification-operation/v2\0
opc/gtpu-selector/decommission-operation/v2\0
opc/gtpu-selector/next-loss-entry-schedule/v2\0
opc/gtpu-selector/backend-fence-coordinate/v2\0
opc/gtpu-selector/backend-mutation-fence-schedule/v2\0
opc/gtpu-selector/protected-state-projection/v2\0
opc/gtpu-selector/backend-state-inventory/v2\0
opc/gtpu-selector/backend-inventory-projection/v2\0
opc/gtpu-selector/backend-mutation-fence/v2\0
```

The relevant canonical codec is the entire HMAC input after its named domain;
there is no generic commitment domain. `NeverPublished` has no caller-supplied
token or receipt field. A partition's source list MUST be a disjoint exact
partition of introduced atoms; it is not a best-effort description. Counts and
lengths are checked before allocation; trailing bytes, duplicate entries,
nonminimal encodings, unsorted entries, and a count/length mismatch are
rejected. All commitments named above are SDK-computed under the selector
secret except the explicitly backend-qualified opaque commitments, which the
SDK verifies before committing.

Fence construction is acyclic and uses the following closed dependency order;
an encoder or decoder that observes any other dependency is nonconforming:

1. Immutable descriptors, backend profile, namespace binding, authority
   leaves, operation coordinates, local semantic fields, and the closed
   pre/post/effect/readback predicates are leaves. A next-loss entry schedule
   may be built here because it contains coordinates, never a full fence.
2. The meta-class/subject codecs and all five role descriptors derive only from
   step 1. For a total-loss settlement, the complete successor restore bundle
   is built independently first in this same dependency order: restore payload,
   restore subjects/descriptors, restore journal plan, restore operation plan,
   then restore coordinate schedule. The restore payload does not refer to its
   own journal, operation plan, or coordinate schedule. Only after that bundle
   exists may the loss payload commit its four successor commitments; the loss
   descriptors still derive only from its local step-1 fields.
3. Fence-free journal-step projections commit under
   `backend-operation-journal-step/v2`; their ordered list commits under
   `backend-operation-journal-plan/v2`. `BackendOperationPlanCodecV2` then
   commits the semantic payload, journal plan, profile, authority coordinate,
   nonce, and protected revision.
4. `BackendMutationFenceScheduleCodecV2` commits only the operation-plan
   commitment and the ordered phase/outcome/generation/nonce coordinates. It
   contains no fence value or protected/backend projection commitment.
5. For an intent fence, the exact proposed `intent-recorded` target record and
   exact observed pre-state form the two target projections. For a
   completion fence, exact post-state readback first forms the observed pre/post
   inventory projections and the deterministic next-CAS record, including its
   next revision, progress/prefix, current-fence-plan commitment, current-fence
   inventory-projection commitment, expected prior fence, and any precommitted
   successor operation. `ProtectedStateProjectionCodecV2` zeros only fields
   that will contain that target fence and its two self-referential metadata
   commitments; it retains the expected-prior-fence commitment as an acyclic
   input. `BackendInventoryProjectionCodecV2` zeros only the target retained-
   fence value and separately binds that same exact expected prior fence.
   Neither projection contains the target fence bytes.
6. The target `BackendMutationFenceCodecV2` commits those two target
   projections and the authorizing operation plan. Only after that keyed
   commitment is computed may it be inserted into the locally constructed
   target record/current journal row and retained backend-fence object. The
   retained target fence is written, synced, and read back under the host lock
   before releasing that lock; after release, the protected CAS must write
   byte-for-byte that target record. The installed fence then recomputes from
   the current protected record after the CAS, not a discarded historical
   record.

Neither an unprojected `SelectorLedgerRecordCodecV2`, a full journal row, a full
`BackendStateInventoryCodecV2` containing the target fence value, nor a fence
commitment feeds an earlier node in this graph. `NamespaceRestorePlanCodecV1` is a
semantic, fence-free operation payload: it commits neither its own journal plan
nor its own fence schedule or computed fence. The containing
`BackendOperationPlanCodecV2` binds the restore payload and journal plan as
siblings, and the namespace-operation row separately binds the coordinate
schedule. This projection rule is part of every golden vector and rejects a
record assembled in a different order.

`NextLossEntryScheduleCodecV2` is the one narrower exception needed while the
namespace is serving in `Bound`: it commits the exact current
`Stable/complete` *coordinate* and only the next quiesce step's
intent/completion coordinates. The full current fence is independently
validated from the retained object and current-fence metadata. Binding the
coordinate, rather than the future full fence commitment, keeps terminal
operation payloads acyclic: the terminal fence commits the target `Bound`
record that contains this schedule. The first loss-qualification CAS consumes
that entry schedule into a complete current operation plan, schedule, and
journal before handing any request to the backend. It does not precompute
either target fence value. The expected stable coordinate must equal the
coordinate decoded from the exact current raw fence. Both future quiesce
coordinates are nonzero, strictly greater in generation than that stable
coordinate and each other, and have mutually distinct nonces. They become the
first row of the consumed loss schedule without renumbering or substitution.
The protected namespace-operation row always retains the exact 120-byte codec
alongside its keyed commitment. A terminal operation that will install it in
`Bound` retains those same bytes before its first effect, even though its
semantic payload binds only their commitment; this is an acyclic sibling
cross-reference because the codec contains coordinates and no target fence.

The transcript domains above are not aliases. In particular, a descriptor,
inventory profile, enumeration, drain transcript, chunk plan, durable
authority, or mutation-fence commitment cannot be substituted for another
32-byte field. `AuthorityDescriptorCodecV1` uses the complete `st_mode`; masking
to permission bits is noncanonical. Descriptor capture and final verification
use no-follow descriptors and compare the current path to the still-open
object. Any replacement between inspection and final verification is
`Indeterminate`.

The immutable backend inventory profile fixes the complete required class set,
including any backend-defined class commitments. `LossInventoryCodecV1`
contains each required class exactly once in `(tag, backend-class commitment)`
order and no unprofiled class. Its observed-enumeration commitment covers the
canonical bounded descriptor enumeration, including the empty observation and
the namespace locations checked for extras; counts without that enumeration do
not qualify loss.

The immutable backend-inventory-profile commitment is fixed in the protected
v2 capacity/profile record during stopped migration and is stable across a
compliant process restart. It binds the selected adapter class, versioned
descriptor ABI, namespace locations, and complete object-class inventory. The
process-local random `BackendIncarnation` used by traffic observation in RFC
016 is deliberately absent from every drain, loss, adoption, and restore
codec: a restarted supervisor must be able to reproduce the same qualified
inspection for the one durable operation. A changed backend profile,
descriptor ABI, namespace location, marker, epoch, or retained fence is a
replacement and remains `Unsupported`, `RebindRequired`, or `Indeterminate`;
it cannot be normalized into a restart.

### 4.3 Exact V2 Record and State Table

`SelectorLedgerRecordCodecV2` is a replacement protected-plaintext schema, not
an appended registry and not a decoder reinterpretation of v1 bytes. Its exact
header is:

```text
version (u8 = 2) || namespace-state tag (u8) || migration tag (u8) ||
zero reserved (u8) || protected ledger revision (u64 big-endian) || exact
RFC 016 namespace binding (145 bytes) || selector secret (32 protected bytes)
|| immutable-capacity-profile commitment (32 bytes) || active stamp ABI
(u8 = 2) || section count (u8 = 10) || zero reserved (6 bytes) || current
backend-mutation-fence commitment (32 bytes)
```

The header is followed by exactly ten sections in this order: atom rows,
group rows, group-atom references, transfer-edge rows, provenance-source rows,
restore-edge rows, frozen-v1 stamp inventory, current-v2 stamp inventory, and
operation-journal rows, and namespace-operation state. Each section is `count (u32
big-endian)` followed by `row-length (u32 big-endian) || row` for every row.
Rows are sorted by their complete encoded order key; duplicate or out-of-order
rows are invalid. No optional field is omitted: an inapplicable fixed-width
field is all zero and a decoder rejects a nonzero value. Exact row layouts are:

```text
AtomRowCodecV2:
  version (u8 = 2) || disposition tag (u8: 1=Installing, 2=Active,
  3=RetiredUnavailable, 4=RetiredAvailable, 5=TransferPending, 6=Poisoned) ||
  lineage depth (u8) || zero reserved (u8) || canonical atom byte length
  (u16 big-endian) || canonical atom bytes || atom commitment (32 bytes) ||
  first-publication group commitment (32 bytes) || first-publication authority
  generation (u64 big-endian) || current-owner group commitment (32 bytes;
  zero only when Poisoned) || transfer-edge start index (u32 big-endian) ||
  transfer-edge count (u16 big-endian) || zero reserved (u16)

GroupRowCodecV2:
  version (u8 = 2) || RFC 016 lifecycle tag (u8: 1=Installing, 2=Active,
  3=Retiring, 4=Retired, 5=Poisoned) || drain tag (u8: 0=not-applicable,
  1=Unqualified, 2=Qualifying, 3=Qualified) || transfer-gate tag
  (u8: 0=not-applicable, 1=Available, 2=Pending, 3=Poisoned) ||
  backend-started (u8: 0 or 1) || zero reserved (3 bytes) || protected group
  ID (16 bytes) || group commitment (32 bytes) || set commitment (32 bytes) ||
  desired commitment (32 bytes) || provenance-partition commitment (32 bytes)
  || canonical desired-group byte length (u32 big-endian) || exact
  GtpuSelectorDesiredCodecV1 bytes || group-atom-reference start index
  (u32 big-endian) || group-atom-reference count (u16 big-endian) || source-row
  start index (u32 big-endian) || source count (u16 big-endian) ||
  current authority generation (u64 big-endian) || current operation nonce
  (16 bytes) || current dataplane generation (u64 big-endian) || precommitted
  terminal authority generation (u64 big-endian) || precommitted terminal
  operation nonce (16 bytes) || precommitted terminal dataplane generation
  (u64 big-endian) || drain qualification generation (u64 big-endian) || drain
  qualification nonce (16 bytes) || drain-qualification commitment (32 bytes)
  || transfer-pending operation commitment (32 bytes) || terminal-v2-stamp
  commitment (32 bytes) || restore-edge start index (u32 big-endian) ||
  restore-edge count (u8) || zero reserved (3 bytes)

GroupAtomReferenceCodecV2:
  version (u8 = 2) || group commitment (32 bytes) || zero-based atom order
  (u16 big-endian) || zero reserved (u16) || atom commitment (32 bytes)

CommittedPayloadRowCodecV2:
  version (u8 = 2) || owning group commitment (32 bytes) || zero-based order
  (u16 big-endian) || kind (u8: 1=transfer, 2=source, 3=restore) || zero
  reserved (u8) || canonical payload byte length (u32 big-endian) || exact
  TransferEdgeCodecV1, ProvenanceSourceCodecV1, or RestoreEdgeCodecV1 payload
  selected by kind || keyed commitment over that complete payload (32 bytes)

StampInventoryRowV1: group ID (16 bytes) || exact RFC 016 value (208 bytes)
StampInventoryRowV2: group ID (16 bytes) || exact RFC 017 value (240 bytes)

OperationJournalRowCodecV2:
  exact 344-byte BackendOperationJournalStepCodecV2

NamespaceOperationStateCodecV2:
  version (u8 = 2) || state tag (u8: 1=Bound,
  2=StampAbiMigrating, 3=LossQualifyingQuiescePending,
  4=LossQualifyingQuiesced, 5=RestorePending, 6=RestoreFinalizing,
  7=Poisoned, 8=Decommissioning, 9=Decommissioned) || backend-started
  (u8: 0 or 1) || operation kind (u8: 0=none, otherwise the closed
  BackendOperationPlanCodecV2 table) || operation-gate tag (u8: 0=idle,
  1=planned, 2=running, 3=settling, 4=poisoned) || zero reserved (3 bytes) || operation
  authority generation (u64 big-endian) || operation nonce (16 bytes) || precommitted
  terminal authority generation (u64 big-endian) || precommitted terminal
  nonce (16 bytes) || current backend-fence commitment (32 bytes) || current-
  fence authorizing-operation-plan commitment (32 bytes) || current-fence
  backend-inventory-projection commitment (32 bytes) || current-fence expected-
  prior-fence commitment (32 bytes) || bound-entry-schedule byte length (u16
  big-endian; zero or exactly 120) || zero reserved (u16) || exact canonical
  NextLossEntryScheduleCodecV2 bytes when length is nonzero || bound-entry-
  schedule commitment (32 bytes; zero iff length is zero) || complete current-operation fence-
  schedule commitment (32 bytes) || operation-plan
  commitment (32 bytes) || operation-journal-plan commitment (32 bytes) ||
  inventory commitment (32 bytes) || receipt commitment (32 bytes) || chunk-
  plan commitment (32 bytes) || journal step count (u16 big-endian) ||
  completed journal prefix (u16 big-endian) || current journal step index (u16
  big-endian; 0xffff when none) || journal progress tag (u8: 0=none,
  1=planned, 2=intent-recorded) || zero reserved (u8) ||
  operation payload byte length (u32 big-endian) || exact canonical operation-
  specific payload selected by operation kind (zero length only for kind=none)
```

The bound-entry schedule field stores bytes, not only a digest. In `Bound/idle`
it is the current consumable loss-entry schedule. During any operation (or
prebuilt successor operation) whose eventual terminal target is `Bound`, it is
the exact target schedule already committed by that operation payload; the
terminal target copies the same 120 bytes and commitment without regeneration.
It is zero only when neither the current state nor a fully committed successor
payload names a target `Bound` entry schedule. The decoder recomputes the keyed
commitment, namespace binding, coordinate ordering, and every payload cross-
reference. Restart therefore recovers the future generations and nonces from
protected canonical bytes; it never attempts to invert a commitment or mint a
replacement schedule.

The group row's source/edge spans must be in range, contiguous, and owned by
that group; atom and group references must be a bijection with their exact
canonical sets. `lineage depth` is zero at first publication, increments once
per transfer, and has immutable maximum 32. A committed-payload row can occur
only in its named section with the matching kind. Its owner, order, complete
canonical payload, and recomputed commitment must agree with the group, atom,
qualification, and operation rows; a decoder never accepts an orphaned digest
as lineage. Operation-journal rows are sorted by strictly increasing step
index, their count and fence-free projections must exactly recompute the
namespace operation's journal-plan commitment. A future `planned` row has two
zero fence-commitment fields and two zero observed-inventory fields because its
runtime observations and exact target projections have not yet been captured.
For the current row, a read-only host-lock preflight captures exact pre-state,
constructs the exact `intent-recorded` target, writes/syncs/reads that target's
intent fence, and releases the lock. The following intent CAS stores its
inventory-projection and intent-fence commitments; fills the header and
namespace current-fence fields and the three associated metadata fields; and
advances `backend_started` one-way before any effect. If the process dies after
the fence write but before this CAS, recovery uses the still-`planned` record,
the scheduled coordinate, exact live pre-state, and raw retained fence to
reconstruct and verify only that byte-for-byte intent target. The completion
and post-state fields remain zero. After the intent target is protected, the
worker reacquires the host lock and revalidates byte-for-byte that record,
intent fence, and pre-state before the effect. After exact post-state, the
completion fence commits the exact successor record whose CAS fills the post-
state and completion-fence fields, advances the prefix, selects the next
`planned` row or terminal successor, and changes the header and namespace
current-fence metadata to that completion target. Completed rows retain all
four exact values while the journal remains present. There is no separately
protected `effect-complete` progress state: before the completion-target CAS
the record is `intent-recorded`, and after it the completed prefix has advanced.
The completed prefix is at most the step count; only the next step may be
`planned` or `intent-recorded`, no later step may have
either fence installed, and every installed fence must recompute from the
operation plan, schedule, target projections, and recorded revision. The operation-journal section is empty only when the closed
operation kind permits no physical effect or the namespace is settled
`Bound` with an idle operation gate, `Poisoned`, or `Decommissioned`. It is cleared only by the terminal
protected CAS after every planned effect and fence has exact readback. The
namespace-operation row retains the complete semantic operation payload, not
only its commitment; for restore it is the exact
`NamespaceRestorePlanCodecV1`, and for migration or an RFC 016 lifecycle
operation it is that operation's explicitly versioned canonical plan codec.
The decoder recomputes `BackendOperationPlanCodecV2` from that payload, the
journal plan, immutable profile, namespace binding, protected revision, and
operation coordinate before it accepts any schedule or fence. The
namespace-operation row count is exactly one. Unknown tag, illegal zero,
nonzero reserved field, dangling span, counter mismatch, wrong recomputed
commitment, or an impossible cross-row state is fieldless `Indeterminate`
before capability minting or backend work.

The header current-fence commitment and namespace-operation current-fence
commitment must be byte-equal. Once a target CAS is installed, for every non-
bootstrap target the stored expected-prior-fence commitment is the exact
retained fence allowed immediately before the target write: the prior complete
fence for an intent, and that row's intent fence for a completion. The stored
inventory-projection commitment and raw fence's inventory field must match;
for an intent-recorded row it is the recorded observed-pre projection, and for
a completion target it is the recorded observed-post projection. The stored
authorizing-plan commitment and the raw fence's plan field must also match. The
raw retained fence, reconstructed protected-state projection, reconstructed
inventory projection, coordinate, and target revision must recompute the
stored current-fence commitment. While an intent row is current, recovery
independently classifies live inventory as its exact precondition or exact
postcondition before acting.
After a completion target is installed, exact live inventory must itself
recompute the stored completion projection after zeroing only the retained
target-fence value and supplying the stored expected prior. These fields remain
nonzero when a terminal CAS clears the source operation and journal, so
`Stable`, `LossQualified`, `RestoreVerified`, and `Decommissioned` fences
remain verifiable from the current record and exact current backend state.
Migration bootstrap alone uses a zero expected prior and its closed §8 rule.
The only legal physical-ahead windows are a `planned` record with its exact
scheduled intent fence and unchanged pre-state, or an `intent-recorded` record
with its exact scheduled completion fence and exact post-state. In either case
the raw ahead fence must reconstruct and authenticate the one next target
record before a no-lock CAS installs it. Every other mismatch between protected
current-fence metadata and the retained raw fence is closed.

A completion fence may target a different successor operation only when the
current semantic payload already contains that successor's complete payload,
plan, schedule, and journal commitments. The target record installs those
bytes atomically while retaining the completing fence's source-plan commitment
in `current-fence authorizing-operation-plan commitment`; the two fields are
intentionally distinct. The successor's first intent target then advances the
current-fence metadata to the successor plan. Loss settlement may therefore
enter the already committed restore plan, and a terminal settlement may enter
`Bound/idle`, without rewriting or invalidating the fence that authorized the
transition. An uncommitted appended row or plan swap is impossible.

The namespace state table is exhaustive:

| State | Required retained fence/graph | Service or capability outcome |
| :--- | :--- | :--- |
| `Bound` with idle operation gate | exact current `Stable/complete` fence plus its immutable `NextLossEntryScheduleCodecV2`, exact current v2 stamps, and graph; no current operation or journal rows | service may proceed; exact retained inspection yields adoption only |
| `Bound` with planned/running/settling operation gate | exact current group install/remove or drain operation plan, schedule, journal prefix, prior/intent/completion fence, and exact target bound-entry schedule bytes committed by its payload | unaffected exact active groups may continue service, but no other backend mutation, loss qualification, adoption, or decommission may begin |
| `StampAbiMigrating` | exact recorded v1 snapshot, operation plan/schedule, journal rows, and completed migration prefix | stopped; resume only the next step of that migration |
| `LossQualifying` | exact root, marker, epoch, operation plan/schedule, and journal prefix; substate is `QuiescePending` with prior `Stable` or its unique quiesce intent/completion fence, or `Quiesced` with the completed quiesce fence or the separately recorded settlement operation's intent/completion fence | stopped; inspection is authorized only in `Quiesced`; a written settlement successor permits only its matching protected CAS |
| `RestorePending` | exact `LossQualified` fence or the unique intent/completion fence for the current restore step, plus the exact recorded journal prefix | stopped; resume only the current or next step of the same namespace plan |
| `RestoreFinalizing` | exact complete graph and `RestoreVerified` or scheduled next `Stable` fence; complete restore journal | stopped; verify once more or perform only the precommitted final CAS |
| `Poisoned` | exact last trusted fence and recorded contradiction | stopped indefinitely |
| `Decommissioning` / `Decommissioned` | RFC 016 terminal authority plus v2 fence | RFC 016 decommission rules only; no restore |

`Bound/idle` requires operation kind zero, gate `idle`, zero current-operation
plan/schedule/journal fields, an exact nonzero 120-byte bound-entry schedule and
its recomputed commitment, and the
nonzero authorizing-plan, inventory-projection, and expected-prior-fence
commitments retained solely to validate its current `Stable` fence. The entry
schedule's expected stable coordinate must equal the coordinate decoded from
that fence; it never substitutes for full fence validation.
`Bound` with a non-idle gate permits only group install, group remove, or drain
qualification; it requires complete current operation material and retains the
exact target bound-entry schedule bytes committed by that operation. Migration,
loss qualification, restore, and decommission
operation kinds are legal only in their named namespace states. `Poisoned`
requires gate `poisoned`; `Decommissioned` requires no current journal. Any
other state/gate/kind/field combination is a decode error, not a recovery hint.

`Bound(idle) -> LossQualifying` is the sole transition that changes the missing-map
precedence described in §2.3, but only its `Quiesced` substate authorizes an
inspection. No observation itself changes state. Every state change is a
protected CAS with exact readback, a strictly greater authority generation, a
distinct nonce, and a recorded successor. The v2 record's application-level
`protected ledger revision` increments by exactly one with checked arithmetic
for every successful record CAS; the protected store's opaque compare token is
separate. A fence worker can therefore construct revision `R + 1` target
bytes without performing or awaiting the CAS under the host lock. Overflow is
terminal `CapacityExceeded`. While `Bound`, the schedule retains the current
stable coordinate and only the two future quiesce coordinates. The
first `LossQualifying(QuiescePending)` CAS consumes them and records the
complete quiesce operation plan, schedule, and journal. After a read-only exact
inspection in `Quiesced`, a separate protected CAS records exactly one closed
settlement operation—retained adoption or qualified loss—before that
settlement writes a fence. The `RestorePending` CAS likewise records the
complete restore plan and two coordinates for every physical journal step
before restore begins. Each return to `Bound` clears the current operation and
atomically commits a fresh next-loss entry schedule. Fence values are derived
by the acyclic projection rule in §4.2; schedules never embed them. A nonce may
be minted only inside the protected CAS that first records its coordinate, and
neither caller nor backend creates one. No state aliases another state during
decode.

### 4.4 Permanent Bounded Lineage

The reference v2 profile retains at most 1,024 atom rows, 1,024 permanent
groups, 4,096 total group-atom references, 1,024 transfer-edge rows, 1,024
provenance-source rows across all permanent groups, 32 sources in one
partition, 256 atoms in one group or transition, 512 simultaneously live
groups, 512 restore-edge rows globally, 32 restore edges for one group, and
2,048 current operation-journal rows. It additionally caps
lineage depth at 32 and the sum of all canonical desired-group bytes at
384 KiB. The encoded protected-plaintext cap is 4 MiB. The protected-store
backend must advertise at least 64 KiB
above that cap for envelope and framing overhead. It also permits four
CAS/readback attempts, 64 concurrent supervisor slots per namespace, 256 per process,
16 marker entries, 512 KiB/256 atoms in one exact backend inspection, and a
4 KiB diagnostic/evidence record, as in RFC 016.

Those count limits are independent ceilings, not permission to combine every
ceiling in one record. Every v2 state also satisfies a coupled **restore
recoverability invariant**. Let `R` be the exact number of reconstructible
objects selected by restore step 3, `T` the exact number of persistent selector
transitions selected by step 4, `A` the exact number of current active v2 stamp
entries selected by step 5, and `K` the exact number of traffic hooks selected
by step 6. The canonical full-namespace restore journal contains exactly
`5 + R + T + A + K` rows: two stamp-map publications, those four expanded
selector lists, and the three readback/verification/settlement rows. That
value must be at most 2,048 and its encoded journal must fit 704 KiB. The
coordinator derives it from protected desired bytes and the immutable built-in
profile; a backend or caller never supplies a count.

The decoder enforces the invariant for every v2 record with active authority
and independently for any fully committed terminal successor encoded by its
current or prebuilt successor operation.
Initialization, stopped migration, and every operation whose terminal target
would add or change active authority preflight the exact successor restore
journal before nonce generation or the first CAS. A candidate that would make
the successor unrestoreable is `CapacityExceeded` while the prior recoverable
state remains unchanged. Migration rejects such a v1 namespace before
publishing the v2 fence or stamp map, so it remains a usable v1 namespace
rather than becoming an unrecoverable v2 namespace. Loss qualification
recomputes the same committed expansion before its first claim; disagreement
with the protected profile/desired state is `Indeterminate`, never a late
`RestorePending` capacity failure. Thus a legal active v2 namespace always has
a fully precommittable restore journal even when several independent count
ceilings cannot be reached together.

Those inherited supervisor numbers are concurrency slots, not a lifetime or
journal-row limit. The RFC 017 namespace mutation gate admits exactly one
supervisor for its current operation; that supervisor executes up to 2,048
precommitted rows sequentially while retaining its one slot. No row spawns a
second task or consumes another slot. The 64-per-namespace ceiling remains for
coexisting RFC 016 work during migration compatibility, and the process-wide
256-slot admission is preflighted before the RFC 017 operation claim.

A namespace loss inspection or restore may use at most four deterministic
chunks of at most 256 atoms and 512 KiB each under the same operation-scoped
host guard. The restore plan commits the ordered chunk boundaries and one
whole-namespace inventory commitment; a chunk is never an independent proof or
settlement unit. The backend must preflight that the complete operation fits
the RFC 016 critical-section bound before any active-authority-changing claim
and revalidate that fact before the loss-settlement CAS. An unrepresentable or
over-bound candidate is `CapacityExceeded` or `Unsupported` while the prior
state is still recoverable; encountering a different expansion after v2 active
authority exists is `Indeterminate` profile/record drift, not a partially
started restore.

The immutable capacity profile assigns simultaneous encoded-byte maxima of
64 KiB to the header/profile/namespace-operation metadata, 128 KiB to atom rows, 1 MiB
to group rows, 384 KiB to group-atom references, 384 KiB to transfer rows,
256 KiB to source rows, 192 KiB to restore rows, 256 KiB to the frozen-v1
inventory, 320 KiB to the current-v2 inventory, 832 KiB to operation material,
and 64 KiB to all count/length framing. The operation-material allowance
reserves 704 KiB for the operation-journal section and 128 KiB for the retained
canonical operation payload. At the 2,048-row maximum, the journal section is
exactly `4 + 2,048 * (4 + 344) = 712,708` bytes and therefore fits its
independent 704 KiB cap. At the 512-live-group maximum, the restore plan is
exactly `243 + 512 * 192 = 98,547` bytes and therefore fits its independent
128 KiB payload cap. Their simultaneous
sum is 3,904 KiB (3,997,696 bytes), leaving 196,608 bytes below the 4 MiB
plaintext cap.
Counts and the applicable section-byte bound are both checked before allocation.

For encoded header length `H` and the ten ordered sections `S` from §4.3, the
only accepted size is:

```text
L = H + sum(for each section in S: 4 +
            sum(for each row in section: 4 + exact_encoded_row_length))
```

The executable codec-size proof uses the production encoder's exact `H` and
row lengths, fills every section to its maximum under the coupled legal-state
invariants (including both retained stamp inventories during migration), and
must prove `L <= 4,194,304` and each section within its independent byte cap.
It also proves that adding one maximum-length row
to each independent section is rejected before allocation or CAS. The durable
record stores each complete canonical source, transfer-edge, and restore-edge
payload alongside its keyed commitment. The decoder recomputes the commitment
and cross-checks every field against protected group, atom, qualification, and
operation rows. Historical coordinates therefore remain verifiable after a
group advances; they are never guessed from its current lifecycle coordinate.

All capacity, including the successor restore-journal expansion, is validated
before capability minting, nonce generation, CAS, or backend work. An empty v2 ledger fixes the profile at initialization. A
nonempty v1 ledger may fix its one v2 profile only inside the stopped
`StampAbiMigrating` transition after the backend and executable maximum-size
proof accept it; this does not rewrite the v1 profile. Once v2 is selected the
profile is immutable. Exhaustion is a closed `CapacityExceeded`
classification; automatic compaction, history truncation, tombstone deletion,
edge coalescing, or changing a limit in place is forbidden. A maximum-edge
result fails closed rather than making an atom reusable without its history.

## 5. Opaque Capability Surface

RFC 017 has no independently caller-constructible authority surface. It builds on #662's
merged protected namespace coordinator while replacing the v1 direct reuse
path at the v2 boundary described in §2.4. For this document only,
**RFC017 retired-qualified view** means a newly defined SDK-private affine view
minted by that coordinator after it decodes the exact protected `Retired`
record with a durable `Qualified` drain annotation. It is not a public Rust
type or a compatibility promise.

The public unsealed `GtpuDataplaneBackend` trait must be able to name its
request and result carriers, so those carrier structs are public opaque Rust
types. Public visibility is not authority: every field, constructor, decoder,
verifier, and successful response builder remains private to the SDK boundary;
the types implement none of `Clone`, `Copy`, `Default`, `Debug`, `Display`, or
serde. An external implementation may accept them and return `Unsupported`,
but cannot manufacture a successful carrier. #671 may later expose only a
versioned SDK-owned adapter codec/lease that constructs a carrier after exact
conformance checks. Coordinator views, admission capabilities, receipt
verification, and authority constructors remain crate-private.

The coordinator alone mints the retired-qualified view, mixed-source request,
drain request and receipt, durable-active authority, loss-inspection request
and observation, restore request and readback receipt, adoption, and restore
admission. Each is namespace-bound, operation-bound, nonserializable,
noncloneable, noncopyable, non-defaultable, nonconstructible by callers, and
consumed or invalidated at its recorded boundary. Affinity and protected
coordinator validation—not a public `Clone` rule, serde trait, caller-held
lease guard, or restart proof—are the authority. A lost response is joined by
the coordinator's recorded operation, never by replaying a value.

A mixed-source request carries only semantic candidate/predecessor projections
selected through the #662 coordinator. It cannot express a source kind,
commitment, generation, nonce, receipt, raw selector, expected revision, or
backend result. The coordinator canonicalizes it under the durable lease and
derives every `NeverPublished` source from that protected revision. The
retired-qualified view never contains or replays the consumed drain receipt;
the durable qualified annotation and current atom rows authorize later
subsets. Durable-active authority is minted only by the protected coordinator
from the exact `Bound` record and is the sole recovery admission.

No authority or proof type may derive or implement `Debug`, `Display`, serde,
or logging traits. Their only permitted diagnostic representation is an
explicit bounded redacted formatter containing an approved state class and
fixed count buckets. The same prohibition applies to TEIDs, PAA, marks,
ifindex values, group IDs and group entries, raw commitments, nonces, fence
values, receipts, selectors, paths, map identifiers, and backend identities in
all public errors, status, logs, metrics, harness output, and RFC 006 evidence.
Protected codec persistence is not general serialization and never leaves the
coordinator/store boundary.

The RFC 016 removal path, as hardened by #662, is the sole source of the exact
terminal-retired record from which RFC 017 may begin drain qualification. The
v1 public direct-reuse receipt is not accepted. RFC 017's default-unsupported
quiescence port instead returns a newly defined SDK-minted affine receipt only
after the selected backend proves the complete predecessor's terminal-retired
stamp, trusted removed dataplane generation, authoritative absence, and real
drain/RCU boundary. The v2 coordinator consumes it once into the durable
annotation before any subset capability can exist. External adapters are
unsupported until #671 provides the codec and conformance harness. The built-in
eBPF profile is a selected TCB only after privileged isolated qualification;
that qualification is operational evidence, never cryptographic attestation.

## 6. Atomic Mixed Admission

### 6.1 Preflight and Partition Validation

The coordinator canonicalizes the exact new candidate and derives its complete
atom set. This version does not modify an existing group: an exact same-group
`Active` candidate is adoption, and overlap with a different `Active`,
`Installing`, or `Retiring` record is conflict. Under one namespace lease and
one expected protected-ledger revision it validates:

1. each named predecessor capability binds this namespace and resolves to the
   exact current qualified `Retired` group record;
2. each requested retired subset is nonempty, canonical, disjoint, contained
   in both predecessor and candidate, and every selected atom row is
   `RetiredAvailable` from that predecessor; exactly one request may name a
   given predecessor in one candidate;
3. the predecessor transfer gate is `Available`, its immutable drain
   qualification is valid, and no pending or poisoned transfer exists;
4. each candidate atom not covered by a retired subset has no immutable atom
   row and is therefore SDK-derived `NeverPublished` in this revision;
5. the union of retired subsets and SDK-derived fresh atoms equals the complete
   candidate set, and no atom occurs twice or conflicts with a recorded
   disposition; and
6. every group, atom, transfer-edge, source, stamp-slot, byte, lineage, current-
   operation row, and exact successor restore-journal capacity is available for
   the full operation; and
7. the candidate group ID is absent from every permanent `Installing`,
   `Active`, `Retiring`, `Retired`, and `Poisoned` group row and tombstone. The
   sole exception is exact same-group `Active` adoption, which returns before
   mixed admission and performs no CAS or effect; and
8. the exact backend capability/profile and SDK supervisor capacity are
   available before nonce generation or the first CAS; and
9. the namespace-wide backend-mutation gate is idle in `Bound`, its complete
   `Stable/complete` fence matches protected state and exact backend readback,
   and no migration, group install/remove, drain/loss qualification, restore,
   or decommission schedule or journal is pending.

No helper performs a separate per-subset CAS. All checks are inputs to one CAS,
so a predecessor that begins another transfer or an atom claimed concurrently
makes the entire candidate stale before it reaches the backend.

### 6.2 One-CAS State Change

Under the same namespace lease, `claim_mixed_complete_group` reserves two new
nonzero generation/nonce coordinates as RFC 016 requires and writes one
`Installing` group record with `backend_started = false`. The same CAS:

- adds immutable roots for all fresh atoms;
- changes each retired-source atom from `RetiredAvailable` to
  `TransferPending(successor)` and appends its immutable transfer edge;
- changes each participating predecessor transfer gate from `Available` to the
  exact `Pending(operation)`;
- retains every predecessor group tombstone and its terminal-retired stamp;
- records the exact canonical partition commitment and source list in the new
  group; and
- reserves the successor's permanent operation-stamp slot; and
- atomically changes the namespace backend-mutation gate from idle to the
  exact group-install operation, storing its complete semantic payload,
  fence-free journal plan, intent/completion fence schedule, journal rows, and
  zero completed prefix.

It fails unless the expected full ledger revision and every inspected atom/group
row still match. After exact readback, the first §7.1 intent fence and its
byte-for-byte protected target advance `backend_started` one-way; only then
does the coordinator synchronously transfer the affine whole-group request to
its pre-reserved SDK supervisor before another externally cancellable await.
The successor cannot become `Active` until that one authorized effect has
recorded its step intent, passed the exact pre-state
classification, advanced through its unique intent and completion fences,
and has exact post-state readback and terminal stamp. Its recorded settlement
row then advances the retained fence to fresh `Stable/complete` under the host
lock. After readback and lock release, the final CAS clears the namespace
operation journal and installs a fresh next-loss entry schedule. On terminal
success, all its atom tips become `Active(successor)` and every participating
predecessor gate returns to `Available` for its remaining atoms in the same
final CAS. On ambiguity the exact `Installing` operation and predecessor gates
remain `Pending` for RFC 016 recovery. Any contradictory trusted readback
poisons the successor, the selected atoms, and every participating predecessor
gate. A predecessor never regains an atom or starts another transfer by
assuming the failed effect did not happen.

This achieves atomicity at the ownership boundary: either all sources and every
atom belong to the one pending successor, or none do. It intentionally does not
claim that independently retired predecessor traffic is still live; receipts
prove the opposite for each complete predecessor.

### 6.3 Invalid Composition

The coordinator rejects before map/program/traffic mutation: a missing source;
a requested atom outside the candidate; duplicate or overlapping atoms; empty
subset; a supposedly fresh atom with any row; a retired source for an unseen
atom; an exact or overlapping active-group modification; a retired predecessor
that is not qualified, has a pending/poisoned gate, or is cross-device,
cross-pin, or stale; a missing/foreign/stale drain qualification; a changed
predecessor set; a candidate group ID present in any permanent group row or
tombstone other than exact `Active` adoption; altered candidate during the call;
and every unknown codec, capacity, CAS, qualification, or backend classification. A caller cannot cite
a source group merely because a semantic readback says it is gone.

## 7. Adoption and Loss-Qualified Restore

The requested same-group republish is represented by a namespace transaction
because RFC 016 aggregates the marker, backend epoch, stamp inventory, and host
writer fence at the device/pin namespace. If exactly one group is active, this
reconstructs that same group. If several groups are active, restoring only one
would mix pre-loss and post-loss authority under one immutable fence and cannot
be proved safe. One accepted exact-group request therefore aggregates every
current active group, restores all of them atomically at this namespace
boundary, and returns authority for the requested exact group only after the
whole namespace has settled. Selective group restore is unsupported, rather
than silently narrowed to a one-group outcome.

### 7.1 Retained Backend-Mutation Fence

Stopped v2 migration creates one retained authority object in addition to the
RFC 016 root and marker. The eBPF profile pins an array map at the fixed leaf
`GTPU_SELECTOR_BACKEND_FENCE_V2`; its kernel object name is
`opc_gtpu_sf_v2`, map type is `BPF_MAP_TYPE_ARRAY`, key size is 4, value size
is 208, `max_entries` is 1, map flags are zero, and the sole key is the native
u32 zero encoded as four zero bytes. The exact root/leaf descriptor, map ID,
ABI, and value are in every open/readback. Other backends must expose the same
logical retained fence through an immutable inventory profile and the future
#671 conformance harness.

Every retained-fence transition is one atomic whole-value replacement under
the host lock with an exact expected-prior compare. After interruption the
sole key must decode as exactly the prior or target 208-byte value; a torn,
third, missing, or multiply keyed state is `Indeterminate`. A backend that
cannot provide this atomicity and durable readback is `Unsupported` and may not
run any RFC 017 physical step.

This fence object is not part of the reconstructible graph eligible for total
loss. Its value is the exact `BackendMutationFenceCodecV2` authorized by the
protected plan/schedule and authenticated by its exact target record. One protected namespace-wide backend-mutation gate owns the
only current operation plan, schedule, and journal. Every v2 backend mutation—
including migration, mixed install/remove, drain or loss qualification,
restore, and decommission—must first win that gate in the same protected CAS
that records its complete operation material. No second operation may fork a
schedule or begin a physical step until the first returns the gate to `Bound`,
settles terminally, or poisons it.

Each physical step has a distinct scheduled `pending` intent fence and
`complete` fence, except the one §8 bootstrap row. Under the process-lifetime
writer lease, the worker first acquires the operation-scoped host lock only to
capture the exact prior complete fence and pre-effect inventory. While still
holding the lock it constructs the deterministic `intent-recorded` target,
writes/syncs/reads the intent fence that commits that target, and only then
releases the lock. The following protected CAS may write only that byte-for-
byte intent target; no backend effect is permitted before the CAS succeeds and
is read back. The worker then reacquires the host lock, revalidates the
protected intent target, retained intent fence, and exact pre-state, performs
only the recorded single step, and proves exact post-effect inventory. It
constructs the deterministic successor record, writes/syncs/reads the
completion fence that commits that target, and releases the lock. The following
protected CAS may write only that byte-for-byte successor. A crash in either
fence-before-CAS window can install only the target authenticated by the raw
ahead fence; it cannot issue the effect or mint a new coordinate. The worker
revalidates the current root, marker, fence descriptor, operation plan, and
projection before each write. No fence generation may recur; every scheduled
nonce is nonzero and distinct within its operation. Missing,
replaced, regressed, malformed, or unexpected fence state is `RebindRequired`
or `Indeterminate`, never loss.

Any operation that returns to `Bound/idle` ends with a recorded settlement
row. Its intent fence uses that operation's phase and its completion fence is
the fresh `Stable/complete` value; the row has no graph effect beyond final
exact readback and the retained-fence advancement. Only after that completion
is read back may the protected CAS clear the operation, install a fresh next-
loss entry schedule, and expose the idle gate. A protected-store CAS never
writes or implies a backend fence.

An old worker retains neither authority nor a reusable backend request across
loss of the writer lease or host lock. On reacquisition it must reopen
protected state and the retained fence; an advanced journal prefix, different
plan/schedule, intent fence, completion fence, or fenced lease generation
rejects it before mutation. Migration retains RFC 016's process-lifetime
writer gate for the entire transition, so a v1 worker cannot race the first v2
fence or any later migration step.

### 7.2 Durable Qualification and Exact Outcomes

Recovery consumes RFC 017 v2 coordinator-minted durable-active authority; no
public loss receipt exists. Explicit v2 migration must be complete, every group
must be terminal `Active` or `Retired`, decommission must not have begun, and
the namespace-wide backend-mutation gate must be idle. Before the first CAS,
the coordinator preflights capacity, chunks, backend profile, supervisor
capacity, and the exact `NextLossEntryScheduleCodecV2` already committed in
`Bound`. That entry schedule binds the current `Stable` fence coordinate and the next
quiesce step's intent/completion coordinates; it contains no target fence
value. Every later return to `Bound` commits a fresh entry schedule. Thus
`Bound` is never a period with only a reusable stable fence.

The protocol has two durable boundaries and follows RFC 016's lease-then-host-
lock order. It never holds `flock` across a protected-store await or CAS.

1. While holding only the durable lease, the coordinator CASes `Bound(Stable
   S, next entry E)` to `LossQualifying(QuiescePending)`. The CAS consumes `E`,
   stores the complete quiesce operation plan/schedule and step row, sets a
   zero completed prefix and a `planned` row with `backend_started = false`, and
   reads it back. This transition stops new compliant work but does not
   authorize loss inspection.
2. The supervisor acquires the host lock only to reopen and capture the exact
   root, marker, epoch, descriptors, fence `S`, and pre-effect inventory. It
   constructs the exact intent target, writes/syncs/reads its scheduled
   `LossQualifying/pending` fence `Qp`, and releases the lock without awaiting
   the store. With no host lock, the coordinator CASes only the exact planned
   record to that byte-for-byte `intent-recorded` target, thereby storing the
   observation and intent commitment and advancing `backend_started`. No drain
   effect is legal before this CAS. A crash after `Qp` but before the CAS can
   only reconstruct and install that target from exact unchanged pre-state. A
   stale stable worker expecting `S` fails its fence compare as soon as `Qp`
   is written.
3. The supervisor reacquires the host lock, revalidates every captured byte,
   protected intent target, and `Qp`, performs the selected real drain
   boundary, and proves the recorded post-state. It then writes/syncs/reads the
   unique `LossQualifying/complete` fence `Qc` that commits the exact
   `Quiesced` successor record and releases the lock. With no host lock, the
   coordinator CASes the exact intent record only to the byte-for-byte target
   `LossQualifying(Quiesced, completed-prefix=1, Qc)`. Only this second durable
   boundary permits inventory inspection. Its compare includes the complete
   plan, schedule, journal row, descriptors, and `Qc`, so the release/CAS
   window is recoverable without guessing.
4. Under the host lock and exact `Qc`, the supervisor performs one bounded
   read-only inspection and releases the lock. If the result is exact retained
   state or candidate total mutable loss, the coordinator records a separate
   single-step settlement plan, schedule, journal row, successor payload, and
   `backend_started = false` in a protected CAS. The adoption payload commits
   the fresh next-loss entry schedule that its completion-fence target must
   install; the loss
   payload commits its complete target `RestorePending` operation. It does not
   persist an unqualified backend value or expose it to a caller. The
   supervisor reacquires the host lock, revalidates the same exact observation,
   writes/reads the settlement intent fence, and releases; only its exact
   intent-target CAS records handoff and permits settlement to continue. Under
   the next host-lock section it revalidates that protected intent and writes
   either the unique `Stable/complete` adoption fence or the unique
   `LossQualified/complete` fence, each committing its exact successor record.
   Only after exact readback and lock release may the matching CAS return to
   `Bound` with a fresh entry schedule or persist the private loss receipt and
   complete restore plan in `RestorePending`. Any changed or other observation
   is closed.

No backend, adapter, or caller generates a fence or coordinate. A target fence
is coordinator-derived only after its plan and coordinate are protected and
its exact fence-free target projections are constructed; it is never supplied
by the backend. Every host-
lock release followed by a CAS names the exact expected written fence; every
CAS followed by host-lock acquisition rechecks the same schedule, journal,
root, marker, epoch, and descriptor identity. This closes the former `Bound ->
LossQualifying` stable-writer race. A nonce may be generated only inside the
coordinator's immediately committed protected operation or next-entry
schedule; no random unrecorded, caller-held, backend-held, or recovery-created
coordinate exists.

| Exact inspection observation after `Quiesced(Qc)` | Settlement |
| :--- | :--- |
| complete frozen-v1 snapshot, current-v2 map, and every active graph object exactly retained | record the adoption-settlement step; under lock revalidate the observation and advance its intent fence to `Stable/complete`; release; CAS directly to `Bound` with a fresh next-entry schedule and mint adoption only |
| root, marker, epoch, and retained fence exact, while every reconstructible object is absent and all locations enumerate no foreign objects | record the loss-settlement step; under lock revalidate the observation and advance its intent fence to `LossQualified/complete`; release; persist the private receipt and complete restore operation in `RestorePending` |
| missing/replaced root, marker, binding, epoch, or retained fence | `RebindRequired`; remain stopped |
| partial, foreign, stale, rollback, semantically absent, mock-only, traffic-derived, structurally converged, altered, or over-bound graph | `Indeterminate` or `LossUnqualified`; remain stopped |

`ExactRetained` is namespace-wide descriptor and byte equality, not a semantic
readback. `TotalMutableLoss` is narrower than absence: all selector/index maps,
non-retained pins, v1/v2 stamp maps, programs, hooks, journals, and profiled
backend-defined classes must be absent, and every configured location must be
enumerated for foreign objects. Counts, semantic absence, a mock, traffic,
counters, time, one missing map, retained exact state, or structural
convergence cannot prove loss. They yield adoption only where exact retained
state is proven; otherwise they fail closed.

### 7.3 Namespace Restore Without Epoch Rotation

`RestorePending` retains the original RFC 016 root, marker, namespace binding,
backend epoch, frozen-v1 inventory, current-v2 inventory, atom/group/lineage
history, qualified-loss receipt commitment, complete canonical restore payload,
fence-free journal plan, full journal rows, and complete coordinate schedule.
The first step expects `LossQualified`; every later step expects only the prior
row's completion fence. There is no operation-wide reusable `RestoreEffect`
fence.

For each current step, the pre-reserved supervisor first performs a read-only
host-lock preflight of the protected plan, step index, exact prior fence,
descriptors, and exact pre-effect inventory. While holding the lock it
constructs the exact intent target, writes/syncs/reads the step's unique
`RestoreEffect/pending` intent fence, and releases. The coordinator CASes only
the exact `planned` record to that byte-for-byte `intent-recorded` target,
stores the pre-state projection and intent-fence commitment with exact
readback, and advances `backend_started` one-way on the first step. A crash in
that first release/CAS window can only install the target authenticated by the
ahead intent fence. Only after the CAS does the coordinator hand the affine
effect request to the supervisor. The supervisor reacquires the host lock and
revalidates every protected target, intent-fence, descriptor, and pre-state
byte before the step. For an atomic transition, exact pre-state permits its one
no-partial effect and exact post-state permits no second effect; any third or
partial state is `Indeterminate`. Pure verification, repeat-safe barriers, and
atomic private publication follow their closed table semantics in §4.2. After
exact post-state, the supervisor constructs the next protected record,
writes/syncs/reads the completion fence that commits it, and releases the host
lock. The protected CAS may install only that target, thereby advancing the
prefix and exposing the next `planned` row or terminal successor. A crash at
any boundary recovers only the same row; every unlisted fence/state/inventory
triple is closed.

The deterministic semantic plan expands these items into fixed, canonical
journal rows in object/group order:

1. Assemble the complete frozen v1 stamp map anonymously from the migration
   snapshot, verify every entry, and atomically publish it in one class-4 row.
   Separately assemble the complete v2 map anonymously with pending-restore
   values for current active keys and exact terminal values for every other
   key, verify it, and atomically publish it in the next class-4 row.
2. Assemble and verify each complete selector map, pin, or program privately,
   then publish it with one class-4 row in canonical object/group order while
   no traffic hook is attached. The built-in profile is eligible only when
   every selected reconstructible object supports this private-build plus
   atomic no-replace publication contract. A profile requiring in-place or
   per-entry reconstruction is `Unsupported`; it cannot silently expand a
   class-4 row or introduce an uncommitted class-2 fallback.
3. Read back the complete graph, both maps, programs, pins, operation journal,
   root, marker, and retained fence. Replace each current active v2 value with
   its precommitted terminal-active value in a separate class-2 row. The frozen
   v1 values do not change, and no row performs a multi-key update.
4. Attach each hook in its own class-2 row in canonical order. Step 7 then
   performs its separately journaled pure complete-graph/hook readback and
   durability verification. Step 8 reopens and revalidates the current root,
   marker, fence paths, and exact graph; its completion fence commits the
   `RestoreVerified` target and produces one internal exact-readback receipt.
5. Consume that receipt in the step-8 completion-target CAS
   `RestorePending -> RestoreFinalizing`. Persist its exact inventory and fence
   commitment and expose the final settlement row—already present in the
   original restore journal—as the sole next planned row; do not mint a
   capability or append/change the plan. Reacquire the host lock, compare the
   current `RestoreVerified` fence and entire final graph with that durable
   record, revalidate all descriptor identities, and release the lock.
6. Follow the precommitted final settlement row: under the host lock revalidate
   `RestoreVerified` and the complete final graph, construct and write/read/sync
   its unique intent fence, then release and install only its exact intent
   target CAS. Reacquire the host lock, revalidate that target and unchanged
   graph, and write/read/sync the scheduled next `Stable/complete` fence.
   Release the lock. Only then does the exact final protected CAS
   `RestoreFinalizing -> Bound` advance all groups to their precommitted active
   coordinates, append restore edges, record the next-loss entry schedule, and mint
   authority for the requested exact group.

The SDK never holds the host lock across a protected-store await. The retained
monotonic fence closes the two release/CAS windows: while a namespace is not
`Bound`, no other compliant operation is authorized, and every stale writer
expects an older complete fence value. Any intervening effect changes or
invalidates the exact fence/graph required by the next CAS or verification and
fails closed. Traffic and product readiness remain fenced until the final
`Bound` CAS, even if hooks are already attached.

### 7.4 Recovery, Cleanup, and Decommission

Recovery first fences the old lease owner, then interprets the protected state,
its substate, and exact retained-fence value together:

| Protected state | Exact admissible fence/backend state | Only action |
| :--- | :--- | :--- |
| `LossQualifying(QuiescePending)` with planned row | exact prior `Stable` fence and exact pre-state, or exact scheduled quiesce-intent fence and unchanged pre-state | under lock write only the scheduled intent target, or with an already exact intent fence perform only its authenticated intent-target CAS; no drain effect |
| `LossQualifying(QuiescePending)` with intent-recorded row | exact quiesce-intent fence and the row's exact pre/post-state classification, or exact quiesce-completion fence and post-state | under lock follow only that row's effect/completion rule, or with completion already exact perform only its authenticated successor CAS |
| `LossQualifying(Quiesced)` with no settlement row | exact quiesce-completion fence | under lock inspect once; release, then record only the matching adoption or loss settlement operation |
| `LossQualifying(Quiesced)` with settlement row | exact prior completion fence and committed observation, exact settlement-intent fence and pre/post-state, or scheduled `Stable`/`LossQualified` completion fence and post-state | follow only the generic fence-first intent/effect/completion rule; an ahead fence permits only its authenticated next CAS |
| `RestorePending` with planned next row | exact prior completion fence and row pre-state, or exact scheduled intent fence and unchanged pre-state | under lock write only the intent target, or with an ahead intent fence perform only its authenticated intent-target CAS; no effect |
| `RestorePending` with intent-recorded row | exact intent fence and exact row pre/post state, or exact completion fence and post-state | under lock follow only that row's effect/completion rule, or with completion ahead perform only its authenticated successor/prefix CAS |
| `RestorePending` after verification row | complete graph plus exact `RestoreVerified/complete` fence whose target exposes the already planned final row | with no lock install only that target `RestoreFinalizing` record; never append or change a row/coordinate |
| `RestoreFinalizing` with final settlement row | complete exact graph and exact prior `RestoreVerified`, settlement-intent, or `Stable/complete` fence in its matching planned/intent state | follow only the generic fence-first rule; an ahead fence permits only its authenticated intent or final CAS |
| `RestoreFinalizing` after final completion | complete exact graph plus the scheduled `Stable/complete` fence | with no lock perform only the recorded final CAS to `Bound` and install its fresh next-loss entry schedule |

Every other protected/fence/inventory triple is `Indeterminate`; no pair may be
guessed, repaired by a fresh coordinate, or treated as loss. In particular, an
intent fence with neither exact pre-state nor exact post-state proves a partial
or foreign effect and cannot be retried. Equal pre/post inventory permits a
repeat only for effect class 1 or 3; class 3's versioned barrier contract makes
that repeat explicitly idempotent/monotonic, while every other equal-state or
non-idempotent effect is `Unsupported`. An extra object, unjournaled mutation,
changed epoch, missing or foreign retained fence, v1 snapshot change, wrong v2
value, marker replacement, altered desired graph, or receipt mismatch is
`Indeterminate`. Recovery cannot mint another coordinate for a recorded step,
replace its plan, downgrade an atom to fresh, rotate the epoch, restore one
group, or expose or reuse a receipt.

Decommission never treats backend loss as permission to remove history. A
recovery state blocks decommission until it settles or a later offline
forensic procedure is specified. RFC 016 decommission retains atom rows,
transfer/restore edges, both stamp inventories, marker, and backend-mutation
fence. Cleanup may remove reconstructible graph objects only after the exact
terminal decommission fence; it cannot fabricate loss, delete retained
authority, or make a decommissioned namespace provisionable.

## 8. Stamp ABI and Migration

RFC 016 `GTPU_SELECTOR_OPERATION_STAMPS` v1 cannot commit a provenance
partition or distinguish restore. RFC 017 defines
`GTPU_SELECTOR_OPERATION_STAMPS_V2`, keyed by the same 16-byte group ID, with
a fixed 240-byte value. The eBPF profile pins a `BPF_MAP_TYPE_HASH` at the
fixed leaf `GTPU_SELECTOR_OPERATION_STAMPS_V2`; its kernel object name is
`opc_gtpu_os_v2`, key size is 16, value size is 240, `max_entries` is 1,024,
and map flags are zero. Pin identity and all map metadata are exact inventory;
a same-shaped replacement is not adoption.

| Bytes | Field |
| :--- | :--- |
| `0` | version `2` |
| `1` | phase: `1=Installing`, `2=Active`, `3=Retiring`, `4=Retired`, `5=RestorePending` |
| `2` | operation: `1=install`, `2=remove`, `3=restore` |
| `3` | outcome: `1=pending`, `2=active`, `3=absent` |
| `4..8` | zero |
| `8..16` | nonzero authority generation, big-endian |
| `16..32` | operation nonce |
| `32..48` | selector-backend epoch |
| `48..64` | grouped transaction ID, zero only for terminal values |
| `64..96` | namespace-binding SHA-256 commitment |
| `96..128` | keyed group commitment |
| `128..160` | keyed complete-set commitment |
| `160..192` | keyed desired-graph commitment |
| `192..224` | keyed provenance-partition commitment |
| `224..232` | nonzero dataplane group generation, big-endian |
| `232..240` | zero |

Decode rejects an unknown tag, an illegal phase/operation/outcome combination,
zero required field, nonzero reserved byte, or a commitment/epoch inconsistent
with the protected record. The chain is now:

```text
absent -> pending-install -> terminal-active -> pending-remove ->
terminal-retired
                                  |
                                  +-> pending-restore -> terminal-active
```

Nested drain `Qualifying` is a protected-ledger annotation, not a dataplane
stamp phase. The exact v2 terminal-retired stamp remains unchanged throughout it and
is an input to the qualified receipt. A backend whose drain qualification
would mutate a map, program, pin, hook, journal, or traffic state is
`Unsupported`; such a mutation would require a separately specified stamped
operation.

The restore edge is legal only from the exact terminal-active value after a
qualified namespace total-mutable-loss transition; it is not a general loop.
Every current active key enters pending restore with the same grouped
transaction ID, and no subset may settle independently. Each terminal-active
replacement contains the unchanged epoch and unchanged atom/provenance
commitment with strictly higher authority and dataplane generations.

Migration from an RFC 016 v1 bound namespace is stopped, fenced, explicit, and
a prerequisite for every RFC 017 mixed-admission or restore API. Before its
first backend effect, protected `StampAbiMigrating` records the exact complete
v1 map inventory as the immutable **migration snapshot**, the v2 capacity
profile, all per-group v2 values to create, the terminal `Stable` coordinate
and next-loss entry schedule, and a complete migration operation payload, fence-
free journal plan, intent/completion schedule, journal rows, and zero completed
prefix. The SDK validates the RFC 016 ledger/v1 map bijection, the idle v1
operation state, the process-lifetime writer gate, and the exact expanded
restore journal for the proposed terminal v2 state before entering that state.
If the restore journal would exceed 2,048 rows or 704 KiB, migration returns
`CapacityExceeded` without publishing a fence or v2 stamp map and leaves the
v1 record unchanged.

Migration row zero is the only fence-bootstrap exception. With the protected
claim and process-lifetime v1 writer gate already held, the supervisor acquires
the host lock and proves the retained-fence leaf absent. It creates an
anonymous array map with the exact §7.1 ABI, derives the row's completion fence
against the exact prefix-one successor record and observed post-inventory
projection, writes that value at key zero, and validates the anonymous map
before one atomic no-replace pin at the fixed leaf. The pin is the sole
persistent effect. It then reopens the pin, verifies descriptor/object identity
and value, releases the lock, and CASes only the committed successor record.
A crash before the pin leaves no persistent object and repeats the same
protected row; a crash after the pin sees only the exact completion fence and
may perform only its target CAS. Any preexisting, partial, replaced, or foreign
pin is `Indeterminate`. This row has no intent coordinate because no v2 fence
exists yet; the protected migration claim, fenced v1 writer lease, host lock,
and atomic publication jointly provide its one-time authority. It can occur
only at index zero and never after any v2 fence has existed.

After bootstrap, the exact retained fence is the prior fence for every row.
The v2 stamp map is fully assembled and checked while anonymous, then published
by the class-4 row as one atomic persistent effect; it is never copied key by
key after publication. Verification and stable settlement follow the normal
intent/pre-state/effect/post-state/completion protocol. No row shares a fence
coordinate, no partially copied prefix is inferred, and a crash resumes only
the next recorded row. Migrated provenance is the SDK-derived
`rfc016-uniform-provenance/v1` commitment over the complete canonical atom
set; it is never caller supplied.

The migration supervisor retains RFC 016's process-lifetime writer lease from
the stopped v1 claim until the terminal v2 `Bound` CAS. Every v1 reconcile,
remove, drain, recovery, and decommission entry must acquire that same gate and
therefore remains blocked; an already-running v1 worker must revalidate its
lease generation and protected v1 state after every host-lock reacquisition
and fails before mutation once migration wins. The bootstrapped completion
fence and every later step additionally reject a stale v1 worker that observed
the old map state before losing the lock.

After the terminal migration CAS, **v2 is the sole current lifecycle stamp
authority**. This sentence explicitly supersedes RFC 016's rule that the v1
value for every permanent key must continue to equal the group's current
lifecycle value. The v1 map instead becomes a frozen historical snapshot: its
key set and every 208-byte value must remain byte-for-byte equal to the
protected migration snapshot forever, and no RFC 017 operation writes it. On
every open, the SDK independently validates (1) the complete v1 map against
that frozen snapshot and (2) the complete v2 map against current v2 group
state. It never compares a post-migration group generation to a v1 value.
Restore reconstructs the v1 map from the frozen snapshot and the v2 map from
current protected state. Missing either map is admissible only inside the
recorded `LossQualifying`/restore state machine in §7; otherwise it is closed.

Every migrated RFC 016 `Retired` group remains outer `Retired`, receives nested
drain annotation `Unqualified`, and changes its still-owned atom tips to
`RetiredUnavailable`; migration never assumes a historical drain. Cleanup
does not delete the frozen snapshot, current v2 inventory, retained fence,
marker, permanent atom/group/lineage history, or decommission fence. A crash
resumes only the recorded migration journal row and its intent/completion
schedule. The transition to `Bound` validates the frozen v1 snapshot, current
v2 authority, retained fence, marker, and history together and records the
fresh next-loss entry schedule. There is no v1 fallback in open, recovery,
adoption, restore, decommission, cleanup, or old-binary startup: an old binary
that cannot decode v2 remains offline and cannot write, repair, remove, or
restore this namespace. Restore recreates the frozen v1 snapshot exactly and
recreates only v2 current authority; it never makes v1 current. Decommission
retains both inventories, marker, history, and fence; post-terminal cleanup may
remove only reconstructible graph objects and never a retained authority.
Missing, extra, changed, partially copied outside the exact journal prefix,
replaced, or unknown-version objects
fail closed. No in-place reinterpretation, raw map replacement, automatic
startup migration, or fallback from v2 authority to v1 history is permitted.

## 9. Backend Contract and Diagnostics

The backend port remains default-unsupported. Its only RFC 017 operations are
the #662-coordinator-minted retired-drain request/receipt, loss-inspection
request/observation, and namespace-restore request/readback receipt. These are
the public opaque carrier types described in §5, never public constructors or
independent capabilities. The existing unsealed `GtpuDataplaneBackend` trait
adds these separately named methods:

```text
qualify_retired_selector_drain(request) -> drain receipt
inspect_selector_namespace_loss(request) -> loss observation
restore_selector_namespace(request) -> restore receipt
readback_selector_namespace_restore(request) -> restore readback receipt
```

Each method has its own object-safe default implementation returning
`GtpuError::UnsupportedFeature`; adding RFC 017 does not break an existing
backend implementation. The v1 `authorize_selector_reuse` method and its
types are not overloaded or accepted by any of these methods. External success
remains impossible until #671 provides the versioned SDK-owned codec and
qualification lease; the built-in implementation uses the same carrier
invariants internally.

All requests and observations are SDK-minted opaque affine values; a third-party
backend gets no public constructor, selector-secret, raw commitment, or
capability verifier bypass. A qualified backend must consume only those SDK
requests; bind every source, drain receipt, inspection,
stamp, and effect to the exact namespace/group/set/desired/generation/nonce/
epoch; and provide bounded exact readback. It must enforce durable lease first,
then the operation-scoped host-global lock, release the host lock before any
store await/renewal, and revalidate after every reacquisition. It must reject
cross-device, cross-pin, stale coordinate, replay, cancellation ambiguity,
wrong receipt, foreign graph, inventory mismatch, and altered desired graph
before mutation.

The loss observation can be returned only to the SDK-owned supervisor that
consumed the matching inspection request. No public coordinator method accepts
it, and only that supervisor may verify it, form the private receipt codec, and
attempt the recorded `LossQualifying -> RestorePending` CAS. Directly invoking
a backend port therefore cannot create durable restore authority.

For mixed admission, the qualified quiescence operation proves only a complete
retired predecessor at a trusted boundary and returns one affine receipt for
the SDK's durable qualification CAS. For restore, the separate total-mutable-
loss operation and whole-namespace restore must meet §7.2–§7.4. A backend that
can reconcile maps but cannot make either proof remains unsupported for the
corresponding capability; it must not return a weaker success. A third-party
backend is unsupported pending #671's codec and conformance harness. The
selected built-in eBPF TCB is likewise unsupported until privileged isolated
qualification passes §11; that qualification is operational evidence, never
cryptographic attestation.

Errors, status, logs, metrics, and RFC 006 evidence are closed and bounded.
Allowed categories include `Unsupported`, `Conflict`, `CoverageInvalid`,
`PredecessorNotRetired`, `DrainUnqualified`, `RetainedAdopted`,
`LossUnqualified`, `RestoreUnavailable`, `CapacityExceeded`, and
`Indeterminate`. They may include fixed count buckets only. They MUST NOT
include TEIDs, PAA, marks, ifindex values, selector values, addresses,
device/pin names, paths, group/ledger IDs or entries, commitments, generations,
nonces, fence values, receipt contents, keys, map identifiers, backend strings,
or raw traces. A redaction validator rejects evidence containing those values.

## 10. Threats and Failure Outcomes

| Condition | Required outcome |
| :--- | :--- |
| crash/restart before or after any mixed CAS, pending stamp, effect, terminal stamp, or final CAS | resume only the exact recorded operation after fencing, or fail closed |
| caller cancellation, lost response, replay, or duplicate ACK | supervisor settles one durable operation; no token reuse or implicit retry |
| two processes, store clone, or racing predecessor transfer | one whole-ledger CAS wins; the other is stale/conflict/poisoned |
| cross-device, cross-pin, cross-group, or stale coordinate source | reject before mutation |
| altered candidate/desired graph during admission | reject before CAS/effect |
| incomplete drain, fabricated receipt, or missing durable qualification | reject before CAS/effect |
| exact retained namespace | adoption only; no republish or epoch change |
| partial/foreign/stale/rollback/ambiguous backend state | fail closed; never adopt or restore |
| forged/semantic/mock/traffic-derived loss proof | reject as unqualified |
| exact marker retained and every mutable authority object genuinely lost | only bounded whole-namespace `RestorePending` may republish without epoch change |
| marker, control root, namespace binding, or backend epoch lost/replaced | `RebindRequired`; remain offline because rebind is `Unsupported` here |
| loss during decommission or decommissioned state | remain offline; no restore or reprovision |

## 11. RFC 006 Conformance and Acceptance Criteria

An implementation may claim only `not-implemented` or `partial` until every
applicable requirement below has evidence records with source/test references,
artifact digests, platform classification, closed outcomes, and redaction
validation under RFC 006. Passing a mock does not establish backend
conformance, forwarding, or product readiness.

1. Begin with RED public-API tests proving callers cannot construct, clone,
   serialize, substitute, widen, or replay drained-predecessor authority,
   drain receipts, backend loss observations, mixed admissions, durable-active
   authority, adoption, or restore capability. No public coordinator method
   accepts a loss observation or receipt. Semantic subset requests cannot carry
   raw authority, and the complete owned mixed-source request is consumed once.
   Compile-fail and runtime fixtures name every v1-only surface from §2.4—
   `Fresh`, `Reused`, `GtpuSessionSelectorReuseProof`,
   `GtpuSessionGroupReconcileRequest::new_reused`, both
   `GtpuSessionSelectorReuseRequest::confirm_*` methods, all
   `GtpuSessionSelectorReuseProof::after_*` constructors,
   `authorize_selector_reuse`, and the old whole-set reconcile entry—and prove
   none can form or enter a v2 call. A pinned old-binary fixture opens a v2
   record only to fail closed before any write.
2. Unit and model tests prove exact atom canonicalization, subset partition
   coverage, no gaps/overlaps/contradictions, atom disposition transitions,
   immutable roots/edges, one-CAS all-or-nothing admission, and multiple
   fully drained-retired predecessors. Fix-removal and mutation tests independently
   make RED each coverage check, predecessor terminal/drain validation, atom
   row CAS, transfer edge, provenance commitment, durable active authority,
   exact-retained adoption rule, total-mutable-loss verifier, two-boundary
   `Bound -> LossQualifying` quiesce fence, every release/CAS fence compare,
   stale stable-worker rejection, namespace backend-mutation gate, every
   journal intent/completion fence and prefix transition,
   unchanged-epoch guard, and redaction check.
3. Codec golden vectors cover every byte of the v1 subset/source/partition,
   drain-qualification, transfer-edge, loss-inventory, total-loss-receipt,
   namespace-restore-plan, restore-edge, uniform-provenance, authority-
   descriptor, inventory-profile, object-enumeration, authoritative-absence,
   backend-drain-transcript, backend-loss-qualification, durable-active-
   authority, inspection-chunk-plan, backend-step descriptor/body/meta-class/
   subject, every operation-specific payload, operation-journal step/
   projection/plan, operation plan, fence coordinate, next-loss entry schedule,
   fence schedule, protected-state
   projection, backend-state inventory, backend-inventory projection, and
   backend-mutation-fence codecs;
   their distinct domain commitments;
   `SelectorLedgerRecordCodecV2`; the 240-byte stamp; and migration records.
   One-field mutations cover every tag, count, length, atom, predecessor,
   receipt commitment, backend qualification kind/commitment, generation,
   nonce, desired/set/group/binding commitment, unchanged epoch, backend
   profile, descriptor ABI, namespace location, logical subject key, observed runtime identity, inventory
   class/tag/count/commitment, operation kind/payload/plan/schedule, journal
   step/index/prefix/pre-state/post-state/readback/fences, protected revision,
   retained prior fence, reserved byte, and version.
   Exact-length vectors separately prove the 200-byte descriptor body,
   304-byte step subject, 216-byte journal projection, 344-byte full journal
   row, 120-byte next-loss entry schedule, and 208-byte mutation fence. For the fence, 200-byte, 209-byte, and
   nonzero-reserved variants are RED. Unknown versions and ABI changes are
   rejected rather than normalized.
4. Boundary suites exercise every limit and one-over: protected bytes, groups,
   atom rows, group-atom references, transfer edges, restore edges, sources,
   atoms, stamps, 512 simultaneously live groups, 2,048 operation-journal rows,
   the exact 98,547-byte 512-group restore payload and 128 KiB payload cap,
   retries, supervisors, marker entries, readback bytes/atoms,
   diagnostics, lease renewal, and critical-section duration. A simultaneous
   worst-case legal v2 record, including retained v1/v2 inventories during
   migration, round trips below its cap.
   Coupled restore-budget vectors expand the exact selector lists and prove a
   2,048-row successor is accepted, 2,049 rows are rejected before mutation,
   and the otherwise individually legal 512-group/1,024-transition/512-hook
   combination is rejected rather than admitted into an unrestoreable state.
   Stopped v1 migration and every active-authority-changing operation exercise
   the same invariant.
5. Two-process races use real local store handles, independent databases,
   protected-store clones before/after effects, and competing host locks. They
   race fresh claims, drain qualification, overlapping retired subsets,
   serialized disjoint subsets of one predecessor, mixed multiple-predecessor
   claims, namespace restore, adoption, and migration; exactly one permitted
   outcome settles and every other path is closed. They specifically schedule a
   stable worker that reads `S`, loses the lock, and reacquires it after the
   recovery worker advances `S -> Qp -> Qc`; its mutation must be RED. They
   also race a stale worker at every restore/migration journal step after the
   winner advances the unique intent or completion fence. Cross-device,
   cross-generation, cross-pin, stale-plan, stale-prefix, and stale-fence
   variants are independently RED. A fix-removal test that moves the protected
   intent CAS before the intent-fence write must let the stale-`S` worker reach
   mutation and therefore go RED. A separate adversarial mutation that embeds
   a full future `Stable` fence commitment in the next-loss schedule must be
   rejected as a dependency cycle.
6. Store, host, and effect fault injection covers every qualification/CAS/
   readback, receipt, marker/stamp readback, journal, map/program/hook mutation,
   response-loss, timeout, wrong/duplicate ACK, cancellation, backend-fence
   compare/write/readback, and every lock release/reacquisition boundary,
   including intent-fence-written/planned-record and completion-fence-written/
   intent-record windows.
   Restart tests cover each recovery classification,
   every planned/intent/pre-state/effect/post-state/completion/prefix boundary,
   protected-store rollback, map/pin/
   program/hook/stamp loss, marker/fence replacement, stale epoch, and all sides
   of `backend_started`; every quiesce prior/intent/completion, settlement
   prior/intent/completion, restore-step prior/intent/completion,
   restore-verified, and final-settlement protected/fence/inventory triple is
   covered. A restart from every `Bound` and pre-terminal operation state must
   decode the exact persisted 120-byte target/current loss-entry schedule and
   reuse its generations/nonces; deleting the bytes, retaining only their
   commitment, or substituting a freshly generated schedule is RED. Migration
   has the same per-row matrix and retains the
   process-lifetime v1 writer gate. No ambiguity may issue another effect or
   create a fresh coordinate.
7. Adoption and restore tests prove exact retained state produces adoption only;
   partial, foreign, stale, rollback, unknown hook, altered desired, and mixed
   inventories fail closed. They prove only qualified complete mutable loss
   with the exact retained marker produces one namespace `RestorePending`,
   reconstructs every active group, the frozen-v1 snapshot, and current-v2
   inventory, advances all group and backend-fence generations, preserves the
   exact epoch and every atom lineage, and
   cannot run during/after decommission. Attempts to forge a receipt, infer
   loss from semantic absence, retained exact state, partial loss, a mock,
   traffic, or structural convergence; restore one group; replace the marker;
   or rotate the epoch are RED. With multiple active groups, one exact-group
   request must restore all and return requested-group authority only after all
   terminal states settle.
8. Until #671 lands, external adapters and their harness are `Unsupported`.
   #671's future harness must use only coordinator-minted opaque requests and
   SDK-private verification, and must test mixed sources, complete drain, loss
   inspection, exact readback, restarts, replay, stale coordinates,
   cross-device/generation isolation, retained adoption, failure closure, and
   the independent default `Unsupported` result of every RFC 017 backend
   method; semantic grouped reconcile alone cannot pass it.
9. A privileged, isolated eBPF proof is mandatory before claiming eBPF drain
   or restore conformance. It exercises real bpffs descriptor traversal,
   `BPF_FS_MAGIC`, operation-scoped flock, complete maps/pins/programs/hooks/
   journals/stamps inventory, controlled total mutable loss with the original
   marker and backend-mutation fence retained, exact retained adoption,
   partial-loss rejection, marker/fence-loss rejection, restart, and
   generation/epoch fencing. The harness must
   attack namespace/path collisions, bind aliases, marker replacement, extra
   pins, hook collisions, stale stamps, and cleanup races, then verify cleanup
   retains authority fences. Synthetic or unprivileged tests do not replace it.
10. Redaction tests inspect all explicit bounded redacted debug/display values,
    errors, logs, metrics,
   status, harness output, and RFC 006 packs. They must contain only approved
   closed classifications and bounded buckets; any derived `Debug`, `Display`,
   serde, or logging implementation on an authority/proof type is RED. Seeded
   TEID, PAA, mark, ifindex, selector, path, group-ID/entry, commitment, nonce,
   fence, receipt, and key canaries are rejected.

## 12. Alternatives Rejected

### 12.1 A Second Per-Atom Registry

Rejected: it splits ownership from RFC 016's protected device ledger, leaves
two histories to reconcile after crash, and weakens the one-CAS admission
proof. Atom rows are an extension of the existing ledger, not a new authority.

### 12.2 Caller-Supplied Provenance or a Drain Duration

Rejected: neither persists exact ownership, survives replay, or proves a
trusted quiescence boundary. Opaque SDK and qualified backend receipts are
required.

### 12.3 Republish When Readback Is Empty

Rejected: empty current maps may mean partial cleanup, replacement, rollback,
or a forged test. Retained exact state is adopted, while restore requires
complete mutable-authority-loss proof with the original immutable marker and
binding retained.

### 12.4 Silent Stamp Upgrade or Epoch Rotation

Rejected: replacing map ABI or rotating epochs during ordinary startup erases
the fence that distinguishes an old writer from a new one. Migration and
restore are durable, fenced state machines.

## 13. Rollout and Governance

All public surfaces, record/codecs, commitments, stamps, and migration states
are explicit-versioned. A decoder rejects unknown versions before mutation.
Existing RFC 016 users remain constrained to its supported uniform admission
until a stopped, explicit migration completes; this RFC does not silently
broaden an old backend.

GitHub Discussions are disabled for this repository. Issue
[#663](https://github.com/openpacketcore/openpacketcore-sdk/issues/663) is the
public interest-gauging artifact for this proposal, not approval of its design.
A maintainer must approve and merge this RFC's pull request before any
implementation PR relies on RFC 017.
