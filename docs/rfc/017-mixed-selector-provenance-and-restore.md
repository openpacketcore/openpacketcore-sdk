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
constructors, if retained for source compatibility, remain v1-only and return
`Unsupported` for a migrated namespace. They cannot open, modify, restore, or
decommission a v2 record. The v1
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
tips remain unavailable. After exact readback, the one-way `backend_started` CAS hands an
affine request to the pre-reserved SDK supervisor. The backend revalidates the
complete predecessor, terminal-retired stamp, trusted removed dataplane
generation, exact absence, and drain/RCU boundary. The final protected CAS
consumes its affine receipt, records an immutable
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
  selector-backend epoch (16 bytes) || backend-incarnation commitment
  (32 bytes) || immutable control-root descriptor commitment (32 bytes) ||
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
  LossInventoryCodecV1 commitment (32 bytes) || backend qualification
  commitment (32 bytes) || prior stable backend-fence commitment (32 bytes) ||
  written loss-qualified backend-fence commitment (32 bytes)

NamespaceRestorePlanCodecV1:
  version (u8 = 1) || namespace-binding commitment (32 bytes) || protected
  ledger revision (u64 big-endian) || unchanged selector-backend epoch
  (16 bytes) || restore authority generation (u64 big-endian) || restore
  operation nonce (16 bytes) || loss-receipt commitment (32 bytes) ||
  prior v1 stamp-inventory commitment (32 bytes) || prior v2 stamp-inventory
  commitment (32 bytes) || ordered inspection-chunk-plan commitment
  (32 bytes) || loss-qualified backend-fence commitment (32 bytes) ||
  restore-effect backend-fence commitment (32 bytes) || restore-verified
  backend-fence commitment (32 bytes) || active-group count (u16 big-endian) || sorted fixed-width
  active-group entries

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
  (16 bytes) || restore-verified backend-fence commitment (32 bytes)

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
  version (u8 = 1) || profile entry count (u16 big-endian) || entries sorted
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
  absence commitment (32 bytes) || backend incarnation commitment (32 bytes)
  || qualification generation (u64 big-endian) || qualification nonce
  (16 bytes) || drain-boundary kind (u8: 1=synchronize-rcu,
  2=backend-versioned-equivalent) || zero reserved (7 bytes) || drain-boundary
  verifier commitment (32 bytes)

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

BackendMutationFenceCodecV2:
  version (u8 = 2) || phase (u8: 1=Stable, 2=LossQualifying,
  3=LossQualified, 4=RestoreEffect, 5=RestoreVerified,
  6=Decommissioned) || outcome (u8: 1=pending, 2=complete) || zero reserved
  (5 bytes) || nonzero fence generation (u64 big-endian) || operation nonce
  (16 bytes) || selector-backend epoch (16 bytes) || namespace-binding
  commitment (32 bytes) || protected-state commitment (32 bytes) || backend-
  inventory commitment (32 bytes) || operation-plan commitment (32 bytes) ||
  protected ledger revision (u64 big-endian) || zero reserved (24 bytes)
```

`BackendMutationFenceCodecV2` is exactly 208 bytes. Its fixed offsets are
`0` version, `1` phase, `2` outcome, `3..8` reserved, `8..16` fence
generation, `16..32` nonce, `32..48` epoch, `48..80` namespace binding,
`80..112` protected-state commitment, `112..144` inventory commitment,
`144..176` plan commitment, `176..184` protected ledger revision, and
`184..208` reserved. A decoder accepts only a 208-byte value, known tags and
legal phase/outcome pairs, a nonzero generation, and all-zero reserved ranges;
it rejects truncation, extension, noncanonical integers, and any field that
does not recompute from the protected operation. It never normalizes a fence.

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
opc/gtpu-selector/authority-descriptor/v1\0
opc/gtpu-selector/backend-inventory-profile/v1\0
opc/gtpu-selector/backend-object-enumeration/v1\0
opc/gtpu-selector/durable-active-authority/v1\0
opc/gtpu-selector/inspection-chunk-plan/v1\0
opc/gtpu-selector/loss-inventory/v1\0
opc/gtpu-selector/loss-receipt/v1\0
opc/gtpu-selector/namespace-restore-plan/v1\0
opc/gtpu-selector/restore-edge/v1\0
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

### 4.3 Exact V2 Record and State Table

`SelectorLedgerRecordCodecV2` is a replacement protected-plaintext schema, not
an appended registry and not a decoder reinterpretation of v1 bytes. Its exact
header is:

```text
version (u8 = 2) || namespace-state tag (u8) || migration tag (u8) ||
zero reserved (u8) || protected ledger revision (u64 big-endian) || exact
RFC 016 namespace binding (145 bytes) || selector secret (32 protected bytes)
|| immutable-capacity-profile commitment (32 bytes) || active stamp ABI
(u8 = 2) || section count (u8 = 9) || zero reserved (6 bytes) || current
backend-mutation-fence commitment (32 bytes)
```

The header is followed by exactly nine sections in this order: atom rows,
group rows, group-atom references, transfer-edge rows, provenance-source rows,
restore-edge rows, frozen-v1 stamp inventory, current-v2 stamp inventory, and
namespace-operation state. Each section is `count (u32
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

NamespaceOperationStateCodecV2:
  version (u8 = 2) || state tag (u8 matching the namespace state table) ||
  backend-started (u8: 0 or 1) || zero reserved (5 bytes) || operation authority
  generation (u64 big-endian) || operation nonce (16 bytes) || precommitted
  terminal authority generation (u64 big-endian) || precommitted terminal
  nonce (16 bytes) || current backend-fence commitment (32 bytes) || complete
  precommitted fence-schedule commitment (32 bytes) || operation-plan
  commitment (32 bytes) || inventory commitment (32 bytes) || receipt
  commitment (32 bytes) || chunk-plan commitment (32 bytes)
```

The group row's source/edge spans must be in range, contiguous, and owned by
that group; atom and group references must be a bijection with their exact
canonical sets. `lineage depth` is zero at first publication, increments once
per transfer, and has immutable maximum 32. A committed-payload row can occur
only in its named section with the matching kind. Its owner, order, complete
canonical payload, and recomputed commitment must agree with the group, atom,
qualification, and operation rows; a decoder never accepts an orphaned digest
as lineage. The namespace-operation row count is exactly one. Unknown tag,
illegal zero, nonzero reserved field, dangling span, counter mismatch, wrong
recomputed commitment, or an impossible cross-row state is fieldless
`Indeterminate` before capability minting or backend work.

The namespace state table is exhaustive:

| State | Required retained fence/graph | Service or capability outcome |
| :--- | :--- | :--- |
| `Bound` | exact current `Stable` fence plus an immutable next-loss fence schedule, exact current v2 stamps, and graph | service may proceed; exact retained inspection yields adoption only |
| `StampAbiMigrating` | exact recorded v1 snapshot and exact migration prefix | stopped; resume only that migration |
| `LossQualifying` | exact root, marker, epoch, and schedule; substate is `QuiescePending` with prior `Stable` or next `LossQualifying` fence, or `Quiesced` with that fence or its precommitted `LossQualified`/next-`Stable` settlement | stopped; inspection is authorized only in `Quiesced`; a written settlement successor permits only its matching protected CAS |
| `RestorePending` | exact `LossQualified`, `RestoreEffect`, or completed `RestoreVerified` fence and exact recorded restore prefix | stopped; resume only the same namespace plan |
| `RestoreFinalizing` | exact complete graph and `RestoreVerified` or scheduled next `Stable` fence | stopped; verify once more or perform only the precommitted final CAS |
| `Poisoned` | exact last trusted fence and recorded contradiction | stopped indefinitely |
| `Decommissioning` / `Decommissioned` | RFC 016 terminal authority plus v2 fence | RFC 016 decommission rules only; no restore |

`Bound -> LossQualifying` is the sole transition that changes the missing-map
precedence described in §2.3, but only its `Quiesced` substate authorizes an
inspection. No observation itself changes state. Every state change is a
protected CAS with exact readback, a strictly greater authority generation, a
distinct nonce, and a precommitted successor. The schedule contains every
fence value required through the next return to `Bound`: quiesce,
loss-qualified, restore-effect, restore-verified, next-stable, and the next
loss/quiesce value. The protected namespace coordinator mints and records this
entire affine schedule before any backend work; neither a caller nor a backend
creates an unrecorded coordinate. No state aliases another state during decode.

### 4.4 Permanent Bounded Lineage

The reference v2 profile retains at most 1,024 atom rows, 1,024 permanent
groups, 4,096 total group-atom references, 1,024 transfer-edge rows, 1,024
provenance-source rows across all permanent groups, 32 sources in one
partition, 256 atoms in one group or transition, 512 restore-edge rows
globally, and 32 restore edges for one group. It additionally caps
lineage depth at 32 and the sum of all canonical desired-group bytes at
384 KiB. The encoded protected-plaintext cap is 4 MiB. The protected-store
backend must advertise at least 64 KiB
above that cap for envelope and framing overhead. It also permits four
CAS/readback attempts, 64 supervised effects per namespace, 256 per process,
16 marker entries, 512 KiB/256 atoms in one exact backend inspection, and a
4 KiB diagnostic/evidence record, as in RFC 016.

A namespace loss inspection or restore may use at most four deterministic
chunks of at most 256 atoms and 512 KiB each under the same operation-scoped
host guard. The restore plan commits the ordered chunk boundaries and one
whole-namespace inventory commitment; a chunk is never an independent proof or
settlement unit. The backend must preflight that the complete operation fits
the RFC 016 critical-section bound before the `RestorePending` CAS. An
unrepresentable or over-bound namespace is `CapacityExceeded` or `Unsupported`,
not partially restored.

The immutable capacity profile assigns simultaneous encoded-byte maxima of
64 KiB to the header/profile/operation metadata, 128 KiB to atom rows, 1 MiB
to group rows, 384 KiB to group-atom references, 384 KiB to transfer rows,
256 KiB to source rows, 192 KiB to restore rows, 256 KiB to the frozen-v1
inventory, 320 KiB to the current-v2 inventory, 384 KiB to migration/restore
operation material, and 64 KiB to all count/length framing. Their simultaneous
sum is 3,456 KiB (3,538,944 bytes), leaving 655,360 bytes below the 4 MiB
plaintext cap.
Counts and the applicable section-byte bound are both checked before allocation.

For encoded header length `H` and the nine ordered sections `S` from §4.3, the
only accepted size is:

```text
L = H + sum(for each section in S: 4 +
            sum(for each row in section: 4 + exact_encoded_row_length))
```

The executable codec-size proof uses the production encoder's exact `H` and
row lengths, fills every independent dimension to its simultaneous legal
maximum (including both retained stamp inventories during migration), and
must prove `L <= 4,194,304` and each section within its independent byte cap.
It also proves that adding one maximum-length row
to each independent section is rejected before allocation or CAS. The durable
record stores each complete canonical source, transfer-edge, and restore-edge
payload alongside its keyed commitment. The decoder recomputes the commitment
and cross-checks every field against protected group, atom, qualification, and
operation rows. Historical coordinates therefore remain verifiable after a
group advances; they are never guessed from its current lifecycle coordinate.

All capacity is validated before capability minting, nonce generation, CAS, or
backend work. An empty v2 ledger fixes the profile at initialization. A
nonempty v1 ledger may fix its one v2 profile only inside the stopped
`StampAbiMigrating` transition after the backend and executable maximum-size
proof accept it; this does not rewrite the v1 profile. Once v2 is selected the
profile is immutable. Exhaustion is a closed `CapacityExceeded`
classification; automatic compaction, history truncation, tombstone deletion,
edge coalescing, or changing a limit in place is forbidden. A maximum-edge
result fails closed rather than making an atom reusable without its history.

## 5. Opaque Capability Surface

RFC 017 has no independently public capability surface. It builds on #662's
merged protected namespace coordinator while replacing the v1 direct reuse
path at the v2 boundary described in §2.4. For this document only,
**RFC017 retired-qualified view** means a newly defined SDK-private affine view
minted by that coordinator after it decodes the exact protected `Retired`
record with a durable `Qualified` drain annotation. It is not a public Rust
type or a compatibility promise.

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
6. every group, atom, transfer-edge, source, stamp-slot, byte, and lineage
   capacity is available for the full operation; and
7. the candidate group ID is absent from every permanent `Installing`,
   `Active`, `Retiring`, `Retired`, and `Poisoned` group row and tombstone. The
   sole exception is exact same-group `Active` adoption, which returns before
   mixed admission and performs no CAS or effect; and
8. the exact backend capability/profile and SDK supervisor capacity are
   available before nonce generation or the first CAS.

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
- reserves the successor's permanent operation-stamp slot.

It fails unless the expected full ledger revision and every inspected atom/group
row still match. After exact readback, the coordinator performs the RFC 016
one-way `backend_started` CAS/readback and synchronously transfers the affine
whole-group request to its pre-reserved SDK supervisor before another
externally cancellable await. The successor cannot become `Active` until that
one authorized effect has exact readback and terminal stamp. On terminal
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

This fence object is not part of the reconstructible graph eligible for total
loss. Its value is the exact `BackendMutationFenceCodecV2` precommitted by the
protected record. Every v2 backend mutation—including mixed install/remove,
loss qualification, restore, migration, and decommission—must, under the host
lock, compare the complete prior value, perform only its recorded effect, write
and sync the strictly greater precommitted value, exactly read it back, and
revalidate the current root/marker/fence descriptors before success. No
generation or nonce may recur. Missing, replaced, regressed, malformed, or
unexpected fence state is `RebindRequired` or `Indeterminate`, never loss.

### 7.2 Durable Qualification and Exact Outcomes

Recovery consumes RFC 017 v2 coordinator-minted durable-active authority; no
public loss receipt exists. Explicit v2 migration must be complete, every group must
be terminal `Active` or `Retired`, and decommission must not have begun. Before
the first CAS, the coordinator preflights capacity, chunks, backend profile,
and supervisor capacity, then validates the complete private fence schedule
already committed in `Bound`; it creates no coordinate at recovery request
time. The schedule is committed when the namespace enters `Bound`, and every
later return to `Bound` commits a fresh next-loss/quiesce coordinate. Thus an
entry to `Bound` is never a period with only a reusable stable fence.

The protocol has two durable boundaries and follows RFC 016's lease-then-host-
lock order. It never holds `flock` across a protected-store await or CAS.

1. While holding only the durable lease, the coordinator CASes
   `Bound(Stable S, next quiesce Q)` to
   `LossQualifying(QuiescePending, expected S, precommitted Q)` and reads it
   back. This transition stops new compliant work but does not authorize
   inspection.
2. The supervisor acquires the host lock, reopens and revalidates the root,
   marker, epoch, descriptors, protected operation, and exact fence `S`; it
   writes, syncs, and reads back `Q`, then releases the lock. A stable worker
   that acquired the lock using `S` before this step must compare/write `S` and
   now fails. A worker that reacquires later must reread the protected state
   and fails because it is no longer `Bound`.
3. While holding no host lock, the coordinator CASes the exact pending pair to
   `LossQualifying(Quiesced, observed Q)`. Only this second boundary permits
   inventory inspection. Its compare includes the schedule and `Q`, so the
   release/CAS window is fenced even if the process crashes.
4. The supervisor reacquires the host lock and, while expecting `Q`, performs
   the one recorded bounded inspection. Exact retained state advances the
   precommitted next `Stable` fence under that lock before an adoption CAS.
   Qualified total mutable loss advances the precommitted `LossQualified`
   fence under that lock and yields one SDK-private affine receipt. The written
   fence commits the complete inspection inventory and operation plan, so an
   exact reinspection can reconstitute only that same receipt after a crash;
   it cannot mint a new coordinate. The supervisor releases the lock before
   either protected CAS. Any other observation is closed.

No backend, adapter, or caller generates a fence or coordinate. All current
and future fence values, including the next return-to-`Bound` loss fence, are
private coordinator values committed before their first use. Every host-lock
release followed by a CAS names the exact expected written fence; every CAS
followed by host-lock acquisition rechecks the same schedule, root, marker,
epoch, and descriptor identity. This closes the former `Bound ->
LossQualifying` stable-writer race. A nonce may be generated only as part of
the coordinator's immediately committed protected schedule; no random,
unrecorded, caller-held, backend-held, or recovery-created coordinate exists.

| Exact inspection observation after `Quiesced(Q)` | Settlement |
| :--- | :--- |
| complete frozen-v1 snapshot, current-v2 map, and every active graph object exactly retained | under lock advance to the scheduled next `Stable`; release; CAS directly to `Bound` and mint adoption only |
| root, marker, epoch, and retained fence exact, while every reconstructible object is absent and all locations enumerate no foreign objects | under lock advance to scheduled `LossQualified`; release; persist the private receipt and plan in `RestorePending` |
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
history, qualified-loss receipt commitment, and complete precommitted schedule.
After exact CAS readback, the coordinator performs the one-way
`backend_started` CAS/readback and hands the affine request to the pre-reserved
supervisor before another externally cancellable await. The supervisor uses
lease then host lock, expects `LossQualified`, advances to the precommitted
`RestoreEffect` fence under that lock, releases it, and only then continues the
intent-first restore journal. It records and syncs each exact next step before
the effect, then reads back and records completion. Each physical
journal/effect/readback step acquires the host lock while expecting its exact
scheduled fence, performs no protected-store call while locked, releases it,
and records the result with the matching protected CAS before the next step.
The deterministic plan is:

1. Recreate the frozen v1 stamp map byte-for-byte from the migration snapshot.
   Recreate the v2 map as the sole current lifecycle authority; current active
   keys receive their precommitted pending-restore values and every other key
   receives its exact current terminal value. Read back both complete maps.
2. Recreate every selector map, pin, program, and active desired group in
   canonical object/group order while no traffic hook is attached. Verify each
   journaled prefix and current authority descriptors.
3. Read back the complete graph, both maps, programs, pins, journal, root,
   marker, and retained fence. Replace current active v2 values with their
   precommitted terminal-active values. The frozen v1 values do not change.
4. Attach hooks in canonical order, read back the complete graph/hook
   inventory, sync durability, then compare-and-write the precommitted
   `RestoreVerified` fence under the host lock. Reopen and revalidate current
   root, marker, and fence paths before releasing the lock and producing one
   internal exact-readback receipt.
5. Consume that receipt in the protected CAS
   `RestorePending -> RestoreFinalizing`. Persist its exact inventory and fence
   commitment; do not mint a capability. Reacquire the host lock, compare the
   current `RestoreVerified` fence and entire final graph with that durable
   record, revalidate all descriptor identities, and release the lock.
6. Reacquire the host lock expecting `RestoreVerified`, revalidate the complete
   final graph, and write/read/sync the scheduled next `Stable` fence. Release
   it. Only then does the exact final protected CAS
   `RestoreFinalizing -> Bound` advance all groups to their precommitted active
   coordinates, append restore edges, record the next loss schedule, and mint
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
| `LossQualifying(QuiescePending)` | exact prior `Stable` fence | under lock perform only recorded `S -> Q`; release before any CAS |
| `LossQualifying(QuiescePending)` | exact `Q` fence | with no lock, persist only `Quiesced(Q)` |
| `LossQualifying(Quiesced)` | exact `Q` fence plus exact retained graph | under lock perform scheduled `Q -> Stable`; release, then adoption CAS |
| `LossQualifying(Quiesced)` | exact scheduled next `Stable` fence plus the same exact retained graph | with no lock, persist only the precommitted adoption result and return to `Bound` |
| `LossQualifying(Quiesced)` | exact `Q` fence plus exact total mutable loss | under lock repeat only recorded inspection and `Q -> LossQualified`; release before receipt CAS |
| `LossQualifying(Quiesced)` | exact `LossQualified` fence plus exact total mutable loss matching its committed inventory and plan | reconstruct only the same private receipt and persist only the precommitted `RestorePending` plan |
| `RestorePending` | exact `LossQualified` fence and no restore effect | under lock perform only scheduled `LossQualified -> RestoreEffect`; release before recording it |
| `RestorePending` | exact `RestoreEffect` fence and one exact journaled prefix | resume only its next journaled step with the matching scheduled fence |
| `RestorePending` | complete graph plus exact `RestoreVerified` fence | with no lock, persist the same readback into `RestoreFinalizing` |
| `RestoreFinalizing` | complete exact graph and `RestoreVerified` fence | under lock perform scheduled `RestoreVerified -> Stable`; release, then final CAS to `Bound` |
| `RestoreFinalizing` | complete exact graph plus the scheduled next `Stable` fence | with no lock, perform only the precommitted final CAS to `Bound` |

Every other protected/fence pair is `Indeterminate`; no pair may be guessed,
repaired by a fresh coordinate, or treated as loss. An extra object,
unjournaled mutation, changed epoch, missing or foreign retained fence, v1
snapshot change, wrong v2 value, marker replacement, altered desired graph, or
receipt mismatch is `Indeterminate`. Recovery cannot mint another plan,
downgrade an atom to fresh, rotate the epoch, restore one group, or expose or
reuse a receipt.

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
profile, all per-group v2 values to create, the initial `Stable` fence and
complete next-loss schedule, and one migration coordinate. The SDK validates
the RFC 016 ledger/v1 map bijection before entering that state. Under the host
lock it creates the exact v2 stamp map and retained backend-fence map, copies
each group into v2, writes the recorded initial fence, and exactly reads all
three authority maps. Migrated provenance is the SDK-derived
`rfc016-uniform-provenance/v1` commitment over the complete canonical atom
set; it is never caller supplied.

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
resumes only the recorded migration phase and its precommitted map/fence
schedule. The transition to `Bound` validates the frozen v1 snapshot, current
v2 authority, retained fence, marker, and history together and records the
next loss/quiesce coordinate. There is no v1 fallback in open, recovery,
adoption, restore, decommission, cleanup, or old-binary startup: an old binary
that cannot decode v2 remains offline and cannot write, repair, remove, or
restore this namespace. Restore recreates the frozen v1 snapshot exactly and
recreates only v2 current authority; it never makes v1 current. Decommission
retains both inventories, marker, history, and fence; post-terminal cleanup may
remove only reconstructible graph objects and never a retained authority.
Missing, extra, changed, partially copied, replaced, or unknown-version objects
fail closed. No in-place reinterpretation, raw map replacement, automatic
startup migration, or fallback from v2 authority to v1 history is permitted.

## 9. Backend Contract and Diagnostics

The backend port remains default-unsupported. Its only RFC 017 operations are
the #662-coordinator-minted retired-drain request/receipt, loss-inspection
request/observation, and namespace-restore request/readback receipt. These are
SDK-private protocol values, not public Rust constructors or extension traits.

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
2. Unit and model tests prove exact atom canonicalization, subset partition
   coverage, no gaps/overlaps/contradictions, atom disposition transitions,
   immutable roots/edges, one-CAS all-or-nothing admission, and multiple
   fully drained-retired predecessors. Fix-removal and mutation tests independently
   make RED each coverage check, predecessor terminal/drain validation, atom
   row CAS, transfer edge, provenance commitment, durable active authority,
   exact-retained adoption rule, total-mutable-loss verifier, two-boundary
   `Bound -> LossQualifying` quiesce fence, every release/CAS fence compare,
   stale stable-worker rejection, namespace `RestorePending` fence,
   unchanged-epoch guard, and redaction check.
3. Codec golden vectors cover every byte of the v1 subset/source/partition,
   drain-qualification, transfer-edge, loss-inventory, total-loss-receipt,
   namespace-restore-plan, restore-edge, uniform-provenance, authority-
   descriptor, inventory-profile, object-enumeration, authoritative-absence,
   backend-drain-transcript, durable-active-authority, inspection-chunk-plan,
   and backend-mutation-fence codecs; their domain commitments;
   `SelectorLedgerRecordCodecV2`; the 240-byte stamp; and migration records.
   One-field mutations cover every tag, count, length, atom, predecessor,
   receipt commitment, generation, nonce, desired/set/group/binding commitment,
   unchanged epoch, inventory class/tag/count/commitment, reserved byte, and version.
   `BackendMutationFenceCodecV2` vectors prove all offsets, 208-byte exact
   length, and each reserved byte; 200-byte, 209-byte, and nonzero-reserved
   variants are RED. Unknown versions and ABI changes are rejected rather than
   normalized.
4. Boundary suites exercise every limit and one-over: protected bytes, groups,
   atom rows, group-atom references, transfer edges, restore edges, sources,
   atoms, stamps, retries, supervisors, marker entries, readback bytes/atoms,
   diagnostics, lease renewal, and critical-section duration. A simultaneous
   worst-case legal v2 record, including retained v1/v2 inventories during
   migration, round trips below its cap.
5. Two-process races use real local store handles, independent databases,
   protected-store clones before/after effects, and competing host locks. They
   race fresh claims, drain qualification, overlapping retired subsets,
   serialized disjoint subsets of one predecessor, mixed multiple-predecessor
   claims, namespace restore, adoption, and migration; exactly one permitted
   outcome settles and every other path is closed. They specifically schedule a
   stable worker that reads `S`, loses the lock, and reacquires it after the
   recovery worker advances `S -> Q`; its mutation must be RED. Cross-device,
   cross-generation, cross-pin, and stale-fence variants are independently RED.
6. Store, host, and effect fault injection covers every qualification/CAS/
   readback, receipt, marker/stamp readback, journal, map/program/hook mutation,
   response-loss, timeout, wrong/duplicate ACK, cancellation, backend-fence
   compare/write/readback, and every lock release/reacquisition boundary.
   Restart tests cover each recovery classification,
   every intent/effect journal boundary, protected-store rollback, map/pin/
   program/hook/stamp loss, marker/fence replacement, stale epoch, and all sides
   of `backend_started`; every `QuiescePending/Q`, `Quiesced/Q`,
   `Quiesced/LossQualified`, `Quiesced/next-Stable`, restore-effect,
   restore-verified, and `RestoreFinalizing/next-Stable` protected/fence pair
   is covered. No ambiguity may issue another effect or create a fresh
   coordinate.
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
   default `Unsupported`; semantic grouped reconcile alone cannot pass it.
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
