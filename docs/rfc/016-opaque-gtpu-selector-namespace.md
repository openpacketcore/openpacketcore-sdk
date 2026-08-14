# OPC-SDK-RFC-016: Opaque Durable GTP-U Selector Namespace

**Status**: Proposed

**Version**: 1.0.0

**Date**: 2026-08-13

**Audience**: SDK dataplane implementers, durable-store implementers, security
reviewers, and downstream packet-core product teams

## 1. Abstract

This RFC defines an experimental, product-neutral SDK authority boundary for a
grouped GTP-U selector namespace. It replaces a caller assertion that a
selector set is `Fresh` with an SDK-issued, affine admission capability.

The authority is one device-scoped durable selector ledger. It binds a stable
device namespace, exact group, and every canonical TEID, PAA, and bearer-mark
selector atom. It records a nonzero monotonic generation, operation nonce,
and permanent tombstones. It composes existing durable SessionStore and, where
distributed authority is required, the existing Openraft-backed state-machine
path. It does not create a new consensus engine, sequence authority, product
allocator, readiness policy, or persistence product choice.

This RFC is an SDK mechanism proposal only. It is experimental and does not
claim ePDG, EPC, carrier, traffic, or production readiness.

## 2. Problem and Scope

### 2.1 Problem

The existing grouped GTP-U reconcile API accepts a publicly constructible
`GtpuSessionSelectorProvenance::Fresh`. A caller can therefore assert that a
TEID/PAA/mark selector set has never been published, but cannot prove it. The
dataplane deliberately keeps no permanent selector history: maps and programs
can be lost, a pin tree can be cleaned, and an ordinary readback can establish
only current state, not absence from all prior publication.

An application-local wrapper cannot repair this generic anti-ABA boundary. It
cannot bind a different process, backend instance, durable history, or prior
cleanup to an SDK-visible authority. The SDK must issue the admission only
after a complete durable namespace transaction.

### 2.2 In Scope

- One backend-neutral, device-scoped durable selector ledger and its exact
  state machine.
- An opaque affine admission, effect, and removal capability surface.
- Exact canonicalization and atomic ownership of a complete grouped selector
  set: every TEID, PAA, and nonzero bearer-mark selector atom.
- Durable identity, encryption boundary, permanent tombstones, CAS recovery,
  and backend conformance.
- A persistent eBPF control marker that prevents a live or cleaned pin graph
  from silently changing the ledger authority.
- Local and distributed composition with RFC 004 SessionStore and ADR 0019's
  single Openraft engine.
- Bounded redacted diagnostics and RFC 006 evidence requirements.

### 2.3 Out of Scope

- Product selector allocation, subscriber/session lifecycle, authorization,
  traffic admission, readiness, drain, retry, and deployment policy.
- A product's persistence provider, retention tier, key-custody choice, or
  operator workflow, subject to this RFC's durability and conformance rules.
- Per-selector mixed provenance and same-group republish. They require a
  distinct proposal tracked by issue #663.
- Rebinding traffic-proof authority after a selector authority change. That is
  distinct work tracked by issue #664.
- A claim that reconcile/readback proves forwarding traffic, a carrier
  qualification, or a product-safe migration.

## 3. Design Goals

### 3.1 Safety

- A public caller MUST NOT name, construct, serialize, clone, or substitute a
  `Fresh` assertion.
- A successful claim MUST cover the complete exact group and its complete
  selector set atomically; partial atom ownership is not representable.
- A stale, replayed, cross-device, cross-pin-namespace, cross-group, malformed,
  partial, or split-brain operation MUST fail closed before map or traffic
  mutation.
- Each committed lifecycle transition MUST have a nonzero monotonic generation
  and a unique operation nonce. A generation MUST never wrap or be reused.
- Retired history MUST be permanent within the selected durable authority.

### 3.2 Product Boundary

In accordance with ADR 0018, the SDK owns this reusable mechanism; a downstream
product owns which selectors to request, whether its lifecycle is ready, how
to allocate them, its credentials, and its deployment policy. No API in this
RFC is an ePDG facade or chooses APN, realm, PLMN, subscriber, IKE, or traffic
policy. All public types and documentation MUST call the feature experimental.

### 3.3 Boundedness and Privacy

All complete sets, records, retries, filesystem work, and diagnostics MUST have
fixed documented bounds. Selector values, subscriber addresses, ledger IDs,
secrets, commitments, operation nonces, and cryptographic keys MUST be absent
from `Debug`, `Display`, logs, metrics, status, errors, and RFC 006 evidence.
Only closed classifications, count buckets, and bounded outcome summaries are
permitted.

## 4. Terms and Canonical Identity

### 4.1 Selector Atoms and Group

A *selector atom* is the canonical bytes of one GTP-U matching component:

- a local TEID together with the selector role and address family where the
  existing group model requires it;
- a PAA together with address family and prefix semantics; or
- a nonzero bearer mark together with its full-mask semantics.

The existing grouped model remains the sole source of selector semantics. The
namespace code MUST canonicalize the exact `GtpuSessionGroup` before hashing:
it validates all model invariants, normalizes ordered fields, rejects duplicate
or ambiguous atoms, and produces one sorted complete atom set. It MUST NOT
invent per-atom APIs or accept caller-supplied digests.

The *group identity* is the canonical complete group identity, excluding only
volatile process and kernel-instance values. The *set identity* is the complete
sorted atom set. Both are domain-separated HMAC-SHA-256 digests under the
selector secret and remain inside SDK opaque values. Length-prefixed inputs use
unsigned 64-bit big-endian lengths; fixed-width numeric selector fields use
their existing model/network byte order. Public output exposes neither the
canonical bytes nor a digest.

### 4.2 Device-Scoped Namespace

One selector namespace is identified by this exact tuple:

```text
selector-namespace/v1 || stable-device-namespace || canonical-pin-namespace
```

`stable-device-namespace` is the stable SDK GTP-U device identity, not a Linux
ifindex, process ID, network-namespace inode, interface name, or caller label.
`canonical-pin-namespace` is the validated bpffs namespace used by the eBPF
backend. The SDK backend owns its opaque 32-byte SHA-256 namespace commitment;
third-party callers never supply path bytes. It is part of the identity even
when the maps are presently absent. A backend MUST reject an alias, relative
path, noncanonical encoding, or a request which cannot prove both bindings.

The tuple is the ledger aggregation and ownership boundary. There is exactly
one durable ledger for it. A device with a different pin namespace, or a pin
namespace with a different stable device, is a different namespace and cannot
reuse a capability.

The RFC 004 `TenantId` and `SessionKey` used to route the ledger record are
storage-scope coordinates, not additional selector namespaces. The backend
mints one opaque namespace binding that commits to those coordinates when the
namespace is first initialized. They cannot be supplied again on each claim or
changed after binding. A second tenant, record key, database, or copied store
which names the same device/pin tuple therefore conflicts with the immutable
backend binding; it does not create another usable ledger. Implementations MUST
not offer a production `open(store, arbitrary_session_key, ...)` constructor.

## 5. Durable Selector Ledger

### 5.1 Authority Record

The SDK MUST mint a cryptographically random ledger ID and a fresh 32-byte
selector secret when it transitions an exact `Provisioned` record into an
`Initializing` ledger. It first validates all configured capacities and the
selected store profile, then settles that CAS by exact readback. The full
record, including the ID and secret,
MUST be protected according to RFC 004 §14.1: production profiles use
`EncryptingSessionBackend` or `RemoteSealingSessionBackend`; an explicitly
declared same-cryptographic-boundary profile is permitted only where RFC 004
permits it and cannot claim at-rest protection.

The production constructor accepts only a `SessionStore` whose backend
implements the SDK-sealed `ProtectedSessionBackend` gate, rather than a generic
`SessionBackend`. Only the SDK's built-in `EncryptingSessionBackend` and
`RemoteSealingSessionBackend` wrappers implement that gate. Third-party durable
stores compose underneath one of those wrappers, and third-party KMS/HSM
providers compose through the remote-sealing provider port; downstream code
cannot implement the gate or mint its protected-payload scope. A test-only
in-memory constructor is not a production capability. A future
same-cryptographic-boundary adapter requires a separately named, SDK-owned and
reviewed gate; a downstream marker trait or capability assertion is
insufficient. The product supplies the validated administrative `TenantId`, NF
kind, and protected-backend scope once when creating this wrapper. The SDK
derives the reserved selector-ledger key type and stable ID from the exact
storage-key seed defined below and from the backend bootstrap's device/pin
coordinates. This happens before the random ledger material and complete
namespace binding are minted. Claims cannot replace that scope or key.
The AAD MUST bind the schema revision, authority purpose, storage tenant, NF
scope, storage key type, exact device namespace, exact pin namespace, and the
domain-separated ledger-ID commitment. A plaintext `EncryptedSessionPayload`
wrapper, a caller assertion, or generic backend capability flags cannot satisfy
this gate. The selector secret never leaves that protected record. Only its
commitment may appear in the opaque backend binding; it is not an API identifier
and is redacted. The random ledger ID may also enter that fixed-width opaque
binding, but is never persisted outside the protected record except through the
marker filename digest and never appears in diagnostics or evidence.

The record contains at least:

```text
schema revision and protected-storage profile
administrative storage-scope commitment
stable-device-namespace and canonical-pin-namespace bindings
random ledger ID and selector-secret commitment
nonzero current generation and current operation nonce
state and exact group/set commitments
complete atom ownership and immutable tombstone/reissue-lineage records
for a pending phase, its precommitted terminal generation and nonce
whether backend work began and therefore requires an operation stamp
bounded configured capacities and record checksum
```

The encrypted payload carries the secret and any protected canonical values
needed for exact recovery. The durable header and control marker may carry only
the necessary domain-separated commitments, schema/version, state, generation,
capacity classification, and checksum. A decoder MUST validate canonical AAD,
schema, all bindings, record checksum, and all cross-field invariants before it
uses any state. It MUST return one fieldless, redaction-safe indeterminate
error on failure.

The secret produces keyed domain-separated commitments for group, set, and atom
membership. It is never a substitute for encrypted record integrity, CAS,
generation fencing, or filesystem integrity.

The reference implementation uses HMAC-SHA-256 under the selector secret with
the following ASCII NUL-terminated domains:
`opc/gtpu-selector/group/v1`, `opc/gtpu-selector/set/v1`,
`opc/gtpu-selector/atom/v1`, `opc/gtpu-selector/desired/v1`, and
`opc/gtpu-selector/secret-commitment/v1`. The domain, including its terminating
NUL, is the first HMAC input for the corresponding versioned codec; one generic
domain cannot serve multiple commitment kinds. Storage-key and storage-scope
derivation use the separate unkeyed SHA-256 domains defined below. Marker and
binding names use lowercase hexadecimal SHA-256 over the SDK codec's
fixed-width versioned binding bytes. External backends receive those opaque
bytes and the SDK-generated marker name; they do not reproduce canonicalization
or derivation logic.

`StorageKeySeedCodecV1` has this exact, padding-free byte layout:

```text
version 1 (u8)
tenant length (u64 big-endian) || canonical TenantId UTF-8 bytes
NF-kind length (u64 big-endian) || canonical NetworkFunctionKind UTF-8 bytes
key-type length (u64 big-endian) || ASCII "gtpu-selector-ledger-v1"
backend-scope length (u64 big-endian) || canonical protected-backend-scope bytes
stable device ID (16 bytes)
pin-namespace commitment (32 bytes)
```

The protected-backend scope is a nonempty, NUL-free canonical UTF-8 value of at
most 128 bytes fixed when its encryption or remote-sealing wrapper is created;
the selector namespace constructor does not accept another value. The reserved
`SessionKey` stable ID is exactly
`SHA-256("opc/gtpu-selector/storage-key/v1\0" || StorageKeySeedCodecV1)` and
therefore has the required 32-byte width. Its tenant and NF fields are the same
canonical values, and its key type is the exact reserved string above.

`StorageScopeCodecV1` is version `1`, the same length-prefixed tenant, NF kind,
reserved key type, the derived 32-byte stable ID without a length prefix, and
the same length-prefixed protected-backend scope, in that order. The 32-byte
storage-scope commitment is exactly
`SHA-256("opc/gtpu-selector/storage-scope/v1\0" || StorageScopeCodecV1)`.
These two digests are deliberately unkeyed: the inputs are bounded
administrative routing coordinates rather than subscriber identifiers, the SDK
alone owns the codecs and hashing calls, callers never supply a digest, and no
digest is emitted through diagnostics. Integrity and confidentiality remain the
responsibility of the protected record, its AAD, and the opaque marker binding.
Local encryption and remote-sealing wrappers consume the same SDK-built
`SessionKey`, storage-scope bytes, and commitment before applying their distinct
custody mechanisms; a third-party store beneath either wrapper cannot replace
them.

The canonical desired-group bytes are the SDK `GtpuSelectorDesiredCodecV1`
projection, independent of whether the selected backend is eBPF:

```text
version 1 (u8)
stable device ID (16 bytes)
group ID (16 bytes)
entry count (u8)
entries in IPv4-then-IPv6 order; for each entry:
  canonical inner address (family tag, 4 or 16 address bytes)
  peer outer address (family tag, 4 or 16 bytes)
  local outer address (family tag, 4 or 16 bytes)
  local TEID (u32 big-endian)
  peer TEID (u32 big-endian)
  link ifindex (u32 big-endian)
  GTP version tag (1=v1)
  bearer mark tag (0=none, 1=present + u32 big-endian)
  downlink source-port policy (0=any; 1=exact + u16; 2=range + two u16)
  uplink source-port policy (0=legacy; 1=selected + u16)
  egress DSCP tag (0=none, 1=present + u8)
```

No padding is present. The complete-set codec is version `1`, then a u16 big-
endian atom count, then sorted unique atoms. Each atom is `tag || u16 length ||
bytes`: tag `U` contains the existing 24-byte
`GtpuSessionUplinkKey::encode(inner_paa, complete_mark)` and tag `D` contains
the existing 8-byte `GtpuSessionDownlinkKey::encode(outer_family,
inner_family, local_teid)`. This matches the exact map selector keys, including
valid cross-family distinctions; duplicate encoded map keys are rejected
before hashing. Group commitment is HMAC over version `1`, stable device ID,
and group ID; desired commitment is HMAC over desired-group bytes; set
commitment is HMAC over complete-set bytes; each atom commitment is HMAC over
one atom. After the storage key and scope commitment are fixed, the SDK mints
the random ledger ID and selector secret. The selector-secret commitment is
HMAC under that secret over the secret-commitment domain, version `1`, random
ledger ID, pin commitment, stable device, and storage-scope commitment; it is
not plain SHA-256 of the secret. The namespace binding codec is version `1`
followed by the 32-byte
pin-namespace commitment, 16-byte stable device, 16-byte random ledger ID,
32-byte selector-secret commitment, 32-byte storage-scope commitment, and
16-byte selector-backend epoch. The marker filename digest is SHA-256 over
exactly those 145 bytes. Any change to these bytes requires a new codec/domain
version and an explicit migration. The derivation order is therefore acyclic:
backend bootstrap coordinates, storage-key seed, reserved `SessionKey`, storage
scope, random ledger material, selector-secret commitment, complete 145-byte
binding, then marker name.

### 5.2 Capacity

The implementation MUST define finite maximums for ledger bytes, total groups,
total live groups, retained tombstones, atoms per group, and atoms in a
transition. Defaults and an accepted backend must leave enough protected value
space after envelope overhead. Admission validates every bound before random
generation, encryption, durable CAS, eBPF work, or map mutation. Capacity
exhaustion is a closed non-identifying outcome; automatic tombstone eviction,
compaction that erases history, or silently changing a configured limit is
forbidden.

The initial reference profile caps the encoded plaintext ledger at 512 KiB,
all permanent group records at 1,024, live groups at 512, atoms in one group or
transition at 256, all permanently known selector atoms at 1,024, and the sum
of atom references retained by all permanent group records at 4,096. The last
bound is independent of unique-atom count: a long exact-reissue chain retains
the complete set in every predecessor. The executable codec-size calculation
must prove that the simultaneous maximum legal record, including live selector
rows, retained atom tombstones, successor links, and precommitted terminal
coordinates, is at most 512 KiB. A backend must advertise at least 64 KiB above
the plaintext cap for envelope/framing overhead. A smaller deployment profile
may lower these values only when creating an empty ledger; no limit is mutable
afterward.

A claim permanently consumes its group-record slot and every previously unseen
atom slot at `Installing`; retirement reclassifies that same group record and
does not allocate a tombstone or atom. Exact reissue consumes one new successor
group-record slot but no atom slot. Claim preflight also reserves that group's
one permanent operation-stamp map key. Its value is the current lifecycle fence
and is replaced only by the legal sequence in §8.1; retirement allocates no
additional key. The predecessor's final `Retired` value is never changed, and
exact reissue uses the distinct successor group/key. The ledger invariant
therefore checks byte length, permanent groups, live groups, known atoms,
retained tombstones, cumulative group-atom references, per-operation atoms, and
stamp slots as independent dimensions in every phase. It does not infer one
limit from another. Every counter and the encoded successor record are checked
before secret/nonce generation or an external effect. If a future schema needs
an allocation at retirement, it must reserve that capacity at claim time;
`Active -> Retiring` cannot be admitted unless `Retiring -> Retired` is
allocation-free.

The reference control profile additionally permits four CAS/readback attempts
per transition, 64 supervised effects per namespace, 256 supervised effects per
process, at most 16 directory entries examined while validating a marker, 256
atoms and 512 KiB examined by one exact readback, and 4 KiB for one SDK-created
diagnostic or evidence record. It uses a 30-second namespace lease, renews no
later than every 10 seconds, and admits only backend critical sections bounded
to 5 seconds. Exceeding a work, byte, entry, task, retry, lease, or diagnostic
limit fails closed before further mutation; it never truncates authority data
or restarts a deadline. Alternative profiles may only lower these bounds and
must record the chosen immutable values in the protected ledger.

### 5.3 Permanent Tombstones and Reissue

A completed retirement writes a permanent group-and-complete-set tombstone. A
tombstone is an immutable record containing the group and complete-set
commitments, its activation and retirement generations, the retirement nonce
commitment, and at most one successor group/generation link. The successor link
is written in the same CAS that admits an exact reissue; a conflicting or
second successor is indeterminate. Neither retirement nor reissue deletes atom
history. An ordinary `Fresh` path accepts only a set with no prior publication
history.

This RFC permits exactly one other admission form: SDK-mediated transfer of the
*identical complete atom set* from one exact, permanently retired predecessor
to one distinct successor group. Reissue MUST require the SDK's exact retired
capability and the existing drain/grace evidence, validate the retained source
tombstone and all namespace bindings, and create a higher generation and new
nonce while preserving the permanent predecessor tombstone/lineage. It MUST
NOT admit a subset, superset, mixed provenance set, multiple predecessors, the
same group identity, or a changed selector set. Mixed transfers and exact
same-group republish are #663 work. Thus no caller can cause accidental reuse
merely by reasserting `Fresh` or by retaining old values.

The product-provided drain/grace observation remains policy input, not selector
authority. `reissue_exact_retired_group(retired_capability, successor_group,
drain_evidence)` consumes the exact SDK retired capability and the existing
typed `GtpuSessionSelectorReuseEvidence`. The coordinator binds the closed
evidence kind and predecessor tombstone into the successor ledger CAS; the
evidence alone cannot mint provenance, select a different predecessor, or
authorize same-group/mixed reissue. This RFC does not treat traffic-proof
authority as drain evidence and does not implement #664.

## 6. Public Capability Surface

The public API MUST expose SDK-minted, opaque, non-serializable, non-`Clone`
affine values analogous to:

```rust
pub struct GtpuSessionSelectorAdmission { /* private */ }
pub struct GtpuSessionSelectorEffect { /* private */ }
pub struct GtpuSessionSelectorRemoval { /* private */ }
```

Only the namespace coordinator can mint them. They bind the namespace tuple,
ledger commitment, exact group and complete set commitment, generation, and
operation nonce. Their `Debug` representation may expose only a closed state
classification and a bounded count class; it MUST expose no identity,
generation value, or commitment. Serialization, deserialization, public
fields, `Default`, generic token constructors, and a public `Fresh` variant are
prohibited.

The backend integration is a separate default-unsupported capability port. A
bootstrap call first returns an affine SDK/backend value containing the
backend-minted canonical pin-namespace commitment while the backend-global
ownership gate is held. That commitment is the input to reserved storage-key
derivation and protected AAD; it is not accepted as caller bytes. Its public
shape is analogous to:

```rust
pub struct GtpuSelectorNamespaceBindingCandidate { /* opaque */ }
pub struct GtpuSelectorNamespaceBootstrap { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceBackendLease { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceEffectRequest { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceRemovalRequest { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceReadbackReceipt { /* opaque */ }

async fn bootstrap_selector_namespace(
    &self,
    stable_device: GtpuSessionDeviceId,
) -> Result<GtpuSelectorNamespaceBootstrap, GtpuError>;

async fn bind_selector_namespace(
    &self,
    bootstrap: GtpuSelectorNamespaceBootstrap,
    candidate: GtpuSelectorNamespaceBindingCandidate,
) -> Result<GtpuSelectorNamespaceBackendLease, GtpuError>;

async fn reconcile_group_authorized(
    &self,
    request: GtpuSelectorNamespaceEffectRequest,
) -> Result<GtpuSelectorNamespaceReadbackReceipt, GtpuError>;

async fn remove_group_authorized(
    &self,
    request: GtpuSelectorNamespaceRemovalRequest,
) -> Result<GtpuSelectorNamespaceReadbackReceipt, GtpuError>;
```

The SDK supplies a verifier/codec for external backend implementations. It
reveals only the canonical 145-byte binding, canonical marker name, canonical
208-byte pending and terminal stamps, and constant-time comparison operations,
never the selector secret or fields from which a caller can mint those values.
The lease validates the exact marker, complete permanent group-key inventory,
and each key's exact current lifecycle-stamp value again immediately before
each effect. An authorized request also exposes a borrowed read-only
`GtpuSessionGroup` projection and closed operation kind while it is consumed,
so an external backend can perform the requested real mutation; those semantic
fields do not mint or validate authority. A receipt is valid only for the exact
namespace binding, complete set, phase generation, operation nonce, marker
commitment, requested outcome, terminal 208-byte stamp, and backend
incarnation. A receipt codec contains the terminal stamp followed by a
versioned, length-delimited exact desired-group readback; it has no semantic-
equality fallback. The conformance harness
can mint test requests, but ordinary callers cannot. This makes third-party
implementation possible without making caller-side authority fields
constructible.

`claim_fresh_complete_group` consumes an exact group and returns an admission
only after durable `Installing` ownership commits. `reissue_exact_retired_group`
is separately named and requires the exact retired capability. Reconcile
consumes the admission and returns an effect only after authority-bound exact
backend readback and the `Installing` to `Active` CAS. Exact removal consumes
the effect and returns a removal capability only after the authoritative
retirement workflow completes. A stale or consumed capability is unusable;
cancellation cannot make it reusable.

The public caller-owned `Fresh` provenance variant, raw grouped reconcile
request constructor, generationless grouped removal, and raw authoritative
group-readback methods are removed from the public production surface. All
fresh publication requires a namespace claim, including an as-yet unbound
namespace. Legacy cleanup is a separately reviewed, stopped-dataplane operator
procedure under §11; it is not a reusable trait method or caller capability.
Semantic readback remains available only for bounded diagnostics and cannot
mint a receipt, complete recovery, or authorize deletion.

## 7. State Machine and Recovery

### 7.1 States

Every group/set entry is exactly one of:

| State | Meaning | Permitted next state |
| :--- | :--- | :--- |
| `Unbound` | No authority has committed the complete set. | `Installing`, `Poisoned` |
| `Installing` | A claim committed; exact dataplane effect/readback is pending. | `Active`, `Poisoned` |
| `Active` | Exact set is durably owned and read back. | `Retiring`, `Poisoned` |
| `Retiring` | Retirement committed; exact removal/readback is pending. | `Retired`, `Poisoned` |
| `Retired` | Permanent complete-set tombstone; no live effect. | `Installing` only through exact retired reissue, `Poisoned` |
| `Poisoned` | Safety cannot prove one coherent outcome. | no automatic transition |

Every state transition is a single compare-and-set over the ledger revision and
expected phase generation. `Unbound -> Installing` and `Active -> Retiring`
each atomically reserve two strictly increasing, nonzero generations and two
fresh operation nonces: one for the committed pending phase and one for its
only permitted terminal successor. The ledger's namespace-wide allocation
counter advances past both reservations in that first CAS, so another group can
never allocate either value. `Installing -> Active` and `Retiring -> Retired`
then consume the exact precommitted successor coordinate; they do not mint a
value after the backend effect. This lets the backend write an exact terminal
stamp before the final durable CAS without guessing its future coordinate.
Every logical phase therefore has a distinct monotonic generation and nonce;
an RFC 004 record revision is not a substitute. A successor reissue reserves a
new pair in the same way. The implementation MUST reject arithmetic overflow
instead of wrapping. An operation MAY identify itself only with a private,
fixed-width idempotency descriptor; it MUST NOT accept a caller-selected nonce
as authority.

The encoded `Installing` and `Retiring` records contain both the current
coordinate and the complete precommitted terminal coordinate. They also contain
a one-way `backend_started` bit. The coordinator sets that bit by CAS before it
hands the request to a backend supervisor, and never clears it. A decoder
rejects a pending phase without a greater terminal generation, a duplicate or
zero nonce, or an allocation counter that has not advanced past both
generations. Namespace-open validation accepts, for a backend-started pending
phase, only its exact pending stamp or its exact precommitted terminal stamp;
absence or every other value is indeterminate.

### 7.2 Claim and Effect Ordering

1. Validate the complete canonical group, every independent capacity, protected
   store profile, and backend capability before random minting or mutation.
2. Bind or exactly validate the SDK-minted ledger candidate against the
   backend's canonical device/pin namespace and immutable marker, without map
   mutation. This settles an ambiguous marker creation only by exact readback.
3. Under the namespace ownership gate, CAS `Unbound` or exact `Retired` into
   `Installing` with its generation/nonce, the precommitted `Active` successor
   generation/nonce, and `backend_started = false`. The entire group, all
   atoms, group binding, and prior tombstone lineage commit together.
4. Re-read the exact `Installing` phase, then CAS/read back
   `backend_started = true` and consume its affine authorized request into a
   supervisor. The backend validates the marker and complete stamp inventory
   immediately before its pending-stamp write and first journal, map, program,
   or traffic mutation.
5. Require an authority-bound whole-group readback, then write and exactly read
   the terminal `Active` operation stamp using the precommitted successor
   generation/nonce. A successful syscall, map update, semantic-only group
   match, partial readback, or current-map absence alone is not success.
6. CAS the exact `Installing` operation to the exact precommitted `Active`
   coordinate and persist its private capability-recovery descriptor. Only then
   mint the Active effect capability.

No operation may publish a live capability after a durable failure. A rejected
or lost ACK, timeout, cancellation, process death, readback ambiguity, or CAS
conflict is not permission to retry by assuming no effect.

### 7.3 Retirement and Removal Ordering

1. Consume the active effect, validate the exact current generation and
   control-marker binding, and CAS `Active` to `Retiring` with its next
   generation/nonce, the precommitted `Retired` successor generation/nonce,
   and `backend_started = false`. CAS/read back `backend_started = true` before
   supervision.
2. Invoke capability-bound exact whole-group removal. Per-selector removal,
   best-effort cleanup, and deletion based on an absent map are forbidden.
3. Require exact backend readback proving the complete group is absent under
   this authority and no residual partial group is present, then write and
   exactly read the terminal absent stamp using the precommitted `Retired`
   successor coordinate.
4. CAS `Retiring` to the exact precommitted permanent `Retired` coordinate,
   retaining all tombstones, lineage, and its private capability-recovery
   descriptor, then mint the removal capability.

Retirement must commit before a selector can be reissued. An interrupted
retirement remains `Retiring`, never `Unbound`; it blocks all claims.

### 7.4 Recovery Outcomes

Recovery obtains the same local ownership gate, performs a durable exact read,
and validates the immutable eBPF control marker before any dataplane operation.
It has only these outcomes:

- `Installing` plus exact authority-stamped, operation-matching complete backend
  readback: finish or validate the exact terminal stamp and CAS to the
  precommitted higher-generation `Active` phase, then recover one effect
  capability for the recorded owner operation.
- `Installing` plus exact absence: atomically move the operation and its full
  selector set to `Poisoned`/permanently reserved history. Current absence
  cannot prove that an interrupted writer never published the selectors before
  map loss or cleanup, so recovery MUST NOT return them to `Unbound` or
  `Retired` and MUST NOT reissue them.
- `Retiring` plus exact authority-stamped absence: finish or validate the exact
  terminal absent stamp and CAS to the precommitted higher-generation permanent
  `Retired`.
- `Active` plus exact matching readback: retain `Active`; `Retired` plus exact
  absence: retain `Retired`.
- Any mismatched generation, group, set, device, pin namespace, nonce,
  capability, partial readback, unavailable durable read, ambiguous ACK,
  unexpected resident atom, malformed record, or duplicate live claimant:
  atomically poison the reachable ledger entry when possible and otherwise
  fail closed with service unavailable. It MUST NOT infer rollback or issue a
  capability.

`Poisoned` requires an explicitly authorized, offline, forensic recovery
procedure defined by a later RFC or runbook. Ordinary cleanup, retry, restart,
or decommission cannot clear it.

Every successful final phase CAS persists enough private, protected input to
reconstruct the same logical generation-bound capability, but never serializes
the Rust capability itself. If the CAS response or returned capability is lost,
the current namespace-lease owner may re-mint it only after exact ledger and
backend readback and after fencing the prior lease/host-lock owner. Multiple
wrappers for one phase do not create multiple authorities: every use must win
the same exact phase-generation CAS and backend lease check, so at most one can
advance the state and every other wrapper becomes stale before an effect. The
same rule recovers the retired/removal capability needed for exact reissue.
An in-process retry joins the existing supervised operation instead of
re-minting while its delivery owner remains live.

### 7.5 Process and Cancellation Ownership

One namespace operation owns a bounded coordinator task and its capability from
durable transition through final readback/CAS. Before the first externally
cancellable await after a phase CAS, the coordinator transfers the affine
request to a backend-owned supervisor. Dropping or cancelling the caller future
MUST NOT release this ownership while durable or kernel work is pending. The
backend worker retains and renews the namespace lease and request until one
terminal receipt is durably settled or process death releases the host lock.
Every renewal uses the exact phase generation/fence. A failed, late, or
ambiguous renewal fences the worker before any further effect and leaves the
phase recoverable/poisoned; it cannot continue until TTL. The maximum one-step
kernel work duration must be below the admitted lease-renewal safety margin.
A coordinator either rejoins the recorded operation or leaves it recoverable/
poisoned. It must retain at most the configured number of supervisors and
report only a closed cancellation classification. If no runtime can provide
this worker ownership, the capability is unsupported.

The durable lock/CAS authority, not a process mutex, decides ownership. A
process-local lock may serialize same-process calls but cannot prove cross-
process exclusivity. Concurrent processes must serialize through the durable
generation/CAS and the host-global control-marker lock.

## 8. Persistent eBPF Control Marker

### 8.1 Purpose and Contents

The eBPF backend MUST keep one persistent immutable directory marker in the
canonical per-pin-namespace control directory already used for host-global
reconciler ownership:

```text
<bpffs-root>/GTPU_RECONCILER_LOCKS/<canonical-namespace-hash>/
  SELECTOR_AUTHORITY_V1_<canonical-binding-digest>
```

The marker is an empty directory, not a regular file or pinned BPF object. Its
name is the fixed version prefix plus lowercase hexadecimal SHA-256 over the
exact 145-byte namespace-binding codec in §5.1; no field is reordered,
omitted, or independently rehashed. The digest is an opaque binding, not an
identifier for diagnostics. Raw caller strings cannot select the path. The marker is
created before the first map/program mutation and MUST NOT contain selector
values, subscriber data, the ledger ID, secret, or a nonce in plaintext. The
control directory is outside the mutable per-device pin graph, so the binding
survives map/program loss and ordinary pin-tree cleanup. A missing marker after
a previously bound durable ledger, more than one marker, a marker with a
conflicting binding, or a map graph whose binding cannot be proved MUST fail
before traffic or map mutation. It has mode `0700`, link count two, and the
effective UID/GID of the already-qualified reconciler control directory. A
child entry or different metadata is indeterminate.

The immutable marker binds the ledger; it is not the changing operation stamp.
Every grouped backend record and its crash-recovery journal MUST additionally
retain a fixed-width opaque stamp for the phase generation, operation nonce,
complete-set commitment, requested outcome, and durable selector-backend epoch.
Exact readback returns a receipt for that stamp. An old semantic graph without
the current stamp, even if its selectors compare equal, is stale and cannot
complete or recover an operation.

The selector-backend epoch is a random 128-bit value minted at first binding,
stored in the protected ledger and operation-stamp map, and stable across a
process restart that reopens the exact marker and pin namespace. It is not the
process-local random `BackendIncarnation` used by traffic observation. The old
host-lock owner must be fenced before a restarted process can reuse the epoch.
A replacement, moved pin namespace, missing stamp map, or epoch conflict is not
an ordinary restart and remains fail closed; #663 may authorize a distinct
restore/republish transition. A process constructor must never silently rotate
the selector-backend epoch and then adopt an old semantic graph.

The reference eBPF backend adds a userspace-owned pinned HASH map named
`GTPU_SELECTOR_OPERATION_STAMPS`, keyed by the existing 16-byte group ID, with
an exact 208-byte version-1 value and `max_entries = 1,024`, matching the
permanent group-record cap. The tc programs do not read this map. The map is a
required member of the exact versioned Aya map set: object validation, pin
identity, snapshot/readback, cleanup, and privileged conformance all include
it. A legacy graph missing the map is not silently upgraded or adopted. Its
canonical value layout is:

| Bytes | Field |
| :--- | :--- |
| `0` | version `1` |
| `1` | phase: `1=Installing`, `2=Active`, `3=Retiring`, `4=Retired` |
| `2` | operation: `1=install`, `2=remove` |
| `3` | outcome: `1=pending`, `2=active`, `3=absent` |
| `4..8` | zero |
| `8..16` | nonzero authority generation, big-endian |
| `16..32` | operation nonce |
| `32..48` | durable selector-backend epoch |
| `48..64` | existing grouped transaction ID, or zero after finalization |
| `64..96` | namespace-binding SHA-256 commitment |
| `96..128` | keyed group commitment |
| `128..160` | keyed complete-set commitment |
| `160..192` | keyed desired-graph commitment |
| `192..200` | nonzero dataplane group generation, big-endian |
| `200..208` | zero |

Decode rejects any unknown tag, zero required field, nonzero reserved byte, or
cross-field mismatch. A pending stamp uses the current `Installing` or
`Retiring` coordinate, outcome `pending`, and the exact nonzero transaction ID
of the existing journal. A terminal stamp uses the precommitted `Active` or
`Retired` successor coordinate and a zero transaction ID. The install/active
dataplane generation is the generation of the exact resident group; the
remove/absent value is the nonzero generation of the exact group being removed.
All keyed commitments and the dataplane generation remain identical from the
pending operation to its terminal result.

The protected record and map have this exact key/value relationship:

| Ledger phase | Required stamp for the group key |
| :--- | :--- |
| `Installing`, not started | absent |
| `Installing`, started | exact pending-install or exact terminal-active |
| `Active` | exact terminal-active |
| `Retiring`, not started | prior exact terminal-active |
| `Retiring`, started | exact pending-remove or exact terminal-retired |
| `Retired` | exact terminal-retired |
| `Poisoned` | the exact last observed stamp, or an explicit protected no-stamp poison classification |

Each permanent group key has exactly one current value. The only ordinary CAS
replacement chain is:

```text
absent -> pending-install -> terminal-active -> pending-remove -> terminal-retired
```

Every arrow compares the complete prior 208-byte value (or proven absence) and
writes the complete precommitted successor. `terminal-active` is deliberately
superseded by the authorized retirement operation; the ledger's immutable
activation coordinate and group history preserve that earlier fact. The final
`terminal-retired` value is permanent for that predecessor and is never deleted
or replaced. Exact reissue consumes a different group identity and therefore a
different permanent map key. No recovery, cleanup, compaction, or decommission
may skip, reverse, normalize, or add an edge to this chain.

Every other stamp key is foreign history. A started phase with an absent stamp
is atomically converted to the no-stamp poisoned classification after the old
host owner is fenced; it never returns to an admissible phase. A mismatched or
unrecognized stamp stays unavailable for offline recovery and cannot be
normalized into a caller-selected poison record.

The coordinator constructs the bounded journal and reserves its nonzero target
dataplane generation in memory, writes and exactly reads the pending stamp, and
only then persists the journal or performs the first selector mutation. The
journal transaction ID and target generation must equal the pending stamp.
After exact whole-group readback it writes and exactly reads the terminal stamp
before finalizing the journal and before the terminal
ledger CAS. Active recovery requires the exact terminal stamp plus the existing
authority/index graph. Retired recovery requires exact group absence and the
terminal absent stamp. Group stamp keys are permanent namespace inventory, and
each key's value must be the one exact current lifecycle fence allowed by the
table and replacement chain. The terminal `Retired` value is never removed by
cleanup, compaction, or decommission; capacity is reserved one-for-one with
permanent groups. On every open,
the coordinator compares the complete bounded stamp-key inventory with the
protected ledger. An extra stamp proves a rolled-back or foreign ledger; a
missing stamp for any operation recorded as backend-started proves map loss or
rollback. Either is indeterminate. An `Installing` operation durably recorded
as not backend-started may have no stamp and can only follow the exact poison/
recovery rule in §7.4. A missing, malformed, stale, wrong-generation,
wrong-nonce, wrong-epoch, wrong-commitment, or journal-mismatched stamp is
indeterminate and never falls back to semantic group equality. No stamp alone
is a selector tombstone or admission.

### 8.2 Initialization and Crash Recovery

Initialization is an explicit two-sided protocol; neither a ledger write nor a
marker alone is a complete binding. Normal runtime never interprets a missing
record as a virgin namespace. It starts only from the exact permanent
`Provisioned` record created by the stopped installation workflow in §11. That
record already binds the storage scope, stable device, pin namespace, immutable
capacities, and reserved key, but contains no selector secret, claimable atom,
group, marker, or backend epoch:

1. After all preflights, CAS the exact `Provisioned` record to an `Initializing`
   ledger containing the SDK-minted random binding candidate, protected storage
   scope, zero groups, and no claimable atoms.
2. Under the backend ownership descriptor/lock, create or exactly read back the
   immutable marker for that candidate. The marker directory initially denotes
   only `Initializing`; it does not authorize group effects.
3. While still `Initializing`, validate the eBPF object identity and create or
   validate the complete versioned empty control-map set required by this
   backend, including the operation-stamp map. It does not attach a program.
   Exact bounded readback must prove that no selector, journal, group, or stamp
   exists. This structural initialization cannot mint a receipt or admission
   and is the only normal path allowed to create a missing stamp map.
4. Re-read the exact protected `Initializing` record, marker, and empty map set,
   then CAS the ledger to `Bound` at a higher generation/nonce before any claim.

Recovery of `Initializing` plus an exact marker may complete steps 3 and 4. An
exact `Initializing` ledger with no marker may create that one expected marker
and settle it by readback because no selector has yet been claimable or
published. The marker is created only after exact readback of the first ledger
CAS, so a marker with an absent ledger proves rollback, corruption, or authority
loss and is an orphan conflict requiring offline recovery; startup never
recreates a record from marker material. An absent record, even with an empty
backend and no marker, is likewise unprovisioned/indeterminate and cannot enter
`Initializing`. A different, malformed, multiple, or unprovable pair fails
closed. Once `Bound`, a missing marker or required control map is never
recreated by normal startup; #663 owns an explicitly fenced restore/republish
design. `Decommissioned` is permanent and cannot enter `Provisioned`,
`Initializing`, or `Bound`. No group claim or group effect is possible until
the protected ledger, marker, and backend graph are exactly `Bound`.

### 8.3 Host Filesystem Semantics

Control-marker operations are serialized under the existing host-global
advisory `flock` held on the canonical control-directory descriptor. The lock
is held across marker validation/creation and all map/program mutation/readback
that relies on it. Network namespaces, process IDs, per-process paths, and a
lock created in an untrusted directory are not equivalent.

The backend MUST resolve each path component relative to a trusted bpffs root
descriptor using descriptor-relative traversal. It MUST reject symlinks,
non-directories, unexpected owner or mode, non-bpffs filesystems, unexpected
links, and inode replacement. Creation uses descriptor-relative, no-replace
directory creation; it never follows a replacement path. Existing markers are
enumerated to a fixed bound, type/owner/mode/inode/link checked, and compared
exactly to the single expected canonical marker name. The containing control
directory and marker are re-stat'ed by descriptor before use to detect
replacement races.

Creation makes the complete marker atomically, syncs the opened marker and
containing directory, re-enumerates exactly one marker, and verifies the opened
directory identity before allowing the first map/program mutation. The
containing filesystem must match Linux `BPF_FS_MAGIC` on the trusted root and
control descriptors. `mkdirat` success is followed by descriptor-relative
open, `fsync` (and `syncfs` where available), close-result handling where the
host API exposes it, and exact re-open/re-stat. Linux bpffs may return `EINVAL`
for directory `fsync`; that one result is accepted only after `BPF_FS_MAGIC`,
the held host-global lock, and exact re-enumeration/re-stat. The marker is a
same-running-kernel ownership fence, not a power-loss store: loss across host
reboot leaves the protected ledger `Bound` and therefore fails closed rather
than recreating authority. Any other unsupported durability result, I/O, sync,
close, ACK, enumeration, ownership, mode, link-count, or identity failure is
ambiguous and fails closed. The marker is never renamed,
modified, or silently recreated after deletion. A separately authorized
decommission procedure may remove mutable programs, selector maps, and journals
only after the protected namespace record is permanently `Decommissioned`; it
MUST retain this immutable marker and the protected record. Normal cleanup and
decommission never erase either authority fence.

## 9. Backend Contract

The public `GtpuDataplaneBackend` capability default for this feature MUST be
unsupported. A third-party backend opts in only by declaring the selector
namespace capability and passing this RFC's conformance suite. An opt-in
backend MUST:

- accept only the opaque capability-bound complete group operations;
- atomically associate every effect and exact removal with namespace tuple,
  group/set commitment, generation, and operation nonce;
- provide bounded exact whole-group readback whose `Absent` result proves the
  conditions required by §7.4, and otherwise return `Indeterminate`;
- distinguish confirmed exact ACK/readback from timeout, duplicate ACK, wrong
  reply, partial result, cancellation, and I/O uncertainty;
- reject mismatched/replayed/stale/cross-boundary capabilities before traffic or
  map mutation; and
- preserve the immutable control-marker binding across its supported restart,
  cleanup, and replacement paths.

An adapter that cannot make these statements remains unsupported even if it can
reconcile maps, has a session store, or reports a successful mock operation.
Capability reporting is an admission declaration, not a runtime liveness
claim. A replacement backend or backend incarnation must validate the exact
durable/control binding before it performs any action; it cannot adopt a live
legacy graph on the basis of current map content.

An eBPF backend uses the directory marker defined in §8. A non-eBPF backend
must provide an equivalent immutable, independently durable namespace binding
under its backend-global exclusive ownership and pass the same split-store,
restart, rollback, replacement, and conflict cases. If it has no such binding,
two independent durable stores could both mint history for one dataplane
namespace, so the selector-namespace capability remains unsupported.

The SDK publishes a backend conformance harness which owns the only test-token
minting path. External implementations consume opaque authorized requests and
use the SDK codec/verifier to persist and echo operation stamps. They do not
reconstruct tokens from public fields. Passing pure mock success tests is not
conformance; a backend profile must execute its real mutation, exact readback,
restart, cancellation, and conflicting-binding paths.

## 10. Authority Composition

### 10.1 Local Durable Authority

For a local profile, the SDK exposes a separately named constructor accepting
the affine backend bootstrap, the target `GtpuDataplaneBackend`, and a
`SessionStore` over an SDK-sealed `ProtectedSessionBackend`, backed by one RFC
004 store shared by every writer for the namespace. The bootstrap's canonical
pin commitment, stable device, and protected administrative scope derive the
one reserved ledger key and its AAD before the first record CAS. No raw session
key, pin commitment, ledger ID, secret, epoch, or binding digest is a
constructor argument. The composed adapter MUST
provide atomic compare-and-set over the whole protected ledger record,
monotonic record generation/fencing,
bounded value capacity, durable readback, and crash recovery. The constructor
derives the reserved ledger key from `StorageKeySeedCodecV1` before minting the
complete namespace binding; it does not accept an arbitrary caller key. A
sequence of per-atom writes, a
`batch` with independently observable slots, a cache, an independent per-
process database, or a process mutex is insufficient. A same-cryptographic-
boundary profile is separately named and cannot claim encrypted-at-rest
evidence.

The ledger record is created with `expires_at = None`. An admitted backend must
prove that non-expiring records are excluded from TTL pruning, capacity
eviction, ordinary session teardown, compaction, and automatic cleanup. Any
profile that cannot retain the record and every tombstone for the namespace's
lifetime, including after decommission, remains unsupported.

### 10.2 Distributed Durable Authority

For a distributed profile, a distinct constructor accepts the same affine
backend bootstrap plus only the protected RFC 004 consensus adapter and its
linearizable-read capability. The selector-
ledger command is a deterministic domain state-machine command committed
exclusively by the existing Openraft-backed SessionStore path. The adapter
seals the payload before `client_write`, performs state transitions at
committed apply, and uses the existing linearizable read barrier for recovery.
A generic `SessionBackend + SessionLeaseManager` bound is not a distributed
profile. Follower clocks, caches, backend scans, or an SDK-added majority/
sequence protocol must not decide an outcome.

This RFC composes SessionStore and ADR 0019; it does not add consensus,
election, votes, leader leases, membership, a second transport, or a fast-path
remote-store call. In particular, the packet fast path MUST NOT access the
remote selector ledger. It consumes only a locally held opaque effect whose
validity was established by the control workflow.

## 11. Upgrade, Migration, and Decommission

An upgrade MUST NOT silently adopt a nonempty legacy GTP-U map/program/pin
graph. A production runtime cannot create the reserved durable row from
absence. Before first use, a separately authorized, stopped installation
workflow authenticates and fences the target, obtains the backend-global lock,
and performs a complete bounded privileged inspection. Only exact emptiness,
no legacy control marker, and no prior provision/decommission fence permit it to
CAS-allocate the permanent `Provisioned` record at the SDK-derived reserved
key. It exactly reads the record back before release and records only a redacted
classification. A missing record during ordinary startup means
unprovisioned/indeterminate, not never-used.

If legacy state exists, an operator must use a separately reviewed cleanup-only
procedure: drain product traffic, stop all writers, authenticate and fence the
target, preserve an immutable pre-cleanup record, remove only positively
identified legacy state, and prove exact emptiness before the installation
workflow may create `Provisioned`. The procedure does not infer legacy selector
history, issue `Fresh` admissions for old state, or preserve live service. It is
not automatic startup behavior.

Decommission is a terminal namespace transition, not record deletion. After
all groups are exactly `Retired`, the separately authorized stopped workflow
holds both authority gates, verifies the complete ledger/marker/stamp
inventory, and CASes `Bound` to permanent `Decommissioned`, retaining the
complete binding and all group/atom/tombstone history. It exactly reads that
record and marker back before removing any mutable program, selector map,
journal, or non-authority pin. Crashes before the CAS leave `Bound` and permit
no cleanup; crashes afterward leave `Decommissioned`, forbid traffic and
claims, and may only resume the same bounded cleanup. The protected record and
immutable marker are never removed. `Decommissioned` can be restored or moved
only by a future separately authorized, versioned migration that preserves this
fence; it can never become an ordinary fresh namespace.

Deleting maps, pins, a copied database, or a control file never authorizes
deletion of selector history or creation of `Provisioned`. Rollback to an image
lacking this RFC is unsupported once a namespace is provisioned, except through
a stopped, explicitly approved recovery that preserves the permanent authority
record.

## 12. Security and Privacy Analysis

| Threat | Required mitigation |
| :--- | :--- |
| Split brain or concurrent claimant | One complete ledger CAS, monotonic generation, host-global control lock, and exact readback; disagreement poisons or fails closed. |
| ABA, replay, or stale effect | SDK-minted affine capabilities bind exact set, namespace, generation, and nonce; permanent tombstones and non-wrapping generations reject reuse. |
| Cross-device, cross-pin, or cross-group use | Both durable AAD and immutable control marker bind the exact tuple; backend validates before mutation. |
| Partial selector claim/removal | Canonical whole-group transaction and exact whole-group readback; mixed provenance is unsupported. |
| ACK loss, cancellation, or process death | Durable progress states, operation nonce, exact recovery outcomes, bounded supervision, and poison on ambiguity. |
| Map/program loss or ordinary cleanup | Immutable persistent control marker plus durable ledger; absence does not prove historical absence. |
| Control-marker tampering | Trusted descriptor traversal, no-follow/no-replace, owner/mode/link/inode checks, exact enumeration/digest binding, directory sync, and host-global lock. |
| Symlink, hardlink, or replacement race | Descriptor-relative no-follow traversal; reject links, unexpected metadata, changed inode, and non-bpffs objects before mutation. |
| Durable rollback or cloned database | Protected AAD plus permanent backend-owned group stamp keys and exact current lifecycle values; every effect revalidates the exact ledger/stamp bijection while holding the backend-global gate. Extra/missing/mismatched history fails closed. |
| Decommission followed by re-adoption | Runtime requires a permanent exact `Provisioned` record rather than inferring virgin state from absence; terminal `Decommissioned` ledger/marker fences are never deleted or reused. |
| Secret or subscriber disclosure | Encrypt ledger material; redact every public surface; evidence is identity-free and uses only closed classifications/counts. |
| Capacity or operation DoS | Pre-effect finite capacities, bounded canonicalization/readback/retries/tasks, and fail-closed exhaustion. Products own admission quotas. |

A coherent copy made before any selector effect initially has the same binding
and stamp inventory as its source. It does not become a second writer: both
copies must acquire the same backend-global ownership gate, and immediately
before mutation each compares its exact protected ledger with every permanent
group stamp key and exact current lifecycle value. The first backend-started
operation adds its pending stamp before any
selector mutation. A second copy then observes an extra stamp and fails closed;
the first copy similarly fails if the second won. Copying or rolling back the
ledger after publication leaves an extra key or a newer/mismatched current
value. Loss or rollback of the stamp map makes a previously backend-started
ledger entry miss or regress its stamp and fails closed. A backend that cannot
retain and enumerate these permanent keys and current fences does not support
the local profile. Protected storage, key custody, backup controls, and ADR
0019 consensus authentication remain defense in depth rather than a substitute
for this effect-time fence.

## 13. Observability and Evidence

The implementation MAY emit only fixed-cardinality metrics such as:

```text
opc_gtpu_selector_namespace_operations_total{operation,outcome}
opc_gtpu_selector_namespace_state_total{state}
opc_gtpu_selector_namespace_poisoned_total{reason}
opc_gtpu_selector_namespace_capacity_rejections_total{limit}
```

All labels are SDK-owned closed enums. They MUST NOT contain selector values,
addresses, device/pin names, IDs, commitments, generations, nonces, paths,
backend text, or error strings. Status and errors use the same restriction.

RFC 006 evidence for this feature MUST identify the experimental requirement,
source and test references, feature/version, artifact digests, platform
classification, and closed outcomes. Evidence packs MUST be identity-free:
they contain no selectors, subscriber addresses, ledger/control IDs, secrets,
keys, commitments, operation nonces, raw path, or raw trace. A redaction
validator must reject a pack containing any of them. Evidence proves the
specified mechanism test ran; it does not prove traffic forwarding or product
readiness.

## 14. Conformance and Acceptance Criteria

Implementation is accepted only when all of the following have passing,
evidence-linked tests. Tests must begin as RED tests where stated; a test that
passes before the implementing surface exists is not evidence of this RFC.

1. A compile-fail public-API test is initially RED because callers can name or
   construct `Fresh`; after implementation they cannot construct, clone,
   serialize, or substitute an admission, effect, or removal capability.
2. Deterministic tests prove atomic fresh complete-set claim, exact full-set
   retired reissue, and rejection of duplicate, partial, mixed, same-group
   changed, stale-generation, replayed, cross-device, cross-pin, and
   cross-group requests before backend mutation.
3. Concurrent-process and split-brain tests use two real local store handles,
   two independent local databases, coherent protected-store clones made before
   and after first effect, two canonical pin namespaces, and the distributed
   profile. They prove exactly one claimant can bind and effect the real
   namespace; a duplicate operation returns the recorded result only for its
   exact private identity, while an independent store, split pin, rolled-back
   clone, or unprovable race conflicts/poisons/fails closed.
4. Durable CAS and protected-record fault injection at every prepare, commit,
   readback, checksum, AAD, capacity, and response-loss boundary proves one
   recoverable complete outcome or `Poisoned`, never partial live atoms.
5. Backend-effect fault injection covers lost/wrong/duplicate ACK, timeout,
   partial map update, partial readback, map/program loss, backend replacement,
   and conflicting immutable binding. No case may issue an effect on ambiguity.
6. Exact removal tests prove `Retiring` persists before effects, permanent
   tombstones survive restart, no raw selector removal bypasses binding, and
   only exact whole-set retired reissue is admitted after `Retired`.
7. Restart, process-death, caller cancellation, and supervisor-bound tests
   exercise every `Installing` and `Retiring` recovery outcome and verify no
   leaked worker/capability can issue a later effect. They also inject response
   loss and process death after each final phase CAS and prove the exact
   capability is safely re-minted or joined without duplicate authority.
8. A privileged, isolated real-eBPF qualification creates the canonical marker
   and operation stamps, exercises no-follow/no-replace/exact-enumeration/
   digest/directory-sync and host-global flock semantics, mutates the real
   graph, restarts, loses maps/programs, and proves a stale stamp or conflicting
   ledger/control binding fails before traffic/map mutation.
9. Mutation tests independently make RED: admission/effect/removal capability
   opacity removal, their namespace-binding validation removal, and independent
   tombstone and generation validation removal. A combined happy-path mutation
   is insufficient evidence for these independent guards.
10. Redaction tests inspect `Debug`, logs, metrics, status, errors, and RFC 006
    evidence and prove they contain only bounded classifications/counts, with
    no selector, subscriber, ledger, commitment, nonce, secret, or key data.
11. Third-party backend conformance runs the published SDK harness against a
    real backend profile. The default backend remains unsupported; a backend
    cannot opt in with mock success alone.
12. Upgrade tests prove live legacy maps are never silently adopted, ordinary
    startup rejects an absent reserved record, only an exact pre-provisioned
    record may initialize, and cleanup-only migration is explicit. Decommission
    fault injection covers every ledger/marker/stamp/readback/graph-removal
    boundary and proves `Decommissioned` plus all history remain permanent.
    Removing the database, maps, stamp map, and marker after decommission still
    cannot make ordinary startup provision or initialize the tuple.
13. Fix-removal tests independently remove operation-stamp validation, phase
    generation advancement, protected-store admission, canonical storage-key
    derivation, and supervisor ownership; each mutation goes RED without
    relying on a combined happy-path test.
14. Boundary tests hit every reference-profile limit and one-over value for
    ledger bytes, permanent/live groups, unique atoms, cumulative group-atom
    references, stamp slots, per-operation atoms, retries, supervisors,
    directory entries, readback work, diagnostics, lease renewal, and critical-
    section duration. One executable simultaneous-worst-case record round trips
    below 512 KiB. Active groups always retain allocation-free retirement
    capacity.
15. Restart tests reuse the durable selector-backend epoch only after fencing
    the prior host/lease owner, and reject random process incarnation,
    replacement, missing stamp map, stale stamp, and epoch rotation/adoption.
16. Stamp-inventory tests cover every row in the ledger/stamp table; the exact
    `absent -> pending-install -> terminal-active -> pending-remove ->
    terminal-retired` CAS chain; the predecessor's permanent retired key plus a
    distinct exact-reissue successor key; extra and missing keys; and response
    loss or process death after every pending/terminal stamp write and before
    every matching ledger CAS. Independent ledger-only and stamp-map-only
    rollback, full-capacity inventory, and a clone racing the original under the
    real backend ownership gate all fail closed. No semantic readback or mock
    receipt settles a mismatch.
17. Storage-codec golden vectors cover every byte of `StorageKeySeedCodecV1`,
    the reserved stable ID, `StorageScopeCodecV1`, its commitment, the
    selector-secret commitment, the exact 145-byte binding, and marker digest.
    One-field mutations cover tenant, NF kind, key type, stable ID,
    protected-backend scope, device, pin, ledger ID, selector-secret
    commitment, storage-scope commitment, and backend epoch. Local and remote
    wrappers produce identical SDK scope/binding bytes; cross-store and
    cross-tenant aliases, external-backend substitution, unknown versions, and
    migration without an explicit codec version are rejected.

The privileged test is environment-specific evidence and may be isolated from
ordinary unprivileged CI. It remains mandatory before a release claims the
corresponding eBPF backend conformance; synthetic/mock tests do not replace it.

## 15. Alternatives Rejected

### 15.1 Caller-Owned `Fresh` Enum

Rejected because a public assertion cannot establish never-published history or
survive process loss, map loss, backend replacement, and concurrent writers.

### 15.2 Dataplane Map Readback as History

Rejected because maps/programs/pins may be absent after cleanup or loss. Current
absence is not permanent non-publication evidence.

### 15.3 Product-Local Registry

Rejected because it fragments the reusable anti-ABA contract and cannot fence
generic SDK raw paths. Products may choose persistence composition but must use
the SDK authority contract for this namespace.

### 15.4 Per-Selector Ledger

Rejected because it permits mixed provenance and partial claim/removal. The
atomic ownership unit is the exact complete group. #663 may design a different
unit with its own safety proof.

### 15.5 New Consensus or Sequence Service

Rejected by ADR 0019. The authority composes existing SessionStore CAS and
Openraft `client_write` state-machine mechanisms.

### 15.6 Silent Legacy Adoption or Automatic Tombstone Cleanup

Rejected because both convert unprovable historical state into a false fresh
claim and reintroduce ABA after ordinary operations.

## 16. Rollout and Versioning

The public capability and durable record use explicit `v1` domain separators
and schema revisions. A decoder must reject an unknown revision, noncanonical
encoding, unknown state, unknown capability binding, or unknown control-marker
format before map mutation. Compatible extension requires a new bounded
versioned representation and a migration that preserves all tombstones;
in-place reinterpretation is prohibited.

The new capability ports are additive and existing backends report unsupported.
Closing the forgeable-publication defect is deliberately source breaking:
public `Fresh` and raw grouped-request construction are removed for every
namespace, so an unbound namespace cannot continue caller-asserted fresh
publication. Raw generationless grouped removal and authoritative readback are
also removed from the public production trait; stopped legacy cleanup follows
the separately authorized operator procedure in §11. Once a namespace is
durably bound, rollback to a legacy writer is unsupported.

The normal RFC process calls for interest-gauging in GitHub Discussions, but
Discussions are currently disabled. Issue [#662](https://github.com/openpacketcore/openpacketcore-sdk/issues/662)
is the interest-gauging artifact for this proposal. That does not approve the
design: a maintainer must approve and merge this RFC's pull request before any
implementation PR relies on it.
