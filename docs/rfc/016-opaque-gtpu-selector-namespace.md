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

The selector dataplane adapter is a deliberately trusted part of that
authority boundary. Supplying a `GtpuDataplaneBackend` implementation to a
production selector lifecycle selects it into the trusted computing base
(TCB): its receipt says that this adapter performed and exactly read back the
requested mutation under its ownership gate. SDK-minted affine requests and
exact receipt-coordinate binding prevent ordinary callers from constructing,
replaying, or cross-binding a receipt without the corresponding request. They
do not cryptographically attest a real kernel effect by a malicious in-process
implementation of the public, unsealed trait, and Rust cannot distinguish a
production adapter from a fake which a product passes to that lifecycle. The
built-in eBPF adapter is the initial supported trusted adapter and must perform
the real mutation, stamp validation, and exact readback specified here. A
future third-party production profile requires the backend-neutral stamp codec
and qualification harness described in §9; implementing or overriding the
public trait methods alone is not conformance. This RFC defines no adapter-
attestation credential scheme.

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
- An opaque affine admission, effect, removal, retirement, and reuse-
  quiescence capability surface.
- Exact canonicalization and atomic ownership of a complete grouped selector
  set: every TEID, PAA, and nonzero bearer-mark selector atom.
- Durable identity, encryption boundary, permanent tombstones, CAS recovery,
  and backend conformance.
- A persistent eBPF control marker that prevents a live or cleaned pin graph
  from silently changing the ledger authority.
- The trusted-adapter boundary, public capability protections, and qualification
  evidence required before a product selects a backend for this feature.
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
- Cryptographic attestation of a real effect by a malicious selected adapter,
  remote adapter credentials, or credential provisioning, rotation, revocation,
  and verification. Those require a distinct proposal with a concrete trust
  root.

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

These safety properties constrain SDK-mediated operations initiated by ordinary
callers and non-TCB code. They do not constrain arbitrary code inside the
selected trusted adapter, which could bypass its contract or falsely report an
effect.

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

### 3.4 Trusted Adapter Boundary

`GtpuDataplaneBackend` remains public and unsealed so a product can supply a
backend profile. Its selector methods default to `Unsupported`. The SDK does
not issue a qualification credential or a sealed selected-backend wrapper:
passing an implementation to a production selector lifecycle is the product's
explicit selection of that implementation into the TCB. That trust decision
covers every receipt class: namespace binding and provisioning; effect,
readback, removal, and quiescence; and terminal-fence inspection, creation, and
readback. Qualification under §9 and §14.11 is required deployment evidence,
but it is not a runtime gate which Rust can enforce. Passing a fake or an
unqualified implementation is an unsafe product configuration and a TCB
compromise, not a condition the receipt type can detect.

The SDK enforces opaque affine capability ownership, exact private request
coordinates, durable CAS state, and rejection of stale, replayed, cross-request,
and cross-namespace receipts presented without the matching request. The
coordinate binds the request kind, namespace, complete set, phase generations
and nonces, and durable selector-backend epoch. The receipt's private class and
the coordinator's closed outcome checks are separate from that coordinate. It
is not evidence that the selected adapter wrote or read an operation stamp. A
malicious selected adapter is therefore a TCB compromise, not an attacker that
this RFC claims to distinguish at runtime. Test-only authority constructors and
tokens remain excluded from production builds, but a product is responsible
for never supplying a fake backend to a production lifecycle.

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

The protected ledger also retains one immutable row for every atom commitment
ever reserved for possible publication in this namespace. That row records
only its keyed atom commitment and the first `Installing` group/generation
that committed it; it is never deleted, reassigned, or inferred from the
set/group tombstones. A failed, poisoned, or never-started installation remains
conservatively consumed because a delayed external effect can no longer be
excluded. A fresh claim is valid only when every atom commitment in the
candidate is absent from this permanent atom ledger in the same whole-ledger
snapshot. An unseen complete-set or group commitment is insufficient when even
one constituent atom was reserved. The atom ledger is internal authority data,
not a public per-atom claim API.

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

The eBPF commitment is a live filesystem attestation, not the durable lookup
coordinate. Its exact padding-free `PinNamespaceCodecV1` is version `1` (u8),
the opened reconciler-control-root `st_dev` (u64 big-endian), that descriptor's
`st_ino` (u64 big-endian), the pin leaf length (u64 big-endian), and the raw Unix
leaf bytes. The commitment is
`SHA-256("opc/gtpu-selector/pin-namespace/v1\0" || PinNamespaceCodecV1)`.
The backend obtains every value from no-follow descriptor traversal under its
ownership gate; no caller path or digest enters the codec. Different control-
root inodes with the same leaf differ, while accepted bind-mount path aliases
which resolve to the same opened inode and leaf converge. Symlink traversal is
rejected rather than canonicalized. A bpffs unmount/remount or root replacement
may change this attestation. Startup still locates the old ledger by stable
device, observes the mismatch or missing marker, and fails closed; it never
treats the new value as a virgin namespace.

The tuple is the ledger aggregation and ownership boundary. There is exactly
one durable ledger for it. One stable device is permanently bound to the first
provisioned pin attestation: presenting that device at another pin namespace is
a configuration conflict, not a second ledger. A moved/restored pin namespace
requires the separately fenced #663 transition (or a genuinely different
stable device); it cannot reuse a capability.

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
insufficient. The product supplies the validated administrative `TenantId` and
NF kind to the selector-ledger constructor and fixes the protected-backend scope
when creating the wrapper. The wrapper converts that latter value into an
opaque protected-payload-scope base; its raw scope bytes do not cross the
session-store boundary. The dataplane derives the one stable lookup key from
that genuine base and the bootstrap's backend-qualified stable device, then
stores and validates the bootstrap's pin attestation inside the protected
record and backend marker. This stable lookup is deliberate: a remount or pin
loss must locate old history and fail closed rather than derive a new empty key.
This happens before the random ledger material and complete namespace binding
are minted. Claims cannot replace the base, bootstrap, scope, or key.
The existing RFC 004 envelope AAD MUST bind its schema revision, authority
purpose/state type, storage tenant, NF scope, exact reserved `SessionKey`,
record generation, fence, and protected-backend namespace. The authenticated
plaintext additionally binds the exact device namespace, pin attestation,
storage-scope commitment, and domain-separated ledger-ID commitment. A
plaintext `EncryptedSessionPayload` wrapper, a caller assertion, or generic
backend capability flags cannot satisfy this gate. The selector secret never
leaves that protected record. Only its
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

The sealed local-encryption and remote-sealing wrappers first construct
`ProtectedPayloadScopeCodecV1` with this exact, padding-free byte layout:

```text
version 1 (u8)
backend-scope length (u64 big-endian) || canonical protected-backend-scope bytes
```

The protected-backend scope is a nonempty, NUL-free canonical UTF-8 value of at
most 128 bytes fixed when its wrapper is created. Its 32-byte commitment is
exactly
`SHA-256("opc/session-store/protected-payload-scope/v1\0" ||
ProtectedPayloadScopeCodecV1)`. `SessionStore::protected_selector_ledger_base`
returns a redacted, non-constructible SDK value containing the validated
administrative tenant/NF coordinates and that nonsecret commitment. It does not
return the raw backend scope. Reading a commitment from this genuine base does
not grant selector authority; the production dataplane constructor additionally
requires and consumes the non-forgeable backend bootstrap.

`StorageKeySeedCodecV1` then has this exact, padding-free byte layout:

```text
version 1 (u8)
tenant length (u64 big-endian) || canonical TenantId UTF-8 bytes
NF-kind length (u64 big-endian) || canonical NetworkFunctionKind UTF-8 bytes
key-type length (u64 big-endian) || ASCII "gtpu-selector-ledger-v1"
protected-payload-scope commitment (32 bytes)
stable device ID (16 bytes)
```

The selector namespace constructor accepts neither a raw backend scope nor any
raw commitment. In particular, the transient pin attestation is not a lookup-
key input. The reserved `SessionKey` stable ID is exactly
`SHA-256("opc/gtpu-selector/storage-key/v1\0" || StorageKeySeedCodecV1)` and
therefore has the required 32-byte width. Its tenant and NF fields are the same
canonical values, and its key type is the exact reserved string above.

`StorageScopeCodecV1` is version `1`, the same length-prefixed tenant, NF kind,
reserved key type, the derived 32-byte stable ID without a length prefix, and
the same 32-byte protected-payload-scope commitment, in that order. The 32-byte
storage-scope commitment is exactly
`SHA-256("opc/gtpu-selector/storage-scope/v1\0" || StorageScopeCodecV1)`.
These two digests are deliberately unkeyed: the inputs are bounded
administrative routing coordinates rather than subscriber identifiers, the SDK
alone owns the codecs and hashing calls, callers never supply a digest, and no
digest is emitted through diagnostics. Integrity and confidentiality remain the
responsibility of the protected record, its AAD, and the opaque marker binding.
Local encryption and remote-sealing wrappers produce the same SDK-built base,
`SessionKey`, storage-scope bytes, and commitment for the same canonical inputs
before applying their distinct custody mechanisms; a third-party store beneath
either wrapper cannot replace them.

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
bytes`: tag `T` contains the existing 8-byte
`GtpuSessionDownlinkKey::encode(outer_family, inner_family, local_teid)`; tag
`P` contains the PAA family tag (`4` or `6`), prefix length (`32` or `64`), and
the canonical four-byte IPv4 address or eight-byte IPv6 prefix; and tag `M`
contains a nonzero four-byte bearer mark in its model/network order followed by
four `0xff` bytes encoding the required full-mask semantics. A zero mark emits
no `M` atom. Sorting and deduplication occur over the complete tagged encodings.
This deliberately tracks PAA and mark independently rather than treating the
existing combined uplink map key as one atom: changing one component cannot
hide reuse of the other. The `T` atom retains the exact cross-family TEID
distinctions enforced by the map ABI. Repeated elementary atoms shared by two
valid family entries collapse to one row; duplicate group entries or duplicate
encoded map keys are rejected before hashing. Group commitment is HMAC over
version `1`, stable device ID, and group ID; desired commitment is HMAC over
desired-group bytes; set commitment is HMAC over complete-set bytes; each atom
commitment is HMAC over one atom. After the storage key and scope commitment
are fixed, the SDK mints the random ledger ID and selector secret. The
selector-secret commitment is
HMAC under that secret over the secret-commitment domain, version `1`, random
ledger ID, pin commitment, stable device, and storage-scope commitment; it is
not plain SHA-256 of the secret. The namespace binding codec is version `1`
followed by the 32-byte
pin-namespace commitment, 16-byte stable device, 16-byte random ledger ID,
32-byte selector-secret commitment, 32-byte storage-scope commitment, and
16-byte selector-backend epoch. The marker filename digest is SHA-256 over
exactly those 145 bytes. Any change to these bytes requires a new codec/domain
version and an explicit migration. The derivation order is therefore acyclic:
protected-payload base plus backend-qualified stable device, storage-key seed,
reserved `SessionKey`, storage scope, bootstrap pin attestation, random ledger
material, selector-secret commitment, complete 145-byte binding, then marker
name. The pin attestation is authenticated inside the protected record and the
complete binding but never feeds back into durable lookup.

The stopped decommission workflow additionally commits the exact predecessor
which may be reconstructed after protected-store rollback. Its
`PreDecommissionBoundCodecV1` is version `1`, the exact RFC 004 record
generation (u64 big-endian), the canonical `Bound` ledger length (u64
big-endian), and the complete canonical protected-ledger plaintext. The
predecessor commitment is HMAC-SHA-256 under the selector secret over
`"opc/gtpu-selector/pre-decommission-bound/v1\0" ||
PreDecommissionBoundCodecV1`. It therefore covers the complete group/atom/
tombstone history, allocation counter, capacity profile, binding, and exact
store generation without depending on AEAD framing randomness.

`DecommissionFenceCoordinateV1` is the exact 81-byte plaintext containing
version `1`, that 32-byte predecessor commitment, the nonzero
`Decommissioning` generation (u64 big-endian) and 16-byte operation nonce, and
the strictly greater `Decommissioned` generation and distinct 16-byte operation
nonce. Two 32-byte subkeys are HMAC-SHA-256 under the selector secret over,
respectively,
`"opc/gtpu-selector/decommission-fence/aead-key/v1\0" || binding` and
`"opc/gtpu-selector/decommission-fence/nonce-key/v1\0" || binding`. The AAD is
`"opc/gtpu-selector/decommission-fence/aad/v1\0" || binding`. The canonical
12-byte synthetic nonce is the first 12 bytes of HMAC-SHA-256 under the nonce
subkey over `AAD || plaintext`. AES-256-GCM-SIV under the AEAD subkey encrypts
the coordinate. The fixed 110-byte capsule is version `1`, the 12-byte
synthetic nonce, 81-byte ciphertext, and 16-byte tag. Decode verifies the AEAD,
recomputes the synthetic nonce in constant time, and rejects any length,
version, zero/equal coordinate, or predecessor mismatch. The capsule is
canonical URL-safe Base64 without padding when used in the terminal marker
name. It is opaque authority material and is never emitted in diagnostics.

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

A fresh claim permanently consumes its group-record slot and one immutable atom
row for every candidate atom at `Installing`; because freshness requires every
candidate atom row to be absent, it cannot partially extend prior history.
Retirement reclassifies that same group record and does not allocate a
tombstone or atom. Exact reissue consumes one new successor group-record slot
but no atom slot and references the already-retained identical rows. Claim
preflight also reserves that group's
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
per transition, 64 admitted supervisor slots per namespace, 256 admitted
supervisor slots per process, at most 16 directory entries examined while
validating a marker, 256 atoms and 512 KiB examined by one exact readback, and
4 KiB for one SDK-created diagnostic or evidence record. The admitted slots
bound queued result owners; exactly one worker per protected storage-scope
commitment is polled at a time. It uses a 30-second namespace lease, renews no
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
history. An ordinary `Fresh` path accepts only when **every** canonical atom
commitment is absent from the permanent atom ledger and inserts all of those
rows in the same whole-ledger CAS as the new `Installing` group. It rejects a
new group or newly shaped complete set that contains any previously published
TEID, PAA, or mark atom; checking only the candidate group or complete-set
commitment is forbidden.

This RFC permits exactly one other admission form: SDK-mediated transfer of the
*identical complete atom set* from one exact, permanently retired predecessor
to one distinct successor group. Reissue MUST require the SDK's exact retired
capability and an opaque SDK/backend quiescence authorization, validate the
retained source tombstone, terminal-retired stamp, authoritative absence, and
all namespace bindings, and create a higher generation and new nonce while
preserving the permanent predecessor tombstone/lineage. It MUST NOT admit a
subset, superset, mixed provenance set, multiple predecessors, the same group
identity, or a changed selector set. Mixed transfers and exact same-group
republish are #663 work. Thus no caller can cause accidental reuse merely by
reasserting `Fresh`, retaining old values, or constructing a drain enum.

Exact removal returns an opaque retired capability. A separately named,
default-unsupported backend port consumes a request bound to that capability
and returns the opaque quiescence authorization only after it revalidates the
terminal-retired stamp and absence and performs its trusted drain/RCU barrier.
The backend-neutral port permits a backend with a separately reviewed concrete
quiescence boundary to implement this operation. The built-in eBPF backend
leaves it `Unsupported` until it has a real kernel/network quiescence mechanism;
ordinary map deletion, userspace sleep, or an in-process RCU assumption is not
such a mechanism. A conformance fake can exercise protocol state transitions
with test-only authority, but a product MUST NOT pass that fake to a production
lifecycle. Doing so would select it into the TCB and let it assert a production
receipt. Any other backend must be deliberately selected into the TCB and
provide qualification evidence for an equivalent real quiescence boundary, or
leave reissue unsupported. A public constructor, raw duration completion,
caller assertion, sleep, mock success, or traffic-readiness proof cannot mint
this authorization without the exact affine request; the SDK does not claim to
detect a malicious selected adapter that lies about its own barrier.
`reissue_exact_retired_group` consumes the exact retired capability, exact
authorization, and distinct successor group in one ledger transition; neither
input is cloneable or reusable. This RFC does not treat traffic-proof authority
as drain evidence and does not implement #664.

## 6. Public Capability Surface

The public API MUST expose SDK-minted, opaque, non-serializable, non-`Clone`
affine values analogous to:

```rust
pub struct GtpuSessionSelectorAdmission { /* private */ }
pub struct GtpuSessionSelectorEffect { /* private */ }
pub struct GtpuSessionSelectorRemoval { /* private */ }
pub struct GtpuSessionSelectorRetired { /* private */ }
pub struct GtpuSessionSelectorReuseAuthorization { /* private */ }
```

Only the namespace coordinator can mint them. They bind the namespace tuple,
ledger commitment, exact group and complete set commitment, generation, and
operation nonce. Their `Debug` representation may expose only a closed state
classification and a bounded count class; it MUST expose no identity,
generation value, or commitment. Serialization, deserialization, public
fields, `Default`, generic token constructors, public drain/grace constructors,
and a public `Fresh` variant are prohibited.

The backend integration is a separate default-unsupported capability port. A
bootstrap call first returns an affine SDK/backend value containing the
backend-minted canonical pin-namespace commitment while the backend-global
ownership gate is held. The protected constructor consumes that bootstrap,
retains its private expected pin commitment in the authenticated record and
authority, and includes it in the complete backend binding; it is deliberately
not part of the stable lookup key. No other API accepts the commitment as
caller bytes. Every later binding candidate carries that same private expected
commitment. The backend compares it to its currently qualified pin namespace
before marker creation, readback, recovery, or mutation. Merely pairing an
authority with another backend instance therefore cannot move the ledger to a
different pin namespace. Its public shape is analogous to:

```rust
pub struct GtpuSelectorNamespaceBindingCandidate { /* opaque */ }
pub struct GtpuSelectorNamespaceBootstrap { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceBackendLease { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceEffectRequest { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceRemovalRequest { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceQuiescenceRequest { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceTerminalFenceInspection { /* opaque */ }
pub struct GtpuSelectorNamespaceTerminalFenceCreateRequest { /* opaque, affine */ }
pub struct GtpuSelectorNamespaceReadbackReceipt { /* opaque */ }
pub struct GtpuSelectorNamespaceQuiescenceReceipt { /* opaque */ }
pub struct GtpuSelectorNamespaceTerminalFenceReceipt { /* opaque */ }

async fn bootstrap_selector_namespace(
    &self,
    stable_device: GtpuSessionDeviceId,
) -> Result<GtpuSelectorNamespaceBootstrap, GtpuError>;

async fn provision_protected_selector_namespace(
    backend: &impl GtpuDataplaneBackend,
    store: SessionStore<impl ProtectedSessionBackend>,
    storage_scope: SelectorLedgerStorageScope,
    bootstrap: GtpuSelectorNamespaceBootstrap,
    owner: OwnerId,
) -> Result<GtpuProvisionedSelectorNamespace, GtpuError>;

async fn open_protected_selector_namespace(
    backend: &impl GtpuDataplaneBackend,
    store: SessionStore<impl ProtectedSessionBackend>,
    storage_scope: SelectorLedgerStorageScope,
    bootstrap: GtpuSelectorNamespaceBootstrap,
    owner: OwnerId,
) -> Result<GtpuSessionSelectorNamespaceAuthority, GtpuError>;

async fn bind_selector_namespace(
    &self,
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

async fn authorize_retired_group_reuse(
    &self,
    request: GtpuSelectorNamespaceQuiescenceRequest,
) -> Result<GtpuSelectorNamespaceQuiescenceReceipt, GtpuError>;

async fn inspect_selector_namespace_terminal_fence(
    &self,
    lease: &mut GtpuSelectorNamespaceBackendLease,
) -> Result<GtpuSelectorNamespaceTerminalFenceInspection, GtpuError>;

async fn create_selector_namespace_terminal_fence(
    &self,
    request: GtpuSelectorNamespaceTerminalFenceCreateRequest,
) -> Result<GtpuSelectorNamespaceTerminalFenceReceipt, GtpuError>;
```

The SDK supplies an affine request to the adapter selected for this authority
instance. Each request carries a private receipt coordinate and exposes only
the semantic projection and binding comparisons needed by its operation;
ordinary callers cannot independently mint the request or its coordinate. The
coordinate validator is not a cryptographic attestation credential: consuming
the request proves which SDK operation the selected adapter is answering, not
that the adapter performed the kernel or backend effect it reports.

The built-in eBPF adapter additionally uses the SDK-private canonical 145-byte
binding, marker name, canonical 208-byte pending and terminal stamps, opaque
110-byte decommission capsule, terminal-fence key, and constant-time comparison
operations. Under its ownership gate it validates the exact marker, complete
permanent group-key inventory, and each key's exact lifecycle-stamp value again
immediately before each effect. Its receipt coordinate binds the exact
namespace, complete set, phase generations and operation nonces, marker
commitment, request kind, and durable selector-backend epoch. The coordinator
separately accepts only the closed receipt class and outcome valid for that
request. The raw operation-stamp bytes and exact readback remain trusted adapter
assertions; the receipt does not independently attest them.

A future external production adapter cannot qualify merely by consuming the
current public request and calling its completion method. Before such a profile
is supported, the SDK MUST publish a bounded backend-neutral stamp/capsule codec
and conformance harness which let the adapter perform the same exact persistence
and readback without exposing the selector secret or public authority
constructors. That change requires its own public-API and mutation tests under
§14.11. Until then external implementations remain `Unsupported`. Test-only
authority may exercise protocol state transitions, but it is not production
qualification.

Terminal-fence inspection is a mandatory part of an RFC 016 backend profile,
not an eBPF extension. Under the backend's real global ownership gate it returns
an opaque classification which the selected adapter asserts from exact absence
or the exact append-only capsule bound to this namespace. The SDK validates its
coordinate; that validation does not independently attest the adapter's
inspection. Only the coordinator can turn an exact `Decommissioning` record
into the affine create request. Creation must be no-replace/idempotent for that
one exact capsule, durably settle independently of protected-store rollback,
and return an exact readback receipt; a different existing capsule is
indeterminate. The default methods are `Unsupported`, and a backend that cannot
implement this independent permanent fence cannot advertise RFC 016 selector-
namespace capability. The eBPF directory name in §8 is the reference
implementation; another backend may use a different durable medium only when
its conformance profile proves equivalent append-only identity, serialization,
crash recovery, bounded inspection, and exact readback.

`GtpuSelectorNamespaceBootstrap` has no `Clone`, serialization, field getter,
raw-parts constructor, or backend-neutral minting trait. The built-in eBPF
backend mints it only after checking the stable device and canonical pin
namespace under its real ownership gate. Passing that backend to the protected
production lifecycle is the product's trust selection; there is no separate
qualification credential. The built-in eBPF backend is the initial production
implementation and must perform the real mutation, stamp validation, and exact
readback. Test-only bootstrap minting is compiled only for tests and cannot be
linked into a production constructor.
The separately named provisioning call is available only to the stopped
workflow from §11 and performs the privileged empty-backend proof before its
absence-to-`Provisioned` CAS. The ordinary open call rejects an absent record;
it may join only the exact preprovisioned initialization or open an exact
already-`Bound` namespace.

`claim_fresh_complete_group` consumes an exact group and returns an admission
only after durable `Installing` ownership commits. `reissue_exact_retired_group`
is separately named and requires the exact retired capability. Reconcile
consumes the admission and returns an effect only after authority-bound exact
backend readback and the `Installing` to `Active` CAS. Exact removal consumes
the effect, moves a private removal request through the authoritative
retirement workflow, and returns a retired capability only after `Retired`
commits. A stale or consumed capability is unusable; cancellation cannot make
it reusable.

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
| `Retired` | Permanent complete-set tombstone; no live effect. | successor-link annotation in the same CAS that creates a distinct `Installing` successor, `Poisoned` |
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
a one-way `backend_started` bit. This bit records the durable handoff decision;
it is not evidence that a backend effect or even a pending-stamp write occurred.
The coordinator preflights supervisor capacity, CASes and reads this bit before
handoff, and then synchronously transfers the affine request into an SDK-owned
supervisor before its next externally cancellable await. It never clears the
bit. The backend MUST write and exactly read the operation's pending stamp
before its first journal, map, program, or traffic mutation.

A decoder rejects a pending phase without a greater terminal generation, a
duplicate or zero nonce, or an allocation counter that has not advanced past
both generations. After the prior process lease and host lock are fenced,
recovery may therefore observe an exact pre-effect state, the exact pending
stamp, or the exact precommitted terminal stamp when `backend_started = true`:
process death is possible at either side of each write. It deterministically
re-enters or completes the same precommitted operation as specified in §7.4.
When `backend_started = false`, only the exact pre-effect state is admissible;
a pending or terminal stamp proves rollback or an incoherent writer and fails
closed. Missing stamp inventory, partial effect, or every other value is
indeterminate; plain structural absence is never enough.

### 7.2 Claim and Effect Ordering

1. Validate the complete canonical group, every independent capacity, protected
   store profile, and backend capability before random minting or mutation.
2. Bind or exactly validate the SDK-minted ledger candidate against the
   backend's canonical device/pin namespace and immutable marker, without map
   mutation. This settles an ambiguous marker creation only by exact readback.
3. Under the namespace ownership gate, a fresh claim first proves every
   candidate atom commitment absent in the exact expected ledger revision, then
   uses one whole-ledger CAS to insert every immutable first-publication atom
   row and the new group entry in `Installing` with its generation/nonce, the
   precommitted `Active` successor generation/nonce, and
   `backend_started = false`. The CAS fails if any atom, group, or set history
   changed. An exact retired reissue instead performs one whole-ledger CAS that
   leaves every atom row and the predecessor `Retired`, writes its immutable
   one-time successor link, and creates the distinct successor group in
   `Installing`. The entire successor group, identical atom ownership, group
   binding, and prior tombstone lineage commit together. No transition ever
   rewrites a predecessor `Retired` entry into `Installing`.
4. Re-read the exact `Installing` phase, then CAS/read back
   `backend_started = true` and, without another await, consume its affine
   authorized request into a pre-reserved SDK-owned supervisor. The caller
   receives only a result observer whose drop does not abort that task. Inside
   the task, the backend validates the marker and complete stamp inventory,
   writes and exactly reads the pending stamp, and only then performs its first
   journal, map, program, or traffic mutation.
5. Require an authority-bound whole-group readback, then write and exactly read
   the terminal `Active` operation stamp using the precommitted successor
   generation/nonce. A successful syscall, map update, semantic-only group
   match, partial readback, or current-map absence alone is not success.
6. CAS the exact `Installing` operation to the exact precommitted `Active`
   coordinate and persist its private capability-recovery descriptor. Only then
   mint the Active effect capability.

No operation may publish a live capability after a durable failure. A rejected
or lost ACK, timeout, cancellation, process death, readback ambiguity, or CAS
conflict is not permission to retry by assuming no effect. In particular, a
caller-side timeout or dropped observer cannot poison the operation while its
supervisor or backend worker may still publish an effect.

### 7.3 Retirement and Removal Ordering

1. Consume the active effect, validate the exact current generation and
   control-marker binding, and CAS `Active` to `Retiring` with its next
   generation/nonce, the precommitted `Retired` successor generation/nonce,
   and `backend_started = false`. After preflighting capacity, CAS/read back
   `backend_started = true` and synchronously transfer the removal request into
   the same SDK-owned supervision boundary before another await.
2. Invoke capability-bound exact whole-group removal. Per-selector removal,
   best-effort cleanup, and deletion based on an absent map are forbidden.
3. Require exact backend readback proving the complete group is absent under
   this authority and no residual partial group is present, then write and
   exactly read the terminal absent stamp using the precommitted `Retired`
   successor coordinate.
4. CAS `Retiring` to the exact precommitted permanent `Retired` coordinate,
   retaining all tombstones, lineage, and its private capability-recovery
   descriptor, then mint the retired capability.

Retirement must commit before a selector can be reissued. An interrupted
retirement remains `Retiring`, never `Unbound`; it blocks all claims.

### 7.4 Recovery Outcomes

Recovery obtains the same local ownership gate, performs a durable exact read,
fences the prior process lease/host-lock owner, and validates the immutable eBPF
control marker plus complete operation-stamp inventory before any dataplane
operation. It has only these outcomes:

- `Installing` plus the exact pre-effect inventory (no operation stamp,
  journal, group, or selector effect) may hand the same precommitted coordinate
  to a new supervisor. With `backend_started = false`, recovery first performs
  the one-way CAS; with it already true, the fenced new owner resumes directly.
  This classification is available only from the authority-bound negative
  inspection, never semantic `Absent`.
- `Installing` plus its exact pending stamp resumes the same backend journal;
  plus its exact terminal-active stamp and operation-matching complete backend
  readback, it CASes to the precommitted higher-generation `Active` phase and
  recovers one effect capability for the recorded owner operation.
- `Retiring` plus the exact prior terminal-active stamp and complete old graph
  re-enters the same precommitted removal. Its exact pending-remove stamp resumes
  that removal journal. Its exact terminal-retired stamp plus authority-stamped
  whole-group absence CASes to the precommitted permanent `Retired` phase.
- `Active` plus exact matching readback: retain `Active`; `Retired` plus exact
  terminal-retired stamp and exact absence: retain `Retired`.
- Any mismatched generation, group, set, device, pin namespace, nonce,
  capability, partial readback, unavailable durable read, ambiguous ACK,
  unexpected resident atom, missing/foreign stamp, malformed record, or
  duplicate live claimant:
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
same rule recovers the retired capability needed for exact reissue.
An in-process retry joins the existing supervised operation instead of
re-minting while its delivery owner remains live.

### 7.5 Process and Cancellation Ownership

One namespace operation owns a bounded SDK coordinator task and its capability
from durable transition through final readback/CAS. Supervisor capacity is
reserved before the pending-phase CAS. After the `backend_started` CAS returns,
the coordinator transfers the affine request, an owned backend handle, and the
protected-store authority into that task synchronously before another await.
The backend effect future is polled only inside this task. The public caller
awaits a separate non-aborting result receiver; dropping or cancelling it MUST
NOT release ownership or cancel blocking kernel work while a durable effect is
pending.

One process polls exactly one such worker for a protected storage-scope
commitment from durable lease acquisition through release. Other admitted
same-scope supervisors remain bounded and unpolled. This is required because a
same-`OwnerId` store acquire denotes recovery by that replica and replaces its
prior credential; overlapping local acquisitions would invalidate a live guard
without invalidating its time-bounded backend request. Protected open and
binding verification use the same detached ownership rule. Every concurrently
live process MUST use a stable `OwnerId` unique to that replica. Reusing one
owner in multiple processes is outside the session-store contract and MUST NOT
be treated as supported failover.

The SDK supervisor retains and renews the namespace lease and request until one
terminal receipt is durably settled. It acquires the host lock only for the
bounded validation/effect/readback sections defined by the operation, releases
it before every durable-store await or renewal, and revalidates after every
reacquisition; process death releases only a lock held in the current bounded
section. Every renewal uses the exact phase generation/fence. A failed, late, or
ambiguous renewal fences the worker before any further effect and leaves the
phase recoverable/poisoned; it cannot continue until the prior owner is fenced.
A watchdog may make a caller observation time out, but it cannot drop a worker
or declare `Poisoned` while that worker can still mutate. The maximum one-step
kernel work duration must be below the admitted lease-renewal safety margin.
A coordinator either rejoins the recorded operation or leaves it recoverable/
poisoned. The registries retain at most the configured per-namespace and
per-process number of supervisors and report only a closed cancellation
classification. If the SDK runtime cannot provide this worker ownership, the
capability is unsupported.

The durable lock/CAS authority, not a process mutex, decides cross-process
ownership. The process-local worker gate prevents only reentrant acquisition by
one replica identity; it is not a distributed fence. Concurrent replicas with
distinct owner identities still serialize through the durable generation/CAS
and the host-global control-marker lock.

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

The same control directory has a second, initially absent, append-only namespace
lifecycle fence:

```text
SELECTOR_DECOMMISSIONED_V1_<64-lower-hex-binding-digest>_<147-char-coordinate-capsule>
```

It is an empty directory with the same creation, metadata, sync, ownership, and
descriptor-readback requirements as the authority marker. The first suffix is
the SHA-256 digest over the same exact 145-byte binding; the second is the
authenticated encrypted coordinate capsule from §5.1. The complete name is
exactly 239 ASCII bytes, below Linux `NAME_MAX`; a different encoding, padding,
case, length, or extra matching entry is invalid. The protected
`Decommissioning` record retains the exact predecessor commitment, both
precommitted coordinates, and canonical capsule before marker creation.

The terminal marker is created only by the stopped decommission workflow, is
never removed, and makes the transition one-way independently of the protected
store. Ordinary `Bound` requires its proved absence. `Decommissioning` may have
it absent or exact depending on recorded progress and, when present, requires
the decoded capsule to equal its stored predecessor and coordinate fields.
`Decommissioned` requires that same exact marker. If protected storage rolls
back to the exact predecessor `Bound` record, the coordinator decrypts and
authenticates the capsule, recomputes the predecessor commitment over that
record, proves every group and stamp terminal-retired, and CASes only that exact
record back to the capsule's `Decommissioning` coordinate while advancing the
allocation counter past both reserved generations. It then resumes the one
precommitted terminal transition. A different/older `Bound` record, a capsule
whose generations are not the exact next two allocation values, or any history,
nonce, binding, inventory, or commitment mismatch is indeterminate and remains
offline. No path invents replacement coordinates. A `Bound` or earlier ledger
paired with any terminal fence can never serve, claim, reprovision, or recreate
prior state.

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
reserved for its journal. A terminal stamp uses the precommitted `Active` or
`Retired` successor coordinate and a zero transaction ID. The install/active
dataplane generation is the generation of the exact resident group; the
remove/absent value is the nonzero generation of the exact group being removed.
All keyed commitments and the dataplane generation remain identical from the
pending operation to its terminal result.

The protected record and map have this exact key/value relationship:

| Ledger phase | Required stamp for the group key |
| :--- | :--- |
| `Installing`, not started | absent |
| `Installing`, started | absent only with exact pre-effect inventory, otherwise exact pending-install or exact terminal-active |
| `Active` | exact terminal-active |
| `Retiring`, not started | prior exact terminal-active |
| `Retiring`, started | prior exact terminal-active only with the complete pre-effect graph, otherwise exact pending-remove or exact terminal-retired |
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

Every other stamp key is foreign history. After the old host owner is fenced, a
started phase at its exact pre-effect inventory resumes only its same
precommitted operation as specified in §7.4; it never becomes `Unbound`, skips
to a terminal phase, or issues another coordinate. Absence without the complete
authority-bound negative inspection is indeterminate. A mismatched or
unrecognized stamp stays unavailable for offline recovery and cannot be
normalized into a caller-selected poison record.

The coordinator constructs the bounded journal and reserves its nonzero target
dataplane generation in memory, writes and exactly reads the pending stamp, and
only then persists the journal or performs the first selector mutation. The
journal transaction ID and target generation must equal the pending stamp.
After exact whole-group readback it writes and exactly reads the terminal stamp
before finalizing the journal and before the terminal
ledger CAS. Active recovery requires the exact terminal stamp plus the existing
authority and selector-index graph. Retired recovery requires exact group
absence and the
terminal absent stamp. Group stamp keys are permanent namespace inventory, and
each key's value must be the one exact current lifecycle fence allowed by the
table and replacement chain. The terminal `Retired` value is never removed by
cleanup, compaction, or decommission; capacity is reserved one-for-one with
permanent groups. On every open,
the coordinator compares the complete bounded stamp-key inventory with the
protected ledger. An extra stamp proves a rolled-back or foreign ledger; a
missing stamp for a terminal operation proves map loss or rollback. A pending
operation with no current-operation stamp is admissible only when §7.4's exact
pre-effect inventory also holds; it must enter recovery before the namespace
can serve. An `Installing` operation durably recorded as not backend-started
may have no stamp and can only start its same precommitted coordinate under the
exact recovery rule in §7.4. A missing, malformed, stale, wrong-generation,
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
4. Re-read the exact protected `Initializing` record, authority marker, proved
   absence of the decommission fence, and empty map set, then CAS the ledger to
   `Bound` at a higher generation/nonce before any claim.

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

The total cross-boundary lock order is durable namespace lease/fence first,
then the host-global control-directory `flock`; no path may acquire or renew a
durable lease, perform a protected-store CAS/readback, or await another durable
store operation while holding that `flock`. Bootstrap may briefly acquire the
host lock to mint a bounded, affine namespace sample, but releases it before
any store operation. That sample is not authority: after durable ownership is
established, every initialization, recovery, effect, retirement, or
decommission path reacquires the host lock in the declared order and exactly
revalidates the live descriptors, binding, markers, and inventory before use.
The admitted backend critical section must finish inside the lease safety
margin, so it never depends on a lock-inverted renewal. Failure to reacquire or
revalidate leaves the durable phase recoverable/offline without mutation.

The backend MUST resolve each path component relative to a trusted bpffs root
descriptor using descriptor-relative traversal. It MUST reject symlinks,
non-directories, unexpected owner or mode, non-bpffs filesystems, unexpected
links, and inode replacement. Creation uses descriptor-relative, no-replace
directory creation; it never follows a replacement path. Existing markers are
enumerated to a fixed bound, type/owner/mode/inode/link checked, and compared
exactly to the lifecycle-dependent canonical set: none for `Provisioned`; only
the authority marker for `Initializing` and ordinary `Bound`; the authority
marker alone or the authority plus the exact recorded terminal marker for
`Decommissioning`; and both exact markers for `Decommissioned`. The sole extra
case is the exact predecessor-`Bound` rollback recovery in §8.1, where both
markers force offline reconstruction before any serving action. Every other
missing, extra, duplicate, malformed, or state-inconsistent marker fails
closed. The containing control directory and every expected marker are
re-stat'ed by descriptor before use to detect replacement races.

Creation makes the complete marker atomically, syncs the opened marker and
containing directory, re-enumerates the exact lifecycle-dependent marker set,
and verifies every opened directory identity before allowing the first
map/program mutation. Authority-marker creation must yield exactly the one
authority marker; terminal-marker creation must yield exactly the authority
marker plus its recorded terminal marker. The
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
decommission procedure may remove mutable programs, selector maps, journals,
and non-authority pins only after the protected namespace record is permanently
`Decommissioned`; it MUST retain the authority marker, terminal decommission
fence, complete operation-stamp authority map, and protected record. Normal
cleanup and decommission never erase any of those authority fences.

## 9. Backend Contract

The public `GtpuDataplaneBackend` capability default for this feature MUST be
unsupported. The capability port is public and unsealed. Passing an
implementation to a production selector lifecycle is the product's deliberate
selection of that implementation into the TCB described in §3.4; the SDK does
not issue a separate qualification token or sealed wrapper. SDK code constructs
the opaque requests and validates their exact private receipt coordinates, but
an adapter which receives a request can cause the SDK to accept its assertion
without a separate cryptographic proof of the underlying effect. A malicious
selected adapter can therefore lie or bypass its ownership gate; this RFC does
not claim the public trait alone can detect that compromise.

A qualified adapter MUST:

- accept only the opaque capability-bound complete group operations;
- let only the SDK supervisor poll an accepted effect future; dropping the
  caller's result observer cannot cancel or detach the backend operation;
- atomically associate every effect and exact removal with namespace tuple,
  group/set commitment, generation, and operation nonce;
- perform the requested real backend mutation and exact full readback under its
  real backend-global ownership gate before it asserts a successful receipt;
- write and exactly read the pending operation stamp before its first effect,
  and compare the complete permanent stamp-key inventory with the protected
  ledger before every recovery or mutation;
- provide bounded exact whole-group readback whose `Absent` result proves the
  conditions required by §7.4, and otherwise return `Indeterminate`;
- distinguish confirmed exact ACK/readback from timeout, duplicate ACK, wrong
  reply, partial result, cancellation, and I/O uncertainty;
- reject mismatched/replayed/stale/cross-boundary capabilities before traffic or
  map mutation; and
- preserve the immutable control-marker binding across its supported restart,
  cleanup, and replacement paths;
- under the same backend-global gate, provide bounded exact terminal-fence
  absence/presence inspection plus no-replace creation and exact readback of
  the SDK-authorized capsule; and
- retain that terminal fence and its exact capsule across every supported
  restart, cleanup, backend replacement, and mutable-graph loss independently
  of the protected store.

An adapter that cannot make these statements remains unsupported even if it can
reconcile maps, has a session store, or reports a successful mock operation.
Capability reporting and conformance evidence qualify a product's trusted
adapter selection; they are not a runtime liveness claim or a cryptographic
trust root. A replacement adapter or restarted adapter process must validate
the exact durable/control binding and durable selector-backend epoch before it
performs any action; it cannot adopt a live legacy graph on the basis of current
map content.

An eBPF backend uses the directory marker defined in §8. A non-eBPF backend
must provide an equivalent immutable, independently durable namespace binding
and a separate append-only terminal-capsule fence under its backend-global
exclusive ownership and pass the same split-store, restart, rollback,
decommission, replacement, and conflict cases. If it has neither independently
durable object, two independent durable stores could mint history or a rolled-
back `Bound` store could reopen a decommissioned namespace, so the complete
selector-namespace capability remains unsupported.

The initial implementation publishes the built-in eBPF qualification path and
test-only authority for state-machine tests. Those test-only authority values
cannot enter a production constructor. This does not prevent a product from
passing ordinary fake backend code to the public production lifecycle; doing
that selects the fake into the TCB and is outside the safety claim. The SDK
does not yet publish the backend-neutral operation-stamp/capsule codec required
for a third-party
production profile. Therefore an external implementation remains unsupported
even if it overrides every default method and can consume an opaque request.
Adding the missing generic codec and external-profile harness is an SDK change,
not something a product may replace with a local authority type.

Once that generic boundary exists, external implementations consume opaque
authorized requests and use the SDK codec to persist and compare operation
stamps; they do not reconstruct authority from public fields. Passing pure mock
success tests is not conformance: a backend profile must execute its real
mutation, exact readback, restart, process loss, caller cancellation, and
conflicting-binding paths. This evidence qualifies the adapter for deliberate
TCB selection; it does not transform a public trait implementation into a
runtime-attested trust root. Implementing the semantic grouped reconcile
methods alone is never qualification.

## 10. Authority Composition

### 10.1 Local Durable Authority

For a local profile, the SDK exposes a separately named constructor accepting
the affine backend bootstrap, the target `GtpuDataplaneBackend`, and a
`SessionStore` over an SDK-sealed `ProtectedSessionBackend`, backed by one RFC
004 store shared by every writer for the namespace. The bootstrap's canonical
stable device and the protected administrative base derive the one reserved
ledger lookup key before the first record CAS; the bootstrap's pin attestation
is then authenticated in the record and complete backend binding. No raw
session key, pin commitment, ledger ID, secret, epoch, or binding digest is a
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
workflow authenticates and fences the target, acquires the backend-global lock,
performs a complete bounded privileged inspection, mints an affine inspection
receipt, and releases that lock before any store operation. Only exact
emptiness, no legacy control marker, and no prior provision/decommission fence
permit the durable installation owner to CAS-allocate and exactly read the
permanent `Provisioned` record at the SDK-derived reserved key. Initialization
later reacquires the backend lock and revalidates the complete empty backend
before marker creation; intervening backend state fails closed rather than
rolling back the record. The workflow records only a redacted classification.
A missing record during ordinary startup means
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
first acquires/fences the durable namespace lease. It obeys the §8.3 lock order
through this complete sequence; every backend section is bounded and releases
the host lock before a protected-store await or lease renewal:

1. Acquire the backend-global lock, revalidate the live namespace binding,
   complete terminal-retired group/stamp inventory, and exact terminal-fence
   absence through the mandatory backend inspection port, mint an opaque
   inspection receipt, then release the backend lock.
2. While holding only the durable namespace lease, CAS `Bound` to
   `Decommissioning`, precommitting its strictly greater
   phase generation/nonce and the strictly greater terminal
   `Decommissioned` generation/nonce as the exact next two allocation values.
   The same CAS retains the complete binding and all group/atom/tombstone
   history and stores the §5.1 predecessor commitment plus canonical encrypted
   coordinate capsule, and consumes the exact prior inspection receipt. Exactly
   read that complete record back; renew the durable lease here if required.
3. Reacquire the backend-global lock in that order, revalidate the binding and
   complete inventory against the recorded operation, and inspect the terminal
   fence again. If absent, consume the SDK-minted affine request to create,
   settle, and exactly read the recorded capsule; if already exact, join the
   same operation. A different or ambiguous fence fails closed. Release the
   backend lock with an opaque exact receipt. Once this append-only backend
   effect exists, no `Bound` record may serve even if protected storage rolls
   back; only an exact predecessor match may reconstruct the recorded
   operation.
4. While holding only the durable namespace lease, validate that receipt, CAS
   the exact `Decommissioning` operation to its precommitted permanent
   `Decommissioned` coordinate, and exactly read the protected record back.
5. Reacquire the backend-global lock, revalidate both lifecycle fences and the
   complete terminal stamp inventory against the exact `Decommissioned`
   receipt, then remove only mutable programs, selector maps, journals, and
   non-authority pins. Exactly read back the retained authority marker,
   terminal fence, and complete operation-stamp authority map, then release the
   backend lock. It never removes any authority fence.
6. With the same durable lease and no host lock held, exactly re-read the
   `Decommissioned` protected record. Only the pair of final store/backend
   receipts is completion; disagreement remains offline.

Lease renewal occurs only between these bounded host-lock sections. Failure to
renew or reacquire stops before another backend effect and leaves the exact
recorded phase recoverable. No decommission path holds both gates while awaiting
the store, and no lock release authorizes a skipped revalidation.

A crash before or after step 1 leaves `Bound` with no terminal fence and permits
no cleanup; a later attempt repeats the bounded inspection. A crash after step
2 resumes only the exact stored `Decommissioning` operation. A crash or
protected-store rollback after step 3 is fenced by the terminal marker and
cannot return to serving. The exact predecessor `Bound` record can recover only
the authenticated phase/terminal coordinates from that marker as specified in
§8.1; any other rollback remains indeterminate rather than inventing a
generation or nonce. A crash after step 4 leaves `Decommissioned`, forbids
traffic and claims, and may only resume the same bounded steps 5–6 cleanup and
verification. Neither marker nor the protected record is ever removed.
`Decommissioned` can be restored or moved only by a future separately
authorized, versioned migration that preserves both terminal fences; it can
never become an ordinary fresh namespace.

Deleting maps, pins, a copied database, or a control file never authorizes
deletion of selector history or creation of `Provisioned`. Rollback to an image
lacking this RFC is unsupported once a namespace is provisioned, except through
a stopped, explicitly approved recovery that preserves the permanent authority
record.

## 12. Security and Privacy Analysis

| Threat | Required mitigation |
| :--- | :--- |
| Split brain or concurrent claimant | One complete ledger CAS, monotonic generation, host-global control lock, and exact readback; disagreement poisons or fails closed. |
| ABA, replay, or stale effect | SDK-minted affine capabilities bind exact set, namespace, generation, and nonce; permanent per-atom history, group/set tombstones, and non-wrapping generations reject reuse. |
| Cross-device, cross-pin, or cross-group use | The authenticated protected record and immutable control marker bind the exact tuple; backend validates before mutation. |
| Partial selector claim/removal | Canonical whole-group transaction and exact whole-group readback; mixed provenance is unsupported. |
| Ordinary caller or non-selected mock forges evidence | Opaque affine requests and private receipt coordinates are not independently constructible; the SDK validates the exact request kind, binding, complete set, phase generations/nonces, durable selector-backend epoch, receipt class, and closed coordinator outcome. Structural or semantic equality alone cannot supply the missing request. A backend deliberately passed to the production lifecycle is selected into the TCB and is not in this attacker class. |
| ACK loss, cancellation, or process death | Durable progress states, operation nonce, exact recovery outcomes, bounded supervision, and poison on ambiguity. |
| Map/program loss or ordinary cleanup | Immutable persistent control marker plus durable ledger; absence does not prove historical absence. |
| Control-marker tampering | Trusted descriptor traversal, no-follow/no-replace, owner/mode/link/inode checks, exact enumeration/digest binding, directory sync, and host-global lock. |
| Symlink, hardlink, or replacement race | Descriptor-relative no-follow traversal; reject links, unexpected metadata, changed inode, and non-bpffs objects before mutation. |
| Durable rollback or cloned database | Protected AAD plus permanent backend-owned group stamp keys and exact current lifecycle values; every effect revalidates the exact ledger/stamp bijection while holding the backend-global gate. Extra/missing/mismatched history fails closed. |
| Decommission followed by re-adoption | Runtime locates history by stable device rather than inferring virgin state from absence; the precommitted `Decommissioning -> Decommissioned` record transition and append-only authenticated terminal capsule bind the exact predecessor and coordinates and are never deleted or reused. |
| Secret or subscriber disclosure | Encrypt ledger material; redact every public surface; evidence is identity-free and uses only closed classifications/counts. |
| Capacity or operation DoS | Pre-effect finite capacities, bounded canonicalization/readback/retries/tasks, and fail-closed exhaustion. Products own admission quotas. |
| Malicious selected adapter | The selected adapter is in the TCB. Product selection, implementation review, deployment control, and §14.11 qualification evidence are required; SDK types cannot cryptographically prove that malicious in-process adapter code performed a real effect. |

The backend-related mitigations in this table assume the selected adapter honors
its contract. The public capability surface prevents an ordinary caller or a
non-selected mock from independently cross-binding or replaying a receipt, but
it does not provide remote or in-process cryptographic attestation of the
adapter's real kernel/backend action. In particular, an exact stamp or
structurally valid readback reported by a malicious selected adapter is not
independently verifiable under this RFC.

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
specified mechanism test ran and may qualify a trusted adapter profile; it does
not cryptographically attest a production adapter effect, prove traffic
forwarding, or prove product readiness.

## 14. Conformance and Acceptance Criteria

Implementation is accepted only when all of the following have passing,
evidence-linked tests. Tests must begin as RED tests where stated; a test that
passes before the implementing surface exists is not evidence of this RFC.

1. A compile-fail public-API test is initially RED because callers can name or
   construct `Fresh`; after implementation they cannot construct, clone,
   serialize, or substitute an admission, effect, removal, retired, or
   quiescence/reuse capability, terminal-fence create request, or terminal-
   fence receipt.
2. Deterministic tests prove atomic fresh complete-set claim, exact full-set
   retired reissue, and rejection of duplicate, partial, mixed, same-group
   changed, stale-generation, replayed, cross-device, cross-pin, and
   cross-group requests before backend mutation. A newly shaped set and new
   group containing exactly one atom from any retired or active predecessor is
   rejected by the permanent atom ledger even though both whole-set/group
   commitments are unseen.
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
   only exact whole-set retired reissue is admitted after `Retired` and a
   trusted backend quiescence receipt. Immediate reissue, caller-constructed
   drain/grace evidence, missing or foreign terminal-retired stamps, and mock
   quiescence all fail closed. The built-in eBPF backend reports reissue
   `Unsupported` until a separately qualified real quiescence mechanism exists.
7. Restart, process-death, caller cancellation, and supervisor-bound tests
   exercise every `Installing` and `Retiring` recovery outcome, including each
   side of the `backend_started` CAS, pending-stamp write/readback, journal
   write, first mutation, terminal-stamp write/readback, and final phase CAS.
   Dropping the public future at every boundary proves the SDK supervisor and
   lease renewal continue to one settled outcome; no caller timeout poisons a
   still-live worker, and no leaked worker/capability can issue a later effect.
   Exhausted supervisor capacity rejects before a phase CAS. Response loss and
   process death after each final phase CAS prove the exact capability is safely
   re-minted or joined without duplicate authority.
8. A privileged, isolated real-eBPF qualification creates the canonical marker
   and operation stamps, exercises no-follow/no-replace/exact-enumeration/
   digest/directory-sync, `BPF_FS_MAGIC`, and host-global flock semantics;
   proves different control roots with the same leaf differ while bind aliases
   to one opened inode converge; mutates the real graph; restarts; replaces or
   remounts the pin root; loses maps/programs; and proves the stable lookup still
   finds old history while a stale pin attestation, stamp, or conflicting
   ledger/control binding fails before traffic/map mutation.
9. Mutation tests independently make RED: admission/effect/removal/retired/
   quiescence/terminal-fence capability opacity removal, their namespace-
   binding validation removal, backend quiescence/terminal-receipt validation
   removal, per-atom historical freshness removal, and independent tombstone
   and generation validation removal. A combined happy-path mutation is
   insufficient evidence for these independent guards.
10. Redaction tests inspect `Debug`, logs, metrics, status, errors, and RFC 006
    evidence and prove they contain only bounded classifications/counts, with
    no selector, subscriber, ledger, commitment, nonce, secret, or key data.
11. The built-in eBPF profile exercises real mutation and exact full readback,
    lost/wrong/duplicate acknowledgement, restart, backend replacement, stale
    durable selector-backend epoch, cross-namespace rejection, independently
    durable terminal-fence absence inspection, exact capsule creation/readback,
    idempotent join, conflicting capsule, protected-store rollback, and mutable-
    graph cleanup through the opaque operations. Public-API tests prove an
    ordinary caller cannot construct, clone, replay, or cross-bind requests,
    coordinates, evidence, or receipts without becoming the selected backend.
    Test-only authority values never enter production constructors. A product
    which passes a fake backend has selected it into the TCB; runtime detection
    of that compromise is not an acceptance claim.

    Before any third-party production profile is advertised, a separate SDK
    change MUST publish the bounded generic stamp/capsule codec and real-backend
    harness missing from the current public port. That harness must run this
    same matrix through the unsealed trait without a raw authority constructor,
    and mutation tests must prove stale, wrong, duplicate, and cross-namespace
    stamp/readback coordinates fail. Qualification is evidence for deliberately
    selecting the adapter into the TCB, not runtime cryptographic attestation.
    Until that change lands, all external profiles remain unsupported.
12. Upgrade tests prove live legacy maps are never silently adopted, ordinary
    startup rejects an absent reserved record, only an exact pre-provisioned
    record may initialize, and cleanup-only migration is explicit. Decommission
    fault injection covers every ledger/authority-marker/decommission-fence/
    stamp/readback/graph-removal boundary, including rollback to the exact prior
    `Bound` record after the terminal fence appears. They prove the
    authenticated capsule reconstructs only its exact predecessor and exact
    precommitted phase/terminal generations and nonces; older/different `Bound`,
    capsule ciphertext/tag/nonce/AAD/predecessor/coordinate mutation, and an
    invented coordinate all remain offline. `Decommissioned` plus all history
    remain permanent. Removing the database, maps, stamp map, and markers after
    decommission still cannot make ordinary startup provision or initialize
    the tuple. Instrumented lock tests prove the exact lease/flock sequence and
    make any store CAS/readback or lease renewal while the host lock is held go
    RED; response loss at every release/reacquire boundary requires complete
    revalidation before the next effect.
13. Fix-removal tests independently remove operation-stamp validation, phase
    generation advancement, protected-store admission, canonical storage-key
    derivation, supervisor ownership, generic terminal-fence validation, and
    the durable-lease-then-host-lock order; each mutation goes RED without
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
    every matching ledger CAS, including the exact pre-effect inventory on
    either side of `backend_started`. Independent ledger-only and stamp-map-only
    rollback, full-capacity inventory, and a clone racing the original under the
    real backend ownership gate all fail closed. No semantic readback or mock
    receipt settles a mismatch.
17. Storage-codec golden vectors cover every byte of
    `ProtectedPayloadScopeCodecV1`, its commitment,
    `StorageKeySeedCodecV1`, the reserved stable ID, `StorageScopeCodecV1`, its
    commitment, `PinNamespaceCodecV1`, the selector-secret commitment, the
    exact 145-byte binding, predecessor-bound codec/commitment, the 110-byte
    decommission capsule, authority-marker digest, and complete 239-byte
    terminal-marker name. One-field mutations cover
    tenant, NF kind, key type,
    stable ID, raw protected-backend scope before sealing, protected-payload-
    scope commitment, device, pin, ledger ID, selector-secret commitment,
    storage-scope commitment, and backend epoch. Local and remote wrappers
    produce identical SDK base/scope/binding bytes; cross-store and cross-
    tenant aliases, external-backend substitution, a synthetic base, unknown
    versions, and migration without an explicit codec version are rejected.
    Pin-attestation mutations leave the reserved lookup key unchanged but make
    protected-record/backend binding validation fail closed.

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

### 15.7 Runtime Attestation from an Unsealed Trait

Rejected because a verifier lease, receipt codec, opaque stamp, or structural
readback exposed to the selected `GtpuDataplaneBackend` implementation cannot
cryptographically establish that its in-process code performed a real kernel
effect. Moving the same inputs behind another public verifier only relocates
the forgery point. A real attestation design would require a separate concrete
trust root and credential lifecycle, including provisioning, rotation,
revocation, incarnation/request/stamp binding, and replay handling. This RFC
instead makes the selected adapter part of the TCB and treats third-party
conformance as qualification evidence.

## 16. Rollout and Versioning

The public capability and durable record use explicit `v1` domain separators
and schema revisions. A decoder must reject an unknown revision, noncanonical
encoding, unknown state, unknown capability binding, or unknown control-marker
format before map mutation. Compatible extension requires a new bounded
versioned representation and a migration that preserves all tombstones;
in-place reinterpretation is prohibited.

The new capability ports are additive and existing backends report unsupported.
Implementing the public trait or passing structural/mock tests does not change
that default. The built-in eBPF adapter is the initial selected profile and
retains its requirement for real mutation, exact stamp validation, and exact
readback. External production profiles remain unsupported until the generic
codec and conformance boundary in §9 and §14.11 is implemented. If a product
nonetheless passes another implementation to the public lifecycle, it has
accepted that implementation into its TCB; the SDK does not reinterpret that
choice as conformance. No compatibility path treats an arbitrary external
adapter, test harness, or request coordinate as a runtime cryptographic trust
root.

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
