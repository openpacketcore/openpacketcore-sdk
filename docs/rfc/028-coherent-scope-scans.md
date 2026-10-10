# Coherent scope restore, index and claim scans

Status: implemented; combined profile qualification and release remain required.
This contract uses the untimed authority in [RFC 022](022-scope-leases.md).

## Contract and API

Independent point reads can combine children, application indexes and claims
from different commits. A scope scan instead retains one committed snapshot
across bounded pages. Retaining the snapshot lets a large scan progress while
ordinary writes continue, without copying the entire namespace at open time.

`scope_scan::ScopeScanStore` sits beside `ScopeBatchStore`, bound to the existing
name-derived store identity and explicit `ScopeNamespace { scope, incarnation }`.
It requires strictly durable consensus. Its operations are:

| Operation | Result and admission |
| --- | --- |
| `open_restore(&CommittedScopeAuthority)` | An opaque restore view, only for the exact current successor admitted by `SucceedClosed` in this namespace. |
| `page(view, cursor)` | A bounded ordered page of values and per-item failures, its cut, and either a continuation or explicit `Complete`. |
| `lookup(view, record_key)` | One child or claim at the identical cut, including explicit absence. |
| `view.close()` | Idempotently revoke and drain local retention; dropping the last local handle also revokes it. |

Open returns a `ScopeCut`, the authority view and the stable-scope batch
checkpoint. The cut binds the namespace (including store identity), authority revision,
stable batch revision, complete applied log position, backend capture epoch,
serving node and a process-local capture ID. Authority and
batch revisions remain distinct. Maximum page budgets and ordering are fixed
at open; a retry can reduce its effective row limit.
Every page and lookup carries the same cut; mixing cuts is an error.
`open_observe` is deferred until a named consumer needs it.

Enumerate every child, then every claim. Within each kind, canonical keys
come first in byte order, followed by bounded malformed-key phases described
below. Positions are opaque item identities within a kind and cut. Include child tombstones and released claims with their retained
birth/generation/revision metadata. Application indexes already represented as
sealed children participate in the same stream and lookup API; the SDK does
not invent an index payload schema or decrypt application data. Callers use
same-cut lookups to validate index targets and other application references.

Child lookup distinguishes `Present`, `Tombstone` and `MissingAtCut`; claim
lookup distinguishes `Owned`, `Released` and `MissingAtCut`. Absence is a fact
about this snapshot, not evidence that an earlier command never applied.
All item results carry a final verdict. Missing and corrupt results at this
post-admission cut are final, including classification lookups; retry never
changes their verdict within the view.
Predecessor uncertainty uses RFC 027's exact outcome lookup under the
successor's authorization, never resubmission with the predecessor's stamp.

## Snapshot and restore invariants

1. **One committed cut.** Open performs the current-configuration, full quorum
   read barrier with time-based read leases disabled, then atomically captures
   the applied state at or beyond that barrier. Read the authority, checkpoint,
   children and claims through that capture. A backend that cannot retain the
   cut must refuse open, rather than join independent point reads.
2. **Current admission.** Every operation checks authenticated scope access and
   locally applied configuration, authority stamp and retired-through floor.
   Only open performs a full quorum barrier; page checks are local and may lag
   retirement. They do not provide the safety fence: RFC 022's current-state
   checks at apply and the local effect gates remain mandatory.
   The initial capture must itself contain that exact successor. Ordinary
   batch commits do not invalidate a retained view. Configuration or backend
   replacement that invalidates capture admission requires a fresh view.
3. **Positive handover.** Restore eligibility comes from RFC 022's committed
   `SucceedClosed` operation and trusted predecessor-closure evidence. The scan
   API adds no independently constructible handover assertion. A controller receives
   no successor capability: the successor authenticates its boot and obtains
   its capability through the exact authority-request retry. `AdmitInitial`
   starts empty and cannot authorize restoration of historical rows. A lost
   or retired incarnation is never restored into a selected replacement.
   Closure excludes installed forwarding, which may survive process restart.
4. **Observation is not authority.** Validate each item's application envelope
   and references before restoring that item. One failed item does not block
   healthy items. Neither a page nor a complete scan authorizes a write or
   effect. Mutations compare current authority and RFC 027 read-set predicates
   at apply; effects use their current local
   gate checks. Selective predicates retain namespace, birth/generation and
   exact claim revision/owner, including a retained released row. Missing-key,
   range and scope-wide predicates compare the stable batch revision; an
   unversioned absence is not a selective predicate. A coherent old value is
   not a current-state precondition.
5. **No implicit empty recovery.** Initial admission atomically persists an
   explicit empty stable-scope checkpoint. Its logical batch revision, birth,
   counter and lane floors start at zero under the new encoding. Thereafter
   a missing required authority/checkpoint row is an explicit failure, never
   a synthesized empty value. Empty completion requires both namespace ranges
   to be exhausted in a valid captured state. Selection, reclamation and scan
   lifecycle never reset the checkpoint's revision, 16 counters, birth floor
   or retained lane sequence floors.

The stream validates reserved row kind, key/body agreement, namespace, bounds
and revisions. Claims and child claim lists must agree at the same cut,
including the owner's birth and live state. A bad row yields final
`Corrupt { kind, key_if_readable, position, reason }`; a missing reference yields
final `Missing { reference, position }`. Keep scanning. Cross-checks count
against page work, and failures have stable identities for retry deduplication.
A legacy-encoded child or claim body is a final `CorruptEncoding` item. Only
missing/corrupt scope authority, batch checkpoint or namespace header terminates
the entire inventory. Inability to establish the committed cut is
an operation failure, never a successful empty inventory.

A corrupt claim body or unverifiable owner means **held by an unknown holder**,
never released or reallocated. A child with an unverifiable claim list keeps
its claims held. An unreadable claim key yields final
`InventoryIncomplete { kind }`; callers stop new allocations of that kind while
continuing restoration of existing sessions. The scan performs no repair,
claim release or deletion. These restrictions survive a retry or view restart
until independently justified repair/reclamation resolves them.

`Complete` carries the full ordered list of item failures and any incomplete
inventory kinds. The list is paged, with a descriptor in the terminal result,
so a badly damaged namespace cannot create an unbounded final response. Every
failure is also delivered in the inventory stream; none is silently skipped.
Application payload authentication, schema and references remain the caller's
responsibility. Completion describes the SDK inventory, not success of every
item or completeness of an application's object graph.

## Bounded paging and restart

Use keyset continuation, never offset scans or whole-scope materialization.
Reuse the existing restore budgets: default 256 and maximum 1,024 returned
rows, at most 4 MiB + 64 KiB stored payload and 8 MiB retained page bytes,
4,096 examined row/lookup visits and 8 MiB examined metadata per operation.
Bound decoder allocation and work before reading payloads. SQLite's VM/work
budget and cancellation hook also apply. Every maximum-size legal child must
fit one page, including envelope overhead; the authenticated transport applies
its frame-safe budget before encoding. Bounds limit work per operation, never
the number of stored children, sessions or pages.

An opaque, authenticated confidential cursor binds its version, view ID,
backend epoch, namespace, cut, caller/purpose, page limits, attempt number and
last examined kind/key. It grants no authority. Page requests are sequenced:
one attempt may execute per view, and its reply is retained until the client
uses the successor cursor. Repeating that outstanding attempt returns its
identical reply and continuation, including a no-progress reply's reduced-limit
cursor. Using the successor cursor acknowledges the preceding reply and releases
it; an acknowledged older cursor returns final `InvalidCursor`. The terminal
reply remains replayable until close or view invalidation. This keeps one bounded
reply per view even when time budgets produce variable partial-page boundaries.
The SDK client sends no successor request until it accepts the prior reply.
A successful nonterminal page advances a checked position. A reported final item failure counts as
examined progress. On the 1 s SQLite work budget, return all fully examined
items and an advancing continuation if any completed; no partially validated
item is emitted. With no progress, return retryable `WorkBudgetExceeded` and
halve the next attempt's page limit, down to one. The effective smaller limit
remains bound into that attempt's cursor. Clients deduplicate retries by cut
and position; a lost reply is safe to retry.

Native storage retains an immutable index of reserved scope records, sharing
row owners with the applied state. It does not retain ordinary session records,
watch history or the complete business state. Each view reserves 64 KiB for
its context and two bounded 8 MiB pages for reply and classification work.
Sharing the immutable storage root does not multiply the store's row count
into each view's admission cost. A retained root can keep older shared index
nodes and rows alive; the reservation is a page-working-memory budget, not a
bound on total storage reachability or process RSS. With at most `V` admitted
views, retained native index memory is at most `V * S_max`, where `S_max` is
the largest full scope-index footprint among the captured cuts, including its
index nodes and reserved row owners. Page/context working memory adds at most
`V * (64 KiB + 2 * 8 MiB)`. The current live index is additional; sharing nodes
or rows between cuts can reduce actual retention. For the default four views,
budget for up to four historical scope indexes plus 64.25 MiB of page/context
memory and the current live index. Size historical indexes for churn: the
512 MiB reservation does not bound these retained versions, allocator caches
or process RSS. Each operation takes a short checked native permit. SQLite uses a dedicated read-only connection
and read transaction whose first read fixes the cut. Neither backend holds the
apply mutex or an installation-blocking permit between pages. Defaults per
serving node are four admitted views, four dedicated SQLite readers, 512 MiB
of native capture reservation and a 1 GiB retained-WAL admission high-water
mark. These limits are configurable; waiters queue fairly across scopes and
are cancellable. A view whose fixed reservation exceeds the configured native
budget receives final `CapacityRefused`, never a retryable restart. Otherwise,
capacity pressure admits no additional views until active views drain. The WAL mark controls
new scan admission, not writer truncation: existing readers may temporarily
retain more WAL, which is measured explicitly. Expose active/waiting views,
reserved native page/context bytes, retained WAL bytes and oldest idle age.

An admitted view is retained while the client requests pages within the
default 30 s idle bound; time queued or executing an accepted operation is
activity. Resource pressure never evicts an actively paging view. Idle expiry
and cancellation release it. A queued open keeps its admission ticket until the
caller's restore deadline or cancellation; waiting never consumes the lifetime
recovery budget. SQLite WAL measurements for admission and current-authority
checks wait fairly for writer ownership under the same caller deadline. WAL
measurement uses the actual linked writer descriptor, and a pending measurement
does not delay idle-view cleanup. Page work starts after the authority wait. Restore
pressure uses backpressure, never an attach ceiling or session eviction.

| Operation | Scheduling class and source |
| --- | --- |
| Open and bulk restore paging/lookup | Normal; authenticated worker for its own scope. |
| Unknown-traffic classification lookup | Emergency classification sub-budget; authenticated own-scope worker, with final missing/corrupt verdicts leaving that budget. |
| Future observation, currently deferred | Maintenance. |

Pages yield to RFC 024 scheduling so SafetyControl and established Emergency
retain their independent budgets. No class is part of cursor ownership or
the immutable batch request digest.

Idle expiry, server restart or snapshot installation can revoke a view.
Installation first invalidates the view epoch,
cancels/drains bounded page work and releases pinned resources; it never waits
for a client to send another page. No view survives by silently switching to
the latest state. Clock values may schedule local resource cleanup only;
arbitrary clock jumps affect availability, never ownership or floors.

The SDK restore client owns reopening and page-size reduction. It stays on the
view's serving node, preferring the leader when opening where routing permits,
and discards staging associated with the invalidated cut before reopening.
Already performed effects remain governed by their own reconciliation rules.
Back off from 25 ms, doubling to at most 1 s, between failed attempts. The
default bound is `K = 16` recovery attempts over the entire restore, with
separate counters per cause; successful partial pages do not consume attempts.
No-progress retries at one row, repeated open unavailability and view restarts
all consume that bound. At the bound return final
`RestoreStalled { cause, attempts }` to caller policy, never an infinite loop.
Callers may choose another recovery action; the SDK does not silently begin a
new restore to reset the attempt count.

| Result | Required handling |
| --- | --- |
| Final item: `MissingAtCut`, `Missing`, `Corrupt`, `InventoryIncomplete` | Report once per item/cut and continue; keep affected claims held and allocations restricted. |
| Final scope fault: missing/corrupt authority, checkpoint or namespace header | Stop this restore; no empty fallback. |
| Retryable: `RestartRequired`, `Unavailable`, no-progress work-budget exhaustion | SDK client backs off and retries within K, reopening only when necessary. |
| Final: `RestoreStalled` | Return cause and attempt counts to caller policy. |
| Final: `StaleAuthority`, `Retired`, `Unauthorized` | Refuse restore; retry cannot substitute for a new authorized handover. |
| Final: `InvalidCursor`, `FreshInstallationRequired`, cancellation | Reject the request or finish cancellation explicitly; no automatic retry. |

Idle expiry never closes an execution, selects an incarnation, clears
rows, releases claims or drops forwarding. Reopen needs no operator or node
action. Failed items remain visible without preventing healthy sessions from
restoring; this API does not manufacture recoverable state.

## Stored format and integration

The authority (RFC 022), batch (RFC 027) and scan contracts share one
fresh-install stored profile, **4**, with one final digest for their combined
implementation. Advertise that
profile only after all three implementations are integrated and their joint
checks pass. No slice advertises an intermediate stored profile independently.
The combined profile digest includes the `coherent-restore-scan-1` contract tag.
The authority-request codec's version is a separate contract.

Children and claims use the shared 64-byte stable-ID encoding:

```text
stable_id = SHA-256("openpacketcore/scope-namespace/key/v4\0" || postcard(ScopeNamespace))[32]
            || logical_key[32]
```

The domain ends with a literal NUL byte. The complete namespace, including its
incarnation, is committed by the first 32 bytes; the logical child/claim key
occupies the final 32 bytes. Tenant, network-function kind and reserved row kind
remain separate key fields. Each exact namespace is one contiguous keyset range
within its kind. Scans use `scope_storage::namespace_prefix` for range bounds and
`scope_storage::namespace_key` (or its typed child/claim wrappers) for full-key
validation. No scan or lane implementation derives a second encoding.

The accepted trade-off is that a key-prefix scan cannot span all incarnations
of one stable slot. A successor obtains its predecessor's incarnation from the
stable-scope authority ledger and scans that exact namespace. Initial admission's
broader body-decoding scan remains the orphan fallback. The batch checkpoint
remains stable-scope keyed. Define the explicit initialized-zero checkpoint encoding
and its atomic initial-admission write in that shared profile. Unknown, timed
or prior incompatible formats require a fresh installation: no migration,
compatibility reader or inferred defaults. If the authority profile has already
shipped, adding an incompatible encoding requires a new profile version.

Views and cursor keys are process-local, non-authoritative retention state;
they are neither consensus rows nor serialized capabilities. Persist no scan
lease or expiry timestamp. Snapshot export/install and replay preserve the
authority, retirement, counter, birth and lane floors independently of views.
Use the existing ordered reserved-key ranges and backend integrity checks;
there is no secondary durable application-index catalog to reconcile.

SQLite keeps two derived physical indexes for canonical and malformed scan
keys. Their names, row-kind predicates, key widths and malformed-prefix
expression have one shared DDL definition. Recovery accepts either the exact
pair or a predecessor image without these indexes; read-only inspection never
adds or repairs them. A partial pair or changed definition is refused. Snapshot
and recovery schema budgets grant exactly two additional objects only after
validating the pair, while all existing authority-profile limits stay fixed.
These derived indexes do not redefine a frozen predecessor's authority schema.

The dedicated scope scan facade is necessary: ordinary session restore filters
reserved scope rows. Its cursor's latest-revision checks and timed row filtering
cannot supply this retained scope view. The authenticated scope transport
carries the new bounded results and derives roles from verified channel facts.
The public scan types never expose raw backend handles or cursor secrets.

## Malformed physical keys and consumer staging

A malformed reserved key is a final item, including keys too short to contain
its namespace prefix. Native storage uses disjoint persistent indexes for
canonical 64-byte keys, known-prefix 32..63-byte keys, and unattributable
1..64-byte keys. SQLite uses non-authoritative partial indexes for canonical
BLOB keys and malformed reserved keys. The latter indexes at most a 32-byte
prefix and advances by the exact signed rowid within its retained transaction;
it never copies or truncates a large corrupt key into a substitute identity.

The native index compares the physical prefix with the namespace in a bounded
current-format child/claim header. A mismatch is an unattributable corrupt key;
the body never grants authority or repairs the physical key. Native index
maintenance decodes at most 4 KiB of header, without materializing a child value.
SQLite's persistent indexes use only SQLite built-ins and key bytes, so earlier
SDK builds and plain SQLite can write, check integrity and vacuum the store
without registering application-defined functions. Indexed paging does not
rescan the store or decode payloads to find the next key.

Known-prefix corruption belongs to that namespace. Native mismatches, and short,
empty or non-BLOB SQLite keys, are conservatively visible in each scan of the same
tenant, network-function kind and reserved row kind. An enumerated malformed
claim key is held by an unknown holder and makes claim inventory incomplete.
These indexes contain no second authority or application-index catalog; the
existing reserved rows remain authoritative.

SQLite cannot attribute a BLOB key with at least 32 bytes whose namespace prefix
is damaged, including a 32..64-byte key with an intact body. The original
namespace's bounded key scan does not find that row and cannot report its
corruption. There is no independent manifest or whole-store payload scan to
recover its namespace. Native attribution likewise cannot establish the original
namespace if both physical prefix and body header are damaged. Neither backend
claims original-namespace completeness against damage to the physical tenant,
network-function kind or reserved row kind.

`ScopeScanClient<T>` drives one restore through `ScopeScanTransport` and a
caller-provided `ScopeScanSink`. Both `restore(sink, deadline)` and its
`restore_until` alias require one caller-owned deadline for admission, paging,
staging and recovery. Expiry returns `DeadlineElapsed`, discards partial staging
and cancels outstanding work without consuming a retry. Neither path periodically
cancels and requeues a healthy admission wait. `begin` creates staging for one cut, `stage`
accepts a page before its continuation is acknowledged, and `finish` commits
staging only after the matching `Complete`. Cancellation, a failed sink, or a
lost cut synchronously invokes `discard`. The sink must preserve held-claim and
allocation restrictions separately: discarding staging cannot clear them.

Local callers use `ScopeScanLocalTransport`. Authenticated callers obtain
`ScopeScanPort` from `ScopeClient::scans`, retaining both the committed successor
and its original `PendingScopeAuthority`. A remote open sends the exact
`SucceedClosed` request as an observation claim. The server verifies its request
ID and digest against the captured committed authority; decoding a stamp or
request never mints a mutation/effect capability. The port stays on its configured
serving endpoint across retries. On Linux, scope TCP sockets enable keepalive
with a 2 s idle period, 2 s probe interval, four probes and a 10 s TCP user timeout.
A silently lost peer fails in approximately 10 s and permits transport recovery;
a live peer's kernel answers during arbitrarily long admission or writer waits,
so those waits keep their place and consume no retry. This is TCP liveness, not
an application-progress deadline; the required restore deadline also bounds an
unresponsive process with a live TCP stack. The process gate is held only while
polling each read-only exchange step and released before every wait. Quiescence
wakes and cancels pending observations without waiting for network progress.
Dropping a remote view leaves bounded idle
retention; explicit close drains accepted work.

## Authenticated wire format

All integers below are unsigned big-endian unless explicitly stated. `LP16(x)`
and `LP32(x)` prefix the exact byte length with a 16- or 32-bit integer. Boolean
fields are exactly `0` or `1`; unknown tags, noncanonical nested values and
trailing bytes are refused. Scope, stamp, authority-view and succession encodings
reuse RFC 026's shared authority codecs. Child/claim bodies reuse the stored
profile's canonical `ScopeRow` bytes, including its profile header.

RFC 026 method tags 12..16 are `ScanOpen`, `ScanPage`, `ScanLookup`,
`ScanClassify` and `ScanClose`. Each requires the current worker's own boot,
namespace and complete stamp. Open/page/lookup/close use Normal; classify uses
EmergencyClassification. These methods cannot arrive on other class listeners.
The request digest is SHA-256 over
`"openpacketcore/scope/scan/v1\0" || method:u8 || request_id[16] || canonical_request`.
The result status is `ScanObservation`, with a zero own-execution field: every
successful result is an observation, never an authority grant. The existing
frame response binding covers the request ID, digest, method and class.

The request body is bounded by 8,226 bytes; the response body by 2,096,640 bytes.
The ordinary authority command bound is unchanged. Transport page limits reserve
16 KiB plus 512 bytes per item for cut, failures and framing before opening;
the remaining payload budget must still hold a maximum legal child. This limit
is fixed before building the cached reply, so reply loss cannot change its page
boundary.

```text
request = 1:u8 || request_tag:u8 || request_body
request_tag 1: open = 1:u8 || LP16(stamp) || LP16(succession) || rows:u32 || payload_bytes:u32
request_tag 2: token || LP16(cursor)
request_tag 3: token || lookup_key
request_tag 4: token || lookup_key
request_tag 5: token

token = LP16(stamp) || serving_node:u64 || capture_id[16]
lookup_key = kind:u8 || logical_key[32]       # kind 0 Child, 1 Claim

cut = LP16(scope_id) || incarnation:u64 || authority_revision:u64 || batch_revision:u64
      || LP16(applied_log_id) || backend_epoch:u64 || capture_id[16] || serving_node:u64
```

`applied_log_id` is the canonical Postcard encoding of the complete SDK `LogId`,
bounded by 32 bytes. The pinned single-term-leader engine encodes its term and
index; it has no independent leader-node field. The serving node is separate.
Cursor bytes are opaque, at most 256 bytes, authenticated and encrypted with a
per-view key. They bind all cut and request-purpose fields and are invalid on
another capture or after their acknowledgement.

```text
response = 1:u8 || response_tag:u8 || response_body
response_tag 1: cut || LP16(authority_view) || checkpoint || LP16(initial_cursor)
response_tag 2: cut || page_body
response_tag 3: cut || item
response_tag 4: empty
response_tag 5: failure_class:u8 || failure_tag:u8
checkpoint = revision:u64 || birth_floor:u64 || counters[16]:u64
page_body 0: count:u16 || item[count] || LP16(next_cursor)
page_body 1: LP16(next_cursor)               # no-progress work budget
page_body 2: items:u64 || failed_items:u64 || failures:u64 || claims_incomplete:bool
             || has_manifest:bool || [LP16(manifest_cursor)]
item = kind:u8 || locator_tag:u8 || position_length:u8 || position[position_length]
       || disposition || inventory_incomplete:bool || failure_count:u8
       || item_failure[failure_count] || body_tag:u8 || [LP32(stored_row)]
```

There are at most 1,024 items, eight distinct failures per item, and 8 MiB of
accounted retained page allocation. Bounds are checked before allocating nested
rows. `body_tag` is 0 for none, 1 for Child and 2 for Claim. A body must agree with
the position, kind and namespace. Noncanonical locators carry only the final
unknown-key corruption verdict, without a body.

| Locator tag | Position |
| --- | --- |
| 0 | Canonical 64-byte namespace/key. |
| 1 | Native known-prefix malformed key, 32..63 bytes. |
| 2 | Native unattributable malformed key, 1..64 bytes. |
| 3 | SQLite known-prefix malformed rowid, 8 bytes. |
| 4 | SQLite unattributable malformed rowid, 8 bytes. |

SQLite rowids encode `(rowid as u64) XOR 0x8000000000000000` in big-endian order,
so byte order covers the full signed rowid range exactly. Ordering is kind,
locator tag, then position bytes. A backend uses only its own malformed tags.
Canonical and native known-prefix positions must match the cut's namespace
prefix. These locators are process-local observations, not durable logical keys.

Disposition tags are 0 LiveChild, 1 ChildTombstone, 2 UnrestorableChild,
3 ClaimHeld (followed by owner-child[32] and birth:u64), 4 ClaimHeldUnknown,
5 ClaimReleased and 6 MissingAtCut. An item failure is either
`0 || kind || logical_key[32]` for Missing, or
`1 || kind || has_key:bool || [logical_key[32]] || reason:u8` for Corrupt.
Reasons are 0 Encoding, 1 Key, 2 Header and 3 Ownership. Unknown-key claim
corruption requires incomplete inventory and cannot decode as Released.

Failure class 0 is final, with tags 1 Unauthorized, 2 HandoverRequired,
3 StaleAuthority, 4 Retired, 5 Unavailable, 6 RestartRequired, 7 InvalidPageLimits,
8 InvalidCursor, 9 Authority header fault, 10 Checkpoint header fault,
11 Namespace header fault, 12 FreshInstallationRequired and
13 DurableConsensusRequired, 14 CapacityRefused. The server classifies operational recovery as class
1: tags 0 Unavailable, 1 IdleExpired, 2 BackendRestarted, 3 SnapshotInstalled,
4 ConfigurationChanged, 5 WorkBudgetExceeded, 6 AdmissionPressure and 7 ViewEnded.
The driver consumes only class 1 and no-progress page results as retries.

## Verification plan

Write deterministic failing tests before implementation, shared across native
and SQLite, then mutation-check each safety guard:

- Interleave create/update/delete, index-child updates, claim transfer and
  counter increments between every page and lookup. The old view stays exact;
  a new view sees the whole committed change, with no mixed transaction.
- Exercise maximum-size records, byte/work boundaries, sparse ranges,
  tombstones, released claims, duplicate/lost replies and cancellation. Assert
  bounded allocation, advancing continuation and exact completion.
- Put one corrupt child among healthy children, introduce a dangling claim and
  unreadable claim key, and corrupt an application envelope. Healthy items
  restore; every bad item is reported once and final. Unknown claims stay held;
  incomplete inventory blocks only new allocations of the affected kind.
  Missing/corrupt scope headers alone stop the entire inventory.
- Forge/replay cursors across namespace, boot, role, backend and limits; change
  authority or retire between pages. Refuse stale data as restoration authority.
  Test worker-only succession and exact successor retry, positive closed handover, initial
  empty admission and lost-incarnation refusal with forwarding still installed.
- Exercise continuous writes with periodic snapshot installs, a slow-disk
  fixture exceeding the 1 s page budget, and more concurrent restores than the
  view cap. Active views cannot be evicted; partial pages advance and no-progress
  attempts shrink to one row. Every restore completes or returns `RestoreStalled`
  within K; backoff, sticky serving node, idle expiry and cancellation are tested.
- Force clock jumps, restart, compaction and configuration change. Reopen only
  under current authorization; never merge cuts or reset any floor. Prove that
  page calls perform no additional quorum barrier and current apply still fences.
- Saturate scans and cancel queued/in-flight work; prove bounded retained
  resources and continued SafetyControl/Emergency service. Mutations that remove
  cut binding, current admission, final item reporting, conservative claims,
  progress/retry limits or floor protection must fail their corresponding tests.
  Silently skipping a bad row or stopping healthy restoration must also fail.

Final implementation gates include focused tests in both backends, existing
authority/batch/continuation and snapshot regressions, authenticated transport
bounds, formatting, Clippy and documentation checks for the touched crates.
