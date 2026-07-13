# OpenPacketCore High Availability and Consensus Design

This document details the High Availability (HA) architecture and
implementation for the OpenPacketCore config and session persistence surfaces.

- **Config Store**: #177 migrates `ConsensusConfigStore` to the workspace's
  exact-pinned Openraft engine and removes the custom Raft, majority wrapper,
  and private TCP/mTLS authority paths.
- **Session Store**: `ConsensusSessionStore` (and its `QuorumSessionStore` type
  alias) uses the same Openraft engine as the sole election, log, commit,
  membership, and linearizable-read authority.
- **Shared boundary**: both domain adapters use `opc-consensus` engine and
  transport ports. Production mTLS and credential lifecycle are composed by
  `opc-session-net`; domain storage crates do not implement a second network
  authority.

#127 and #177 close the one-engine implementation transition, not production
qualification. Config release evidence remains `GAP-001-006`; session
current-format repair is hardened under #128 and #133 supplies bounded restore
from Openraft-applied state. #129 supplies bounded default-deny legacy recovery
with a full-fleet quarantine and an Openraft-committed recovery epoch.
Production network qualification (#143), the credential-rotation chain, and
config release evidence retain their own gates. Historical closure language
below refers only to scoped algorithms and test harnesses; neither component is
yet approved as a production deployment profile.

---

## 1. Openraft Config Store: `ConsensusConfigStore`

`ConsensusConfigStore` coordinates config commits, confirmations, and rollback
points through the shared Openraft engine and a deterministic SQLite state
machine. Openraft alone owns elections, votes/terms, log matching, quorum
commit, the persisted membership primitive, linearizable barriers, and
snapshot lineage. The config profile admits only the exact immutable voter set
within an epoch; a topology change requires a coordinated new epoch.

### Authority and protection boundary

```text
application -> HKMS-backed encryption -> ConsensusConfigStore
            -> Openraft -> SQLite and Openraft snapshots
```

The application seals config before proposal and receives one-shot evidence
bound to the exact encrypted bytes and plaintext digest. The adapter consumes
that evidence, validates the canonical AEAD envelope and config AAD, masks
audit values, tokenizes sensitive predicate values, and finalizes their HMAC
chain.
Openraft persists and replicates sealed ciphertext, deterministic metadata,
and redacted finalized audit only. Plaintext, provider objects, key handles,
and raw key material never enter an Openraft command, RPC, log, outcome, or
snapshot. This is payload-envelope protection, not metadata/full-file
encryption.

The Openraft authority marker is created in the same immediate SQLite
transaction that checks or imports old authority. Once claimed, all public
standalone SQLite mutations fail closed, including through retained backend
clones. An explicit singleton or odd 3-through-9 topology is admitted; HA
readiness and reads use the same fresh linearizable barrier.

### Legacy admission and rollback

Nonempty legacy authority returns `RecoveryRequired` and is never interpreted
as Openraft metadata. Offline recovery requires one checkpointed applied
SQLite snapshot, its exact SHA-256 checksum, its exact latest transaction ID
and version, and the explicit `DiscardUnknownAppendedSuffix` decision. The
adapter verifies SQLite/table/audit/envelope integrity and the exact head before
atomically replacing one target database and claiming it for Openraft. The
unprovable target suffix is discarded, never merged.

Atomicity is per database, so the fleet must be drained and converted under one
coordinated authority decision. Rollback is possible only from untouched
pre-migration backups after stopping the full fleet. Removing
`config_raft_*` state or reconstructing the removed engine is prohibited. See
[ADR 0002](adr/0002-config-store-consensus-ha.md) and the
[operator runbook](consensus-operator-runbook.md).

### Shared transport and qualification

The config adapter exposes and consumes only the bounded `opc-consensus`
handler/peer ports. `opc-session-net` owns the production mTLS implementation
and the existing certificate/trust lifecycle; `opc-persist` has no private TCP
listener or rotation path. Trust overlap, fresh authentication, connection
drain, and rotation readiness retain the shared transport's existing
qualification gate.

In-process config tests cover pristine formation, sealed/redacted persistence,
direct-write fencing, partition/failover/heal, response-loss idempotency,
snapshots, and exact legacy recovery. An AMF-lite integration composes the real
config encryption wrapper, rotates provider-backed keys, exercises
followers/snapshots/restart, and scans durable artifacts for plaintext,
raw-key, and provider-endpoint canaries. Shared transport tests observe a
renewed SVID on a subsequent new call/full handshake and reject rotated
identities outside the bound peer scope. These qualify the three-node HKMS
boundary and scoped new-call SVID transport mechanism, not seamless connection
retirement or remote HKMS. The same suite forms a real three-node config
Openraft cluster and commits/linearizably reads over loopback mTLS. It does not
provide out-of-process/deployed-network integration, resource/soak, complete
trust-bundle/revocation/authentication-age fleet lifecycle, or candidate
release evidence. Those production claims remain `GAP-001-006`.


---

## 2. Openraft Session Store: `ConsensusSessionStore`

#127 replaces the custom majority-prefix coordinator with Openraft.
`ConsensusSessionStore` is the implementation and `QuorumSessionStore` is an
alias to it. Openraft alone elects leaders, persists votes, matches logs,
commits entries, owns membership and snapshot lineage, and supplies
linearizable read barriers. The SDK implements deterministic session commands,
SQLite storage traits, bounded authenticated RPC adapters, idempotent request
outcomes, a committed application journal, watch cursors, logical expiry time,
and encryption-envelope admission.

This is durable sequencing authority, but not yet a complete production
deployment claim. Current-format follower recovery is Openraft-owned and
hardened under #128. #129 supplies an offline, audited whole-fleet legacy-fork
campaign that quarantines every selected PVC and resumes from one immutable
operator-selected checkpoint without becoming a second runtime authority; see
the [recovery runbook](session-store-legacy-recovery.md). #133 provides bounded
applied-state restore with snapshot-bound cursors. Watch and expiry hardening
remain #145/#148, and network/resource/rotation qualification remains #143 and
the #161 -> #162 -> #163 -> #164 credential chain under umbrella #158. Stable
ID bounds are implemented under #167. #168 adds the bounded durable
transaction-ID type, canonical coordinator mint, exact legacy preservation,
SQLite/snapshot/recovery validation, and version-3 migration audit. Log-range
cursors remain #171.

### Configured topology admission

Operational construction consumes `ValidatedQuorumTopology`. HA admission
requires an odd set of 3 through 31 members, one exact local `ReplicaId`, and
unique logical IDs, canonical endpoints, expected TLS identities, failure
domains, backing-store identities, and derived stable node IDs. The topology is
descriptor-only: the node's one local SQLite backend and exact remote
consensus-peer map are supplied separately after admission. Admission also
requires a cluster ID, monotonic configuration epoch, and an
order-independent configuration digest that exactly matches the descriptors.
Stable Openraft node IDs are derived from cluster plus logical `ReplicaId`, fit
SQLite's positive signed-64-bit domain, and do not change when other members
are reordered, added, or removed. Openraft owns vote accounting and quorum.

Logical identity, endpoint, TLS identity, failure domain, and backing identity
are independent. A bare local ID can belong to a member with an FQDN endpoint;
no hostname shortening or endpoint-as-identity inference occurs. The explicit
consensus lab singleton uses the same engine but reports `single-replica`.

Production peers use the dedicated `opc-session-consensus/1` ALPN. Every RPC
binds the live SPIFFE identity, configured local and remote logical IDs, stable
node IDs, cluster/configuration/epoch, sender field, expected server profile,
and a fresh challenge before Openraft dispatch. This is authentication and
composition evidence, not physical-store provenance. A CNF must still map each
logical voter to exactly one durable backing volume.

### Structural identity and legacy persistence admission

`OwnerId` and each deployment-specific session-key type name now contain 1
through 128 UTF-8 encoded bytes. `SessionKeyType::Other` wraps a private
`CustomSessionKeyType`; the five reserved canonical strings map only to their
well-known variants. Known and custom values serialize, persist, hash, and sort
by the canonical string, not enum declaration order.

Serde, SQLite record/restore/active-lease/fenced-mutation/log hydration, and
session-net request/response decoding apply the same invariant. A bad owner or
key type—including one nested in a replication operation—fails closed before
mutation or caller exposure with a fixed or fieldless error that omits the raw
value. New handover envelopes use an exact `OPCH` magic/version header. The
bounded non-`OPCH` classifier accepts current-valid original syntax and some
bare payloads; ambiguous, truncated, oversized JSON-looking, unknown, or
typed-invalid claims fail before mutation. Successful syntax detection is not
provenance. The identity audit does not classify live or nested-log payloads, so
products must run the complete provenance-aware replay preflight in RFC 004
§5.2/§10.3.

Existing valid v4 values keep their JSON string shape, but source construction
and pattern matching change and admission is stricter. An older v3 member may
emit an invalid value v4 rejects, so this is not a rolling-compatibility claim.
The fixed-width DTO and handshake now bind the contract. Drain and stop every
client, server, and wrapper plus every product handover reader/writer, audit
identities and handover payloads, upgrade the complete fleet, and restart it
together. Once any live or replayable `OPCH` copy is written, rollback to an
older SDK requires a drained coherent fleet-wide checkpoint restore (with
post-checkpoint mutation handling) or reviewed reverse migration of every live,
log, snapshot, and restore copy; the v4 handshake does not make the format
backward-readable.

The offline command is:

```text
opc-session-store-audit identity-invariants \
  --database PATH \
  --max-rows N \
  --max-entry-json-bytes N \
  --max-total-json-bytes N
```

All budgets are required and non-zero, with the per-entry JSON limit no larger
than the total or SQLite's signed `i64` length range. The audit opens one drained SQLite snapshot read-only and
query-only, scans the four identity-bearing tables in fixed 256-row pages, and
emits version-1 count-only JSON. `compliant`/0 is the sole pass;
`violations_found`/1, `incomplete`/2, and redacted command/setup `error`/2 all
block upgrade. Reports contain version/status, limits, bounded scanned and
violation counts, and an optional bounded `incomplete_reason` only—never a
database path, row identity, owner, key type, session key,
payload, transaction, or raw JSON. Neither the audit nor runtime truncates,
renames, repairs, or rewrites an invalid value. Use a reviewed
semantic-preserving product migration or audited store replacement, then
re-audit before startup.

This is #135 boundary evidence, not production HA. #127 now supplies durable
consensus independently; #134 closes only fixed-width legacy-v4 admission.
#143 still includes distributed load and payload-protection-key qualification,
while seamless SVID/trust rotation follows the dedicated rotation issue chain.

### Fresh durable readiness

Capability declarations and `SessionStorePlatformProfile::Quorum` remain
admission evidence only. `QuorumSessionStore::probe_durable_readiness` bypasses
cached capabilities and invokes Openraft's bounded linearizable-read barrier,
then waits until the local state machine has applied through that log ID.
`Ready` therefore proves the same fresh quorum path required by real reads, not
merely that a listener was bound. Writes use bounded `client_write`; reads use
the barrier every time and never trust a prior readiness result.

The report remains point-in-time evidence rather than an ownership lease.
Products must continuously close ownership publication and traffic
advertisement when it becomes `NoQuorum`. Diagnostics remain bounded and
redacted; peer identities and peer-controlled errors are not labels or report
payloads.

Openraft reconciles current-format follower log divergence. SQLite refuses a
truncate at or below either persisted committed or applied index. Snapshot
install validates checksum, exact cluster/configuration/epoch and membership,
then refuses an image older than the local committed/applied floor before one
transaction replaces application state. Restart validates the referenced
snapshot and removes only bounded SDK staging/orphan names left by an
interrupted receive/build/promote. Covered-log purge waits under one ten-second
bound for the asynchronous snapshot apply worker, preventing a successfully
installed image from being followed by a false purge-before-apply fatal error.
Readiness reports typed local recovery posture and index counters without peer
text or session identifiers.

Recovery of an already forked legacy custom-coordinator database uses #129's
[audited offline campaign](session-store-legacy-recovery.md) because the old
format cannot prove which conflicting tail was committed. Readiness never
guesses or performs an unaudited destructive rebuild.

### Bounded TTL inputs

All `Duration` inputs used for session refresh and lease TTLs use the public
`MAX_SESSION_TTL` bound of exactly 365 days. Zero is accepted as immediate
expiry and the exact maximum is accepted. Larger values fail with
`StoreError::InvalidSessionTtl` or
`LeaseError::InvalidSessionTtl`. Conversion to the internal duration and
addition to an injected/backend clock use exact checked integer arithmetic, so
an oversized input or a near-maximum clock cannot unwind the process.

Validation occurs before effects for direct acquire/renew/refresh calls,
TTL-bearing batch and replication entries, wrappers, quorum dispatch, local
backends, and authenticated client/server admission. Here, effects means
application/backend mutation or provider work: clients reject before
resolution/dialing, while servers reject after request receipt but before
backend dispatch and may return the typed response. The new public error
variants require external exhaustive matches. Protocol v4 introduced their
private fixed-width DTOs in error revision 1; current error revision 5 retains
those encodings and rejects error-revision-4 or older v4 peers during the exact
handshake. Operators must audit legacy
persisted logs before upgrade because a TTL-bearing entry
above the bound now fails closed during replay/rebuild rather than being
clamped or rewritten. Replicated deadline validation permits at most one
microsecond above exact `entry.timestamp + ttl` for legacy `seconds_f64`
rounding only; new deadlines remain exact, the TTL bound is unchanged, and
larger mismatches fail closed.

This closes only the duration-input/process-availability gap in #137. Openraft
commit authority is independent; repair, restore, and qualification work remain
open. Caller-authored absolute record expiry remains #148.

### Bounded protected replication trees

`MAX_REPLICATION_OPERATION_DEPTH` is 16 and
`MAX_REPLICATION_OPERATIONS_PER_ENTRY` is 256. The root is depth 1, each child
increments depth, and every operation node—including each `Batch`—counts toward
the entry total. Validation and transformation use iterative traversal. An
over-limit entry fails with the fieldless
`StoreError::ReplicationOperationLimitExceeded`, without exposing count, depth,
key, payload, provider detail, or nesting shape.

Entry and complete rebuild-prefix preflight finishes before provider or backend
work. Complete returned pages are validated before transformation or caller
exposure. `EncryptingSessionBackend` and `RemoteSealingSessionBackend` protect
every nested CAS on replicate/rebuild and unprotect every nested CAS on log and
watch reads. Provider calls remain sequential and operation order/non-payload
fields are preserved. A late provider error may follow earlier provider calls,
but a write performs no backend delegation and a read exposes no partially
transformed entry/page; earlier independent watch items may already have been
yielded.

This was a breaking confidentiality contract before protocol v4. An older peer
cannot decode the new error, and an older wrapper may forward a deep CAS as
plaintext/unsealed data. Protocol v4 rejects the older wire participant and
pins the limits/error revision, but cannot attest that a protection wrapper is
actually installed. Drain and upgrade all clients, servers, and wrapper
participants together, verify product composition, and do not call this
rolling-compatible.

Historical nested plaintext is not automatically scrubbed. Operators must
audit persisted tree shape and payload encoding offline before upgrade. Entries
within the new limits may be explicitly rewritten/rebuilt through the configured
protection wrapper. Over-limit history fails before transformation and requires
a separately reviewed atomicity-preserving offline migration or audited store
replacement before the new SDK starts; it must not be clamped or split ad hoc.
Raw inner-backend rebuild does not add protection.

#147 closes only this bounded nested-payload path. The session profile remains
experimental until the remaining non-consensus gates pass. Seamless
SVID/trust-bundle lifecycle remains #158. Remote-seal historical selection is
implemented with KMS/HKMS-owned retention; the SDK has no local historical
cache, retirement API, or enforcement gate. Distributed payload-protection and
production qualification remain #143. These are separate mandatory gates.

### Consensus transport and encryption boundary

The production authority path uses `SessionConsensusServer` and
`RemoteSessionConsensusPeer` over the exact `opc-session-consensus/1` ALPN.
Consensus DTOs carry only bounded Openraft RPC families and application
forward/read-barrier requests. Sender identity is checked against both the
authenticated peer and the inner Openraft vote/log sender before dispatch.
The legacy writable backend protocol cannot negotiate on this listener.

Payload protection remains outside consensus:

```text
application -> EncryptingSessionBackend / RemoteSealingSessionBackend
            -> ConsensusSessionStore -> Openraft -> SQLite and snapshots
```

New plaintext writes are sealed before `client_write`. Openraft, consensus RPC
encoding, follower apply, replay, outcomes, snapshots, and restart have no key
provider and see only opaque envelopes. Historical-key lookup occurs only when
a read crosses the outer wrapper. Tests prove plaintext and raw key canaries are
absent from RPC frames, state/log/outcome tables, WAL/SHM, and snapshot files;
provider call counts stay unchanged during replication, snapshot, and restart.
Missing historical keys fail reads closed without preventing already-sealed
quorum recovery.

This is payload-envelope encryption, not full-database encryption. Membership,
indexes, routing fields, owners, fences, timestamps, and envelope key IDs remain
visible unless a separate approved storage layer protects them.

### Legacy backend and restore transport (protocol v4)

The opt-in `opc-session-net` protocol v4 carries validated restore-scan
requests and pages to individual remote replicas. It admits only the
`DurableOpaqueV1` page profile; offset cursors from the local fake are rejected
and can never become remote restore evidence. Backend pages are capped at
1,024 records, 4 MiB of payload, and 4,096 examined live candidates plus one
lookahead. Narrow scopes may therefore return an empty advancing page. The
cursor is an AES-256-GCM-SIV ciphertext that confidentially and
authentically binds the composite seek key, backend epoch, record revision,
logical time, scope, and progress. A modified, stale, or cross-scope cursor
fails typed and restarts from page one. A server never fabricates a replacement
cursor while fitting a wire frame; an encoded page that cannot fit returns
`RestoreScanResponseTooLarge` so the caller can retry the same cursor with a
smaller record limit.

Every production participant is created with an opaque authenticated TLS
config and a binding derived from one immutable `SessionReplicationManifest`.
The manifest's configuration ID is an order-independent SHA-256 digest of the
cluster ID, operator-controlled generation, and every field of every replica
descriptor. During the v4 handshake, each side extracts the canonical SPIFFE
URI from the live certificate and requires it to match the claimed stable
`ReplicaId`, expected opposite member, cluster, and configuration ID before
dispatch. The client verifies its fresh challenge is echoed by the server.
DNS/FQDN/IP aliases and resolver overrides affect
routing only; they never redefine replica identity.

The exact `opc-session-net/4` ALPN, version, and contract profile have no
production fallback to v3. A v3-to-v4 change is a coordinated
stop/upgrade/start of all clients and servers, not a mixed-version rolling
deployment or highest-common-version negotiation. Public `Request`/`Response`
remain available, but `Hello`/`HelloAck` gain an optional `contract_profile`, so
exhaustive construction and matching must account for the new field.

Wire-schema revision 3 retains revision 2's directional frame
budgets. Hello sends `requested_response_frame_size`; HelloAck returns the
client/server-minimum `accepted_response_frame_size` plus the independent
`server_request_frame_size`. Each checked `u32` must be at least
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes) and at most
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes).
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases the same minimum. Unequal
client/server settings are therefore explicit. Revision 3 carries the
confidential cursor and explicit durable-page profile and pins the payload and
8 MiB retained-page, 8 MiB examined key/filter-metadata, and
examined-candidate budgets; error-set revision 3 carries stale-cursor,
direct-CAS idempotency, and work-budget failures. Error-set revision 4 adds
checked replication-log range outcomes; revision 5 adds non-CAS backend and
lease ambiguity outcomes. Different exact v4
profiles do not interoperate even though their ALPN text is the same.

Cursor ciphertext is variable-length up to the consensus RPC/key ceiling and
uses separated HMAC-derived AES-256-GCM-SIV and synthetic-nonce keys. Identical
semantic positions encode identically. Only the cumulative examined-row
position is clear and bound into cursor authentication, allowing a structural
check of the issuer's claimed progress; the issuer authenticates it when the
cursor returns. It cannot prove page completeness or server honesty. The seek
and snapshot fields remain confidential. Cursors survive a same-PVC
restart but are node/incarnation-bound. Another node or an installed snapshot
returns typed stale-cursor state and the caller restarts at page one.

The private v4 DTOs use `u32` for restore/log request limits and the restore
response budget, a confidential authenticated strictly bounded restore cursor, and
`u64` excluded counts,
`max_value_bytes`, and size-bearing store errors. Restore `loaded_count` and
`complete` are omitted and recomputed after decode. Independent work limits
admit 256 batch operations, 1,024 restore records, 65,536 log entries, and
65,536 rebuild entries; the configured frame bound remains separate. The exact
profile pins wire-schema revision 4, error-set revision 5, a 4 MiB restore
payload bound, `max_restore_scan_examined_rows = 4096`, 128-byte
owner/custom-key/state-type bounds, the
31,536,000-second TTL maximum, and
depth-16/256-node replication trees. Revision 2 also pins
`min_frame_size = 8192`, `max_frame_size = 16777216`,
`stable_id_max_bytes = 64`,
`replication_tx_id_max_bytes = 128`, and `cas_request_id_bytes = 36`.
Transported stable IDs contain 1 through 64 bytes, transaction IDs contain 1
through 128 UTF-8 bytes, and CAS request IDs, when present, use the canonical
lowercase hyphenated 36-byte UUID encoding.
Error-set revision 4 adds checked replication-log range overflow, page-limit,
and compacted-cursor outcomes; revision 5 adds non-CAS backend and lease
ambiguity outcomes. A revision-4 or older peer is therefore incompatible.

Every server response and watch item is fully bounded-encoded before a length
prefix is emitted. Common non-pageable and complete-page successes use one
bounded encode without a sizing preflight. An oversized pageable direct attempt
emits no prefix; bounded logarithmic sizing probes and the final encode share
one absolute deadline established before the first encode/probe and continuing
through prefix, payload, and flush. Lazy exact-length boxed chunks are not
coalesced and retained encoded-JSON
byte storage stays within the limit; metadata and allocator slab/RSS overhead
remain separate. Storage/sizing sinks check deadline and server-abort
cancellation cooperatively between serializer writes/chunks. Tokio cannot
preempt one synchronous serializer callback, whose input remains bounded by the
profile. Expiry closes the connection and returns the handler/connection permit.
Get/CAS records and positional batch vectors are never truncated. Restore may
return a complete cursor-correct prefix; replication-log reads return the
largest complete contiguous-sequence prefix that fits. Watch cannot skip an
oversized entry; it emits a fixed SDK-owned error when representable and ends,
or closes immediately. A fixed fallback that itself cannot fit also causes a
fail-closed close. Rejected nested entries keep iterative disposal and bounded
work.

Transport `max_value_bytes` is clamped to the backend maximum and exactly
`(frame - 8192) / 8` for both the accepted response and server request frames.
The reserve and factor cover the record/key/error envelope, worst-case JSON
byte-array expansion, and equal escaping/metadata headroom. The advertised
maximum can perform a real write/read round trip under unequal limits. It
is zero at the exact 8 KiB minimum; payload-bearing traffic requires a larger
frame. The 1 MiB default advertises 130,048 bytes; the 16 MiB ceiling advertises
2,096,128, and SQLite's full 1 MiB limit requires at least 8,396,800 frame
bytes. A 16 MiB setting is recommended for that profile. This is per frame: at
the default 128 connection slots, concurrent ceiling-sized encodes can retain
about 2 GiB before metadata/TLS/runtime overhead. The aggregate scales with
`with_max_connections`, so aggregate limiting and resource/soak evidence remain
#143. It remains descriptive, not traffic or quorum authority.

A version/profile/authentication or malformed-handshake failure clears cached
capabilities and reports every boolean false with `max_value_bytes = 0`.
Capabilities retained after transient transport loss remain descriptive only;
they never authorize a store operation or readiness. Use fresh bounded quorum
evidence and continuous traffic gating.

Before the v4 rollout, drain traffic and writers, run the #135 count-only
identity audit, and preflight every live/replayable handover and nested-payload
copy. Stop and upgrade every client, server, protection wrapper, and product
handover reader/writer together; verify exact-v4 authenticated restore/log
traffic and fresh quorum evidence before reopening traffic. Once `OPCH` has
been written, rollback to a v3 binary additionally requires a coherent drained
checkpoint restore or reviewed reverse migration of every live and replayable
record, log, snapshot, and restore source.

The revision-1 to revision-2 profile transition uses the same coordinated
stop/upgrade/start and verification; it is not a same-ALPN rolling upgrade.
#167 does not rewrite compliant persisted stable-ID bytes. Its `StableId`
newtype and new-database SQLite checks enforce 1..=64 bytes throughout the
model/store/network stack; existing files and snapshots require the version-3
count-only audit. Strict revision-2 transport also rejects empty/over-128-byte
UTF-8 transaction IDs. Before startup, quiesce writers, audit every
record/log/snapshot/restore/replay source, and perform a decoder-first
product-aware migration or coherent store replacement under the #167 runbook
and #168. The migration reader must decode the legacy representation
before rewrite, must not truncate/hash/rename durable identities, and the strict
decoder must verify the result before writers restart. Rollback must first
install a decoder that reads the retained target representation, or restore a
coherent checkpoint/run a reviewed reverse migration. Every participant still
moves to one exact profile together. Rollback across `OPCH`/#135 retains its
independent coherent-checkpoint or reverse-migration requirement.

Session caches, tickets, resumption, early data, and 0-RTT are disabled, so a
reconnect performs a full mutual-TLS certificate exchange. Production still
requires complete certificate and trust-bundle rotation without interrupting
session service. Real-mTLS tests now qualify a correctly scoped renewed SVID on
a subsequent new call/full handshake and wrong-scope rejection. They do not
exercise a retained old connection. Fleet trust overlap, revocation,
long-lived-connection retirement, reconnect storms, a documented maximum
authentication age, multi-process rotation, seamless continuity, and soak
remain open production work under the existing lifecycle/#143 gates.

For Kubernetes mounts, `ProjectedSvidSource` now publishes only a bounded,
validated candidate read from one immutable `..data` target and retains a
failed candidate's predecessor only until expiry. That closes source-level
atomicity, not connection continuity: #162 still owns coherent handshake
epochs, #163 owns retirement/reauthentication, #164 owns fleet evidence, and
#158 remains their umbrella. Distributed qualification remains #143. Session
TTL is application-state lifetime; the 365-day bound is not a
certificate-expiry, trust-validity, or authentication-age policy.

Response delivery is not atomic with backend mutation. A CAS, batch slot, lease
change, replicated append, or rebuild may commit before bounded encoding or the
socket write fails. Missing responses are ambiguous; clients recover through
the operation's request-ID/idempotency and fencing rules plus authoritative
re-read, never by assuming rollback and blindly replaying. Operational evidence
uses bounded operation-family/reason categories for oversize/fallback/timeout
without logging keys, payloads, owners, transaction IDs, peer identities, or
backend/peer-controlled error text.

Protocol v4 remains a compatibility transport and does not establish
authority. #127 uses the separate Openraft transport; #133 scans only the
barrier-confirmed local applied state with bounded work, while #129 legacy-fork
recovery remains an offline, operator-authorized campaign.

### Log & Replication Model
- **Openraft Log Authority**: Openraft allocates and commits its zero-based log
  indexes. No SDK coordinator assigns an authoritative distributed sequence or
  performs majority-prefix rollback. Vote, log, committed/applied/purged,
  membership, and snapshot metadata persist transactionally in SQLite.
- **Deterministic Application Journal**: Committed mutations (AcquireLease,
  RenewLease, ReleaseLease, CompareAndSet, DeleteFenced, RefreshTtl, Batch) are
  applied in order and produce the existing 1-based
  `session_replication_log` as a state-machine output for watches/restores. It
  is not a second consensus log.
- **Idempotent Outcomes**: Durable request IDs bind to a digest of semantic
  intent. Exact retries return the original logical time, journal sequence,
  Raft index, and result, including after leader change; a changed intent under
  the same ID fails closed.
- **Logical Expiry Time**: Expiry-sensitive reads first commit monotonic
  logical time, preventing clock rollback or leader failover from resurrecting
  an expired record or lease.
- **Resume Tokens / Watch Cursors**: Watches publish only committed application
  entries and allow consumers to resume from the 1-based sequence cursor.
- **Raw Authority Rejection**: Direct `replicate_entry`, whole-state rebuild,
  and caller-selected lease metadata operations are rejected by
  `ConsensusSessionStore`.
- **Feature Declarations**: Replicated adapters declare `ordered_replication_log = true` and `watch = true`, while standalone SQLite reports `false`. These bits describe implemented methods; they are not fresh-quorum readiness or production qualification. Consumers must use `probe_durable_readiness` for current evidence.
- **Low-Cardinality Readiness Telemetry**: Metrics expose probe success/failure and bounded Openraft state without replica IDs, endpoints, SPIFFE IDs, tenants, keys, or raw errors as labels.

---

## 3. Local Session Cache Invalidation: `SessionCache`

`SessionCache` (implemented in the `opc-session-cache` crate) provides a local, in-memory read-through cache for session records in downstream CNFs. It keeps cache hits behind an explicit coherence gate: local values are served only when the background watch stream is active and the processed sequence is caught up to the backend's reported replication sequence. If the cursor cannot be verified, reads bypass local memory and go directly to the authoritative backend.

### Coherence & Invalidation Model
- **Read-Through Population**: When `get` misses the local cache, the record is fetched from the authoritative backend. It is populated in memory only after the cache verifies that the watch cursor is caught up to `max_replication_sequence`. If the cursor is lagging, unavailable, or syncing, the read succeeds from the backend but the value is not cached.
- **Coherent Cache Hits Only**: Before serving a cached value, the cache checks that the watched sequence is at least the backend's current reported sequence. If the backend is ahead, the cache clears local state, marks the watch unhealthy, and bypasses cache hits until the watch loop catches up or resyncs.
- **Background Watch Subscription**: Spawns a background task that subscribes to `watch(last_sequence + 1)` on the session store, receiving replication entries in monotonic order. Any mutation (CompareAndSet, DeleteFenced, RefreshTtl, AcquireLease, RenewLease, ReleaseLease) to a key results in the key being evicted from the cache.
- **Monotonic Sequence Tracking & Gaps**: The cache tracks the processed sequence number globally. If a gap is detected (`sequence > last_sequence + 1`), indicating missed log entries, the cache invalidates its entire state and triggers a full resync from the current maximum sequence number of the backend.
- **Idempotency**: Duplicate events (`sequence <= last_sequence`) are detected and ignored, preserving the sequence cursor and cache safety.
- **Fail-Closed & Gap Recovery**: If the watch stream encounters a connection error, reports a gap, lacks ordered-watch capabilities, or cannot prove the cursor is current, the cache clears its local entries and bypasses local reads. It attempts to re-establish the watch from the latest sequence after querying `max_replication_sequence`; subsequent `get` calls fall back to direct backend lookups until coherence is restored.
- **Write-Through Wrapper Safety**: `SessionCache` implements the `SessionBackend` trait and delegates mutations to the authoritative backend. Mutating calls through the wrapper evict affected keys before and after successful writes, so callers do not need to wait for the async watch stream to invalidate their own local writes.
- **Redacted Diagnostics**: Key operations and lifecycle state transitions (such as resyncs and stream restarts) are logged with redacted session keys, protecting subscriber identifiers from diagnostics exposure.

---

## 4. HA Implementation Test Status

Config Openraft coverage lives in
`crates/opc-persist/tests/consensus_openraft.rs` and the application protection
integration in
`crates/opc-amf-lite/tests/config_consensus_encryption.rs`.
`opc-session-testkit` supplies the session fault harness without implementing a
second consensus algorithm.

### Config Store Openraft Tests

- **Sealed singleton and fencing**: A caller-retained request ID is idempotent,
  audit values are redacted, a retained raw backend cannot mutate after the
  atomic authority claim, and plaintext canaries remain absent from SQLite,
  WAL/SHM, and Openraft snapshots across restart.
- **Exact offline migration**: Nonempty legacy authority fails closed. An
  approved applied snapshot replaces an unknown target suffix only when its
  checksum and exact transaction/version head match. Wrong checksum/head,
  nonempty source WAL, and invalid audit state fail without claiming or
  modifying the target authority.
- **Three-node authority**: Tests form an Openraft fleet, commit through the
  quorum, isolate the old leader, elect and write through the surviving
  majority, heal/converge, and replay a delivered-but-lost response without a
  duplicate application outcome.
- **Membership**: the configured voter set is exact and immutable within an
  epoch; subset/superset requests fail before Openraft work and topology change
  requires a coordinated new configuration epoch.
- **Application/HKMS boundary**: The AMF-lite integration composes the real
  config encryption wrapper with a three-node store, rotates provider-backed
  config keys, reads from followers, snapshots and restarts the fleet, and
  scans durable artifacts for plaintext, raw-key, and provider-endpoint
  canaries. Followers, apply, snapshots, and recovery make no provider calls.
- **Shared mTLS lifecycle**: `opc-session-net` transport tests observe a
  renewed SVID on a subsequent new call/full handshake and reject a rotated
  client or server identity outside the bound peer scope. They do not exercise
  retained-connection retirement or seamless continuity. The suite also forms
  a real three-node config Openraft cluster and commits/linearizably reads
  through the existing mTLS peer/server types.

This evidence establishes the single-engine and migration behavior, qualifies
the three-node HKMS boundary, and qualifies scoped new-call/full-handshake SVID
reload plus three-node in-process real-mTLS config composition on the shared
transport. It does not yet provide seamless connection
retirement, remote HKMS, out-of-process/deployed-network integration,
restart/rejoin, resource/soak, complete
trust-bundle/revocation/authentication-age fleet lifecycle, or candidate
release evidence; those remain `GAP-001-006`.

### Session Store HA Failure Tests (Openraft)

The fleet tests use three distinct file-backed SQLite databases and real
Openraft RPC handlers over controllable in-process paths; the testkit does not
implement a second quorum algorithm.

- **Cold-start concurrency**: Concurrent first writes form one gap-free
  committed journal without equal-sequence forks.
- **Cross-node authority**: Lease/CAS writes converge, follower reads pass a
  linearizable barrier, and only Openraft-backed stores claim quorum.
- **Partition and healing**: A node isolation causes bounded readiness/write
  failure where quorum is unavailable; healed paths catch up and rejoin.
- **Ambiguous response retry**: A delivered-but-lost forwarded response can be
  retried with the same durable request identity and produces exactly one
  committed application event.
- **Raw authority rejection**: Direct replication/rebuild/lease-sequence
  surfaces cannot bypass Openraft.
- **Encryption/HKMS isolation**: Real outer-wrapper writes, key rotation,
  snapshots, restart, and missing historical keys prove only sealed envelopes
  enter consensus and no provider calls occur below the wrapper.
- **Stale-fence replay**: Stale fence updates are rejected monotonically.
- **No wall-clock LWW**: Leader-selected monotonic logical time, not replica
  wall-clock last-writer-wins, drives expiry state.
- **Bounded TTLs**: Exercises zero, the exact 365-day maximum, maximum plus one,
  and `Duration::MAX` across direct, nested, persisted, quorum, and
  authenticated-wire paths, including no-partial-effect and near-maximum-clock
  cases.
- **Nested payload protection**: Exercises depth/count edges, deep CAS
  encryption/sealing round trips through replicate/rebuild/log/watch, complete
  prefix/page preflight, sequential-provider failure, and no backend delegation
  or partial entry/page exposure.
- **Required bounded-response qualification**: Must exercise equal/unequal revision-2 budgets,
  8 KiB/16 MiB/MAX+1 admission, a non-power-of-two retained-chunk allocation,
  exact-limit and one-byte-over response families, conservative maximum-payload
  round trips, cursor/sequence-preserving prefixes, non-truncated batches,
  fixed redaction-safe fallbacks, authenticated slow-reader reaping, connection
  slot recovery, ambiguous mutation outcomes, and deterministic shutdown.
  Passing those tests demonstrates the #159 transport boundary only; it does
  not close #171 log-range cursor work, the complete seamless credential
  lifecycle, or #143 production qualification. #167/#168 separately supply
  the structural retained-identity and migration contracts. #177 reuses this shared
  transport boundary for config consensus instead of maintaining a separate
  config TCP deadline or credential path.
