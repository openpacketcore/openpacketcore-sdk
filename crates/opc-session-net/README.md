# opc-session-net

Authenticated network transport for session consensus peers. Legacy direct
session-backend networking is retained only as an opt-in migration surface.

## Purpose

The default crate surface exposes `RemoteSessionConsensusPeer` and
`SessionConsensusServer`. It does not expose a client, listener, or public wire
DTO capable of direct session mutation, raw replication-log append, or rebuild.
Every production connection is bound to one authenticated member of one
immutable replication manifest.

## Consensus production profile

Issue #127 introduces a separate least-authority transport for the shared
Openraft engine. `SessionConsensusServer` advertises only
`opc-session-consensus/2` and owns only an
`Arc<dyn SessionConsensusRpcHandler>`; it cannot dispatch `SessionBackend`,
lease, raw replication-log append, or rebuild operations.
`RemoteSessionConsensusPeer` implements only `SessionConsensusPeer`.

The legacy `RemoteSessionBackend`, `SessionReplicationServer`, and protocol-v5
`Request`/`Response` surface compile only with the non-default
`legacy-session-net-compat` feature. That feature grants direct mutation and raw
replication/rebuild authority. It is for controlled migration and compatibility
testing only; it must not be enabled in a production Openraft build or served on
a production consensus endpoint. The `insecure-test` feature does not enable it
implicitly.

`SessionReplicationManifest::try_new_with_epoch` is the production manifest
constructor. It derives the exact shared consensus identity from the hashed
cluster ID, positive numeric configuration epoch, and complete descriptor
fingerprints. Stable non-zero Openraft node IDs are domain-separated hashes of
the cluster identity and immutable logical `ReplicaId`; they survive member
reordering, addition, removal, and epoch changes. Derived collisions are
rejected during admission. The legacy `try_new` constructor is deprecated and
fixes the epoch to 1 only for source compatibility with protocol-v5 callers.

Each directed consensus peer retains at most one authenticated connection and
allows at most one in-flight RPC on it. Establishment performs a fresh
mutual-TLS handshake and binds the certificate SPIFFE identity, logical replica
ID, stable node ID, expected server, cluster/configuration/epoch, exact
transport profile, and a fresh handshake nonce. Each call carries a fresh
correlation ID; only a complete, correctly correlated, fully validated
successful response returns the connection to the sole slot. A typed failed
response, cancellation, timeout, EOF, framing,
protocol, authentication, evidence mismatch, or lifecycle retirement drops it,
so a late or partial response cannot be consumed by another Openraft RPC. The
client applies one absolute logical deadline to gate acquisition and, when a
connection is required, DNS, TCP, TLS, bootstrap, bounded encoding, write, and
response read.

This cache removes repeated handshakes from a healthy steady-state heartbeat
path. A first call, dead cached socket, or replacement still performs DNS, TCP,
mutual TLS, identity admission, and bootstrap. One absolute family deadline
starts before gate acquisition. A fresh connection receives the lesser of the
remaining family budget and a 1,500 ms cold-phase cap; response work keeps only
the original remaining budget, so cold time is contained and never additive.

| RPC family | Complete deadline |
|:---|---:|
| AppendEntries and Openraft read-index confirmation | 2,000 ms |
| Vote | 5,000 ms |
| InstallSnapshot | 10,000 ms |
| ForwardMutation | 10,000 ms |
| Consumer ReadBarrier | 10,000 ms |

The election range is `[5,000 ms, 8,000 ms)`, the session/config operation
default is 10,000 ms, and listener idle/handler ceilings are 30,000 ms.
The exact consensus contract is transport/wire-schema revision 2 and error-set
revision 4. Revision 2 carries the payload-free bounded expiry-authority
preflight used before wrapper/provider work; error revision 4 adds the typed
`RecordExpiryPreflightLimitExceeded` bound. Revision 1/error revision 3 or
older peers fail before dispatch;
upgrade every consensus member together while traffic and writers are drained.
This is not a rolling mixed-profile transition.

The consensus profile accepts encoded frame budgets from 9 MiB through 16 MiB.
The 9 MiB minimum is proven to hold the worst JSON expansion of the shared
2 MiB opaque RPC ceiling plus its bounded envelope. Private Openraft RPCs are
compact-encoded by the session-store adapter; the transport does not interpret
or authorize engine decisions. On a production #127 endpoint the consensus
ALPN replaces the legacy backend ALPN. Restore now consumes the local
Openraft-applied state after a linearizable barrier rather than reopening raw
mutation or rebuild authority beside Openraft.

## API Shape

- `SessionReplicationManifest::try_new_with_epoch` validates one cluster ID,
  positive consensus configuration epoch, one legacy protocol-v5
  operator-controlled configuration generation, and the complete replica
  descriptor set. The deprecated `try_new` compatibility constructor uses
  epoch 1.
- `SessionReplicationManifest::bind_local` selects the exact local
  `ReplicaId`; `LocalReplicaBinding::bind_remote` derives the only supported
  production client binding for an admitted peer.
- `RemoteSessionConsensusPeer::new` and `new_with_resolver` create the
  authenticated outbound consensus-only port. Unmodified clones share one
  bounded connection slot and one call gate per directed peer; clone-local
  frame, lifecycle, or reauthentication builders detach incompatible cached
  state. `None` selects the shared family profile. `Some(duration)` remains a
  source-compatible fixed complete-call test/compatibility override, but cannot
  enlarge the shared 1,500 ms cold cap. `new_profiled` and
  `new_profiled_with_resolver` select the production profile explicitly.
- `SessionConsensusServer::new` accepts only an
  `Arc<dyn SessionConsensusRpcHandler>` and serves only the dedicated consensus
  ALPN.

### Legacy compatibility API (`legacy-session-net-compat` only)

- `RemoteSessionBackend::new(binding, tls_config, deadline)` creates an mTLS
  client that implements `SessionBackend` and `SessionLeaseManager`. The
  endpoint comes from the binding; `new_with_resolver` may override address
  resolution, but not identity.
- `RemoteSessionBackend::new_insecure` exists only behind the `insecure-test`
  feature.
- `with_max_frame_size` overrides the default 1 MiB frame limit within the
  exact 8 KiB..=16 MiB negotiated range. During the
  frozen bootstrap the client sends this as `requested_response_frame_size`;
  the server acknowledges the smaller executable response budget as
  `accepted_response_frame_size` and separately publishes its inbound
  `server_request_frame_size`.
- `SessionReplicationServer::new(backend, tls_config, binding)` creates an mTLS
  server over an `Arc<dyn SessionStoreBackend>` and the exact local manifest
  member.
- `SessionReplicationServer::new_insecure` exists only behind the
  `insecure-test` feature.
- `with_idle_timeout`, `with_backend_operation_timeout`,
  `with_backend_operation_concurrency`, `with_max_connections`, and
  `with_max_frame_size` configure the server. Backend queueing plus work has
  one absolute deadline after a complete request frame is decoded; one
  `idle_timeout` interval is then reserved for response validation, bounded
  encoding, prefix, payload, and flush. Their checked sum is the post-decode
  lifetime. Full connection-slot occupancy has three bounded phases: one
  inbound `idle_timeout`, backend queue/work, and one outbound `idle_timeout`.
  `with_restore_scan_timeout` may further shorten cancellable restore work.
- `RemoteSessionBackend::scan_restore_records` validates requests and peer
  pages against the exact request limit actually dispatched after frame
  narrowing. Only `DurableOpaqueV1` pages are transportable: compatibility
  offset pages from the in-process fake are rejected before they can be used
  as remote restore evidence. Validation bounds page bytes, record order,
  scope, cursor shape, and the server's claimed progress; it cannot prove that
  an authenticated server did not omit records or falsely report completion.
  Production completeness is the local Openraft-applied scan after a
  linearizable barrier, not this compatibility RPC. Backends may return fewer records than requested
  (including an empty advancing sparse page) to stay within the fixed 4 MiB
  payload, 8 MiB retained-page, 8 MiB examined-metadata, and 4,096
  examined-candidate budgets; callers continue from the
  confidential authenticated `next_cursor` until `complete`. A server does not
  rewrite a backend cursor to fit a smaller wire frame: it returns
  `RestoreScanResponseTooLarge`, allowing the caller to retry from the same
  cursor with a smaller record limit. The wire omits redundant `loaded_count`
  and `complete` values and recomputes both from records and cursor.
- `SessionBackend::probe_replication_head` performs a fresh, deadline-bounded
  wire request. It does not consult the client's capability cache and reports
  transport, authentication, timeout, protocol, and backend failures through
  redaction-safe `ReplicaReadinessFailure` variants.
- Replication append and rebuild calls validate sequence metadata before
  resolution or dispatch; malformed authenticated wire requests receive the
  typed store error without consuming the connection.
- Protocol decoding reuses `OwnerId` and `SessionKeyType`'s structural Serde
  validation for every request, response, restore record, lease guard, batch,
  and nested replication entry before backend dispatch or caller exposure.
- Replication entries, rebuild prefixes, returned log pages, and watch items
  enforce `MAX_REPLICATION_OPERATION_DEPTH` (16) and
  `MAX_REPLICATION_OPERATIONS_PER_ENTRY` (256). The root is depth 1 and every
  operation node, including `Batch`, counts toward the per-entry total.
- Independent protocol work limits admit at most 256 batch operations, 1,024
  restore records and 4 MiB of restore payload, 65,536 replication-log
  entries, and 65,536 rebuild entries.
  These limits apply in addition to the configured encoded-frame bound.
- Every post-bootstrap server response and watch item is fully bounded-encoded
  before any length prefix is written. Common successes use one bounded encode;
  an oversized pageable attempt emits no prefix and may then use bounded
  logarithmic sizing probes plus one final encode. Lazy exact-length boxed
  chunks are never coalesced, and their retained encoded-JSON byte storage
  cannot exceed the negotiated response budget; chunk metadata and allocator
  slab/RSS overhead are not wire bytes. One absolute deadline begins before
  the first encode/probe and covers all probes, final encode, prefix, payload,
  and flush.
- Acquire, renew, TTL refresh, batch, and nested replication requests enforce
  `opc_session_store::MAX_SESSION_TTL` (365 days) before resolution or backend
  dispatch. Zero remains valid and means immediate expiry.
- CAS records enforce the time-independent `None`/state-class expiry profile
  before dialing or dispatch. A direct backend with explicit clock authority
  also enforces the finite 365-day horizon; production OpenRaft binds it to the
  leader-authored command time, never the client's or follower's wall clock.
- If one record cannot fit, the call returns
  `StoreError::RestoreScanResponseTooLarge` instead of retrying indefinitely.
- `listen(bind_addr).await` starts the listener and returns a server handle and
  bound address.
- `ServerHandle::abort()` schedules non-blocking listener/connection
  cancellation. `abort_and_wait().await` consumes the handle and returns only
  after the listener and every registered connection handler have stopped;
  use that barrier before deterministic restart or post-shutdown probes.
  `shutdown()` remains a graceful request, not a completion barrier.
- `Request`, `Response`, `HelloRejectReason`, `ProtocolError`, and protocol
  constants remain in the public protocol layer. Public semantic frames use
  custom Serde implementations backed by private v5 fixed-width DTOs rather
  than serializing target-width domain integers directly.

```rust,ignore
use opc_session_net::{RemoteSessionBackend, SessionReplicationManifest};
use opc_session_store::ReplicaId;
use std::time::Duration;

let manifest: std::sync::Arc<SessionReplicationManifest> = validated_manifest;
let local = manifest.bind_local(ReplicaId::new("epdg-app-0")?)?;
let peer = local.bind_remote(ReplicaId::new("epdg-app-1")?)?;
let tls_config = opc_tls::TlsConfigBuilder::new(identity_state_rx)
    .with_policy(replication_peer_policy)
    .build_authenticated_client_config()?;
let remote = RemoteSessionBackend::new(
    peer,
    tls_config,
    Some(Duration::from_secs(2)),
);
let _remote = remote.with_max_frame_size(1024 * 1024);
```

## Legacy protocol-v5 details (`legacy-session-net-compat` only)

Everything below this heading documents the quarantined compatibility
protocol. None of these APIs or public DTOs are present in a default production
build.

### Outbound response contract

Protocol v5 contract-profile wire-schema revision 6 retains revision 5's
confidential authenticated snapshot-bound
restore cursor, explicit durable-page profile, fixed 4 MiB restore payload and
8 MiB retained-page, 8 MiB examined-metadata, and 4,096 examined-candidate
budgets and exact configuration/process epoch binding for direct CAS. Revision
5 adds the bounded, payload-free `RecordExpiryPreflight` authority exchange.
Revision 6 adds the fixed `ConnectionRetiring` no-dispatch proof used for safe
reconnection during authentication-material rotation. When lifecycle
retirement is observed after mutual TLS and before any `HelloAck` bytes are
written, the server returns the same complete control as
`BootstrapResponse::ConnectionRetiring`. The client retries before sending an
application request only after decoding that complete authenticated frame.
EOF, an incomplete frame, and a partially written acknowledgement remain
fail-closed; the server does not append a retirement frame after a partial
acknowledgement.
The error-set revision is 8. Directional budgets are part of the exact
handshake. `requested_response_frame_size`,
`accepted_response_frame_size`, and `server_request_frame_size` are public
`Option<u32>` bootstrap fields so an older decoder can classify an otherwise
decodable legacy minimal bootstrap. This is not bidirectional mismatch
negotiation: an older decoder may reject unknown fields by simply closing.
Exact revision-6 v5 admission requires each to be `Some`, at least
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes), and at most
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes). The profile pins
both as `min_frame_size = 8192` and `max_frame_size = 16777216`.
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` is an alias of that same minimum, not a
second independently configurable limit. The accepted response size is the
smaller of the client's receive limit and the server's configured frame limit;
the server request size independently bounds frames sent by that client. This
supports unequal client/server settings without assuming either configured
limit applies in both directions. A revision-4/error-revision-7 or older peer
is incompatible; the ALPN is `opc-session-net/5`.

Error-set revision 4 adds typed replication-log range overflow, page-limit,
and compacted-cursor outcomes. A log request normalizes `start = 0` to one;
`limit = 0` returns before resolution or network work; a non-empty result must
start at the exact normalized cursor, remain contiguous, and stay within the
checked inclusive interval of at most 65,536 entries. Empty/terminal/future
cursors return an empty page. An otherwise contiguous peer page before or
after the requested interval is a protocol violation: the client discards the
connection and capability cache, then requires a fresh handshake. A response
that exceeds the negotiated frame may expose only the largest complete exact
prefix; the caller resumes at its first unsent sequence with no skip or
duplicate. A typed compacted resume point may be used only after the product
installs a coherent snapshot/rebuild through its existing authority path.

Error-set revision 5 adds non-CAS backend and lease ambiguity outcomes. It is
another exact-profile transition and does not add a downgrade or rolling
mixed-revision mode.

Error-set revision 6 adds the fieldless
`ReplicationWatchCatchUpRequired` outcome. Watch setup is now completed within
the caller's absolute deadline before `RemoteSessionBackend::watch` returns,
so an initial typed rejection is returned directly and is not confused with a
later transport close. Accepted watches require the exact inclusive next
sequence (zero was normalized to one in the request); future and terminal
cursors never receive lower items. A duplicate, gap, invalid entry, or other
authenticated-peer metadata violation ends the dedicated connection with a
redaction-safe protocol failure before an outer store wrapper can invoke an
encryption provider. Backlog overflow is non-retryable until the caller has
invalidated dependent state and completed a coherent catch-up; it never
supplies a cursor that could skip history. This changes only the exact legacy
error set and requires a coordinated compatibility-fleet upgrade.

Error-set revision 7 introduced the fieldless `InvalidRecordExpiry` outcome.
Wire revision 5 adds a bounded, payload-free authority
preflight of at most 256 expiry/state-class descriptors. Every authenticated
CAS and complete batch awaits that verdict before CAS-idempotency admission,
cache invalidation, key-provider/HKMS work, sealing, or backend dispatch.
Remote/consensus clients never substitute their wall clock for coordinator
time. Invalid input produces no provider call or log/state mutation; a queue,
transport, or authority timeout returns retry-safe `BackendUnavailable`
because only the logical-time floor may have committed and the requested
mutation did not start.
Error revision 8 adds the fieldless
`RecordExpiryPreflightLimitExceeded` outcome for that bound.

Direct CAS uses a canonical request UUID plus the server's
`cas_idempotency_epoch` from the authenticated `HelloAck`. The server binds
that pair to the authenticated logical replica, exact cluster/configuration
identity and monotonic configuration epoch, and a domain-separated SHA-256
digest of the complete CAS. Exact successes and conflicts replay; another
peer or operation reusing the UUID returns `CasIdempotencyConflict` before
backend dispatch. Concurrent duplicates share one in-flight execution. If
that execution is cancelled, or the bounded result cannot be retained, the
entry becomes `CasIdempotencyOutcomeUnavailable` rather than being silently
re-executed.

The cache admits at most 4,096 total entries, 512 per authenticated peer,
32 MiB total retained bytes, and 8 MiB per peer. Each request performs at most
64 cleanup inspections. Results are retained for five minutes, then become
small ambiguous tombstones; after the ten-minute tombstone interval the
server rotates its process epoch and clears the cache only when no CAS is in
flight. Restart also creates a fresh epoch. A request carrying an old epoch is
therefore rejected before mutation. The public `RemoteSessionBackend` injects
the live epoch internally and sends a direct CAS only once: transport loss
after any write/read boundary returns the typed unavailable outcome. The CNF
must authoritatively re-read and derive a new CAS; it must not resubmit the
historical operation under either the old or a fresh UUID. A backend-returned
`BackendUnavailable` after CAS dispatch is also converted to that typed outcome
and leaves an ambiguous tombstone; it is never cached as a completed result
that invites replay.
Diagnostics use only the fixed reasons `stale_epoch`, `identity_reuse`,
`ambiguous`, and `capacity`; they never include a peer, UUID, digest, key,
owner, lease, record, or payload.

All other legacy backend RPCs use independent fixed-size admission pools for
reads, mutations, lease mutations, and watch setup; restore retains its
single-worker pool. Queue timeout occurs before backend polling and is known
not to have applied an effect. A read execution timeout drops the read future
and is retryable. A non-CAS mutation or lease call that times out after backend
polling returns `BackendOperationOutcomeUnavailable` or
`LeaseError::OperationOutcomeUnavailable`: the caller must not replay it and
must stop writes until product recovery obtains authoritative state or a safe
uncertainty window permits a fresh guard. Transport failure
before the first request write remains retryable; once a write begins, response
loss is conservatively ambiguous. The public client automatically retries only
read-only operations (including an all-Get batch). It sends CAS, any mutating
batch, delete, refresh, replication/rebuild, and lease mutations once.
After transmission, a malformed response, wrong response family, or a
same-family success whose key/owner/fence/credential/result cardinality does
not match the request is equally ambiguous. The client discards retained
payloads, clears the negotiated connection/cache, increments the fixed
ambiguity metric, and returns the CAS, backend-mutation, or lease typed outcome
instead of a retryable protocol availability error.

Backend trait implementations are cancellation boundaries. Dropping a read
future signals cancellation; queue and database resources are released after
bounded cancellation completes, not necessarily synchronously with `Drop`.
Dropping a mutation leaves its caller with an unknown outcome that requires an
authoritative re-read even if supervised work later finishes. Durable
operation-bound replay is Openraft/direct-CAS-specific, not a generic adapter
promise. An internally detected deadline or transport failure surfaces the
typed ambiguity contract above. Blocking or spawned adapters must own a bounded
queue and retain their worker permit until the worker exits; they may not create
detached unbounded work. Session-net watches also monitor peer EOF and server
cancellation while the backend stream is idle.

The cursor's seek key and snapshot metadata remain confidential. Its one clear
cumulative examined-row position is bound into cursor authentication and lets
the client reject structurally inconsistent claimed progress before issuing
another request; the issuer authenticates it when consuming that cursor. This
does not prove page completeness or an authenticated server's honesty. Cursor encoding
is deterministic for an identical semantic position, so a response retry
reuses the same token. The cursor is backend-incarnation/node-bound: same-PVC
restart can resume it, but another node or an installed snapshot returns typed
`RestoreScanCursorStale`; restart at the first page instead of merging pages.
The model-wide 64-byte stable-ID bound keeps the complete confidential cursor
below 2 KiB after hex encoding, so it fits the minimum legacy session-net
frame. Response sizing remains exact and bounded: an otherwise oversized page
returns typed `RestoreScanResponseTooLarge` without a prefix or partial cursor.

The existing restore request's `max_response_frame_size` remains an additional
per-call cap; it may reduce, never enlarge, that connection's accepted response
budget.

`SessionReplicationServer::listen` validates resource configuration before it
binds or spawns: frame limits outside 8 KiB..=16 MiB, zero or unsupported
connection-slot counts, and unrepresentable idle/restore timeouts return
`InvalidInput`. A zero timeout is valid and intentionally causes immediate
deadline failure.

After bootstrap, the negotiated response budget applies to every response, not
only restore pages. A non-pageable response, or a complete restore/log page
that fits, takes the common single-encode path: it is bounded-encoded once and
then emitted without a separate sizing serialization. If a complete pageable
response is too large, that failed bounded encode emits no prefix; restore/log
shaping may then use bounded logarithmic sizing probes and one final bounded
encode. The direct attempt, every probe, final encode, prefix, payload, and
flush all share one absolute deadline established before the first encode or
probe. Sizing counters and encoded storage check that deadline and
`ServerHandle::abort` cancellation cooperatively between serializer
writes/chunks. Tokio task abortion cannot preempt one synchronous serializer
callback, so maximum wire-field widths remain part of the finite shutdown
interval. No retained encoded-JSON byte store can exceed the budget. Deadline
expiry terminates the connection and releases its handler/connection permit,
so an authenticated slow reader cannot retain a server slot indefinitely.

Response families use these fail-closed rules:

| Family | Oversize backend/output behavior |
| --- | --- |
| Capabilities | The fixed-width capability envelope is bounded by the 8 KiB minimum. A protocol encoding failure closes without emitting an oversized frame. |
| Fixed/scalar store or lease results | Replace an oversized backend-provided result/error with the operation's fixed SDK-owned, redaction-safe fallback when it fits; otherwise close. |
| Get and CAS conflict records | Never truncate a record. Replace the record-bearing result with the fixed fallback, or close if even that cannot fit. |
| Batch | Never truncate or reorder the positional result vector. Replace the complete batch response with its fixed fallback, or close. Earlier backend effects may already exist. |
| Restore scan | Return a complete record prefix that fits and preserve `next_cursor`/excluded-count semantics. If the first record cannot fit, return the fixed restore-size error; never split a record. |
| Replication log | Return the largest complete contiguous entry prefix that fits. Never split an entry or skip a sequence; use the fixed fallback when no entry can fit. |
| Watch | Bound the stream acknowledgement and every item independently. An item that cannot fit is not skipped; emit a fixed error item when representable and terminate the stream/connection so the client resumes from its last delivered sequence. |

Fallback strings are SDK-owned constants and must not incorporate backend or
peer-controlled text. Rejected nested replication trees are still consumed
iteratively, preserving the depth/node work bounds and non-recursive disposal.

`conservative_payload_budget(frame_size)` is exactly
`frame_size.saturating_sub(8192) / 8`: one 8 KiB block is reserved for the
record/key/error envelope, and the factor of eight covers a worst-case JSON byte
array (four encoded bytes per payload byte) plus equal metadata/escaping
headroom. The transported capability is the minimum of the backend limit and
this calculation for both `accepted_response_frame_size` and
`server_request_frame_size`, never the raw frame size. It is therefore
executable for a real maximum-sized write/read round trip under unequal limits.
At the exact 8 KiB protocol minimum the conservative payload budget is zero;
the minimum guarantees room for maximum-profile metadata/envelopes, not a
non-zero application payload. Configure a larger frame for payload-bearing
traffic. The 1 MiB default advertises 130,048 payload bytes; the 16 MiB ceiling
advertises 2,096,128 bytes. Advertising SQLite's full 1 MiB value limit needs
at least 8,396,800 frame bytes, so 16 MiB is the recommended setting for that
profile. The ceiling is per frame, not aggregate admission: at the default 128
connection slots, simultaneous ceiling-sized encodes can retain about 2 GiB
before chunk metadata, TLS, and runtime overhead. The aggregate scales with
`with_max_connections`; #143 owns aggregate byte permits and distributed
resource/soak qualification. The capability remains descriptive rather than
readiness or quorum authority.

A backend mutation can commit before response serialization or socket delivery
fails. An outbound rejection, disconnect, or write timeout therefore makes the
mutation outcome ambiguous; it does not prove rollback. Callers must use the
operation's existing idempotency/fencing contract, re-read authoritative state,
and never blindly replay a lease or mutation merely because no response arrived.

Operational diagnostics use the finite `response_family` values in the table
and fixed reasons such as `frame_too_large`, `page_shortened`, `write_timeout`,
`transport`, and `encoding`. Outbound-bound logs and metrics must not include
session keys, payloads, owners, transaction/request IDs, SPIFFE IDs, backend
error text, or peer-controlled strings. This crate does not promise a new
metrics-export API; #143 qualification must demonstrate bounded counters,
memory, tasks, file descriptors, and CPU under repeated oversize and slow-reader
campaigns.

## Relationships

- The default consensus transport implements `SessionConsensusPeer` and serves
  only a `SessionConsensusRpcHandler`. It supplies remote peers to
  `ConsensusSessionStore`; it is not a backend nested under that store.
- The feature-gated legacy `RemoteSessionBackend` implements session backend
  and lease traits only for controlled migration and compatibility work. It
  cannot become a member or vote in descriptor-only Openraft topology.
- Uses the opaque authenticated client/server configs from `opc-tls` for
  production mTLS transport. The consensus and legacy compatibility profiles
  set and require separate exact ALPN values.
- HA-shaped composition admits descriptor-only `ValidatedQuorumTopology` and
  separately supplies the local SQLite backend plus exact consensus peer map.
  Logical replica ID, dial endpoint, expected TLS identity, failure domain,
  backing identity, and exact local self remain independent descriptor fields.

## Authentication lifetime and seamless credential rotation

Authenticated direct and consensus transports use one validated
`ConnectionLifecyclePolicy` on clients and servers. The defaults are a 15-minute
maximum authentication age, a 30-second drain window, 50 ms through 1 second
bounded reconnect backoff, and up to 30 seconds of stable directed-peer
rotation jitter. A connection's hard deadline is the earliest of its maximum
age, the earliest expiry in the local presented certificate chain, and the
earliest expiry in the peer presented certificate chain. Every certificate
configured/presented in an SVID chain contributes to that bound, including a
redundantly presented root. Production SVID chains should omit the trust anchor,
so this normally means the leaf plus its presented intermediates. Certificates
that appear only in a configured trust bundle are not independently scanned,
and the time an anchor is removed is not an expiry-deadline input. Retirement
begins one drain window before that hard deadline, or immediately when less than
one drain window remains.

At TLS completion the transport retains exact monotonic deadline evidence for
both presented chains and the coherent `TlsMaterialEpoch` admitted by
`opc-tls`. A later material epoch, or
`SessionReauthenticationControl::request_reauthentication`, starts cooperative
retirement after the configured stable jitter. Configure a shared control with
`with_reauthentication_control`, and configure non-default finite bounds with
`with_connection_lifecycle`, on every client/peer and listener that must rotate
together.

The bounded same-issuer credential-compromise/revocation mechanism is
short-lived SVID expiry, not material rotation or connection reauthentication.
Choose the SVID validity bound as the maximum acceptable exposure window.
Publishing replacement material and retiring connections moves cooperative
participants to the replacement, but does not revoke the old certificate/key:
its holder can establish a fresh connection until the earliest expiry in that
old presented chain while its issuer remains trusted. The transport does not
implement immediate generic CRL, OCSP, certificate/identity denylist, or other
selective same-issuer revocation. Removing a root is instead a trust-anchor
cutover for every chain that depends on it; it rejects those chains on later
full handshakes and, with reauthentication, drains connections established
under the previous trust material. Root removal is not a certificate-expiry
deadline.

Retirement has these invariants:

- no request is assigned or dispatched after its connection's soft retirement
  boundary;
- work already admitted may return once before the hard deadline; at that
  deadline the transport stops waiting, closes the connection, releases its
  slot, and reports a typed ambiguous mutation outcome where an effect may
  already have crossed the backend boundary;
- dropping the backend future requests cancellation but does not prove
  rollback: a bounded supervised mutation may finish after transport closure,
  so callers never automatically replay it and must authoritatively re-read or
  use its operation-bound idempotency/fencing contract;
- a replacement repeats TCP resolution, mutual TLS, canonical SPIFFE identity,
  nonce/challenge, ALPN, version, and exact contract-profile checks;
- a consensus connection is cached only after a complete correlated successful
  response passes wire validation; a typed failed response, cancellation, or
  every uncertain stream position leaves the slot empty, and a subsequent
  Openraft retry reconnects without an implicit transport replay;
- after mutual TLS and before acknowledgement, a complete generic
  `BootstrapResponse::ConnectionRetiring` result proves server admission did
  not occur; the sequential client has not yet sent application request bytes.
  The consensus bootstrap context reserves
  `SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)`
  for the equivalent state before any Openraft request bytes. Ordinary
  authentication, identity/scope, contract, protocol, and post-bootstrap
  engine rejections remain distinct and are never reclassified as this
  rotation control;
- the fixed, fully decoded `ConnectionRetiring` response proves that a legacy
  direct mutation was not dispatched after bootstrap and is therefore the only
  post-bootstrap retirement signal that permits an automatic mutation retry;
  EOF, a partial frame, or a generic error remains an ambiguous mutation
  outcome;
- if an acknowledgement write has partially completed when rotation is
  observed, the server closes without appending a second frame; the client
  treats that incomplete stream as a failure, never as a no-dispatch proof;
- a caller-visible legacy watch survives planned retirement and resumes from
  checked `last_delivered_sequence + 1`; a partially read item stays on the old
  connection, the cursor advances only after caller delivery, and overflow,
  compaction/permanent errors, cancellation, and slow consumers terminate
  explicitly.

This is credential continuity, not protocol negotiation. The move to direct
wire-schema revision 6 is still a coordinated drained stop/upgrade/start of
every participant. After the fleet is uniformly on revision 6, leaf and trust
rotation uses the lifecycle above without a protocol downgrade or plaintext
fallback. The bootstrap retirement control does not advance the direct or
consensus profile revision and does not change the public API, but an older
same-profile decoder fails closed rather than treating the new control as an
acknowledgement. Mixed-patch rolling rotation is therefore not seamless.
Persistent formats and Openraft authority are unchanged. Session payload
protection and HKMS placement are also unchanged: encryption remains above
consensus and the network lifecycle never receives plaintext, provider handles,
or raw key material.

The server records a connection-attempt `success` only after completely writing
the bootstrap retirement control; the client records its own `success` only
after decoding the complete control. In both cases `success` means authenticated
transport/control completion rather than application admission. That decode
initiates the client's existing bounded deadline/backoff path and records a
reconnect `attempt`. The client records no reconnect `failure` or
connection-failure outcome for the complete control. EOF and incomplete
controls retain their ordinary transport/protocol failure accounting.

This closes only the narrow authenticated post-TLS/pre-acknowledgement rotation
race. It does not complete #164's remaining multi-process trust-removal,
short-lived-SVID, reconnect-storm, resource, or soak qualification.

The exporter provides only closed, low-cardinality lifecycle dimensions:
`opc_session_net_connection_retirements_total{reason}`, current
`opc_session_net_connection_lifecycle{state}`,
`opc_session_net_connection_drain_events_total{event}`,
`opc_session_net_connection_attempts_total{outcome}`,
`opc_session_net_reconnect_events_total{outcome}`, and
`opc_session_net_watch_slow_consumers_total`. Their fixed labels contain no
endpoint, SPIFFE ID, certificate, key, transaction, or payload text.

## Status Notes

- `publish = false`.
- The transport is experimental.
- Production client and server construction requires opaque
  `AuthenticatedClientConfig`/`AuthenticatedServerConfig` values built by
  `opc-tls`; raw Rustls configs cannot enter these constructors.
- Plaintext client/server support is test-only and gated behind
  `insecure-test`.
- The wire contract version is `5`; the default max frame size is 1 MiB and the
  exact negotiated ceiling is 16 MiB.
- Protocol v5 uses `u32` for restore/log request limits and the client restore
  response budget; a confidential authenticated strictly bounded restore cursor;
  `u64` excluded counts,
  `max_value_bytes`, and size-bearing `StoreError` fields; and checked
  conversion at both domain boundaries. Non-representable values fail before
  backend dispatch or caller exposure. The negotiated frame-size limit remains
  a separate encoded-byte bound and now covers every ordinary response/watch
  item under one absolute write deadline.
- The v5 handshake extracts the canonical SPIFFE URI from the live peer
  certificate and requires it to match the claimed stable `ReplicaId` in the
  manifest. Client and server also verify the expected opposite replica,
  cluster ID, and configuration ID; the client verifies its fresh challenge is
  echoed by the server. Wrong, missing,
  ambiguous, malformed, cross-cluster, or stale configuration identities fail
  before backend dispatch.
- Session-net disables TLS session caches, tickets, resumption, early data, and
  0-RTT. Every reconnect pays for a full mutual-TLS handshake so SVID rotation
  cannot reuse a cached peer certificate or authority decision.
- Authenticated connections now retire at a finite age, exact earliest
  local/peer presented-chain expiry, material-epoch change, or explicit
  reauthentication request. Both sides stop new admission at the soft boundary,
  bound the transport wait and
  connection-slot lifetime by the hard deadline, and reconnect through a
  complete mutual-TLS/application handshake. An already-admitted supervised
  backend mutation may still finish later and therefore remains typed
  ambiguous and non-retryable. Legacy watches resume from the exact delivered
  cursor. Scoped real-mTLS tests cover retained connections and continuous
  request/watch recycling. An in-process three- and five-voter Openraft/SQLite
  campaign additionally exercises one-member-at-a-time leaf, presented
  intermediate, and root changes; overlap-first rollback before and after old
  trust removal; fresh directed mutual-TLS handshakes and durable probes; old
  root rejection; and an encrypted acknowledged canary. It is SDK-generated
  loopback evidence, not the independent multi-process qualification profile.
  #164 and #143 still own unavailable-member/malformed-reload, short-lived-SVID
  expiry, partition/restart, continuous mixed traffic/watch, reconnect-storm,
  resource, soak, deployed-network, and signed release evidence. Any production
  acceptance criteria must explicitly acknowledge that immediate generic
  revocation remains unsupported. The 365-day session TTL remains unrelated to
  certificate lifetime, trust-bundle lifetime, or authentication age.
- The configuration ID is a SHA-256 digest of the cluster ID, explicit
  generation, and the full sorted descriptor set. Changing a member ID,
  endpoint, TLS identity, failure domain, backing identity, cluster, or
  generation changes the authenticated scope.
- Protocol v5 has no production fallback. The exact
  `opc-session-net/5` ALPN, version, and contract profile require a coordinated
  stop/upgrade/start of every session-net participant; mixed-profile fleets are
  unsupported and there is no highest-common-version downgrade negotiation.
  `Hello` and `HelloAck` gain optional `contract_profile`, exact
  `configuration_epoch`, and directional-frame fields; `HelloAck` also gains
  `cas_idempotency_epoch`, and direct CAS gains `idempotency_epoch`. These are
  Rust source breaks for exhaustive construction and matching
  even though public `Request`/`Response` remain available. Revision 2 also
  adds public `ContractProfile::max_frame_size`, so external profile struct
  literals and exhaustive destructuring must be updated in the same
  coordinated change.
- The v5 profile pins wire-schema revision 6 and error-set revision 8;
  `max_restore_scan_page_payload_bytes = 4194304`;
  `max_restore_scan_examined_rows = 4096`;
  `min_frame_size = 8192`; `max_frame_size = 16777216`; the 128-byte
  owner/custom-key/state-type rules;
  `stable_id_max_bytes = 64`; `replication_tx_id_max_bytes = 128`;
  `cas_request_id_bytes = 36`; depth-16/256-node replication trees; the
  31,536,000-second TTL maximum; and the collection limits above. Transported
  stable IDs must contain 1 through 64 bytes, replication transaction IDs must
  contain 1 through 128 UTF-8 bytes, and CAS request IDs and process epochs,
  when present, must be
  canonical lowercase hyphenated UUIDs with the exact 36-byte encoding. A version or
  profile mismatch is rejected before backend dispatch.
- #135 kept the JSON shape of valid v3 owner and session-key type values as a
  string, but tightens semantic admission: owner IDs and custom key-type names
  must contain 1 through 128 UTF-8 encoded bytes. The five reserved key-type
  strings decode only to their canonical well-known variants; custom values
  are structurally wrapped and ordered by canonical string. This is also a
  Rust source break because `SessionKeyType::Other(String)` becomes
  `Other(CustomSessionKeyType)` and `SessionKeyType::other` is fallible. A
  pre-v4 peer built before #135 can still send an empty or oversized value
  that a new peer rejects before dispatch, so unchanged valid JSON shape is not
  a rolling-compatibility claim.
- Treat every v5 exact-profile migration through wire-schema revision 6 and
  error-set revision 8 as a
  coordinated stop/upgrade/start boundary. Drain
  traffic and writers, audit every persisted SQLite replica with the count-only
  `opc-session-store-audit identity-invariants` command, and separately
  preflight every live/replayable handover payload and nested payload-protection
  boundary. Upgrade all clients, servers, protection wrappers, and product
  handover readers/writers together; verify authenticated handshakes and
  representative v5 restore/log reads, including an empty advancing sparse
  page and rejection of a modified cursor; and only then restore traffic. The
  fixed-width DTO and handshake now state the #135 admission contract
  explicitly, and revision 2 adds the exact directional response/request
  budgets and replication-transaction-ID/CAS-request-ID wire containment.
  #167 promotes stable-ID admission to the shared model/store contract. The
  audit and runtime never
  truncate, rename, or rewrite rejected identities or log entries, and their
  errors do not expose the rejected raw value.
- Before enabling revision 2, inventory every retained record, replication log,
  snapshot, restore source, and replay source for empty or over-limit stable and
  transaction IDs. A migration must be decoder-first: while writers are
  quiesced, install or run a reviewed reader that can decode the legacy retained
  representation before it rewrites or replaces any data; apply the
  product-aware semantic policy from #167 (stable IDs) and the
  [#168 durable transaction-ID runbook](../../docs/session-store-replication-tx-id-migration.md);
  verify that the strict revision-2 decoder accepts the
  result; only then start revision-2 writers. Never truncate, hash, or rename a
  durable key or idempotency identity as an implicit transport fix.
- Once a live or replayable `OPCH` envelope has been written, a v3 rollback
  requires a coherent drained pre-upgrade checkpoint restore or a reviewed
  reverse migration of every live record, log, snapshot, and restore source.
  Protocol negotiation cannot make the opaque handover format backward-readable.
- #159 itself does not rewrite the persisted record/log representation. An
  already in-profile store needs no format conversion, but an out-of-profile
  retained stable or transaction ID is not made safe by that fact: it must be
  handled through #167/#168 before strict revision-2 transport starts. Rolling
  back requires a drained, coordinated fleet at one exact profile and a
  rollback-side decoder capable of reading the retained target representation
  before old writers restart; otherwise restore a coherent checkpoint or run a
  reviewed reverse migration. Revision-1 and revision-2 peers fail closed
  rather than interoperate. Rollback across `OPCH`/#135 retains its independent
  checkpoint/reverse-migration requirements.
- DNS names and resolver overrides select only where to dial. FQDN, short-name,
  IP, and alias changes do not alter the expected `ReplicaId`, certificate
  SPIFFE identity, or manifest scope.
- `capabilities()` is descriptive admission evidence. Clean transport loss or
  timeout may fall back to a previously successful exact-v5 negotiation while
  masking operations such as restore scan that require a fresh handshake. A
  cache entry is keyed by the exact profile plus negotiated request/response
  limits; a successful reconnect with different limits clears it before a new
  maximum is advertised. A
  fresh negotiation that fails authentication, version/profile comparison, or
  malformed/relabelled acknowledgement clears the entire cache and returns all
  capability booleans false with `max_value_bytes = 0`. Neither cached nor
  cleared capabilities authorize an operation or readiness: replicated callers
  must use the fresh replication-head probe and require a distinct agreeing
  majority.
- Legacy remote adapters bind local/remote IDs, expected TLS identity,
  descriptor fingerprints, member count, and compatibility configuration
  scope during their own handshake. That binding never grants an Openraft vote
  and is not consumed by `ValidatedQuorumTopology`.
- Consensus peer binding is static admission evidence, not current health.
  Capability declarations and a successful handshake do not replace
  `ConsensusSessionStore::probe_durable_readiness` or continuous traffic
  gating. Long-running network/resource qualification remains #143; watch
  handoff and bounded journal cursor/retention semantics are implemented under
  #145/#171.
- Replication entry sequence zero and malformed rebuild prefixes are rejected
  before dialing on the client and before backend dispatch on the server. The
  unit `InvalidReplicationSequence` error contains no peer-controlled data;
  an authenticated server returns it as a typed v5 response and keeps the
  connection usable. This is input-boundary safety, not sequence authority.
- TTL-bearing requests above 365 days are rejected with
  `StoreError::InvalidSessionTtl` or `LeaseError::InvalidSessionTtl` before
  dialing on the client and before backend dispatch on the server. The exact
  maximum is accepted and zero means immediate expiry. The TTL request shape is
  unchanged for entries within the operation-tree contract. The new serialized
  error variants require external exhaustive matches. Their wire representation
  was introduced by v4 error revision 1 and is retained by current error
  revision 8; an error-revision-7 or older peer fails exact negotiation.
  Legacy persisted replication logs must be
  audited before upgrade because an entry carrying a larger TTL now fails
  closed during replay or rebuild rather than being clamped. Cross-field
  validation permits at most one microsecond of positive absolute-deadline
  drift solely for legacy `seconds_f64` rounding; new deadlines remain exact,
  the TTL maximum is unchanged, and larger mismatches fail closed.
- Replication operation trees are validated iteratively and fail with the
  fieldless `StoreError::ReplicationOperationLimitExceeded` when any entry
  exceeds depth 16 or 256 total nodes. Outbound clients reject before
  resolution/dialing; authenticated servers reject decoded requests before
  backend dispatch; clients validate complete returned pages/items before
  caller exposure. A typed rejection does not consume the connection.
- Protection wrappers above the transport encrypt or remotely seal every
  nested replicated CAS before replicate/rebuild delegation and decrypt or
  unseal every nested CAS from log/watch reads. Provider calls are sequential,
  and transformation is staged: a late provider failure may follow earlier
  provider calls, but causes no backend delegation on writes and exposes no
  partially transformed entry/page on reads.
- This was a breaking same-v3 confidentiality boundary before v4. An older v3
  peer cannot decode the new error, and an older wrapper
  can still forward a deeply nested CAS without protection. Mixed SDK versions
  are therefore not confidentiality-safe. Protocol v4 rejects the older wire
  participant and pins both tree limits and error revision, but it does not
  attest that an encryption/sealing wrapper is actually wired. Drain and
  upgrade every client, server, and wrapper participant as one coordinated
  fleet and verify the product composition before restoring traffic.
- Existing logs are not scrubbed automatically. Audit tree shape and payload
  encoding offline before upgrade. A plaintext/unsealed nested CAS within the
  new limits may use an explicit wrapper-mediated rewrite/rebuild. A historical
  over-limit entry is rejected before transformation and cannot be ingested
  unchanged; use a separately audited semantic-preserving offline migration or
  replace the store before starting the new SDK. Never clamp or split the entry
  ad hoc; a raw inner-backend rebuild preserves the protection gap.
- Remote scan and fresh-probe transport parity do not by themselves qualify
  networked session HA for production. Protocol v5 authenticates membership;
  it does not establish consensus, fork reconciliation, or
  majority-authoritative restore. The separate consensus ALPN supplies durable
  sequence/commit authority under #127 and bounded applied-state restore under
  #133; #128 current-format reconciliation and #129 bounded legacy recovery
  are implemented. #134's fixed-width boundary and #135's
  model-level decode boundary are implemented but do not provide any of those
  distributed properties.
- #159 contains stable IDs and replication transaction IDs at the wire
  boundary. #167 supplies the production stable-ID contract. #168 now makes
  the 1-through-128-byte transaction-ID invariant structural across the model,
  persistence, recovery, and wire DTO; new coordinator writes use fixed
  32-byte lowercase hexadecimal IDs while valid legacy strings remain exact.
  Its version-3 audit and coordinated migration must be used with #128/#143.
  #177 removes `opc-persist`'s private config TCP
  path and composes config consensus through these shared peer/handler ports;
  it does not define a second deadline or credential lifecycle.

## Roadmap

- Retain #171's bounded cursor contract and add distributed
  failure and soak evidence. Connection continuity, bounded authentication age,
  and full-handshake reauthentication are implemented; complete fleet
  trust-bundle overlap/removal, short-lived-SVID expiry and compromise response,
  reconnect-storm, multi-process/deployed-network, payload-protection-key, and
  production qualification evidence remains under #164/#143. Close those
  evidence gates before treating this as production transport.
- Keep plaintext transport limited to tests.
- Keep the compatibility server wrapping `SessionStoreBackend` rather than
  owning storage; production authority uses only `SessionConsensusServer`.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, client, server, protocol, and
  tests.
- `tests/authenticated_replica_identity.rs` covers exact v5 profile/identity,
  routing aliases, certificate/claim/scope mismatches, downgrade and malformed
  Hello, local and peer leaf-expiry retirement, overlapping trust rotation,
  old-trust rejection, fresh nonce/profile/ALPN checks on
  replacements, relabeling, and replayed challenge responses over mTLS.
- `opc-tls/tests/material_epochs.rs` proves effective configured/presented-chain
  expiry across a real mutual-TLS handshake, and `src/lifecycle.rs` unit tests
  prove the corresponding local/peer retirement deadlines and fixed metric
  reasons. This component evidence is not a fleet rotation test.
- `tests/consensus_transport.rs` covers the shared consensus-only ALPN,
  complete call deadlines, scope binding, validated steady-state connection
  reuse, cancellation/timeout/dead-socket eviction, exact replacement after an
  explicit generation or material epoch, finite cached-connection retirement,
  renewed SVID handshakes, wrong rotated identities, rejection of legacy
  backend authority, the 1,500 ms contained cold cap, and every 2/5/10-second
  family. It forms a real three-node `ConsensusConfigStore` over the existing
  mTLS peer/server, restarts a follower listener, injects a persistent 500 ms
  cold delay, and proves same-leader, same-term
  catch-up/readiness/linearizable read within 10 seconds without a preflight.
  Its bounded session-store rotation case also forms real three- and five-voter
  Openraft/SQLite fleets over the production mTLS peer/server, executes forward
  and rollback trust procedures, and preserves an encryption-wrapper canary
  through every phase. It does not emit the `opc-session-testkit` evidence
  schema and does not change `foundation_counts_for_tls_rotation = false`;
  out-of-process deployment and the remaining #164/#143 matrix are still
  required.
- `tests/three_node_quorum.rs` covers typed TTL and replication-tree-limit
  rejection before resolution and authenticated server dispatch, plus
  connection reuse after rejection, deterministic listener/handler teardown,
  and cached descriptive capabilities that cannot authorize operations after
  fresh quorum loss. Client/server suites also cover malformed log/watch output
  rejection before caller exposure and cache clearing after invalid fresh
  negotiation.
- Required outbound-boundary evidence covers exact-limit/one-byte-over responses across
  get/CAS/batch/lease/log/restore/watch families, unequal negotiated limits,
  conservative maximum-payload round trips, fixed redaction-safe fallbacks,
  slow-reader deadline reaping, connection-slot recovery, and deterministic
  shutdown while a write is blocked.
- Run with: `cargo test -p opc-session-net --all-features`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
