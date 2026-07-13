# ADR 0003: Session Store Openraft Replication

## Status

Accepted

## Date

2026-06-08

Amended 2026-07-12 by #127.

## Context

Authoritative telecom session state cannot rely on single-node storage,
wall-clock last-writer-wins, or best-effort replica repair. Session records need
monotonic fencing, compare-and-set semantics, TTL handling, watch resume
support, and stale replica recovery.

## Decision

Authoritative session HA uses Openraft as its only election, vote, log-matching,
commit, membership, and linearizable-read authority. `ConsensusSessionStore`
is the production adapter; `QuorumSessionStore` is a compatibility type alias
to that same implementation and is not a second consensus algorithm. The
previous majority-visible-prefix coordinator is removed.

The target session-store contract includes:

- A validated immutable topology: stable logical replica IDs, canonical network
  endpoints, expected TLS identities, unique failure/backing identities, one
  exact local logical ID, and a cluster/configuration/epoch identity whose
  descriptor digest exactly matches the admitted set. Logical IDs are never
  inferred from endpoint strings. Stable Openraft node IDs are cluster-scoped,
  nonzero, SQLite-safe signed-64-bit values derived from logical replica IDs;
  adding, removing, or reordering another member does not renumber them.
- Monotonic fences and CAS for authoritative writes.
- Durable Openraft vote, log, committed/applied/purged, membership, request
  outcome, and snapshot metadata, plus a committed 1-based application journal
  for lease acquire, renew, release, CAS, delete, TTL refresh, and batch
  operations.
- One public 365-day maximum for `Duration`-based session refresh and lease
  TTLs, with zero accepted as immediate expiry and exact checked deadline
  arithmetic at every direct, nested, persistence, quorum, and transport
  boundary.
- Structural owner and session-key identities: owner IDs and custom key-type
  names contain 1 through 128 UTF-8 encoded bytes; reserved key-type strings
  have one canonical well-known representation; ordering follows the persisted
  string; and model, persistence, and transport decode all fail closed.
- Bounded iterative replication trees: depth 16 from a depth-1 root and 256
  total operation nodes per entry, counting every node including `Batch`.
- Encryption/sealing before `client_write` and decryption/unsealing only above
  the consensus adapter. Openraft logs, RPCs, follower apply, replay, outcomes,
  and snapshots contain opaque envelopes, never plaintext or HKMS/key-provider
  handles.
- Durable request IDs and semantic request digests. A response-loss retry,
  including after leader change, returns the original committed outcome;
  reusing an ID for different intent fails closed.
- Openraft log reconciliation from committed authority. The SQLite adapter
  rejects truncation at or below its persisted committed/applied floor,
  rejects stale or cross-identity snapshots, atomically installs one validated
  state-machine image, and cleans bounded interrupted staging on restart.
  Persisted data created by the removed legacy coordinator uses #129's
  explicit offline campaign because that format cannot prove which divergent
  suffix was committed.
- Watch/change-stream resume cursors.
- Fail-closed no-quorum handling. Openraft may have committed before response
  delivery fails, so clients retry the same durable request ID or perform a
  linearizable read; they never infer rollback from a missing response.
- Truthful capability reporting so standalone SQLite does not claim replicated
  behavior.
- Fresh, bounded durable readiness through the same Openraft linearizable-read
  barrier and local apply wait used by real operations, independent of a bound
  listener or cached capability declarations.

Configured topology admission now rejects empty/even/undersized or over-31 HA sets,
missing or ambiguous self, and duplicate declared identities before I/O. The
topology is descriptor-only; each node supplies its one local SQLite backend
and exact remote consensus-peer map separately, so remote votes do not require
dummy storage adapters or the legacy remote-backend protocol.
`ValidatedQuorumTopology::try_new_consensus_lab_singleton` is a separate
one-replica Openraft profile that reports `single-replica`, never HA, while
exercising the same durable engine and state machine.

Production replication uses `SessionConsensusServer` and
`RemoteSessionConsensusPeer` on the exact `opc-session-consensus/1` ALPN. One
immutable consensus identity binds the cluster ID, descriptor-derived
configuration ID, and monotonic epoch into topology, storage, snapshots, and
every RPC. Before Openraft dispatch, both sides extract the canonical SPIFFE
URI from the live certificate and require it to match the logical `ReplicaId`,
stable node ID, expected opposite member, cluster, configuration, epoch, RPC
sender, server profile, and fresh challenge. DNS/FQDN/IP aliases remain routing
inputs only. The legacy writable backend protocol is not a production HA
authority and is isolated behind an explicit compatibility surface.

TLS session caches, tickets, resumption, early data, and 0-RTT are disabled;
every reconnect performs a full mutual-TLS certificate exchange so rotated
SVIDs cannot inherit cached replica authority.

That reconnect rule is necessary but not sufficient for production rotation.
The qualified CNF/operator profile must rotate workload certificates and trust
bundles seamlessly, without interrupting session service, while proving trust
overlap, revocation, retirement of long-lived connections, reconnect-storm
behavior, and a documented maximum authentication age. This evidence remains
open in #143. Session/lease TTL is an application-state lifetime and does not
set certificate expiry, trust-bundle validity, or authentication age.

Transport authentication does not replace topology admission or prove physical
store provenance. The operator must still map each logical member to exactly
one persistent backing store and reject duplicate stable node-ID derivations.

`probe_durable_readiness` supplies fresh, bounded point-in-time evidence without
consulting cached capabilities. It calls Openraft's linearizable barrier and
waits for local state-machine application through the returned log ID.
Authoritative reads perform that same barrier; writes use `client_write`.
Listener readiness therefore cannot disagree with the store merely because a
server socket is bound.

The SDK state machine, rather than a competing quorum algorithm, deterministically
applies session commands, advances leader-selected logical time, maintains
fences and the committed application journal, and publishes watch events only
after commit. Direct log append, whole-state rebuild, and caller-selected lease
sequence APIs fail closed on `ConsensusSessionStore`.

The encryption boundary is deliberately above consensus:
`application -> EncryptingSessionBackend/RemoteSealingSessionBackend ->
ConsensusSessionStore -> Openraft/storage`. Encryption completes before
`client_write`; follower apply, replay, snapshots, and quorum recovery operate
only on opaque envelopes and never call HKMS. Reads use the outer wrapper to
resolve the envelope's historical key. Tests inject plaintext and raw-key
canaries through the actual wrapper and prove they are absent from consensus
RPC payloads, SQLite/Raft log and outcome tables, WAL/SHM files, and snapshots;
they also prove restart, snapshot install, and active-key rotation preserve
decryptability without provider calls inside consensus.

This contract encrypts record payloads, not the entire database. Membership,
log indexes, tenant/key routing fields, owners, fences, timestamps, envelope
key IDs, and other SQLite/Raft metadata remain visible to the host storage
boundary. Full-file or metadata confidentiality requires a separate approved
storage layer and must not move nondeterministic key-provider calls into the
replicated state machine.

The current networked profile remains experimental, not yet a production HA
qualification claim. #127 establishes durable commit/sequencing authority with
Openraft and removes the custom session quorum algorithm. #128 hardens and
qualifies current-format Openraft follower recovery without adding another
repair authority. #129 adds a default-deny, audited offline legacy-fork
campaign: it binds a full-fleet plan, quarantines every explicitly selected
PVC, installs one immutable operator-selected checkpoint on the whole legacy
voter set, and commits fencing only through Openraft. See the
[legacy recovery runbook](../session-store-legacy-recovery.md). #133 adds
bounded local applied-state restore with an
AEAD-sealed composite-key seek cursor, bounded candidate work, and prompt
SQLite cancellation. It adds no remote quorum, digest comparison, or Merkle
authority; neither recovery path becomes a second runtime consensus authority.
Fixed-width private wire DTOs and checked domain conversion are implemented
under #134. Invariant-safe owner/key model decoding, bounded count-only SQLite
admission, and typed-invalid handover rejection are
implemented under #135; checked TTL rejection is implemented under #137, and
malformed sequence zero, checked increment, rebuild-prefix, SQLite
signed-boundary, cache, and authenticated wire rejection are implemented under
#138. Seamless session-net credential/trust lifecycle remains #158, and its
distributed production qualification remains #143.
Watch handoff correctness (#145) and absolute-record-expiry admission (#148)
also remain open. Bounded nested-CAS protection is implemented under #147;
outbound response allocation/frame bounds and slow-reader deadlines are
implemented under #159. Distributed failure/resource qualification remains
#143, and seamless credential/trust lifecycle remains the #162 -> #161 -> #163
-> #158 -> #164 dependency chain. These remaining gates keep the networked
profile experimental.

The v4 wire uses `u32` for restore/log request limits and the client restore
response budget; a confidential authenticated strictly bounded restore cursor;
`u64` excluded counts,
`max_value_bytes`, and size-bearing store errors; and checked conversion before
backend dispatch or caller exposure. It omits restore `loaded_count` and
`complete` and recomputes them after decode. Independent limits admit 256 batch
operations, 1,024 restore records, 65,536 replication-log entries, and 65,536
rebuild entries, in addition to the configured frame-size bound. The exact
profile pins wire-schema revision 3, error-set revision 2, a 4 MiB restore
payload bound, 8 MiB retained-page and examined key/filter-metadata bounds,
`max_restore_scan_examined_rows = 4096`, 128-byte
owner/custom-key/state-type bounds, depth-16/256-node replication trees, and the
31,536,000-second TTL maximum. Revision 2 additionally pins
`min_frame_size = 8192`, `max_frame_size = 16777216`,
`stable_id_max_bytes = 64`,
`replication_tx_id_max_bytes = 128`, and `cas_request_id_bytes = 36`.
Transported stable IDs contain 1 through 64 bytes, transaction IDs contain 1
through 128 UTF-8 bytes, and CAS request IDs, when present, are canonical
lowercase hyphenated UUIDs with the exact 36-byte encoding. Public
`Request`/`Response` remain, but `Hello`/`HelloAck` gain an optional
`contract_profile`; exhaustive construction and matching must account for the
new field. The public `ContractProfile::max_frame_size` field is also a Rust
source break for external literals/destructuring and shares the coordinated
revision-2 deployment boundary.

The cursor is variable-length up to the consensus RPC/key ceiling. Separate
HMAC-derived AEAD and synthetic-nonce keys make identical semantic positions
canonical. Only its cumulative examined-row position is clear and bound into
cursor authentication. That permits a structural check of claimed progress,
not proof of peer completeness; seek and snapshot fields remain confidential.
Cursors survive a same-PVC
restart but are node/incarnation-bound, so another node or installed snapshot
returns typed stale state and requires a first-page restart.

Wire-schema revision 2 adds directional response-budget admission to the exact
v4 handshake. Hello carries the client's requested response frame size; HelloAck
returns the accepted response size (the client/server minimum) and the server's
independent request-frame size. Each is a checked `u32` between
`MIN_NEGOTIATED_FRAME_SIZE` (8 KiB, or 8,192 bytes) and
`MAX_NEGOTIATED_FRAME_SIZE` (16 MiB, or 16,777,216 bytes), and
`MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE` aliases that same minimum.
This makes unequal client/server limits explicit. Revision-1, revision-2, and
current revision-3 v4 profiles are mutually incompatible even though all use
the `opc-session-net/4` ALPN.

Every response and watch item is fully bounded-encoded before any frame prefix
is emitted. Common non-pageable and complete-page successes use one bounded
encode without a sizing preflight. An oversized pageable direct attempt emits
no prefix; bounded logarithmic sizing probes and the final encode reuse one
absolute deadline established before the first encode/probe and continuing
through prefix, payload, and flush. Lazy exact-length boxed chunks are not
coalesced; their total retained encoded-JSON byte storage never exceeds the
negotiated cap. Chunk metadata and allocator slab/RSS overhead remain separate.
The synchronous storage/sizing sinks check deadline and server-abort
cancellation cooperatively between serializer writes/chunks; one bounded
serializer callback is not asynchronously preemptible. A slow reader is
disconnected and its slot is recovered.
Records and positional batch results are never truncated. Restore and log reads
may return only complete cursor/contiguous-sequence prefixes. Watch never skips
an oversized entry; a fixed SDK-owned redaction-safe error is emitted when it
fits and the stream ends, otherwise the connection closes. Nested rejected
entries retain iterative consuming disposal.

Transport capability clamping takes the backend maximum and `(frame - 8192) / 8`
for both the accepted response and server request frames, rather than the raw
frame size. The reserve and factor cover the record/key/error envelope,
worst-case JSON byte-array expansion, and equal escaping/metadata headroom. The
advertised `max_value_bytes` is executable for both directions with unequal
limits. It is zero at the exact 8 KiB minimum; that minimum fits bounded
metadata/envelopes, not a non-zero application payload. It remains
static/descriptive evidence, not quorum readiness.
The 1 MiB default advertises 130,048 bytes and the 16 MiB ceiling advertises
2,096,128. SQLite's full 1 MiB value limit requires at least 8,396,800 frame
bytes, so 16 MiB is the recommended setting for that profile. This remains a
per-frame limit: at the default 128 connection slots, simultaneous
ceiling-sized encodes can retain about 2 GiB before metadata/TLS/runtime
overhead. The aggregate scales with `with_max_connections`; aggregate byte
permits and distributed resource/soak qualification remain #143.

## Consequences

Standalone `SqliteSessionBackend` remains useful as a durable local backend,
but it is not HA. Production CNFs need a separately qualified replicated
profile; #127 provides the correct consensus authority but does not by itself
complete #143's networked production qualification.

The SDK favors fail-closed reads over returning divergent session state when a
majority cannot agree.

`MAX_SESSION_TTL` is exactly 365 days. Zero remains valid as immediate expiry;
larger values return `StoreError::InvalidSessionTtl` or
`LeaseError::InvalidSessionTtl` before application/backend effects. The
implementation converts seconds/nanoseconds and adds deadlines with checked
integer operations rather than floating point or panicking timestamp
  arithmetic. This prevents an oversized direct or authenticated input from
  unwinding a process; Openraft supplies commit proof independently.

The new public error variants require exhaustive callers. Protocol v4
introduced their private fixed-width DTOs in error revision 1; current error
revision 2 retains those encodings and rejects a v3 peer during negotiation.
Operators must first audit persisted legacy
replication logs: a TTL-bearing entry above 365 days now fails closed during
replay/rebuild and is neither clamped nor rewritten automatically. Replicated
deadline validation admits at most one microsecond above exact
`entry.timestamp + ttl` solely for legacy `seconds_f64` rounding; new deadlines
remain exact, the TTL maximum is unchanged, and larger mismatches fail closed.

Under #135, `OwnerId` and custom session-key names accept 1 through 128 UTF-8
encoded bytes. `SessionKeyType::Other` now contains a validated
`CustomSessionKeyType`; reserved names decode only to the canonical well-known
variants, and ordering uses canonical string order. Serde, SQLite hydration,
and session-net decode reuse that admission. Valid identity JSON strings retain their
shape, but Rust construction is source-breaking and semantic admission is
stricter. An older v3 peer may emit values v4 rejects, so all clients, servers,
and wrappers require coordinated stop/upgrade/start. Protocol v4's exact
profile now binds this admission rule.

Existing SQLite replicas must be drained and checked with
`opc-session-store-audit identity-invariants` using explicit non-zero
`--max-rows`, `--max-entry-json-bytes`, and `--max-total-json-bytes` budgets.
The per-entry budget cannot exceed the total or SQLite's signed `i64` length
range.
The read-only/query-only audit scans one snapshot in fixed 256-row pages and
emits version-1 count-only JSON. Only `compliant` with exit 0 passes;
`violations_found`/1, `incomplete`/2, and redacted `error`/2 block upgrade. It
never emits database paths or persisted raw values and never truncates,
renames, repairs, or rewrites state. A violation requires a reviewed
semantic-preserving migration or audited store replacement and a new audit.

New handover envelopes use the `OPCH` magic and an exact version byte. The exact
bounded non-`OPCH` classifier in RFC 004 §10.3 accepts current-valid original
syntax and some bare payloads; ambiguous, truncated, oversized JSON-looking,
malformed, unknown, or typed-invalid claims return a fieldless error before
mutation. Successful detection is not provenance. The identity audit does not
classify live or nested-log payload bytes, so products require the complete
provenance-aware replay preflight. Once any live/replayable `OPCH` copy is
written, old SDKs silently see opaque `Stable` data; downgrade requires a
coherent drained checkpoint restore or reviewed reverse migration of every
record/log/snapshot/restore copy across every handover reader/writer.

This closes the scoped #135 boundary, not production HA. #127 now owns durable
session authority through Openraft; #134 closes the fixed-width legacy wire
boundary only, and #143 still requires distributed and payload-protection-key
qualification. Seamless SVID/trust-bundle lifecycle remains #158.

`MAX_REPLICATION_OPERATION_DEPTH` is 16 and
`MAX_REPLICATION_OPERATIONS_PER_ENTRY` is 256. The root operation is depth 1,
and every node—including `Batch`—counts once. Complete entries, rebuild
prefixes, and returned pages are preflighted iteratively. A violation returns
the fieldless `StoreError::ReplicationOperationLimitExceeded` without revealing
the tree shape.

Protection wrappers transform every nested CAS, not only the root or first
batch level. Replicate/rebuild transformations are fully staged before backend
delegation; log/watch transformations complete before an entry/page is exposed.
Provider calls are sequential. A late provider failure may follow earlier
provider calls, but it causes no backend delegation on writes and no partial
entry/page exposure on reads.

This added a public error variant before the v4 boundary. An older peer cannot
decode it and, more critically, an older wrapper can forward deep
plaintext/unsealed CAS payloads. Protocol v4 rejects the older wire participant
and pins the depth-16/256-node limits and error revision, but it cannot attest
that a protection wrapper is actually installed. All clients, servers, and
wrapper participants require a coordinated upgrade plus composition
verification, not a rolling compatibility claim.

Historical nested plaintext is not automatically scrubbed. Before upgrade,
operators must audit persisted tree shape and payload encoding offline. An
affected entry within the new limits may be explicitly rewritten/rebuilt
through the configured protection wrapper. Over-limit history fails before
transformation and requires a separately reviewed atomicity-preserving offline
migration or audited store replacement before the new SDK starts; it must not
be clamped or split ad hoc. A raw inner-backend rebuild is insufficient.

These guarantees close #147's traversal/confidentiality boundary only. They do
not by themselves establish production HA. #143 remains the distributed and
payload-protection-key qualification owner; seamless
SVID/trust-bundle lifecycle remains #158.

Capability/profile validation and fresh readiness have different scopes. The
former is static admission evidence. A v4 version/profile/authentication or
malformed-handshake failure clears the remote cache and reports every capability
boolean false with `max_value_bytes = 0`; a cache retained after transient
transport loss remains descriptive only. Fresh readiness is a bounded
observation that can become stale immediately, so a CNF must gate traffic
continuously and each authoritative operation must reassess quorum.

Bounded response delivery does not roll back backend work. A mutation may have
committed before encoding, write, or flush fails; the client must treat a
missing response as ambiguous and recover through existing idempotency/request
IDs, fencing, and an authoritative re-read. Diagnostics are limited to bounded
operation-family/reason categories and must not include keys, payloads, owners,
transaction IDs, peer identities, or backend/peer-controlled error text.

The revision-1 to revision-2 transition requires the same drained coordinated
stop/upgrade/start as other exact-profile changes. #159 does not rewrite
persisted record/log bytes, but its stable-ID and transaction-ID rules are
wire-only containment, not a production persistence contract. Before strict
revision-2 startup, quiesce writers and inventory every retained record, log,
snapshot, restore source, and replay source. Any out-of-profile value requires a
decoder-first, product-aware migration or coherent store replacement under
#167/#168: the migration reader must decode the legacy representation before
rewriting it, must not silently truncate/hash/rename durable identities, and the
strict decoder must verify the result before writers restart. Rollback likewise
installs a decoder for the retained target representation before old writers, or
uses a coherent checkpoint/reviewed reverse migration. All participants must
move together; independent `OPCH`/#135 rollback barriers still apply. #167 owns
the production stable-ID model/persistence/privacy/audit contract; #168 owns the
canonical durable transaction-ID type and migration coordinated with
#127/#128/#143.
Session-net's deadline does not fix `opc-persist`'s `TcpPeer::timeout`
per-stage multiplication across up to three attempts with backoff; #169 owns one atomic
end-to-end logical-RPC deadline, safe retry policy, and metrics.
Seamless SVID and trust-bundle lifecycle remains #158; remote-seal
historical-key rotation remains #179; distributed payload-protection and
failure/soak/resource qualification remains #143.

A product composes one descriptor per physical vote. For example, logical self
`epdg-app-0` may select the member whose dial endpoint is the full
`epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local:7443`; the SDK does
not shorten the FQDN or compare it with the logical ID. Any resolver override
changes only where the client connects; the expected replica and SPIFFE
identity remain fixed by the manifest.

## Evidence

- `crates/opc-consensus/`
- `crates/opc-session-store/src/consensus/`
- `crates/opc-session-store/src/sqlite/consensus.rs`
- `crates/opc-session-store/src/topology.rs`
- `crates/opc-session-store/tests/consensus_openraft.rs`
- `crates/opc-session-store/tests/quorum_topology.rs`
- `crates/opc-session-store/tests/encryption.rs`
- `crates/opc-session-store/tests/replication_structure_bounds.rs`
- `crates/opc-session-store/tests/persisted_identity_bounds.rs`
- `crates/opc-session-store/tests/sqlite_identity_audit.rs`
- `crates/opc-session-store/tests/sqlite_identity_audit_cli.rs`
- `crates/opc-session-store/tests/handover.rs`
- `crates/opc-session-net/tests/three_node_quorum.rs`
- `crates/opc-session-net/tests/authenticated_replica_identity.rs`
- `crates/opc-amf-lite/tests/amf_lite_tests.rs`
- `crates/opc-session-store/src/sqlite/mod.rs`
- `crates/opc-session-testkit/`
- `docs/ha-design.md`
- `docs/operator-readiness.md`
