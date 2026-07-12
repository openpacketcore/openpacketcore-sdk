# ADR 0002: Config Store Consensus HA

## Status

Accepted

## Date

2026-06-08

Amended 2026-07-12 for the logical RPC deadline, retry, fan-out, observability,
and identity-rotation contract.

## Context

Single-node SQLite persistence is not acceptable for carrier HA configuration
claims. The SDK needed a config-consensus hardening path toward production
with leader fencing, majority commit behavior, restart recovery, and
authenticated transport. It also needed to make clear that standalone SQLite remains a
development, lab, conformance, or explicitly accepted edge/single-replica
profile. A per-I/O-stage timeout was also insufficient: repeated timeout
budgets and retry sleeps could make one peer call many times longer than its
configured value, and sequential fan-out could multiply that again.

## Decision

The SDK's high-availability configuration-persistence hardening prototype is
`ConsensusConfigStore`. It is not carrier-production qualification by itself.

The consensus backend uses:

- Durable cluster membership and node identity checks.
- Leader election, current-term no-op gating, and majority write commitment.
- Linearizable read verification instead of follower-local reads.
- Authenticated mTLS/SPIFFE transport using shared identity/TLS substrates.
- One checked absolute logical deadline per client RPC, covering local
  authentication/TLS setup, bounded cooperative encoding, TCP, mTLS, write,
  response reads/decode, no more than three attempts, and retry backoff. Zero
  expires before I/O and unrepresentable monotonic-clock durations fail closed.
- Request-aware retry ambiguity: vote/append/snapshot coordinates and read RPCs
  may be replayed, while `TimeoutNow` is not replayed after possible delivery;
  permanent local identity and certificate-verification failures fail
  immediately.
- Concurrent election and replication fan-out across peers. Per-peer catch-up
  is capped at 64 sequential catch-up rounds per pass or trigger and
  resumes from `next_index` on a later trigger. A rejected snapshot can fall
  through to one append in the same round, so the pass ceiling is 128 logical
  RPCs.
- Controlled TCP server lifecycle with 100-handler concurrency, a five-second
  TLS-accept timeout, 16 MiB request/response frame bounds, and explicit
  listener shutdown. Post-handshake request reads and response writes do not
  currently have an independent server-side I/O deadline; the client logical
  deadline is not evidence of that server property.
- Snapshot persistence and HMAC verification.
- Non-voter catch-up and promotion guards for membership changes.
- A typed logical-timeout count split by fixed low-cardinality request-family
  and failure-stage dimensions, plus chaos/failover/stall/cancellation tests.
- Live `set_identity` replacement for new connections/attempts. Production CNF
  operators must watch identity and bundle changes, roll out old/new trust
  overlap before leaf replacement, preserve the exact SPIFFE/node identity,
  drain old connections, verify fresh quorum handshakes, and retire old trust
  only after the maximum authentication age. The test-node binary's startup-only
  PEM loading is not a rotation controller.

## Consequences

Config HA is a quorum system, not a property of SQLite. Any production claim
must use the consensus backend or an equivalent adapter that satisfies the same
contract.

The SDK accepts additional operational complexity so correctness is explicit:
membership, certificates, node identity, quorum availability, and recovery
state all become deployment responsibilities. Election fan-out is bounded by
one peer logical deadline because peer requests are concurrent. A single
lagging peer's catch-up pass can consume up to `128 * peer timeout`, plus local
database and scheduling work, before a later trigger resumes it.

Operators must distinguish client and server timing guarantees. The logical
deadline bounds a client call and cancellation; it does not claim that every
post-handshake server read/write has an idle deadline. Operators must also use
the typed `rpc_timeouts`, `rpc_timeouts_by_family`, and
`rpc_timeouts_by_stage` surfaces without adding identity or endpoint labels.

Changing from per-stage resets to one logical deadline is intentionally
breaking. Operators must retune and coherently roll out the end-to-end timeout
with matching election/failover/drain budgets. The new public
`PersistErrorKind::ConsensusRpcTimeout` also requires downstream exhaustive
matches to be updated.

## Evidence

- `crates/opc-persist/src/consensus/transport.rs`
- `crates/opc-persist/src/consensus/election.rs`
- `crates/opc-persist/src/consensus/replication.rs`
- `crates/opc-persist/tests/consensus_tests.rs`
- `crates/opc-persist/tests/tcp_consensus_deadline.rs`
- `crates/opc-persist/tests/consensus_rpc_fanout.rs`
- `docs/ha-design.md`
- `docs/consensus-operator-runbook.md`
