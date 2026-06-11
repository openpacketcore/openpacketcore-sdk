# ADR 0002: Config Store Consensus HA

## Status

Accepted

## Date

2026-06-08

## Context

Single-node SQLite persistence is not acceptable for carrier HA configuration
claims. The SDK needed a production HA config persistence path with leader
fencing, majority commit behavior, restart recovery, and authenticated
transport. It also needed to make clear that standalone SQLite remains a
development, lab, conformance, or explicitly accepted edge/single-replica
profile.

## Decision

High-availability configuration persistence is provided by
`ConsensusConfigStore`.

The consensus backend uses:

- Durable cluster membership and node identity checks.
- Leader election, current-term no-op gating, and majority write commitment.
- Linearizable read verification instead of follower-local reads.
- Authenticated mTLS/SPIFFE transport using shared identity/TLS substrates.
- Controlled TCP server lifecycle with bounded concurrency, read timeouts, and
  explicit shutdown.
- Snapshot persistence and HMAC verification.
- Non-voter catch-up and promotion guards for membership changes.
- Metrics and chaos/failover tests for partitions, restart, rejoin, and stale
  leader behavior.

## Consequences

Config HA is a quorum system, not a property of SQLite. Any production claim
must use the consensus backend or an equivalent adapter that satisfies the same
contract.

The SDK accepts additional operational complexity so correctness is explicit:
membership, certificates, node identity, quorum availability, and recovery
state all become deployment responsibilities.

## Evidence

- `crates/opc-persist/src/consensus.rs`
- `crates/opc-persist/tests/consensus_tests.rs`
- `crates/opc-persist/tests/tcp_consensus_tests.rs`
- `docs/ha-design.md`
- `docs/consensus-operator-runbook.md`

