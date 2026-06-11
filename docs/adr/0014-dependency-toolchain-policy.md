# ADR 0014: Dependency and Toolchain Policy

## Status

Accepted

## Date

2026-06-11

## Context

The SDK is the foundation for downstream CNFs with carrier security and
audit requirements. Every dependency the workspace takes is inherited by
every downstream NF, and several incidents during development showed that
implicit policy does not survive contact with routine maintenance:

- The declared MSRV silently drifted out of truth: routine lockfile updates
  pulled a `getrandom` release whose manifest requires `edition2024`,
  unparseable by the Cargo version the workspace claimed to support — and
  the breakage reached the graph through three independent parents
  (`uuid`, `tempfile`, `quickcheck`), one of them in the production graph.
- An HTTP adapter was nearly built on a second client stack when the
  workspace already standardized on one.
- A license gate failure appeared days after the dependency that caused it,
  because the gate's evidence had been captured before the dependency landed.

## Decision

1. **TLS: rustls only.** No `openssl`/`native-tls` anywhere in the graph,
   including transitively via feature defaults (disable `default-features`
   where needed). Rationale: a single auditable TLS stack, no C toolchain
   coupling, reproducible cross-compilation.
2. **Async runtime: tokio only.** No second runtime, no runtime-agnostic
   abstraction layers.
3. **No gRPC stack (`tonic`/`prost`) in SDK crates.** Internal transports
   (e.g. session replication) use hand-specified framing over the existing
   tokio/rustls stack; external 3GPP interfaces are HTTP/2 (`hyper`) or raw
   protocol codecs. A future exception requires an ADR, not a Cargo.toml
   edit. (An ASN.1 codec dependency for NGAP per ADR 0013 is the kind of
   exception that warrants that process.)
4. **HTTP clients:** `hyper` is the workspace HTTP stack. `reqwest`
   (rustls-backed, built on hyper) is tolerated in leaf adapter crates
   (currently `opc-key-vault`) but must not spread into core crates.
5. **MSRV is the measured floor of the resolved graph, not an aspiration.**
   Currently **1.88** (set by `time`). The CI `msrv` job compiles the whole
   workspace (`--all-targets --all-features`) on exactly the declared
   version; a lockfile update that raises the floor must raise
   `rust-version`, this ADR's record, and the contributor docs in the same
   change. Raising MSRV is acceptable for a pre-1.0 SDK; lying about it is
   not.
6. **Licenses:** Apache-2.0/MIT/BSD-family only, enforced by `cargo deny`
   with a curated allow-list; uncommon-but-permissive licenses are admitted
   as per-crate exceptions in `deny.toml`, never as global allows.
7. **Every new dependency is justified** in the PR description (what it
   replaces, why the existing stack cannot serve, license, MSRV impact).
8. **`unsafe_code = "forbid"` is workspace-wide and non-negotiable**, which
   also rules out FFI-based protocol libraries (see ADR 0013).

## Consequences

- Some integrations cost more to build (hand-rolled framing instead of
  tonic; hyper plumbing instead of convenience clients) in exchange for a
  dependency graph that downstream carriers can audit once and trust.
- MSRV moves forward with the ecosystem rather than pinning old dependency
  lines; downstream consumers should track a recent stable toolchain.
- `scripts/publish-order.py --check` and `cargo deny check` are the
  mechanical halves of this policy; this ADR is the rationale they enforce.
