# ADR 0016: Northbound gRPC Stack Exception (gNMI)

## Status

Proposed

## Date

2026-06-13

## Context

ADR 0014 §3 states: *"No gRPC stack (`tonic`/`prost`) in SDK crates. … A future
exception requires an ADR, not a Cargo.toml edit."* That rule keeps the **core**
SDK dependency graph lean and auditable: internal transports use hand-specified
framing over tokio/rustls, and external 3GPP interfaces are HTTP/2 (`hyper`) or
raw protocol codecs.

The management-plane work introduces `opc-gnmi-server` (see
`.planning/opc-gnmi-server-spec.md`). gNMI (OpenConfig) **is** a gRPC service:
its contract is a protobuf service over HTTP/2. There is no rustls/`hyper`-only
or hand-framed path to a conformant gNMI server — a client (`gnmic`, `gNMIc`,
OpenConfig collectors) speaks gRPC and nothing else. So `opc-gnmi-server` cannot
exist without a gRPC stack, and per ADR 0014 §3 that requires this ADR.

gNMI is a distinct dependency category from the cases ADR 0014 §3 was written
for. It is a **northbound management** interface embedded by a CNF that chooses
to expose gNMI — not an internal SDK transport and not a 3GPP data-plane codec.

## Decision

Permit `tonic` and `prost` **only for the northbound gNMI server crate**,
`opc-gnmi-server`. `tonic-build` is permitted only as that crate's build-time
proto-generation dependency if the Phase-0 spike chooses build-time generation.
Any future gRPC-based management crate requires an explicit ADR amendment and an
update to the mechanical allow-list; this exception is not a blanket
"management crates may use gRPC" policy. Specifically:

1. **Scope boundary.** `tonic`/`prost` MUST NOT appear in any core SDK crate
   (`opc-config-bus`, `opc-config-model`, `opc-persist`, `opc-runtime`,
   `opc-identity`, `opc-tls`, `opc-nacm`, `opc-yanggen`, the `opc-proto-*`
   codecs, `opc-sbi`, the `opc-mgmt-*` foundation crates, etc.). They live only
   in `opc-gnmi-server` unless this ADR is amended. ADR 0014 §3 remains in force
   everywhere else. Inside this SDK workspace, no other crate may depend on or
   re-export `opc-gnmi-server`; downstream CNFs outside the workspace opt in to
   gNMI by depending on the server crate directly.
2. **Boundary is enforced mechanically.**
   `scripts/check-management-plane-policy.py --check` asserts that no crate
   outside the explicit allowed set directly or transitively depends on
   `tonic`/`prost`/`tonic-build`, or on `opc-gnmi-server` itself. The CI job
   runs this gate. The initial allowed set is exactly `opc-gnmi-server`.
3. **One TLS stack only (ADR 0014 §1 preserved).** `opc-gnmi-server` serves
   tonic over the `rustls::ServerConfig` produced by `opc-mgmt-transport`
   (`ring` provider), not tonic's own/native TLS. No `openssl`/`native-tls`
   enters the graph (verify `tonic`/`hyper` features with `default-features =
   false`, rustls only).
4. **Dependency hygiene (ADR 0014 §6/§7).** `tonic`/`prost` are MIT/Apache —
   compatible with the license gate. The PR adding them justifies them per §7
   and passes `cargo deny`. The pinned `tonic` version MUST compile on the
   workspace MSRV (currently 1.88, ADR 0014 §5); the Phase-0 spike validates
   this before the version is pinned, and any MSRV bump follows the §5 process.
5. **Proto pin and generation mode.** The gNMI proto is vendored at an exact tag
   under `crates/opc-gnmi-server/proto/`; the vendored files carry the upstream
   tag/commit in their header, and the advertised gNMI version string derives
   from this pin. The Phase-0 spike must choose and document exactly one
   generation mode:
   - build-time generation with `tonic-build`, which adds an explicit `protoc`
     build prerequisite and a CI check that generated output is reproducible; or
   - checked-in generated Rust, which avoids `protoc` in downstream builds but
     requires a regeneration script and a CI drift check.
   In either mode, generated service code is treated as part of the
   `opc-gnmi-server` boundary and does not become a shared SDK dependency.
6. **This exception does not generalize.** It authorizes a gRPC **server** for a
   northbound management protocol that is gRPC by definition. It is not license
   to adopt gRPC for internal transports or to relax ADR 0014 §3 for core crates.

## Consequences

- A downstream CNF outside this workspace that embeds `opc-gnmi-server` inherits
  `tonic`/`prost`. That is an explicit opt-in to gNMI; CNFs that do not expose
  gNMI never pull the stack.
- The core SDK graph stays gRPC-free and auditable, exactly as ADR 0014 §3
  intends; only the optional northbound server adds gRPC.
- The mechanical gate from point 2 exists and runs in CI, so this exception's
  scope cannot silently erode — the same "implicit policy does not survive
  maintenance" lesson that motivated ADR 0014.
- NETCONF (`opc-netconf-server`) is unaffected: it is XML over SSH/TLS and needs
  no gRPC stack.
