# OPC gNMI Server Design Spec

## Status

Implemented foundation, owned by `opc-gnmi-server`.

## Scope

`opc-gnmi-server` is the optional northbound gNMI server for CNFs that choose to
expose OpenConfig management. It is outside the core SDK dependency graph and is
the only workspace crate allowed to depend on `tonic`, `prost`, `prost-types`,
or `tonic-build`.

The crate owns:

- vendored gNMI protobuf bindings and the tonic service wrapper;
- authenticated gNMI-over-TLS listener integration;
- Capabilities, Get, Set, and Subscribe handling;
- OpenPacketCore commit-confirmed registered extension semantics;
- gNMI master-arbitration enforcement;
- schema-backed path, value, audit, metrics, and config-bus integration.

## Security Contract

Production embeddings must construct `GnmiServer` with an explicit audit sink
through `new`, `new_with_audit`, `new_with_arbitration`, or
`new_with_audit_and_arbitration`. The tracing audit sink is available only
through `*_dev_only` constructors for tests, conformance fixtures, and local
development.

`GnmiService::new` requires an authenticated transport principal on every RPC.
The unauthenticated service wrapper is crate-private and compiled only for
tests. Runtime listeners must derive principals from the mTLS transport and
attach them to requests before dispatch.

Set commits submit complete candidates to `opc-config-bus` with the running
snapshot version they were built from. `opc-config-bus` enforces that base
version for candidate-bearing requests, so a stale gNMI Set cannot overwrite an
intervening commit.

## Extension Semantics

The OpenPacketCore commit-confirmed extension uses the experimental registered
extension ID documented in `opc-gnmi-server`. It is advertised only when the
extension registry enables it and master arbitration is also configured.

Every commit-confirmed Begin, Confirm, or Cancel Set must carry a valid
master-arbitration extension. This binds control actions to the gNMI election
fence for the tenant and role, preventing a different writer from confirming or
cancelling another writer's pending commit unless it wins arbitration first.

Servers with arbitration disabled reject commit-confirmed registration at
construction time.

## Dependency Boundary

ADR 0016 permits the gRPC stack only in `opc-gnmi-server`. The CI policy script
must continue to enforce that:

- no other workspace crate depends on `tonic`, `prost`, `prost-types`, or
  `tonic-build`;
- no other workspace crate depends on or re-exports `opc-gnmi-server`;
- all gNMI TLS serving uses the shared `rustls` configuration built by the OPC
  management transport stack.

## Verification

The gNMI foundation is covered by crate tests for:

- authenticated Capabilities, Get, Set, and Subscribe behavior;
- Set stale-candidate rejection after intervening commits;
- commit-confirmed timeout, confirm, cancel, malformed payload, and missing
  arbitration cases;
- master-arbitration election, tenant, and role fencing;
- listener mTLS principal derivation and max-session bounds;
- extension payload redaction in status, metrics, and audit paths.
