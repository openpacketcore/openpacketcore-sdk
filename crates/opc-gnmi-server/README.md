# opc-gnmi-server

gNMI server core for OpenPacketCore management bindings.

This crate provides a tonic-based gNMI service, TLS listener wiring, request
normalization, authorization, audit integration, capability generation, Set
normalization, Subscribe handling, and binding traits for CNF config and
operational-state implementations.

## API Shape

Main exports include:

- `GnmiServer`, the validated server handle.
- `GnmiService`, the tonic service implementation.
- `GnmiConfigBinding`, the CNF binding trait.
- `GnmiPatchApplicator`, used by generated or CNF-specific Set handling.
- Capability and encoding types:
  `CapabilityProfile`, `EncodingRegistry`, `GnmiCapabilities`, and
  `GNMI_VERSION`.
- Set types:
  `NormalizedSet` and `SetOperation`.
- Path and value normalization helpers, including `resolve_path`,
  `resolve_paths`, and JSON/JSON_IETF typed-value normalization.
- Arbitration and confirmed-commit extension types.
- TLS listener, smoke-test, transport-principal, and supervision helpers.

Example imports:

```rust
use opc_gnmi_server::{GnmiConfigBinding, GnmiServer};
```

`GnmiConfigBinding<C>` supplies the config bus, schema registry, Set patcher,
policy source, config JSON renderer, and optional operational-state providers.
Default config rendering fails closed unless implemented by generated or
CNF-specific code.

## Relationships

- Uses generated protobuf bindings from `crates/opc-gnmi-server/proto`.
- Uses `opc-config-bus` and `opc-config-model` for Set commits.
- Uses `opc-mgmt-path`, `opc-mgmt-schema`, `opc-mgmt-authz`,
  `opc-mgmt-audit`, `opc-mgmt-limits`, `opc-mgmt-opstate`,
  `opc-mgmt-principal`, and `opc-mgmt-transport`.
- Generated gNMI JSON and Set patching support normally comes from
  `opc-yanggen`.

## Status And Limits

Implemented scope:

- gNMI Capabilities, Get, Set, and Subscribe service paths.
- JSON and JSON_IETF encodings.
- TLS listener with HTTP/2 ALPN and authenticated principal injection.
- Management limits, schema self-checks, audit hooks, policy source wiring, and
  optional master arbitration.
- Unknown critical extensions fail closed; unknown non-critical extensions are
  ignored.

Limitations:

- BYTES, PROTO, ASCII, leaf-list typed values, and non-finite floats are
  rejected until codecs exist.
- Set requires a generated or CNF-specific `GnmiPatchApplicator`.
- Config Get requires a generated or CNF-specific JSON renderer.
- Streaming operational ON_CHANGE needs explicit operational-event providers.
- gNMI `target` routing is not implemented; non-empty targets are rejected.
- The commit-confirmed extension uses the experimental OpenPacketCore extension
  ID and requires arbitration wiring.

## Roadmap

- Keep advertised encodings and extensions matched to implemented behavior.
- Add codecs, target routing, and richer streaming only with schema, authz,
  audit, and limit coverage.

## Verification

Run:

```sh
cargo test -p opc-gnmi-server
```
