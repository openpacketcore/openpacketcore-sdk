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
- Opt-in writer-of-record and revision response types:
  `ConfigAuthorityPort` (from `opc-config-bus`),
  `CommittedRevisionExtension`, `OPC_COMMITTED_REVISION_EXTENSION_ID`, and
  `GNMI_LEADER_HINT_METADATA_KEY`.
- TLS listener, smoke-test, transport-principal, and supervision helpers.

Example imports:

```rust
use opc_gnmi_server::{GnmiConfigBinding, GnmiServer};
```

`GnmiConfigBinding<C>` supplies the config bus, schema registry, Set patcher,
policy source, config JSON renderer, and optional operational-state providers.
Default config rendering fails closed unless implemented by generated or
CNF-specific code.

## HA config authority opt-in

Install one authority port on the server core to make Set and Get requests
writer-of-record aware:

```rust,ignore
use std::sync::Arc;

use opc_config_bus::ConfigAuthorityPort;

let authority: Arc<dyn ConfigAuthorityPort> =
    Arc::new(raft_managed_datastore.config_authority());
let server = GnmiServer::new(binding, limits, profile, extensions, audit)?
    .with_config_authority(authority)?;
```

The installed port is checked after authentication and request-extension
validation but before local Set candidate construction, config-bus submission,
or Get projection. `Retry` and `Unavailable` return gRPC `UNAVAILABLE`; a known
bounded hint is carried only in the `opc-leader-hint` response metadata. It is
not included in the status message or logs. Applications resolve a numeric
consensus-node hint through their fixed authenticated management roster.

Installing the port also opts successful Set replies into registered extension
ID `999`, payload name `openpacketcore.committed-revision.v1`. Decode `msg` as
`CommittedRevisionExtension`, containing `version` and an exact 32-byte
SHA-256 `content_hash`. The hash is the datastore's persisted plaintext
envelope digest, including bound request/replay metadata; it is not a hash of
the config alone.

Without a port, an authoritative bus keeps the legacy request behavior and
byte-identical SetResponse shape (no committed-revision extension). A shadow
bus without a port fails closed instead of serving or mutating its local
mirror. Installing the port requires a datastore that advertises exact digest
receipts. A replay of a pre-digest legacy record has no committed revision and
the opted-in response fails closed; reconcile it with a new durable write
rather than fabricating a hash from reserialized data.

For the concrete consensus adapter, the local config bus's `{tx_id, version}`
must also equal the canonical state-machine head. An empty canonical store may
admit a Set that creates the genesis commit, but Get remains unavailable until
that durable head exists; an empty transaction/version cannot prove that
independently supplied bootstrap payloads are equal across pods.

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
- Authority-enabled Get is the explicit linearizable-read profile. It rejects
  whenever local leadership and apply catch-up cannot be proven; it never
  falls back to the local snapshot.

## Roadmap

- Keep advertised encodings and extensions matched to implemented behavior.
- Add codecs, target routing, and richer streaming only with schema, authz,
  audit, and limit coverage.

## Verification

Run:

```sh
cargo test -p opc-gnmi-server
```
