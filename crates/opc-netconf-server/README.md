# opc-netconf-server

NETCONF server core for OpenPacketCore management bindings.

This crate provides NETCONF parsing, capability rendering, session handling,
transport listeners, and binding traits that connect generated CNF config and
operational-state code to the management plane. It is capability-driven: a
feature is advertised only when the binding and runtime hooks implement it.

## API Shape

Main exports include:

- Binding contracts:
  `NetconfConfigBinding`, `ReadSelection`, `EditConfigCandidate`,
  `NetconfMonitoringCapability`, `YangLibraryCapability`,
  `WithDefaultsCapability`, and notification capability types.
- Capability helpers:
  `read_only_base_capabilities`, `read_only_capabilities`,
  `render_server_hello`, `NETCONF_BASE_1_0`, `NETCONF_BASE_1_1`,
  `WRITABLE_RUNNING_1_0`, `WITH_DEFAULTS_1_0_BASE`,
  `YANG_LIBRARY_1_1_BASE`, and related namespace constants.
- XML parser types:
  `parse_client_hello`, `parse_rpc`, `ParsedRpc`, `RpcOperation`,
  `GetConfigRequest`, `GetRequest`, `EditConfigRequest`, `Filter`,
  `SubtreeFilter`, `WithDefaultsMode`, and `XmlError`.
- Reply helpers:
  `rpc_ok_reply`, `rpc_ok_empty_reply`, `rpc_error_reply`,
  `rpc_get_schema_reply`, `rpc_ok_committed_revision_reply`, `xml_escape`, and
  `RpcError`.
- Server/session/listener types:
  `ReadOnlyNetconfServer`, `SessionConfig`, `SessionRegistry`,
  `run_read_only_session`, `run_read_only_session_with_registry`,
  `run_read_only_tls_listener`, and TLS/SSH listener and supervision helpers.
- SSH support:
  `SshHostKey`, `SshAuthorizedKey`, key-file loaders, listener config, and
  call-home config.

Example imports:

```rust
use opc_netconf_server::{NetconfConfigBinding, SessionConfig};
```

`NetconfConfigBinding<C>` supplies the config bus, schema registry, generated
XML renderer/applicator hooks, operational-state hooks, advertised capabilities,
schema-source lookup, and edit-config candidate construction. Default render and
edit hooks fail closed unless a generated or CNF-specific binding implements
them.

## HA config authority opt-in

Install the same config authority used by the consensus datastore on the
server core:

```rust,ignore
use std::sync::Arc;

use opc_config_bus::ConfigAuthorityPort;

let authority: Arc<dyn ConfigAuthorityPort> =
    Arc::new(raft_managed_datastore.config_authority());
let server = ReadOnlyNetconfServer::new(binding, policy, audit, transport)?
    .with_config_authority(authority)?;
```

The async session dispatcher checks the port before `<edit-config>`,
`<edit-data>`, `<commit>`, and config read projection. `Retry` and
`Unavailable` return an `operation-failed` RPC error with
`<error-app-tag>not-leader</error-app-tag>`. A known bounded hint appears as:

```xml
<error-info>
  <leader-hint xmlns="urn:openpacketcore:params:xml:ns:netconf:config-authority:1.0">2</leader-hint>
</error-info>
```

The value is XML-escaped and never logged. A numeric consensus-node hint must
be resolved through the product's fixed authenticated management roster.

Installing the port also opts durable write replies into an `<ok/>`-adjacent
committed revision:

```xml
<committed-revision xmlns="urn:openpacketcore:params:xml:ns:netconf:config-authority:1.0">
  <version>42</version>
  <content-hash algorithm="sha-256">…64 lowercase hex characters…</content-hash>
</committed-revision>
```

The hash exactly matches the persisted plaintext-envelope digest, including
bound request/replay metadata; it is not a config-only equality hash.
Construction rejects a datastore that cannot attest new commit digests. A
replay of a pre-digest legacy record still has no revision and the response
fails closed until an explicitly reconciled new durable write exists.

For the concrete consensus adapter, the local config bus's `{tx_id, version}`
must also equal the canonical state-machine head. An empty canonical store may
admit a write that creates the genesis commit, but linearizable reads remain
unavailable until that durable head exists; an empty transaction/version cannot
prove bootstrap-content equality across pods.

Without a port, an authoritative bus preserves the legacy reply bytes and read
behavior. A shadow bus without a port fails closed. The public synchronous
`handle_rpc`/`handle_rpc_xml` helpers cannot await an async authority port and
therefore reject gated operations whenever one is configured. Production
leader-aware traffic must use the async session/listener runners.

Source migration: exhaustive matches on `ServerInitError` must handle the
additive `CommittedRevisionUnsupported` variant. Existing public `RpcError`
and `RpcErrorInfo` values retain their prior `Copy` behavior and exhaustive
shape; the runtime leader hint is rendered through a private response path.
Code constructing `CommitResult` literals must initialize its new optional
`committed_revision` field.

## Relationships

- Uses `opc-config-bus` and `opc-config-model` for config commits.
- Uses `opc-mgmt-schema` for registry metadata and generated XML projection
  contracts.
- Uses `opc-mgmt-authz`, `opc-mgmt-audit`, `opc-mgmt-limits`,
  `opc-mgmt-principal`, and `opc-mgmt-transport` for management guardrails.
- Generated XML projection and edit support normally come from `opc-yanggen`.

## Status And Limits

Implemented scope:

- NETCONF 1.0 and 1.1 framing.
- Bounded XML parsing and management limits.
- `<get-config>`, `<get>`, monitoring/YANG Library/schema-source helpers where
  binding metadata is present.
- Optional writable-running, candidate, startup, confirmed-commit, with-defaults,
  notifications, and NMDA hooks when the binding advertises and implements
  them.
- TLS and SSH listener entry points with authenticated principal mapping.

NETCONF config-change subscriptions use `DisconnectOnLag` with both the
existing event-count cap and `MgmtLimits::max_subscriber_queue_bytes`. The byte
limit is the config bus's conservative accounting bound: it includes both
heap-backed snapshots, deltas, and changed-path storage without cloning values,
but excludes allocator metadata, `Arc` control blocks, and queue spare
capacity. Shared allocations are deliberately charged in full per event. An
event larger than the whole budget disconnects before enqueue; already queued
events retain their original order and remain drainable.

Migration: the additive `OpcConfig` retained-size hooks default to `None`, so
existing implementations remain source-compatible. A notification-enabled
implementation must now implement both snapshot and delta hooks. Otherwise its
byte-budgeted NETCONF subscriber disconnects predictably on the first
unsizeable config-change event with the value-free
`retained-size-unavailable` reason. The server never falls back to shallow
`size_of` accounting.

Limitations:

- No generic XML projection engine; generated or CNF-specific bindings must
  render and apply config.
- Full XPath predicates, functions, axes, and the `:xpath` capability are not
  implemented.
- Notification replay, stop-time, and notification filters are rejected.
- Direct `handle_rpc` helpers are useful for tests, but full session side
  effects require the session/listener runners and `SessionRegistry`.
- Authority-enabled config reads are the explicit linearizable-read profile;
  they never fall back to a local projection when leadership is unavailable.

## Roadmap

- Keep capability advertisement tied to implemented binding hooks.
- Add protocol features only with limits, authorization, audit, and generated
  projection support.

## Verification

Run:

```sh
cargo test -p opc-netconf-server
```
