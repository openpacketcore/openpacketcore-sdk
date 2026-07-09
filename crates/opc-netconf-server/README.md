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
  `rpc_get_schema_reply`, `xml_escape`, and `RpcError`.
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

Limitations:

- No generic XML projection engine; generated or CNF-specific bindings must
  render and apply config.
- Full XPath predicates, functions, axes, and the `:xpath` capability are not
  implemented.
- Notification replay, stop-time, and notification filters are rejected.
- Direct `handle_rpc` helpers are useful for tests, but full session side
  effects require the session/listener runners and `SessionRegistry`.

## Roadmap

- Keep capability advertisement tied to implemented binding hooks.
- Add protocol features only with limits, authorization, audit, and generated
  projection support.

## Verification

Run:

```sh
cargo test -p opc-netconf-server
```
