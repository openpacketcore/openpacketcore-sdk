# opc-mgmt-schema

Runtime YANG schema-registry contracts for OpenPacketCore management protocols.

This crate is the shared schema view used by management-plane code such as gNMI,
NETCONF, path resolution, NACM authorization, and generated CNF bindings. It does
not parse YANG source or generate Rust code; generated registries and XML/JSON
projectors are expected to come from `opc-yanggen` or CNF-specific code.

## API Shape

Core exports:

- `SchemaRegistry`, the trait implemented by generated schema registries.
- `NodeMeta`, `NodeKind`, `LeafType`, `ModelData`, `OriginEntry`,
  `ModuleConformance`, `ModuleImport`, and `DiscoveryMetadata`.
- `NacmAction`, a local mirror of management actions so this crate does not
  depend on `opc-nacm`.
- Helpers such as `normalize_schema_path`, `bare_segment`,
  `check_registry`, `xml_escape_text`, and `xml_escape_attr`.
- NETCONF projection contracts:
  `NetconfXmlRenderer`, `NetconfXmlEditApplicator`, `EditConfigNode`,
  `NetconfXmlRenderContext`, `EditOperation`, and NETCONF projection/edit
  error types.

Typical generated use:

```rust
use opc_mgmt_schema::SchemaRegistry;

fn accepts_path(registry: &dyn SchemaRegistry, schema_path: &str) -> bool {
    registry.is_valid_path(schema_path)
}
```

`SchemaRegistry` implementors provide the raw registry tables through
`schema_digest`, `served_models`, `nodes`, and `origins`. Default methods derive
lookup indexes, discovery metadata, module/origin lookup, key-leaf metadata,
numeric ranges, defaults, NACM actions, and self-check behavior.

## Relationships

- `opc-yanggen` emits registry implementations for generated CNF models.
- `opc-mgmt-path` resolves protocol request paths against this trait.
- `opc-mgmt-authz` uses schema metadata to authorize read/write/exec access.
- `opc-netconf-server` and `opc-gnmi-server` use the registry for capabilities,
  discovery, path validation, and generated projection hooks.

## Status And Limits

Current scope is intentionally small and contract-oriented:

- Default discovery and schema-source methods are empty unless implementors
  provide metadata.
- NETCONF XML render/apply traits are contracts only; there is no generic XML
  projection engine in this crate.
- NACM actions are metadata hints, not an authorization engine.

## Roadmap

- Keep generated registries deterministic and self-checkable.
- Expand registry metadata only when protocol crates need stable contracts.
- Keep this crate free of datastore, transport, and policy dependencies.

## Verification

Run:

```sh
cargo test -p opc-mgmt-schema
```
