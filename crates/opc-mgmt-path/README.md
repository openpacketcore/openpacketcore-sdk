# opc-mgmt-path

Protocol request-path resolution for the management plane.

This crate converts gNMI/NETCONF-style request paths into schema paths validated
against `opc-mgmt-schema`. It produces a predicate-free schema path for registry
lookups and a canonical keyed `YangPath` for config-bus and authorization use.

## API Shape

Public API:

- `PathSegment`, a request segment with optional prefix and ordered key values.
- `RequestPath`, a complete request path with optional origin.
- `ResolvedPath`, containing the matched origin, schema path, canonical path,
  and node metadata.
- `PathError`, covering malformed segments, unknown origin or prefix, unknown
  schema nodes, missing or unexpected list keys, and unsafe key values.
- `resolve`, the main resolver.

Example:

```rust
use opc_mgmt_path::{resolve, RequestPath};
use opc_mgmt_schema::SchemaRegistry;

fn resolve_for_read(
    registry: &dyn SchemaRegistry,
    path: &RequestPath,
) -> Result<String, opc_mgmt_path::PathError> {
    Ok(resolve(registry, path)?.schema_path)
}
```

The canonical `YangPath` orders list keys by schema metadata and emits
single-quoted predicates. Key values containing a single quote are rejected
rather than escaped privately.

## Relationships

- Consumes `SchemaRegistry` metadata from `opc-mgmt-schema`.
- Produces `opc-config-model::YangPath` values for config and authorization
  flows.
- Used by `opc-mgmt-authz`, `opc-gnmi-server`, and NETCONF path/filter helpers.

## Status And Limits

Current scope:

- Schema-node and list-key validation.
- Origin and module-prefix validation.
- Error messages avoid echoing key values.

Not in scope:

- Generic XPath evaluation.
- Wildcard expansion across arbitrary instance data.
- Private escaping for key predicates.

## Roadmap

- Extend only around protocol requirements that can still be validated against
  the schema registry.

## Verification

Run:

```sh
cargo test -p opc-mgmt-path
```
