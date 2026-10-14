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
- `resolve`, the complete-key resolver for writes.
- `resolve_read`, which accepts omitted keys and canonicalizes integer and
  boolean selectors, returning no selection for an invalid typed value.
- `resolve_instance`, which requires complete declared keys and canonical
  encoding for a provider's concrete path.
- `CanonicalPath`, `canonical_path_matches`, and `append_key_predicate`, the
  shared literal path parser, instance matcher, and builder.

Example:

```rust
use opc_mgmt_path::{resolve_read, RequestPath};
use opc_mgmt_schema::SchemaRegistry;

fn resolve_for_read(
    registry: &dyn SchemaRegistry,
    path: &RequestPath,
) -> Result<Option<String>, opc_mgmt_path::PathError> {
    Ok(resolve_read(registry, path)?.map(|resolved| resolved.schema_path))
}
```

The canonical `YangPath` orders list keys by schema metadata. Read literals use
single quotes, or double quotes when the value contains an apostrophe, and keep
backslashes literal. Values containing both quote characters fail closed. The
write resolver retains its complete-key and apostrophe rejection contract.

Read key-value matches against masked or unclassified key leaves are refused
using schema metadata before callers consult policy or data. Omitted keys carry
no value constraint. A canonical asterisk is literal; protocol adapters handle
their own wildcard conventions. Matching requires equal depth and qualified
node names, with every selected key present and equal on the reported instance.
The syntax matcher alone does not establish schema validity or complete keys.

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
