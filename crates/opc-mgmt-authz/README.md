# opc-mgmt-authz

NACM-backed authorization adapters for management-plane operations.

This crate connects trusted principals, schema paths, and active NACM policies
to read, write, and exec decisions. It is an adapter layer around `opc-nacm`,
not a policy datastore.

## API Shape

Public API:

- `PolicySource`, a trait that supplies the active compiled `NacmPolicy`.
- `ResolvedPolicy`, the policy plus optional signed groups and roles for the
  requesting principal.
- `ReadAuthorizer` for read, subscribe, and notification reads.
- `ConfigWriteAuthorizer`, implementing `opc_config_bus::ConfigAuthorizer`.
- `ExecAuthorizer` for static RPC/action paths.
- `PathDecision`, `WritePathDecision`, `ReadAction`, and `AuthzError`.

Example:

```rust
use opc_mgmt_authz::{PolicySource, ReadAuthorizer};
use opc_mgmt_schema::SchemaRegistry;

fn make_read_authorizer(
    source: std::sync::Arc<dyn PolicySource>,
    registry: std::sync::Arc<dyn SchemaRegistry>,
) -> ReadAuthorizer {
    ReadAuthorizer::new(source, registry)
}
```

If the policy source is unavailable, callers must fail closed. An empty active
policy default-denies. Path resolution failures also deny access.

## Relationships

- Uses `opc-nacm` for rule evaluation.
- Uses `opc-mgmt-path` and `opc-mgmt-schema` for schema-scoped path decisions.
- Implements the write-authorization trait consumed by `opc-config-bus`.
- Uses signed groups/roles attached through `opc-mgmt-principal`.

## Status And Limits

Current scope:

- Schema-node scoped read/write/exec decisions.
- Config operations mapped to NACM actions:
  create, update, replace, delete, and rollback-as-replace.
- `Patch` operations require both create and update permission.

Limitations:

- Decisions are not per-list-instance beyond the canonical path used for NACM
  matching.
- This crate does not store or compile operator-facing NACM config.

## Roadmap

- Keep authorization fail-closed.
- Add protocol action mappings when new management operations are introduced.

## Verification

Run:

```sh
cargo test -p opc-mgmt-authz
```
