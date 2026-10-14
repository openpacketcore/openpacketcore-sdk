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
use opc_mgmt_authz::{AuthzError, PolicySource, ReadAuthorizer};
use opc_mgmt_schema::SchemaRegistry;

fn make_read_authorizer<P: PolicySource>(
    source: P,
    registry: &dyn SchemaRegistry,
) -> Result<ReadAuthorizer<'_, P>, AuthzError> {
    ReadAuthorizer::new(registry, source)
}
```

If the policy source is unavailable, callers must fail closed. An empty active
policy default-denies. Path resolution failures also deny access.

## List identity and subscription contexts

`ReadAuthorizer::authorize_selection` loads one resolved policy context for the
requested nodes and every identifying key, including composite components and
ancestor-list keys. A denied or unknown key omits its entire dependent entry.
This applies to public keys as well as sensitive keys. `ReadAction::Read` and
`ReadAction::Subscribe` are separate permissions. Canonical predicates select
instances after authorization and never grant permission.

Use `ReadNode::operational` for opaque provider values and events. Its dependency
set includes every descendant schema node, and all identifying keys must permit
cleartext. The protocol omits an unauthorized aggregate before reading its JSON;
it does not rewrite provider JSON. Use `ReadNode::projected` for generated
schema-aware projection. `AuthorizedReadSelection::xml_paths` adds permitted keys
to material XML selections without turning a structural parent into permission
to read children. Multi-registry reads share one `ResolvedPolicy` through
`authorize_selection_resolved`.

Use `authorize_event_selection_resolved` for per-event subscription checks.
It evaluates the same complete dependency batch against the supplied context
without emitting decision traces that would reveal denied-event activity.
Requests, snapshots, and independent authorization-control reevaluations keep
using the ordinary traced selection API.

A live `PolicySource` must implement `watch_authorization` using one
`AuthorizationChangeHub` for its authorization context. Register the watch and
resolve its initial context together with `hub.register(gate, || resolve())`.
Install every new policy, resolved group/role set, or principal validity state
inside `hub.activate(|| install_context())`, and await its result. Prepare any
external reads before activation; the context returned by read authorization
must be the context installed under the hub's barrier. Updating a database and
having readers load it directly before activating the hub would violate that
boundary.

Activation gates all attached output before installing the context. It delivers
ordered control notifications and waits until every affected stream has
reevaluated or closed. A later activation waits for that acknowledgement, so a
revoke-then-restore sequence cannot skip the revoked revision. The hub wakes all
attached streams conservatively; applications can use separate hubs when they
have independently scoped contexts. `prepare_change` and `complete` expose the
same barrier in two steps. Dropping an incomplete change fails the source.
Call `hub.fail()` when context refresh or change delivery fails with unknown
scope. Rebuilding a failed source requires fresh subscriptions.

The default watch method refuses subscriptions. `AuthorizationWatch::immutable`
is an explicit option only for a policy **and resolved principal context** that
cannot change during any attached subscription. It is unsuitable for a live
datastore, revocable principal, or dynamic group resolver. These APIs require no
stored-data migration or manual key-management action.

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
