# opc-mgmt-authz

NACM authorization facade for OpenPacketCore management-plane reads,
subscriptions, config writes, and management RPC/action execution checks.

`opc-config-bus` enforces NACM on the **write** path (`ConfigAuthorizer`), but a
running-config snapshot read is raw and unfiltered. The gNMI `Get`/`Subscribe`
and NETCONF `<get>`/`<get-config>` paths must therefore authorize **reads**
themselves, default-deny, and omit subtrees the caller may not see.

The authorizers reject served module sets with ambiguous prefixes at
construction time. `opc-nacm` would otherwise preserve the ambiguity and make
each later parse fail; surfacing that as a startup/schema error is clearer and
still fail-closed.

`ReadAuthorizer`:

- builds a NACM `ModuleRegistry` once from the schema registry's served models;
- selects the **tenant's** active compiled policy through a pluggable
  `PolicySource` (the CNF wires `opc-persist`'s
  `SqliteSecurityPolicyService::get_active_policy_compiled`, keeping this crate
  free of the persistence/rusqlite dependency);
- first resolves every input through the generated schema registry, then maps
  the predicate-free schema path to a normalized NACM path and evaluates `read`
  or `subscribe`, returning an allow/deny decision per path;
- **fails closed**: an unparseable, unknown-prefix, or unknown-schema path denies;
  a tenant with no policy (an empty policy default-denies) denies; a genuinely
  unavailable policy store returns a payload-free `Err`, which the server maps to
  a deny/`UNAVAILABLE`.

It returns per-path decisions; the server uses the schema registry's data class
plus `opc-redaction` to mask secret values on the paths that are allowed. NACM
here is schema-node scoped (the SDK NACM model collapses list instances), so this
facade does not perform per-instance read authorization.

`ConfigWriteAuthorizer`:

- implements the `opc-config-bus` `ConfigAuthorizer` admission hook;
- maps `ConfigOperation` values to NACM write actions (`update`, `replace`, or
  `delete`);
- resolves each config-bus changed path through the generated schema registry
  before evaluating NACM;
- allows empty changed-path batches for no-op/pre-authorized rollback admission;
- denies unknown or unparseable paths with a fixed invalid marker so list key
  values are not echoed; and
- returns payload-free policy-store errors so servers can fail closed without
  leaking storage details.

`ExecAuthorizer`:

- builds a NACM `ModuleRegistry` from the YANG modules that define management
  RPC/action nodes;
- evaluates static operation paths such as `/nc:kill-session` with NACM
  `exec`;
- denies invalid or unknown operation paths fail-closed;
- returns the same payload-free policy-store error as `ReadAuthorizer`.

This is only the shared authorization seam. A server still must implement the
actual operation semantics, audit, and any cross-session or datastore state
before claiming support for an RPC such as NETCONF `<kill-session>`.
