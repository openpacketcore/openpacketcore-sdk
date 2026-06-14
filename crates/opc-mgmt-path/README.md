# opc-mgmt-path

Registry-validated, instance-aware canonical YANG path construction shared by the
OpenPacketCore gNMI and NETCONF servers.

Both servers must turn a northbound path (a gNMI `Path` with prefix + keyed
`PathElem`s, or a NETCONF XML element path) into the SDK's canonical commit/audit
form:

```
/module:container/module:list[module:key='value']/module:leaf
```

This crate does that conversion **once**, against the generated
`opc_mgmt_schema::SchemaRegistry` (the single schema source, no side schema):

- applies a request prefix before the per-request elements;
- validates the gNMI origin against the registry's served modules (unknown
  origin and paths outside that origin's module set fail closed) and uses a
  known origin to disambiguate otherwise-ambiguous bare paths inside that
  origin's module set;
- resolves the whole path to a real schema node (unknown paths fail closed);
- requires schema prefixes to resolve to served models before accepting a match,
  so malformed registry/input prefix pairs fail closed;
- requires keyed lists to carry exactly their `key` leaves; missing or extra
  keys fail closed, and it **emits them in the schema's `key` order** regardless of
  the order the client supplied them, preserving a prefix-qualified key leaf's
  prefix when the registry provides one;
- rejects key predicates on non-list segments;
- rejects malformed segment and key names before lookup/rendering, so malformed
  input is never echoed as an unknown path;
- escapes key values once (`\` and `'`), so callers never hand-concatenate paths.

It returns both the predicate-free schema path (for registry / NACM lookup) and
the instance-aware canonical `opc_config_model::YangPath` (for commit metadata
and audit).
