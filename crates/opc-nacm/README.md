# opc-nacm

Normalized YANG path parsing and NACM authorization evaluation for
OpenPacketCore management-plane policy.

This crate provides:

- `ModuleRegistry`: canonical module/prefix resolution for served YANG models.
- `YangPath` and `YangPathPattern`: predicate-free schema path parsing,
  normalization, wildcard matching, and subtree matching.
- `NacmPolicy`: immutable compiled policy with default-deny semantics.
- `NacmRule`: flat compatibility rules for existing SDK policy callers.
- `NacmRuleList`: RFC 8341-style rule-lists scoped to signed principal groups,
  including an all-users rule-list helper.
- `NacmEvaluator`: bounded evaluation cache scoped by policy identity, action,
  path, and principal group set.

Flat rules remain supported for existing policies. New northbound authorization
paths should prefer `NacmRuleList` with groups populated from signed policy, not
from transport metadata or client-supplied request fields.

The crate does not perform datastore persistence, principal mapping, transport
authentication, per-list-instance authorization, or YANG schema discovery.
