# opc-nacm-config

Typed northbound NACM datastore model for OpenPacketCore.

This crate provides the operator-facing `/nacm:nacm` configuration surface that
feeds the lower-level `opc-nacm` authorization engine:

- RFC 8341-style `groups`, `rule-list`, and `rule` data structures.
- OpenPacketCore SPIFFE selector extensions for deriving NACM group membership
  from verified workload identities.
- Strict validation for duplicate names, unknown group references, empty access
  operations, unsafe strings, malformed selectors, and invalid NACM path
  patterns.
- Compilation into `opc_nacm::NacmPolicy` with default-deny behavior.
- `SignedGrantSource` integration for populating `TrustedPrincipal.groups`
  only from signed policy data after transport authentication.
- A static `SchemaRegistry` for the standalone `/nacm` subtree.

Fail-closed behavior is intentional. An empty config denies by default, and a
disabled config compiles to an empty policy rather than bypassing NACM.

The exact `user-name` membership rules are:

- SSH users match the authenticated username.
- SPIFFE workloads match the full `spiffe://...` URI.
- Internal principals match `internal:<name>`.

SPIFFE selectors match the canonical OpenPacketCore SPIFFE path layout:

```text
spiffe://<trust-domain>/tenant/<tenant>/ns/<namespace>/sa/<service-account>/nf/<nf-kind>/instance/<instance>
```

Selectors are exact-match and must set at least one criterion.
