# opc-mgmt-principal

Maps a transport-authenticated SPIFFE workload identity
(`opc_identity::WorkloadIdentity`) or verified SSH public-key user to the config-bus
`opc_config_model::TrustedPrincipal` used for commit admission, authorization,
and audit.

The conversion is deliberately narrow and **fail-safe by omission**: it stamps
`AuthStrength::MutualTls` for SPIFFE/mTLS or `AuthStrength::SshPublicKey` for
SSH public-key/certificate authentication and carries the identity + tenant, but
produces a principal with **no roles and no groups**. Authorization grants must
come only from a signed policy source (e.g. `opc-persist`'s NACM policy
datastore), never from transport metadata - so the caller attaches roles/groups
*after* this conversion, from a trusted source, via
`opc_mgmt_principal::with_signed_grants`. That wrapper is intentionally thin:
its job is to make the signed-policy requirement visible at every call site.

For callers that need a typed source boundary, the crate also provides:

- `SignedGrantSource`: resolves signed roles/groups for an already verified
  `TrustedPrincipal`.
- `SignedPrincipalGrants`: the resolved role and NACM group set.
- `PrincipalGrantKey`: tenant plus identity lookup key, preventing cross-tenant
  grant bleed.
- `InMemorySignedGrantStore`: deterministic test/adapter store for policy
  material that has already been verified by the caller.
- `attach_signed_grants_from_source`: fail-closed helper that resolves grants
  and returns a principal populated with only those signed grants.

An unavailable grant source returns a payload-free error. A missing key in the
in-memory store returns empty grants, which leaves the principal without NACM
groups and therefore fails closed under group-scoped rule-lists.

`opc-identity` only verifies SAN/expiry/trust-domain when it derives the
identity; the mTLS chain itself must already have been verified by rustls during
the handshake. SSH callers must likewise verify the SSH key or certificate before
calling `principal_for_ssh_user`; the tenant must come from trusted listener or
operator policy, not from the username.
