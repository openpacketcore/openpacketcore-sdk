# opc-mgmt-principal

Maps a transport-authenticated SPIFFE workload identity
(`opc_identity::WorkloadIdentity`) to the config-bus
`opc_config_model::TrustedPrincipal` used for commit admission, authorization,
and audit.

The conversion is deliberately narrow and **fail-safe by omission**: it stamps
`AuthStrength::MutualTls` and carries the SPIFFE id + tenant, but produces a
principal with **no roles and no groups**. Authorization grants must come only
from a signed policy source (e.g. `opc-persist`'s NACM policy datastore), never
from transport metadata — so the caller attaches roles/groups *after* this
conversion, from a trusted source, via `opc_mgmt_principal::with_signed_grants`.
That wrapper is intentionally thin: its job is to make the signed-policy
requirement visible at every call site.

`opc-identity` only verifies SAN/expiry/trust-domain when it derives the
identity; the mTLS chain itself must already have been verified by rustls during
the handshake. This crate assumes an already-verified identity.
