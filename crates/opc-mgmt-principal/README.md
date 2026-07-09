# opc-mgmt-principal

Trusted principal construction for management-plane requests.

This crate converts already-verified transport identities into
`opc-config-model::TrustedPrincipal` values and attaches signed authorization
grants from trusted policy sources. It does not verify certificates or SSH keys
itself.

## API Shape

Public API:

- `principal_for_workload`, mapping verified SPIFFE/mTLS workload identity into
  a mutual-TLS principal.
- `principal_for_ssh_user`, mapping a verified SSH username and tenant into an
  SSH public-key principal.
- `SignedPrincipalGrants` and `PrincipalGrantKey`.
- `SignedGrantSource`, implemented by policy/config sources that issue signed
  group and role grants.
- `InMemorySignedGrantStore`, a small in-memory implementation for tests and
  local wiring.
- `with_signed_grants` and `attach_signed_grants_from_source`.
- `PrincipalMappingError` and `GrantResolutionError`.

Example:

```rust
use opc_mgmt_principal::{principal_for_ssh_user, SignedGrantSource};
```

Transport-derived principals start with no roles or groups. Roles and groups
must be attached from a trusted signed-grant source, not from transport metadata
or request headers.

## Relationships

- Uses `opc-identity` workload identities for SPIFFE/mTLS mapping.
- Produces `opc-config-model::TrustedPrincipal` values consumed by config,
  NACM, audit, and protocol crates.
- `opc-nacm-config` implements `SignedGrantSource` for NACM group membership.

## Status And Limits

Current scope:

- Verified workload and SSH-user principal mapping.
- Signed grant attachment.
- Bounded SSH username validation.

Not in scope:

- Certificate validation.
- SSH authentication.
- Persistent grant storage.

## Roadmap

- Keep principal construction narrow and auditable.
- Add new transport mappings only after their identity has already been
  verified outside this crate.

## Verification

Run:

```sh
cargo test -p opc-mgmt-principal
```
