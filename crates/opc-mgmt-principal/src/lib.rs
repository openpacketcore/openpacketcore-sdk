//! Maps a transport-authenticated management identity to a config-bus
//! [`TrustedPrincipal`].
//!
//! The gNMI and NETCONF servers terminate mTLS and derive the peer's
//! [`opc_identity::WorkloadIdentity`] (via `WorkloadIdentity::from_cert_der` on
//! the verified peer leaf). Before a request can be authorized or committed it
//! must become an [`opc_config_model::TrustedPrincipal`]. NETCONF-over-SSH
//! terminates a different transport but has the same boundary: an already
//! verified SSH public-key or SSH-certificate user is mapped to a principal with
//! a caller-supplied tenant.
//!
//! Security contract (RFC 003): the conversion stamps
//! [`AuthStrength::MutualTls`] for SPIFFE/mTLS or
//! [`AuthStrength::SshPublicKey`] for SSH user-key auth and carries the verified
//! identity + tenant, but the resulting principal has **no roles and no
//! groups**. Authorization grants must be sourced only from signed policy (the
//! `opc-persist` NACM policy datastore), never from transport metadata. Callers
//! attach grants *after* this conversion with [`with_signed_grants`], which
//! documents that requirement at the call site; using transport-derived
//! roles/groups is a security defect.
//!
//! ```
//! # use opc_mgmt_principal::principal_for_workload;
//! # fn demo(id: &opc_identity::WorkloadIdentity) {
//! let principal = principal_for_workload(id);
//! assert!(principal.roles.is_empty());
//! assert!(principal.groups.is_empty());
//! # }
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use opc_config_model::{
    AuthStrength, TrustedPrincipal, WorkloadIdentity as ConfigWorkloadIdentity,
};
use opc_identity::WorkloadIdentity as TransportIdentity;
use opc_types::TenantId;

const SSH_USERNAME_MAX_LEN: usize = 256;

/// Error mapping a transport-authenticated identity into a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalMappingError {
    /// SSH username is not safe to place in principal/audit state.
    InvalidSshUsername(&'static str),
}

impl std::fmt::Display for PrincipalMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSshUsername(reason) => {
                write!(f, "invalid SSH username: {reason}")
            }
        }
    }
}

impl std::error::Error for PrincipalMappingError {}

/// Payload-free failure resolving signed authorization grants.
///
/// Grant sources can contain policy-store paths, key metadata, or tenant
/// internals. Keep those details in server-side logs and surface only this
/// coarse error across the management-plane boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantResolutionError;

impl std::fmt::Display for GrantResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("signed principal grants unavailable")
    }
}

impl std::error::Error for GrantResolutionError {}

/// Roles and NACM groups resolved from signed authorization policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedPrincipalGrants {
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

impl SignedPrincipalGrants {
    pub fn new<R, G, RI, GI>(roles: R, groups: G) -> Self
    where
        R: IntoIterator<Item = RI>,
        RI: Into<String>,
        G: IntoIterator<Item = GI>,
        GI: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
            groups: groups.into_iter().map(Into::into).collect(),
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }
}

/// Stable lookup key for signed grants.
///
/// The key is tenant-scoped and identity-scoped so grants for the same user name
/// or SPIFFE ID cannot bleed across tenants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalGrantKey {
    tenant: String,
    identity: String,
}

impl PrincipalGrantKey {
    pub fn new(tenant: impl Into<String>, identity: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            identity: identity.into(),
        }
    }

    pub fn from_principal(principal: &TrustedPrincipal) -> Self {
        Self::new(
            principal.tenant.as_str(),
            identity_wire_key(&principal.identity),
        )
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Source of signed roles/groups for a verified principal.
pub trait SignedGrantSource {
    fn signed_grants_for(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<SignedPrincipalGrants, GrantResolutionError>;
}

impl<T> SignedGrantSource for &T
where
    T: SignedGrantSource + ?Sized,
{
    fn signed_grants_for(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<SignedPrincipalGrants, GrantResolutionError> {
        (*self).signed_grants_for(principal)
    }
}

/// In-memory signed-grant source for tests, fixtures, and single-process
/// adapters that have already loaded verified policy material.
#[derive(Debug, Clone, Default)]
pub struct InMemorySignedGrantStore {
    grants: BTreeMap<PrincipalGrantKey, SignedPrincipalGrants>,
}

impl InMemorySignedGrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_key(
        &mut self,
        key: PrincipalGrantKey,
        grants: SignedPrincipalGrants,
    ) -> &mut Self {
        self.grants.insert(key, grants);
        self
    }

    pub fn insert_principal(
        &mut self,
        principal: &TrustedPrincipal,
        grants: SignedPrincipalGrants,
    ) -> &mut Self {
        self.insert_key(PrincipalGrantKey::from_principal(principal), grants)
    }
}

impl SignedGrantSource for InMemorySignedGrantStore {
    fn signed_grants_for(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<SignedPrincipalGrants, GrantResolutionError> {
        Ok(self
            .grants
            .get(&PrincipalGrantKey::from_principal(principal))
            .cloned()
            .unwrap_or_else(SignedPrincipalGrants::empty))
    }
}

/// Converts a verified transport SPIFFE identity into a config-bus
/// [`TrustedPrincipal`] with `AuthStrength::MutualTls` and **no** roles/groups.
///
/// The SPIFFE id and tenant come from the transport identity; everything an
/// authorizer keys on beyond authentication (roles, groups) is intentionally
/// left empty so it can only be populated from signed policy.
pub fn principal_for_workload(identity: &TransportIdentity) -> TrustedPrincipal {
    TrustedPrincipal::new(
        ConfigWorkloadIdentity::Spiffe(identity.spiffe_id.clone()),
        identity.tenant.clone(),
    )
    .with_auth_strength(AuthStrength::MutualTls)
}

/// Converts an already-authenticated SSH public-key/certificate user into a
/// [`TrustedPrincipal`] with `AuthStrength::SshPublicKey` and **no**
/// roles/groups.
///
/// The SSH transport layer must verify the key or certificate before calling
/// this function. The tenant is supplied by trusted listener/operator policy,
/// not inferred from the username. This keeps transport authentication separate
/// from authorization and tenancy assignment.
pub fn principal_for_ssh_user(
    username: impl Into<String>,
    tenant: TenantId,
) -> Result<TrustedPrincipal, PrincipalMappingError> {
    let username = username.into();
    validate_ssh_username(&username)?;
    Ok(
        TrustedPrincipal::new(ConfigWorkloadIdentity::User(username), tenant)
            .with_auth_strength(AuthStrength::SshPublicKey),
    )
}

fn validate_ssh_username(username: &str) -> Result<(), PrincipalMappingError> {
    if username.is_empty() {
        return Err(PrincipalMappingError::InvalidSshUsername(
            "must not be empty",
        ));
    }
    if username.len() > SSH_USERNAME_MAX_LEN {
        return Err(PrincipalMappingError::InvalidSshUsername(
            "exceeds maximum length",
        ));
    }
    if username.trim() != username {
        return Err(PrincipalMappingError::InvalidSshUsername(
            "must not contain leading or trailing whitespace",
        ));
    }
    if username.chars().any(char::is_control) {
        return Err(PrincipalMappingError::InvalidSshUsername(
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Attaches authorization grants (roles and groups) to a principal.
///
/// This is a thin, intention-revealing wrapper over
/// [`TrustedPrincipal::with_roles`]/[`with_groups`](TrustedPrincipal::with_groups):
/// call it **only** with roles/groups resolved from a signed policy source
/// (e.g. the `opc-persist` security-policy datastore). Never pass values taken
/// from transport metadata, gRPC headers, or the client-supplied request body.
pub fn with_signed_grants<R, G, RI, GI>(
    principal: TrustedPrincipal,
    roles: R,
    groups: G,
) -> TrustedPrincipal
where
    R: IntoIterator<Item = RI>,
    RI: Into<String>,
    G: IntoIterator<Item = GI>,
    GI: Into<String>,
{
    principal.with_roles(roles).with_groups(groups)
}

/// Resolves signed grants and attaches them to the already-authenticated
/// principal.
pub fn attach_signed_grants_from_source<S>(
    principal: TrustedPrincipal,
    source: &S,
) -> Result<TrustedPrincipal, GrantResolutionError>
where
    S: SignedGrantSource + ?Sized,
{
    let grants = source.signed_grants_for(&principal)?;
    Ok(with_signed_grants(principal, grants.roles, grants.groups))
}

fn identity_wire_key(identity: &ConfigWorkloadIdentity) -> String {
    match identity {
        ConfigWorkloadIdentity::Spiffe(spiffe) => format!("spiffe:{}", spiffe.as_str()),
        ConfigWorkloadIdentity::User(user) => format!("user:{user}"),
        ConfigWorkloadIdentity::Internal(name) => format!("internal:{name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::AuthStrength;
    use opc_identity::{Namespace, ServiceAccount, TrustDomain, WorkloadIdentity};
    use opc_types::{InstanceId, NfKind, SpiffeId, TenantId, Timestamp};

    fn sample_identity() -> WorkloadIdentity {
        WorkloadIdentity {
            trust_domain: TrustDomain::new("example.org").expect("trust domain"),
            tenant: TenantId::from_static("acme"),
            namespace: Namespace::new("default").expect("namespace"),
            service_account: ServiceAccount::new("gnmi").expect("service account"),
            nf_kind: NfKind::amf(),
            instance: InstanceId::from_static("i1"),
            spiffe_id: SpiffeId::new(
                "spiffe://example.org/tenant/acme/ns/default/sa/gnmi/nf/amf/instance/i1",
            )
            .expect("spiffe id"),
            expires_at: Timestamp::now_utc(),
        }
    }

    #[test]
    fn maps_spiffe_identity_and_tenant() {
        let id = sample_identity();
        let principal = principal_for_workload(&id);

        match &principal.identity {
            ConfigWorkloadIdentity::Spiffe(s) => assert_eq!(s, &id.spiffe_id),
            other => panic!("expected Spiffe identity, got {other:?}"),
        }
        assert_eq!(principal.tenant, id.tenant);
    }

    #[test]
    fn stamps_mutual_tls_auth_strength() {
        let principal = principal_for_workload(&sample_identity());
        assert_eq!(principal.auth_strength, AuthStrength::MutualTls);
    }

    #[test]
    fn carries_no_transport_derived_grants() {
        // The security-critical invariant: a freshly mapped principal must have
        // NO roles or groups. Transport authentication never confers authority;
        // that can only come from signed policy.
        let principal = principal_for_workload(&sample_identity());
        assert!(principal.roles.is_empty());
        assert!(principal.groups.is_empty());
    }

    #[test]
    fn maps_ssh_user_identity_and_tenant_without_grants() {
        let principal =
            principal_for_ssh_user("operator@example.org", TenantId::from_static("acme"))
                .expect("ssh principal");

        assert_eq!(principal.auth_strength, AuthStrength::SshPublicKey);
        assert_eq!(principal.tenant, TenantId::from_static("acme"));
        assert!(principal.roles.is_empty());
        assert!(principal.groups.is_empty());
        match principal.identity {
            ConfigWorkloadIdentity::User(user) => assert_eq!(user, "operator@example.org"),
            other => panic!("expected SSH user identity, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unsafe_ssh_usernames() {
        for username in ["", " operator", "operator ", "operator\nname"] {
            assert!(matches!(
                principal_for_ssh_user(username, TenantId::from_static("acme")),
                Err(PrincipalMappingError::InvalidSshUsername(_))
            ));
        }

        let too_long = "a".repeat(SSH_USERNAME_MAX_LEN + 1);
        assert!(matches!(
            principal_for_ssh_user(too_long, TenantId::from_static("acme")),
            Err(PrincipalMappingError::InvalidSshUsername(_))
        ));
    }

    #[test]
    fn signed_grants_are_attached_explicitly() {
        let principal = principal_for_workload(&sample_identity());
        let original = principal.clone();

        let granted = with_signed_grants(principal, ["nacm-admin"], ["operators"]);

        assert_eq!(granted.roles, vec!["nacm-admin".to_string()]);
        assert_eq!(granted.groups, vec!["operators".to_string()]);
        // Auth strength and identity survive grant attachment.
        assert_eq!(granted.identity, original.identity);
        assert_eq!(granted.tenant, original.tenant);
        assert_eq!(granted.auth_strength, original.auth_strength);
    }

    #[test]
    fn in_memory_signed_grant_store_attaches_policy_groups() {
        let principal = principal_for_workload(&sample_identity());
        let mut source = InMemorySignedGrantStore::new();
        source.insert_principal(
            &principal,
            SignedPrincipalGrants::new(["security-admin"], ["telco-writer"]),
        );

        let granted = attach_signed_grants_from_source(principal, &source).expect("grants");

        assert_eq!(granted.roles, vec!["security-admin".to_string()]);
        assert_eq!(granted.groups, vec!["telco-writer".to_string()]);
    }

    #[test]
    fn signed_grants_are_tenant_and_identity_scoped() {
        let principal = principal_for_workload(&sample_identity());
        let other_tenant = TrustedPrincipal::new(
            principal.identity.clone(),
            TenantId::from_static("other-tenant"),
        );
        let mut source = InMemorySignedGrantStore::new();
        source.insert_principal(
            &principal,
            SignedPrincipalGrants::new(["security-admin"], ["tenant-a-writers"]),
        );

        let granted =
            attach_signed_grants_from_source(other_tenant, &source).expect("missing grants");

        assert!(granted.roles.is_empty());
        assert!(granted.groups.is_empty());
    }

    #[test]
    fn missing_signed_grants_leave_principal_without_authority() {
        let principal = principal_for_workload(&sample_identity());
        let source = InMemorySignedGrantStore::new();

        let granted = attach_signed_grants_from_source(principal, &source).expect("empty grants");

        assert!(granted.roles.is_empty());
        assert!(granted.groups.is_empty());
    }

    #[test]
    fn signed_grant_source_errors_are_payload_free() {
        struct FailingSource;
        impl SignedGrantSource for FailingSource {
            fn signed_grants_for(
                &self,
                _principal: &TrustedPrincipal,
            ) -> Result<SignedPrincipalGrants, GrantResolutionError> {
                Err(GrantResolutionError)
            }
        }

        let principal = principal_for_workload(&sample_identity());
        let err =
            attach_signed_grants_from_source(principal, &FailingSource).expect_err("source error");

        assert_eq!(err.to_string(), "signed principal grants unavailable");
        assert!(!err.to_string().contains("db"));
    }
}
