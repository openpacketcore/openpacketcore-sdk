//! Maps a transport-authenticated SPIFFE workload identity to a config-bus
//! [`TrustedPrincipal`].
//!
//! The gNMI and NETCONF servers terminate mTLS and derive the peer's
//! [`opc_identity::WorkloadIdentity`] (via `WorkloadIdentity::from_cert_der` on
//! the verified peer leaf). Before a request can be authorized or committed it
//! must become an [`opc_config_model::TrustedPrincipal`]. This crate is that one
//! boundary.
//!
//! Security contract (RFC 003): the conversion stamps
//! [`AuthStrength::MutualTls`] and carries the SPIFFE id + tenant, but the
//! resulting principal has **no roles and no groups**. Authorization grants must
//! be sourced only from signed policy (the `opc-persist` NACM policy datastore),
//! never from transport metadata. Callers attach grants *after* this conversion
//! with [`with_signed_grants`], which documents that requirement at the call
//! site; using transport-derived roles/groups is a security defect.
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

use opc_config_model::{
    AuthStrength, TrustedPrincipal, WorkloadIdentity as ConfigWorkloadIdentity,
};
use opc_identity::WorkloadIdentity as TransportIdentity;

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
}
