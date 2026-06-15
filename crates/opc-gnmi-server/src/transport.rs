//! gNMI TLS principal extraction.
//!
//! `opc-tls`/rustls verifies the mTLS chain and peer policy during the
//! handshake. The gNMI listener re-derives the peer workload identity from the
//! verified leaf certificate and maps it to a grant-free config-bus principal.

use opc_config_model::TrustedPrincipal;
use opc_identity::{IdentityReloadError, IdentityState, WorkloadIdentity};
use thiserror::Error;
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Error deriving a gNMI principal from a verified TLS peer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GnmiTlsPrincipalError {
    /// The hot-reload identity watch has not produced a usable identity state.
    #[error("gNMI TLS identity state is unavailable")]
    MissingIdentityState,
    /// rustls did not expose a peer certificate chain after mTLS.
    #[error("gNMI TLS peer certificate is missing")]
    MissingPeerCertificate,
    /// The peer certificate could not be decoded into an allowed SPIFFE
    /// workload identity.
    #[error("gNMI TLS peer identity is invalid")]
    InvalidPeerIdentity(#[from] IdentityReloadError),
}

/// Derives a principal from a rustls server-side TLS stream.
pub fn principal_from_tls_stream<IO>(
    stream: &tokio_rustls::server::TlsStream<IO>,
    identity_rx: &watch::Receiver<Option<IdentityState>>,
) -> Result<TrustedPrincipal, GnmiTlsPrincipalError> {
    let (_, connection) = stream.get_ref();
    let certs = connection
        .peer_certificates()
        .ok_or(GnmiTlsPrincipalError::MissingPeerCertificate)?;
    principal_from_identity_watch(certs, identity_rx)
}

/// Derives a principal from a verified peer certificate chain and current
/// identity state.
pub fn principal_from_identity_watch(
    peer_certs: &[CertificateDer<'static>],
    identity_rx: &watch::Receiver<Option<IdentityState>>,
) -> Result<TrustedPrincipal, GnmiTlsPrincipalError> {
    let state = identity_rx.borrow();
    let state = state
        .as_ref()
        .ok_or(GnmiTlsPrincipalError::MissingIdentityState)?;
    principal_from_identity_state(peer_certs, state)
}

/// Derives a principal from a verified peer certificate chain and an identity
/// state containing the active trust bundles.
pub fn principal_from_identity_state(
    peer_certs: &[CertificateDer<'static>],
    identity_state: &IdentityState,
) -> Result<TrustedPrincipal, GnmiTlsPrincipalError> {
    let peer_leaf = peer_certs
        .first()
        .ok_or(GnmiTlsPrincipalError::MissingPeerCertificate)?;
    let identity =
        WorkloadIdentity::from_cert_der(peer_leaf.as_ref(), &identity_state.trust_bundles)?;
    Ok(opc_mgmt_principal::principal_for_workload(&identity))
}

#[cfg(test)]
mod tests {
    use opc_config_model::{AuthStrength, WorkloadIdentity as ConfigWorkloadIdentity};
    use opc_identity::{
        parse_certs_pem, parse_key_pem, IdentityReloadError, IdentityState, SvidDocument,
        TrustBundle, TrustBundleSet, TrustDomain, WorkloadIdentity,
    };
    use opc_types::Timestamp;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tokio::sync::watch;

    use super::*;

    fn generate_test_certs(
        spiffe_id: &str,
    ) -> (rcgen::Certificate, KeyPair, rcgen::Certificate, KeyPair) {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut wl_params = CertificateParams::default();
        wl_params
            .distinguished_name
            .push(DnType::CommonName, "Workload");
        wl_params.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("spiffe san"),
        ));

        let now = ::time::OffsetDateTime::now_utc();
        wl_params.not_before = now - ::time::Duration::days(1);
        wl_params.not_after = now + ::time::Duration::days(1);

        let wl_key = KeyPair::generate().expect("workload key");
        let wl_cert = wl_params
            .signed_by(&wl_key, &ca_cert, &ca_key)
            .expect("workload cert");

        (ca_cert, ca_key, wl_cert, wl_key)
    }

    fn identity_state_and_peer_chain(
        spiffe_id: &str,
    ) -> (IdentityState, Vec<CertificateDer<'static>>) {
        let (ca_cert, _ca_key, wl_cert, wl_key) = generate_test_certs(spiffe_id);
        let ca_certs = parse_certs_pem(&ca_cert.pem()).expect("ca cert pem");
        let peer_chain = parse_certs_pem(&(wl_cert.pem() + &ca_cert.pem())).expect("peer chain");

        let trust_domain_name = spiffe_id
            .strip_prefix("spiffe://")
            .expect("spiffe prefix")
            .split('/')
            .next()
            .expect("trust domain name");
        let trust_domain = TrustDomain::new(trust_domain_name).expect("trust domain");
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: ca_certs,
        });

        let identity = WorkloadIdentity::from_cert_der(peer_chain[0].as_ref(), &trust_bundles)
            .expect("identity");
        let private_key = parse_key_pem(&wl_key.serialize_pem()).expect("private key");
        let svid = SvidDocument {
            spiffe_id: identity.spiffe_id.clone(),
            cert_chain: peer_chain.clone(),
            private_key,
            expires_at: Timestamp::now_utc(),
        };

        (
            IdentityState {
                identity,
                svid,
                trust_bundles,
            },
            peer_chain,
        )
    }

    #[test]
    fn maps_verified_spiffe_peer_to_mutual_tls_principal_without_grants() {
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0";
        let (state, peer_chain) = identity_state_and_peer_chain(spiffe);

        let principal =
            principal_from_identity_state(&peer_chain, &state).expect("principal from cert");

        assert_eq!(principal.auth_strength, AuthStrength::MutualTls);
        assert_eq!(principal.tenant.as_str(), "test");
        assert!(principal.roles.is_empty());
        assert!(principal.groups.is_empty());
        match principal.identity {
            ConfigWorkloadIdentity::Spiffe(id) => assert_eq!(id.as_str(), spiffe),
            other => panic!("expected SPIFFE principal, got {other:?}"),
        }
    }

    #[test]
    fn missing_peer_certificate_fails_closed() {
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0";
        let (state, _peer_chain) = identity_state_and_peer_chain(spiffe);

        let err = principal_from_identity_state(&[], &state).expect_err("missing cert");

        assert_eq!(err, GnmiTlsPrincipalError::MissingPeerCertificate);
    }

    #[test]
    fn missing_identity_state_fails_closed() {
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0";
        let (_state, peer_chain) = identity_state_and_peer_chain(spiffe);
        let (_tx, rx) = watch::channel(None);

        let err = principal_from_identity_watch(&peer_chain, &rx).expect_err("missing identity");

        assert_eq!(err, GnmiTlsPrincipalError::MissingIdentityState);
    }

    #[test]
    fn unknown_trust_domain_fails_closed() {
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0";
        let (mut state, peer_chain) = identity_state_and_peer_chain(spiffe);
        state.trust_bundles = TrustBundleSet::new();

        let err = principal_from_identity_state(&peer_chain, &state).expect_err("unknown domain");

        assert!(matches!(
            err,
            GnmiTlsPrincipalError::InvalidPeerIdentity(IdentityReloadError::UnknownTrustDomain)
        ));
    }
}
