//! NETCONF transport principal extraction and authenticated-session helpers.
//!
//! `opc-tls`/rustls performs mTLS chain verification and peer-policy checks
//! during the handshake. The verifier intentionally does not attach an
//! application principal to the stream, so the server re-derives the peer
//! [`opc_identity::WorkloadIdentity`] from the verified peer leaf certificate
//! and maps it through `opc-mgmt-principal`.
//!
//! NETCONF-over-SSH uses the same transport-neutral session runner after an SSH
//! layer has authenticated a public key or SSH certificate. This module exposes
//! a narrow SSH entry point that validates the already-authenticated principal
//! and server transport before handing the byte stream to NETCONF.

use opc_config_model::{AuthStrength, OpcConfig, TransportType, TrustedPrincipal};
use opc_identity::{IdentityReloadError, IdentityState, WorkloadIdentity};
use opc_mgmt_audit::AuditSink;
use opc_mgmt_authz::PolicySource;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::binding::NetconfConfigBinding;
use crate::server::ReadOnlyNetconfServer;
use crate::session::{
    run_read_only_session, run_read_only_session_with_registry, SessionConfig, SessionError,
    SessionResult,
};
use crate::session_registry::SessionRegistry;

/// Error deriving a NETCONF principal from a verified TLS peer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TlsPrincipalError {
    /// The hot-reload identity watch has not produced a usable identity state.
    #[error("NETCONF TLS identity state is unavailable")]
    MissingIdentityState,
    /// rustls did not expose a peer certificate chain after mTLS.
    #[error("NETCONF TLS peer certificate is missing")]
    MissingPeerCertificate,
    /// The peer certificate could not be decoded into an allowed SPIFFE
    /// workload identity.
    #[error("NETCONF TLS peer identity is invalid")]
    InvalidPeerIdentity(#[from] IdentityReloadError),
}

/// Error running a NETCONF session over a verified TLS stream.
#[derive(Debug, Error)]
pub enum TlsSessionError {
    /// Principal extraction failed before the NETCONF hello exchange.
    #[error(transparent)]
    Principal(#[from] TlsPrincipalError),
    /// NETCONF session handling failed.
    #[error(transparent)]
    Session(#[from] SessionError),
}

/// Error running a NETCONF session over an already-authenticated SSH channel.
#[derive(Debug, Error)]
pub enum SshSessionError {
    /// The server core was not constructed for `TransportType::NetconfSsh`.
    #[error("NETCONF SSH session requires a NetconfSsh server transport")]
    WrongServerTransport {
        /// Transport currently recorded by the server.
        actual: TransportType,
    },
    /// The supplied principal did not come from SSH public-key/certificate auth.
    #[error("NETCONF SSH session requires an SshPublicKey principal")]
    WrongPrincipalAuthStrength {
        /// Auth strength currently carried by the principal.
        actual: AuthStrength,
    },
    /// NETCONF session handling failed.
    #[error(transparent)]
    Session(#[from] SessionError),
}

/// Derives a principal from a rustls server-side TLS stream.
pub fn principal_from_tls_stream<IO>(
    stream: &tokio_rustls::server::TlsStream<IO>,
    identity_rx: &watch::Receiver<Option<IdentityState>>,
) -> Result<TrustedPrincipal, TlsPrincipalError> {
    let (_, connection) = stream.get_ref();
    let certs = connection
        .peer_certificates()
        .ok_or(TlsPrincipalError::MissingPeerCertificate)?;
    principal_from_identity_watch(certs, identity_rx)
}

/// Derives a principal from a verified peer certificate chain and current
/// identity state.
pub fn principal_from_identity_watch(
    peer_certs: &[CertificateDer<'static>],
    identity_rx: &watch::Receiver<Option<IdentityState>>,
) -> Result<TrustedPrincipal, TlsPrincipalError> {
    let state = identity_rx.borrow();
    let state = state
        .as_ref()
        .ok_or(TlsPrincipalError::MissingIdentityState)?;
    principal_from_identity_state(peer_certs, state)
}

/// Derives a principal from a verified peer certificate chain and an identity
/// state containing the active trust bundles.
pub fn principal_from_identity_state(
    peer_certs: &[CertificateDer<'static>],
    identity_state: &IdentityState,
) -> Result<TrustedPrincipal, TlsPrincipalError> {
    let peer_leaf = peer_certs
        .first()
        .ok_or(TlsPrincipalError::MissingPeerCertificate)?;
    let identity =
        WorkloadIdentity::from_cert_der(peer_leaf.as_ref(), &identity_state.trust_bundles)?;
    Ok(opc_mgmt_principal::principal_for_workload(&identity))
}

/// Runs a read-only NETCONF session over an already-accepted TLS stream.
///
/// This convenience helper creates an isolated session registry after principal
/// extraction. Use [`run_read_only_tls_session_with_registry`] when multiple TLS
/// sessions must be addressable by RFC 6241 `<kill-session>`.
pub async fn run_read_only_tls_session<C, B, P, A, IO>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    stream: &mut tokio_rustls::server::TlsStream<IO>,
    identity_rx: &watch::Receiver<Option<IdentityState>>,
    config: SessionConfig,
    session_id: u64,
) -> Result<SessionResult, TlsSessionError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let principal = principal_from_tls_stream(stream, identity_rx)?;
    Ok(run_read_only_session(server, &principal, stream, config, session_id).await?)
}

/// Runs a read-only NETCONF TLS session registered for cross-session
/// `<kill-session>` control.
pub async fn run_read_only_tls_session_with_registry<C, B, P, A, IO>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    stream: &mut tokio_rustls::server::TlsStream<IO>,
    identity_rx: &watch::Receiver<Option<IdentityState>>,
    config: SessionConfig,
    session_id: u64,
    sessions: &SessionRegistry,
) -> Result<SessionResult, TlsSessionError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let principal = principal_from_tls_stream(stream, identity_rx)?;
    Ok(run_read_only_session_with_registry(
        server, &principal, stream, config, session_id, sessions,
    )
    .await?)
}

/// Runs a NETCONF session over an already-authenticated SSH channel.
///
/// This helper intentionally does not perform the SSH handshake or host/client
/// key validation. It is the safe boundary that an SSH implementation calls
/// *after* public-key or SSH-certificate authentication maps the peer to a
/// `TrustedPrincipal` through `opc-mgmt-principal`.
pub async fn run_read_only_ssh_session<C, B, P, A, IO>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    principal: &TrustedPrincipal,
    stream: &mut IO,
    config: SessionConfig,
    session_id: u64,
) -> Result<SessionResult, SshSessionError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    validate_ssh_session_context(server, principal)?;
    Ok(run_read_only_session(server, principal, stream, config, session_id).await?)
}

/// Runs an authenticated SSH NETCONF session registered for cross-session
/// `<kill-session>` control.
pub async fn run_read_only_ssh_session_with_registry<C, B, P, A, IO>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    principal: &TrustedPrincipal,
    stream: &mut IO,
    config: SessionConfig,
    session_id: u64,
    sessions: &SessionRegistry,
) -> Result<SessionResult, SshSessionError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    validate_ssh_session_context(server, principal)?;
    Ok(
        run_read_only_session_with_registry(
            server, principal, stream, config, session_id, sessions,
        )
        .await?,
    )
}

fn validate_ssh_session_context<C, B, P, A>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    principal: &TrustedPrincipal,
) -> Result<(), SshSessionError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    let actual_transport = server.transport_type();
    if actual_transport != TransportType::NetconfSsh {
        return Err(SshSessionError::WrongServerTransport {
            actual: actual_transport,
        });
    }
    if principal.auth_strength != AuthStrength::SshPublicKey {
        return Err(SshSessionError::WrongPrincipalAuthStrength {
            actual: principal.auth_strength,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use opc_config_model::{AuthStrength, WorkloadIdentity as ConfigWorkloadIdentity};
    use opc_identity::{
        parse_certs_pem, parse_key_pem, IdentityState, SvidDocument, TrustBundle, TrustBundleSet,
        TrustDomain, WorkloadIdentity,
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
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/netconf/nf/amf/instance/0";
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
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/netconf/nf/amf/instance/0";
        let (state, _peer_chain) = identity_state_and_peer_chain(spiffe);

        let err = principal_from_identity_state(&[], &state).expect_err("missing cert");

        assert_eq!(err, TlsPrincipalError::MissingPeerCertificate);
    }

    #[test]
    fn missing_identity_state_fails_closed() {
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/netconf/nf/amf/instance/0";
        let (_state, peer_chain) = identity_state_and_peer_chain(spiffe);
        let (_tx, rx) = watch::channel(None);

        let err = principal_from_identity_watch(&peer_chain, &rx).expect_err("missing identity");

        assert_eq!(err, TlsPrincipalError::MissingIdentityState);
    }

    #[test]
    fn unknown_trust_domain_fails_closed() {
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/netconf/nf/amf/instance/0";
        let (mut state, peer_chain) = identity_state_and_peer_chain(spiffe);
        state.trust_bundles = TrustBundleSet::new();

        let err = principal_from_identity_state(&peer_chain, &state).expect_err("unknown domain");

        assert!(matches!(
            err,
            TlsPrincipalError::InvalidPeerIdentity(IdentityReloadError::UnknownTrustDomain)
        ));
    }
}
