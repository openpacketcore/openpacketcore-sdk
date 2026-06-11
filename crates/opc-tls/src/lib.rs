//! Reloadable SPIFFE-aware mTLS client and server support for OpenPacketCore.
//!
//! Wraps rustls with SPIFFE-SVID-driven certificate selection and hot reload.

use opc_identity::{IdentityState, TrustDomain, WorkloadIdentity};
use opc_types::{InstanceId, NfKind, TenantId};
use rustls::DistinguishedName;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::watch;

const TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
const TLS13_WITH_TLS12_COMPAT: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS13, &rustls::version::TLS12];

fn protocol_versions(compat_mode: bool) -> &'static [&'static rustls::SupportedProtocolVersion] {
    if compat_mode {
        &TLS13_WITH_TLS12_COMPAT
    } else {
        &TLS13_ONLY
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    pub allowed_trust_domains: Option<HashSet<TrustDomain>>,
    pub allowed_tenants: Option<HashSet<TenantId>>,
    pub allowed_nf_kinds: Option<HashSet<NfKind>>,
    pub allowed_instances: Option<HashSet<InstanceId>>,
}

impl PeerPolicy {
    pub fn check(&self, id: &WorkloadIdentity) -> Result<(), String> {
        if let Some(ref tds) = self.allowed_trust_domains {
            if !tds.contains(&id.trust_domain) {
                return Err(format!("Trust domain {} not allowed", id.trust_domain));
            }
        }
        if let Some(ref tenants) = self.allowed_tenants {
            if !tenants.contains(&id.tenant) {
                return Err(format!("Tenant {} not allowed", id.tenant));
            }
        }
        if let Some(ref kinds) = self.allowed_nf_kinds {
            if !kinds.contains(&id.nf_kind) {
                return Err(format!("NF kind {} not allowed", id.nf_kind));
            }
        }
        if let Some(ref instances) = self.allowed_instances {
            if !instances.contains(&id.instance) {
                return Err(format!("Instance {} not allowed", id.instance));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReloadingClientCertResolver {
    state_rx: watch::Receiver<Option<IdentityState>>,
}

impl ReloadingClientCertResolver {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>) -> Self {
        Self { state_rx }
    }
}

impl rustls::client::ResolvesClientCert for ReloadingClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let state = self.state_rx.borrow().clone()?;
        let certs = state.svid.cert_chain;
        let key = state.svid.private_key.clone_key();

        let provider = rustls::crypto::ring::default_provider();
        let signing_key = provider.key_provider.load_private_key(key).ok()?;
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            certs,
            signing_key,
        )))
    }

    fn has_certs(&self) -> bool {
        self.state_rx.borrow().is_some()
    }
}

#[derive(Debug)]
pub struct ReloadingServerCertResolver {
    state_rx: watch::Receiver<Option<IdentityState>>,
}

impl ReloadingServerCertResolver {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>) -> Self {
        Self { state_rx }
    }
}

impl rustls::server::ResolvesServerCert for ReloadingServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let state = self.state_rx.borrow().clone()?;
        let certs = state.svid.cert_chain;
        let key = state.svid.private_key.clone_key();

        let provider = rustls::crypto::ring::default_provider();
        let signing_key = provider.key_provider.load_private_key(key).ok()?;
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            certs,
            signing_key,
        )))
    }
}

#[derive(Debug)]
pub struct SpiffeServerCertVerifier {
    state_rx: watch::Receiver<Option<IdentityState>>,
    policy: PeerPolicy,
}

impl SpiffeServerCertVerifier {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>, policy: PeerPolicy) -> Self {
        Self { state_rx, policy }
    }
}

impl rustls::client::danger::ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let state = self.state_rx.borrow().clone().ok_or_else(|| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;

        let id = WorkloadIdentity::from_cert_der(end_entity.as_ref(), &state.trust_bundles)
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })?;

        self.policy.check(&id).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;

        let bundle = state.trust_bundles.get(&id.trust_domain).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        })?;

        let mut root_store = rustls::RootCertStore::empty();
        for root in &bundle.certificates {
            root_store.add(root.clone()).ok();
        }

        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        let provider = rustls::crypto::ring::default_provider();
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &root_store,
            intermediates,
            now,
            provider.signature_verification_algorithms.all,
        )?;

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let provider = rustls::crypto::ring::default_provider();
        provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct SpiffeClientCertVerifier {
    state_rx: watch::Receiver<Option<IdentityState>>,
    policy: PeerPolicy,
}

impl SpiffeClientCertVerifier {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>, policy: PeerPolicy) -> Self {
        Self { state_rx, policy }
    }
}

impl rustls::server::danger::ClientCertVerifier for SpiffeClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let state = self.state_rx.borrow().clone().ok_or_else(|| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;

        let id = WorkloadIdentity::from_cert_der(end_entity.as_ref(), &state.trust_bundles)
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })?;

        self.policy.check(&id).map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;

        let bundle = state.trust_bundles.get(&id.trust_domain).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        })?;

        let mut root_store = rustls::RootCertStore::empty();
        for root in &bundle.certificates {
            root_store.add(root.clone()).ok();
        }

        let default_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|_| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })?;

        default_verifier.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        let schemes = provider.signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        let schemes = provider.signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let provider = rustls::crypto::ring::default_provider();
        provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct TlsConfigBuilder {
    state_rx: watch::Receiver<Option<IdentityState>>,
    policy: PeerPolicy,
    compat_mode: bool,
}

impl TlsConfigBuilder {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>) -> Self {
        Self {
            state_rx,
            policy: PeerPolicy::default(),
            compat_mode: false,
        }
    }

    pub fn with_policy(mut self, policy: PeerPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_compat_mode(mut self, enabled: bool) -> Self {
        self.compat_mode = enabled;
        self
    }

    pub fn build_client_config(self) -> Result<rustls::ClientConfig, rustls::Error> {
        static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();
        INIT_CRYPTO.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
        });

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(SpiffeServerCertVerifier {
            state_rx: self.state_rx.clone(),
            policy: self.policy.clone(),
        });

        let resolver = Arc::new(ReloadingClientCertResolver {
            state_rx: self.state_rx,
        });

        let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(protocol_versions(self.compat_mode))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(resolver);

        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(client_config)
    }

    pub fn build_server_config(self) -> Result<rustls::ServerConfig, rustls::Error> {
        static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();
        INIT_CRYPTO.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
        });

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(SpiffeClientCertVerifier {
            state_rx: self.state_rx.clone(),
            policy: self.policy.clone(),
        });

        let resolver = Arc::new(ReloadingServerCertResolver {
            state_rx: self.state_rx,
        });

        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(protocol_versions(self.compat_mode))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);

        Ok(server_config)
    }
}
