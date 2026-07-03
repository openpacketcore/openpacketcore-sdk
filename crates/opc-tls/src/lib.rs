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

/// Authorization policy applied to an authenticated peer's SPIFFE workload
/// identity, after the certificate chain has been verified against the trust
/// bundles.
///
/// Each field is an optional allowlist; `None` means "no constraint on this
/// dimension". **A policy with every field `None` — including the derived
/// [`Default`] — authorizes any peer whose certificate chains to a trusted
/// bundle: authentication without authorization.** Callers that need
/// authorization must populate at least one allowlist; use
/// [`PeerPolicy::is_unconstrained`] to detect the allow-all case and fail
/// closed at configuration time (e.g. in production) rather than silently
/// admitting every trusted peer.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    pub allowed_trust_domains: Option<HashSet<TrustDomain>>,
    pub allowed_tenants: Option<HashSet<TenantId>>,
    pub allowed_nf_kinds: Option<HashSet<NfKind>>,
    pub allowed_instances: Option<HashSet<InstanceId>>,
}

impl PeerPolicy {
    /// Returns `true` when the policy imposes no constraints and will therefore
    /// authorize any authenticated peer. Configuration layers should reject an
    /// unconstrained policy where authorization is required (e.g. production).
    pub fn is_unconstrained(&self) -> bool {
        self.allowed_trust_domains.is_none()
            && self.allowed_tenants.is_none()
            && self.allowed_nf_kinds.is_none()
            && self.allowed_instances.is_none()
    }

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
        if state.is_expired() {
            return None;
        }
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
        self.state_rx
            .borrow()
            .as_ref()
            .is_some_and(|state| !state.is_expired())
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
        if state.is_expired() {
            return None;
        }
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
        if state.is_expired() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

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
        if state.is_expired() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

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

pub type ServerConfig = rustls::ServerConfig;
pub type ClientConfig = rustls::ClientConfig;

pub struct TlsConfigBuilder {
    state_rx: watch::Receiver<Option<IdentityState>>,
    policy: PeerPolicy,
    compat_mode: bool,
    allow_unconstrained_peer_policy: bool,
}

impl TlsConfigBuilder {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>) -> Self {
        Self {
            state_rx,
            policy: PeerPolicy::default(),
            compat_mode: false,
            allow_unconstrained_peer_policy: false,
        }
    }

    pub fn with_policy(mut self, policy: PeerPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Explicitly authorize any peer whose certificate chains to a trusted
    /// bundle.
    ///
    /// This is intentionally separate from [`TlsConfigBuilder::new`] so callers
    /// must opt in to authentication-only behavior instead of getting it by
    /// omission.
    pub fn allow_any_trusted_peer(mut self) -> Self {
        self.allow_unconstrained_peer_policy = true;
        self
    }

    pub fn with_compat_mode(mut self, enabled: bool) -> Self {
        self.compat_mode = enabled;
        self
    }

    pub fn build_client_config(self) -> Result<rustls::ClientConfig, rustls::Error> {
        self.validate_peer_policy()?;

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
        self.validate_peer_policy()?;

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

    fn validate_peer_policy(&self) -> Result<(), rustls::Error> {
        if self.policy.is_unconstrained() && !self.allow_unconstrained_peer_policy {
            return Err(rustls::Error::General(
                "unconstrained SPIFFE peer policy requires explicit allow_any_trusted_peer() opt-in"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use opc_identity::{Namespace, ServiceAccount};
    use opc_types::{SpiffeId, Timestamp};

    fn workload(td: &str, tenant: &str, nf: &str, inst: &str) -> WorkloadIdentity {
        WorkloadIdentity {
            trust_domain: TrustDomain::new(td).unwrap(),
            tenant: TenantId::new(tenant).unwrap(),
            namespace: Namespace::new("core").unwrap(),
            service_account: ServiceAccount::new("default").unwrap(),
            nf_kind: NfKind::new(nf).unwrap(),
            instance: InstanceId::new(inst).unwrap(),
            spiffe_id: SpiffeId::new(format!(
                "spiffe://{td}/tenant/{tenant}/ns/core/sa/default/nf/{nf}/instance/{inst}"
            ))
            .unwrap(),
            expires_at: Timestamp::now_utc(),
        }
    }

    fn td_set(v: &str) -> HashSet<TrustDomain> {
        HashSet::from([TrustDomain::new(v).unwrap()])
    }

    #[test]
    fn unconstrained_policy_authorizes_any_peer() {
        // Pins (and documents) the allow-all behavior of an unconfigured policy.
        let policy = PeerPolicy::default();
        assert!(policy.is_unconstrained());
        assert!(policy
            .check(&workload("example.test", "tenant-a", "amf", "amf-01"))
            .is_ok());
    }

    #[test]
    fn each_dimension_rejects_a_non_allowlisted_peer() {
        let id = workload("example.test", "tenant-a", "amf", "amf-01");

        let by_td = PeerPolicy {
            allowed_trust_domains: Some(td_set("other.test")),
            ..Default::default()
        };
        assert!(!by_td.is_unconstrained());
        assert!(by_td.check(&id).is_err());

        let by_tenant = PeerPolicy {
            allowed_tenants: Some(HashSet::from([TenantId::new("tenant-b").unwrap()])),
            ..Default::default()
        };
        assert!(by_tenant.check(&id).is_err());

        let by_nf = PeerPolicy {
            allowed_nf_kinds: Some(HashSet::from([NfKind::new("smf").unwrap()])),
            ..Default::default()
        };
        assert!(by_nf.check(&id).is_err());

        let by_instance = PeerPolicy {
            allowed_instances: Some(HashSet::from([InstanceId::new("amf-99").unwrap()])),
            ..Default::default()
        };
        assert!(by_instance.check(&id).is_err());
    }

    #[test]
    fn matching_allowlists_authorize_the_peer() {
        let id = workload("example.test", "tenant-a", "amf", "amf-01");
        let policy = PeerPolicy {
            allowed_trust_domains: Some(td_set("example.test")),
            allowed_tenants: Some(HashSet::from([TenantId::new("tenant-a").unwrap()])),
            allowed_nf_kinds: Some(HashSet::from([NfKind::new("amf").unwrap()])),
            allowed_instances: Some(HashSet::from([InstanceId::new("amf-01").unwrap()])),
        };
        assert!(policy.check(&id).is_ok());
    }

    #[test]
    fn builder_rejects_unconstrained_policy_without_explicit_opt_in() {
        let (_tx, rx) = watch::channel(None);
        let err = TlsConfigBuilder::new(rx)
            .build_server_config()
            .expect_err("default unconstrained policy must fail closed");

        assert!(err
            .to_string()
            .contains("requires explicit allow_any_trusted_peer() opt-in"));
    }

    #[test]
    fn builder_accepts_unconstrained_policy_with_explicit_opt_in() {
        let (_tx, rx) = watch::channel(None);
        let result = TlsConfigBuilder::new(rx)
            .allow_any_trusted_peer()
            .build_server_config();

        assert!(result.is_ok());
    }
}
