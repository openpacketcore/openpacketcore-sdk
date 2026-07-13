//! Reloadable SPIFFE-aware mTLS client and server support for OpenPacketCore.
//!
//! Wraps rustls with SPIFFE-SVID-driven certificate selection and hot reload.

#![forbid(unsafe_code)]

use opc_identity::{
    extract_spiffe_id_from_cert_der, IdentityState, SpiffeSanError, TrustBundle, TrustDomain,
    WorkloadIdentity,
};
use opc_types::{InstanceId, NfKind, SpiffeId, TenantId, Timestamp};
use rustls::DistinguishedName;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use tokio::sync::watch;
use x509_parser::prelude::{FromDer, X509Certificate};

mod material;
pub use material::{
    TlsAdmittedConnection, TlsClientHandshake, TlsHandshakeOutcome, TlsHandshakeRunError,
    TlsMaterialAvailability, TlsMaterialController, TlsMaterialEpoch, TlsMaterialError,
    TlsMaterialReloadReason, TlsMaterialStatus, TlsMaterialStatusReceiver, TlsServerHandshake,
    MAX_TLS_CONCURRENT_HANDSHAKES, MAX_TLS_HANDSHAKE_EPOCH_RETRIES,
    MAX_TLS_MATERIAL_CHAIN_CERTIFICATES, MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES,
    MAX_TLS_MATERIAL_TOTAL_BYTES, MAX_TLS_MATERIAL_TRUST_ANCHORS, MAX_TLS_MATERIAL_TRUST_BUNDLES,
};

const TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
const TLS13_WITH_TLS12_COMPAT: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS13, &rustls::version::TLS12];
const RAW_CONFIG_MATERIAL_SETTINGS_ERROR: &str =
    "TLS material pinning requires an authenticated TLS config builder";

fn protocol_versions(compat_mode: bool) -> &'static [&'static rustls::SupportedProtocolVersion] {
    if compat_mode {
        &TLS13_WITH_TLS12_COMPAT
    } else {
        &TLS13_ONLY
    }
}

#[derive(Clone, Copy)]
struct CertificateValidity {
    not_before: Timestamp,
    not_after: Timestamp,
}

fn certificate_validity(certificate: &CertificateDer<'_>) -> Result<CertificateValidity, ()> {
    let (remaining, certificate) =
        X509Certificate::from_der(certificate.as_ref()).map_err(|_| ())?;
    if !remaining.is_empty() {
        return Err(());
    }
    let not_before =
        time::OffsetDateTime::from_unix_timestamp(certificate.validity().not_before.timestamp())
            .map_err(|_| ())?;
    let not_after =
        time::OffsetDateTime::from_unix_timestamp(certificate.validity().not_after.timestamp())
            .map_err(|_| ())?;
    Ok(CertificateValidity {
        not_before: Timestamp::from_offset_datetime(not_before),
        not_after: Timestamp::from_offset_datetime(not_after),
    })
}

fn certificate_not_after(certificate: &CertificateDer<'_>) -> Result<Timestamp, ()> {
    certificate_validity(certificate).map(|validity| validity.not_after)
}

fn presented_certificate_chain_expires_at(
    certificates: &[CertificateDer<'_>],
) -> Result<Timestamp, ()> {
    let mut certificates = certificates.iter();
    let first = certificates.next().ok_or(())?;
    certificates.try_fold(certificate_not_after(first)?, |earliest, certificate| {
        certificate_not_after(certificate).map(|expires_at| earliest.min(expires_at))
    })
}

fn root_store_from_bundle(bundle: &TrustBundle) -> Result<rustls::RootCertStore, rustls::Error> {
    let mut root_store = rustls::RootCertStore::empty();
    for root in &bundle.certificates {
        root_store.add(root.clone())?;
    }
    Ok(root_store)
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

        let root_store = root_store_from_bundle(bundle)?;

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

        let root_store = root_store_from_bundle(bundle)?;

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

/// A rustls client configuration built with mandatory SPIFFE peer
/// authentication and a reloadable client SVID.
///
/// Construction is intentionally limited to
/// [`TlsConfigBuilder::build_authenticated_client_config`]. The wrapped
/// configuration is opaque so APIs that require authenticated mTLS can accept
/// this type instead of an arbitrary rustls configuration.
#[derive(Clone)]
pub struct AuthenticatedClientConfig {
    config: Arc<rustls::ClientConfig>,
    controller: TlsMaterialController,
    policy: PeerPolicy,
    compat_mode: bool,
    allow_unconstrained_peer_policy: bool,
}

impl AuthenticatedClientConfig {
    /// Clone the shared rustls configuration for a connection or connector.
    pub fn rustls_config(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(&self.config)
    }

    /// Current coherent material-controller status.
    pub fn material_status(&self) -> TlsMaterialStatus {
        self.controller.status()
    }

    /// Drive source changes and expose only reconciled redaction-safe status.
    pub fn subscribe_material_changes(&self) -> TlsMaterialStatusReceiver {
        self.controller.subscribe_material_changes()
    }

    /// Freeze one coherent client certificate/key/trust snapshot.
    ///
    /// Use the returned fixed config for TLS and call
    /// [`TlsClientHandshake::admit`] only after application negotiation.
    pub fn begin_handshake(&self) -> Result<TlsClientHandshake, TlsMaterialError> {
        let snapshot = self.controller.snapshot()?;
        let config = fixed_client_config(
            &snapshot,
            self.policy.clone(),
            self.compat_mode,
            self.allow_unconstrained_peer_policy,
        )?;
        Ok(TlsClientHandshake::new(
            Arc::new(config),
            self.controller.clone(),
            snapshot,
        ))
    }

    /// Run TLS plus application negotiation with bounded epoch-change retries.
    ///
    /// `operation` must return only after both TLS and the application protocol
    /// have completed their admission handshake. Cancellation drops the current
    /// immutable attempt and does not publish or retain partial state.
    pub async fn run_handshake<T, E, F, Fut>(
        &self,
        mut operation: F,
    ) -> Result<TlsHandshakeOutcome<T>, TlsHandshakeRunError<E>>
    where
        F: FnMut(TlsClientHandshake) -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let _permit = self
            .controller
            .acquire_handshake()
            .await
            .map_err(TlsHandshakeRunError::Material)?;
        for retry in 0..=MAX_TLS_HANDSHAKE_EPOCH_RETRIES {
            let handshake = self
                .begin_handshake()
                .map_err(TlsHandshakeRunError::Material)?;
            let value = match operation(handshake.clone()).await {
                Ok(value) => value,
                Err(error) => match handshake.admit() {
                    Err(TlsMaterialError::EpochChanged)
                        if retry < MAX_TLS_HANDSHAKE_EPOCH_RETRIES =>
                    {
                        continue;
                    }
                    Err(TlsMaterialError::EpochChanged) => {
                        return Err(TlsHandshakeRunError::Material(
                            TlsMaterialError::EpochRetryLimit,
                        ));
                    }
                    Err(material_error) => {
                        return Err(TlsHandshakeRunError::Material(material_error));
                    }
                    Ok(_) => return Err(TlsHandshakeRunError::Operation(error)),
                },
            };
            match handshake.admit() {
                Ok(admission) => return Ok(TlsHandshakeOutcome { value, admission }),
                Err(TlsMaterialError::EpochChanged) if retry < MAX_TLS_HANDSHAKE_EPOCH_RETRIES => {}
                Err(TlsMaterialError::EpochChanged) => {
                    return Err(TlsHandshakeRunError::Material(
                        TlsMaterialError::EpochRetryLimit,
                    ));
                }
                Err(error) => return Err(TlsHandshakeRunError::Material(error)),
            }
        }
        Err(TlsHandshakeRunError::Material(
            TlsMaterialError::EpochRetryLimit,
        ))
    }
}

impl fmt::Debug for AuthenticatedClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedClientConfig([redacted])")
    }
}

/// A rustls server configuration built with mandatory SPIFFE client
/// authentication and a reloadable server SVID.
///
/// Construction is intentionally limited to
/// [`TlsConfigBuilder::build_authenticated_server_config`].
#[derive(Clone)]
pub struct AuthenticatedServerConfig {
    config: Arc<rustls::ServerConfig>,
    controller: TlsMaterialController,
    policy: PeerPolicy,
    compat_mode: bool,
    allow_unconstrained_peer_policy: bool,
}

impl AuthenticatedServerConfig {
    /// Clone the shared rustls configuration for a connection or acceptor.
    pub fn rustls_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.config)
    }

    /// Current coherent material-controller status.
    pub fn material_status(&self) -> TlsMaterialStatus {
        self.controller.status()
    }

    /// Drive source changes and expose only reconciled redaction-safe status.
    pub fn subscribe_material_changes(&self) -> TlsMaterialStatusReceiver {
        self.controller.subscribe_material_changes()
    }

    /// Freeze one coherent server certificate/key/trust snapshot.
    ///
    /// Use the returned fixed config for TLS and call
    /// [`TlsServerHandshake::admit`] only after application negotiation.
    pub fn begin_handshake(&self) -> Result<TlsServerHandshake, TlsMaterialError> {
        let snapshot = self.controller.snapshot()?;
        let config = fixed_server_config(
            &snapshot,
            self.policy.clone(),
            self.compat_mode,
            self.allow_unconstrained_peer_policy,
        )?;
        Ok(TlsServerHandshake::new(
            Arc::new(config),
            self.controller.clone(),
            snapshot,
        ))
    }

    /// Run TLS plus application negotiation with bounded epoch-change retries.
    pub async fn run_handshake<T, E, F, Fut>(
        &self,
        mut operation: F,
    ) -> Result<TlsHandshakeOutcome<T>, TlsHandshakeRunError<E>>
    where
        F: FnMut(TlsServerHandshake) -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let _permit = self
            .controller
            .acquire_handshake()
            .await
            .map_err(TlsHandshakeRunError::Material)?;
        for retry in 0..=MAX_TLS_HANDSHAKE_EPOCH_RETRIES {
            let handshake = self
                .begin_handshake()
                .map_err(TlsHandshakeRunError::Material)?;
            let value = match operation(handshake.clone()).await {
                Ok(value) => value,
                Err(error) => match handshake.admit() {
                    Err(TlsMaterialError::EpochChanged)
                        if retry < MAX_TLS_HANDSHAKE_EPOCH_RETRIES =>
                    {
                        continue;
                    }
                    Err(TlsMaterialError::EpochChanged) => {
                        return Err(TlsHandshakeRunError::Material(
                            TlsMaterialError::EpochRetryLimit,
                        ));
                    }
                    Err(material_error) => {
                        return Err(TlsHandshakeRunError::Material(material_error));
                    }
                    Ok(_) => return Err(TlsHandshakeRunError::Operation(error)),
                },
            };
            match handshake.admit() {
                Ok(admission) => return Ok(TlsHandshakeOutcome { value, admission }),
                Err(TlsMaterialError::EpochChanged) if retry < MAX_TLS_HANDSHAKE_EPOCH_RETRIES => {}
                Err(TlsMaterialError::EpochChanged) => {
                    return Err(TlsHandshakeRunError::Material(
                        TlsMaterialError::EpochRetryLimit,
                    ));
                }
                Err(error) => return Err(TlsHandshakeRunError::Material(error)),
            }
        }
        Err(TlsHandshakeRunError::Material(
            TlsMaterialError::EpochRetryLimit,
        ))
    }
}

impl fmt::Debug for AuthenticatedServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedServerConfig([redacted])")
    }
}

/// Failure to recover the peer's canonical SPIFFE identity from a completed
/// rustls connection.
///
/// No variant carries certificate bytes or identity text, keeping `Display`
/// and `Debug` suitable for logs and protocol error mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeerSpiffeIdentityError {
    #[error("TLS handshake is incomplete")]
    HandshakeIncomplete,
    #[error("peer certificate is unavailable")]
    PeerCertificateUnavailable,
    #[error("peer certificate is malformed")]
    MalformedCertificate,
    #[error("peer certificate is missing a SPIFFE URI SAN")]
    MissingSpiffeId,
    #[error("peer certificate contains multiple URI SANs")]
    MultipleUriSans,
    #[error("peer certificate contains a malformed SPIFFE URI SAN")]
    MalformedSpiffeId,
}

/// Redaction-safe identity and certificate-expiry evidence from one completed
/// peer handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerTlsIdentity {
    spiffe_id: SpiffeId,
    leaf_expires_at: Timestamp,
    certificate_chain_expires_at: Timestamp,
}

impl fmt::Debug for PeerTlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerTlsIdentity([redacted])")
    }
}

impl PeerTlsIdentity {
    /// Canonical SPIFFE identity authenticated on this connection.
    pub const fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Peer leaf-certificate expiry authenticated on this connection.
    pub const fn leaf_expires_at(&self) -> Timestamp {
        self.leaf_expires_at
    }

    /// Earliest expiry across every certificate presented by the peer.
    pub const fn certificate_chain_expires_at(&self) -> Timestamp {
        self.certificate_chain_expires_at
    }
}

impl From<SpiffeSanError> for PeerSpiffeIdentityError {
    fn from(error: SpiffeSanError) -> Self {
        match error {
            SpiffeSanError::MalformedCertificate => Self::MalformedCertificate,
            SpiffeSanError::MissingSpiffeId => Self::MissingSpiffeId,
            SpiffeSanError::MultipleUriSans => Self::MultipleUriSans,
            SpiffeSanError::MalformedSpiffeId => Self::MalformedSpiffeId,
            _ => Self::MalformedSpiffeId,
        }
    }
}

fn peer_spiffe_id(
    is_handshaking: bool,
    peer_certificates: Option<&[CertificateDer<'static>]>,
) -> Result<SpiffeId, PeerSpiffeIdentityError> {
    if is_handshaking {
        return Err(PeerSpiffeIdentityError::HandshakeIncomplete);
    }

    let leaf = peer_certificates
        .and_then(|chain| chain.first())
        .ok_or(PeerSpiffeIdentityError::PeerCertificateUnavailable)?;
    extract_spiffe_id_from_cert_der(leaf.as_ref()).map_err(Into::into)
}

fn peer_tls_identity(
    is_handshaking: bool,
    peer_certificates: Option<&[CertificateDer<'static>]>,
) -> Result<PeerTlsIdentity, PeerSpiffeIdentityError> {
    if is_handshaking {
        return Err(PeerSpiffeIdentityError::HandshakeIncomplete);
    }
    let peer_certificates =
        peer_certificates.ok_or(PeerSpiffeIdentityError::PeerCertificateUnavailable)?;
    let leaf = peer_certificates
        .first()
        .ok_or(PeerSpiffeIdentityError::PeerCertificateUnavailable)?;
    let leaf_expires_at =
        certificate_not_after(leaf).map_err(|()| PeerSpiffeIdentityError::MalformedCertificate)?;
    let certificate_chain_expires_at = presented_certificate_chain_expires_at(peer_certificates)
        .map_err(|()| PeerSpiffeIdentityError::MalformedCertificate)?;
    Ok(PeerTlsIdentity {
        spiffe_id: extract_spiffe_id_from_cert_der(leaf.as_ref())?,
        leaf_expires_at,
        certificate_chain_expires_at,
    })
}

/// Extract the server SPIFFE ID presented on a completed rustls client
/// connection.
///
/// The result is authenticated only when `connection` was created from an
/// [`AuthenticatedClientConfig`].
pub fn peer_spiffe_id_from_client_connection(
    connection: &rustls::ClientConnection,
) -> Result<SpiffeId, PeerSpiffeIdentityError> {
    peer_spiffe_id(connection.is_handshaking(), connection.peer_certificates())
}

/// Extract canonical identity and certificate expiries from a completed server
/// certificate authenticated by a client connection.
pub fn peer_tls_identity_from_client_connection(
    connection: &rustls::ClientConnection,
) -> Result<PeerTlsIdentity, PeerSpiffeIdentityError> {
    peer_tls_identity(connection.is_handshaking(), connection.peer_certificates())
}

/// Extract the client SPIFFE ID presented on a completed rustls server
/// connection.
///
/// The result is authenticated only when `connection` was created from an
/// [`AuthenticatedServerConfig`].
pub fn peer_spiffe_id_from_server_connection(
    connection: &rustls::ServerConnection,
) -> Result<SpiffeId, PeerSpiffeIdentityError> {
    peer_spiffe_id(connection.is_handshaking(), connection.peer_certificates())
}

/// Extract canonical identity and certificate expiries from a completed client
/// certificate authenticated by a server connection.
pub fn peer_tls_identity_from_server_connection(
    connection: &rustls::ServerConnection,
) -> Result<PeerTlsIdentity, PeerSpiffeIdentityError> {
    peer_tls_identity(connection.is_handshaking(), connection.peer_certificates())
}

pub struct TlsConfigBuilder {
    state_rx: watch::Receiver<Option<IdentityState>>,
    material_controller: Option<TlsMaterialController>,
    local_spiffe_id: Option<SpiffeId>,
    policy: PeerPolicy,
    compat_mode: bool,
    allow_unconstrained_peer_policy: bool,
}

impl TlsConfigBuilder {
    pub fn new(state_rx: watch::Receiver<Option<IdentityState>>) -> Self {
        Self {
            state_rx,
            material_controller: None,
            local_spiffe_id: None,
            policy: PeerPolicy::default(),
            compat_mode: false,
            allow_unconstrained_peer_policy: false,
        }
    }

    /// Build client/server configs from one already shared material controller.
    pub fn from_material_controller(controller: TlsMaterialController) -> Self {
        Self {
            state_rx: controller.source_receiver(),
            material_controller: Some(controller),
            local_spiffe_id: None,
            policy: PeerPolicy::default(),
            compat_mode: false,
            allow_unconstrained_peer_policy: false,
        }
    }

    /// Pin the local SPIFFE identity instead of pinning the first valid update.
    pub fn with_local_spiffe_id(mut self, local_spiffe_id: SpiffeId) -> Self {
        self.local_spiffe_id = Some(local_spiffe_id);
        self
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
        self.validate_raw_config_material_settings()?;
        self.build_reloadable_client_config()
    }

    fn build_reloadable_client_config(self) -> Result<rustls::ClientConfig, rustls::Error> {
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
        client_config.resumption = rustls::client::Resumption::disabled();
        client_config.enable_early_data = false;

        Ok(client_config)
    }

    /// Build an opaque client configuration that proves it was constructed
    /// with this crate's SPIFFE verifier and reloadable client SVID resolver.
    pub fn build_authenticated_client_config(
        self,
    ) -> Result<AuthenticatedClientConfig, rustls::Error> {
        self.validate_material_controller_configuration()?;
        let controller = self.material_controller.clone().unwrap_or_else(|| {
            match self.local_spiffe_id.clone() {
                Some(local_spiffe_id) => {
                    TlsMaterialController::new_pinned(self.state_rx.clone(), local_spiffe_id)
                }
                None => TlsMaterialController::new(self.state_rx.clone()),
            }
        });
        let policy = self.policy.clone();
        let compat_mode = self.compat_mode;
        let allow_unconstrained_peer_policy = self.allow_unconstrained_peer_policy;
        let config = self.build_reloadable_client_config()?;
        Ok(AuthenticatedClientConfig {
            config: Arc::new(config),
            controller,
            policy,
            compat_mode,
            allow_unconstrained_peer_policy,
        })
    }

    pub fn build_server_config(self) -> Result<rustls::ServerConfig, rustls::Error> {
        self.validate_raw_config_material_settings()?;
        self.build_reloadable_server_config()
    }

    fn build_reloadable_server_config(self) -> Result<rustls::ServerConfig, rustls::Error> {
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

        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(protocol_versions(self.compat_mode))?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver);

        disable_server_resumption(&mut server_config);

        Ok(server_config)
    }

    /// Build an opaque server configuration that proves it was constructed
    /// with this crate's SPIFFE verifier and mandatory client SVID resolver.
    pub fn build_authenticated_server_config(
        self,
    ) -> Result<AuthenticatedServerConfig, rustls::Error> {
        self.validate_material_controller_configuration()?;
        let controller = self.material_controller.clone().unwrap_or_else(|| {
            match self.local_spiffe_id.clone() {
                Some(local_spiffe_id) => {
                    TlsMaterialController::new_pinned(self.state_rx.clone(), local_spiffe_id)
                }
                None => TlsMaterialController::new(self.state_rx.clone()),
            }
        });
        let policy = self.policy.clone();
        let compat_mode = self.compat_mode;
        let allow_unconstrained_peer_policy = self.allow_unconstrained_peer_policy;
        let config = self.build_reloadable_server_config()?;
        Ok(AuthenticatedServerConfig {
            config: Arc::new(config),
            controller,
            policy,
            compat_mode,
            allow_unconstrained_peer_policy,
        })
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

    fn validate_material_controller_configuration(&self) -> Result<(), rustls::Error> {
        if self.material_controller.is_some() && self.local_spiffe_id.is_some() {
            return Err(rustls::Error::General(
                "a shared TLS material controller already owns local identity pinning".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_raw_config_material_settings(&self) -> Result<(), rustls::Error> {
        if self.material_controller.is_some() || self.local_spiffe_id.is_some() {
            return Err(rustls::Error::General(
                RAW_CONFIG_MATERIAL_SETTINGS_ERROR.to_string(),
            ));
        }
        Ok(())
    }
}

fn fixed_client_config(
    snapshot: &material::TlsMaterialSnapshot,
    policy: PeerPolicy,
    compat_mode: bool,
    allow_unconstrained_peer_policy: bool,
) -> Result<rustls::ClientConfig, TlsMaterialError> {
    let (_state_tx, state_rx) = watch::channel(Some(snapshot.state.as_ref().clone()));
    let mut builder = TlsConfigBuilder::new(state_rx)
        .with_policy(policy)
        .with_compat_mode(compat_mode);
    if allow_unconstrained_peer_policy {
        builder = builder.allow_any_trusted_peer();
    }
    builder
        .build_client_config()
        .map_err(|_| TlsMaterialError::Configuration)
}

fn fixed_server_config(
    snapshot: &material::TlsMaterialSnapshot,
    policy: PeerPolicy,
    compat_mode: bool,
    allow_unconstrained_peer_policy: bool,
) -> Result<rustls::ServerConfig, TlsMaterialError> {
    let (_state_tx, state_rx) = watch::channel(Some(snapshot.state.as_ref().clone()));
    let mut builder = TlsConfigBuilder::new(state_rx)
        .with_policy(policy)
        .with_compat_mode(compat_mode);
    if allow_unconstrained_peer_policy {
        builder = builder.allow_any_trusted_peer();
    }
    builder
        .build_server_config()
        .map_err(|_| TlsMaterialError::Configuration)
}

fn disable_server_resumption(config: &mut rustls::ServerConfig) {
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
}

#[derive(Debug)]
struct DisabledSessionTickets;

impl rustls::server::ProducesTickets for DisabledSessionTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use opc_identity::{build_identity_state, Namespace, ServiceAccount, TrustBundleSet};
    use opc_types::{SpiffeId, Timestamp};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::io::Cursor;

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

    fn test_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        (params.self_signed(&key).unwrap(), key)
    }

    fn identity_state(
        spiffe_id: &str,
        ca: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
    ) -> IdentityState {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).unwrap(),
        ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca, ca_key).unwrap();
        let trust_domain = TrustDomain::new("example.test").unwrap();
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: vec![ca.der().clone()],
        });

        build_identity_state(
            vec![cert.der().clone(), ca.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            trust_bundles,
        )
        .unwrap()
    }

    fn complete_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) {
        for _ in 0..32 {
            let mut made_progress = false;

            let mut client_flight = Vec::new();
            if client.write_tls(&mut client_flight).unwrap() > 0 {
                made_progress = true;
                server.read_tls(&mut Cursor::new(client_flight)).unwrap();
                server.process_new_packets().unwrap();
            }

            let mut server_flight = Vec::new();
            if server.write_tls(&mut server_flight).unwrap() > 0 {
                made_progress = true;
                client.read_tls(&mut Cursor::new(server_flight)).unwrap();
                client.process_new_packets().unwrap();
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
            assert!(made_progress, "TLS handshake stopped making progress");
        }

        panic!("TLS handshake did not complete within the bounded exchange");
    }

    fn assert_raw_material_setting_rejected<T>(result: Result<T, rustls::Error>) {
        let error = match result {
            Ok(_) => panic!("raw config builder accepted a material-controller setting"),
            Err(error) => error,
        };
        assert!(matches!(
            &error,
            rustls::Error::General(message) if message == RAW_CONFIG_MATERIAL_SETTINGS_ERROR
        ));
        assert_eq!(
            error.to_string(),
            format!("unexpected error: {RAW_CONFIG_MATERIAL_SETTINGS_ERROR}")
        );
        assert!(!format!("{error:?}").contains("spiffe://"));
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

    #[test]
    fn raw_builders_reject_explicit_local_identity_pinning() {
        let (_tx, rx) = watch::channel(None);
        let local_spiffe_id = SpiffeId::new(
            "spiffe://example.test/tenant/tenant-a/ns/core/sa/default/nf/smf/instance/local-0",
        )
        .unwrap();

        assert_raw_material_setting_rejected(
            TlsConfigBuilder::new(rx.clone())
                .with_local_spiffe_id(local_spiffe_id.clone())
                .allow_any_trusted_peer()
                .build_client_config(),
        );
        assert_raw_material_setting_rejected(
            TlsConfigBuilder::new(rx)
                .with_local_spiffe_id(local_spiffe_id)
                .allow_any_trusted_peer()
                .build_server_config(),
        );
    }

    #[test]
    fn raw_builders_reject_shared_material_controller() {
        let (_tx, rx) = watch::channel(None);
        let controller = TlsMaterialController::new(rx);

        assert_raw_material_setting_rejected(
            TlsConfigBuilder::from_material_controller(controller.clone())
                .allow_any_trusted_peer()
                .build_client_config(),
        );
        assert_raw_material_setting_rejected(
            TlsConfigBuilder::from_material_controller(controller)
                .allow_any_trusted_peer()
                .build_server_config(),
        );
    }

    #[test]
    fn authenticated_config_wrappers_are_cloneable_and_redacted() {
        let (_client_tx, client_rx) = watch::channel(None);
        let client = TlsConfigBuilder::new(client_rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .unwrap();
        let (_server_tx, server_rx) = watch::channel(None);
        let server = TlsConfigBuilder::new(server_rx)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .unwrap();

        assert_eq!(
            format!("{client:?}"),
            "AuthenticatedClientConfig([redacted])"
        );
        assert_eq!(
            format!("{server:?}"),
            "AuthenticatedServerConfig([redacted])"
        );
        let client_rustls = client.clone().rustls_config();
        let server_rustls = server.clone().rustls_config();
        assert!(Arc::strong_count(&client_rustls) >= 2);
        assert!(Arc::strong_count(&server_rustls) >= 2);
        assert!(!client_rustls.enable_early_data);
        assert!(!server_rustls.ticketer.enabled());
        assert_eq!(server_rustls.send_tls13_tickets, 0);
        assert_eq!(server_rustls.max_early_data_size, 0);
        assert!(!server_rustls.send_half_rtt_data);
    }

    #[test]
    fn peer_identity_helpers_reject_incomplete_connections() {
        let (_client_tx, client_rx) = watch::channel(None);
        let client_config = TlsConfigBuilder::new(client_rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .unwrap();
        let mut client = rustls::ClientConnection::new(
            client_config.rustls_config(),
            ServerName::try_from("localhost").unwrap().to_owned(),
        )
        .unwrap();
        let (_server_tx, server_rx) = watch::channel(None);
        let server_config = TlsConfigBuilder::new(server_rx)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .unwrap();
        let server = rustls::ServerConnection::new(server_config.rustls_config()).unwrap();

        assert_eq!(
            peer_spiffe_id_from_client_connection(&client),
            Err(PeerSpiffeIdentityError::HandshakeIncomplete)
        );
        assert_eq!(
            peer_tls_identity_from_client_connection(&client),
            Err(PeerSpiffeIdentityError::HandshakeIncomplete)
        );
        assert_eq!(
            peer_spiffe_id_from_server_connection(&server),
            Err(PeerSpiffeIdentityError::HandshakeIncomplete)
        );
        assert_eq!(
            peer_tls_identity_from_server_connection(&server),
            Err(PeerSpiffeIdentityError::HandshakeIncomplete)
        );

        // The client stays in handshaking state even after emitting its first
        // flight, so helpers cannot accidentally treat "started" as complete.
        let mut first_flight = Vec::new();
        client.write_tls(&mut first_flight).unwrap();
        assert!(!first_flight.is_empty());
        assert_eq!(
            peer_spiffe_id_from_client_connection(&client),
            Err(PeerSpiffeIdentityError::HandshakeIncomplete)
        );
    }

    #[test]
    fn peer_identity_evidence_rejects_a_malformed_non_leaf_certificate() {
        const CLIENT_ID: &str =
            "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/client-0";
        let (ca, ca_key) = test_ca();
        let mut certificates = identity_state(CLIENT_ID, &ca, &ca_key).svid.cert_chain;
        certificates.insert(1, CertificateDer::from(vec![0xde, 0xad]));

        assert_eq!(
            peer_tls_identity(false, Some(&certificates)),
            Err(PeerSpiffeIdentityError::MalformedCertificate)
        );
    }

    #[test]
    fn peer_identity_helpers_extract_each_completed_connection_peer() {
        const CLIENT_ID: &str =
            "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/client-0";
        const SERVER_ID: &str =
            "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/server-0";

        let (ca, ca_key) = test_ca();
        let (_client_tx, client_rx) = watch::channel(Some(identity_state(CLIENT_ID, &ca, &ca_key)));
        let (_server_tx, server_rx) = watch::channel(Some(identity_state(SERVER_ID, &ca, &ca_key)));
        let client_config = TlsConfigBuilder::new(client_rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .unwrap();
        let server_config = TlsConfigBuilder::new(server_rx)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .unwrap();
        let mut client = rustls::ClientConnection::new(
            client_config.rustls_config(),
            ServerName::try_from("localhost").unwrap().to_owned(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(server_config.rustls_config()).unwrap();

        complete_handshake(&mut client, &mut server);

        assert_eq!(
            peer_spiffe_id_from_client_connection(&client)
                .unwrap()
                .as_str(),
            SERVER_ID
        );
        assert_eq!(
            peer_spiffe_id_from_server_connection(&server)
                .unwrap()
                .as_str(),
            CLIENT_ID
        );
        let server_evidence = peer_tls_identity_from_client_connection(&client).unwrap();
        assert_eq!(server_evidence.spiffe_id().as_str(), SERVER_ID);
        assert!(server_evidence.leaf_expires_at() > Timestamp::now_utc());
        assert_eq!(
            format!("{server_evidence:?}"),
            "PeerTlsIdentity([redacted])"
        );
        let client_evidence = peer_tls_identity_from_server_connection(&server).unwrap();
        assert_eq!(client_evidence.spiffe_id().as_str(), CLIENT_ID);
        assert!(client_evidence.leaf_expires_at() > Timestamp::now_utc());
    }

    #[test]
    fn malformed_trust_bundle_root_is_rejected() {
        let bundle = opc_identity::TrustBundle {
            trust_domain: TrustDomain::new("example.test").unwrap(),
            certificates: vec![CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef])],
        };

        assert!(root_store_from_bundle(&bundle).is_err());
    }
}
