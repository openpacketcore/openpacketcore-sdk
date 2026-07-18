//! SPIFFE Workload Identity and SVID reload support for OpenPacketCore.
//!
//! Provides X.509 SVID parsing, trust-domain validation, and hot-reload
//! primitives for mTLS identity.

#![forbid(unsafe_code)]

use opc_types::{InstanceId, NfKind, SpiffeId, TenantId, Timestamp};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, UnixTime};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{broadcast, watch};
use x509_parser::prelude::*;
use zeroize::{Zeroize, Zeroizing};

/// Maximum encoded length accepted for a SPIFFE URI SAN.
///
/// Certificate inputs are untrusted. Keeping the identity bounded also makes
/// it safe for callers to carry the validated value into fixed-size protocol
/// handshakes and topology manifests.
pub const MAX_SPIFFE_ID_URI_LEN: usize = 2_048;

pub mod file_svid;
pub mod projected_svid;
pub use file_svid::FileSvidSource;
pub use projected_svid::{
    ProjectedSvidAuthoritativeError, ProjectedSvidAvailability, ProjectedSvidConfigError,
    ProjectedSvidControllerClaimError, ProjectedSvidControllerInput, ProjectedSvidReloadReason,
    ProjectedSvidReloadStatus, ProjectedSvidSource, ProjectedSvidWithMetricsError,
};

#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum IdentityReloadError {
    #[error("SPIRE socket is unavailable")]
    SocketUnavailable,
    #[error("Expired SVID")]
    ExpiredSvid,
    #[error("SVID is not yet valid")]
    NotYetValidSvid,
    #[error("Malformed SPIFFE ID")]
    MalformedSpiffeId,
    #[error("Invalid trust domain")]
    InvalidTrustDomain,
    #[error("Unknown trust domain")]
    UnknownTrustDomain,
    #[error("Malformed SVID path")]
    MalformedPath,
    #[error("Invalid tenant")]
    InvalidTenant,
    #[error("Invalid NF kind")]
    InvalidNfKind,
    #[error("Invalid instance")]
    InvalidInstance,
    #[error("SVID certificate chain does not validate against the trust bundle")]
    InvalidCertificateChain,
    #[error("SVID private key does not match the leaf certificate")]
    PrivateKeyMismatch,
    #[error("internal I/O reload error")]
    IoError,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IdentityReloadEvent {
    Success { expires_at: u64 },
    Failure { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Namespace(String);

impl Namespace {
    pub fn new(val: impl Into<String>) -> Result<Self, String> {
        let val = val.into();
        if val.is_empty() {
            return Err("namespace cannot be empty".to_string());
        }
        for ch in val.chars() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_') {
                return Err("invalid namespace character".to_string());
            }
        }
        Ok(Self(val))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ServiceAccount(String);

impl ServiceAccount {
    pub fn new(val: impl Into<String>) -> Result<Self, String> {
        let val = val.into();
        if val.is_empty() {
            return Err("service account cannot be empty".to_string());
        }
        for ch in val.chars() {
            if !matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_') {
                return Err("invalid service account character".to_string());
            }
        }
        Ok(Self(val))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TrustDomain(String);

impl TrustDomain {
    pub fn new(val: impl Into<String>) -> Result<Self, String> {
        let val = val.into();
        if val.is_empty() {
            return Err("trust domain cannot be empty".to_string());
        }
        for label in val.split('.') {
            if label.is_empty() {
                return Err("trust domain label cannot be empty".to_string());
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err("trust domain label cannot start/end with '-'".to_string());
            }
            for ch in label.chars() {
                if !matches!(ch, 'a'..='z' | '0'..='9' | '-') {
                    return Err("invalid trust domain character".to_string());
                }
            }
        }
        Ok(Self(val))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub trust_domain: TrustDomain,
    pub certificates: Vec<CertificateDer<'static>>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustBundleSet {
    pub bundles: HashMap<TrustDomain, TrustBundle>,
}

impl TrustBundleSet {
    pub fn new() -> Self {
        Self {
            bundles: HashMap::new(),
        }
    }
    pub fn insert(&mut self, bundle: TrustBundle) {
        self.bundles.insert(bundle.trust_domain.clone(), bundle);
    }
    pub fn get(&self, domain: &TrustDomain) -> Option<&TrustBundle> {
        self.bundles.get(domain)
    }
    pub fn contains(&self, domain: &TrustDomain) -> bool {
        self.bundles.contains_key(domain)
    }
    pub fn remove(&mut self, domain: &TrustDomain) {
        self.bundles.remove(domain);
    }
}

pub fn parse_certs_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse cert PEM: {e}"))
}

pub fn parse_key_pem(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| format!("failed to parse private key: {e}"))
}

#[derive(Debug)]
pub struct SvidDocument {
    pub spiffe_id: SpiffeId,
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    pub expires_at: Timestamp,
}

impl Clone for SvidDocument {
    fn clone(&self) -> Self {
        Self {
            spiffe_id: self.spiffe_id.clone(),
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadIdentity {
    pub trust_domain: TrustDomain,
    pub tenant: TenantId,
    pub namespace: Namespace,
    pub service_account: ServiceAccount,
    pub nf_kind: NfKind,
    pub instance: InstanceId,
    pub spiffe_id: SpiffeId,
    pub expires_at: Timestamp,
}

/// Failure to extract one canonical OpenPacketCore SPIFFE ID from an X.509
/// certificate.
///
/// The variants intentionally contain no certificate or identity material so
/// both `Display` and `Debug` are safe to use at an untrusted-input boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpiffeSanError {
    #[error("malformed X.509 certificate")]
    MalformedCertificate,
    #[error("certificate is missing a SPIFFE URI SAN")]
    MissingSpiffeId,
    #[error("certificate contains multiple URI SANs")]
    MultipleUriSans,
    #[error("certificate contains a malformed SPIFFE URI SAN")]
    MalformedSpiffeId,
}

/// Extract exactly one canonical, bounded OpenPacketCore SPIFFE ID from an
/// X.509 certificate's Subject Alternative Name extension.
///
/// Non-URI SAN entries are ignored. A certificate with more than one URI SAN
/// is rejected even when only one is a SPIFFE URI, so callers never select an
/// identity from an ambiguous X.509-SVID.
pub fn extract_spiffe_id_from_cert_der(cert_der: &[u8]) -> Result<SpiffeId, SpiffeSanError> {
    let (remaining, x509) =
        X509Certificate::from_der(cert_der).map_err(|_| SpiffeSanError::MalformedCertificate)?;
    if !remaining.is_empty() {
        return Err(SpiffeSanError::MalformedCertificate);
    }

    let san = x509
        .subject_alternative_name()
        .map_err(|_| SpiffeSanError::MalformedCertificate)?
        .ok_or(SpiffeSanError::MissingSpiffeId)?;

    let mut candidate = None;
    for name in &san.value.general_names {
        let GeneralName::URI(uri) = name else {
            continue;
        };
        if candidate.replace(*uri).is_some() {
            return Err(SpiffeSanError::MultipleUriSans);
        }
    }

    let candidate = candidate.ok_or(SpiffeSanError::MissingSpiffeId)?;
    if candidate.len() > MAX_SPIFFE_ID_URI_LEN {
        return Err(SpiffeSanError::MalformedSpiffeId);
    }

    SpiffeId::new(candidate).map_err(|_| SpiffeSanError::MalformedSpiffeId)
}

impl WorkloadIdentity {
    pub fn from_cert_der(
        cert_der: &[u8],
        active_bundles: &TrustBundleSet,
    ) -> Result<Self, IdentityReloadError> {
        let (remaining, x509) = X509Certificate::from_der(cert_der)
            .map_err(|_| IdentityReloadError::MalformedSpiffeId)?;
        if !remaining.is_empty() {
            return Err(IdentityReloadError::MalformedSpiffeId);
        }

        let not_before_secs = x509.validity().not_before.timestamp();
        let not_after_secs = x509.validity().not_after.timestamp();
        let now_secs = Timestamp::now_utc().as_offset_datetime().unix_timestamp();

        if not_after_secs <= now_secs {
            return Err(IdentityReloadError::ExpiredSvid);
        }
        if not_before_secs > now_secs {
            return Err(IdentityReloadError::NotYetValidSvid);
        }

        let dt = ::time::OffsetDateTime::from_unix_timestamp(not_after_secs)
            .map_err(|_| IdentityReloadError::MalformedSpiffeId)?;
        let expires_at = Timestamp::from_offset_datetime(dt);

        let spiffe_id = extract_spiffe_id_from_cert_der(cert_der)
            .map_err(|_| IdentityReloadError::MalformedSpiffeId)?;

        let trust_domain_str = spiffe_id.trust_domain();
        let trust_domain = TrustDomain::new(trust_domain_str)
            .map_err(|_| IdentityReloadError::InvalidTrustDomain)?;

        if !active_bundles.contains(&trust_domain) {
            return Err(IdentityReloadError::UnknownTrustDomain);
        }

        let path = spiffe_id.path();
        let mut seg: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if seg.first() == Some(&"trust-domain") {
            seg.remove(0);
        }
        if seg.len() != 10
            || seg[0] != "tenant"
            || seg[2] != "ns"
            || seg[4] != "sa"
            || seg[6] != "nf"
            || seg[8] != "instance"
        {
            return Err(IdentityReloadError::MalformedPath);
        }

        let tenant = TenantId::new(seg[1]).map_err(|_| IdentityReloadError::InvalidTenant)?;
        let namespace = Namespace::new(seg[3]).map_err(|_| IdentityReloadError::MalformedPath)?;
        let service_account =
            ServiceAccount::new(seg[5]).map_err(|_| IdentityReloadError::MalformedPath)?;
        let nf_kind = NfKind::new(seg[7]).map_err(|_| IdentityReloadError::InvalidNfKind)?;
        let instance = InstanceId::new(seg[9]).map_err(|_| IdentityReloadError::InvalidInstance)?;

        Ok(Self {
            trust_domain,
            tenant,
            namespace,
            service_account,
            nf_kind,
            instance,
            spiffe_id,
            expires_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IdentityState {
    pub identity: WorkloadIdentity,
    pub svid: SvidDocument,
    pub trust_bundles: TrustBundleSet,
}

impl IdentityState {
    pub fn is_expired(&self) -> bool {
        self.identity.expires_at <= Timestamp::now_utc()
    }
}

pub fn build_identity_state(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    trust_bundles: TrustBundleSet,
) -> Result<IdentityState, IdentityReloadError> {
    let leaf_der = cert_chain
        .first()
        .ok_or(IdentityReloadError::MalformedSpiffeId)?;
    let identity = WorkloadIdentity::from_cert_der(leaf_der.as_ref(), &trust_bundles)?;

    validate_leaf_chains_to_bundle(&identity, &cert_chain, &trust_bundles)?;
    validate_private_key_matches_leaf(&cert_chain, &private_key)?;

    let svid = SvidDocument {
        spiffe_id: identity.spiffe_id.clone(),
        cert_chain,
        private_key,
        expires_at: identity.expires_at,
    };

    Ok(IdentityState {
        identity,
        svid,
        trust_bundles,
    })
}

fn validate_leaf_chains_to_bundle(
    identity: &WorkloadIdentity,
    cert_chain: &[CertificateDer<'static>],
    trust_bundles: &TrustBundleSet,
) -> Result<(), IdentityReloadError> {
    let bundle = trust_bundles
        .get(&identity.trust_domain)
        .ok_or(IdentityReloadError::UnknownTrustDomain)?;
    let mut root_store = rustls::RootCertStore::empty();
    let (valid_roots, _invalid_roots) =
        root_store.add_parsable_certificates(bundle.certificates.iter().cloned());
    if valid_roots == 0 {
        return Err(IdentityReloadError::InvalidCertificateChain);
    }

    let leaf = cert_chain
        .first()
        .ok_or(IdentityReloadError::MalformedSpiffeId)?;
    let parsed = rustls::server::ParsedCertificate::try_from(leaf)
        .map_err(|_| IdentityReloadError::InvalidCertificateChain)?;
    let provider = rustls::crypto::ring::default_provider();

    rustls::client::verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &root_store,
        &cert_chain[1..],
        UnixTime::now(),
        provider.signature_verification_algorithms.all,
    )
    .map_err(|_| IdentityReloadError::InvalidCertificateChain)
}

fn validate_private_key_matches_leaf(
    cert_chain: &[CertificateDer<'static>],
    private_key: &PrivateKeyDer<'static>,
) -> Result<(), IdentityReloadError> {
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(private_key.clone_key())
        .map_err(|_| IdentityReloadError::PrivateKeyMismatch)?;
    let certified_key = rustls::sign::CertifiedKey::new(cert_chain.to_vec(), signing_key);

    certified_key
        .keys_match()
        .map_err(|_| IdentityReloadError::PrivateKeyMismatch)
}

pub(crate) fn spawn_expiry_monitor(
    state_tx: watch::Sender<Option<IdentityState>>,
    event_tx: broadcast::Sender<IdentityReloadEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut state_rx = state_tx.subscribe();
        loop {
            let sleep_for = expiry_monitor_sleep_duration(state_rx.borrow().as_ref());
            tokio::select! {
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                () = tokio::time::sleep(sleep_for) => {
                    if state_tx.borrow().as_ref().is_some_and(IdentityState::is_expired) {
                        state_tx.send_replace(None);
                        let _ = event_tx.send(IdentityReloadEvent::Failure {
                            error: IdentityReloadError::ExpiredSvid.to_string(),
                        });
                    }
                }
            }
        }
    })
}

fn expiry_monitor_sleep_duration(state: Option<&IdentityState>) -> Duration {
    const MAX_SLEEP: Duration = Duration::from_secs(60);
    let Some(state) = state else {
        return MAX_SLEEP;
    };

    let expires_at = *state.identity.expires_at.as_offset_datetime();
    let now = ::time::OffsetDateTime::now_utc();
    if expires_at <= now {
        return Duration::ZERO;
    }

    let until_expiry = (expires_at - now).try_into().unwrap_or(Duration::ZERO);
    until_expiry.min(MAX_SLEEP)
}

pub struct SvidWatcher {
    state_rx: watch::Receiver<Option<IdentityState>>,
    event_tx: tokio::sync::broadcast::Sender<IdentityReloadEvent>,
    _task_handle: tokio::task::JoinHandle<()>,
    _expiry_task_handle: tokio::task::JoinHandle<()>,
}

impl SvidWatcher {
    pub fn new(socket_path: impl AsRef<Path>, initial_bundles: TrustBundleSet) -> Self {
        let (state_tx, state_rx) = watch::channel(None);
        let (event_tx, _) = tokio::sync::broadcast::channel(32);

        let path = socket_path.as_ref().to_path_buf();
        let event_tx_clone = event_tx.clone();
        let expiry_task_handle = spawn_expiry_monitor(state_tx.clone(), event_tx.clone());

        let task_handle = tokio::spawn(async move {
            tracing::debug!(
                "SvidWatcher started with {} initial trust bundles",
                initial_bundles.bundles.len()
            );

            loop {
                match tokio::net::UnixStream::connect(&path).await {
                    Ok(mut stream) => {
                        tracing::debug!("connected to SPIRE workload socket");

                        loop {
                            let mut len_buf = [0u8; 4];
                            if let Err(e) = stream.read_exact(&mut len_buf).await {
                                tracing::error!("Socket read error: {}", e);
                                let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                                    error: "Socket read error".to_string(),
                                });
                                break;
                            }
                            let len = u32::from_be_bytes(len_buf) as usize;
                            if len > 10 * 1024 * 1024 {
                                tracing::error!("Length prefix too large: {}", len);
                                break;
                            }

                            let mut buf = vec![0u8; len];
                            if let Err(e) = stream.read_exact(&mut buf).await {
                                tracing::error!("Failed to read message body: {}", e);
                                break;
                            }

                            #[derive(serde::Deserialize)]
                            struct SvidUpdateMsg {
                                cert_chain_pem: String,
                                private_key_pem: String,
                                trust_bundles: Vec<(String, String)>,
                            }

                            let msg: SvidUpdateMsg = match serde_json::from_slice(&buf) {
                                Ok(m) => {
                                    buf.zeroize();
                                    m
                                }
                                Err(e) => {
                                    buf.zeroize();
                                    tracing::error!("Failed to parse SVID JSON: {}", e);
                                    continue;
                                }
                            };
                            let private_key_pem = Zeroizing::new(msg.private_key_pem);

                            let mut updated_bundles = TrustBundleSet::new();
                            let mut bundle_parse_err = false;
                            for (td_str, certs_pem) in msg.trust_bundles {
                                match TrustDomain::new(&td_str) {
                                    Ok(td) => match parse_certs_pem(&certs_pem) {
                                        Ok(certs) => {
                                            updated_bundles.insert(TrustBundle {
                                                trust_domain: td,
                                                certificates: certs,
                                            });
                                        }
                                        Err(e) => {
                                            tracing::error!("Failed to parse bundle certs: {}", e);
                                            bundle_parse_err = true;
                                            break;
                                        }
                                    },
                                    Err(e) => {
                                        tracing::error!("Invalid trust domain in update: {}", e);
                                        bundle_parse_err = true;
                                        break;
                                    }
                                }
                            }

                            if bundle_parse_err {
                                let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                                    error: "Failed to parse trust bundles".to_string(),
                                });
                                continue;
                            }

                            let cert_chain = match parse_certs_pem(&msg.cert_chain_pem) {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::error!("Failed to parse leaf cert: {}", e);
                                    let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                                        error: "Failed to parse SVID certificate".to_string(),
                                    });
                                    continue;
                                }
                            };

                            let private_key = match parse_key_pem(&private_key_pem) {
                                Ok(k) => k,
                                Err(e) => {
                                    tracing::error!("Failed to parse private key: {}", e);
                                    let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                                        error: "Failed to parse SVID private key".to_string(),
                                    });
                                    continue;
                                }
                            };

                            match build_identity_state(
                                cert_chain,
                                private_key,
                                updated_bundles.clone(),
                            ) {
                                Ok(state) => {
                                    let identity = state.identity.clone();
                                    state_tx.send_replace(Some(state));

                                    let _ = event_tx_clone.send(IdentityReloadEvent::Success {
                                        expires_at: identity
                                            .expires_at
                                            .as_offset_datetime()
                                            .unix_timestamp()
                                            as u64,
                                    });
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to validate reload workload identity: {:?}",
                                        e
                                    );
                                    let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                                        error: e.to_string(),
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("failed to connect to SPIRE workload socket: {}", e);
                        let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                            error: "SPIRE socket unavailable".to_string(),
                        });
                    }
                }

                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        Self {
            state_rx,
            event_tx,
            _task_handle: task_handle,
            _expiry_task_handle: expiry_task_handle,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<IdentityState>> {
        self.state_rx.clone()
    }

    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<IdentityReloadEvent> {
        self.event_tx.subscribe()
    }

    pub async fn wait_for_initial_identity(
        &self,
        timeout: Duration,
    ) -> Result<IdentityState, IdentityReloadError> {
        let mut rx = self.subscribe();
        loop {
            if let Some(state) = rx.borrow().clone() {
                return Ok(state);
            }
            if tokio::time::timeout(timeout, rx.changed()).await.is_err() {
                return Err(IdentityReloadError::SocketUnavailable);
            }
        }
    }
}

#[cfg(test)]
mod spiffe_san_tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, SanType};

    const SPIFFE_ID: &str =
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-0";
    const OTHER_SPIFFE_ID: &str =
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-1";

    fn certificate_with_uris(uris: &[&str]) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI(rcgen::string::Ia5String::try_from(*uri).unwrap()))
            .collect();
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn strict_extractor_accepts_one_canonical_spiffe_uri() {
        let cert = certificate_with_uris(&[SPIFFE_ID]);

        let actual = extract_spiffe_id_from_cert_der(&cert).unwrap();

        assert_eq!(actual.as_str(), SPIFFE_ID);
    }

    #[test]
    fn strict_extractor_rejects_missing_spiffe_uri() {
        let cert = certificate_with_uris(&[]);

        assert_eq!(
            extract_spiffe_id_from_cert_der(&cert),
            Err(SpiffeSanError::MissingSpiffeId)
        );
    }

    #[test]
    fn strict_extractor_rejects_multiple_spiffe_uris() {
        let cert = certificate_with_uris(&[SPIFFE_ID, OTHER_SPIFFE_ID]);

        assert_eq!(
            extract_spiffe_id_from_cert_der(&cert),
            Err(SpiffeSanError::MultipleUriSans)
        );
    }

    #[test]
    fn strict_extractor_rejects_spiffe_plus_non_spiffe_uri() {
        let cert = certificate_with_uris(&[SPIFFE_ID, "https://service.example.test"]);

        assert_eq!(
            extract_spiffe_id_from_cert_der(&cert),
            Err(SpiffeSanError::MultipleUriSans)
        );
    }

    #[test]
    fn strict_extractor_rejects_noncanonical_spiffe_uri() {
        let cert = certificate_with_uris(&[
            "SPIFFE://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-0",
        ]);

        assert_eq!(
            extract_spiffe_id_from_cert_der(&cert),
            Err(SpiffeSanError::MalformedSpiffeId)
        );
    }

    #[test]
    fn strict_extractor_rejects_oversized_uri_san() {
        let prefix = "spiffe://example.test/tenant/tenant-a/ns/";
        let suffix = "/sa/session/nf/smf/instance/smf-0";
        let uri_with_len = |len: usize| {
            let namespace_len = len
                .checked_sub(prefix.len() + suffix.len())
                .expect("test URI length");
            format!("{prefix}{}{suffix}", "a".repeat(namespace_len))
        };
        let at_limit = uri_with_len(MAX_SPIFFE_ID_URI_LEN);
        assert_eq!(at_limit.len(), MAX_SPIFFE_ID_URI_LEN);
        let at_limit_cert = certificate_with_uris(&[&at_limit]);
        assert_eq!(
            extract_spiffe_id_from_cert_der(&at_limit_cert)
                .expect("maximum-sized canonical SPIFFE ID")
                .as_str(),
            at_limit
        );

        let oversized = uri_with_len(MAX_SPIFFE_ID_URI_LEN + 1);
        let cert = certificate_with_uris(&[&oversized]);

        assert_eq!(
            extract_spiffe_id_from_cert_der(&cert),
            Err(SpiffeSanError::MalformedSpiffeId)
        );
    }

    #[test]
    fn strict_extractor_rejects_trailing_certificate_data() {
        let mut cert = certificate_with_uris(&[SPIFFE_ID]);
        cert.push(0);

        assert_eq!(
            extract_spiffe_id_from_cert_der(&cert),
            Err(SpiffeSanError::MalformedCertificate)
        );
    }

    #[test]
    fn workload_identity_reuses_strict_san_cardinality() {
        let cert = certificate_with_uris(&[SPIFFE_ID, OTHER_SPIFFE_ID]);
        let trust_domain = TrustDomain::new("example.test").unwrap();
        let mut bundles = TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain,
            certificates: Vec::new(),
        });

        assert_eq!(
            WorkloadIdentity::from_cert_der(&cert, &bundles),
            Err(IdentityReloadError::MalformedSpiffeId)
        );
    }
}
