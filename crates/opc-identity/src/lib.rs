//! SPIFFE Workload Identity and SVID reload support for OpenPacketCore.
//!
//! Provides X.509 SVID parsing, trust-domain validation, and hot-reload
//! primitives for mTLS identity.

use opc_types::{InstanceId, NfKind, SpiffeId, TenantId, Timestamp};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use x509_parser::prelude::*;

pub mod file_svid;
pub use file_svid::FileSvidSource;

#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum IdentityReloadError {
    #[error("SPIRE socket is unavailable")]
    SocketUnavailable,
    #[error("Expired SVID")]
    ExpiredSvid,
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

impl WorkloadIdentity {
    pub fn from_cert_der(
        cert_der: &[u8],
        active_bundles: &TrustBundleSet,
    ) -> Result<Self, IdentityReloadError> {
        let (_, x509) = X509Certificate::from_der(cert_der)
            .map_err(|_| IdentityReloadError::MalformedSpiffeId)?;

        let not_after = x509.validity().not_after;
        let expires_secs = not_after.timestamp() as u64;
        let dt = ::time::OffsetDateTime::from_unix_timestamp(expires_secs as i64)
            .map_err(|_| IdentityReloadError::MalformedSpiffeId)?;
        let expires_at = Timestamp::from_offset_datetime(dt);

        let now_secs = Timestamp::now_utc().as_offset_datetime().unix_timestamp() as u64;
        if expires_secs < now_secs {
            return Err(IdentityReloadError::ExpiredSvid);
        }

        let mut spiffe_id_str = None;
        for ext in x509.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::URI(uri) = name {
                        if uri.starts_with("spiffe://") {
                            spiffe_id_str = Some((*uri).to_string());
                            break;
                        }
                    }
                }
            }
        }

        let spiffe_id_str = spiffe_id_str.ok_or(IdentityReloadError::MalformedSpiffeId)?;
        let spiffe_id =
            SpiffeId::new(&spiffe_id_str).map_err(|_| IdentityReloadError::MalformedSpiffeId)?;

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

pub struct SvidWatcher {
    state_rx: watch::Receiver<Option<IdentityState>>,
    event_tx: tokio::sync::broadcast::Sender<IdentityReloadEvent>,
    _task_handle: tokio::task::JoinHandle<()>,
}

impl SvidWatcher {
    pub fn new(socket_path: impl AsRef<Path>, initial_bundles: TrustBundleSet) -> Self {
        let (state_tx, state_rx) = watch::channel(None);
        let (event_tx, _) = tokio::sync::broadcast::channel(32);

        let path = socket_path.as_ref().to_path_buf();
        let event_tx_clone = event_tx.clone();

        let task_handle = tokio::spawn(async move {
            let mut active_bundles = initial_bundles;
            tracing::debug!(
                "SvidWatcher started with {} initial trust bundles",
                active_bundles.bundles.len()
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
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::error!("Failed to parse SVID JSON: {}", e);
                                    continue;
                                }
                            };

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

                            let private_key = match parse_key_pem(&msg.private_key_pem) {
                                Ok(k) => k,
                                Err(e) => {
                                    tracing::error!("Failed to parse private key: {}", e);
                                    let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                                        error: "Failed to parse SVID private key".to_string(),
                                    });
                                    continue;
                                }
                            };

                            let leaf_der = match cert_chain.first() {
                                Some(d) => d,
                                None => {
                                    tracing::error!("Empty cert chain");
                                    continue;
                                }
                            };

                            // Replace active bundles with the updated list
                            active_bundles = updated_bundles;

                            match WorkloadIdentity::from_cert_der(
                                leaf_der.as_ref(),
                                &active_bundles,
                            ) {
                                Ok(identity) => {
                                    let svid = SvidDocument {
                                        spiffe_id: identity.spiffe_id.clone(),
                                        cert_chain,
                                        private_key,
                                        expires_at: identity.expires_at,
                                    };

                                    let state = IdentityState {
                                        identity: identity.clone(),
                                        svid,
                                        trust_bundles: active_bundles.clone(),
                                    };

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
                                    state_tx.send_replace(None);
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
        let rx = self.subscribe();
        let start = std::time::Instant::now();
        loop {
            if let Some(state) = rx.borrow().clone() {
                return Ok(state);
            }
            if start.elapsed() >= timeout {
                return Err(IdentityReloadError::SocketUnavailable);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
