use crate::{
    build_identity_state, parse_certs_pem, parse_key_pem, spawn_expiry_monitor,
    IdentityReloadError, IdentityReloadEvent, IdentityState, TrustBundle, TrustBundleSet,
    TrustDomain,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use x509_parser::prelude::*;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
struct FileSnapshot {
    hash: String,
}

/// Loads X.509 SVID cert chain, private key, and trust bundles from PEM files
/// on disk and polls for changes.
///
/// Re-emits the same reload-event stream the socket-based [`crate::SvidWatcher`]
/// produces, making it a drop-in alternative for environments where a SPIRE
/// workload socket is not available.
pub struct FileSvidSource {
    state_rx: watch::Receiver<Option<IdentityState>>,
    event_tx: broadcast::Sender<IdentityReloadEvent>,
    _task_handle: tokio::task::JoinHandle<()>,
    _expiry_task_handle: tokio::task::JoinHandle<()>,
}

impl FileSvidSource {
    pub fn new(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        bundle_paths: Vec<impl AsRef<Path>>,
        poll_interval: Option<Duration>,
    ) -> Self {
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        let bundle_paths: Vec<PathBuf> = bundle_paths
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect();
        let poll_interval = poll_interval.unwrap_or(Duration::from_secs(5));

        let (state_tx, state_rx) = watch::channel(None);
        let (event_tx, _) = broadcast::channel(32);
        let event_tx_clone = event_tx.clone();
        let expiry_task_handle = spawn_expiry_monitor(state_tx.clone(), event_tx.clone());

        let task_handle = tokio::spawn(async move {
            let mut snapshots: HashMap<PathBuf, FileSnapshot> = HashMap::new();

            loop {
                let mut current_snapshots = HashMap::new();
                let mut read_error = false;

                for path in std::iter::once(&cert_path)
                    .chain(std::iter::once(&key_path))
                    .chain(bundle_paths.iter())
                {
                    match snapshot_file(path, snapshots.get(path)).await {
                        Some(snap) => {
                            current_snapshots.insert(path.clone(), snap);
                        }
                        None => {
                            read_error = true;
                            break;
                        }
                    }
                }

                if read_error {
                    let _ = event_tx_clone.send(IdentityReloadEvent::Failure {
                        error: "failed to read identity files".to_string(),
                    });
                } else {
                    let content_changed = has_content_changed(&snapshots, &current_snapshots);
                    snapshots = current_snapshots;

                    if content_changed {
                        match reload_identity(&cert_path, &key_path, &bundle_paths).await {
                            Ok(state) => {
                                let expires_at = state
                                    .identity
                                    .expires_at
                                    .as_offset_datetime()
                                    .unix_timestamp()
                                    as u64;
                                state_tx.send_replace(Some(state));
                                let _ = event_tx_clone
                                    .send(IdentityReloadEvent::Success { expires_at });
                            }
                            Err(error) => {
                                let _ = event_tx_clone.send(IdentityReloadEvent::Failure { error });
                            }
                        }
                    }
                }

                tokio::time::sleep(poll_interval).await;
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

    pub fn subscribe_events(&self) -> broadcast::Receiver<IdentityReloadEvent> {
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
                return Err(IdentityReloadError::IoError);
            }
        }
    }
}

async fn snapshot_file(path: &Path, previous: Option<&FileSnapshot>) -> Option<FileSnapshot> {
    let content = tokio::fs::read(path).await.ok()?;
    let hash = format!("{:x}", Sha256::digest(&content));
    if let Some(prev) = previous {
        if prev.hash == hash {
            return Some(prev.clone());
        }
    }
    Some(FileSnapshot { hash })
}

fn has_content_changed(
    previous: &HashMap<PathBuf, FileSnapshot>,
    current: &HashMap<PathBuf, FileSnapshot>,
) -> bool {
    if previous.len() != current.len() {
        return true;
    }
    for (path, snap) in current {
        match previous.get(path) {
            Some(prev) if prev.hash == snap.hash => {}
            _ => return true,
        }
    }
    false
}

async fn reload_identity(
    cert_path: &Path,
    key_path: &Path,
    bundle_paths: &[PathBuf],
) -> Result<IdentityState, String> {
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .map_err(|e| format!("failed to read cert file: {e}"))?;
    let key_pem = Zeroizing::new(
        tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| format!("failed to read key file: {e}"))?,
    );

    let cert_chain =
        parse_certs_pem(&cert_pem).map_err(|e| format!("failed to parse SVID certificate: {e}"))?;

    let private_key =
        parse_key_pem(&key_pem).map_err(|e| format!("failed to parse SVID private key: {e}"))?;

    let leaf_der = cert_chain
        .first()
        .ok_or_else(|| "empty cert chain".to_string())?;

    let mut all_bundle_certs = Vec::new();
    for bundle_path in bundle_paths {
        let bundle_pem = tokio::fs::read_to_string(bundle_path)
            .await
            .map_err(|e| format!("failed to read trust bundle file: {e}"))?;
        let certs = parse_certs_pem(&bundle_pem)
            .map_err(|e| format!("failed to parse trust bundle: {e}"))?;
        all_bundle_certs.extend(certs);
    }

    let trust_domain = extract_trust_domain_from_cert(leaf_der.as_ref())
        .map_err(|e| format!("failed to extract trust domain: {e}"))?;

    let mut trust_bundles = TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain: trust_domain.clone(),
        certificates: all_bundle_certs,
    });

    build_identity_state(cert_chain, private_key, trust_bundles)
        .map_err(|e| format!("failed to validate workload identity: {e}"))
}

fn extract_trust_domain_from_cert(cert_der: &[u8]) -> Result<TrustDomain, String> {
    let (_, x509) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse X.509 certificate: {e}"))?;

    let mut spiffe_id_str = None;
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        spiffe_id_str = Some(uri.to_string());
                        break;
                    }
                }
            }
        }
    }

    let spiffe_id_str = spiffe_id_str.ok_or("missing SPIFFE ID URI in SAN extension")?;
    let rest = &spiffe_id_str["spiffe://".len()..];
    let slash = rest
        .find('/')
        .ok_or("malformed SPIFFE ID: missing path separator")?;
    let trust_domain_str = &rest[..slash];

    TrustDomain::new(trust_domain_str)
        .map_err(|e| format!("invalid trust domain '{trust_domain_str}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use std::fs;
    use std::io::Write;
    use tokio::time::timeout;

    fn generate_test_certs(
        spiffe_id: &str,
    ) -> (
        rcgen::CertifiedIssuer<'static, KeyPair>,
        rcgen::Certificate,
        KeyPair,
    ) {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let ca_key = KeyPair::generate().unwrap();
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let (wl_cert, wl_key) = generate_workload_cert(spiffe_id, &ca);

        (ca, wl_cert, wl_key)
    }

    fn generate_workload_cert(
        spiffe_id: &str,
        issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
    ) -> (rcgen::Certificate, KeyPair) {
        let now = ::time::OffsetDateTime::now_utc();
        generate_workload_cert_with_validity(
            spiffe_id,
            issuer,
            now - ::time::Duration::days(1),
            now + ::time::Duration::days(1),
        )
    }

    fn generate_workload_cert_with_validity(
        spiffe_id: &str,
        issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
        not_before: ::time::OffsetDateTime,
        not_after: ::time::OffsetDateTime,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut wl_params = CertificateParams::default();
        wl_params
            .distinguished_name
            .push(DnType::CommonName, "Workload");
        wl_params.subject_alt_names.push(SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).unwrap(),
        ));

        wl_params.not_before = not_before;
        wl_params.not_after = not_after;

        let wl_key = KeyPair::generate().unwrap();
        let wl_cert = wl_params.signed_by(&wl_key, issuer).unwrap();

        (wl_cert, wl_key)
    }

    async fn wait_for_failure_event(
        event_rx: &mut broadcast::Receiver<IdentityReloadEvent>,
    ) -> IdentityReloadEvent {
        timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(event) = event_rx.recv().await {
                    if matches!(event, IdentityReloadEvent::Failure { .. }) {
                        return event;
                    }
                }
            }
        })
        .await
        .expect("should receive failure event")
    }

    fn write_pem_files(
        dir: &Path,
        cert_chain_pem: &str,
        key_pem: &str,
        bundle_pem: &str,
    ) -> (PathBuf, PathBuf, PathBuf) {
        let cert_path = dir.join("svid.crt");
        let key_path = dir.join("svid.key");
        let bundle_path = dir.join("bundle.crt");

        fs::create_dir_all(dir).unwrap();
        let mut f = fs::File::create(&cert_path).unwrap();
        f.write_all(cert_chain_pem.as_bytes()).unwrap();
        let mut f = fs::File::create(&key_path).unwrap();
        f.write_all(key_pem.as_bytes()).unwrap();
        let mut f = fs::File::create(&bundle_path).unwrap();
        f.write_all(bundle_pem.as_bytes()).unwrap();

        (cert_path, key_path, bundle_path)
    }

    #[tokio::test]
    async fn test_initial_load_success() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-test-{}",
            std::process::id()
        ));
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca, wl_cert, wl_key) = generate_test_certs(spiffe);

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert.pem() + &ca.pem()),
            &wl_key.serialize_pem(),
            &ca.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );

        let state = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("should load initial identity");

        assert_eq!(state.identity.spiffe_id.as_str(), spiffe);
        assert_eq!(state.identity.trust_domain.as_str(), "test-domain");
        assert_eq!(state.identity.tenant.as_str(), "test");
        assert_eq!(state.identity.namespace.as_str(), "default");
        assert_eq!(state.identity.service_account.as_str(), "svc");
        assert_eq!(state.identity.nf_kind.as_str(), "test");
        assert_eq!(state.identity.instance.as_str(), "0");
        assert_eq!(state.svid.cert_chain.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_rotation() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-rotation-{}",
            std::process::id()
        ));
        let spiffe1 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca1, wl_cert1, wl_key1) = generate_test_certs(spiffe1);

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert1.pem() + &ca1.pem()),
            &wl_key1.serialize_pem(),
            &ca1.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );

        let state1 = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("should load initial identity");
        let initial_spiffe = state1.identity.spiffe_id.clone();

        // Generate a new cert with a different SPIFFE ID to prove rotation.
        let spiffe2 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
        let (ca2, wl_cert2, wl_key2) = generate_test_certs(spiffe2);

        let mut f = fs::File::create(&cert_path).unwrap();
        f.write_all((wl_cert2.pem() + &ca2.pem()).as_bytes())
            .unwrap();
        let mut f = fs::File::create(&key_path).unwrap();
        f.write_all(wl_key2.serialize_pem().as_bytes()).unwrap();
        let mut f = fs::File::create(&bundle_path).unwrap();
        f.write_all(ca2.pem().as_bytes()).unwrap();

        // Wait for the state to update.
        let rx = source.subscribe();
        let updated = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(state) = rx.borrow().clone() {
                    if state.identity.spiffe_id != initial_spiffe {
                        return state;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("should rotate within timeout");

        assert_eq!(updated.identity.spiffe_id.as_str(), spiffe2);
        assert_eq!(updated.identity.instance.as_str(), "1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_initial_load_rejects_expired_svid() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-expired-{}",
            std::process::id()
        ));
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca, _wl_cert, _wl_key) = generate_test_certs(spiffe);
        let now = ::time::OffsetDateTime::now_utc();
        let (wl_cert, wl_key) = generate_workload_cert_with_validity(
            spiffe,
            &ca,
            now - ::time::Duration::days(2),
            now - ::time::Duration::days(1),
        );

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert.pem() + &ca.pem()),
            &wl_key.serialize_pem(),
            &ca.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );
        let mut event_rx = source.subscribe_events();

        let event = wait_for_failure_event(&mut event_rx).await;
        assert!(
            matches!(event, IdentityReloadEvent::Failure { ref error } if error.contains("Expired SVID")),
            "expected expired-SVID failure, got {event:?}"
        );
        assert!(source
            .wait_for_initial_identity(Duration::from_millis(100))
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_initial_load_rejects_not_yet_valid_svid() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-not-yet-valid-{}",
            std::process::id()
        ));
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca, _wl_cert, _wl_key) = generate_test_certs(spiffe);
        let now = ::time::OffsetDateTime::now_utc();
        let (wl_cert, wl_key) = generate_workload_cert_with_validity(
            spiffe,
            &ca,
            now + ::time::Duration::days(1),
            now + ::time::Duration::days(2),
        );

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert.pem() + &ca.pem()),
            &wl_key.serialize_pem(),
            &ca.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );
        let mut event_rx = source.subscribe_events();

        let event = wait_for_failure_event(&mut event_rx).await;
        assert!(
            matches!(event, IdentityReloadEvent::Failure { ref error } if error.contains("not yet valid")),
            "expected not-yet-valid failure, got {event:?}"
        );
        assert!(source
            .wait_for_initial_identity(Duration::from_millis(100))
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_rotation_rejects_leaf_not_signed_by_bundle_and_retains_last_good() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-wrong-ca-{}",
            std::process::id()
        ));
        let spiffe1 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca1, wl_cert1, wl_key1) = generate_test_certs(spiffe1);

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert1.pem() + &ca1.pem()),
            &wl_key1.serialize_pem(),
            &ca1.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );

        let state = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("should load initial identity");
        let initial_spiffe = state.identity.spiffe_id.clone();
        let mut event_rx = source.subscribe_events();

        let spiffe2 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
        let (ca2, wl_cert2, wl_key2) = generate_test_certs(spiffe2);

        let mut f = fs::File::create(&cert_path).unwrap();
        f.write_all((wl_cert2.pem() + &ca2.pem()).as_bytes())
            .unwrap();
        let mut f = fs::File::create(&key_path).unwrap();
        f.write_all(wl_key2.serialize_pem().as_bytes()).unwrap();

        let event = wait_for_failure_event(&mut event_rx).await;
        assert!(
            matches!(event, IdentityReloadEvent::Failure { ref error } if error.contains("certificate chain")),
            "expected certificate-chain failure, got {event:?}"
        );

        let rx = source.subscribe();
        let current = rx
            .borrow()
            .clone()
            .expect("last-good identity should be retained");
        assert_eq!(current.identity.spiffe_id, initial_spiffe);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_rotation_rejects_torn_cert_key_pair_and_retains_last_good() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-torn-pair-{}",
            std::process::id()
        ));
        let spiffe1 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca, wl_cert1, wl_key1) = generate_test_certs(spiffe1);

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert1.pem() + &ca.pem()),
            &wl_key1.serialize_pem(),
            &ca.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );

        let state = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("should load initial identity");
        let initial_spiffe = state.identity.spiffe_id.clone();
        let mut event_rx = source.subscribe_events();

        let spiffe2 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
        let (wl_cert2, _wl_key2) = generate_workload_cert(spiffe2, &ca);

        let mut f = fs::File::create(&cert_path).unwrap();
        f.write_all((wl_cert2.pem() + &ca.pem()).as_bytes())
            .unwrap();
        let mut f = fs::File::create(&key_path).unwrap();
        f.write_all(wl_key1.serialize_pem().as_bytes()).unwrap();

        let event = wait_for_failure_event(&mut event_rx).await;
        assert!(
            matches!(event, IdentityReloadEvent::Failure { ref error } if error.contains("private key")),
            "expected private-key mismatch failure, got {event:?}"
        );

        let rx = source.subscribe();
        let current = rx
            .borrow()
            .clone()
            .expect("last-good identity should be retained");
        assert_eq!(current.identity.spiffe_id, initial_spiffe);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_malformed_pem_fail_closed() {
        let dir = std::env::temp_dir().join(format!(
            "opc-identity-file-svid-fail-closed-{}",
            std::process::id()
        ));
        let spiffe = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
        let (ca, wl_cert, wl_key) = generate_test_certs(spiffe);

        let (cert_path, key_path, bundle_path) = write_pem_files(
            &dir,
            &(wl_cert.pem() + &ca.pem()),
            &wl_key.serialize_pem(),
            &ca.pem(),
        );

        let source = FileSvidSource::new(
            &cert_path,
            &key_path,
            vec![&bundle_path],
            Some(Duration::from_millis(100)),
        );

        let state = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("should load initial identity");
        let initial_spiffe = state.identity.spiffe_id.clone();

        let mut event_rx = source.subscribe_events();

        // Corrupt the cert file.
        let mut f = fs::File::create(&cert_path).unwrap();
        f.write_all(b"not a valid pem").unwrap();

        // Wait for a failure event.
        let event = wait_for_failure_event(&mut event_rx).await;

        assert!(
            matches!(event, IdentityReloadEvent::Failure { ref error } if error.contains("failed to parse") || error.contains("empty cert chain")),
            "expected failure event with parse error, got {event:?}"
        );

        // Verify old identity is retained.
        let rx = source.subscribe();
        let current = rx.borrow().clone();
        assert!(
            current.is_some(),
            "old identity should be retained after failure"
        );
        assert_eq!(
            current.unwrap().identity.spiffe_id,
            initial_spiffe,
            "spiffe id should remain unchanged"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
