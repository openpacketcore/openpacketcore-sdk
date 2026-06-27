//! Fake fixtures and fault injection test utilities for OpenPacketCore security validation.
//!
//! This is an internal testkit crate and is not published.

use rcgen::{CertificateParams, DnType, SanType};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Return a short, unique Unix-domain socket path.
///
/// Tests that create sockets inside `tempfile::tempdir()` can fail when the
/// effective temp directory is deep, because Linux's `sun_path` is limited to
/// 108 bytes. This helper deliberately hard-codes `/tmp` (instead of
/// `std::env::temp_dir()`) so the path is always short and unique per
/// invocation, regardless of the value of `TMPDIR`.
///
/// # Limitations
///
/// * `/tmp` is assumed to be a short, writable tmpfs on Linux test hosts. The
///   helper does not consult `TMPDIR` or `std::env::temp_dir()` because deep
///   temporary directories would reintroduce the `sun_path` length problem.
/// * `name` must be a short filename-safe label. It must not contain path
///   separators and must be no more than 44 bytes so the final path stays
///   comfortably below the 108-byte `sun_path` limit.
pub fn short_unix_socket_path(name: &str) -> PathBuf {
    assert!(
        !name.contains('/') && !name.contains('\\'),
        "short_unix_socket_path name must be a filename-safe label, got {name:?}"
    );
    assert!(
        name.len() <= 44,
        "short_unix_socket_path name must be <= 44 bytes, got {} bytes in {name:?}",
        name.len()
    );
    let path = PathBuf::from(format!(
        "/tmp/opc-test-{name}-{}.sock",
        uuid::Uuid::new_v4()
    ));
    assert!(
        path.as_os_str().as_encoded_bytes().len() <= 100,
        "short_unix_socket_path produced a path that is too long: {}",
        path.display()
    );
    path
}

pub struct FakeCa {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key_pair: rcgen::KeyPair,
}

impl FakeCa {
    pub fn new(trust_domain: &str) -> Self {
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, format!("CA for {trust_domain}"));

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        Self {
            ca_cert_pem: cert.pem(),
            ca_key_pem: key_pair.serialize_pem(),
            ca_cert: cert,
            ca_key_pair: key_pair,
        }
    }

    pub fn sign_spiffe_id(&self, spiffe_id: &str, expires_in_secs: i64) -> (String, String) {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Workload");
        params
            .subject_alt_names
            .push(SanType::URI(rcgen::Ia5String::try_from(spiffe_id).unwrap()));

        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now - ::time::Duration::days(1);
        params.not_after = now + ::time::Duration::seconds(expires_in_secs);

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params
            .signed_by(&key_pair, &self.ca_cert, &self.ca_key_pair)
            .unwrap();

        (cert.pem(), key_pair.serialize_pem())
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SvidUpdateMsg {
    pub cert_chain_pem: String,
    pub private_key_pem: String,
    pub trust_bundles: Vec<(String, String)>,
}

pub struct FakeSpire {
    socket_path: std::path::PathBuf,
    current_state: Arc<Mutex<SvidUpdateMsg>>,
    update_tx: tokio::sync::broadcast::Sender<SvidUpdateMsg>,
    _listener_handle: tokio::task::JoinHandle<()>,
}

async fn write_update_state(stream: &mut tokio::net::UnixStream, msg: &SvidUpdateMsg) -> bool {
    use tokio::io::AsyncWriteExt;
    let bytes = match serde_json::to_vec(msg) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let len = bytes.len() as u32;
    if stream.write_all(&len.to_be_bytes()).await.is_err() {
        return false;
    }
    if stream.write_all(&bytes).await.is_err() {
        return false;
    }
    if stream.flush().await.is_err() {
        return false;
    }
    true
}

impl FakeSpire {
    pub async fn new(
        socket_path: impl AsRef<Path>,
        initial: SvidUpdateMsg,
    ) -> std::io::Result<Self> {
        let path = socket_path.as_ref().to_path_buf();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        let listener = tokio::net::UnixListener::bind(&path)?;
        let current_state = Arc::new(Mutex::new(initial.clone()));
        let (update_tx, _) = tokio::sync::broadcast::channel(32);

        let current_state_clone = current_state.clone();
        let update_tx_clone = update_tx.clone();

        let listener_handle = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let state = current_state_clone.lock().unwrap().clone();
                    let mut update_rx = update_tx_clone.subscribe();

                    tokio::spawn(async move {
                        if !write_update_state(&mut stream, &state).await {
                            return;
                        }

                        while let Ok(msg) = update_rx.recv().await {
                            if !write_update_state(&mut stream, &msg).await {
                                break;
                            }
                        }
                    });
                }
            }
        });

        Ok(Self {
            socket_path: path,
            current_state,
            update_tx,
            _listener_handle: listener_handle,
        })
    }

    pub fn rotate(&self, next: SvidUpdateMsg) {
        *self.current_state.lock().unwrap() = next.clone();
        let _ = self.update_tx.send(next);
    }
}

impl Drop for FakeSpire {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[derive(Clone)]
struct KmsKeyEntry {
    key_id: String,
    purpose: String,
    tenant: String,
    key_bytes_hex: String,
}

#[derive(Clone, Default)]
pub struct KmsBehavior {
    pub delay: Option<Duration>,
    pub unavailable: bool,
    pub simulate_error: bool,
}

pub struct FakeKms {
    endpoint: String,
    socket_path: Option<std::path::PathBuf>,
    keys: Arc<Mutex<HashMap<String, KmsKeyEntry>>>,
    active_keys: Arc<Mutex<HashMap<(String, String), String>>>,
    behavior: Arc<Mutex<KmsBehavior>>,
    _listener_handle: Option<tokio::task::JoinHandle<()>>,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = fmt::write(&mut s, format_args!("{b:02x}"));
    }
    s
}

async fn handle_kms_stream<S>(
    mut stream: S,
    keys: Arc<Mutex<HashMap<String, KmsKeyEntry>>>,
    active_keys: Arc<Mutex<HashMap<(String, String), String>>>,
    behavior: Arc<Mutex<KmsBehavior>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut req_buf = vec![0u8; len];
        if stream.read_exact(&mut req_buf).await.is_err() {
            break;
        }

        #[derive(serde::Deserialize)]
        struct KmsRequest {
            request_type: String,
            purpose: Option<String>,
            tenant: Option<String>,
            key_id: Option<String>,
        }

        let req: KmsRequest = match serde_json::from_slice(&req_buf) {
            Ok(r) => r,
            Err(_) => break,
        };

        let beh = behavior.lock().unwrap().clone();
        if beh.unavailable {
            break;
        }
        if let Some(delay) = beh.delay {
            tokio::time::sleep(delay).await;
        }

        #[derive(serde::Serialize)]
        struct KmsResponse {
            status: String,
            key_id: Option<String>,
            key_bytes_hex: Option<String>,
            purpose: Option<String>,
            tenant: Option<String>,
            error_message: Option<String>,
        }

        let resp = if beh.simulate_error {
            KmsResponse {
                status: "error".to_string(),
                key_id: None,
                key_bytes_hex: None,
                purpose: None,
                tenant: None,
                error_message: Some("simulated error".to_string()),
            }
        } else {
            match req.request_type.as_str() {
                "get_active_key" => {
                    let purpose = req.purpose.unwrap_or_default();
                    let tenant = req.tenant.unwrap_or_default();

                    let active = active_keys.lock().unwrap();
                    if let Some(kid) = active.get(&(purpose.clone(), tenant.clone())) {
                        let ks = keys.lock().unwrap();
                        let entry = ks.get(kid).unwrap();
                        KmsResponse {
                            status: "success".to_string(),
                            key_id: Some(entry.key_id.clone()),
                            key_bytes_hex: Some(entry.key_bytes_hex.clone()),
                            purpose: Some(purpose),
                            tenant: Some(tenant),
                            error_message: None,
                        }
                    } else {
                        KmsResponse {
                            status: "error".to_string(),
                            key_id: None,
                            key_bytes_hex: None,
                            purpose: None,
                            tenant: None,
                            error_message: Some("not found".to_string()),
                        }
                    }
                }
                "get_key_by_id" => {
                    let kid = req.key_id.unwrap_or_default();
                    let ks = keys.lock().unwrap();
                    if let Some(entry) = ks.get(&kid) {
                        KmsResponse {
                            status: "success".to_string(),
                            key_id: Some(entry.key_id.clone()),
                            key_bytes_hex: Some(entry.key_bytes_hex.clone()),
                            purpose: Some(entry.purpose.clone()),
                            tenant: Some(entry.tenant.clone()),
                            error_message: None,
                        }
                    } else {
                        KmsResponse {
                            status: "error".to_string(),
                            key_id: None,
                            key_bytes_hex: None,
                            purpose: None,
                            tenant: None,
                            error_message: Some("not found".to_string()),
                        }
                    }
                }
                "rotate_key" => {
                    let purpose = req.purpose.unwrap_or_default();
                    let tenant = req.tenant.unwrap_or_default();

                    let mut active = active_keys.lock().unwrap();
                    let mut ks = keys.lock().unwrap();

                    let next_counter = active
                        .get(&(purpose.clone(), tenant.clone()))
                        .and_then(|kid| kid.rsplit_once("-r"))
                        .and_then(|(_, suffix)| suffix.parse::<u64>().ok())
                        .unwrap_or(0)
                        + 1;

                    let next_kid = format!("{purpose}-{tenant}-r{next_counter}");
                    let next_bytes = vec![next_counter as u8; 32];
                    let next_hex = hex_encode(&next_bytes);

                    let entry = KmsKeyEntry {
                        key_id: next_kid.clone(),
                        purpose: purpose.clone(),
                        tenant: tenant.clone(),
                        key_bytes_hex: next_hex,
                    };

                    ks.insert(next_kid.clone(), entry);
                    active.insert((purpose, tenant), next_kid.clone());

                    KmsResponse {
                        status: "success".to_string(),
                        key_id: Some(next_kid),
                        key_bytes_hex: None,
                        purpose: None,
                        tenant: None,
                        error_message: None,
                    }
                }
                _ => KmsResponse {
                    status: "error".to_string(),
                    key_id: None,
                    key_bytes_hex: None,
                    purpose: None,
                    tenant: None,
                    error_message: Some("unknown request type".to_string()),
                },
            }
        };

        let resp_bytes = match serde_json::to_vec(&resp) {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        let resp_len = resp_bytes.len() as u32;
        if stream.write_all(&resp_len.to_be_bytes()).await.is_err() {
            break;
        }
        if stream.write_all(&resp_bytes).await.is_err() {
            break;
        }
        if stream.flush().await.is_err() {
            break;
        }
    }
}

impl FakeKms {
    pub async fn new_tcp(addr: &str, behavior: KmsBehavior) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let endpoint = format!("tcp://{}", listener.local_addr().unwrap());

        let keys = Arc::new(Mutex::new(HashMap::<String, KmsKeyEntry>::new()));
        let active_keys = Arc::new(Mutex::new(HashMap::<(String, String), String>::new()));
        let behavior = Arc::new(Mutex::new(behavior));

        let keys_clone = keys.clone();
        let active_keys_clone = active_keys.clone();
        let behavior_clone = behavior.clone();

        let handle = tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let keys = keys_clone.clone();
                    let active_keys = active_keys_clone.clone();
                    let behavior = behavior_clone.clone();
                    tokio::spawn(handle_kms_stream(stream, keys, active_keys, behavior));
                }
            }
        });

        Ok(Self {
            endpoint,
            socket_path: None,
            keys,
            active_keys,
            behavior,
            _listener_handle: Some(handle),
        })
    }

    pub async fn new_unix(
        socket_path: impl AsRef<Path>,
        behavior: KmsBehavior,
    ) -> std::io::Result<Self> {
        let path = socket_path.as_ref().to_path_buf();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        let listener = tokio::net::UnixListener::bind(&path)?;
        let endpoint = format!("unix://{}", path.display());

        let keys = Arc::new(Mutex::new(HashMap::<String, KmsKeyEntry>::new()));
        let active_keys = Arc::new(Mutex::new(HashMap::<(String, String), String>::new()));
        let behavior = Arc::new(Mutex::new(behavior));

        let keys_clone = keys.clone();
        let active_keys_clone = active_keys.clone();
        let behavior_clone = behavior.clone();

        let handle = tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let keys = keys_clone.clone();
                    let active_keys = active_keys_clone.clone();
                    let behavior = behavior_clone.clone();
                    tokio::spawn(handle_kms_stream(stream, keys, active_keys, behavior));
                }
            }
        });

        Ok(Self {
            endpoint,
            socket_path: Some(path),
            keys,
            active_keys,
            behavior,
            _listener_handle: Some(handle),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn set_behavior(&self, beh: KmsBehavior) {
        *self.behavior.lock().unwrap() = beh;
    }

    pub fn insert_key(&self, key_id: &str, purpose: &str, tenant: &str, key: [u8; 32]) {
        let hex_str = hex_encode(&key);
        let entry = KmsKeyEntry {
            key_id: key_id.to_string(),
            purpose: purpose.to_string(),
            tenant: tenant.to_string(),
            key_bytes_hex: hex_str,
        };
        self.keys.lock().unwrap().insert(key_id.to_string(), entry);
    }

    pub fn set_active_key(&self, purpose: &str, tenant: &str, key_id: &str) {
        self.active_keys.lock().unwrap().insert(
            (purpose.to_string(), tenant.to_string()),
            key_id.to_string(),
        );
    }
}

impl Drop for FakeKms {
    fn drop(&mut self) {
        if let Some(path) = &self.socket_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::short_unix_socket_path;

    /// Maximum bytes Linux reserves for `sockaddr_un.sun_path` (including the
    /// trailing NUL).
    const SUN_PATH_LEN: usize = 108;

    /// Leave a small margin for the trailing NUL and any implementation
    /// overhead when `tokio::net::UnixListener::bind` converts the path.
    const COMFORTABLE_LIMIT: usize = 100;

    #[test]
    fn short_unix_socket_path_is_short_and_unique() {
        let spire = short_unix_socket_path("spire");
        let spire2 = short_unix_socket_path("spire");
        let kms = short_unix_socket_path("kms");

        assert!(
            spire.starts_with("/tmp/"),
            "spire path should be under /tmp: {spire:?}"
        );
        assert!(
            kms.starts_with("/tmp/"),
            "kms path should be under /tmp: {kms:?}"
        );

        assert!(
            spire.as_os_str().as_encoded_bytes().len() <= COMFORTABLE_LIMIT,
            "spire path should be comfortably below the sun_path limit: {spire:?}"
        );
        assert!(
            kms.as_os_str().as_encoded_bytes().len() <= COMFORTABLE_LIMIT,
            "kms path should be comfortably below the sun_path limit: {kms:?}"
        );

        assert!(
            spire.as_os_str().as_encoded_bytes().len() < SUN_PATH_LEN,
            "spire path must fit inside sun_path: {spire:?}"
        );
        assert!(
            kms.as_os_str().as_encoded_bytes().len() < SUN_PATH_LEN,
            "kms path must fit inside sun_path: {kms:?}"
        );

        assert_ne!(
            spire, spire2,
            "two calls with the same label should produce unique paths"
        );
        assert_ne!(spire, kms, "different labels should produce unique paths");
    }

    #[test]
    #[should_panic(expected = "short_unix_socket_path name must be a filename-safe label")]
    fn short_unix_socket_path_rejects_path_separator() {
        let _ = short_unix_socket_path("foo/bar");
    }

    #[test]
    #[should_panic(expected = "short_unix_socket_path name must be <= 44 bytes")]
    fn short_unix_socket_path_rejects_long_name() {
        let _ = short_unix_socket_path(&"a".repeat(45));
    }

    #[test]
    fn short_unix_socket_path_max_length_name_binds() {
        let path = short_unix_socket_path(&"a".repeat(44));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }
}
