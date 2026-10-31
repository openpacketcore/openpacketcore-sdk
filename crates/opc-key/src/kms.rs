use async_trait::async_trait;
use opc_types::TenantId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{EncryptedPayload, KeyHandle, KeyProvider, AEAD_TAG_LEN},
    remote::{RemoteSealMaterialController, RemoteSealMaterialEpoch, RemoteSealProvider},
    scope::{serialize_bound_aad, EnvelopeAad, KeyId, KeyPurpose},
};

enum KmsStream {
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Unix(tokio::net::UnixStream),
}

impl KmsStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::Tls(s) => s.write_all(buf).await,
            Self::Unix(s) => s.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::Tls(s) => s.flush().await,
            Self::Unix(s) => s.flush().await,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        use tokio::io::AsyncReadExt;
        match self {
            Self::Tls(s) => s.read_exact(buf).await.map(|_| ()),
            Self::Unix(s) => s.read_exact(buf).await.map(|_| ()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct KmsRequest {
    request_type: String,
    purpose: Option<String>,
    tenant: Option<String>,
    key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aad_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext_and_tag_hex: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KmsResponse {
    status: String,
    key_id: Option<String>,
    key_bytes_hex: Option<String>,
    purpose: Option<String>,
    tenant: Option<String>,
    error_message: Option<String>,
    ciphertext_and_tag_hex: Option<String>,
    plaintext_hex: Option<String>,
}

fn decode_hex_32(hex: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(KeyError::OperationFailed);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (i, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes[i] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, KeyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(KeyError::OperationFailed),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn decode_hex_vec(hex: &str) -> Result<Vec<u8>, KeyError> {
    let (chunks, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() || !hex.is_ascii() {
        return Err(KeyError::OperationFailed);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in chunks {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn unix_endpoint_path(endpoint: &str) -> Result<&str, KeyError> {
    let path = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
    if !std::path::Path::new(path).is_absolute() {
        return Err(KeyError::OperationFailed);
    }
    // Validate the platform's actual sun_path limit and reject interior NULs
    // before attempting I/O. An endpoint has at most one scheme prefix.
    std::os::unix::net::SocketAddr::from_pathname(path).map_err(|_| KeyError::OperationFailed)?;
    Ok(path)
}

fn unix_connect_error(error: std::io::Error) -> KeyError {
    match error.raw_os_error() {
        // The service socket is absent or has no listener.
        Some(libc::ENOENT | libc::ECONNREFUSED)
        // A connection raced service shutdown or exceeded its transport wait.
        | Some(libc::ECONNRESET | libc::ECONNABORTED | libc::ETIMEDOUT)
        // Interrupted syscall or a full local socket backlog.
        | Some(libc::EINTR | libc::EAGAIN)
        // Temporary memory, buffer or process/system descriptor exhaustion.
        | Some(libc::ENOMEM | libc::ENOBUFS | libc::EMFILE | libc::ENFILE) => {
            KeyError::Unavailable
        }
        // Permissions, invalid path components, protocol mismatch and other
        // local configuration failures must not consume a retry budget.
        _ => KeyError::OperationFailed,
    }
}

fn kms_transport_error(error: std::io::Error) -> KeyError {
    // Rustls wraps certificate verification and fatal peer alerts in io::Error.
    // TLS 1.3 can deliver a peer authentication refusal on application I/O after
    // the client's connect future completes, so use this at every TLS I/O site.
    if error
        .get_ref()
        .is_some_and(|cause| cause.is::<tokio_rustls::rustls::Error>())
        || matches!(
            error.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
        )
    {
        KeyError::OperationFailed
    } else {
        KeyError::Unavailable
    }
}

fn tcp_endpoint_addr(endpoint: &str) -> Result<&str, KeyError> {
    // Keep the address spelling accepted by the released adapters. In
    // particular, converting scoped IPv6 to an (Ipv6Addr, port) tuple would
    // discard its scope. Tokio parses a complete SocketAddr before resolving.
    let addr = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);
    if addr.contains("://") {
        return Err(KeyError::OperationFailed);
    }
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(addr);
    }
    let (host, port) = addr.rsplit_once(':').ok_or(KeyError::OperationFailed)?;
    if host.is_empty()
        || host
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || port.parse::<u16>().is_err()
        || host.contains(['[', ']', '/', '?', '#', '@'])
    {
        return Err(KeyError::OperationFailed);
    }
    if host.contains(':') {
        // The resolver also accepts unbracketed numeric IPv6 host:port forms.
        // A zone is resolved with the address rather than treated as a name.
        let literal = if let Some((literal, zone)) = host.split_once('%') {
            if zone.is_empty() {
                return Err(KeyError::OperationFailed);
            }
            literal
        } else {
            host
        };
        literal
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| KeyError::OperationFailed)?;
    }
    Ok(addr)
}

pub struct KmsKeyProvider {
    endpoint: String,
    connector: Option<tokio_rustls::TlsConnector>,
    server_name: String,
    timeout: std::time::Duration,
}

pub struct KmsRemoteSealProvider {
    endpoint: String,
    connector: Option<tokio_rustls::TlsConnector>,
    server_name: String,
    timeout: std::time::Duration,
    material: RemoteSealMaterialController,
}

impl std::fmt::Debug for KmsRemoteSealProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KmsRemoteSealProvider")
            .field("material_epoch", &self.material.epoch().ok())
            .finish_non_exhaustive()
    }
}

impl KmsKeyProvider {
    const DEFAULT_SERVER_NAME: &'static str = "kms.openpacketcore.internal";
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;

    pub fn new(
        endpoint: String,
        connector: Option<tokio_rustls::TlsConnector>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            endpoint,
            connector,
            server_name: Self::DEFAULT_SERVER_NAME.to_string(),
            timeout,
        }
    }

    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    async fn call_kms(&self, req: KmsRequest) -> Result<KmsResponse, KeyError> {
        match tokio::time::timeout(self.timeout, self.call_kms_inner(req)).await {
            Ok(result) => result,
            Err(_) => Err(KeyError::Unavailable),
        }
    }

    async fn call_kms_inner(&self, req: KmsRequest) -> Result<KmsResponse, KeyError> {
        let connect_fut = async {
            if self.endpoint.starts_with('/') || self.endpoint.starts_with("unix://") {
                let path = unix_endpoint_path(&self.endpoint)?;
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(unix_connect_error)?;
                Ok::<KmsStream, KeyError>(KmsStream::Unix(stream))
            } else {
                let addr = tcp_endpoint_addr(&self.endpoint)?;
                let connector = self.connector.as_ref().ok_or(KeyError::OperationFailed)?;
                let domain = rustls_pki_types::ServerName::try_from(self.server_name.clone())
                    .map_err(|_| KeyError::OperationFailed)?;
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                let tls_stream = connector
                    .connect(domain, stream)
                    .await
                    .map_err(kms_transport_error)?;
                Ok(KmsStream::Tls(Box::new(tls_stream)))
            }
        };

        let mut stream = connect_fut.await?;

        let req_bytes = serde_json::to_vec(&req).map_err(|_| KeyError::OperationFailed)?;
        let req_len = req_bytes.len() as u32;

        stream
            .write_all(&req_len.to_be_bytes())
            .await
            .map_err(kms_transport_error)?;
        stream
            .write_all(&req_bytes)
            .await
            .map_err(kms_transport_error)?;
        stream.flush().await.map_err(kms_transport_error)?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(kms_transport_error)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > Self::MAX_RESPONSE_BYTES {
            return Err(KeyError::OperationFailed);
        }

        let mut resp_buf = Zeroizing::new(vec![0u8; len]);
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(kms_transport_error)?;
        let resp: KmsResponse =
            serde_json::from_slice(&resp_buf).map_err(|_| KeyError::OperationFailed)?;

        if resp.status == "success" {
            Ok(resp)
        } else if resp.status == "unavailable" {
            // Only this protocol status signals temporary busy/throttling.
            // Free-form provider messages never select a retryable class.
            Err(KeyError::Unavailable)
        } else {
            let msg = resp
                .error_message
                .unwrap_or_else(|| "KMS failed".to_string());
            if msg.contains("not found") {
                Err(KeyError::NotFound)
            } else {
                Err(KeyError::OperationFailed)
            }
        }
    }
}

#[async_trait]
impl KeyProvider for KmsKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        let req = KmsRequest {
            request_type: "get_active_key".to_string(),
            purpose: Some(purpose.as_str().to_string()),
            tenant: Some(tenant.as_str().to_string()),
            key_id: None,
            aad_hex: None,
            plaintext_hex: None,
            ciphertext_and_tag_hex: None,
        };
        let resp = self.call_kms(req).await?;
        let key_id_str = resp.key_id.ok_or(KeyError::OperationFailed)?;
        let key_bytes_hex = Zeroizing::new(resp.key_bytes_hex.ok_or(KeyError::OperationFailed)?);

        let key_id = KeyId::new(key_id_str).map_err(|_| KeyError::OperationFailed)?;
        let key_bytes = decode_hex_32(&key_bytes_hex)?;

        let handle = KeyHandle::new(key_id, purpose, tenant.clone(), key_bytes);
        Ok(handle)
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        let req = KmsRequest {
            request_type: "get_key_by_id".to_string(),
            purpose: None,
            tenant: None,
            key_id: Some(key_id.as_str().to_string()),
            aad_hex: None,
            plaintext_hex: None,
            ciphertext_and_tag_hex: None,
        };
        let resp = self.call_kms(req).await?;
        let key_bytes_hex = Zeroizing::new(resp.key_bytes_hex.ok_or(KeyError::OperationFailed)?);
        let purpose_str = resp.purpose.ok_or(KeyError::OperationFailed)?;
        let tenant_str = resp.tenant.ok_or(KeyError::OperationFailed)?;

        let purpose = match purpose_str.as_str() {
            "config" => KeyPurpose::Config,
            "config-consumer-checkpoint" => KeyPurpose::ConfigConsumerCheckpoint,
            "shadow-security" => KeyPurpose::ShadowSecurity,
            "session" => KeyPurpose::Session,
            "ipsec-sa" => KeyPurpose::IpsecSa,
            "audit" => KeyPurpose::Audit,
            "backup" => KeyPurpose::Backup,
            _ => return Err(KeyError::OperationFailed),
        };
        let tenant = TenantId::new(tenant_str).map_err(|_| KeyError::OperationFailed)?;
        let key_bytes = decode_hex_32(&key_bytes_hex)?;

        let handle = KeyHandle::new(key_id.clone(), purpose, tenant, key_bytes);
        Ok(handle)
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        let req = KmsRequest {
            request_type: "rotate_key".to_string(),
            purpose: Some(purpose.as_str().to_string()),
            tenant: Some(tenant.as_str().to_string()),
            key_id: None,
            aad_hex: None,
            plaintext_hex: None,
            ciphertext_and_tag_hex: None,
        };
        let resp = self.call_kms(req).await?;
        let key_id_str = resp.key_id.ok_or(KeyError::OperationFailed)?;
        KeyId::new(key_id_str).map_err(|_| KeyError::OperationFailed)
    }
}

impl KmsRemoteSealProvider {
    /// Default TLS server name used when `endpoint` is a TCP address.
    pub const DEFAULT_SERVER_NAME: &'static str = KmsKeyProvider::DEFAULT_SERVER_NAME;

    /// Create a remote-seal KMS client with an initial active remote key ID.
    ///
    /// The external service is expected to perform AEAD/KMS Encrypt and
    /// Decrypt server-side. The SDK sends the same serialized bound AAD bytes
    /// used by the local envelope path and never asks the KMS to hand key
    /// material back to the application.
    pub fn new(
        endpoint: String,
        connector: Option<tokio_rustls::TlsConnector>,
        timeout: std::time::Duration,
        key_id: KeyId,
    ) -> Self {
        Self {
            endpoint,
            connector,
            server_name: Self::DEFAULT_SERVER_NAME.to_string(),
            timeout,
            material: RemoteSealMaterialController::new(key_id),
        }
    }

    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    /// Shared coherent material controller used by this provider.
    ///
    /// Clones of the returned controller publish into this provider's same
    /// process-local state. Publishing affects future seal requests only;
    /// unseal always selects the envelope key ID.
    pub fn material_controller(&self) -> RemoteSealMaterialController {
        self.material.clone()
    }

    /// Atomically select a new key for future seal operations.
    pub fn publish_active_key(&self, key_id: KeyId) -> Result<RemoteSealMaterialEpoch, KeyError> {
        self.material.publish_active_key(key_id)
    }

    /// Current redaction-safe process-local material epoch.
    pub fn material_epoch(&self) -> Result<RemoteSealMaterialEpoch, KeyError> {
        self.material.epoch()
    }

    async fn call_kms(&self, req: KmsRequest) -> Result<KmsResponse, KeyError> {
        match tokio::time::timeout(self.timeout, self.call_kms_inner(req)).await {
            Ok(result) => result,
            Err(_) => Err(KeyError::Unavailable),
        }
    }

    async fn call_kms_inner(&self, req: KmsRequest) -> Result<KmsResponse, KeyError> {
        let connect_fut = async {
            if self.endpoint.starts_with('/') || self.endpoint.starts_with("unix://") {
                let path = unix_endpoint_path(&self.endpoint)?;
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(unix_connect_error)?;
                Ok::<KmsStream, KeyError>(KmsStream::Unix(stream))
            } else {
                let addr = tcp_endpoint_addr(&self.endpoint)?;
                let connector = self.connector.as_ref().ok_or(KeyError::OperationFailed)?;
                let domain = rustls_pki_types::ServerName::try_from(self.server_name.clone())
                    .map_err(|_| KeyError::OperationFailed)?;
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                let tls_stream = connector
                    .connect(domain, stream)
                    .await
                    .map_err(kms_transport_error)?;
                Ok(KmsStream::Tls(Box::new(tls_stream)))
            }
        };

        let mut stream = connect_fut.await?;

        let req_bytes = serde_json::to_vec(&req).map_err(|_| KeyError::OperationFailed)?;
        let req_len = req_bytes.len() as u32;

        stream
            .write_all(&req_len.to_be_bytes())
            .await
            .map_err(kms_transport_error)?;
        stream
            .write_all(&req_bytes)
            .await
            .map_err(kms_transport_error)?;
        stream.flush().await.map_err(kms_transport_error)?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(kms_transport_error)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > KmsKeyProvider::MAX_RESPONSE_BYTES {
            return Err(KeyError::OperationFailed);
        }

        let mut resp_buf = Zeroizing::new(vec![0u8; len]);
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(kms_transport_error)?;
        let resp: KmsResponse =
            serde_json::from_slice(&resp_buf).map_err(|_| KeyError::OperationFailed)?;

        if resp.status == "success" {
            Ok(resp)
        } else if resp.status == "unavailable" {
            // Only this protocol status signals temporary busy/throttling.
            // Free-form provider messages never select a retryable class.
            Err(KeyError::Unavailable)
        } else {
            let msg = resp
                .error_message
                .unwrap_or_else(|| "KMS failed".to_string());
            if msg.contains("not found") {
                Err(KeyError::NotFound)
            } else {
                Err(KeyError::OperationFailed)
            }
        }
    }
}

#[async_trait]
impl RemoteSealProvider for KmsRemoteSealProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        let (_epoch, key_id) = self.material.active_selection()?;
        let bound_aad = serialize_bound_aad(aad, &key_id)?;
        let req = KmsRequest {
            request_type: "encrypt".to_string(),
            purpose: Some(aad.purpose().as_str().to_string()),
            tenant: Some(aad.tenant().as_str().to_string()),
            key_id: Some(key_id.as_str().to_string()),
            aad_hex: Some(encode_hex(&bound_aad)),
            plaintext_hex: Some(encode_hex(plaintext)),
            ciphertext_and_tag_hex: None,
        };
        let resp = self.call_kms(req).await?;
        let ciphertext_hex = resp
            .ciphertext_and_tag_hex
            .ok_or(KeyError::OperationFailed)?;
        let ciphertext_and_tag = decode_hex_vec(&ciphertext_hex)?;
        // RemoteSeal output is opaque and may include provider framing, but
        // even an empty plaintext requires an authentication tag.
        if ciphertext_and_tag.len() < AEAD_TAG_LEN {
            return Err(KeyError::OperationFailed);
        }

        Ok(EncryptedPayload {
            aad: bound_aad,
            ciphertext_and_tag,
        })
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let bound_aad = serialize_bound_aad(aad, key_id)?;
        let req = KmsRequest {
            request_type: "decrypt".to_string(),
            purpose: Some(aad.purpose().as_str().to_string()),
            tenant: Some(aad.tenant().as_str().to_string()),
            key_id: Some(key_id.as_str().to_string()),
            aad_hex: Some(encode_hex(&bound_aad)),
            plaintext_hex: None,
            ciphertext_and_tag_hex: Some(encode_hex(ciphertext_and_tag)),
        };
        let resp = self.call_kms(req).await?;
        let plaintext_hex = Zeroizing::new(resp.plaintext_hex.ok_or(KeyError::OperationFailed)?);
        Ok(Zeroizing::new(decode_hex_vec(&plaintext_hex)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn kms_unix_connect_classification_preserves_outages_and_rejects_configuration() {
        for errno in [
            libc::ENOENT,
            libc::ECONNREFUSED,
            libc::ECONNRESET,
            libc::ECONNABORTED,
            libc::ETIMEDOUT,
            libc::EINTR,
            libc::EAGAIN,
            libc::ENOMEM,
            libc::ENOBUFS,
            libc::EMFILE,
            libc::ENFILE,
        ] {
            assert_eq!(
                unix_connect_error(std::io::Error::from_raw_os_error(errno)),
                KeyError::Unavailable,
                "temporary service or resource failure: {errno}"
            );
        }
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::EINVAL,
            libc::ENOTDIR,
            libc::ENAMETOOLONG,
            libc::ELOOP,
            libc::ENOTSOCK,
            libc::EPROTOTYPE,
        ] {
            assert_eq!(
                unix_connect_error(std::io::Error::from_raw_os_error(errno)),
                KeyError::OperationFailed,
                "invalid local configuration: {errno}"
            );
        }
    }

    #[tokio::test]
    async fn kms_invalid_unix_paths_are_permanent_for_all_operations() {
        let mut results = Vec::new();
        for endpoint in [
            "unix://".to_string(),
            "unix://relative.sock".to_string(),
            "unix://unix:///tmp/kms.sock".to_string(),
            "/tmp/kms\0.sock".to_string(),
            "unix:///tmp/kms\0.sock".to_string(),
            format!("unix:///{}", "x".repeat(256)),
        ] {
            results.push(kms_request_errors(endpoint, None, "kms.example").await);
        }
        assert!(
            results
                .iter()
                .flatten()
                .all(|error| *error == KeyError::OperationFailed),
            "invalid paths must fail permanently: {results:?}"
        );
    }

    #[tokio::test]
    async fn kms_repeated_tcp_scheme_is_permanent_before_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let errors = kms_request_errors(
            format!("tcp://tcp://{}", listener.local_addr().unwrap()),
            Some(kms_test_tls_connector()),
            "kms.example",
        )
        .await;
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "repeated scheme must fail permanently: {errors:?}"
        );
        // A rejected configuration must not send even a TLS ClientHello.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn kms_absent_and_refused_unix_services_remain_unavailable() {
        let path = next_mock_socket_path();
        for prefix in ["", "unix://"] {
            let errors =
                kms_request_errors(format!("{prefix}{}", path.display()), None, "kms.example")
                    .await;
            assert!(errors.iter().all(|error| *error == KeyError::Unavailable));
        }
        // Dropping the listener leaves a valid socket pathname with no service.
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        let errors = kms_request_errors(path.display().to_string(), None, "kms.example").await;
        std::fs::remove_file(path).unwrap();
        assert!(errors.iter().all(|error| *error == KeyError::Unavailable));
    }

    #[tokio::test]
    async fn kms_non_socket_unix_path_is_permanent_for_all_operations() {
        let directory = next_mock_socket_path();
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("regular-file");
        std::fs::write(&file, b"not a socket").unwrap();
        // ENOTDIR is a configuration defect, unlike an absent service socket.
        let errors = kms_request_errors(
            file.join("socket").display().to_string(),
            None,
            "kms.example",
        )
        .await;
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(directory).unwrap();
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "non-directory path component must fail permanently: {errors:?}"
        );
    }

    async fn kms_certificate_failure_errors(trust_certificate: bool) -> [KeyError; 5] {
        use tokio_rustls::rustls;
        let generated = rcgen::generate_simple_self_signed(vec!["kms.example".into()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key = rustls_pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let crypto = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(crypto.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key.into())
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        if trust_certificate {
            roots.add(certificate).unwrap();
        }
        let client = rustls::ClientConfig::builder_with_provider(crypto)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
        let task = tokio::spawn(async move {
            for _ in 0..5 {
                let (stream, _) = listener.accept().await.unwrap();
                assert!(
                    acceptor.accept(stream).await.is_err(),
                    "client must reject the certificate"
                );
            }
        });
        let name = if trust_certificate {
            "wrong.example"
        } else {
            "kms.example"
        };
        let errors = kms_request_errors(
            endpoint,
            Some(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
                client,
            ))),
            name,
        )
        .await;
        task.await.unwrap();
        errors
    }

    #[tokio::test]
    async fn kms_untrusted_certificate_is_permanent_for_all_operations() {
        let errors = kms_certificate_failure_errors(false).await;
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "untrusted certificate must fail permanently: {errors:?}"
        );
    }

    #[tokio::test]
    async fn kms_certificate_name_mismatch_is_permanent_for_all_operations() {
        let errors = kms_certificate_failure_errors(true).await;
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "certificate name mismatch must fail permanently: {errors:?}"
        );
    }

    async fn kms_peer_alert_errors(alert: Option<u8>) -> [KeyError; 5] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = [0u8; 5];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22, "client must send a handshake record");
                let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
                stream.read_exact(&mut body).await.unwrap();
                if let Some(alert) = alert {
                    // TLS fatal alert record: bad_certificate, unknown_ca or access_denied.
                    stream.write_all(&[21, 3, 3, 0, 2, 2, alert]).await.unwrap();
                }
            }
        });
        let errors =
            kms_request_errors(endpoint, Some(kms_test_tls_connector()), "kms.example").await;
        task.await.unwrap();
        errors
    }

    #[tokio::test]
    async fn kms_peer_authentication_alerts_are_permanent_for_all_operations() {
        let mut results = Vec::new();
        for alert in [42, 48, 49] {
            results.push(kms_peer_alert_errors(Some(alert)).await);
        }
        assert!(
            results
                .iter()
                .flatten()
                .all(|error| *error == KeyError::OperationFailed),
            "peer authentication rejection must fail permanently: {results:?}"
        );
    }

    #[tokio::test]
    async fn kms_tls13_client_authentication_rejection_is_permanent_for_all_operations() {
        use tokio_rustls::rustls;
        let generated = rcgen::generate_simple_self_signed(vec!["kms.example".into()]).unwrap();
        let certificate = generated.cert.der().clone();
        let key = rustls_pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let crypto = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            std::sync::Arc::new(roots.clone()),
            crypto.clone(),
        )
        .build()
        .unwrap();
        let server = rustls::ServerConfig::builder_with_provider(crypto.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![certificate], key.into())
            .unwrap();
        let client = rustls::ClientConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
        let task = tokio::spawn(async move {
            for _ in 0..5 {
                let (stream, _) = listener.accept().await.unwrap();
                let error = acceptor.accept(stream).await.unwrap_err();
                assert!(matches!(
                    error
                        .get_ref()
                        .and_then(|cause| cause.downcast_ref::<rustls::Error>()),
                    Some(rustls::Error::NoCertificatesPresented)
                ));
            }
        });
        let errors = kms_request_errors(
            endpoint,
            Some(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
                client,
            ))),
            "kms.example",
        )
        .await;
        task.await.unwrap();
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "TLS 1.3 client authentication rejection must fail permanently: {errors:?}"
        );
    }

    #[tokio::test]
    async fn kms_handshake_transport_loss_remains_unavailable() {
        let errors = kms_peer_alert_errors(None).await;
        assert!(errors.iter().all(|error| *error == KeyError::Unavailable));
    }

    #[tokio::test]
    async fn kms_explicit_unavailable_status_is_retryable_for_all_operations() {
        let mut results = Vec::new();
        for operation in [
            "get_active_key",
            "get_key_by_id",
            "rotate_key",
            "seal",
            "unseal",
        ] {
            for message in [
                "busy",
                "throttled",
                "key not found in temporarily unavailable replica",
            ] {
                let response =
                    serde_json::json!({"status": "unavailable", "error_message": message});
                results.push(
                    malformed_response_error(
                        operation,
                        MockResponse::Bytes(response.to_string().into_bytes()),
                    )
                    .await,
                );
            }
        }
        assert!(
            results.iter().all(|error| *error == KeyError::Unavailable),
            "explicit availability status must remain retryable: {results:?}"
        );
        for error in results {
            assert_eq!(format!("{error:?}"), "Unavailable");
        }
    }

    #[tokio::test]
    async fn kms_error_text_cannot_make_a_rejection_retryable() {
        for operation in [
            "get_active_key",
            "get_key_by_id",
            "rotate_key",
            "seal",
            "unseal",
        ] {
            for status in ["error", "busy", "throttled", "UNAVAILABLE"] {
                let response = serde_json::json!({"status": status,
                    "error_message": "busy throttled service unavailable sensitive-canary", "retryable": true});
                let error = malformed_response_error(
                    operation,
                    MockResponse::Bytes(response.to_string().into_bytes()),
                )
                .await;
                assert_eq!(error, KeyError::OperationFailed);
                assert_eq!(format!("{error:?}"), "OperationFailed");
                assert_eq!(error.to_string(), "key provider operation failed");
            }
        }
    }

    fn next_mock_socket_path() -> PathBuf {
        let unique = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        // `sockaddr_un::sun_path` is short on supported Unix targets. A
        // fixed-width PID/counter basename stays unique within the test
        // process without consuming the budget with timestamps or labels.
        std::env::temp_dir().join(format!("ok-{:08x}-{unique:016x}.s", std::process::id()))
    }

    enum MockResponse {
        Bytes(Vec<u8>),
        OversizedLength,
        Hang(Duration),
    }

    struct MockKms {
        endpoint: String,
        path: PathBuf,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockKms {
        fn drop(&mut self) {
            self.handle.abort();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn mock_kms(response: MockResponse) -> MockKms {
        mock_kms_recording(response).await.0
    }

    async fn mock_kms_recording(
        response: MockResponse,
    ) -> (MockKms, tokio::sync::oneshot::Receiver<KmsRequest>) {
        let path = next_mock_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind mock KMS socket");
        let task_path = path.clone();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept mock KMS client");
            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .await
                .expect("read request length");
            let request_len = u32::from_be_bytes(len_buf) as usize;
            let mut request = vec![0u8; request_len];
            stream
                .read_exact(&mut request)
                .await
                .expect("read request body");
            let request: KmsRequest =
                serde_json::from_slice(&request).expect("request JSON should decode");
            let _ = request_tx.send(request);

            match response {
                MockResponse::Bytes(body) => {
                    let len = u32::try_from(body.len()).expect("mock body length");
                    stream
                        .write_all(&len.to_be_bytes())
                        .await
                        .expect("write response length");
                    stream.write_all(&body).await.expect("write response body");
                }
                MockResponse::OversizedLength => {
                    let len = u32::try_from(KmsKeyProvider::MAX_RESPONSE_BYTES + 1)
                        .expect("oversized mock length");
                    stream
                        .write_all(&len.to_be_bytes())
                        .await
                        .expect("write oversized response length");
                }
                MockResponse::Hang(delay) => {
                    tokio::time::sleep(delay).await;
                }
            }
            let _ = std::fs::remove_file(task_path);
        });

        let mock = MockKms {
            endpoint: path.to_string_lossy().into_owned(),
            path,
            handle,
        };
        (mock, request_rx)
    }

    async fn two_request_gated_kms(
        response_body: Vec<u8>,
    ) -> (
        MockKms,
        tokio::sync::mpsc::Receiver<KmsRequest>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let path = next_mock_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind gated KMS socket");
        let task_path = path.clone();
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(2);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let mut release_rx = Some(release_rx);
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept KMS client");
                let mut len_buf = [0u8; 4];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .expect("read request length");
                let request_len = u32::from_be_bytes(len_buf) as usize;
                let mut request = vec![0u8; request_len];
                stream
                    .read_exact(&mut request)
                    .await
                    .expect("read request body");
                let request: KmsRequest =
                    serde_json::from_slice(&request).expect("decode KMS request");
                request_tx.send(request).await.expect("capture KMS request");

                if request_index == 0 {
                    release_rx
                        .take()
                        .expect("first request release")
                        .await
                        .expect("release first KMS response");
                }
                let len = u32::try_from(response_body.len()).expect("response length");
                stream
                    .write_all(&len.to_be_bytes())
                    .await
                    .expect("write response length");
                stream
                    .write_all(&response_body)
                    .await
                    .expect("write response body");
            }
            let _ = std::fs::remove_file(task_path);
        });

        (
            MockKms {
                endpoint: path.to_string_lossy().into_owned(),
                path,
                handle,
            },
            request_rx,
            release_tx,
        )
    }

    fn tenant() -> TenantId {
        TenantId::new("tenant-a").expect("tenant")
    }

    fn key_hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(AES_256_GCM_SIV_KEY_LEN)
    }

    fn success_response(
        key_id: &str,
        key_bytes_hex: impl Into<String>,
        purpose: Option<&str>,
        tenant: Option<&str>,
    ) -> Vec<u8> {
        serde_json::json!({
            "status": "success",
            "key_id": key_id,
            "key_bytes_hex": key_bytes_hex.into(),
            "purpose": purpose,
            "tenant": tenant,
        })
        .to_string()
        .into_bytes()
    }

    fn session_aad() -> EnvelopeAad {
        EnvelopeAad::session(
            tenant(),
            1,
            crate::SessionAad::new(
                "smf",
                "session-digest",
                "ipsec-sa",
                2,
                9,
                "regional-cache-a",
            )
            .expect("session aad"),
        )
    }

    #[test]
    fn decode_hex_32_accepts_valid_ascii_hex() {
        let decoded =
            decode_hex_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("valid key bytes");

        assert_eq!(decoded[0], 0x00);
        assert_eq!(decoded[15], 0x0f);
        assert_eq!(decoded[31], 0x1f);
    }

    #[test]
    fn decode_hex_32_rejects_non_ascii_without_panic() {
        let malformed = "ä".repeat(32);

        assert_eq!(decode_hex_32(&malformed), Err(KeyError::OperationFailed));
    }

    #[test]
    fn decode_hex_32_rejects_non_hex_ascii() {
        assert_eq!(
            decode_hex_32("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"),
            Err(KeyError::OperationFailed)
        );
    }

    #[tokio::test]
    async fn kms_provider_success_round_trip_from_unix_mock() {
        let mock = mock_kms(MockResponse::Bytes(success_response(
            "session-active-2026-01",
            key_hex(0x42),
            None,
            None,
        )))
        .await;
        let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));

        let handle = provider
            .get_active_key(KeyPurpose::Session, &tenant())
            .await
            .expect("active key");

        assert_eq!(handle.key_id().as_str(), "session-active-2026-01");
        assert_eq!(handle.purpose(), KeyPurpose::Session);
        assert_eq!(handle.tenant(), &tenant());
        assert_eq!(handle.material.bytes.as_slice(), &[0x42; 32]);
    }

    #[tokio::test]
    async fn kms_provider_rejects_oversized_response() {
        let mock = mock_kms(MockResponse::OversizedLength).await;
        let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));

        let err = provider
            .get_active_key(KeyPurpose::Session, &tenant())
            .await
            .expect_err("oversized KMS response must fail");

        assert_eq!(err, KeyError::OperationFailed);
    }

    #[tokio::test]
    async fn kms_provider_rejects_malformed_json_response() {
        let mock = mock_kms(MockResponse::Bytes(br#"{"status":"success""#.to_vec())).await;
        let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));

        let err = provider
            .get_active_key(KeyPurpose::Session, &tenant())
            .await
            .expect_err("malformed KMS JSON must fail");

        assert_eq!(err, KeyError::OperationFailed);
    }

    #[tokio::test]
    async fn kms_provider_rejects_malformed_key_hex() {
        for malformed in [
            "00".repeat(31),
            format!("zz{}", "00".repeat(31)),
            "ä".repeat(32),
        ] {
            let mock = mock_kms(MockResponse::Bytes(success_response(
                "session-active-2026-01",
                malformed,
                None,
                None,
            )))
            .await;
            let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));

            let err = provider
                .get_active_key(KeyPurpose::Session, &tenant())
                .await
                .expect_err("malformed KMS key hex must fail");

            assert_eq!(err, KeyError::OperationFailed);
        }
    }

    #[tokio::test]
    async fn kms_provider_rejects_unknown_purpose_from_lookup() {
        let key_id = KeyId::new("session-active-2026-01").expect("key id");
        let mock = mock_kms(MockResponse::Bytes(success_response(
            key_id.as_str(),
            key_hex(0x24),
            Some("unknown-purpose"),
            Some("tenant-a"),
        )))
        .await;
        let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));

        let err = provider
            .get_key_by_id(&key_id)
            .await
            .expect_err("unknown KMS purpose must fail");

        assert_eq!(err, KeyError::OperationFailed);
    }

    #[tokio::test]
    async fn kms_malformed_success_fields_are_permanent_and_redacted() {
        let mut errors = Vec::new();
        for (operation, fields) in [
            ("get_active_key", &["key_id", "key_bytes_hex"][..]),
            ("get_key_by_id", &["key_bytes_hex", "purpose", "tenant"][..]),
            ("rotate_key", &["key_id"][..]),
            ("seal", &["ciphertext_and_tag_hex"][..]),
            ("unseal", &["plaintext_hex"][..]),
        ] {
            for field in fields {
                let invalid = match *field {
                    "key_id" | "tenant" => vec![None, Some(String::new())],
                    "purpose" => vec![None, Some("unknown-sensitive-purpose".to_string())],
                    "key_bytes_hex" => vec![
                        None,
                        Some("00".repeat(31)),
                        Some("gg".repeat(32)),
                        Some("ä".repeat(32)),
                    ],
                    "ciphertext_and_tag_hex" => vec![
                        None,
                        Some(String::new()),
                        Some("00".into()),
                        Some("00".repeat(AEAD_TAG_LEN - 1)),
                        Some("0".into()),
                        Some("gg".into()),
                        Some("ä".into()),
                    ],
                    _ => vec![None, Some("0".into()), Some("gg".into()), Some("ä".into())],
                };
                for value in invalid {
                    let mut response = serde_json::json!({
                        "status": "success",
                        "key_id": "kms-sensitive-key",
                        "key_bytes_hex": key_hex(0x42),
                        "purpose": "session",
                        "tenant": "tenant-a",
                        "ciphertext_and_tag_hex": encode_hex(b"ciphertext-canary"),
                        "plaintext_hex": encode_hex(b"plaintext-canary"),
                    });
                    if let Some(value) = value {
                        response[field] = serde_json::Value::String(value);
                    } else {
                        response.as_object_mut().unwrap().remove(*field);
                    }
                    let error = malformed_response_error(
                        operation,
                        MockResponse::Bytes(response.to_string().into_bytes()),
                    )
                    .await;
                    errors.push((operation, *field, error));
                }
            }
        }
        assert!(
            errors
                .iter()
                .all(|(_, _, error)| *error == KeyError::OperationFailed),
            "malformed success responses must be permanent: {errors:?}"
        );
        for (_, _, error) in errors {
            assert_eq!(error.to_string(), "key provider operation failed");
            assert_eq!(format!("{error:?}"), "OperationFailed");
        }
    }

    async fn malformed_response_error(operation: &str, response: MockResponse) -> KeyError {
        let key_id = KeyId::new("kms-sensitive-key").expect("key ID");
        let mock = mock_kms(response).await;
        let local = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));
        let remote = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );
        match operation {
            "get_active_key" => local
                .get_active_key(KeyPurpose::Session, &tenant())
                .await
                .expect_err("invalid active key response"),
            "get_key_by_id" => local
                .get_key_by_id(&key_id)
                .await
                .expect_err("invalid historical key response"),
            "rotate_key" => local
                .rotate_key(KeyPurpose::Session, &tenant())
                .await
                .expect_err("invalid rotation response"),
            "seal" => remote
                .seal(&session_aad(), b"plaintext-canary")
                .await
                .expect_err("invalid encrypt response"),
            "unseal" => remote
                .unseal(&key_id, &session_aad(), b"ciphertext-canary")
                .await
                .expect_err("invalid decrypt response"),
            _ => unreachable!("fixed operation fixture"),
        }
    }

    #[tokio::test]
    async fn kms_malformed_response_frames_are_permanent_for_all_operations() {
        let mut errors = Vec::new();
        for operation in [
            "get_active_key",
            "get_key_by_id",
            "rotate_key",
            "seal",
            "unseal",
        ] {
            for response in [
                MockResponse::Bytes(br#"{"status":"success""#.to_vec()),
                MockResponse::OversizedLength,
            ] {
                errors.push((
                    operation,
                    malformed_response_error(operation, response).await,
                ));
            }
        }
        assert!(
            errors
                .iter()
                .all(|(_, error)| *error == KeyError::OperationFailed),
            "malformed complete response frames must be permanent: {errors:?}"
        );
    }

    #[tokio::test]
    async fn kms_remote_seal_rejects_short_success_outputs() {
        let mut results = Vec::new();
        for plaintext in [b"".as_slice(), b"x".as_slice()] {
            for length in 0..AEAD_TAG_LEN {
                let mock = mock_kms(MockResponse::Bytes(
                    serde_json::json!({
                        "status": "success",
                        "ciphertext_and_tag_hex": "00".repeat(length),
                    })
                    .to_string()
                    .into_bytes(),
                ))
                .await;
                let provider = KmsRemoteSealProvider::new(
                    mock.endpoint.clone(),
                    None,
                    Duration::from_secs(1),
                    KeyId::new("short-response-key").expect("key ID"),
                );
                let result = provider.seal(&session_aad(), plaintext).await;
                results.push((plaintext.len(), length, result.err()));
            }
        }
        assert!(
            results
                .iter()
                .all(|(_, _, error)| *error == Some(KeyError::OperationFailed)),
            "every short success output must fail permanently: {results:?}"
        );
    }

    #[tokio::test]
    async fn kms_remote_seal_accepts_empty_plaintext_with_valid_tag() {
        let key_id = KeyId::new("empty-plaintext-key").expect("key ID");
        let handle = KeyHandle::new(
            key_id.clone(),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x42; AES_256_GCM_SIV_KEY_LEN]),
        );
        let aad = session_aad();
        let nonce = [0x24; AES_256_GCM_SIV_NONCE_LEN];
        let expected = handle
            .encrypt_payload(&aad, b"", nonce)
            .expect("seal empty payload");
        assert_eq!(expected.ciphertext_and_tag.len(), AEAD_TAG_LEN);
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(
            serde_json::json!({
                "status": "success",
                "ciphertext_and_tag_hex": encode_hex(&expected.ciphertext_and_tag),
            })
            .to_string()
            .into_bytes(),
        ))
        .await;
        let provider =
            KmsRemoteSealProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1), key_id);
        let sealed = provider
            .seal(&aad, b"")
            .await
            .expect("valid empty-plaintext seal");
        assert_eq!(sealed, expected);
        assert!(handle
            .decrypt_payload(&aad, &sealed.aad, &sealed.ciphertext_and_tag, nonce)
            .expect("authenticate empty plaintext")
            .is_empty());
        assert_eq!(
            request_rx
                .await
                .expect("request captured")
                .plaintext_hex
                .as_deref(),
            Some("")
        );
    }

    async fn kms_request_errors(
        endpoint: String,
        connector: Option<tokio_rustls::TlsConnector>,
        server_name: &str,
    ) -> [KeyError; 5] {
        let key_id = KeyId::new("configuration-key").expect("key ID");
        let local =
            KmsKeyProvider::new(endpoint.clone(), connector.clone(), Duration::from_secs(1))
                .with_server_name(server_name);
        let remote =
            KmsRemoteSealProvider::new(endpoint, connector, Duration::from_secs(1), key_id.clone())
                .with_server_name(server_name);
        [
            local
                .get_active_key(KeyPurpose::Session, &tenant())
                .await
                .expect_err("request must fail"),
            local
                .get_key_by_id(&key_id)
                .await
                .expect_err("request must fail"),
            local
                .rotate_key(KeyPurpose::Session, &tenant())
                .await
                .expect_err("request must fail"),
            remote
                .seal(&session_aad(), b"plaintext-canary")
                .await
                .expect_err("request must fail"),
            remote
                .unseal(&key_id, &session_aad(), b"ciphertext-canary")
                .await
                .expect_err("request must fail"),
        ]
    }

    #[tokio::test]
    async fn kms_missing_tls_connector_is_permanent_before_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let errors = kms_request_errors(
            format!("tcp://{}", listener.local_addr().expect("fixture address")),
            None,
            KmsRemoteSealProvider::DEFAULT_SERVER_NAME,
        )
        .await;
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "invalid configuration must fail permanently: {errors:?}"
        );
        assert_eq!(
            listener
                .accept()
                .expect_err("no plaintext connection")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    fn kms_test_tls_connector() -> tokio_rustls::TlsConnector {
        use tokio_rustls::rustls;
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("supported TLS versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
    }

    #[test]
    fn kms_tcp_endpoint_preserves_valid_authorities_and_rejects_uri_extras() {
        for (endpoint, expected) in [
            ("kms.example:443", "kms.example:443"),
            ("tcp://kms.example:443", "kms.example:443"),
            ("tcp://kms.example:+443", "kms.example:+443"),
            ("tcp://127.0.0.1:0", "127.0.0.1:0"),
            ("tcp://127.0.0.1:65535", "127.0.0.1:65535"),
            ("tcp://[::1]:443", "[::1]:443"),
            ("tcp://[2001:db8::1]:443", "[2001:db8::1]:443"),
            ("tcp://::1:443", "::1:443"),
            ("tcp://fe80::1%2:443", "fe80::1%2:443"),
        ] {
            assert_eq!(tcp_endpoint_addr(endpoint), Ok(expected), "{endpoint}");
        }
        for endpoint in [
            // Only one scheme prefix is valid; repeated prefixes are configuration errors.
            "tcp://tcp://kms.example:443",
            "tcp://kms.example:443/path",
            "tcp://kms.example/path:443",
            "tcp://user@kms.example:443",
            "tcp://kms.example?query:443",
            "tcp://kms.example#fragment:443",
            "tcp://kms example:443",
            "tcp://[not-an-ip]:443",
            "tcp://[::1:443",
            "tcp://::1]:443",
            "tcp://fe80::1%:443",
        ] {
            assert_eq!(
                tcp_endpoint_addr(endpoint),
                Err(KeyError::OperationFailed),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn kms_tcp_endpoint_accepts_release_address_forms() {
        for endpoint in [
            "kms.example:7443",
            "tcp://kms.example:7443",
            "127.0.0.1:7443",
            "tcp://127.0.0.1:7443",
            "127.0.0.1:+7443",
            "tcp://127.0.0.1:+7443",
            "[::1]:7443",
            "tcp://[::1]:7443",
            "::1:7443",
            "tcp://::1:7443",
        ] {
            assert!(tcp_endpoint_addr(endpoint).is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn kms_tcp_endpoint_accepts_scoped_ipv6_without_connecting() {
        let addr =
            std::net::SocketAddrV6::new("fe80::1".parse().expect("IPv6 literal"), 7443, 0, 2);
        for endpoint in [addr.to_string(), format!("tcp://{addr}")] {
            assert_eq!(
                tcp_endpoint_addr(&endpoint).expect("scoped IPv6 remains valid"),
                addr.to_string(),
                "scope must survive validation: {endpoint}"
            );
        }
    }

    #[test]
    fn kms_tcp_endpoint_rejects_control_characters_in_hosts() {
        for control in ['\0', '\u{1}', '\u{1f}', '\u{7f}', '\u{85}'] {
            let endpoint = format!("tcp://kms{control}.example:7443");
            assert_eq!(
                tcp_endpoint_addr(&endpoint),
                Err(KeyError::OperationFailed),
                "{endpoint:?}"
            );
        }
    }

    #[tokio::test]
    async fn kms_bare_endpoint_connection_failure_remains_unavailable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let port = listener.local_addr().expect("fixture address").port();
        drop(listener);
        for endpoint in [format!("127.0.0.1:{port}"), format!("localhost:{port}")] {
            let errors = kms_request_errors(
                endpoint.clone(),
                Some(kms_test_tls_connector()),
                KmsRemoteSealProvider::DEFAULT_SERVER_NAME,
            )
            .await;
            assert!(
                errors.iter().all(|error| *error == KeyError::Unavailable),
                "valid bare endpoint {endpoint} must reach connection: {errors:?}"
            );
        }
    }

    #[tokio::test]
    async fn kms_nul_host_is_permanent_before_connect() {
        let errors = kms_request_errors(
            "tcp://kms\0.example:7443".into(),
            Some(kms_test_tls_connector()),
            KmsRemoteSealProvider::DEFAULT_SERVER_NAME,
        )
        .await;
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "a NUL host must fail permanently for every operation: {errors:?}"
        );
    }

    #[tokio::test]
    async fn kms_invalid_server_name_is_permanent_before_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let errors = kms_request_errors(
            format!("tcp://{}", listener.local_addr().expect("fixture address")),
            Some(kms_test_tls_connector()),
            "not a dns name",
        )
        .await;
        assert!(
            errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed),
            "invalid configuration must fail permanently: {errors:?}"
        );
        assert_eq!(
            listener
                .accept()
                .expect_err("validate before connecting")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn kms_invalid_tcp_endpoint_is_permanent_before_connect() {
        let endpoints = [
            "tcp://127.0.0.1",
            "tcp://127.0.0.1:",
            "tcp://:1234",
            "tcp://127.0.0.1:not-a-port",
            "tcp://127.0.0.1:65536",
            "tcp://127.0.0.1:-1",
            "tcp://[::1]",
            "tcp://[]:1234",
        ];
        let mut observed = Vec::new();
        for endpoint in endpoints {
            let errors = kms_request_errors(
                endpoint.to_string(),
                Some(kms_test_tls_connector()),
                KmsRemoteSealProvider::DEFAULT_SERVER_NAME,
            )
            .await;
            observed.push((endpoint, errors));
        }
        assert!(
            observed.iter().all(|(_, errors)| errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed)),
            "invalid endpoint configuration must fail permanently: {observed:?}"
        );
    }

    #[tokio::test]
    async fn kms_unsupported_endpoint_scheme_is_permanent_before_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let addr = listener.local_addr().expect("fixture address");
        let mut observed = Vec::new();
        for endpoint in [format!("https://{addr}"), format!("http://{addr}")] {
            let errors = kms_request_errors(
                endpoint.clone(),
                Some(kms_test_tls_connector()),
                KmsRemoteSealProvider::DEFAULT_SERVER_NAME,
            )
            .await;
            observed.push((endpoint, errors));
        }
        assert!(
            observed.iter().all(|(_, errors)| errors
                .iter()
                .all(|error| *error == KeyError::OperationFailed)),
            "unsupported endpoint schemes must fail permanently: {observed:?}"
        );
        assert_eq!(
            listener
                .accept()
                .expect_err("validate before connecting")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn kms_tcp_connection_failure_remains_unavailable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture address");
        drop(listener);
        let errors = kms_request_errors(
            format!("tcp://{addr}"),
            Some(kms_test_tls_connector()),
            KmsRemoteSealProvider::DEFAULT_SERVER_NAME,
        )
        .await;
        assert!(
            errors.iter().all(|error| *error == KeyError::Unavailable),
            "valid endpoints must preserve connection failures as retryable: {errors:?}"
        );
    }

    #[tokio::test]
    async fn kms_provider_times_out_waiting_for_response() {
        let mock = mock_kms(MockResponse::Hang(Duration::from_secs(5))).await;
        let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_millis(25));

        let err = provider
            .get_active_key(KeyPurpose::Session, &tenant())
            .await
            .expect_err("KMS timeout must fail");

        assert_eq!(err, KeyError::Unavailable);
    }

    #[tokio::test]
    async fn kms_completed_failure_is_not_unavailability() {
        let key_id = KeyId::new("kms-denial-sensitive-key").expect("key id");
        for reason in ["authentication failed", "access denied", "key revoked"] {
            for operation in ["get_active_key", "get_key_by_id", "seal", "unseal"] {
                let response = serde_json::json!({
                    "status": "error",
                    "error_message": format!("{reason}: key={} payload=secret-canary", key_id.as_str()),
                })
                .to_string()
                .into_bytes();
                let mock = mock_kms(MockResponse::Bytes(response)).await;
                let local =
                    KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));
                let remote = KmsRemoteSealProvider::new(
                    mock.endpoint.clone(),
                    None,
                    Duration::from_secs(1),
                    key_id.clone(),
                );
                let error = match operation {
                    "get_active_key" => local
                        .get_active_key(KeyPurpose::Session, &tenant())
                        .await
                        .expect_err("explicit denial fails active lookup"),
                    "get_key_by_id" => local
                        .get_key_by_id(&key_id)
                        .await
                        .expect_err("explicit denial fails historical lookup"),
                    "seal" => remote
                        .seal(&session_aad(), b"plaintext-canary")
                        .await
                        .expect_err("explicit denial fails seal"),
                    "unseal" => remote
                        .unseal(&key_id, &session_aad(), b"ciphertext-canary")
                        .await
                        .expect_err("explicit denial fails unseal"),
                    _ => unreachable!("fixed operation fixture"),
                };
                assert_ne!(error, KeyError::Unavailable, "{operation}: {reason}");
                assert_eq!(error, KeyError::OperationFailed);
                assert_eq!(error.to_string(), "key provider operation failed");
                assert_eq!(format!("{error:?}"), "OperationFailed");
            }
        }
    }

    #[tokio::test]
    async fn kms_remote_timeout_remains_unavailability() {
        let key_id = KeyId::new("remote-timeout-key").expect("key id");
        for unseal in [false, true] {
            let mock = mock_kms(MockResponse::Hang(Duration::from_secs(5))).await;
            let provider = KmsRemoteSealProvider::new(
                mock.endpoint.clone(),
                None,
                Duration::from_millis(25),
                key_id.clone(),
            );
            let error = if unseal {
                provider
                    .unseal(&key_id, &session_aad(), b"ciphertext-canary")
                    .await
                    .expect_err("unseal times out")
            } else {
                provider
                    .seal(&session_aad(), b"plaintext-canary")
                    .await
                    .expect_err("seal times out")
            };
            assert_eq!(error, KeyError::Unavailable);
        }
    }

    #[tokio::test]
    async fn kms_remote_seal_provider_maps_seal_to_encrypt_request() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let ciphertext = b"kms-ciphertext-and-auth-tag";
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(
            serde_json::json!({
                "status": "success",
                "ciphertext_and_tag_hex": encode_hex(ciphertext),
            })
            .to_string()
            .into_bytes(),
        ))
        .await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );
        let aad = session_aad();

        let sealed = provider
            .seal(&aad, b"plain-session")
            .await
            .expect("kms seal");

        assert_eq!(sealed.ciphertext_and_tag, ciphertext);
        let request = request_rx.await.expect("request captured");
        assert_eq!(request.request_type, "encrypt");
        assert_eq!(request.key_id.as_deref(), Some(key_id.as_str()));
        assert_eq!(
            request.aad_hex.as_deref(),
            Some(encode_hex(&sealed.aad).as_str())
        );
        assert_eq!(
            request.plaintext_hex.as_deref(),
            Some(encode_hex(b"plain-session").as_str())
        );
        assert!(request.ciphertext_and_tag_hex.is_none());
    }

    #[tokio::test]
    async fn kms_remote_seal_provider_maps_unseal_to_decrypt_request() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let ciphertext = b"kms-ciphertext-and-auth-tag";
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(
            serde_json::json!({
                "status": "success",
                "plaintext_hex": encode_hex(b"plain-session"),
            })
            .to_string()
            .into_bytes(),
        ))
        .await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );
        let aad = session_aad();
        let historical_bound_aad =
            serialize_bound_aad(&aad, &key_id).expect("historical bound AAD");
        let next_key_id = KeyId::new("session-remote-2026-02").expect("next key id");
        assert_eq!(
            provider
                .publish_active_key(next_key_id)
                .expect("publish active key")
                .get(),
            2
        );

        let plaintext = provider
            .unseal(&key_id, &aad, ciphertext)
            .await
            .expect("kms unseal");

        assert_eq!(plaintext.as_slice(), b"plain-session");
        let request = request_rx.await.expect("request captured");
        assert_eq!(request.request_type, "decrypt");
        assert_eq!(request.key_id.as_deref(), Some(key_id.as_str()));
        assert_eq!(
            request.aad_hex.as_deref(),
            Some(encode_hex(&historical_bound_aad).as_str())
        );
        assert_eq!(
            request.ciphertext_and_tag_hex.as_deref(),
            Some(encode_hex(ciphertext).as_str())
        );
        assert!(request.plaintext_hex.is_none());
    }

    #[tokio::test]
    async fn kms_remote_seal_failure_redacts_remote_context() {
        let key_id = KeyId::new("session-remote-sensitive-key").expect("key id");
        let payload_canary = "subscriber-payload-canary";
        let response = serde_json::json!({
            "status": "error",
            "error_message": format!(
                "not found: key={} tenant=tenant-a endpoint=provider.internal payload={payload_canary}",
                key_id.as_str()
            ),
        })
        .to_string()
        .into_bytes();
        let mock = mock_kms(MockResponse::Bytes(response)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );

        let error = provider
            .unseal(&key_id, &session_aad(), b"ciphertext-canary")
            .await
            .expect_err("remote failure must fail closed");
        assert_eq!(error, KeyError::NotFound);
        let rendered = format!("{error} {error:?} {provider:?}");
        for secret in [
            key_id.as_str(),
            "tenant-a",
            "provider.internal",
            payload_canary,
            mock.endpoint.as_str(),
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[tokio::test]
    async fn kms_remote_seal_revoked_history_fails_closed() {
        let key_id = KeyId::new("session-remote-revoked-sensitive").expect("key id");
        let response = serde_json::json!({
            "status": "error",
            "error_message": format!("revoked key {} for tenant-a", key_id.as_str()),
        })
        .to_string()
        .into_bytes();
        let mock = mock_kms(MockResponse::Bytes(response)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );

        let error = provider
            .unseal(&key_id, &session_aad(), b"ciphertext-canary")
            .await
            .expect_err("revoked historical key must fail closed");
        assert_eq!(error, KeyError::OperationFailed);
        assert_eq!(error.to_string(), "key provider operation failed");
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(key_id.as_str()));
        assert!(!rendered.contains("tenant-a"));
        assert!(!rendered.contains(&mock.endpoint));
    }

    #[tokio::test]
    async fn kms_remote_seal_in_flight_request_keeps_its_material_epoch() {
        let old_key_id = KeyId::new("session-remote-2026-01").expect("old key id");
        let new_key_id = KeyId::new("session-remote-2026-02").expect("new key id");
        let response = serde_json::json!({
            "status": "success",
            "ciphertext_and_tag_hex": encode_hex(&[0xA5; 32]),
        })
        .to_string()
        .into_bytes();
        let (mock, mut requests, release_first) = two_request_gated_kms(response).await;
        let provider = std::sync::Arc::new(KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(2),
            old_key_id.clone(),
        ));
        let aad = session_aad();

        let first = tokio::spawn({
            let provider = std::sync::Arc::clone(&provider);
            let aad = aad.clone();
            async move { provider.seal(&aad, b"in flight").await }
        });
        let first_request = requests.recv().await.expect("first KMS request");
        assert_eq!(first_request.key_id.as_deref(), Some(old_key_id.as_str()));

        assert_eq!(
            provider
                .publish_active_key(new_key_id.clone())
                .expect("publish next active key")
                .get(),
            2
        );
        release_first.send(()).expect("release first response");
        first
            .await
            .expect("join first seal")
            .expect("complete first seal");

        provider.seal(&aad, b"after publish").await.expect("seal");
        let second_request = requests.recv().await.expect("second KMS request");
        assert_eq!(second_request.key_id.as_deref(), Some(new_key_id.as_str()));
        assert_eq!(provider.material_epoch().expect("material epoch").get(), 2);

        let rendered = format!("{provider:?}");
        assert!(!rendered.contains(old_key_id.as_str()));
        assert!(!rendered.contains(new_key_id.as_str()));
        assert!(!rendered.contains(&mock.endpoint));
    }
}
