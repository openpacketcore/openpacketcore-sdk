use async_trait::async_trait;
use opc_types::TenantId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{EncryptedPayload, KeyHandle, KeyProvider},
    remote::RemoteSealProvider,
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
        return Err(KeyError::Unavailable);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
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
        _ => Err(KeyError::Unavailable),
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
    let chunks = hex.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() || !hex.is_ascii() {
        return Err(KeyError::Unavailable);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in chunks {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
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
    key_id: KeyId,
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
                let path = self.endpoint.trim_start_matches("unix://");
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                Ok::<KmsStream, KeyError>(KmsStream::Unix(stream))
            } else {
                let addr = self.endpoint.trim_start_matches("tcp://");
                let connector = self.connector.as_ref().ok_or(KeyError::Unavailable)?;
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                let domain = rustls_pki_types::ServerName::try_from(self.server_name.clone())
                    .map_err(|_| KeyError::Unavailable)?;
                let tls_stream = connector
                    .connect(domain, stream)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                Ok(KmsStream::Tls(Box::new(tls_stream)))
            }
        };

        let mut stream = connect_fut.await?;

        let req_bytes = serde_json::to_vec(&req).map_err(|_| KeyError::Unavailable)?;
        let req_len = req_bytes.len() as u32;

        stream
            .write_all(&req_len.to_be_bytes())
            .await
            .map_err(|_| KeyError::Unavailable)?;
        stream
            .write_all(&req_bytes)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        stream.flush().await.map_err(|_| KeyError::Unavailable)?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > Self::MAX_RESPONSE_BYTES {
            return Err(KeyError::Unavailable);
        }

        let mut resp_buf = Zeroizing::new(vec![0u8; len]);
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let resp: KmsResponse =
            serde_json::from_slice(&resp_buf).map_err(|_| KeyError::Unavailable)?;

        if resp.status == "success" {
            Ok(resp)
        } else {
            let msg = resp
                .error_message
                .unwrap_or_else(|| "KMS failed".to_string());
            if msg.contains("not found") {
                Err(KeyError::NotFound)
            } else {
                Err(KeyError::Unavailable)
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
        let key_id_str = resp.key_id.ok_or(KeyError::NotFound)?;
        let key_bytes_hex = Zeroizing::new(resp.key_bytes_hex.ok_or(KeyError::NotFound)?);

        let key_id = KeyId::new(key_id_str)?;
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
        let key_bytes_hex = Zeroizing::new(resp.key_bytes_hex.ok_or(KeyError::NotFound)?);
        let purpose_str = resp.purpose.ok_or(KeyError::NotFound)?;
        let tenant_str = resp.tenant.ok_or(KeyError::NotFound)?;

        let purpose = match purpose_str.as_str() {
            "config" => KeyPurpose::Config,
            "shadow-security" => KeyPurpose::ShadowSecurity,
            "session" => KeyPurpose::Session,
            "ipsec-sa" => KeyPurpose::IpsecSa,
            "audit" => KeyPurpose::Audit,
            "backup" => KeyPurpose::Backup,
            _ => return Err(KeyError::Unavailable),
        };
        let tenant = TenantId::new(tenant_str)
            .map_err(|e| KeyError::invalid_metadata("tenant", e.to_string()))?;
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
        let key_id_str = resp.key_id.ok_or(KeyError::NotFound)?;
        KeyId::new(key_id_str)
    }
}

impl KmsRemoteSealProvider {
    /// Default TLS server name used when `endpoint` is a TCP address.
    pub const DEFAULT_SERVER_NAME: &'static str = KmsKeyProvider::DEFAULT_SERVER_NAME;

    /// Create a remote-seal KMS client for one remote key id.
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
            key_id,
        }
    }

    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
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
                let path = self.endpoint.trim_start_matches("unix://");
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                Ok::<KmsStream, KeyError>(KmsStream::Unix(stream))
            } else {
                let addr = self.endpoint.trim_start_matches("tcp://");
                let connector = self.connector.as_ref().ok_or(KeyError::Unavailable)?;
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                let domain = rustls_pki_types::ServerName::try_from(self.server_name.clone())
                    .map_err(|_| KeyError::Unavailable)?;
                let tls_stream = connector
                    .connect(domain, stream)
                    .await
                    .map_err(|_| KeyError::Unavailable)?;
                Ok(KmsStream::Tls(Box::new(tls_stream)))
            }
        };

        let mut stream = connect_fut.await?;

        let req_bytes = serde_json::to_vec(&req).map_err(|_| KeyError::Unavailable)?;
        let req_len = req_bytes.len() as u32;

        stream
            .write_all(&req_len.to_be_bytes())
            .await
            .map_err(|_| KeyError::Unavailable)?;
        stream
            .write_all(&req_bytes)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        stream.flush().await.map_err(|_| KeyError::Unavailable)?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > KmsKeyProvider::MAX_RESPONSE_BYTES {
            return Err(KeyError::Unavailable);
        }

        let mut resp_buf = Zeroizing::new(vec![0u8; len]);
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let resp: KmsResponse =
            serde_json::from_slice(&resp_buf).map_err(|_| KeyError::Unavailable)?;

        if resp.status == "success" {
            Ok(resp)
        } else {
            let msg = resp
                .error_message
                .unwrap_or_else(|| "KMS failed".to_string());
            if msg.contains("not found") {
                Err(KeyError::NotFound)
            } else {
                Err(KeyError::Unavailable)
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
        let bound_aad = serialize_bound_aad(aad, &self.key_id)?;
        let req = KmsRequest {
            request_type: "encrypt".to_string(),
            purpose: Some(aad.purpose().as_str().to_string()),
            tenant: Some(aad.tenant().as_str().to_string()),
            key_id: Some(self.key_id.as_str().to_string()),
            aad_hex: Some(encode_hex(&bound_aad)),
            plaintext_hex: Some(encode_hex(plaintext)),
            ciphertext_and_tag_hex: None,
        };
        let resp = self.call_kms(req).await?;
        let ciphertext_hex = resp.ciphertext_and_tag_hex.ok_or(KeyError::Unavailable)?;
        let ciphertext_and_tag = decode_hex_vec(&ciphertext_hex)?;

        Ok(EncryptedPayload {
            aad: bound_aad,
            ciphertext_and_tag,
        })
    }

    async fn unseal(
        &self,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let bound_aad = serialize_bound_aad(aad, &self.key_id)?;
        let req = KmsRequest {
            request_type: "decrypt".to_string(),
            purpose: Some(aad.purpose().as_str().to_string()),
            tenant: Some(aad.tenant().as_str().to_string()),
            key_id: Some(self.key_id.as_str().to_string()),
            aad_hex: Some(encode_hex(&bound_aad)),
            plaintext_hex: None,
            ciphertext_and_tag_hex: Some(encode_hex(ciphertext_and_tag)),
        };
        let resp = self.call_kms(req).await?;
        let plaintext_hex = Zeroizing::new(resp.plaintext_hex.ok_or(KeyError::Unavailable)?);
        Ok(Zeroizing::new(decode_hex_vec(&plaintext_hex)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::AES_256_GCM_SIV_KEY_LEN;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);

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
        let unique = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "opc-key-kms-{}-{nanos}-{unique}.sock",
            std::process::id()
        ));
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

        assert_eq!(decode_hex_32(&malformed), Err(KeyError::Unavailable));
    }

    #[test]
    fn decode_hex_32_rejects_non_hex_ascii() {
        assert_eq!(
            decode_hex_32("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"),
            Err(KeyError::Unavailable)
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

        assert_eq!(err, KeyError::Unavailable);
    }

    #[tokio::test]
    async fn kms_provider_rejects_malformed_json_response() {
        let mock = mock_kms(MockResponse::Bytes(br#"{"status":"success""#.to_vec())).await;
        let provider = KmsKeyProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1));

        let err = provider
            .get_active_key(KeyPurpose::Session, &tenant())
            .await
            .expect_err("malformed KMS JSON must fail");

        assert_eq!(err, KeyError::Unavailable);
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

            assert_eq!(err, KeyError::Unavailable);
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

        assert_eq!(err, KeyError::Unavailable);
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

        let plaintext = provider.unseal(&aad, ciphertext).await.expect("kms unseal");

        assert_eq!(plaintext.as_slice(), b"plain-session");
        let request = request_rx.await.expect("request captured");
        assert_eq!(request.request_type, "decrypt");
        assert_eq!(request.key_id.as_deref(), Some(key_id.as_str()));
        assert_eq!(
            request.ciphertext_and_tag_hex.as_deref(),
            Some(encode_hex(ciphertext).as_str())
        );
        assert!(request.plaintext_hex.is_none());
    }
}
