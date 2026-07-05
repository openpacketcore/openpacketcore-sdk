use async_trait::async_trait;
use opc_types::TenantId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{KeyHandle, KeyProvider},
    scope::{KeyId, KeyPurpose},
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
}

#[derive(Serialize, Deserialize)]
struct KmsResponse {
    status: String,
    key_id: Option<String>,
    key_bytes_hex: Option<String>,
    purpose: Option<String>,
    tenant: Option<String>,
    error_message: Option<String>,
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], KeyError> {
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(KeyError::Unavailable);
    }
    let mut bytes = [0u8; 32];
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

pub struct KmsKeyProvider {
    endpoint: String,
    connector: Option<tokio_rustls::TlsConnector>,
    server_name: String,
    timeout: std::time::Duration,
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

        let mut stream = match tokio::time::timeout(self.timeout, connect_fut).await {
            Ok(Ok(s)) => s,
            _ => return Err(KeyError::Unavailable),
        };

        let req_bytes = serde_json::to_vec(&req).map_err(|_| KeyError::Unavailable)?;
        let req_len = req_bytes.len() as u32;

        let write_fut = async {
            stream.write_all(&req_len.to_be_bytes()).await?;
            stream.write_all(&req_bytes).await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        };

        if tokio::time::timeout(self.timeout, write_fut).await.is_err() {
            return Err(KeyError::Unavailable);
        }

        let read_fut = async {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > Self::MAX_RESPONSE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Response too large",
                ));
            }
            let mut resp_buf = vec![0u8; len];
            stream.read_exact(&mut resp_buf).await?;
            let resp: KmsResponse = serde_json::from_slice(&resp_buf)?;
            Ok::<KmsResponse, std::io::Error>(resp)
        };

        match tokio::time::timeout(self.timeout, read_fut).await {
            Ok(Ok(resp)) => {
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
            _ => Err(KeyError::Unavailable),
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
        };
        let resp = self.call_kms(req).await?;
        let key_id_str = resp.key_id.ok_or(KeyError::NotFound)?;
        let key_bytes_hex = resp.key_bytes_hex.ok_or(KeyError::NotFound)?;

        let key_id = KeyId::new(key_id_str)?;
        let key_bytes = decode_hex_32(&key_bytes_hex)?;

        let handle = KeyHandle::new(key_id, purpose, tenant.clone(), Zeroizing::new(key_bytes));
        Ok(handle)
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        let req = KmsRequest {
            request_type: "get_key_by_id".to_string(),
            purpose: None,
            tenant: None,
            key_id: Some(key_id.as_str().to_string()),
        };
        let resp = self.call_kms(req).await?;
        let key_bytes_hex = resp.key_bytes_hex.ok_or(KeyError::NotFound)?;
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

        let handle = KeyHandle::new(key_id.clone(), purpose, tenant, Zeroizing::new(key_bytes));
        Ok(handle)
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        let req = KmsRequest {
            request_type: "rotate_key".to_string(),
            purpose: Some(purpose.as_str().to_string()),
            tenant: Some(tenant.as_str().to_string()),
            key_id: None,
        };
        let resp = self.call_kms(req).await?;
        let key_id_str = resp.key_id.ok_or(KeyError::NotFound)?;
        KeyId::new(key_id_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
