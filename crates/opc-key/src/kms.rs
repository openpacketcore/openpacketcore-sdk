use async_trait::async_trait;
use opc_types::TenantId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    errors::KeyError,
    provider::{EncryptedPayload, KeyHandle, KeyProvider, AEAD_TAG_LEN},
    remote::{
        RemoteSealActiveKeyedDigest, RemoteSealCapabilities, RemoteSealMaterialController,
        RemoteSealMaterialEpoch, RemoteSealProvider, REMOTE_SEAL_MAX_KEY_ID_BYTES,
    },
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

/// Legacy KMS key-management response.
///
/// Key-management operations intentionally remain forward-compatible with
/// additive server fields. Remote-seal successes use the separate strict DTO
/// below because their exact wire shape defines the advertised payload bound.
#[derive(Deserialize)]
struct KmsResponse {
    status: String,
    key_id: Option<String>,
    key_bytes_hex: Option<String>,
    purpose: Option<String>,
    tenant: Option<String>,
    error_message: Option<String>,
}

/// Minimal, forward-compatible response used only to classify remote errors
/// before a successful response is parsed through the strict DTO.
#[derive(Deserialize)]
struct KmsRemoteResponseStatus {
    status: String,
    error_message: Option<String>,
}

/// Strict remote-seal success response.
///
/// In particular, decrypted plaintext hexadecimal text remains zeroizing from
/// parsing until it is decoded for the caller. This type is never used by the
/// legacy key-management client.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KmsRemoteSuccessResponse {
    status: String,
    key_id: Option<String>,
    key_bytes_hex: Option<String>,
    purpose: Option<String>,
    tenant: Option<String>,
    error_message: Option<String>,
    ciphertext_and_tag_hex: Option<String>,
    #[serde(default, deserialize_with = "deserialize_zeroizing_string_option")]
    plaintext_hex: Option<Zeroizing<String>>,
    keyed_digest_hex: Option<String>,
}

#[derive(Serialize)]
struct KmsRemoteSuccessResponseRef<'a> {
    status: &'static str,
    key_id: Option<&'a str>,
    key_bytes_hex: Option<&'a str>,
    purpose: Option<&'a str>,
    tenant: Option<&'a str>,
    error_message: Option<&'a str>,
    ciphertext_and_tag_hex: Option<&'a str>,
    plaintext_hex: Option<&'a str>,
    keyed_digest_hex: Option<&'a str>,
}

impl KmsRemoteSuccessResponse {
    fn canonical_remote_success_bytes(
        ciphertext_and_tag_hex: Option<&str>,
        plaintext_hex: Option<&str>,
        keyed_digest_hex: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(
            &mut *bytes,
            &KmsRemoteSuccessResponseRef {
                status: "success",
                key_id: None,
                key_bytes_hex: None,
                purpose: None,
                tenant: None,
                error_message: None,
                ciphertext_and_tag_hex,
                plaintext_hex,
                keyed_digest_hex,
            },
        )
        .map_err(|_| KeyError::Unavailable)?;
        Ok(bytes)
    }
}

fn deserialize_zeroizing_string_option<'de, D>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ZeroizingStringVisitor;

    impl<'de> serde::de::Visitor<'de> for ZeroizingStringVisitor {
        type Value = Zeroizing<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Zeroizing::new(value.to_owned()))
        }
    }

    struct OptionVisitor;

    impl<'de> serde::de::Visitor<'de> for OptionVisitor {
        type Value = Option<Zeroizing<String>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer
                .deserialize_string(ZeroizingStringVisitor)
                .map(Some)
        }
    }

    deserializer.deserialize_option(OptionVisitor)
}

/// JSON escapes make `serde_json` materialize an ordinary scratch buffer.
/// Remote successful values are fixed ASCII protocol tokens or hexadecimal, so
/// no escape is valid. Reject before *any* response deserialization, while the
/// framed response buffer is still zeroizing.
fn reject_remote_json_escapes(response: &[u8]) -> Result<(), KeyError> {
    if response.contains(&b'\\') {
        return Err(KeyError::Unavailable);
    }
    Ok(())
}

/// Accept only the operation-specific remote-seal success shape.
///
/// Legacy remote KMS implementations may omit null optional fields, so their
/// exact JSON spelling is not required. The all-null canonical serialization
/// remains a conservative capacity oracle: a valid response must fit within
/// its length for the actual result, and that oracle itself must fit the framed
/// response limit.
fn validate_remote_success_response(
    request: &KmsRequest,
    response: &KmsRemoteSuccessResponse,
    received: &[u8],
) -> Result<(), KeyError> {
    if response.status != "success" {
        return Err(KeyError::Unavailable);
    }
    let expected = match request.request_type.as_str() {
        "encrypt" => {
            let ciphertext = response
                .ciphertext_and_tag_hex
                .as_deref()
                .ok_or(KeyError::Unavailable)?;
            if response.plaintext_hex.is_some() || response.keyed_digest_hex.is_some() {
                return Err(KeyError::Unavailable);
            }
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(Some(ciphertext), None, None)?
        }
        "decrypt" => {
            let plaintext = response
                .plaintext_hex
                .as_ref()
                .map(|plaintext| plaintext.as_str())
                .ok_or(KeyError::Unavailable)?;
            if response.ciphertext_and_tag_hex.is_some() || response.keyed_digest_hex.is_some() {
                return Err(KeyError::Unavailable);
            }
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(None, Some(plaintext), None)?
        }
        "derive_keyed_digest" => {
            let digest = response
                .keyed_digest_hex
                .as_deref()
                .ok_or(KeyError::Unavailable)?;
            if response.ciphertext_and_tag_hex.is_some() || response.plaintext_hex.is_some() {
                return Err(KeyError::Unavailable);
            }
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(None, None, Some(digest))?
        }
        _ => return Err(KeyError::Unavailable),
    };

    if response.key_id.is_some()
        || response.key_bytes_hex.is_some()
        || response.purpose.is_some()
        || response.tenant.is_some()
        || response.error_message.is_some()
        || expected.len() > KmsKeyProvider::MAX_RESPONSE_BYTES
        || received.len() > expected.len()
    {
        return Err(KeyError::Unavailable);
    }
    Ok(())
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

fn decode_hex_vec_zeroizing(hex: &str) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let chunks = hex.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() || !hex.is_ascii() {
        return Err(KeyError::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
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
        let req_len = u32::try_from(req_bytes.len()).map_err(|_| KeyError::Unavailable)?;

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

    /// Canonical response overhead for a particular remote operation.
    ///
    /// This is derived from the actual serde serialization we require on the
    /// wire. It is deliberately not a hand-maintained JSON-size constant.
    fn success_hex_response_overhead_bytes(encrypt: bool) -> usize {
        let bytes = if encrypt {
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(Some(""), None, None)
        } else {
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(None, Some(""), None)
        };
        match bytes {
            Ok(bytes) => bytes.len(),
            // Fixed-shape serialization is expected to be infallible, but a
            // capacity advertisement must remain fail-closed if that ever
            // changes.
            Err(_) => KmsKeyProvider::MAX_RESPONSE_BYTES,
        }
    }

    fn max_success_hex_bytes(encrypt: bool) -> usize {
        KmsKeyProvider::MAX_RESPONSE_BYTES
            .saturating_sub(Self::success_hex_response_overhead_bytes(encrypt))
    }

    fn max_unseal_output_bytes() -> usize {
        Self::max_success_hex_bytes(false) / 2
    }

    fn max_seal_plaintext_bytes() -> usize {
        (Self::max_success_hex_bytes(true) / 2).saturating_sub(AEAD_TAG_LEN)
    }

    /// Create a remote-seal KMS client with an initial active remote key ID.
    ///
    /// The external service is expected to perform AEAD/KMS Encrypt, Decrypt,
    /// and the domain-separated `derive_keyed_digest` operation server-side.
    /// The SDK sends the same serialized bound AAD bytes used by the local
    /// envelope path and never asks the KMS to hand key material back to the
    /// application.
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

    async fn call_kms(&self, req: KmsRequest) -> Result<KmsRemoteSuccessResponse, KeyError> {
        match tokio::time::timeout(self.timeout, self.call_kms_inner(req)).await {
            Ok(result) => result,
            Err(_) => Err(KeyError::Unavailable),
        }
    }

    async fn call_kms_inner(&self, req: KmsRequest) -> Result<KmsRemoteSuccessResponse, KeyError> {
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
        let req_len = u32::try_from(req_bytes.len()).map_err(|_| KeyError::Unavailable)?;

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
        reject_remote_json_escapes(&resp_buf)?;
        let status: KmsRemoteResponseStatus =
            serde_json::from_slice(&resp_buf).map_err(|_| KeyError::Unavailable)?;

        if status.status == "success" {
            let resp: KmsRemoteSuccessResponse =
                serde_json::from_slice(&resp_buf).map_err(|_| KeyError::Unavailable)?;
            validate_remote_success_response(&req, &resp, &resp_buf)?;
            Ok(resp)
        } else {
            let msg = status
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
    fn capabilities(&self) -> RemoteSealCapabilities {
        RemoteSealCapabilities {
            // Encrypt responses contain hexadecimal ciphertext plus the known
            // 16-byte AEAD tag, so this is the limiting half of a round trip.
            max_seal_plaintext_bytes: Self::max_seal_plaintext_bytes(),
            max_unseal_output_bytes: Self::max_unseal_output_bytes(),
            max_round_trip_plaintext_bytes: Self::max_seal_plaintext_bytes(),
            max_ciphertext_expansion_bytes: AEAD_TAG_LEN,
            max_key_id_bytes: REMOTE_SEAL_MAX_KEY_ID_BYTES,
        }
    }

    async fn active_keyed_digest(
        &self,
        domain: &[u8],
        input: &[u8],
    ) -> Result<RemoteSealActiveKeyedDigest, KeyError> {
        let (_epoch, key_id) = self.material.active_selection()?;
        let digest = self.keyed_digest(&key_id, domain, input).await?;
        Ok(RemoteSealActiveKeyedDigest { key_id, digest })
    }

    async fn keyed_digest(
        &self,
        key_id: &KeyId,
        domain: &[u8],
        input: &[u8],
    ) -> Result<[u8; 32], KeyError> {
        let req = KmsRequest {
            request_type: "derive_keyed_digest".to_string(),
            purpose: None,
            tenant: None,
            key_id: Some(key_id.as_str().to_string()),
            // The KMS protocol binds a caller-defined domain and input as
            // separate framed fields rather than concatenating ambiguously.
            aad_hex: Some(encode_hex(domain)),
            plaintext_hex: Some(encode_hex(input)),
            ciphertext_and_tag_hex: None,
        };
        let resp = self.call_kms(req).await?;
        let digest_hex = resp.keyed_digest_hex.ok_or(KeyError::Unavailable)?;
        let digest = decode_hex_vec(&digest_hex)?;
        digest.try_into().map_err(|_| KeyError::Unavailable)
    }

    async fn seal_with_key_id(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        let capabilities = self.capabilities();
        capabilities.validate_seal_plaintext(plaintext.len())?;
        let bound_aad = serialize_bound_aad(aad, key_id)?;
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
        let ciphertext_hex = resp.ciphertext_and_tag_hex.ok_or(KeyError::Unavailable)?;
        let ciphertext_and_tag = decode_hex_vec(&ciphertext_hex)?;
        capabilities.validate_seal_output(plaintext.len(), ciphertext_and_tag.len())?;
        Ok(EncryptedPayload {
            aad: bound_aad,
            ciphertext_and_tag,
        })
    }

    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        let (_epoch, key_id) = self.material.active_selection()?;
        self.seal_with_key_id(&key_id, aad, plaintext).await
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let capabilities = self.capabilities();
        capabilities.validate_unseal_input(ciphertext_and_tag.len())?;
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
        let plaintext_hex = resp.plaintext_hex.ok_or(KeyError::Unavailable)?;
        let plaintext = decode_hex_vec_zeroizing(&plaintext_hex)?;
        capabilities.validate_unseal_output(ciphertext_and_tag.len(), plaintext.len())?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::AES_256_GCM_SIV_KEY_LEN;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);

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

    fn remote_success_response(ciphertext: Option<Vec<u8>>, plaintext: Option<Vec<u8>>) -> Vec<u8> {
        let ciphertext_hex = ciphertext.as_deref().map(encode_hex);
        let plaintext_hex = plaintext.as_deref().map(encode_hex);
        KmsRemoteSuccessResponse::canonical_remote_success_bytes(
            ciphertext_hex.as_deref(),
            plaintext_hex.as_deref(),
            None,
        )
        .expect("canonical remote success response")
        .to_vec()
    }

    fn response_with_unknown_field(response: Vec<u8>) -> Vec<u8> {
        let mut response = String::from_utf8(response).expect("JSON response");
        response.pop().expect("trailing JSON object delimiter");
        response.push_str(",\"future_kms_extension\":true}");
        response.into_bytes()
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
    async fn kms_provider_legacy_operations_tolerate_unknown_response_fields() {
        let active = mock_kms(MockResponse::Bytes(response_with_unknown_field(
            success_response("session-active-2026-01", key_hex(0x42), None, None),
        )))
        .await;
        KmsKeyProvider::new(active.endpoint.clone(), None, Duration::from_secs(1))
            .get_active_key(KeyPurpose::Session, &tenant())
            .await
            .expect("legacy active-key fetch must tolerate additive fields");

        let key_id = KeyId::new("session-active-2026-01").expect("key id");
        let lookup = mock_kms(MockResponse::Bytes(response_with_unknown_field(
            success_response(
                key_id.as_str(),
                key_hex(0x24),
                Some("session"),
                Some("tenant-a"),
            ),
        )))
        .await;
        KmsKeyProvider::new(lookup.endpoint.clone(), None, Duration::from_secs(1))
            .get_key_by_id(&key_id)
            .await
            .expect("legacy key lookup must tolerate additive fields");

        let rotate = mock_kms(MockResponse::Bytes(response_with_unknown_field(
            success_response("session-rotated-2026-02", key_hex(0x11), None, None),
        )))
        .await;
        KmsKeyProvider::new(rotate.endpoint.clone(), None, Duration::from_secs(1))
            .rotate_key(KeyPurpose::Session, &tenant())
            .await
            .expect("legacy rotation must tolerate additive fields");
    }

    #[test]
    fn remote_decrypt_response_and_canonical_comparison_buffer_are_zeroizing() {
        let wire =
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(None, Some("00112233"), None)
                .expect("canonical response");
        let response: KmsRemoteSuccessResponse =
            serde_json::from_slice(&wire).expect("strict remote response");
        let plaintext_hex: Zeroizing<String> = response.plaintext_hex.expect("plaintext hex");
        let comparison: Zeroizing<Vec<u8>> =
            KmsRemoteSuccessResponse::canonical_remote_success_bytes(
                None,
                Some(plaintext_hex.as_str()),
                None,
            )
            .expect("canonical comparison buffer");

        assert_eq!(comparison.as_slice(), wire.as_slice());
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
        let ciphertext = [0xA5; b"plain-session".len() + AEAD_TAG_LEN];
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(
            serde_json::json!({
                "status": "success",
                "ciphertext_and_tag_hex": encode_hex(&ciphertext),
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
        let ciphertext = [0xA5; b"plain-session".len() + AEAD_TAG_LEN];
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
            .unseal(&key_id, &aad, &ciphertext)
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
            Some(encode_hex(&ciphertext).as_str())
        );
        assert!(request.plaintext_hex.is_none());
    }

    #[tokio::test]
    async fn kms_remote_success_rejects_unknown_response_fields() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let response = response_with_unknown_field(
            serde_json::json!({
                "status": "success",
                "plaintext_hex": encode_hex(b"plain-session"),
            })
            .to_string()
            .into_bytes(),
        );
        let mock = mock_kms(MockResponse::Bytes(response)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );

        assert_eq!(
            provider
                .unseal(
                    &key_id,
                    &session_aad(),
                    &[0xA5; b"plain-session".len() + AEAD_TAG_LEN],
                )
                .await,
            Err(KeyError::Unavailable)
        );
    }

    #[tokio::test]
    async fn kms_remote_success_rejects_escaped_plaintext_hex() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        // The escaped `6` still decodes to the otherwise valid hexadecimal
        // plaintext `706c61696e2d73657373696f6e`.
        let response =
            br#"{"status":"success","plaintext_hex":"706c\u00361696e2d73657373696f6e"}"#.to_vec();
        let mock = mock_kms(MockResponse::Bytes(response)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );

        assert_eq!(
            provider
                .unseal(
                    &key_id,
                    &session_aad(),
                    &[0xA5; b"plain-session".len() + AEAD_TAG_LEN],
                )
                .await,
            Err(KeyError::Unavailable)
        );
    }

    #[test]
    fn kms_remote_success_rejects_populated_cross_operation_fields() {
        let cases = [
            (
                "encrypt",
                serde_json::json!({
                    "status": "success",
                    "ciphertext_and_tag_hex": "aabb",
                    "plaintext_hex": "ccdd",
                }),
            ),
            (
                "encrypt",
                serde_json::json!({
                    "status": "success",
                    "ciphertext_and_tag_hex": "aabb",
                    "keyed_digest_hex": "ccdd",
                }),
            ),
            (
                "decrypt",
                serde_json::json!({
                    "status": "success",
                    "plaintext_hex": "aabb",
                    "ciphertext_and_tag_hex": "ccdd",
                }),
            ),
            (
                "decrypt",
                serde_json::json!({
                    "status": "success",
                    "plaintext_hex": "aabb",
                    "keyed_digest_hex": "ccdd",
                }),
            ),
            (
                "derive_keyed_digest",
                serde_json::json!({
                    "status": "success",
                    "keyed_digest_hex": "aabb",
                    "ciphertext_and_tag_hex": "ccdd",
                }),
            ),
            (
                "derive_keyed_digest",
                serde_json::json!({
                    "status": "success",
                    "keyed_digest_hex": "aabb",
                    "plaintext_hex": "ccdd",
                }),
            ),
        ];

        for (request_type, value) in cases {
            let received = value.to_string().into_bytes();
            let response: KmsRemoteSuccessResponse =
                serde_json::from_slice(&received).expect("strict response DTO");
            let request = KmsRequest {
                request_type: request_type.to_string(),
                purpose: None,
                tenant: None,
                key_id: None,
                aad_hex: None,
                plaintext_hex: None,
                ciphertext_and_tag_hex: None,
            };

            assert_eq!(
                validate_remote_success_response(&request, &response, &received),
                Err(KeyError::Unavailable),
                "{request_type} must reject cross-operation output fields"
            );
        }
    }

    #[tokio::test]
    async fn kms_remote_seal_rejects_canonical_undersized_ciphertext_for_nonempty_plaintext() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(remote_success_response(
            Some(vec![0xA5; AEAD_TAG_LEN]),
            None,
        )))
        .await;
        let provider =
            KmsRemoteSealProvider::new(mock.endpoint.clone(), None, Duration::from_secs(1), key_id);

        assert_eq!(
            provider.seal(&session_aad(), b"nonempty").await,
            Err(KeyError::Unavailable)
        );
        assert_eq!(
            request_rx.await.expect("request captured").request_type,
            "encrypt"
        );
    }

    #[tokio::test]
    async fn kms_remote_seal_provider_derives_exact_keyed_digest() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let expected = [0xD3; 32];
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(
            serde_json::json!({
                "status": "success",
                "keyed_digest_hex": encode_hex(&expected),
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

        assert_eq!(
            provider
                .keyed_digest(&key_id, b"session-aad-domain", b"canonical-key-input")
                .await,
            Ok(expected)
        );
        let request = request_rx.await.expect("request captured");
        assert_eq!(request.request_type, "derive_keyed_digest");
        assert_eq!(request.key_id.as_deref(), Some(key_id.as_str()));
        assert_eq!(
            request.aad_hex.as_deref(),
            Some(encode_hex(b"session-aad-domain").as_str())
        );
        assert_eq!(
            request.plaintext_hex.as_deref(),
            Some(encode_hex(b"canonical-key-input").as_str())
        );
    }

    #[tokio::test]
    async fn kms_remote_seal_capability_is_exact_and_rejects_one_byte_before_io() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let max = KmsRemoteSealProvider::max_seal_plaintext_bytes();
        let response = remote_success_response(Some(vec![0xA5; max + AEAD_TAG_LEN]), None);
        assert_eq!(response.len(), KmsKeyProvider::MAX_RESPONSE_BYTES);
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(response)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );
        let caps = provider.capabilities();
        // The digest-response protocol field is present (as canonical null)
        // in every remote success response, so the exact derived public
        // capacity is lower than the previous two-operation response schema.
        assert_eq!(32_663, caps.max_round_trip_plaintext_bytes);
        assert_eq!(max, caps.max_seal_plaintext_bytes);

        provider
            .seal(&session_aad(), &vec![0x11; max])
            .await
            .expect("exact KMS limit must seal");
        assert_eq!(
            request_rx.await.expect("exact-limit request").request_type,
            "encrypt"
        );

        let no_io_provider = KmsRemoteSealProvider::new(
            "/definitely-not-a-kms-socket".to_string(),
            None,
            Duration::from_secs(1),
            key_id,
        );
        assert_eq!(
            no_io_provider
                .seal(&session_aad(), &vec![0x11; max + 1])
                .await,
            Err(KeyError::Unavailable)
        );

        let oversized = vec![b' '; KmsKeyProvider::MAX_RESPONSE_BYTES + 1];
        let (mock, _request_rx) = mock_kms_recording(MockResponse::Bytes(oversized)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            KeyId::new("session-remote-2026-01").expect("key id"),
        );
        assert_eq!(
            provider.seal(&session_aad(), &vec![0x11; max]).await,
            Err(KeyError::Unavailable)
        );
    }

    #[tokio::test]
    async fn kms_remote_unseal_capacity_accepts_exact_limit_and_rejects_one_byte_more() {
        let key_id = KeyId::new("session-remote-2026-01").expect("key id");
        let max = KmsRemoteSealProvider::max_unseal_output_bytes();
        let response = remote_success_response(None, Some(vec![0x5A; max]));
        assert_eq!(response.len(), KmsKeyProvider::MAX_RESPONSE_BYTES);
        let (mock, request_rx) = mock_kms_recording(MockResponse::Bytes(response)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );

        let plaintext = provider
            .unseal(&key_id, &session_aad(), &vec![0xA5; max + AEAD_TAG_LEN])
            .await
            .expect("exact KMS limit must unseal");
        assert_eq!(plaintext.len(), max);
        assert_eq!(
            request_rx.await.expect("exact-limit request").request_type,
            "decrypt"
        );

        let oversized = vec![b' '; KmsKeyProvider::MAX_RESPONSE_BYTES + 1];
        let (mock, _request_rx) = mock_kms_recording(MockResponse::Bytes(oversized)).await;
        let provider = KmsRemoteSealProvider::new(
            mock.endpoint.clone(),
            None,
            Duration::from_secs(1),
            key_id.clone(),
        );
        assert_eq!(
            provider
                .unseal(&key_id, &session_aad(), &vec![0xA5; max + AEAD_TAG_LEN])
                .await,
            Err(KeyError::Unavailable)
        );

        let no_io_provider = KmsRemoteSealProvider::new(
            "/definitely-not-a-kms-socket".to_string(),
            None,
            Duration::from_secs(1),
            key_id,
        );
        assert_eq!(
            no_io_provider
                .unseal(
                    &KeyId::new("session-remote-2026-01").expect("key id"),
                    &session_aad(),
                    &vec![0xA5; max + AEAD_TAG_LEN + 1],
                )
                .await,
            Err(KeyError::Unavailable)
        );
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
        assert_eq!(error, KeyError::Unavailable);
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(key_id.as_str()));
        assert!(!rendered.contains("tenant-a"));
        assert!(!rendered.contains(&mock.endpoint));
    }

    #[tokio::test]
    async fn kms_remote_seal_in_flight_request_keeps_its_material_epoch() {
        let old_key_id = KeyId::new("session-remote-2026-01").expect("old key id");
        let new_key_id = KeyId::new("session-remote-2026-02").expect("new key id");
        let response = remote_success_response(Some(vec![0xA5; 25]), None);
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

        provider.seal(&aad, b"published").await.expect("seal");
        let second_request = requests.recv().await.expect("second KMS request");
        assert_eq!(second_request.key_id.as_deref(), Some(new_key_id.as_str()));
        assert_eq!(provider.material_epoch().expect("material epoch").get(), 2);

        let rendered = format!("{provider:?}");
        assert!(!rendered.contains(old_key_id.as_str()));
        assert!(!rendered.contains(new_key_id.as_str()));
        assert!(!rendered.contains(&mock.endpoint));
    }
}
