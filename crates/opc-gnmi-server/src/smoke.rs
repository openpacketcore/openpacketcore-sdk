//! Public live gNMI smoke client for SDK/product evidence lanes.
//!
//! The helper intentionally returns summaries rather than raw protobuf payloads
//! so products can serialize evidence without copying certificate material or
//! full northbound data.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use opc_config_model::YangPath;
use opc_identity::{parse_certs_pem, parse_key_pem};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::codegen::http::Uri;
use tonic::codegen::Service;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use crate::get::yang_path_to_proto;
use crate::proto::gnmi;
use crate::proto_adapter::encoding_to_proto;
use crate::Encoding;

const MAX_SMOKE_GETS: usize = 16;
const MAX_MODELS_SUMMARY: usize = 64;
const MAX_ENCODINGS_SUMMARY: usize = 32;
const MAX_SUMMARY_STRING_BYTES: usize = 256;
const TLS_PROTOCOL_VERSIONS: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

/// Connection and mTLS material for one live gNMI smoke run.
pub struct GnmiSmokeClientConfig {
    /// Listener address, usually a port-forwarded `127.0.0.1:<port>`.
    pub addr: SocketAddr,
    /// TLS server name used for certificate verification.
    pub server_name: String,
    /// PEM-encoded client certificate chain.
    pub client_cert_pem: Vec<u8>,
    /// PEM-encoded client private key.
    pub client_key_pem: Vec<u8>,
    /// PEM-encoded trust roots used to verify the server certificate.
    pub trust_roots_pem: Vec<u8>,
    /// Per TCP/TLS/RPC operation timeout.
    pub timeout: Duration,
}

impl fmt::Debug for GnmiSmokeClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnmiSmokeClientConfig")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .field("client_cert_pem", &RedactedPem(self.client_cert_pem.len()))
            .field("client_key_pem", &RedactedPem(self.client_key_pem.len()))
            .field("trust_roots_pem", &RedactedPem(self.trust_roots_pem.len()))
            .field("timeout", &self.timeout)
            .finish()
    }
}

struct RedactedPem(usize);

impl fmt::Debug for RedactedPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted pem, {} bytes>", self.0)
    }
}

/// One minimal gNMI `Get` probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeGetRequest {
    /// SDK-canonical path string. `""` or `"/"` probes the whole root.
    pub path: String,
    /// gNMI data type to request.
    pub data_type: GnmiSmokeDataType,
    /// gNMI encoding to request.
    pub encoding: GnmiSmokeEncoding,
}

/// gNMI `GetRequest.DataType` choices exposed by the smoke helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GnmiSmokeDataType {
    /// All available data.
    All,
    /// Config data only.
    Config,
    /// State data only.
    State,
    /// Operational data only.
    Operational,
}

impl GnmiSmokeDataType {
    const fn to_proto(self) -> i32 {
        match self {
            Self::All => gnmi::get_request::DataType::All as i32,
            Self::Config => gnmi::get_request::DataType::Config as i32,
            Self::State => gnmi::get_request::DataType::State as i32,
            Self::Operational => gnmi::get_request::DataType::Operational as i32,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Config => "config",
            Self::State => "state",
            Self::Operational => "operational",
        }
    }
}

/// gNMI encodings supported by the smoke helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GnmiSmokeEncoding {
    /// OpenConfig `JSON_IETF`.
    JsonIetf,
    /// OpenConfig `JSON`.
    Json,
}

impl GnmiSmokeEncoding {
    const fn to_proto(self) -> i32 {
        match self {
            Self::JsonIetf => encoding_to_proto(Encoding::JsonIetf),
            Self::Json => encoding_to_proto(Encoding::Json),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::JsonIetf => "json_ietf",
            Self::Json => "json",
        }
    }
}

/// Redaction-safe evidence transcript for one smoke run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeTranscript {
    /// Target address.
    pub addr: SocketAddr,
    /// TLS server name used by the client.
    pub server_name: String,
    /// `Capabilities` summary.
    pub capabilities: GnmiSmokeCapabilitySummary,
    /// Per-`Get` outcomes, in caller-supplied order.
    pub gets: Vec<GnmiSmokeGetOutcome>,
}

/// Bounded gNMI capabilities summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeCapabilitySummary {
    /// Advertised gNMI version.
    pub gnmi_version: String,
    /// Bounded supported model rows.
    pub supported_models: Vec<GnmiSmokeModelSummary>,
    /// Total model count observed before truncation.
    pub supported_model_count: usize,
    /// Bounded supported encoding labels.
    pub supported_encodings: Vec<String>,
    /// Total encoding count observed before truncation.
    pub supported_encoding_count: usize,
    /// Whether model or encoding lists were truncated.
    pub truncated: bool,
}

/// Bounded gNMI model row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeModelSummary {
    /// Model name.
    pub name: String,
    /// Model organization, if advertised.
    pub organization: String,
    /// Model version/revision, if advertised.
    pub version: String,
}

/// Per-`Get` smoke outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeGetOutcome {
    /// Caller-supplied path string.
    pub path: String,
    /// Data type requested.
    pub data_type: String,
    /// Encoding requested.
    pub encoding: String,
    /// Redaction-safe RPC status.
    pub status: GnmiSmokeGetStatus,
}

/// Redaction-safe gNMI `Get` status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GnmiSmokeGetStatus {
    /// The RPC succeeded. Counts are bounded summaries of the response shape.
    Success {
        /// Number of notifications in the response.
        notification_count: usize,
        /// Number of updates across all notifications.
        update_count: usize,
        /// Number of deletes across all notifications.
        delete_count: usize,
    },
    /// The RPC returned a gRPC status. Message text is intentionally omitted.
    Failure {
        /// Stable gRPC status code label.
        grpc_code: String,
    },
}

/// Stable machine-readable helper error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GnmiSmokeErrorCode {
    /// Client-side configuration was invalid.
    InvalidConfig,
    /// TLS PEM material or rustls client config was invalid.
    TlsConfig,
    /// TCP connection failed.
    TcpConnectFailed,
    /// TLS handshake failed, including server or client certificate rejection.
    TlsAuthenticationRejected,
    /// A bounded operation timed out.
    Timeout,
    /// The gRPC channel could not be established.
    ChannelConnectFailed,
    /// gNMI `Capabilities` failed.
    CapabilitiesFailed,
    /// gNMI `Capabilities` succeeded but omitted required fields.
    CapabilityMismatch,
    /// Caller supplied too many smoke probes.
    RequestLimitExceeded,
}

impl GnmiSmokeErrorCode {
    /// Stable string label for evidence bundles and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::TlsConfig => "tls_config",
            Self::TcpConnectFailed => "tcp_connect_failed",
            Self::TlsAuthenticationRejected => "tls_authentication_rejected",
            Self::Timeout => "timeout",
            Self::ChannelConnectFailed => "channel_connect_failed",
            Self::CapabilitiesFailed => "capabilities_failed",
            Self::CapabilityMismatch => "capability_mismatch",
            Self::RequestLimitExceeded => "request_limit_exceeded",
        }
    }
}

/// gNMI smoke helper error. Display text is payload-free.
#[derive(Debug, Error)]
pub enum GnmiSmokeError {
    /// Client-side configuration was invalid.
    #[error("gNMI smoke client config is invalid")]
    InvalidConfig,
    /// TLS client config could not be built from caller PEMs.
    #[error("gNMI smoke TLS client config is invalid")]
    TlsConfig,
    /// TCP connection failed.
    #[error("gNMI smoke TCP connection failed")]
    TcpConnectFailed,
    /// TLS handshake failed, including server or client certificate rejection.
    #[error("gNMI smoke TLS authentication failed")]
    TlsAuthenticationRejected,
    /// A bounded operation timed out.
    #[error("gNMI smoke operation timed out")]
    Timeout,
    /// The gRPC channel could not be established.
    #[error("gNMI smoke gRPC channel connection failed")]
    ChannelConnectFailed,
    /// gNMI `Capabilities` failed.
    #[error("gNMI smoke Capabilities RPC failed")]
    CapabilitiesFailed,
    /// gNMI `Capabilities` succeeded but omitted required fields.
    #[error("gNMI smoke Capabilities response is missing required fields")]
    CapabilityMismatch,
    /// Caller supplied too many smoke probes.
    #[error("gNMI smoke request limit exceeded")]
    RequestLimitExceeded,
}

impl GnmiSmokeError {
    /// Stable machine-readable code for this error.
    pub const fn code(&self) -> GnmiSmokeErrorCode {
        match self {
            Self::InvalidConfig => GnmiSmokeErrorCode::InvalidConfig,
            Self::TlsConfig => GnmiSmokeErrorCode::TlsConfig,
            Self::TcpConnectFailed => GnmiSmokeErrorCode::TcpConnectFailed,
            Self::TlsAuthenticationRejected => GnmiSmokeErrorCode::TlsAuthenticationRejected,
            Self::Timeout => GnmiSmokeErrorCode::Timeout,
            Self::ChannelConnectFailed => GnmiSmokeErrorCode::ChannelConnectFailed,
            Self::CapabilitiesFailed => GnmiSmokeErrorCode::CapabilitiesFailed,
            Self::CapabilityMismatch => GnmiSmokeErrorCode::CapabilityMismatch,
            Self::RequestLimitExceeded => GnmiSmokeErrorCode::RequestLimitExceeded,
        }
    }
}

/// Runs a live gNMI-over-mTLS smoke probe against an already-running listener.
pub async fn run_gnmi_smoke(
    config: GnmiSmokeClientConfig,
    gets: impl IntoIterator<Item = GnmiSmokeGetRequest>,
) -> Result<GnmiSmokeTranscript, GnmiSmokeError> {
    validate_config(&config)?;
    let gets = collect_gets(gets)?;
    probe_tls_connection(&config).await?;
    let timeout = config.timeout;
    let mut grpc = connect_channel(&config).await?;
    let capabilities = request_capabilities(&mut grpc, timeout).await?;
    let mut outcomes = Vec::with_capacity(gets.len());
    for get in gets {
        outcomes.push(request_get(&mut grpc, get, timeout).await?);
    }

    Ok(GnmiSmokeTranscript {
        addr: config.addr,
        server_name: bounded_string(&config.server_name),
        capabilities,
        gets: outcomes,
    })
}

fn validate_config(config: &GnmiSmokeClientConfig) -> Result<(), GnmiSmokeError> {
    if config.server_name.is_empty()
        || config.client_cert_pem.is_empty()
        || config.client_key_pem.is_empty()
        || config.trust_roots_pem.is_empty()
        || config.timeout.is_zero()
    {
        return Err(GnmiSmokeError::InvalidConfig);
    }
    Ok(())
}

fn collect_gets(
    gets: impl IntoIterator<Item = GnmiSmokeGetRequest>,
) -> Result<Vec<GnmiSmokeGetRequest>, GnmiSmokeError> {
    let gets = gets.into_iter().collect::<Vec<_>>();
    if gets.len() > MAX_SMOKE_GETS {
        return Err(GnmiSmokeError::RequestLimitExceeded);
    }
    Ok(gets)
}

async fn connect_channel(config: &GnmiSmokeClientConfig) -> Result<Grpc<Channel>, GnmiSmokeError> {
    let tls_config = Arc::new(build_client_config(config)?);
    let endpoint = Endpoint::from_static("http://gnmi.smoke")
        .connect_timeout(config.timeout)
        .timeout(config.timeout);
    let channel = endpoint
        .connect_with_connector(TlsSmokeConnector {
            addr: config.addr,
            server_name: Arc::<str>::from(config.server_name.as_str()),
            config: tls_config,
            timeout: config.timeout,
        })
        .await
        .map_err(classify_channel_error)?;
    Ok(Grpc::new(channel))
}

fn build_client_config(config: &GnmiSmokeClientConfig) -> Result<ClientConfig, GnmiSmokeError> {
    static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });

    let client_cert_pem =
        std::str::from_utf8(&config.client_cert_pem).map_err(|_| GnmiSmokeError::TlsConfig)?;
    let client_key_pem =
        std::str::from_utf8(&config.client_key_pem).map_err(|_| GnmiSmokeError::TlsConfig)?;
    let trust_roots_pem =
        std::str::from_utf8(&config.trust_roots_pem).map_err(|_| GnmiSmokeError::TlsConfig)?;

    let client_certs = parse_certs_pem(client_cert_pem).map_err(|_| GnmiSmokeError::TlsConfig)?;
    if client_certs.is_empty() {
        return Err(GnmiSmokeError::TlsConfig);
    }
    let client_key = parse_key_pem(client_key_pem).map_err(|_| GnmiSmokeError::TlsConfig)?;
    let trust_roots = parse_certs_pem(trust_roots_pem).map_err(|_| GnmiSmokeError::TlsConfig)?;
    if trust_roots.is_empty() {
        return Err(GnmiSmokeError::TlsConfig);
    }
    let mut root_store = RootCertStore::empty();
    for root in trust_roots {
        root_store
            .add(root)
            .map_err(|_| GnmiSmokeError::TlsConfig)?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&TLS_PROTOCOL_VERSIONS)
        .map_err(|_| GnmiSmokeError::TlsConfig)?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|_| GnmiSmokeError::TlsConfig)?;
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(client_config)
}

async fn probe_tls_connection(config: &GnmiSmokeClientConfig) -> Result<(), GnmiSmokeError> {
    let tcp = tokio::time::timeout(config.timeout, TcpStream::connect(config.addr))
        .await
        .map_err(|_| GnmiSmokeError::Timeout)?
        .map_err(|_| GnmiSmokeError::TcpConnectFailed)?;
    let server_name = ServerName::try_from(config.server_name.as_str())
        .map_err(|_| GnmiSmokeError::InvalidConfig)?
        .to_owned();
    let connector = TlsConnector::from(Arc::new(build_client_config(config)?));
    tokio::time::timeout(config.timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| GnmiSmokeError::Timeout)?
        .map_err(|_| GnmiSmokeError::TlsAuthenticationRejected)?;
    Ok(())
}

#[derive(Clone)]
struct TlsSmokeConnector {
    addr: SocketAddr,
    server_name: Arc<str>,
    config: Arc<ClientConfig>,
    timeout: Duration,
}

impl Service<Uri> for TlsSmokeConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = GnmiSmokeConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let addr = self.addr;
        let server_name = Arc::clone(&self.server_name);
        let config = Arc::clone(&self.config);
        let timeout = self.timeout;
        Box::pin(async move {
            let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| GnmiSmokeConnectError::Timeout)?
                .map_err(|_| GnmiSmokeConnectError::TcpConnectFailed)?;
            let server_name = ServerName::try_from(server_name.as_ref())
                .map_err(|_| GnmiSmokeConnectError::InvalidServerName)?
                .to_owned();
            let connector = TlsConnector::from(config);
            let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
                .await
                .map_err(|_| GnmiSmokeConnectError::Timeout)?
                .map_err(|_| GnmiSmokeConnectError::TlsAuthenticationRejected)?;
            Ok(TokioIo::new(tls))
        })
    }
}

#[derive(Debug, Clone, Error)]
enum GnmiSmokeConnectError {
    #[error("gNMI smoke TCP connection failed")]
    TcpConnectFailed,
    #[error("gNMI smoke TLS authentication failed")]
    TlsAuthenticationRejected,
    #[error("gNMI smoke operation timed out")]
    Timeout,
    #[error("gNMI smoke server name is invalid")]
    InvalidServerName,
}

fn classify_channel_error(err: tonic::transport::Error) -> GnmiSmokeError {
    let rendered = format!("{err:?} {err}");
    if rendered.contains("gNMI smoke operation timed out") {
        return GnmiSmokeError::Timeout;
    }
    if rendered.contains("gNMI smoke TLS authentication failed") {
        return GnmiSmokeError::TlsAuthenticationRejected;
    }
    if rendered.contains("gNMI smoke TCP connection failed") {
        return GnmiSmokeError::TcpConnectFailed;
    }
    if rendered.contains("gNMI smoke server name is invalid") {
        return GnmiSmokeError::InvalidConfig;
    }
    let mut current = std::error::Error::source(&err);
    while let Some(source) = current {
        if let Some(connect) = source.downcast_ref::<GnmiSmokeConnectError>() {
            return match connect {
                GnmiSmokeConnectError::TcpConnectFailed => GnmiSmokeError::TcpConnectFailed,
                GnmiSmokeConnectError::TlsAuthenticationRejected => {
                    GnmiSmokeError::TlsAuthenticationRejected
                }
                GnmiSmokeConnectError::Timeout => GnmiSmokeError::Timeout,
                GnmiSmokeConnectError::InvalidServerName => GnmiSmokeError::InvalidConfig,
            };
        }
        current = source.source();
    }
    GnmiSmokeError::ChannelConnectFailed
}

async fn request_capabilities(
    grpc: &mut Grpc<Channel>,
    timeout: Duration,
) -> Result<GnmiSmokeCapabilitySummary, GnmiSmokeError> {
    let response = tokio::time::timeout(timeout, async {
        grpc.ready()
            .await
            .map_err(|_| GnmiSmokeError::CapabilitiesFailed)?;
        grpc.unary(
            Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }),
            PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
            ProstCodec::<gnmi::CapabilityRequest, gnmi::CapabilityResponse>::default(),
        )
        .await
        .map_err(classify_capabilities_status)
    })
    .await
    .map_err(|_| GnmiSmokeError::Timeout)??;

    let response = response.into_inner();
    if response.g_nmi_version.is_empty() || response.supported_encodings.is_empty() {
        return Err(GnmiSmokeError::CapabilityMismatch);
    }
    Ok(summarize_capabilities(response))
}

fn classify_capabilities_status(status: tonic::Status) -> GnmiSmokeError {
    match status.code() {
        tonic::Code::Unavailable | tonic::Code::Unknown => {
            GnmiSmokeError::TlsAuthenticationRejected
        }
        _ => GnmiSmokeError::CapabilitiesFailed,
    }
}

async fn request_get(
    grpc: &mut Grpc<Channel>,
    request: GnmiSmokeGetRequest,
    timeout: Duration,
) -> Result<GnmiSmokeGetOutcome, GnmiSmokeError> {
    let path = gnmi_path_from_string(&request.path)?;
    let data_type = request.data_type;
    let encoding = request.encoding;
    let response = tokio::time::timeout(timeout, async {
        grpc.ready()
            .await
            .map_err(|_| GnmiSmokeError::ChannelConnectFailed)?;
        Ok::<_, GnmiSmokeError>(
            grpc.unary(
                Request::new(gnmi::GetRequest {
                    prefix: None,
                    path: vec![path],
                    r#type: data_type.to_proto(),
                    encoding: encoding.to_proto(),
                    use_models: Vec::new(),
                    extension: Vec::new(),
                }),
                PathAndQuery::from_static("/gnmi.gNMI/Get"),
                ProstCodec::<gnmi::GetRequest, gnmi::GetResponse>::default(),
            )
            .await,
        )
    })
    .await
    .map_err(|_| GnmiSmokeError::Timeout)??;

    let status = match response {
        Ok(response) => {
            let response = response.into_inner();
            let notification_count = response.notification.len();
            let update_count = response
                .notification
                .iter()
                .map(|notification| notification.update.len())
                .sum();
            let delete_count = response
                .notification
                .iter()
                .map(|notification| notification.delete.len())
                .sum();
            GnmiSmokeGetStatus::Success {
                notification_count,
                update_count,
                delete_count,
            }
        }
        Err(status) => GnmiSmokeGetStatus::Failure {
            grpc_code: status.code().to_string(),
        },
    };

    Ok(GnmiSmokeGetOutcome {
        path: bounded_string(&request.path),
        data_type: data_type.as_str().to_string(),
        encoding: encoding.as_str().to_string(),
        status,
    })
}

fn gnmi_path_from_string(path: &str) -> Result<gnmi::Path, GnmiSmokeError> {
    if path.is_empty() || path == "/" {
        return Ok(gnmi::Path::default());
    }
    let yang_path = YangPath::new(path).map_err(|_| GnmiSmokeError::InvalidConfig)?;
    yang_path_to_proto(&yang_path).map_err(|_| GnmiSmokeError::InvalidConfig)
}

fn summarize_capabilities(response: gnmi::CapabilityResponse) -> GnmiSmokeCapabilitySummary {
    let supported_model_count = response.supported_models.len();
    let supported_encoding_count = response.supported_encodings.len();
    let supported_models = response
        .supported_models
        .into_iter()
        .take(MAX_MODELS_SUMMARY)
        .map(|model| GnmiSmokeModelSummary {
            name: bounded_string(&model.name),
            organization: bounded_string(&model.organization),
            version: bounded_string(&model.version),
        })
        .collect::<Vec<_>>();
    let supported_encodings = response
        .supported_encodings
        .into_iter()
        .take(MAX_ENCODINGS_SUMMARY)
        .map(|encoding| {
            gnmi::Encoding::try_from(encoding)
                .map(|encoding| format!("{encoding:?}"))
                .unwrap_or_else(|_| "UNKNOWN".to_string())
        })
        .collect::<Vec<_>>();
    GnmiSmokeCapabilitySummary {
        gnmi_version: bounded_string(&response.g_nmi_version),
        supported_models,
        supported_model_count,
        supported_encodings,
        supported_encoding_count,
        truncated: supported_model_count > MAX_MODELS_SUMMARY
            || supported_encoding_count > MAX_ENCODINGS_SUMMARY,
    }
}

fn bounded_string(value: &str) -> String {
    if value.len() <= MAX_SUMMARY_STRING_BYTES {
        return value.to_string();
    }
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() + ch.len_utf8() > MAX_SUMMARY_STRING_BYTES.saturating_sub(3) {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::HashSet;

    use opc_config_bus::{ConfigBus, MockManagedDatastore};
    use opc_identity::{
        parse_certs_pem, parse_key_pem, IdentityState, SvidDocument, TrustBundle, TrustBundleSet,
        TrustDomain, WorkloadIdentity,
    };
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_opstate::{
        OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
    };
    use opc_mgmt_schema::{DataClass, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry};
    use opc_mgmt_transport::TlsBootstrap;
    use opc_runtime::{RuntimeMode, ShutdownToken};
    use opc_tls::PeerPolicy;
    use opc_types::Timestamp;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use super::*;
    use crate::{
        run_gnmi_tls_listener, CapabilityProfile, ExtensionRegistry, GnmiError, GnmiListenerConfig,
        GnmiPatchApplicator, GnmiServer, GnmiVersion, GNMI_VERSION,
    };

    const CERT_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nsecret-cert\n-----END CERTIFICATE-----\n";
    const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nsecret-key\n-----END PRIVATE KEY-----\n";

    #[test]
    fn config_debug_redacts_pem_material() {
        let config = GnmiSmokeClientConfig {
            addr: "127.0.0.1:9339".parse().expect("addr"),
            server_name: "localhost".to_string(),
            client_cert_pem: CERT_PEM.to_vec(),
            client_key_pem: KEY_PEM.to_vec(),
            trust_roots_pem: CERT_PEM.to_vec(),
            timeout: Duration::from_secs(1),
        };

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("secret-cert"));
        assert!(!rendered.contains("secret-key"));
        assert!(rendered.contains("<redacted pem"));
    }

    #[test]
    fn error_display_is_payload_free() {
        assert!(!GnmiSmokeError::TlsConfig.to_string().contains("secret-key"));
        assert_eq!(GnmiSmokeError::Timeout.code().as_str(), "timeout");
    }

    #[test]
    fn empty_path_maps_to_root_proto_path() {
        let path = gnmi_path_from_string("/").expect("root");
        assert!(path.elem.is_empty());
    }

    #[test]
    fn canonical_path_maps_to_proto_elems() {
        let path = gnmi_path_from_string("/sys:system/sys:hostname").expect("path");
        assert_eq!(path.elem.len(), 2);
        assert_eq!(path.elem[0].name, "sys:system");
        assert_eq!(path.elem[1].name, "sys:hostname");
    }

    struct TestRegistry;

    static MODELS: &[ModelData] = &[ModelData {
        name: "demo-system",
        revision: "2026-06-15",
        namespace: "urn:demo",
        prefix: "sys",
    }];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["demo-system"],
    }];

    static NODES: &[NodeMeta] = &[NodeMeta {
        path: "/sys:system",
        module: "demo-system",
        kind: NodeKind::Container,
        config: true,
        leaf_type: None,
        key_leaves: &[],
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:test"
        }

        fn served_models(&self) -> &'static [ModelData] {
            MODELS
        }

        fn nodes(&self) -> &'static [NodeMeta] {
            NODES
        }

        fn origins(&self) -> &'static [OriginEntry] {
            ORIGINS
        }
    }

    struct EmptyPolicy;

    impl PolicySource for EmptyPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<opc_nacm::NacmPolicy, AuthzError> {
            Ok(opc_nacm::NacmPolicy::empty(opc_nacm::PolicyVersion::new(1)))
        }
    }

    struct EmptyOperationalState;

    impl OperationalStateProvider for EmptyOperationalState {
        fn get(
            &self,
            _request: &OperationalRequest,
        ) -> Result<OperationalResponse, OperationalError> {
            Ok(OperationalResponse::default())
        }
    }

    struct UnitPatcher;

    impl GnmiPatchApplicator<()> for UnitPatcher {
        fn apply_set(&self, _running: &(), _set: &crate::NormalizedSet) -> Result<(), GnmiError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestBinding {
        bus: Arc<ConfigBus<()>>,
    }

    impl crate::GnmiConfigBinding<()> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<()>> {
            Arc::clone(&self.bus)
        }

        fn schema(&self) -> &'static dyn SchemaRegistry {
            &TestRegistry
        }

        fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<()>> {
            Arc::new(UnitPatcher)
        }

        fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
            Arc::new(EmptyOperationalState)
        }

        fn policy_source(&self) -> Arc<dyn PolicySource> {
            Arc::new(EmptyPolicy)
        }
    }

    struct MtlsMaterial {
        server_state: IdentityState,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
        trust_roots_pem: Vec<u8>,
    }

    async fn test_server() -> GnmiServer<(), TestBinding> {
        let bus = Arc::new(
            ConfigBus::new_dev_only((), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        GnmiServer::new_dev_only(
            TestBinding { bus },
            opc_mgmt_limits::MgmtLimits::default(),
            profile,
            ExtensionRegistry::default(),
        )
        .expect("server")
    }

    fn peer_policy() -> PeerPolicy {
        PeerPolicy {
            allowed_trust_domains: Some(HashSet::from([
                TrustDomain::new("test-domain").expect("trust domain")
            ])),
            ..Default::default()
        }
    }

    fn mtls_material() -> MtlsMaterial {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Smoke Test CA");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let server = signed_leaf(
            &ca_cert,
            &ca_key,
            "gNMI Server",
            "spiffe://test-domain/tenant/test/ns/default/sa/gnmi-server/nf/amf/instance/0",
            true,
        );
        let client = signed_leaf(
            &ca_cert,
            &ca_key,
            "gNMI Client",
            "spiffe://test-domain/tenant/test/ns/default/sa/gnmi-client/nf/amf/instance/0",
            false,
        );
        let server_state = identity_state_from_pem(
            &(server.0.pem() + &ca_cert.pem()),
            &server.1.serialize_pem(),
            &ca_cert.pem(),
        );
        MtlsMaterial {
            server_state,
            client_cert_pem: (client.0.pem() + &ca_cert.pem()).into_bytes(),
            client_key_pem: client.1.serialize_pem().into_bytes(),
            trust_roots_pem: ca_cert.pem().into_bytes(),
        }
    }

    fn mtls_material_with_untrusted_client() -> (MtlsMaterial, Vec<u8>, Vec<u8>) {
        let material = mtls_material();
        let mut other_ca_params = CertificateParams::default();
        other_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        other_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Other CA");
        let other_ca_key = KeyPair::generate().expect("other ca key");
        let other_ca = other_ca_params
            .self_signed(&other_ca_key)
            .expect("other ca cert");
        let other_client = signed_leaf(
            &other_ca,
            &other_ca_key,
            "Untrusted Client",
            "spiffe://test-domain/tenant/test/ns/default/sa/gnmi-client/nf/amf/instance/1",
            false,
        );
        (
            material,
            (other_client.0.pem() + &other_ca.pem()).into_bytes(),
            other_client.1.serialize_pem().into_bytes(),
        )
    }

    fn signed_leaf(
        ca_cert: &rcgen::Certificate,
        ca_key: &KeyPair,
        common_name: &str,
        spiffe_id: &str,
        include_localhost_dns: bool,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("spiffe san"),
        ));
        if include_localhost_dns {
            params.subject_alt_names.push(SanType::DnsName(
                rcgen::Ia5String::try_from("localhost").expect("dns san"),
            ));
        }
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now - ::time::Duration::days(1);
        params.not_after = now + ::time::Duration::days(1);
        let key = KeyPair::generate().expect("leaf key");
        let cert = params.signed_by(&key, ca_cert, ca_key).expect("leaf cert");
        (cert, key)
    }

    fn identity_state_from_pem(cert_chain_pem: &str, key_pem: &str, ca_pem: &str) -> IdentityState {
        let ca_certs = parse_certs_pem(ca_pem).expect("ca pem");
        let cert_chain = parse_certs_pem(cert_chain_pem).expect("cert chain pem");
        let trust_domain = TrustDomain::new("test-domain").expect("trust domain");
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: ca_certs,
        });
        let identity = WorkloadIdentity::from_cert_der(cert_chain[0].as_ref(), &trust_bundles)
            .expect("identity");
        let private_key = parse_key_pem(key_pem).expect("key pem");
        let svid = SvidDocument {
            spiffe_id: identity.spiffe_id.clone(),
            cert_chain,
            private_key,
            expires_at: Timestamp::now_utc(),
        };
        IdentityState {
            identity,
            svid,
            trust_bundles,
        }
    }

    fn smoke_config(addr: SocketAddr, material: &MtlsMaterial) -> GnmiSmokeClientConfig {
        GnmiSmokeClientConfig {
            addr,
            server_name: "localhost".to_string(),
            client_cert_pem: material.client_cert_pem.clone(),
            client_key_pem: material.client_key_pem.clone(),
            trust_roots_pem: material.trust_roots_pem.clone(),
            timeout: Duration::from_secs(3),
        }
    }

    async fn spawn_listener(
        material: &MtlsMaterial,
    ) -> (
        SocketAddr,
        ShutdownToken,
        tokio::task::JoinHandle<crate::GnmiListenerResult>,
    ) {
        let (_identity_tx, identity_rx) = watch::channel(Some(material.server_state.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = ShutdownToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_gnmi_tls_listener(
                test_server().await,
                listener,
                TlsBootstrap::new(RuntimeMode::Production, peer_policy()),
                identity_rx,
                task_shutdown,
                GnmiListenerConfig {
                    handshake_timeout: Duration::from_secs(3),
                    incoming_channel_capacity: 4,
                },
            )
            .await
            .expect("listener result")
        });
        (addr, shutdown, task)
    }

    #[tokio::test]
    async fn live_mtls_smoke_runs_capabilities_and_get() {
        let material = mtls_material();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;

        let transcript = run_gnmi_smoke(
            smoke_config(addr, &material),
            [GnmiSmokeGetRequest {
                path: "/".to_string(),
                data_type: GnmiSmokeDataType::All,
                encoding: GnmiSmokeEncoding::JsonIetf,
            }],
        )
        .await
        .expect("smoke transcript");

        assert_eq!(transcript.capabilities.gnmi_version, "0.10.0");
        assert_eq!(
            transcript.capabilities.supported_models[0].name,
            "demo-system"
        );
        assert!(matches!(
            transcript.gets[0].status,
            GnmiSmokeGetStatus::Success { .. }
        ));

        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join");
    }

    #[tokio::test]
    async fn live_mtls_smoke_records_unsupported_get_status() {
        let material = mtls_material();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;

        let transcript = run_gnmi_smoke(
            smoke_config(addr, &material),
            [GnmiSmokeGetRequest {
                path: "/sys:missing".to_string(),
                data_type: GnmiSmokeDataType::All,
                encoding: GnmiSmokeEncoding::JsonIetf,
            }],
        )
        .await
        .expect("smoke transcript");

        assert!(matches!(
            &transcript.gets[0].status,
            GnmiSmokeGetStatus::Failure { grpc_code } if !grpc_code.is_empty()
        ));

        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join");
    }

    #[tokio::test]
    async fn live_mtls_smoke_reports_tls_auth_failure_code() {
        let (material, bad_client_cert, bad_client_key) = mtls_material_with_untrusted_client();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;
        let mut config = smoke_config(addr, &material);
        config.client_cert_pem = bad_client_cert;
        config.client_key_pem = bad_client_key;

        let err = run_gnmi_smoke(config, []).await.expect_err("auth failure");

        assert!(matches!(
            err.code(),
            GnmiSmokeErrorCode::TlsAuthenticationRejected
                | GnmiSmokeErrorCode::ChannelConnectFailed
        ));

        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join");
    }

    #[tokio::test]
    async fn live_mtls_smoke_reports_timeout_code() {
        let material = mtls_material();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            let (_stream, _peer) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        let mut config = smoke_config(addr, &material);
        config.timeout = Duration::from_millis(50);

        let err = run_gnmi_smoke(config, []).await.expect_err("timeout");

        assert_eq!(err.code(), GnmiSmokeErrorCode::Timeout);
        server_task.await.expect("server task");
    }
}
