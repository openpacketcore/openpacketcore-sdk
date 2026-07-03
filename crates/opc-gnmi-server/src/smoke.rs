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
use crate::proto_adapter::{encoding_to_proto, path_from_proto};
use crate::Encoding;

const MAX_SMOKE_GETS: usize = 16;
const MAX_SMOKE_SETS: usize = 8;
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

/// One bounded gNMI Set operation for the mutating smoke helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeSetOp {
    /// SDK-canonical path string.
    pub path: String,
    /// Set operation kind.
    pub op: GnmiSmokeSetOpKind,
    /// JSON value for non-delete operations. Must be absent for delete.
    pub json_value: Option<String>,
    /// JSON encoding to place in the generated `TypedValue`.
    pub encoding: GnmiSmokeEncoding,
    /// Expected Set RPC outcome.
    pub expectation: GnmiSmokeSetExpectation,
}

/// gNMI Set operation kinds exposed by the smoke helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GnmiSmokeSetOpKind {
    /// `update`.
    Update,
    /// `replace`.
    Replace,
    /// `union_replace`.
    UnionReplace,
    /// `delete`.
    Delete,
}

impl GnmiSmokeSetOpKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Replace => "replace",
            Self::UnionReplace => "union_replace",
            Self::Delete => "delete",
        }
    }
}

/// Expected Set RPC result for a mutating smoke step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GnmiSmokeSetExpectation {
    /// The Set is expected to be accepted.
    Accept,
    /// The Set is expected to be rejected.
    Reject,
}

impl GnmiSmokeSetExpectation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
        }
    }
}

/// A Set operation plus optional follow-up readbacks over the same channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeMutationStep {
    /// Set operation to send.
    pub set: GnmiSmokeSetOp,
    /// Follow-up readbacks to run after the expected Set outcome is observed.
    #[serde(default)]
    pub readbacks: Vec<GnmiSmokeReadback>,
}

/// One follow-up Get readback with an optional leaf expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeReadback {
    /// Get probe to run.
    pub get: GnmiSmokeGetRequest,
    /// Optional exact leaf expectation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_leaf: Option<GnmiSmokeLeafExpectation>,
}

/// Expected JSON value for one public leaf returned by a readback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeLeafExpectation {
    /// Canonical leaf path to compare.
    pub leaf_path: String,
    /// Expected compact JSON value.
    pub expected_json: String,
}

/// Redaction-safe mutating smoke transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeMutationTranscript {
    /// Target address.
    pub addr: SocketAddr,
    /// TLS server name used by the client.
    pub server_name: String,
    /// Per-step outcomes, in caller-supplied order.
    pub steps: Vec<GnmiSmokeStepOutcome>,
}

/// Per-step mutating smoke outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeStepOutcome {
    /// Set outcome.
    pub set: GnmiSmokeSetOutcome,
    /// Follow-up readback outcomes.
    pub readbacks: Vec<GnmiSmokeReadbackOutcome>,
}

/// Redaction-safe Set outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeSetOutcome {
    /// Caller-supplied path string, bounded for evidence.
    pub path: String,
    /// Set operation label.
    pub op: String,
    /// Expected outcome label.
    pub expectation: String,
    /// Redaction-safe Set status.
    pub status: GnmiSmokeSetStatus,
}

/// Redaction-safe gNMI `Set` status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GnmiSmokeSetStatus {
    /// The Set RPC succeeded.
    Accepted {
        /// Number of per-operation response rows.
        response_count: usize,
        /// Stable `UpdateResult.Operation` labels.
        ops: Vec<String>,
    },
    /// The Set RPC returned a gRPC status. Message text is intentionally omitted.
    Rejected {
        /// Stable gRPC status code label.
        grpc_code: String,
    },
}

/// Redaction-safe readback outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeReadbackOutcome {
    /// Caller-supplied Get path string.
    pub path: String,
    /// Data type requested.
    pub data_type: String,
    /// Encoding requested.
    pub encoding: String,
    /// Redaction-safe Get status.
    pub status: GnmiSmokeGetStatus,
    /// Optional leaf comparison outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<GnmiSmokeLeafReadback>,
}

/// Leaf value extracted for an explicit readback expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnmiSmokeLeafReadback {
    /// Canonical leaf path that was compared.
    pub leaf_path: String,
    /// Bounded compact JSON value observed, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_json: Option<String>,
    /// Whether the observed JSON matched the expectation.
    pub matches_expected: bool,
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
    /// Caller supplied an invalid Set JSON value.
    InvalidSetValue,
    /// A Set expected to be rejected was accepted.
    UnexpectedSetAccepted,
    /// A Set expected to be accepted was rejected.
    UnexpectedSetRejected,
    /// A readback value did not match its expectation.
    ReadbackMismatch,
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
            Self::InvalidSetValue => "invalid_set_value",
            Self::UnexpectedSetAccepted => "unexpected_set_accepted",
            Self::UnexpectedSetRejected => "unexpected_set_rejected",
            Self::ReadbackMismatch => "readback_mismatch",
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
    /// Caller supplied an invalid Set JSON value.
    #[error("gNMI smoke Set value is invalid")]
    InvalidSetValue,
    /// A Set expected to be rejected was accepted.
    #[error("gNMI smoke Set was unexpectedly accepted")]
    UnexpectedSetAccepted,
    /// A Set expected to be accepted was rejected.
    #[error("gNMI smoke Set was unexpectedly rejected")]
    UnexpectedSetRejected,
    /// A readback value did not match its expectation.
    #[error("gNMI smoke readback mismatch")]
    ReadbackMismatch,
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
            Self::InvalidSetValue => GnmiSmokeErrorCode::InvalidSetValue,
            Self::UnexpectedSetAccepted => GnmiSmokeErrorCode::UnexpectedSetAccepted,
            Self::UnexpectedSetRejected => GnmiSmokeErrorCode::UnexpectedSetRejected,
            Self::ReadbackMismatch => GnmiSmokeErrorCode::ReadbackMismatch,
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

/// Runs live gNMI Set operations and optional readbacks over mTLS.
pub async fn run_gnmi_mutating_smoke(
    config: GnmiSmokeClientConfig,
    steps: impl IntoIterator<Item = GnmiSmokeMutationStep>,
) -> Result<GnmiSmokeMutationTranscript, GnmiSmokeError> {
    validate_config(&config)?;
    let steps = collect_mutation_steps(steps)?;
    probe_tls_connection(&config).await?;
    let timeout = config.timeout;
    let mut grpc = connect_channel(&config).await?;
    let _capabilities = request_capabilities(&mut grpc, timeout).await?;

    let mut outcomes = Vec::with_capacity(steps.len());
    for step in steps {
        let set = request_set(&mut grpc, step.set, timeout).await?;
        let mut readbacks = Vec::with_capacity(step.readbacks.len());
        for readback in step.readbacks {
            readbacks.push(request_readback(&mut grpc, readback, timeout).await?);
        }
        outcomes.push(GnmiSmokeStepOutcome { set, readbacks });
    }

    Ok(GnmiSmokeMutationTranscript {
        addr: config.addr,
        server_name: bounded_string(&config.server_name),
        steps: outcomes,
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

fn collect_mutation_steps(
    steps: impl IntoIterator<Item = GnmiSmokeMutationStep>,
) -> Result<Vec<GnmiSmokeMutationStep>, GnmiSmokeError> {
    let steps = steps.into_iter().collect::<Vec<_>>();
    if steps.len() > MAX_SMOKE_SETS {
        return Err(GnmiSmokeError::RequestLimitExceeded);
    }
    let readback_count = steps.iter().map(|step| step.readbacks.len()).sum::<usize>();
    if readback_count > MAX_SMOKE_GETS {
        return Err(GnmiSmokeError::RequestLimitExceeded);
    }
    for step in &steps {
        validate_set_op(&step.set)?;
        for readback in &step.readbacks {
            validate_readback(readback)?;
        }
    }
    Ok(steps)
}

fn validate_set_op(op: &GnmiSmokeSetOp) -> Result<(), GnmiSmokeError> {
    let _path = gnmi_path_from_string(&op.path)?;
    match (op.op, op.json_value.as_deref()) {
        (GnmiSmokeSetOpKind::Delete, None) => Ok(()),
        (GnmiSmokeSetOpKind::Delete, Some(_)) => Err(GnmiSmokeError::InvalidSetValue),
        (_, Some(value)) => {
            let _parsed: serde_json::Value =
                serde_json::from_str(value).map_err(|_| GnmiSmokeError::InvalidSetValue)?;
            Ok(())
        }
        (_, None) => Err(GnmiSmokeError::InvalidSetValue),
    }
}

fn validate_readback(readback: &GnmiSmokeReadback) -> Result<(), GnmiSmokeError> {
    let _path = gnmi_path_from_string(&readback.get.path)?;
    if let Some(expectation) = &readback.expect_leaf {
        let _path = gnmi_path_from_string(&expectation.leaf_path)?;
        let parsed: serde_json::Value = serde_json::from_str(&expectation.expected_json)
            .map_err(|_| GnmiSmokeError::InvalidConfig)?;
        let _compact = serde_json::to_string(&parsed).map_err(|_| GnmiSmokeError::InvalidConfig)?;
    }
    Ok(())
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
    let (outcome, _response) = request_get_with_response(grpc, request, timeout).await?;
    Ok(outcome)
}

async fn request_get_with_response(
    grpc: &mut Grpc<Channel>,
    request: GnmiSmokeGetRequest,
    timeout: Duration,
) -> Result<(GnmiSmokeGetOutcome, Option<gnmi::GetResponse>), GnmiSmokeError> {
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

    let mut successful_response = None;
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
            successful_response = Some(response);
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

    Ok((
        GnmiSmokeGetOutcome {
            path: bounded_string(&request.path),
            data_type: data_type.as_str().to_string(),
            encoding: encoding.as_str().to_string(),
            status,
        },
        successful_response,
    ))
}

async fn request_set(
    grpc: &mut Grpc<Channel>,
    op: GnmiSmokeSetOp,
    timeout: Duration,
) -> Result<GnmiSmokeSetOutcome, GnmiSmokeError> {
    let request = set_request_from_op(&op)?;
    let expectation = op.expectation;
    let response = tokio::time::timeout(timeout, async {
        grpc.ready()
            .await
            .map_err(|_| GnmiSmokeError::ChannelConnectFailed)?;
        Ok::<_, GnmiSmokeError>(
            grpc.unary(
                Request::new(request),
                PathAndQuery::from_static("/gnmi.gNMI/Set"),
                ProstCodec::<gnmi::SetRequest, gnmi::SetResponse>::default(),
            )
            .await,
        )
    })
    .await
    .map_err(|_| GnmiSmokeError::Timeout)??;

    let status = match response {
        Ok(response) => {
            let response = response.into_inner();
            let ops = response
                .response
                .iter()
                .map(|result| {
                    gnmi::update_result::Operation::try_from(result.op)
                        .map(|op| op.as_str_name().to_string())
                        .unwrap_or_else(|_| "UNKNOWN".to_string())
                })
                .collect::<Vec<_>>();
            GnmiSmokeSetStatus::Accepted {
                response_count: response.response.len(),
                ops,
            }
        }
        Err(status) => GnmiSmokeSetStatus::Rejected {
            grpc_code: status.code().to_string(),
        },
    };

    match (expectation, &status) {
        (GnmiSmokeSetExpectation::Accept, GnmiSmokeSetStatus::Accepted { .. })
        | (GnmiSmokeSetExpectation::Reject, GnmiSmokeSetStatus::Rejected { .. }) => {}
        (GnmiSmokeSetExpectation::Accept, GnmiSmokeSetStatus::Rejected { .. }) => {
            return Err(GnmiSmokeError::UnexpectedSetRejected);
        }
        (GnmiSmokeSetExpectation::Reject, GnmiSmokeSetStatus::Accepted { .. }) => {
            return Err(GnmiSmokeError::UnexpectedSetAccepted);
        }
    }

    Ok(GnmiSmokeSetOutcome {
        path: bounded_string(&op.path),
        op: op.op.as_str().to_string(),
        expectation: expectation.as_str().to_string(),
        status,
    })
}

fn set_request_from_op(op: &GnmiSmokeSetOp) -> Result<gnmi::SetRequest, GnmiSmokeError> {
    let path = gnmi_path_from_string(&op.path)?;
    let mut request = gnmi::SetRequest {
        prefix: None,
        delete: Vec::new(),
        replace: Vec::new(),
        update: Vec::new(),
        union_replace: Vec::new(),
        extension: Vec::new(),
    };

    match op.op {
        GnmiSmokeSetOpKind::Delete => request.delete.push(path),
        GnmiSmokeSetOpKind::Update => request.update.push(update_from_op(path, op)?),
        GnmiSmokeSetOpKind::Replace => request.replace.push(update_from_op(path, op)?),
        GnmiSmokeSetOpKind::UnionReplace => request.union_replace.push(update_from_op(path, op)?),
    }

    Ok(request)
}

fn update_from_op(path: gnmi::Path, op: &GnmiSmokeSetOp) -> Result<gnmi::Update, GnmiSmokeError> {
    let value = op
        .json_value
        .as_deref()
        .ok_or(GnmiSmokeError::InvalidSetValue)?;
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| GnmiSmokeError::InvalidSetValue)?;
    let compact = serde_json::to_vec(&parsed).map_err(|_| GnmiSmokeError::InvalidSetValue)?;
    let typed = match op.encoding {
        GnmiSmokeEncoding::JsonIetf => gnmi::typed_value::Value::JsonIetfVal(compact),
        GnmiSmokeEncoding::Json => gnmi::typed_value::Value::JsonVal(compact),
    };
    Ok(gnmi::Update {
        path: Some(path),
        val: Some(gnmi::TypedValue { value: Some(typed) }),
        duplicates: 0,
        ..Default::default()
    })
}

async fn request_readback(
    grpc: &mut Grpc<Channel>,
    readback: GnmiSmokeReadback,
    timeout: Duration,
) -> Result<GnmiSmokeReadbackOutcome, GnmiSmokeError> {
    let expectation = readback.expect_leaf.clone();
    let (outcome, response) = request_get_with_response(grpc, readback.get, timeout).await?;
    let leaf = match expectation {
        Some(expectation) => {
            let expected = compact_json(&expectation.expected_json)?;
            let decoded = response
                .as_ref()
                .and_then(|response| extract_leaf_json(response, &expectation.leaf_path));
            let matches_expected = decoded.as_deref() == Some(expected.as_str());
            let leaf = GnmiSmokeLeafReadback {
                leaf_path: bounded_string(&expectation.leaf_path),
                decoded_json: decoded.as_deref().map(bounded_string),
                matches_expected,
            };
            if !matches_expected {
                return Err(GnmiSmokeError::ReadbackMismatch);
            }
            Some(leaf)
        }
        None => None,
    };

    Ok(GnmiSmokeReadbackOutcome {
        path: outcome.path,
        data_type: outcome.data_type,
        encoding: outcome.encoding,
        status: outcome.status,
        leaf,
    })
}

fn compact_json(value: &str) -> Result<String, GnmiSmokeError> {
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| GnmiSmokeError::InvalidConfig)?;
    serde_json::to_string(&parsed).map_err(|_| GnmiSmokeError::InvalidConfig)
}

fn extract_leaf_json(response: &gnmi::GetResponse, leaf_path: &str) -> Option<String> {
    response.notification.iter().find_map(|notification| {
        notification.update.iter().find_map(|update| {
            let path = update.path.as_ref()?;
            if proto_path_to_string(path).as_deref() != Some(leaf_path) {
                return None;
            }
            typed_json(update.val.as_ref()?)
        })
    })
}

fn typed_json(value: &gnmi::TypedValue) -> Option<String> {
    match value.value.as_ref()? {
        gnmi::typed_value::Value::JsonIetfVal(bytes) | gnmi::typed_value::Value::JsonVal(bytes) => {
            let text = std::str::from_utf8(bytes).ok()?;
            compact_json(text).ok()
        }
        gnmi::typed_value::Value::StringVal(value) => serde_json::to_string(value)
            .ok()
            .map(|json| bounded_string(&json)),
        gnmi::typed_value::Value::BoolVal(value) => Some(value.to_string()),
        gnmi::typed_value::Value::IntVal(value) => Some(value.to_string()),
        gnmi::typed_value::Value::UintVal(value) => Some(value.to_string()),
        gnmi::typed_value::Value::FloatVal(value) => Some(value.to_string()),
        gnmi::typed_value::Value::DoubleVal(value) => Some(value.to_string()),
        _ => None,
    }
}

fn proto_path_to_string(path: &gnmi::Path) -> Option<String> {
    let path = path_from_proto(path).ok()?;
    if path.elems.is_empty() {
        return Some("/".to_string());
    }
    let mut out = String::new();
    for elem in path.elems {
        out.push('/');
        out.push_str(&elem.name);
        for (key, value) in elem.keys {
            out.push('[');
            out.push_str(&key);
            out.push_str("='");
            out.push_str(&value.replace('\\', "\\\\").replace('\'', "\\'"));
            out.push_str("']");
        }
    }
    Some(out)
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
    use opc_mgmt_schema::{
        DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
    };
    use opc_mgmt_transport::TlsBootstrap;
    use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, YangPathPattern};
    use opc_runtime::{RuntimeMode, ShutdownToken};
    use opc_tls::PeerPolicy;
    use opc_types::Timestamp;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use super::*;
    use crate::{
        run_gnmi_tls_listener, CapabilityProfile, ExtensionRegistry, GnmiError,
        GnmiJsonProjectionError, GnmiJsonUpdate, GnmiListenerConfig, GnmiPatchApplicator,
        GnmiServer, GnmiVersion, ReadSelection, GNMI_VERSION,
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
        assert_eq!(
            GnmiSmokeError::InvalidSetValue.code().as_str(),
            "invalid_set_value"
        );
    }

    #[test]
    fn mutation_step_validation_rejects_bad_set_values_and_limits() {
        let bad_json = collect_mutation_steps([GnmiSmokeMutationStep {
            set: GnmiSmokeSetOp {
                path: "/sys:system/sys:hostname".to_string(),
                op: GnmiSmokeSetOpKind::Update,
                json_value: Some("not-json".to_string()),
                encoding: GnmiSmokeEncoding::JsonIetf,
                expectation: GnmiSmokeSetExpectation::Accept,
            },
            readbacks: Vec::new(),
        }])
        .expect_err("invalid set JSON");
        assert_eq!(bad_json.code(), GnmiSmokeErrorCode::InvalidSetValue);

        let too_many =
            collect_mutation_steps((0..=MAX_SMOKE_SETS).map(|_| GnmiSmokeMutationStep {
                set: GnmiSmokeSetOp {
                    path: "/sys:system/sys:hostname".to_string(),
                    op: GnmiSmokeSetOpKind::Delete,
                    json_value: None,
                    encoding: GnmiSmokeEncoding::JsonIetf,
                    expectation: GnmiSmokeSetExpectation::Reject,
                },
                readbacks: Vec::new(),
            }))
            .expect_err("too many sets");
        assert_eq!(too_many.code(), GnmiSmokeErrorCode::RequestLimitExceeded);
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

    static SYSTEM_CHILD_PATHS: &[&str] = &["/sys:system/sys:hostname"];

    static NODES: &[NodeMeta] = &[
        NodeMeta {
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
            child_paths: SYSTEM_CHILD_PATHS,
        },
        NodeMeta {
            path: "/sys:system/sys:hostname",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
    ];

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

    struct AllowPolicy;

    impl PolicySource for AllowPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<opc_nacm::NacmPolicy, AuthzError> {
            Ok(allow_policy())
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

    #[derive(Clone, PartialEq, Eq)]
    struct SmokeConfig {
        hostname: String,
    }

    impl opc_config_model::OpcConfig for SmokeConfig {
        type Delta = ();

        fn schema_digest(&self) -> opc_types::SchemaDigest {
            opc_types::SchemaDigest::from_bytes([9u8; 32])
        }

        fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, opc_config_model::ConfigError> {
            if self == previous {
                Ok(Vec::new())
            } else {
                Ok(vec![()])
            }
        }

        fn changed_paths(
            &self,
            previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, opc_config_model::ConfigError> {
            if self == previous {
                Ok(Vec::new())
            } else {
                Ok(vec![hostname_yang_path()])
            }
        }

        fn apply_delta(
            &mut self,
            _delta: Self::Delta,
        ) -> Result<(), opc_config_model::ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), opc_config_model::ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &opc_config_model::ValidationContext<Self>,
        ) -> Result<(), opc_config_model::ValidationError> {
            Ok(())
        }
    }

    struct UnitPatcher;

    impl GnmiPatchApplicator<SmokeConfig> for UnitPatcher {
        fn apply_set(
            &self,
            running: &SmokeConfig,
            set: &crate::NormalizedSet,
        ) -> Result<SmokeConfig, GnmiError> {
            let mut candidate = running.clone();
            for path in &set.deletes {
                if path == &hostname_yang_path() {
                    candidate.hostname.clear();
                }
            }
            for (path, value) in set
                .replaces
                .iter()
                .chain(set.updates.iter())
                .chain(set.union_replaces.iter())
            {
                if path == &hostname_yang_path() {
                    let hostname: String = serde_json::from_str(value.json())
                        .map_err(|_| GnmiError::invalid("invalid smoke hostname"))?;
                    if hostname == "reject-secret" {
                        return Err(GnmiError::invalid("invalid smoke hostname"));
                    }
                    candidate.hostname = hostname;
                }
            }
            Ok(candidate)
        }
    }

    #[derive(Clone)]
    struct TestBinding {
        bus: Arc<ConfigBus<SmokeConfig>>,
    }

    impl crate::GnmiConfigBinding<SmokeConfig> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<SmokeConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema(&self) -> &'static dyn SchemaRegistry {
            &TestRegistry
        }

        fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<SmokeConfig>> {
            Arc::new(UnitPatcher)
        }

        fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
            Arc::new(EmptyOperationalState)
        }

        fn policy_source(&self) -> Arc<dyn PolicySource> {
            Arc::new(AllowPolicy)
        }

        fn render_running_json(
            &self,
            config: &SmokeConfig,
            selection: ReadSelection<'_>,
        ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
            if selection.contains("/sys:system/sys:hostname") {
                Ok(vec![GnmiJsonUpdate::new(
                    hostname_yang_path(),
                    serde_json::to_string(&config.hostname)
                        .map_err(|_| GnmiJsonProjectionError::projection("hostname JSON"))?,
                )?])
            } else {
                Ok(Vec::new())
            }
        }
    }

    struct MtlsMaterial {
        server_state: IdentityState,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
        trust_roots_pem: Vec<u8>,
    }

    async fn test_server() -> GnmiServer<SmokeConfig, TestBinding> {
        let bus = Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
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

    fn initial_config() -> SmokeConfig {
        SmokeConfig {
            hostname: "initial-host".to_string(),
        }
    }

    fn hostname_yang_path() -> YangPath {
        YangPath::new("/sys:system/sys:hostname").expect("static hostname path")
    }

    fn allow_policy() -> NacmPolicy {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("demo module");
        let mut builder = NacmPolicy::builder(opc_nacm::PolicyVersion::new(1));
        for action in [
            NacmAction::Read,
            NacmAction::Update,
            NacmAction::Replace,
            NacmAction::Delete,
        ] {
            builder = builder
                .add_rule(NacmRule::allow(
                    action,
                    YangPathPattern::parse("/sys:system", &modules).expect("root pattern"),
                ))
                .add_rule(NacmRule::allow(
                    action,
                    YangPathPattern::parse("/sys:system/**", &modules).expect("subtree pattern"),
                ));
        }
        builder.build()
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
    async fn live_mtls_mutating_smoke_runs_set_and_readback() {
        let material = mtls_material();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;

        let transcript = run_gnmi_mutating_smoke(
            smoke_config(addr, &material),
            [GnmiSmokeMutationStep {
                set: GnmiSmokeSetOp {
                    path: "/sys:system/sys:hostname".to_string(),
                    op: GnmiSmokeSetOpKind::Update,
                    json_value: Some(r#""mutated-host""#.to_string()),
                    encoding: GnmiSmokeEncoding::JsonIetf,
                    expectation: GnmiSmokeSetExpectation::Accept,
                },
                readbacks: vec![GnmiSmokeReadback {
                    get: GnmiSmokeGetRequest {
                        path: "/sys:system/sys:hostname".to_string(),
                        data_type: GnmiSmokeDataType::Config,
                        encoding: GnmiSmokeEncoding::JsonIetf,
                    },
                    expect_leaf: Some(GnmiSmokeLeafExpectation {
                        leaf_path: "/sys:system/sys:hostname".to_string(),
                        expected_json: r#""mutated-host""#.to_string(),
                    }),
                }],
            }],
        )
        .await
        .expect("mutating smoke transcript");

        assert!(matches!(
            transcript.steps[0].set.status,
            GnmiSmokeSetStatus::Accepted {
                response_count: 1,
                ..
            }
        ));
        assert_eq!(
            transcript.steps[0].readbacks[0]
                .leaf
                .as_ref()
                .expect("leaf")
                .decoded_json
                .as_deref(),
            Some(r#""mutated-host""#)
        );
        assert!(!format!("{transcript:?}").contains("BEGIN"));

        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join");
    }

    #[tokio::test]
    async fn live_mtls_mutating_smoke_readback_proves_rejected_set_not_published() {
        let material = mtls_material();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;

        let transcript = run_gnmi_mutating_smoke(
            smoke_config(addr, &material),
            [GnmiSmokeMutationStep {
                set: GnmiSmokeSetOp {
                    path: "/sys:system/sys:hostname".to_string(),
                    op: GnmiSmokeSetOpKind::Update,
                    json_value: Some(r#""reject-secret""#.to_string()),
                    encoding: GnmiSmokeEncoding::JsonIetf,
                    expectation: GnmiSmokeSetExpectation::Reject,
                },
                readbacks: vec![GnmiSmokeReadback {
                    get: GnmiSmokeGetRequest {
                        path: "/sys:system/sys:hostname".to_string(),
                        data_type: GnmiSmokeDataType::Config,
                        encoding: GnmiSmokeEncoding::JsonIetf,
                    },
                    expect_leaf: Some(GnmiSmokeLeafExpectation {
                        leaf_path: "/sys:system/sys:hostname".to_string(),
                        expected_json: r#""initial-host""#.to_string(),
                    }),
                }],
            }],
        )
        .await
        .expect("rejected mutating smoke transcript");

        assert!(matches!(
            transcript.steps[0].set.status,
            GnmiSmokeSetStatus::Rejected { .. }
        ));
        let rendered = format!("{transcript:?}");
        assert!(!rendered.contains("reject-secret"));
        assert_eq!(
            transcript.steps[0].readbacks[0]
                .leaf
                .as_ref()
                .expect("leaf")
                .decoded_json
                .as_deref(),
            Some(r#""initial-host""#)
        );

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
