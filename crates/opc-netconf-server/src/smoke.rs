//! Public live NETCONF-over-TLS smoke client for SDK/product evidence lanes.
//!
//! The helper performs a real mTLS connection, NETCONF `<hello>` exchange, and
//! bounded RPC exchange while returning only redaction-safe summaries.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opc_identity::{parse_certs_pem, parse_key_pem};
use opc_mgmt_limits::{LimitsError, MgmtLimits};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::capabilities::{NETCONF_BASE_1_0, NETCONF_BASE_1_1, NETCONF_BASE_NS};
use crate::error::xml_escape;
use crate::framing::{base10, base11, FramingError};

const MAX_SMOKE_RPCS: usize = 16;
const MAX_CAPABILITIES_SUMMARY: usize = 128;
const MAX_SUMMARY_STRING_BYTES: usize = 256;
const TLS_PROTOCOL_VERSIONS: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

/// Connection and mTLS material for one live NETCONF-over-TLS smoke run.
pub struct NetconfTlsSmokeClientConfig {
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
    /// Per TCP/TLS/frame operation timeout.
    pub timeout: Duration,
    /// Client framing capability to advertise after the base 1.0 hello frame.
    pub framing: NetconfSmokeFramingPreference,
}

impl fmt::Debug for NetconfTlsSmokeClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetconfTlsSmokeClientConfig")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .field("client_cert_pem", &RedactedPem(self.client_cert_pem.len()))
            .field("client_key_pem", &RedactedPem(self.client_key_pem.len()))
            .field("trust_roots_pem", &RedactedPem(self.trust_roots_pem.len()))
            .field("timeout", &self.timeout)
            .field("framing", &self.framing)
            .finish()
    }
}

struct RedactedPem(usize);

impl fmt::Debug for RedactedPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted pem, {} bytes>", self.0)
    }
}

/// NETCONF framing preference advertised by the smoke client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetconfSmokeFramingPreference {
    /// Advertise only base 1.0 end-marker framing.
    Base10,
    /// Advertise base 1.1 and use chunked framing after hello.
    Base11,
}

/// NETCONF framing used for post-hello RPCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetconfSmokeFramingUsed {
    /// RFC 6241 base 1.0 `]]>]]>` end-marker framing.
    Base10,
    /// RFC 6242/base 1.1 chunked framing.
    Base11,
}

/// One caller-supplied NETCONF smoke RPC body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetconfSmokeRpc {
    /// RFC 6241 message id for the generated `<rpc>` envelope.
    pub message_id: String,
    /// Inner RPC operation XML, for example `<get/>` or `<get-config>...</get-config>`.
    pub body: String,
}

/// Redaction-safe evidence transcript for one NETCONF smoke run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetconfSmokeTranscript {
    /// Target address.
    pub addr: SocketAddr,
    /// TLS server name used by the client.
    pub server_name: String,
    /// Server hello summary.
    pub server_hello: NetconfSmokeHelloSummary,
    /// Post-hello framing used for RPCs.
    pub framing: NetconfSmokeFramingUsed,
    /// Per-RPC outcomes, in caller-supplied order.
    pub rpcs: Vec<NetconfSmokeRpcOutcome>,
}

/// Bounded NETCONF server `<hello>` summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetconfSmokeHelloSummary {
    /// Bounded capability URI list.
    pub capabilities: Vec<String>,
    /// Total capability count observed before truncation.
    pub capability_count: usize,
    /// Whether capability list capture was truncated.
    pub truncated: bool,
}

/// Per-RPC NETCONF smoke outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetconfSmokeRpcOutcome {
    /// Caller-supplied message id.
    pub message_id: String,
    /// Best-effort operation element name.
    pub operation: String,
    /// Redaction-safe reply status.
    pub status: NetconfSmokeRpcStatus,
}

/// Minimal successful NETCONF reply summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetconfSmokeRpcSummary {
    /// `ok`, `data`, or `reply`.
    pub reply_kind: String,
}

/// Redaction-safe NETCONF RPC status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetconfSmokeRpcStatus {
    /// The reply did not contain `<rpc-error>`.
    Success {
        /// Bounded reply shape summary.
        summary: NetconfSmokeRpcSummary,
    },
    /// The reply contained `<rpc-error>`.
    RpcError {
        /// RFC 6241 `error-type`, if present.
        error_type: Option<String>,
        /// RFC 6241 `error-tag`, if present.
        error_tag: Option<String>,
    },
    /// The framed reply was not parseable enough to classify.
    MalformedReply,
}

/// Stable machine-readable helper error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetconfSmokeErrorCode {
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
    /// Server hello XML was malformed or missing capabilities.
    ServerHelloInvalid,
    /// Server hello did not advertise the required base capability.
    ServerHelloMissingBaseCapability,
    /// NETCONF frame encoding/decoding failed.
    FramingFailure,
    /// Caller supplied too many or too-large smoke RPCs.
    RequestLimitExceeded,
}

impl NetconfSmokeErrorCode {
    /// Stable string label for evidence bundles and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::TlsConfig => "tls_config",
            Self::TcpConnectFailed => "tcp_connect_failed",
            Self::TlsAuthenticationRejected => "tls_authentication_rejected",
            Self::Timeout => "timeout",
            Self::ServerHelloInvalid => "server_hello_invalid",
            Self::ServerHelloMissingBaseCapability => "server_hello_missing_base_capability",
            Self::FramingFailure => "framing_failure",
            Self::RequestLimitExceeded => "request_limit_exceeded",
        }
    }
}

/// NETCONF smoke helper error. Display text is payload-free.
#[derive(Debug, Error)]
pub enum NetconfSmokeError {
    /// Client-side configuration was invalid.
    #[error("NETCONF smoke client config is invalid")]
    InvalidConfig,
    /// TLS client config could not be built from caller PEMs.
    #[error("NETCONF smoke TLS client config is invalid")]
    TlsConfig,
    /// TCP connection failed.
    #[error("NETCONF smoke TCP connection failed")]
    TcpConnectFailed,
    /// TLS handshake failed, including server or client certificate rejection.
    #[error("NETCONF smoke TLS authentication failed")]
    TlsAuthenticationRejected,
    /// A bounded operation timed out.
    #[error("NETCONF smoke operation timed out")]
    Timeout,
    /// Server hello XML was malformed or missing capabilities.
    #[error("NETCONF smoke server hello is invalid")]
    ServerHelloInvalid,
    /// Server hello did not advertise the required base capability.
    #[error("NETCONF smoke server hello is missing a required base capability")]
    ServerHelloMissingBaseCapability,
    /// NETCONF frame encoding/decoding failed.
    #[error("NETCONF smoke framing failed")]
    FramingFailure,
    /// Caller supplied too many or too-large smoke RPCs.
    #[error("NETCONF smoke request limit exceeded")]
    RequestLimitExceeded,
}

impl NetconfSmokeError {
    /// Stable machine-readable code for this error.
    pub const fn code(&self) -> NetconfSmokeErrorCode {
        match self {
            Self::InvalidConfig => NetconfSmokeErrorCode::InvalidConfig,
            Self::TlsConfig => NetconfSmokeErrorCode::TlsConfig,
            Self::TcpConnectFailed => NetconfSmokeErrorCode::TcpConnectFailed,
            Self::TlsAuthenticationRejected => NetconfSmokeErrorCode::TlsAuthenticationRejected,
            Self::Timeout => NetconfSmokeErrorCode::Timeout,
            Self::ServerHelloInvalid => NetconfSmokeErrorCode::ServerHelloInvalid,
            Self::ServerHelloMissingBaseCapability => {
                NetconfSmokeErrorCode::ServerHelloMissingBaseCapability
            }
            Self::FramingFailure => NetconfSmokeErrorCode::FramingFailure,
            Self::RequestLimitExceeded => NetconfSmokeErrorCode::RequestLimitExceeded,
        }
    }
}

/// Runs a live NETCONF-over-TLS smoke probe against an already-running listener.
pub async fn run_netconf_tls_smoke(
    config: NetconfTlsSmokeClientConfig,
    rpcs: impl IntoIterator<Item = NetconfSmokeRpc>,
) -> Result<NetconfSmokeTranscript, NetconfSmokeError> {
    validate_config(&config)?;
    let rpcs = collect_rpcs(rpcs)?;
    let limits = MgmtLimits::default();
    let mut stream = connect_tls(&config).await?;

    let server_hello_bytes = match read_message(
        &mut stream,
        NetconfSmokeFramingUsed::Base10,
        &limits,
        config.timeout,
    )
    .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) | Err(NetconfSmokeError::FramingFailure) => {
            return Err(NetconfSmokeError::TlsAuthenticationRejected);
        }
        Err(err) => return Err(err),
    };
    let server_hello_xml = std::str::from_utf8(&server_hello_bytes)
        .map_err(|_| NetconfSmokeError::ServerHelloInvalid)?;
    let server_capabilities = parse_server_hello_capabilities(server_hello_xml, &limits)?;
    validate_server_capabilities(&server_capabilities, config.framing)?;
    let hello_summary = summarize_hello(&server_capabilities);

    let client_hello = client_hello_xml(config.framing);
    write_message(
        &mut stream,
        NetconfSmokeFramingUsed::Base10,
        client_hello.as_bytes(),
        &limits,
        config.timeout,
    )
    .await?;
    let framing = framing_used(config.framing);

    let mut outcomes = Vec::with_capacity(rpcs.len());
    for rpc in rpcs {
        let operation = operation_name_from_body(&rpc.body);
        let envelope = rpc_envelope(&rpc);
        limits
            .check_request_bytes(envelope.len())
            .map_err(map_limit_error)?;
        write_message(
            &mut stream,
            framing,
            envelope.as_bytes(),
            &limits,
            config.timeout,
        )
        .await?;
        let reply_bytes = read_message(&mut stream, framing, &limits, config.timeout)
            .await?
            .ok_or(NetconfSmokeError::FramingFailure)?;
        let status = std::str::from_utf8(&reply_bytes)
            .ok()
            .map(summarize_rpc_reply)
            .unwrap_or(NetconfSmokeRpcStatus::MalformedReply);
        outcomes.push(NetconfSmokeRpcOutcome {
            message_id: bounded_string(&rpc.message_id),
            operation,
            status,
        });
    }

    Ok(NetconfSmokeTranscript {
        addr: config.addr,
        server_name: bounded_string(&config.server_name),
        server_hello: hello_summary,
        framing,
        rpcs: outcomes,
    })
}

fn validate_config(config: &NetconfTlsSmokeClientConfig) -> Result<(), NetconfSmokeError> {
    if config.server_name.is_empty()
        || config.client_cert_pem.is_empty()
        || config.client_key_pem.is_empty()
        || config.trust_roots_pem.is_empty()
        || config.timeout.is_zero()
    {
        return Err(NetconfSmokeError::InvalidConfig);
    }
    Ok(())
}

fn collect_rpcs(
    rpcs: impl IntoIterator<Item = NetconfSmokeRpc>,
) -> Result<Vec<NetconfSmokeRpc>, NetconfSmokeError> {
    let rpcs = rpcs.into_iter().collect::<Vec<_>>();
    if rpcs.len() > MAX_SMOKE_RPCS {
        return Err(NetconfSmokeError::RequestLimitExceeded);
    }
    if rpcs
        .iter()
        .any(|rpc| rpc.message_id.is_empty() || rpc.body.is_empty())
    {
        return Err(NetconfSmokeError::InvalidConfig);
    }
    Ok(rpcs)
}

async fn connect_tls(
    config: &NetconfTlsSmokeClientConfig,
) -> Result<TlsStream<TcpStream>, NetconfSmokeError> {
    let tls_config = Arc::new(build_client_config(config)?);
    let tcp = tokio::time::timeout(config.timeout, TcpStream::connect(config.addr))
        .await
        .map_err(|_| NetconfSmokeError::Timeout)?
        .map_err(|_| NetconfSmokeError::TcpConnectFailed)?;
    let server_name = ServerName::try_from(config.server_name.as_str())
        .map_err(|_| NetconfSmokeError::InvalidConfig)?
        .to_owned();
    let connector = TlsConnector::from(tls_config);
    tokio::time::timeout(config.timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| NetconfSmokeError::Timeout)?
        .map_err(|_| NetconfSmokeError::TlsAuthenticationRejected)
}

fn build_client_config(
    config: &NetconfTlsSmokeClientConfig,
) -> Result<ClientConfig, NetconfSmokeError> {
    static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });

    let client_cert_pem =
        std::str::from_utf8(&config.client_cert_pem).map_err(|_| NetconfSmokeError::TlsConfig)?;
    let client_key_pem =
        std::str::from_utf8(&config.client_key_pem).map_err(|_| NetconfSmokeError::TlsConfig)?;
    let trust_roots_pem =
        std::str::from_utf8(&config.trust_roots_pem).map_err(|_| NetconfSmokeError::TlsConfig)?;

    let client_certs =
        parse_certs_pem(client_cert_pem).map_err(|_| NetconfSmokeError::TlsConfig)?;
    if client_certs.is_empty() {
        return Err(NetconfSmokeError::TlsConfig);
    }
    let client_key = parse_key_pem(client_key_pem).map_err(|_| NetconfSmokeError::TlsConfig)?;
    let trust_roots = parse_certs_pem(trust_roots_pem).map_err(|_| NetconfSmokeError::TlsConfig)?;
    if trust_roots.is_empty() {
        return Err(NetconfSmokeError::TlsConfig);
    }
    let mut root_store = RootCertStore::empty();
    for root in trust_roots {
        root_store
            .add(root)
            .map_err(|_| NetconfSmokeError::TlsConfig)?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&TLS_PROTOCOL_VERSIONS)
        .map_err(|_| NetconfSmokeError::TlsConfig)?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|_| NetconfSmokeError::TlsConfig)
}

fn validate_server_capabilities(
    capabilities: &[String],
    preference: NetconfSmokeFramingPreference,
) -> Result<(), NetconfSmokeError> {
    let has_base10 = capabilities
        .iter()
        .any(|capability| capability == NETCONF_BASE_1_0);
    let has_base11 = capabilities
        .iter()
        .any(|capability| capability == NETCONF_BASE_1_1);
    match preference {
        NetconfSmokeFramingPreference::Base10 if has_base10 => Ok(()),
        NetconfSmokeFramingPreference::Base11 if has_base10 && has_base11 => Ok(()),
        _ => Err(NetconfSmokeError::ServerHelloMissingBaseCapability),
    }
}

fn parse_server_hello_capabilities(
    xml: &str,
    limits: &MgmtLimits,
) -> Result<Vec<String>, NetconfSmokeError> {
    limits
        .check_request_bytes(xml.len())
        .map_err(map_limit_error)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_capability = false;
    let mut capabilities = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) if local_name(start.name().as_ref()) == Some("capability") => {
                in_capability = true;
            }
            Ok(Event::End(end)) if local_name(end.name().as_ref()) == Some("capability") => {
                in_capability = false;
            }
            Ok(Event::Text(text)) if in_capability => {
                limits
                    .check_value_bytes(text.as_ref().len())
                    .map_err(map_limit_error)?;
                let decoded = text
                    .decode()
                    .map_err(|_| NetconfSmokeError::ServerHelloInvalid)?;
                let capability = decoded.trim();
                if !capability.is_empty() {
                    capabilities.push(capability.to_string());
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(NetconfSmokeError::ServerHelloInvalid),
            _ => {}
        }
    }

    if capabilities.is_empty() {
        return Err(NetconfSmokeError::ServerHelloInvalid);
    }
    Ok(capabilities)
}

fn summarize_hello(capabilities: &[String]) -> NetconfSmokeHelloSummary {
    let capability_count = capabilities.len();
    let capabilities = capabilities
        .iter()
        .take(MAX_CAPABILITIES_SUMMARY)
        .map(|capability| bounded_string(capability))
        .collect::<Vec<_>>();
    NetconfSmokeHelloSummary {
        capabilities,
        capability_count,
        truncated: capability_count > MAX_CAPABILITIES_SUMMARY,
    }
}

fn client_hello_xml(preference: NetconfSmokeFramingPreference) -> String {
    let mut out = format!(r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities>"#);
    out.push_str("<capability>");
    out.push_str(NETCONF_BASE_1_0);
    out.push_str("</capability>");
    if matches!(preference, NetconfSmokeFramingPreference::Base11) {
        out.push_str("<capability>");
        out.push_str(NETCONF_BASE_1_1);
        out.push_str("</capability>");
    }
    out.push_str("</capabilities></hello>");
    out
}

const fn framing_used(preference: NetconfSmokeFramingPreference) -> NetconfSmokeFramingUsed {
    match preference {
        NetconfSmokeFramingPreference::Base10 => NetconfSmokeFramingUsed::Base10,
        NetconfSmokeFramingPreference::Base11 => NetconfSmokeFramingUsed::Base11,
    }
}

fn rpc_envelope(rpc: &NetconfSmokeRpc) -> String {
    format!(
        r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="{}">{}</rpc>"#,
        xml_escape(&rpc.message_id),
        rpc.body
    )
}

async fn write_message<W>(
    writer: &mut W,
    framing: NetconfSmokeFramingUsed,
    message: &[u8],
    limits: &MgmtLimits,
    timeout: Duration,
) -> Result<(), NetconfSmokeError>
where
    W: AsyncWrite + Unpin,
{
    let frame = match framing {
        NetconfSmokeFramingUsed::Base10 => base10::encode_message(message, limits),
        NetconfSmokeFramingUsed::Base11 => base11::encode_message(message, limits),
    }
    .map_err(map_framing_error)?;
    tokio::time::timeout(timeout, async {
        writer.write_all(&frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| NetconfSmokeError::Timeout)?
    .map_err(|_| NetconfSmokeError::FramingFailure)
}

async fn read_message<R>(
    reader: &mut R,
    framing: NetconfSmokeFramingUsed,
    limits: &MgmtLimits,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, NetconfSmokeError>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, async {
        match framing {
            NetconfSmokeFramingUsed::Base10 => read_base10_message(reader, limits).await,
            NetconfSmokeFramingUsed::Base11 => read_base11_message(reader, limits).await,
        }
    })
    .await
    .map_err(|_| NetconfSmokeError::Timeout)?
}

async fn read_base10_message<R>(
    reader: &mut R,
    limits: &MgmtLimits,
) -> Result<Option<Vec<u8>>, NetconfSmokeError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .await
            .map_err(|_| NetconfSmokeError::FramingFailure)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(NetconfSmokeError::FramingFailure);
        }
        buf.push(byte[0]);
        if buf.len()
            > limits
                .max_request_bytes
                .saturating_add(base10::END_MARKER.len())
        {
            return Err(NetconfSmokeError::RequestLimitExceeded);
        }
        if buf.ends_with(base10::END_MARKER) {
            let message_len = buf.len() - base10::END_MARKER.len();
            limits
                .check_request_bytes(message_len)
                .map_err(map_limit_error)?;
            buf.truncate(message_len);
            return Ok(Some(buf));
        }
    }
}

async fn read_base11_message<R>(
    reader: &mut R,
    limits: &MgmtLimits,
) -> Result<Option<Vec<u8>>, NetconfSmokeError>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunks = 0usize;

    loop {
        let Some(first) = read_one(reader).await? else {
            return if out.is_empty() {
                Ok(None)
            } else {
                Err(NetconfSmokeError::FramingFailure)
            };
        };
        if first != b'\n' || read_required_one(reader).await? != b'#' {
            return Err(NetconfSmokeError::FramingFailure);
        }

        let next = read_required_one(reader).await?;
        if next == b'#' {
            if read_required_one(reader).await? != b'\n' || chunks == 0 {
                return Err(NetconfSmokeError::FramingFailure);
            }
            limits
                .check_request_bytes(out.len())
                .map_err(map_limit_error)?;
            return Ok(Some(out));
        }

        if !next.is_ascii_digit() || next == b'0' {
            return Err(NetconfSmokeError::FramingFailure);
        }
        let mut len_bytes = vec![next];
        loop {
            let b = read_required_one(reader).await?;
            if b == b'\n' {
                break;
            }
            if !b.is_ascii_digit() || len_bytes.len() >= 20 {
                return Err(NetconfSmokeError::FramingFailure);
            }
            len_bytes.push(b);
        }
        let len_str =
            std::str::from_utf8(&len_bytes).map_err(|_| NetconfSmokeError::FramingFailure)?;
        let chunk_len = len_str
            .parse::<usize>()
            .map_err(|_| NetconfSmokeError::FramingFailure)?;
        if chunk_len == 0 {
            return Err(NetconfSmokeError::FramingFailure);
        }
        let next_chunks = chunks
            .checked_add(1)
            .ok_or(NetconfSmokeError::FramingFailure)?;
        limits
            .check_frame_chunks(next_chunks)
            .map_err(map_limit_error)?;
        let next_len = out
            .len()
            .checked_add(chunk_len)
            .ok_or(NetconfSmokeError::FramingFailure)?;
        limits
            .check_request_bytes(next_len)
            .map_err(map_limit_error)?;
        let start = out.len();
        out.resize(next_len, 0);
        reader
            .read_exact(&mut out[start..next_len])
            .await
            .map_err(|_| NetconfSmokeError::FramingFailure)?;
        chunks = next_chunks;
    }
}

async fn read_one<R>(reader: &mut R) -> Result<Option<u8>, NetconfSmokeError>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    match reader
        .read(&mut byte)
        .await
        .map_err(|_| NetconfSmokeError::FramingFailure)?
    {
        0 => Ok(None),
        _ => Ok(Some(byte[0])),
    }
}

async fn read_required_one<R>(reader: &mut R) -> Result<u8, NetconfSmokeError>
where
    R: AsyncRead + Unpin,
{
    read_one(reader)
        .await?
        .ok_or(NetconfSmokeError::FramingFailure)
}

fn summarize_rpc_reply(reply: &str) -> NetconfSmokeRpcStatus {
    let mut reader = Reader::from_str(reply);
    reader.config_mut().trim_text(true);
    let mut in_rpc_error = false;
    let mut saw_ok = false;
    let mut saw_data = false;
    let mut current_text_element: Option<&'static str> = None;
    let mut error_type: Option<String> = None;
    let mut error_tag: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => match local_name(start.name().as_ref()) {
                Some("rpc-error") => in_rpc_error = true,
                Some("ok") => saw_ok = true,
                Some("data") => saw_data = true,
                Some("error-type") => current_text_element = Some("error-type"),
                Some("error-tag") => current_text_element = Some("error-tag"),
                _ => {}
            },
            Ok(Event::Empty(start)) => match local_name(start.name().as_ref()) {
                Some("ok") => saw_ok = true,
                Some("data") => saw_data = true,
                Some("rpc-error") => in_rpc_error = true,
                _ => {}
            },
            Ok(Event::End(end)) => {
                if let Some("error-type" | "error-tag") = local_name(end.name().as_ref()) {
                    current_text_element = None;
                }
            }
            Ok(Event::Text(text)) => {
                let Ok(decoded) = text.decode() else {
                    return NetconfSmokeRpcStatus::MalformedReply;
                };
                match current_text_element {
                    Some("error-type") => error_type = Some(bounded_string(decoded.as_ref())),
                    Some("error-tag") => error_tag = Some(bounded_string(decoded.as_ref())),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return NetconfSmokeRpcStatus::MalformedReply,
            _ => {}
        }
    }

    if in_rpc_error {
        NetconfSmokeRpcStatus::RpcError {
            error_type,
            error_tag,
        }
    } else {
        let reply_kind = if saw_ok {
            "ok"
        } else if saw_data {
            "data"
        } else {
            "reply"
        };
        NetconfSmokeRpcStatus::Success {
            summary: NetconfSmokeRpcSummary {
                reply_kind: reply_kind.to_string(),
            },
        }
    }
}

fn local_name(raw_name: &[u8]) -> Option<&str> {
    let name = std::str::from_utf8(raw_name).ok()?;
    Some(name.rsplit(':').next().unwrap_or(name))
}

fn operation_name_from_body(body: &str) -> String {
    let Some(start) = body.find('<') else {
        return "unknown".to_string();
    };
    let rest = &body[start + 1..];
    if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
        return "unknown".to_string();
    }
    let end = rest
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(rest.len());
    if end == 0 {
        return "unknown".to_string();
    }
    let name = rest[..end].rsplit(':').next().unwrap_or(&rest[..end]);
    bounded_string(name)
}

fn map_framing_error(err: FramingError) -> NetconfSmokeError {
    match err {
        FramingError::Limit(err) => map_limit_error(err),
        _ => NetconfSmokeError::FramingFailure,
    }
}

fn map_limit_error(_err: LimitsError) -> NetconfSmokeError {
    NetconfSmokeError::RequestLimitExceeded
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
    use std::collections::HashSet;
    use std::sync::Arc;

    use opc_config_bus::{ConfigBus, MockManagedDatastore};
    use opc_config_model::{
        ConfigError, OpcConfig, TransportType, ValidationContext, ValidationError, YangPath,
    };
    use opc_identity::{
        parse_certs_pem, parse_key_pem, IdentityState, SvidDocument, TrustBundle, TrustBundleSet,
        TrustDomain, WorkloadIdentity,
    };
    use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_schema::{
        DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
    };
    use opc_mgmt_transport::TlsBootstrap;
    use opc_nacm::{
        ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern,
    };
    use opc_runtime::{RuntimeMode, ShutdownToken};
    use opc_tls::PeerPolicy;
    use opc_types::{SchemaDigest, Timestamp};
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use super::*;
    use crate::{
        run_read_only_tls_listener, BindingError, NetconfConfigBinding, ReadOnlyNetconfServer,
        ReadSelection, SessionConfig, TlsListenerConfig,
    };

    const CERT_PEM: &[u8] =
        b"-----BEGIN CERTIFICATE-----\nsecret-cert\n-----END CERTIFICATE-----\n";
    const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nsecret-key\n-----END PRIVATE KEY-----\n";

    #[test]
    fn config_debug_redacts_pem_material() {
        let config = NetconfTlsSmokeClientConfig {
            addr: "127.0.0.1:830".parse().expect("addr"),
            server_name: "localhost".to_string(),
            client_cert_pem: CERT_PEM.to_vec(),
            client_key_pem: KEY_PEM.to_vec(),
            trust_roots_pem: CERT_PEM.to_vec(),
            timeout: Duration::from_secs(1),
            framing: NetconfSmokeFramingPreference::Base10,
        };

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("secret-cert"));
        assert!(!rendered.contains("secret-key"));
        assert!(rendered.contains("<redacted pem"));
    }

    #[test]
    fn error_display_is_payload_free() {
        assert!(!NetconfSmokeError::TlsConfig
            .to_string()
            .contains("secret-key"));
        assert_eq!(NetconfSmokeError::Timeout.code().as_str(), "timeout");
    }

    #[test]
    fn rpc_error_summary_extracts_standard_tags_without_payload() {
        let reply = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><rpc-error><error-type>protocol</error-type><error-tag>operation-not-supported</error-tag><error-message>do-not-leak</error-message></rpc-error></rpc-reply>"#;

        let summary = summarize_rpc_reply(reply);

        assert_eq!(
            summary,
            NetconfSmokeRpcStatus::RpcError {
                error_type: Some("protocol".to_string()),
                error_tag: Some("operation-not-supported".to_string()),
            }
        );
        assert!(!format!("{summary:?}").contains("do-not-leak"));
    }

    #[test]
    fn ok_summary_is_success_without_raw_xml() {
        let reply =
            r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><ok/></rpc-reply>"#;

        assert_eq!(
            summarize_rpc_reply(reply),
            NetconfSmokeRpcStatus::Success {
                summary: NetconfSmokeRpcSummary {
                    reply_kind: "ok".to_string()
                }
            }
        );
    }

    #[test]
    fn operation_name_uses_element_name_only() {
        assert_eq!(
            operation_name_from_body("<get><filter>secret</filter></get>"),
            "get"
        );
        assert_eq!(operation_name_from_body("not-xml"), "unknown");
    }

    #[derive(Clone)]
    struct DemoConfig {
        hostname: String,
    }

    impl OpcConfig for DemoConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([3u8; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    struct TestRegistry;

    static MODELS: &[ModelData] = &[ModelData {
        name: "demo-system",
        revision: "2026-06-13",
        namespace: "urn:opc:demo",
        prefix: "sys",
    }];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["demo-system"],
    }];

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
            child_paths: &["/sys:system/sys:hostname"],
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

    #[derive(Clone)]
    struct TestBinding {
        bus: Arc<ConfigBus<DemoConfig>>,
    }

    impl NetconfConfigBinding<DemoConfig> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &TestRegistry
        }

        fn render_running_config(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            if !selection.contains("/sys:system") && !selection.contains("/sys:system/sys:hostname")
            {
                return Ok(String::new());
            }
            Ok(format!(
                r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>{}</sys:hostname></sys:system>"#,
                crate::xml_escape(&config.hostname)
            ))
        }
    }

    struct FixedPolicy(NacmPolicy);

    impl PolicySource for FixedPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Clone)]
    struct NoopAudit;

    impl AuditSink for NoopAudit {
        fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Ok(())
        }
    }

    struct MtlsMaterial {
        server_state: IdentityState,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
        trust_roots_pem: Vec<u8>,
    }

    async fn test_server() -> ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, NoopAudit>
    {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        ReadOnlyNetconfServer::new(
            TestBinding { bus },
            FixedPolicy(read_policy()),
            NoopAudit,
            TransportType::NetconfTls,
        )
        .expect("server")
    }

    fn read_policy() -> NacmPolicy {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("demo module");
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system", &modules).expect("allow root"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("allow subtree"),
            ))
            .build()
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
            "NETCONF Server",
            "spiffe://test-domain/tenant/test/ns/default/sa/netconf-server/nf/amf/instance/0",
            true,
        );
        let client = signed_leaf(
            &ca_cert,
            &ca_key,
            "NETCONF Client",
            "spiffe://test-domain/tenant/test/ns/default/sa/netconf-client/nf/amf/instance/0",
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
            "spiffe://test-domain/tenant/test/ns/default/sa/netconf-client/nf/amf/instance/1",
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

    fn smoke_config(addr: SocketAddr, material: &MtlsMaterial) -> NetconfTlsSmokeClientConfig {
        NetconfTlsSmokeClientConfig {
            addr,
            server_name: "localhost".to_string(),
            client_cert_pem: material.client_cert_pem.clone(),
            client_key_pem: material.client_key_pem.clone(),
            trust_roots_pem: material.trust_roots_pem.clone(),
            timeout: Duration::from_secs(3),
            framing: NetconfSmokeFramingPreference::Base11,
        }
    }

    async fn spawn_listener(
        material: &MtlsMaterial,
    ) -> (
        SocketAddr,
        ShutdownToken,
        tokio::task::JoinHandle<crate::TlsListenerResult>,
    ) {
        let (_identity_tx, identity_rx) = watch::channel(Some(material.server_state.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = ShutdownToken::new();
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run_read_only_tls_listener(
                Arc::new(test_server().await),
                listener,
                TlsBootstrap::new(RuntimeMode::Production, peer_policy()),
                identity_rx,
                task_shutdown,
                TlsListenerConfig {
                    session: SessionConfig {
                        frame_timeout: Duration::from_secs(3),
                        ..SessionConfig::default()
                    },
                    handshake_timeout: Duration::from_secs(3),
                    drain_timeout: Duration::from_secs(3),
                    ..TlsListenerConfig::default()
                },
            )
            .await
            .expect("listener result")
        });
        (addr, shutdown, task)
    }

    #[tokio::test]
    async fn live_tls_smoke_runs_hello_get_config_and_rpc_error() {
        let material = mtls_material();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;

        let transcript = run_netconf_tls_smoke(
            smoke_config(addr, &material),
            [
                NetconfSmokeRpc {
                    message_id: "101".to_string(),
                    body: "<get-config><source><running/></source></get-config>".to_string(),
                },
                NetconfSmokeRpc {
                    message_id: "102".to_string(),
                    body: "<unknown/>".to_string(),
                },
            ],
        )
        .await
        .expect("smoke transcript");

        assert!(transcript
            .server_hello
            .capabilities
            .iter()
            .any(|capability| capability == NETCONF_BASE_1_1));
        assert_eq!(transcript.framing, NetconfSmokeFramingUsed::Base11);
        assert!(matches!(
            transcript.rpcs[0].status,
            NetconfSmokeRpcStatus::Success { .. }
        ));
        assert_eq!(transcript.rpcs[0].operation, "get-config");
        assert!(matches!(
            &transcript.rpcs[1].status,
            NetconfSmokeRpcStatus::RpcError { error_tag, .. }
                if error_tag.as_deref() == Some("unknown-namespace")
                    || error_tag.as_deref() == Some("operation-not-supported")
        ));

        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join");
    }

    #[tokio::test]
    async fn live_tls_smoke_reports_tls_auth_failure_code() {
        let (material, bad_client_cert, bad_client_key) = mtls_material_with_untrusted_client();
        let (addr, shutdown, listener_task) = spawn_listener(&material).await;
        let mut config = smoke_config(addr, &material);
        config.client_cert_pem = bad_client_cert;
        config.client_key_pem = bad_client_key;

        let err = run_netconf_tls_smoke(config, [])
            .await
            .expect_err("auth failure");

        assert_eq!(err.code(), NetconfSmokeErrorCode::TlsAuthenticationRejected);

        shutdown.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join");
    }

    #[tokio::test]
    async fn live_tls_smoke_reports_timeout_code() {
        let material = mtls_material();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            let (_stream, _peer) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        let mut config = smoke_config(addr, &material);
        config.timeout = Duration::from_millis(50);

        let err = run_netconf_tls_smoke(config, [])
            .await
            .expect_err("timeout");

        assert_eq!(err.code(), NetconfSmokeErrorCode::Timeout);
        server_task.await.expect("server task");
    }
}
