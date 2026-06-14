//! NETCONF session handshake and RPC loop.
//!
//! The session layer is transport-neutral over an already-authenticated byte
//! stream. A TLS listener composes this with `opc-mgmt-transport` and principal
//! mapping; this module owns the NETCONF protocol sequencing:
//!
//! 1. send server `<hello>` using base 1.0 framing,
//! 2. read and parse client `<hello>` using base 1.0 framing,
//! 3. select base 1.1 chunked framing only when the client advertised it,
//! 4. dispatch bounded RPC frames through [`ReadOnlyNetconfServer`].

use std::str;
use std::time::Duration;

use opc_config_model::{OpcConfig, RequestId, TrustedPrincipal};
use opc_mgmt_audit::AuditSink;
use opc_mgmt_authz::PolicySource;
use opc_mgmt_limits::{LimitsError, MgmtLimits};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::binding::NetconfConfigBinding;
use crate::capabilities::{NETCONF_BASE_1_0, NETCONF_BASE_1_1};
use crate::framing::{base10, base11, FramingError};
use crate::server::ReadOnlyNetconfServer;
use crate::xml::{parse_client_hello, ClientHello, XmlError};

/// Negotiated NETCONF message framing after hello exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFraming {
    /// RFC 6241 base 1.0 `]]>]]>` end marker framing.
    Base10,
    /// RFC 6242/base 1.1 chunked framing.
    Base11,
}

/// Runtime bounds for one NETCONF session.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Shared management-plane input limits.
    pub limits: MgmtLimits,
    /// Maximum wall-clock time allowed to receive one complete hello/RPC frame.
    pub frame_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            limits: MgmtLimits::default(),
            frame_timeout: Duration::from_secs(30),
        }
    }
}

/// Summary returned after a session exits cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResult {
    /// Capabilities advertised by the client hello.
    pub client_capabilities: Vec<String>,
    /// Negotiated framing for post-hello RPCs.
    pub framing: SessionFraming,
    /// Number of RPCs dispatched before EOF.
    pub rpc_count: u64,
}

/// NETCONF session error. Display text is payload-free.
#[derive(Debug, Error)]
pub enum SessionError {
    /// I/O failure on the already-authenticated stream.
    #[error("NETCONF session I/O error")]
    Io(#[from] std::io::Error),
    /// Shared management-plane limit failure.
    #[error(transparent)]
    Limit(#[from] LimitsError),
    /// NETCONF framing failure.
    #[error(transparent)]
    Framing(#[from] FramingError),
    /// XML hello parser failure.
    #[error(transparent)]
    Xml(#[from] XmlError),
    /// The client did not advertise any supported base capability.
    #[error("NETCONF client did not advertise a supported base capability")]
    UnsupportedClientCapabilities,
    /// A frame was not valid UTF-8 XML.
    #[error("NETCONF frame is not valid UTF-8 XML")]
    InvalidUtf8,
    /// The peer closed the stream before the client hello was received.
    #[error("NETCONF session closed before client hello")]
    MissingClientHello,
}

/// Runs one read-only NETCONF session over an authenticated stream.
pub async fn run_read_only_session<C, B, P, A, S>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    principal: &TrustedPrincipal,
    stream: &mut S,
    config: SessionConfig,
    session_id: u64,
) -> Result<SessionResult, SessionError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    S: AsyncRead + AsyncWrite + Unpin,
{
    config.limits.validate()?;

    let server_hello = server.server_hello(Some(session_id));
    write_message(
        stream,
        SessionFraming::Base10,
        server_hello.as_bytes(),
        &config.limits,
    )
    .await?;

    let client_hello_bytes = read_message(stream, SessionFraming::Base10, &config).await?;
    let Some(client_hello_bytes) = client_hello_bytes else {
        return Err(SessionError::MissingClientHello);
    };
    let client_hello_xml =
        str::from_utf8(&client_hello_bytes).map_err(|_| SessionError::InvalidUtf8)?;
    let client_hello = parse_client_hello(client_hello_xml, &config.limits)?;
    let framing = negotiate_framing(&client_hello)?;

    let mut rpc_count = 0u64;
    loop {
        let Some(message) = read_message(stream, framing, &config).await? else {
            return Ok(SessionResult {
                client_capabilities: client_hello.capabilities,
                framing,
                rpc_count,
            });
        };
        let rpc_xml = str::from_utf8(&message).map_err(|_| SessionError::InvalidUtf8)?;
        let result = server.handle_rpc(RequestId::new(), principal, rpc_xml, &config.limits);
        write_message(stream, framing, result.reply_xml.as_bytes(), &config.limits).await?;
        rpc_count = rpc_count.saturating_add(1);
        if result.close_session {
            return Ok(SessionResult {
                client_capabilities: client_hello.capabilities,
                framing,
                rpc_count,
            });
        }
    }
}

fn negotiate_framing(hello: &ClientHello) -> Result<SessionFraming, SessionError> {
    if hello
        .capabilities
        .iter()
        .any(|capability| capability == NETCONF_BASE_1_1)
    {
        Ok(SessionFraming::Base11)
    } else if hello
        .capabilities
        .iter()
        .any(|capability| capability == NETCONF_BASE_1_0)
    {
        Ok(SessionFraming::Base10)
    } else {
        Err(SessionError::UnsupportedClientCapabilities)
    }
}

async fn write_message<W>(
    writer: &mut W,
    framing: SessionFraming,
    message: &[u8],
    limits: &MgmtLimits,
) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    let frame = match framing {
        SessionFraming::Base10 => base10::encode_message(message, limits)?,
        SessionFraming::Base11 => base11::encode_message(message, limits)?,
    };
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_message<R>(
    reader: &mut R,
    framing: SessionFraming,
    config: &SessionConfig,
) -> Result<Option<Vec<u8>>, SessionError>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(config.frame_timeout, async {
        match framing {
            SessionFraming::Base10 => read_base10_message(reader, &config.limits).await,
            SessionFraming::Base11 => read_base11_message(reader, &config.limits).await,
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(SessionError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out reading NETCONF frame",
        ))),
    }
}

async fn read_base10_message<R>(
    reader: &mut R,
    limits: &MgmtLimits,
) -> Result<Option<Vec<u8>>, SessionError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(FramingError::MissingEndMarker.into());
        }
        buf.push(byte[0]);
        if buf.len()
            > limits
                .max_request_bytes
                .saturating_add(base10::END_MARKER.len())
        {
            return Err(LimitsError::Exceeded {
                limit: "request_bytes",
                max: limits.max_request_bytes,
                actual: limits.max_request_bytes.saturating_add(1),
            }
            .into());
        }
        if buf.ends_with(base10::END_MARKER) {
            let message_len = buf.len() - base10::END_MARKER.len();
            limits.check_request_bytes(message_len)?;
            buf.truncate(message_len);
            return Ok(Some(buf));
        }
    }
}

async fn read_base11_message<R>(
    reader: &mut R,
    limits: &MgmtLimits,
) -> Result<Option<Vec<u8>>, SessionError>
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
                Err(FramingError::InvalidEndMarker.into())
            };
        };
        if first != b'\n' || read_required_one(reader).await? != b'#' {
            return Err(FramingError::InvalidChunkHeader.into());
        }

        let next = read_required_one(reader).await?;
        if next == b'#' {
            if read_required_one(reader).await? != b'\n' {
                return Err(FramingError::InvalidEndMarker.into());
            }
            if chunks == 0 {
                return Err(FramingError::InvalidChunkHeader.into());
            }
            limits.check_request_bytes(out.len())?;
            return Ok(Some(out));
        }

        if !next.is_ascii_digit() {
            return Err(FramingError::InvalidChunkHeader.into());
        }
        let mut len_bytes = vec![next];
        loop {
            let b = read_required_one(reader).await?;
            if b == b'\n' {
                break;
            }
            if !b.is_ascii_digit() || len_bytes.len() >= 20 {
                return Err(FramingError::InvalidChunkLength.into());
            }
            len_bytes.push(b);
        }
        let len_str = str::from_utf8(&len_bytes).map_err(|_| FramingError::InvalidChunkLength)?;
        let chunk_len = len_str
            .parse::<usize>()
            .map_err(|_| FramingError::InvalidChunkLength)?;
        if chunk_len == 0 {
            return Err(FramingError::InvalidChunkLength.into());
        }
        let next_len = out
            .len()
            .checked_add(chunk_len)
            .ok_or(FramingError::InvalidChunkLength)?;
        limits.check_request_bytes(next_len)?;
        let start = out.len();
        out.resize(next_len, 0);
        reader.read_exact(&mut out[start..next_len]).await?;
        chunks += 1;
    }
}

async fn read_one<R>(reader: &mut R) -> Result<Option<u8>, std::io::Error>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    match reader.read(&mut byte).await? {
        0 => Ok(None),
        _ => Ok(Some(byte[0])),
    }
}

async fn read_required_one<R>(reader: &mut R) -> Result<u8, SessionError>
where
    R: AsyncRead + Unpin,
{
    read_one(reader)
        .await?
        .ok_or_else(|| FramingError::MissingChunkData.into())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use opc_config_bus::{ConfigBus, MockManagedDatastore};
    use opc_config_model::{
        AuthStrength, ConfigError, OpcConfig, TrustedPrincipal, ValidationContext, ValidationError,
        WorkloadIdentity, YangPath,
    };
    use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_schema::{
        DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
    };
    use opc_nacm::{
        ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern,
    };
    use opc_types::{SchemaDigest, TenantId};

    use super::*;
    use crate::binding::{BindingError, ReadSelection};
    use crate::capabilities::NETCONF_BASE_NS;
    use crate::server::ReadOnlyNetconfServer;

    #[derive(Clone)]
    struct DemoConfig {
        hostname: String,
    }

    impl OpcConfig for DemoConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([2u8; 32])
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
            "fnv1a64:session"
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

    static REGISTRY: TestRegistry = TestRegistry;

    struct TestBinding {
        bus: Arc<ConfigBus<DemoConfig>>,
    }

    impl NetconfConfigBinding<DemoConfig> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            if !selection.contains("/sys:system/sys:hostname") {
                return Ok(String::new());
            }
            Ok(format!(
                r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>{}</sys:hostname></sys:system>"#,
                crate::xml_escape(&config.hostname)
            ))
        }
    }

    #[derive(Clone, Default)]
    struct CapturingAudit {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl AuditSink for CapturingAudit {
        fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
            self.events.lock().expect("audit mutex").push(event.clone());
            Ok(())
        }
    }

    struct FixedPolicy(NacmPolicy);

    impl PolicySource for FixedPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Ok(self.0.clone())
        }
    }

    fn principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::User("operator".to_string()),
            TenantId::new("tenant-a").expect("tenant"),
        )
        .with_auth_strength(AuthStrength::MutualTls)
    }

    fn allow_all_policy() -> NacmPolicy {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("module");
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("path"),
            ))
            .build()
    }

    async fn server_fixture(
    ) -> ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit> {
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
            FixedPolicy(allow_all_policy()),
            CapturingAudit::default(),
            opc_config_model::TransportType::NetconfTls,
        )
        .expect("server")
    }

    fn client_hello(capabilities: &[&str]) -> String {
        let mut out = format!(r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities>"#);
        for capability in capabilities {
            out.push_str("<capability>");
            out.push_str(capability);
            out.push_str("</capability>");
        }
        out.push_str("</capabilities></hello>");
        out
    }

    fn get_config_rpc(message_id: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="{message_id}"><get-config><source><running/></source></get-config></rpc>"#
        )
    }

    fn close_session_rpc(message_id: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="{message_id}"><close-session/></rpc>"#
        )
    }

    async fn client_write_message<S>(
        stream: &mut S,
        framing: SessionFraming,
        xml: &str,
    ) -> Result<(), SessionError>
    where
        S: AsyncWrite + Unpin,
    {
        write_message(stream, framing, xml.as_bytes(), &MgmtLimits::default()).await
    }

    #[tokio::test]
    async fn session_sends_hello_then_uses_base11_when_client_advertises_it() {
        let server = server_fixture().await;
        let principal = principal();
        let (mut client, mut server_io) = tokio::io::duplex(64 * 1024);

        let task = tokio::spawn(async move {
            run_read_only_session(
                &server,
                &principal,
                &mut server_io,
                SessionConfig::default(),
                77,
            )
            .await
        });

        let server_hello = read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read server hello")
            .expect("server hello");
        let server_hello = str::from_utf8(&server_hello).expect("utf8");
        assert!(server_hello.contains(NETCONF_BASE_1_0));
        assert!(server_hello.contains(NETCONF_BASE_1_1));
        assert!(server_hello.contains("<session-id>77</session-id>"));

        client_write_message(
            &mut client,
            SessionFraming::Base10,
            &client_hello(&[NETCONF_BASE_1_0, NETCONF_BASE_1_1]),
        )
        .await
        .expect("client hello");
        client_write_message(&mut client, SessionFraming::Base11, &get_config_rpc("201"))
            .await
            .expect("rpc");

        let reply = read_base11_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read reply")
            .expect("reply");
        let reply = str::from_utf8(&reply).expect("utf8");
        assert!(reply.contains(r#"message-id="201""#));
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));

        drop(client);
        let result = task.await.expect("join").expect("session result");
        assert_eq!(result.framing, SessionFraming::Base11);
        assert_eq!(result.rpc_count, 1);
    }

    #[tokio::test]
    async fn session_falls_back_to_base10_for_base10_only_client() {
        let server = server_fixture().await;
        let principal = principal();
        let (mut client, mut server_io) = tokio::io::duplex(64 * 1024);

        let task = tokio::spawn(async move {
            run_read_only_session(
                &server,
                &principal,
                &mut server_io,
                SessionConfig::default(),
                78,
            )
            .await
        });

        read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read server hello")
            .expect("server hello");
        client_write_message(
            &mut client,
            SessionFraming::Base10,
            &client_hello(&[NETCONF_BASE_1_0]),
        )
        .await
        .expect("client hello");
        client_write_message(&mut client, SessionFraming::Base10, &get_config_rpc("202"))
            .await
            .expect("rpc");

        let reply = read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read reply")
            .expect("reply");
        let reply = str::from_utf8(&reply).expect("utf8");
        assert!(reply.contains(r#"message-id="202""#));

        drop(client);
        let result = task.await.expect("join").expect("session result");
        assert_eq!(result.framing, SessionFraming::Base10);
        assert_eq!(result.rpc_count, 1);
    }

    #[tokio::test]
    async fn close_session_writes_ok_then_ends_the_session() {
        let server = server_fixture().await;
        let principal = principal();
        let (mut client, mut server_io) = tokio::io::duplex(64 * 1024);

        let task = tokio::spawn(async move {
            run_read_only_session(
                &server,
                &principal,
                &mut server_io,
                SessionConfig::default(),
                81,
            )
            .await
        });

        read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read server hello")
            .expect("server hello");
        client_write_message(
            &mut client,
            SessionFraming::Base10,
            &client_hello(&[NETCONF_BASE_1_0]),
        )
        .await
        .expect("client hello");
        client_write_message(
            &mut client,
            SessionFraming::Base10,
            &close_session_rpc("301"),
        )
        .await
        .expect("close rpc");

        let reply = read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read close reply")
            .expect("close reply");
        let reply = str::from_utf8(&reply).expect("utf8");
        assert!(reply.contains(r#"message-id="301""#));
        assert!(reply.contains("<ok/>"));
        assert!(!reply.contains("<data"));

        let result = task.await.expect("join").expect("session result");
        assert_eq!(result.framing, SessionFraming::Base10);
        assert_eq!(result.rpc_count, 1);

        let eof = read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read eof");
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn mixed_framing_after_base11_negotiation_fails_closed() {
        let server = server_fixture().await;
        let principal = principal();
        let (mut client, mut server_io) = tokio::io::duplex(64 * 1024);

        let task = tokio::spawn(async move {
            run_read_only_session(
                &server,
                &principal,
                &mut server_io,
                SessionConfig::default(),
                79,
            )
            .await
        });

        read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read server hello")
            .expect("server hello");
        client_write_message(
            &mut client,
            SessionFraming::Base10,
            &client_hello(&[NETCONF_BASE_1_0, NETCONF_BASE_1_1]),
        )
        .await
        .expect("client hello");
        client_write_message(&mut client, SessionFraming::Base10, &get_config_rpc("203"))
            .await
            .expect("wrong framing rpc");

        let err = task.await.expect("join").expect_err("framing error");
        assert!(matches!(
            err,
            SessionError::Framing(FramingError::InvalidChunkHeader)
        ));
    }

    #[tokio::test]
    async fn client_without_base_capability_is_rejected() {
        let server = server_fixture().await;
        let principal = principal();
        let (mut client, mut server_io) = tokio::io::duplex(64 * 1024);

        let task = tokio::spawn(async move {
            run_read_only_session(
                &server,
                &principal,
                &mut server_io,
                SessionConfig::default(),
                80,
            )
            .await
        });

        read_base10_message(&mut client, &MgmtLimits::default())
            .await
            .expect("read server hello")
            .expect("server hello");
        client_write_message(
            &mut client,
            SessionFraming::Base10,
            &client_hello(&["urn:example:unknown"]),
        )
        .await
        .expect("client hello");

        let err = task
            .await
            .expect("join")
            .expect_err("unsupported capabilities");
        assert!(matches!(err, SessionError::UnsupportedClientCapabilities));
    }
}
