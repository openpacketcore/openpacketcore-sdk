//! gNMI-over-mTLS listener.
//!
//! The listener owns TCP accept, SDK TLS bootstrap, mTLS principal derivation,
//! and request-extension injection. Tonic owns HTTP/2 and protobuf dispatch.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use opc_config_model::OpcConfig;
use opc_identity::IdentityState;
use opc_mgmt_limits::LimitsError;
use opc_mgmt_transport::{TlsBootstrap, TransportError, ALPN_H2};
use opc_runtime::ShutdownToken;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;

use crate::proto::gnmi;
use crate::service::AuthenticatedGnmiPrincipal;
use crate::transport::{principal_from_tls_stream, GnmiTlsPrincipalError};
use crate::{GnmiConfigBinding, GnmiServer, GnmiService};

/// Runtime configuration for the gNMI-over-TLS listener.
#[derive(Debug, Clone, Copy)]
pub struct GnmiListenerConfig {
    /// Maximum time allowed for one TLS handshake and principal derivation.
    pub handshake_timeout: Duration,
    /// Capacity of the accepted-connection channel handed to tonic.
    pub incoming_channel_capacity: usize,
}

impl Default for GnmiListenerConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            incoming_channel_capacity: 16,
        }
    }
}

/// Summary returned when the listener stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GnmiListenerResult {
    /// Connections that completed mTLS, mapped a principal, and were handed to
    /// tonic.
    pub accepted_connections: u64,
    /// Connections rejected before TLS because `max_sessions` was already
    /// reached.
    pub rejected_connections: u64,
    /// TCP accept, TLS handshake, principal mapping, or worker failures.
    pub failed_connections: u64,
}

/// Listener-level failure before or during tonic serving.
#[derive(Debug, Error)]
pub enum GnmiListenerError {
    /// Management-plane limits were invalid.
    #[error(transparent)]
    Limit(#[from] LimitsError),
    /// Listener config is invalid.
    #[error("gNMI listener config is invalid")]
    InvalidConfig,
    /// TLS bootstrap failed, usually due to fail-closed peer-policy rejection.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Tonic failed while serving accepted streams.
    #[error("gNMI tonic server error")]
    Serve(#[from] tonic::transport::Error),
    /// The accept task panicked or was cancelled.
    #[error("gNMI listener accept task failed")]
    AcceptTask(#[from] JoinError),
}

#[derive(Debug, Error)]
enum HandshakeError {
    #[error("gNMI TLS accept failed")]
    TlsAccept(#[source] std::io::Error),
    #[error("gNMI TLS handshake timed out")]
    Timeout,
    #[error(transparent)]
    Principal(#[from] GnmiTlsPrincipalError),
}

/// Runs a gNMI-over-TLS listener until shutdown is requested.
///
/// The listener uses [`TlsBootstrap`] to stamp HTTP/2 ALPN and enforce
/// production peer-policy rules, then injects an
/// [`AuthenticatedGnmiPrincipal`] into every tonic request. `Capabilities` is
/// `Capabilities` and authenticated read-only `Get` are implemented at this
/// phase; `Set` and `Subscribe` remain explicit `UNIMPLEMENTED` responses.
pub async fn run_gnmi_tls_listener<C, B>(
    server: GnmiServer<C, B>,
    listener: TcpListener,
    tls: TlsBootstrap,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    shutdown: ShutdownToken,
    config: GnmiListenerConfig,
) -> Result<GnmiListenerResult, GnmiListenerError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
{
    validate_listener_config(&config)?;
    server.limits().validate()?;
    let max_sessions = server.limits().max_sessions;
    let tls_config = Arc::new(
        tls.with_alpn([ALPN_H2.to_vec()])
            .build_server_config(identity_rx.clone())?,
    );
    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(max_sessions));
    let counters = Arc::new(ListenerCounters::default());
    let (tx, rx) = mpsc::channel(config.incoming_channel_capacity);
    let accept_shutdown = shutdown.clone();
    let accept_counters = Arc::clone(&counters);

    let accept_task = tokio::spawn(async move {
        accept_loop(
            listener,
            acceptor,
            identity_rx,
            accept_shutdown,
            config,
            semaphore,
            tx,
            accept_counters,
        )
        .await;
    });

    let service = gnmi::g_nmi_server::GNmiServer::new(GnmiService::new_authenticated(server));
    let incoming = ReceiverStream::new(rx);
    let serve_result = tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(incoming, shutdown.shutdown_acknowledged())
        .await;

    shutdown.request_shutdown();
    accept_task.await?;
    serve_result?;
    Ok(counters.snapshot())
}

fn validate_listener_config(config: &GnmiListenerConfig) -> Result<(), GnmiListenerError> {
    if config.handshake_timeout.is_zero() || config.incoming_channel_capacity == 0 {
        return Err(GnmiListenerError::InvalidConfig);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    shutdown: ShutdownToken,
    config: GnmiListenerConfig,
    semaphore: Arc<Semaphore>,
    tx: mpsc::Sender<Result<AuthenticatedTlsStream, std::io::Error>>,
    counters: Arc<ListenerCounters>,
) {
    let mut handshakes = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.shutdown_acknowledged() => {
                break;
            }
            joined = handshakes.join_next(), if !handshakes.is_empty() => {
                if let Some(joined) = joined {
                    record_handshake_join(joined, &counters);
                }
            }
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(error = ?err, "gNMI TCP accept failed");
                        counters.failed_connections.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                };

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits) => {
                        counters.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(TryAcquireError::Closed) => break,
                };

                let acceptor = acceptor.clone();
                let identity_rx = identity_rx.clone();
                let tx = tx.clone();
                let counters = Arc::clone(&counters);
                handshakes.spawn(async move {
                    match accept_authenticated_stream(
                        acceptor,
                        identity_rx,
                        stream,
                        permit,
                        config.handshake_timeout,
                    )
                    .await
                    {
                        Ok(stream) => {
                            if tx.send(Ok(stream)).await.is_ok() {
                                counters.accepted_connections.fetch_add(1, Ordering::Relaxed);
                            } else {
                                counters.failed_connections.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(err) => {
                            tracing::debug!(error = ?err, "gNMI TLS handshake rejected");
                            counters.failed_connections.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
    }

    handshakes.abort_all();
    while let Some(joined) = handshakes.join_next().await {
        record_shutdown_handshake_join(joined, &counters);
    }
}

async fn accept_authenticated_stream(
    acceptor: TlsAcceptor,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    stream: TcpStream,
    permit: OwnedSemaphorePermit,
    timeout: Duration,
) -> Result<AuthenticatedTlsStream, HandshakeError> {
    let tls = tokio::time::timeout(timeout, acceptor.accept(stream))
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(HandshakeError::TlsAccept)?;
    let principal = principal_from_tls_stream(&tls, &identity_rx)?;
    Ok(AuthenticatedTlsStream {
        inner: tls,
        principal: AuthenticatedGnmiPrincipal::new(principal),
        _permit: permit,
    })
}

fn record_handshake_join(joined: Result<(), JoinError>, counters: &ListenerCounters) {
    if joined.is_err() {
        counters.failed_connections.fetch_add(1, Ordering::Relaxed);
    }
}

fn record_shutdown_handshake_join(joined: Result<(), JoinError>, counters: &ListenerCounters) {
    if let Err(err) = joined {
        if err.is_panic() {
            counters.failed_connections.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct ListenerCounters {
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
    failed_connections: AtomicU64,
}

impl ListenerCounters {
    fn snapshot(&self) -> GnmiListenerResult {
        GnmiListenerResult {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
        }
    }
}

struct AuthenticatedTlsStream {
    inner: TlsStream<TcpStream>,
    principal: AuthenticatedGnmiPrincipal,
    _permit: OwnedSemaphorePermit,
}

impl Connected for AuthenticatedTlsStream {
    type ConnectInfo = AuthenticatedGnmiPrincipal;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.principal.clone()
    }
}

impl AsyncRead for AuthenticatedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use hyper_util::rt::TokioIo;
    use opc_config_bus::{ConfigBus, MockManagedDatastore};
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_opstate::{
        OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
    };
    use opc_mgmt_schema::{DataClass, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry};
    use opc_runtime::RuntimeMode;
    use opc_tls::{PeerPolicy, TlsConfigBuilder};
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;
    use tonic::client::Grpc;
    use tonic::codec::ProstCodec;
    use tonic::codegen::http::uri::PathAndQuery;
    use tonic::codegen::http::Uri;
    use tonic::codegen::Service;
    use tonic::transport::Endpoint;
    use tonic::Request;

    use super::*;
    use crate::{
        CapabilityProfile, ExtensionRegistry, GnmiError, GnmiPatchApplicator, GnmiVersion,
        GNMI_VERSION,
    };

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

    impl GnmiConfigBinding<()> for TestBinding {
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

    async fn server() -> GnmiServer<(), TestBinding> {
        let bus = Arc::new(
            ConfigBus::new_dev_only((), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let profile =
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version"));
        GnmiServer::new(
            TestBinding { bus },
            opc_mgmt_limits::MgmtLimits::default(),
            profile,
            ExtensionRegistry::default(),
        )
        .expect("server")
    }

    fn peer_policy() -> PeerPolicy {
        PeerPolicy {
            allowed_trust_domains: Some(HashSet::from([opc_identity::TrustDomain::new(
                "test-domain",
            )
            .expect("trust domain")])),
            ..Default::default()
        }
    }

    fn identity_state(spiffe_id: &str) -> IdentityState {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "gNMI Workload");
        leaf_params.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("spiffe san"),
        ));
        let now = ::time::OffsetDateTime::now_utc();
        leaf_params.not_before = now - ::time::Duration::days(1);
        leaf_params.not_after = now + ::time::Duration::days(1);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf cert");

        let ca_certs = opc_identity::parse_certs_pem(&ca_cert.pem()).expect("ca pem");
        let cert_chain =
            opc_identity::parse_certs_pem(&(leaf_cert.pem() + &ca_cert.pem())).expect("chain");

        let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        trust_bundles.insert(opc_identity::TrustBundle {
            trust_domain,
            certificates: ca_certs,
        });

        let identity =
            opc_identity::WorkloadIdentity::from_cert_der(cert_chain[0].as_ref(), &trust_bundles)
                .expect("identity");
        let private_key =
            opc_identity::parse_key_pem(&leaf_key.serialize_pem()).expect("leaf key pem");
        let svid = opc_identity::SvidDocument {
            spiffe_id: identity.spiffe_id.clone(),
            cert_chain,
            private_key,
            expires_at: opc_types::Timestamp::now_utc(),
        };

        IdentityState {
            identity,
            svid,
            trust_bundles,
        }
    }

    #[derive(Clone)]
    struct TlsTestConnector {
        addr: SocketAddr,
        config: Arc<tokio_rustls::rustls::ClientConfig>,
    }

    impl Service<Uri> for TlsTestConnector {
        type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _uri: Uri) -> Self::Future {
            let addr = self.addr;
            let config = Arc::clone(&self.config);
            Box::pin(async move {
                let tcp = TcpStream::connect(addr).await?;
                let connector = TlsConnector::from(config);
                let server_name = ServerName::try_from("localhost")?.to_owned();
                let tls = connector.connect(server_name, tcp).await?;
                Ok(TokioIo::new(tls))
            })
        }
    }

    async fn connect_client(
        addr: SocketAddr,
        identity_rx: watch::Receiver<Option<IdentityState>>,
    ) -> Grpc<tonic::transport::Channel> {
        let client_config = Arc::new(
            TlsConfigBuilder::new(identity_rx)
                .with_policy(peer_policy())
                .build_client_config()
                .expect("client tls config"),
        );
        let channel = Endpoint::from_static("http://gnmi.test")
            .connect_with_connector(TlsTestConnector {
                addr,
                config: client_config,
            })
            .await
            .expect("channel");
        Grpc::new(channel)
    }

    #[tokio::test]
    async fn production_listener_rejects_unconstrained_peer_policy() {
        let state =
            identity_state("spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0");
        let (_identity_tx, identity_rx) = watch::channel(Some(state));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let shutdown = ShutdownToken::new();

        let err = run_gnmi_tls_listener(
            server().await,
            listener,
            TlsBootstrap::new(RuntimeMode::Production, PeerPolicy::default()),
            identity_rx,
            shutdown,
            GnmiListenerConfig::default(),
        )
        .await
        .expect_err("unconstrained policy");

        assert!(matches!(
            err,
            GnmiListenerError::Transport(TransportError::UnconstrainedPeerPolicy {
                mode: RuntimeMode::Production
            })
        ));
    }

    #[tokio::test]
    async fn tls_listener_serves_authenticated_capabilities_over_real_mtls() {
        let state =
            identity_state("spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0");
        let (_identity_tx, identity_rx) = watch::channel(Some(state));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = ShutdownToken::new();
        let listener_task = tokio::spawn(run_gnmi_tls_listener(
            server().await,
            listener,
            TlsBootstrap::new(RuntimeMode::Production, peer_policy()),
            identity_rx.clone(),
            shutdown.clone(),
            GnmiListenerConfig {
                handshake_timeout: Duration::from_secs(5),
                incoming_channel_capacity: 4,
            },
        ));

        let mut grpc = connect_client(addr, identity_rx).await;
        grpc.ready().await.expect("capabilities ready");
        let response = grpc
            .unary(
                Request::new(gnmi::CapabilityRequest {
                    extension: Vec::new(),
                }),
                PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
                ProstCodec::<gnmi::CapabilityRequest, gnmi::CapabilityResponse>::default(),
            )
            .await
            .expect("capabilities")
            .into_inner();

        assert_eq!(response.g_nmi_version, "0.10.0");
        assert_eq!(response.supported_models.len(), 1);
        assert_eq!(response.supported_models[0].name, "demo-system");

        grpc.ready().await.expect("get ready");
        let get = grpc
            .unary(
                Request::new(gnmi::GetRequest {
                    prefix: None,
                    path: Vec::new(),
                    r#type: gnmi::get_request::DataType::All as i32,
                    encoding: gnmi::Encoding::JsonIetf as i32,
                    use_models: Vec::new(),
                    extension: Vec::new(),
                }),
                PathAndQuery::from_static("/gnmi.gNMI/Get"),
                ProstCodec::<gnmi::GetRequest, gnmi::GetResponse>::default(),
            )
            .await
            .expect("get")
            .into_inner();
        assert!(get.notification.is_empty());

        drop(grpc);
        shutdown.request_shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join")
            .expect("listener result");

        assert_eq!(result.accepted_connections, 1);
        assert_eq!(result.rejected_connections, 0);
        assert_eq!(result.failed_connections, 0);
    }
}
