mod common;

use opc_yanggen::rust::generate_rust;
use opc_yanggen::{
    CanonicalInput, GenerationInput, SchemaModule, SchemaNode, SchemaNodeKind, StackBudget,
    TypeRef, YangSourceLocation,
};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn build_input() -> CanonicalInput {
    let source = YangSourceLocation::new("gnmi-wire.yang", 1, 1);
    let module = SchemaModule {
        name: "example".to_string(),
        revision: "2026-06-15".to_string(),
        namespace: "urn:example".to_string(),
        prefix: "ex".to_string(),
        source: source.clone(),
        ..Default::default()
    };

    let nodes = vec![
        SchemaNode {
            path: "/ex:system".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Container,
            config: true,
            child_paths: vec![
                "/ex:system/ex:hostname".to_string(),
                "/ex:system/ex:secret".to_string(),
                "/ex:system/ex:interfaces".to_string(),
                "/ex:system/ex:routes".to_string(),
                "/ex:system/ex:uptime".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:hostname".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:secret".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            data_class: Some("security-secret".to_string()),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["name".to_string()],
            child_paths: vec![
                "/ex:system/ex:interfaces/ex:name".to_string(),
                "/ex:system/ex:interfaces/ex:mtu".to_string(),
                "/ex:system/ex:interfaces/ex:admin".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:name".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:mtu".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint16),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:interfaces/ex:admin".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Boolean),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::List,
            config: true,
            key_leaves: vec!["dest".to_string(), "next-hop".to_string()],
            child_paths: vec![
                "/ex:system/ex:routes/ex:dest".to_string(),
                "/ex:system/ex:routes/ex:next-hop".to_string(),
                "/ex:system/ex:routes/ex:metric".to_string(),
            ],
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes/ex:dest".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes/ex:next-hop".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::String),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:routes/ex:metric".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: true,
            type_ref: Some(TypeRef::Uint32),
            source: source.clone(),
            ..Default::default()
        },
        SchemaNode {
            path: "/ex:system/ex:uptime".to_string(),
            module: "example".to_string(),
            kind: SchemaNodeKind::Leaf,
            config: false,
            type_ref: Some(TypeRef::Uint32),
            source,
            ..Default::default()
        },
    ];

    let input = GenerationInput {
        profile: "test".to_string(),
        lockfile: opc_yanggen::ir::ModuleLockfile {
            profile: "test".to_string(),
            modules: vec![],
        },
        schema_modules: vec![module],
        nodes,
        constraints: vec![],
        unsupported_features: vec![],
        stack_budget: StackBudget::default(),
        stack_shapes: vec![],
    };

    let ir = opc_yanggen::compile(&input).unwrap();
    CanonicalInput {
        profile: opc_yanggen::emit::CanonicalProfile {
            generation: "test".to_string(),
            lockfile_mismatch: None,
        },
        locked_modules: vec![],
        schema_modules: ir.modules,
        nodes: ir.nodes,
        constraints: vec![],
        stack_shapes: ir.stack_shapes,
        stack_budget: ir.stack_budget,
        canonicalization_skipped: false,
        max_canonical_scan_stack_len: None,
    }
}

#[test]
fn generated_gnmi_wire_conformance() {
    let files = generate_rust(&build_input()).unwrap();

    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();

    for (name, content) in files {
        let name = if name == "mod.rs" {
            "lib.rs".to_string()
        } else {
            name
        };
        fs::write(src_dir.join(name), content).unwrap();
    }

    let workspace_dir = std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let cargo_toml = scratch_cargo_toml(&workspace_dir);
    fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

    let tests_dir = dir.path().join("tests");
    fs::create_dir(&tests_dir).unwrap();
    fs::write(tests_dir.join("gnmi_wire.rs"), GNMI_WIRE_TEST).unwrap();

    let status = Command::new("cargo")
        .arg("test")
        .env("RUSTFLAGS", "-Dwarnings")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
}

fn scratch_cargo_toml(workspace_dir: &std::path::Path) -> String {
    let path = |name: &str| workspace_dir.join(format!("crates/{name}"));
    let time_version = common::locked_version(workspace_dir, "time");
    let tonic_version = common::locked_version(workspace_dir, "tonic");
    let prost_version = common::locked_version(workspace_dir, "prost");
    let tokio_version = common::locked_version(workspace_dir, "tokio");
    let hyper_util_version = common::locked_version(workspace_dir, "hyper-util");
    let http_body_util_version = common::locked_version(workspace_dir, "http-body-util");
    let serde_version = common::locked_version(workspace_dir, "serde");
    let serde_json_version = common::locked_version(workspace_dir, "serde_json");
    let bytes_version = common::locked_version(workspace_dir, "bytes");
    let rcgen_version = common::locked_version(workspace_dir, "rcgen");
    format!(
        r#"
[package]
name = "generated-test"
version = "0.1.0"
edition = "2021"

[dependencies]
bytes = "={bytes_version}"
http-body-util = "={http_body_util_version}"
hyper-util = {{ version = "={hyper_util_version}", features = ["client", "tokio"] }}
prost = "={prost_version}"
rcgen = "={rcgen_version}"
serde = {{ version = "={serde_version}", features = ["derive"] }}
serde_json = "={serde_json_version}"
time = "={time_version}"
tokio = {{ version = "={tokio_version}", features = ["io-util", "macros", "net", "rt-multi-thread", "sync", "time"] }}
tokio-rustls = {{ version = "0.26", default-features = false, features = ["ring"] }}
tonic = {{ version = "={tonic_version}", default-features = false, features = ["channel", "codegen", "prost"] }}
opc-config-bus = {{ path = "{}" }}
opc-config-model = {{ path = "{}" }}
opc-data-governance = {{ path = "{}" }}
opc-gnmi-server = {{ path = "{}" }}
opc-identity = {{ path = "{}" }}
opc-mgmt-audit = {{ path = "{}" }}
opc-mgmt-authz = {{ path = "{}" }}
opc-mgmt-limits = {{ path = "{}" }}
opc-mgmt-opstate = {{ path = "{}" }}
opc-mgmt-schema = {{ path = "{}" }}
opc-mgmt-transport = {{ path = "{}" }}
opc-nacm = {{ path = "{}" }}
opc-redaction = {{ path = "{}" }}
opc-runtime = {{ path = "{}" }}
opc-tls = {{ path = "{}" }}
opc-types = {{ path = "{}" }}
"#,
        path("opc-config-bus").display(),
        path("opc-config-model").display(),
        path("opc-data-governance").display(),
        path("opc-gnmi-server").display(),
        path("opc-identity").display(),
        path("opc-mgmt-audit").display(),
        path("opc-mgmt-authz").display(),
        path("opc-mgmt-limits").display(),
        path("opc-mgmt-opstate").display(),
        path("opc-mgmt-schema").display(),
        path("opc-mgmt-transport").display(),
        path("opc-nacm").display(),
        path("opc-redaction").display(),
        path("opc-runtime").display(),
        path("opc-tls").display(),
        path("opc-types").display(),
    )
}

const GNMI_WIRE_TEST: &str = r####"
#![allow(deprecated)]

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use generated_test::types::{Interfaces, LeafPresence, Routes, RoutesKey, SecretLeaf, System};
use hyper_util::rt::TokioIo;
use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::YangPath;
use opc_gnmi_server::proto::{gnmi, gnmi_ext};
use opc_gnmi_server::{
    CapabilityProfile, CommitConfirmedExtension, ExtensionRegistry, GnmiConfigBinding,
    GnmiJsonProjectionError, GnmiJsonRenderer, GnmiJsonUpdate, GnmiListenerConfig,
    GnmiPatchApplicator, GnmiServer, GnmiVersion, ReadSelection,
    SupervisedGnmiTlsListenerConfig, GNMI_VERSION, OPC_COMMIT_CONFIRMED_EXTENSION_ID,
};
use opc_identity::IdentityState;
use opc_mgmt_audit::{AuditError, AuditEvent, AuditOutcome, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    operational_event_channel, OperationalError, OperationalEvent, OperationalEventReceiver,
    OperationalEventSender, OperationalEventSource, OperationalRequest, OperationalResponse,
    OperationalStateProvider, OperationalSubscriptionRequest, OperationalValue,
};
use opc_mgmt_schema::SchemaRegistry;
use opc_mgmt_transport::TlsBootstrap;
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, YangPathPattern};
use opc_redaction::metrics::METRICS;
use opc_runtime::{
    Readiness, RestartPolicy, RuntimeMode, RuntimeProfile, ShutdownPolicy, ShutdownToken,
    Supervisor, TaskHandle,
};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tonic::client::Grpc;
use tonic::codec::ProstCodec;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::codegen::http::Uri;
use tonic::codegen::Service;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request};

#[derive(Clone)]
struct FixedPolicy(NacmPolicy);

impl PolicySource for FixedPolicy {
    fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Default)]
struct CapturingAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl AuditSink for CapturingAudit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.events.lock().expect("audit").push(event.clone());
        Ok(())
    }
}

struct TestOperationalState;

impl OperationalStateProvider for TestOperationalState {
    fn get(&self, request: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        let path = uptime_yang_path();
        if request.paths().contains(&path) {
            Ok(OperationalResponse::new([OperationalValue::new(path, "123").expect("state json")]))
        } else {
            Ok(OperationalResponse::default())
        }
    }
}

#[derive(Default)]
struct CapturingOperationalEvents {
    requests: Mutex<Vec<OperationalSubscriptionRequest>>,
    senders: Mutex<Vec<OperationalEventSender>>,
}

impl CapturingOperationalEvents {
    async fn send_update(&self, value: &str) {
        for _ in 0..100 {
            if let Some(sender) = self.senders.lock().expect("senders").first().cloned() {
                sender
                    .send(OperationalEvent::Update(
                        OperationalValue::new(uptime_yang_path(), value).expect("event json"),
                    ))
                    .await
                    .expect("send operational event");
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("operational subscription was not registered");
    }
}

impl OperationalEventSource for CapturingOperationalEvents {
    fn subscribe(
        &self,
        request: &OperationalSubscriptionRequest,
    ) -> Result<OperationalEventReceiver, OperationalError> {
        self.requests.lock().expect("requests").push(request.clone());
        let (tx, rx) = operational_event_channel(request.max_queued_events());
        self.senders.lock().expect("senders").push(tx);
        Ok(rx)
    }
}

#[derive(Clone)]
struct TestBinding {
    bus: Arc<ConfigBus<System>>,
    policy: Arc<dyn PolicySource>,
    operational: Arc<dyn OperationalStateProvider>,
    events: Option<Arc<dyn OperationalEventSource>>,
}

impl GnmiConfigBinding<System> for TestBinding {
    fn config_bus(&self) -> Arc<ConfigBus<System>> {
        Arc::clone(&self.bus)
    }

    fn schema(&self) -> &'static dyn SchemaRegistry {
        generated_test::schema_registry::registry()
    }

    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<System>> {
        Arc::new(generated_test::gnmi_set::patcher())
    }

    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        Arc::clone(&self.operational)
    }

    fn operational_events(&self) -> Option<Arc<dyn OperationalEventSource>> {
        self.events.clone()
    }

    fn policy_source(&self) -> Arc<dyn PolicySource> {
        Arc::clone(&self.policy)
    }

    fn render_running_json(
        &self,
        config: &System,
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        generated_test::gnmi_json::renderer().render_running_json(config, selection)
    }
}

struct Harness {
    addr: SocketAddr,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    supervisor: Supervisor,
    handle: TaskHandle,
    bus: Arc<ConfigBus<System>>,
    audit: CapturingAudit,
}

impl Harness {
    async fn client(&self) -> Grpc<Channel> {
        connect_client(self.addr, self.identity_rx.clone()).await
    }

    async fn shutdown(self) {
        self.supervisor
            .shutdown_all(ShutdownPolicy::DrainWithTimeout(Duration::from_secs(2)))
            .await;
        assert!(!self.handle.is_running());
    }
}

async fn start_harness(
    policy: NacmPolicy,
    limits: MgmtLimits,
    events: Option<Arc<CapturingOperationalEvents>>,
) -> Harness {
    start_harness_with_extensions(policy, limits, events, ExtensionRegistry::default()).await
}

async fn start_harness_with_extensions(
    policy: NacmPolicy,
    limits: MgmtLimits,
    events: Option<Arc<CapturingOperationalEvents>>,
    extensions: ExtensionRegistry,
) -> Harness {
    let state =
        identity_state("spiffe://test-domain/tenant/test/ns/default/sa/gnmi/nf/amf/instance/0");
    let (_identity_tx, identity_rx) = watch::channel(Some(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let mut profile = RuntimeProfile::conformance("gnmi-wire");
    profile.drain_timeout = Duration::from_secs(2);
    let supervisor = Supervisor::new(profile, shutdown.clone());
    let bus = Arc::new(
        ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
            .await
            .expect("bus"),
    );
    let audit = CapturingAudit::default();
    let server = GnmiServer::new_with_audit(
        TestBinding {
            bus: Arc::clone(&bus),
            policy: Arc::new(FixedPolicy(policy)),
            operational: Arc::new(TestOperationalState),
            events: events
                .as_ref()
                .map(|events| Arc::clone(events) as Arc<dyn OperationalEventSource>),
        },
        limits,
        CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).expect("version")),
        extensions,
        Arc::new(audit.clone()),
    )
    .expect("server");
    let handle = opc_gnmi_server::spawn_gnmi_tls_listener(
        &supervisor,
        Arc::new(server),
        listener,
        TlsBootstrap::new(RuntimeMode::Conformance, peer_policy()),
        identity_rx.clone(),
        shutdown,
        SupervisedGnmiTlsListenerConfig {
            restart: RestartPolicy::no_restart(),
            listener: GnmiListenerConfig {
                handshake_timeout: Duration::from_secs(5),
                incoming_channel_capacity: 4,
            },
            ..Default::default()
        },
    )
    .await
    .expect("spawn listener");
    wait_for_readiness(&supervisor, Readiness::Ready).await;
    Harness {
        addr,
        identity_rx,
        supervisor,
        handle,
        bus,
        audit,
    }
}

fn initial_config() -> System {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("router1".to_string());
    system.secret = SecretLeaf::new(LeafPresence::Explicit("hunter2".to_string()));

    let mut eth0 = Interfaces::default();
    eth0.name = LeafPresence::Explicit("eth0".to_string());
    eth0.mtu = LeafPresence::Explicit(1500);
    eth0.admin = LeafPresence::Explicit(true);
    system.interfaces.insert("eth0".to_string(), eth0);

    let mut eth1 = Interfaces::default();
    eth1.name = LeafPresence::Explicit("eth1".to_string());
    eth1.mtu = LeafPresence::Explicit(9000);
    eth1.admin = LeafPresence::Explicit(false);
    system.interfaces.insert("eth1".to_string(), eth1);

    let mut route = Routes::default();
    route.dest = LeafPresence::Explicit("0.0.0.0/0".to_string());
    route.next_hop = LeafPresence::Explicit("10.0.0.1".to_string());
    route.metric = LeafPresence::Explicit(10);
    system.routes.insert(
        RoutesKey {
            dest: "0.0.0.0/0".to_string(),
            next_hop: "10.0.0.1".to_string(),
        },
        route,
    );

    system
}

fn peer_policy() -> PeerPolicy {
    PeerPolicy {
        allowed_trust_domains: Some(HashSet::from([opc_identity::TrustDomain::new("test-domain")
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
    let private_key = opc_identity::parse_key_pem(&leaf_key.serialize_pem()).expect("key pem");
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

async fn try_connect_client(
    addr: SocketAddr,
    identity_rx: watch::Receiver<Option<IdentityState>>,
) -> Result<Grpc<Channel>, tonic::transport::Error> {
    let client_config = Arc::new(
        TlsConfigBuilder::new(identity_rx)
            .with_policy(peer_policy())
            .build_client_config()
            .expect("client tls config"),
    );
    let channel = Endpoint::from_static("http://gnmi.test")
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(2))
        .connect_with_connector(TlsTestConnector {
            addr,
            config: client_config,
        })
        .await?;
    Ok(Grpc::new(channel))
}

async fn connect_client(
    addr: SocketAddr,
    identity_rx: watch::Receiver<Option<IdentityState>>,
) -> Grpc<Channel> {
    try_connect_client(addr, identity_rx)
        .await
        .expect("gNMI client")
}

async fn capabilities(grpc: &mut Grpc<Channel>) -> gnmi::CapabilityResponse {
    grpc.ready().await.expect("capabilities ready");
    grpc.unary(
        Request::new(gnmi::CapabilityRequest {
            extension: Vec::new(),
        }),
        PathAndQuery::from_static("/gnmi.gNMI/Capabilities"),
        ProstCodec::<gnmi::CapabilityRequest, gnmi::CapabilityResponse>::default(),
    )
    .await
    .expect("capabilities")
    .into_inner()
}

async fn get(
    grpc: &mut Grpc<Channel>,
    data_type: gnmi::get_request::DataType,
    path: Vec<gnmi::Path>,
) -> Result<gnmi::GetResponse, tonic::Status> {
    grpc.ready().await.expect("get ready");
    grpc.unary(
        Request::new(gnmi::GetRequest {
            prefix: None,
            path,
            r#type: data_type as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        }),
        PathAndQuery::from_static("/gnmi.gNMI/Get"),
        ProstCodec::<gnmi::GetRequest, gnmi::GetResponse>::default(),
    )
    .await
    .map(|response| response.into_inner())
}

async fn get_with_encoding(
    grpc: &mut Grpc<Channel>,
    encoding: gnmi::Encoding,
) -> Result<gnmi::GetResponse, tonic::Status> {
    grpc.ready().await.expect("get ready");
    grpc.unary(
        Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![hostname_path()],
            r#type: gnmi::get_request::DataType::Config as i32,
            encoding: encoding as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        }),
        PathAndQuery::from_static("/gnmi.gNMI/Get"),
        ProstCodec::<gnmi::GetRequest, gnmi::GetResponse>::default(),
    )
    .await
    .map(|response| response.into_inner())
}

async fn set(
    grpc: &mut Grpc<Channel>,
    request: gnmi::SetRequest,
) -> Result<gnmi::SetResponse, tonic::Status> {
    grpc.ready().await.expect("set ready");
    grpc.unary(
        Request::new(request),
        PathAndQuery::from_static("/gnmi.gNMI/Set"),
        ProstCodec::<gnmi::SetRequest, gnmi::SetResponse>::default(),
    )
    .await
    .map(|response| response.into_inner())
}

async fn open_subscribe(
    grpc: &mut Grpc<Channel>,
    rx: tokio::sync::mpsc::Receiver<gnmi::SubscribeRequest>,
) -> tonic::Streaming<gnmi::SubscribeResponse> {
    grpc.ready().await.expect("subscribe ready");
    grpc.streaming(
        Request::new(tonic::codegen::tokio_stream::wrappers::ReceiverStream::new(rx)),
        PathAndQuery::from_static("/gnmi.gNMI/Subscribe"),
        ProstCodec::<gnmi::SubscribeRequest, gnmi::SubscribeResponse>::default(),
    )
    .await
    .expect("subscribe")
    .into_inner()
}

async fn next_subscribe(
    stream: &mut tonic::Streaming<gnmi::SubscribeResponse>,
) -> gnmi::SubscribeResponse {
    tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("subscribe response timeout")
        .expect("subscribe message")
        .expect("subscribe response")
}

async fn wait_for_readiness(supervisor: &Supervisor, expected: Readiness) {
    for _ in 0..100 {
        if supervisor.readiness().await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("readiness did not reach {expected:?}");
}

fn module_registry() -> ModuleRegistry {
    let mut modules = ModuleRegistry::new();
    modules.register_module("example", "ex").expect("example module");
    modules
}

fn allow_all_read_subscribe_policy() -> NacmPolicy {
    let modules = module_registry();
    NacmPolicy::builder(opc_nacm::PolicyVersion::new(1))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/ex:system", &modules).expect("read root"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/ex:system/**", &modules).expect("read subtree"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Subscribe,
            YangPathPattern::parse("/ex:system", &modules).expect("subscribe root"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Subscribe,
            YangPathPattern::parse("/ex:system/**", &modules).expect("subscribe subtree"),
        ))
        .build()
}

fn deny_hostname_read_subscribe_policy() -> NacmPolicy {
    let modules = module_registry();
    NacmPolicy::builder(opc_nacm::PolicyVersion::new(2))
        .add_rule(NacmRule::deny(
            NacmAction::Read,
            YangPathPattern::parse("/ex:system/ex:hostname", &modules).expect("deny read"),
        ))
        .add_rule(NacmRule::deny(
            NacmAction::Subscribe,
            YangPathPattern::parse("/ex:system/ex:hostname", &modules).expect("deny subscribe"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/ex:system/**", &modules).expect("allow read subtree"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Subscribe,
            YangPathPattern::parse("/ex:system/**", &modules).expect("allow subscribe subtree"),
        ))
        .build()
}

fn path_elem(name: &str) -> gnmi::PathElem {
    gnmi::PathElem {
        name: name.to_string(),
        key: Default::default(),
    }
}

fn keyed_path_elem(name: &str, key: &str, value: &str) -> gnmi::PathElem {
    gnmi::PathElem {
        name: name.to_string(),
        key: [(key.to_string(), value.to_string())].into_iter().collect(),
    }
}

fn gnmi_path(elems: Vec<gnmi::PathElem>) -> gnmi::Path {
    gnmi::Path {
        element: Vec::new(),
        origin: String::new(),
        elem: elems,
        target: String::new(),
    }
}

fn hostname_path() -> gnmi::Path {
    gnmi_path(vec![path_elem("system"), path_elem("hostname")])
}

fn secret_path() -> gnmi::Path {
    gnmi_path(vec![path_elem("system"), path_elem("secret")])
}

fn uptime_path() -> gnmi::Path {
    gnmi_path(vec![path_elem("system"), path_elem("uptime")])
}

fn interface_path(name: &str) -> gnmi::Path {
    gnmi_path(vec![
        path_elem("system"),
        keyed_path_elem("interfaces", "name", name),
    ])
}

fn interface_mtu_path(name: &str) -> gnmi::Path {
    gnmi_path(vec![
        path_elem("system"),
        keyed_path_elem("interfaces", "name", name),
        path_elem("mtu"),
    ])
}

fn route_metric_path(dest: &str, next_hop: &str) -> gnmi::Path {
    gnmi_path(vec![
        path_elem("system"),
        gnmi::PathElem {
            name: "routes".to_string(),
            key: [
                ("dest".to_string(), dest.to_string()),
                ("next-hop".to_string(), next_hop.to_string()),
            ]
            .into_iter()
            .collect(),
        },
        path_elem("metric"),
    ])
}

fn uptime_yang_path() -> YangPath {
    YangPath::new("/ex:system/ex:uptime").expect("uptime path")
}

fn json_update(path: gnmi::Path, json: impl Into<Vec<u8>>) -> gnmi::Update {
    gnmi::Update {
        path: Some(path),
        value: None,
        val: Some(gnmi::TypedValue {
            value: Some(gnmi::typed_value::Value::JsonIetfVal(json.into())),
        }),
        duplicates: 0,
    }
}

fn commit_confirmed_extension(payload: CommitConfirmedExtension) -> gnmi_ext::Extension {
    gnmi_ext::Extension {
        ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
            gnmi_ext::RegisteredExtension {
                id: OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32,
                msg: payload.encode_payload(),
            },
        )),
    }
}

async fn wait_for_wire_hostname(harness: &Harness, expected: &str) {
    let expected = LeafPresence::Explicit(expected.to_string());
    for _ in 0..50 {
        if harness.bus.current_snapshot().config.hostname == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(harness.bus.current_snapshot().config.hostname, expected);
}

fn subscription_list(
    mode: gnmi::subscription_list::Mode,
    path: gnmi::Path,
    subscription_mode: gnmi::SubscriptionMode,
) -> gnmi::SubscriptionList {
    gnmi::SubscriptionList {
        prefix: None,
        subscription: vec![gnmi::Subscription {
            path: Some(path),
            mode: subscription_mode as i32,
            sample_interval: 10_000_000,
            suppress_redundant: false,
            heartbeat_interval: 0,
        }],
        qos: None,
        mode: mode as i32,
        allow_aggregation: false,
        use_models: Vec::new(),
        encoding: gnmi::Encoding::JsonIetf as i32,
        updates_only: false,
    }
}

async fn send_subscribe(
    tx: &tokio::sync::mpsc::Sender<gnmi::SubscribeRequest>,
    list: gnmi::SubscriptionList,
) {
    tx.send(gnmi::SubscribeRequest {
        request: Some(gnmi::subscribe_request::Request::Subscribe(list)),
        extension: Vec::new(),
    })
    .await
    .expect("send subscribe");
}

fn json_values(response: &gnmi::GetResponse) -> Vec<String> {
    response
        .notification
        .iter()
        .flat_map(|notification| &notification.update)
        .filter_map(|update| update.val.as_ref())
        .filter_map(|value| value.value.as_ref())
        .filter_map(|value| match value {
            gnmi::typed_value::Value::JsonIetfVal(bytes)
            | gnmi::typed_value::Value::JsonVal(bytes) => {
                Some(String::from_utf8(bytes.clone()).expect("json utf8"))
            }
            _ => None,
        })
        .collect()
}

fn subscribe_update_values(response: &gnmi::SubscribeResponse) -> Vec<String> {
    match response.response.as_ref().expect("subscribe response") {
        gnmi::subscribe_response::Response::Update(notification) => notification
            .update
            .iter()
            .filter_map(|update| update.val.as_ref())
            .filter_map(|value| value.value.as_ref())
            .filter_map(|value| match value {
                gnmi::typed_value::Value::JsonIetfVal(bytes)
                | gnmi::typed_value::Value::JsonVal(bytes) => {
                    Some(String::from_utf8(bytes.clone()).expect("json utf8"))
                }
                _ => None,
            })
            .collect(),
        gnmi::subscribe_response::Response::SyncResponse(_) => Vec::new(),
        gnmi::subscribe_response::Response::Error(_) => Vec::new(),
    }
}

fn is_sync(response: &gnmi::SubscribeResponse) -> bool {
    matches!(
        response.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    )
}

fn listener_event_count(event: &str) -> u64 {
    METRICS
        .gnmi_listener_events_total
        .lock()
        .expect("metrics")
        .get(&("gnmi-tls".to_string(), event.to_string()))
        .copied()
        .unwrap_or_default()
}

fn rpc_success_count(operation: &str) -> u64 {
    METRICS
        .gnmi_rpc_requests_total
        .lock()
        .expect("metrics")
        .get(&(operation.to_string(), "success".to_string()))
        .copied()
        .unwrap_or_default()
}

#[tokio::test]
async fn generated_stack_serves_gnmi_over_real_mtls() {
    let events = Arc::new(CapturingOperationalEvents::default());
    let get_success_before = rpc_success_count("Get");
    let start_before = listener_event_count("start");
    let harness = start_harness(
        allow_all_read_subscribe_policy(),
        MgmtLimits::default(),
        Some(Arc::clone(&events)),
    )
    .await;
    assert!(listener_event_count("start") > start_before);

    let mut grpc = harness.client().await;
    let caps = capabilities(&mut grpc).await;
    assert_eq!(caps.g_nmi_version, "0.10.0");
    assert_eq!(caps.supported_models.len(), 1);
    assert_eq!(caps.supported_models[0].name, "example");
    assert_eq!(
        caps.supported_encodings,
        vec![gnmi::Encoding::JsonIetf as i32, gnmi::Encoding::Json as i32]
    );

    let config = get(
        &mut grpc,
        gnmi::get_request::DataType::Config,
        vec![hostname_path()],
    )
    .await
    .expect("get config");
    assert_eq!(json_values(&config), vec![r#""router1""#.to_string()]);

    let state = get(
        &mut grpc,
        gnmi::get_request::DataType::State,
        vec![uptime_path()],
    )
    .await
    .expect("get state");
    assert_eq!(json_values(&state), vec!["123".to_string()]);

    let all = get(&mut grpc, gnmi::get_request::DataType::All, Vec::new())
        .await
        .expect("get all");
    let all_values = json_values(&all);
    assert!(all_values.contains(&r#""router1""#.to_string()));
    assert!(all_values.contains(&"123".to_string()));
    assert!(!format!("{all:?}").contains("hunter2"));

    let response = set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: vec![interface_path("eth1")],
            replace: vec![json_update(hostname_path(), br#""router2""#.to_vec())],
            update: vec![json_update(interface_mtu_path("eth0"), b"1600".to_vec())],
            union_replace: vec![json_update(
                route_metric_path("0.0.0.0/0", "10.0.0.1"),
                b"11".to_vec(),
            )],
            extension: Vec::new(),
        },
    )
    .await
    .expect("set");
    assert_eq!(response.response.len(), 4);
    let snapshot = harness.bus.current_snapshot();
    assert_eq!(snapshot.config.hostname, LeafPresence::Explicit("router2".to_string()));
    assert!(!snapshot.config.interfaces.contains_key("eth1"));
    assert_eq!(
        snapshot.config.interfaces["eth0"].mtu,
        LeafPresence::Explicit(1600)
    );

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    send_subscribe(
        &tx,
        subscription_list(
            gnmi::subscription_list::Mode::Once,
            hostname_path(),
            gnmi::SubscriptionMode::Sample,
        ),
    )
    .await;
    drop(tx);
    let mut once = open_subscribe(&mut harness.client().await, rx).await;
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut once).await),
        vec![r#""router2""#.to_string()]
    );
    assert!(is_sync(&next_subscribe(&mut once).await));

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    send_subscribe(
        &tx,
        subscription_list(
            gnmi::subscription_list::Mode::Poll,
            hostname_path(),
            gnmi::SubscriptionMode::Sample,
        ),
    )
    .await;
    let mut poll = open_subscribe(&mut harness.client().await, rx).await;
    assert!(is_sync(&next_subscribe(&mut poll).await));
    tx.send(gnmi::SubscribeRequest {
        request: Some(gnmi::subscribe_request::Request::Poll(gnmi::Poll {})),
        extension: Vec::new(),
    })
    .await
    .expect("send poll");
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut poll).await),
        vec![r#""router2""#.to_string()]
    );
    assert!(is_sync(&next_subscribe(&mut poll).await));
    drop(tx);

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    send_subscribe(
        &tx,
        subscription_list(
            gnmi::subscription_list::Mode::Stream,
            hostname_path(),
            gnmi::SubscriptionMode::Sample,
        ),
    )
    .await;
    let mut sample = open_subscribe(&mut harness.client().await, rx).await;
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut sample).await),
        vec![r#""router2""#.to_string()]
    );
    assert!(is_sync(&next_subscribe(&mut sample).await));
    drop(tx);

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    send_subscribe(
        &tx,
        subscription_list(
            gnmi::subscription_list::Mode::Stream,
            hostname_path(),
            gnmi::SubscriptionMode::OnChange,
        ),
    )
    .await;
    let mut config_change = open_subscribe(&mut harness.client().await, rx).await;
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut config_change).await),
        vec![r#""router2""#.to_string()]
    );
    assert!(is_sync(&next_subscribe(&mut config_change).await));
    set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(hostname_path(), br#""router3""#.to_vec())],
            union_replace: Vec::new(),
            extension: Vec::new(),
        },
    )
    .await
    .expect("set on-change");
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut config_change).await),
        vec![r#""router3""#.to_string()]
    );
    drop(tx);

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    send_subscribe(
        &tx,
        subscription_list(
            gnmi::subscription_list::Mode::Stream,
            uptime_path(),
            gnmi::SubscriptionMode::OnChange,
        ),
    )
    .await;
    let mut op_change = open_subscribe(&mut harness.client().await, rx).await;
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut op_change).await),
        vec!["123".to_string()]
    );
    assert!(is_sync(&next_subscribe(&mut op_change).await));
    events.send_update("321").await;
    assert_eq!(
        subscribe_update_values(&next_subscribe(&mut op_change).await),
        vec!["321".to_string()]
    );
    drop(tx);

    assert!(rpc_success_count("Get") > get_success_before);
    let audit = harness.audit.events.lock().expect("audit").clone();
    assert!(audit.iter().any(|event| event.outcome == AuditOutcome::Success));
    let audit_debug = format!("{audit:?}");
    assert!(!audit_debug.contains("hunter2"));
    assert!(!audit_debug.contains("router3"));
    harness.shutdown().await;
}

#[tokio::test]
async fn generated_stack_supports_commit_confirmed_extension_over_real_mtls() {
    let harness = start_harness_with_extensions(
        allow_all_read_subscribe_policy(),
        MgmtLimits::default(),
        None,
        ExtensionRegistry::with_commit_confirmed().expect("registry"),
    )
    .await;
    let mut grpc = harness.client().await;

    let caps = capabilities(&mut grpc).await;
    assert_eq!(caps.extension.len(), 1);
    let Some(gnmi_ext::extension::Ext::RegisteredExt(extension)) = caps.extension[0].ext.as_ref()
    else {
        panic!("expected registered extension");
    };
    assert_eq!(extension.id, OPC_COMMIT_CONFIRMED_EXTENSION_ID as i32);
    assert!(extension.msg.is_empty());

    set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(hostname_path(), br#""wire-parent""#.to_vec())],
            union_replace: Vec::new(),
            extension: Vec::new(),
        },
    )
    .await
    .expect("parent commit");

    set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(hostname_path(), br#""wire-confirmed""#.to_vec())],
            union_replace: Vec::new(),
            extension: vec![commit_confirmed_extension(CommitConfirmedExtension::begin(
                Duration::from_millis(120),
            )
            .expect("payload"))],
        },
    )
    .await
    .expect("begin confirmed");
    assert_eq!(
        harness.bus.current_snapshot().config.hostname,
        LeafPresence::Explicit("wire-confirmed".to_string())
    );

    let confirm = set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: Vec::new(),
            union_replace: Vec::new(),
            extension: vec![commit_confirmed_extension(CommitConfirmedExtension::confirm())],
        },
    )
    .await
    .expect("confirm");
    assert!(confirm.response.is_empty());
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(
        harness.bus.current_snapshot().config.hostname,
        LeafPresence::Explicit("wire-confirmed".to_string())
    );

    set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(hostname_path(), br#""wire-cancelled""#.to_vec())],
            union_replace: Vec::new(),
            extension: vec![commit_confirmed_extension(CommitConfirmedExtension::begin(
                Duration::from_secs(30),
            )
            .expect("payload"))],
        },
    )
    .await
    .expect("begin to cancel");
    set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: Vec::new(),
            union_replace: Vec::new(),
            extension: vec![commit_confirmed_extension(CommitConfirmedExtension::cancel())],
        },
    )
    .await
    .expect("cancel");
    wait_for_wire_hostname(&harness, "wire-confirmed").await;

    harness.shutdown().await;
}

#[tokio::test]
async fn generated_stack_fails_closed_without_wire_leaks() {
    let harness = start_harness(
        deny_hostname_read_subscribe_policy(),
        MgmtLimits::default(),
        None,
    )
    .await;
    let mut grpc = harness.client().await;

    let denied = get(
        &mut grpc,
        gnmi::get_request::DataType::Config,
        vec![hostname_path()],
    )
    .await
    .expect("denied read is empty success");
    assert!(denied.notification.is_empty());
    assert!(!format!("{denied:?}").contains("router1"));

    let secret = get(
        &mut grpc,
        gnmi::get_request::DataType::Config,
        vec![secret_path()],
    )
    .await
    .expect("redacted secret read");
    assert!(!format!("{secret:?}").contains("hunter2"));

    let unsupported = get_with_encoding(&mut grpc, gnmi::Encoding::Proto)
        .await
        .unwrap_err();
    assert_eq!(unsupported.code(), Code::Unimplemented);
    assert_eq!(unsupported.message(), "gNMI operation is not supported");

    let extension = set(
        &mut grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(hostname_path(), br#""router4""#.to_vec())],
            union_replace: Vec::new(),
            extension: vec![gnmi_ext::Extension {
                ext: Some(gnmi_ext::extension::Ext::RegisteredExt(
                    gnmi_ext::RegisteredExtension {
                        id: gnmi_ext::ExtensionId::EidExperimental as i32,
                        msg: b"secret-extension-payload".to_vec(),
                    },
                )),
            }],
        },
    )
    .await
    .unwrap_err();
    assert_eq!(extension.code(), Code::Unimplemented);
    assert!(!extension.message().contains("secret-extension-payload"));

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut list = subscription_list(
        gnmi::subscription_list::Mode::Once,
        hostname_path(),
        gnmi::SubscriptionMode::Sample,
    );
    list.qos = Some(gnmi::QosMarking { marking: 46 });
    send_subscribe(&tx, list).await;
    drop(tx);
    let mut stream = open_subscribe(&mut harness.client().await, rx).await;
    let status = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("qos status timeout")
        .expect_err("qos should fail closed");
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(status.message(), "gNMI operation is not supported");

    let audit_debug = format!("{:?}", harness.audit.events.lock().expect("audit"));
    assert!(!audit_debug.contains("secret-extension-payload"));
    assert!(!audit_debug.contains("hunter2"));
    harness.shutdown().await;

    let limited = start_harness(
        allow_all_read_subscribe_policy(),
        MgmtLimits {
            max_value_bytes: 8,
            ..Default::default()
        },
        None,
    )
    .await;
    let mut limited_grpc = limited.client().await;
    let too_large = set(
        &mut limited_grpc,
        gnmi::SetRequest {
            prefix: None,
            delete: Vec::new(),
            replace: Vec::new(),
            update: vec![json_update(hostname_path(), br#""secret-too-long""#.to_vec())],
            union_replace: Vec::new(),
            extension: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(too_large.code(), Code::InvalidArgument);
    assert_eq!(too_large.message(), "invalid gNMI request");
    assert!(!too_large.message().contains("secret-too-long"));
    assert!(!format!("{:?}", limited.audit.events.lock().expect("audit"))
        .contains("secret-too-long"));
    limited.shutdown().await;
}

#[tokio::test]
async fn generated_stack_enforces_session_limit_and_drains() {
    let rejected_before = listener_event_count("rejected");
    let harness = start_harness(
        allow_all_read_subscribe_policy(),
        MgmtLimits {
            max_sessions: 1,
            ..Default::default()
        },
        None,
    )
    .await;

    let mut first = harness.client().await;
    assert_eq!(capabilities(&mut first).await.g_nmi_version, "0.10.0");

    let second = tokio::time::timeout(
        Duration::from_secs(3),
        try_connect_client(harness.addr, harness.identity_rx.clone()),
    )
    .await
    .expect("second connection timeout");
    let err = match second {
        Ok(_) => panic!("second session should be rejected"),
        Err(err) => err,
    };
    let rendered = err.to_string();
    assert!(!rendered.contains("spiffe://"));
    assert!(!rendered.contains("tenant/test"));
    assert!(listener_event_count("rejected") > rejected_before);

    drop(first);
    harness.shutdown().await;
}
"####;
