use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{
    AuthStrength, ConfigError, OpcConfig, TransportType, TrustedPrincipal, ValidationContext,
    ValidationError, WorkloadIdentity, YangPath,
};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    OperationalError, OperationalRequest, OperationalResponse, OperationalValue,
};
use opc_mgmt_schema::{
    DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_netconf_server::binding::{StartupDatastore, StartupDatastoreError};
use opc_netconf_server::framing::{base10, base11};
use opc_netconf_server::{
    BindingError, EditConfigCandidate, EditConfigError, EditConfigRequest, NetconfConfigBinding,
    NetconfGetSchemaRequest, NetconfMonitoringCapability, ReadOnlyNetconfServer, ReadSelection,
    SessionConfig, SessionError, SessionFraming, SessionRegistry, SessionResult,
    WithDefaultsCapability, WithDefaultsMode, YangLibraryCapability, NETCONF_BASE_1_0,
    NETCONF_BASE_1_1,
};
use opc_types::{SchemaDigest, TenantId};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

const WRITABLE_RUNNING_1_0: &str = "urn:ietf:params:netconf:capability:writable-running:1.0";
const CANDIDATE_1_0: &str = "urn:ietf:params:netconf:capability:candidate:1.0";
const CONFIRMED_COMMIT_1_1: &str = "urn:ietf:params:netconf:capability:confirmed-commit:1.1";
const STARTUP_1_0: &str = "urn:ietf:params:netconf:capability:startup:1.0";

const CLIENT_HELLO_BASE10: &str = include_str!("fixtures/conformance/client-hello-base10.xml");
const CLIENT_HELLO_BASE11: &str = include_str!("fixtures/conformance/client-hello-base11.xml");
const CLOSE_SESSION: &str = include_str!("fixtures/conformance/close-session.xml");

type ConformanceServer =
    ReadOnlyNetconfServer<ConformanceConfig, ConformanceBinding, FixedPolicy, NoopAudit>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConformanceConfig {
    hostname: String,
    secret: String,
}

impl OpcConfig for ConformanceConfig {
    type Delta = ();

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([9u8; 32])
    }

    fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(Vec::new())
    }

    fn changed_paths(
        &self,
        previous: &Self,
        _deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        let mut paths = Vec::new();
        if self.hostname != previous.hostname {
            paths.push(YangPath::new("/sys:system/sys:hostname").expect("hostname path"));
        }
        if self.secret != previous.secret {
            paths.push(YangPath::new("/sys:system/sys:secret").expect("secret path"));
        }
        Ok(paths)
    }

    fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

struct ConformanceRegistry;

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
        child_paths: &[
            "/sys:system/sys:hostname",
            "/sys:system/sys:secret",
            "/sys:system/sys:uptime",
        ],
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
    NodeMeta {
        path: "/sys:system/sys:secret",
        module: "demo-system",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: &[],
        data_class: DataClass::SecuritySecret,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    },
    NodeMeta {
        path: "/sys:system/sys:uptime",
        module: "demo-system",
        kind: NodeKind::Leaf,
        config: false,
        leaf_type: Some(LeafType::Int64),
        key_leaves: &[],
        data_class: DataClass::Operational,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    },
];

impl SchemaRegistry for ConformanceRegistry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:conformance"
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

static REGISTRY: ConformanceRegistry = ConformanceRegistry;

struct ConformanceBinding {
    bus: Arc<ConfigBus<ConformanceConfig>>,
    startup: Arc<MemoryStartup>,
    observed_with_defaults: Arc<Mutex<Vec<WithDefaultsMode>>>,
}

impl NetconfConfigBinding<ConformanceConfig> for ConformanceBinding {
    fn config_bus(&self) -> Arc<ConfigBus<ConformanceConfig>> {
        Arc::clone(&self.bus)
    }

    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        &REGISTRY
    }

    fn writable_running_capability(&self) -> bool {
        true
    }

    fn candidate_datastore_capability(&self) -> bool {
        true
    }

    fn startup_datastore(&self) -> Option<&dyn StartupDatastore<ConformanceConfig>> {
        Some(self.startup.as_ref())
    }

    fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
        Some(
            WithDefaultsCapability::new(WithDefaultsMode::Trim, [WithDefaultsMode::ReportAll])
                .expect("valid with-defaults capability"),
        )
    }

    fn yang_library_capability(&self) -> Option<YangLibraryCapability> {
        Some(YangLibraryCapability::new("conformance-content-id").expect("content id"))
    }

    fn netconf_monitoring_capability(&self) -> Option<NetconfMonitoringCapability> {
        Some(NetconfMonitoringCapability)
    }

    fn render_running_config(
        &self,
        config: &ConformanceConfig,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        Ok(render_config(
            config,
            selection,
            None,
            ReadSelection::new(&[]),
        ))
    }

    fn render_running_config_with_defaults(
        &self,
        config: &ConformanceConfig,
        selection: ReadSelection<'_>,
        mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        self.observed_with_defaults
            .lock()
            .expect("with-defaults mutex")
            .push(mode);
        Ok(render_config(
            config,
            selection,
            None,
            ReadSelection::new(&[]),
        ))
    }

    fn get_operational_state(
        &self,
        request: &OperationalRequest,
    ) -> Result<OperationalResponse, OperationalError> {
        let values = request
            .paths()
            .iter()
            .filter(|path| path.as_str() == "/sys:system/sys:uptime")
            .map(|path| OperationalValue::new(path.clone(), "12345").expect("valid JSON value"))
            .collect::<Vec<_>>();
        Ok(OperationalResponse::new(values))
    }

    fn render_get_data(
        &self,
        config: &ConformanceConfig,
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        operational_selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        Ok(render_config(
            config,
            config_selection,
            Some(operational),
            operational_selection,
        ))
    }

    fn render_get_data_with_defaults(
        &self,
        config: &ConformanceConfig,
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        operational_selection: ReadSelection<'_>,
        mode: WithDefaultsMode,
    ) -> Result<String, BindingError> {
        self.observed_with_defaults
            .lock()
            .expect("with-defaults mutex")
            .push(mode);
        self.render_get_data(config, config_selection, operational, operational_selection)
    }

    fn render_yang_library(&self, selection: ReadSelection<'_>) -> Result<String, BindingError> {
        if !selection
            .schema_paths()
            .iter()
            .any(|path| path.starts_with("/yanglib:yang-library"))
        {
            return Ok(String::new());
        }
        Ok(r#"<yanglib:yang-library xmlns:yanglib="urn:ietf:params:xml:ns:yang:ietf-yang-library"><yanglib:content-id>conformance-content-id</yanglib:content-id></yanglib:yang-library>"#.to_string())
    }

    fn render_netconf_monitoring(
        &self,
        selection: ReadSelection<'_>,
    ) -> Result<String, BindingError> {
        if !selection
            .schema_paths()
            .iter()
            .any(|path| path.starts_with("/ncm:netconf-state"))
        {
            return Ok(String::new());
        }
        Ok(r#"<ncm:netconf-state xmlns:ncm="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><ncm:schemas><ncm:schema><ncm:identifier>demo-system</ncm:identifier><ncm:version>2026-06-13</ncm:version><ncm:format>yang</ncm:format><ncm:namespace>urn:opc:demo</ncm:namespace><ncm:location>NETCONF</ncm:location></ncm:schema></ncm:schemas></ncm:netconf-state>"#.to_string())
    }

    fn get_schema(
        &self,
        request: &NetconfGetSchemaRequest,
    ) -> Result<String, opc_netconf_server::GetSchemaError> {
        if request.identifier == "demo-system"
            && request.version.as_deref() == Some("2026-06-13")
            && request.format == "yang"
        {
            Ok(r#"module demo-system { namespace "urn:opc:demo"; prefix sys; }"#.to_string())
        } else {
            Err(opc_netconf_server::GetSchemaError::NotFound)
        }
    }

    fn build_edit_config_candidate(
        &self,
        running: &ConformanceConfig,
        request: &EditConfigRequest,
    ) -> Result<EditConfigCandidate<ConformanceConfig>, EditConfigError> {
        let mut candidate = running.clone();
        candidate.hostname = extract_hostname(&request.config_xml)?;
        Ok(EditConfigCandidate::new(
            candidate,
            [YangPath::new("/sys:system/sys:hostname").expect("hostname path")],
        ))
    }
}

#[derive(Default)]
struct MemoryStartup {
    config: Mutex<Option<ConformanceConfig>>,
}

impl StartupDatastore<ConformanceConfig> for MemoryStartup {
    fn load_startup_config(&self) -> Result<Option<ConformanceConfig>, StartupDatastoreError> {
        Ok(self.config.lock().expect("startup mutex").clone())
    }

    fn store_startup_config(
        &self,
        config: &ConformanceConfig,
    ) -> Result<(), StartupDatastoreError> {
        *self.config.lock().expect("startup mutex") = Some(config.clone());
        Ok(())
    }

    fn delete_startup_supported(&self) -> bool {
        true
    }

    fn delete_startup_config(&self) -> Result<(), StartupDatastoreError> {
        *self.config.lock().expect("startup mutex") = None;
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct NoopAudit;

impl AuditSink for NoopAudit {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}

struct FixedPolicy(NacmPolicy);

impl PolicySource for FixedPolicy {
    fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn conformance_harness_advertised_capabilities_match_behavior() {
    REGISTRY.self_check().expect("test registry is consistent");
    let (server, _) = conformance_server().await;

    let hello = server.server_hello(NonZeroU32::new(77));

    assert!(hello.contains(NETCONF_BASE_1_0));
    assert!(hello.contains(NETCONF_BASE_1_1));
    assert!(hello.contains(WRITABLE_RUNNING_1_0));
    assert!(hello.contains(CANDIDATE_1_0));
    assert!(hello.contains(CONFIRMED_COMMIT_1_1));
    assert!(hello.contains(STARTUP_1_0));
    assert!(hello.contains("capability:with-defaults:1.0?basic-mode=trim"));
    assert!(hello.contains("capability:yang-library:1.1"));
    assert!(hello.contains("ietf-netconf-monitoring"));
    assert!(!hello.contains("capability:xpath"));
    assert!(!hello.contains("notification"));
    assert!(!hello.contains("call-home"));
    assert!(!hello.contains("get-data"));
    assert!(!hello.contains("edit-data"));
}

#[tokio::test]
async fn conformance_harness_base10_read_and_xpath_flow() {
    let (mut client, task, _) = spawn_session(77).await;
    let server_hello = read_base10_frame(&mut client).await;
    assert!(server_hello.contains(NETCONF_BASE_1_0));
    write_base10(&mut client, CLIENT_HELLO_BASE10).await;

    write_base10(
        &mut client,
        include_str!("fixtures/conformance/get-config-running-subtree.xml"),
    )
    .await;
    let reply = read_base10_frame(&mut client).await;
    assert_ok_data(&reply);
    assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
    assert_no_secret(&reply);

    write_base10(
        &mut client,
        include_str!("fixtures/conformance/get-running-xpath.xml"),
    )
    .await;
    let reply = read_base10_frame(&mut client).await;
    assert_ok_data(&reply);
    assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
    assert!(reply.contains("<sys:uptime>12345</sys:uptime>"));
    assert_no_secret(&reply);

    write_base10(&mut client, CLOSE_SESSION).await;
    let reply = read_base10_frame(&mut client).await;
    assert_ok(&reply);

    let result = task.await.expect("session task").expect("session succeeds");
    assert_eq!(result.framing, SessionFraming::Base10);
    assert_eq!(result.rpc_count, 3);
}

#[tokio::test]
async fn conformance_harness_base11_write_candidate_startup_confirmed_flow() {
    let (mut client, task, observed_with_defaults) = spawn_session(78).await;
    let server_hello = read_base10_frame(&mut client).await;
    assert!(server_hello.contains(NETCONF_BASE_1_1));
    write_base10(&mut client, CLIENT_HELLO_BASE11).await;

    rpc11(
        &mut client,
        include_str!("fixtures/conformance/edit-running-hostname.xml"),
    )
    .await;
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-running.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-running</sys:hostname>"));
    assert_no_secret(&reply);

    rpc11(
        &mut client,
        include_str!("fixtures/conformance/edit-candidate-hostname.xml"),
    )
    .await;
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-candidate.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-candidate</sys:hostname>"));
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-running.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-running</sys:hostname>"));

    rpc11(&mut client, include_str!("fixtures/conformance/commit.xml")).await;
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-running.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-candidate</sys:hostname>"));

    rpc11(
        &mut client,
        include_str!("fixtures/conformance/copy-running-to-startup.xml"),
    )
    .await;
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-startup.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-candidate</sys:hostname>"));

    rpc11(
        &mut client,
        include_str!("fixtures/conformance/edit-candidate-confirmed-hostname.xml"),
    )
    .await;
    rpc11(
        &mut client,
        include_str!("fixtures/conformance/commit-confirmed.xml"),
    )
    .await;
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-running.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-confirmed</sys:hostname>"));
    rpc11(
        &mut client,
        include_str!("fixtures/conformance/cancel-commit.xml"),
    )
    .await;
    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-running.xml"),
    )
    .await;
    assert!(reply.contains("<sys:hostname>amf-candidate</sys:hostname>"));

    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-schema-demo.xml"),
    )
    .await;
    assert!(reply.contains("module demo-system"));

    let reply = rpc11(
        &mut client,
        include_str!("fixtures/conformance/get-config-with-defaults-trim.xml"),
    )
    .await;
    assert_ok_data(&reply);
    assert!(observed_with_defaults
        .lock()
        .expect("with-defaults mutex")
        .contains(&WithDefaultsMode::Trim));

    write_base11(&mut client, CLOSE_SESSION).await;
    let reply = read_base11_frame(&mut client).await;
    assert_ok(&reply);

    let result = task.await.expect("session task").expect("session succeeds");
    assert_eq!(result.framing, SessionFraming::Base11);
    assert_eq!(result.rpc_count, 17);
}

async fn conformance_server() -> (Arc<ConformanceServer>, Arc<Mutex<Vec<WithDefaultsMode>>>) {
    let bus = Arc::new(
        ConfigBus::new_dev_only(
            ConformanceConfig {
                hostname: "amf-1".to_string(),
                secret: "do-not-leak".to_string(),
            },
            MockManagedDatastore::new(),
        )
        .await
        .expect("config bus"),
    );
    let observed_with_defaults = Arc::new(Mutex::new(Vec::new()));
    let binding = ConformanceBinding {
        bus,
        startup: Arc::new(MemoryStartup::default()),
        observed_with_defaults: Arc::clone(&observed_with_defaults),
    };
    let server = ReadOnlyNetconfServer::new(
        binding,
        FixedPolicy(policy_allow_system_discovery_and_exec_but_deny_secret()),
        NoopAudit,
        TransportType::NetconfTls,
    )
    .expect("NETCONF server");
    (Arc::new(server), observed_with_defaults)
}

async fn spawn_session(
    session_id: u64,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<Result<SessionResult, SessionError>>,
    Arc<Mutex<Vec<WithDefaultsMode>>>,
) {
    let (server, observed_with_defaults) = conformance_server().await;
    let principal = principal();
    let sessions = Arc::new(SessionRegistry::new());
    let (client, mut server_stream) = tokio::io::duplex(65_536);
    let task = tokio::spawn({
        let server = Arc::clone(&server);
        let sessions = Arc::clone(&sessions);
        async move {
            opc_netconf_server::run_read_only_session_with_registry(
                server.as_ref(),
                &principal,
                &mut server_stream,
                SessionConfig {
                    limits: MgmtLimits::default(),
                    frame_timeout: Duration::from_secs(5),
                },
                session_id,
                sessions.as_ref(),
            )
            .await
        }
    });
    (client, task, observed_with_defaults)
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User("operator".to_string()),
        TenantId::new("tenant-a").expect("tenant"),
    )
    .with_auth_strength(AuthStrength::MutualTls)
}

fn policy_allow_system_discovery_and_exec_but_deny_secret() -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    modules
        .register_module("demo-system", "sys")
        .expect("demo module");
    modules
        .register_module("ietf-netconf", "nc")
        .expect("NETCONF module");
    modules
        .register_module("ietf-yang-library", "yanglib")
        .expect("yang-library module");
    modules
        .register_module("ietf-netconf-monitoring", "ncm")
        .expect("monitoring module");

    let mut builder = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::deny(
            NacmAction::Read,
            YangPathPattern::parse("/sys:system/sys:secret", &modules).expect("deny secret path"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/sys:system/**", &modules).expect("allow system path"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/yanglib:yang-library/**", &modules)
                .expect("allow yang-library path"),
        ))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/ncm:netconf-state/**", &modules)
                .expect("allow monitoring path"),
        ));

    for action in [
        NacmAction::Create,
        NacmAction::Update,
        NacmAction::Replace,
        NacmAction::Delete,
    ] {
        builder = builder
            .add_rule(NacmRule::allow(
                action,
                YangPathPattern::parse("/sys:system", &modules).expect("allow system root path"),
            ))
            .add_rule(NacmRule::allow(
                action,
                YangPathPattern::parse("/sys:system/**", &modules).expect("allow system path"),
            ));
    }

    for path in [
        "/nc:close-session",
        "/nc:edit-config",
        "/nc:kill-session",
        "/nc:lock",
        "/nc:unlock",
        "/nc:validate",
        "/nc:commit",
        "/nc:cancel-commit",
        "/nc:discard-changes",
        "/nc:copy-config",
        "/nc:delete-config",
    ] {
        builder = builder.add_rule(NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(path, &modules).expect("allow exec path"),
        ));
    }
    builder.build()
}

fn render_config(
    config: &ConformanceConfig,
    config_selection: ReadSelection<'_>,
    operational: Option<&OperationalResponse>,
    operational_selection: ReadSelection<'_>,
) -> String {
    let wants_config = config_selection
        .schema_paths()
        .iter()
        .any(|path| path.starts_with("/sys:system"));
    let wants_operational = operational_selection
        .schema_paths()
        .iter()
        .any(|path| path.starts_with("/sys:system"));
    if !wants_config && !wants_operational {
        return String::new();
    }

    let mut out = String::from(r#"<sys:system xmlns:sys="urn:opc:demo">"#);
    if config_selection.contains("/sys:system/sys:hostname") {
        out.push_str("<sys:hostname>");
        out.push_str(&opc_netconf_server::xml_escape(&config.hostname));
        out.push_str("</sys:hostname>");
    }
    if config_selection.contains("/sys:system/sys:secret") {
        out.push_str("<sys:secret>******</sys:secret>");
    }
    if operational_selection.contains("/sys:system/sys:uptime") {
        if let Some(raw) = operational.and_then(operational_uptime) {
            out.push_str("<sys:uptime>");
            out.push_str(&opc_netconf_server::xml_escape(&raw));
            out.push_str("</sys:uptime>");
        }
    }
    out.push_str("</sys:system>");
    out
}

fn operational_uptime(operational: &OperationalResponse) -> Option<String> {
    let path = YangPath::new("/sys:system/sys:uptime").expect("uptime path");
    let value = operational.value_for(&path)?;
    let json: serde_json::Value = serde_json::from_str(value.value_json()).ok()?;
    match json {
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::String(string) => Some(string),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

fn extract_hostname(config_xml: &str) -> Result<String, EditConfigError> {
    let mut reader = Reader::from_str(config_xml);
    reader.config_mut().trim_text(false);
    let mut in_hostname = false;
    let mut value = String::new();

    loop {
        match reader
            .read_event()
            .map_err(|_| EditConfigError::InvalidValue)?
        {
            Event::Start(start) if local_name(start.name().as_ref()) == b"hostname" => {
                in_hostname = true;
                value.clear();
            }
            Event::Empty(start) if local_name(start.name().as_ref()) == b"hostname" => {
                return Ok(String::new());
            }
            Event::Text(text) if in_hostname => {
                value.push_str(&text.decode().map_err(|_| EditConfigError::InvalidValue)?);
            }
            Event::CData(text) if in_hostname => {
                value.push_str(&text.decode().map_err(|_| EditConfigError::InvalidValue)?);
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"hostname" && in_hostname => {
                return Ok(value);
            }
            Event::Eof => return Err(EditConfigError::InvalidValue),
            _ => {}
        }
    }
}

fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

async fn rpc11(client: &mut DuplexStream, xml: &str) -> String {
    write_base11(client, xml).await;
    let reply = read_base11_frame(client).await;
    assert_ok(&reply);
    reply
}

async fn write_base10<W>(writer: &mut W, xml: &str)
where
    W: AsyncWrite + Unpin,
{
    let frame = base10::encode_message(xml.as_bytes(), &MgmtLimits::default()).expect("base10");
    writer.write_all(&frame).await.expect("write base10");
    writer.flush().await.expect("flush base10");
}

async fn write_base11<W>(writer: &mut W, xml: &str)
where
    W: AsyncWrite + Unpin,
{
    let frame = base11::encode_message(xml.as_bytes(), &MgmtLimits::default()).expect("base11");
    writer.write_all(&frame).await.expect("write base11");
    writer.flush().await.expect("flush base11");
}

async fn read_base10_frame<R>(reader: &mut R) -> String
where
    R: AsyncRead + Unpin,
{
    let mut frame = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .await
            .expect("read base10 byte");
        frame.push(byte[0]);
        if frame.ends_with(base10::END_MARKER) {
            let decoded =
                base10::decode_message(&frame, &MgmtLimits::default()).expect("decode base10");
            return String::from_utf8(decoded).expect("utf8 base10");
        }
    }
}

async fn read_base11_frame<R>(reader: &mut R) -> String
where
    R: AsyncRead + Unpin,
{
    let mut frame = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .await
            .expect("read base11 byte");
        frame.push(byte[0]);
        if frame.ends_with(b"\n##\n") {
            let decoded =
                base11::decode_message(&frame, &MgmtLimits::default()).expect("decode base11");
            return String::from_utf8(decoded).expect("utf8 base11");
        }
    }
}

fn assert_ok(reply: &str) {
    assert!(
        !reply.contains("<rpc-error"),
        "unexpected rpc-error: {reply}"
    );
    assert!(
        reply.contains("<ok/>") || reply.contains("<data"),
        "reply was not ok/data: {reply}"
    );
}

fn assert_ok_data(reply: &str) {
    assert!(
        !reply.contains("<rpc-error"),
        "unexpected rpc-error: {reply}"
    );
    assert!(
        reply.contains("<data"),
        "reply did not contain data: {reply}"
    );
}

fn assert_no_secret(reply: &str) {
    assert!(!reply.contains("do-not-leak"), "secret leaked: {reply}");
}
