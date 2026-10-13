use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::collections::BTreeMap;
use std::io::Write;
use tracing::instrument::WithSubscriber;

use subtree_content_service::{netconf_xml, schema_registry, types::*};
use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{AuthStrength, TransportType, TrustedPrincipal, WorkloadIdentity, YangPath};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalError, OperationalRequest, OperationalResponse, OperationalValue};
use opc_mgmt_schema::{DataClass, LeafType, ModelData, NetconfXmlRenderer, NodeMeta, OriginEntry, SchemaRegistry};
use opc_mgmt_schema::subtree::{SubtreeAccessKind, SubtreeAccessObserver, SubtreeBudget, SubtreeError};
use opc_netconf_server::binding::ReadSelection;
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_netconf_server::binding::WithDefaultsCapability;
use opc_netconf_server::xml::WithDefaultsMode;
use opc_netconf_server::{run_read_only_session_with_registry, NetconfConfigBinding,
    ReadOnlyNetconfServer, SessionConfig, SessionRegistry};
use opc_types::TenantId;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const NC: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";
const EX: &str = "urn:example:subtree-content";
const WD: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults";

#[derive(Clone)]
struct Policy {
    rules: Arc<NacmPolicy>,
    calls: Arc<AtomicUsize>,
    mode: Arc<AtomicUsize>,
    alternate: Arc<Mutex<Option<Arc<NacmPolicy>>>>,
}

impl PolicySource for Policy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode.load(Ordering::SeqCst) == 1 { return Err(AuthzError::PolicyUnavailable); }
        if call % 2 == 1 {
            if let Some(policy) = self.alternate.lock().unwrap().as_ref() { return Ok(policy.clone()); }
        }
        Ok(self.rules.clone())
    }
}

#[derive(Clone, Default)]
struct Audit(Arc<Mutex<Vec<AuditEvent>>>);

impl AuditSink for Audit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
}

#[derive(Default)]
struct Access {
    model: AtomicUsize,
    provider: AtomicUsize,
    requests: Mutex<Vec<OperationalRequest>>,
    values: Mutex<Vec<OperationalValue>>,
    reads: Mutex<Vec<(&'static str, SubtreeAccessKind)>>,
    trap: Mutex<Option<&'static str>>,
    budget: Mutex<Option<SubtreeBudget>>,
    logs: Arc<Mutex<Vec<u8>>>,
    metric_delta: Mutex<BTreeMap<String, u64>>,
    filter_response: AtomicUsize,
    provider_trap: Mutex<Option<&'static str>>,
    unsupported_projection: AtomicUsize,
    basic_report_all: AtomicUsize,
}

impl SubtreeAccessObserver for Access {
    fn before_read(&self, path: &'static str, kind: SubtreeAccessKind) {
        if let Some(hidden) = *self.trap.lock().unwrap() {
            assert!(!path.starts_with(hidden), "denied branch was inspected: {path}");
        }
        self.reads.lock().unwrap().push((path, kind));
    }
}

#[derive(Clone)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);
impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> { self.0.lock().unwrap().extend_from_slice(bytes); Ok(bytes.len()) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn metric_counts() -> BTreeMap<String, u64> {
    let metrics = &opc_redaction::metrics::METRICS;
    let mut counts = BTreeMap::new();
    for (kind, map) in [("requests", &metrics.netconf_rpc_requests_total), ("errors", &metrics.netconf_rpc_errors_total)] {
        for ((operation, outcome), count) in map.lock().unwrap().iter() {
            counts.insert(format!("{kind}/{operation}/{outcome}"), *count);
        }
    }
    for (action, count) in metrics.netconf_nacm_denials_total.lock().unwrap().iter() { counts.insert(format!("denied/{action}"), *count); }
    counts
}

struct Binding {
    bus: Arc<ConfigBus<System>>,
    access: Arc<Access>,
    startup: Option<Arc<Startup>>,
    candidate: bool,
}

struct Startup {
    config: Mutex<Option<System>>,
    loads: AtomicUsize,
}

impl opc_netconf_server::binding::StartupDatastore<System> for Startup {
    fn load_startup_config(&self) -> Result<Option<System>, opc_netconf_server::binding::StartupDatastoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(self.config.lock().unwrap().clone())
    }
    fn store_startup_config(&self, _: &System) -> Result<(), opc_netconf_server::binding::StartupDatastoreError> {
        Err(opc_netconf_server::binding::StartupDatastoreError::Unsupported)
    }
}

// The binding retains generated typed access while supplying leafref/custom
// metadata and an absent data-class lookup through the registry contract.
// This isolates the read codec from unrelated edit/validation generator paths.
struct Registry;

impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str { schema_registry::registry().schema_digest() }
    fn served_models(&self) -> &'static [ModelData] { schema_registry::registry().served_models() }
    fn origins(&self) -> &'static [OriginEntry] { schema_registry::registry().origins() }
    fn discovery_metadata(&self) -> &'static [opc_mgmt_schema::DiscoveryMetadata] { schema_registry::registry().discovery_metadata() }
    fn numeric_ranges(&self) -> &'static [opc_mgmt_schema::NodeNumericRangeMeta] { schema_registry::registry().numeric_ranges() }
    fn nodes(&self) -> &'static [NodeMeta] {
        static NODES: OnceLock<Vec<NodeMeta>> = OnceLock::new();
        NODES.get_or_init(|| {
          let mut nodes: Vec<_> = schema_registry::registry().nodes().iter().map(|node| {
            let mut node = *node;
            // Exercise state-default metadata without the baseline generator's
            // unrelated Option<T>/LeafPresence<T> default initializer defect.
            if node.path == "/ex:system/ex:state-default" { node.default = Some("7"); node.has_default = true; }
            node.leaf_type = match node.path {
                "/ex:system/ex:opaque" | "/ex:system/ex:state-opaque" => Some(LeafType::Custom { name: "opaque" }),
                "/ex:system/ex:port-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:port" }),
                "/ex:system/ex:chained-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:port-ref" }),
                "/ex:system/ex:ratio-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:ratio" }),
                "/ex:system/ex:identity-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:identity" }),
                "/ex:system/ex:opaque-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:opaque" }),
                "/ex:system/ex:state-ratio-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:ratio-ref" }),
                "/ex:system/ex:state-identity-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:identity-ref" }),
                "/ex:system/ex:state-opaque-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:opaque-ref" }),
                "/ex:system/ex:typed-peer/ex:identity" => Some(LeafType::IdentityRef { base: "identity-base" }),
                "/ex:system/ex:typed-peer/ex:ratio" => Some(LeafType::Decimal64),
                _ => node.leaf_type,
            };
            node
          }).collect();
          // Provider-owned state identities do not need a config representation.
          // Supply this registry subtree directly so the fixture does not depend
          // on the baseline edit generator's unsupported config-false list keys.
          let mut state_list = *nodes.iter().find(|node| node.path == "/ex:system/ex:peer").unwrap();
          state_list.path = "/ex:system/ex:state-peer";
          state_list.config = false;
          state_list.child_paths = &["/ex:system/ex:state-peer/ex:id", "/ex:system/ex:state-peer/ex:label", "/ex:system/ex:state-peer/ex:site", "/ex:system/ex:state-peer/ex:up"];
          nodes.push(state_list);
          for (source, path) in [("/ex:system/ex:peer/ex:site", "/ex:system/ex:state-peer/ex:site"), ("/ex:system/ex:peer/ex:id", "/ex:system/ex:state-peer/ex:id"), ("/ex:system/ex:peer/ex:label", "/ex:system/ex:state-peer/ex:label"), ("/ex:system/ex:peer/ex:up", "/ex:system/ex:state-peer/ex:up")] {
              let mut leaf = *nodes.iter().find(|node| node.path == source).unwrap();
              leaf.path = path;
              leaf.config = false;
              nodes.push(leaf);
          }
          let mut hidden_list = *nodes.iter().find(|node| node.path == "/ex:system/ex:hidden-peer").unwrap();
          hidden_list.path = "/ex:system/ex:state-hidden-peer";
          hidden_list.config = false;
          hidden_list.child_paths = &["/ex:system/ex:state-hidden-peer/ex:label", "/ex:system/ex:state-hidden-peer/ex:secret"];
          nodes.push(hidden_list);
          for (source, path) in [("/ex:system/ex:hidden-peer/ex:secret", "/ex:system/ex:state-hidden-peer/ex:secret"), ("/ex:system/ex:hidden-peer/ex:label", "/ex:system/ex:state-hidden-peer/ex:label")] {
              let mut leaf = *nodes.iter().find(|node| node.path == source).unwrap();
              leaf.path = path;
              leaf.config = false;
              nodes.push(leaf);
          }
          static ROOT_CHILDREN: OnceLock<Vec<&'static str>> = OnceLock::new();
          let root = nodes.iter_mut().find(|node| node.path == "/ex:system").unwrap();
          root.child_paths = ROOT_CHILDREN.get_or_init(|| {
              let mut paths = root.child_paths.to_vec();
              paths.push("/ex:system/ex:state-peer");
              paths.push("/ex:system/ex:state-hidden-peer");
              paths.sort();
              paths
          });
          let mut top = *nodes.iter().find(|node| node.path == "/ex:system/ex:hostname").unwrap();
          top.path = "/ex:top-match";
          nodes.push(top);
          let mut root = *nodes.iter().find(|node| node.path == "/ex:system").unwrap();
          root.path = "/ex:yang-library";
          root.child_paths = &["/ex:yang-library/ex:content-id"];
          nodes.push(root);
          top.path = "/ex:yang-library/ex:content-id";
          nodes.push(top);
          nodes.sort_by_key(|node| node.path);
          nodes
        })
    }
    fn data_class(&self, path: &str) -> Option<DataClass> {
        if path.ends_with("/ex:unclassified") || path.ends_with("/ex:state-unclassified") { None }
        else { self.node(path).map(|node| node.data_class) }
    }
}

impl NetconfConfigBinding<System> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<System>> {
        self.access.model.fetch_add(1, Ordering::SeqCst);
        self.bus.clone()
    }
    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        &Registry
    }
    fn generated_xml_renderer(&self) -> Option<&dyn NetconfXmlRenderer<System>> {
        Some(&netconf_xml::GeneratedNetconfXmlRenderer)
    }
    fn generated_xml_edit_applicator(&self) -> Option<&dyn opc_mgmt_schema::NetconfXmlEditApplicator<System>> {
        Some(&subtree_content_service::netconf_xml_edit::GeneratedNetconfXmlEditApplicator)
    }
    fn supports_subtree_content(&self) -> bool { self.access.unsupported_projection.load(Ordering::SeqCst) == 0 }
    fn subtree_default_report(&self) -> opc_mgmt_schema::DefaultReport {
        if self.access.basic_report_all.load(Ordering::SeqCst) == 0 { opc_mgmt_schema::DefaultReport::Trim }
        else { opc_mgmt_schema::DefaultReport::ReportAll }
    }
    fn render_running_config(&self, config: &System, selection: ReadSelection<'_>)
        -> Result<String, opc_netconf_server::binding::BindingError>
    {
        assert!(selection.subtree_plan().is_none(), "constrained reads must use the typed projection");
        netconf_xml::GeneratedNetconfXmlRenderer.render_running_config(config, selection.schema_paths(), self.subtree_default_report())
            .map_err(|_| opc_netconf_server::binding::BindingError::projection("fixture projection failed"))
    }
    fn render_get_data(&self, config: &System, selection: ReadSelection<'_>, operational: &OperationalResponse, operational_selection: ReadSelection<'_>)
        -> Result<String, opc_netconf_server::binding::BindingError>
    {
        let mut xml = self.render_running_config(config, selection)?;
        xml.push_str(&opc_netconf_server::binding::render_operational_xml(self.schema_registry(), operational_selection.schema_paths(), operational)?);
        Ok(xml)
    }
    fn project_subtree_content(&self, config: &System, selection: ReadSelection<'_>, report: opc_mgmt_schema::DefaultReport)
        -> Result<Vec<opc_mgmt_schema::NetconfXmlNode>, SubtreeError>
    {
        let plan = selection.subtree_plan().ok_or(SubtreeError::Unsupported)?;
        *self.access.budget.lock().unwrap() = Some(plan.budget().clone());
        let ctx = plan.projection(self.schema_registry(), report).with_observer(self.access.as_ref());
        let mut nodes = netconf_xml::GeneratedNetconfXmlRenderer.project_subtree_content(config, &ctx)?;
        if ctx.enter("/ex:top-match", false)? {
            if let LeafPresence::Explicit(value) = &config.hostname {
                if let Some(node) = ctx.scalar("/ex:top-match", opc_mgmt_schema::subtree::SubtreeScalar::Text(value), false)? { ctx.append(&mut nodes, vec![node])?; }
            }
        }
        if ctx.enter("/ex:yang-library", true)? {
            let mut root = opc_mgmt_schema::NetconfXmlNode::branch("/ex:yang-library");
            if ctx.enter("/ex:yang-library/ex:content-id", false)? {
                if let LeafPresence::Explicit(value) = &config.hostname {
                    if let Some(node) = ctx.scalar("/ex:yang-library/ex:content-id", opc_mgmt_schema::subtree::SubtreeScalar::Text(value), false)? { ctx.append(&mut root.children, vec![node])?; }
                }
            }
            ctx.append(&mut nodes, vec![root])?;
        }
        Ok(nodes)
    }
    fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
        let basic = if self.access.basic_report_all.load(Ordering::SeqCst) == 0 { WithDefaultsMode::Trim } else { WithDefaultsMode::ReportAll };
        Some(WithDefaultsCapability::new(basic, [
            WithDefaultsMode::ReportAll, WithDefaultsMode::ReportAllTagged,
            WithDefaultsMode::Explicit, WithDefaultsMode::Trim,
        ]).unwrap())
    }
    fn nmda_get_data_supported(&self) -> bool { true }
    fn nmda_intended_equals_running(&self) -> bool { true }
    fn candidate_datastore_capability(&self) -> bool { self.candidate }
    fn startup_datastore(&self) -> Option<&dyn opc_netconf_server::binding::StartupDatastore<System>> {
        self.startup.as_deref().map(|store| store as &dyn opc_netconf_server::binding::StartupDatastore<System>)
    }
    fn get_operational_state(&self, request: &OperationalRequest)
        -> Result<OperationalResponse, OperationalError>
    {
        self.access.provider.fetch_add(1, Ordering::SeqCst);
        if let Some(hidden) = *self.access.provider_trap.lock().unwrap() {
            assert!(!request.paths.iter().any(|path| path.as_str().contains(hidden)), "denied provider dependency requested");
        }
        self.access.requests.lock().unwrap().push(request.clone());
        if self.access.filter_response.load(Ordering::SeqCst) != 0 {
            return Ok(OperationalResponse::new(self.access.values.lock().unwrap().iter()
                .filter(|value| request.paths.iter().any(|path| opc_mgmt_path::canonical_path_matches(path.as_str(), value.path().as_str())))
                .take(request.max_values.saturating_add(1)).cloned()));
        }
        Ok(OperationalResponse::new(self.access.values.lock().unwrap().clone()))
    }
}

type Server = ReadOnlyNetconfServer<System, Binding, Policy, Audit>;

struct Fixture {
    server: Server,
    access: Arc<Access>,
    policy_calls: Arc<AtomicUsize>,
    audit: Audit,
    policy_mode: Arc<AtomicUsize>,
    alternate: Arc<Mutex<Option<Arc<NacmPolicy>>>>,
}

impl Fixture {
    async fn new(config: System, denied: &[&str]) -> Self {
        Self::with_datastores(config, denied, None, false).await
    }

    async fn with_datastores(config: System, denied: &[&str], startup: Option<Arc<Startup>>, candidate: bool) -> Self {
        let rules = policy(denied);
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let policy_mode = Arc::new(AtomicUsize::new(0));
        let alternate = Arc::new(Mutex::new(None));
        let access = Arc::new(Access::default());
        let audit = Audit::default();
        let bus = Arc::new(ConfigBus::new_dev_only(config, MockManagedDatastore::new())
            .await.unwrap());
        let server = ReadOnlyNetconfServer::new(
            Binding { bus, access: access.clone(), startup, candidate },
            Policy { rules: Arc::new(rules), calls: policy_calls.clone(), mode: policy_mode.clone(), alternate: alternate.clone() },
            audit.clone(), TransportType::NetconfTls,
        ).unwrap();
        Self { server, access, policy_calls, audit, policy_mode, alternate }
    }

    async fn rpc(&self, body: &str, limits: MgmtLimits) -> String {
        self.rpc_after_setup(body, limits, "").await
    }

    async fn rpc_after_setup(&self, body: &str, limits: MgmtLimits, setup: &str) -> String {
        let principal = TrustedPrincipal::new(
            WorkloadIdentity::User("subtree-reader".into()), TenantId::new("fixture").unwrap(),
        ).with_auth_strength(AuthStrength::MutualTls);
        let registry = SessionRegistry::new();
        let (mut client, mut stream) = tokio::io::duplex(262_144);
        let before_metrics = metric_counts();
        let writer = LogWriter(self.access.logs.clone());
        let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
            .with_max_level(tracing::Level::TRACE).with_writer(move || writer.clone()).finish();
        let serving = run_read_only_session_with_registry(&self.server, &principal, &mut stream,
            SessionConfig { limits, frame_timeout: Duration::from_secs(5) }, 1, &registry);
        let exchange = async {
            assert!(read_frame(&mut client).await.contains("<hello"));
            write_frame(&mut client, &format!("<hello xmlns=\"{NC}\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>")).await;
            if !setup.is_empty() {
                write_frame(&mut client, &format!("<rpc xmlns=\"{NC}\" message-id=\"setup\">{setup}</rpc>")).await;
                let reply = read_frame(&mut client).await;
                assert!(reply.contains("<ok/>"), "candidate setup failed: {reply}");
            }
            SECRET_CLONES.store(0, Ordering::SeqCst);
            self.access.model.store(0, Ordering::SeqCst);
            self.access.provider.store(0, Ordering::SeqCst);
            self.policy_calls.store(0, Ordering::SeqCst);
            self.audit.0.lock().unwrap().clear();
            self.access.reads.lock().unwrap().clear();
            self.access.logs.lock().unwrap().clear();
            *self.access.budget.lock().unwrap() = None;
            write_frame(&mut client, &format!("<rpc xmlns=\"{NC}\" message-id=\"match\">{body}</rpc>")).await;
            let reply = read_frame(&mut client).await;
            // End the authenticated session without a second RPC or policy load.
            client.shutdown().await.unwrap();
            reply
        };
        let (reply, result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(exchange, serving)
        }.with_subscriber(subscriber)).await.unwrap();
        result.unwrap();
        *self.access.metric_delta.lock().unwrap() = metric_counts().into_iter()
            .filter_map(|(key, value)| { let delta = value - before_metrics.get(&key).copied().unwrap_or(0); (delta > 0).then_some((key, delta)) }).collect();
        reply
    }

    async fn read(&self, op: &str, children: &str, defaults: &str) -> String {
        self.rpc(&request(op, children, defaults), MgmtLimits::default()).await
    }

    fn direct_rpc(&self, body: &str, limits: MgmtLimits) -> String {
        self.access.model.store(0, Ordering::SeqCst);
        self.access.provider.store(0, Ordering::SeqCst);
        self.policy_calls.store(0, Ordering::SeqCst);
        self.access.reads.lock().unwrap().clear();
        let principal = TrustedPrincipal::new(WorkloadIdentity::User("subtree-reader".into()), TenantId::new("fixture").unwrap())
            .with_auth_strength(AuthStrength::MutualTls);
        self.server.handle_rpc(opc_config_model::RequestId::new(), &principal, &format!("<rpc xmlns=\"{NC}\" message-id=\"match\">{body}</rpc>"), &limits).reply_xml
    }

    fn no_access(&self) {
        assert_eq!(self.access.model.load(Ordering::SeqCst), 0, "no model access");
        assert_eq!(self.access.provider.load(Ordering::SeqCst), 0, "no provider access");
        assert_eq!(self.policy_calls.load(Ordering::SeqCst), 0, "schema refusal precedes policy");
        assert!(self.access.reads.lock().unwrap().is_empty());
    }

    fn observation(&self) -> String {
        let audit: Vec<_> = self.audit.0.lock().unwrap().iter().map(|event| format!("{:?}:{:?}:{:?}", event.operation, event.outcome, event.schema_paths)).collect();
        format!("{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{}", self.access.model.load(Ordering::SeqCst), self.access.provider.load(Ordering::SeqCst), self.policy_calls.load(Ordering::SeqCst), self.access.reads.lock().unwrap(), self.access.budget.lock().unwrap().as_ref().map(|budget| (budget.remaining(), budget.predicate_trials())), self.access.metric_delta.lock().unwrap(), audit, String::from_utf8(self.access.logs.lock().unwrap().clone()).unwrap())
    }
}

fn policy(denied: &[&str]) -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    for (module, prefix) in [("subtree-content", "ex"), ("ietf-netconf", "nc"), ("ietf-yang-library", "yanglib"), ("ietf-netconf-monitoring", "ncm")] {
        modules.register_module(module, prefix).unwrap();
    }
    let mut rules = NacmPolicy::builder(PolicyVersion::new(1));
    for path in denied {
        rules = rules.add_rule(NacmRule::deny(NacmAction::Read, YangPathPattern::parse(path, &modules).unwrap()));
    }
    for path in ["/ex:system", "/ex:system/**", "/ex:top-match", "/ex:yang-library", "/ex:yang-library/**", "/yanglib:yang-library", "/yanglib:yang-library/**", "/ncm:netconf-state", "/ncm:netconf-state/**"] {
        rules = rules.add_rule(NacmRule::allow(NacmAction::Read, YangPathPattern::parse(path, &modules).unwrap()));
    }
    rules = rules.add_rule(NacmRule::allow(NacmAction::Update, YangPathPattern::parse("/ex:system/ex:hostname", &modules).unwrap()));
    rules = rules.add_rule(NacmRule::allow(NacmAction::Exec, YangPathPattern::parse("/nc:edit-config", &modules).unwrap()));
    rules.add_rule(NacmRule::allow(NacmAction::Exec, YangPathPattern::parse("/nc:close-session", &modules).unwrap())).build()
}

async fn read_frame(stream: &mut DuplexStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        bytes.push(byte);
        if bytes.ends_with(b"]]>]]>") {
            bytes.truncate(bytes.len() - 6);
            return String::from_utf8(bytes).unwrap();
        }
    }
}

async fn write_frame(stream: &mut DuplexStream, xml: &str) {
    stream.write_all(xml.as_bytes()).await.unwrap();
    stream.write_all(b"]]>]]>").await.unwrap();
    stream.flush().await.unwrap();
}

fn request(op: &str, children: &str, defaults: &str) -> String {
    let wd = if defaults.is_empty() { String::new() } else {
        format!("<with-defaults xmlns=\"{WD}\">{defaults}</with-defaults>")
    };
    let tree = format!("<system xmlns=\"{EX}\">{children}</system>");
    match op {
        "get-config" => format!("<get-config><source><running/></source><filter>{tree}</filter>{wd}</get-config>"),
        "get" => format!("<get><filter>{tree}</filter>{wd}</get>"),
        "get-data" => format!("<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\"><datastore>ds:operational</datastore><subtree-filter>{tree}</subtree-filter>{wd}</get-data>"),
        _ => panic!("unsupported fixture operation"),
    }
}

fn nmda(datastore: &str, config_filter: Option<bool>, children: &str, defaults: &str) -> String {
    let filter = config_filter.map(|value| format!("<config-filter>{value}</config-filter>")).unwrap_or_default();
    request("get-data", children, defaults).replace("ds:operational</datastore>", &format!("ds:{datastore}</datastore>{filter}"))
}

fn config() -> System {
    let mut config = System::default();
    config.hostname = LeafPresence::Explicit("router-marker".into());
    config.enabled = LeafPresence::Explicit(true);
    config.count = LeafPresence::Explicit(u32::MAX);
    config.bounded = LeafPresence::Explicit(7);
    config.signed = LeafPresence::Explicit(YangInt64(i64::MIN));
    config.role = serde_json::from_str("\"active\"").unwrap();
    config.port_ref = LeafPresence::Explicit(7);
    config.chained_ref = LeafPresence::Explicit(7);
    config.ratio = LeafPresence::Explicit(YangDecimal64(1.0));
    config.ratio_ref = LeafPresence::Explicit(YangDecimal64(1.0));
    config.identity = LeafPresence::Explicit("a:router".into());
    config.identity_ref = LeafPresence::Explicit("a:router".into());
    config.opaque = LeafPresence::Explicit("opaque-marker".into());
    config.opaque_ref = LeafPresence::Explicit("opaque-marker".into());
    config.secret = SecretLeaf::new(LeafPresence::Explicit("secret-marker".into()));
    config.intercept = SecretLeaf::new(LeafPresence::Explicit("intercept-marker".into()));
    config.password = SecretLeaf::new(LeafPresence::Explicit("password-marker".into()));
    config.unclassified = SecretLeaf::new(LeafPresence::Explicit("unclassified-marker".into()));
    let mut settings = Settings::default();
    settings.label = LeafPresence::Explicit("settings-marker".into());
    settings.enabled = LeafPresence::Explicit(true);
    config.settings = Some(settings);
    for (site, id, label, cost, enabled) in [
        ("west", 7, "gamma-marker", 8, true),
        ("east", 8, "beta-marker", 8, false),
        ("east", 7, "alpha-marker", 7, true),
    ] {
        let mut peer = Peer::default();
        peer.site = LeafPresence::Explicit(site.into());
        peer.id = LeafPresence::Explicit(id);
        peer.label = LeafPresence::Explicit(label.into());
        peer.cost = LeafPresence::Explicit(cost);
        peer.enabled = LeafPresence::Explicit(enabled);
        peer.credential = SecretLeaf::new(LeafPresence::Explicit(format!("credential-{label}")));
        for (slot, kind) in [(1, "a"), (2, "b")] {
            let mut lane = Lane::default();
            lane.slot = LeafPresence::Explicit(slot);
            lane.kind = LeafPresence::Explicit(kind.into());
            lane.label = LeafPresence::Explicit(format!("{label}-{slot}"));
            peer.lane.insert(LaneKey { slot, kind: kind.into() }, lane);
        }
        config.peer.insert(PeerKey { site: site.into(), id }, peer);
    }
    for ratio in ["1.00", "1.0"] {
        let mut row = TypedPeer::default();
        row.identity = LeafPresence::Explicit("a:router".into());
        row.ratio = LeafPresence::Explicit(ratio.into());
        row.label = LeafPresence::Explicit(format!("ratio-{ratio}"));
        config.typed_peer.insert(TypedPeerKey { identity: "a:router".into(), ratio: ratio.into() }, row);
    }
    for suffix in ["a", "b"] {
        let mut row = ClassPeer::default();
        let secret = format!("secret-{suffix}");
        let intercept = format!("intercept-{suffix}");
        let password = format!("password-{suffix}");
        let unclassified = format!("unclassified-{suffix}");
        row.secret = SecretLeaf::new(LeafPresence::Explicit(secret.clone()));
        row.intercept = SecretLeaf::new(LeafPresence::Explicit(intercept.clone()));
        row.password = SecretLeaf::new(LeafPresence::Explicit(password.clone()));
        row.unclassified = SecretLeaf::new(LeafPresence::Explicit(unclassified.clone()));
        row.label = LeafPresence::Explicit(format!("class-row-{suffix}"));
        config.class_peer.insert(ClassPeerKey { secret, intercept, password, unclassified }, row);
    }
    for name in ["z", "a", "m"] {
        let mut row = UserPeer::default();
        row.name = LeafPresence::Explicit(name.into());
        row.label = LeafPresence::Explicit(format!("user-{name}-<&\"'\\-marker"));
        config.user_peer.insert(name.to_string(), row).unwrap();
    }
    config
}

#[tokio::test]
async fn subtree_content_default_limits_key_lookup_over_100_entries() {
    let mut model = System::default();
    let mut values = Vec::new();
    for id in 0..100u16 {
        let mut peer = Peer::default();
        peer.site = LeafPresence::Explicit("s".into());
        peer.id = LeafPresence::Explicit(id);
        peer.label = LeafPresence::Explicit(format!("p{id}"));
        peer.cost = LeafPresence::Explicit(id);
        peer.enabled = LeafPresence::Explicit(true);
        peer.credential = SecretLeaf::new(LeafPresence::Explicit("secret".into()));
        model.peer.insert(PeerKey { site: "s".into(), id }, peer);
        values.push(state(&format!("/ex:system/ex:peer[ex:site='s'][ex:id='{id}']/ex:up"), "true"));
    }
    let fixture = Fixture::new(model, &[]).await;
    *fixture.access.values.lock().unwrap() = values;
    fixture.access.filter_response.store(1, Ordering::SeqCst);
    let mut replies = Vec::new();
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.rpc(&request(op, "<peer><site>s</site><id>49</id></peer>", ""), MgmtLimits::default()).await;
        replies.push((op, reply, fixture.access.provider.load(Ordering::SeqCst), fixture.policy_calls.load(Ordering::SeqCst)));
    }
    assert!(replies.iter().all(|(_, reply, _, _)| !reply.contains("<rpc-error>")), "default-limit key lookups: {replies:?}");
    for (op, reply, provider_calls, policy_calls) in replies {
        assert_eq!(data(&reply).matches("<ex:peer>").count(), 1, "{op}: {reply}");
        assert_eq!(tags(&reply, "site"), ["s"]);
        assert_eq!(tags(&reply, "id"), ["49"]);
        assert_eq!(tags(&reply, "label"), ["p49"]);
        assert_eq!(tags(&reply, "cost"), ["49"]);
        assert_eq!(tags(&reply, "enabled"), ["true"]);
        assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;"]);
        assert_eq!(tags(&reply, "up"), if op == "get-config" { vec![] } else { vec!["true"] });
        assert_eq!(provider_calls, usize::from(op != "get-config"));
        assert_eq!(policy_calls, 1);
    }
}

#[tokio::test]
async fn subtree_content_default_limits_state_read_with_1024_provider_values() {
    let fixture = Fixture::new(System::default(), &[]).await;
    *fixture.access.values.lock().unwrap() = (0..1024u16).map(|id|
        state(&format!("/ex:system/ex:peer[ex:site='s'][ex:id='{id}']/ex:up"), "true")
    ).collect();
    let mut replies = Vec::new();
    for op in ["get", "get-data"] {
        let reply = fixture.rpc(&request(op, "<peer><up>true</up><up/></peer>", ""), MgmtLimits::default()).await;
        replies.push((op, reply, fixture.access.provider.load(Ordering::SeqCst), fixture.policy_calls.load(Ordering::SeqCst)));
    }
    assert!(replies.iter().all(|(_, reply, _, _)| !reply.contains("<rpc-error>")), "default-limit state reads: {replies:?}");
    for (op, reply, provider_calls, policy_calls) in replies {
        assert_eq!(data(&reply).matches("<ex:peer>").count(), 1024, "{op}");
        assert_eq!(tags(&reply, "site"), vec!["s"; 1024]);
        assert_eq!(tags(&reply, "up"), vec!["true"; 1024]);
        assert_eq!(tags(&reply, "id").iter().map(|id| id.parse::<u16>().unwrap()).collect::<std::collections::BTreeSet<_>>(), (0..1024u16).collect());
        assert!(tags(&reply, "label").is_empty());
        assert_eq!(provider_calls, 1);
        assert_eq!(policy_calls, 1);
    }
}

fn data(reply: &str) -> &str {
    assert!(!reply.contains("<rpc-error>"), "{reply}");
    let data = reply.split_once("<data").expect(reply).1;
    let (start, contents) = data.split_once('>').expect(reply);
    if start.ends_with('/') { return ""; }
    contents.split_once("</data>").unwrap().0
}

fn tags(reply: &str, tag: &str) -> Vec<String> {
    let xml = data(reply);
    let start = format!("<ex:{tag}>");
    let end = format!("</ex:{tag}>");
    xml.split(&start).skip(1).map(|part| part.split_once(&end).unwrap().0.to_owned()).collect()
}

fn error(reply: &str, tag: &str) {
    assert!(reply.contains(&format!("<error-tag>{tag}</error-tag>")), "{reply}");
    assert!(!reply.contains("<data"), "errors cannot contain partial data");
}

fn state(path: &str, json: &str) -> OperationalValue {
    OperationalValue::new(YangPath::new(path).unwrap(), json).unwrap()
}

#[tokio::test]
async fn subtree_content_siblings_are_same_instance_and() {
    let fixture = Fixture::new(config(), &[]).await;
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.read(op, "<peer><site>east</site><cost>8</cost><enabled>true</enabled><label/></peer>", "").await;
        assert_eq!(data(&reply), "");
        let reply = fixture.read(op, "<peer><site>east</site><cost>7</cost><enabled>true</enabled><label/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
        let reply = fixture.read(op, "<peer><cost>7</cost><cost>8</cost><label/></peer>", "").await;
        assert_eq!(data(&reply), "");
        let reply = fixture.read(op, "<hostname>router-marker</hostname><enabled>true</enabled><count/>", "").await;
        assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
        let reply = fixture.read(op, "<settings><label>settings-marker</label><enabled>true</enabled></settings><hostname/>", "").await;
        assert_eq!(tags(&reply, "label"), ["settings-marker"]);
        let reply = fixture.read(op, "<settings><label>settings-marker</label><enabled>false</enabled></settings><hostname/>", "").await;
        assert!(tags(&reply, "label").is_empty());
        assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
    }
    for (literal, matched) in [("router-marker", true), ("wrong-marker", false)] {
        let reply = fixture.rpc(&format!("<get><filter><top-match xmlns=\"{EX}\">{literal}</top-match><system xmlns=\"{EX}\"><hostname/></system></filter></get>"), MgmtLimits::default()).await;
        assert_eq!(tags(&reply, "hostname"), if matched { vec!["router-marker"] } else { vec![] });
        if !matched { assert_eq!(data(&reply), ""); }
    }
}

#[tokio::test]
async fn subtree_content_node_classification() {
    let fixture = Fixture::new(config(), &[]).await;
    let selected = fixture.read("get-config", "<hostname/>", "").await;
    assert_eq!(tags(&selected, "hostname"), ["router-marker"]);
    assert_eq!(fixture.read("get-config", "<hostname> \t\r\n </hostname>", "").await, selected);
    let reply = fixture.read("get-config", "<hostname>router-marker</hostname><count/>", "").await;
    assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
    let reply = fixture.read("get-config", "<hostname>\u{a0}</hostname><count/>", "").await;
    assert_eq!(data(&reply), "", "Unicode nonbreaking space is content");
    for contents in ["<peer>text</peer>", "<settings>text</settings>", "<peer>text<label/></peer>", "<hostname>text<child/></hostname>"] {
        error(&fixture.read("get-config", contents, "").await, "bad-element");
        fixture.no_access();
    }
    error(&fixture.read("get-config", "<tags>text</tags>", "").await, "operation-not-supported");
    fixture.no_access();
    let reply = fixture.read("get-config", "<uptime>7</uptime><hostname/>", "").await;
    assert_eq!(data(&reply), "");
    assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn subtree_content_text_accumulates_before_trim() {
    let mut model = config();
    model.hostname = LeafPresence::Explicit("a & b  c".into());
    let fixture = Fixture::new(model, &[]).await;
    for literal in [" a &amp; b  c ", "a &#38; b  c", "a &#x26; b  c", "<![CDATA[a & b  c]]>", "a <![CDATA[& b ]]><![CDATA[ c]]>"] {
        let reply = fixture.read("get-config", &format!("<hostname>{literal}</hostname><count/>"), "").await;
        assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
        assert_eq!(tags(&reply, "hostname"), ["a &amp; b  c"]);
    }
    for reference in ["&missing;", "&#0;", "&#xD800;", "&#xFFFE;"] {
        let reply = fixture.read("get-config", &format!("<hostname>{reference}</hostname>"), "").await;
        error(&reply, "malformed-message");
        fixture.no_access();
    }
    for dtd in ["<!DOCTYPE rpc [<!ENTITY probe 'a & b  c'>]>", "<!DOCTYPE rpc SYSTEM 'file:///not-read-subtree-marker'>"] {
        let body = format!("{dtd}{}", request("get-config", "<hostname>&probe;</hostname>", ""));
        error(&fixture.direct_rpc(&body, MgmtLimits::default()), "malformed-message");
        fixture.no_access();
    }
    let marker = "predicate-UNIQUE-disclosure-marker";
    let xml = format!("<rpc xmlns=\"{NC}\" message-id=\"redaction\">{}</rpc>", request("get-config", &format!("<hostname>{marker}</hostname>"), ""));
    let parsed = opc_netconf_server::xml::parse_rpc(&xml, &MgmtLimits::default()).unwrap();
    assert!(!format!("{parsed:?}").contains(marker));
    let reply = fixture.read("get-config", &format!("<hostname>{marker}</hostname><count/>"), "").await;
    assert_eq!(data(&reply), "");
    assert!(!format!("{:?}", fixture.audit.0.lock().unwrap()).contains(marker));
    assert!(!String::from_utf8(fixture.access.logs.lock().unwrap().clone()).unwrap().contains(marker));
    assert!(!opc_redaction::metrics::export_prometheus_text().contains(marker));
    assert!(!reply.contains(marker));
}

#[tokio::test]
async fn subtree_content_element_namespaces() {
    let fixture = Fixture::new(config(), &[]).await;
    let expected = fixture.read("get-config", "<hostname>router-marker</hostname><count/>", "").await;
    assert_eq!(tags(&expected, "count"), [u32::MAX.to_string()]);
    for tree in [
        format!("<q:system xmlns:q=\"{EX}\"><q:hostname>router-marker</q:hostname><q:count/></q:system>"),
        "<system xmlns=\"\"><hostname>router-marker</hostname><count/></system>".into(),
        format!("<system xmlns=\"{EX}\"><hostname xmlns=\"\">router-marker</hostname><count/></system>"),
    ] {
        let body = format!("<get-config><source><running/></source><filter>{tree}</filter></get-config>");
        assert_eq!(fixture.rpc(&body, MgmtLimits::default()).await, expected);
    }
    for (literal, prefix, excluded) in [("router-marker", "ex", "yanglib"), (Registry.schema_digest(), "yanglib", "ex")] {
        let reply = fixture.rpc(&format!("<get><filter><yang-library xmlns=\"\"><content-id>{literal}</content-id><content-id/></yang-library></filter></get>"), MgmtLimits::default()).await;
        assert!(data(&reply).contains(&format!("<{prefix}:content-id>{literal}</{prefix}:content-id>")), "{reply}");
        assert!(!data(&reply).contains(&format!("<{excluded}:yang-library")), "{reply}");
    }
    let reply = fixture.rpc(&format!("<get><filter><q:yang-library xmlns:q=\"{EX}\"><q:content-id>router-marker</q:content-id><q:content-id/></q:yang-library></filter></get>"), MgmtLimits::default()).await;
    assert!(data(&reply).contains("<ex:content-id>router-marker</ex:content-id>"));
    assert!(!data(&reply).contains("yanglib:"));
}

#[tokio::test]
async fn subtree_content_scalar_canonical_values() {
    let fixture = Fixture::new(config(), &[]).await;
    for (leaf, literal) in [
        ("port", "+007"), ("enabled", "true"), ("count", "04294967295"),
        ("signed", "-9223372036854775808"), ("role", "active"),
        ("port-ref", "+007"), ("chained-ref", "007"), ("bounded", "+007"),
    ] {
        let reply = fixture.read("get-config", &format!("<{leaf}>{literal}</{leaf}><hostname/>"), "report-all").await;
        assert_eq!(tags(&reply, "hostname"), ["router-marker"], "{leaf}");
    }
    for (leaf, literal) in [
        ("port", "65536"), ("port", "-1"), ("port", "seven"),
        ("enabled", "TRUE"), ("enabled", "1"), ("count", "4294967296"),
        ("signed", "9223372036854775808"), ("role", "ACTIVE"), ("empty", "present"),
        ("port-ref", "65536"), ("bounded", "4"), ("bounded", "9"), ("bounded", "12"),
    ] {
        let reply = fixture.read("get-config", &format!("<{leaf}>{literal}</{leaf}><hostname/>"), "report-all").await;
        assert_eq!(data(&reply), "", "{leaf}");
    }
    let mut model = config();
    model.hostname = LeafPresence::Explicit("+007".into());
    let fixture = Fixture::new(model, &[]).await;
    assert_eq!(data(&fixture.read("get-config", "<hostname>7</hostname><count/>", "").await), "");
    assert_eq!(tags(&fixture.read("get-config", "<hostname>+007</hostname><count/>", "").await, "count"), [u32::MAX.to_string()]);
    for value in [5, 8, 11] {
        let mut model = config();
        model.bounded = LeafPresence::Explicit(value);
        let fixture = Fixture::new(model, &[]).await;
        assert_eq!(tags(&fixture.read("get-config", &format!("<bounded>{value}</bounded><hostname/>"), "").await, "hostname"), ["router-marker"]);
    }
    let fixture = Fixture::new(config(), &["/ex:system/ex:port"]).await;
    *fixture.access.trap.lock().unwrap() = Some("/ex:system/ex:port");
    // The chained leafref requires target metadata, never target instance data.
    assert_eq!(tags(&fixture.read("get-config", "<chained-ref>+007</chained-ref><hostname/>", "").await, "hostname"), ["router-marker"]);
}

#[tokio::test]
async fn subtree_content_unsupported_codec_is_schema_only() {
    for denied in [vec![], vec!["/ex:system/**"]] {
      for model in [config(), System::default()] {
        let fixture = Fixture::new(model, &denied).await;
        for op in ["get-config", "get", "get-data"] {
            for leaf in ["ratio", "identity", "opaque", "ratio-ref", "identity-ref", "opaque-ref", "state-ratio", "state-identity", "state-opaque", "state-ratio-ref", "state-identity-ref", "state-opaque-ref"] {
                for literal in ["unsupported-probe", "1.00"] {
                  for provider_value in [None, Some("\"unsupported-probe\""), Some("123"), Some("{}") ] {
                    *fixture.access.values.lock().unwrap() = provider_value.into_iter().map(|value| state(&format!("/ex:system/ex:{leaf}"), value)).collect();
                    let reply = fixture.read(op, &format!("<{leaf}>{literal}</{leaf}>"), "").await;
                    error(&reply, "operation-not-supported");
                    fixture.no_access();
                  }
                }
            }
        }
      }
    }
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.read("get-config", "<port>+007</port><hostname/>", "report-all").await;
    assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.read(op, "<typed-peer><identity>a:router</identity><ratio>1.00</ratio><label/></typed-peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["ratio-1.00"]);
        assert_eq!(tags(&reply, "ratio"), ["1.00"]);
        assert_eq!(data(&fixture.read(op, "<typed-peer><identity>b:router</identity><ratio>1.00</ratio><label/></typed-peer>", "").await), "");
        assert_eq!(data(&fixture.read(op, "<typed-peer><identity>a:router</identity><ratio>1</ratio><label/></typed-peer>", "").await), "");
    }
}

#[tokio::test]
async fn subtree_content_alternatives_keep_nested_scope() {
    let fixture = Fixture::new(config(), &[]).await;
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.read(op, "<peer><site>east</site><id>7</id><lane><slot>1</slot><label/></lane></peer><peer><site>west</site><lane><slot>2</slot><label/></lane></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker-1", "gamma-marker-2"]);
        assert_eq!(tags(&reply, "id"), ["7", "7"]);
        let reply = fixture.read(op, "<peer><cost>7</cost><label/></peer><peer><site>east</site><id>7</id><label/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
        assert_eq!(tags(&reply, "id"), ["7"]);
    }
}

#[tokio::test]
async fn subtree_content_output_selection_rules() {
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.read("get-config", "<peer><site>east</site><id>7</id><label/></peer>", "").await;
    assert_eq!(data(&reply), format!("<ex:system xmlns:ex=\"{EX}\"><ex:peer><ex:site>east</ex:site><ex:id>7</ex:id><ex:label>alpha-marker</ex:label></ex:peer></ex:system>"));
    let reply = fixture.read("get-config", "<peer><site>east</site><id>7</id></peer>", "").await;
    assert_eq!(tags(&reply, "cost"), ["7"]);
    assert_eq!(tags(&reply, "enabled"), ["true"]);
    assert_eq!(tags(&reply, "label"), ["alpha-marker", "alpha-marker-1", "alpha-marker-2"]);
    assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;"]);
}

#[tokio::test]
async fn subtree_content_key_subsets_and_state_join() {
    let fixture = Fixture::new(config(), &[]).await;
    *fixture.access.values.lock().unwrap() = vec![
        state("/ex:system/ex:peer[ex:site='east'][ex:id='7']/ex:up", "true"),
        state("/ex:system/ex:peer[ex:site='east'][ex:id='8']/ex:up", "false"),
        state("/ex:system/ex:peer[ex:site='west'][ex:id='7']/ex:up", "true"),
    ];
    for op in ["get", "get-data"] {
        let reply = fixture.read(op, "<peer><cost>7</cost><up>true</up><label/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
        assert_eq!(tags(&reply, "up"), ["true"]);
        let requests = fixture.access.requests.lock().unwrap();
        assert!(requests.last().unwrap().paths.iter().any(|path| path.as_str().ends_with("/ex:up")));
    }
    fixture.access.values.lock().unwrap().clear();
    assert_eq!(data(&fixture.read("get", "<peer><up>true</up><label/></peer>", "").await), "");
    fixture.access.filter_response.store(1, Ordering::SeqCst);
    *fixture.access.values.lock().unwrap() = vec![
        state("/ex:system/ex:peer[ex:site='east'][ex:id='7']/ex:up", "true"),
        state("/ex:system/ex:peer[ex:site='east'][ex:id='8']/ex:up", "false"),
        state("/ex:system/ex:peer[ex:site='west'][ex:id='7']/ex:up", "true"),
        state("/ex:system/ex:peer[ex:site='east'][ex:id='7']/ex:lane[ex:slot='1'][ex:kind='a']/ex:up", "true"),
        state("/ex:system/ex:peer[ex:site='west'][ex:id='7']/ex:lane[ex:slot='2'][ex:kind='b']/ex:up", "true"),
    ];
    for keys in ["<site>east</site>", "<id>+007</id>", "<site>east</site><id>007</id>"] {
        let reply = fixture.read("get", &format!("<peer>{keys}<cost>7</cost><up>true</up><label/></peer>"), "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
        assert_eq!(tags(&reply, "up"), ["true"]);
        let requests = fixture.access.requests.lock().unwrap();
        let paths: Vec<_> = requests.last().unwrap().paths.iter().map(|path| path.as_str()).collect();
        if keys.contains("<id>") { assert!(paths.iter().any(|path| path.contains("[ex:id='7']"))); }
        if keys.contains("<site>") { assert!(paths.iter().any(|path| path.contains("[ex:site='east']"))); }
        assert!(!format!("{:?}", requests.last().unwrap()).contains("east"));
    }
    let reply = fixture.read("get", "<peer><site>east</site><id>7</id><lane><slot>1</slot><up>true</up><label/></lane></peer><peer><site>west</site><lane><slot>2</slot><up>true</up><label/></lane></peer>", "").await;
    assert_eq!(tags(&reply, "label"), ["alpha-marker-1", "gamma-marker-2"]);
    assert_eq!(tags(&reply, "kind"), ["a", "b"]);
    let reply = fixture.rpc(&nmda("operational", Some(false), "<peer><site>east</site><id>7</id><up>true</up><up/></peer>", ""), MgmtLimits::default()).await;
    assert_eq!(tags(&reply, "up"), ["true"]);
    assert!(tags(&reply, "label").is_empty());
    assert!(fixture.access.reads.lock().unwrap().is_empty(), "state-only reads do not inspect config rows");
    for datastore in ["running", "operational"] {
        let reply = fixture.rpc(&nmda(datastore, Some(true), "<peer><up>true</up><label/></peer>", ""), MgmtLimits::default()).await;
        assert_eq!(data(&reply), "");
        assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
    }
    *fixture.access.values.lock().unwrap() = vec![
        state("/ex:system/ex:state-peer[ex:site='north'][ex:id='7']/ex:label", "\"state-alpha\""),
        state("/ex:system/ex:state-peer[ex:site='south'][ex:id='7']/ex:label", "\"state-beta\""),
    ];
    for op in ["get", "get-data"] {
        let reply = fixture.read(op, "<state-peer><site>north</site><id>+007</id><label/></state-peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["state-alpha"]);
        assert_eq!(tags(&reply, "site"), ["north"]);
        assert_eq!(tags(&reply, "id"), ["7"]);
    }
    assert_eq!(data(&fixture.read("get-config", "<state-peer><site>north</site><label/></state-peer>", "").await), "");
    assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);

    let mut model = config();
    let mut row = model.peer.remove(&PeerKey { site: "east".into(), id: 7 }).unwrap();
    let site = "e\\ast'one";
    row.site = LeafPresence::Explicit(site.into());
    model.peer.insert(PeerKey { site: site.into(), id: 7 }, row);
    let fixture = Fixture::new(model, &[]).await;
    let canonical = "/ex:system/ex:peer[ex:site=\"e\\ast'one\"][ex:id='7']/ex:up";
    *fixture.access.values.lock().unwrap() = vec![state(canonical, "true")];
    for op in ["get", "get-data"] {
        let reply = fixture.read(op, "<peer><site>e\\ast'one</site><id>+007</id><up>true</up><label/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
        assert_eq!(tags(&reply, "site"), [site]);
        assert_eq!(tags(&reply, "up"), ["true"]);
        assert!(fixture.access.requests.lock().unwrap().last().unwrap().paths.iter().any(|path| path.as_str() == canonical));
    }
}

#[tokio::test]
async fn subtree_content_denied_dependencies_precede_access() {
    for (denied, branch, trap) in [
        ("/ex:system/ex:peer/ex:cost", "<peer><cost>7</cost><label/><lane><label/></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:peer/ex:site", "<peer><lane><label>alpha-marker-1</label></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:peer/ex:id", "<peer><lane><label>alpha-marker-1</label></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:peer/ex:lane/ex:slot", "<peer><lane><label>alpha-marker-1</label></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:peer/ex:lane/ex:kind", "<peer><lane><label>alpha-marker-1</label></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:peer/ex:lane/ex:label", "<peer><lane><label>alpha-marker-1</label></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:peer/ex:lane/ex:up", "<peer><lane><up>true</up><label/></lane></peer>", "/ex:system/ex:peer"),
        ("/ex:system/ex:settings/ex:enabled", "<settings><enabled>true</enabled><label/></settings>", "/ex:system/ex:settings"),
    ] {
      for op in ["get-config", "get", "get-data"] {
        let mut previous = None;
        for rows in 0..3 {
            let mut model = config();
            if rows == 0 { model.peer.clear(); model.settings = None; }
            if rows == 2 {
                for row in model.peer.values_mut() {
                    row.site = LeafPresence::Absent;
                    row.id = LeafPresence::Absent;
                    row.cost = LeafPresence::Absent;
                    for lane in row.lane.values_mut() {
                        lane.slot = LeafPresence::Absent;
                        lane.kind = LeafPresence::Absent;
                        lane.label = LeafPresence::Absent;
                    }
                }
                model.settings.as_mut().unwrap().enabled = LeafPresence::Absent;
            }
            let fixture = Fixture::new(model, &[denied]).await;
            *fixture.access.trap.lock().unwrap() = Some(trap);
            *fixture.access.provider_trap.lock().unwrap() = Some(trap);
            fixture.access.filter_response.store(1, Ordering::SeqCst);
            *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:uptime", "42")];
            if rows != 0 { fixture.access.values.lock().unwrap().push(state(
                if rows == 1 { "/ex:system/ex:peer[ex:site='east'][ex:id='7']/ex:lane[ex:slot='1'][ex:kind='a']/ex:up" }
                else { "/ex:system/ex:peer/ex:lane/ex:up" }, "true")); }
            let reply = fixture.read(op, &format!("{branch}<hostname/><uptime/>"), "").await;
            assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
            assert!(tags(&reply, "label").is_empty());
            assert_eq!(fixture.access.provider.load(Ordering::SeqCst), usize::from(op != "get-config"));
            assert_eq!(tags(&reply, "uptime"), if op == "get-config" { vec![] } else { vec!["42"] });
            assert_eq!(fixture.access.budget.lock().unwrap().as_ref().map(SubtreeBudget::predicate_trials), Some(0));
            let observation = (reply, fixture.observation());
            if let Some(previous) = &previous { assert_eq!(&observation, previous); }
            previous = Some(observation);
        }
      }
    }
    // One alternative on this list is denied while another still reads rows.
    // Changing only the denied leaf cannot change trials, charges or output.
    for op in ["get-config", "get", "get-data"] {
        let mut previous = None;
        for cost in [LeafPresence::Absent, LeafPresence::Explicit(7), LeafPresence::Explicit(u16::MAX)] {
            let mut model = config();
            for row in model.peer.values_mut() { row.cost = cost.clone(); }
            let fixture = Fixture::new(model, &["/ex:system/ex:peer/ex:cost"]).await;
            *fixture.access.trap.lock().unwrap() = Some("/ex:system/ex:peer/ex:cost");
            let reply = fixture.read(op, "<peer><cost>7</cost><label/></peer><peer><site>west</site><label/></peer>", "").await;
            assert_eq!(tags(&reply, "label"), ["gamma-marker"]);
            assert_eq!(fixture.access.budget.lock().unwrap().as_ref().map(SubtreeBudget::predicate_trials), Some(3));
            let observation = (reply, fixture.observation());
            if let Some(previous) = &previous { assert_eq!(&observation, previous); }
            previous = Some(observation);
        }
    }
}

#[tokio::test]
async fn subtree_content_denied_output_preserves_siblings() {
    let fixture = Fixture::new(config(), &["/ex:system/ex:peer/ex:label"]).await;
    for op in ["get-config", "get", "get-data"] {
    let reply = fixture.read(op, "<peer><cost>7</cost><label/><enabled/><credential/></peer>", "").await;
    assert!(tags(&reply, "label").is_empty());
    assert_eq!(tags(&reply, "enabled"), ["true"]);
    assert_eq!(tags(&reply, "cost"), ["7"]);
    assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;"]);
    assert_eq!(tags(&reply, "id"), ["7"]);
    let reply = fixture.read(op, "<hostname>router-marker</hostname><peer/>", "").await;
    assert_eq!(tags(&reply, "label"), ["alpha-marker-1", "alpha-marker-2", "beta-marker-1", "beta-marker-2", "gamma-marker-1", "gamma-marker-2"]);
    assert_eq!(tags(&reply, "cost"), ["7", "8", "8"]);
    }
    let fixture = Fixture::new(config(), &["/ex:system/ex:settings/ex:label", "/ex:system/ex:settings/ex:enabled"]).await;
    *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:uptime", "7")];
    for op in ["get", "get-data"] {
        let reply = fixture.read(op, "<uptime>7</uptime><settings/>", "").await;
        assert!(data(&reply).contains("<ex:settings></ex:settings>"), "a selected existing container survives child denials: {reply}");
        assert!(tags(&reply, "label").is_empty());
        assert!(tags(&reply, "enabled").is_empty());
    }
}

#[tokio::test]
async fn subtree_content_non_cleartext_leaf_is_refused() {
    for denied in [vec![], vec!["/ex:system/**"]] {
        for model in [config(), System::default()] {
            let fixture = Fixture::new(model, &denied).await;
            for op in ["get-config", "get", "get-data"] {
                for leaf in ["secret", "intercept", "password", "unclassified", "state-secret", "state-intercept", "state-password", "state-unclassified"] {
                    for value in [format!("{leaf}-marker"), "incorrect-guess".into()] {
                      for provider_value in [None, Some("\"incorrect-guess\""), Some("\"secret-marker\""), Some("{}") ] {
                        *fixture.access.values.lock().unwrap() = provider_value.into_iter().map(|value| state(&format!("/ex:system/ex:{leaf}"), value)).collect();
                        let reply = fixture.read(op, &format!("<{leaf}>{value}</{leaf}>"), "").await;
                        error(&reply, "operation-not-supported");
                        fixture.no_access();
                      }
                    }
                    if leaf.starts_with("state-") { continue; }
                    for value in [format!("{leaf}-a"), "wrong-key".into()] {
                        let reply = fixture.read(op, &format!("<class-peer><{leaf}>{value}</{leaf}><label/></class-peer>"), "").await;
                        error(&reply, "operation-not-supported");
                        fixture.no_access();
                    }
                }
                let reply = fixture.read(op, "<hidden-peer><secret>guess</secret><label/></hidden-peer>", "").await;
                error(&reply, "operation-not-supported");
                fixture.no_access();
            }
        }
    }
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.read("get-config", "<hostname>router-marker</hostname><secret/>", "").await;
    assert_eq!(tags(&reply, "secret"), ["&lt;redacted&gt;"]);
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.read(op, "<hostname>router-marker</hostname><class-peer><label/></class-peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["class-row-a", "class-row-b"]);
        for key in ["secret", "intercept", "password", "unclassified"] { assert_eq!(tags(&reply, key), ["&lt;redacted&gt;", "&lt;redacted&gt;"]); }
    }
    for op in ["get", "get-data"] {
        for leaf in ["state-secret", "state-intercept", "state-password", "state-unclassified"] {
            *fixture.access.values.lock().unwrap() = vec![state(&format!("/ex:system/ex:{leaf}"), "\"hidden-state-marker\"")];
            let reply = fixture.read(op, &format!("<hostname>router-marker</hostname><{leaf}/>"), "").await;
            assert_eq!(tags(&reply, leaf), ["&lt;redacted&gt;"]);
            assert!(!reply.contains("hidden-state-marker"));
        }
    }
}

#[tokio::test]
async fn subtree_content_dependencies_share_policy_context() {
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.read("get", "<peer><site>east</site><cost>7</cost><label/></peer>", "").await;
    assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
    assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
    // A separate registry must reuse the initial context. The two policies
    // separately deny opposite projections; combining them would reveal both.
    let fixture = Fixture::new(config(), &["/yanglib:yang-library/**"]).await;
    *fixture.alternate.lock().unwrap() = Some(Arc::new(policy(&["/ex:system/**"])));
    let body = format!("<get><filter><system xmlns=\"{EX}\"><hostname>router-marker</hostname><count/></system><yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"><content-id>{}</content-id><module-set><name/></module-set></yang-library></filter></get>", Registry.schema_digest());
    let reply = fixture.rpc(&body, MgmtLimits::default()).await;
    assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
    assert!(!data(&reply).contains("yanglib:"));
    assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.rpc(&body, MgmtLimits::default()).await;
    assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
    assert!(data(&reply).contains("<yanglib:name>complete</yanglib:name>"), "{reply}");
    assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
    fixture.policy_mode.store(1, Ordering::SeqCst);
    let reply = fixture.rpc(&body, MgmtLimits::default()).await;
    error(&reply, "resource-denied");
    assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.access.model.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn subtree_content_no_match_is_empty() {
    let fixture = Fixture::new(config(), &[]).await;
    for op in ["get-config", "get", "get-data"] {
        for content in ["<hostname>absent-marker</hostname><count/>", "<empty>true</empty><count/>", "<port>65536</port><count/>", "<peer><label>absent-marker</label></peer>"] {
            assert_eq!(data(&fixture.read(op, content, "").await), "");
        }
        let reply = fixture.read(op, "<peer><label>absent-marker</label></peer><hostname/>", "").await;
        assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
        assert!(tags(&reply, "label").is_empty());
    }
}

#[tokio::test]
async fn subtree_content_matches_after_defaults() {
    for explicit in [false, true] {
        let mut model = config();
        if explicit { model.port = LeafPresence::Explicit(7); }
        let fixture = Fixture::new(model, &[]).await;
        for op in ["get-config", "get", "get-data"] {
          for mode in ["", "report-all", "report-all-tagged", "trim", "explicit"] {
            let body = if op == "get-data" { nmda("running", None, "<port/>", mode) } else { request(op, "<port/>", mode) };
            let baseline = fixture.rpc(&body, MgmtLimits::default()).await;
            assert!(!baseline.contains("<rpc-error>"), "baseline {op} {mode}: {baseline}");
            let body = if op == "get-data" { nmda("running", None, "<port>+007</port><hostname/>", mode) } else { request(op, "<port>+007</port><hostname/>", mode) };
            let matched = fixture.rpc(&body, MgmtLimits::default()).await;
            let reported = data(&baseline).contains(">7</ex:port>");
            assert_eq!(tags(&matched, "hostname"), if reported { vec!["router-marker"] } else { vec![] });
            if !reported { assert_eq!(data(&matched), ""); }
            if reported && mode == "report-all-tagged" && !explicit { assert!(data(&matched).contains("wd:default=\"true\"")); }
            let body = if op == "get-data" { nmda("running", None, "<peer><mode>auto</mode><label/></peer>", mode) } else { request(op, "<peer><mode>auto</mode><label/></peer>", mode) };
            let matched = fixture.rpc(&body, MgmtLimits::default()).await;
            assert_eq!(tags(&matched, "label"), if matches!(mode, "report-all" | "report-all-tagged") { vec!["alpha-marker", "beta-marker", "gamma-marker"] } else { vec![] });
            if op != "get-data" || mode.is_empty() {
                assert_eq!(data(&fixture.read(op, "<state-default>7</state-default><hostname/>", mode).await), "", "state defaults are never invented");
            }
          }
        }
    }
    let fixture = Fixture::new(System::default(), &[]).await;
    for mode in ["report-all", "report-all-tagged"] {
        assert_eq!(data(&fixture.read("get-config", "<peer><mode>auto</mode><label/></peer>", mode).await), "", "defaults never create list instances");
    }
    let fixture = Fixture::new(config(), &[]).await;
    fixture.access.basic_report_all.store(1, Ordering::SeqCst);
    for op in ["get-config", "get", "get-data"] {
        let body = if op == "get-data" { nmda("running", None, "<port/>", "") } else { request(op, "<port/>", "") };
        assert_eq!(tags(&fixture.rpc(&body, MgmtLimits::default()).await, "port"), ["7"]);
        let body = if op == "get-data" { nmda("running", None, "<port>+007</port><hostname/>", "") } else { request(op, "<port>+007</port><hostname/>", "") };
        assert_eq!(tags(&fixture.rpc(&body, MgmtLimits::default()).await, "hostname"), ["router-marker"]);
    }
}

#[tokio::test]
async fn subtree_content_provider_validation_is_atomic() {
    let fixture = Fixture::new(config(), &[]).await;
    *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:uptime", "7")];
    assert_eq!(tags(&fixture.read("get", "<uptime>7</uptime><hostname/>", "").await, "hostname"), ["router-marker"]);
    for invalid in [
        state("/ex:system/ex:uptime", "8"),
        state("/ex:system/ex:hostname", "\"unsolicited\""),
    ] {
        *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:uptime", "7"), invalid];
        let reply = fixture.read("get", "<uptime>7</uptime><hostname/>", "").await;
        error(&reply, "operation-failed");
        assert!(!reply.contains("router-marker"));
    }
    let valid = "/ex:system/ex:peer[ex:site='east'][ex:id='7']/ex:up";
    for op in ["get", "get-data"] {
        for (bad_path, bad_value) in [
            (valid, "false"),
            ("/ex:system/ex:peer/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='east']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='east'][ex:id='7'][ex:extra='x']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='east'][ex:site='east'][ex:id='8']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:id='8'][ex:site='east']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='east'][ex:id='008']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='east'][ex:id=8]/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site=\"east\"][ex:id='8']/ex:up", "false"),
            ("/ex:system/ex:peer[site='east'][id='8']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='west'][ex:id='8']/ex:up", "false"),
            ("/ex:system/ex:peer[ex:site='east'][ex:id='8']/ex:label", "\"unsolicited\""),
            ("/ex:system/ex:peer[ex:site='east'][ex:id='8']/ex:up", "{}"),
            ("/ex:system/ex:peer[ex:site='east'][ex:id='8']/ex:up", "[false]"),
        ] {
            *fixture.access.values.lock().unwrap() = vec![state(valid, "true"), state(bad_path, bad_value)];
            let reply = fixture.read(op, "<peer><site>east</site><up>true</up><label/></peer>", "").await;
            error(&reply, "operation-failed");
            assert!(!reply.contains("alpha-marker"));
            assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 1);
        }
        *fixture.access.values.lock().unwrap() = vec![state(valid, "true"), state("/ex:system/ex:peer[ex:site='east'][ex:id='8']/ex:up", "false").with_origin(Some(opc_mgmt_opstate::Origin::System))];
        error(&fixture.read(op, "<peer><up>true</up><label/></peer>", "").await, "operation-failed");
        *fixture.access.values.lock().unwrap() = vec![
            state("/ex:system/ex:state-peer[ex:site='north'][ex:id='7']/ex:label", "\"state-marker\""),
            state("/ex:system/ex:state-peer[ex:site='north'][ex:id='7']/ex:id", "8"),
        ];
        error(&fixture.read(op, "<state-peer><label>state-marker</label><id/></state-peer>", "").await, "operation-failed");
        let body = request(op, "<peer><up>true</up><up/></peer>", "");
        let limits = MgmtLimits { max_paths_per_request: 16, max_value_bytes: 64, ..MgmtLimits::default() };
        *fixture.access.values.lock().unwrap() = (0..16).map(|id| state(&format!("/ex:system/ex:peer[ex:site='east'][ex:id='{id}']/ex:up"), "true")).collect();
        let reply = fixture.rpc(&body, limits).await;
        assert_eq!(tags(&reply, "up"), vec!["true"; 16]);
        assert_eq!(fixture.access.requests.lock().unwrap().last().unwrap().max_values, 16);
        fixture.access.values.lock().unwrap().push(state("/ex:system/ex:peer[ex:site='east'][ex:id='16']/ex:up", "false"));
        error(&fixture.rpc(&body, limits).await, "too-big");
        let path = format!("/ex:system/ex:peer[ex:site='{}'][ex:id='7']/ex:up", "x".repeat(64 - valid.len() + 4));
        assert_eq!(path.len(), 64);
        *fixture.access.values.lock().unwrap() = vec![state(&path, "true")];
        assert_eq!(tags(&fixture.rpc(&body, limits).await, "up"), ["true"]);
        fixture.access.values.lock().unwrap().push(state(&path.replace("xxx", "xxxx"), "false"));
        error(&fixture.rpc(&body, limits).await, "too-big");
        let body = request(op, "<uptime>7</uptime><hostname/>", "");
        *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:uptime", &format!("7{}", " ".repeat(63)))];
        assert_eq!(tags(&fixture.rpc(&body, limits).await, "hostname"), ["router-marker"]);
        *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:uptime", &format!("7{}", " ".repeat(64)))];
        error(&fixture.rpc(&body, limits).await, "too-big");
    }
}

#[tokio::test]
async fn subtree_content_size_and_plan_limits() {
    let fixture = Fixture::new(config(), &[]).await;
    let body = request("get-config", "<hostname>router<![CDATA[-marker]]></hostname><count/>", "");
    let limits = MgmtLimits { max_value_bytes: 64, max_subtree_filter_content_match_nodes: 1, ..MgmtLimits::default() };
    assert_eq!(tags(&fixture.rpc(&body, limits).await, "count"), [u32::MAX.to_string()]);
    let body = request("get-config", &format!("<hostname>{}<![CDATA[{}]]></hostname>", "a".repeat(40), "b".repeat(25)), "");
    error(&fixture.rpc(&body, limits).await, "too-big");
    fixture.no_access();
    let body = request("get-config", "<hostname>router-marker</hostname><enabled>true</enabled>", "");
    error(&fixture.rpc(&body, limits).await, "too-big");
    fixture.no_access();
    let body = request("get-config", "<hostname>router-marker</hostname><count/>", "");
    let xml = format!("<rpc xmlns=\"{NC}\" message-id=\"match\">{body}</rpc>");
    let exact = MgmtLimits { max_request_bytes: xml.len(), max_value_bytes: 64, max_xpath_filter_bytes: 1, ..MgmtLimits::default() };
    let reply = fixture.direct_rpc(&body, exact);
    assert!(!reply.contains("<rpc-error>"), "exact request bytes: {reply}");
    assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
    error(&fixture.direct_rpc(&body, MgmtLimits { max_request_bytes: xml.len() - 1, ..exact }), "too-big");
    fixture.no_access();
    let exact = MgmtLimits { max_xml_depth: 5, max_xml_attributes_per_element: 2, max_xml_namespace_decls: 1, ..MgmtLimits::default() };
    let reply = fixture.rpc(&body, exact).await;
    assert!(!reply.contains("<rpc-error>"), "exact XML shape: {reply}");
    assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
    for small in [MgmtLimits { max_xml_depth: 4, ..exact }, MgmtLimits { max_xml_attributes_per_element: 1, ..exact }] {
        error(&fixture.direct_rpc(&body, small), "too-big"); fixture.no_access();
    }
    let extra_ns = body.replace(&format!("<system xmlns=\"{EX}\">"), &format!("<system xmlns=\"{EX}\" xmlns:extra=\"urn:unused\">"));
    error(&fixture.direct_rpc(&extra_ns, exact), "too-big"); fixture.no_access();
    // Three raw nodes fit before expansion. A separate plan bound then rejects
    // additional resolved scopes and dependencies, without data access.
    let raw_exact = MgmtLimits { max_subtree_filter_nodes: 3, ..MgmtLimits::default() };
    assert!(opc_netconf_server::xml::parse_rpc(&xml, &raw_exact).is_ok());
    assert!(opc_netconf_server::xml::parse_rpc(&xml, &MgmtLimits { max_subtree_filter_nodes: 2, ..raw_exact }).is_err());
    error(&fixture.direct_rpc(&body, raw_exact), "too-big"); fixture.no_access();
    let mut first = None;
    for bound in 4..128 {
        let reply = fixture.direct_rpc(&body, MgmtLimits { max_subtree_filter_nodes: bound, ..MgmtLimits::default() });
        if !reply.contains("<rpc-error>") { first = Some(bound); assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]); break; }
        error(&reply, "too-big"); fixture.no_access();
    }
    let first = first.expect("small plan fits a small node cap");
    error(&fixture.direct_rpc(&body, MgmtLimits { max_subtree_filter_nodes: first - 1, ..MgmtLimits::default() }), "too-big");
    fixture.no_access();
}

#[tokio::test]
async fn subtree_content_work_is_bounded_without_output() {
    let fixture = Fixture::new(config(), &[]).await;
    assert_eq!(data(&fixture.read("get-config", "<peer><label>missing</label></peer>", "").await), "");
    let mut model = config();
    model.peer.clear();
    for id in 0..20_000 {
        let mut peer = Peer::default();
        peer.site = LeafPresence::Explicit("wide".into());
        peer.id = LeafPresence::Explicit(id);
        peer.label = LeafPresence::Explicit("x".repeat(1_024));
        model.peer.insert(PeerKey { site: "wide".into(), id }, peer);
    }
    let fixture = Fixture::new(model, &[]).await;
    error(&fixture.read("get-config", "<peer><label>missing</label></peer>", "").await, "too-big");
    for content in [
        "<peer><label>missing</label><id/></peer>",
        "<peer><label>missing</label><id/></peer><peer><label>missing</label><id/></peer>",
        "<peer><lane><label>missing</label><slot/></lane></peer>",
    ] {
        let fixture = Fixture::new(config(), &[]).await;
        let body = request("get-config", content, "");
        assert_eq!(data(&fixture.rpc(&body, MgmtLimits::default()).await), "");
        let used = MgmtLimits::default().max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
        assert!(used < 250_000, "small fixtures need a small allowance");
        let exact = MgmtLimits { max_subtree_filter_work_units: used, ..MgmtLimits::default() };
        assert_eq!(data(&fixture.rpc(&body, exact).await), "");
        assert_eq!(fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining(), 0);
        let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: used - 1, ..exact }).await;
        error(&reply, "too-big");
        assert!(!reply.contains("<data"));
    }
    let mut previous = None;
    let mut hidden_budget = None;
    for mut model in [config(), System::default(), config()] {
        if previous.is_some() { for row in model.peer.values_mut() { row.id = LeafPresence::Absent; row.label = LeafPresence::Explicit("hidden".repeat(500)); } }
        model.hostname = LeafPresence::Explicit("router-marker".into());
        let fixture = Fixture::new(model, &["/ex:system/ex:peer/ex:label"]).await;
        *fixture.access.trap.lock().unwrap() = Some("/ex:system/ex:peer");
        let body = request("get-config", "<peer><label>missing</label><id/></peer><hostname/>", "");
        if hidden_budget.is_none() {
            assert_eq!(tags(&fixture.rpc(&body, MgmtLimits::default()).await, "hostname"), ["router-marker"]);
            hidden_budget = Some(MgmtLimits::default().max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining());
        }
        let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: hidden_budget.unwrap(), ..MgmtLimits::default() }).await;
        assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
        let observation = fixture.observation();
        if let Some(previous) = &previous { assert_eq!(&observation, previous); }
        previous = Some(observation);
    }
}

#[tokio::test]
async fn subtree_content_read_preservation() {
    let fixture = Fixture::new(config(), &[]).await;
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.read(op, "<peer><site>east</site><label/><credential/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker", "beta-marker"]);
        assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;", "&lt;redacted&gt;"]);
        assert_eq!(tags(&reply, "id"), ["7", "8"]);
        let reply = fixture.read(op, "<hostname>router-marker</hostname><user-peer><name/><label/></user-peer>", "").await;
        assert_eq!(tags(&reply, "name"), ["z", "a", "m"]);
        assert_eq!(tags(&reply, "label"), ["user-z-&lt;&amp;\"'\\-marker", "user-a-&lt;&amp;\"'\\-marker", "user-m-&lt;&amp;\"'\\-marker"]);
        let reply = fixture.read(op, "<user-peer><name>m</name><label/></user-peer><user-peer><name>z</name><label/></user-peer><user-peer><name>z</name><label/></user-peer>", "").await;
        assert_eq!(tags(&reply, "name"), ["z", "m"]);
        let reply = fixture.read(op, "<peer><site>west</site><label/></peer><peer><site>east</site><label/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker", "beta-marker", "gamma-marker"]);
        let structural = fixture.read(op, "<user-peer><name/><label/></user-peer>", "").await;
        assert_eq!(tags(&structural, "name"), ["z", "a", "m"]);
    }
    let mut stored = config();
    stored.hostname = LeafPresence::Explicit("startup-marker".into());
    let startup = Arc::new(Startup { config: Mutex::new(Some(stored)), loads: AtomicUsize::new(0) });
    let fixture = Fixture::with_datastores(config(), &[], Some(startup.clone()), true).await;
    for datastore in ["running", "candidate", "startup", "intended"] {
      for op in ["get-config", "get-data"] {
        if op == "get-config" && datastore == "intended" { continue; }
        let hostname = if datastore == "startup" { "startup-marker" } else { "router-marker" };
        let children = format!("<hostname>{hostname}</hostname><peer><label/><credential/></peer>");
        let body = if op == "get-config" { request(op, &children, "").replace("<running/>", &format!("<{datastore}/>")) }
            else { nmda(datastore, None, &children, "") };
        let reply = fixture.rpc(&body, MgmtLimits::default()).await;
        assert_eq!(tags(&reply, "hostname"), [hostname]);
        assert_eq!(tags(&reply, "label"), ["alpha-marker", "beta-marker", "gamma-marker"]);
        assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;"; 3]);
        assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
      }
    }
    for denied in [vec![], vec!["/ex:system/**"]] {
      let fixture = Fixture::with_datastores(config(), &denied, Some(startup.clone()), true).await;
      for datastore in ["candidate", "startup"] {
        for op in ["get-config", "get-data"] {
          for (children, schema_refusal) in [("<secret>probe</secret>", true), ("<peer><cost>7</cost><label/></peer>", false)] {
            if !schema_refusal && denied.is_empty() { continue; }
            startup.loads.store(0, Ordering::SeqCst);
            let body = if op == "get-config" { request(op, children, "").replace("<running/>", &format!("<{datastore}/>")) }
                else { nmda(datastore, None, children, "") };
            let reply = fixture.rpc(&body, MgmtLimits::default()).await;
            if schema_refusal { error(&reply, "operation-not-supported"); fixture.no_access(); }
            else { assert_eq!(data(&reply), ""); assert_eq!(fixture.access.model.load(Ordering::SeqCst), 0); }
            assert_eq!(startup.loads.load(Ordering::SeqCst), 0);
          }
        }
      }
    }
    let fixture = Fixture::new(config(), &[]).await;
    fixture.access.unsupported_projection.store(1, Ordering::SeqCst);
    for op in ["get-config", "get", "get-data"] {
        error(&fixture.read(op, "<hostname>router-marker</hostname><count/>", "").await, "operation-not-supported");
        fixture.no_access();
        assert_eq!(tags(&fixture.read(op, "<hostname/>", "").await, "hostname"), ["router-marker"]);
    }
}

#[tokio::test]
async fn subtree_content_masked_payload_has_fixed_work() {
    for op in ["get-config", "get", "get-data"] {
      for mode in ["", "explicit", "trim", "report-all", "report-all-tagged"] {
        let children = "<hostname>router-marker</hostname><secret/><intercept/><password/><unclassified/>";
        let body = if op == "get-data" { nmda("running", None, children, mode) } else { request(op, children, mode) };
        let mut expected = None;
        let mut fixed_work = None;
        for size in [1, 4096] {
            let mut model = config();
            model.secret = SecretLeaf::new(LeafPresence::Explicit("s".repeat(size)));
            model.intercept = SecretLeaf::new(LeafPresence::Explicit("i".repeat(size)));
            model.password = SecretLeaf::new(LeafPresence::Explicit("p".repeat(size)));
            model.unclassified = SecretLeaf::new(LeafPresence::Explicit("u".repeat(size)));
            let fixture = Fixture::new(model, &[]).await;
            if fixed_work.is_none() {
                let reply = fixture.rpc(&body, MgmtLimits::default()).await;
                for leaf in ["secret", "intercept", "password", "unclassified"] {
                    assert_eq!(tags(&reply, leaf), ["&lt;redacted&gt;"]);
                }
                fixed_work = Some(MgmtLimits::default().max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining());
            }
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap(), ..MgmtLimits::default() }).await;
            assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
            assert_eq!(fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining(), 0);
            let observed = (reply, fixture.observation());
            if let Some(expected) = &expected { assert_eq!(&observed, expected, "masked bytes must not change observable work"); }
            expected = Some(observed);
        }
      }
    }
}

async fn candidate_access_is_shared(stored: bool) {
    for op in ["get-config", "get-data"] {
        let mut expected = None;
        let mut fixed_work = None;
        for populated in [false, true] {
            let mut model = config();
            if !populated { model.peer.clear(); }
            let fixture = Fixture::with_datastores(model, &["/ex:system/ex:peer/ex:label"], None, true).await;
            *fixture.access.trap.lock().unwrap() = Some("/ex:system/ex:peer");
            let children = "<peer><label>hidden</label><id/></peer><hostname/>";
            let body = if op == "get-config" { request(op, children, "").replace("<running/>", "<candidate/>") }
                else { nmda("candidate", None, children, "") };
            let setup = if stored {
                format!("<edit-config><target><candidate/></target><config><system xmlns=\"{EX}\"><hostname>candidate-marker</hostname></system></config></edit-config>")
            } else { String::new() };
            let limits = MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap_or(MgmtLimits::default().max_subtree_filter_work_units), ..MgmtLimits::default() };
            let reply = fixture.rpc_after_setup(&body, limits, &setup).await;
            assert_eq!(tags(&reply, "hostname"), [if stored { "candidate-marker" } else { "router-marker" }]);
            assert_eq!(SECRET_CLONES.load(Ordering::SeqCst), 0, "candidate read copied model data before projection");
            assert!(tags(&reply, "id").is_empty());
            assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
            let budget = fixture.access.budget.lock().unwrap().as_ref().unwrap().clone();
            let work = limits.max_subtree_filter_work_units - budget.remaining();
            assert_eq!(budget.predicate_trials(), 0);
            if let Some(expected) = &expected { assert_eq!(&(reply.clone(), work, fixture.access.reads.lock().unwrap().clone()), expected); }
            expected = Some((reply, work, fixture.access.reads.lock().unwrap().clone()));
            fixed_work = Some(work);
        }
    }
}

#[tokio::test]
async fn subtree_content_candidate_fallback_never_clones_denied_rows() {
    candidate_access_is_shared(false).await;
}

#[tokio::test]
async fn subtree_content_stored_candidate_never_clones_denied_rows() {
    candidate_access_is_shared(true).await;
}

#[tokio::test]
async fn subtree_content_state_order_is_canonical() {
    let fixture = Fixture::new(config(), &[]).await;
    for op in ["get", "get-data"] {
        let values = vec![
            state("/ex:system/ex:state-peer[ex:site='north'][ex:id='7']/ex:label", "\"north-label\""),
            state("/ex:system/ex:state-peer[ex:site='south'][ex:id='7']/ex:label", "\"south-label\""),
        ];
        let mut expected = None;
        for reverse in [false, true] {
            *fixture.access.values.lock().unwrap() = values.clone();
            if reverse { fixture.access.values.lock().unwrap().reverse(); }
            let reply = fixture.read(op, "<state-peer><id>7</id><label/></state-peer>", "").await;
            assert_eq!(tags(&reply, "site"), ["north", "south"]);
            assert_eq!(tags(&reply, "label"), ["north-label", "south-label"]);
            if let Some(expected) = &expected { assert_eq!(&reply, expected); }
            expected = Some(reply);
        }
        // State ordering must not reorder configuration's ordered-by-user rows.
        let values: Vec<_> = ["a", "m", "z"].into_iter().map(|name|
            state(&format!("/ex:system/ex:user-peer[ex:name='{name}']/ex:up"), "true")).collect();
        for reverse in [false, true] {
            *fixture.access.values.lock().unwrap() = values.clone();
            if reverse { fixture.access.values.lock().unwrap().reverse(); }
            let reply = fixture.read(op, "<hostname>router-marker</hostname><user-peer><name/><label/><up/></user-peer>", "").await;
            assert_eq!(tags(&reply, "name"), ["z", "a", "m"]);
            assert_eq!(tags(&reply, "up"), ["true"; 3]);
        }
    }
}

#[tokio::test]
async fn subtree_content_signed_references_are_malformed_before_access() {
    let mut model = config();
    model.hostname = LeafPresence::Explicit("A".into());
    let fixture = Fixture::new(model, &[]).await;
    let mut expected = None;
    for op in ["get-config", "get", "get-data"] {
        for reference in ["&#+65;", "&#x+41;", "&#;", "&#x;", "&#-65;", "&#x-41;", "&#0;", "&#xD800;", "&#xFFFF;", "&#x110000;"] {
            let reply = fixture.read(op, &format!("<hostname>{reference}</hostname><count/>"), "").await;
            error(&reply, "malformed-message");
            fixture.no_access();
            assert!(reply.contains("<error-message>malformed message</error-message>"));
            if let Some(expected) = &expected { assert_eq!(&reply, expected); }
            expected = Some(reply);
        }
    }
}

#[tokio::test]
async fn subtree_content_reference_limit_counts_decoded_bytes() {
    let limits = MgmtLimits { max_value_bytes: 64, ..MgmtLimits::default() };
    for op in ["get-config", "get", "get-data"] {
      for literal in ["A".to_string(), "A".repeat(64), "é".repeat(32)] {
        let mut model = config();
        model.hostname = LeafPresence::Explicit(literal.clone());
        let fixture = Fixture::new(model, &[]).await;
        let mut expected = None;
        let decimal: String = literal.chars().map(|ch| format!("&#{}{};", "0".repeat(80), u32::from(ch))).collect();
        let hex: String = literal.chars().map(|ch| format!("&#x{}{:x};", "0".repeat(80), u32::from(ch))).collect();
        for text in [literal.clone(), format!("<![CDATA[{literal}]]>"), decimal, hex] {
            let body = request(op, &format!("<hostname>{text}</hostname><count/>"), "");
            let reply = fixture.rpc(&body, limits).await;
            assert_eq!(tags(&reply, "count"), [u32::MAX.to_string()]);
            if let Some(expected) = &expected { assert_eq!(&reply, expected); }
            expected = Some(reply);
        }
        if literal.len() == limits.max_value_bytes {
            for overflow in [format!("{literal}A"), format!("{literal}&#65;"), format!("<![CDATA[{literal}]]>&#65;")] {
                let reply = fixture.rpc(&request(op, &format!("<hostname>{overflow}</hostname>"), ""), limits).await;
                error(&reply, "too-big");
                fixture.no_access();
            }
        }
      }
    }
}

#[tokio::test]
async fn subtree_content_masked_defaults_preserve_presence() {
    for presence in [LeafPresence::Defaulted("hidden-default".into()), LeafPresence::Defaulted("other".into()), LeafPresence::Explicit("hidden-default".into())] {
        let mut model = config();
        model.secret_default = SecretLeaf::new(presence);
        let fixture = Fixture::new(model, &[]).await;
        for op in ["get-config", "get", "get-data"] {
          for mode in ["", "explicit", "trim", "report-all", "report-all-tagged"] {
            let body = |children| if op == "get-data" { nmda("running", None, children, mode) } else { request(op, children, mode) };
            let ordinary = fixture.rpc(&body("<secret-default/>"), MgmtLimits::default()).await;
            let content = fixture.rpc(&body("<hostname>router-marker</hostname><secret-default/>"), MgmtLimits::default()).await;
            assert_eq!(data(&content).contains("<ex:secret-default"), data(&ordinary).contains("<ex:secret-default"), "{op} {mode}: {ordinary} / {content}");
            assert_eq!(data(&content).contains("wd:default=\"true\""), data(&ordinary).contains("wd:default=\"true\""));
            assert_eq!(data(&content).matches("&lt;redacted&gt;").count(), data(&ordinary).matches("&lt;redacted&gt;").count());
            assert!(!content.contains("hidden-default"));
        }
      }
    }
}

#[tokio::test]
async fn subtree_content_masked_leaf_list_preserves_members_with_fixed_work() {
    for op in ["get-config", "get", "get-data"] {
        let mut expected = None;
        let mut fixed_work = None;
        for size in [1, 4096] {
            let mut model = config();
            model.credentials = SecretLeaf::new(vec![format!("a{}", "s".repeat(size)), format!("b{}", "s".repeat(size))]);
            let fixture = Fixture::new(model, &[]).await;
            let body = request(op, "<hostname>router-marker</hostname><credentials/><credentials/>", "");
            if fixed_work.is_none() {
                assert_eq!(tags(&fixture.rpc(&body, MgmtLimits::default()).await, "credentials"), ["&lt;redacted&gt;"; 2]);
                fixed_work = Some(MgmtLimits::default().max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining());
            }
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap(), ..MgmtLimits::default() }).await;
            assert_eq!(tags(&reply, "credentials"), ["&lt;redacted&gt;"; 2]);
            let observed = (reply, fixture.observation());
            if let Some(expected) = &expected { assert_eq!(&observed, expected); }
            expected = Some(observed);
        }
    }
}

#[tokio::test]
async fn subtree_content_masked_state_payload_has_fixed_work() {
    for op in ["get", "get-data"] {
        let mut expected = None;
        let mut fixed_work = None;
        for size in [1, 2048] {
            let fixture = Fixture::new(config(), &[]).await;
            *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:state-secret", &serde_json::to_string(&"s".repeat(size)).unwrap())];
            let body = request(op, "<hostname>router-marker</hostname><state-secret/>", "");
            let limits = MgmtLimits { max_value_bytes: 4096, ..MgmtLimits::default() };
            if fixed_work.is_none() {
                assert_eq!(tags(&fixture.rpc(&body, limits).await, "state-secret"), ["&lt;redacted&gt;"]);
                fixed_work = Some(limits.max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining());
            }
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap(), ..limits }).await;
            assert_eq!(tags(&reply, "state-secret"), ["&lt;redacted&gt;"]);
            let observed = (reply, fixture.observation());
            if let Some(expected) = &expected { assert_eq!(&observed, expected); }
            expected = Some(observed);
        }
        let fixture = Fixture::new(config(), &[]).await;
        let body = request(op, "<hostname>router-marker</hostname><state-secret/>", "");
        for json in ["\"escaped-\\u0041\"", "true", "false", "7", "1.25"] {
            *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:state-secret", json)];
            assert_eq!(tags(&fixture.rpc(&body, MgmtLimits::default()).await, "state-secret"), ["&lt;redacted&gt;"]);
        }
        *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:state-secret", "null")];
        assert!(tags(&fixture.rpc(&body, MgmtLimits::default()).await, "state-secret").is_empty());
        for json in ["{}", "[false]"] {
            *fixture.access.values.lock().unwrap() = vec![state("/ex:system/ex:state-secret", json)];
            error(&fixture.rpc(&body, MgmtLimits::default()).await, "operation-failed");
        }
    }
}

#[tokio::test]
async fn subtree_content_absent_defaults_match_ordinary_presence() {
    let mut model = config();
    model.secret_default = SecretLeaf::new(LeafPresence::Absent);
    model.port = LeafPresence::Absent;
    let fixture = Fixture::new(model, &[]).await;
    for op in ["get-config", "get", "get-data"] {
      for mode in ["", "explicit", "trim", "report-all", "report-all-tagged"] {
        let body = |children| if op == "get-data" { nmda("running", None, children, mode) } else { request(op, children, mode) };
        let ordinary = fixture.rpc(&body("<port/><secret-default/>"), MgmtLimits::default()).await;
        let content = fixture.rpc(&body("<hostname>router-marker</hostname><port/><secret-default/>"), MgmtLimits::default()).await;
        for leaf in ["port", "secret-default"] {
            let tag = format!("<ex:{leaf}");
            assert!(!data(&ordinary).contains(&tag));
            assert_eq!(data(&content).contains(&tag), data(&ordinary).contains(&tag), "{op} {mode}: {ordinary} / {content}");
        }
        assert_eq!(data(&fixture.rpc(&body("<port>7</port><hostname/>"), MgmtLimits::default()).await), "");
      }
    }
}

#[tokio::test]
async fn subtree_content_masked_config_keys_have_fixed_work() {
    for op in ["get-config", "get", "get-data"] {
      for varied in ["hidden", "secret", "intercept", "password", "unclassified"] {
        let mut expected = None;
        let mut fixed_work = None;
        for size in [1, 4096] {
            let mut model = config();
            model.class_peer.clear();
            let mut values = Vec::new();
            // Crossing the fixed "bb" identity also changes raw sort order.
            // Every row has the same visible values, so that is not observable.
            for identity in ["b".repeat(size), "bb".into()] {
                if varied == "hidden" {
                    let mut row = HiddenPeer::default();
                    row.secret = SecretLeaf::new(LeafPresence::Explicit(identity.clone()));
                    row.label = LeafPresence::Explicit("row-label".into());
                    model.hidden_peer.insert(SensitiveKey::new(identity.clone()), row);
                    values.push(state(&format!("/ex:system/ex:hidden-peer[ex:secret='{identity}']/ex:up"), "true"));
                } else {
                    let secret = if varied == "secret" { identity.clone() } else { "fixed-secret".into() };
                    let intercept = if varied == "intercept" { identity.clone() } else { "fixed-intercept".into() };
                    let password = if varied == "password" { identity.clone() } else { "fixed-password".into() };
                    let unclassified = if varied == "unclassified" { identity.clone() } else { "fixed-unclassified".into() };
                    let mut row = ClassPeer::default();
                    row.secret = SecretLeaf::new(LeafPresence::Explicit(secret.clone()));
                    row.intercept = SecretLeaf::new(LeafPresence::Explicit(intercept.clone()));
                    row.password = SecretLeaf::new(LeafPresence::Explicit(password.clone()));
                    row.unclassified = SecretLeaf::new(LeafPresence::Explicit(unclassified.clone()));
                    row.label = LeafPresence::Explicit("row-label".into());
                    values.push(state(&format!("/ex:system/ex:class-peer[ex:secret='{secret}'][ex:intercept='{intercept}'][ex:password='{password}'][ex:unclassified='{unclassified}']/ex:up"), "true"));
                    model.class_peer.insert(ClassPeerKey { secret, intercept, password, unclassified }, row);
                }
            }
            let fixture = Fixture::new(model, &[]).await;
            if op != "get-config" { *fixture.access.values.lock().unwrap() = values; }
            let list = if varied == "hidden" { "hidden-peer" } else { "class-peer" };
            let children = format!("<hostname>router-marker</hostname><{list}><label/><up/></{list}><{list}><label/><up/></{list}>");
            let body = request(op, &children, "");
            let limits = MgmtLimits { max_value_bytes: 32768, ..MgmtLimits::default() };
            if fixed_work.is_none() {
                assert_eq!(tags(&fixture.rpc(&body, limits).await, "label"), ["row-label"; 2]);
                fixed_work = Some(limits.max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining());
            }
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap(), ..limits }).await;
            assert_eq!(tags(&reply, "label"), ["row-label"; 2], "{op}/{varied}/{size}");
            assert_eq!(tags(&reply, "secret"), ["&lt;redacted&gt;"; 2]);
            if op != "get-config" { assert_eq!(tags(&reply, "up"), ["true"; 2], "state must join the same configuration identities"); }
            assert_eq!(fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining(), 0);
            let observed = (reply, fixture.observation());
            if let Some(expected) = &expected { assert_eq!(&observed, expected, "masked {varied} key length changed {op} work"); }
            expected = Some(observed);
        }
      }
    }
}

#[tokio::test]
async fn subtree_content_masked_state_keys_have_fixed_work() {
    for op in ["get", "get-data"] {
        let mut expected = None;
        let mut fixed_work = None;
        for (size, reverse) in [(1, false), (4096, false), (1, true), (4096, true)] {
            let fixture = Fixture::new(config(), &[]).await;
            let mut values = Vec::new();
            for identity in ["b".repeat(size), "bb".into()] {
                let parent = format!("/ex:system/ex:state-hidden-peer[ex:secret='{identity}']");
                values.push(state(&format!("{parent}/ex:secret"), &serde_json::to_string(&identity).unwrap()));
                values.push(state(&format!("{parent}/ex:label"), "\"state-label\""));
            }
            if reverse { values.reverse(); }
            *fixture.access.values.lock().unwrap() = values;
            let body = request(op, "<hostname>router-marker</hostname><state-hidden-peer><secret/><label/></state-hidden-peer><state-hidden-peer><label/></state-hidden-peer>", "");
            let limits = MgmtLimits { max_value_bytes: 32768, ..MgmtLimits::default() };
            if fixed_work.is_none() {
                assert_eq!(tags(&fixture.rpc(&body, limits).await, "label"), ["state-label"; 2]);
                fixed_work = Some(limits.max_subtree_filter_work_units - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining());
            }
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap(), ..limits }).await;
            assert_eq!(tags(&reply, "label"), ["state-label"; 2]);
            assert_eq!(tags(&reply, "secret"), ["&lt;redacted&gt;"; 2]);
            assert_eq!(fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining(), 0);
            let observed = (reply, fixture.observation());
            if let Some(expected) = &expected { assert_eq!(&observed, expected, "masked state key length/order changed {op} work"); }
            expected = Some(observed);
        }
        // Hashing must not replace complete raw key and canonical-path validation.
        let fixture = Fixture::new(config(), &[]).await;
        let body = request(op, "<hostname>router-marker</hostname><state-hidden-peer><secret/><label/></state-hidden-peer>", "");
        for values in [
            vec![state("/ex:system/ex:state-hidden-peer[ex:secret='b']/ex:secret", "\"different\"")],
            vec![state("/ex:system/ex:state-hidden-peer[ex:secret=\"b\"]/ex:label", "\"state-label\"")],
            vec![state("/ex:system/ex:state-hidden-peer[ex:secret='b']/ex:label", "\"state-label\""), state("/ex:system/ex:state-hidden-peer[ex:secret='b']/ex:label", "\"state-label\"")],
        ] {
            *fixture.access.values.lock().unwrap() = values;
            error(&fixture.rpc(&body, MgmtLimits::default()).await, "operation-failed");
        }
    }
}

async fn direct_context_never_clones_denied_rows(datastore: &str) {
    use opc_mgmt_authz::ReadAuthorizer;
    use opc_netconf_server::operations::get_config::{handle_get_config, GetConfigContext};
    use opc_netconf_server::operations::get_data::{handle_get_data, GetDataContext};
    use opc_netconf_server::xml::RpcOperation;
    for op in ["get-config", "get-data"] {
        let mut expected = None;
        let mut fixed_work = None;
        for populated in [false, true] {
            let mut snapshot = config();
            snapshot.hostname = LeafPresence::Explicit("borrowed-marker".into());
            if !populated { snapshot.peer.clear(); }
            let access = Arc::new(Access::default());
            *access.trap.lock().unwrap() = Some("/ex:system/ex:peer");
            let startup = Arc::new(Startup { config: Mutex::new(None), loads: AtomicUsize::new(0) });
            let binding = Binding {
                bus: Arc::new(ConfigBus::new_dev_only(config(), MockManagedDatastore::new()).await.unwrap()),
                access: access.clone(), startup: Some(startup.clone()), candidate: true,
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let authz = ReadAuthorizer::new(&Registry, Policy {
                rules: Arc::new(policy(&["/ex:system/ex:peer/ex:label"])), calls: calls.clone(),
                mode: Arc::new(AtomicUsize::new(0)), alternate: Arc::new(Mutex::new(None)),
            }).unwrap();
            let audit = Audit::default();
            let principal = TrustedPrincipal::new(WorkloadIdentity::User("subtree-reader".into()), TenantId::new("fixture").unwrap()).with_auth_strength(AuthStrength::MutualTls);
            let children = "<peer><label>hidden</label><id/></peer><hostname/>";
            let body = if op == "get-config" { request(op, children, "").replace("<running/>", &format!("<{datastore}/>")) }
                else { nmda(datastore, None, children, "") };
            let limits = MgmtLimits { max_subtree_filter_work_units: fixed_work.unwrap_or(MgmtLimits::default().max_subtree_filter_work_units), ..MgmtLimits::default() };
            let parsed = opc_netconf_server::xml::parse_rpc(&format!("<rpc xmlns=\"{NC}\" message-id=\"match\">{body}</rpc>"), &limits).unwrap();
            let attrs = opc_netconf_server::error::RpcReplyAttributes::default();
            let candidate_config = (datastore == "candidate").then_some(&snapshot);
            let startup_config = (datastore == "startup").then_some(&snapshot);
            SECRET_CLONES.store(0, Ordering::SeqCst);
            let reply = match parsed.operation {
                RpcOperation::GetConfig(request) => handle_get_config(&binding, GetConfigContext {
                    authz: &authz, audit: &audit, transport: TransportType::NetconfTls,
                    request_id: opc_config_model::RequestId::new(), principal: &principal,
                    message_id: &parsed.message_id, reply_attrs: &attrs, started: std::time::Instant::now(), limits: &limits,
                    candidate_config, candidate_supported: true, startup_config, startup_supported: true,
                }, &request),
                RpcOperation::GetData(request) => handle_get_data(&binding, GetDataContext {
                    authz: &authz, audit: &audit, transport: TransportType::NetconfTls,
                    request_id: opc_config_model::RequestId::new(), principal: &principal,
                    message_id: &parsed.message_id, reply_attrs: &attrs, started: std::time::Instant::now(), limits: &limits,
                    candidate_config, candidate_supported: true, startup_config, startup_supported: true,
                }, &request),
                _ => panic!("expected a datastore read"),
            };
            assert_eq!(tags(&reply, "hostname"), ["borrowed-marker"]);
            assert_eq!(SECRET_CLONES.load(Ordering::SeqCst), 0, "public {op} cloned its {datastore} snapshot");
            assert!(tags(&reply, "id").is_empty());
            assert_eq!(access.model.load(Ordering::SeqCst), 0);
            assert_eq!(access.provider.load(Ordering::SeqCst), 0);
            assert_eq!(startup.loads.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let budget = access.budget.lock().unwrap().as_ref().unwrap().clone();
            let work = limits.max_subtree_filter_work_units - budget.remaining();
            assert_eq!(budget.predicate_trials(), 0);
            let observed = (reply, work, access.reads.lock().unwrap().clone());
            if let Some(expected) = &expected { assert_eq!(&observed, expected); }
            expected = Some(observed);
            fixed_work = Some(work);
        }
    }
}

#[tokio::test]
async fn subtree_content_public_candidate_handler_never_clones_denied_rows() {
    direct_context_never_clones_denied_rows("candidate").await;
}

#[tokio::test]
async fn subtree_content_public_startup_handler_never_clones_denied_rows() {
    direct_context_never_clones_denied_rows("startup").await;
}

#[tokio::test]
async fn subtree_content_masked_composite_key_prefix_equality_has_fixed_work() {
    let mut summaries = Vec::new();
    for op in ["get-config", "get", "get-data"] {
        let body = request(op, "<hostname>router-marker</hostname><class-peer><label/></class-peer><class-peer><label/></class-peer>", "");
        let mut fixtures = Vec::new();
        let mut controls = Vec::new();
        for size in [1, 4096] {
            let mut model = config();
            model.class_peer.clear();
            for (secret, suffix) in [("b".to_owned(), "a"), ("b".repeat(size), "z")] {
                let intercept = "fixed-intercept".to_owned();
                let password = "fixed-password".to_owned();
                let unclassified = suffix.to_owned();
                let mut row = ClassPeer::default();
                row.secret = SecretLeaf::new(LeafPresence::Explicit(secret.clone()));
                row.intercept = SecretLeaf::new(LeafPresence::Explicit(intercept.clone()));
                row.password = SecretLeaf::new(LeafPresence::Explicit(password.clone()));
                row.unclassified = SecretLeaf::new(LeafPresence::Explicit(unclassified.clone()));
                row.label = LeafPresence::Explicit("same-row-label".into());
                model.class_peer.insert(ClassPeerKey { secret, intercept, password, unclassified }, row);
            }
            let fixture = Fixture::new(model, &[]).await;
            let reply = fixture.rpc(&body, MgmtLimits::default()).await;
            assert_eq!(tags(&reply, "label"), ["same-row-label"; 2]);
            assert_eq!(tags(&reply, "secret"), ["&lt;redacted&gt;"; 2]);
            let used = MgmtLimits::default().max_subtree_filter_work_units
                - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
            controls.push((reply, used, fixture.observation()));
            fixtures.push(fixture);
        }
        assert_eq!(controls[0].0, controls[1].0, "generous-budget authorized replies must be identical");
        let limit = controls.iter().map(|(_, used, _)| *used).min().unwrap();
        let mut bounded = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit, ..MgmtLimits::default() }).await;
            if reply.contains("<rpc-error>") { error(&reply, "too-big"); }
            bounded.push((reply, fixture.observation(), fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining()));
        }
        let mut overflow = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
            error(&reply, "too-big");
            overflow.push((reply, fixture.observation()));
        }
        let invariant = controls[0].1 == controls[1].1
            && controls[0].2 == controls[1].2
            && bounded[0] == bounded[1]
            && bounded[0].0 == controls[0].0
            && bounded[0].2 == 0
            && overflow[0] == overflow[1];
        summaries.push((op, controls[0].1, controls[1].1, invariant));
    }
    assert!(summaries.iter().all(|(_, _, _, invariant)| *invariant), "masked identities changed exact-boundary replies, work or complete observations: {summaries:?}");
}

#[tokio::test]
async fn subtree_content_masked_key_reorders_rejected_rows_without_changing_work() {
    let mut summaries = Vec::new();
    for op in ["get-config", "get", "get-data"] {
        let body = request(op, "<hostname>router-marker</hostname><hidden-peer><label>selected-row</label></hidden-peer>", "");
        let mut fixtures = Vec::new();
        let mut controls = Vec::new();
        for key in ["a".to_owned(), "z".repeat(4096)] {
            let mut model = config();
            model.hidden_peer.clear();
            for (secret, label) in [(key, "selected-row"), ("m".to_owned(), "rejected-row")] {
                let mut row = HiddenPeer::default();
                row.secret = SecretLeaf::new(LeafPresence::Explicit(secret.clone()));
                row.label = LeafPresence::Explicit(label.into());
                model.hidden_peer.insert(SensitiveKey::new(secret), row);
            }
            let fixture = Fixture::new(model, &[]).await;
            let reply = fixture.rpc(&body, MgmtLimits::default()).await;
            assert_eq!(tags(&reply, "label"), ["selected-row"]);
            assert_eq!(tags(&reply, "secret"), ["&lt;redacted&gt;"]);
            let used = MgmtLimits::default().max_subtree_filter_work_units
                - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
            controls.push((reply, used, fixture.observation()));
            fixtures.push(fixture);
        }
        assert_eq!(controls[0].0, controls[1].0, "generous-budget authorized replies must be identical");
        let limit = controls.iter().map(|(_, used, _)| *used).min().unwrap();
        let mut bounded = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit, ..MgmtLimits::default() }).await;
            if reply.contains("<rpc-error>") { error(&reply, "too-big"); }
            bounded.push((reply, fixture.observation(), fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining()));
        }
        let mut overflow = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
            error(&reply, "too-big");
            overflow.push((reply, fixture.observation()));
        }
        let invariant = controls[0].1 == controls[1].1
            && controls[0].2 == controls[1].2
            && bounded[0] == bounded[1]
            && bounded[0].0 == controls[0].0
            && bounded[0].2 == 0
            && overflow[0] == overflow[1];
        summaries.push((op, controls[0].1, controls[1].1, invariant));
    }
    assert!(summaries.iter().all(|(_, _, _, invariant)| *invariant), "masked identities changed exact-boundary replies, work or complete observations: {summaries:?}");
}

#[tokio::test]
async fn subtree_content_masked_state_join_shape_has_fixed_work() {
    let mut summaries = Vec::new();
    for op in ["get", "get-data"] {
        let body = request(op, "<hidden-peer><up>true</up><label/></hidden-peer><hostname/>", "");
        let mut fixtures = Vec::new();
        let mut controls = Vec::new();
        for size in [1, 4096] {
            let mut model = config();
            model.hidden_peer.clear();
            let mut row = HiddenPeer::default();
            row.secret = SecretLeaf::new(LeafPresence::Explicit("b".into()));
            row.label = LeafPresence::Explicit("configuration-row".into());
            model.hidden_peer.insert(SensitiveKey::new("b".into()), row);
            let fixture = Fixture::new(model, &[]).await;
            let key = "b".repeat(size);
            *fixture.access.values.lock().unwrap() = vec![state(&format!("/ex:system/ex:hidden-peer[ex:secret='{key}']/ex:up"), "false")];
            let reply = fixture.rpc(&body, MgmtLimits::default()).await;
            assert!(!reply.contains("<rpc-error>"), "{reply}");
            assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
            assert!(tags(&reply, "label").is_empty());
            assert!(tags(&reply, "up").is_empty());
            let used = MgmtLimits::default().max_subtree_filter_work_units
                - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
            controls.push((reply, used, fixture.observation()));
            fixtures.push(fixture);
        }
        assert_eq!(controls[0].0, controls[1].0);
        let limit = controls.iter().map(|(_, used, _)| *used).min().unwrap();
        let mut bounded = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit, ..MgmtLimits::default() }).await;
            if reply.contains("<rpc-error>") { error(&reply, "too-big"); }
            bounded.push((reply, fixture.observation(), fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining()));
        }
        eprintln!("cross-phase-config-state {op}: work={:?}, fixed_limit={limit}, too_big={:?}", controls.iter().map(|x| x.1).collect::<Vec<_>>(), bounded.iter().map(|(reply, _, _)| reply.contains("<error-tag>too-big</error-tag>")).collect::<Vec<_>>());
        let mut below = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
            error(&reply, "too-big");
            below.push((reply, fixture.observation()));
        }
        let invariant = controls[0].1 == controls[1].1
            && controls[0].2 == controls[1].2
            && bounded[0] == bounded[1]
            && bounded[0].0 == controls[0].0
            && bounded[0].2 == 0
            && below[0] == below[1];
        summaries.push((op, controls[0].1, controls[1].1, invariant));
    }
    assert!(summaries.iter().all(|(_, _, _, invariant)| *invariant), "masked join identity changed later accounting: {summaries:?}");
}

#[tokio::test]
async fn subtree_content_masked_provider_grouping_has_fixed_work() {
    let mut summaries = Vec::new();
    for op in ["get", "get-data"] {
        let body = request(op, "<state-hidden-peer><label>selected-row</label></state-hidden-peer><hostname/>", "");
        let mut fixtures = Vec::new();
        let mut controls = Vec::new();
        for size in [1, 4096] {
            let fixture = Fixture::new(config(), &[]).await;
            let key = "b".repeat(size);
            *fixture.access.values.lock().unwrap() = vec![
                state("/ex:system/ex:state-hidden-peer[ex:secret='b']/ex:label", "\"selected-row\""),
                state(&format!("/ex:system/ex:state-hidden-peer[ex:secret='{key}']/ex:secret"), &serde_json::to_string(&key).unwrap()),
            ];
            let reply = fixture.rpc(&body, MgmtLimits::default()).await;
            assert!(!reply.contains("<rpc-error>"), "{reply}");
            assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
            assert_eq!(tags(&reply, "label"), ["selected-row"]);
            assert_eq!(tags(&reply, "secret"), ["&lt;redacted&gt;"]);
            let used = MgmtLimits::default().max_subtree_filter_work_units
                - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
            controls.push((reply, used, fixture.observation()));
            fixtures.push(fixture);
        }
        assert_eq!(controls[0].0, controls[1].0);
        let limit = controls.iter().map(|(_, used, _)| *used).min().unwrap();
        let mut bounded = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit, ..MgmtLimits::default() }).await;
            if reply.contains("<rpc-error>") { error(&reply, "too-big"); }
            bounded.push((reply, fixture.observation(), fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining()));
        }
        eprintln!("cross-phase-provider-grouping {op}: work={:?}, fixed_limit={limit}, too_big={:?}", controls.iter().map(|x| x.1).collect::<Vec<_>>(), bounded.iter().map(|(reply, _, _)| reply.contains("<error-tag>too-big</error-tag>")).collect::<Vec<_>>());
        let mut below = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
            error(&reply, "too-big");
            below.push((reply, fixture.observation()));
        }
        let invariant = controls[0].1 == controls[1].1
            && controls[0].2 == controls[1].2
            && bounded[0] == bounded[1]
            && bounded[0].0 == controls[0].0
            && bounded[0].2 == 0
            && below[0] == below[1];
        summaries.push((op, controls[0].1, controls[1].1, invariant));
    }
    assert!(summaries.iter().all(|(_, _, _, invariant)| *invariant), "masked provider grouping changed later accounting: {summaries:?}");
}

#[tokio::test]
async fn subtree_content_masked_join_preserves_predicate_admissions() {
    let mut summaries = Vec::new();
    for op in ["get", "get-data"] {
        let body = request(op, "<hidden-peer><label>configuration-row</label><up>true</up></hidden-peer><hostname/>", "");
        let mut fixtures = Vec::new();
        let mut controls = Vec::new();
        for size in [1, 4096] {
            let mut model = config();
            model.hidden_peer.clear();
            let mut row = HiddenPeer::default();
            row.secret = SecretLeaf::new(LeafPresence::Explicit("b".into()));
            row.label = LeafPresence::Explicit("configuration-row".into());
            model.hidden_peer.insert(SensitiveKey::new("b".into()), row);
            let fixture = Fixture::new(model, &[]).await;
            let key = "b".repeat(size);
            *fixture.access.values.lock().unwrap() = vec![state(&format!("/ex:system/ex:hidden-peer[ex:secret='{key}']/ex:up"), "false")];
            let reply = fixture.rpc(&body, MgmtLimits::default()).await;
            assert!(!reply.contains("<rpc-error>"), "{reply}");
            assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
            assert!(tags(&reply, "label").is_empty());
            assert!(tags(&reply, "up").is_empty());
            let used = MgmtLimits::default().max_subtree_filter_work_units
                - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
            controls.push((reply, used, fixture.observation()));
            fixtures.push(fixture);
        }
        assert_eq!(controls[0].0, controls[1].0);
        let limit = controls.iter().map(|(_, used, _)| *used).min().unwrap();
        let mut bounded = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit, ..MgmtLimits::default() }).await;
            if reply.contains("<rpc-error>") { error(&reply, "too-big"); }
            bounded.push((reply, fixture.observation(), fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining()));
        }
        eprintln!("cross-phase-predicate-admission {op}: work={:?}, fixed_limit={limit}, too_big={:?}", controls.iter().map(|x| x.1).collect::<Vec<_>>(), bounded.iter().map(|(reply, _, _)| reply.contains("<error-tag>too-big</error-tag>")).collect::<Vec<_>>());
        let mut below = Vec::new();
        for fixture in &fixtures {
            let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: limit.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
            error(&reply, "too-big");
            below.push((reply, fixture.observation()));
        }
        let invariant = controls[0].1 == controls[1].1
            && controls[0].2 == controls[1].2
            && bounded[0] == bounded[1]
            && bounded[0].0 == controls[0].0
            && bounded[0].2 == 0
            && below[0] == below[1];
        summaries.push((op, controls[0].1, controls[1].1, invariant));
    }
    assert!(summaries.iter().all(|(_, _, _, invariant)| *invariant), "masked join identity changed conjunctive predicate admissions: {summaries:?}");
}

async fn masked_provider_get_config_boundary_is_independent(grouped: bool) {
    let tree = if grouped {
        "<state-hidden-peer><label>selected-row</label></state-hidden-peer><hostname/>"
    } else {
        "<hidden-peer><up>true</up><label/></hidden-peer><hostname/>"
    };
    let body = request("get-config", tree, "");
    let mut fixtures = Vec::new();
    let mut controls = Vec::new();
    for size in [1, 4096] {
        let mut model = config();
        model.hidden_peer.clear();
        let mut row = HiddenPeer::default();
        row.secret = SecretLeaf::new(LeafPresence::Explicit("b".into()));
        row.label = LeafPresence::Explicit("configuration-row".into());
        model.hidden_peer.insert(SensitiveKey::new("b".into()), row);
        let fixture = Fixture::new(model, &[]).await;
        let key = "b".repeat(size);
        *fixture.access.values.lock().unwrap() = if grouped {
            vec![
                state("/ex:system/ex:state-hidden-peer[ex:secret='b']/ex:label", "\"selected-row\""),
                state(&format!("/ex:system/ex:state-hidden-peer[ex:secret='{key}']/ex:secret"), &serde_json::to_string(&key).unwrap()),
            ]
        } else {
            vec![state(&format!("/ex:system/ex:hidden-peer[ex:secret='{key}']/ex:up"), "false")]
        };
        let reply = fixture.rpc(&body, MgmtLimits::default()).await;
        assert!(!reply.contains("<rpc-error>"), "{reply}");
        assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
        assert!(tags(&reply, "label").is_empty());
        assert!(tags(&reply, "up").is_empty());
        assert!(tags(&reply, "secret").is_empty());
        assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
        let work = MgmtLimits::default().max_subtree_filter_work_units
            - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
        controls.push((reply, work, fixture.observation()));
        fixtures.push(fixture);
    }
    assert_eq!(controls[0], controls[1], "configuration reads must not observe provider identity changes");
    let boundary = controls[0].1;
    let mut exact = Vec::new();
    let mut below = Vec::new();
    for fixture in &fixtures {
        let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: boundary, ..MgmtLimits::default() }).await;
        assert_eq!(reply, controls[0].0);
        assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining(), 0);
        exact.push((reply, fixture.observation()));
        let reply = fixture.rpc(&body, MgmtLimits { max_subtree_filter_work_units: boundary.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
        error(&reply, "too-big");
        assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
        below.push((reply, fixture.observation()));
    }
    assert_eq!(exact[0], exact[1], "exact-boundary replies and full observations");
    assert_eq!(below[0], below[1], "one-below errors and full observations");
}

#[tokio::test]
async fn subtree_content_masked_state_join_get_config_has_fixed_work() {
    masked_provider_get_config_boundary_is_independent(false).await;
}

#[tokio::test]
async fn subtree_content_masked_provider_grouping_get_config_has_fixed_work() {
    masked_provider_get_config_boundary_is_independent(true).await;
}

#[tokio::test]
async fn subtree_content_discovery_append_is_reserved_from_original_capture() {
    let matched = Registry.schema_digest().to_owned();
    let mut unmatched = matched.clone();
    unmatched.replace_range(..1, if matched.starts_with('a') { "b" } else { "a" });
    let mut cases = Vec::new();
    for (literal, selected) in [(matched.clone(), true), (unmatched, false)] {
        let fixture = Fixture::new(config(), &[]).await;
        let body = format!("<get><filter><system xmlns=\"{EX}\"><hostname/></system><yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"><content-id>{literal}</content-id><content-id/></yang-library></filter></get>");
        let reply = fixture.rpc(&body, MgmtLimits::default()).await;
        assert!(!reply.contains("<rpc-error>"), "{reply}");
        assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
        let content_ids: Vec<_> = data(&reply).split("<yanglib:content-id>").skip(1)
            .map(|part| part.split_once("</yanglib:content-id>").unwrap().0).collect();
        if selected {
            assert_eq!(content_ids, [matched.as_str()]);
        } else {
            assert!(content_ids.is_empty());
            assert!(!data(&reply).contains("yanglib:"));
        }
        let used = MgmtLimits::default().max_subtree_filter_work_units
            - fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining();
        cases.push((fixture, body, reply, used));
    }
    assert_eq!(cases[0].3, cases[1].3, "a predicate result cannot size the later fragment-append reservation");
    assert_eq!(cases[0].0.observation(), cases[1].0.observation());
    let boundary = cases[0].3;
    let mut below = Vec::new();
    for (fixture, body, generous, _) in &cases {
        let reply = fixture.rpc(body, MgmtLimits { max_subtree_filter_work_units: boundary, ..MgmtLimits::default() }).await;
        assert_eq!(&reply, generous);
        assert_eq!(fixture.access.budget.lock().unwrap().as_ref().unwrap().remaining(), 0);
        let reply = fixture.rpc(body, MgmtLimits { max_subtree_filter_work_units: boundary.checked_sub(1).unwrap(), ..MgmtLimits::default() }).await;
        error(&reply, "too-big");
        below.push((reply, fixture.observation()));
    }
    assert_eq!(below[0], below[1]);
}
