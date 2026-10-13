use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use subtree_content_service::{netconf_xml, schema_registry, types::*};
use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{AuthStrength, TransportType, TrustedPrincipal, WorkloadIdentity, YangPath};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalError, OperationalRequest, OperationalResponse, OperationalValue};
use opc_mgmt_schema::{DataClass, LeafType, ModelData, NetconfXmlRenderer, NodeMeta, OriginEntry, SchemaRegistry};
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
}

impl PolicySource for Policy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
}

struct Binding {
    bus: Arc<ConfigBus<System>>,
    access: Arc<Access>,
}

// The binding retains generated typed access while supplying leafref/custom
// metadata and an absent data-class lookup through the registry contract.
// This isolates the read codec from unrelated edit/validation generator paths.
struct Registry;

impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str { schema_registry::registry().schema_digest() }
    fn served_models(&self) -> &'static [ModelData] { schema_registry::registry().served_models() }
    fn origins(&self) -> &'static [OriginEntry] { schema_registry::registry().origins() }
    fn nodes(&self) -> &'static [NodeMeta] {
        static NODES: OnceLock<Vec<NodeMeta>> = OnceLock::new();
        NODES.get_or_init(|| schema_registry::registry().nodes().iter().map(|node| {
            let mut node = *node;
            node.leaf_type = match node.path {
                "/ex:system/ex:opaque" => Some(LeafType::Custom { name: "opaque" }),
                "/ex:system/ex:port-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:port" }),
                "/ex:system/ex:chained-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:port-ref" }),
                "/ex:system/ex:ratio-ref" => Some(LeafType::LeafRef { target_path: "/ex:system/ex:ratio" }),
                _ => node.leaf_type,
            };
            node
        }).collect())
    }
    fn data_class(&self, path: &str) -> Option<DataClass> {
        if path == "/ex:system/ex:unclassified" { None }
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
    fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
        Some(WithDefaultsCapability::new(WithDefaultsMode::Trim, [
            WithDefaultsMode::ReportAll, WithDefaultsMode::ReportAllTagged,
            WithDefaultsMode::Explicit,
        ]).unwrap())
    }
    fn nmda_get_data_supported(&self) -> bool { true }
    fn get_operational_state(&self, request: &OperationalRequest)
        -> Result<OperationalResponse, OperationalError>
    {
        self.access.provider.fetch_add(1, Ordering::SeqCst);
        self.access.requests.lock().unwrap().push(request.clone());
        Ok(OperationalResponse::new(self.access.values.lock().unwrap().clone()))
    }
}

type Server = ReadOnlyNetconfServer<System, Binding, Policy, Audit>;

struct Fixture {
    server: Server,
    access: Arc<Access>,
    policy_calls: Arc<AtomicUsize>,
    audit: Audit,
}

impl Fixture {
    async fn new(config: System, denied: &[&str]) -> Self {
        let mut modules = ModuleRegistry::new();
        modules.register_module("subtree-content", "ex").unwrap();
        modules.register_module("ietf-netconf", "nc").unwrap();
        let mut rules = NacmPolicy::builder(PolicyVersion::new(1));
        for path in denied {
            rules = rules.add_rule(NacmRule::deny(NacmAction::Read,
                YangPathPattern::parse(path, &modules).unwrap()));
        }
        for path in ["/ex:system", "/ex:system/**"] {
            rules = rules.add_rule(NacmRule::allow(NacmAction::Read,
                YangPathPattern::parse(path, &modules).unwrap()));
        }
        rules = rules.add_rule(NacmRule::allow(NacmAction::Exec,
            YangPathPattern::parse("/nc:close-session", &modules).unwrap()));
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let access = Arc::new(Access::default());
        let audit = Audit::default();
        let bus = Arc::new(ConfigBus::new_dev_only(config, MockManagedDatastore::new())
            .await.unwrap());
        let server = ReadOnlyNetconfServer::new(
            Binding { bus, access: access.clone() },
            Policy { rules: Arc::new(rules.build()), calls: policy_calls.clone() },
            audit.clone(), TransportType::NetconfTls,
        ).unwrap();
        Self { server, access, policy_calls, audit }
    }

    async fn rpc(&self, body: &str, limits: MgmtLimits) -> String {
        let principal = TrustedPrincipal::new(
            WorkloadIdentity::User("subtree-reader".into()), TenantId::new("fixture").unwrap(),
        ).with_auth_strength(AuthStrength::MutualTls);
        let registry = SessionRegistry::new();
        let (mut client, mut stream) = tokio::io::duplex(262_144);
        let serving = run_read_only_session_with_registry(&self.server, &principal, &mut stream,
            SessionConfig { limits, frame_timeout: Duration::from_secs(5) }, 1, &registry);
        let exchange = async {
            assert!(read_frame(&mut client).await.contains("<hello"));
            write_frame(&mut client, &format!("<hello xmlns=\"{NC}\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>")).await;
            self.access.model.store(0, Ordering::SeqCst);
            self.access.provider.store(0, Ordering::SeqCst);
            self.policy_calls.store(0, Ordering::SeqCst);
            write_frame(&mut client, &format!("<rpc xmlns=\"{NC}\" message-id=\"match\">{body}</rpc>")).await;
            let reply = read_frame(&mut client).await;
            // End the authenticated session without a second RPC or policy load.
            client.shutdown().await.unwrap();
            reply
        };
        let (reply, result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(exchange, serving)
        }).await.unwrap();
        result.unwrap();
        reply
    }

    async fn read(&self, op: &str, children: &str, defaults: &str) -> String {
        self.rpc(&request(op, children, defaults), MgmtLimits::default()).await
    }

    fn no_access(&self) {
        assert_eq!(self.access.model.load(Ordering::SeqCst), 0, "no model access");
        assert_eq!(self.access.provider.load(Ordering::SeqCst), 0, "no provider access");
        assert_eq!(self.policy_calls.load(Ordering::SeqCst), 0, "schema refusal precedes policy");
    }
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

fn config() -> System {
    let mut config = System::default();
    config.hostname = LeafPresence::Explicit("router-marker".into());
    config.enabled = LeafPresence::Explicit(true);
    config.count = LeafPresence::Explicit(u32::MAX);
    config.signed = LeafPresence::Explicit(YangInt64(i64::MIN));
    config.role = serde_json::from_str("\"active\"").unwrap();
    config.port_ref = LeafPresence::Explicit(7);
    config.chained_ref = LeafPresence::Explicit(7);
    config.secret = SecretLeaf::new(LeafPresence::Explicit("secret-marker".into()));
    config.intercept = SecretLeaf::new(LeafPresence::Explicit("intercept-marker".into()));
    config.password = SecretLeaf::new(LeafPresence::Explicit("password-marker".into()));
    config.unclassified = SecretLeaf::new(LeafPresence::Explicit("unclassified-marker".into()));
    for (site, id, label, cost, enabled) in [
        ("east", 7, "alpha-marker", 7, true),
        ("east", 8, "beta-marker", 8, false),
        ("west", 7, "gamma-marker", 8, true),
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
    config
}

fn data(reply: &str) -> &str {
    assert!(!reply.contains("<rpc-error>"), "{reply}");
    if reply.contains("<data/>") { return ""; }
    reply.split_once("<data>").expect(reply).1.split_once("</data>").unwrap().0
}

fn tags(reply: &str, tag: &str) -> Vec<String> {
    let xml = data(reply);
    let start = format!("<ex:{tag}>");
    let end = format!("</ex:{tag}>");
    xml.split(&start).skip(1).map(|part| part.split_once(&end).unwrap().0.to_owned()).collect()
}

fn error(reply: &str, tag: &str) {
    assert!(reply.contains(&format!("<error-tag>{tag}</error-tag>")), "{reply}");
    assert!(!reply.contains("<data>"), "errors cannot contain partial data");
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
    for contents in ["<peer>text</peer>", "<peer>text<label/></peer>", "<hostname>text<child/></hostname>"] {
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
    let marker = "predicate-UNIQUE-disclosure-marker";
    let xml = format!("<rpc xmlns=\"{NC}\" message-id=\"redaction\">{}</rpc>", request("get-config", &format!("<hostname>{marker}</hostname>"), ""));
    let parsed = opc_netconf_server::xml::parse_rpc(&xml, &MgmtLimits::default()).unwrap();
    assert!(!format!("{parsed:?}").contains(marker));
    let reply = fixture.read("get-config", &format!("<hostname>{marker}</hostname><count/>"), "").await;
    assert_eq!(data(&reply), "");
    assert!(!format!("{:?}", fixture.audit.0.lock().unwrap()).contains(marker));
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
}

#[tokio::test]
async fn subtree_content_scalar_canonical_values() {
    let fixture = Fixture::new(config(), &[]).await;
    for (leaf, literal) in [
        ("port", "+007"), ("enabled", "true"), ("count", "04294967295"),
        ("signed", "-9223372036854775808"), ("role", "active"),
        ("port-ref", "+007"), ("chained-ref", "007"),
    ] {
        let reply = fixture.read("get-config", &format!("<{leaf}>{literal}</{leaf}><hostname/>"), "report-all").await;
        assert_eq!(tags(&reply, "hostname"), ["router-marker"], "{leaf}");
    }
    for (leaf, literal) in [
        ("port", "65536"), ("port", "-1"), ("port", "seven"),
        ("enabled", "TRUE"), ("enabled", "1"), ("count", "4294967296"),
        ("signed", "9223372036854775808"), ("role", "ACTIVE"), ("empty", "present"),
        ("port-ref", "65536"),
    ] {
        let reply = fixture.read("get-config", &format!("<{leaf}>{literal}</{leaf}><hostname/>"), "report-all").await;
        assert_eq!(data(&reply), "", "{leaf}");
    }
    let mut model = config();
    model.hostname = LeafPresence::Explicit("+007".into());
    let fixture = Fixture::new(model, &[]).await;
    assert_eq!(data(&fixture.read("get-config", "<hostname>7</hostname><count/>", "").await), "");
    assert_eq!(tags(&fixture.read("get-config", "<hostname>+007</hostname><count/>", "").await, "count"), [u32::MAX.to_string()]);
}

#[tokio::test]
async fn subtree_content_unsupported_codec_is_schema_only() {
    for denied in [vec![], vec!["/ex:system/**"]] {
        let fixture = Fixture::new(config(), &denied).await;
        for op in ["get-config", "get", "get-data"] {
            for leaf in ["ratio", "identity", "opaque", "ratio-ref"] {
                for literal in ["unsupported-probe", "1.00"] {
                    let reply = fixture.read(op, &format!("<{leaf}>{literal}</{leaf}>"), "").await;
                    error(&reply, "operation-not-supported");
                    fixture.no_access();
                }
            }
        }
    }
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.read("get-config", "<port>+007</port><hostname/>", "report-all").await;
    assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
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
}

#[tokio::test]
async fn subtree_content_denied_dependencies_precede_access() {
    for denied in ["/ex:system/ex:peer/ex:cost", "/ex:system/ex:peer/ex:site", "/ex:system/ex:peer/ex:id"] {
        let mut previous = None;
        for rows in 0..3 {
            let mut model = config();
            if rows == 0 { model.peer.clear(); }
            if rows == 2 {
                for row in model.peer.values_mut() {
                    row.site = LeafPresence::Absent;
                    row.id = LeafPresence::Absent;
                    row.cost = LeafPresence::Absent;
                }
            }
            let fixture = Fixture::new(model, &[denied]).await;
            let reply = fixture.read("get", "<peer><cost>7</cost><label/></peer><hostname/>", "").await;
            assert_eq!(tags(&reply, "hostname"), ["router-marker"]);
            assert!(tags(&reply, "label").is_empty());
            assert_eq!(fixture.access.provider.load(Ordering::SeqCst), 0);
            let observation = (reply, fixture.policy_calls.load(Ordering::SeqCst));
            if let Some(previous) = &previous { assert_eq!(&observation, previous); }
            previous = Some(observation);
        }
    }
}

#[tokio::test]
async fn subtree_content_denied_output_preserves_siblings() {
    let fixture = Fixture::new(config(), &["/ex:system/ex:peer/ex:label"]).await;
    let reply = fixture.read("get-config", "<peer><cost>7</cost><label/><enabled/><credential/></peer>", "").await;
    assert!(tags(&reply, "label").is_empty());
    assert_eq!(tags(&reply, "enabled"), ["true"]);
    assert_eq!(tags(&reply, "cost"), ["7"]);
    assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;"]);
    assert_eq!(tags(&reply, "id"), ["7"]);
}

#[tokio::test]
async fn subtree_content_non_cleartext_leaf_is_refused() {
    for denied in [vec![], vec!["/ex:system/**"]] {
        for model in [config(), System::default()] {
            let fixture = Fixture::new(model, &denied).await;
            for op in ["get-config", "get", "get-data"] {
                for leaf in ["secret", "intercept", "password", "unclassified"] {
                    for value in [format!("{leaf}-marker"), "incorrect-guess".into()] {
                        let reply = fixture.read(op, &format!("<{leaf}>{value}</{leaf}>"), "").await;
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
}

#[tokio::test]
async fn subtree_content_dependencies_share_policy_context() {
    let fixture = Fixture::new(config(), &[]).await;
    let reply = fixture.read("get", "<peer><site>east</site><cost>7</cost><label/></peer>", "").await;
    assert_eq!(tags(&reply, "label"), ["alpha-marker"]);
    assert_eq!(fixture.policy_calls.load(Ordering::SeqCst), 1);
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
        for mode in ["", "report-all", "report-all-tagged", "trim", "explicit"] {
            let baseline = fixture.read("get-config", "<port/>", mode).await;
            let matched = fixture.read("get-config", "<port>+007</port><hostname/>", mode).await;
            let reported = data(&baseline).contains(">7</ex:port>");
            assert_eq!(tags(&matched, "hostname"), if reported { vec!["router-marker"] } else { vec![] });
            if !reported { assert_eq!(data(&matched), ""); }
        }
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
}

#[tokio::test]
async fn subtree_content_read_preservation() {
    let fixture = Fixture::new(config(), &[]).await;
    for op in ["get-config", "get", "get-data"] {
        let reply = fixture.read(op, "<peer><site>east</site><label/><credential/></peer>", "").await;
        assert_eq!(tags(&reply, "label"), ["alpha-marker", "beta-marker"]);
        assert_eq!(tags(&reply, "credential"), ["&lt;redacted&gt;", "&lt;redacted&gt;"]);
        assert_eq!(tags(&reply, "id"), ["7", "8"]);
    }
}
