use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{
    AuthStrength, RequestId, TransportType, TrustedPrincipal, WorkloadIdentity, YangPath,
};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    OperationalError, OperationalRequest, OperationalResponse, OperationalValue,
};
use opc_mgmt_path::canonical_path_matches;
use opc_mgmt_schema::{
    DataClass, DefaultReport, LeafType, ModelData, NetconfProjectionError, NetconfXmlRenderer,
    NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_netconf_server::{NetconfConfigBinding, ReadOnlyNetconfServer};
use opc_types::TenantId;
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};

#[path = "keyed_operational_reads/key_payloads.rs"]
mod key_payloads;

struct Registry;
const fn leaf(path: &'static str, config: bool, class: DataClass) -> NodeMeta {
    NodeMeta {
        path,
        module: "example",
        kind: NodeKind::Leaf,
        config,
        leaf_type: Some(LeafType::String),
        key_leaves: &[],
        data_class: class,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }
}
static NODES: &[NodeMeta] = &[
    NodeMeta {
        kind: NodeKind::Container,
        leaf_type: None,
        child_paths: &[
            "/ex:system/ex:peer",
            "/ex:system/ex:sealed",
            "/ex:system/ex:visible",
        ],
        ..leaf("/ex:system", true, DataClass::Public)
    },
    NodeMeta {
        kind: NodeKind::List,
        leaf_type: None,
        key_leaves: &["site", "name"],
        child_paths: &[
            "/ex:system/ex:peer/ex:name",
            "/ex:system/ex:peer/ex:payload",
            "/ex:system/ex:peer/ex:site",
            "/ex:system/ex:peer/ex:up",
        ],
        ..leaf("/ex:system/ex:peer", true, DataClass::Public)
    },
    leaf("/ex:system/ex:peer/ex:name", true, DataClass::SubscriberId),
    leaf(
        "/ex:system/ex:peer/ex:payload",
        false,
        DataClass::SecuritySecret,
    ),
    leaf("/ex:system/ex:peer/ex:site", true, DataClass::Public),
    NodeMeta {
        leaf_type: Some(LeafType::Boolean),
        ..leaf("/ex:system/ex:peer/ex:up", false, DataClass::Operational)
    },
    NodeMeta {
        kind: NodeKind::List,
        leaf_type: None,
        key_leaves: &["id"],
        child_paths: &["/ex:system/ex:sealed/ex:id", "/ex:system/ex:sealed/ex:up"],
        ..leaf("/ex:system/ex:sealed", true, DataClass::Public)
    },
    leaf(
        "/ex:system/ex:sealed/ex:id",
        true,
        DataClass::SecuritySecret,
    ),
    leaf("/ex:system/ex:sealed/ex:up", false, DataClass::Operational),
    leaf("/ex:system/ex:visible", false, DataClass::Public),
    leaf("/ex:top-state", false, DataClass::Public),
];
impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "example-keyed-operational"
    }
    fn served_models(&self) -> &'static [ModelData] {
        &[ModelData {
            name: "example",
            revision: "",
            namespace: "urn:example",
            prefix: "ex",
        }]
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        NODES
    }
    fn origins(&self) -> &'static [OriginEntry] {
        &[
            OriginEntry {
                origin: "",
                modules: &["example"],
            },
            OriginEntry {
                origin: "example",
                modules: &["example"],
            },
        ]
    }
}

#[derive(Default)]
struct Provider {
    values: Mutex<Vec<OperationalValue>>,
    requests: Mutex<Vec<OperationalRequest>>,
    unchecked: AtomicBool,
}

#[derive(Clone)]
struct Binding {
    registry: &'static dyn SchemaRegistry,
    bus: Arc<ConfigBus<()>>,
    provider: Arc<Provider>,
    config_reads: Arc<AtomicUsize>,
    renders: Arc<AtomicUsize>,
}

impl NetconfXmlRenderer<()> for Binding {
    fn render_selected_nodes(
        &self,
        _: &(),
        _: &[&str],
        _: &[opc_mgmt_schema::NetconfKeyPredicate],
        _: &[opc_mgmt_schema::NetconfInstanceBranch],
        _: DefaultReport,
    ) -> Result<Vec<opc_mgmt_schema::NetconfDataNode>, NetconfProjectionError> {
        // This fixture has no configuration rows; all instance data is supplied
        // through the bounded operational provider and the default renderer.
        self.renders.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }

    fn render_running_config(
        &self,
        _: &(),
        _: &[&str],
        _: DefaultReport,
    ) -> Result<String, NetconfProjectionError> {
        self.renders.fetch_add(1, Ordering::SeqCst);
        Ok(String::new())
    }

    fn supported_default_reports(&self) -> &'static [DefaultReport] {
        &[DefaultReport::Trim]
    }
}

impl NetconfConfigBinding<()> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        self.config_reads.fetch_add(1, Ordering::SeqCst);
        self.bus.clone()
    }

    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        self.registry
    }

    fn generated_xml_renderer(&self) -> Option<&dyn NetconfXmlRenderer<()>> {
        Some(self)
    }

    fn nmda_get_data_supported(&self) -> bool {
        true
    }

    fn get_operational_state(
        &self,
        request: &OperationalRequest,
    ) -> Result<OperationalResponse, OperationalError> {
        self.provider.requests.lock().unwrap().push(request.clone());
        Ok(OperationalResponse::new(
            self.provider
                .values
                .lock()
                .unwrap()
                .iter()
                .filter(|value| {
                    self.provider.unchecked.load(Ordering::SeqCst)
                        || request.paths.iter().any(|path| {
                            canonical_path_matches(path.as_str(), value.path().as_str())
                        })
                })
                .cloned(),
        ))
    }
}

struct Policy {
    calls: AtomicUsize,
    revisions: Vec<Arc<NacmPolicy>>,
}

impl PolicySource for Policy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.revisions[call % self.revisions.len()].clone())
    }
}

#[derive(Default)]
struct Audit(Mutex<Vec<AuditEvent>>);
impl AuditSink for Audit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
}

type Server = ReadOnlyNetconfServer<(), Binding, Arc<Policy>, Arc<Audit>>;

fn policy(paths: &[&str]) -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("example", "ex").unwrap();
    let mut builder = NacmPolicy::builder(PolicyVersion::new(1));
    for path in paths {
        builder = builder.add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse(path, &modules).unwrap(),
        ));
    }
    builder.build()
}

async fn fixture(
    values: Vec<OperationalValue>,
    policies: Vec<NacmPolicy>,
) -> (Server, Binding, Arc<Policy>, Arc<Audit>) {
    fixture_with_registry(values, policies, &Registry).await
}

async fn fixture_with_registry(
    values: Vec<OperationalValue>,
    policies: Vec<NacmPolicy>,
    registry: &'static dyn SchemaRegistry,
) -> (Server, Binding, Arc<Policy>, Arc<Audit>) {
    registry.self_check().unwrap();
    let binding = Binding {
        registry,
        bus: Arc::new(
            ConfigBus::new_dev_only((), MockManagedDatastore::new())
                .await
                .unwrap(),
        ),
        provider: Arc::new(Provider {
            values: Mutex::new(values),
            ..Provider::default()
        }),
        config_reads: Arc::new(AtomicUsize::new(0)),
        renders: Arc::new(AtomicUsize::new(0)),
    };
    let policy = Arc::new(Policy {
        calls: AtomicUsize::new(0),
        revisions: policies.into_iter().map(Arc::new).collect(),
    });
    let audit = Arc::new(Audit::default());
    let server = Server::new(
        binding.clone(),
        policy.clone(),
        audit.clone(),
        TransportType::NetconfTls,
    )
    .unwrap();
    binding.config_reads.store(0, Ordering::SeqCst);
    (server, binding, policy, audit)
}

fn rpc<B: NetconfConfigBinding<()>>(
    server: &ReadOnlyNetconfServer<(), B, Arc<Policy>, Arc<Audit>>,
    operation: &str,
    limits: &MgmtLimits,
) -> String {
    let principal = TrustedPrincipal::new(
        WorkloadIdentity::User("reader".into()),
        TenantId::from_static("example"),
    )
    .with_auth_strength(AuthStrength::MutualTls);
    server.handle_rpc_xml(
        RequestId::new(),
        &principal,
        &format!(r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">{operation}</rpc>"#),
        limits,
    )
}

struct ProjectionProbe(Binding);

impl NetconfConfigBinding<()> for ProjectionProbe {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        self.0.config_bus()
    }

    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        self.0.schema_registry()
    }

    fn nmda_get_data_supported(&self) -> bool {
        true
    }

    fn get_operational_state(
        &self,
        request: &OperationalRequest,
    ) -> Result<OperationalResponse, OperationalError> {
        self.0.get_operational_state(request)
    }

    fn render_get_data(
        &self,
        _: &(),
        _: opc_netconf_server::ReadSelection<'_>,
        _: &OperationalResponse,
        _: opc_netconf_server::ReadSelection<'_>,
    ) -> Result<String, opc_netconf_server::BindingError> {
        self.0.renders.fetch_add(1, Ordering::SeqCst);
        Ok(String::new())
    }
}

#[tokio::test]
async fn netconf_complete_instance_validation_precedes_custom_projection() {
    for (path, valid) in [
        (
            "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:up",
            true,
        ),
        ("/ex:system/ex:peer[ex:name='a']/ex:up", false),
        (
            "/ex:system/ex:peer[ex:name='a'][ex:site='east']/ex:up",
            false,
        ),
        (
            "/ex:system/ex:peer[ex:site=\"east\"][ex:name='a']/ex:up",
            false,
        ),
    ] {
        for operation in [get, get_data] {
            let (_, binding, source, audit) = fixture(
                vec![value(path, "true")],
                vec![policy(&["/ex:system", "/ex:system/**"])],
            )
            .await;
            let server = ReadOnlyNetconfServer::new(
                ProjectionProbe(binding.clone()),
                source.clone(),
                audit,
                TransportType::NetconfTls,
            )
            .unwrap();
            let reply = rpc(
                &server,
                &operation(r#"<system xmlns="urn:example"><peer><up/></peer></system>"#),
                &MgmtLimits::default(),
            );
            assert_eq!(source.calls.load(Ordering::SeqCst), 1);
            assert_eq!(binding.provider.requests.lock().unwrap().len(), 1);
            if valid {
                assert!(!reply.contains("<rpc-error"), "{reply}");
                assert_eq!(binding.renders.load(Ordering::SeqCst), 1);
            } else {
                assert!(
                    reply.contains("<error-tag>operation-failed</error-tag>"),
                    "{reply}"
                );
                assert!(!reply.contains("<data"));
                assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
            }
        }
    }
}

fn value(path: &str, json: &str) -> OperationalValue {
    OperationalValue::new(YangPath::new(path).unwrap(), json).unwrap()
}

fn peer(site: &str, name: &str, leaf: &str, json: &str) -> OperationalValue {
    let mut path = "/ex:system/ex:peer".to_string();
    opc_mgmt_path::append_key_predicate(&mut path, "ex:site", site).unwrap();
    opc_mgmt_path::append_key_predicate(&mut path, "ex:name", name).unwrap();
    path.push_str(&format!("/ex:{leaf}"));
    value(&path, json)
}

fn get(filter: &str) -> String {
    format!("<get><filter type=\"subtree\">{filter}</filter></get>")
}

fn get_data(filter: &str) -> String {
    format!(
        r#"<get-data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-nmda" xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores"><datastore>ds:operational</datastore><subtree-filter>{filter}</subtree-filter><config-filter>false</config-filter></get-data>"#
    )
}

#[derive(Debug, PartialEq, Eq)]
struct Element {
    namespace: String,
    local: String,
    text: String,
    children: Vec<Element>,
}

fn element(local: &str, text: &str, children: Vec<Element>) -> Element {
    Element {
        namespace: "urn:example".into(),
        local: local.into(),
        text: text.into(),
        children,
    }
}

fn peer_xml(site: &str, name: &str, leaf: &str, text: &str) -> Element {
    element(
        "peer",
        "",
        vec![
            element("site", site, vec![]),
            element("name", name, vec![]),
            element(leaf, text, vec![]),
        ],
    )
}

fn data(reply: &str, expected_namespace: &str) -> Vec<Element> {
    assert!(!reply.contains("<rpc-error"), "{reply}");
    let mut reader = NsReader::from_str(reply);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<Element> = Vec::new();
    loop {
        let (namespace, event) = reader.read_resolved_event().unwrap();
        match event {
            Event::Start(start) => {
                let namespace = match namespace {
                    ResolveResult::Bound(value) => value.as_ref().to_string(),
                    _ => String::new(),
                };
                stack.push(Element {
                    namespace,
                    local: start.local_name().as_ref().to_string(),
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Event::Text(text) => stack.last_mut().unwrap().text.push_str(text.as_ref()),
            Event::CData(text) => stack.last_mut().unwrap().text.push_str(text.as_ref()),
            Event::GeneralRef(reference) => {
                let encoded = format!("&{};", reference.as_ref());
                stack
                    .last_mut()
                    .unwrap()
                    .text
                    .push_str(&quick_xml::escape::unescape(&encoded).unwrap());
            }
            Event::End(_) => {
                let finished = stack.pop().unwrap();
                if finished.local == "data" {
                    assert_eq!(finished.namespace, expected_namespace);
                    return finished.children;
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(finished);
                }
            }
            Event::Eof => panic!("missing data element"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn netconf_keyed_get_preserves_instance_tree() {
    for filter in [
        r#"<system xmlns="urn:example"/>"#,
        r#"<system xmlns="urn:example"><peer/></system>"#,
        r#"<system xmlns="urn:example"><peer><up/></peer></system>"#,
    ] {
        let (server, _, source, _) = fixture(
            vec![
                peer("east", "b", "up", "false"),
                peer("east", "a", "up", "true"),
            ],
            vec![policy(&["/ex:system", "/ex:system/**"])],
        )
        .await;
        let reply = rpc(&server, &get(filter), &MgmtLimits::default());
        assert_eq!(
            data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
            vec![element(
                "system",
                "",
                vec![
                    peer_xml("east", "a", "up", "true"),
                    peer_xml("east", "b", "up", "false"),
                ]
            )]
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn netconf_subtree_partial_keys_and_literal_values_select_exact_instances() {
    for (key, expected) in [
        ("<site>east</site>", vec![("east", "a"), ("east", "b")]),
        ("<site>east</site><name>b</name>", vec![("east", "b")]),
        ("<name>*</name>", vec![("west", "*")]),
        ("<name>o&apos;brien\\</name>", vec![("west", "o'brien\\")]),
    ] {
        for (operation, namespace) in [
            (
                get as fn(&str) -> String,
                "urn:ietf:params:xml:ns:netconf:base:1.0",
            ),
            (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
        ] {
            let (server, _, _, _) = fixture(
                vec![
                    peer("west", "o'brien\\", "up", "true"),
                    peer("east", "b", "up", "true"),
                    peer("west", "*", "up", "true"),
                    peer("east", "a", "up", "true"),
                ],
                vec![policy(&["/ex:system", "/ex:system/**"])],
            )
            .await;
            let filter = format!(
                r#"<alias:system xmlns:alias="urn:example"><alias:peer xmlns="urn:example">{key}<up/></alias:peer></alias:system>"#
            );
            let reply = rpc(&server, &operation(&filter), &MgmtLimits::default());
            assert_eq!(
                data(&reply, namespace),
                vec![element(
                    "system",
                    "",
                    expected
                        .iter()
                        .map(|(site, name)| peer_xml(site, name, "up", "true"))
                        .collect()
                )]
            );
        }
    }
}

#[tokio::test]
async fn netconf_subtree_sibling_branches_keep_their_own_descendants() {
    for (operation, namespace) in [
        (
            get as fn(&str) -> String,
            "urn:ietf:params:xml:ns:netconf:base:1.0",
        ),
        (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
    ] {
        let (server, _, _, _) = fixture(
            vec![
                peer("east", "a", "up", "true"),
                peer("east", "a", "payload", "\"east-secret-marker\""),
                peer("west", "b", "up", "false"),
                peer("west", "b", "payload", "\"west-secret-marker\""),
            ],
            vec![policy(&["/ex:system", "/ex:system/**"])],
        )
        .await;
        let reply = rpc(
            &server,
            &operation(
                r#"<system xmlns="urn:example"><peer><site>east</site><up/></peer><peer><site>west</site><payload/></peer></system>"#,
            ),
            &MgmtLimits::default(),
        );
        assert_eq!(
            data(&reply, namespace),
            vec![element(
                "system",
                "",
                vec![
                    peer_xml("east", "a", "up", "true"),
                    peer_xml("west", "b", "payload", "<redacted>"),
                ]
            )]
        );
        assert!(!reply.contains("secret-marker"));
    }
}

#[tokio::test]
async fn netconf_masked_key_match_is_refused_before_access() {
    for populated in [false, true] {
        for permitted in [false, true] {
            for guess in ["correct-marker", "wrong-marker"] {
                for operation in [get, get_data] {
                    let values = if populated {
                        vec![value(
                            "/ex:system/ex:sealed[ex:id='correct-marker']/ex:up",
                            "true",
                        )]
                    } else {
                        vec![]
                    };
                    let paths: &[&str] = if permitted {
                        &["/ex:system", "/ex:system/**"]
                    } else {
                        &[]
                    };
                    let (server, binding, source, audit) =
                        fixture(values, vec![policy(paths)]).await;
                    let filter = format!(
                        r#"<system xmlns="urn:example"><sealed><id>{guess}</id><up/></sealed></system>"#
                    );
                    let reply = rpc(&server, &operation(&filter), &MgmtLimits::default());
                    assert!(
                        reply.contains("<error-tag>invalid-value</error-tag>"),
                        "{reply}"
                    );
                    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
                    assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
                    assert!(binding.provider.requests.lock().unwrap().is_empty());
                    assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
                    assert!(!reply.contains(guess));
                    assert!(!format!("{:?}", audit.0.lock().unwrap()).contains(guess));
                }
            }
        }
    }
}

#[tokio::test]
async fn netconf_keyed_response_limits_precede_projection() {
    for operation in [get, get_data] {
        for values in [
            (0..9)
                .map(|index| peer("east", &index.to_string(), "up", "true"))
                .collect(),
            vec![peer("east", &"name-marker".repeat(20), "up", "true")],
            vec![peer(
                "east",
                "a",
                "up",
                &serde_json::to_string(&"value-marker".repeat(20)).unwrap(),
            )],
        ] {
            let (server, binding, _, _) =
                fixture(values, vec![policy(&["/ex:system", "/ex:system/**"])]).await;
            let limits = MgmtLimits {
                max_paths_per_request: 8,
                max_value_bytes: 128,
                ..MgmtLimits::default()
            };
            let reply = rpc(
                &server,
                &operation(r#"<system xmlns="urn:example"><peer><up/></peer></system>"#),
                &limits,
            );
            assert!(reply.contains("<error-tag>too-big</error-tag>"), "{reply}");
            assert!(!reply.contains("<data"));
            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
            assert_eq!(binding.provider.requests.lock().unwrap()[0].max_values, 8);
            assert!(!reply.contains("marker"));
        }
    }
}

#[tokio::test]
async fn netconf_keyed_instances_require_complete_canonical_keys() {
    for path in [
        "/ex:system/ex:peer[ex:name='a']/ex:up",
        "/ex:system/ex:peer[ex:name='a'][ex:site='east']/ex:up",
        "/ex:system/ex:peer[ex:site='east'][ex:name='a'][ex:extra='x']/ex:up",
    ] {
        for operation in [get, get_data] {
            let (server, binding, _, _) = fixture(
                vec![value(path, "true")],
                vec![policy(&["/ex:system", "/ex:system/**"])],
            )
            .await;
            let reply = rpc(
                &server,
                &operation(r#"<system xmlns="urn:example"><peer><up/></peer></system>"#),
                &MgmtLimits::default(),
            );
            assert!(
                reply.contains("<error-tag>operation-failed</error-tag>"),
                "{reply}"
            );
            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn netconf_keyed_denied_key_prunes_before_provider_with_one_context() {
    for (operation, namespace) in [
        (
            get as fn(&str) -> String,
            "urn:ietf:params:xml:ns:netconf:base:1.0",
        ),
        (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
    ] {
        let (server, binding, source, _) = fixture(
            vec![peer("east", "a", "up", "true")],
            vec![
                policy(&["/ex:system/ex:peer/ex:up", "/ex:system/ex:peer/ex:site"]),
                policy(&["/ex:system/ex:peer/ex:name"]),
            ],
        )
        .await;
        let reply = rpc(
            &server,
            &operation(r#"<system xmlns="urn:example"><peer><up/></peer></system>"#),
            &MgmtLimits::default(),
        );
        assert!(data(&reply, namespace).is_empty());
        assert!(binding.provider.requests.lock().unwrap().is_empty());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn netconf_empty_operational_response_invents_no_instances() {
    for (operation, namespace) in [
        (
            get as fn(&str) -> String,
            "urn:ietf:params:xml:ns:netconf:base:1.0",
        ),
        (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
    ] {
        let (server, binding, _, _) =
            fixture(Vec::new(), vec![policy(&["/ex:system", "/ex:system/**"])]).await;
        let reply = rpc(
            &server,
            &operation(r#"<system xmlns="urn:example"><peer><up/></peer></system>"#),
            &MgmtLimits::default(),
        );
        assert!(data(&reply, namespace).is_empty());
        assert_eq!(binding.provider.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn netconf_keyed_content_match_text_is_bounded_across_parser_events() {
    for operation in [get, get_data] {
        for length in [128, 129] {
            for separator in ["<!-- split -->", "<![CDATA[]]>"] {
                let (server, binding, source, _) =
                    fixture(Vec::new(), vec![policy(&["/ex:system", "/ex:system/**"])]).await;
                let filter = format!(
                    r#"<system xmlns="urn:example"><peer><name>{}{}{}</name><up/></peer></system>"#,
                    "a".repeat(64),
                    separator,
                    "b".repeat(length - 64)
                );
                let limits = MgmtLimits {
                    max_value_bytes: 128,
                    ..MgmtLimits::default()
                };
                let reply = rpc(&server, &operation(&filter), &limits);
                if length == 128 {
                    assert!(!reply.contains("<rpc-error"), "{reply}");
                    assert_eq!(binding.provider.requests.lock().unwrap().len(), 1);
                } else {
                    assert!(reply.contains("<error-tag>too-big</error-tag>"), "{reply}");
                    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
                    assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
                    assert!(binding.provider.requests.lock().unwrap().is_empty());
                }
            }
        }
    }
}

#[tokio::test]
async fn netconf_keyed_filter_nodes_and_content_nodes_are_bounded() {
    for operation in [get, get_data] {
        for (filter, limits) in [
            (
                r#"<system xmlns="urn:example"><peer><site>east</site><name>a</name><up/></peer></system>"#,
                MgmtLimits {
                    max_subtree_filter_content_match_nodes: 1,
                    ..MgmtLimits::default()
                },
            ),
            (
                r#"<system xmlns="urn:example"><peer><up/></peer><peer><up/></peer></system>"#,
                MgmtLimits {
                    max_paths_per_request: 4,
                    ..MgmtLimits::default()
                },
            ),
        ] {
            let (server, binding, source, _) =
                fixture(Vec::new(), vec![policy(&["/ex:system", "/ex:system/**"])]).await;
            let reply = rpc(&server, &operation(filter), &limits);
            assert!(reply.contains("<error-tag>too-big</error-tag>"), "{reply}");
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
            assert!(binding.provider.requests.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn netconf_keyed_xpath_expands_instances_and_refuses_predicates() {
    for expression in [
        "/p:system/p:peer/p:up",
        "/p:system/*/p:up",
        "/p:system/p:peer/p:up | /p:system/p:visible",
    ] {
        for nmda in [false, true] {
            let (server, _, _, _) = fixture(
                vec![peer("east", "a", "up", "true")],
                vec![policy(&["/ex:system", "/ex:system/**"])],
            )
            .await;
            let operation = if nmda {
                format!(
                    r#"<get-data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-nmda" xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores" xmlns:p="urn:example"><datastore>ds:operational</datastore><xpath-filter>{expression}</xpath-filter><config-filter>false</config-filter></get-data>"#
                )
            } else {
                format!(
                    r#"<get><filter xmlns:p="urn:example" type="xpath" select="{expression}"/></get>"#
                )
            };
            let namespace = if nmda {
                "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"
            } else {
                "urn:ietf:params:xml:ns:netconf:base:1.0"
            };
            assert_eq!(
                data(&rpc(&server, &operation, &MgmtLimits::default()), namespace),
                vec![element(
                    "system",
                    "",
                    vec![peer_xml("east", "a", "up", "true")]
                )]
            );
        }
    }
    let (server, binding, source, _) = fixture(
        vec![peer("east", "a", "up", "true")],
        vec![policy(&["/ex:system", "/ex:system/**"])],
    )
    .await;
    let reply = rpc(
        &server,
        r#"<get><filter xmlns:p="urn:example" type="xpath" select="/p:system/p:peer[p:name='a']/p:up"/></get>"#,
        &MgmtLimits::default(),
    );
    assert!(
        reply.contains("<error-tag>operation-not-supported</error-tag>"),
        "{reply}"
    );
    assert!(binding.provider.requests.lock().unwrap().is_empty());
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn netconf_root_state_leaf_has_its_namespace() {
    let (server, _, _, _) = fixture(
        vec![value("/ex:top-state", "\"ready\"")],
        vec![policy(&["/ex:top-state"])],
    )
    .await;
    let reply = rpc(
        &server,
        &get(r#"<top-state xmlns="urn:example"/>"#),
        &MgmtLimits::default(),
    );
    assert_eq!(
        data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
        vec![element("top-state", "ready", vec![])]
    );
}

#[tokio::test]
async fn netconf_overlapping_selectors_use_the_distinct_request_budget() {
    let (server, binding, _, _) = fixture(
        vec![peer("east", "a", "up", "true")],
        vec![policy(&["/ex:system", "/ex:system/**"])],
    )
    .await;
    let limits = MgmtLimits {
        max_paths_per_request: 11,
        ..MgmtLimits::default()
    };
    let filter = r#"<system xmlns="urn:example"/><system xmlns="urn:example"/><system xmlns="urn:example"/>"#;
    let reply = rpc(&server, &get(filter), &limits);
    assert_eq!(
        data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
        vec![element(
            "system",
            "",
            vec![peer_xml("east", "a", "up", "true")]
        )]
    );
    assert_eq!(binding.provider.requests.lock().unwrap()[0].paths.len(), 4);
}

#[tokio::test]
async fn netconf_implicit_identity_keys_do_not_consume_selected_path_budget() {
    let (server, _, _, _) = fixture(
        vec![peer("east", "a", "up", "true")],
        vec![policy(&["/ex:system", "/ex:system/**"])],
    )
    .await;
    let limits = MgmtLimits {
        max_paths_per_request: 3,
        ..MgmtLimits::default()
    };
    let reply = rpc(
        &server,
        &get(r#"<system xmlns="urn:example"><peer><up/></peer></system>"#),
        &limits,
    );
    assert_eq!(
        data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
        vec![element(
            "system",
            "",
            vec![peer_xml("east", "a", "up", "true")]
        )]
    );
}

#[tokio::test]
async fn netconf_configuration_datastore_keeps_unsupported_content_matches() {
    let (server, binding, source, _) =
        fixture(vec![], vec![policy(&["/ex:system", "/ex:system/**"])]).await;
    let operation = r#"<get-data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-nmda" xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores"><datastore>ds:running</datastore><subtree-filter><system xmlns="urn:example"><peer><name>selected-marker</name></peer></system></subtree-filter></get-data>"#;
    let reply = rpc(&server, operation, &MgmtLimits::default());
    assert!(
        reply.contains("<error-tag>operation-not-supported</error-tag>"),
        "{reply}"
    );
    assert!(!reply.contains("selected-marker"));
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert!(binding.provider.requests.lock().unwrap().is_empty());
    assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
}

#[test]
fn netconf_merge_keeps_raw_identity_and_configuration_order_until_masking() {
    use opc_mgmt_schema::{merge_netconf_data, render_netconf_data, NetconfDataNode as Node};
    let entry = |key: &str, up: Option<&str>| {
        let mut children = vec![Node::leaf("/ex:system/ex:sealed/ex:id", key.into(), false)];
        if let Some(up) = up {
            children.push(Node::leaf("/ex:system/ex:sealed/ex:up", up.into(), false));
        }
        Node::branch("/ex:system/ex:sealed", children)
    };
    let mut configuration = vec![Node::branch(
        "/ex:system",
        vec![entry("b-marker", None), entry("a-marker", None)],
    )];
    let operational = vec![Node::branch(
        "/ex:system",
        vec![
            entry("a-marker", Some("true")),
            entry("c-marker", Some("false")),
        ],
    )];
    merge_netconf_data(&Registry, &mut configuration, operational).unwrap();
    let xml = render_netconf_data(&Registry, &configuration, DefaultReport::Trim).unwrap();
    let reply = format!("<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">{xml}</data>");
    assert_eq!(
        data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
        vec![element(
            "system",
            "",
            vec![
                element("sealed", "", vec![element("id", "<redacted>", vec![])]),
                element(
                    "sealed",
                    "",
                    vec![
                        element("id", "<redacted>", vec![]),
                        element("up", "true", vec![])
                    ]
                ),
                element(
                    "sealed",
                    "",
                    vec![
                        element("id", "<redacted>", vec![]),
                        element("up", "false", vec![])
                    ]
                ),
            ]
        )]
    );
    assert!(!xml.contains("marker"));
    assert!(!format!("{configuration:?}").contains("marker"));
}

struct MaskedRegistry {
    nodes: &'static [NodeMeta],
    key: &'static str,
    class: Option<DataClass>,
}

impl SchemaRegistry for MaskedRegistry {
    fn schema_digest(&self) -> &'static str {
        "masked-key-fixture"
    }
    fn served_models(&self) -> &'static [ModelData] {
        Registry.served_models()
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        self.nodes
    }
    fn origins(&self) -> &'static [OriginEntry] {
        Registry.origins()
    }
    fn data_class(&self, path: &str) -> Option<DataClass> {
        if path == self.key {
            self.class
        } else {
            self.node(path).map(|node| node.data_class)
        }
    }
}

fn masked_registry(class: Option<DataClass>, secret_name: bool) -> &'static MaskedRegistry {
    fn owned(text: String) -> &'static str {
        Box::leak(text.into_boxed_str())
    }
    let replace = |path: &str| {
        owned(if secret_name {
            path.replace("/ex:name", "/ex:password")
        } else {
            path.to_string()
        })
    };
    let mut nodes = NODES.to_vec();
    for node in &mut nodes {
        node.path = replace(node.path);
        node.child_paths = Box::leak(
            node.child_paths
                .iter()
                .map(|path| replace(path))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        if node.path == "/ex:system/ex:peer" {
            node.key_leaves = if secret_name {
                &["site", "password"]
            } else {
                &["site", "name"]
            };
            let mut children = node.child_paths.to_vec();
            children.push("/ex:system/ex:peer/ex:child");
            children.sort_unstable();
            node.child_paths = Box::leak(children.into_boxed_slice());
        }
    }
    let key = replace("/ex:system/ex:peer/ex:name");
    nodes
        .iter_mut()
        .find(|node| node.path == key)
        .unwrap()
        .data_class = class.unwrap_or(DataClass::Public);
    nodes.extend([
        NodeMeta {
            kind: NodeKind::List,
            leaf_type: None,
            key_leaves: &["slot"],
            child_paths: &[
                "/ex:system/ex:peer/ex:child/ex:slot",
                "/ex:system/ex:peer/ex:child/ex:up",
            ],
            ..leaf("/ex:system/ex:peer/ex:child", false, DataClass::Public)
        },
        leaf(
            "/ex:system/ex:peer/ex:child/ex:slot",
            false,
            DataClass::Public,
        ),
        leaf(
            "/ex:system/ex:peer/ex:child/ex:up",
            false,
            DataClass::Operational,
        ),
    ]);
    nodes.sort_unstable_by_key(|node| node.path);
    let registry = Box::leak(Box::new(MaskedRegistry {
        nodes: Box::leak(nodes.into_boxed_slice()),
        key,
        class,
    }));
    registry.self_check().unwrap();
    registry
}

#[tokio::test]
async fn netconf_masked_composite_and_ancestor_matches_refuse_all_classes_before_access() {
    for (class, secret_name) in [
        (Some(DataClass::SecuritySecret), false),
        (Some(DataClass::LawfulIntercept), false),
        (None, false),
        (Some(DataClass::Public), true),
    ] {
        let registry = masked_registry(class, secret_name);
        let key = if secret_name { "password" } else { "name" };
        for nested in [false, true] {
            for populated in [false, true] {
                for allowed in [false, true] {
                    for guess in ["correct-marker", "wrong-marker"] {
                        for operation in [get, get_data] {
                            let child = if nested { "/ex:child[ex:slot='1']" } else { "" };
                            let values = if populated {
                                vec![value(&format!("/ex:system/ex:peer[ex:site='east'][ex:{key}='correct-marker']{child}/ex:up"), "true")]
                            } else {
                                vec![]
                            };
                            let (server, binding, source, audit) = fixture_with_registry(
                                values,
                                vec![policy(if allowed {
                                    &["/ex:system", "/ex:system/**"]
                                } else {
                                    &[]
                                })],
                                registry,
                            )
                            .await;
                            let selection = if nested {
                                "<child><up/></child>"
                            } else {
                                "<up/>"
                            };
                            let filter = format!("<system xmlns=\"urn:example\"><peer><{key}>{guess}</{key}>{selection}</peer></system>");
                            let reply = rpc(&server, &operation(&filter), &MgmtLimits::default());
                            assert!(
                                reply.contains("<error-tag>invalid-value</error-tag>"),
                                "{reply}"
                            );
                            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
                            assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
                            assert!(binding.provider.requests.lock().unwrap().is_empty());
                            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
                            assert!(!format!("{reply} {:?}", audit.0.lock().unwrap())
                                .contains("marker"));
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn netconf_nested_branches_keep_ancestor_and_child_key_constraints() {
    let registry = masked_registry(Some(DataClass::Public), false);
    let mut values = Vec::new();
    for name in ["a", "b"] {
        for slot in ["1", "2"] {
            values.push(value(&format!("/ex:system/ex:peer[ex:site='east'][ex:name='{name}']/ex:child[ex:slot='{slot}']/ex:up"), &serde_json::to_string(&format!("{name}-{slot}")).unwrap()));
        }
    }
    for (operation, namespace) in [
        (
            get as fn(&str) -> String,
            "urn:ietf:params:xml:ns:netconf:base:1.0",
        ),
        (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
    ] {
        let (server, _, _, _) = fixture_with_registry(
            values.clone(),
            vec![policy(&["/ex:system", "/ex:system/**"])],
            registry,
        )
        .await;
        let reply = rpc(
            &server,
            &operation(
                r#"<system xmlns="urn:example"><peer><name>a</name><child><slot>1</slot><up/></child></peer><peer><name>b</name><child><slot>2</slot><up/></child></peer></system>"#,
            ),
            &MgmtLimits::default(),
        );
        assert_eq!(
            data(&reply, namespace),
            vec![element(
                "system",
                "",
                [("a", "1"), ("b", "2")]
                    .into_iter()
                    .map(|(name, slot)| element(
                        "peer",
                        "",
                        vec![
                            element("site", "east", vec![]),
                            element("name", name, vec![]),
                            element(
                                "child",
                                "",
                                vec![
                                    element("slot", slot, vec![]),
                                    element("up", &format!("{name}-{slot}"), vec![])
                                ]
                            )
                        ]
                    ))
                    .collect()
            )]
        );
    }
}

#[tokio::test]
async fn netconf_operational_key_payload_must_equal_identity_and_is_emitted_once() {
    let registry = masked_registry(Some(DataClass::Public), false);
    for payload in ["1", "mismatch-marker"] {
        let values = vec![value(
            "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:child[ex:slot='1']/ex:slot",
            &serde_json::to_string(payload).unwrap(),
        )];
        let (server, _, _, _) = fixture_with_registry(
            values,
            vec![policy(&["/ex:system", "/ex:system/**"])],
            registry,
        )
        .await;
        let reply = rpc(
            &server,
            &get(r#"<system xmlns="urn:example"><peer><child><slot/></child></peer></system>"#),
            &MgmtLimits::default(),
        );
        if payload == "1" {
            assert_eq!(
                data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
                vec![element(
                    "system",
                    "",
                    vec![element(
                        "peer",
                        "",
                        vec![
                            element("site", "east", vec![]),
                            element("name", "a", vec![]),
                            element("child", "", vec![element("slot", "1", vec![])])
                        ]
                    )]
                )]
            );
        } else {
            assert!(
                reply.contains("<error-tag>operation-failed</error-tag>"),
                "{reply}"
            );
            assert!(!reply.contains("<data"));
            assert!(!reply.contains("marker"));
        }
    }
}
