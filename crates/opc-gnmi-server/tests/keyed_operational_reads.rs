use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{AuthStrength, TrustedPrincipal, WorkloadIdentity, YangPath};
use opc_gnmi_server::proto::gnmi::{self, g_nmi_server::GNmi};
use opc_gnmi_server::{
    AuthenticatedGnmiPrincipal, CapabilityProfile, ExtensionRegistry, GnmiConfigBinding, GnmiError,
    GnmiJsonProjectionError, GnmiJsonUpdate, GnmiPatchApplicator, GnmiServer, GnmiService,
    GnmiVersion, NormalizedSet, ReadSelection, GNMI_VERSION,
};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
    OperationalValue,
};
use opc_mgmt_path::canonical_path_matches;
use opc_mgmt_schema::{
    DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_types::TenantId;
use tonic::{Code, Request};

#[path = "keyed_operational_reads/subscriptions.rs"]
mod subscriptions;

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
impl OperationalStateProvider for Provider {
    fn get(&self, request: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(OperationalResponse::new(
            self.values
                .lock()
                .unwrap()
                .iter()
                .filter(|value| {
                    self.unchecked.load(Ordering::SeqCst)
                        || request.paths.iter().any(|selector| {
                            canonical_path_matches(selector.as_str(), value.path().as_str())
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
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::clone(&self.revisions[index % self.revisions.len()]))
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
#[derive(Clone)]
struct Binding {
    registry: &'static dyn SchemaRegistry,
    bus: Arc<ConfigBus<()>>,
    provider: Arc<Provider>,
    policy: Arc<Policy>,
    renders: Arc<AtomicUsize>,
    config_reads: Arc<AtomicUsize>,
}
impl GnmiPatchApplicator<()> for Binding {
    fn apply_set(&self, _: &(), _: &NormalizedSet) -> Result<(), GnmiError> {
        Ok(())
    }
}
impl GnmiConfigBinding<()> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        self.config_reads.fetch_add(1, Ordering::SeqCst);
        Arc::clone(&self.bus)
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        self.registry
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<()>> {
        Arc::new(self.clone())
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        self.provider.clone()
    }
    fn policy_source(&self) -> Arc<dyn PolicySource> {
        self.policy.clone()
    }
    fn render_running_json(
        &self,
        _: &(),
        _: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        Ok(Vec::new())
    }
    fn render_get_json(
        &self,
        _: &(),
        _: ReadSelection<'_>,
        operational: &OperationalResponse,
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        self.renders.fetch_add(1, Ordering::SeqCst);
        operational
            .values
            .iter()
            .filter(|value| selection.contains_reported_path(value.path()))
            .map(|value| GnmiJsonUpdate::new(value.path().clone(), value.value_json()))
            .collect()
    }
}

fn policy(paths: &[&str]) -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("example", "ex").unwrap();
    let mut builder = NacmPolicy::builder(PolicyVersion::new(1));
    for path in paths {
        for action in [NacmAction::Read, NacmAction::Subscribe] {
            builder = builder.add_rule(NacmRule::allow(
                action,
                YangPathPattern::parse(path, &modules).unwrap(),
            ));
        }
    }
    builder.build()
}
async fn fixture(
    values: Vec<OperationalValue>,
    policies: Vec<NacmPolicy>,
    limits: MgmtLimits,
) -> (GnmiService<(), Binding>, Binding, Arc<Audit>) {
    fixture_with_registry(values, policies, limits, &Registry).await
}

async fn fixture_with_registry(
    values: Vec<OperationalValue>,
    policies: Vec<NacmPolicy>,
    limits: MgmtLimits,
    registry: &'static dyn SchemaRegistry,
) -> (GnmiService<(), Binding>, Binding, Arc<Audit>) {
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
        policy: Arc::new(Policy {
            calls: AtomicUsize::new(0),
            revisions: policies.into_iter().map(Arc::new).collect(),
        }),
        renders: Arc::new(AtomicUsize::new(0)),
        config_reads: Arc::new(AtomicUsize::new(0)),
    };
    let audit = Arc::new(Audit::default());
    let server = GnmiServer::new_with_audit(
        binding.clone(),
        limits,
        CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
        ExtensionRegistry::default(),
        audit.clone(),
    )
    .unwrap();
    binding.config_reads.store(0, Ordering::SeqCst);
    (GnmiService::new(server), binding, audit)
}
fn value(path: &str, json: &str) -> OperationalValue {
    OperationalValue::new(YangPath::new(path).unwrap(), json).unwrap()
}
fn peer(name: &str, leaf: &str, json: &str) -> OperationalValue {
    value(
        &format!("/ex:system/ex:peer[ex:site='east'][ex:name='{name}']/ex:{leaf}"),
        json,
    )
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

fn masked_selection(secret_name: bool, nested: bool, guess: &str) -> gnmi::Path {
    let mut path = selection(
        &[(if secret_name { "password" } else { "name" }, guess)],
        "up",
    );
    if nested {
        path.elem.insert(
            2,
            gnmi::PathElem {
                name: "child".into(),
                key: HashMap::new(),
            },
        );
    }
    path
}

fn masked_instance(secret_name: bool, nested: bool) -> OperationalValue {
    let key = if secret_name { "password" } else { "name" };
    let child = if nested { "/ex:child[ex:slot='1']" } else { "" };
    value(
        &format!("/ex:system/ex:peer[ex:site='east'][ex:{key}='correct-marker']{child}/ex:up"),
        "true",
    )
}

#[tokio::test]
async fn masked_composite_and_ancestor_matches_refuse_all_classes_and_get_locations() {
    for (class, secret_name) in [
        (Some(DataClass::SecuritySecret), false),
        (Some(DataClass::LawfulIntercept), false),
        (None, false),
        (Some(DataClass::Public), true),
    ] {
        let registry = masked_registry(class, secret_name);
        for nested in [false, true] {
            for populated in [false, true] {
                for allowed in [false, true] {
                    for guess in ["correct-marker", "wrong-marker"] {
                        for prefix in [false, true] {
                            let values = if populated {
                                vec![masked_instance(secret_name, nested)]
                            } else {
                                vec![]
                            };
                            let (service, binding, audit) = fixture_with_registry(
                                values,
                                vec![policy(if allowed { &["/ex:system/**"] } else { &[] })],
                                MgmtLimits::default(),
                                registry,
                            )
                            .await;
                            let path = masked_selection(secret_name, nested, guess);
                            let request = if prefix {
                                get(vec![gnmi::Path::default()], Some(path))
                            } else {
                                get(vec![path], None)
                            };
                            let error = service.get(request).await.unwrap_err();
                            assert_eq!(error.code(), Code::InvalidArgument);
                            assert_eq!(error.message(), "invalid gNMI request");
                            assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 0);
                            assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
                            assert!(binding.provider.requests.lock().unwrap().is_empty());
                            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
                            assert!(!format!("{error:?} {:?}", audit.0.lock().unwrap())
                                .contains("marker"));
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn operational_key_payload_must_equal_the_complete_identity() {
    let registry = masked_registry(Some(DataClass::Public), false);
    for payload in ["1", "mismatch-marker"] {
        let values = vec![value(
            "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:child[ex:slot='1']/ex:slot",
            &serde_json::to_string(payload).unwrap(),
        )];
        let (service, _, _) = fixture_with_registry(
            values,
            vec![policy(&["/ex:system/**"])],
            MgmtLimits::default(),
            registry,
        )
        .await;
        let mut path = masked_selection(false, true, "a");
        path.elem.last_mut().unwrap().name = "slot".into();
        let result = service.get(get(vec![path], None)).await;
        if payload == "1" {
            let output = decoded(result.unwrap().into_inner());
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].0[2].key["ex:slot"], "1");
            assert_eq!(output[0].1, b"\"1\"");
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::Internal);
            assert_eq!(error.message(), "gNMI internal error");
            assert!(!format!("{error:?}").contains("marker"));
        }
    }
}

#[tokio::test]
async fn operational_opaque_keyed_aggregate_requires_a_child_filtering_binding() {
    let registry = masked_registry(Some(DataClass::Public), false);
    let values = vec![value(
        "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:child[ex:slot='1']",
        r#"{"slot":"1","up":"opaque-marker"}"#,
    )];
    let (service, _, _) = fixture_with_registry(
        values,
        vec![policy(&["/ex:system/**"])],
        MgmtLimits::default(),
        registry,
    )
    .await;
    let error = service
        .get(get(vec![selection(&[], "child")], None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Internal);
    assert_eq!(error.message(), "gNMI internal error");
    assert!(!format!("{error:?}").contains("marker"));
}
fn selection(keys: &[(&str, &str)], leaf: &str) -> gnmi::Path {
    gnmi::Path {
        elem: vec![
            gnmi::PathElem {
                name: "system".into(),
                key: HashMap::new(),
            },
            gnmi::PathElem {
                name: "peer".into(),
                key: keys
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            gnmi::PathElem {
                name: leaf.into(),
                key: HashMap::new(),
            },
        ],
        ..Default::default()
    }
}
fn get(paths: Vec<gnmi::Path>, prefix: Option<gnmi::Path>) -> Request<gnmi::GetRequest> {
    let mut request = Request::new(gnmi::GetRequest {
        path: paths,
        prefix,
        encoding: gnmi::Encoding::JsonIetf as i32,
        r#type: gnmi::get_request::DataType::State as i32,
        ..Default::default()
    });
    request
        .extensions_mut()
        .insert(AuthenticatedGnmiPrincipal::new(
            TrustedPrincipal::new(
                WorkloadIdentity::User("reader".into()),
                TenantId::from_static("example"),
            )
            .with_auth_strength(AuthStrength::MutualTls),
        ));
    request
}
fn decoded(response: gnmi::GetResponse) -> Vec<(Vec<gnmi::PathElem>, Vec<u8>)> {
    response
        .notification
        .into_iter()
        .flat_map(|n| n.update)
        .map(|u| {
            let gnmi::typed_value::Value::JsonIetfVal(value) = u.val.unwrap().value.unwrap() else {
                panic!("JSON encoding")
            };
            (u.path.unwrap().elem, value)
        })
        .collect()
}

#[tokio::test]
async fn gnmi_operational_get_expands_instances() {
    for keys in [
        vec![],
        vec![("site", "east")],
        vec![("site", "*"), ("name", "*")],
    ] {
        let (service, _, _) = fixture(
            vec![peer("b", "up", "false"), peer("a", "up", "true")],
            vec![policy(&["/ex:system/**"])],
            MgmtLimits::default(),
        )
        .await;
        let output = decoded(
            service
                .get(get(vec![selection(&keys, "up")], None))
                .await
                .unwrap()
                .into_inner(),
        );
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].0[1].key.get("ex:name").unwrap(), "a");
        assert_eq!(output[1].0[1].key.get("ex:name").unwrap(), "b");
        assert_eq!(output[0].1, b"true");
        assert_eq!(output[1].1, b"false");
    }
}

#[tokio::test]
async fn operational_wildcards_do_not_admit_undeclared_or_duplicate_keys() {
    let unknown = selection(&[("unknown", "*")], "up");
    let duplicate = selection(&[("name", "*"), ("ex:name", "a")], "up");
    let mut non_list = selection(&[], "up");
    non_list.elem[0].key.insert("unknown".into(), "*".into());
    for path in [unknown, duplicate, non_list] {
        let (service, binding, _) = fixture(
            vec![peer("a", "up", "true")],
            vec![policy(&["/ex:system/**"])],
            MgmtLimits::default(),
        )
        .await;
        let error = service.get(get(vec![path], None)).await.unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 0);
        assert!(binding.provider.requests.lock().unwrap().is_empty());
        assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn gnmi_root_and_prefix_expansion_are_canonical_and_ordered() {
    let (service, _, _) = fixture(
        vec![peer("b", "up", "false"), peer("a", "up", "true")],
        vec![policy(&["/ex:system/**"])],
        MgmtLimits::default(),
    )
    .await;
    let root = decoded(
        service
            .get(get(Vec::new(), None))
            .await
            .unwrap()
            .into_inner(),
    );
    let mut prefix = selection(&[("site", "east")], "up");
    prefix.elem.pop();
    let selected = decoded(
        service
            .get(get(Vec::new(), Some(prefix)))
            .await
            .unwrap()
            .into_inner(),
    );
    assert_eq!(selected, root);
    assert_eq!(root.len(), 2);
    assert_eq!(root[0].0[1].key["ex:name"], "a");
}

#[tokio::test]
async fn operational_denied_key_prunes_allowed_child() {
    for denied in ["site", "name"] {
        let allowed_key = if denied == "site" {
            "/ex:system/ex:peer/ex:name"
        } else {
            "/ex:system/ex:peer/ex:site"
        };
        let (service, binding, _) = fixture(
            vec![peer("identity-marker", "up", "true")],
            vec![policy(&["/ex:system/ex:peer/ex:up", allowed_key])],
            MgmtLimits::default(),
        )
        .await;
        let output = decoded(
            service
                .get(get(
                    vec![selection(
                        &[("site", "east"), ("name", "identity-marker")],
                        "up",
                    )],
                    None,
                ))
                .await
                .unwrap()
                .into_inner(),
        );
        assert!(output.is_empty());
        assert!(binding.provider.requests.lock().unwrap().is_empty());
        assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn operational_reads_use_one_policy_context() {
    let control = "/ex:system/ex:visible";
    let (service, binding, _) = fixture(
        vec![peer("a", "up", "true"), value(control, "17")],
        vec![
            policy(&["/ex:system/ex:peer/ex:up", control]),
            policy(&[
                "/ex:system/ex:peer/ex:site",
                "/ex:system/ex:peer/ex:name",
                control,
            ]),
        ],
        MgmtLimits::default(),
    )
    .await;
    let paths = vec![
        selection(&[("site", "east"), ("name", "a")], "up"),
        gnmi::Path {
            elem: vec![
                gnmi::PathElem {
                    name: "system".into(),
                    key: HashMap::new(),
                },
                gnmi::PathElem {
                    name: "visible".into(),
                    key: HashMap::new(),
                },
            ],
            ..Default::default()
        },
    ];
    let output = decoded(service.get(get(paths, None)).await.unwrap().into_inner());
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].1, b"17");
    assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        binding.provider.requests.lock().unwrap()[0].paths,
        vec![YangPath::new(control).unwrap()]
    );
}

#[tokio::test]
async fn operational_masked_key_match_is_refused_before_access() {
    for guess in ["correct-marker", "incorrect-marker"] {
        for permitted in [false, true] {
            let (service, binding, audit) = fixture(
                vec![value(
                    "/ex:system/ex:sealed[ex:id='correct-marker']/ex:up",
                    "true",
                )],
                vec![policy(if permitted { &["/ex:system/**"] } else { &[] })],
                MgmtLimits::default(),
            )
            .await;
            let mut path = selection(&[("id", guess)], "up");
            path.elem[1].name = "sealed".into();
            let error = service.get(get(vec![path], None)).await.unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument);
            assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 0);
            assert!(binding.provider.requests.lock().unwrap().is_empty());
            assert_eq!(binding.config_reads.load(Ordering::SeqCst), 0);
            assert!(!format!("{error:?} {:?}", audit.0.lock().unwrap()).contains(guess));
        }
    }
}

#[tokio::test]
async fn operational_get_masks_payloads_before_binding_projection() {
    let (service, _, _) = fixture(
        vec![peer("a", "payload", "\"payload-marker\"")],
        vec![policy(&["/ex:system/**"])],
        MgmtLimits::default(),
    )
    .await;
    let output = decoded(
        service
            .get(get(
                vec![selection(&[("site", "east"), ("name", "a")], "payload")],
                None,
            ))
            .await
            .unwrap()
            .into_inner(),
    );
    assert_eq!(output.len(), 1);
    assert_eq!(
        serde_json::from_slice::<String>(&output[0].1).unwrap(),
        "<redacted>"
    );
}

#[tokio::test]
async fn operational_expansion_limits_are_checked_before_projection() {
    let limits = MgmtLimits {
        max_paths_per_request: 1,
        ..MgmtLimits::default()
    };
    let (service, binding, _) = fixture(
        vec![peer("a", "up", "true"), peer("b", "up", "false")],
        vec![policy(&["/ex:system/**"])],
        limits,
    )
    .await;
    let error = service
        .get(get(vec![selection(&[], "up")], None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
    assert_eq!(binding.provider.requests.lock().unwrap()[0].max_values, 1);
}

#[tokio::test]
async fn operational_instances_require_complete_declared_keys() {
    for invalid in [
        "/ex:system/ex:peer[ex:name='a']/ex:up",
        "/ex:system/ex:peer[ex:name='a'][ex:site='east']/ex:up",
        "/ex:system/ex:peer[ex:site='east'][ex:name='a'][ex:other='x']/ex:up",
    ] {
        let (service, binding, _) = fixture(
            vec![value(invalid, "true")],
            vec![policy(&["/ex:system/**"])],
            MgmtLimits::default(),
        )
        .await;
        binding.provider.unchecked.store(true, Ordering::SeqCst);
        let error = service.get(get(Vec::new(), None)).await.unwrap_err();
        assert_eq!(error.code(), Code::Internal);
        assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
    }
}
