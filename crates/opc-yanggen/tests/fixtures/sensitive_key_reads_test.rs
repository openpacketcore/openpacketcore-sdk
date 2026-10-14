use generated_sensitive_key_test::{gnmi_json, netconf_xml, schema_registry, types::*};
use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{AuthStrength, TrustedPrincipal, WorkloadIdentity};
use opc_gnmi_server::proto::gnmi::{self, g_nmi_server::GNmi};
use opc_gnmi_server::{
    AuthenticatedGnmiPrincipal, CapabilityProfile, ExtensionRegistry, GnmiConfigBinding, GnmiError,
    GnmiJsonProjectionError, GnmiJsonRenderer, GnmiJsonUpdate, GnmiPatchApplicator, GnmiServer,
    GnmiService, GnmiVersion, NormalizedSet, ReadSelection, GNMI_VERSION,
};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{
    OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider,
};
use opc_mgmt_schema::{NetconfXmlRenderer, SchemaRegistry};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_netconf_server::{
    run_read_only_session_with_registry, NetconfConfigBinding, ReadOnlyNetconfServer,
    SessionConfig, SessionRegistry, WithDefaultsCapability, WithDefaultsMode,
};
use opc_types::TenantId;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MARKER: &str = "subscriber/quote'and\\slash]marker";
const SECRET: &str = "non-key-secret-payload-marker";

#[derive(Clone)]
struct Policy(NacmPolicy);
impl PolicySource for Policy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        Ok(Arc::new(self.0.clone()))
    }
    fn watch_authorization(
        &self,
        principal: &TrustedPrincipal,
        gate: opc_mgmt_authz::AuthorizationGate,
    ) -> Result<opc_mgmt_authz::AuthorizationWatch, AuthzError> {
        opc_mgmt_authz::AuthorizationWatch::immutable(
            self.active_policy_context_for_principal(principal)?,
            gate,
        )
    }
}
fn policy(allowed: &[&str], denied: &[&str]) -> Policy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("keys", "keys").unwrap();
    let mut policy = NacmPolicy::builder(PolicyVersion::new(1));
    for action in [NacmAction::Read, NacmAction::Subscribe] {
        for path in denied {
            policy = policy.add_rule(NacmRule::deny(
                action,
                YangPathPattern::parse(path, &modules).unwrap(),
            ));
        }
        for path in allowed {
            policy = policy.add_rule(NacmRule::allow(
                action,
                YangPathPattern::parse(path, &modules).unwrap(),
            ));
        }
    }
    Policy(policy.build())
}
fn full_policy(denied: &[&str]) -> Policy {
    policy(&["/keys:root", "/keys:root/**"], denied)
}

#[derive(Clone, Default)]
struct Audit(Arc<Mutex<Vec<AuditEvent>>>);
impl AuditSink for Audit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
}
struct EmptyState;
impl OperationalStateProvider for EmptyState {
    fn get(&self, _: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        Ok(OperationalResponse::default())
    }
}
struct NoPatch;
impl GnmiPatchApplicator<Root> for NoPatch {
    fn apply_set(&self, _: &Root, _: &NormalizedSet) -> Result<Root, GnmiError> {
        Err(GnmiError::unimplemented("read fixture"))
    }
}
#[derive(Clone)]
struct Binding {
    bus: Arc<ConfigBus<Root>>,
    policy: Arc<Policy>,
    operational: Vec<opc_mgmt_opstate::OperationalValue>,
}
impl GnmiConfigBinding<Root> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<Root>> {
        self.bus.clone()
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        schema_registry::registry()
    }
    fn policy_source(&self) -> Arc<dyn PolicySource> {
        self.policy.clone()
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<Root>> {
        Arc::new(NoPatch)
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        Arc::new(EmptyState)
    }
    fn render_running_json(
        &self,
        root: &Root,
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        gnmi_json::renderer().render_running_json(root, selection)
    }
}
impl NetconfConfigBinding<Root> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<Root>> {
        self.bus.clone()
    }
    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        schema_registry::registry()
    }
    fn generated_xml_renderer(&self) -> Option<&dyn NetconfXmlRenderer<Root>> {
        Some(&netconf_xml::GeneratedNetconfXmlRenderer)
    }
    fn nmda_get_data_supported(&self) -> bool {
        true
    }
    fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
        Some(
            WithDefaultsCapability::new(WithDefaultsMode::Trim, [WithDefaultsMode::ReportAll])
                .unwrap(),
        )
    }
    fn get_operational_state(
        &self,
        request: &OperationalRequest,
    ) -> Result<OperationalResponse, OperationalError> {
        Ok(OperationalResponse::new(
            self.operational
                .iter()
                .filter(|value| {
                    request.paths.iter().any(|path| {
                        opc_mgmt_path::canonical_path_matches(path.as_str(), value.path().as_str())
                    })
                })
                .cloned(),
        ))
    }
}
fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::User("read-fixture".into()),
        TenantId::new("read-fixture").unwrap(),
    )
    .with_auth_strength(AuthStrength::MutualTls)
}
struct Fixture {
    gnmi: GnmiService<Root, Binding>,
    netconf: ReadOnlyNetconfServer<Root, Binding, Arc<Policy>, Audit>,
    audit: Audit,
}

#[derive(Clone, Copy, Debug)]
enum NetconfRead {
    GetConfig,
    Get,
    GetData,
    GetDataOperational,
}

impl Fixture {
    async fn new(root: Root, policy: Policy) -> Self {
        Self::with_operational(root, policy, vec![]).await
    }
    async fn with_operational(
        root: Root,
        policy: Policy,
        operational: Vec<opc_mgmt_opstate::OperationalValue>,
    ) -> Self {
        let policy = Arc::new(policy);
        let binding = Binding {
            bus: Arc::new(
                ConfigBus::new_dev_only(root, MockManagedDatastore::new())
                    .await
                    .unwrap(),
            ),
            policy: policy.clone(),
            operational,
        };
        let audit = Audit::default();
        let server = GnmiServer::new(
            binding.clone(),
            MgmtLimits::default(),
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
            ExtensionRegistry::default(),
            Arc::new(audit.clone()),
        )
        .unwrap();
        let netconf = ReadOnlyNetconfServer::new(
            binding,
            policy,
            audit.clone(),
            opc_config_model::TransportType::NetconfTls,
        )
        .unwrap();
        Self {
            gnmi: GnmiService::new_authenticated(server),
            netconf,
            audit,
        }
    }
    async fn get(&self, path: gnmi::Path) -> Result<gnmi::GetResponse, tonic::Status> {
        let mut request = tonic::Request::new(gnmi::GetRequest {
            path: vec![path],
            r#type: gnmi::get_request::DataType::Config as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            ..Default::default()
        });
        request
            .extensions_mut()
            .insert(AuthenticatedGnmiPrincipal::new(principal()));
        self.gnmi
            .get(request)
            .await
            .map(tonic::Response::into_inner)
    }
    async fn xml(&self, filter: &str) -> String {
        self.xml_operation(&format!(
            "<get-config><source><running/></source>{filter}</get-config>"
        ))
        .await
    }
    async fn xml_read(
        &self,
        operation: NetconfRead,
        selector: Option<&str>,
        mode: Option<WithDefaultsMode>,
    ) -> String {
        let defaults = mode.map_or_else(String::new, |mode| {
            format!(
                "<wd:with-defaults xmlns:wd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">{}</wd:with-defaults>",
                mode.as_str()
            )
        });
        let filter = selector.map_or_else(String::new, |selector| match operation {
            NetconfRead::GetConfig | NetconfRead::Get => format!(
                "<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"{}\"/>",
                xml_escape(selector).replace('"', "&quot;")
            ),
            NetconfRead::GetData | NetconfRead::GetDataOperational => format!(
                "<ncds:xpath-filter xmlns:k=\"urn:keys\">{}</ncds:xpath-filter>",
                xml_escape(selector)
            ),
        });
        let body = match operation {
            NetconfRead::GetConfig => format!(
                "<get-config><source><running/></source>{filter}{defaults}</get-config>"
            ),
            NetconfRead::Get => format!("<get>{filter}{defaults}</get>"),
            NetconfRead::GetData => format!(
                "<ncds:get-data xmlns:ncds=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\"><ncds:datastore>ds:running</ncds:datastore>{filter}{defaults}</ncds:get-data>"
            ),
            NetconfRead::GetDataOperational => format!(
                "<ncds:get-data xmlns:ncds=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\"><ncds:datastore>ds:operational</ncds:datastore>{filter}{defaults}</ncds:get-data>"
            ),
        };
        self.xml_operation(&body).await
    }
    async fn xml_operation(&self, operation: &str) -> String {
        let sessions = SessionRegistry::new();
        let principal = principal();
        let (mut client, mut transport) = tokio::io::duplex(65536);
        let serving = run_read_only_session_with_registry(
            &self.netconf,
            &principal,
            &mut transport,
            SessionConfig::default(),
            1,
            &sessions,
        );
        async fn frame(client: &mut tokio::io::DuplexStream) -> String {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"]]>]]>") {
                bytes.push(client.read_u8().await.unwrap());
            }
            String::from_utf8(bytes[..bytes.len() - 6].to_vec()).unwrap()
        }
        let exchange = async {
            assert!(frame(&mut client).await.contains("<hello"));
            client.write_all(b"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>").await.unwrap();
            let rpc = format!("<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"read\">{operation}</rpc>]]>]]>");
            client.write_all(rpc.as_bytes()).await.unwrap();
            let reply = frame(&mut client).await;
            client.shutdown().await.unwrap();
            reply
        };
        let (reply, result) = tokio::join!(exchange, serving);
        result.unwrap();
        reply
    }
}
fn root_path() -> gnmi::Path {
    gnmi::Path {
        elem: vec![gnmi::PathElem {
            name: "keys:root".into(),
            key: Default::default(),
        }],
        ..Default::default()
    }
}
fn child_path(list: &str, keys: &[(&str, &str)], leaf: &str) -> gnmi::Path {
    let mut path = root_path();
    path.elem.push(gnmi::PathElem {
        name: format!("keys:{list}"),
        key: keys
            .iter()
            .map(|(key, value)| (format!("keys:{key}"), value.to_string()))
            .collect(),
    });
    path.elem.push(gnmi::PathElem {
        name: format!("keys:{leaf}"),
        key: Default::default(),
    });
    path
}
fn child_filter(list: &str, leaf: &str) -> String {
    format!("<filter><root xmlns=\"urn:keys\"><{list}><{leaf}/></{list}></root></filter>")
}
fn data(reply: &str) -> &str {
    assert!(!reply.contains("<rpc-error>"), "{reply}");
    if reply.contains("<data/>")
        || reply.contains("<data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\"/>")
    {
        ""
    } else {
        reply
            .split_once("<data>")
            .or_else(|| {
                reply.split_once(
                    "<data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">",
                )
            })
            .unwrap_or_else(|| panic!("missing data element: {reply}"))
            .1
            .split_once("</data>")
            .unwrap()
            .0
    }
}
#[allow(deprecated)]
fn updates(response: &gnmi::GetResponse) -> Vec<(gnmi::Path, Value)> {
    assert!(response.error.is_none());
    response
        .notification
        .iter()
        .flat_map(|n| {
            assert!(n.prefix.is_none());
            assert!(n.delete.is_empty());
            n.update.iter().map(|u| {
                let Some(gnmi::typed_value::Value::JsonIetfVal(bytes)) =
                    u.val.as_ref().unwrap().value.as_ref()
                else {
                    panic!("JSON_IETF value")
                };
                (
                    u.path.clone().unwrap(),
                    serde_json::from_slice(bytes).unwrap(),
                )
            })
        })
        .collect()
}
fn config(list: &str, rows: Value) -> Root {
    serde_json::from_value(json!({list: rows})).unwrap()
}
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn observed(list: &str, keys: &[(&str, &str)], text: &str) -> opc_mgmt_opstate::OperationalValue {
    let mut path = format!("/keys:root/keys:{list}");
    for (key, value) in keys {
        opc_mgmt_path::append_key_predicate(&mut path, &format!("keys:{key}"), value).unwrap();
    }
    path.push_str("/keys:observed");
    opc_mgmt_opstate::OperationalValue::new(
        opc_config_model::YangPath::new(path).unwrap(),
        serde_json::to_string(text).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn generated_netconf_get_merges_concrete_state_and_preserves_configuration_order() {
    let fixture = Fixture::with_operational(
        config(
            "ordered-rows",
            json!([{ "id": "z", "value": "first" }, { "id": "a", "value": "second" }]),
        ),
        full_policy(&[]),
        vec![
            observed("ordered-rows", &[("id", "c")], "new-c"),
            observed("ordered-rows", &[("id", "a")], "state-a"),
            observed("ordered-rows", &[("id", "b")], "new-b"),
        ],
    )
    .await;
    let reply = fixture
        .xml_operation(
            "<get><filter><root xmlns=\"urn:keys\"><ordered-rows/></root></filter></get>",
        )
        .await;
    assert_eq!(data(&reply), "<keys:root xmlns:keys=\"urn:keys\"><keys:ordered-rows><keys:id>z</keys:id><keys:value>first</keys:value></keys:ordered-rows><keys:ordered-rows><keys:id>a</keys:id><keys:value>second</keys:value><keys:observed>state-a</keys:observed></keys:ordered-rows><keys:ordered-rows><keys:id>b</keys:id><keys:observed>new-b</keys:observed></keys:ordered-rows><keys:ordered-rows><keys:id>c</keys:id><keys:observed>new-c</keys:observed></keys:ordered-rows></keys:root>");
}

#[tokio::test]
async fn generated_netconf_get_applies_each_branch_to_configuration_and_state() {
    let fixture = Fixture::with_operational(
        config(
            "composite-rows",
            json!([
                { "tenant": "east", "id": "a", "value": "selected-east", "payload": SECRET },
                { "tenant": "west", "id": "a", "value": "hidden-west", "payload": SECRET }
            ]),
        ),
        full_policy(&[]),
        vec![
            observed(
                "composite-rows",
                &[("tenant", "east"), ("id", "a")],
                "hidden-state",
            ),
            observed(
                "composite-rows",
                &[("tenant", "west"), ("id", "a")],
                "selected-west",
            ),
        ],
    )
    .await;
    let reply = fixture.xml_operation("<get><filter><root xmlns=\"urn:keys\"><composite-rows><tenant>east</tenant><value/></composite-rows><composite-rows><tenant>west</tenant><observed/></composite-rows></root></filter></get>").await;
    assert_eq!(data(&reply), "<keys:root xmlns:keys=\"urn:keys\"><keys:composite-rows><keys:tenant>east</keys:tenant><keys:id>a</keys:id><keys:value>selected-east</keys:value></keys:composite-rows><keys:composite-rows><keys:tenant>west</keys:tenant><keys:id>a</keys:id><keys:observed>selected-west</keys:observed></keys:composite-rows></keys:root>");
    assert!(!reply.contains("hidden"));
    assert!(!reply.contains(SECRET));
}

#[tokio::test]
async fn generated_netconf_operational_state_masks_forbidden_keys_without_merging_them() {
    for (list, key) in [
        ("blocked-rows", "id"),
        ("lawful-rows", "id"),
        ("named-rows", "password"),
    ] {
        let fixture = Fixture::with_operational(
            Root::default(),
            full_policy(&[]),
            vec![
                observed(list, &[(key, "b-marker")], "second"),
                observed(list, &[(key, "a-marker")], "first"),
            ],
        )
        .await;
        let reply = fixture.xml_operation(&format!("<get><filter><root xmlns=\"urn:keys\"><{list}><observed/></{list}></root></filter></get>")).await;
        assert_eq!(data(&reply), format!("<keys:root xmlns:keys=\"urn:keys\"><keys:{list}><keys:{key}>&lt;redacted&gt;</keys:{key}><keys:observed>first</keys:observed></keys:{list}><keys:{list}><keys:{key}>&lt;redacted&gt;</keys:{key}><keys:observed>second</keys:observed></keys:{list}></keys:root>"));
        assert!(!reply.contains("marker"));
        assert!(!format!("{:?}", fixture.audit.0.lock().unwrap()).contains("marker"));
    }
}
fn assert_safe(fixture: &Fixture, response: &gnmi::GetResponse, markers: &[&str]) {
    let diagnostic = format!("{response:?} {:?}", fixture.audit.0.lock().unwrap());
    for marker in markers {
        assert!(!diagnostic.contains(marker), "diagnostics contain a value");
    }
}

#[tokio::test]
async fn sensitive_key_permitted_read() {
    let fixture = Fixture::new(
        config(
            "sensitive-rows",
            json!([{ "id": MARKER, "value": "selected-value", "payload": SECRET }]),
        ),
        full_policy(&[]),
    )
    .await;
    let response = fixture.get(root_path()).await.unwrap();
    let found = updates(&response);
    assert_eq!(
        found,
        vec![
            (
                child_path("sensitive-rows", &[("id", MARKER)], "id"),
                json!(MARKER)
            ),
            (
                child_path("sensitive-rows", &[("id", MARKER)], "payload"),
                json!("<redacted>")
            ),
            (
                child_path("sensitive-rows", &[("id", MARKER)], "value"),
                json!("selected-value")
            ),
        ]
    );
    let reply = fixture.xml("").await;
    assert_eq!(data(&reply), format!("<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>{}</keys:id><keys:payload>&lt;redacted&gt;</keys:payload><keys:value>selected-value</keys:value></keys:sensitive-rows></keys:root>", xml_escape(MARKER)));
    assert!(!reply.contains(SECRET));
    assert_safe(&fixture, &response, &[MARKER, SECRET]);
}

#[tokio::test]
async fn sensitive_key_direct_child_read() {
    for marker in [MARKER, "back\\slash/\"marker"] {
        let fixture = Fixture::new(
            config(
                "sensitive-rows",
                json!([{ "id": marker, "value": "selected-value", "payload": SECRET }]),
            ),
            policy(
                &[
                    "/keys:root/keys:sensitive-rows/keys:id",
                    "/keys:root/keys:sensitive-rows/keys:value",
                ],
                &[],
            ),
        )
        .await;
        let path = child_path("sensitive-rows", &[("id", marker)], "value");
        let response = fixture.get(path.clone()).await.unwrap();
        assert_eq!(updates(&response), vec![(path, json!("selected-value"))]);
        let reply = fixture.xml(&child_filter("sensitive-rows", "value")).await;
        assert_eq!(data(&reply), format!("<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>{}</keys:id><keys:value>selected-value</keys:value></keys:sensitive-rows></keys:root>", xml_escape(marker)));
        assert_safe(&fixture, &response, &[marker, SECRET]);
        let quote = if marker.contains('\'') { '"' } else { '\'' };
        let selector = format!("/k:root/k:sensitive-rows[k:id={quote}{marker}{quote}]/k:value");
        let filter = format!(
            "<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"{}\"/>",
            xml_escape(&selector).replace('"', "&quot;")
        );
        assert_eq!(data(&fixture.xml(&filter).await), data(&reply));
    }
}

#[tokio::test]
async fn denied_key_omits_entry() {
    let cases = [
        (
            "public-rows",
            "id",
            json!([{ "id": "hidden-public-key", "value": "hidden-value" }]),
            vec![("id", "hidden-public-key")],
        ),
        (
            "sensitive-rows",
            "id",
            json!([{ "id": "hidden-sensitive-key", "value": "hidden-value" }]),
            vec![("id", "hidden-sensitive-key")],
        ),
        (
            "composite-rows",
            "tenant",
            json!([{ "tenant": "hidden-tenant-key", "id": "hidden-composite-key", "value": "hidden-value" }]),
            vec![
                ("tenant", "hidden-tenant-key"),
                ("id", "hidden-composite-key"),
            ],
        ),
        (
            "composite-rows",
            "id",
            json!([{ "tenant": "hidden-tenant-key", "id": "hidden-composite-key", "value": "hidden-value" }]),
            vec![
                ("tenant", "hidden-tenant-key"),
                ("id", "hidden-composite-key"),
            ],
        ),
    ];
    for (list, denied, rows, keys) in cases {
        for variant in 0..3 {
            let mut root = config(
                list,
                if variant == 0 {
                    json!([])
                } else {
                    rows.clone()
                },
            );
            if variant == 2 {
                match list {
                    "public-rows" => {
                        root.public_rows.values_mut().next().unwrap().id = LeafPresence::Absent
                    }
                    "sensitive-rows" => {
                        root.sensitive_rows.values_mut().next().unwrap().id =
                            SecretLeaf::new(LeafPresence::Absent)
                    }
                    "composite-rows" if denied == "id" => {
                        root.composite_rows.values_mut().next().unwrap().id =
                            SecretLeaf::new(LeafPresence::Absent)
                    }
                    "composite-rows" => {
                        root.composite_rows.values_mut().next().unwrap().tenant =
                            SecretLeaf::new(LeafPresence::Absent)
                    }
                    _ => unreachable!(),
                }
            }
            // Keep a permitted sibling populated so a parent read must invoke
            // projection even when every selected node in this entry is denied.
            let visible_list = if list == "public-rows" {
                root.sensitive_rows = config(
                    "sensitive-rows",
                    json!([{ "id": "visible-sibling-key", "value": "visible-sibling-value" }]),
                )
                .sensitive_rows;
                "sensitive-rows"
            } else {
                root.public_rows = config(
                    "public-rows",
                    json!([{ "id": "visible-sibling-key", "value": "visible-sibling-value" }]),
                )
                .public_rows;
                "public-rows"
            };
            let denied = format!("/keys:root/keys:{list}/keys:{denied}");
            let fixture = Fixture::new(root, full_policy(&[&denied])).await;
            let response = fixture.get(child_path(list, &keys, "value")).await.unwrap();
            assert_eq!(updates(&response), vec![]);
            assert_eq!(data(&fixture.xml(&child_filter(list, "value")).await), "");
            let parent_read = fixture.get(root_path()).await.unwrap();
            assert_eq!(
                updates(&parent_read),
                vec![
                    (
                        child_path(visible_list, &[("id", "visible-sibling-key")], "id"),
                        json!("visible-sibling-key")
                    ),
                    (
                        child_path(visible_list, &[("id", "visible-sibling-key")], "value"),
                        json!("visible-sibling-value")
                    ),
                ]
            );
            assert_eq!(data(&fixture.xml("").await), format!("<keys:root xmlns:keys=\"urn:keys\"><keys:{visible_list}><keys:id>visible-sibling-key</keys:id><keys:value>visible-sibling-value</keys:value></keys:{visible_list}></keys:root>"));
            assert_safe(
                &fixture,
                &parent_read,
                &[
                    "hidden-public-key",
                    "hidden-sensitive-key",
                    "hidden-tenant-key",
                    "hidden-composite-key",
                    "hidden-value",
                ],
            );
        }
    }
}

#[tokio::test]
async fn denied_ancestor_key_omits_nested_entry() {
    for denied in [
        "/keys:root/keys:parents/keys:id",
        "/keys:root/keys:parents/keys:children/keys:id",
    ] {
        for variant in 0..3 {
            let mut root = config(
                "parents",
                if variant == 0 {
                    json!([])
                } else {
                    json!([{ "id": "hidden-parent", "children": [{ "id": "hidden-child", "value": "hidden-value" }] }])
                },
            );
            if variant == 2 {
                let parent = root.parents.values_mut().next().unwrap();
                if denied.contains("children") {
                    parent.children.values_mut().next().unwrap().id =
                        SecretLeaf::new(LeafPresence::Absent);
                } else {
                    parent.id = SecretLeaf::new(LeafPresence::Absent);
                }
            }
            let fixture = Fixture::new(root, full_policy(&[denied])).await;
            let mut path = child_path("parents", &[("id", "hidden-parent")], "children");
            path.elem
                .last_mut()
                .unwrap()
                .key
                .insert("keys:id".into(), "hidden-child".into());
            path.elem.push(gnmi::PathElem {
                name: "keys:value".into(),
                key: Default::default(),
            });
            assert_eq!(updates(&fixture.get(path).await.unwrap()), vec![]);
            assert_eq!(data(&fixture.xml("<filter><root xmlns=\"urn:keys\"><parents><children><value/></children></parents></root></filter>").await), "");
        }
    }
}

#[tokio::test]
async fn allowed_missing_key_keeps_fixed_projection_failure() {
    for list in ["public-rows", "sensitive-rows"] {
        let mut root = config(
            list,
            json!([{ "id": "missing-key-marker", "value": "selected-value" }]),
        );
        if list == "public-rows" {
            root.public_rows.values_mut().next().unwrap().id = LeafPresence::Absent;
        } else {
            root.sensitive_rows.values_mut().next().unwrap().id =
                SecretLeaf::new(LeafPresence::Absent);
        }
        let fixture = Fixture::new(root, full_policy(&[])).await;
        let error = fixture.get(root_path()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert_eq!(error.message(), "gNMI internal error");
        let reply = fixture.xml("").await;
        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("missing-key-marker"));
        assert!(!format!("{error:?}").contains("missing-key-marker"));
    }
}

#[derive(Clone, Default)]
struct CaptureLogs(Arc<Mutex<Vec<String>>>);
struct LogFields(String);
impl tracing::field::Visit for LogFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}={value:?};", field.name()));
    }
}
impl tracing::Subscriber for CaptureLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = LogFields(String::new());
        attributes.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut fields = LogFields(String::new());
        values.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = LogFields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn sensitive_key_outputs_are_value_free() {
    use tracing::instrument::WithSubscriber;
    for (list, denied, refused) in [
        ("sensitive-rows", false, false),
        ("sensitive-rows", true, false),
        ("blocked-rows", false, true),
    ] {
        let marker = "distinct-diagnostic-key-marker";
        let logs = CaptureLogs::default();
        let key = format!("/keys:root/keys:{list}/keys:id");
        let denied_paths = if denied { vec![key.as_str()] } else { vec![] };
        let fixture = Fixture::new(
            config(
                list,
                json!([{ "id": marker, "value": "visible-payload", "payload": SECRET }]),
            ),
            full_policy(&denied_paths),
        )
        .await;
        let response = fixture.get(root_path()).with_subscriber(logs.clone()).await;
        if refused {
            assert_eq!(
                response.as_ref().unwrap_err().message(),
                "gNMI internal error"
            );
        } else if denied {
            assert_eq!(updates(response.as_ref().unwrap()), vec![]);
        } else {
            assert!(updates(response.as_ref().unwrap())
                .iter()
                .any(|(path, value)| path.elem[1].key["keys:id"] == marker
                    && value == &json!(marker)));
        }
        let reply = fixture.xml("").with_subscriber(logs.clone()).await;
        if denied {
            assert_eq!(data(&reply), "");
        } else if refused {
            assert!(!reply.contains(marker));
        } else {
            assert!(reply.contains(marker));
        }
        let diagnostics = format!(
            "{response:?} {:?} {:?} {}",
            fixture.audit.0.lock().unwrap(),
            logs.0.lock().unwrap(),
            opc_redaction::metrics::export_prometheus_text()
        );
        assert!(
            logs.0
                .lock()
                .unwrap()
                .iter()
                .any(|record| record.contains("management authorization decision")),
            "capture real authorization logs"
        );
        assert!(!diagnostics.contains(marker));
        assert!(!diagnostics.contains(SECRET));
    }
}

#[tokio::test]
async fn no_cleartext_key_predicate_is_refused() {
    let mut failures = Vec::new();
    for (list, key) in [
        ("blocked-rows", "id"),
        ("lawful-rows", "id"),
        ("named-rows", "password"),
    ] {
        let fixture = Fixture::new(
            config(
                list,
                json!([{ key: "forbidden-key-marker", "value": "selected-value" }]),
            ),
            full_policy(&[]),
        )
        .await;
        for operation in [NetconfRead::GetConfig, NetconfRead::Get, NetconfRead::GetData] {
            let matching = fixture
                .xml_read(
                    operation,
                    Some(&format!(
                        "/k:root/k:{list}[k:{key}='forbidden-key-marker']/k:value"
                    )),
                    None,
                )
                .await;
            let missing = fixture
                .xml_read(
                    operation,
                    Some(&format!("/k:root/k:{list}[k:{key}='other-marker']/k:value")),
                    None,
                )
                .await;
            let refused = matching == missing
                && matching.contains("<error-tag>operation-not-supported</error-tag>")
                && ["forbidden-key-marker", "other-marker", "selected-value", "<data", "<keys:"]
                    .iter()
                    .all(|marker| !matching.contains(marker));
            if !refused {
                failures.push(format!(
                    "{list}/{key} {operation:?}: matching and missing predicates must return byte-identical operation-not-supported errors without data; matching={matching:?}, missing={missing:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn no_cleartext_key_class_is_refused() {
    for (list, key) in [
        ("blocked-rows", "id"),
        ("lawful-rows", "id"),
        ("named-rows", "password"),
    ] {
        let fixture = Fixture::new(
            config(
                list,
                json!([{ key: "forbidden-key-marker", "value": "selected-value" }]),
            ),
            full_policy(&[]),
        )
        .await;
        let error = fixture.get(root_path()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert_eq!(error.message(), "gNMI internal error");
        assert!(!format!("{error:?}").contains("forbidden-key-marker"));
        let xml = fixture.xml("").await;
        assert!(!xml.contains("forbidden-key-marker"));
        assert!(
            data(&xml).contains(&format!("<keys:{key}>&lt;redacted&gt;</keys:{key}>")),
            "{xml}"
        );
        assert!(data(&xml).contains("<keys:value>selected-value</keys:value>"));
    }
}

#[tokio::test]
async fn denied_leaf_with_allowed_keys_is_omitted() {
    let fixture = Fixture::new(
        config(
            "sensitive-rows",
            json!([{ "id": "permitted-key", "value": "denied-value" }]),
        ),
        full_policy(&["/keys:root/keys:sensitive-rows/keys:value"]),
    )
    .await;
    assert_eq!(
        updates(
            &fixture
                .get(child_path(
                    "sensitive-rows",
                    &[("id", "permitted-key")],
                    "value"
                ))
                .await
                .unwrap()
        ),
        vec![]
    );
    assert_eq!(
        data(&fixture.xml(&child_filter("sensitive-rows", "value")).await),
        ""
    );
}

#[tokio::test]
async fn structural_only_selection_grants_no_child_permission() {
    let fixture = Fixture::new(
        config(
            "sensitive-rows",
            json!([{ "id": "hidden-key", "value": "hidden-value" }]),
        ),
        policy(&["/keys:root", "/keys:root/keys:sensitive-rows"], &[]),
    )
    .await;
    assert_eq!(updates(&fixture.get(root_path()).await.unwrap()), vec![]);
    assert_eq!(data(&fixture.xml("").await), "");
}

#[tokio::test]
async fn unmatched_canonical_instance_is_omitted() {
    let fixture = Fixture::new(
        config(
            "sensitive-rows",
            json!([{ "id": "existing-key", "value": "existing-value" }]),
        ),
        full_policy(&[]),
    )
    .await;
    assert_eq!(
        updates(
            &fixture
                .get(child_path(
                    "sensitive-rows",
                    &[("id", "absent-key")],
                    "value"
                ))
                .await
                .unwrap()
        ),
        vec![]
    );
    let xml = fixture.xml("<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"/k:root/k:sensitive-rows[k:id='absent-key']/k:value\"/>").await;
    assert_eq!(data(&xml), "");
    let matched = fixture.xml("<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"/k:root/k:sensitive-rows[k:id='existing-key']/k:value\"/>").await;
    assert_eq!(data(&matched), "<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>existing-key</keys:id><keys:value>existing-value</keys:value></keys:sensitive-rows></keys:root>");
}

#[tokio::test]
async fn unmatched_nested_canonical_instance_is_omitted() {
    let fixture = Fixture::new(
        config(
            "parents",
            json!([{
                "id": "existing-parent",
                "children": [{ "id": "existing-child", "value": "nested-value" }]
            }]),
        ),
        full_policy(&[]),
    )
    .await;
    for (parent, child, matched) in [
        ("existing-parent", "absent-child", false),
        ("absent-parent", "existing-child", false),
        ("existing-parent", "existing-child", true),
    ] {
        let mut path = child_path("parents", &[("id", parent)], "children");
        path.elem
            .last_mut()
            .unwrap()
            .key
            .insert("keys:id".into(), child.into());
        path.elem.push(gnmi::PathElem {
            name: "keys:value".into(),
            key: Default::default(),
        });
        let result = updates(&fixture.get(path.clone()).await.unwrap());
        assert_eq!(
            result,
            if matched {
                vec![(path, json!("nested-value"))]
            } else {
                vec![]
            }
        );
        let xml = fixture.xml(&format!("<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"/k:root/k:parents[k:id='{parent}']/k:children[k:id='{child}']/k:value\"/>")).await;
        assert_eq!(
            data(&xml),
            if matched {
                "<keys:root xmlns:keys=\"urn:keys\"><keys:parents><keys:id>existing-parent</keys:id><keys:children><keys:id>existing-child</keys:id><keys:value>nested-value</keys:value></keys:children></keys:parents></keys:root>"
            } else {
                ""
            }
        );
    }
}

#[tokio::test]
async fn keyed_list_ordering_is_preserved() {
    for (list, expected) in [
        ("ordered-rows", ["z-last", "a-first"]),
        ("sensitive-rows", ["a-first", "z-last"]),
    ] {
        let fixture = Fixture::new(config(list, json!([{ "id": "z-last", "value": "first" }, { "id": "a-first", "value": "second" }])), full_policy(&[])).await;
        let response = fixture.get(root_path()).await.unwrap();
        let found = updates(&response);
        let mut keys = found
            .iter()
            .map(|(path, _)| path.elem[1].key["keys:id"].as_str())
            .collect::<Vec<_>>();
        keys.dedup();
        assert_eq!(keys, expected);
        let xml = fixture.xml("").await;
        let content = data(&xml);
        let first = content
            .find(&format!("<keys:id>{}</keys:id>", expected[0]))
            .unwrap();
        let second = content
            .find(&format!("<keys:id>{}</keys:id>", expected[1]))
            .unwrap();
        assert!(first < second);
        if list == "ordered-rows" {
            assert_eq!(
                found
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect::<Vec<_>>(),
                vec![
                    json!({"id":"z-last","value":"first"}),
                    json!({"id":"a-first","value":"second"})
                ]
            );
        }
    }
}

async fn assert_empty_presence_read(operation: NetconfRead) {
    let root: Root = serde_json::from_value(json!({ "empty-presence": {} })).unwrap();
    assert!(matches!(
        &root.empty_presence.as_ref().unwrap().optional,
        LeafPresence::Absent
    ));
    let fixture = Fixture::new(root, full_policy(&[])).await;
    for selector in [None, Some("/k:root/k:empty-presence")] {
        let reply = fixture.xml_read(operation, selector, None).await;
        assert_eq!(
            data(&reply),
            "<keys:root xmlns:keys=\"urn:keys\"><keys:empty-presence></keys:empty-presence></keys:root>",
            "{operation:?}: preserve an authorized stored presence container"
        );
    }
    let absent = Fixture::new(serde_json::from_value(json!({})).unwrap(), full_policy(&[])).await;
    assert_eq!(
        data(&absent.xml_read(operation, None, None).await),
        "",
        "{operation:?}: do not fabricate an absent presence container"
    );
}

async fn assert_default_trimmed_presence_read(operation: NetconfRead) {
    let mut root: Root = serde_json::from_value(json!({ "default-presence": {} })).unwrap();
    root.default_presence.as_mut().unwrap().defaulted =
        LeafPresence::Defaulted("default-value".into());
    let fixture = Fixture::new(root, full_policy(&[])).await;
    let report_all = fixture
        .xml_read(operation, None, Some(WithDefaultsMode::ReportAll))
        .await;
    assert_eq!(
        data(&report_all),
        "<keys:root xmlns:keys=\"urn:keys\"><keys:default-presence><keys:defaulted>default-value</keys:defaulted></keys:default-presence></keys:root>",
        "{operation:?}: the stored defaulted child is available in report-all"
    );
    let trimmed = fixture
        .xml_read(operation, None, Some(WithDefaultsMode::Trim))
        .await;
    assert_eq!(
        data(&trimmed),
        "<keys:root xmlns:keys=\"urn:keys\"><keys:default-presence></keys:default-presence></keys:root>",
        "{operation:?}: trimming a child must preserve its stored presence container"
    );
}

async fn assert_keyed_list_presence_read(operation: NetconfRead) {
    let root = config(
        "public-rows",
        json!([{ "id": "visible-row", "row-presence": {} }]),
    );
    assert!(root.public_rows.values().next().unwrap().row_presence.is_some());
    let fixture = Fixture::new(root, full_policy(&[])).await;
    for selector in [
        None,
        Some("/k:root/k:public-rows[k:id='visible-row']/k:row-presence"),
    ] {
        let reply = fixture.xml_read(operation, selector, None).await;
        assert_eq!(
            data(&reply),
            "<keys:root xmlns:keys=\"urn:keys\"><keys:public-rows><keys:id>visible-row</keys:id><keys:row-presence></keys:row-presence></keys:public-rows></keys:root>",
            "{operation:?}: retain presence inside an authorized keyed entry"
        );
    }
}

async fn assert_presence_omission_controls(operation: NetconfRead) {
    let root: Root = serde_json::from_value(json!({
        "scope": { "members": [{ "id": "existing-member", "value": "member-value" }] }
    }))
    .unwrap();
    assert!(root.scope.is_some());
    let fixture = Fixture::new(root, full_policy(&[])).await;
    let unmatched = fixture
        .xml_read(
            operation,
            Some("/k:root/k:scope/k:members[k:id='missing-member']/k:value"),
            None,
        )
        .await;
    assert_eq!(
        data(&unmatched),
        "",
        "{operation:?}: omit presence and structural ancestors of an unmatched instance"
    );
    let matched = fixture
        .xml_read(
            operation,
            Some("/k:root/k:scope/k:members[k:id='existing-member']/k:value"),
            None,
        )
        .await;
    assert_eq!(
        data(&matched),
        "<keys:root xmlns:keys=\"urn:keys\"><keys:scope><keys:members><keys:id>existing-member</keys:id><keys:value>member-value</keys:value></keys:members></keys:scope></keys:root>",
        "{operation:?}: an authorized matching instance still renders"
    );

    let hidden: Root = serde_json::from_value(json!({
        "empty-presence": {},
        "public-rows": [{ "id": "hidden-row", "row-presence": {} }],
        "sensitive-rows": [{ "id": "visible-sibling", "value": "visible-value" }]
    }))
    .unwrap();
    let fixture = Fixture::new(
        hidden,
        full_policy(&[
            "/keys:root/keys:empty-presence",
            "/keys:root/keys:public-rows/keys:id",
        ]),
    )
    .await;
    let denied = fixture
        .xml_read(
            operation,
            Some("/k:root/k:public-rows[k:id='hidden-row']/k:row-presence"),
            None,
        )
        .await;
    assert_eq!(data(&denied), "", "{operation:?}: a denied key hides presence in its entry");
    let all = fixture.xml_read(operation, None, None).await;
    assert_eq!(
        data(&all),
        "<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>visible-sibling</keys:id><keys:value>visible-value</keys:value></keys:sensitive-rows></keys:root>",
        "{operation:?}: hide denied presence branches while preserving a permitted sibling"
    );
}

#[tokio::test]
async fn empty_presence_survives_get_config() {
    assert_empty_presence_read(NetconfRead::GetConfig).await;
}

#[tokio::test]
async fn empty_presence_survives_get() {
    assert_empty_presence_read(NetconfRead::Get).await;
}

#[tokio::test]
async fn empty_presence_survives_get_data() {
    assert_empty_presence_read(NetconfRead::GetData).await;
}

#[tokio::test]
async fn default_trimmed_presence_survives_get_config() {
    assert_default_trimmed_presence_read(NetconfRead::GetConfig).await;
}

#[tokio::test]
async fn default_trimmed_presence_survives_get() {
    assert_default_trimmed_presence_read(NetconfRead::Get).await;
}

#[tokio::test]
async fn default_trimmed_presence_survives_get_data() {
    assert_default_trimmed_presence_read(NetconfRead::GetData).await;
}

#[tokio::test]
async fn keyed_list_presence_survives_get_config() {
    assert_keyed_list_presence_read(NetconfRead::GetConfig).await;
}

#[tokio::test]
async fn keyed_list_presence_survives_get() {
    assert_keyed_list_presence_read(NetconfRead::Get).await;
}

#[tokio::test]
async fn keyed_list_presence_survives_get_data() {
    assert_keyed_list_presence_read(NetconfRead::GetData).await;
}

#[tokio::test]
async fn presence_omission_controls_get_config() {
    assert_presence_omission_controls(NetconfRead::GetConfig).await;
}

#[tokio::test]
async fn presence_omission_controls_get() {
    assert_presence_omission_controls(NetconfRead::Get).await;
}

#[tokio::test]
async fn presence_omission_controls_get_data() {
    assert_presence_omission_controls(NetconfRead::GetData).await;
}

#[tokio::test]
async fn empty_presence_survives_operational_get_data() {
    assert_empty_presence_read(NetconfRead::GetDataOperational).await;
}

#[tokio::test]
async fn keyed_list_presence_survives_operational_get_data() {
    assert_keyed_list_presence_read(NetconfRead::GetDataOperational).await;
}

#[tokio::test]
async fn presence_omission_controls_operational_get_data() {
    assert_presence_omission_controls(NetconfRead::GetDataOperational).await;
}
