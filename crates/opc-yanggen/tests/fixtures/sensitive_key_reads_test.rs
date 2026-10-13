use std::sync::{Arc, Mutex};
use generated_sensitive_key_test::{gnmi_json, netconf_xml, schema_registry, types::*};
use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{AuthStrength, TrustedPrincipal, WorkloadIdentity};
use opc_gnmi_server::{AuthenticatedGnmiPrincipal, CapabilityProfile, ExtensionRegistry, GnmiConfigBinding, GnmiError, GnmiJsonProjectionError, GnmiJsonRenderer, GnmiJsonUpdate, GnmiPatchApplicator, GnmiServer, GnmiService, GnmiVersion, NormalizedSet, ReadSelection, GNMI_VERSION};
use opc_gnmi_server::proto::gnmi::{self, g_nmi_server::GNmi};
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};
use opc_mgmt_authz::{AuthzError, PolicySource};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalError, OperationalRequest, OperationalResponse, OperationalStateProvider};
use opc_mgmt_schema::{NetconfXmlRenderer, SchemaRegistry};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_netconf_server::{NetconfConfigBinding, ReadOnlyNetconfServer, SessionConfig, SessionRegistry, run_read_only_session_with_registry};
use opc_types::TenantId;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MARKER: &str = "subscriber/quote'and\\slash]marker";
const SECRET: &str = "non-key-secret-payload-marker";

#[derive(Clone)]
struct Policy(NacmPolicy);
impl PolicySource for Policy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> { Ok(Arc::new(self.0.clone())) }
    fn watch_authorization(&self, principal: &TrustedPrincipal, gate: opc_mgmt_authz::AuthorizationGate) -> Result<opc_mgmt_authz::AuthorizationWatch, AuthzError> {
        opc_mgmt_authz::AuthorizationWatch::immutable(self.active_policy_context_for_principal(principal)?, gate)
    }
}
fn policy(allowed: &[&str], denied: &[&str]) -> Policy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("keys", "keys").unwrap();
    let mut policy = NacmPolicy::builder(PolicyVersion::new(1));
    for action in [NacmAction::Read, NacmAction::Subscribe] {
        for path in denied { policy = policy.add_rule(NacmRule::deny(action, YangPathPattern::parse(path, &modules).unwrap())); }
        for path in allowed { policy = policy.add_rule(NacmRule::allow(action, YangPathPattern::parse(path, &modules).unwrap())); }
    }
    Policy(policy.build())
}
fn full_policy(denied: &[&str]) -> Policy { policy(&["/keys:root", "/keys:root/**"], denied) }

#[derive(Clone, Default)]
struct Audit(Arc<Mutex<Vec<AuditEvent>>>);
impl AuditSink for Audit {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> { self.0.lock().unwrap().push(event.clone()); Ok(()) }
}
struct EmptyState;
impl OperationalStateProvider for EmptyState {
    fn get(&self, _: &OperationalRequest) -> Result<OperationalResponse, OperationalError> { Ok(OperationalResponse::default()) }
}
struct NoPatch;
impl GnmiPatchApplicator<Root> for NoPatch {
    fn apply_set(&self, _: &Root, _: &NormalizedSet) -> Result<Root, GnmiError> { Err(GnmiError::unimplemented("read fixture")) }
}
#[derive(Clone)]
struct Binding { bus: Arc<ConfigBus<Root>>, policy: Arc<Policy> }
impl GnmiConfigBinding<Root> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<Root>> { self.bus.clone() }
    fn schema(&self) -> &'static dyn SchemaRegistry { schema_registry::registry() }
    fn policy_source(&self) -> Arc<dyn PolicySource> { self.policy.clone() }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<Root>> { Arc::new(NoPatch) }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> { Arc::new(EmptyState) }
    fn render_running_json(&self, root: &Root, selection: ReadSelection<'_>) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> { gnmi_json::renderer().render_running_json(root, selection) }
}
impl NetconfConfigBinding<Root> for Binding {
    fn config_bus(&self) -> Arc<ConfigBus<Root>> { self.bus.clone() }
    fn schema_registry(&self) -> &'static dyn SchemaRegistry { schema_registry::registry() }
    fn generated_xml_renderer(&self) -> Option<&dyn NetconfXmlRenderer<Root>> { Some(&netconf_xml::GeneratedNetconfXmlRenderer) }
    fn nmda_get_data_supported(&self) -> bool { true }
}
fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(WorkloadIdentity::User("read-fixture".into()), TenantId::new("read-fixture").unwrap()).with_auth_strength(AuthStrength::MutualTls)
}
struct Fixture {
    gnmi: GnmiService<Root, Binding>,
    netconf: ReadOnlyNetconfServer<Root, Binding, Arc<Policy>, Audit>,
    audit: Audit,
}
impl Fixture {
    async fn new(root: Root, policy: Policy) -> Self {
        let policy = Arc::new(policy);
        let binding = Binding { bus: Arc::new(ConfigBus::new_dev_only(root, MockManagedDatastore::new()).await.unwrap()), policy: policy.clone() };
        let audit = Audit::default();
        let server = GnmiServer::new(binding.clone(), MgmtLimits::default(), CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()), ExtensionRegistry::default(), Arc::new(audit.clone())).unwrap();
        let netconf = ReadOnlyNetconfServer::new(binding, policy, audit.clone(), opc_config_model::TransportType::NetconfTls).unwrap();
        Self { gnmi: GnmiService::new_authenticated(server), netconf, audit }
    }
    async fn get(&self, path: gnmi::Path) -> Result<gnmi::GetResponse, tonic::Status> {
        let mut request = tonic::Request::new(gnmi::GetRequest { path: vec![path], r#type: gnmi::get_request::DataType::Config as i32, encoding: gnmi::Encoding::JsonIetf as i32, ..Default::default() });
        request.extensions_mut().insert(AuthenticatedGnmiPrincipal::new(principal()));
        self.gnmi.get(request).await.map(tonic::Response::into_inner)
    }
    async fn xml(&self, filter: &str) -> String {
        let sessions = SessionRegistry::new();
        let principal = principal();
        let (mut client, mut transport) = tokio::io::duplex(65536);
        let serving = run_read_only_session_with_registry(&self.netconf, &principal, &mut transport, SessionConfig::default(), 1, &sessions);
        async fn frame(client: &mut tokio::io::DuplexStream) -> String {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"]]>]]>") { bytes.push(client.read_u8().await.unwrap()); }
            String::from_utf8(bytes[..bytes.len()-6].to_vec()).unwrap()
        }
        let exchange = async {
            assert!(frame(&mut client).await.contains("<hello"));
            client.write_all(b"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>").await.unwrap();
            let rpc = format!("<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"read\"><get-config><source><running/></source>{filter}</get-config></rpc>]]>]]>");
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
fn root_path() -> gnmi::Path { gnmi::Path { elem: vec![gnmi::PathElem { name: "keys:root".into(), key: Default::default() }], ..Default::default() } }
fn child_path(list: &str, keys: &[(&str, &str)], leaf: &str) -> gnmi::Path {
    let mut path = root_path();
    path.elem.push(gnmi::PathElem { name: format!("keys:{list}"), key: keys.iter().map(|(key,value)| (format!("keys:{key}"), value.to_string())).collect() });
    path.elem.push(gnmi::PathElem { name: format!("keys:{leaf}"), key: Default::default() });
    path
}
fn child_filter(list: &str, leaf: &str) -> String { format!("<filter><root xmlns=\"urn:keys\"><{list}><{leaf}/></{list}></root></filter>") }
fn data(reply: &str) -> &str {
    assert!(!reply.contains("<rpc-error>"), "{reply}");
    if reply.contains("<data/>") { "" } else { reply.split_once("<data>").unwrap().1.split_once("</data>").unwrap().0 }
}
#[allow(deprecated)]
fn updates(response: &gnmi::GetResponse) -> Vec<(gnmi::Path, Value)> {
    assert!(response.error.is_none());
    response.notification.iter().flat_map(|n| {
        assert!(n.prefix.is_none()); assert!(n.delete.is_empty());
        n.update.iter().map(|u| {
            let Some(gnmi::typed_value::Value::JsonIetfVal(bytes)) = u.val.as_ref().unwrap().value.as_ref() else { panic!("JSON_IETF value") };
            (u.path.clone().unwrap(), serde_json::from_slice(bytes).unwrap())
        })
    }).collect()
}
fn config(list: &str, rows: Value) -> Root { serde_json::from_value(json!({list: rows})).unwrap() }
fn xml_escape(text: &str) -> String { text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;") }
fn assert_safe(fixture: &Fixture, response: &gnmi::GetResponse, markers: &[&str]) {
    let diagnostic = format!("{response:?} {:?}", fixture.audit.0.lock().unwrap());
    for marker in markers { assert!(!diagnostic.contains(marker), "diagnostics contain a value"); }
}

#[tokio::test]
async fn sensitive_key_permitted_read() {
    let fixture = Fixture::new(config("sensitive-rows", json!([{ "id": MARKER, "value": "selected-value", "payload": SECRET }])), full_policy(&[])).await;
    let response = fixture.get(root_path()).await.unwrap();
    let found = updates(&response);
    assert_eq!(found, vec![
        (child_path("sensitive-rows", &[("id", MARKER)], "id"), json!(MARKER)),
        (child_path("sensitive-rows", &[("id", MARKER)], "payload"), json!("<redacted>")),
        (child_path("sensitive-rows", &[("id", MARKER)], "value"), json!("selected-value")),
    ]);
    let reply = fixture.xml("").await;
    assert_eq!(data(&reply), format!("<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>{}</keys:id><keys:payload>&lt;redacted&gt;</keys:payload><keys:value>selected-value</keys:value></keys:sensitive-rows></keys:root>", xml_escape(MARKER)));
    assert!(!reply.contains(SECRET));
    assert_safe(&fixture, &response, &[MARKER, SECRET]);
}

#[tokio::test]
async fn sensitive_key_direct_child_read() {
    for marker in [MARKER, "back\\slash/\"marker"] {
        let fixture = Fixture::new(config("sensitive-rows", json!([{ "id": marker, "value": "selected-value", "payload": SECRET }])), policy(&["/keys:root/keys:sensitive-rows/keys:id", "/keys:root/keys:sensitive-rows/keys:value"], &[])).await;
        let path = child_path("sensitive-rows", &[("id", marker)], "value");
        let response = fixture.get(path.clone()).await.unwrap();
        assert_eq!(updates(&response), vec![(path, json!("selected-value"))]);
        let reply = fixture.xml(&child_filter("sensitive-rows", "value")).await;
        assert_eq!(data(&reply), format!("<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>{}</keys:id><keys:value>selected-value</keys:value></keys:sensitive-rows></keys:root>", xml_escape(marker)));
        assert_safe(&fixture, &response, &[marker, SECRET]);
    }
}

#[tokio::test]
async fn denied_key_omits_entry() {
    let cases = [
        ("public-rows", "id", json!([{ "id": "hidden-public-key", "value": "hidden-value" }]), vec![("id", "hidden-public-key")]),
        ("sensitive-rows", "id", json!([{ "id": "hidden-sensitive-key", "value": "hidden-value" }]), vec![("id", "hidden-sensitive-key")]),
        ("composite-rows", "tenant", json!([{ "tenant": "hidden-tenant-key", "id": "hidden-composite-key", "value": "hidden-value" }]), vec![("tenant", "hidden-tenant-key"), ("id", "hidden-composite-key")]),
        ("composite-rows", "id", json!([{ "tenant": "hidden-tenant-key", "id": "hidden-composite-key", "value": "hidden-value" }]), vec![("tenant", "hidden-tenant-key"), ("id", "hidden-composite-key")]),
    ];
    for (list, denied, rows, keys) in cases {
        for variant in 0..3 {
            let mut root = config(list, if variant == 0 { json!([]) } else { rows.clone() });
            if variant == 2 {
                match list {
                    "public-rows" => root.public_rows.values_mut().next().unwrap().id = LeafPresence::Absent,
                    "sensitive-rows" => root.sensitive_rows.values_mut().next().unwrap().id = SecretLeaf::new(LeafPresence::Absent),
                    "composite-rows" if denied == "id" => root.composite_rows.values_mut().next().unwrap().id = SecretLeaf::new(LeafPresence::Absent),
                    "composite-rows" => root.composite_rows.values_mut().next().unwrap().tenant = SecretLeaf::new(LeafPresence::Absent),
                    _ => unreachable!(),
                }
            }
            let denied = format!("/keys:root/keys:{list}/keys:{denied}");
            let fixture = Fixture::new(root, full_policy(&[&denied])).await;
            let response = fixture.get(child_path(list, &keys, "value")).await.unwrap();
            assert_eq!(updates(&response), vec![]);
            assert_eq!(data(&fixture.xml(&child_filter(list, "value")).await), "");
            assert_safe(&fixture, &response, &["hidden-public-key", "hidden-sensitive-key", "hidden-tenant-key", "hidden-composite-key", "hidden-value"]);
        }
    }
}

#[tokio::test]
async fn denied_ancestor_key_omits_nested_entry() {
    for denied in ["/keys:root/keys:parents/keys:id", "/keys:root/keys:parents/keys:children/keys:id"] {
        let fixture = Fixture::new(config("parents", json!([{ "id": "hidden-parent", "children": [{ "id": "hidden-child", "value": "hidden-value" }] }])), full_policy(&[denied])).await;
        let mut path = child_path("parents", &[("id", "hidden-parent")], "children");
        path.elem.last_mut().unwrap().key.insert("keys:id".into(), "hidden-child".into());
        path.elem.push(gnmi::PathElem { name: "keys:value".into(), key: Default::default() });
        assert_eq!(updates(&fixture.get(path).await.unwrap()), vec![]);
        assert_eq!(data(&fixture.xml("<filter><root xmlns=\"urn:keys\"><parents><children><value/></children></parents></root></filter>").await), "");
    }
}

#[tokio::test]
async fn no_cleartext_key_class_is_refused() {
    for (list, key) in [("blocked-rows", "id"), ("lawful-rows", "id"), ("named-rows", "password")] {
        let fixture = Fixture::new(config(list, json!([{ key: "forbidden-key-marker", "value": "selected-value" }])), full_policy(&[])).await;
        let error = fixture.get(root_path()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert_eq!(error.message(), "gNMI internal error");
        assert!(!format!("{error:?}").contains("forbidden-key-marker"));
        let xml = fixture.xml("").await;
        assert!(!xml.contains("forbidden-key-marker"));
        assert!(data(&xml).contains(&format!("<keys:{key}>&lt;redacted&gt;</keys:{key}>")), "{xml}");
        assert!(data(&xml).contains("<keys:value>selected-value</keys:value>"));
    }
}

#[tokio::test]
async fn denied_leaf_with_allowed_keys_is_omitted() {
    let fixture = Fixture::new(config("sensitive-rows", json!([{ "id": "permitted-key", "value": "denied-value" }])), full_policy(&["/keys:root/keys:sensitive-rows/keys:value"])).await;
    assert_eq!(updates(&fixture.get(child_path("sensitive-rows", &[("id", "permitted-key")], "value")).await.unwrap()), vec![]);
    assert_eq!(data(&fixture.xml(&child_filter("sensitive-rows", "value")).await), "");
}

#[tokio::test]
async fn structural_only_selection_grants_no_child_permission() {
    let fixture = Fixture::new(config("sensitive-rows", json!([{ "id": "hidden-key", "value": "hidden-value" }])), policy(&["/keys:root", "/keys:root/keys:sensitive-rows"], &[])).await;
    assert_eq!(updates(&fixture.get(root_path()).await.unwrap()), vec![]);
    assert_eq!(data(&fixture.xml("").await), "");
}

#[tokio::test]
async fn unmatched_canonical_instance_is_omitted() {
    let fixture = Fixture::new(config("sensitive-rows", json!([{ "id": "existing-key", "value": "existing-value" }])), full_policy(&[])).await;
    assert_eq!(updates(&fixture.get(child_path("sensitive-rows", &[("id", "absent-key")], "value")).await.unwrap()), vec![]);
    let xml = fixture.xml("<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"/k:root/k:sensitive-rows[k:id='absent-key']/k:value\"/>").await;
    assert_eq!(data(&xml), "");
    let matched = fixture.xml("<filter type=\"xpath\" xmlns:k=\"urn:keys\" select=\"/k:root/k:sensitive-rows[k:id='existing-key']/k:value\"/>").await;
    assert_eq!(data(&matched), "<keys:root xmlns:keys=\"urn:keys\"><keys:sensitive-rows><keys:id>existing-key</keys:id><keys:value>existing-value</keys:value></keys:sensitive-rows></keys:root>");
}

#[tokio::test]
async fn keyed_list_ordering_is_preserved() {
    for (list, expected) in [("ordered-rows", ["z-last", "a-first"]), ("sensitive-rows", ["a-first", "z-last"])] {
        let fixture = Fixture::new(config(list, json!([{ "id": "z-last", "value": "first" }, { "id": "a-first", "value": "second" }])), full_policy(&[])).await;
        let response = fixture.get(root_path()).await.unwrap();
        let found = updates(&response);
        let mut keys = found.iter().map(|(path,_)| path.elem[1].key["keys:id"].as_str()).collect::<Vec<_>>();
        keys.dedup();
        assert_eq!(keys, expected);
        let xml = fixture.xml("").await;
        let content = data(&xml);
        let first = content.find(&format!("<keys:id>{}</keys:id>", expected[0])).unwrap();
        let second = content.find(&format!("<keys:id>{}</keys:id>", expected[1])).unwrap();
        assert!(first < second);
        if list == "ordered-rows" {
            assert_eq!(found.iter().map(|(_, value)| value.clone()).collect::<Vec<_>>(), vec![json!({"id":"z-last","value":"first"}), json!({"id":"a-first","value":"second"})]);
        }
    }
}
