use super::*;

fn selected_policy(paths: &[&str], action: NacmAction) -> NacmPolicy {
    let modules = module_registry();
    let mut policy = NacmPolicy::builder(opc_nacm::PolicyVersion::new(1));
    for path in paths {
        policy = policy.add_rule(NacmRule::allow(
            action,
            YangPathPattern::parse(path, &modules).expect("schema path"),
        ));
    }
    policy.build()
}

fn selected_get(path: &str) -> gnmi::GetRequest {
    gnmi::GetRequest {
        path: vec![crate::get::yang_path_to_proto(&YangPath::new(path).unwrap()).unwrap()],
        r#type: gnmi::get_request::DataType::Config as i32,
        encoding: gnmi::Encoding::JsonIetf as i32,
        ..Default::default()
    }
}

#[tokio::test]
async fn denied_key_omits_entry() {
    let service = authenticated_service_with_policy(selected_policy(
        &["/sys:system/sys:user/sys:role"],
        NacmAction::Read,
    ))
    .await;
    for path in [
        "/sys:system",
        "/sys:system/sys:user[sys:name='admin']/sys:role",
        "/sys:system/sys:user[sys:name='absent-hidden-marker']/sys:role",
    ] {
        let response = service
            .get(authenticated_get_request(selected_get(path)))
            .await
            .expect("denied keys omit entries without an error")
            .into_inner();
        assert_eq!(response.notification, Vec::new());
        assert_eq!(response.error, None);
    }
}

struct AlternatingPolicy {
    calls: AtomicUsize,
}

impl PolicySource for AlternatingPolicy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        let path = if self.calls.fetch_add(1, Ordering::SeqCst) % 2 == 0 {
            "/sys:system/sys:user/sys:role"
        } else {
            "/sys:system/sys:user/sys:name"
        };
        Ok(Arc::new(selected_policy(&[path], NacmAction::Read)))
    }
}

#[tokio::test]
async fn key_dependencies_share_one_policy_snapshot() {
    let policy = Arc::new(AlternatingPolicy {
        calls: AtomicUsize::new(0),
    });
    let service = authenticated_service_with_policy_source_operational_audit(
        policy.clone(),
        Arc::new(TestOperationalState),
        Arc::new(CapturingAudit::default()),
    )
    .await;
    for call in 1..=4 {
        let response = service
            .get(authenticated_get_request(selected_get(
                "/sys:system/sys:user[sys:name='admin']/sys:role",
            )))
            .await
            .expect("read")
            .into_inner();
        assert_eq!(policy.calls.load(Ordering::SeqCst), call);
        assert_eq!(response.notification, Vec::new());
    }
}

#[test]
fn sensitive_key_outputs_are_value_free() {
    let marker = "diagnostic-sensitive-key-marker";
    let path = YangPath::new(format!(
        "/sys:system/sys:user[sys:name='{marker}']/sys:role"
    ))
    .unwrap();
    let selection = crate::ReadSelectionEntry::new("/sys:system/sys:user/sys:role", path.clone());
    let update = GnmiJsonUpdate::new(path.clone(), format!("\"{marker}\"")).unwrap();
    let value = OperationalValue::new(path.clone(), format!("\"{marker}\"")).unwrap();
    for diagnostic in [
        format!("{selection:?}"),
        format!("{update:?}"),
        format!("{value:?}"),
        format!("{:?}", OperationalEvent::Delete { path }),
    ] {
        assert!(
            !diagnostic.contains(marker),
            "path-bearing diagnostics must omit values"
        );
    }
}

#[test]
fn protocol_diagnostics_do_not_expose_keys_or_values() {
    let marker = "permitted-protocol-key-marker";
    let canonical = YangPath::new(format!(
        "/sys:system/sys:user[sys:name='{marker}']/sys:role"
    ))
    .unwrap();
    let path = crate::get::yang_path_to_proto(&canonical).unwrap();
    let value = gnmi::TypedValue {
        value: Some(gnmi::typed_value::Value::StringVal(marker.to_string())),
    };
    let update = gnmi::Update {
        path: Some(path.clone()),
        val: Some(value.clone()),
        ..Default::default()
    };
    let response = gnmi::GetResponse {
        notification: vec![gnmi::Notification {
            prefix: Some(path.clone()),
            update: vec![update.clone()],
            delete: vec![path.clone()],
            ..Default::default()
        }],
        ..Default::default()
    };
    for diagnostic in [
        format!("{path:?}"),
        format!("{:?}", path.elem[1]),
        format!("{value:?}"),
        format!("{:?}", value.value),
        format!("{update:?}"),
        format!("{response:?}"),
    ] {
        assert!(
            !diagnostic.contains(marker),
            "protocol Debug must not reveal identifiers or values"
        );
    }
    assert_eq!(path.elem[1].key["sys:name"], marker);
    assert_eq!(
        value.value,
        Some(gnmi::typed_value::Value::StringVal(marker.to_string()))
    );
    let error = GnmiJsonUpdate::new(canonical, "invalid-json-marker").unwrap_err();
    assert_eq!(error.detail(), "invalid gNMI projection JSON");
    assert!(!format!("{error:?}").contains(marker));
}

struct XmlKeyBinding {
    bus: Arc<ConfigBus<DemoConfig>>,
    traversals: Arc<AtomicUsize>,
}

impl opc_netconf_server::NetconfConfigBinding<DemoConfig> for XmlKeyBinding {
    fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        self.bus.clone()
    }
    fn schema_registry(&self) -> &'static dyn SchemaRegistry {
        &TestRegistry
    }
    fn nmda_get_data_supported(&self) -> bool {
        true
    }
    fn render_get_data(
        &self,
        config: &DemoConfig,
        selection: opc_netconf_server::ReadSelection<'_>,
        _: &OperationalResponse,
        _: opc_netconf_server::ReadSelection<'_>,
    ) -> Result<String, opc_netconf_server::binding::BindingError> {
        self.render_running_config(config, selection)
    }
    fn render_running_config(
        &self,
        config: &DemoConfig,
        selection: opc_netconf_server::ReadSelection<'_>,
    ) -> Result<String, opc_netconf_server::binding::BindingError> {
        if !selection.contains("/sys:system/sys:user/sys:role")
            && !selection.contains("/sys:system/sys:user/sys:name")
        {
            return Ok(String::new());
        }
        self.traversals.fetch_add(1, Ordering::SeqCst);
        if !selection.contains("/sys:system/sys:user/sys:name") && !config.users.is_empty() {
            return Err(opc_netconf_server::binding::BindingError::projection(
                "missing selected key",
            ));
        }
        let mut xml = String::new();
        for (name, user) in &config.users {
            let role = if selection.contains("/sys:system/sys:user/sys:role") {
                format!("<sys:role>{}</sys:role>", user.role)
            } else {
                String::new()
            };
            xml.push_str(&format!(
                "<sys:user xmlns:sys=\"urn:demo\"><sys:name>{name}</sys:name>{role}</sys:user>"
            ));
        }
        Ok(xml)
    }
}

async fn xml_key_read(
    policy: Arc<dyn PolicySource>,
    populated: bool,
    operation: &str,
) -> (String, usize) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut config = initial_config();
    if !populated {
        config.users.clear();
    }
    let traversals = Arc::new(AtomicUsize::new(0));
    let server = opc_netconf_server::ReadOnlyNetconfServer::new(
        XmlKeyBinding {
            bus: Arc::new(
                ConfigBus::new_dev_only(config, MockManagedDatastore::new())
                    .await
                    .unwrap(),
            ),
            traversals: traversals.clone(),
        },
        policy,
        CapturingAudit::default(),
        opc_config_model::TransportType::NetconfTls,
    )
    .unwrap();
    let sessions = opc_netconf_server::SessionRegistry::new();
    let principal = authenticated_principal();
    let (mut client, mut transport) = tokio::io::duplex(65536);
    async fn frame(client: &mut tokio::io::DuplexStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"]]>]]>") {
            bytes.push(client.read_u8().await.unwrap());
        }
        String::from_utf8(bytes[..bytes.len() - 6].to_vec()).unwrap()
    }
    let serving = opc_netconf_server::run_read_only_session_with_registry(
        &server,
        principal.principal(),
        &mut transport,
        opc_netconf_server::SessionConfig::default(),
        1,
        &sessions,
    );
    let exchange = async {
        assert!(frame(&mut client).await.contains("<hello"));
        client.write_all(b"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>").await.unwrap();
        let request = format!("<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"key\">{operation}</rpc>]]>]]>");
        client.write_all(request.as_bytes()).await.unwrap();
        let response = frame(&mut client).await;
        client.shutdown().await.unwrap();
        response
    };
    let (reply, result) = tokio::join!(exchange, serving);
    result.unwrap();
    (reply, traversals.load(Ordering::SeqCst))
}

fn xml_key_operations() -> Vec<String> {
    let content =
        "<sys:system xmlns:sys=\"urn:demo\"><sys:user><sys:role/></sys:user></sys:system>";
    vec![
        format!("<get-config><source><running/></source><filter>{content}</filter></get-config>"),
        format!("<get><filter>{content}</filter></get>"),
        format!("<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\"><datastore>ds:running</datastore><subtree-filter>{content}</subtree-filter></get-data>"),
        format!("<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\"><datastore>ds:operational</datastore><subtree-filter>{content}</subtree-filter></get-data>"),
    ]
}

#[tokio::test]
async fn netconf_denied_key_omits_entry_before_rows() {
    for operation in xml_key_operations() {
        for populated in [false, true] {
            let (reply, traversals) = xml_key_read(
                Arc::new(FixedPolicy(selected_policy(
                    &["/sys:system/sys:user/sys:role"],
                    NacmAction::Read,
                ))),
                populated,
                &operation,
            )
            .await;
            assert!(
                !reply.contains("<rpc-error>"),
                "operation {operation}: {reply}"
            );
            assert!(
                !reply.contains("<sys:user"),
                "operation {operation}: {reply}"
            );
            assert_eq!(traversals, 0, "denied branch must not traverse stored rows");
        }
    }
}

#[tokio::test]
async fn netconf_direct_child_includes_authorized_unrequested_key() {
    for operation in xml_key_operations() {
        let (reply, traversals) = xml_key_read(
            Arc::new(FixedPolicy(selected_policy(
                &[
                    "/sys:system/sys:user/sys:role",
                    "/sys:system/sys:user/sys:name",
                ],
                NacmAction::Read,
            ))),
            true,
            &operation,
        )
        .await;
        assert!(
            !reply.contains("<rpc-error>"),
            "operation {operation}: {reply}"
        );
        assert!(
            reply.contains("<sys:name>admin</sys:name><sys:role>superuser</sys:role>"),
            "operation {operation}: {reply}"
        );
        assert!(
            reply.contains("<sys:name>guest</sys:name><sys:role>readonly</sys:role>"),
            "operation {operation}: {reply}"
        );
        assert_eq!(traversals, 1);
    }
}

#[tokio::test]
async fn netconf_key_dependencies_share_one_policy_snapshot() {
    for operation in xml_key_operations() {
        let policy = Arc::new(AlternatingPolicy {
            calls: AtomicUsize::new(0),
        });
        let (reply, traversals) = xml_key_read(policy.clone(), true, &operation).await;
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
        assert!(
            !reply.contains("<rpc-error>"),
            "operation {operation}: {reply}"
        );
        assert!(
            !reply.contains("<sys:user"),
            "operation {operation}: {reply}"
        );
        assert_eq!(traversals, 0);
    }
}

struct UnregisteredPolicy;
impl PolicySource for UnregisteredPolicy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        Ok(Arc::new(allow_all_subscribe_policy()))
    }
}

#[tokio::test]
async fn authorization_notification_registration_failure_refuses_subscription() {
    let service = authenticated_service_with_policy_source_operational_audit(
        Arc::new(UnregisteredPolicy),
        Arc::new(TestOperationalState),
        Arc::new(CapturingAudit::default()),
    )
    .await;
    let mut stream = service
        .subscribe(authenticated_subscribe_request(subscribe_request(
            subscribe_list(
                gnmi::subscription_list::Mode::Once,
                hostname_path(),
                gnmi::SubscriptionMode::Sample,
            ),
        )))
        .await
        .unwrap()
        .into_inner();
    let error = stream
        .next()
        .await
        .unwrap()
        .expect_err("unregistered policy source must refuse before output");
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "gNMI service unavailable");
}

#[tokio::test]
async fn hidden_operational_event_skips_validation_limits_and_audit() {
    let service = authenticated_service_with_policy_bus_events_audit(
        Arc::new(FixedPolicy(allow_all_read_policy())),
        Arc::new(
            ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                .await
                .unwrap(),
        ),
        Some(Arc::new(TestOperationalEvents::default())),
        MgmtLimits::default(),
        Arc::new(FailingAudit),
        Arc::new(TestOperationalState),
    )
    .await;
    let plan = SubscribePlan::from_subscription_list(
        service.server(),
        subscribe_list(
            gnmi::subscription_list::Mode::Stream,
            uptime_path(),
            gnmi::SubscriptionMode::OnChange,
        ),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    for event in [
        OperationalEvent::Update(
            OperationalValue::new(
                YangPath::new("/sys:system/sys:uptime").unwrap(),
                serde_json::to_string(&"denied-event-marker".repeat(100000)).unwrap(),
            )
            .unwrap(),
        ),
        OperationalEvent::Delete {
            path: YangPath::new("/sys:system/sys:hostname").unwrap(),
        },
    ] {
        assert!(send_operational_event(
            service.server(),
            RequestId::new(),
            authenticated_principal().principal(),
            &plan,
            event,
            &tx
        )
        .await
        .expect("hidden event must be silently dropped before validation and audit"));
        assert!(rx.try_recv().is_err());
    }
}

struct StateKeyRegistry;
impl SchemaRegistry for StateKeyRegistry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:state-key"
    }
    fn served_models(&self) -> &'static [ModelData] {
        MODELS
    }
    fn origins(&self) -> &'static [OriginEntry] {
        ORIGINS
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        static STATE: std::sync::OnceLock<Vec<NodeMeta>> = std::sync::OnceLock::new();
        STATE.get_or_init(|| {
            NODES
                .iter()
                .map(|node| {
                    let mut node = *node;
                    node.config = false;
                    if node.path == "/sys:system/sys:user/sys:name" {
                        node.data_class = DataClass::SubscriberId;
                    }
                    node
                })
                .collect()
        })
    }
}

struct StateKeyBinding(TestBinding);
impl GnmiConfigBinding<DemoConfig> for StateKeyBinding {
    fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        self.0.bus.clone()
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        &StateKeyRegistry
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<DemoConfig>> {
        self.0.patcher.clone()
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        self.0.operational.clone()
    }
    fn operational_events(&self) -> Option<Arc<dyn OperationalEventSource>> {
        self.0.events.clone()
    }
    fn policy_source(&self) -> Arc<dyn PolicySource> {
        self.0.policy.clone()
    }
}

#[derive(Default)]
struct KeyOperational {
    requests: Mutex<Vec<OperationalRequest>>,
}
impl OperationalStateProvider for KeyOperational {
    fn get(&self, request: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(OperationalResponse::new(request.paths().iter().map(
            |path| OperationalValue::new(path.clone(), "\"visible-role-marker\"").unwrap(),
        )))
    }
}

struct ControlledEvents {
    receiver: Mutex<Option<OperationalEventReceiver>>,
    requests: Mutex<Vec<OperationalSubscriptionRequest>>,
}
impl OperationalEventSource for ControlledEvents {
    fn subscribe(
        &self,
        request: &OperationalSubscriptionRequest,
    ) -> Result<OperationalEventReceiver, OperationalError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(self.receiver.lock().unwrap().take().unwrap())
    }
}

async fn state_key_service(
    policy: Arc<dyn PolicySource>,
    operational: Arc<dyn OperationalStateProvider>,
    events: Arc<dyn OperationalEventSource>,
    audit: Arc<dyn AuditSink>,
) -> GnmiService<DemoConfig, StateKeyBinding> {
    let server = GnmiServer::new(
        StateKeyBinding(TestBinding {
            bus: Arc::new(
                ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
                    .await
                    .unwrap(),
            ),
            policy,
            operational,
            events: Some(events),
            patcher: unit_patcher(),
        }),
        MgmtLimits::default(),
        CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
        ExtensionRegistry::default(),
        audit,
    )
    .unwrap();
    GnmiService::new_authenticated(server)
}

fn group_key_policy() -> NacmPolicy {
    let modules = module_registry();
    NacmPolicy::builder(opc_nacm::PolicyVersion::new(1))
        .add_rule(NacmRule::allow(
            NacmAction::Subscribe,
            YangPathPattern::parse("/sys:system/sys:user/sys:role", &modules).unwrap(),
        ))
        .add_rule_list(
            opc_nacm::NacmRuleList::new(
                "key-readers",
                ["key-reader"],
                vec![NacmRule::allow(
                    NacmAction::Subscribe,
                    YangPathPattern::parse("/sys:system/sys:user/sys:name", &modules).unwrap(),
                )],
            )
            .unwrap(),
        )
        .build()
}

struct ChangingContext {
    hub: opc_mgmt_authz::AuthorizationChangeHub,
    policy: Mutex<NacmPolicy>,
    resolved_group: AtomicBool,
    invalid: AtomicBool,
    calls: AtomicUsize,
    registrations: AtomicUsize,
    evaluated: tokio::sync::Notify,
}
impl ChangingContext {
    fn new() -> Self {
        Self {
            hub: Default::default(),
            policy: Mutex::new(group_key_policy()),
            resolved_group: AtomicBool::new(true),
            invalid: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            registrations: AtomicUsize::new(0),
            evaluated: Default::default(),
        }
    }
    async fn wait_calls(&self, count: usize) {
        loop {
            let notified = self.evaluated.notified();
            if self.calls.load(Ordering::SeqCst) >= count {
                break;
            }
            notified.await;
        }
    }
}
impl PolicySource for ChangingContext {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        Ok(Arc::new(self.policy.lock().unwrap().clone()))
    }
    fn active_policy_context_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<opc_mgmt_authz::ResolvedPolicy, AuthzError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.evaluated.notify_one();
        if self.invalid.load(Ordering::SeqCst) {
            return Err(AuthzError::PolicyUnavailable);
        }
        let mut principal = principal.clone();
        if self.resolved_group.load(Ordering::SeqCst) {
            principal = principal.with_groups(["key-reader"]);
        }
        Ok(opc_mgmt_authz::ResolvedPolicy::new(
            self.active_policy("")?,
            principal,
        ))
    }
    fn watch_authorization(
        &self,
        principal: &TrustedPrincipal,
        gate: opc_mgmt_authz::AuthorizationGate,
    ) -> Result<opc_mgmt_authz::AuthorizationWatch, AuthzError> {
        self.registrations.fetch_add(1, Ordering::SeqCst);
        self.hub
            .register(gate, || self.active_policy_context_for_principal(principal))
    }
}

fn open_subscribe_request(
    list: gnmi::SubscriptionList,
) -> Request<tonic::Streaming<gnmi::SubscribeRequest>> {
    use http_body_util::BodyExt;
    let request = subscribe_request(list);
    let payload = request.encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let body =
        http_body_util::Full::new(bytes::Bytes::from(frame)).with_trailers(std::future::pending::<
            Option<Result<tonic::codegen::http::HeaderMap, std::convert::Infallible>>,
        >());
    let mut codec =
        tonic_prost::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
    let stream =
        tonic::Streaming::new_request(codec.decoder(), tonic::body::Body::new(body), None, None);
    let mut request = Request::new(stream);
    request.extensions_mut().insert(authenticated_principal());
    request
}

#[tokio::test]
async fn idle_on_change_revocation_terminates_on_context_change() {
    for resolved_group_change in [false, true] {
        for hidden_events in [0, 1] {
            let policy = Arc::new(ChangingContext::new());
            let (sender, receiver) = operational_event_channel(8);
            let events = Arc::new(ControlledEvents {
                receiver: Mutex::new(Some(receiver)),
                requests: Default::default(),
            });
            let service = state_key_service(
                policy.clone(),
                Arc::new(KeyOperational::default()),
                events,
                Arc::new(CapturingAudit::default()),
            )
            .await;
            let mut list = subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                crate::get::yang_path_to_proto(&user_role_yang_path("permitted-key-marker"))
                    .unwrap(),
                gnmi::SubscriptionMode::OnChange,
            );
            list.subscription[0].sample_interval = 0;
            let mut stream = service
                .subscribe(open_subscribe_request(list))
                .await
                .unwrap()
                .into_inner();
            let initial = stream.next().await.unwrap().unwrap();
            let gnmi::subscribe_response::Response::Update(initial) = initial.response.unwrap()
            else {
                panic!("initial update")
            };
            assert_eq!(initial.update.len(), 1);
            assert_eq!(
                initial.update[0].path.as_ref().unwrap().elem[1].key["sys:name"],
                "permitted-key-marker"
            );
            assert_eq!(
                stream.next().await.unwrap().unwrap().response,
                Some(gnmi::subscribe_response::Response::SyncResponse(true))
            );
            assert_eq!(
                policy.registrations.load(Ordering::SeqCst),
                1,
                "register before initial snapshot"
            );
            assert_eq!(
                policy.calls.load(Ordering::SeqCst),
                1,
                "one initial context for the full dependency batch"
            );
            let pending = policy
                .hub
                .prepare_change(|| {
                    if resolved_group_change {
                        policy.resolved_group.store(false, Ordering::SeqCst);
                    } else {
                        *policy.policy.lock().unwrap() = selected_policy(
                            &["/sys:system/sys:user/sys:role"],
                            NacmAction::Subscribe,
                        );
                    }
                })
                .await
                .unwrap();
            for _ in 0..hidden_events {
                sender
                    .send(OperationalEvent::Delete {
                        path: user_role_yang_path("hidden-other-key-marker"),
                    })
                    .await
                    .unwrap();
            }
            policy.wait_calls(1 + hidden_events).await;
            let pending_without_trigger = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(stream.as_mut().poll_next(cx).is_pending())
            })
            .await;
            assert!(
                pending_without_trigger,
                "hidden events cannot terminate while the control notification is held"
            );
            assert_eq!(pending.complete().await.unwrap(), 1);
            assert_eq!(
                policy.calls.load(Ordering::SeqCst),
                2 + hidden_events,
                "one context for control-triggered reevaluation"
            );
            let terminal =
                std::future::poll_fn(|cx| std::task::Poll::Ready(stream.as_mut().poll_next(cx)))
                    .await;
            let std::task::Poll::Ready(Some(Err(error))) = terminal else {
                panic!("termination must be ready at acknowledgement")
            };
            assert_eq!(error.code(), Code::Unavailable);
            assert_eq!(error.message(), "gNMI service unavailable");
            assert!(stream.next().await.is_none());
        }
    }
}

#[tokio::test]
async fn netconf_denied_leaf_with_allowed_keys_is_omitted() {
    for operation in xml_key_operations() {
        let (reply, traversals) = xml_key_read(
            Arc::new(FixedPolicy(selected_policy(
                &[
                    "/sys:system",
                    "/sys:system/sys:user",
                    "/sys:system/sys:user/sys:name",
                ],
                NacmAction::Read,
            ))),
            true,
            &operation,
        )
        .await;
        assert!(!reply.contains("<rpc-error>"), "{reply}");
        assert!(!reply.contains("<sys:user"), "{reply}");
        assert_eq!(traversals, 0);
    }
}
