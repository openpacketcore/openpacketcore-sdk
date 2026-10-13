use super::*;

use std::time::Duration;

use http_body_util::BodyExt;
use opc_mgmt_authz::{AuthorizationChangeHub, AuthorizationGate, AuthorizationWatch};
use opc_mgmt_opstate::{
    operational_event_channel, OperationalEvent, OperationalEventReceiver, OperationalEventSender,
    OperationalEventSource, OperationalSubscriptionRequest,
};
use prost::Message;
use tonic::codec::Codec;
use tonic::codegen::tokio_stream::StreamExt;

struct SubscriptionPolicy {
    current: Mutex<Arc<NacmPolicy>>,
    calls: AtomicUsize,
    changes: AuthorizationChangeHub,
    resolved_group: AtomicBool,
    invalid: AtomicBool,
    evaluated: tokio::sync::Notify,
}

impl PolicySource for SubscriptionPolicy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.current.lock().unwrap().clone())
    }

    fn active_policy_context_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<opc_mgmt_authz::ResolvedPolicy, AuthzError> {
        let policy = self.active_policy("")?;
        self.evaluated.notify_one();
        if self.invalid.load(Ordering::SeqCst) {
            return Err(AuthzError::PolicyUnavailable);
        }
        let principal = if self.resolved_group.load(Ordering::SeqCst) {
            principal.clone().with_groups(["key-readers"])
        } else {
            principal.clone()
        };
        Ok(opc_mgmt_authz::ResolvedPolicy::new(policy, principal))
    }

    fn watch_authorization(
        &self,
        principal: &TrustedPrincipal,
        gate: AuthorizationGate,
    ) -> Result<AuthorizationWatch, AuthzError> {
        self.changes
            .register(gate, || self.active_policy_context_for_principal(principal))
    }
}

struct Events {
    receiver: Mutex<Option<OperationalEventReceiver>>,
    requests: Mutex<Vec<OperationalSubscriptionRequest>>,
}

impl OperationalEventSource for Events {
    fn subscribe(
        &self,
        request: &OperationalSubscriptionRequest,
    ) -> Result<OperationalEventReceiver, OperationalError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(self.receiver.lock().unwrap().take().unwrap())
    }
}

#[derive(Clone)]
struct SubscriptionBinding {
    inner: Binding,
    policy: Arc<SubscriptionPolicy>,
    events: Arc<Events>,
    rendered: Arc<tokio::sync::Notify>,
    state_override: Option<Arc<dyn OperationalStateProvider>>,
    events_override: Option<Arc<dyn OperationalEventSource>>,
}

impl GnmiPatchApplicator<()> for SubscriptionBinding {
    fn apply_set(&self, _: &(), _: &NormalizedSet) -> Result<(), GnmiError> {
        Ok(())
    }
}

impl GnmiConfigBinding<()> for SubscriptionBinding {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        self.inner.config_bus()
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        self.inner.schema()
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<()>> {
        Arc::new(self.clone())
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        self.state_override
            .clone()
            .unwrap_or_else(|| self.inner.provider.clone())
    }
    fn operational_events(&self) -> Option<Arc<dyn OperationalEventSource>> {
        Some(
            self.events_override
                .clone()
                .unwrap_or_else(|| self.events.clone()),
        )
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
        config: &(),
        config_selection: ReadSelection<'_>,
        values: &OperationalResponse,
        state_selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        let result = self
            .inner
            .render_get_json(config, config_selection, values, state_selection);
        self.rendered.notify_one();
        result
    }
}

async fn subscription_fixture(
    values: Vec<OperationalValue>,
    permissions: NacmPolicy,
    limits: MgmtLimits,
) -> (
    GnmiService<(), SubscriptionBinding>,
    SubscriptionBinding,
    OperationalEventSender,
) {
    subscription_fixture_with_registry(values, permissions, limits, &Registry).await
}

async fn subscription_fixture_with_registry(
    values: Vec<OperationalValue>,
    permissions: NacmPolicy,
    limits: MgmtLimits,
    registry: &'static dyn SchemaRegistry,
) -> (
    GnmiService<(), SubscriptionBinding>,
    SubscriptionBinding,
    OperationalEventSender,
) {
    let (_, inner, audit) =
        fixture_with_registry(values, vec![permissions.clone()], limits, registry).await;
    let (sender, receiver) = operational_event_channel(8);
    let binding = SubscriptionBinding {
        inner,
        policy: Arc::new(SubscriptionPolicy {
            current: Mutex::new(Arc::new(permissions)),
            calls: AtomicUsize::new(0),
            changes: AuthorizationChangeHub::default(),
            resolved_group: AtomicBool::new(true),
            invalid: AtomicBool::new(false),
            evaluated: tokio::sync::Notify::new(),
        }),
        events: Arc::new(Events {
            receiver: Mutex::new(Some(receiver)),
            requests: Mutex::new(Vec::new()),
        }),
        rendered: Arc::new(tokio::sync::Notify::new()),
        state_override: None,
        events_override: None,
    };
    let service = GnmiService::new(
        GnmiServer::new_with_audit(
            binding.clone(),
            limits,
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
            ExtensionRegistry::default(),
            audit,
        )
        .unwrap(),
    );
    binding.inner.config_reads.store(0, Ordering::SeqCst);
    (service, binding, sender)
}

fn subscription(path: gnmi::Path) -> gnmi::SubscriptionList {
    gnmi::SubscriptionList {
        subscription: vec![gnmi::Subscription {
            path: Some(path),
            mode: gnmi::SubscriptionMode::OnChange as i32,
            ..Default::default()
        }],
        mode: gnmi::subscription_list::Mode::Stream as i32,
        encoding: gnmi::Encoding::JsonIetf as i32,
        updates_only: true,
        ..Default::default()
    }
}

fn open_requests(
    list: gnmi::SubscriptionList,
    poll: bool,
) -> Request<tonic::Streaming<gnmi::SubscribeRequest>> {
    let mut requests = vec![gnmi::SubscribeRequest {
        request: Some(gnmi::subscribe_request::Request::Subscribe(list)),
        extension: Vec::new(),
    }];
    if poll {
        requests.push(gnmi::SubscribeRequest {
            request: Some(gnmi::subscribe_request::Request::Poll(gnmi::Poll {})),
            extension: Vec::new(),
        });
    }
    let mut frame = Vec::new();
    for request in requests {
        let payload = request.encode_to_vec();
        frame.push(0);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
    }
    let body =
        http_body_util::Full::new(bytes::Bytes::from(frame)).with_trailers(std::future::pending::<
            Option<Result<tonic::codegen::http::HeaderMap, std::convert::Infallible>>,
        >());
    let mut codec =
        tonic_prost::ProstCodec::<gnmi::SubscribeResponse, gnmi::SubscribeRequest>::default();
    let stream =
        tonic::Streaming::new_request(codec.decoder(), tonic::body::Body::new(body), None, None);
    let mut request = Request::new(stream);
    request.extensions_mut().insert(
        get(Vec::new(), None)
            .extensions()
            .get::<AuthenticatedGnmiPrincipal>()
            .unwrap()
            .clone(),
    );
    request
}

fn sync(response: gnmi::SubscribeResponse) {
    assert_eq!(
        response.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
}

fn notification(response: gnmi::SubscribeResponse) -> gnmi::Notification {
    let Some(gnmi::subscribe_response::Response::Update(notification)) = response.response else {
        panic!("data notification expected")
    };
    notification
}

#[tokio::test]
async fn keyed_on_change_masks_operational_payloads() {
    let (service, _, sender) = subscription_fixture(
        Vec::new(),
        policy(&["/ex:system/**"]),
        MgmtLimits::default(),
    )
    .await;
    let mut stream = service
        .subscribe(open_requests(
            subscription(selection(&[], "payload")),
            false,
        ))
        .await
        .unwrap()
        .into_inner();
    sync(stream.next().await.unwrap().unwrap());
    sender
        .send(OperationalEvent::Update(peer(
            "a",
            "payload",
            "\"payload-marker\"",
        )))
        .await
        .unwrap();
    let update = notification(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    );
    assert_eq!(update.update.len(), 1);
    assert_eq!(
        update.update[0].path.as_ref().unwrap().elem[1].key["ex:name"],
        "a"
    );
    assert_eq!(
        update.update[0].val.as_ref().unwrap().value,
        Some(gnmi::typed_value::Value::JsonIetfVal(
            b"\"<redacted>\"".to_vec()
        ))
    );
}

#[tokio::test]
async fn keyed_on_change_requires_complete_canonical_instances() {
    for path in [
        "/ex:system/ex:peer[ex:name='a']/ex:up",
        "/ex:system/ex:peer[ex:name='a'][ex:site='east']/ex:up",
        "/ex:system/ex:peer[ex:site='east'][ex:name='a'][ex:extra='x']/ex:up",
    ] {
        for delete in [false, true] {
            let (service, _, sender) = subscription_fixture(
                Vec::new(),
                policy(&["/ex:system/**"]),
                MgmtLimits::default(),
            )
            .await;
            let mut stream = service
                .subscribe(open_requests(subscription(selection(&[], "up")), false))
                .await
                .unwrap()
                .into_inner();
            sync(stream.next().await.unwrap().unwrap());
            let event = if delete {
                OperationalEvent::Delete {
                    path: YangPath::new(path).unwrap(),
                }
            } else {
                OperationalEvent::Update(value(path, "true"))
            };
            sender.send(event).await.unwrap();
            let error = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(error.code(), Code::Internal);
            assert_eq!(error.message(), "gNMI internal error");
        }
    }
}

#[tokio::test]
async fn keyed_on_change_bounds_paths_before_instance_parsing() {
    for delete in [false, true] {
        let (service, _, sender) = subscription_fixture(
            Vec::new(),
            policy(&["/ex:system/**"]),
            MgmtLimits {
                max_value_bytes: 128,
                ..MgmtLimits::default()
            },
        )
        .await;
        let mut stream = service
            .subscribe(open_requests(subscription(selection(&[], "up")), false))
            .await
            .unwrap()
            .into_inner();
        sync(stream.next().await.unwrap().unwrap());
        // This also lacks a composite key. The byte budget must decide first.
        let path = format!(
            "/ex:system/ex:peer[ex:name='{}']/ex:up",
            "path-marker".repeat(40)
        );
        let event = if delete {
            OperationalEvent::Delete {
                path: YangPath::new(path).unwrap(),
            }
        } else {
            OperationalEvent::Update(value(&path, "true"))
        };
        sender.send(event).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.message(), "invalid gNMI request");
    }
}

#[tokio::test]
async fn keyed_subscription_snapshots_preserve_partial_and_wildcard_selection() {
    for mode in [
        gnmi::subscription_list::Mode::Once,
        gnmi::subscription_list::Mode::Poll,
        gnmi::subscription_list::Mode::Stream,
    ] {
        for keys in [
            vec![],
            vec![("site", "east")],
            vec![("site", "*"), ("name", "*")],
        ] {
            let (service, binding, _sender) = subscription_fixture(
                vec![peer("b", "up", "false"), peer("a", "up", "true")],
                policy(&["/ex:system/**"]),
                MgmtLimits::default(),
            )
            .await;
            let mut list = subscription(selection(&keys, "up"));
            list.mode = mode as i32;
            list.updates_only = false;
            let mut stream = service
                .subscribe(open_requests(
                    list,
                    mode == gnmi::subscription_list::Mode::Poll,
                ))
                .await
                .unwrap()
                .into_inner();
            if mode == gnmi::subscription_list::Mode::Poll {
                sync(stream.next().await.unwrap().unwrap());
            }
            let data = notification(stream.next().await.unwrap().unwrap());
            assert_eq!(data.update.len(), 2);
            assert_eq!(
                data.update[0].path.as_ref().unwrap().elem[1].key["ex:name"],
                "a"
            );
            assert_eq!(
                data.update[1].path.as_ref().unwrap().elem[1].key["ex:name"],
                "b"
            );
            assert_eq!(
                data.update[0].val.as_ref().unwrap().value,
                Some(gnmi::typed_value::Value::JsonIetfVal(b"true".to_vec()))
            );
            assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 1);
            sync(stream.next().await.unwrap().unwrap());
        }
    }
}

#[tokio::test]
async fn expanded_idle_on_change_revocation_terminates_at_acknowledgement() {
    let (service, binding, _sender) = subscription_fixture(
        vec![peer("a", "up", "true")],
        policy(&["/ex:system/**"]),
        MgmtLimits::default(),
    )
    .await;
    let mut list = subscription(selection(&[("site", "east")], "up"));
    list.updates_only = false;
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        notification(stream.next().await.unwrap().unwrap())
            .update
            .len(),
        1
    );
    sync(stream.next().await.unwrap().unwrap());
    let revoked = Arc::new(policy(&[
        "/ex:system/ex:peer/ex:up",
        "/ex:system/ex:peer/ex:site",
    ]));
    tokio::time::timeout(
        Duration::from_secs(5),
        binding.policy.changes.activate(|| {
            *binding.policy.current.lock().unwrap() = revoked;
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let status = stream.next().await.unwrap().unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), "gNMI service unavailable");
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn masked_subscription_key_is_refused_before_policy_or_data_access() {
    for prefix in [false, true] {
        let (service, binding, _sender) = subscription_fixture(
            Vec::new(),
            policy(&["/ex:system/**"]),
            MgmtLimits::default(),
        )
        .await;
        let mut path = selection(&[("id", "request-marker")], "up");
        path.elem[1].name = "sealed".into();
        let mut list = subscription(path.clone());
        if prefix {
            list.prefix = Some(path);
            list.subscription[0].path = Some(gnmi::Path::default());
        }
        let mut stream = service
            .subscribe(open_requests(list, false))
            .await
            .unwrap()
            .into_inner();
        let status = stream.next().await.unwrap().unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 0);
        assert!(binding.inner.provider.requests.lock().unwrap().is_empty());
        assert!(binding.events.requests.lock().unwrap().is_empty());
        assert_eq!(binding.inner.config_reads.load(Ordering::SeqCst), 0);
        assert!(!format!("{status:?}").contains("request-marker"));
    }
}

#[tokio::test]
async fn masked_composite_and_ancestor_matches_refuse_all_classes_and_subscribe_locations() {
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
                            let (service, binding, _sender) = subscription_fixture_with_registry(
                                values,
                                policy(if allowed { &["/ex:system/**"] } else { &[] }),
                                MgmtLimits::default(),
                                registry,
                            )
                            .await;
                            let path = masked_selection(secret_name, nested, guess);
                            let mut list = subscription(path.clone());
                            if prefix {
                                list.prefix = Some(path);
                                list.subscription[0].path = Some(gnmi::Path::default());
                            }
                            let mut stream = service
                                .subscribe(open_requests(list, false))
                                .await
                                .unwrap()
                                .into_inner();
                            let error = stream.next().await.unwrap().unwrap_err();
                            assert_eq!(error.code(), Code::InvalidArgument);
                            assert_eq!(error.message(), "invalid gNMI request");
                            assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 0);
                            assert_eq!(binding.inner.config_reads.load(Ordering::SeqCst), 0);
                            assert!(binding.inner.provider.requests.lock().unwrap().is_empty());
                            assert!(binding.events.requests.lock().unwrap().is_empty());
                            assert_eq!(binding.inner.renders.load(Ordering::SeqCst), 0);
                            assert!(!format!("{error:?}").contains("marker"));
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn keyed_on_change_literal_paths_preserve_trailing_backslashes() {
    let (service, _, sender) = subscription_fixture(
        Vec::new(),
        policy(&["/ex:system/**"]),
        MgmtLimits::default(),
    )
    .await;
    let mut stream = service
        .subscribe(open_requests(subscription(selection(&[], "up")), false))
        .await
        .unwrap()
        .into_inner();
    sync(stream.next().await.unwrap().unwrap());
    sender
        .send(OperationalEvent::Update(peer("literal\\", "up", "true")))
        .await
        .unwrap();
    sender
        .send(OperationalEvent::Update(peer("barrier", "up", "false")))
        .await
        .unwrap();
    let data = notification(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        data.update[0].path.as_ref().unwrap().elem[1].key["ex:name"],
        "literal\\"
    );
    assert_eq!(
        data.update[0].val.as_ref().unwrap().value,
        Some(gnmi::typed_value::Value::JsonIetfVal(b"true".to_vec()))
    );
}

#[tokio::test]
async fn denied_large_event_does_not_count_or_interrupt_visible_events() {
    let _diagnostics = DIAGNOSTICS.lock().await;
    let control = "/ex:system/ex:visible";
    let (service, binding, sender) = subscription_fixture(
        Vec::new(),
        policy(&[control, "/ex:system/ex:peer/ex:up"]),
        MgmtLimits {
            max_value_bytes: 128,
            ..MgmtLimits::default()
        },
    )
    .await;
    let mut list = subscription(selection(&[], "up"));
    list.subscription.push(gnmi::Subscription {
        path: Some(gnmi::Path {
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
        }),
        mode: gnmi::SubscriptionMode::OnChange as i32,
        ..Default::default()
    });
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    sync(stream.next().await.unwrap().unwrap());
    let denials = || {
        opc_redaction::metrics::METRICS
            .gnmi_nacm_denials_total
            .lock()
            .unwrap()
            .get("subscribe")
            .copied()
            .unwrap_or_default()
    };
    let before = denials();
    let calls = binding.policy.calls.load(Ordering::SeqCst);
    // The first event is too large and lacks a key, but its identity dependency
    // is denied. It must be dropped before either validation or size checking.
    sender
        .send(OperationalEvent::Update(value(
            &format!(
                "/ex:system/ex:peer[ex:name='{}']/ex:up",
                "hidden".repeat(100)
            ),
            &serde_json::to_string(&"hidden-payload".repeat(100)).unwrap(),
        )))
        .await
        .unwrap();
    sender
        .send(OperationalEvent::Update(value(control, "17")))
        .await
        .unwrap();
    let data = notification(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    );
    assert_eq!(data.update.len(), 1);
    assert_eq!(
        data.update[0].path.as_ref().unwrap().elem[1].name,
        "ex:visible"
    );
    assert_eq!(
        data.update[0].val.as_ref().unwrap().value,
        Some(gnmi::typed_value::Value::JsonIetfVal(b"17".to_vec()))
    );
    assert_eq!(binding.policy.calls.load(Ordering::SeqCst), calls + 2);
    assert_eq!(
        denials(),
        before,
        "hidden events never add denial activity counts"
    );
}

async fn hidden_overflow_preserves_visible_stream(event: OperationalEvent) {
    let _diagnostics = DIAGNOSTICS.lock().await;
    let control = "/ex:system/ex:visible";
    let (service, binding, sender) = subscription_fixture(
        Vec::new(),
        policy(&[control, "/ex:system/ex:peer/ex:up"]),
        MgmtLimits {
            max_value_bytes: 128,
            ..MgmtLimits::default()
        },
    )
    .await;
    let mut list = subscription(selection(&[], "up"));
    list.subscription.push(gnmi::Subscription {
        path: Some(gnmi::Path {
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
        }),
        mode: gnmi::SubscriptionMode::OnChange as i32,
        ..Default::default()
    });
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    sync(stream.next().await.unwrap().unwrap());
    let denials = || {
        opc_redaction::metrics::METRICS
            .gnmi_nacm_denials_total
            .lock()
            .unwrap()
            .get("subscribe")
            .copied()
            .unwrap_or_default()
    };
    let before = denials();
    let calls = binding.policy.calls.load(Ordering::SeqCst);
    sender.send(event).await.unwrap();
    sender
        .send(OperationalEvent::Update(value(control, "17")))
        .await
        .unwrap();
    let data = notification(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    );
    assert_eq!(data.update.len(), 1);
    assert_eq!(
        data.update[0].path.as_ref().unwrap().elem[1].name,
        "ex:visible"
    );
    assert_eq!(
        data.update[0].val.as_ref().unwrap().value,
        Some(gnmi::typed_value::Value::JsonIetfVal(b"17".to_vec()))
    );
    assert_eq!(binding.policy.calls.load(Ordering::SeqCst), calls + 2);
    assert_eq!(denials(), before);
}

#[tokio::test]
async fn hidden_path_overflow_is_dropped_before_size_validation() {
    hidden_overflow_preserves_visible_stream(OperationalEvent::Update(peer(
        &"hidden".repeat(100),
        "up",
        "true",
    )))
    .await;
}

#[tokio::test]
async fn hidden_value_overflow_is_dropped_before_size_validation() {
    hidden_overflow_preserves_visible_stream(OperationalEvent::Update(peer(
        "hidden",
        "up",
        &serde_json::to_string(&"hidden".repeat(100)).unwrap(),
    )))
    .await;
}

async fn wait_for_render(binding: &SubscriptionBinding, calls: usize) {
    loop {
        let rendered = binding.rendered.notified();
        if binding.inner.renders.load(Ordering::SeqCst) >= calls {
            return;
        }
        rendered.await;
    }
}

#[tokio::test(start_paused = true)]
async fn expanded_sample_suppresses_reordered_values_including_updates_only() {
    for updates_only in [false, true] {
        let (service, binding, _sender) = subscription_fixture(
            vec![peer("b", "up", "false"), peer("a", "up", "true")],
            policy(&["/ex:system/**"]),
            MgmtLimits::default(),
        )
        .await;
        let mut list = subscription(selection(&[("site", "east")], "up"));
        list.subscription[0].mode = gnmi::SubscriptionMode::Sample as i32;
        list.subscription[0].sample_interval = 100_000_000;
        list.subscription[0].suppress_redundant = true;
        list.updates_only = updates_only;
        let mut stream = service
            .subscribe(open_requests(list, false))
            .await
            .unwrap()
            .into_inner();
        if !updates_only {
            assert_eq!(
                notification(stream.next().await.unwrap().unwrap())
                    .update
                    .len(),
                2
            );
        }
        sync(stream.next().await.unwrap().unwrap());
        binding.inner.provider.values.lock().unwrap().reverse();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        wait_for_render(&binding, 2).await;
        *binding.inner.provider.values.lock().unwrap() =
            vec![peer("b", "up", "false"), peer("a", "up", "false")];
        tokio::time::advance(Duration::from_millis(100)).await;
        let data = notification(stream.next().await.unwrap().unwrap());
        assert_eq!(data.update.len(), 2);
        assert_eq!(
            data.update[0].path.as_ref().unwrap().elem[1].key["ex:name"],
            "a"
        );
        assert_eq!(
            data.update[0].val.as_ref().unwrap().value,
            Some(gnmi::typed_value::Value::JsonIetfVal(b"false".to_vec()))
        );
        assert_eq!(
            data.update[1].path.as_ref().unwrap().elem[1].key["ex:name"],
            "b"
        );
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                stream.as_mut().poll_next(cx).is_pending()
            ))
            .await
        );
    }
}

#[tokio::test(start_paused = true)]
async fn expanded_heartbeat_keeps_cadence_and_canonical_order() {
    let (service, binding, _sender) = subscription_fixture(
        vec![peer("b", "up", "false"), peer("a", "up", "true")],
        policy(&["/ex:system/**"]),
        MgmtLimits::default(),
    )
    .await;
    let mut list = subscription(selection(&[], "up"));
    list.updates_only = false;
    list.subscription[0].heartbeat_interval = 100_000_000;
    list.subscription[0].suppress_redundant = true;
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    let initial = notification(stream.next().await.unwrap().unwrap());
    sync(stream.next().await.unwrap().unwrap());
    binding.inner.provider.values.lock().unwrap().reverse();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(99)).await;
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(
            stream.as_mut().poll_next(cx).is_pending()
        ))
        .await
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    let repeated = notification(stream.next().await.unwrap().unwrap());
    assert_eq!(repeated.update, initial.update);
    assert_eq!(repeated.delete, Vec::new());
}

#[tokio::test]
async fn expanded_subscribe_snapshots_refuse_response_count_overflow() {
    for mode in [
        gnmi::subscription_list::Mode::Once,
        gnmi::subscription_list::Mode::Poll,
        gnmi::subscription_list::Mode::Stream,
    ] {
        let (service, binding, _sender) = subscription_fixture(
            vec![
                peer("a", "up", "true"),
                peer("b", "up", "true"),
                peer("c", "up", "true"),
            ],
            policy(&["/ex:system/**"]),
            MgmtLimits {
                max_paths_per_request: 2,
                ..MgmtLimits::default()
            },
        )
        .await;
        let mut list = subscription(selection(&[], "up"));
        list.mode = mode as i32;
        list.updates_only = false;
        let mut stream = service
            .subscribe(open_requests(
                list,
                mode == gnmi::subscription_list::Mode::Poll,
            ))
            .await
            .unwrap()
            .into_inner();
        if mode == gnmi::subscription_list::Mode::Poll {
            sync(stream.next().await.unwrap().unwrap());
        }
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.message(), "invalid gNMI request");
        assert_eq!(binding.inner.renders.load(Ordering::SeqCst), 0);
        assert_eq!(
            binding.inner.provider.requests.lock().unwrap()[0].max_values,
            2
        );
    }
}

#[tokio::test]
async fn non_cleartext_operational_key_is_refused_in_delete() {
    let (service, _, sender) = subscription_fixture(
        Vec::new(),
        policy(&["/ex:system/**"]),
        MgmtLimits::default(),
    )
    .await;
    let mut path = selection(&[], "up");
    path.elem[1].name = "sealed".into();
    let mut stream = service
        .subscribe(open_requests(subscription(path), false))
        .await
        .unwrap()
        .into_inner();
    sync(stream.next().await.unwrap().unwrap());
    sender
        .send(OperationalEvent::Delete {
            path: YangPath::new("/ex:system/ex:sealed[ex:id='hidden-key-marker']/ex:up").unwrap(),
        })
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), Code::Internal);
    assert_eq!(error.message(), "gNMI internal error");
    assert!(!format!("{error:?}").contains("hidden-key-marker"));
}

static DIAGNOSTICS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn group_key_policy() -> NacmPolicy {
    let mut modules = ModuleRegistry::new();
    modules.register_module("example", "ex").unwrap();
    let mut builder = NacmPolicy::builder(PolicyVersion::new(1));
    for path in ["/ex:system/ex:peer/ex:up", "/ex:system/ex:peer/ex:site"] {
        builder = builder.add_rule(NacmRule::allow(
            NacmAction::Subscribe,
            YangPathPattern::parse(path, &modules).unwrap(),
        ));
    }
    builder
        .add_rule_list(
            opc_nacm::NacmRuleList::new(
                "read-keys",
                ["key-readers"],
                vec![NacmRule::allow(
                    NacmAction::Subscribe,
                    YangPathPattern::parse("/ex:system/ex:peer/ex:name", &modules).unwrap(),
                )],
            )
            .unwrap(),
        )
        .build()
}

async fn wait_policy_calls(policy: &SubscriptionPolicy, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let notified = policy.evaluated.notified();
            if policy.calls.load(Ordering::SeqCst) >= count {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn expanded_revocation_control_is_independent_of_hidden_event_activity() {
    for context_change in [false, true] {
        for hidden in [0, 1, usize::MAX] {
            let (service, binding, sender) = subscription_fixture(
                vec![peer("a", "up", "true")],
                group_key_policy(),
                MgmtLimits::default(),
            )
            .await;
            let mut list = subscription(selection(&[("site", "east")], "up"));
            list.updates_only = false;
            let mut stream = service
                .subscribe(open_requests(list, false))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                notification(stream.next().await.unwrap().unwrap())
                    .update
                    .len(),
                1
            );
            sync(stream.next().await.unwrap().unwrap());
            assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 1);
            let pending = binding
                .policy
                .changes
                .prepare_change(|| {
                    if context_change {
                        binding.policy.resolved_group.store(false, Ordering::SeqCst);
                    } else {
                        *binding.policy.current.lock().unwrap() = Arc::new(policy(&[
                            "/ex:system/ex:peer/ex:up",
                            "/ex:system/ex:peer/ex:site",
                        ]));
                    }
                })
                .await
                .unwrap();
            let producer = if hidden == usize::MAX {
                Some(tokio::spawn(async move {
                    loop {
                        if sender
                            .send(OperationalEvent::Delete {
                                path: peer("hidden-key-marker", "up", "true").path().clone(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }))
            } else {
                for _ in 0..hidden {
                    sender
                        .send(OperationalEvent::Delete {
                            path: peer("hidden-key-marker", "up", "true").path().clone(),
                        })
                        .await
                        .unwrap();
                }
                None
            };
            wait_policy_calls(&binding.policy, if hidden == 0 { 1 } else { 2 }).await;
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    stream.as_mut().poll_next(cx).is_pending()
                ))
                .await
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), pending.complete())
                    .await
                    .unwrap()
                    .unwrap(),
                1
            );
            if hidden != usize::MAX {
                assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 2 + hidden);
            }
            let terminal =
                std::future::poll_fn(|cx| std::task::Poll::Ready(stream.as_mut().poll_next(cx)))
                    .await;
            let std::task::Poll::Ready(Some(Err(error))) = terminal else {
                panic!("termination must be ready at acknowledgement");
            };
            assert_eq!(error.code(), Code::Unavailable);
            assert_eq!(error.message(), "gNMI service unavailable");
            assert!(stream.next().await.is_none());
            if let Some(producer) = producer {
                tokio::time::timeout(Duration::from_secs(5), producer)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }
}

#[tokio::test]
async fn expanded_pending_principal_invalidation_waits_for_control_delivery() {
    let (service, binding, sender) = subscription_fixture(
        vec![peer("a", "up", "true")],
        group_key_policy(),
        MgmtLimits::default(),
    )
    .await;
    let mut list = subscription(selection(&[], "up"));
    list.updates_only = false;
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        notification(stream.next().await.unwrap().unwrap())
            .update
            .len(),
        1
    );
    sync(stream.next().await.unwrap().unwrap());
    let pending = binding
        .policy
        .changes
        .prepare_change(|| binding.policy.invalid.store(true, Ordering::SeqCst))
        .await
        .unwrap();
    for count in 2..=3 {
        sender
            .send(OperationalEvent::Delete {
                path: peer("hidden-key-marker", "up", "true").path().clone(),
            })
            .await
            .unwrap();
        wait_policy_calls(&binding.policy, count).await;
    }
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(
            stream.as_mut().poll_next(cx).is_pending()
        ))
        .await
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .unwrap(),
        1
    );
    assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 4);
    let terminal =
        std::future::poll_fn(|cx| std::task::Poll::Ready(stream.as_mut().poll_next(cx))).await;
    let std::task::Poll::Ready(Some(Err(error))) = terminal else {
        panic!("termination must be ready at acknowledgement");
    };
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "gNMI service unavailable");
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn expanded_snapshots_require_subscribe_permission_in_every_mode() {
    let _diagnostics = DIAGNOSTICS.lock().await;
    for mode in [
        gnmi::subscription_list::Mode::Once,
        gnmi::subscription_list::Mode::Poll,
        gnmi::subscription_list::Mode::Stream,
    ] {
        let mut modules = ModuleRegistry::new();
        modules.register_module("example", "ex").unwrap();
        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/ex:system/**", &modules).unwrap(),
            ))
            .build();
        let (service, binding, _sender) =
            subscription_fixture(vec![peer("a", "up", "true")], policy, MgmtLimits::default())
                .await;
        let mut list = subscription(selection(&[], "up"));
        list.mode = mode as i32;
        list.updates_only = false;
        let mut stream = service
            .subscribe(open_requests(
                list,
                mode == gnmi::subscription_list::Mode::Poll,
            ))
            .await
            .unwrap()
            .into_inner();
        sync(stream.next().await.unwrap().unwrap());
        if mode == gnmi::subscription_list::Mode::Poll {
            sync(stream.next().await.unwrap().unwrap());
        }
        assert!(binding.inner.provider.requests.lock().unwrap().is_empty());
        assert!(binding.events.requests.lock().unwrap().is_empty());
        assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 1);
    }
}

async fn terminal_at_ack(
    stream: &mut <GnmiService<(), SubscriptionBinding> as GNmi>::SubscribeStream,
) {
    let terminal =
        std::future::poll_fn(|cx| std::task::Poll::Ready(stream.as_mut().poll_next(cx))).await;
    let std::task::Poll::Ready(Some(Err(error))) = terminal else {
        panic!("termination must be ready at acknowledgement");
    };
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "gNMI service unavailable");
    assert!(!format!("{error:?}").contains("marker"));
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn expanded_authorization_delivery_and_refresh_fail_closed() {
    for failure in ["refresh", "source", "delivery"] {
        let (service, binding, _sender) = subscription_fixture(
            vec![peer("permitted-marker", "up", "true")],
            group_key_policy(),
            MgmtLimits::default(),
        )
        .await;
        let mut list = subscription(selection(&[], "up"));
        list.updates_only = false;
        let mut stream = service
            .subscribe(open_requests(list, false))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            notification(stream.next().await.unwrap().unwrap())
                .update
                .len(),
            1
        );
        sync(stream.next().await.unwrap().unwrap());
        match failure {
            "refresh" => {
                let pending = binding
                    .policy
                    .changes
                    .prepare_change(|| binding.policy.invalid.store(true, Ordering::SeqCst))
                    .await
                    .unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), pending.complete())
                        .await
                        .unwrap()
                        .unwrap(),
                    1
                );
                assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 2);
            }
            "source" => binding.policy.changes.fail(),
            "delivery" => drop(binding.policy.changes.prepare_change(|| {}).await.unwrap()),
            _ => unreachable!(),
        }
        terminal_at_ack(&mut stream).await;
    }
}

#[tokio::test]
async fn expanded_revoke_then_restore_terminates_the_old_stream() {
    let (service, binding, _sender) = subscription_fixture(
        vec![peer("permitted-marker", "up", "true")],
        group_key_policy(),
        MgmtLimits::default(),
    )
    .await;
    let mut list = subscription(selection(&[], "up"));
    list.updates_only = false;
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        notification(stream.next().await.unwrap().unwrap())
            .update
            .len(),
        1
    );
    sync(stream.next().await.unwrap().unwrap());
    let revoke = binding
        .policy
        .changes
        .prepare_change(|| binding.policy.resolved_group.store(false, Ordering::SeqCst))
        .await
        .unwrap();
    let restore = binding
        .policy
        .changes
        .prepare_change(|| binding.policy.resolved_group.store(true, Ordering::SeqCst));
    tokio::pin!(restore);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
            restore.as_mut(),
            cx
        )))
        .await
        .is_pending()
    );
    assert!(!binding.policy.resolved_group.load(Ordering::SeqCst));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), revoke.complete())
            .await
            .unwrap()
            .unwrap(),
        1
    );
    assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), restore.await.unwrap().complete())
            .await
            .unwrap()
            .unwrap(),
        2
    );
    terminal_at_ack(&mut stream).await;
}

#[tokio::test]
async fn expanded_revocation_discards_buffered_output_without_waiting_for_capacity() {
    let limits = MgmtLimits {
        max_subscriber_queue_bytes: 4096,
        ..MgmtLimits::default()
    };
    let (service, binding, sender) = subscription_fixture(
        vec![peer("permitted-marker", "up", "true")],
        group_key_policy(),
        limits,
    )
    .await;
    let mut list = subscription(selection(&[], "up"));
    list.updates_only = false;
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    notification(stream.next().await.unwrap().unwrap());
    sync(stream.next().await.unwrap().unwrap());
    for _ in 0..2 {
        sender
            .send(OperationalEvent::Update(peer(
                "permitted-marker",
                "up",
                "false",
            )))
            .await
            .unwrap();
    }
    wait_policy_calls(&binding.policy, 3).await;
    let pending = binding
        .policy
        .changes
        .prepare_change(|| binding.policy.resolved_group.store(false, Ordering::SeqCst))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .unwrap(),
        1
    );
    assert_eq!(binding.policy.calls.load(Ordering::SeqCst), 4);
    terminal_at_ack(&mut stream).await;
}

struct BlockedExpandedProvider {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    block_subscription: bool,
    receiver: Mutex<Option<OperationalEventReceiver>>,
}

impl BlockedExpandedProvider {
    fn wait(&self) {
        self.entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}

impl OperationalStateProvider for BlockedExpandedProvider {
    fn get(&self, _: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        if !self.block_subscription {
            self.wait();
        }
        Ok(OperationalResponse::new([peer(
            "permitted-marker",
            "up",
            "true",
        )]))
    }
}

impl OperationalEventSource for BlockedExpandedProvider {
    fn subscribe(
        &self,
        _: &OperationalSubscriptionRequest,
    ) -> Result<OperationalEventReceiver, OperationalError> {
        if self.block_subscription {
            self.wait();
        }
        Ok(self.receiver.lock().unwrap().take().unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expanded_revocation_does_not_wait_for_provider_get_or_registration() {
    for block_subscription in [false, true] {
        let (_, mut binding, _sender) =
            subscription_fixture(vec![], group_key_policy(), MgmtLimits::default()).await;
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let (_events, receiver) = operational_event_channel(1);
        let provider = Arc::new(BlockedExpandedProvider {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(release_rx),
            block_subscription,
            receiver: Mutex::new(Some(receiver)),
        });
        binding.state_override = Some(provider.clone());
        binding.events_override = Some(provider);
        let service = GnmiService::new(
            GnmiServer::new_with_audit(
                binding.clone(),
                MgmtLimits::default(),
                CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
                ExtensionRegistry::default(),
                Arc::new(Audit::default()),
            )
            .unwrap(),
        );
        let mut list = subscription(selection(&[], "up"));
        list.updates_only = false;
        let mut stream = service
            .subscribe(open_requests(list, false))
            .await
            .unwrap()
            .into_inner();
        entered_rx.await.unwrap();
        let pending = binding
            .policy
            .changes
            .prepare_change(|| binding.policy.resolved_group.store(false, Ordering::SeqCst))
            .await
            .unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(5), pending.complete()).await;
        // Release the provider even if the isolation guard regresses.
        release.send(()).unwrap();
        assert_eq!(completed.unwrap().unwrap(), 1);
        terminal_at_ack(&mut stream).await;
    }
}

struct PendingExpandedAudit(tokio::sync::Notify);

impl AuditSink for PendingExpandedAudit {
    fn record(&self, _: &AuditEvent) -> Result<(), AuditError> {
        panic!("expected async audit path");
    }
    fn record_async<'a>(
        &'a self,
        _: &'a AuditEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AuditError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.0.notify_one();
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn expanded_revocation_does_not_wait_for_audit_work() {
    let (_, binding, _sender) = subscription_fixture(
        vec![peer("permitted-marker", "up", "true")],
        group_key_policy(),
        MgmtLimits::default(),
    )
    .await;
    let audit = Arc::new(PendingExpandedAudit(tokio::sync::Notify::new()));
    let service = GnmiService::new(
        GnmiServer::new_with_audit(
            binding.clone(),
            MgmtLimits::default(),
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
            ExtensionRegistry::default(),
            audit.clone(),
        )
        .unwrap(),
    );
    let mut list = subscription(selection(&[], "up"));
    list.updates_only = false;
    let mut stream = service
        .subscribe(open_requests(list, false))
        .await
        .unwrap()
        .into_inner();
    tokio::time::timeout(Duration::from_secs(5), audit.0.notified())
        .await
        .unwrap();
    let pending = binding
        .policy
        .changes
        .prepare_change(|| binding.policy.resolved_group.store(false, Ordering::SeqCst))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), pending.complete())
            .await
            .unwrap()
            .unwrap(),
        1
    );
    terminal_at_ack(&mut stream).await;
}
