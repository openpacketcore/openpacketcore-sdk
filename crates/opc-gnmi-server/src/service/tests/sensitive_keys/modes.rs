use super::*;

struct ConfigKeyRegistry;
impl SchemaRegistry for ConfigKeyRegistry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:config-key"
    }
    fn served_models(&self) -> &'static [ModelData] {
        MODELS
    }
    fn origins(&self) -> &'static [OriginEntry] {
        ORIGINS
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        static CONFIG: std::sync::OnceLock<Vec<NodeMeta>> = std::sync::OnceLock::new();
        CONFIG.get_or_init(|| {
            NODES
                .iter()
                .map(|node| {
                    let mut node = *node;
                    node.config = true;
                    if node.path == "/sys:system/sys:user/sys:name" {
                        node.data_class = DataClass::SubscriberId;
                    }
                    node
                })
                .collect()
        })
    }
}

#[derive(Default)]
struct RenderProbe {
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    block: Mutex<Option<(usize, std::sync::mpsc::Receiver<()>)>>,
}
impl RenderProbe {
    async fn wait_calls(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = self.entered.notified();
                if self.calls.load(Ordering::SeqCst) >= count {
                    break;
                }
                notified.await;
            }
        })
        .await
        .expect("snapshot reaches deterministic rendering barrier");
    }
    fn enter(&self) {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.entered.notify_one();
        let block = {
            let mut block = self.block.lock().unwrap();
            if block.as_ref().is_some_and(|(target, _)| *target == call) {
                block.take()
            } else {
                None
            }
        };
        if let Some((_, release)) = block {
            release.recv().unwrap();
        }
    }
}

struct ConfigKeyBinding {
    inner: TestBinding,
    probe: Arc<RenderProbe>,
}
impl GnmiConfigBinding<DemoConfig> for ConfigKeyBinding {
    fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
        self.inner.bus.clone()
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        &ConfigKeyRegistry
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<DemoConfig>> {
        self.inner.patcher.clone()
    }
    fn policy_source(&self) -> Arc<dyn PolicySource> {
        self.inner.policy.clone()
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        self.inner.operational.clone()
    }
    fn render_running_json(
        &self,
        config: &DemoConfig,
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        self.probe.enter();
        self.inner.render_running_json(config, selection)
    }
}

async fn config_service(
    policy: Arc<dyn PolicySource>,
    probe: Arc<RenderProbe>,
) -> GnmiService<DemoConfig, ConfigKeyBinding> {
    let bus = Arc::new(
        ConfigBus::new_dev_only(initial_config(), MockManagedDatastore::new())
            .await
            .unwrap(),
    );
    let binding = ConfigKeyBinding {
        inner: TestBinding {
            bus,
            policy,
            operational: Arc::new(TestOperationalState),
            events: None,
            patcher: unit_patcher(),
        },
        probe,
    };
    let limits = MgmtLimits {
        max_subscriber_queue_bytes: 4096,
        ..Default::default()
    };
    let server = GnmiServer::new(
        binding,
        limits,
        CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
        ExtensionRegistry::default(),
        Arc::new(CapturingAudit::default()),
    )
    .unwrap();
    GnmiService::new_authenticated(server)
}

fn list(
    mode: gnmi::subscription_list::Mode,
    subscription: gnmi::SubscriptionMode,
    root: bool,
) -> gnmi::SubscriptionList {
    let path = if root {
        crate::get::yang_path_to_proto(&YangPath::new("/sys:system").unwrap()).unwrap()
    } else {
        crate::get::yang_path_to_proto(&user_role_yang_path("admin")).unwrap()
    };
    let mut list = subscribe_list(mode, path, subscription);
    list.subscription[0].sample_interval = if subscription == gnmi::SubscriptionMode::Sample {
        100_000_000
    } else {
        0
    };
    list
}

async fn next(stream: &mut SubscribeStream) -> gnmi::SubscribeResponse {
    tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("expected protocol emission")
        .unwrap()
        .unwrap()
}

async fn expect_value(stream: &mut SubscribeStream, path: &str, value: &str) {
    let response = next(stream).await;
    let Some(gnmi::subscribe_response::Response::Update(notification)) = response.response else {
        panic!("expected exactly one update, without an extra sync")
    };
    assert_eq!(notification.prefix, None);
    assert_eq!(notification.delete, Vec::new());
    assert_eq!(notification.update.len(), 1);
    assert_eq!(
        notification.update[0].path,
        Some(crate::get::yang_path_to_proto(&YangPath::new(path).unwrap()).unwrap())
    );
    assert_eq!(
        notification.update[0].val.as_ref().unwrap().value,
        Some(gnmi::typed_value::Value::JsonIetfVal(
            serde_json::to_vec(value).unwrap()
        ))
    );
}

async fn expect_sync(stream: &mut SubscribeStream) {
    assert_eq!(
        next(stream).await.response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
}

async fn commit(
    service: &GnmiService<DemoConfig, ConfigKeyBinding>,
    visible: Option<&str>,
    hidden: &str,
) {
    let bus = service.server().binding().config_bus();
    let snapshot = bus.current_snapshot();
    let mut config = snapshot.config.as_ref().clone();
    if let Some(visible) = visible {
        config.hostname = visible.to_string();
    }
    config.users = [(
        hidden.to_string(),
        DemoUser {
            role: "excluded-value".into(),
        },
    )]
    .into_iter()
    .collect();
    let mut request = opc_config_model::CommitRequest::commit(
        RequestId::new(),
        authenticated_principal().principal().clone(),
        opc_config_model::TransportType::Internal,
        opc_config_model::RequestSource::Northbound,
        opc_config_model::ConfigOperation::Replace,
        config,
        vec![],
        std::time::Instant::now() + Duration::from_secs(5),
    );
    request.base_version = snapshot.version;
    bus.submit(request).await.unwrap();
}

#[tokio::test]
async fn sensitive_key_subscribe_once_and_poll_distinguish_read_permission() {
    for mode in [
        gnmi::subscription_list::Mode::Once,
        gnmi::subscription_list::Mode::Poll,
    ] {
        for action in [NacmAction::Read, NacmAction::Subscribe] {
            let policy = selected_policy(
                &[
                    "/sys:system/sys:user/sys:name",
                    "/sys:system/sys:user/sys:role",
                ],
                action,
            );
            let service = config_service(
                Arc::new(FixedPolicy(policy)),
                Arc::new(RenderProbe::default()),
            )
            .await;
            let mut requests = vec![subscribe_request(list(
                mode,
                gnmi::SubscriptionMode::Sample,
                false,
            ))];
            if mode == gnmi::subscription_list::Mode::Poll {
                requests.push(gnmi::SubscribeRequest {
                    request: Some(gnmi::subscribe_request::Request::Poll(gnmi::Poll {})),
                    ..Default::default()
                });
            }
            let mut stream = service
                .subscribe(open_subscribe_requests(requests))
                .await
                .unwrap()
                .into_inner();
            if mode == gnmi::subscription_list::Mode::Poll {
                expect_sync(&mut stream).await;
            }
            if action == NacmAction::Subscribe {
                expect_value(
                    &mut stream,
                    "/sys:system/sys:user[sys:name='admin']/sys:role",
                    "superuser",
                )
                .await;
            }
            expect_sync(&mut stream).await;
            if mode == gnmi::subscription_list::Mode::Once {
                assert!(stream.next().await.is_none());
            } else {
                assert!(
                    std::future::poll_fn(|cx| std::task::Poll::Ready(
                        stream.as_mut().poll_next(cx).is_pending()
                    ))
                    .await
                );
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sensitive_key_subscribe_modes_and_revocation() {
    for heartbeat in [false, true] {
        let policy = Arc::new(ChangingContext::new());
        let probe = Arc::new(RenderProbe::default());
        let service = config_service(policy.clone(), probe.clone()).await;
        let mut requested = list(
            gnmi::subscription_list::Mode::Stream,
            if heartbeat {
                gnmi::SubscriptionMode::OnChange
            } else {
                gnmi::SubscriptionMode::Sample
            },
            false,
        );
        if heartbeat {
            requested.subscription[0].heartbeat_interval = 100_000_000;
            requested.subscription[0].suppress_redundant = true;
        }
        let mut stream = service
            .subscribe(open_subscribe_request(requested))
            .await
            .unwrap()
            .into_inner();
        expect_value(
            &mut stream,
            "/sys:system/sys:user[sys:name='admin']/sys:role",
            "superuser",
        )
        .await;
        expect_sync(&mut stream).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                stream.as_mut().poll_next(cx).is_pending()
            ))
            .await
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        expect_value(
            &mut stream,
            "/sys:system/sys:user[sys:name='admin']/sys:role",
            "superuser",
        )
        .await;
        let before_hidden = tokio::time::Instant::now();
        let bus = service.server().binding().config_bus();
        let snapshot = bus.current_snapshot();
        let mut hidden_change = snapshot.config.as_ref().clone();
        hidden_change.users.insert(
            "excluded-cadence-key-marker".into(),
            DemoUser {
                role: "excluded-cadence-value".into(),
            },
        );
        let mut change = opc_config_model::CommitRequest::commit(
            RequestId::new(),
            authenticated_principal().principal().clone(),
            opc_config_model::TransportType::Internal,
            opc_config_model::RequestSource::Northbound,
            opc_config_model::ConfigOperation::Replace,
            hidden_change,
            vec![],
            std::time::Instant::now() + Duration::from_secs(5),
        );
        change.base_version = snapshot.version;
        bus.submit(change).await.unwrap();
        if heartbeat {
            probe.wait_calls(3).await;
        }
        assert_eq!(tokio::time::Instant::now(), before_hidden);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                stream.as_mut().poll_next(cx).is_pending()
            ))
            .await
        );
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                stream.as_mut().poll_next(cx).is_pending()
            ))
            .await
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        expect_value(
            &mut stream,
            "/sys:system/sys:user[sys:name='admin']/sys:role",
            "superuser",
        )
        .await;
        let pending = policy
            .hub
            .prepare_change(|| policy.resolved_group.store(false, Ordering::SeqCst))
            .await
            .unwrap();
        pending.complete().await.unwrap();
        let terminal =
            std::future::poll_fn(|cx| std::task::Poll::Ready(stream.as_mut().poll_next(cx))).await;
        let std::task::Poll::Ready(Some(Err(error))) = terminal else {
            panic!("key revocation must end cadence before further output")
        };
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.message(), "gNMI service unavailable");
        assert!(stream.next().await.is_none());
    }
}

#[tokio::test]
async fn hidden_change_has_no_visible_effect_including_updates_only_and_lag_resync() {
    for updates_only in [false, true] {
        for lag in [false, true] {
            let probe = Arc::new(RenderProbe::default());
            let service = config_service(
                Arc::new(FixedPolicy(selected_policy(
                    &["/sys:system", "/sys:system/sys:hostname"],
                    NacmAction::Subscribe,
                ))),
                probe.clone(),
            )
            .await;
            let mut requested = list(
                gnmi::subscription_list::Mode::Stream,
                gnmi::SubscriptionMode::OnChange,
                true,
            );
            requested.updates_only = updates_only;
            let mut stream = service
                .subscribe(open_subscribe_request(requested))
                .await
                .unwrap()
                .into_inner();
            if !updates_only {
                expect_value(&mut stream, "/sys:system/sys:hostname", "amf-1").await;
            }
            expect_sync(&mut stream).await;
            assert_eq!(
                probe.calls.load(Ordering::SeqCst),
                1,
                "updates_only seeds authorized content without sending it"
            );
            let (release, release_rx) = std::sync::mpsc::channel();
            *probe.block.lock().unwrap() = Some((2, release_rx));
            commit(&service, None, "first-hidden-key-marker").await;
            probe.wait_calls(2).await;
            if lag {
                // The config queue has capacity one. Two commits behind the
                // blocked renderer replace its pending change with a resync.
                commit(&service, None, "second-hidden-key-marker").await;
                commit(&service, None, "third-hidden-key-marker").await;
            }
            release.send(()).unwrap();
            if lag {
                probe.wait_calls(3).await;
            }
            commit(
                &service,
                Some("next-visible-value"),
                "final-hidden-key-marker",
            )
            .await;
            expect_value(
                &mut stream,
                "/sys:system/sys:hostname",
                "next-visible-value",
            )
            .await;
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    stream.as_mut().poll_next(cx).is_pending()
                ))
                .await,
                "excluded changes add no notification or sync response"
            );
        }
    }
}

#[tokio::test]
async fn configuration_subscription_registers_before_initial_snapshot() {
    let probe = Arc::new(RenderProbe::default());
    let (release, release_rx) = std::sync::mpsc::channel();
    *probe.block.lock().unwrap() = Some((1, release_rx));
    let service = config_service(
        Arc::new(FixedPolicy(selected_policy(
            &["/sys:system/sys:hostname"],
            NacmAction::Subscribe,
        ))),
        probe.clone(),
    )
    .await;
    let mut requested = list(
        gnmi::subscription_list::Mode::Stream,
        gnmi::SubscriptionMode::OnChange,
        true,
    );
    requested.updates_only = true;
    let mut stream = service
        .subscribe(open_subscribe_request(requested))
        .await
        .unwrap()
        .into_inner();
    probe.wait_calls(1).await;
    commit(
        &service,
        Some("changed-during-initial-snapshot"),
        "hidden-key-marker",
    )
    .await;
    release.send(()).unwrap();
    expect_sync(&mut stream).await;
    expect_value(
        &mut stream,
        "/sys:system/sys:hostname",
        "changed-during-initial-snapshot",
    )
    .await;
}
