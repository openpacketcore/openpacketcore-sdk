use super::*;

fn opaque_policy(denied: &str) -> NacmPolicy {
    let modules = module_registry();
    let mut builder = NacmPolicy::builder(opc_nacm::PolicyVersion::new(1));
    for action in [NacmAction::Read, NacmAction::Subscribe] {
        builder = builder.add_rule(NacmRule::deny(
            action,
            YangPathPattern::parse(denied, &modules).unwrap(),
        ));
        for path in ["/sys:system", "/sys:system/**"] {
            builder = builder.add_rule(NacmRule::allow(
                action,
                YangPathPattern::parse(path, &modules).unwrap(),
            ));
        }
    }
    builder.build()
}

#[derive(Default)]
struct AggregateProvider(Mutex<Vec<OperationalRequest>>);
impl OperationalStateProvider for AggregateProvider {
    fn get(&self, request: &OperationalRequest) -> Result<OperationalResponse, OperationalError> {
        self.0.lock().unwrap().push(request.clone());
        Ok(OperationalResponse::new(
            request
                .paths()
                .iter()
                .filter(|path| matches!(path.as_str(), "/sys:system" | "/sys:system/sys:user"))
                .map(|path| {
                    OperationalValue::new(
                        path.clone(),
                        r#"{"user":[{"name":"opaque-hidden-key","role":"opaque-hidden-payload"}]}"#,
                    )
                    .unwrap()
                }),
        ))
    }
}

#[tokio::test]
async fn operational_subtree_with_denied_key_is_omitted() {
    for request_aggregate in [true, false] {
        for denied in [
            "/sys:system/sys:user/sys:name",
            "/sys:system/sys:user/sys:role",
        ] {
            let policy = Arc::new(FixedPolicy(opaque_policy(denied)));
            let provider = Arc::new(AggregateProvider::default());
            let (sender, receiver) = operational_event_channel(4);
            let events = Arc::new(ControlledEvents {
                receiver: Mutex::new(Some(receiver)),
                requests: Default::default(),
            });
            let audit = Arc::new(CapturingAudit::default());
            let service =
                state_key_service(policy, provider.clone(), events.clone(), audit.clone()).await;
            let mut get = selected_get("/sys:system");
            get.r#type = gnmi::get_request::DataType::State as i32;
            let response = service
                .get(authenticated_get_request(get))
                .await
                .unwrap()
                .into_inner();
            assert!(response.notification.is_empty());
            for request in provider.0.lock().unwrap().iter() {
                assert!(request.paths().iter().all(|path| !matches!(
                    path.as_str(),
                    "/sys:system" | "/sys:system/sys:user" | "/sys:system/sys:user/sys:role"
                )));
            }
            let mut list = subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            );
            list.subscription[0].sample_interval = 0;
            if request_aggregate {
                list.subscription.push(gnmi::Subscription {
                    path: Some(
                        crate::get::yang_path_to_proto(&YangPath::new("/sys:system").unwrap())
                            .unwrap(),
                    ),
                    mode: gnmi::SubscriptionMode::OnChange as i32,
                    ..Default::default()
                });
            }
            let mut stream = service
                .subscribe(open_subscribe_request(list))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                stream.next().await.unwrap().unwrap().response,
                Some(gnmi::subscribe_response::Response::SyncResponse(true))
            );
            let before = audit.events.lock().unwrap().len();
            // This aggregate is also outside the pruned provider subscription. Its
            // denial must happen before path validation, size checks or audit work.
            sender
                .send(OperationalEvent::Update(
                    OperationalValue::new(
                        YangPath::new("/sys:system").unwrap(),
                        serde_json::to_string(&"opaque-hidden-key".repeat(100000)).unwrap(),
                    )
                    .unwrap(),
                ))
                .await
                .unwrap();
            sender
                .send(OperationalEvent::Delete {
                    path: user_role_yang_path("opaque-hidden-key"),
                })
                .await
                .unwrap();
            sender
                .send(OperationalEvent::Update(
                    OperationalValue::new(YangPath::new("/sys:system/sys:uptime").unwrap(), "17")
                        .unwrap(),
                ))
                .await
                .unwrap();
            let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let Some(gnmi::subscribe_response::Response::Update(notification)) = response.response
            else {
                panic!("visible barrier event")
            };
            assert_eq!(notification.delete, Vec::new());
            assert_eq!(notification.update.len(), 1);
            assert_eq!(
                notification.update[0].path,
                Some(
                    crate::get::yang_path_to_proto(
                        &YangPath::new("/sys:system/sys:uptime").unwrap()
                    )
                    .unwrap()
                )
            );
            assert_eq!(
                notification.update[0].val.as_ref().unwrap().value,
                Some(gnmi::typed_value::Value::JsonIetfVal(b"17".to_vec()))
            );
            assert_eq!(
                audit.events.lock().unwrap().len(),
                before,
                "hidden data never adds audit work"
            );
            let requests = events.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            let mut expected = if request_aggregate {
                vec![
                    YangPath::new("/sys:system/sys:contact").unwrap(),
                    YangPath::new("/sys:system/sys:hostname").unwrap(),
                    YangPath::new("/sys:system/sys:uptime").unwrap(),
                ]
            } else {
                vec![YangPath::new("/sys:system/sys:uptime").unwrap()]
            };
            if request_aggregate && denied.ends_with("sys:role") {
                expected.push(YangPath::new("/sys:system/sys:user/sys:name").unwrap());
            }
            assert_eq!(requests[0].paths(), expected);
            assert!(!format!("{:?}", audit.events.lock().unwrap()).contains("opaque-hidden"));
        }
    }
}

struct AlternatingSubscribePolicy {
    calls: AtomicUsize,
    evaluated: tokio::sync::Notify,
}
impl PolicySource for AlternatingSubscribePolicy {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.evaluated.notify_one();
        let dependency = if call.is_multiple_of(2) {
            "/sys:system/sys:user/sys:role"
        } else {
            "/sys:system/sys:user/sys:name"
        };
        Ok(Arc::new(selected_policy(
            &["/sys:system/sys:uptime", dependency],
            NacmAction::Subscribe,
        )))
    }
    fn watch_authorization(
        &self,
        principal: &TrustedPrincipal,
        gate: opc_mgmt_authz::AuthorizationGate,
    ) -> Result<opc_mgmt_authz::AuthorizationWatch, AuthzError> {
        // A deliberately alternating test source detects a second load inside
        // one evaluation. Explicit immutable notification registration keeps
        // this test about batching, with no independently activated revision.
        opc_mgmt_authz::AuthorizationWatch::immutable(
            self.active_policy_context_for_principal(principal)?,
            gate,
        )
    }
}

#[tokio::test]
async fn key_dependencies_share_one_policy_snapshot_for_snapshots_and_events() {
    for snapshot in [false, true] {
        let policy = Arc::new(AlternatingSubscribePolicy {
            calls: AtomicUsize::new(0),
            evaluated: Default::default(),
        });
        let (sender, receiver) = operational_event_channel(4);
        let events = Arc::new(ControlledEvents {
            receiver: Mutex::new(Some(receiver)),
            requests: Default::default(),
        });
        let provider = Arc::new(KeyOperational::default());
        let service = state_key_service(
            policy.clone(),
            provider.clone(),
            events,
            Arc::new(CapturingAudit::default()),
        )
        .await;
        let path = if snapshot {
            crate::get::yang_path_to_proto(&user_role_yang_path("alternating-key-marker")).unwrap()
        } else {
            uptime_path()
        };
        let mode = if snapshot {
            gnmi::subscription_list::Mode::Once
        } else {
            gnmi::subscription_list::Mode::Stream
        };
        let list = subscribe_list(mode, path, gnmi::SubscriptionMode::OnChange);
        let mut stream = service
            .subscribe(open_subscribe_request(list))
            .await
            .unwrap()
            .into_inner();
        if !snapshot {
            stream.next().await.unwrap().unwrap();
        }
        assert_eq!(
            stream.next().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
        if snapshot {
            assert!(provider.requests.lock().unwrap().is_empty());
            assert!(stream.next().await.is_none());
        } else {
            for _ in 0..2 {
                sender
                    .send(OperationalEvent::Update(
                        OperationalValue::new(
                            user_role_yang_path("alternating-key-marker"),
                            "\"hidden-role-marker\"",
                        )
                        .unwrap(),
                    ))
                    .await
                    .unwrap();
            }
            sender
                .send(OperationalEvent::Update(
                    OperationalValue::new(YangPath::new("/sys:system/sys:uptime").unwrap(), "23")
                        .unwrap(),
                ))
                .await
                .unwrap();
            let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let Some(gnmi::subscribe_response::Response::Update(notification)) = response.response
            else {
                panic!("visible barrier event")
            };
            assert_eq!(notification.update.len(), 1);
            assert_eq!(
                notification.update[0].path,
                Some(
                    crate::get::yang_path_to_proto(
                        &YangPath::new("/sys:system/sys:uptime").unwrap()
                    )
                    .unwrap()
                )
            );
            assert_eq!(
                policy.calls.load(Ordering::SeqCst),
                4,
                "one context per complete event dependency batch"
            );
        }
    }
}

#[tokio::test]
async fn revoked_key_delete_is_dropped_before_visible_event_reestablishes_stream() {
    let policy = Arc::new(ChangingContext::new());
    *policy.policy.lock().unwrap() = selected_policy(
        &[
            "/sys:system/sys:user/sys:name",
            "/sys:system/sys:user/sys:role",
            "/sys:system/sys:uptime",
        ],
        NacmAction::Subscribe,
    );
    let (sender, receiver) = operational_event_channel(4);
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
        crate::get::yang_path_to_proto(&user_role_yang_path("revoked-key-marker")).unwrap(),
        gnmi::SubscriptionMode::OnChange,
    );
    list.subscription.push(gnmi::Subscription {
        path: Some(uptime_path()),
        mode: gnmi::SubscriptionMode::OnChange as i32,
        ..Default::default()
    });
    let mut stream = service
        .subscribe(open_subscribe_request(list))
        .await
        .unwrap()
        .into_inner();
    let Some(gnmi::subscribe_response::Response::Update(initial)) =
        stream.next().await.unwrap().unwrap().response
    else {
        panic!("initial snapshot")
    };
    assert_eq!(initial.update.len(), 2);
    assert!(initial.update.iter().any(|update| update
        .path
        .as_ref()
        .unwrap()
        .elem
        .iter()
        .any(|element| element.key.values().any(|key| key == "revoked-key-marker"))));
    assert_eq!(
        stream.next().await.unwrap().unwrap().response,
        Some(gnmi::subscribe_response::Response::SyncResponse(true))
    );
    // Deliberately simulate a faulty publisher that changed its context before
    // notifying. The independent per-event check must still protect output;
    // the denied delete itself is not a revocation control notification.
    *policy.policy.lock().unwrap() = selected_policy(
        &["/sys:system/sys:user/sys:role", "/sys:system/sys:uptime"],
        NacmAction::Subscribe,
    );
    sender
        .send(OperationalEvent::Delete {
            path: user_role_yang_path("revoked-key-marker"),
        })
        .await
        .unwrap();
    let evaluated_without_output = tokio::select! {
        biased;
        _ = stream.next() => false,
        _ = policy.wait_calls(2) => true,
    };
    assert!(
        evaluated_without_output,
        "a denied delete must be authorized without emitting or closing the stream"
    );
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(
            stream.as_mut().poll_next(cx).is_pending()
        ))
        .await
    );
    sender
        .send(OperationalEvent::Update(
            OperationalValue::new(YangPath::new("/sys:system/sys:uptime").unwrap(), "31").unwrap(),
        ))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .expect_err("visible event requires stream reestablishment after revoked identity");
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "gNMI service unavailable");
    assert_eq!(policy.calls.load(Ordering::SeqCst), 3);
    assert!(stream.next().await.is_none());
}

struct ForbiddenKeyRegistry(DataClass);
impl SchemaRegistry for ForbiddenKeyRegistry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:forbidden-state-key"
    }
    fn served_models(&self) -> &'static [ModelData] {
        MODELS
    }
    fn origins(&self) -> &'static [OriginEntry] {
        ORIGINS
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        static SECRET: std::sync::OnceLock<Vec<NodeMeta>> = std::sync::OnceLock::new();
        static LAWFUL: std::sync::OnceLock<Vec<NodeMeta>> = std::sync::OnceLock::new();
        let nodes = if self.0 == DataClass::SecuritySecret {
            &SECRET
        } else {
            &LAWFUL
        };
        nodes.get_or_init(|| {
            StateKeyRegistry
                .nodes()
                .iter()
                .map(|node| {
                    let mut node = *node;
                    if node.path == "/sys:system/sys:user/sys:name" {
                        node.data_class = self.0;
                    }
                    node
                })
                .collect()
        })
    }
}

#[tokio::test]
async fn operational_subtree_with_forbidden_key_class_is_omitted() {
    static REGISTRIES: [ForbiddenKeyRegistry; 2] = [
        ForbiddenKeyRegistry(DataClass::SecuritySecret),
        ForbiddenKeyRegistry(DataClass::LawfulIntercept),
    ];
    for registry in &REGISTRIES {
        let mut policy = NacmPolicy::builder(opc_nacm::PolicyVersion::new(1));
        for action in [NacmAction::Read, NacmAction::Subscribe] {
            for path in ["/sys:system", "/sys:system/**"] {
                policy = policy.add_rule(NacmRule::allow(
                    action,
                    YangPathPattern::parse(path, &module_registry()).unwrap(),
                ));
            }
        }
        let provider = Arc::new(AggregateProvider::default());
        let (sender, receiver) = operational_event_channel(2);
        let events = Arc::new(ControlledEvents {
            receiver: Mutex::new(Some(receiver)),
            requests: Default::default(),
        });
        let base = state_key_service(
            Arc::new(FixedPolicy(policy.build())),
            provider.clone(),
            events,
            Arc::new(CapturingAudit::default()),
        )
        .await;
        let server = GnmiServer::new(
            StateKeyBinding(base.server().binding().0.clone(), registry),
            MgmtLimits::default(),
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
            ExtensionRegistry::default(),
            Arc::new(CapturingAudit::default()),
        )
        .unwrap();
        let service = GnmiService::new_authenticated(server);
        let mut request = selected_get("/sys:system");
        request.r#type = gnmi::get_request::DataType::State as i32;
        assert!(service
            .get(authenticated_get_request(request))
            .await
            .unwrap()
            .into_inner()
            .notification
            .is_empty());
        assert_eq!(
            provider.0.lock().unwrap()[0].paths(),
            &[
                YangPath::new("/sys:system/sys:contact").unwrap(),
                YangPath::new("/sys:system/sys:hostname").unwrap(),
                YangPath::new("/sys:system/sys:uptime").unwrap(),
                YangPath::new("/sys:system/sys:user/sys:name").unwrap(),
                YangPath::new("/sys:system/sys:user/sys:role").unwrap()
            ]
        );
        let mut stream = service
            .subscribe(open_subscribe_request(subscribe_list(
                gnmi::subscription_list::Mode::Stream,
                uptime_path(),
                gnmi::SubscriptionMode::OnChange,
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            stream.next().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
        sender
            .send(OperationalEvent::Update(
                OperationalValue::new(
                    YangPath::new("/sys:system").unwrap(),
                    r#"{"user":[{"name":"forbidden-provider-key"}]}"#,
                )
                .unwrap(),
            ))
            .await
            .unwrap();
        sender
            .send(OperationalEvent::Update(
                OperationalValue::new(YangPath::new("/sys:system/sys:uptime").unwrap(), "43")
                    .unwrap(),
            ))
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Some(gnmi::subscribe_response::Response::Update(notification)) = response.response
        else {
            panic!("visible event")
        };
        assert_eq!(notification.delete, Vec::new());
        assert_eq!(notification.update.len(), 1);
        assert_eq!(
            notification.update[0].path,
            Some(
                crate::get::yang_path_to_proto(&YangPath::new("/sys:system/sys:uptime").unwrap())
                    .unwrap()
            )
        );
        assert_eq!(
            notification.update[0].val.as_ref().unwrap().value,
            Some(gnmi::typed_value::Value::JsonIetfVal(b"43".to_vec()))
        );
    }
}
