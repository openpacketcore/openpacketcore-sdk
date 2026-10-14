use super::*;

struct AggregateRegistry(&'static [NodeMeta]);

impl SchemaRegistry for AggregateRegistry {
    fn schema_digest(&self) -> &'static str {
        "operational-aggregate-contracts"
    }
    fn served_models(&self) -> &'static [ModelData] {
        Registry.served_models()
    }
    fn origins(&self) -> &'static [OriginEntry] {
        Registry.origins()
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        self.0
    }
}

fn aggregate_registry(
    container_class: DataClass,
    leaf_class: DataClass,
) -> &'static AggregateRegistry {
    let mut nodes = masked_registry(Some(DataClass::Public), false)
        .nodes
        .to_vec();
    for (parent, children) in [
        (
            "/ex:system",
            &[
                "/ex:system/ex:aggregate",
                "/ex:system/ex:labels",
                "/ex:system/ex:opaque",
            ][..],
        ),
        ("/ex:system/ex:peer", &["/ex:system/ex:peer/ex:state"][..]),
    ] {
        let node = nodes.iter_mut().find(|node| node.path == parent).unwrap();
        let mut paths = node.child_paths.to_vec();
        paths.extend(children);
        paths.sort_unstable();
        node.child_paths = Box::leak(paths.into_boxed_slice());
    }
    nodes.extend([
        NodeMeta {
            kind: NodeKind::List,
            leaf_type: None,
            key_leaves: &["name"],
            child_paths: &[
                "/ex:system/ex:aggregate/ex:name",
                "/ex:system/ex:aggregate/ex:up",
            ],
            ..leaf("/ex:system/ex:aggregate", false, DataClass::Public)
        },
        leaf("/ex:system/ex:aggregate/ex:name", false, DataClass::Public),
        leaf("/ex:system/ex:aggregate/ex:up", false, DataClass::Public),
        NodeMeta {
            kind: NodeKind::LeafList,
            ..leaf("/ex:system/ex:labels", false, DataClass::Public)
        },
        NodeMeta {
            kind: NodeKind::Container,
            leaf_type: None,
            child_paths: &[
                "/ex:system/ex:opaque/ex:hidden",
                "/ex:system/ex:opaque/ex:public",
            ],
            ..leaf("/ex:system/ex:opaque", false, container_class)
        },
        leaf("/ex:system/ex:opaque/ex:hidden", false, leaf_class),
        leaf("/ex:system/ex:opaque/ex:public", false, DataClass::Public),
        NodeMeta {
            kind: NodeKind::Container,
            leaf_type: None,
            child_paths: &["/ex:system/ex:peer/ex:state/ex:seen"],
            ..leaf("/ex:system/ex:peer/ex:state", false, DataClass::Public)
        },
        leaf(
            "/ex:system/ex:peer/ex:state/ex:seen",
            false,
            DataClass::Public,
        ),
    ]);
    nodes.sort_unstable_by_key(|node| node.path);
    let registry = Box::leak(Box::new(AggregateRegistry(Box::leak(
        nodes.into_boxed_slice(),
    ))));
    registry.self_check().unwrap();
    registry
}

fn wire_path(path: &str) -> gnmi::Path {
    gnmi::Path {
        elem: opc_mgmt_path::CanonicalPath::parse(path)
            .unwrap()
            .segments()
            .iter()
            .map(|segment| gnmi::PathElem {
                name: segment.name.into(),
                key: segment
                    .keys
                    .iter()
                    .map(|(key, value)| ((*key).into(), (*value).into()))
                    .collect(),
            })
            .collect(),
        ..Default::default()
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadMode {
    Get,
    Once,
    Sample,
    Event,
}

fn list(mode: ReadMode, paths: &[gnmi::Path]) -> gnmi::SubscriptionList {
    let mut list = subscription(paths[0].clone());
    list.subscription = paths
        .iter()
        .map(|path| gnmi::Subscription {
            path: Some(path.clone()),
            mode: if matches!(mode, ReadMode::Sample) {
                gnmi::SubscriptionMode::Sample
            } else {
                gnmi::SubscriptionMode::OnChange
            } as i32,
            sample_interval: 100_000_000,
            ..Default::default()
        })
        .collect();
    list.updates_only = matches!(mode, ReadMode::Event);
    if matches!(mode, ReadMode::Once) {
        list.mode = gnmi::subscription_list::Mode::Once as i32;
    }
    list
}

async fn exact_contract(mode: ReadMode, primary: &str, json: &str) {
    let registry = aggregate_registry(DataClass::Public, DataClass::Public);
    for (path, json) in [
        (primary, json),
        (
            "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:child",
            r#"[{"slot":"1","up":"nested-marker"}]"#,
        ),
        ("/ex:system/ex:labels", r#"["first","second"]"#),
    ] {
        let reported = value(path, json);
        if matches!(mode, ReadMode::Get) {
            let (service, binding, _) = fixture_with_registry(
                vec![reported],
                vec![policy(&["/ex:system", "/ex:system/**"])],
                MgmtLimits::default(),
                registry,
            )
            .await;
            let response = service
                .get(get(vec![wire_path(path)], None))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                decoded(response),
                vec![(wire_path(path).elem, json.as_bytes().to_vec())]
            );
            assert!(binding.provider.requests.lock().unwrap()[0]
                .paths
                .contains(&YangPath::new(path).unwrap()));
            continue;
        }
        let values = if matches!(mode, ReadMode::Event) {
            vec![]
        } else {
            vec![reported.clone()]
        };
        let (service, binding, sender) = subscription_fixture_with_registry(
            values,
            policy(&["/ex:system", "/ex:system/**"]),
            MgmtLimits::default(),
            registry,
        )
        .await;
        let mut stream = service
            .subscribe(open_requests(list(mode, &[wire_path(path)]), false))
            .await
            .unwrap()
            .into_inner();
        if matches!(mode, ReadMode::Event) {
            sync(stream.next().await.unwrap().unwrap());
            sender
                .send(OperationalEvent::Update(reported))
                .await
                .unwrap();
        }
        let data = notification(
            tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        );
        assert_eq!(data.update.len(), 1);
        assert_eq!(
            data.update[0].path.as_ref().unwrap().elem,
            wire_path(path).elem
        );
        assert_eq!(
            data.update[0].val.as_ref().unwrap().value,
            Some(gnmi::typed_value::Value::JsonIetfVal(
                json.as_bytes().to_vec()
            ))
        );
        assert!(data.delete.is_empty());
        if !matches!(mode, ReadMode::Event) {
            sync(stream.next().await.unwrap().unwrap());
            assert!(binding.inner.provider.requests.lock().unwrap()[0]
                .paths
                .contains(&YangPath::new(path).unwrap()));
        }
        if matches!(mode, ReadMode::Once) {
            assert!(stream.next().await.is_none());
        }
    }
}

const LIST_PATH: &str = "/ex:system/ex:aggregate";
const LIST_JSON: &str = r#"[{"name":"row-marker","up":"true"}]"#;
const CONTAINER_PATH: &str = "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:state";
const CONTAINER_JSON: &str = r#"{"seen":"aggregate-marker"}"#;

#[tokio::test]
async fn exact_list_aggregate_get_preserves_encoding() {
    exact_contract(ReadMode::Get, LIST_PATH, LIST_JSON).await;
}
#[tokio::test]
async fn exact_keyed_container_get_preserves_encoding() {
    exact_contract(ReadMode::Get, CONTAINER_PATH, CONTAINER_JSON).await;
}
#[tokio::test]
async fn exact_list_aggregate_once_preserves_encoding() {
    exact_contract(ReadMode::Once, LIST_PATH, LIST_JSON).await;
}
#[tokio::test]
async fn exact_keyed_container_once_preserves_encoding() {
    exact_contract(ReadMode::Once, CONTAINER_PATH, CONTAINER_JSON).await;
}
#[tokio::test]
async fn exact_list_aggregate_sample_preserves_encoding() {
    exact_contract(ReadMode::Sample, LIST_PATH, LIST_JSON).await;
}
#[tokio::test]
async fn exact_keyed_container_sample_preserves_encoding() {
    exact_contract(ReadMode::Sample, CONTAINER_PATH, CONTAINER_JSON).await;
}
#[tokio::test]
async fn exact_list_aggregate_event_preserves_encoding() {
    exact_contract(ReadMode::Event, LIST_PATH, LIST_JSON).await;
}
#[tokio::test]
async fn exact_keyed_container_event_preserves_encoding() {
    exact_contract(ReadMode::Event, CONTAINER_PATH, CONTAINER_JSON).await;
}

async fn key_class_refusal(
    mode: ReadMode,
    registry: &'static dyn SchemaRegistry,
    secret_name: bool,
) {
    let reported = masked_instance(secret_name, false);
    let path = selection(&[], "up");
    let (error, audit) = if matches!(mode, ReadMode::Get) {
        let (service, _, audit) = fixture_with_registry(
            vec![reported],
            vec![policy(&["/ex:system/**"])],
            MgmtLimits::default(),
            registry,
        )
        .await;
        (service.get(get(vec![path], None)).await.unwrap_err(), audit)
    } else {
        let values = if matches!(mode, ReadMode::Event) {
            vec![]
        } else {
            vec![reported.clone()]
        };
        let (service, binding, sender) = subscription_fixture_with_registry(
            values,
            policy(&["/ex:system/**"]),
            MgmtLimits::default(),
            registry,
        )
        .await;
        let mut stream = service
            .subscribe(open_requests(list(mode, &[path]), false))
            .await
            .unwrap()
            .into_inner();
        if matches!(mode, ReadMode::Event) {
            sync(stream.next().await.unwrap().unwrap());
            sender
                .send(OperationalEvent::Update(reported))
                .await
                .unwrap();
        }
        let error = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        (error, binding.audit.clone())
    };
    assert_eq!(error.code(), Code::Internal, "{mode:?}");
    assert_eq!(error.message(), "gNMI internal error", "{mode:?}");
    assert!(!format!("{error:?} {:?}", audit.0.lock().unwrap()).contains("correct-marker"));
}

async fn denied_key_is_omitted(
    mode: ReadMode,
    registry: &'static dyn SchemaRegistry,
    secret_name: bool,
) {
    let hidden = masked_instance(secret_name, false);
    let visible = value("/ex:system/ex:visible", "true");
    let permissions = policy(&[
        "/ex:system/ex:peer/ex:site",
        "/ex:system/ex:peer/ex:up",
        "/ex:system/ex:visible",
    ]);
    let paths = [selection(&[], "up"), wire_path("/ex:system/ex:visible")];
    if matches!(mode, ReadMode::Get) {
        let (service, binding, audit) = fixture_with_registry(
            vec![hidden, visible],
            vec![permissions],
            MgmtLimits::default(),
            registry,
        )
        .await;
        let response = service
            .get(get(paths.to_vec(), None))
            .await
            .unwrap()
            .into_inner();
        assert!(!format!("{response:?} {:?}", audit.0.lock().unwrap()).contains("correct-marker"));
        assert_eq!(
            decoded(response),
            vec![(paths[1].elem.clone(), b"true".to_vec())]
        );
        assert!(binding.provider.requests.lock().unwrap()[0]
            .paths
            .iter()
            .all(|path| path.as_str() != "/ex:system/ex:peer/ex:up"));
        return;
    }
    let values = if matches!(mode, ReadMode::Event) {
        vec![]
    } else {
        vec![hidden.clone(), visible.clone()]
    };
    let (service, binding, sender) =
        subscription_fixture_with_registry(values, permissions, MgmtLimits::default(), registry)
            .await;
    let mut stream = service
        .subscribe(open_requests(list(mode, &paths), false))
        .await
        .unwrap()
        .into_inner();
    if matches!(mode, ReadMode::Event) {
        sync(stream.next().await.unwrap().unwrap());
        sender.send(OperationalEvent::Update(hidden)).await.unwrap();
        sender
            .send(OperationalEvent::Update(visible))
            .await
            .unwrap();
    }
    let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        !format!("{response:?} {:?}", binding.audit.0.lock().unwrap()).contains("correct-marker")
    );
    let data = notification(response);
    assert_eq!(data.update.len(), 1);
    assert_eq!(data.update[0].path.as_ref().unwrap().elem, paths[1].elem);
    assert_eq!(
        data.update[0].val.as_ref().unwrap().value,
        Some(gnmi::typed_value::Value::JsonIetfVal(b"true".to_vec()))
    );
    assert!(data.delete.is_empty());
    if !matches!(mode, ReadMode::Event) {
        sync(stream.next().await.unwrap().unwrap());
    }
    if matches!(mode, ReadMode::Once) {
        assert!(stream.next().await.is_none());
    }
}

#[tokio::test]
async fn operational_non_cleartext_key_class_is_refused() {
    for (class, secret_name) in [
        (DataClass::SecuritySecret, false),
        (DataClass::LawfulIntercept, false),
        (DataClass::Public, true),
    ] {
        let registry = masked_registry(Some(class), secret_name);
        for mode in [
            ReadMode::Get,
            ReadMode::Once,
            ReadMode::Sample,
            ReadMode::Event,
        ] {
            key_class_refusal(mode, registry, secret_name).await;
            denied_key_is_omitted(mode, registry, secret_name).await;
        }
    }
}

async fn opaque_class_is_pruned(mode: ReadMode) {
    for (container_class, leaf_class) in [
        (DataClass::Public, DataClass::SecuritySecret),
        (DataClass::Public, DataClass::LawfulIntercept),
        (DataClass::SecuritySecret, DataClass::Public),
        (DataClass::LawfulIntercept, DataClass::Public),
    ] {
        let registry = aggregate_registry(container_class, leaf_class);
        let opaque = value(
            "/ex:system/ex:opaque",
            r#"{"hidden":"hidden-value-marker","public":"public-value-marker"}"#,
        );
        let visible = value("/ex:system/ex:visible", "true");
        let paths = [
            wire_path("/ex:system/ex:opaque"),
            wire_path("/ex:system/ex:visible"),
        ];
        if matches!(mode, ReadMode::Get) {
            let (service, binding, audit) = fixture_with_registry(
                vec![opaque, visible],
                vec![policy(&["/ex:system", "/ex:system/**"])],
                MgmtLimits::default(),
                registry,
            )
            .await;
            let response = service
                .get(get(paths.to_vec(), None))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                decoded(response.clone()),
                vec![(paths[1].elem.clone(), b"true".to_vec())]
            );
            assert!(binding
                .provider
                .requests
                .lock()
                .unwrap()
                .iter()
                .flat_map(|request| &request.paths)
                .all(|path| path.as_str() != "/ex:system/ex:opaque"));
            assert!(!format!("{response:?} {:?}", audit.0.lock().unwrap()).contains("value-marker"));
        } else {
            let (service, binding, sender) = subscription_fixture_with_registry(
                vec![],
                policy(&["/ex:system", "/ex:system/**"]),
                MgmtLimits::default(),
                registry,
            )
            .await;
            let mut stream = service
                .subscribe(open_requests(list(mode, &paths), false))
                .await
                .unwrap()
                .into_inner();
            sync(stream.next().await.unwrap().unwrap());
            sender.send(OperationalEvent::Update(opaque)).await.unwrap();
            sender
                .send(OperationalEvent::Update(visible))
                .await
                .unwrap();
            let response = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(
                !format!("{response:?} {:?}", binding.audit.0.lock().unwrap())
                    .contains("value-marker")
            );
            let data = notification(response);
            assert_eq!(data.update.len(), 1);
            assert_eq!(data.update[0].path.as_ref().unwrap().elem, paths[1].elem);
            assert_eq!(
                data.update[0].val.as_ref().unwrap().value,
                Some(gnmi::typed_value::Value::JsonIetfVal(b"true".to_vec()))
            );
            assert!(data.delete.is_empty());
            assert!(binding.events.requests.lock().unwrap()[0]
                .paths
                .iter()
                .all(|path| path.as_str() != "/ex:system/ex:opaque"));
        }
    }
}

#[tokio::test]
async fn get_prunes_opaque_aggregates_with_non_cleartext_data_before_provider_access() {
    opaque_class_is_pruned(ReadMode::Get).await;
}

#[tokio::test]
async fn events_prune_opaque_aggregates_with_non_cleartext_data() {
    opaque_class_is_pruned(ReadMode::Event).await;
}

#[derive(Clone)]
struct MatchingProbe {
    inner: Binding,
    allocations: Arc<AtomicUsize>,
}

impl GnmiConfigBinding<()> for MatchingProbe {
    fn config_bus(&self) -> Arc<ConfigBus<()>> {
        self.inner.config_bus()
    }
    fn schema(&self) -> &'static dyn SchemaRegistry {
        self.inner.schema()
    }
    fn patcher(&self) -> Arc<dyn GnmiPatchApplicator<()>> {
        self.inner.patcher()
    }
    fn operational_state(&self) -> Arc<dyn OperationalStateProvider> {
        self.inner.operational_state()
    }
    fn policy_source(&self) -> Arc<dyn PolicySource> {
        self.inner.policy_source()
    }
    fn render_running_json(
        &self,
        config: &(),
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        self.inner.render_running_json(config, selection)
    }
    fn render_get_json(
        &self,
        config: &(),
        config_selection: ReadSelection<'_>,
        operational: &OperationalResponse,
        selection: ReadSelection<'_>,
    ) -> Result<Vec<GnmiJsonUpdate>, GnmiJsonProjectionError> {
        let stats = allocation_counter::measure(|| {
            for value in &operational.values {
                assert!(selection.contains_reported_path(value.path()));
            }
        });
        self.allocations
            .store(stats.count_total as usize, Ordering::SeqCst);
        self.inner
            .render_get_json(config, config_selection, operational, selection)
    }
}

#[tokio::test]
async fn operational_render_selection_reuses_validated_matches_without_allocating() {
    let (_, inner, audit) = fixture(
        (0..64)
            .map(|index| peer(&format!("row-{index:04}"), "up", "true"))
            .collect(),
        vec![policy(&["/ex:system/**"])],
        MgmtLimits::default(),
    )
    .await;
    let binding = MatchingProbe {
        inner,
        allocations: Arc::new(AtomicUsize::new(usize::MAX)),
    };
    let service = GnmiService::new(
        GnmiServer::new_with_audit(
            binding.clone(),
            MgmtLimits::default(),
            CapabilityProfile::json_only(GnmiVersion::new(GNMI_VERSION).unwrap()),
            ExtensionRegistry::default(),
            audit,
        )
        .unwrap(),
    );
    let response = service
        .get(get(vec![selection(&[], "up")], None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(decoded(response).len(), 64);
    assert_eq!(
        binding.allocations.load(Ordering::SeqCst),
        0,
        "validated render selection must not parse paths again"
    );
}

struct ClassificationRegistry {
    inner: &'static AggregateRegistry,
    path: &'static str,
    class: Option<DataClass>,
    hidden_class: DataClass,
}

impl SchemaRegistry for ClassificationRegistry {
    fn schema_digest(&self) -> &'static str {
        self.inner.schema_digest()
    }
    fn served_models(&self) -> &'static [ModelData] {
        self.inner.served_models()
    }
    fn origins(&self) -> &'static [OriginEntry] {
        self.inner.origins()
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        self.inner.nodes()
    }
    fn data_class(&self, path: &str) -> Option<DataClass> {
        if path == self.path {
            self.class
        } else if path == HIDDEN_PATH {
            Some(self.hidden_class)
        } else {
            self.inner.data_class(path)
        }
    }
}

fn classification_registry(
    path: &'static str,
    class: Option<DataClass>,
    hidden_class: DataClass,
) -> &'static ClassificationRegistry {
    let registry = Box::leak(Box::new(ClassificationRegistry {
        inner: aggregate_registry(DataClass::Public, DataClass::Public),
        path,
        class,
        hidden_class,
    }));
    assert_eq!(registry.node(path).unwrap().data_class, DataClass::Public);
    assert_eq!(
        registry.node(HIDDEN_PATH).unwrap().data_class,
        DataClass::Public
    );
    assert_eq!(registry.data_class(path), class);
    assert_eq!(
        registry.data_class(HIDDEN_PATH),
        if path == HIDDEN_PATH {
            class
        } else {
            Some(hidden_class)
        }
    );
    registry
}

const OPAQUE_PATH: &str = "/ex:system/ex:opaque";
const HIDDEN_PATH: &str = "/ex:system/ex:opaque/ex:hidden";
const PUBLIC_PATH: &str = "/ex:system/ex:opaque/ex:public";
const VISIBLE_PATH: &str = "/ex:system/ex:visible";
const OPAQUE_JSON: &str = r#"{"hidden":"protected-marker","public":"public"}"#;

async fn registry_classification_masks_leaf(class: Option<DataClass>) {
    let registry = classification_registry(HIDDEN_PATH, class, DataClass::SecuritySecret);
    let (service, binding, _) = fixture_with_registry(
        vec![value(HIDDEN_PATH, r#""protected-marker""#)],
        vec![policy(&["/ex:system", "/ex:system/**"])],
        MgmtLimits::default(),
        registry,
    )
    .await;
    let response = service
        .get(get(vec![wire_path(HIDDEN_PATH)], None))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        decoded(response),
        vec![(wire_path(HIDDEN_PATH).elem, br#""<redacted>""#.to_vec())]
    );
    assert_eq!(
        binding.provider.requests.lock().unwrap()[0].paths,
        vec![YangPath::new(HIDDEN_PATH).unwrap()]
    );
}

#[tokio::test]
async fn registry_classification_masks_overridden_leaf() {
    registry_classification_masks_leaf(Some(DataClass::SecuritySecret)).await;
}

#[tokio::test]
async fn registry_classification_masks_unclassified_leaf() {
    registry_classification_masks_leaf(None).await;
}

async fn registry_classification_prunes_get(
    path: &'static str,
    class: Option<DataClass>,
    hidden_class: DataClass,
) {
    let registry = classification_registry(path, class, hidden_class);
    let (service, binding, _) = fixture_with_registry(
        vec![
            value(OPAQUE_PATH, OPAQUE_JSON),
            value(HIDDEN_PATH, r#""protected-marker""#),
            value(PUBLIC_PATH, r#""public""#),
            value(VISIBLE_PATH, "true"),
        ],
        vec![policy(&["/ex:system", "/ex:system/**"])],
        MgmtLimits::default(),
        registry,
    )
    .await;
    let response = service
        .get(get(
            vec![wire_path(OPAQUE_PATH), wire_path(VISIBLE_PATH)],
            None,
        ))
        .await
        .unwrap()
        .into_inner();
    let hidden_json = if hidden_class == DataClass::Public {
        br#""protected-marker""#.to_vec()
    } else {
        br#""<redacted>""#.to_vec()
    };
    assert_eq!(
        decoded(response),
        vec![
            (wire_path(HIDDEN_PATH).elem, hidden_json),
            (wire_path(PUBLIC_PATH).elem, br#""public""#.to_vec()),
            (wire_path(VISIBLE_PATH).elem, b"true".to_vec()),
        ]
    );
    let requests = binding.provider.requests.lock().unwrap();
    assert!(!requests.is_empty());
    for request in requests.iter() {
        assert_eq!(
            request.paths,
            vec![
                YangPath::new(HIDDEN_PATH).unwrap(),
                YangPath::new(PUBLIC_PATH).unwrap(),
                YangPath::new(VISIBLE_PATH).unwrap(),
            ]
        );
    }
}

#[tokio::test]
async fn registry_classification_get_prunes_overridden_descendant() {
    registry_classification_prunes_get(
        HIDDEN_PATH,
        Some(DataClass::SecuritySecret),
        DataClass::SecuritySecret,
    )
    .await;
}

#[tokio::test]
async fn registry_classification_get_prunes_unclassified_descendant() {
    registry_classification_prunes_get(HIDDEN_PATH, None, DataClass::SecuritySecret).await;
}

#[tokio::test]
async fn registry_classification_get_prunes_overridden_aggregate() {
    registry_classification_prunes_get(
        OPAQUE_PATH,
        Some(DataClass::SecuritySecret),
        DataClass::SecuritySecret,
    )
    .await;
}

#[tokio::test]
async fn registry_classification_get_prunes_unclassified_aggregate() {
    registry_classification_prunes_get(OPAQUE_PATH, None, DataClass::SecuritySecret).await;
}

#[tokio::test]
async fn registry_classification_get_refuses_aggregate_with_public_descendants() {
    // Isolate the aggregate's own check: no descendant classification can refuse it.
    for class in [Some(DataClass::SecuritySecret), None] {
        registry_classification_prunes_get(OPAQUE_PATH, class, DataClass::Public).await;
    }
}

async fn registry_classification_prunes_event(
    path: &'static str,
    class: Option<DataClass>,
    hidden_class: DataClass,
) {
    let registry = classification_registry(path, class, hidden_class);
    let (service, binding, sender) = subscription_fixture_with_registry(
        vec![],
        policy(&["/ex:system", "/ex:system/**"]),
        MgmtLimits::default(),
        registry,
    )
    .await;
    let mut stream = service
        .subscribe(open_requests(
            list(
                ReadMode::Event,
                &[wire_path(OPAQUE_PATH), wire_path(VISIBLE_PATH)],
            ),
            false,
        ))
        .await
        .unwrap()
        .into_inner();
    sync(stream.next().await.unwrap().unwrap());
    sender
        .send(OperationalEvent::Update(value(OPAQUE_PATH, OPAQUE_JSON)))
        .await
        .unwrap();
    sender
        .send(OperationalEvent::Update(value(
            HIDDEN_PATH,
            r#""protected-marker""#,
        )))
        .await
        .unwrap();
    sender
        .send(OperationalEvent::Update(value(PUBLIC_PATH, r#""public""#)))
        .await
        .unwrap();
    sender
        .send(OperationalEvent::Update(value(VISIBLE_PATH, "true")))
        .await
        .unwrap();
    let hidden_json = if hidden_class == DataClass::Public {
        br#""protected-marker""#.to_vec()
    } else {
        br#""<redacted>""#.to_vec()
    };
    for (path, json) in [
        (HIDDEN_PATH, hidden_json),
        (PUBLIC_PATH, br#""public""#.to_vec()),
        (VISIBLE_PATH, b"true".to_vec()),
    ] {
        let data = notification(
            tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        );
        assert_eq!(data.update.len(), 1);
        assert_eq!(
            data.update[0].path.as_ref().unwrap().elem,
            wire_path(path).elem
        );
        assert_eq!(
            data.update[0].val.as_ref().unwrap().value,
            Some(gnmi::typed_value::Value::JsonIetfVal(json))
        );
        assert!(data.delete.is_empty());
    }
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(
            stream.as_mut().poll_next(cx).is_pending()
        ))
        .await
    );
    let requests = binding.events.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].paths,
        vec![
            YangPath::new(HIDDEN_PATH).unwrap(),
            YangPath::new(PUBLIC_PATH).unwrap(),
            YangPath::new(VISIBLE_PATH).unwrap(),
        ]
    );
}

#[tokio::test]
async fn registry_classification_event_prunes_overridden_descendant() {
    registry_classification_prunes_event(
        HIDDEN_PATH,
        Some(DataClass::SecuritySecret),
        DataClass::SecuritySecret,
    )
    .await;
}

#[tokio::test]
async fn registry_classification_event_prunes_unclassified_descendant() {
    registry_classification_prunes_event(HIDDEN_PATH, None, DataClass::SecuritySecret).await;
}

#[tokio::test]
async fn registry_classification_event_prunes_overridden_aggregate() {
    registry_classification_prunes_event(
        OPAQUE_PATH,
        Some(DataClass::SecuritySecret),
        DataClass::SecuritySecret,
    )
    .await;
}

#[tokio::test]
async fn registry_classification_event_prunes_unclassified_aggregate() {
    registry_classification_prunes_event(OPAQUE_PATH, None, DataClass::SecuritySecret).await;
}

#[tokio::test]
async fn registry_classification_event_refuses_aggregate_with_public_descendants() {
    // Isolate the aggregate's own check: no descendant classification can refuse it.
    for class in [Some(DataClass::SecuritySecret), None] {
        registry_classification_prunes_event(OPAQUE_PATH, class, DataClass::Public).await;
    }
}
