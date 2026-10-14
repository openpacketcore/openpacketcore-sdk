use super::*;

struct CompatibilityRegistry(&'static [NodeMeta]);

impl SchemaRegistry for CompatibilityRegistry {
    fn schema_digest(&self) -> &'static str {
        "operational-read-compatibility"
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

fn registry() -> &'static CompatibilityRegistry {
    let mut nodes = masked_registry(Some(DataClass::Public), false)
        .nodes
        .to_vec();
    for (parent, children) in [
        (
            "/ex:system",
            &[
                "/ex:system/ex:aggregate",
                "/ex:system/ex:labels",
                "/ex:system/ex:nested",
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
            child_paths: &["/ex:system/ex:nested/ex:up"],
            ..leaf("/ex:system/ex:nested", false, DataClass::Public)
        },
        leaf("/ex:system/ex:nested/ex:up", false, DataClass::Public),
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
    let registry = Box::leak(Box::new(CompatibilityRegistry(Box::leak(
        nodes.into_boxed_slice(),
    ))));
    registry.self_check().unwrap();
    registry
}

async fn whitespace_selection(nmda: bool, empty: &str, formatted: &str) {
    let operation = if nmda { get_data } else { get };
    let namespace = if nmda {
        "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"
    } else {
        "urn:ietf:params:xml:ns:netconf:base:1.0"
    };
    let (server, binding, _, _) = fixture_with_registry(
        vec![
            peer("east", "a", "up", "true"),
            peer("east", "  a  ", "up", "false"),
            value("/ex:system/ex:nested/ex:up", "true"),
            value("/ex:system/ex:visible", "true"),
        ],
        vec![policy(&["/ex:system", "/ex:system/**"])],
        registry(),
    )
    .await;
    let expected = data(
        &rpc(&server, &operation(empty), &MgmtLimits::default()),
        namespace,
    );
    assert!(!expected.is_empty());
    let actual = data(
        &rpc(&server, &operation(formatted), &MgmtLimits::default()),
        namespace,
    );
    assert_eq!(actual, expected);
    let requests = binding.provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].paths, requests[1].paths);
    drop(requests);

    // A nonempty literal keeps every space; only whitespace-only content is absent.
    let literal = rpc(
        &server,
        &operation(r#"<system xmlns="urn:example"><peer><name>  a  </name><up/></peer></system>"#),
        &MgmtLimits::default(),
    );
    assert_eq!(
        data(&literal, namespace),
        vec![element(
            "system",
            "",
            vec![peer_xml("east", "  a  ", "up", "false")]
        )]
    );
}

#[tokio::test]
async fn get_ignores_whitespace_only_root_filter() {
    whitespace_selection(
        false,
        r#"<system xmlns="urn:example"/>"#,
        "<system xmlns=\"urn:example\">\n  </system>",
    )
    .await;
}

#[tokio::test]
async fn get_data_ignores_whitespace_only_root_filter() {
    whitespace_selection(
        true,
        r#"<system xmlns="urn:example"/>"#,
        "<system xmlns=\"urn:example\">\n  </system>",
    )
    .await;
}

#[tokio::test]
async fn get_ignores_whitespace_only_container_filter() {
    whitespace_selection(
        false,
        r#"<system xmlns="urn:example"><nested/></system>"#,
        "<system xmlns=\"urn:example\"><nested>\n  </nested></system>",
    )
    .await;
}

#[tokio::test]
async fn get_data_ignores_whitespace_only_container_filter() {
    whitespace_selection(
        true,
        r#"<system xmlns="urn:example"><nested/></system>"#,
        "<system xmlns=\"urn:example\"><nested>\n  </nested></system>",
    )
    .await;
}

#[tokio::test]
async fn get_ignores_whitespace_only_key_filter() {
    whitespace_selection(
        false,
        r#"<system xmlns="urn:example"><peer><name/><up/></peer></system>"#,
        "<system xmlns=\"urn:example\"><peer><name>\n  </name><up/></peer></system>",
    )
    .await;
}

#[tokio::test]
async fn get_data_ignores_whitespace_only_key_filter() {
    whitespace_selection(
        true,
        r#"<system xmlns="urn:example"><peer><name/><up/></peer></system>"#,
        "<system xmlns=\"urn:example\"><peer><name>\n  </name><up/></peer></system>",
    )
    .await;
}

async fn unkeyed_non_leaf(nmda: bool, node: &str, json: &str) {
    let operation = if nmda { get_data } else { get };
    let namespace = if nmda {
        "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"
    } else {
        "urn:ietf:params:xml:ns:netconf:base:1.0"
    };
    let path = format!("/ex:system/ex:{node}");
    let (server, binding, _, _) = fixture_with_registry(
        vec![value(&path, json), value("/ex:system/ex:visible", "true")],
        vec![policy(&["/ex:system", "/ex:system/**"])],
        registry(),
    )
    .await;
    let reply = rpc(
        &server,
        &operation(&format!(
            "<system xmlns=\"urn:example\"><{node}/><visible/></system>"
        )),
        &MgmtLimits::default(),
    );
    assert_eq!(
        data(&reply, namespace),
        vec![element(
            "system",
            "",
            vec![element("visible", "true", vec![])]
        )]
    );
    assert!(binding.provider.requests.lock().unwrap()[0]
        .paths
        .contains(&YangPath::new(&path).unwrap()));
    assert!(!reply.contains("aggregate-marker"));

    // The scalar NETCONF projector still refuses a non-leaf carrying list keys.
    let (server, binding, _, audit) = fixture_with_registry(
        vec![value(
            "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:state",
            r#"{"seen":"aggregate-marker"}"#,
        )],
        vec![policy(&["/ex:system", "/ex:system/**"])],
        registry(),
    )
    .await;
    let reply = rpc(
        &server,
        &operation(
            r#"<system xmlns="urn:example"><peer><site>east</site><name>a</name><state/></peer></system>"#,
        ),
        &MgmtLimits::default(),
    );
    assert!(
        reply.contains("<error-tag>operation-failed</error-tag>"),
        "{reply}"
    );
    assert!(!reply.contains("<data"));
    assert_eq!(binding.provider.requests.lock().unwrap().len(), 1);
    assert!(!format!("{reply} {:?}", audit.0.lock().unwrap()).contains("aggregate-marker"));
}

#[tokio::test]
async fn get_skips_exact_unkeyed_list_aggregate() {
    unkeyed_non_leaf(
        false,
        "aggregate",
        r#"[{"name":"aggregate-marker","up":"true"}]"#,
    )
    .await;
}

#[tokio::test]
async fn get_data_skips_exact_unkeyed_list_aggregate() {
    unkeyed_non_leaf(
        true,
        "aggregate",
        r#"[{"name":"aggregate-marker","up":"true"}]"#,
    )
    .await;
}

#[tokio::test]
async fn get_skips_unkeyed_container_aggregate() {
    unkeyed_non_leaf(false, "nested", r#"{"up":"aggregate-marker"}"#).await;
}

#[tokio::test]
async fn get_data_skips_unkeyed_container_aggregate() {
    unkeyed_non_leaf(true, "nested", r#"{"up":"aggregate-marker"}"#).await;
}

#[tokio::test]
async fn get_skips_state_leaf_list() {
    unkeyed_non_leaf(false, "labels", r#"["aggregate-marker"]"#).await;
}

#[tokio::test]
async fn get_data_skips_state_leaf_list() {
    unkeyed_non_leaf(true, "labels", r#"["aggregate-marker"]"#).await;
}
