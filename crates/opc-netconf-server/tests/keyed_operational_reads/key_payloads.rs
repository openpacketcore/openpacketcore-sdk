use super::*;

const KEY_PATH: &str =
    "/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:child[ex:slot='1']/ex:slot";
const KEY_SCHEMA: &str = "/ex:system/ex:peer/ex:child/ex:slot";
const VISIBLE_SCHEMA: &str = "/ex:system/ex:visible";
const FILTER: &str =
    r#"<system xmlns="urn:example"><visible/><peer><child><slot/></child></peer></system>"#;

fn mixed_values(payload: &str) -> Vec<OperationalValue> {
    vec![
        value(VISIBLE_SCHEMA, r#""visible-value""#),
        value(KEY_PATH, payload),
    ]
}

fn expected_data(key: &str, visible: bool) -> Vec<Element> {
    let mut children = vec![element(
        "peer",
        "",
        vec![
            element("site", "east", vec![]),
            element("name", "a", vec![]),
            element("child", "", vec![element("slot", key, vec![])]),
        ],
    )];
    if visible {
        children.push(element("visible", "visible-value", vec![]));
    }
    vec![element("system", "", children)]
}

async fn assert_custom_rejection(operation: fn(&str) -> String, invalid: &str) {
    let registry = masked_registry(Some(DataClass::Public), false);
    for (payload, valid) in [(r#""1""#, true), (invalid, false)] {
        let (_, binding, source, audit) = fixture_with_registry(
            mixed_values(payload),
            vec![policy(&["/ex:system", "/ex:system/**"])],
            registry,
        )
        .await;
        let server = ReadOnlyNetconfServer::new(
            ProjectionProbe(binding.clone()),
            source.clone(),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .unwrap();
        let reply = rpc(&server, &operation(FILTER), &MgmtLimits::default());
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
            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
            assert!(!reply.contains("<data"));
            assert!(!reply.contains("visible-value"));
            assert!(!format!("{reply} {:?}", audit.0.lock().unwrap()).contains("marker"));
        }
    }
}

#[tokio::test]
async fn get_rejects_key_payload_mismatch_before_custom_projection() {
    assert_custom_rejection(get, r#""mismatch-marker""#).await;
}

#[tokio::test]
async fn get_data_rejects_key_payload_mismatch_before_custom_projection() {
    assert_custom_rejection(get_data, r#""mismatch-marker""#).await;
}

async fn assert_default_null_rejection(operation: fn(&str) -> String, namespace: &str) {
    let registry = masked_registry(Some(DataClass::Public), false);
    for (payload, valid) in [(r#""1""#, true), ("null", false)] {
        let (server, binding, source, audit) = fixture_with_registry(
            mixed_values(payload),
            vec![policy(&["/ex:system", "/ex:system/**"])],
            registry,
        )
        .await;
        let reply = rpc(&server, &operation(FILTER), &MgmtLimits::default());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        assert_eq!(binding.provider.requests.lock().unwrap().len(), 1);
        if valid {
            assert_eq!(data(&reply, namespace), expected_data("1", true));
        } else {
            assert!(
                reply.contains("<error-tag>operation-failed</error-tag>"),
                "{reply}"
            );
            assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
            assert!(!reply.contains("<data"));
            assert!(!reply.contains("visible-value"));
            assert!(!format!("{reply} {:?}", audit.0.lock().unwrap()).contains("marker"));
        }
    }
}

#[tokio::test]
async fn get_rejects_null_key_payload_before_default_projection() {
    assert_default_null_rejection(get, "urn:ietf:params:xml:ns:netconf:base:1.0").await;
}

#[tokio::test]
async fn get_data_rejects_null_key_payload_before_default_projection() {
    assert_default_null_rejection(get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda").await;
}

#[tokio::test]
async fn custom_projection_rejects_non_scalar_declared_key_payloads() {
    for operation in [get, get_data] {
        for payload in ["null", "[1]", r#"{"slot":"1"}"#] {
            assert_custom_rejection(operation, payload).await;
        }
    }
}

#[test]
fn generic_projection_checks_reported_keys_before_null_omission() {
    let registry = masked_registry(Some(DataClass::Public), false);
    for (payload, valid) in [
        (r#""1""#, true),
        ("1", true),
        ("null", false),
        ("[1]", false),
        (r#"{"slot":"1"}"#, false),
        (r#""mismatch-marker""#, false),
    ] {
        let result = opc_netconf_server::binding::render_operational_xml(
            registry,
            &[KEY_SCHEMA, VISIBLE_SCHEMA],
            &OperationalResponse::new(mixed_values(payload)),
        );
        if valid {
            let xml = result.unwrap();
            let reply =
                format!(r#"<data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">{xml}</data>"#);
            let mut expected = expected_data("1", true);
            // Direct projection retains the response order; RPC reads sort it first.
            expected[0].children.swap(0, 1);
            assert_eq!(
                data(&reply, "urn:ietf:params:xml:ns:netconf:base:1.0"),
                expected
            );
        } else {
            let error = result.unwrap_err();
            assert!(!format!("{error} {error:?}").contains("marker"));
        }
    }
}

#[tokio::test]
async fn non_key_null_omission_preserves_matching_key_and_valid_response() {
    let registry = masked_registry(Some(DataClass::Public), false);
    for (operation, namespace) in [
        (
            get as fn(&str) -> String,
            "urn:ietf:params:xml:ns:netconf:base:1.0",
        ),
        (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
    ] {
        let (server, _, _, _) = fixture_with_registry(
            vec![value(VISIBLE_SCHEMA, "null"), value(KEY_PATH, r#""1""#)],
            vec![policy(&["/ex:system", "/ex:system/**"])],
            registry,
        )
        .await;
        let reply = rpc(&server, &operation(FILTER), &MgmtLimits::default());
        assert_eq!(data(&reply, namespace), expected_data("1", false));
    }
}

#[tokio::test]
async fn declared_key_payload_uses_real_identity_before_masking() {
    let mut nodes = masked_registry(Some(DataClass::Public), false)
        .nodes
        .to_vec();
    nodes
        .iter_mut()
        .find(|node| node.path == KEY_SCHEMA)
        .unwrap()
        .data_class = DataClass::SecuritySecret;
    let registry = Box::leak(Box::new(MaskedRegistry {
        nodes: Box::leak(nodes.into_boxed_slice()),
        key: KEY_SCHEMA,
        class: Some(DataClass::SecuritySecret),
    }));
    for (operation, namespace) in [
        (
            get as fn(&str) -> String,
            "urn:ietf:params:xml:ns:netconf:base:1.0",
        ),
        (get_data, "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"),
    ] {
        for (payload, valid) in [(r#""1""#, true), (r#""mismatch-marker""#, false)] {
            let (server, binding, _, audit) = fixture_with_registry(
                mixed_values(payload),
                vec![policy(&["/ex:system", "/ex:system/**"])],
                registry,
            )
            .await;
            let reply = rpc(&server, &operation(FILTER), &MgmtLimits::default());
            if valid {
                assert_eq!(data(&reply, namespace), expected_data("<redacted>", true));
            } else {
                assert!(
                    reply.contains("<error-tag>operation-failed</error-tag>"),
                    "{reply}"
                );
                assert_eq!(binding.renders.load(Ordering::SeqCst), 0);
                assert!(!reply.contains("<data"));
                assert!(!reply.contains("visible-value"));
            }
            assert!(!format!("{reply} {:?}", audit.0.lock().unwrap()).contains("marker"));
        }
    }
}
