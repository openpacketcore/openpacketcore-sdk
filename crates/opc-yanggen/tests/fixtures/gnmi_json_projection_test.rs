use generated_test::gnmi_json::renderer;
use generated_test::redaction::Redactable;
use generated_test::serde::{DUPLICATE_LIST_KEY_ERROR, MISSING_LIST_KEY_ERROR};
use generated_test::types::*;
use opc_config_model::YangPath;
use opc_gnmi_server::{GnmiJsonRenderer, ReadSelection, ReadSelectionEntry};
use serde_json::{json, Value};

fn entry(schema_path: &'static str, canonical_path: &'static str) -> ReadSelectionEntry {
    ReadSelectionEntry::new(
        schema_path,
        YangPath::new(canonical_path).expect("canonical test path"),
    )
}

fn render(system: &System, entries: Vec<ReadSelectionEntry>) -> Vec<(String, String)> {
    let mut schema_paths = entries
        .iter()
        .map(ReadSelectionEntry::schema_path)
        .collect::<Vec<_>>();
    schema_paths.sort();
    schema_paths.dedup();
    renderer()
        .render_running_json(system, ReadSelection::with_entries(&schema_paths, &entries))
        .expect("render")
        .into_iter()
        .map(|update| {
            (
                update.path().as_str().to_string(),
                update.value_json().to_string(),
            )
        })
        .collect()
}

fn sample_config() -> System {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("router1".to_string());
    system.secret = SecretLeaf::new(LeafPresence::Explicit("hunter2".to_string()));

    let mut dns = Dns::default();
    dns.server = LeafPresence::Explicit("1.1.1.1".to_string());
    system.dns = Some(dns);

    let mut eth0 = Interfaces::default();
    eth0.name = LeafPresence::Explicit("eth0".to_string());
    eth0.mtu = LeafPresence::Explicit(1500);
    eth0.admin = LeafPresence::Explicit(true);
    system.interfaces.insert("eth0".to_string(), eth0);

    let mut eth1 = Interfaces::default();
    eth1.name = LeafPresence::Explicit("eth1".to_string());
    eth1.mtu = LeafPresence::Explicit(9000);
    eth1.admin = LeafPresence::Explicit(false);
    system.interfaces.insert("eth1".to_string(), eth1);

    let mut route = Routes::default();
    route.dest = LeafPresence::Explicit("0.0.0.0/0".to_string());
    route.next_hop = LeafPresence::Explicit("10.0.0.1".to_string());
    route.metric = LeafPresence::Explicit(10);
    system.routes.insert(
        RoutesKey {
            dest: "0.0.0.0/0".to_string(),
            next_hop: "10.0.0.1".to_string(),
        },
        route,
    );

    let mut subscriber = Subscriber::default();
    subscriber.imsi = SecretLeaf::new(LeafPresence::Explicit("001010000000001".to_string()));
    subscriber.tier = LeafPresence::Explicit("gold".to_string());
    system
        .subscriber
        .insert("001010000000001".to_string().into(), subscriber);

    system.servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
    system.custom_tags = vec!["opaque".to_string()];
    system
}

fn assert_copy_and_hash<T: Copy + std::hash::Hash>() {}

#[test]
fn sensitive_key_preserves_conditional_scalar_traits() {
    assert_copy_and_hash::<SensitiveKey<u32>>();
}

#[test]
fn selected_leaf_only_does_not_leak_siblings() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry(
            "/ex:system/ex:hostname",
            "/ex:system/ex:hostname",
        )],
    );

    assert_eq!(
        updates,
        vec![(
            "/ex:system/ex:hostname".to_string(),
            r#""router1""#.to_string()
        )]
    );
}

#[test]
fn nested_container_selection_renders_selected_descendant() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry(
            "/ex:system/ex:dns/ex:server",
            "/ex:system/ex:dns/ex:server",
        )],
    );

    assert_eq!(
        updates,
        vec![(
            "/ex:system/ex:dns/ex:server".to_string(),
            r#""1.1.1.1""#.to_string()
        )]
    );
}

#[test]
fn wildcard_list_leaf_selection_renders_all_entries_deterministically() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry(
            "/ex:system/ex:interfaces/ex:mtu",
            "/ex:system/ex:interfaces/ex:mtu",
        )],
    );

    assert_eq!(
        updates,
        vec![
            (
                "/ex:system/ex:interfaces[ex:name='eth0']/ex:mtu".to_string(),
                "1500".to_string()
            ),
            (
                "/ex:system/ex:interfaces[ex:name='eth1']/ex:mtu".to_string(),
                "9000".to_string()
            ),
        ]
    );
}

#[test]
fn keyed_instance_selection_renders_only_that_entry() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry(
            "/ex:system/ex:interfaces/ex:mtu",
            "/ex:system/ex:interfaces[ex:name='eth1']/ex:mtu",
        )],
    );

    assert_eq!(
        updates,
        vec![(
            "/ex:system/ex:interfaces[ex:name='eth1']/ex:mtu".to_string(),
            "9000".to_string()
        )]
    );
}

#[test]
fn multi_key_list_paths_use_schema_key_order() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry(
            "/ex:system/ex:routes/ex:metric",
            "/ex:system/ex:routes[ex:dest='0.0.0.0/0'][ex:next-hop='10.0.0.1']/ex:metric",
        )],
    );

    assert_eq!(
        updates,
        vec![(
            "/ex:system/ex:routes[ex:dest='0.0.0.0/0'][ex:next-hop='10.0.0.1']/ex:metric"
                .to_string(),
            "10".to_string()
        )]
    );
}

#[test]
fn leaf_list_renders_json_array() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry(
            "/ex:system/ex:servers",
            "/ex:system/ex:servers",
        )],
    );

    assert_eq!(
        updates,
        vec![(
            "/ex:system/ex:servers".to_string(),
            r#"["8.8.8.8","1.1.1.1"]"#.to_string()
        )]
    );
}

#[test]
fn secret_leaf_is_redacted_without_raw_value() {
    let system = sample_config();
    let updates = render(
        &system,
        vec![entry("/ex:system/ex:secret", "/ex:system/ex:secret")],
    );

    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].0, "/ex:system/ex:secret");
    assert!(!updates[0].1.contains("hunter2"));
}

#[test]
fn unsupported_custom_leaf_list_fails_closed() {
    let system = sample_config();
    let entries = vec![entry(
        "/ex:system/ex:custom-tags",
        "/ex:system/ex:custom-tags",
    )];
    let schema_paths = entries
        .iter()
        .map(ReadSelectionEntry::schema_path)
        .collect::<Vec<_>>();

    let err = renderer()
        .render_running_json(&system, ReadSelection::with_entries(&schema_paths, &entries))
        .unwrap_err();

    assert!(!err.detail().contains("opaque"));
}

#[test]
fn sensitive_list_key_fails_closed_without_key_value_leak() {
    let system = sample_config();
    let entries = vec![entry(
        "/ex:system/ex:subscriber/ex:tier",
        "/ex:system/ex:subscriber[ex:imsi='001010000000001']/ex:tier",
    )];
    let schema_paths = entries
        .iter()
        .map(ReadSelectionEntry::schema_path)
        .collect::<Vec<_>>();

    let err = renderer()
        .render_running_json(&system, ReadSelection::with_entries(&schema_paths, &entries))
        .unwrap_err();

    assert!(!err.detail().contains("001010000000001"));
}

fn decode_error(value: Value) -> String {
    serde_json::from_value::<System>(value)
        .expect_err("invalid keyed list must fail")
        .to_string()
}

#[test]
fn keyed_list_serde_accepts_complete_single_and_composite_keys() {
    let input = json!({
        "interfaces": [
            { "name": "edge-a.example", "mtu": 1500 },
            { "name": "edge-b.example", "mtu": 9000 }
        ],
        "routes": [
            {
                "dest": "site-b.example",
                "next-hop": "gateway-b.example",
                "metric": 20
            },
            {
                "dest": "site-a.example",
                "next-hop": "gateway-a.example",
                "metric": 10
            }
        ],
        "origins": [
            {
                "origin-host": "origin-a.example",
                "origin-realm": "realm-a.example"
            }
        ],
        "subscriber": [
            { "imsi": "terminal-a.example", "tier": "gold" }
        ]
    });

    let system: System = serde_json::from_value(input).expect("complete keys decode");
    assert!(system.interfaces.contains_key("edge-a.example"));
    assert!(system.subscriber.contains_key("terminal-a.example"));
    assert!(system.routes.contains_key(&RoutesKey {
        dest: "site-a.example".to_string(),
        next_hop: "gateway-a.example".to_string(),
    }));

    let ordered_destinations = system
        .routes
        .keys()
        .map(|key| key.dest.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ordered_destinations, ["site-a.example", "site-b.example"]);

    let encoded = serde_json::to_value(&system).expect("encode valid keyed lists");
    let decoded: System = serde_json::from_value(encoded).expect("round trip valid keyed lists");
    assert_eq!(decoded, system);
}

#[test]
fn keyed_list_serde_rejects_duplicate_single_key_without_value_disclosure() {
    let value = "duplicate-single.example";
    let error = decode_error(json!({
        "subscriber": [
            { "imsi": value },
            { "imsi": value }
        ]
    }));

    assert_eq!(error, DUPLICATE_LIST_KEY_ERROR);
    assert!(!error.contains(value));
}

#[test]
fn keyed_list_serde_rejects_duplicate_composite_key_without_value_disclosure() {
    let first = "duplicate-origin.example";
    let second = "duplicate-realm.example";
    let error = decode_error(json!({
        "origins": [
            { "origin-host": first, "origin-realm": second },
            { "origin-host": first, "origin-realm": second }
        ]
    }));

    assert_eq!(error, DUPLICATE_LIST_KEY_ERROR);
    assert!(!error.contains(first));
    assert!(!error.contains(second));
}

#[test]
fn keyed_list_serde_rejects_missing_single_key() {
    let error = decode_error(json!({
        "subscriber": [{ "tier": "gold" }]
    }));

    assert_eq!(error, MISSING_LIST_KEY_ERROR);
}

#[test]
fn keyed_list_serde_rejects_each_missing_composite_key_component() {
    let first_only = "only-first.example";
    let second_only = "only-second.example";

    let missing_second = decode_error(json!({
        "origins": [{ "origin-host": first_only }]
    }));
    assert_eq!(missing_second, MISSING_LIST_KEY_ERROR);
    assert!(!missing_second.contains(first_only));

    let missing_first = decode_error(json!({
        "origins": [{ "origin-realm": second_only }]
    }));
    assert_eq!(missing_first, MISSING_LIST_KEY_ERROR);
    assert!(!missing_first.contains(second_only));
}

#[test]
fn sensitive_single_and_composite_key_debug_is_safe_by_construction() {
    let single = "terminal-debug.example";
    let first = "origin-debug.example";
    let second = "realm-debug.example";
    let system: System = serde_json::from_value(json!({
        "subscriber": [{ "imsi": single, "tier": "silver" }],
        "origins": [{ "origin-host": first, "origin-realm": second }]
    }))
    .expect("valid sensitive keys");

    let subscriber_row = system.subscriber.get(single).expect("single-key row");
    let origin_key = OriginsKey {
        origin_host: first.to_string(),
        origin_realm: second.to_string(),
    };
    let origin_row = system
        .origins
        .get(&origin_key)
        .expect("composite-key row");

    for debug in [
        format!("{subscriber_row:?}"),
        format!("{:?}", system.subscriber),
        format!("{:?}", system.subscriber.keys().next()),
        format!(
            "{}",
            system.subscriber.keys().next().expect("single-key value")
        ),
        format!("{origin_key:?}"),
        format!("{origin_row:?}"),
        format!("{:?}", system.origins),
        format!("{system:?}"),
    ] {
        assert!(!debug.contains(single));
        assert!(!debug.contains(first));
        assert!(!debug.contains(second));
    }

    let encoded = serde_json::to_string(&system).expect("serialize sensitive keys");
    assert!(encoded.contains(single));
    assert!(encoded.contains(first));
    assert!(encoded.contains(second));
}

#[test]
fn redaction_keeps_sensitive_map_keys_and_rows_synchronized() {
    let raw_values = [
        "terminal-a.example",
        "terminal-b.example",
        "origin-a.example",
        "origin-b.example",
        "realm-a.example",
        "realm-b.example",
    ];
    let mut system: System = serde_json::from_value(json!({
        "subscriber": [
            { "imsi": raw_values[0], "tier": "gold" },
            { "imsi": raw_values[1], "tier": "silver" }
        ],
        "origins": [
            { "origin-host": raw_values[2], "origin-realm": raw_values[4] },
            { "origin-host": raw_values[3], "origin-realm": raw_values[5] }
        ]
    }))
    .expect("valid sensitive-key lists");

    system.redact_sensitive();

    assert_eq!(system.subscriber.len(), 2);
    for (key, row) in &system.subscriber {
        assert_eq!(Some(key.get()), row.imsi.get().as_option());
        assert!(!raw_values.contains(&key.as_str()));
    }

    assert_eq!(system.origins.len(), 2);
    for (key, row) in &system.origins {
        assert_eq!(Some(&key.origin_host), row.origin_host.get().as_option());
        assert_eq!(Some(&key.origin_realm), row.origin_realm.get().as_option());
        assert!(!raw_values.contains(&key.origin_host.as_str()));
        assert!(!raw_values.contains(&key.origin_realm.as_str()));
    }
}
