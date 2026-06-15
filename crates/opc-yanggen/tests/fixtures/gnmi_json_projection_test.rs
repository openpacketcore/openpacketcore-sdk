use generated_test::gnmi_json::renderer;
use generated_test::types::*;
use opc_config_model::YangPath;
use opc_gnmi_server::{GnmiJsonRenderer, ReadSelection, ReadSelectionEntry};

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
        .insert("001010000000001".to_string(), subscriber);

    system.servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
    system.custom_tags = vec!["opaque".to_string()];
    system
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
