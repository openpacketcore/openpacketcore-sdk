#![allow(unused_mut)]

use generated_test::netconf_xml_edit::applicator;
use generated_test::schema_registry::registry;
use generated_test::types::*;
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::{EditConfigNode, EditOperation, NetconfEditError, NetconfXmlEditApplicator, NodeKind};
use opc_netconf_server::{parse_edit_config_xml_with_limits, EditDefaultOperation};
use std::collections::BTreeMap;

fn leaf(schema_path: &'static str, operation: EditOperation, value: &str) -> EditConfigNode {
    EditConfigNode {
        schema_path,
        operation,
        value: Some(value.to_string()),
        children: Vec::new(),
        list_keys: BTreeMap::new(),
    }
}

fn container(
    schema_path: &'static str,
    operation: EditOperation,
    children: Vec<EditConfigNode>,
) -> EditConfigNode {
    EditConfigNode {
        schema_path,
        operation,
        value: None,
        children,
        list_keys: BTreeMap::new(),
    }
}

fn list_entry(
    schema_path: &'static str,
    operation: EditOperation,
    keys: &[(&str, &str)],
    children: Vec<EditConfigNode>,
) -> EditConfigNode {
    EditConfigNode {
        schema_path,
        operation,
        value: None,
        children,
        list_keys: keys.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }
}

fn empty_system() -> System {
    System::default()
}

fn apply_xml(
    running: &System,
    xml: &str,
    default_operation: EditDefaultOperation,
) -> Result<System, NetconfEditError> {
    let edit = parse_edit_config_xml_with_limits(
        xml,
        registry(),
        default_operation,
        &MgmtLimits::default(),
    )?;
    applicator().apply_edit_config(running, &edit)
}

#[test]
fn scalar_leaf_merge_creates_value() {
    let mut running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Merge, "router1")],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(
        candidate.hostname,
        LeafPresence::Explicit("router1".to_string())
    );
}

#[test]
fn default_operation_none_leaf_is_noop() {
    let mut running = empty_system();
    running.hostname = LeafPresence::Explicit("old".to_string());
    let edit = container(
        "/ex:system",
        EditOperation::None,
        vec![leaf("/ex:system/ex:hostname", EditOperation::None, "new")],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();

    assert_eq!(candidate.hostname, LeafPresence::Explicit("old".to_string()));
}

#[test]
fn string_leaf_edit_preserves_leading_and_trailing_whitespace() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf(
            "/ex:system/ex:hostname",
            EditOperation::Merge,
            "  router1  ",
        )],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();

    assert_eq!(
        candidate.hostname,
        LeafPresence::Explicit("  router1  ".to_string())
    );
}

#[test]
fn scalar_leaf_replace_overwrites_existing() {
    let mut running = empty_system();
    running.hostname = LeafPresence::Explicit("old".to_string());
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Replace, "new")],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(candidate.hostname, LeafPresence::Explicit("new".to_string()));
}

#[test]
fn scalar_leaf_create_succeeds_when_absent() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Create, "router1")],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(
        candidate.hostname,
        LeafPresence::Explicit("router1".to_string())
    );
}

#[test]
fn scalar_leaf_create_fails_when_present() {
    let mut running = empty_system();
    running.hostname = LeafPresence::Explicit("old".to_string());
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Create, "new")],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::OperationNotSupported {
                operation: EditOperation::Create,
                kind: NodeKind::Leaf,
                ..
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn scalar_leaf_delete_removes_value() {
    let mut running = empty_system();
    running.hostname = LeafPresence::Explicit("router1".to_string());
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Delete, "")],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert!(candidate.hostname.is_absent());
}

#[test]
fn scalar_leaf_delete_fails_when_absent() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Delete, "")],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::OperationNotSupported {
                operation: EditOperation::Delete,
                ..
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn scalar_leaf_remove_is_idempotent() {
    let mut running = empty_system();
    running.hostname = LeafPresence::Explicit("router1".to_string());
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Remove, "")],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert!(candidate.hostname.is_absent());

    let candidate2 = applicator().apply_edit_config(&candidate, &edit).unwrap();
    assert!(candidate2.hostname.is_absent());
}

#[test]
fn nested_container_merge_creates_container_and_leaf() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![container(
            "/ex:system/ex:dns",
            EditOperation::Merge,
            vec![leaf("/ex:system/ex:dns/ex:server", EditOperation::Merge, "8.8.8.8")],
        )],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert!(candidate.dns.is_some());
    assert_eq!(
        candidate.dns.unwrap().server,
        LeafPresence::Explicit("8.8.8.8".to_string())
    );
}

#[test]
fn default_operation_none_container_does_not_materialize_empty_frame() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::None,
        vec![container(
            "/ex:system/ex:dns",
            EditOperation::None,
            vec![leaf(
                "/ex:system/ex:dns/ex:server",
                EditOperation::None,
                "8.8.8.8",
            )],
        )],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();

    assert!(candidate.dns.is_none());
}

#[test]
fn default_operation_none_container_can_frame_explicit_child_op() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::None,
        vec![container(
            "/ex:system/ex:dns",
            EditOperation::None,
            vec![leaf(
                "/ex:system/ex:dns/ex:server",
                EditOperation::Merge,
                "8.8.8.8",
            )],
        )],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    let dns = candidate.dns.expect("explicit child op should create frame");

    assert_eq!(
        dns.server,
        LeafPresence::Explicit("8.8.8.8".to_string())
    );
}

#[test]
fn nested_container_replace_resets_subtree() {
    let mut running = empty_system();
    let mut dns = Dns::default();
    dns.server = LeafPresence::Explicit("1.1.1.1".to_string());
    running.dns = Some(dns);

    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![container(
            "/ex:system/ex:dns",
            EditOperation::Replace,
            vec![leaf("/ex:system/ex:dns/ex:server", EditOperation::Merge, "8.8.8.8")],
        )],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(
        candidate.dns.unwrap().server,
        LeafPresence::Explicit("8.8.8.8".to_string())
    );
}

#[test]
fn nested_container_delete_removes_container() {
    let mut running = empty_system();
    running.dns = Some(Dns::default());
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![container("/ex:system/ex:dns", EditOperation::Delete, Vec::new())],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert!(candidate.dns.is_none());
}

#[test]
fn keyed_list_create_and_merge() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Create,
            &[("name", "eth0")],
            vec![
                leaf("/ex:system/ex:interfaces/ex:mtu", EditOperation::Merge, "1500"),
                leaf("/ex:system/ex:interfaces/ex:admin", EditOperation::Merge, "true"),
            ],
        )],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(candidate.interfaces.len(), 1);
    let eth0 = candidate.interfaces.get("eth0").unwrap();
    assert_eq!(eth0.mtu, LeafPresence::Explicit(1500));
    assert_eq!(eth0.admin, LeafPresence::Explicit(true));

    // Merge into the existing entry.
    let edit2 = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Merge,
            &[("name", "eth0")],
            vec![leaf(
                "/ex:system/ex:interfaces/ex:mtu",
                EditOperation::Replace,
                "9000",
            )],
        )],
    );
    let candidate2 = applicator().apply_edit_config(&candidate, &edit2).unwrap();
    let eth0 = candidate2.interfaces.get("eth0").unwrap();
    assert_eq!(eth0.mtu, LeafPresence::Explicit(9000));
    assert_eq!(eth0.admin, LeafPresence::Explicit(true));
}

#[test]
fn default_operation_none_list_does_not_create_entry() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::None,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::None,
            &[("name", "eth0")],
            vec![leaf(
                "/ex:system/ex:interfaces/ex:mtu",
                EditOperation::None,
                "1500",
            )],
        )],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();

    assert!(candidate.interfaces.is_empty());
}

#[test]
fn default_operation_none_list_traverses_existing_entry_for_explicit_child_op() {
    let mut running = empty_system();
    let mut iface = Interfaces::default();
    iface.name = LeafPresence::Explicit("eth0".to_string());
    iface.mtu = LeafPresence::Explicit(1500);
    iface.admin = LeafPresence::Explicit(true);
    running.interfaces.insert("eth0".to_string(), iface);

    let edit = container(
        "/ex:system",
        EditOperation::None,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::None,
            &[("name", "eth0")],
            vec![leaf(
                "/ex:system/ex:interfaces/ex:mtu",
                EditOperation::Replace,
                "9000",
            )],
        )],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    let eth0 = candidate.interfaces.get("eth0").unwrap();

    assert_eq!(eth0.mtu, LeafPresence::Explicit(9000));
    assert_eq!(eth0.admin, LeafPresence::Explicit(true));
}

#[test]
fn default_operation_none_list_explicit_child_can_create_needed_entry() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::None,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::None,
            &[("name", "eth0")],
            vec![leaf(
                "/ex:system/ex:interfaces/ex:mtu",
                EditOperation::Merge,
                "1500",
            )],
        )],
    );

    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    let eth0 = candidate.interfaces.get("eth0").unwrap();

    assert_eq!(eth0.name, LeafPresence::Explicit("eth0".to_string()));
    assert_eq!(eth0.mtu, LeafPresence::Explicit(1500));
    assert!(eth0.admin.is_absent());
}

#[test]
fn keyed_list_create_fails_when_entry_exists() {
    let mut running = empty_system();
    let mut iface = Interfaces::default();
    iface.name = LeafPresence::Explicit("eth0".to_string());
    running.interfaces.insert("eth0".to_string(), iface);

    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Create,
            &[("name", "eth0")],
            Vec::new(),
        )],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::OperationNotSupported {
                operation: EditOperation::Create,
                kind: NodeKind::List,
                ..
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn keyed_list_delete_and_remove() {
    let mut running = empty_system();
    let mut iface = Interfaces::default();
    iface.name = LeafPresence::Explicit("eth0".to_string());
    running.interfaces.insert("eth0".to_string(), iface);

    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Delete,
            &[("name", "eth0")],
            Vec::new(),
        )],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert!(candidate.interfaces.is_empty());

    let err = applicator().apply_edit_config(&candidate, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::OperationNotSupported {
                operation: EditOperation::Delete,
                ..
            }
        ),
        "unexpected error: {err}"
    );

    let edit_remove = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Remove,
            &[("name", "eth0")],
            Vec::new(),
        )],
    );
    let candidate2 = applicator().apply_edit_config(&candidate, &edit_remove).unwrap();
    assert!(candidate2.interfaces.is_empty());
}

#[test]
fn multi_key_list_create_and_replace() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:routes",
            EditOperation::Create,
            &[("dest", "0.0.0.0/0"), ("next-hop", "10.0.0.1")],
            vec![leaf("/ex:system/ex:routes/ex:metric", EditOperation::Merge, "1")],
        )],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(candidate.routes.len(), 1);
    let route = candidate
        .routes
        .get(&RoutesKey {
            dest: "0.0.0.0/0".to_string(),
            next_hop: "10.0.0.1".to_string(),
        })
        .unwrap();
    assert_eq!(route.metric, LeafPresence::Explicit(1));

    let edit2 = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:routes",
            EditOperation::Replace,
            &[("dest", "0.0.0.0/0"), ("next-hop", "10.0.0.1")],
            vec![leaf("/ex:system/ex:routes/ex:metric", EditOperation::Merge, "5")],
        )],
    );
    let candidate2 = applicator().apply_edit_config(&candidate, &edit2).unwrap();
    let route = candidate2
        .routes
        .get(&RoutesKey {
            dest: "0.0.0.0/0".to_string(),
            next_hop: "10.0.0.1".to_string(),
        })
        .unwrap();
    assert_eq!(route.metric, LeafPresence::Explicit(5));
}

#[test]
fn secret_leaf_value_applies_but_does_not_leak() {
    let running = empty_system();
    let secret_value = "hunter2";
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf(
            "/ex:system/ex:secret",
            EditOperation::Merge,
            secret_value,
        )],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(
        candidate.secret.get().as_option(),
        Some(&secret_value.to_string())
    );

    // The generated EditConfigNode and SecretLeaf Debug impls must not expose the raw value.
    let edit_debug = format!("{edit:?}");
    assert!(!edit_debug.contains(secret_value), "EditConfigNode leaked secret: {edit_debug}");
    let secret_debug = format!("{:?}", candidate.secret);
    assert!(!secret_debug.contains(secret_value), "SecretLeaf leaked secret: {secret_debug}");

    // Error messages must not echo the value.
    let bad_edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf(
            "/ex:system/ex:secret",
            EditOperation::Create,
            secret_value,
        )],
    );
    let err = applicator().apply_edit_config(&candidate, &bad_edit).unwrap_err();
    let err_string = format!("{err}");
    assert!(!err_string.contains(secret_value), "error message leaked secret: {err_string}");
}

#[test]
fn unknown_node_fails_closed() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:bogus", EditOperation::Merge, "x")],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(err, NetconfEditError::UnknownPath(_)),
        "unexpected error: {err}"
    );
}

#[test]
fn state_leaf_edit_fails_read_only() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![leaf("/ex:system/ex:uptime", EditOperation::Merge, "100")],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(err, NetconfEditError::ReadOnly { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn missing_list_key_fails_before_mutation() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Merge,
            &[], // missing name key
            vec![leaf("/ex:system/ex:interfaces/ex:mtu", EditOperation::Merge, "1500")],
        )],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::MissingKey {
                key: "name",
                ..
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn extra_list_key_fails_before_mutation() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![list_entry(
            "/ex:system/ex:interfaces",
            EditOperation::Merge,
            &[("name", "eth0"), ("bogus", "x")],
            vec![leaf("/ex:system/ex:interfaces/ex:mtu", EditOperation::Merge, "1500")],
        )],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::ExtraKey {
                ref key,
                ..
            } if key == "bogus"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn custom_typedef_leaf_list_fails_closed() {
    let running = empty_system();
    let edit = container(
        "/ex:system",
        EditOperation::Merge,
        vec![container(
            "/ex:system/ex:custom-tags",
            EditOperation::Merge,
            Vec::new(),
        )],
    );
    let err = applicator().apply_edit_config(&running, &edit).unwrap_err();
    assert!(
        matches!(
            err,
            NetconfEditError::UnsupportedShape {
                kind: NodeKind::LeafList,
                ..
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn replace_root_resets_whole_config() {
    let mut running = empty_system();
    running.hostname = LeafPresence::Explicit("old".to_string());
    let edit = container(
        "/ex:system",
        EditOperation::Replace,
        vec![leaf("/ex:system/ex:hostname", EditOperation::Merge, "new")],
    );
    let candidate = applicator().apply_edit_config(&running, &edit).unwrap();
    assert_eq!(candidate.hostname, LeafPresence::Explicit("new".to_string()));
}

#[test]
fn real_xml_full_root_replace_from_no_config_preserves_leaf_list_entries() {
    let no_config_sentinel = empty_system();
    let candidate = apply_xml(
        &no_config_sentinel,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" nc:operation="replace" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ex:servers>apn-beta</ex:servers>
                <ex:servers>apn-alpha</ex:servers>
                <ex:tags>41</ex:tags>
                <ex:tags>42</ex:tags>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect("full root replacement must accept schema-valid leaf-lists");

    assert_eq!(
        candidate.servers,
        vec!["apn-beta".to_string(), "apn-alpha".to_string()]
    );
    assert_eq!(candidate.tags, vec![41, 42]);
    assert!(candidate.hostname.is_absent());
    assert_eq!(
        no_config_sentinel,
        empty_system(),
        "building the replacement candidate must not mutate the no-config sentinel"
    );
}

#[test]
fn real_xml_enclosing_replace_resets_leaf_list_collection() {
    let mut running = empty_system();
    running.servers = vec!["old-apn".to_string(), "retired-apn".to_string()];
    running.tags = vec![9];
    let before = running.clone();

    let candidate = apply_xml(
        &running,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="replace">
                <ex:servers>apn-alpha</ex:servers>
                <ex:servers>apn-beta</ex:servers>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect("an enclosing replace must rebuild leaf-list state from XML siblings");

    assert_eq!(
        candidate.servers,
        vec!["apn-alpha".to_string(), "apn-beta".to_string()]
    );
    assert!(candidate.tags.is_empty());
    assert_eq!(running, before, "successful XML edits build a separate candidate");
}

#[test]
fn real_xml_leaf_list_operations_are_schema_typed_and_ordered() {
    let mut running = empty_system();
    running.servers = vec!["apn-alpha".to_string(), "apn-beta".to_string()];

    let created = apply_xml(
        &running,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ex:servers nc:operation="create">apn-gamma</ex:servers>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect("create must append a new leaf-list value");
    assert_eq!(
        created.servers,
        vec![
            "apn-alpha".to_string(),
            "apn-beta".to_string(),
            "apn-gamma".to_string(),
        ]
    );

    let merged = apply_xml(
        &created,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example">
                <ex:servers>apn-gamma</ex:servers>
                <ex:servers>apn-delta</ex:servers>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect("merge must preserve an existing value and add a distinct one");
    assert_eq!(
        merged.servers,
        vec![
            "apn-alpha".to_string(),
            "apn-beta".to_string(),
            "apn-gamma".to_string(),
            "apn-delta".to_string(),
        ]
    );

    let entry_replaced = apply_xml(
        &merged,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ex:servers nc:operation="replace">apn-delta</ex:servers>
                <ex:servers nc:operation="replace">apn-epsilon</ex:servers>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect("entry replace must preserve unrelated leaf-list values and upsert a new entry");
    assert_eq!(
        entry_replaced.servers,
        vec![
            "apn-alpha".to_string(),
            "apn-beta".to_string(),
            "apn-gamma".to_string(),
            "apn-delta".to_string(),
            "apn-epsilon".to_string(),
        ]
    );

    let deleted = apply_xml(
        &entry_replaced,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ex:servers nc:operation="delete">apn-delta</ex:servers>
                <ex:servers nc:operation="remove">absent-entry</ex:servers>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect("delete and idempotent remove must use leaf-list value identity");
    assert_eq!(
        deleted.servers,
        vec![
            "apn-alpha".to_string(),
            "apn-beta".to_string(),
            "apn-gamma".to_string(),
            "apn-epsilon".to_string(),
        ]
    );

    let err = apply_xml(
        &deleted,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ex:servers nc:operation="create">apn-epsilon</ex:servers>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect_err("create must reject an existing leaf-list value");
    assert!(matches!(
        err,
        NetconfEditError::OperationNotSupported {
            operation: EditOperation::Create,
            kind: NodeKind::LeafList,
            ..
        }
    ));
}

#[test]
fn real_xml_leaf_list_rejects_semantic_duplicates_and_invalid_values() {
    let mut running = empty_system();
    running.tags = vec![9];
    let before = running.clone();

    let duplicate = apply_xml(
        &running,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="replace">
                <ex:tags>007</ex:tags>
                <ex:tags>7</ex:tags>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect_err("duplicate typed leaf-list values must fail closed");
    assert!(matches!(duplicate, NetconfEditError::InvalidValue { .. }));
    assert_eq!(running, before, "failed XML edits must not mutate running state");

    let none_and_merge_duplicate = apply_xml(
        &running,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <ex:tags>007</ex:tags>
                <ex:tags nc:operation="merge">7</ex:tags>
            </ex:system>
        </config>"#,
        EditDefaultOperation::None,
    )
    .expect_err("default-operation none must not bypass typed duplicate validation");
    assert!(matches!(none_and_merge_duplicate, NetconfEditError::InvalidValue { .. }));
    assert_eq!(
        running, before,
        "a rejected none-plus-mutation request must not mutate running state"
    );

    let invalid = apply_xml(
        &running,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example">
                <ex:tags>not-a-uint16</ex:tags>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect_err("invalid leaf-list values must fail before candidate construction");
    assert!(matches!(invalid, NetconfEditError::InvalidValue { .. }));
    assert_eq!(running, before, "invalid XML must not mutate running state");

    let unsupported = apply_xml(
        &running,
        r#"<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <ex:system xmlns:ex="urn:example">
                <ex:custom-tags>opaque</ex:custom-tags>
            </ex:system>
        </config>"#,
        EditDefaultOperation::Merge,
    )
    .expect_err("custom leaf-list element types remain fail-closed");
    assert!(matches!(
        unsupported,
        NetconfEditError::UnsupportedShape {
            kind: NodeKind::LeafList,
            ..
        }
    ));
    assert_eq!(running, before, "unsupported XML must not mutate running state");
}

#[test]
fn generated_leaf_list_rejects_invalid_normalized_shapes_and_duplicate_running_state() {
    let mut duplicate_running = empty_system();
    duplicate_running.servers = vec!["apn-duplicate".to_string(), "apn-duplicate".to_string()];
    let duplicate_before = duplicate_running.clone();
    let duplicate_running_err = applicator()
        .apply_edit_config(
            &duplicate_running,
            &container(
                "/ex:system",
                EditOperation::Merge,
                vec![leaf(
                    "/ex:system/ex:servers",
                    EditOperation::Merge,
                    "apn-new",
                )],
            ),
        )
        .expect_err("a mutation must refuse a duplicate running leaf-list collection");
    assert!(matches!(
        duplicate_running_err,
        NetconfEditError::InvalidValue {
            path: "/ex:system/ex:servers"
        }
    ));
    assert_eq!(
        duplicate_running, duplicate_before,
        "rejecting duplicate running state must not mutate the caller's config"
    );

    let invalid_value = container(
        "/ex:system",
        EditOperation::Merge,
        vec![EditConfigNode {
            schema_path: "/ex:system/ex:servers",
            operation: EditOperation::Merge,
            value: None,
            children: Vec::new(),
            list_keys: BTreeMap::new(),
        }],
    );
    let invalid_value_err = applicator()
        .apply_edit_config(&empty_system(), &invalid_value)
        .expect_err("a normalized leaf-list entry without a value is invalid");
    assert!(matches!(
        invalid_value_err,
        NetconfEditError::InvalidValue {
            path: "/ex:system/ex:servers"
        }
    ));

    let invalid_children = container(
        "/ex:system",
        EditOperation::Merge,
        vec![EditConfigNode {
            schema_path: "/ex:system/ex:servers",
            operation: EditOperation::Merge,
            value: Some("apn-value".to_string()),
            children: vec![leaf(
                "/ex:system/ex:hostname",
                EditOperation::Merge,
                "not-a-child",
            )],
            list_keys: BTreeMap::new(),
        }],
    );
    let invalid_children_err = applicator()
        .apply_edit_config(&empty_system(), &invalid_children)
        .expect_err("a normalized leaf-list entry cannot have child nodes");
    assert!(matches!(invalid_children_err, NetconfEditError::MalformedXml));

    let invalid_keys = container(
        "/ex:system",
        EditOperation::Merge,
        vec![EditConfigNode {
            schema_path: "/ex:system/ex:servers",
            operation: EditOperation::Merge,
            value: Some("apn-value".to_string()),
            children: Vec::new(),
            list_keys: BTreeMap::from([("bogus".to_string(), "entry".to_string())]),
        }],
    );
    let invalid_keys_err = applicator()
        .apply_edit_config(&empty_system(), &invalid_keys)
        .expect_err("a normalized leaf-list entry cannot carry list keys");
    assert!(matches!(
        invalid_keys_err,
        NetconfEditError::KeyOnNonList {
            path: "/ex:system/ex:servers"
        }
    ));
}
