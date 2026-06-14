#![allow(unused_mut)]

use generated_test::netconf_xml_edit::applicator;
use generated_test::types::*;
use opc_mgmt_schema::{EditConfigNode, EditOperation, NetconfEditError, NetconfXmlEditApplicator, NodeKind};
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
