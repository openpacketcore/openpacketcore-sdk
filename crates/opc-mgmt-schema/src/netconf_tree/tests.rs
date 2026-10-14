use super::*;
use crate::{DataClass, DefaultReport, LeafType, ModelData, NodeMeta, OriginEntry, SchemaRegistry};

struct Registry;

const fn node(path: &'static str, kind: NodeKind) -> NodeMeta {
    NodeMeta {
        path,
        module: "tree",
        kind,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: &[],
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }
}

static NODES: &[NodeMeta] = &[
    node("/t:member", NodeKind::LeafList),
    node("/t:root", NodeKind::Container),
    node("/t:root/t:value", NodeKind::Leaf),
    NodeMeta {
        key_leaves: &["tenant", "id"],
        ..node("/t:row", NodeKind::List)
    },
    node("/t:row/t:id", NodeKind::Leaf),
    NodeMeta {
        data_class: DataClass::SecuritySecret,
        ..node("/t:row/t:tenant", NodeKind::Leaf)
    },
    node("/t:row/t:value", NodeKind::Leaf),
    node("/t:scalar", NodeKind::Leaf),
];

impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "tree"
    }
    fn served_models(&self) -> &'static [ModelData] {
        &[ModelData {
            name: "tree",
            revision: "",
            namespace: "urn:tree",
            prefix: "t",
        }]
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        NODES
    }
    fn origins(&self) -> &'static [OriginEntry] {
        &[]
    }
}

fn row(tenant: &str, value: &str) -> NetconfXmlNode {
    NetconfXmlNode {
        keys: vec![
            ("/t:row/t:tenant", tenant.into()),
            ("/t:row/t:id", "1".into()),
        ],
        children: vec![NetconfXmlNode::scalar("/t:row/t:value", value, false)],
        ..NetconfXmlNode::branch("/t:row")
    }
}

#[test]
fn netconf_tree_merge_preserves_leaf_list_members_and_order() {
    let member = |value| NetconfXmlNode::scalar("/t:member", value, false);
    let mut existing = vec![member("b"), member("a")];
    merge_netconf_nodes(&Registry, &mut existing, vec![member("a"), member("c")]).unwrap();
    assert_eq!(existing, vec![member("b"), member("a"), member("c")]);
    let xml = NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
        .render_nodes(&existing)
        .unwrap();
    assert_eq!(xml.matches("<t:member").count(), 3);
}

#[test]
fn netconf_tree_merge_uses_raw_identity_before_masking() {
    let mut existing = vec![row("private-a", "first")];
    merge_netconf_nodes(&Registry, &mut existing, vec![row("private-b", "second")]).unwrap();
    assert_eq!(
        existing,
        vec![row("private-a", "first"), row("private-b", "second")]
    );
    let xml = NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
        .render_nodes(&existing)
        .unwrap();
    assert_eq!(xml.matches("<t:row ").count(), 2);
    assert_eq!(
        xml.matches("<t:tenant>&lt;redacted&gt;</t:tenant>").count(),
        2
    );
    assert!(!xml.contains("private-"));
    assert!(!format!("{existing:?}").contains("private-"));
}

#[test]
fn netconf_tree_root_scalar_declares_data_and_default_namespaces() {
    for report in [DefaultReport::Trim, DefaultReport::ReportAllTagged] {
        let xml = NetconfXmlRenderContext::new(&Registry, &[], report)
            .render_nodes(&[NetconfXmlNode::scalar("/t:scalar", "<&>", true)])
            .unwrap();
        assert!(xml.contains("xmlns:t=\"urn:tree\""), "{xml}");
        assert!(xml.contains("&lt;&amp;&gt;"), "{xml}");
        if report == DefaultReport::ReportAllTagged {
            assert!(
                xml.contains(&format!("xmlns:wd=\"{}\"", crate::WITH_DEFAULTS_NS)),
                "{xml}"
            );
            assert!(xml.contains("wd:default=\"true\""), "{xml}");
        }
    }
}

#[test]
fn netconf_tree_rejects_incorrect_key_paths_and_order() {
    for keys in [
        vec![
            ("/t:row/t:id", "1".into()),
            ("/t:row/t:tenant", "private".into()),
        ],
        vec![
            ("/t:row/t:tenant", "private".into()),
            ("/t:scalar", "1".into()),
        ],
    ] {
        let mut invalid = row("private", "value");
        invalid.keys = keys;
        assert!(
            NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
                .render_nodes(&[invalid])
                .is_err()
        );
    }
}

#[test]
fn netconf_tree_rejects_children_under_wrong_parent() {
    let invalid = NetconfXmlNode {
        children: vec![NetconfXmlNode::scalar("/t:row/t:value", "private", false)],
        ..NetconfXmlNode::branch("/t:root")
    };
    assert!(
        NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
            .render_nodes(&[invalid])
            .is_err()
    );
}

#[test]
fn netconf_tree_rejects_scalar_structural_content() {
    for invalid in [
        NetconfXmlNode::scalar("/t:root", "private", false),
        NetconfXmlNode {
            children: vec![NetconfXmlNode::branch("/t:root")],
            ..NetconfXmlNode::scalar("/t:scalar", "private", false)
        },
        NetconfXmlNode {
            keys: vec![("/t:row/t:tenant", "private".into())],
            ..NetconfXmlNode::scalar("/t:scalar", "private", false)
        },
    ] {
        assert!(
            NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
                .render_nodes(&[invalid])
                .is_err()
        );
    }
}

#[test]
fn netconf_tree_rejects_container_keys() {
    let invalid = NetconfXmlNode {
        keys: vec![("/t:row/t:tenant", "private".into())],
        ..NetconfXmlNode::branch("/t:root")
    };
    assert!(
        NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
            .render_nodes(&[invalid])
            .is_err()
    );
}

#[test]
fn netconf_tree_rejects_conflicting_scalars_and_key_payloads() {
    let mut existing = vec![NetconfXmlNode::scalar("/t:scalar", "first", false)];
    assert!(merge_netconf_nodes(
        &Registry,
        &mut existing,
        vec![NetconfXmlNode::scalar("/t:scalar", "second", false)]
    )
    .is_err());
    let mut invalid = row("private", "value");
    invalid
        .children
        .push(NetconfXmlNode::scalar("/t:row/t:id", "2", false));
    assert!(
        NetconfXmlRenderContext::new(&Registry, &[], DefaultReport::Trim)
            .render_nodes(&[invalid])
            .is_err()
    );
}
