use super::*;
use crate::{DataClass, LeafType, ModelData, NodeMeta, OriginEntry};

struct Registry;
impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "reservation-probe"
    }
    fn served_models(&self) -> &'static [ModelData] {
        &[ModelData {
            name: "m",
            revision: "",
            namespace: "urn:example:m",
            prefix: "m",
        }]
    }
    fn origins(&self) -> &'static [OriginEntry] {
        &[]
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        const fn node(
            path: &'static str,
            kind: NodeKind,
            children: &'static [&'static str],
        ) -> NodeMeta {
            NodeMeta {
                path,
                module: "m",
                kind,
                config: true,
                leaf_type: None,
                key_leaves: &[],
                data_class: DataClass::Public,
                default: None,
                has_default: false,
                presence: false,
                child_paths: children,
            }
        }
        const ROOT: NodeMeta = node("/m:root", NodeKind::Container, &["/m:root/m:peer"]);
        const ROW: NodeMeta = NodeMeta {
            key_leaves: &["key"],
            ..node(
                "/m:root/m:peer",
                NodeKind::List,
                &["/m:root/m:peer/m:key", "/m:root/m:peer/m:label"],
            )
        };
        const KEY: NodeMeta = NodeMeta {
            leaf_type: Some(LeafType::String),
            data_class: DataClass::SecuritySecret,
            ..node("/m:root/m:peer/m:key", NodeKind::Leaf, &[])
        };
        const LABEL: NodeMeta = NodeMeta {
            leaf_type: Some(LeafType::String),
            ..node("/m:root/m:peer/m:label", NodeKind::Leaf, &[])
        };
        &[ROOT, ROW, KEY, LABEL]
    }
}

fn forest(rows: &[(&str, &str)]) -> Vec<NetconfXmlNode> {
    let mut root = NetconfXmlNode::branch("/m:root");
    for (key, label) in rows {
        let mut row = NetconfXmlNode::branch("/m:root/m:peer");
        row.keys.push(("/m:root/m:peer/m:key", key.repeat(64)));
        row.children.push(NetconfXmlNode::scalar(
            "/m:root/m:peer/m:label",
            *label,
            false,
        ));
        root.children.push(row);
    }
    vec![root]
}

#[test]
fn merge_reservation_precedes_destination_mutation() {
    let initial = forest(&[("a", "first")]);
    let incoming = forest(&[("b", "second")]);
    let expected = forest(&[("a", "first"), ("b", "second")]);
    let metadata = SubtreeBudget::new(1_000_000, 0).unwrap();
    let mut work = CapturedWork::default();
    work.include_nodes(&initial, Some(&Registry), &metadata)
        .unwrap();
    work.include_nodes(&incoming, Some(&Registry), &metadata)
        .unwrap();
    let metadata_used = 1_000_000 - metadata.remaining();
    let control = SubtreeBudget::new(1_000_000, 0).unwrap();
    let mut output = initial.clone();
    merge_bounded(&Registry, &mut output, incoming.clone(), &control).unwrap();
    assert_eq!(output, expected);
    let total = 1_000_000 - control.remaining();
    assert!(
        total > metadata_used,
        "identity work must consume a reservation beyond sizing"
    );
    for limit in [metadata_used, total - 1] {
        let budget = SubtreeBudget::new(limit, 0).unwrap();
        let mut output = initial.clone();
        assert_eq!(
            merge_bounded(&Registry, &mut output, incoming.clone(), &budget),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(
            output, initial,
            "failed admission must preserve the whole destination"
        );
        assert_eq!(budget.remaining(), limit - metadata_used);
    }
    let exact = SubtreeBudget::new(total, 0).unwrap();
    let mut output = initial;
    merge_bounded(&Registry, &mut output, incoming, &exact).unwrap();
    assert_eq!(output, expected);
    assert_eq!(exact.remaining(), 0);
}

#[test]
fn order_reservation_precedes_destination_mutation() {
    let initial = forest(&[("a", "first"), ("b", "second")]);
    let input = forest(&[("b", "second"), ("a", "first")]);
    let metadata = SubtreeBudget::new(1_000_000, 0).unwrap();
    let mut work = CapturedWork::default();
    work.include_nodes(&initial, None, &metadata).unwrap();
    work.include_nodes(&input, None, &metadata).unwrap();
    let metadata_used = 1_000_000 - metadata.remaining();
    let control = SubtreeBudget::new(1_000_000, 0).unwrap();
    let mut output = initial.clone();
    order_like(&mut output, &input, &[], &control).unwrap();
    assert_eq!(output, input);
    let total = 1_000_000 - control.remaining();
    assert!(
        total > metadata_used,
        "identity work must consume a reservation beyond sizing"
    );
    for limit in [metadata_used, total - 1] {
        let budget = SubtreeBudget::new(limit, 0).unwrap();
        let mut output = initial.clone();
        assert_eq!(
            order_like(&mut output, &input, &[], &budget),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(
            output, initial,
            "failed admission must preserve the whole destination"
        );
        assert_eq!(budget.remaining(), limit - metadata_used);
    }
    let exact = SubtreeBudget::new(total, 0).unwrap();
    let mut output = initial;
    order_like(&mut output, &input, &[], &exact).unwrap();
    assert_eq!(output, input);
    assert_eq!(exact.remaining(), 0);
}

#[test]
fn reservation_arithmetic_rejects_overflow() {
    let mut value = usize::MAX;
    assert_eq!(add_work(&mut value, 1), Err(SubtreeError::TooBig));
    assert_eq!(value, usize::MAX);
    assert_eq!(multiply_work(usize::MAX, 2), Err(SubtreeError::TooBig));
    for field in 0..5 {
        let mut work = CapturedWork {
            nodes: 1,
            ..CapturedWork::default()
        };
        match field {
            0 => work.nodes = usize::MAX,
            1 => work.keys = usize::MAX,
            2 => work.schema_bytes = usize::MAX,
            3 => work.key_bytes = usize::MAX,
            4 => work.value_bytes = usize::MAX,
            _ => unreachable!(),
        }
        assert_eq!(
            work.merge_units(),
            Err(SubtreeError::TooBig),
            "merge field {field}"
        );
        assert_eq!(
            work.ordering_units(),
            Err(SubtreeError::TooBig),
            "order field {field}"
        );
    }
}
