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

struct TypedRegistry;

impl SchemaRegistry for TypedRegistry {
    fn schema_digest(&self) -> &'static str {
        "evaluation-reservation"
    }

    fn served_models(&self) -> &'static [ModelData] {
        Registry.served_models()
    }

    fn origins(&self) -> &'static [OriginEntry] {
        Registry.origins()
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        static NODES: std::sync::OnceLock<Vec<NodeMeta>> = std::sync::OnceLock::new();
        NODES.get_or_init(|| {
            Registry
                .nodes()
                .iter()
                .map(|node| NodeMeta {
                    leaf_type: (node.kind == NodeKind::Leaf).then_some(LeafType::String),
                    ..*node
                })
                .collect()
        })
    }
}

fn evaluation_plan(budget: SubtreeBudget) -> AuthorizedSubtreePlan {
    let compile = SubtreeBudget::new(1_000_000, 0).unwrap();
    let leaf = "/m:root/m:peer/m:label";
    let row = SubtreeScope {
        predicates: vec![SubtreePredicate {
            alternatives: vec![SubtreeMatch {
                path: leaf,
                predicate: ScalarPredicate::compile(&TypedRegistry, leaf, "first", false, &compile)
                    .unwrap(),
                in_scope: true,
                keys: vec!["/m:root/m:peer/m:key"],
            }],
        }],
        implicit_outputs: vec![SubtreeOutput {
            path: leaf,
            keys: vec!["/m:root/m:peer/m:key"],
        }],
        ..SubtreeScope::default()
    };
    let branch = |path, children| SubtreeScope {
        branches: vec![SubtreeBranch {
            path,
            keys: Vec::new(),
            children: Some(Box::new(children)),
            outputs: Vec::new(),
        }],
        ..SubtreeScope::default()
    };
    let scope = branch("/m:root", branch("/m:root/m:peer", row));
    let mut plan = SubtreePlan::new(vec![scope], compile, 64)
        .unwrap()
        .authorize(|_| true, 64)
        .unwrap();
    // Isolate admission of captured data from the separately tested compiler.
    plan.budget = budget;
    plan
}

#[test]
fn evaluation_reservation_precedes_all_data_phases_and_predicate_admissions() {
    let input = forest(&[("a", "first"), ("b", "second")]);
    let original = input.clone();
    let expected = forest(&[("a", "first")]);
    let metadata = SubtreeBudget::new(1_000_000, 0).unwrap();
    let plan = evaluation_plan(metadata.clone());
    let work = evaluation::EvaluationWork::measure(&plan.scopes, &input, &TypedRegistry, &metadata)
        .unwrap();
    let metadata_used = 1_000_000 - metadata.remaining();
    assert_eq!(metadata.predicate_trials(), 0);
    let control = SubtreeBudget::new(1_000_000, 0).unwrap();
    assert_eq!(
        evaluation_plan(control.clone())
            .evaluate(&TypedRegistry, &input)
            .unwrap(),
        expected
    );
    let total = 1_000_000 - control.remaining();
    assert!(total > metadata_used);
    assert_eq!(total - metadata_used, work.units);
    assert_eq!(control.predicate_trials(), 2);
    assert_eq!(work.predicate_trials, 2);
    for limit in [metadata_used, total - 1] {
        let budget = SubtreeBudget::new(limit, 0).unwrap();
        assert_eq!(
            evaluation_plan(budget.clone()).evaluate(&TypedRegistry, &input),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(input, original);
        assert_eq!(budget.remaining(), limit);
        assert_eq!(budget.predicate_trials(), 0);
    }
    let exact = SubtreeBudget::new(total, 0).unwrap();
    assert_eq!(
        evaluation_plan(exact.clone())
            .evaluate(&TypedRegistry, &input)
            .unwrap(),
        expected
    );
    assert_eq!(input, original);
    assert_eq!(exact.remaining(), 0);
    assert_eq!(exact.predicate_trials(), 2);
}

#[test]
fn evaluation_reservation_is_independent_of_capture_order() {
    let first = forest(&[("a", "first")]).remove(0);
    let mut key_only = forest(&[("b", "unused")]).remove(0);
    key_only.children[0].children = vec![NetconfXmlNode::scalar(
        "/m:root/m:peer/m:key",
        "b".repeat(64),
        false,
    )];
    let second = forest(&[("c", "second")]).remove(0);
    let captures = [first, key_only, second];
    let expected = forest(&[("a", "first")]);
    let control = SubtreeBudget::new(1_000_000, 0).unwrap();
    assert_eq!(
        evaluation_plan(control.clone())
            .evaluate(&TypedRegistry, &captures)
            .unwrap(),
        expected
    );
    let used = 1_000_000 - control.remaining();
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let input: Vec<_> = order.iter().map(|index| captures[*index].clone()).collect();
        for limit in [1, 8, 128, 512, used / 2, used - 1, used, 1_000_000] {
            let budget = SubtreeBudget::new(limit, 0).unwrap();
            let result = evaluation_plan(budget.clone()).evaluate(&TypedRegistry, &input);
            if limit < used {
                assert_eq!(result, Err(SubtreeError::TooBig));
                assert_eq!(budget.remaining(), limit);
                assert_eq!(budget.predicate_trials(), 0);
            } else {
                assert_eq!(result.unwrap(), expected);
                assert_eq!(budget.remaining(), limit - used);
                assert_eq!(budget.predicate_trials(), control.predicate_trials());
            }
        }
    }
}

#[test]
fn whole_evaluation_counts_actual_index_comparisons_copies_and_moves() {
    for count in [0, 1, 2, 3, 7, 8, 9, 31, 32, 33, 100, 1024] {
        let mut expected_allowance = None;
        for coalescing in [false, true] {
            for matching in [false, true] {
                let mut input = Vec::new();
                for index in 0..count {
                    let mut root =
                        forest(&[("a", if matching { "first" } else { "other" })]).remove(0);
                    root.children[0].keys[0].1 =
                        format!("{:064x}", if coalescing { 0 } else { index });
                    input.push(root);
                }
                let budget = SubtreeBudget::new(16_777_216, 0).unwrap();
                let plan = evaluation_plan(budget.clone());
                identity::take_audits();
                let selected = plan.evaluate(&TypedRegistry, &input).unwrap_or_else(|error| {
                    let sizing = SubtreeBudget::new(usize::MAX, 0).unwrap();
                    let measured = evaluation::EvaluationWork::measure(&plan.scopes, &input, &TypedRegistry, &sizing).unwrap();
                    panic!("rows={count}, coalescing={coalescing}, matching={matching}: {error:?}; metadata={}, executor={}", usize::MAX - sizing.remaining(), measured.units);
                });
                let audits = identity::take_audits();
                assert_eq!(audits.len(), 1, "one admission for the whole evaluation");
                let audit = audits[0];
                assert_eq!(audit.admitted, 16_777_216 - budget.remaining());
                if let Some(expected) = expected_allowance {
                    assert_eq!(
                        (audit.admitted, audit.executor_allowance),
                        expected,
                        "identity equality and predicate outcomes cannot change admission"
                    );
                } else {
                    expected_allowance = Some((audit.admitted, audit.executor_allowance));
                }
                assert!(audit.actual() <= audit.executor_allowance, "{audit:?}");
                assert!(
                    audit.actual() <= audit.admitted,
                    "rows={count}, coalescing={coalescing}, matching={matching}: {audit:?}"
                );
                if count != 0 {
                    assert!(
                        audit.comparisons > 0 && audit.copies > 0 && audit.moves > 0,
                        "{audit:?}"
                    );
                }
                let rows = selected.first().map_or(0, |root| root.children.len());
                assert_eq!(
                    rows,
                    if matching {
                        if coalescing {
                            usize::from(count != 0)
                        } else {
                            count
                        }
                    } else {
                        0
                    }
                );
            }
        }
    }
}

#[test]
fn actual_work_counter_rejects_an_insufficient_admission() {
    let result = std::panic::catch_unwind(|| {
        let budget = SubtreeBudget::new(1, 0).unwrap();
        let reservation = IdentityReservation::admit(&budget, 1).unwrap();
        reservation.scalar("/m:root/m:peer/m:label", "value");
    });
    assert!(
        result.is_err(),
        "the executor counter must enforce its reservation"
    );
    let audits = identity::take_audits();
    assert!(audits.iter().any(|audit| audit.actual() > audit.admitted));
}

#[test]
fn whole_evaluation_normalizes_single_captures_before_assigning_positions() {
    let mut input = forest(&[("b", "first"), ("a", "first")]);
    let expected = input.clone();
    let duplicate = input[0].children[0].clone();
    input[0].children.push(duplicate);
    for row in &mut input[0].children {
        row.children.push(row.children[0].clone());
    }
    for alternatives in [1, 2, 8] {
        let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
        let mut plan = evaluation_plan(budget.clone());
        plan.scopes = vec![plan.scopes[0].clone(); alternatives];
        identity::take_audits();
        assert_eq!(plan.evaluate(&TypedRegistry, &input).unwrap(), expected);
        let audits = identity::take_audits();
        assert_eq!(audits.len(), 1);
        assert!(
            audits[0].actual() <= audits[0].executor_allowance,
            "{:?}",
            audits[0]
        );
    }
    input[0].children[0].children[1].value = Some("other".into());
    let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
    assert_eq!(
        evaluation_plan(budget).evaluate(&TypedRegistry, &input),
        Err(SubtreeError::Projection),
        "coalescing still rejects conflicting scalar values"
    );
}

struct LeafListRegistry;

impl SchemaRegistry for LeafListRegistry {
    fn schema_digest(&self) -> &'static str {
        "indexed-selection"
    }
    fn served_models(&self) -> &'static [ModelData] {
        Registry.served_models()
    }
    fn origins(&self) -> &'static [OriginEntry] {
        Registry.origins()
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        static NODES: std::sync::OnceLock<Vec<NodeMeta>> = std::sync::OnceLock::new();
        NODES.get_or_init(|| {
            let mut nodes = TypedRegistry.nodes().to_vec();
            nodes[1].child_paths = &[
                "/m:root/m:peer/m:key",
                "/m:root/m:peer/m:label",
                "/m:root/m:peer/m:tag",
            ];
            nodes.push(NodeMeta {
                path: "/m:root/m:peer/m:tag",
                kind: NodeKind::LeafList,
                ..nodes[3]
            });
            nodes
        })
    }
}

#[test]
fn whole_evaluation_indexes_keys_leaf_lists_and_overlapping_selections() {
    let key = "/m:root/m:peer/m:key";
    let tag = "/m:root/m:peer/m:tag";
    let mut input = forest(&[("b", "first"), ("a", "first")]);
    for row in &mut input[0].children {
        for value in ["b", "a", "b"] {
            row.children.push(NetconfXmlNode::scalar(tag, value, false));
        }
        for ordinal in [1, 0] {
            let mut masked = NetconfXmlNode::scalar(tag, "<redacted>", false);
            masked.masked_ordinal = Some(ordinal);
            row.children.push(masked);
        }
        row.children
            .push(NetconfXmlNode::scalar(key, row.keys[0].1.clone(), false));
    }
    let mut expected = input.clone();
    for row in &mut expected[0].children {
        row.children.remove(3);
        let key = row.children.pop().unwrap();
        row.children.insert(0, key);
    }
    for alternatives in [1, 2, 8] {
        let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
        let mut plan = evaluation_plan(budget);
        let row = plan.scopes[0].branches[0]
            .children
            .as_mut()
            .unwrap()
            .branches[0]
            .children
            .as_mut()
            .unwrap();
        row.implicit_outputs.extend([
            SubtreeOutput {
                path: tag,
                keys: vec![key],
            },
            SubtreeOutput {
                path: key,
                keys: vec![key],
            },
        ]);
        row.branches.push(SubtreeBranch {
            path: key,
            keys: vec![key],
            children: None,
            outputs: vec![SubtreeOutput {
                path: key,
                keys: vec![key],
            }],
        });
        plan.scopes = vec![plan.scopes[0].clone(); alternatives];
        identity::take_audits();
        assert_eq!(plan.evaluate(&LeafListRegistry, &input).unwrap(), expected);
        let audits = identity::take_audits();
        assert_eq!(audits.len(), 1);
        assert!(
            audits[0].actual() <= audits[0].executor_allowance,
            "{:?}",
            audits[0]
        );
    }
}

#[test]
fn capture_cardinality_checks_precede_identity_admission() {
    for malformed in 0..4 {
        let mut input = forest(&[("a", "first")]);
        match malformed {
            0 => input[0]
                .keys
                .push(("/m:root/m:peer/m:key", "unexpected".into())),
            1 => input[0].children[0].children[0].masked_ordinal = Some(0),
            2 => input[0].children[0]
                .keys
                .push(("/m:root/m:peer/m:key", "duplicate".into())),
            3 => input[0].children[0].children[0].schema_path = "/m:root",
            _ => unreachable!(),
        }
        let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
        identity::take_audits();
        assert_eq!(
            evaluation_plan(budget.clone()).evaluate(&TypedRegistry, &input),
            Err(SubtreeError::Projection)
        );
        assert_eq!(budget.remaining(), 1_000_000);
        assert_eq!(budget.predicate_trials(), 0);
        assert!(identity::take_audits().is_empty());
    }
}

#[test]
fn indexed_sort_is_stable_and_respects_the_comparison_and_move_bound() {
    use std::cell::Cell;
    for count in [0, 1, 2, 3, 7, 8, 9, 31, 32, 33, 1023, 1024, 1025] {
        for pattern in 0..3 {
            let input: Vec<_> = (0..count)
                .map(|value: usize| match pattern {
                    0 => count - 1 - value,
                    1 => (count - 1 - value) % 7,
                    // Bit reversal makes the sorted halves interleave at
                    // every level, exercising the maximum comparison count.
                    _ => value.reverse_bits() >> (usize::BITS as usize - sort_levels(count).max(1)),
                })
                .collect();
            let comparisons = Cell::new(0usize);
            let moves = Cell::new(0usize);
            let sorted = identity::sorted_indices(
                count,
                |left, right| {
                    comparisons.set(comparisons.get() + 1);
                    input[left].cmp(&input[right])
                },
                |units| moves.set(moves.get() + units),
            );
            let mut expected: Vec<_> = (0..count).collect();
            expected.sort_by_key(|index| input[*index]);
            assert_eq!(sorted, expected);
            assert!(comparisons.get() <= count * sort_levels(count));
            assert!(moves.get() <= count * (sort_levels(count) + 2));
        }
    }
}
