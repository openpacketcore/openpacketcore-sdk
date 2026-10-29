//! Server-linked witnesses for schema operations outside generated predicates.

#![allow(clippy::unwrap_used)]

use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::subtree::{
    take_admission_observations, AdmissionObservation, ScalarPredicate, SubtreeBudget,
    SubtreeOutput, SubtreePlan, SubtreeScalar, SubtreeScope,
};
use opc_mgmt_schema::{
    DataClass, DefaultReport, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
};

const fn leaf(path: &'static str, kind: LeafType, default: Option<&'static str>) -> NodeMeta {
    NodeMeta {
        path,
        module: "model",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(kind),
        key_leaves: &[],
        data_class: DataClass::Public,
        default,
        has_default: default.is_some(),
        presence: false,
        child_paths: &[],
    }
}

struct Registry;

impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "admission-witness"
    }

    fn served_models(&self) -> &'static [ModelData] {
        &[ModelData {
            name: "model",
            revision: "",
            namespace: "urn:example:model",
            prefix: "m",
        }]
    }

    fn origins(&self) -> &'static [OriginEntry] {
        &[]
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        static NODES: &[NodeMeta] = &[
            leaf("/m:bool", LeafType::Boolean, Some("true")),
            leaf(
                "/m:decimal",
                LeafType::Decimal64 { fraction_digits: 2 },
                Some("1.25"),
            ),
            leaf("/m:int", LeafType::Int64, Some("-11")),
            NodeMeta {
                kind: NodeKind::Container,
                leaf_type: None,
                child_paths: &["/m:root/m:alias", "/m:root/m:target"],
                ..leaf("/m:root", LeafType::String, None)
            },
            leaf(
                "/m:root/m:alias",
                LeafType::LeafRef {
                    target_path: "../target",
                },
                None,
            ),
            leaf("/m:root/m:target", LeafType::Uint16, None),
            NodeMeta {
                kind: NodeKind::List,
                leaf_type: None,
                key_leaves: &["id"],
                child_paths: &["/m:rows/m:id", "/m:rows/m:tag"],
                ..leaf("/m:rows", LeafType::String, None)
            },
            leaf("/m:rows/m:id", LeafType::Uint16, None),
            NodeMeta {
                kind: NodeKind::LeafList,
                ..leaf("/m:rows/m:tag", LeafType::String, None)
            },
            leaf("/m:text", LeafType::String, Some("expected")),
            leaf("/m:uint", LeafType::Uint16, Some("7")),
        ];
        NODES
    }
}

fn require_observed(observations: &[AdmissionObservation], phases: &[&str]) {
    for phase in phases {
        let matching: Vec<_> = observations
            .iter()
            .filter(|item| item.phase == *phase)
            .collect();
        assert!(!matching.is_empty(), "operation was not reached: {phase}");
        assert!(
            matching.iter().any(|item| item.actual() > 0),
            "no work observed: {phase}"
        );
        assert!(
            matching.iter().all(|item| item.actual() <= item.admitted),
            "{matching:?}"
        );
    }
}

#[test]
fn scalar_predicates_observe_direct_trials_and_relative_leafref_resolution() {
    let budget =
        SubtreeBudget::new(MgmtLimits::default().max_subtree_filter_work_units, 0).unwrap();
    take_admission_observations();
    for (path, literal, canonical, different) in [
        ("/m:bool", "true", "true", "false"),
        ("/m:int", "-11", "-11", "-12"),
        ("/m:text", "expected", "expected", "different"),
        ("/m:root/m:alias", "+007", "7", "8"),
    ] {
        let predicate = ScalarPredicate::compile(&Registry, path, literal, false, &budget).unwrap();
        assert!(predicate.matches(canonical, &budget).unwrap());
        assert!(!predicate.matches(different, &budget).unwrap());
        assert_eq!(
            predicate.canonical_literal(&budget).unwrap().as_deref(),
            Some(canonical)
        );
    }
    assert_eq!(budget.predicate_trials(), 8);
    require_observed(
        &take_admission_observations(),
        &[
            "predicate trial",
            "scalar comparison",
            "integer literal rendering",
            "leafref path decoding",
            "leafref source segment",
            "leafref target segment",
            "leafref segment append",
            "leafref path rendering",
        ],
    );
}

#[test]
fn projection_observes_each_typed_default_and_scalar_rendering() {
    let limits = MgmtLimits::default();
    let budget = SubtreeBudget::new(limits.max_subtree_filter_work_units, 0).unwrap();
    let outputs = ["/m:bool", "/m:decimal", "/m:int", "/m:text", "/m:uint"]
        .into_iter()
        .map(|path| SubtreeOutput {
            path,
            keys: Vec::new(),
        })
        .collect();
    let plan = SubtreePlan::new(
        vec![SubtreeScope {
            implicit_outputs: outputs,
            ..SubtreeScope::default()
        }],
        budget,
        limits.max_subtree_filter_nodes,
    )
    .unwrap()
    .authorize(|_| true, limits.max_subtree_filter_nodes)
    .unwrap();
    let trim = plan.projection(&Registry, DefaultReport::Trim);
    let explicit = plan.projection(&Registry, DefaultReport::Explicit);
    take_admission_observations();
    for (path, default, changed, text) in [
        (
            "/m:bool",
            SubtreeScalar::Boolean(true),
            SubtreeScalar::Boolean(false),
            "false",
        ),
        (
            "/m:decimal",
            SubtreeScalar::Decimal(opc_mgmt_schema::Decimal64::parse("1.25", 2).unwrap()),
            SubtreeScalar::Decimal(opc_mgmt_schema::Decimal64::parse("2.5", 2).unwrap()),
            "2.5",
        ),
        (
            "/m:int",
            SubtreeScalar::Integer(-11),
            SubtreeScalar::Integer(-12),
            "-12",
        ),
        (
            "/m:text",
            SubtreeScalar::Text("expected"),
            SubtreeScalar::Text("different"),
            "different",
        ),
        (
            "/m:uint",
            SubtreeScalar::Unsigned(7),
            SubtreeScalar::Unsigned(8),
            "8",
        ),
    ] {
        assert!(trim.scalar(path, default, true).unwrap().is_none());
        for (projection, defaulted) in [(&trim, true), (&explicit, false)] {
            let node = projection
                .scalar(path, changed, defaulted)
                .unwrap()
                .unwrap();
            assert_eq!(node.schema_path, path);
            assert_eq!(node.value.as_deref(), Some(text));
            assert_eq!(node.is_defaulted, defaulted);
        }
    }
    require_observed(
        &take_admission_observations(),
        &[
            "default comparison",
            "signed default rendering",
            "unsigned default rendering",
            "decimal default rendering",
            "signed scalar rendering",
            "unsigned scalar rendering",
            "decimal scalar rendering",
        ],
    );
}

#[test]
fn bounded_merge_observes_capture_metadata_before_coalescing_fragments() {
    use opc_mgmt_schema::subtree::merge_bounded;
    use opc_mgmt_schema::NetconfXmlNode;

    fn row(id: &str, tag: &str) -> NetconfXmlNode {
        let mut row = NetconfXmlNode::branch("/m:rows");
        row.keys.push(("/m:rows/m:id", id.into()));
        row.children
            .push(NetconfXmlNode::scalar("/m:rows/m:tag", tag, false));
        row
    }

    let budget =
        SubtreeBudget::new(MgmtLimits::default().max_subtree_filter_work_units, 0).unwrap();
    let mut output = vec![row("1", "alpha")];
    take_admission_observations();
    merge_bounded(
        &Registry,
        &mut output,
        vec![row("1", "beta"), row("2", "gamma")],
        &budget,
    )
    .unwrap();
    assert_eq!(output.len(), 2);
    assert_eq!(output[0].keys, [("/m:rows/m:id", "1".into())]);
    assert_eq!(output[1].keys, [("/m:rows/m:id", "2".into())]);
    assert_eq!(
        output[0]
            .children
            .iter()
            .map(|node| node.value.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    assert_eq!(output[1].children[0].value.as_deref(), Some("gamma"));
    require_observed(
        &take_admission_observations(),
        &[
            "plan include_nodes visit 1",
            "plan include_nodes visit 2",
            "captured key metadata",
        ],
    );
}

#[test]
fn root_predicate_observes_implicit_outputs_within_its_namespace() {
    use crate::filter::{compile_content, yang_library_registry, ContentScope};
    use crate::xml::{parse_rpc, Filter, RpcOperation};
    use opc_mgmt_schema::NetconfXmlNode;

    let limits = MgmtLimits::default();
    let request = parse_rpc(
        r#"<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><get><filter type="subtree"><text xmlns="urn:example:model">expected</text></filter></get></rpc>"#,
        &limits,
    ).unwrap();
    let RpcOperation::Get(request) = request.operation else {
        panic!("expected get");
    };
    let Some(Filter::Subtree(filter)) = request.filter else {
        panic!("expected subtree filter");
    };
    take_admission_observations();
    let plan = compile_content(
        &[&Registry, yang_library_registry()],
        &filter,
        ContentScope::All,
        &limits,
    )
    .unwrap();
    assert_eq!(
        plan.authorization_paths(),
        Registry
            .nodes()
            .iter()
            .map(|node| node.path)
            .collect::<Vec<_>>()
    );
    let plan = plan
        .authorize(|_| true, limits.max_subtree_filter_nodes)
        .unwrap();
    let mut input = vec![
        NetconfXmlNode::scalar("/m:text", "expected", false),
        NetconfXmlNode::scalar("/m:uint", "7", false),
    ];
    assert_eq!(plan.evaluate(&Registry, &input).unwrap(), input);
    input[0].value = Some("different".into());
    assert!(plan.evaluate(&Registry, &input).unwrap().is_empty());
    require_observed(
        &take_admission_observations(),
        &[
            "content resolved_scope visit 3",
            "implicit root schema scan",
            "implicit root outputs",
        ],
    );
}
