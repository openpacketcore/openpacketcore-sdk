use super::*;
use crate::{DataClass, EnumValueMeta, ModelData, NodeNumericRangeMeta, OriginEntry};

mod integer_keys;

const fn leaf(path: &'static str, leaf_type: LeafType, data_class: DataClass) -> NodeMeta {
    NodeMeta {
        path,
        module: "model",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(leaf_type),
        key_leaves: &[],
        data_class,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }
}

static NODES: &[NodeMeta] = &[
    leaf("/m:bool", LeafType::Boolean, DataClass::Public),
    leaf(
        "/m:chain",
        LeafType::LeafRef {
            target_path: "/m:ref",
        },
        DataClass::Public,
    ),
    leaf(
        "/m:custom",
        LeafType::Custom { name: "opaque" },
        DataClass::Public,
    ),
    leaf(
        "/m:cycle",
        LeafType::LeafRef {
            target_path: "/m:cycle",
        },
        DataClass::Public,
    ),
    leaf("/m:decimal", LeafType::Decimal64, DataClass::Public),
    leaf("/m:empty", LeafType::Empty, DataClass::Public),
    leaf(
        "/m:enum",
        LeafType::Enumeration {
            values: &[
                EnumValueMeta {
                    name: "active",
                    description: None,
                },
                EnumValueMeta {
                    name: "standby",
                    description: None,
                },
            ],
        },
        DataClass::Public,
    ),
    leaf(
        "/m:identity",
        LeafType::IdentityRef { base: "base" },
        DataClass::Public,
    ),
    leaf("/m:int", LeafType::Int64, DataClass::Public),
    leaf("/m:intercept", LeafType::String, DataClass::LawfulIntercept),
    leaf("/m:ranged", LeafType::Uint16, DataClass::Public),
    leaf(
        "/m:ref",
        LeafType::LeafRef {
            target_path: "/m:uint",
        },
        DataClass::Public,
    ),
    leaf("/m:secret", LeafType::String, DataClass::SecuritySecret),
    leaf("/m:text", LeafType::String, DataClass::Public),
    leaf("/m:uint", LeafType::Uint16, DataClass::Public),
    leaf("/m:unclassified", LeafType::String, DataClass::Public),
    leaf(
        "/m:unsupported-ref",
        LeafType::LeafRef {
            target_path: "/m:decimal",
        },
        DataClass::Public,
    ),
    leaf("/m:wide", LeafType::Uint32, DataClass::Public),
];

struct Registry;
impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "fixture"
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
        NODES
    }
    fn numeric_ranges(&self) -> &'static [NodeNumericRangeMeta] {
        &[NodeNumericRangeMeta {
            path: "/m:ranged",
            intervals: &[
                NumericRangeIntervalMeta { min: 5, max: 8 },
                NumericRangeIntervalMeta { min: 11, max: 11 },
            ],
        }]
    }
    fn data_class(&self, path: &str) -> Option<DataClass> {
        if path == "/m:unclassified" {
            None
        } else {
            self.node(path).map(|node| node.data_class)
        }
    }
}

fn budget() -> SubtreeBudget {
    SubtreeBudget::new(100_000, 0).unwrap()
}

#[test]
fn scalar_predicates_normalize_supported_types_and_preserve_strings() {
    for (path, literal, reported) in [
        ("/m:uint", "+007", "7"),
        ("/m:wide", "04294967295", "4294967295"),
        ("/m:int", "-9223372036854775808", "-9223372036854775808"),
        ("/m:bool", "true", "true"),
        ("/m:enum", "active", "active"),
        ("/m:ref", "007", "7"),
        ("/m:chain", "+007", "7"),
        ("/m:text", "+007", "+007"),
        ("/m:ranged", "0008", "8"),
    ] {
        let budget = budget();
        let predicate = ScalarPredicate::compile(&Registry, path, literal, false, &budget).unwrap();
        assert!(predicate.is_satisfiable(), "{path}");
        assert!(predicate.matches(reported, &budget).unwrap(), "{path}");
        assert!(!predicate.matches("other", &budget).unwrap(), "{path}");
    }
    let budget = budget();
    let predicate = ScalarPredicate::compile(&Registry, "/m:text", "+007", false, &budget).unwrap();
    assert!(!predicate.matches("7", &budget).unwrap());
}

#[test]
fn invalid_supported_literals_are_unsatisfiable() {
    for (path, literal) in [
        ("/m:uint", "65536"),
        ("/m:uint", "-1"),
        ("/m:uint", "seven"),
        ("/m:wide", "4294967296"),
        ("/m:int", "9223372036854775808"),
        ("/m:bool", "1"),
        ("/m:bool", "TRUE"),
        ("/m:enum", "ACTIVE"),
        ("/m:empty", "present"),
        ("/m:ref", "65536"),
        ("/m:ranged", "4"),
        ("/m:ranged", "9"),
    ] {
        let budget = budget();
        let predicate = ScalarPredicate::compile(&Registry, path, literal, false, &budget).unwrap();
        assert!(!predicate.is_satisfiable(), "{path}");
        assert!(!predicate.matches(literal, &budget).unwrap(), "{path}");
    }
}

#[test]
fn unsupported_types_and_masked_leaves_are_schema_refusals() {
    for path in [
        "/m:identity",
        "/m:decimal",
        "/m:custom",
        "/m:unsupported-ref",
        "/m:cycle",
    ] {
        assert_eq!(
            ScalarPredicate::compile(&Registry, path, "probe", false, &budget()),
            Err(SubtreeError::Unsupported)
        );
    }
    for key in [false, true] {
        for path in ["/m:secret", "/m:intercept", "/m:unclassified"] {
            assert_eq!(
                ScalarPredicate::compile(&Registry, path, "probe", key, &budget()),
                Err(SubtreeError::Unsupported)
            );
        }
    }
    for path in ["/m:identity", "/m:decimal", "/m:custom"] {
        let budget = budget();
        let predicate = ScalarPredicate::compile(&Registry, path, "1.00", true, &budget).unwrap();
        assert!(predicate.matches("1.00", &budget).unwrap());
        assert!(!predicate.matches("1.0", &budget).unwrap());
    }
}

#[test]
fn shared_budget_and_comparison_fail_at_the_first_overflow() {
    let shared = SubtreeBudget::new(12, 3).unwrap();
    shared.charge(4).unwrap();
    let other = shared.clone();
    assert!(other.compare("ab", "abc").is_ok());
    assert_eq!(shared.charge(1), Err(SubtreeError::TooBig));
    assert_eq!(other.copy("x"), Err(SubtreeError::TooBig));
    assert!(SubtreeBudget::new(1, 2).is_err());
    assert!(SubtreeBudget::new(0, 0).is_err());
    let exact = SubtreeBudget::new(4, 0).unwrap();
    assert!(!exact.compare("ab", "cd").unwrap());
    assert_eq!(exact.compare("x", "y"), Err(SubtreeError::TooBig));
    let trial = SubtreeBudget::new(1, 0).unwrap();
    trial.begin_predicate_trial().unwrap();
    assert_eq!(trial.clone().predicate_trials(), 1);
    assert_eq!(trial.begin_predicate_trial(), Err(SubtreeError::TooBig));
    assert_eq!(trial.predicate_trials(), 1);
}

#[test]
fn predicate_and_budget_debug_never_include_payloads_or_work_counts() {
    let budget = budget();
    let predicate = ScalarPredicate::compile(
        &Registry,
        "/m:text",
        "UNIQUE-predicate-marker",
        false,
        &budget,
    )
    .unwrap();
    assert_eq!(format!("{predicate:?}"), "ScalarPredicate(<redacted>)");
    assert_eq!(format!("{budget:?}"), "SubtreeBudget");
    assert_eq!(
        format!("{}", SubtreeError::TooBig),
        "subtree read exceeds a limit"
    );
}

#[test]
fn leafref_target_names_inherit_the_declaring_module_without_data_access() {
    assert_eq!(
        resolve_relative_target("/m:system/m:ref", "../port", &budget()).unwrap(),
        "/m:system/m:port"
    );
    assert_eq!(
        resolve_relative_target("/m:system/m:ref", "/system/port", &budget()).unwrap(),
        "/m:system/m:port"
    );
    assert_eq!(
        resolve_relative_target("/m:system/m:ref", "../x:port", &budget()).unwrap(),
        "/m:system/x:port"
    );
    assert_eq!(
        resolve_relative_target("/m:ref", "../../port", &budget()),
        Err(SubtreeError::Unsupported)
    );
}

#[test]
fn projection_rejected_enter_checks_consume_work_before_access() {
    for structural in [false, true] {
        let budget = budget();
        let plan = SubtreePlan::new(
            vec![SubtreeScope {
                implicit_outputs: vec![SubtreeOutput {
                    path: "/m:text",
                    keys: vec![],
                }],
                ..SubtreeScope::default()
            }],
            budget.clone(),
            32,
        )
        .unwrap()
        .authorize(|_| true, 32)
        .unwrap();
        let projection = plan.projection(&Registry, crate::DefaultReport::Trim);
        let before = budget.remaining();
        assert!(!projection.enter("/m:secret", structural).unwrap());
        assert!(
            budget.remaining() < before,
            "a rejected enter must not be free"
        );
        budget.charge(budget.remaining()).unwrap();
        assert_eq!(
            projection.enter("/m:secret", structural),
            Err(SubtreeError::TooBig)
        );
    }
}

#[test]
fn projection_structural_lookup_probes_share_the_work_budget() {
    let budget = budget();
    let paths = [
        "/m:a/m:value",
        "/m:b/m:value",
        "/m:c/m:value",
        "/m:d/m:value",
    ];
    let plan = SubtreePlan::new(
        vec![SubtreeScope {
            implicit_outputs: paths
                .into_iter()
                .map(|path| SubtreeOutput { path, keys: vec![] })
                .collect(),
            ..SubtreeScope::default()
        }],
        budget.clone(),
        32,
    )
    .unwrap()
    .authorize(|_| true, 32)
    .unwrap();
    let projection = plan.projection(&Registry, crate::DefaultReport::Trim);
    assert!(projection.enter("/m:c", true).unwrap());
    assert!(!projection.enter("/m:cc", true).unwrap());
    budget.charge(budget.remaining() - 1).unwrap();
    assert_eq!(
        projection.enter("/m:c", true),
        Err(SubtreeError::TooBig),
        "one admission unit cannot pay for plan-path probes"
    );
}

#[test]
fn projection_empty_authorized_plan_charges_enter_admission() {
    struct Observer(std::sync::atomic::AtomicUsize);
    impl SubtreeAccessObserver for Observer {
        fn before_read(&self, _: &'static str, _: SubtreeAccessKind) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    for structural in [false, true] {
        let budget = budget();
        let plan = SubtreePlan::new(Vec::new(), budget.clone(), 32)
            .unwrap()
            .authorize(|_| true, 32)
            .unwrap();
        let observer = Observer(std::sync::atomic::AtomicUsize::new(0));
        let projection = plan
            .projection(&Registry, crate::DefaultReport::Trim)
            .with_observer(&observer);
        let before = budget.remaining();
        assert!(!projection.enter("/m:secret", structural).unwrap());
        assert_eq!(budget.remaining(), before - 1);
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        budget.charge(budget.remaining()).unwrap();
        assert_eq!(
            projection.enter("/m:secret", structural),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(budget.remaining(), 0);
        assert_eq!(observer.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
