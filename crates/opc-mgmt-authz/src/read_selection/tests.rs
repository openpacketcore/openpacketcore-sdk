#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use opc_mgmt_schema::{DataClass, LeafType, ModelData, NodeMeta, OriginEntry};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Registry(u8);
const fn leaf(path: &'static str, module: &'static str) -> NodeMeta {
    NodeMeta {
        path,
        module,
        kind: NodeKind::Leaf,
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
const fn nodes(keys: &'static [&'static str]) -> [NodeMeta; 4] {
    [
        NodeMeta {
            path: "/d:rows",
            module: "demo",
            kind: NodeKind::List,
            config: true,
            leaf_type: None,
            key_leaves: keys,
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &["/d:rows/x:id", "/d:rows/d:id", "/d:rows/d:value"],
        },
        leaf("/d:rows/d:id", "demo"),
        leaf("/d:rows/d:value", "demo"),
        leaf("/d:rows/x:id", "extra"),
    ]
}
impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:qualified-keys"
    }
    fn served_models(&self) -> &'static [ModelData] {
        &[
            ModelData {
                name: "demo",
                revision: "2026-10-12",
                namespace: "urn:demo",
                prefix: "d",
            },
            ModelData {
                name: "extra",
                revision: "2026-10-12",
                namespace: "urn:extra",
                prefix: "x",
            },
        ]
    }
    fn origins(&self) -> &'static [OriginEntry] {
        &[OriginEntry {
            origin: "",
            modules: &["demo", "extra"],
        }]
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        static LOCAL: [NodeMeta; 4] = nodes(&["id"]);
        static QUALIFIED: [NodeMeta; 4] = nodes(&["x:id"]);
        static UNKNOWN: [NodeMeta; 4] = nodes(&["missing"]);
        match self.0 {
            0 => &LOCAL,
            1 => &QUALIFIED,
            _ => &UNKNOWN,
        }
    }
}
struct Source(AtomicUsize);
impl PolicySource for Source {
    fn active_policy(&self, _: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut modules = ModuleRegistry::new();
        modules.register_module("demo", "d").unwrap();
        modules.register_module("extra", "x").unwrap();
        let mut policy = NacmPolicy::builder(PolicyVersion::new(1));
        for path in ["/d:rows/d:value", "/d:rows/x:id"] {
            policy = policy.add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse(path, &modules).unwrap(),
            ));
        }
        Ok(Arc::new(policy.build()))
    }
}

#[test]
fn key_dependencies_respect_the_declaring_module_and_unknown_keys_fail_closed() {
    let principal = TrustedPrincipal::new(
        opc_config_model::WorkloadIdentity::User("namespace-fixture".into()),
        opc_types::TenantId::new("namespace-fixture").unwrap(),
    );
    for (kind, allowed, keys) in [
        (0, false, vec!["/d:rows/d:id"]),
        (1, true, vec!["/d:rows/x:id"]),
        (2, false, vec![]),
    ] {
        let registry = Registry(kind);
        let source = Source(AtomicUsize::new(0));
        let authorizer = ReadAuthorizer::new(&registry, &source).unwrap();
        let result = authorizer
            .authorize_selection(
                &principal,
                ReadAction::Read,
                &[ReadNode::projected("/d:rows/d:value")],
                &BTreeSet::new(),
            )
            .unwrap();
        assert_eq!(result.decisions[0].allowed, allowed);
        assert_eq!(result.identifying_keys(0), keys);
        assert_eq!(source.0.load(Ordering::SeqCst), 1);
    }
}
